#include "kernel_runtime.h"
#include "guest_process_context.h"
#include "guest_call_bridge.h"
#include "guest_libc_allocator.h"
#include "guest_tcb_runtime.h"

#include <cstdint>
#include <algorithm>
#include <cstdlib>
#include <cerrno>
#include <atomic>
#include <array>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace nba16 {
extern "C" std::uint64_t nba16_guest_sysctl_syscall_last_rax = UINT64_MAX;
extern "C" std::uint64_t nba16_guest_sysctl_guest_caller = 0;
extern "C" std::uint64_t nba16_guest_sysctl_actual_caller = 0;
extern "C" std::uint64_t nba16_guest_virtual_query_guest_caller = 0;
extern "C" std::uint64_t nba16_guest_virtual_query_parent_caller = 0;
std::atomic<std::uint64_t> last_sysctl_dispatch_mib0{};
std::atomic<std::uint64_t> last_sysctl_dispatch_mib1{};
std::atomic<std::uint64_t> last_sysctl_dispatch_result{UINT64_MAX};
std::atomic<std::uint64_t> sysctl_dispatch_sequence{};
std::array<std::atomic<std::uint64_t>, 32> sysctl_dispatch_history{};
namespace {

thread_local int guest_errno{};
thread_local std::int32_t guest_cancel_state{};
std::atomic<std::uint64_t> guest_usrstack_top{};
std::atomic<void*> guest_process_parameter{};
std::atomic<std::uint64_t> sysctl_calls{};
std::atomic<std::uint64_t> sysctlbyname_calls{};
std::atomic<std::uint64_t> usrstack_sysctl_calls{};
std::atomic<std::uint64_t> virtual_query_calls{};
std::atomic<std::uint64_t> mmap_calls{};
std::atomic<std::uint64_t> cpuset_calls{};
std::atomic<std::uint64_t> virtual_query_end_calls{};
struct DirectMemoryBlock { std::uint64_t start{}, size{}; std::int32_t type{}; };
struct DirectMemoryMapping {
    std::uintptr_t address{};
    std::uint64_t size{}, physical{};
    bool provider_owned{};
};
struct GuestQueryRegion {
    std::uint64_t begin{}, end{};
    std::uint32_t protection{};
    std::string name;
};
std::mutex guest_query_regions_lock;
std::vector<GuestQueryRegion> guest_query_regions;
std::mutex direct_memory_lock;
std::vector<DirectMemoryBlock> direct_memory_blocks;
std::vector<DirectMemoryMapping> direct_memory_mappings;
std::mutex direct_memory_provider_lock;
DirectMemoryProvider direct_memory_provider;

DirectMemoryProvider current_direct_memory_provider() noexcept {
    std::lock_guard lock(direct_memory_provider_lock);
    return direct_memory_provider;
}
#ifdef _WIN32
HANDLE direct_memory_section{};
constexpr std::uint64_t direct_memory_pool_size = 5056ULL * 1024ULL * 1024ULL;

HANDLE get_direct_memory_section() {
    if (direct_memory_section != nullptr) return direct_memory_section;
    const auto section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE | SEC_COMMIT,
        static_cast<DWORD>(direct_memory_pool_size >> 32U),
        static_cast<DWORD>(direct_memory_pool_size), nullptr);
    if (section != nullptr) direct_memory_section = section;
    return section;
}
#endif
// Keep auto-placed direct mappings in the PS4 user range used by the working
// port. Fixed/special requests (including 0x5000100000) still honor their hint.
std::uint64_t next_direct_memory_address = 0x1000000000ULL;
struct GuestMspace {
    std::uintptr_t base{};
    std::size_t size{};
    std::vector<std::pair<std::size_t, std::size_t>> free_ranges;
    std::unordered_map<std::size_t, std::size_t> used_ranges;
    std::size_t current_use{};
    std::size_t peak_use{};
};
struct GuestMspaceStats {
    std::uint16_t size{};
    std::uint16_t version{};
    std::uint32_t reserved{};
    std::uint64_t max_system{}, current_system{}, max_in_use{}, current_in_use{};
};
static_assert(sizeof(GuestMspaceStats) == 40);
std::mutex guest_mspace_lock;
std::unordered_map<std::uintptr_t, GuestMspace> guest_mspaces;
void** guest_mspace_default_slot{};
std::array<std::atomic<std::uint64_t>, 8> last_sysctl_trace{};
std::array<std::atomic<std::uint64_t>, 8> usrstack_sysctl_trace{};
std::atomic<std::uint64_t> usrstack_sysctl_result{};
std::atomic<std::uint64_t> usrstack_sysctl_response_length{};
std::atomic<std::uint64_t> usrstack_sysctl_response_value{};
constexpr int guest_error_permission = 1;
constexpr int guest_error_no_such_process = 3;
constexpr int guest_error_busy = 16;
constexpr int guest_error_invalid = 22;
constexpr int guest_error_deadlock = 35;
constexpr int guest_error_again = 11;
constexpr int guest_error_timed_out = 60;
constexpr std::int32_t orbis_kernel_error_esrch = std::bit_cast<std::int32_t>(0x80020003U);
constexpr std::int32_t orbis_kernel_error_eacces = std::bit_cast<std::int32_t>(0x8002000dU);
constexpr std::int32_t orbis_kernel_error_ebusy = std::bit_cast<std::int32_t>(0x80020010U);
constexpr std::int32_t orbis_kernel_error_einval = std::bit_cast<std::int32_t>(0x80020016U);
constexpr std::int32_t orbis_kernel_error_etimedout = std::bit_cast<std::int32_t>(0x8002003cU);
constexpr std::int32_t orbis_kernel_error_ecanceled = std::bit_cast<std::int32_t>(0x80020055U);
std::uintptr_t guest_stack_guard = sizeof(std::uintptr_t) == 8
    ? static_cast<std::uintptr_t>(0x9e3779b97f4a7c15ULL)
    : static_cast<std::uintptr_t>(0x9e3779b9U);

struct GuestMutex {
    std::mutex native;
    std::mutex owner_lock;
    std::thread::id owner{};
    std::uintptr_t owner_caller{};
    std::uint32_t owner_thread_id{};
    int type{1};
    std::uint32_t recursion_depth{};
    std::atomic<bool> destroyed{};
};

struct GuestMutexAttributes {
    int type{1};
    int process_shared{};
};

std::mutex mutex_registry_lock;
std::unordered_map<void*, std::shared_ptr<GuestMutex>> mutex_registry;
std::unordered_map<const void*, std::shared_ptr<GuestMutex>> static_guest_mutexes;

struct GuestCondition {
    std::condition_variable native;
    std::atomic<std::uint32_t> waiters{};
    std::atomic<bool> destroyed{};
};

std::mutex condition_registry_lock;
std::unordered_map<void*, std::shared_ptr<GuestCondition>> condition_registry;

struct GuestThread {
    std::thread native;
    std::mutex lifecycle_lock;
    void* result{};
    bool detached{};
    bool joined{};
    GuestProcessContext* process_context{};
    std::uintptr_t guest_entry{};
    void* guest_argument{};
};

std::mutex thread_registry_lock;
std::unordered_map<void*, std::shared_ptr<GuestThread>> thread_registry;
thread_local GuestThread* current_guest_thread{};
thread_local std::byte external_thread_token{};

using GuestDestructor = GuestFunction<void, void*>;
struct GuestSpecificKey {
    std::uint32_t generation{};
    GuestDestructor destructor{};
    bool allocated{};
};
struct GuestSpecificValue {
    std::uint32_t generation{};
    void* value{};
};
constexpr std::size_t guest_specific_key_count = 256;
constexpr int guest_specific_destructor_iterations = 4;
std::mutex specific_key_lock;
std::array<GuestSpecificKey, guest_specific_key_count> specific_keys{};
thread_local std::array<GuestSpecificValue, guest_specific_key_count> specific_values{};
std::atomic_uint32_t wait_trace_events{};

void trace_wait_event(const char* message, std::size_t length) noexcept {
#ifdef _WIN32
    if (std::getenv("NBA16_TRACE_WAIT") == nullptr &&
        std::getenv("NBA16_TRACE_WAIT_EVENTS") == nullptr) return;
    if (wait_trace_events.fetch_add(1, std::memory_order_relaxed) >= 1024) return;
    DWORD written{};
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), message, static_cast<DWORD>(length),
              &written, nullptr);
#else
    (void)message;
    (void)length;
#endif
}

void trace_pthread_create_event(const char* message, std::size_t length) noexcept {
    if (std::getenv("NBA16_TRACE_PTHREAD_CREATE") == nullptr) {
        trace_wait_event(message, length);
        return;
    }
#ifdef _WIN32
    (void)std::fwrite(message, 1, length, stderr);
#else
    (void)message;
    (void)length;
#endif
}

struct GuestSemaphore {
    std::mutex lock;
    std::condition_variable changed;
    std::string name;
    std::int32_t tokens{};
    std::int32_t initial{};
    std::int32_t maximum{};
    std::uint32_t cancel_generation{};
    std::size_t waiters{};
    std::uint32_t trace_wait_records{};
    bool deleted{};
};

void run_specific_destructors() noexcept {
    for (int iteration = 0; iteration < guest_specific_destructor_iterations; ++iteration) {
        bool invoked = false;
        for (std::size_t index = 0; index < guest_specific_key_count; ++index) {
            GuestDestructor destructor{};
            void* value{};
            {
                std::lock_guard lock(specific_key_lock);
                auto& slot = specific_values[index];
                auto& key = specific_keys[index];
                if (slot.value == nullptr) continue;
                value = slot.value;
                if (key.allocated && key.generation == slot.generation) {
                    destructor = key.destructor;
                }
                slot = {};
            }
            if (destructor != nullptr) {
                invoked = true;
                try { destructor(value); } catch (...) {}
            }
        }
        if (!invoked) break;
    }
}

int NBA16_GUEST_SYSV_ABI guest_pthread_key_create(
    std::uint32_t* output, GuestDestructor destructor) {
    if (output == nullptr) return guest_error_invalid;
    std::lock_guard lock(specific_key_lock);
    for (std::size_t index = 0; index < specific_keys.size(); ++index) {
        auto& key = specific_keys[index];
        if (key.allocated) continue;
        ++key.generation;
        if (key.generation == 0) ++key.generation;
        key.destructor = destructor;
        key.allocated = true;
        *output = static_cast<std::uint32_t>(index);
        return 0;
    }
    return guest_error_again;
}

int NBA16_GUEST_SYSV_ABI guest_pthread_key_delete(std::uint32_t key_index) {
    if (key_index >= specific_keys.size()) return guest_error_invalid;
    std::lock_guard lock(specific_key_lock);
    auto& key = specific_keys[key_index];
    if (!key.allocated) return guest_error_invalid;
    key.allocated = false;
    key.destructor = nullptr;
    ++key.generation;
    if (key.generation == 0) ++key.generation;
    return 0;
}

void* NBA16_GUEST_SYSV_ABI guest_pthread_getspecific(std::uint32_t key_index) {
    if (key_index >= specific_keys.size()) return nullptr;
    std::lock_guard lock(specific_key_lock);
    const auto& key = specific_keys[key_index];
    const auto& value = specific_values[key_index];
    return key.allocated && key.generation == value.generation ? value.value : nullptr;
}

int NBA16_GUEST_SYSV_ABI guest_pthread_setspecific(std::uint32_t key_index, void* value) {
    if (key_index >= specific_keys.size()) return guest_error_invalid;
    std::lock_guard lock(specific_key_lock);
    const auto& key = specific_keys[key_index];
    if (!key.allocated) return guest_error_invalid;
    specific_values[key_index] = {key.generation, value};
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_pthread_setcancelstate(
    std::int32_t state, std::int32_t* previous_state) {
    if (state != 0 && state != 1) return orbis_kernel_error_einval;
    if (previous_state != nullptr) *previous_state = guest_cancel_state;
    guest_cancel_state = state;
    return 0;
}

std::mutex semaphore_registry_lock;
std::unordered_map<std::int32_t, std::shared_ptr<GuestSemaphore>> semaphore_registry;
std::atomic<std::int32_t> next_semaphore_handle{1};

struct GuestTimespec {
    std::int64_t seconds;
    std::int64_t nanoseconds;
};

struct GuestTimeval {
    std::int64_t seconds;
    std::int64_t microseconds;
};

std::uint64_t NBA16_GUEST_SYSV_ABI guest_read_tsc() {
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    return static_cast<std::uint64_t>(ticks);
}

std::uint64_t NBA16_GUEST_SYSV_ABI guest_get_tsc_frequency() {
    using Period = std::chrono::steady_clock::period;
    return static_cast<std::uint64_t>(Period::den / Period::num);
}

int NBA16_GUEST_SYSV_ABI guest_nanosleep(const GuestTimespec* request,
                                        GuestTimespec* remaining) {
    if (request == nullptr || request->seconds < 0 || request->nanoseconds < 0 ||
        request->nanoseconds >= 1'000'000'000) {
        return guest_error_invalid;
    }
    trace_wait_event("WAIT nanosleep entered\n", 23);
    const auto duration = std::chrono::seconds(request->seconds) +
                          std::chrono::nanoseconds(request->nanoseconds);
    std::this_thread::sleep_for(duration);
    if (remaining != nullptr) *remaining = {};
    trace_wait_event("WAIT nanosleep returned\n", 24);
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_usleep(std::uint32_t microseconds) {
    if (microseconds > 1'000'000U) return guest_error_invalid;
    trace_wait_event("WAIT usleep entered\n", 20);
    std::this_thread::sleep_for(std::chrono::microseconds(microseconds));
    trace_wait_event("WAIT usleep returned\n", 21);
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_clock_gettime(std::uint32_t clock_id,
                                             GuestTimespec* output) {
    if (output == nullptr) return guest_error_invalid;
    if (clock_id == 0) {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now);
        const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now - seconds);
        *output = {seconds.count(), nanos.count()};
        return 0;
    }
    if (clock_id == 4) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now);
        const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now - seconds);
        *output = {seconds.count(), nanos.count()};
        return 0;
    }
    return guest_error_invalid;
}

int NBA16_GUEST_SYSV_ABI guest_gettimeofday(GuestTimeval* output) {
    if (output == nullptr) return guest_error_invalid;
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now);
    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(now - seconds);
    *output = {seconds.count(), micros.count()};
    return 0;
}

std::shared_ptr<GuestMutex> find_mutex(void* handle) {
    if (handle == nullptr) return {};
    std::lock_guard lock(mutex_registry_lock);
    const auto found = mutex_registry.find(handle);
    return found == mutex_registry.end() ? nullptr : found->second;
}

std::shared_ptr<GuestMutex> static_guest_mutex(const void* slot, bool create) {
    if (slot == nullptr) return {};
    std::lock_guard lock(mutex_registry_lock);
    const auto found = static_guest_mutexes.find(slot);
    if (found != static_guest_mutexes.end()) return found->second;
    if (!create) return {};
    auto state = std::shared_ptr<GuestMutex>(new (std::nothrow) GuestMutex());
    if (!state) return {};
    static_guest_mutexes.emplace(slot, state);
    return state;
}

std::shared_ptr<GuestCondition> find_condition(void* handle) {
    if (handle == nullptr) return {};
    std::lock_guard lock(condition_registry_lock);
    const auto found = condition_registry.find(handle);
    return found == condition_registry.end() ? nullptr : found->second;
}

std::shared_ptr<GuestThread> find_thread(void* handle) {
    if (handle == nullptr) return {};
    std::lock_guard lock(thread_registry_lock);
    const auto found = thread_registry.find(handle);
    return found == thread_registry.end() ? nullptr : found->second;
}

int NBA16_GUEST_SYSV_ABI guest_pthread_create(
    void** output, const void* attributes,
    GuestFunction<void*, void*> entry, void* argument) {
    (void)attributes;
    trace_wait_event("THREAD create requested\n", 24);
    if (std::getenv("NBA16_TRACE_WAIT") != nullptr ||
        std::getenv("NBA16_TRACE_WAIT_EVENTS") != nullptr ||
        std::getenv("NBA16_TRACE_PTHREAD_CREATE") != nullptr) {
        char message[128]{};
        const auto length = std::snprintf(message, sizeof(message),
            "THREAD create entry=0x%llx argument=%p\n",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(entry)), argument);
        if (length > 0) trace_pthread_create_event(message, static_cast<std::size_t>(length));
#ifdef _WIN32
        std::array<std::uint64_t, 16> task_fields{};
        SIZE_T copied{};
        if (argument != nullptr && ReadProcessMemory(GetCurrentProcess(), argument,
                task_fields.data(), sizeof(task_fields), &copied) != 0 &&
            copied == sizeof(task_fields)) {
            const auto task_length = std::snprintf(message, sizeof(message),
                "THREAD task-data work=0x%llx callback=0x%llx state=0x%llx sema=%llu\n",
                static_cast<unsigned long long>(task_fields[3]),
                static_cast<unsigned long long>(task_fields[5]),
                static_cast<unsigned long long>(task_fields[13]),
                static_cast<unsigned long long>(task_fields[14]));
            if (task_length > 0)
                trace_pthread_create_event(message, static_cast<std::size_t>(task_length));
            std::uintptr_t work_vtable{};
            SIZE_T vtable_pointer_bytes{};
            const auto work_object = static_cast<std::uintptr_t>(task_fields[3]);
            if (work_object != 0 && ReadProcessMemory(GetCurrentProcess(),
                    reinterpret_cast<const void*>(work_object), &work_vtable,
                    sizeof(work_vtable), &vtable_pointer_bytes) != 0 &&
                vtable_pointer_bytes == sizeof(work_vtable)) {
                std::array<std::uintptr_t, 27> methods{};
                SIZE_T method_bytes{};
                if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(work_vtable),
                        methods.data(), sizeof(methods), &method_bytes) != 0 &&
                    method_bytes == sizeof(methods)) {
                    const auto vtable_length = std::snprintf(message, sizeof(message),
                        "THREAD task-vtable object=0x%llx table=0x%llx run=0x%llx "
                        "typecheck=0x%llx dispatch=0x%llx\n",
                        static_cast<unsigned long long>(work_object),
                        static_cast<unsigned long long>(work_vtable),
                        static_cast<unsigned long long>(methods[2]),
                        static_cast<unsigned long long>(methods[7]),
                        static_cast<unsigned long long>(methods[26]));
                    if (vtable_length > 0)
                        trace_pthread_create_event(message, static_cast<std::size_t>(vtable_length));
                }
            }
        }
#endif
    }
    if (output == nullptr || entry == nullptr) return guest_error_invalid;
    if (*output != nullptr) return guest_error_busy;
    std::shared_ptr<GuestThread> state;
    try {
        state = std::make_shared<GuestThread>();
        state->process_context = current_guest_process_context();
        state->guest_entry = reinterpret_cast<std::uintptr_t>(entry);
        state->guest_argument = argument;
        void* handle = state.get();
        {
            std::lock_guard registry_guard(thread_registry_lock);
            thread_registry.emplace(handle, state);
            *output = handle;
        }
        state->native = std::thread([state, entry, argument] {
            ScopedGuestProcessContext process_scope(state->process_context);
            current_guest_thread = state.get();
            std::string tcb_error;
            if (!initialize_guest_tcb(tcb_error)) {
                const auto message = "THREAD guest TCB setup failed: " + tcb_error + "\n";
                trace_wait_event(message.data(), message.size());
                current_guest_thread = nullptr;
                return;
            }
            trace_wait_event("THREAD entry started\n", 21);
            try {
#ifdef _WIN32
                struct GuestThreadInvocation {
                    GuestFunction<void*, void*> entry;
                    void* argument;
                    void* result;
                } invocation{entry, argument, nullptr};
                nba16_guest_run_on_fiber([](void* opaque) {
                    auto& call = *static_cast<GuestThreadInvocation*>(opaque);
                    call.result = call.entry(call.argument);
                }, &invocation);
                state->result = invocation.result;
#else
                state->result = entry(argument);
#endif
            } catch (...) {
                state->result = nullptr;
            }
            run_specific_destructors();
            clear_guest_tcb_for_current_thread();
            current_guest_thread = nullptr;
            trace_wait_event("THREAD entry returned\n", 22);
        });
    } catch (...) {
        if (state) {
            std::lock_guard registry_guard(thread_registry_lock);
            thread_registry.erase(state.get());
        }
        *output = nullptr;
        return guest_error_again;
    }
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_pthread_join(void* handle, void** result_output) {
    trace_wait_event("THREAD join requested\n", 22);
    const auto state = find_thread(handle);
    if (!state) return guest_error_no_such_process;
    std::lock_guard lifecycle_guard(state->lifecycle_lock);
    if (state->detached || state->joined || !state->native.joinable()) {
        return guest_error_invalid;
    }
    if (state->native.get_id() == std::this_thread::get_id()) return guest_error_deadlock;
    try {
        state->native.join();
    } catch (...) {
        return guest_error_invalid;
    }
    state->joined = true;
    if (result_output != nullptr) *result_output = state->result;
    {
        std::lock_guard registry_guard(thread_registry_lock);
        thread_registry.erase(handle);
    }
    trace_wait_event("THREAD join completed\n", 23);
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_pthread_detach(void* handle) {
    const auto state = find_thread(handle);
    if (!state) return guest_error_no_such_process;
    std::lock_guard lifecycle_guard(state->lifecycle_lock);
    if (state->detached || state->joined || !state->native.joinable()) {
        return guest_error_invalid;
    }
    try {
        state->native.detach();
    } catch (...) {
        return guest_error_invalid;
    }
    state->detached = true;
    std::lock_guard registry_guard(thread_registry_lock);
    thread_registry.erase(handle);
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_pthread_equal(void* left, void* right) {
    return left == right ? 1 : 0;
}

void* NBA16_GUEST_SYSV_ABI guest_pthread_self() {
    return current_guest_thread != nullptr
        ? static_cast<void*>(current_guest_thread)
        : static_cast<void*>(&external_thread_token);
}

std::shared_ptr<GuestSemaphore> find_semaphore(std::int32_t handle) {
    std::lock_guard lock(semaphore_registry_lock);
    const auto found = semaphore_registry.find(handle);
    return found == semaphore_registry.end() ? nullptr : found->second;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_kernel_create_sema(
    std::int32_t* output, const char* name, std::uint32_t attributes,
    std::int32_t initial, std::int32_t maximum, const void* options) {
    (void)options;
    if (output == nullptr || name == nullptr || attributes > 2 || initial < 0 ||
        maximum <= 0 || initial > maximum) return orbis_kernel_error_einval;
    auto state = std::make_shared<GuestSemaphore>();
    state->name = name;
    state->tokens = initial;
    state->initial = initial;
    state->maximum = maximum;
    auto handle = next_semaphore_handle.fetch_add(1, std::memory_order_relaxed);
    if (handle <= 0) {
        next_semaphore_handle.store(2, std::memory_order_relaxed);
        handle = 1;
    }
    {
        std::lock_guard lock(semaphore_registry_lock);
        while (semaphore_registry.contains(handle)) {
            handle = next_semaphore_handle.fetch_add(1, std::memory_order_relaxed);
            if (handle <= 0) handle = next_semaphore_handle.fetch_add(1, std::memory_order_relaxed);
        }
        semaphore_registry.emplace(handle, std::move(state));
    }
    *output = handle;
    if (std::getenv("NBA16_TRACE_WAIT") != nullptr) {
        char message[256]{};
        const auto size = std::snprintf(message, sizeof(message),
            "SEMAPHORE create handle=%d name='%s' initial=%d maximum=%d\n",
            handle, name, initial, maximum);
        if (size > 0) trace_wait_event(message, static_cast<std::size_t>(size));
    }
    return 0;
}

std::int32_t wait_semaphore(std::int32_t handle, std::int32_t requested,
                            const std::uint32_t* timeout, bool block) {
    if (requested <= 0) return orbis_kernel_error_einval;
    const auto state = find_semaphore(handle);
    if (!state) return orbis_kernel_error_esrch;
    std::unique_lock lock(state->lock);
    if (state->deleted) return orbis_kernel_error_eacces;
    if (state->tokens >= requested) {
        state->tokens -= requested;
        return 0;
    }
    if (!block) return orbis_kernel_error_ebusy;
    if (timeout != nullptr && *timeout == 0) return orbis_kernel_error_etimedout;
    const auto generation = state->cancel_generation;
    ++state->waiters;
    const auto* trace_thread = current_guest_thread;
    const auto trace_thread_handle = static_cast<const void*>(trace_thread);
    const auto trace_thread_entry = trace_thread == nullptr ? 0 : trace_thread->guest_entry;
    const auto trace_thread_argument = trace_thread == nullptr ? nullptr : trace_thread->guest_argument;
    const bool trace_this_wait = std::getenv("NBA16_TRACE_WAIT") != nullptr &&
                                 state->trace_wait_records++ < 2;
    const auto ready = [&] {
        return state->deleted || state->cancel_generation != generation ||
               state->tokens >= requested;
    };
    if (trace_this_wait) {
        char message[320]{};
        const auto timeout_us = timeout == nullptr ? UINT32_MAX : *timeout;
        const auto size = std::snprintf(message, sizeof(message),
            "WAIT semaphore begin handle=%d name='%s' thread=%p entry=0x%llx arg=%p "
            "requested=%d tokens=%d timeout_us=%u waiters=%zu\n",
            handle, state->name.c_str(), trace_thread_handle,
            static_cast<unsigned long long>(trace_thread_entry), trace_thread_argument,
            requested, state->tokens, timeout_us, state->waiters);
        if (size > 0) trace_wait_event(message, static_cast<std::size_t>(size));
    }
    bool awakened = true;
    if (timeout == nullptr) {
        state->changed.wait(lock, ready);
    } else {
        awakened = state->changed.wait_for(lock, std::chrono::microseconds(*timeout), ready);
    }
    --state->waiters;
    if (trace_this_wait) {
        char message[320]{};
        const auto timeout_us = timeout == nullptr ? UINT32_MAX : *timeout;
        const auto status = state->deleted ? orbis_kernel_error_eacces :
            state->cancel_generation != generation ? orbis_kernel_error_ecanceled :
            !awakened || state->tokens < requested ? orbis_kernel_error_etimedout : 0;
        const auto size = std::snprintf(message, sizeof(message),
            "WAIT semaphore end handle=%d name='%s' thread=%p entry=0x%llx arg=%p "
            "status=0x%x tokens=%d timeout_us=%u awakened=%d waiters=%zu\n",
            handle, state->name.c_str(), trace_thread_handle,
            static_cast<unsigned long long>(trace_thread_entry), trace_thread_argument,
            status, state->tokens, timeout_us, awakened ? 1 : 0, state->waiters);
        if (size > 0) trace_wait_event(message, static_cast<std::size_t>(size));
    }
    if (state->deleted) return orbis_kernel_error_eacces;
    if (state->cancel_generation != generation) return orbis_kernel_error_ecanceled;
    if (!awakened || state->tokens < requested) return orbis_kernel_error_etimedout;
    state->tokens -= requested;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_kernel_wait_sema(
    std::int32_t handle, std::int32_t requested, const std::uint32_t* timeout) {
    return wait_semaphore(handle, requested, timeout, true);
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_kernel_poll_sema(
    std::int32_t handle, std::int32_t requested) {
    return wait_semaphore(handle, requested, nullptr, false);
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_kernel_signal_sema(
    std::int32_t handle, std::int32_t count) {
    if (count < 0) return orbis_kernel_error_einval;
    const auto state = find_semaphore(handle);
    if (!state) return orbis_kernel_error_esrch;
    {
        std::lock_guard lock(state->lock);
        if (state->deleted) return orbis_kernel_error_eacces;
        if (count > state->maximum - state->tokens) return orbis_kernel_error_einval;
        state->tokens += count;
        if (std::getenv("NBA16_TRACE_WAIT") != nullptr) {
            char message[256]{};
            const auto size = std::snprintf(message, sizeof(message),
                "SEMAPHORE signal handle=%d name='%s' count=%d tokens=%d waiters=%zu\n",
                handle, state->name.c_str(), count, state->tokens, state->waiters);
            if (size > 0) trace_wait_event(message, static_cast<std::size_t>(size));
        }
    }
    state->changed.notify_all();
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_kernel_cancel_sema(
    std::int32_t handle, std::int32_t set_count, std::int32_t* waiter_count) {
    const auto state = find_semaphore(handle);
    if (!state) return orbis_kernel_error_esrch;
    {
        std::lock_guard lock(state->lock);
        if (state->deleted) return orbis_kernel_error_eacces;
        if (set_count > state->maximum) return orbis_kernel_error_einval;
        if (waiter_count != nullptr) *waiter_count = static_cast<std::int32_t>(state->waiters);
        state->tokens = set_count < 0 ? state->initial : set_count;
        ++state->cancel_generation;
    }
    state->changed.notify_all();
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_kernel_delete_sema(std::int32_t handle) {
    std::shared_ptr<GuestSemaphore> state;
    {
        std::lock_guard lock(semaphore_registry_lock);
        const auto found = semaphore_registry.find(handle);
        if (found == semaphore_registry.end()) return orbis_kernel_error_esrch;
        state = found->second;
        semaphore_registry.erase(found);
    }
    {
        std::lock_guard lock(state->lock);
        state->deleted = true;
    }
    state->changed.notify_all();
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_init(void** slot, const void* attributes,
                                          const char* name) {
    (void)name;
    if (slot == nullptr) return guest_error_invalid;
    const auto type = attributes == nullptr ? 1 :
        static_cast<const GuestMutexAttributes*>(attributes)->type;
    if (type < 1 || type > 4) return guest_error_invalid;
    std::lock_guard registry_guard(mutex_registry_lock);
    if (*slot != nullptr) return guest_error_busy;
    auto state = std::shared_ptr<GuestMutex>(new (std::nothrow) GuestMutex());
    if (!state) return guest_error_busy;
    state->type = type;
    if (std::getenv("NBA16_TRACE_MUTEX") != nullptr) {
        std::fprintf(stderr, "mutex init slot=%p attributes=%p type=%d\n",
                     static_cast<void*>(slot), attributes, type);
    }
    void* handle = state.get();
    mutex_registry.emplace(handle, std::move(state));
    *slot = handle;
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_attribute_init(void** output) {
    if (output == nullptr) return guest_error_invalid;
    auto* attributes = new (std::nothrow) GuestMutexAttributes();
    if (attributes == nullptr) return guest_error_again;
    *output = attributes;
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_attribute_set_type(void** output, int type) {
    if (output == nullptr || *output == nullptr || type < 1 || type > 4) {
        return guest_error_invalid;
    }
    static_cast<GuestMutexAttributes*>(*output)->type = type;
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_attribute_set_pshared(void** output, int process_shared) {
    if (output == nullptr || *output == nullptr ||
        (process_shared != 0 && process_shared != 1)) {
        return guest_error_invalid;
    }
    static_cast<GuestMutexAttributes*>(*output)->process_shared = process_shared;
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_attribute_destroy(void** output) {
    if (output == nullptr || *output == nullptr) return guest_error_invalid;
    delete static_cast<GuestMutexAttributes*>(*output);
    *output = nullptr;
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_lock(void** slot) {
    if (slot == nullptr) return guest_error_invalid;
    static std::atomic<std::uint32_t> trace_count{};
    const bool trace = std::getenv("NBA16_TRACE_MUTEX") != nullptr &&
        trace_count.fetch_add(1, std::memory_order_relaxed) < 128;
    if (trace) {
        std::fprintf(stderr, "mutex lock entry slot=%p caller=%p\n", static_cast<void*>(slot),
            __builtin_return_address(0));
    }
    if (reinterpret_cast<std::uintptr_t>(slot) < 0x10000U) {
        std::fprintf(stderr, "mutex lock rejected low slot=%p caller=%p\n",
            static_cast<void*>(slot), __builtin_return_address(0));
        return guest_error_invalid;
    }
    auto registered = find_mutex(*slot);
    if (!registered) registered = static_guest_mutex(slot, true);
    auto* state = registered.get();
    if (!state) return guest_error_invalid;
    {
        std::lock_guard owner_guard(state->owner_lock);
        if (state->owner == std::this_thread::get_id()) {
            if (state->type == 2) {
                if (state->recursion_depth == UINT32_MAX) return guest_error_again;
                ++state->recursion_depth;
                return 0;
            }
            if (state->type == 1 || state->type == 4) return guest_error_deadlock;
        }
    }
    if (trace) {
        std::lock_guard owner_guard(state->owner_lock);
        std::fprintf(stderr, "mutex lock attempt slot=%p handle=%p type=%d caller=%p thread=%zu owner=%zu\n",
                     static_cast<void*>(slot), *slot, state->type, __builtin_return_address(0),
                     std::hash<std::thread::id>{}(std::this_thread::get_id()),
                     std::hash<std::thread::id>{}(state->owner));
    }
#ifdef _WIN32
    const auto lock_caller = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));
    if (std::getenv("NBA16_TRACE_MUTEX_STACK") != nullptr &&
        (lock_caller & 0xffffU) == 0xf4b9U) {
        static std::atomic<std::uint32_t> target_caller_count{};
        const auto sample = target_caller_count.fetch_add(1, std::memory_order_relaxed);
        if (sample < 2 || (sample >= 128 && sample <= 384 && sample % 128 == 0)) {
            ULONG_PTR stack_low{};
            ULONG_PTR stack_high{};
            GetCurrentThreadStackLimits(&stack_low, &stack_high);
            std::uintptr_t stack_marker{};
            const auto stack_begin = (reinterpret_cast<std::uintptr_t>(&stack_marker) + 7U) & ~7ULL;
            const auto stack_end = std::min<std::uintptr_t>(stack_high, stack_begin + 0x3000U);
            std::array<std::uintptr_t, 32> words{};
            std::size_t emitted{};
            std::fprintf(stderr, "mutex stack sample=%u caller=%p range=%p..%p\n",
                         sample,
                         __builtin_return_address(0), reinterpret_cast<void*>(stack_low),
                         reinterpret_cast<void*>(stack_high));
            for (auto address = stack_begin; address + sizeof(words) <= stack_end && emitted < 16;
                 address += sizeof(words)) {
                SIZE_T bytes_read{};
                if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                                      words.data(), sizeof(words), &bytes_read) == 0 ||
                    bytes_read != sizeof(words)) continue;
                for (std::size_t index = 0; index < words.size() && emitted < 16; ++index) {
                    const auto value = words[index];
                    if (value < 0x10000000000ULL || value >= 0x500000000000ULL) continue;
                    std::fprintf(stderr, "  stack+0x%llx=%p\n",
                                 static_cast<unsigned long long>(address + index * sizeof(std::uintptr_t) - stack_begin),
                                 reinterpret_cast<void*>(value));
                    ++emitted;
                }
            }
        }
    }
#endif
    try {
        if (!state->native.try_lock()) {
            if (std::getenv("NBA16_TRACE_MUTEX_CONTENTION") != nullptr) {
                std::lock_guard owner_guard(state->owner_lock);
#ifdef _WIN32
                const auto thread_id = GetCurrentThreadId();
#else
                const auto thread_id = 0U;
#endif
                std::fprintf(stderr,
                    "mutex contention slot=%p handle=%p caller=%p thread_id=%lu "
                    "owner_id=%u owner_caller=%p owner=%zu\n",
                    static_cast<void*>(slot), *slot,
                    __builtin_return_address(0), thread_id, state->owner_thread_id,
                    reinterpret_cast<void*>(state->owner_caller),
                    std::hash<std::thread::id>{}(state->owner));
            }
            state->native.lock();
        }
    } catch (...) {
        return guest_error_invalid;
    }
    if (state->destroyed.load(std::memory_order_acquire)) {
        state->native.unlock();
        return guest_error_invalid;
    }
    {
        std::lock_guard owner_guard(state->owner_lock);
        state->owner = std::this_thread::get_id();
        state->owner_caller = reinterpret_cast<std::uintptr_t>(
            __builtin_return_address(0));
        state->recursion_depth = 0;
#ifdef _WIN32
        state->owner_thread_id = GetCurrentThreadId();
#else
        state->owner_thread_id = 0;
#endif
    }
    if (trace) std::fprintf(stderr, "mutex lock acquired slot=%p thread=%zu\n",
        static_cast<void*>(slot), std::hash<std::thread::id>{}(std::this_thread::get_id()));
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_trylock(void** slot) {
    if (slot == nullptr) return guest_error_invalid;
    auto registered = find_mutex(*slot);
    if (!registered) registered = static_guest_mutex(slot, true);
    auto* state = registered.get();
    if (!state) return guest_error_invalid;
    {
        std::lock_guard owner_guard(state->owner_lock);
        if (state->owner == std::this_thread::get_id()) {
            if (state->type == 2) {
                if (state->recursion_depth == UINT32_MAX) return guest_error_again;
                ++state->recursion_depth;
                return 0;
            }
            return guest_error_busy;
        }
    }
    if (!state->native.try_lock()) return guest_error_busy;
    if (state->destroyed.load(std::memory_order_acquire)) {
        state->native.unlock();
        return guest_error_invalid;
    }
    {
        std::lock_guard owner_guard(state->owner_lock);
        state->owner = std::this_thread::get_id();
        state->owner_caller = reinterpret_cast<std::uintptr_t>(
            __builtin_return_address(0));
        state->recursion_depth = 0;
#ifdef _WIN32
        state->owner_thread_id = GetCurrentThreadId();
#else
        state->owner_thread_id = 0;
#endif
    }
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_unlock(void** slot) {
    if (slot == nullptr) return guest_error_invalid;
    static std::atomic<std::uint32_t> trace_count{};
    auto registered = find_mutex(*slot);
    if (!registered) registered = static_guest_mutex(slot, false);
    auto* state = registered.get();
    if (!state) return guest_error_invalid;
    const bool trace = std::getenv("NBA16_TRACE_MUTEX") != nullptr &&
        trace_count.fetch_add(1, std::memory_order_relaxed) < 256;
    if (trace) std::fprintf(stderr, "mutex unlock slot=%p handle=%p caller=%p thread=%zu\n",
        static_cast<void*>(slot), *slot,
        __builtin_return_address(0),
        std::hash<std::thread::id>{}(std::this_thread::get_id()));
    {
        std::lock_guard owner_guard(state->owner_lock);
        if (state->owner != std::this_thread::get_id()) return guest_error_permission;
        if (state->type == 2 && state->recursion_depth > 0) {
            --state->recursion_depth;
            return 0;
        }
        state->owner = {};
        state->owner_caller = 0;
        state->owner_thread_id = 0;
    }
    state->native.unlock();
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_mutex_destroy(void** slot) {
    if (slot == nullptr) return guest_error_invalid;
    if (auto state = static_guest_mutex(slot, false)) {
        if (!state->native.try_lock()) return guest_error_busy;
        {
            std::lock_guard registry_guard(mutex_registry_lock);
            const auto found = static_guest_mutexes.find(slot);
            if (found == static_guest_mutexes.end() || found->second != state) {
                state->native.unlock();
                return guest_error_invalid;
            }
            static_guest_mutexes.erase(found);
            state->destroyed.store(true, std::memory_order_release);
        }
        state->native.unlock();
        return 0;
    }
    const auto handle = *slot;
    auto state = find_mutex(handle);
    if (!state) return guest_error_invalid;
    if (!state->native.try_lock()) return guest_error_busy;
    {
        std::lock_guard registry_guard(mutex_registry_lock);
        const auto found = mutex_registry.find(handle);
        if (found == mutex_registry.end() || found->second != state) {
            state->native.unlock();
            return guest_error_invalid;
        }
        mutex_registry.erase(found);
        *slot = nullptr;
        state->destroyed.store(true, std::memory_order_release);
    }
    state->native.unlock();
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_condition_init(void** slot, const void* attributes,
                                              const char* name) {
    (void)attributes;
    (void)name;
    if (slot == nullptr) return guest_error_invalid;
    std::lock_guard registry_guard(condition_registry_lock);
    if (*slot != nullptr) return guest_error_busy;
    auto state = std::shared_ptr<GuestCondition>(new (std::nothrow) GuestCondition());
    if (!state) return guest_error_busy;
    void* handle = state.get();
    condition_registry.emplace(handle, std::move(state));
    *slot = handle;
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_condition_signal(void** slot) {
    if (slot == nullptr) return guest_error_invalid;
    const auto state = find_condition(*slot);
    if (!state || state->destroyed.load(std::memory_order_acquire)) {
        return guest_error_invalid;
    }
    state->native.notify_one();
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_condition_broadcast(void** slot) {
    if (slot == nullptr) return guest_error_invalid;
    const auto state = find_condition(*slot);
    if (!state || state->destroyed.load(std::memory_order_acquire)) {
        return guest_error_invalid;
    }
    state->native.notify_all();
    return 0;
}

int guest_condition_wait_impl(void** condition_slot, void** mutex_slot,
                              std::uint64_t timeout_microseconds, bool timed) {
    if (condition_slot == nullptr || mutex_slot == nullptr) return guest_error_invalid;
    const auto condition = find_condition(*condition_slot);
    auto mutex = find_mutex(*mutex_slot);
    if (!mutex) mutex = static_guest_mutex(mutex_slot, false);
    if (!condition || !mutex || condition->destroyed.load(std::memory_order_acquire)) {
        return guest_error_invalid;
    }
    {
        std::lock_guard owner_guard(mutex->owner_lock);
        if (mutex->owner != std::this_thread::get_id()) return guest_error_permission;
    }
    condition->waiters.fetch_add(1, std::memory_order_acq_rel);
    if (condition->destroyed.load(std::memory_order_acquire)) {
        condition->waiters.fetch_sub(1, std::memory_order_acq_rel);
        return guest_error_invalid;
    }

    int result = 0;
    trace_wait_event("WAIT condition blocked\n", 23);
    std::unique_lock<std::mutex> lock(mutex->native, std::adopt_lock);
    {
        std::lock_guard owner_guard(mutex->owner_lock);
        mutex->owner = {};
    }
    try {
        if (timed) {
            const auto status = condition->native.wait_for(
                lock, std::chrono::microseconds(timeout_microseconds));
            if (status == std::cv_status::timeout) result = guest_error_timed_out;
        } else {
            condition->native.wait(lock);
        }
    } catch (...) {
        result = guest_error_invalid;
    }
    if (lock.owns_lock()) {
        {
            std::lock_guard owner_guard(mutex->owner_lock);
            mutex->owner = std::this_thread::get_id();
        }
        lock.release();
    } else {
        result = guest_error_invalid;
    }
    condition->waiters.fetch_sub(1, std::memory_order_acq_rel);
    trace_wait_event("WAIT condition released\n", 24);
    return result;
}

int NBA16_GUEST_SYSV_ABI guest_condition_wait(void** condition, void** mutex) {
    return guest_condition_wait_impl(condition, mutex, 0, false);
}

int NBA16_GUEST_SYSV_ABI guest_condition_timed_wait(
    void** condition, void** mutex, std::uint64_t timeout_microseconds) {
    return guest_condition_wait_impl(condition, mutex, timeout_microseconds, true);
}

int NBA16_GUEST_SYSV_ABI guest_condition_destroy(void** slot) {
    if (slot == nullptr) return guest_error_invalid;
    const auto handle = *slot;
    const auto state = find_condition(handle);
    if (!state) return guest_error_invalid;
    std::lock_guard registry_guard(condition_registry_lock);
    const auto found = condition_registry.find(handle);
    if (found == condition_registry.end() || found->second != state) {
        return guest_error_invalid;
    }
    if (state->waiters.load(std::memory_order_acquire) != 0) return guest_error_busy;
    state->destroyed.store(true, std::memory_order_release);
    condition_registry.erase(found);
    *slot = nullptr;
    return 0;
}

int* NBA16_GUEST_SYSV_ABI guest_error_location() {
    return &guest_errno;
}

void* NBA16_GUEST_SYSV_ABI guest_get_process_parameter() {
    const auto* value = guest_process_parameter.load(std::memory_order_acquire);
    std::fprintf(stderr, "guest procparam import -> %p\n", const_cast<void*>(value));
    return const_cast<void*>(value);
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_get_pid() {
    // Keep a stable Orbis application PID for process-scoped sysctl queries.
    // The known-good NBA Live 16 runtime used 1000 for the guest process.
    if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr)
        std::fprintf(stderr, "GETPID guest pid=1000 caller=%p\n",
            __builtin_return_address(0));
    return 1000;
}

[[noreturn]] void NBA16_GUEST_SYSV_ABI guest_stack_check_failure() {
    std::abort();
}

int NBA16_GUEST_SYSV_ABI guest_sysctl(const std::int32_t* name,
                                     std::uint32_t name_length,
                                     void* old_value,
                                     std::uint64_t* old_length,
                                     const void* new_value,
                                     std::uint64_t new_length) {
    nba16_guest_sysctl_actual_caller = reinterpret_cast<std::uintptr_t>(
        __builtin_return_address(0));
    sysctl_calls.fetch_add(1, std::memory_order_relaxed);
    if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr) {
        std::fprintf(stderr, "SYSCTL call caller=0x%llx mib-len=%u mib=%d,%d,%d,%d old=%p oldlenp=%p new=%p newlen=%llu\n",
            static_cast<unsigned long long>(nba16_guest_sysctl_actual_caller),
            name_length, name != nullptr && name_length > 0 ? name[0] : -1,
            name != nullptr && name_length > 1 ? name[1] : -1,
            name != nullptr && name_length > 2 ? name[2] : -1,
            name != nullptr && name_length > 3 ? name[3] : -1,
            old_value, static_cast<void*>(old_length), new_value,
            static_cast<unsigned long long>(new_length));
        if (name != nullptr && name_length >= 3 && name[0] == 1 &&
            name[1] == 14 && name[2] == 42 && new_value != nullptr &&
            new_length == sizeof(std::uint32_t)) {
            std::uint32_t input{};
            std::memcpy(&input, new_value, sizeof(input));
            std::fprintf(stderr, "SYSCTL kern.proc selector=42 input-u32=%u (0x%x)\n",
                input, input);
        }
    }
    const std::uint32_t mib_count = name_length == 16 ? 4 : name_length;
    if (name != nullptr && name_length > 1 && name[0] == 1 && name[1] == 33) {
        usrstack_sysctl_calls.fetch_add(1, std::memory_order_relaxed);
        usrstack_sysctl_trace[0].store(static_cast<std::uint32_t>(name[0]), std::memory_order_relaxed);
        usrstack_sysctl_trace[1].store(static_cast<std::uint32_t>(name[1]), std::memory_order_relaxed);
        usrstack_sysctl_trace[2].store(name_length, std::memory_order_relaxed);
        usrstack_sysctl_trace[3].store(reinterpret_cast<std::uintptr_t>(old_value), std::memory_order_relaxed);
        usrstack_sysctl_trace[4].store(reinterpret_cast<std::uintptr_t>(old_length), std::memory_order_relaxed);
        usrstack_sysctl_trace[5].store(old_length != nullptr ? *old_length : 0, std::memory_order_relaxed);
        usrstack_sysctl_trace[6].store(reinterpret_cast<std::uintptr_t>(new_value), std::memory_order_relaxed);
        usrstack_sysctl_trace[7].store(new_length, std::memory_order_relaxed);
    }
    last_sysctl_trace[0].store(name != nullptr ? static_cast<std::uint32_t>(name[0]) : 0,
                               std::memory_order_relaxed);
    last_sysctl_trace[1].store(name != nullptr && name_length > 1
        ? static_cast<std::uint32_t>(name[1]) : 0, std::memory_order_relaxed);
    last_sysctl_trace[2].store(name_length, std::memory_order_relaxed);
    last_sysctl_trace[3].store(reinterpret_cast<std::uintptr_t>(old_value), std::memory_order_relaxed);
    last_sysctl_trace[4].store(reinterpret_cast<std::uintptr_t>(old_length), std::memory_order_relaxed);
    last_sysctl_trace[5].store(old_length != nullptr ? *old_length : 0, std::memory_order_relaxed);
    last_sysctl_trace[6].store(reinterpret_cast<std::uintptr_t>(new_value), std::memory_order_relaxed);
    last_sysctl_trace[7].store(new_length, std::memory_order_relaxed);
    // The observed Orbis libkernel kern.proc.cwd helper passes its target PID
    // as the four-byte new value and requests no output. It uses the result only
    // to validate the process query; there is no directory value to copy back.
    // Accept this exact read-only probe without changing guest process state.
    if (name != nullptr && name_length == 3 && name[0] == 1 && name[1] == 14 &&
        name[2] == 42 && old_value == nullptr && old_length == nullptr &&
        new_value != nullptr && new_length == sizeof(std::uint32_t)) {
        std::uint32_t process_id{};
        std::memcpy(&process_id, new_value, sizeof(process_id));
        if (process_id == 0) {
            guest_errno = guest_error_invalid;
            return -1;
        }
        if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr &&
            sysctl_calls.load(std::memory_order_relaxed) <= 8) {
            std::fprintf(stderr,
                "SYSCTL kern.proc.cwd validation accepted pid=%u (no output requested)\n",
                process_id);
        }
        return 0;
    }
    if (name == nullptr || (mib_count != 2 && mib_count != 3 && mib_count != 4) || old_length == nullptr) {
        guest_errno = guest_error_invalid;
        return -1;
    }
    if (mib_count == 4 && (name[2] != 0 || name[3] != 0)) {
        guest_errno = guest_error_invalid;
        return -1;
    }
    if (name[0] == 0 && name[1] == 3) { // CTL_SYSCTL_NAME2OID
        if (new_value == nullptr || new_length == 0 || new_length > 128) {
            guest_errno = guest_error_invalid;
            return -1;
        }
        auto requested_name = std::string_view(static_cast<const char*>(new_value),
                                               static_cast<std::size_t>(new_length));
        if (!requested_name.empty() && requested_name.back() == '\0')
            requested_name.remove_suffix(1);
        std::array<std::int32_t, 2> oid{};
        const std::int32_t* oid_data = oid.data();
        std::size_t oid_size = sizeof(oid);
        if (requested_name == "kern.sched.cpusetsize") {
            oid = {1, 33};
        } else if (requested_name == "hw.pagesize") {
            oid = {6, 7};
        } else if (requested_name == "kern.smp.cpus") {
            // Synthetic leaf handled below; avoid assuming a firmware-specific dynamic OID.
            oid = {1, 0x4e424131};
        } else {
            if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr)
                std::fprintf(stderr, "SYSCTL name2oid unsupported name='%.*s'\n",
                    static_cast<int>(requested_name.size()), requested_name.data());
            guest_errno = 2;
            return -1;
        }
        if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr)
            std::fprintf(stderr, "SYSCTL name2oid name='%.*s' oid-count=%zu\n",
                static_cast<int>(requested_name.size()), requested_name.data(),
                oid_size / sizeof(std::int32_t));
        const auto supplied_size = *old_length;
        *old_length = oid_size;
        if (old_value == nullptr) return 0;
        if (supplied_size < oid_size) {
            guest_errno = 12;
            return -1;
        }
        std::memcpy(old_value, oid_data, oid_size);
        return 0;
    }
    if (name[0] == 1 && name[1] == 0x4e424131 && new_value == nullptr) {
        // `kern.smp.cpus` is a string sysctl (for example, "0-7"), not a
        // processor-count integer. Keep the name2oid shim's synthetic leaf
        // compatible with the working NBA Live 16 runtime.
        constexpr char online_cpus[] = "0-7";
        const auto supplied_size = *old_length;
        *old_length = sizeof(online_cpus);
        if (old_value == nullptr) return 0;
        if (supplied_size < sizeof(online_cpus)) {
            guest_errno = 12;
            return -1;
        }
        std::memcpy(old_value, online_cpus, sizeof(online_cpus));
        return 0;
    }
    if (new_value != nullptr) {
        guest_errno = guest_error_invalid;
        return -1;
    }
    if (name[0] == 6 && name[1] == 7) { // hw.pagesize
        constexpr std::uint32_t page_size = 16384;
        const auto supplied_size = *old_length;
        *old_length = sizeof(page_size);
        if (old_value == nullptr) return 0;
        if (supplied_size < sizeof(page_size)) {
            guest_errno = 12;
            return -1;
        }
        std::memcpy(old_value, &page_size, sizeof(page_size));
        return 0;
    }
    if (name[0] != 1 || name[1] != 33) {
        guest_errno = 2;
        return -1;
    }
    // KERN_CPUSETSIZE: one 64-bit CPU-affinity mask, reported as int32_t.
    // Match the established NBA LIVE 16 runtime contract. This node is not
    // the guest stack address; libkernel uses a separate internal stack query.
    constexpr std::int32_t cpu_set_size = sizeof(std::uint64_t);
    const auto supplied_size = *old_length;
    if (old_value != nullptr && supplied_size < sizeof(cpu_set_size)) {
        guest_errno = 12;
        return -1;
    }
    *old_length = sizeof(cpu_set_size);
    if (old_value != nullptr)
        std::memcpy(old_value, &cpu_set_size, sizeof(cpu_set_size));
    usrstack_sysctl_result.store(0, std::memory_order_relaxed);
    usrstack_sysctl_response_length.store(*old_length, std::memory_order_relaxed);
    usrstack_sysctl_response_value.store(static_cast<std::uint32_t>(cpu_set_size),
                                         std::memory_order_relaxed);
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_sysctlbyname(const char* name, void* old_value,
                                            std::uint64_t* old_length,
                                            const void* new_value,
                                            std::uint64_t new_length) {
    sysctlbyname_calls.fetch_add(1, std::memory_order_relaxed);
    if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr)
        std::fprintf(stderr, "SYSCTLBYNAME caller=0x%llx name=%s old=%p oldlenp=%p\n",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(
                __builtin_return_address(0))), name != nullptr ? name : "<null>",
            old_value, static_cast<void*>(old_length));
    if (name == nullptr) {
        guest_errno = guest_error_invalid;
        return -1;
    }
    std::array<std::int32_t, 3> mib{};
    std::uint32_t mib_length = 2;
    if (std::strcmp(name, "kern.sched.cpusetsize") == 0) {
        mib = {1, 33};
    } else if (std::strcmp(name, "kern.smp.cpus") == 0) {
        mib = {1, 0x4e424131};
    } else if (std::strcmp(name, "hw.pagesize") == 0) {
        mib = {6, 7};
    } else {
        guest_errno = 2;
        return -1;
    }
    return guest_sysctl(mib.data(), mib_length,
                        old_value, old_length, new_value, new_length);
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_cpuset_syscall(
    std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d,
    std::uint64_t e, std::uint64_t f) {
    // The game only configures worker affinity during bootstrap. The host
    // scheduler owns thread placement in this native runtime.
    cpuset_calls.fetch_add(1, std::memory_order_relaxed);
    if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr)
        std::fprintf(stderr, "CPUSET syscall args=%llx,%llx,%llx,%llx,%llx,%llx\n",
            static_cast<unsigned long long>(a), static_cast<unsigned long long>(b),
            static_cast<unsigned long long>(c), static_cast<unsigned long long>(d),
            static_cast<unsigned long long>(e), static_cast<unsigned long long>(f));
    return 0;
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_mmap_syscall(
    std::uint64_t requested_address, std::uint64_t requested_size,
    std::uint64_t protection, std::uint64_t flags,
    std::int64_t, std::uint64_t) {
    mmap_calls.fetch_add(1, std::memory_order_relaxed);
    const bool trace_mmap = std::getenv("NBA16_TRACE_MEMORY") != nullptr;
    if (trace_mmap) std::fprintf(stderr,
        "MEM mmap enter addr=0x%llx size=0x%llx prot=0x%llx flags=0x%llx\n",
        static_cast<unsigned long long>(requested_address),
        static_cast<unsigned long long>(requested_size),
        static_cast<unsigned long long>(protection),
        static_cast<unsigned long long>(flags));
    if (requested_size == 0 || requested_size > 0x40000000ULL) {
        guest_errno = guest_error_invalid;
        return -1;
    }
    constexpr std::uint64_t page_size = 16384;
    if (requested_size > UINT64_MAX - (page_size - 1)) {
        guest_errno = guest_error_invalid;
        return -1;
    }
    const auto size = (requested_size + page_size - 1) & ~(page_size - 1);
    const bool can_read = (protection & 1U) != 0;
    const bool can_write = (protection & 2U) != 0;
#ifdef _WIN32
    DWORD page_protection = PAGE_NOACCESS;
    const bool can_execute = (protection & 4U) != 0;
    if (can_execute) page_protection = can_write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    else if (can_write) page_protection = PAGE_READWRITE;
    else if (can_read) page_protection = PAGE_READONLY;

    constexpr std::uint64_t low_start = 0x0800000000ULL;
    constexpr std::uint64_t low_end = 0x1000000000ULL;
    const bool usable_hint = requested_address >= low_start && requested_address < low_end;
    void* result = nullptr;
    if (usable_hint) {
        result = VirtualAlloc(reinterpret_cast<void*>(static_cast<std::uintptr_t>(requested_address)),
            static_cast<SIZE_T>(size), MEM_RESERVE | MEM_COMMIT, page_protection);
        if (result != nullptr && (flags & 0x10U) != 0 &&
            reinterpret_cast<std::uintptr_t>(result) != requested_address) {
            VirtualFree(result, 0, MEM_RELEASE);
            result = nullptr;
        }
        if (result == nullptr && (flags & 0x10U) != 0) {
            guest_errno = guest_error_no_such_process;
            if (trace_mmap) std::fprintf(stderr,
                "MEM mmap fixed hint unavailable errno=%d\n", guest_errno);
            return -1;
        }
    }
    if (result == nullptr) {
        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);
        const auto granularity = static_cast<std::uint64_t>(system_info.dwAllocationGranularity);
        constexpr std::uint64_t low_start = 0x0800000000ULL;
        constexpr std::uint64_t low_end = 0x1000000000ULL;
        const auto start = usable_hint
            ? (requested_address + granularity - 1) & ~(granularity - 1)
            : low_start;
        for (auto address = start; address < low_end && size <= low_end - address;
             address += granularity) {
            result = VirtualAlloc(reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)),
                static_cast<SIZE_T>(size), MEM_RESERVE | MEM_COMMIT, page_protection);
            if (result != nullptr) break;
        }
    }
    // Stack and other flexible mappings may carry a preferred address outside
    // the PS4 low-address window. The hint is advisory unless MAP_FIXED is set;
    // let Windows choose a free host range when our guest window is exhausted.
    if (result == nullptr && (flags & 0x10U) == 0) {
        result = VirtualAlloc(nullptr, static_cast<SIZE_T>(size),
                              MEM_RESERVE | MEM_COMMIT, page_protection);
    }
    if (result == nullptr) {
        guest_errno = 12;
        if (trace_mmap) std::fprintf(stderr, "MEM mmap failed errno=%d\n", guest_errno);
        return -1;
    }
    if (auto* process = current_guest_process_context();
        process != nullptr && process->is_initialized()) {
        std::string registration_error;
        if (!process->memory().add_host_region(
                static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result)),
                static_cast<std::size_t>(size), registration_error,
                can_read || can_write, can_write)) {
#ifdef _WIN32
            VirtualFree(result, 0, MEM_RELEASE);
#else
            munmap(result, static_cast<std::size_t>(size));
#endif
            guest_errno = 12;
            if (trace_mmap) std::fprintf(stderr,
                "MEM mmap region registration failed addr=%p size=0x%llx detail='%s'\n",
                result, static_cast<unsigned long long>(size), registration_error.c_str());
            return -1;
        }
        (void)register_guest_query_region(
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result)),
            static_cast<std::size_t>(size), static_cast<std::uint32_t>(protection), "mmap");
    }
    if (trace_mmap) std::fprintf(stderr, "MEM mmap result=%p rounded=0x%llx\n", result,
        static_cast<unsigned long long>(size));
    return static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(result));
#else
    int native_protection = 0;
    if ((protection & 1U) != 0) native_protection |= PROT_READ;
    if ((protection & 2U) != 0) native_protection |= PROT_WRITE;
    if ((protection & 4U) != 0) native_protection |= PROT_EXEC;
    void* result = mmap(requested_address == 0 ? nullptr :
            reinterpret_cast<void*>(static_cast<std::uintptr_t>(requested_address)),
        static_cast<std::size_t>(size), native_protection, MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0);
    if (result == MAP_FAILED) {
        guest_errno = 12;
        return -1;
    }
    return static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(result));
#endif
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_map_named_flexible_memory(
    std::uint64_t* output_address, std::uint64_t size,
    std::int32_t protection, std::int32_t flags, const char*) {
    if (output_address == nullptr) {
        guest_errno = guest_error_invalid;
        return guest_error_invalid;
    }
    constexpr std::uint64_t primary_thread_tls_base = 0x881000000ULL;
    const auto mapped = guest_mmap_syscall(primary_thread_tls_base, size,
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(protection)),
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(flags)), -1, 0);
    if (mapped < 0) return static_cast<std::int32_t>(guest_errno);
    *output_address = static_cast<std::uint64_t>(mapped);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_kernel_mlock(
    const void* address, std::uint64_t size) {
    if (address == nullptr || size == 0 ||
        reinterpret_cast<std::uintptr_t>(address) > UINTPTR_MAX - size) {
        guest_errno = guest_error_invalid;
        return guest_error_invalid;
    }
#ifdef _WIN32
    // The runtime's guest mappings are already committed with VirtualAlloc.
    // PS4 mlock is a residency request; Windows controls residency through the
    // process working set, so validating the committed range is the portable
    // equivalent needed during libc's primary-thread bootstrap.
    auto cursor = reinterpret_cast<std::uintptr_t>(address);
    const auto end = cursor + static_cast<std::uintptr_t>(size);
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) == 0 ||
            info.State != MEM_COMMIT || (info.Protect & PAGE_NOACCESS) != 0) {
            guest_errno = guest_error_invalid;
            return guest_error_invalid;
        }
        const auto region_end = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
        if (region_end <= cursor) {
            guest_errno = guest_error_invalid;
            return guest_error_invalid;
        }
        cursor = region_end < end ? region_end : end;
    }
    return 0;
#else
    if (mlock(address, static_cast<std::size_t>(size)) == 0) return 0;
    guest_errno = errno;
    return guest_errno == 0 ? guest_error_invalid : guest_errno;
#endif
}

std::uint64_t NBA16_GUEST_SYSV_ABI guest_direct_memory_size() {
    const auto provider = current_direct_memory_provider();
    if (provider.get_size != nullptr) return provider.get_size(provider.context);
    return 5056ULL * 1024ULL * 1024ULL;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_direct_memory_type(
    std::uint64_t physical, std::int32_t* type_out,
    void** start_out, void** end_out) {
    const auto provider = current_direct_memory_provider();
    if (provider.get_type != nullptr)
        return provider.get_type(provider.context, physical, type_out, start_out, end_out);
    constexpr std::int32_t access = std::bit_cast<std::int32_t>(0x80020003U);
    std::lock_guard lock(direct_memory_lock);
    const auto found = std::find_if(direct_memory_blocks.begin(), direct_memory_blocks.end(),
        [physical](const auto& block) {
            return physical >= block.start && physical - block.start < block.size;
        });
    if (found == direct_memory_blocks.end()) return access;
    if (type_out != nullptr) *type_out = found->type;
    if (start_out != nullptr) *start_out = reinterpret_cast<void*>(found->start);
    if (end_out != nullptr) *end_out = reinterpret_cast<void*>(found->start + found->size);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_allocate_direct_memory(
    std::int64_t low, std::int64_t high, std::uint64_t size,
    std::uint64_t alignment, std::int32_t type, std::int64_t* physical_out) {
    const auto provider = current_direct_memory_provider();
    if (provider.allocate != nullptr)
        return provider.allocate(provider.context, low, high, size, alignment, type, physical_out);
    constexpr std::uint64_t page = 16384;
    constexpr std::uint64_t pool = 5056ULL * 1024ULL * 1024ULL;
    constexpr std::int32_t invalid = std::bit_cast<std::int32_t>(0x80020016U);
    constexpr std::int32_t no_space = std::bit_cast<std::int32_t>(0x80020023U);
    if (physical_out == nullptr || low < 0 || high < 0 || size == 0 ||
        size % page != 0 || type < 0 || type > 10) return invalid;
    if (alignment == 0) alignment = page;
    if (alignment < page || alignment > pool || (alignment & (alignment - 1)) != 0)
        return invalid;
    const auto begin = static_cast<std::uint64_t>(low);
    const auto end = std::min<std::uint64_t>(static_cast<std::uint64_t>(high), pool);
    if (begin >= end || size > end - begin) return no_space;
    std::lock_guard lock(direct_memory_lock);
    auto candidate = (begin + alignment - 1) & ~(alignment - 1);
    for (;;) {
        if (candidate > end || size > end - candidate) return no_space;
        auto conflict = std::find_if(direct_memory_blocks.begin(), direct_memory_blocks.end(),
            [&](const auto& block) {
                return candidate < block.start + block.size &&
                    block.start < candidate + size;
            });
        if (conflict == direct_memory_blocks.end()) break;
        if (conflict->start > UINT64_MAX - conflict->size) return no_space;
        candidate = (conflict->start + conflict->size + alignment - 1) & ~(alignment - 1);
    }
    direct_memory_blocks.push_back({candidate, size, type});
    *physical_out = static_cast<std::int64_t>(candidate);
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
        std::fprintf(stderr, "MEM direct-allocate offset=0x%llx size=0x%llx type=%d\n",
            static_cast<unsigned long long>(candidate),
            static_cast<unsigned long long>(size), type);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_available_direct_memory(
    std::int64_t low, std::int64_t high, std::uint64_t alignment,
    std::int64_t* physical_out, std::uint64_t* size_out) {
    const auto provider = current_direct_memory_provider();
    if (provider.available != nullptr)
        return provider.available(provider.context, low, high, alignment, physical_out, size_out);
    constexpr std::uint64_t page = 16384;
    constexpr std::uint64_t pool = 5056ULL * 1024ULL * 1024ULL;
    constexpr std::int32_t invalid = std::bit_cast<std::int32_t>(0x80020016U);
    constexpr std::int32_t no_space = std::bit_cast<std::int32_t>(0x80020023U);
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
        std::fprintf(stderr, "MEM direct-available-entry low=0x%llx high=0x%llx align=0x%llx phys_out=%p size_out=%p\n",
            static_cast<unsigned long long>(low), static_cast<unsigned long long>(high),
            static_cast<unsigned long long>(alignment), static_cast<void*>(physical_out),
            static_cast<void*>(size_out));
    if (low < 0 || high < 0 || physical_out == nullptr || size_out == nullptr)
        return invalid;
    if (alignment == 0) alignment = page;
    if (alignment < page || (alignment & (alignment - 1)) != 0) return invalid;
    const auto begin = static_cast<std::uint64_t>(low);
    const auto end = std::min<std::uint64_t>(static_cast<std::uint64_t>(high), pool);
    if (begin >= end) return no_space;
    std::lock_guard lock(direct_memory_lock);
    auto cursor = (begin + alignment - 1) & ~(alignment - 1);
    std::uint64_t best_begin{};
    std::uint64_t best_size{};
    while (cursor < end) {
        auto next = end;
        auto resume = end;
        for (const auto& block : direct_memory_blocks) {
            if (block.start + block.size <= cursor) continue;
            if (block.start <= cursor) {
                next = cursor;
                resume = block.start + block.size;
                break;
            }
            if (block.start < next) {
                next = block.start;
                resume = block.start + block.size;
            }
        }
        const auto aligned = (cursor + alignment - 1) & ~(alignment - 1);
        if (next > aligned && next - aligned > best_size) {
            best_begin = aligned;
            best_size = next - aligned;
        }
        if (resume <= cursor) break;
        cursor = resume;
    }
    if (best_size == 0) return no_space;
    *physical_out = static_cast<std::int64_t>(best_begin);
    *size_out = best_size;
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
        std::fprintf(stderr, "MEM direct-available-result phys=0x%llx size=0x%llx\n",
            static_cast<unsigned long long>(best_begin), static_cast<unsigned long long>(best_size));
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_map_direct_memory(
    void** output_address, std::uint64_t requested_size, std::int32_t protection,
    std::int32_t flags, std::int64_t physical, std::uint64_t alignment) {
    const auto provider = current_direct_memory_provider();
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
        std::fprintf(stderr,
            "MEM direct-map-entry out=%p requested=%p size=0x%llx prot=0x%x flags=0x%x "
            "physical=0x%llx align=0x%llx caller=%p\n",
            static_cast<void*>(output_address),
            output_address == nullptr ? nullptr : *output_address,
            static_cast<unsigned long long>(requested_size), protection, flags,
            static_cast<unsigned long long>(physical),
            static_cast<unsigned long long>(alignment), __builtin_return_address(0));
    constexpr std::uint64_t page = 16384;
    constexpr std::int32_t invalid = std::bit_cast<std::int32_t>(0x80020016U);
    constexpr std::int32_t no_memory = std::bit_cast<std::int32_t>(0x8002000cU);
    if (output_address == nullptr || physical < 0 || requested_size == 0 ||
        requested_size > UINT64_MAX - (page - 1) || (protection & ~0x37) != 0)
        return invalid;
    const auto size = (requested_size + page - 1) & ~(page - 1);
    if ((static_cast<std::uint64_t>(physical) % page) != 0 ||
        (alignment != 0 && (alignment < page || (alignment & (alignment - 1)) != 0)))
        return invalid;
    const bool can_read = (protection & 0x11) != 0;
    const bool can_write = (protection & 0x22) != 0;
    if (provider.map != nullptr) {
        if (provider.unmap == nullptr || provider.release == nullptr)
            return invalid;
        const auto result = provider.map(provider.context, output_address, size, protection,
                                         flags, physical, alignment);
        if (result != 0) return result;
        if (*output_address == nullptr) return no_memory;
        const auto address = reinterpret_cast<std::uintptr_t>(*output_address);
        if (auto* process = current_guest_process_context();
            process != nullptr && process->is_initialized()) {
            std::string registration_error;
            if (!process->memory().add_host_region(address, static_cast<std::size_t>(size),
                    registration_error, can_read || can_write, can_write)) {
                (void)provider.unmap(provider.context, address, size);
                if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
                    std::fprintf(stderr,
                        "MEM provider-map registration failed addr=%p size=0x%llx detail='%s'\n",
                        *output_address, static_cast<unsigned long long>(size),
                        registration_error.c_str());
                return no_memory;
            }
        }
        {
            std::lock_guard lock(direct_memory_lock);
            direct_memory_mappings.push_back({address, size,
                static_cast<std::uint64_t>(physical), true});
        }
        (void)register_guest_query_region(address, size,
            static_cast<std::uint32_t>(protection), "direct memory");
        if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
            std::fprintf(stderr,
                "MEM provider-map addr=%p size=0x%llx physical=0x%llx flags=0x%x\n",
                *output_address, static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(physical), flags);
        return 0;
    }
#ifdef _WIN32
    const bool can_execute = (protection & 4) != 0;
    const auto requested = reinterpret_cast<std::uintptr_t>(*output_address);
    std::uintptr_t address = requested;
    {
    std::lock_guard lock(direct_memory_lock);
    const auto physical_begin = static_cast<std::uint64_t>(physical);
    if (physical_begin > direct_memory_pool_size || size > direct_memory_pool_size - physical_begin) {
        if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
            std::fprintf(stderr, "MEM direct-map-rejected physical=0x%llx size=0x%llx reason=pool-range\n",
                static_cast<unsigned long long>(physical_begin), static_cast<unsigned long long>(size));
        return invalid;
    }
    const auto section = get_direct_memory_section();
    if (section == nullptr) {
        if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
            std::fprintf(stderr, "MEM direct-section-create-failed error=%lu size=0x%llx\n",
                GetLastError(), static_cast<unsigned long long>(direct_memory_pool_size));
        return no_memory;
    }
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const auto allocation_granularity = static_cast<std::uintptr_t>(
        std::max<DWORD>(system_info.dwAllocationGranularity, static_cast<DWORD>(page)));
    const auto address_alignment = static_cast<std::uintptr_t>(
        std::max<std::uint64_t>(alignment == 0 ? page : alignment, allocation_granularity));
    DWORD last_error{};
    std::uintptr_t first_attempt{};
    for (unsigned attempt = 0; attempt < 256; ++attempt) {
        if (address == 0) {
            const auto next = static_cast<std::uintptr_t>(next_direct_memory_address);
            if (next > UINTPTR_MAX - (address_alignment - 1)) break;
            address = (next + address_alignment - 1) & ~(address_alignment - 1);
        }
        if (attempt == 0) first_attempt = address;
        const DWORD access = (can_read ? FILE_MAP_READ : 0U) |
            (can_write ? FILE_MAP_WRITE : 0U) |
            (can_execute ? FILE_MAP_EXECUTE : 0U);
        void* mapped = MapViewOfFileEx(section, access,
            static_cast<DWORD>(physical_begin >> 32U),
            static_cast<DWORD>(physical_begin), static_cast<SIZE_T>(size),
            reinterpret_cast<void*>(address));
        if (mapped != nullptr && reinterpret_cast<std::uintptr_t>(mapped) == address) {
            direct_memory_mappings.push_back({address, size, physical_begin, false});
            if (requested == 0 && address >= next_direct_memory_address &&
                size <= UINT64_MAX - address)
                next_direct_memory_address = address + size;
            *output_address = mapped;
            break;
        }
        last_error = GetLastError();
        if (mapped != nullptr) UnmapViewOfFile(mapped);
        if (requested != 0 || (flags & 0x10) != 0) return no_memory;
        if (address > UINTPTR_MAX - address_alignment) break;
        address += address_alignment;
    }
    if (address == 0 || std::none_of(direct_memory_mappings.begin(), direct_memory_mappings.end(),
            [&](const auto& mapping) { return mapping.physical == physical_begin && mapping.size == size &&
                mapping.address == address; })) {
        if (std::getenv("NBA16_TRACE_MEMORY") != nullptr) {
            MEMORY_BASIC_INFORMATION mbi{};
            const auto queried = VirtualQuery(reinterpret_cast<const void*>(first_attempt),
                &mbi, sizeof(mbi));
            std::fprintf(stderr,
                "MEM direct-map-failed first=0x%llx last=0x%llx winerr=%lu "
                "query=%d state=0x%lx type=0x%lx base=%p span=0x%llx\n",
                static_cast<unsigned long long>(first_attempt),
                static_cast<unsigned long long>(address), last_error, queried != 0,
                queried ? mbi.State : 0, queried ? mbi.Type : 0,
                queried ? mbi.AllocationBase : nullptr,
                static_cast<unsigned long long>(queried ? mbi.RegionSize : 0));
        }
        return no_memory;
    }
    }
#else
    {
        std::lock_guard lock(direct_memory_lock);
        const auto allocated = std::any_of(direct_memory_blocks.begin(),
            direct_memory_blocks.end(), [&](const auto& block) {
                return static_cast<std::uint64_t>(physical) >= block.start &&
                    static_cast<std::uint64_t>(physical) - block.start <= block.size &&
                    size <= block.size - (static_cast<std::uint64_t>(physical) - block.start);
            });
        if (!allocated) return invalid;
    }
    int native_protection = 0;
    if (protection & 0x11) native_protection |= PROT_READ;
    if (protection & 0x22) native_protection |= PROT_WRITE;
    if (protection & 4) native_protection |= PROT_EXEC;
    void* mapped = mmap(*output_address, static_cast<std::size_t>(size), native_protection,
        MAP_PRIVATE | MAP_ANONYMOUS | ((*output_address != nullptr || (flags & 0x10) != 0)
            ? MAP_FIXED : 0), -1, 0);
    if (mapped == MAP_FAILED) return no_memory;
    std::lock_guard lock(direct_memory_lock);
    const auto address = reinterpret_cast<std::uintptr_t>(mapped);
    direct_memory_mappings.push_back({address, size, static_cast<std::uint64_t>(physical), false});
    *output_address = mapped;
#endif
    if (auto* process = current_guest_process_context();
        process != nullptr && process->is_initialized()) {
        std::string registration_error;
        const auto guest_address = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(*output_address));
        if (!process->memory().add_host_region(guest_address,
                static_cast<std::size_t>(size), registration_error,
                can_read || can_write, can_write)) {
            if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
                std::fprintf(stderr,
                    "MEM direct-map memory registration failed addr=%p size=0x%llx detail='%s'\n",
                    *output_address, static_cast<unsigned long long>(size),
                    registration_error.c_str());
            return no_memory;
        }
    }
    (void)register_guest_query_region(reinterpret_cast<std::uintptr_t>(*output_address),
        size, static_cast<std::uint32_t>(protection), "direct memory");
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
        std::fprintf(stderr, "MEM direct-map addr=%p size=0x%llx physical=0x%llx flags=0x%x\n",
            *output_address, static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(physical), flags);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_release_direct_memory(
    std::int64_t physical, std::uint64_t size) {
    const auto provider = current_direct_memory_provider();
    constexpr std::uint64_t page = 16384;
    constexpr std::int32_t invalid = std::bit_cast<std::int32_t>(0x80020016U);
    if (physical < 0 || static_cast<std::uint64_t>(physical) % page != 0 || size % page != 0)
        return invalid;
    if (provider.release != nullptr) {
        if (provider.unmap == nullptr || size > UINT64_MAX - static_cast<std::uint64_t>(physical))
            return invalid;
        const auto start = static_cast<std::uint64_t>(physical);
        const auto end = start + size;
        std::vector<DirectMemoryMapping> mappings;
        {
            std::lock_guard lock(direct_memory_lock);
            for (const auto& mapping : direct_memory_mappings) {
                if (mapping.provider_owned && mapping.physical < end &&
                    start < mapping.physical + mapping.size)
                    mappings.push_back(mapping);
            }
        }
        for (const auto& mapping : mappings) {
            const auto result = provider.unmap(provider.context, mapping.address, mapping.size);
            if (result != 0) return result;
            if (auto* process = current_guest_process_context(); process != nullptr)
                process->memory().remove_host_region(mapping.address,
                    static_cast<std::size_t>(mapping.size));
            unregister_guest_query_region(mapping.address, mapping.size);
            std::lock_guard lock(direct_memory_lock);
            std::erase_if(direct_memory_mappings, [&](const auto& current) {
                return current.provider_owned && current.address == mapping.address &&
                    current.physical == mapping.physical;
            });
        }
        return provider.release(provider.context, physical, size);
    }
    std::lock_guard lock(direct_memory_lock);
    const auto start = static_cast<std::uint64_t>(physical);
    const auto end = start + size;
    for (auto it = direct_memory_mappings.begin(); it != direct_memory_mappings.end();) {
        if (it->physical < end && start < it->physical + it->size) {
            if (auto* process = current_guest_process_context(); process != nullptr)
                process->memory().remove_host_region(it->address,
                    static_cast<std::size_t>(it->size));
            unregister_guest_query_region(it->address, it->size);
#ifdef _WIN32
            UnmapViewOfFile(reinterpret_cast<void*>(it->address));
#else
            munmap(reinterpret_cast<void*>(it->address), static_cast<std::size_t>(it->size));
#endif
            it = direct_memory_mappings.erase(it);
        } else ++it;
    }
    for (auto it = direct_memory_blocks.begin(); it != direct_memory_blocks.end();) {
        if (it->start < end && start < it->start + it->size) it = direct_memory_blocks.erase(it);
        else ++it;
    }
    return 0;
}

void guest_mspace_set_default_slot_impl(void** slot) noexcept {
    std::lock_guard lock(guest_mspace_lock);
    guest_mspace_default_slot = slot;
    if (slot != nullptr && *slot == nullptr && !guest_mspaces.empty())
        *slot = reinterpret_cast<void*>(guest_mspaces.begin()->first);
}

void* NBA16_GUEST_SYSV_ABI guest_mspace_create(
    const char*, void* base, std::size_t size, std::uint32_t flags) {
    if (base == nullptr || size <= 0x580 || flags > 0xf) return nullptr;
    const auto address = reinterpret_cast<std::uintptr_t>(base);
    const auto prefix = (16 - (address & 15U)) & 15U;
    if (prefix >= size) return nullptr;
    GuestMspace arena{};
    arena.base = address;
    arena.size = size;
    arena.free_ranges.emplace_back(prefix, (size - prefix) & ~std::size_t{15});
    std::lock_guard lock(guest_mspace_lock);
    if (!guest_mspaces.emplace(address, std::move(arena)).second) return nullptr;
    if (guest_mspace_default_slot != nullptr && *guest_mspace_default_slot == nullptr)
        *guest_mspace_default_slot = base;
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
        std::fprintf(stderr, "MEM mspace-create base=%p size=0x%zx flags=%u\n", base, size, flags);
    return base;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_mspace_destroy(void* handle) {
    std::lock_guard lock(guest_mspace_lock);
    const auto erased = guest_mspaces.erase(reinterpret_cast<std::uintptr_t>(handle));
    return erased == 0 ? 1 : 0;
}

void* guest_mspace_allocate(void* handle, std::size_t size, std::size_t alignment) {
    if (size == 0) size = 1;
    if (alignment < 16) alignment = 16;
    if ((alignment & (alignment - 1)) != 0) return nullptr;
    std::lock_guard lock(guest_mspace_lock);
    auto found = guest_mspaces.find(reinterpret_cast<std::uintptr_t>(handle));
    if (found == guest_mspaces.end()) return nullptr;
    auto& arena = found->second;
    for (auto it = arena.free_ranges.begin(); it != arena.free_ranges.end(); ++it) {
        const auto start = it->first;
        const auto length = it->second;
        const auto aligned = (start + alignment - 1) & ~(alignment - 1);
        if (aligned < start || aligned - start > length || size > length - (aligned - start))
            continue;
        const auto end = aligned + size;
        const auto range_end = start + length;
        arena.free_ranges.erase(it);
        if (aligned > start) arena.free_ranges.emplace_back(start, aligned - start);
        if (end < range_end) arena.free_ranges.emplace_back(end, range_end - end);
        arena.used_ranges.emplace(aligned, size);
        arena.current_use += size;
        arena.peak_use = std::max(arena.peak_use, arena.current_use);
        auto* result = reinterpret_cast<void*>(arena.base + aligned);
        if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
            std::fprintf(stderr, "MEM mspace-alloc handle=%p size=0x%zx align=0x%zx -> %p\n",
                handle, size, alignment, result);
        return result;
    }
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr)
        std::fprintf(stderr, "MEM mspace-alloc failed handle=%p size=0x%zx align=0x%zx\n",
            handle, size, alignment);
    return nullptr;
}

bool guest_mspace_free_block(GuestMspace& arena, void* pointer) {
    const auto address = reinterpret_cast<std::uintptr_t>(pointer);
    if (address < arena.base || address - arena.base >= arena.size) return false;
    const auto offset = static_cast<std::size_t>(address - arena.base);
    auto used = arena.used_ranges.find(offset);
    if (used == arena.used_ranges.end()) return false;
    arena.current_use -= used->second;
    arena.free_ranges.emplace_back(offset, used->second);
    arena.used_ranges.erase(used);
    std::sort(arena.free_ranges.begin(), arena.free_ranges.end());
    std::vector<std::pair<std::size_t, std::size_t>> merged;
    for (const auto& range : arena.free_ranges) {
        if (!merged.empty() && merged.back().first + merged.back().second == range.first)
            merged.back().second += range.second;
        else merged.push_back(range);
    }
    arena.free_ranges.swap(merged);
    return true;
}

void* NBA16_GUEST_SYSV_ABI guest_mspace_malloc(void* handle, std::size_t size) {
    return guest_mspace_allocate(handle, size, 16);
}

void NBA16_GUEST_SYSV_ABI guest_mspace_free(void* handle, void* pointer) {
    if (pointer == nullptr) return;
    std::lock_guard lock(guest_mspace_lock);
    auto found = guest_mspaces.find(reinterpret_cast<std::uintptr_t>(handle));
    if (found != guest_mspaces.end()) (void)guest_mspace_free_block(found->second, pointer);
}

void* NBA16_GUEST_SYSV_ABI guest_mspace_calloc(void* handle, std::size_t count,
                                               std::size_t size) {
    if (size != 0 && count > SIZE_MAX / size) return nullptr;
    const auto bytes = count * size;
    auto* pointer = guest_mspace_allocate(handle, bytes, 16);
    if (pointer != nullptr) std::memset(pointer, 0, bytes);
    return pointer;
}

void NBA16_GUEST_SYSV_ABI guest_mspace_free(void* handle, void* pointer);

void* NBA16_GUEST_SYSV_ABI guest_mspace_realloc(void* handle, void* pointer,
                                                std::size_t size) {
    if (pointer == nullptr) return guest_mspace_malloc(handle, size);
    std::size_t old_size{};
    {
        std::lock_guard lock(guest_mspace_lock);
        auto found = guest_mspaces.find(reinterpret_cast<std::uintptr_t>(handle));
        if (found == guest_mspaces.end()) return nullptr;
        const auto offset = reinterpret_cast<std::uintptr_t>(pointer) - found->second.base;
        auto used = found->second.used_ranges.find(static_cast<std::size_t>(offset));
        if (used == found->second.used_ranges.end()) return nullptr;
        old_size = used->second;
        if (size <= old_size) return pointer;
    }
    auto* replacement = guest_mspace_allocate(handle, size, 16);
    if (replacement == nullptr) return nullptr;
    std::memcpy(replacement, pointer, old_size);
    guest_mspace_free(handle, pointer);
    return replacement;
}

void* NBA16_GUEST_SYSV_ABI guest_mspace_memalign(void* handle,
    std::size_t alignment, std::size_t size) {
    return guest_mspace_allocate(handle, size, alignment);
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_mspace_posix_memalign(
    void* handle, void** output, std::size_t alignment, std::size_t size) {
    if (output == nullptr || alignment < sizeof(void*) || (alignment & (alignment - 1)) != 0)
        return 22;
    auto* result = guest_mspace_allocate(handle, size, alignment);
    if (result == nullptr) return 12;
    *output = result;
    return 0;
}

std::size_t NBA16_GUEST_SYSV_ABI guest_mspace_usable_size(void* pointer) {
    std::lock_guard lock(guest_mspace_lock);
    const auto address = reinterpret_cast<std::uintptr_t>(pointer);
    for (const auto& [base, arena] : guest_mspaces) {
        if (address < base || address - base >= arena.size) continue;
        const auto used = arena.used_ranges.find(static_cast<std::size_t>(address - base));
        return used == arena.used_ranges.end() ? 0 : used->second;
    }
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_mspace_is_empty(void* handle) {
    std::lock_guard lock(guest_mspace_lock);
    const auto found = guest_mspaces.find(reinterpret_cast<std::uintptr_t>(handle));
    return found != guest_mspaces.end() && found->second.used_ranges.empty() ? 1 : 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_mspace_stats(void* handle,
                                                     GuestMspaceStats* stats) {
    std::lock_guard lock(guest_mspace_lock);
    const auto found = guest_mspaces.find(reinterpret_cast<std::uintptr_t>(handle));
    if (found == guest_mspaces.end()) return 1;
    if (stats != nullptr) {
        if (stats->size != sizeof(*stats) || stats->version != 1) return 1;
        stats->max_system = stats->current_system = found->second.size;
        stats->max_in_use = found->second.peak_use;
        stats->current_in_use = found->second.current_use;
    }
    return 0;
}


} // namespace

bool install_direct_memory_provider(const DirectMemoryProvider& provider) noexcept {
    if (provider.get_size == nullptr || provider.get_type == nullptr ||
        provider.allocate == nullptr || provider.available == nullptr ||
        provider.map == nullptr || provider.unmap == nullptr || provider.release == nullptr)
        return false;
    std::lock_guard lock(direct_memory_provider_lock);
    direct_memory_provider = provider;
    return true;
}

void remove_direct_memory_provider() noexcept {
    std::lock_guard lock(direct_memory_provider_lock);
    direct_memory_provider = {};
}

GuestThreadSnapshot current_guest_thread_snapshot() noexcept {
    if (current_guest_thread == nullptr) return {};
    return {static_cast<std::uint64_t>(current_guest_thread->guest_entry),
            reinterpret_cast<std::uintptr_t>(current_guest_thread->guest_argument), true};
}

void set_guest_mspace_default_slot(void** slot) noexcept {
    guest_mspace_set_default_slot_impl(slot);
}

bool initialize_guest_mspace_default(std::uint64_t base, std::size_t size) noexcept {
    if (base == 0 || size <= 0x580) return false;
    auto* handle = guest_mspace_create(nullptr, reinterpret_cast<void*>(base), size, 0);
    return handle != nullptr;
}

extern "C" std::int32_t NBA16_GUEST_SYSV_ABI nba16_guest_sysctl_dispatch(
    const std::int32_t* name, std::uint32_t name_length, void* old_value,
    std::uint64_t* old_length, const void* new_value, std::uint64_t new_length) {
    const auto result = guest_sysctl(name, name_length, old_value, old_length, new_value, new_length);
    const auto syscall_result = result < 0
        ? -std::max(guest_errno, 1) : result;
    if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr)
        std::fprintf(stderr, "SYSCTL dispatch returned-from-handler result=%d syscall-result=%d\n",
            result, syscall_result);
    last_sysctl_dispatch_mib0.store(name != nullptr ? static_cast<std::uint32_t>(name[0]) : 0, std::memory_order_relaxed);
    last_sysctl_dispatch_mib1.store(name != nullptr && name_length > 1 ? static_cast<std::uint32_t>(name[1]) : 0, std::memory_order_relaxed);
    last_sysctl_dispatch_result.store(static_cast<std::uint32_t>(result), std::memory_order_relaxed);
    const auto sequence = sysctl_dispatch_sequence.fetch_add(1, std::memory_order_relaxed);
    const auto history_slot = static_cast<std::size_t>(sequence % 8U) * 4U;
    sysctl_dispatch_history[history_slot].store(name != nullptr ? static_cast<std::uint32_t>(name[0]) : 0, std::memory_order_relaxed);
    sysctl_dispatch_history[history_slot + 1].store(name != nullptr && name_length > 1 ? static_cast<std::uint32_t>(name[1]) : 0, std::memory_order_relaxed);
    sysctl_dispatch_history[history_slot + 2].store(static_cast<std::uint32_t>(result), std::memory_order_relaxed);
#ifdef _WIN32
    sysctl_dispatch_history[history_slot + 3].store(GetCurrentThreadId(), std::memory_order_relaxed);
#else
    sysctl_dispatch_history[history_slot + 3].store(0, std::memory_order_relaxed);
#endif
    if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr)
        std::fprintf(stderr, "SYSCTL return mib=%d,%d result=%d oldlen=%llu errno=%d\n",
            name != nullptr && name_length > 0 ? name[0] : -1,
            name != nullptr && name_length > 1 ? name[1] : -1, result,
            old_length != nullptr ? static_cast<unsigned long long>(*old_length) : 0ULL,
            guest_errno);
    return syscall_result;
}

extern "C" std::int32_t NBA16_GUEST_SYSV_ABI nba16_guest_sysctl_syscall_thunk(
    const std::int32_t*, std::uint32_t, void*, std::uint64_t*,
    const void*, std::uint64_t);

void set_guest_errno(int error) noexcept {
    guest_errno = error;
}

void set_guest_usrstack_top(std::uint64_t address) noexcept {
    guest_usrstack_top.store(address, std::memory_order_release);
}

void set_guest_process_parameter(void* parameter) noexcept {
    guest_process_parameter.store(parameter, std::memory_order_release);
}

std::int32_t NBA16_GUEST_SYSV_ABI guest_virtual_query(std::uint64_t address,
    std::uint64_t find_next, void* output, std::uint64_t output_size) {
    const auto call_index = virtual_query_calls.fetch_add(1, std::memory_order_relaxed);
    // Raw syscall 572 uses the 64-byte kernel record (distinct from the
    // 72-byte sceKernelVirtualQuery API structure used by the other port).
    constexpr std::size_t query_info_size = 0x40;
    if (output == nullptr || output_size < query_info_size) {
        if (std::getenv("NBA16_TRACE_MEMORY") != nullptr && call_index < 16)
            std::fprintf(stderr, "MEM virtual-query[%llu] invalid addr=%llx next=%llu output=%p size=%llu\n",
                static_cast<unsigned long long>(call_index),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(find_next), output,
                static_cast<unsigned long long>(output_size));
        set_guest_errno(22);
        return -22; // The syscall thunk converts this to positive EINVAL with CF set.
    }
    struct QueryResult {
        std::uint64_t begin{}, end{};
        std::uint32_t protection{};
        std::array<char, 32> name{};
    } selected{};
    bool found = false;
    {
        std::lock_guard lock(guest_query_regions_lock);
        const auto region_count = guest_query_regions.size();
        for (std::size_t index = 0; index < region_count; ++index) {
            const auto& region = guest_query_regions[index];
            if ((address >= region.begin && address < region.end) ||
                (find_next != 0 && region.end > address)) {
                selected.begin = region.begin;
                selected.end = region.end;
                selected.protection = region.protection;
                const auto name_size = std::min<std::size_t>(region.name.size(), selected.name.size() - 1U);
                std::memcpy(selected.name.data(), region.name.data(), name_size);
                found = true;
                break;
            }
        }
    }
    if (!found) {
        set_guest_errno(13); // EACCES, matching the port's unmapped-address result.
        if (auto* guest_errno_location = guest_tcb_errno_location(); guest_errno_location != nullptr)
            *guest_errno_location = 13;
        const auto end_call_index = virtual_query_end_calls.fetch_add(1,
            std::memory_order_relaxed);
        const auto* guest_errno_pointer = guest_tcb_errno_location();
        if (std::getenv("NBA16_TRACE_MEMORY") != nullptr && call_index >= 240 &&
            call_index < 2048 && (end_call_index < 16 || end_call_index % 64U == 0))
            std::fprintf(stderr, "MEM virtual-query[%llu] end-of-map[%llu] tid=%zu addr=%llx next=%llu caller=%llx parent=%llx tls_errno=%d tcb_errno=%d\n",
                static_cast<unsigned long long>(call_index),
                static_cast<unsigned long long>(end_call_index),
                std::hash<std::thread::id>{}(std::this_thread::get_id()),
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(find_next),
                static_cast<unsigned long long>(nba16_guest_virtual_query_guest_caller),
                static_cast<unsigned long long>(nba16_guest_virtual_query_parent_caller),
                guest_errno, guest_errno_pointer != nullptr ? *guest_errno_pointer : -1);
        return -13; // The syscall ABI expects positive EACCES in RAX when CF is set.
    }
    auto* bytes = static_cast<std::byte*>(output);
    std::memset(bytes, 0, query_info_size);
    std::memcpy(bytes, &selected.begin, sizeof(selected.begin));
    std::memcpy(bytes + 8, &selected.end, sizeof(selected.end));
    std::memcpy(bytes + 0x10, &selected.protection, sizeof(selected.protection));
    std::memcpy(bytes + 0x20, selected.name.data(), selected.name.size());
    if (std::getenv("NBA16_TRACE_MEMORY") != nullptr &&
        (call_index < 32 || (call_index >= 128 && call_index < 256) ||
         call_index % 128U == 0))
        std::fprintf(stderr, "MEM virtual-query[%llu] addr=%llx next=%llu -> %llx-%llx prot=%x name=%s\n",
            static_cast<unsigned long long>(call_index),
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(find_next),
            static_cast<unsigned long long>(selected.begin),
            static_cast<unsigned long long>(selected.end), selected.protection,
            selected.name.data());
    return 0;
}

extern "C" std::int32_t NBA16_GUEST_SYSV_ABI nba16_guest_virtual_query_api(
    std::uint64_t address, std::uint64_t find_next, void* output,
    std::uint64_t output_size) {
    const auto result = guest_virtual_query(address, find_next, output, output_size);
    if (result == -13) return std::bit_cast<std::int32_t>(0x8002000dU);
    if (result == -22) return std::bit_cast<std::int32_t>(0x80020016U);
    return result;
}

bool register_guest_query_region(std::uint64_t begin, std::uint64_t size,
    std::uint32_t protection, std::string_view name) noexcept {
    if (begin == 0 || size == 0 || size > UINT64_MAX - begin) return false;
    try {
        std::lock_guard lock(guest_query_regions_lock);
        const auto end = begin + size;
        const auto same = std::find_if(guest_query_regions.begin(), guest_query_regions.end(),
            [&](const GuestQueryRegion& item) { return item.begin == begin && item.end == end; });
        if (same != guest_query_regions.end()) {
            same->protection = protection;
            same->name.assign(name);
        } else {
            guest_query_regions.push_back({begin, end, protection, std::string(name)});
        }
        std::sort(guest_query_regions.begin(), guest_query_regions.end(),
            [](const auto& a, const auto& b) { return a.begin < b.begin; });
        return true;
    } catch (...) {
        return false;
    }
}

void unregister_guest_query_region(std::uint64_t begin, std::uint64_t size) noexcept {
    if (size > UINT64_MAX - begin) return;
    std::lock_guard lock(guest_query_regions_lock);
    const auto end = begin + size;
    std::erase_if(guest_query_regions, [&](const GuestQueryRegion& item) {
        return item.begin == begin && item.end == end;
    });
}

std::uint64_t guest_sysctl_dispatch_result() noexcept {
    return last_sysctl_dispatch_result.load(std::memory_order_relaxed);
}
std::uint64_t guest_sysctl_dispatch_mib0() noexcept {
    return last_sysctl_dispatch_mib0.load(std::memory_order_relaxed);
}
std::uint64_t guest_sysctl_dispatch_mib1() noexcept {
    return last_sysctl_dispatch_mib1.load(std::memory_order_relaxed);
}
GuestSysctlHistory guest_sysctl_dispatch_history() noexcept {
    GuestSysctlHistory history{};
    history.count = static_cast<std::size_t>(std::min<std::uint64_t>(sysctl_dispatch_sequence.load(std::memory_order_relaxed), 8U));
    for (std::size_t index = 0; index < history.values.size(); ++index)
        history.values[index] = sysctl_dispatch_history[index].load(std::memory_order_relaxed);
    return history;
}
std::uint64_t guest_sysctl_thunk_return_value() noexcept {
    return nba16_guest_sysctl_syscall_last_rax;
}
std::uint64_t guest_sysctl_last_caller() noexcept {
    return nba16_guest_sysctl_guest_caller;
}
void reset_guest_sysctl_diagnostics() noexcept {
    sysctl_calls.store(0, std::memory_order_relaxed);
    nba16_guest_sysctl_guest_caller = 0;
    sysctlbyname_calls.store(0, std::memory_order_relaxed);
    usrstack_sysctl_calls.store(0, std::memory_order_relaxed);
    mmap_calls.store(0, std::memory_order_relaxed);
    cpuset_calls.store(0, std::memory_order_relaxed);
    virtual_query_end_calls.store(0, std::memory_order_relaxed);
    sysctl_dispatch_sequence.store(0, std::memory_order_relaxed);
    last_sysctl_dispatch_mib0.store(0, std::memory_order_relaxed);
    last_sysctl_dispatch_mib1.store(0, std::memory_order_relaxed);
    last_sysctl_dispatch_result.store(UINT64_MAX, std::memory_order_relaxed);
    nba16_guest_sysctl_syscall_last_rax = UINT64_MAX;
    for (auto& item : sysctl_dispatch_history) item.store(0, std::memory_order_relaxed);
    for (auto& item : last_sysctl_trace) item.store(0, std::memory_order_relaxed);
    for (auto& item : usrstack_sysctl_trace) item.store(0, std::memory_order_relaxed);
    usrstack_sysctl_result.store(UINT64_MAX, std::memory_order_relaxed);
    usrstack_sysctl_response_length.store(0, std::memory_order_relaxed);
    usrstack_sysctl_response_value.store(0, std::memory_order_relaxed);
}
std::uint64_t guest_sysctl_call_count() noexcept {
    return sysctl_calls.load(std::memory_order_relaxed);
}

std::uint64_t guest_sysctlbyname_call_count() noexcept {
    return sysctlbyname_calls.load(std::memory_order_relaxed);
}

std::uint64_t guest_usrstack_sysctl_call_count() noexcept {
    return usrstack_sysctl_calls.load(std::memory_order_relaxed);
}

std::uint64_t guest_mmap_call_count() noexcept {
    return mmap_calls.load(std::memory_order_relaxed);
}


std::uint64_t guest_cpuset_call_count() noexcept {
    return cpuset_calls.load(std::memory_order_relaxed);
}

GuestSysctlTrace guest_sysctl_last_trace() noexcept {
    return {last_sysctl_trace[0].load(std::memory_order_relaxed),
            last_sysctl_trace[1].load(std::memory_order_relaxed),
            last_sysctl_trace[2].load(std::memory_order_relaxed),
            last_sysctl_trace[3].load(std::memory_order_relaxed),
            last_sysctl_trace[4].load(std::memory_order_relaxed),
            last_sysctl_trace[5].load(std::memory_order_relaxed),
            last_sysctl_trace[6].load(std::memory_order_relaxed),
            last_sysctl_trace[7].load(std::memory_order_relaxed)};
}

GuestSysctlTrace guest_usrstack_sysctl_trace() noexcept {
    return {usrstack_sysctl_trace[0].load(std::memory_order_relaxed),
            usrstack_sysctl_trace[1].load(std::memory_order_relaxed),
            usrstack_sysctl_trace[2].load(std::memory_order_relaxed),
            usrstack_sysctl_trace[3].load(std::memory_order_relaxed),
            usrstack_sysctl_trace[4].load(std::memory_order_relaxed),
            usrstack_sysctl_trace[5].load(std::memory_order_relaxed),
            usrstack_sysctl_trace[6].load(std::memory_order_relaxed),
            usrstack_sysctl_trace[7].load(std::memory_order_relaxed),
            usrstack_sysctl_result.load(std::memory_order_relaxed),
            usrstack_sysctl_response_length.load(std::memory_order_relaxed),
            usrstack_sysctl_response_value.load(std::memory_order_relaxed)};
}

bool register_native_kernel_runtime_imports(ImportResolver& resolver,
                                           std::string& error) {
    if (!resolver.register_function("libkernel", "libkernel", "HoLVWNanBBc",
                                    &guest_get_pid, error) ||
        !resolver.register_function("libkernel", "libkernel", "959qrazPIrg",
                                    &guest_get_process_parameter, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "-hn1tcVHq5Q",
                                    &guest_mspace_create, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "W6SiVSiCDtI",
                                    &guest_mspace_destroy, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "OJjm-QOIHlI",
                                    &guest_mspace_malloc, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "Vla-Z+eXlxo",
                                    &guest_mspace_free, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "LYo3GhIlB38",
                                    &guest_mspace_calloc, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "gigoVHZvVPE",
                                    &guest_mspace_realloc, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "iF1iQHzxBJU",
                                    &guest_mspace_memalign, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "qWESlyXMI3E",
                                    &guest_mspace_posix_memalign, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "fEoW6BJsPt4",
                                    &guest_mspace_usable_size, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "pzUa7KEoydw",
                                    &guest_mspace_is_empty, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "mfHdJTIvhuo",
                                    &guest_mspace_stats, error) ||
        !resolver.register_function("libSceLibcInternal", "libSceLibcInternal", "k04jLXu3+Ic",
                                    &guest_mspace_stats, error) ||
        !resolver.register_function("libkernel", "libkernel", "pO96TwzOm5E",
                                    &guest_direct_memory_size, error) ||
        !resolver.register_function("libkernel", "libkernel", "BC+OG5m9+bw",
                                    &guest_direct_memory_type, error) ||
        !resolver.register_function("libkernel", "libkernel", "rTXw65xmLIA",
                                    &guest_allocate_direct_memory, error) ||
        !resolver.register_function("libkernel", "libkernel", "C0f7TJcbfac",
                                    &guest_available_direct_memory, error) ||
        !resolver.register_function("libkernel", "libkernel", "L-Q3LEjIbgA",
                                    &guest_map_direct_memory, error) ||
        !resolver.register_function("libkernel", "libkernel", "NcaWUxfMNIQ",
                                    &guest_map_direct_memory, error) ||
        !resolver.register_function("libkernel", "libkernel", "MBuItvba6z8",
                                    &guest_release_direct_memory, error) ||
        !resolver.register_function("libkernel", "libkernel", "mL8NDH86iQI",
                                    &guest_map_named_flexible_memory, error) ||
        !resolver.register_function("libkernel", "libkernel", "kc+LEEIYakc",
                                    &guest_map_named_flexible_memory, error) ||
        !resolver.register_function("libkernel", "libkernel", "3k6kx-zOOSQ",
                                    &guest_kernel_mlock, error) ||
        !resolver.register_function("libkernel", "libkernel", "bt0POEUZddE",
                                    &guest_sanitizer_malloc_replace, error) ||
        !resolver.register_function("libkernel", "libkernel", "9BcDykPmo1I",
                                    &guest_error_location, error) ||
        !resolver.register_function("libkernel", "libkernel", "DFmMT80xcNI",
                                    &guest_sysctl, error) ||
        !resolver.register_code_interposition("libkernel", "libkernel", "DFmMT80xcNI",
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&nba16_guest_sysctl_syscall_thunk)), error) ||
        !resolver.register_function("libkernel", "libkernel", "MhC53TKmjVA",
                                    &guest_sysctlbyname, error) ||
        !resolver.register_code_interposition("libkernel", "libkernel", "MhC53TKmjVA",
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&guest_sysctlbyname)), error) ||
        !resolver.register_code_offset_interposition("libkernel.sprx", 0x1010,
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&nba16_guest_sysctl_syscall_thunk)), error) ||
        !resolver.register_code_offset_interposition("libkernel.sprx", 0x1030,
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&guest_sysctlbyname)), error) ||
        !resolver.register_code_offset_interposition("libkernel.sprx", 0x181b0,
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&nba16_guest_virtual_query_api)), error) ||
        !resolver.register_code_offset_interposition("libkernel.sprx", 0x2990,
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&guest_mmap_syscall)), error) ||
        !resolver.register_code_offset_interposition("libkernel.sprx", 0x1dd0,
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&guest_cpuset_syscall)), error) ||
        !resolver.register_code_offset_interposition("libkernel.sprx", 0x1df0,
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&guest_cpuset_syscall)), error) ||
        !resolver.register_function("libkernel", "libkernel", "Ou3iL1abvng",
                                    &guest_stack_check_failure, error) ||
        !resolver.register_function("libkernel", "libkernel", "F8bUHwAG284",
                                    &guest_mutex_attribute_init, error) ||
        !resolver.register_function("libkernel", "libkernel", "iMp8QpE+XO4",
                                    &guest_mutex_attribute_set_type, error) ||
        !resolver.register_function("libScePosix", "libkernel", "dQHWEsJtoE4",
                                    &guest_mutex_attribute_init, error) ||
        !resolver.register_function("libScePosix", "libkernel", "EXv3ztGqtDM",
                                    &guest_mutex_attribute_set_pshared, error) ||
        !resolver.register_function("libScePosix", "libkernel", "mDmgMOGVUqg",
                                    &guest_mutex_attribute_set_type, error) ||
        !resolver.register_function("libkernel", "libkernel", "smWEktiyyG0",
                                    &guest_mutex_attribute_destroy, error) ||
        !resolver.register_function("libScePosix", "libkernel", "HF7lK46xzjY",
                                    &guest_mutex_attribute_destroy, error) ||
        !resolver.register_function("libkernel", "libkernel", "cmo1RIYva9o",
                                    &guest_mutex_init, error) ||
        !resolver.register_function("libScePosix", "libkernel", "ttHNfU+qDBU",
                                    &guest_mutex_init, error) ||
        !resolver.register_function("libkernel", "libkernel", "9UK1vLZQft4",
                                    &guest_mutex_lock, error) ||
        !resolver.register_function("libScePosix", "libkernel", "7H0iTOciTLo",
                                    &guest_mutex_lock, error) ||
        !resolver.register_function("libkernel", "libkernel", "upoVrzMHFeE",
                                    &guest_mutex_trylock, error) ||
        !resolver.register_function("libkernel", "libkernel", "tn3VlD0hG60",
                                    &guest_mutex_unlock, error) ||
        !resolver.register_function("libScePosix", "libkernel", "2Z+PpY6CaJg",
                                    &guest_mutex_unlock, error) ||
        !resolver.register_function("libkernel", "libkernel", "2Of0f+3mhhE",
                                    &guest_mutex_destroy, error) ||
        !resolver.register_function("libkernel", "libkernel", "2Tb92quprl0",
                                    &guest_condition_init, error) ||
        !resolver.register_function("libkernel", "libkernel", "kDh-NfxgMtE",
                                    &guest_condition_signal, error) ||
        !resolver.register_function("libkernel", "libkernel", "JGgj7Uvrl+A",
                                    &guest_condition_broadcast, error) ||
        !resolver.register_function("libkernel", "libkernel", "WKAXJ4XBPQ4",
                                    &guest_condition_wait, error) ||
        !resolver.register_function("libkernel", "libkernel", "BmMjYxmew1w",
                                    &guest_condition_timed_wait, error) ||
        !resolver.register_function("libkernel", "libkernel", "g+PZd2hiacg",
                                    &guest_condition_destroy, error) ||
        !resolver.register_function("libkernel", "libkernel", "-2IRUCO--PM",
                                    &guest_read_tsc, error) ||
        !resolver.register_function("libkernel", "libkernel", "1j3S3n-tTW4",
                                    &guest_get_tsc_frequency, error) ||
        !resolver.register_function("libkernel", "libkernel", "QvsZxomvUHs",
                                    &guest_nanosleep, error) ||
        !resolver.register_function("libkernel", "libkernel", "1jfXLRVzisc",
                                    &guest_usleep, error) ||
        !resolver.register_function("libkernel", "libkernel", "QBi7HCK03hw",
                                    &guest_clock_gettime, error) ||
        !resolver.register_function("libkernel", "libkernel", "ejekcaNQNq0",
                                    &guest_gettimeofday, error) ||
        !resolver.register_function("libkernel", "libkernel", "6UgtwV+0zb4",
                                    &guest_pthread_create, error) ||
        !resolver.register_function("libkernel", "libkernel", "onNY9Byn-W8",
                                    &guest_pthread_join, error) ||
        !resolver.register_function("libkernel", "libkernel", "4qGrR6eoP9Y",
                                    &guest_pthread_detach, error) ||
        !resolver.register_function("libkernel", "libkernel", "3PtV6p3QNX4",
                                    &guest_pthread_equal, error) ||
        !resolver.register_function("libkernel", "libkernel", "aI+OeCz8xrQ",
                                    &guest_pthread_self, error) ||
        !resolver.register_function("libkernel", "libkernel", "188x57JYp0g",
                                    &guest_kernel_create_sema, error) ||
        !resolver.register_function("libkernel", "libkernel", "Zxa0VhQVTsk",
                                    &guest_kernel_wait_sema, error) ||
        !resolver.register_function("libkernel", "libkernel", "4czppHBiriw",
                                    &guest_kernel_signal_sema, error) ||
        !resolver.register_function("libkernel", "libkernel", "12wOHk8ywb0",
                                    &guest_kernel_poll_sema, error) ||
        !resolver.register_function("libkernel", "libkernel", "4DM06U2BNEY",
                                    &guest_kernel_cancel_sema, error) ||
        !resolver.register_function("libkernel", "libkernel", "R1Jvn8bSCW8",
                                    &guest_kernel_delete_sema, error) ||
        !resolver.register_function("libkernel", "libkernel", "geDaqgH9lTg",
                                    &guest_pthread_key_create, error) ||
        !resolver.register_function("libkernel", "libkernel", "PrdHuuDekhY",
                                    &guest_pthread_key_delete, error) ||
        !resolver.register_function("libkernel", "libkernel", "eoht7mQOCmo",
                                    &guest_pthread_getspecific, error) ||
        !resolver.register_function("libkernel", "libkernel", "+BzXYkqYeLE",
                                    &guest_pthread_setspecific, error) ||
        !resolver.register_function("libkernel", "libkernel", "OAmWq+OHSjw",
                                    &guest_pthread_setcancelstate, error)) {
        return false;
    }
    return resolver.register_symbol(
        "libkernel", "libkernel", "f7uOxY9mM1U", GuestSymbolKind::object,
        static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&guest_stack_guard)),
        error);
}

} // namespace nba16

