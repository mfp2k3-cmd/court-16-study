#include "posix_fs_imports.h"

#include "guest_process_context.h"
#include "guest_syscalls.h"
#include "kernel_runtime.h"

#include <algorithm>
#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <span>
#include <string>
#include <thread>

#if defined(_WIN32) && defined(NBA16_ENABLE_FS_EOF_INSTRUCTION_TRACE)
extern "C" void nba16_start_fs_eof_instruction_trace();
#endif

namespace nba16 {
namespace {

std::atomic_uint32_t eof_trace_events{};
std::atomic_uint32_t seek_trace_events{};
std::atomic_bool shader_entry_trace_dumped{};
std::atomic_uint32_t fstat_trace_events{};

std::int64_t NBA16_GUEST_SYSV_ABI guest_fstat_syscall(
    std::int32_t descriptor, std::uint64_t output,
    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    const bool ok = guest_fstat_to_memory(context->descriptors(), context->memory(),
        descriptor, output, error, &failure);
    if (!ok) {
        set_guest_errno(static_cast<int>(failure));
        if (std::getenv("NBA16_TRACE_FS") != nullptr &&
            fstat_trace_events.fetch_add(1, std::memory_order_relaxed) < 64) {
            std::fprintf(stderr,
                "FS fstat syscall fd=%d output=0x%llx failed errno=%d detail=%s\n",
                descriptor, static_cast<unsigned long long>(output),
                static_cast<int>(failure), error.c_str());
        }
        return -1;
    }
    if (std::getenv("NBA16_TRACE_FS") != nullptr &&
        fstat_trace_events.fetch_add(1, std::memory_order_relaxed) < 64) {
        VfsMetadata metadata{};
        std::string metadata_error;
        std::string path;
        const bool has_metadata = context->descriptors().stat_descriptor(
            descriptor, metadata, metadata_error);
        const bool has_path = context->descriptors().descriptor_path(
            descriptor, path, metadata_error);
        std::fprintf(stderr,
            "FS fstat syscall fd=%d output=0x%llx size=%llu path=%s\n",
            descriptor, static_cast<unsigned long long>(output),
            static_cast<unsigned long long>(has_metadata ? metadata.size : 0),
            has_path ? path.c_str() : "<unknown>");
    }
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_getcwd_import(std::uint64_t buffer,
                                             std::uint64_t size) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    constexpr char cwd[] = "/app0";
    if (buffer == 0) { set_guest_errno(14); return -1; }
    if (size < sizeof(cwd)) { set_guest_errno(34); return -1; }
    std::string error;
    if (!context->memory().write(buffer,
            std::as_bytes(std::span(cwd, sizeof(cwd))), error)) {
        set_guest_errno(14);
        return -1;
    }
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_statfs_import(std::uint64_t path,
                                             std::uint64_t output) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    if (!guest_statfs(context->vfs(), context->memory(), path, output,
                      error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_fstatfs_import(int descriptor,
                                              std::uint64_t output) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    if (!guest_fstatfs(context->vfs(), context->descriptors(),
                       context->memory(), descriptor, output, error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    return 0;
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_pathconf_import(
    std::uint64_t path, int name) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    std::int64_t value{};
    if (!guest_pathconf(context->vfs(), context->memory(), path, name,
                        value, error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    return value;
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_readlink_import(
    std::uint64_t path, std::uint64_t buffer, std::uint64_t buffer_size) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    std::size_t bytes_read{};
    if (!guest_readlink(context->vfs(), context->memory(), path, buffer,
                        static_cast<std::size_t>(buffer_size), bytes_read,
                        error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    return static_cast<std::int64_t>(bytes_read);
}

int NBA16_GUEST_SYSV_ABI guest_openat_import(int directory_descriptor,
                                             std::uint64_t path, int flags,
                                             std::uint16_t mode) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    const int descriptor = guest_openat(context->vfs(), context->descriptors(),
        context->memory(), directory_descriptor, path, flags, mode, error, &failure);
    if (descriptor < 0) set_guest_errno(static_cast<int>(failure));
    return descriptor;
}

int NBA16_GUEST_SYSV_ABI guest_open_import(std::uint64_t path, int flags,
                                           std::uint32_t mode) {
    auto* context = current_guest_process_context();
    const bool trace_open = std::getenv("NBA16_TRACE_FS") != nullptr;
    if (trace_open) std::fprintf(stderr,
        "FS syscall-open enter path_ptr=0x%llx flags=0x%x mode=0x%x context=%p initialized=%d\n",
        static_cast<unsigned long long>(path), flags, mode, static_cast<void*>(context),
        context != nullptr && context->is_initialized() ? 1 : 0);
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    const int descriptor = guest_open(context->vfs(), context->descriptors(),
        context->memory(), path, flags, static_cast<std::uint16_t>(mode), error, &failure);
    if (descriptor < 0) set_guest_errno(static_cast<int>(failure));
    if (trace_open) std::fprintf(stderr,
        "FS syscall-open result fd=%d errno=%d detail='%s'\n",
        descriptor, static_cast<int>(failure), error.c_str());
    return descriptor;
}

int NBA16_GUEST_SYSV_ABI guest_ioctl_import(int descriptor, std::uint64_t request,
                                            std::uint64_t argument) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string device_path;
    if (!context->descriptors().is_device(descriptor, device_path)) {
        set_guest_errno(9);
        return -1;
    }
    if (std::getenv("NBA16_TRACE_GNM_DEVICE") != nullptr) {
        static std::atomic_uint32_t ioctl_events{};
        if (ioctl_events.fetch_add(1, std::memory_order_relaxed) < 128) {
            const auto encoded_size = static_cast<std::size_t>(
                (request >> 16U) & 0x1fffU);
            const auto payload_size = std::min(encoded_size, std::size_t{256});
            std::array<std::byte, 256> payload{};
            std::string memory_error;
            const bool payload_read = payload_size != 0 && argument != 0 &&
                context->memory().read(argument,
                    std::span<std::byte>(payload.data(), payload_size), memory_error);
            std::fprintf(stderr,
                "GNM device ioctl fd=%d path='%s' request=0x%llx arg=0x%llx size=%zu input=",
                descriptor, device_path.c_str(),
                static_cast<unsigned long long>(request),
                static_cast<unsigned long long>(argument), encoded_size);
            if (payload_read) {
                for (std::size_t index = 0; index < payload_size; ++index)
                    std::fprintf(stderr, "%02x", std::to_integer<unsigned>(payload[index]));
            } else if (encoded_size != 0) {
                std::fprintf(stderr, "<unreadable:%s>", memory_error.c_str());
            } else {
                std::fprintf(stderr, "<none>");
            }
            std::fprintf(stderr, "\n");
        }
    }
    if (std::getenv("NBA16_TRACE_GNM_DEVICE") != nullptr)
        std::fprintf(stderr, "GNM device ioctl request=0x%llx -> ENOTTY\n",
            static_cast<unsigned long long>(request));
    set_guest_errno(25);
    return -1;
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_kernel_read_import(
    int descriptor, std::uint64_t buffer, std::uint64_t size) {
    const bool trace_read = std::getenv("NBA16_TRACE_FS") != nullptr;
    static std::atomic<std::uint32_t> shader_read_trace_events{};
    const auto trace_thread_id = trace_read ||
            std::getenv("NBA16_TRACE_FS_CALLER") != nullptr
        ? std::hash<std::thread::id>{}(std::this_thread::get_id()) : 0U;
    bool trace_shader_read = false;
    std::string shader_read_path;
    std::uint64_t shader_position_before{};
    if (std::getenv("NBA16_TRACE_SHADER_FS_READ") != nullptr) {
        auto* process = current_guest_process_context();
        std::string path_error;
        std::uint64_t ignored_size{};
        if (process != nullptr && process->is_initialized() &&
            process->descriptors().descriptor_path(descriptor, shader_read_path, path_error) &&
            shader_read_path.find("/eatext_glyphshader.rnafx") != std::string::npos) {
            trace_shader_read = process->descriptors().descriptor_position(
                descriptor, shader_position_before, ignored_size, path_error);
        }
    }
    if (trace_read) std::fprintf(stderr,
        "FS syscall-read enter thread=%016llx fd=%d buffer=0x%llx size=%llu\n",
        static_cast<unsigned long long>(trace_thread_id), descriptor,
        static_cast<unsigned long long>(buffer),
        static_cast<unsigned long long>(size));
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        if (trace_read) std::fprintf(stderr, "FS syscall-read rejected: process context unavailable\n");
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    std::size_t bytes_read{};
    if (!guest_read(context->vfs(), context->descriptors(), context->memory(),
            descriptor, buffer, static_cast<std::size_t>(size), bytes_read,
            error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        if (trace_read) std::fprintf(stderr,
            "FS syscall-read failed fd=%d errno=%d detail='%s'\n", descriptor,
            static_cast<int>(failure), error.c_str());
        return -1;
    }
    if (trace_shader_read && shader_read_trace_events.fetch_add(
            1, std::memory_order_relaxed) < 96) {
        std::uint64_t shader_position_after{};
        std::uint64_t ignored_size{};
        std::string position_error;
        (void)context->descriptors().descriptor_position(
            descriptor, shader_position_after, ignored_size, position_error);
        std::fprintf(stderr,
            "FS SHADER-READ thread=%016llx caller=%p fd=%d path='%s' "
            "requested=%llu returned=%zu position=%llu->%llu\n",
            static_cast<unsigned long long>(trace_thread_id), __builtin_return_address(0),
            descriptor, shader_read_path.c_str(), static_cast<unsigned long long>(size),
            bytes_read, static_cast<unsigned long long>(shader_position_before),
            static_cast<unsigned long long>(shader_position_after));
    }
    if (trace_read) std::fprintf(stderr,
        "FS syscall-read result thread=%016llx fd=%d bytes=%zu\n",
        static_cast<unsigned long long>(trace_thread_id), descriptor, bytes_read);
    if (bytes_read == 0 && std::getenv("NBA16_TRACE_FS_CALLER") != nullptr) {
        const auto eof_event = eof_trace_events.fetch_add(1, std::memory_order_relaxed);
        if (eof_event >= 32) return static_cast<std::int64_t>(bytes_read);
        std::string path;
        std::string path_error;
        (void)context->descriptors().descriptor_path(descriptor, path, path_error);
        std::uint64_t position{};
        std::uint64_t logical_size{};
        (void)context->descriptors().descriptor_position(descriptor, position,
                                                         logical_size, path_error);
        const auto guest_thread = current_guest_thread_snapshot();
        std::fprintf(stderr,
            "FS EOF thread=%016llx host_return=%p fd=%d path='%s' "
            "position=%llu size=%llu requested=%llu entry=0x%llx arg=0x%llx\n",
            static_cast<unsigned long long>(trace_thread_id),
            __builtin_return_address(0), descriptor, path.c_str(),
            static_cast<unsigned long long>(position),
            static_cast<unsigned long long>(logical_size),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(guest_thread.entry),
            static_cast<unsigned long long>(guest_thread.argument));
        const bool trace_shader_entry =
            path.find("/eatext_glyphshader.rnafx") != std::string::npos &&
            guest_thread.is_guest_thread &&
            !shader_entry_trace_dumped.exchange(true, std::memory_order_relaxed);
        if (trace_shader_entry) {
            std::array<std::uint64_t, 16> worker_argument_words{};
            path_error.clear();
            if (guest_thread.argument <= UINT64_MAX - sizeof(worker_argument_words) &&
                context->memory().read(guest_thread.argument,
                    std::as_writable_bytes(std::span(worker_argument_words)), path_error)) {
                std::fprintf(stderr,
                    "FS EOF guest-worker-argument address=0x%llx "
                    "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                    static_cast<unsigned long long>(guest_thread.argument),
                    static_cast<unsigned long long>(worker_argument_words[0]),
                    static_cast<unsigned long long>(worker_argument_words[1]),
                    static_cast<unsigned long long>(worker_argument_words[2]),
                    static_cast<unsigned long long>(worker_argument_words[3]),
                    static_cast<unsigned long long>(worker_argument_words[4]),
                    static_cast<unsigned long long>(worker_argument_words[5]),
                    static_cast<unsigned long long>(worker_argument_words[6]),
                    static_cast<unsigned long long>(worker_argument_words[7]),
                    static_cast<unsigned long long>(worker_argument_words[8]),
                    static_cast<unsigned long long>(worker_argument_words[9]),
                    static_cast<unsigned long long>(worker_argument_words[10]),
                    static_cast<unsigned long long>(worker_argument_words[11]),
                    static_cast<unsigned long long>(worker_argument_words[12]),
                    static_cast<unsigned long long>(worker_argument_words[13]),
                    static_cast<unsigned long long>(worker_argument_words[14]),
                    static_cast<unsigned long long>(worker_argument_words[15]));
                const auto task_state_address = worker_argument_words[4];
                std::array<std::uint64_t, 12> task_state_words{};
                path_error.clear();
                if (task_state_address <= UINT64_MAX - sizeof(task_state_words) &&
                    context->memory().read(task_state_address,
                        std::as_writable_bytes(std::span(task_state_words)), path_error)) {
                    std::fprintf(stderr,
                        "FS EOF guest-worker-task-state address=0x%llx "
                        "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                        static_cast<unsigned long long>(task_state_address),
                        static_cast<unsigned long long>(task_state_words[0]),
                        static_cast<unsigned long long>(task_state_words[1]),
                        static_cast<unsigned long long>(task_state_words[2]),
                        static_cast<unsigned long long>(task_state_words[3]),
                        static_cast<unsigned long long>(task_state_words[4]),
                        static_cast<unsigned long long>(task_state_words[5]),
                        static_cast<unsigned long long>(task_state_words[6]),
                        static_cast<unsigned long long>(task_state_words[7]),
                        static_cast<unsigned long long>(task_state_words[8]),
                        static_cast<unsigned long long>(task_state_words[9]),
                        static_cast<unsigned long long>(task_state_words[10]),
                        static_cast<unsigned long long>(task_state_words[11]));
                    for (const auto parent_address : {task_state_words[0], task_state_words[1]}) {
                        std::array<std::uint64_t, 8> parent_words{};
                        path_error.clear();
                        if (parent_address <= UINT64_MAX - sizeof(parent_words) &&
                            context->memory().read(parent_address,
                                std::as_writable_bytes(std::span(parent_words)), path_error)) {
                            std::fprintf(stderr,
                                "FS EOF guest-worker-parent address=0x%llx "
                                "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                                static_cast<unsigned long long>(parent_address),
                                static_cast<unsigned long long>(parent_words[0]),
                                static_cast<unsigned long long>(parent_words[1]),
                                static_cast<unsigned long long>(parent_words[2]),
                                static_cast<unsigned long long>(parent_words[3]),
                                static_cast<unsigned long long>(parent_words[4]),
                                static_cast<unsigned long long>(parent_words[5]),
                                static_cast<unsigned long long>(parent_words[6]),
                                static_cast<unsigned long long>(parent_words[7]));
                        } else {
                            std::fprintf(stderr,
                                "FS EOF guest-worker-parent address=0x%llx unavailable: %s\n",
                                static_cast<unsigned long long>(parent_address), path_error.c_str());
                        }
                    }
                    const auto chain_address = task_state_words[0];
                    std::array<std::uint64_t, 8> chain_words{};
                    path_error.clear();
                    if (chain_address <= UINT64_MAX - sizeof(chain_words) &&
                        context->memory().read(chain_address,
                            std::as_writable_bytes(std::span(chain_words)), path_error)) {
                        const auto next_chain_address = chain_words[0];
                        if (next_chain_address <= UINT64_MAX - sizeof(chain_words)) {
                            path_error.clear();
                            if (context->memory().read(next_chain_address,
                                std::as_writable_bytes(std::span(chain_words)), path_error)) {
                                std::fprintf(stderr,
                                    "FS EOF guest-worker-chain address=0x%llx "
                                    "qwords=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
                                    static_cast<unsigned long long>(next_chain_address),
                                    static_cast<unsigned long long>(chain_words[0]),
                                    static_cast<unsigned long long>(chain_words[1]),
                                    static_cast<unsigned long long>(chain_words[2]),
                                    static_cast<unsigned long long>(chain_words[3]),
                                    static_cast<unsigned long long>(chain_words[4]),
                                    static_cast<unsigned long long>(chain_words[5]),
                                    static_cast<unsigned long long>(chain_words[6]),
                                    static_cast<unsigned long long>(chain_words[7]));
                            }
                        }
                    }
                } else {
                    std::fprintf(stderr,
                        "FS EOF guest-worker-task-state unavailable: %s\n", path_error.c_str());
                }
            } else {
                std::fprintf(stderr,
                    "FS EOF guest-worker-argument unavailable: %s\n", path_error.c_str());
            }
            const auto caller_address = reinterpret_cast<std::uintptr_t>(
                __builtin_return_address(0));
            if (caller_address >= 32) {
                std::array<std::byte, 256> caller_code{};
                path_error.clear();
                if (context->memory().read(caller_address - 32, caller_code, path_error)) {
                    std::fprintf(stderr, "FS EOF guest-caller-code-at-minus-32=");
                    for (const auto byte : caller_code)
                        std::fprintf(stderr, "%02x", std::to_integer<unsigned>(byte));
                    std::fputc('\n', stderr);
                } else {
                    std::fprintf(stderr, "FS EOF guest-caller-code unavailable: %s\n",
                        path_error.c_str());
                }
            }
            std::array<std::byte, 256> entry_code{};
            if (context->memory().read(guest_thread.entry, entry_code, path_error)) {
                std::fprintf(stderr, "FS EOF guest-entry-code=");
                for (const auto byte : entry_code)
                    std::fprintf(stderr, "%02x", std::to_integer<unsigned>(byte));
                std::fputc('\n', stderr);
            } else {
                std::fprintf(stderr, "FS EOF guest-entry-code unavailable: %s\n",
                    path_error.c_str());
            }
            std::array<std::byte, sizeof(std::uint64_t)> callback_pointer_bytes{};
            std::uint64_t callback_pointer{};
            path_error.clear();
            if (guest_thread.argument <= UINT64_MAX - 0x28U &&
                context->memory().read(guest_thread.argument + 0x28U,
                    callback_pointer_bytes, path_error)) {
                std::memcpy(&callback_pointer, callback_pointer_bytes.data(),
                    sizeof(callback_pointer));
                std::fprintf(stderr, "FS EOF guest-worker-callback=0x%llx\n",
                    static_cast<unsigned long long>(callback_pointer));
                std::array<std::byte, 192> callback_code{};
                path_error.clear();
                if (callback_pointer != 0 && context->memory().read(callback_pointer,
                        callback_code, path_error)) {
                    std::fprintf(stderr, "FS EOF guest-worker-callback-code=");
                    for (const auto byte : callback_code)
                        std::fprintf(stderr, "%02x", std::to_integer<unsigned>(byte));
                    std::fputc('\n', stderr);
                    std::int32_t global_displacement{};
                    std::memcpy(&global_displacement, callback_code.data() + 0x68,
                        sizeof(global_displacement));
                    const auto global_slot = static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(callback_pointer + 0x6cU) +
                        global_displacement);
                    std::array<std::byte, sizeof(std::uint64_t)> pointer_bytes{};
                    path_error.clear();
                    if (context->memory().read(global_slot, pointer_bytes, path_error)) {
                        std::uint64_t object{};
                        std::memcpy(&object, pointer_bytes.data(), sizeof(object));
                        std::fprintf(stderr,
                            "FS EOF callback-global-slot=0x%llx object=0x%llx\n",
                            static_cast<unsigned long long>(global_slot),
                            static_cast<unsigned long long>(object));
                        if (object != 0 && context->memory().read(object,
                                pointer_bytes, path_error)) {
                            std::uint64_t vtable{};
                            std::memcpy(&vtable, pointer_bytes.data(), sizeof(vtable));
                            std::uint64_t method{};
                            if (vtable <= UINT64_MAX - 0xc8U && context->memory().read(
                                    vtable + 0xc8U, pointer_bytes, path_error)) {
                                std::memcpy(&method, pointer_bytes.data(), sizeof(method));
                            }
                            std::fprintf(stderr,
                                "FS EOF callback-vtable=0x%llx method_c8=0x%llx\n",
                                static_cast<unsigned long long>(vtable),
                                static_cast<unsigned long long>(method));
                            std::array<std::byte, 0x200> vtable_bytes{};
                            path_error.clear();
                            if (vtable != 0 && context->memory().read(
                                    vtable, vtable_bytes, path_error)) {
                                for (std::size_t slot = 0; slot < vtable_bytes.size() / 8; ++slot) {
                                    std::uint64_t target{};
                                    std::memcpy(&target, vtable_bytes.data() + slot * 8,
                                        sizeof(target));
                                    if (target == 0) continue;
                                    std::fprintf(stderr,
                                        "FS EOF callback-vtable-slot[%02zu]=0x%llx target=0x%llx\n",
                                        slot, static_cast<unsigned long long>(vtable + slot * 8),
                                        static_cast<unsigned long long>(target));
                                }
                            } else {
                                std::fprintf(stderr,
                                    "FS EOF callback-vtable dump unavailable: %s\n",
                                    path_error.c_str());
                            }
                            std::uint64_t callback_state{};
                            path_error.clear();
                            if (object <= UINT64_MAX - 0x10U && context->memory().read(
                                    object + 0x10U, pointer_bytes, path_error)) {
                                std::memcpy(&callback_state, pointer_bytes.data(),
                                    sizeof(callback_state));
                                std::fprintf(stderr,
                                    "FS EOF callback-object-state+10=0x%llx\n",
                                    static_cast<unsigned long long>(callback_state));
                                std::array<std::byte, 128> callback_state_bytes{};
                                path_error.clear();
                                if (callback_state != 0 && context->memory().read(
                                        callback_state, callback_state_bytes, path_error)) {
                                    std::fprintf(stderr,
                                        "FS EOF callback-object-state-target=");
                                    for (const auto byte : callback_state_bytes)
                                        std::fprintf(stderr, "%02x",
                                            std::to_integer<unsigned>(byte));
                                    std::fputc('\n', stderr);
                                } else if (callback_state != 0) {
                                    std::fprintf(stderr,
                                        "FS EOF callback-object-state-target unavailable: %s\n",
                                        path_error.c_str());
                                }
                            } else {
                                std::fprintf(stderr,
                                    "FS EOF callback-object-state+10 unavailable: %s\n",
                                    path_error.c_str());
                            }
                            std::array<std::byte, 128> method_code{};
                            path_error.clear();
                            if (method != 0 && context->memory().read(
                                    method, method_code, path_error)) {
                                std::fprintf(stderr, "FS EOF callback-method-c8-code=");
                                for (const auto byte : method_code)
                                    std::fprintf(stderr, "%02x",
                                        std::to_integer<unsigned>(byte));
                                std::fputc('\n', stderr);
                            } else {
                                std::fprintf(stderr,
                                    "FS EOF callback-method-c8-code unavailable: %s\n",
                                    path_error.c_str());
                            }
                        }
                    } else {
                        std::fprintf(stderr, "FS EOF callback-global unavailable: %s\n",
                            path_error.c_str());
                    }
                } else {
                    std::fprintf(stderr, "FS EOF guest-worker-callback-code unavailable: %s\n",
                        path_error.c_str());
                }
            }
            std::array<std::byte, 160> argument_bytes{};
            path_error.clear();
            if (guest_thread.argument != 0 && context->memory().read(
                    guest_thread.argument, argument_bytes, path_error)) {
                std::fprintf(stderr, "FS EOF guest-argument-bytes=");
                for (const auto byte : argument_bytes)
                    std::fprintf(stderr, "%02x", std::to_integer<unsigned>(byte));
                std::fputc('\n', stderr);
                std::uint64_t task_callback{};
                std::memcpy(&task_callback, argument_bytes.data() + 0x18U,
                    sizeof(task_callback));
                std::fprintf(stderr, "FS EOF task-callback=0x%llx\n",
                    static_cast<unsigned long long>(task_callback));
                std::array<std::byte, 384> task_callback_code{};
                path_error.clear();
                if (task_callback != 0 && context->memory().read(task_callback,
                        task_callback_code, path_error)) {
                    std::fprintf(stderr, "FS EOF task-callback-code=");
                    for (const auto byte : task_callback_code)
                        std::fprintf(stderr, "%02x", std::to_integer<unsigned>(byte));
                    std::fputc('\n', stderr);
                } else {
                    std::fprintf(stderr, "FS EOF task-callback-code unavailable: %s\n",
                        path_error.c_str());
                }
            } else {
                std::fprintf(stderr, "FS EOF guest-argument-bytes unavailable: %s\n",
                    path_error.c_str());
            }
        }
#if defined(_WIN32) && defined(NBA16_ENABLE_FS_EOF_INSTRUCTION_TRACE)
        if (trace_shader_entry) nba16_start_fs_eof_instruction_trace();
#endif
    }
    return static_cast<std::int64_t>(bytes_read);
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_kernel_pread_import(
    int descriptor, std::uint64_t buffer, std::uint64_t size, std::int64_t offset) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    std::size_t bytes_read{};
    if (!guest_pread(context->vfs(), context->descriptors(), context->memory(),
            descriptor, buffer, static_cast<std::size_t>(size), offset, bytes_read,
            error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    return static_cast<std::int64_t>(bytes_read);
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_kernel_write_import(
    int descriptor, std::uint64_t buffer, std::uint64_t size) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    std::size_t bytes_written{};
    if (!guest_write(context->vfs(), context->descriptors(), context->memory(),
            descriptor, buffer, static_cast<std::size_t>(size), bytes_written,
            error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    return static_cast<std::int64_t>(bytes_written);
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_kernel_pwrite_import(
    int descriptor, std::uint64_t buffer, std::uint64_t size, std::int64_t offset) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    std::size_t bytes_written{};
    if (!guest_pwrite(context->vfs(), context->descriptors(), context->memory(),
            descriptor, buffer, static_cast<std::size_t>(size), offset, bytes_written,
            error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    return static_cast<std::int64_t>(bytes_written);
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_kernel_lseek_import(
    int descriptor, std::int64_t offset, int whence) {
    const bool trace_seek = std::getenv("NBA16_TRACE_FS") != nullptr ||
                            std::getenv("NBA16_TRACE_FS_CALLER") != nullptr;
    const auto trace_event = trace_seek
        ? seek_trace_events.fetch_add(1, std::memory_order_relaxed) : 128U;
    const bool log_seek = trace_event < 1024;
    const auto thread_id = log_seek
        ? std::hash<std::thread::id>{}(std::this_thread::get_id()) : 0U;
    if (log_seek) std::fprintf(stderr,
        "FS syscall-lseek enter thread=%016llx fd=%d offset=%lld whence=%d\n",
        static_cast<unsigned long long>(thread_id), descriptor,
        static_cast<long long>(offset), whence);
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        if (log_seek) std::fprintf(stderr,
            "FS syscall-lseek rejected: process context unavailable\n");
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    std::uint64_t new_offset{};
    if (!guest_seek(context->descriptors(), descriptor, offset, whence,
            new_offset, error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        if (log_seek) std::fprintf(stderr,
            "FS syscall-lseek failed thread=%016llx fd=%d errno=%d detail='%s'\n",
            static_cast<unsigned long long>(thread_id), descriptor,
            static_cast<int>(failure), error.c_str());
        return -1;
    }
    if (log_seek) std::fprintf(stderr,
        "FS syscall-lseek result thread=%016llx fd=%d offset=%llu\n",
        static_cast<unsigned long long>(thread_id), descriptor,
        static_cast<unsigned long long>(new_offset));
    return static_cast<std::int64_t>(new_offset);
}

int NBA16_GUEST_SYSV_ABI guest_kernel_close_import(int descriptor) {
    const bool trace_close = std::getenv("NBA16_TRACE_FS") != nullptr;
    if (trace_close) std::fprintf(stderr, "FS syscall-close enter fd=%d\n", descriptor);
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    if (!guest_close(context->descriptors(), descriptor, error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        if (trace_close) std::fprintf(stderr,
            "FS syscall-close failed fd=%d errno=%d detail='%s'\n",
            descriptor, static_cast<int>(failure), error.c_str());
        return -1;
    }
    if (trace_close) std::fprintf(stderr, "FS syscall-close result fd=%d\n", descriptor);
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_fstatat_import(int directory_descriptor,
                                              std::uint64_t path,
                                              std::uint64_t output,
                                              int flags) {
    auto* context = current_guest_process_context();
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::string error;
    Ps4Errno failure{};
    if (!guest_fstatat_to_memory(context->vfs(), context->descriptors(),
            context->memory(), directory_descriptor, path, output, flags,
            error, &failure)) {
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    return 0;
}

std::int64_t NBA16_GUEST_SYSV_ABI guest_getdents_syscall(
    int descriptor, std::uint64_t buffer, std::size_t buffer_size) {
    auto* context = current_guest_process_context();
    const bool trace = std::getenv("NBA16_TRACE_FS") != nullptr;
    if (trace) {
        std::fprintf(stderr,
            "FS getdents enter fd=%d buffer=0x%llx size=%llu context=%p initialized=%d\n",
            descriptor, static_cast<unsigned long long>(buffer),
            static_cast<unsigned long long>(buffer_size), static_cast<void*>(context),
            context != nullptr && context->is_initialized() ? 1 : 0);
    }
    if (context == nullptr || !context->is_initialized()) {
        set_guest_errno(22);
        return -1;
    }
    std::size_t bytes_written{};
    std::string error;
    Ps4Errno failure{};
    if (!guest_getdents(context->vfs(), context->descriptors(), context->memory(),
            descriptor, buffer, buffer_size, bytes_written, error, &failure)) {
        if (trace) std::fprintf(stderr,
            "FS getdents failed fd=%d errno=%d detail='%s'\n",
            descriptor, static_cast<int>(failure), error.c_str());
        set_guest_errno(static_cast<int>(failure));
        return -1;
    }
    if (trace) std::fprintf(stderr, "FS getdents result fd=%d bytes=%zu\n",
                            descriptor, bytes_written);
    return static_cast<std::int64_t>(bytes_written);
}

} // namespace

bool register_native_posix_fs_imports(ImportResolver& resolver,
                                     std::string& error) {
    return resolver.register_function("libkernel", "libkernel", "ngZnQWyUvGI",
                                      &guest_statfs_import, error) &&
           resolver.register_function("libkernel", "libkernel", "+rWFNYiNaEM",
                                      &guest_fstatfs_import, error) &&
           resolver.register_function("libkernel", "libkernel", "Qsxbb+aty0U",
                                      &guest_getcwd_import, error) &&
           resolver.register_function("libkernel", "libkernel", "oc98+zOImus",
                                      &guest_pathconf_import, error) &&
           resolver.register_function("libkernel", "libkernel", "pd02UI9TbOA",
                                      &guest_readlink_import, error) &&
           resolver.register_function("libkernel", "libkernel", "6c3rCVE-fTU",
                                      &guest_open_import, error) &&
           resolver.register_function("libkernel", "libkernel", "1G3lF1Gg1k8",
                                      &guest_open_import, error) &&
           resolver.register_function("libkernel", "libkernel", "wuCroIGjt2g",
                                      &guest_open_import, error) &&
           resolver.register_function("libkernel", "libkernel", "PfccT7qURYE",
                                      &guest_ioctl_import, error) &&
           resolver.register_function("libkernel", "libkernel", "Cg4srZ6TKbU",
                                      &guest_kernel_read_import, error) &&
           resolver.register_function("libkernel", "libkernel", "+r3rMFwItV4",
                                      &guest_kernel_pread_import, error) &&
           resolver.register_function("libkernel", "libkernel", "4wSze92BhLI",
                                      &guest_kernel_write_import, error) &&
           resolver.register_function("libkernel", "libkernel", "nKWi-N2HBV4",
                                      &guest_kernel_pwrite_import, error) &&
           resolver.register_function("libkernel", "libkernel", "oib76F-12fk",
                                      &guest_kernel_lseek_import, error) &&
           resolver.register_function("libkernel", "libkernel", "UK2Tl2DWUns",
                                      &guest_kernel_close_import, error) &&
           resolver.register_function("libkernel", "libkernel", "A8Yk5AhNDck",
                                      &guest_openat_import, error) &&
           resolver.register_function("libkernel", "libkernel", "t6haf4s-eE0",
                                      &guest_fstatat_import, error) &&
           resolver.register_code_offset_interposition("libkernel.sprx", 0x9d0,
               static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(
                   &guest_fstat_syscall)), error) &&
           resolver.register_code_offset_interposition("libkernel.sprx", 0x11b0,
               static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(
                   &guest_getdents_syscall)), error);
}

} // namespace nba16
