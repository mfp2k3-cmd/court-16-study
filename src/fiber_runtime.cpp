#include "fiber_runtime.h"

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <new>

namespace nba16 {
namespace {

constexpr std::int32_t fiber_error_null = static_cast<std::int32_t>(0x80590001U);
constexpr std::int32_t fiber_error_alignment = static_cast<std::int32_t>(0x80590002U);
constexpr std::int32_t fiber_error_range = static_cast<std::int32_t>(0x80590003U);
constexpr std::int32_t fiber_error_invalid = static_cast<std::int32_t>(0x80590004U);
constexpr std::int32_t fiber_error_permission = static_cast<std::int32_t>(0x80590005U);
constexpr std::int32_t fiber_error_state = static_cast<std::int32_t>(0x80590006U);
constexpr std::uint64_t minimum_stack_size = 512;
constexpr std::uint64_t default_stack_size = 1024 * 1024;
constexpr std::uint64_t maximum_stack_size = 256 * 1024 * 1024;

extern "C" void NBA16_GUEST_SYSV_ABI nba16_fiber_swap_context(void* from, const void* to);
extern "C" [[noreturn]] void NBA16_GUEST_SYSV_ABI nba16_fiber_entry_trampoline();

[[noreturn]] void NBA16_GUEST_SYSV_ABI fiber_return_trap() {
    std::abort();
}

std::int32_t NBA16_GUEST_SYSV_ABI fiber_initialize_import(
    void* fiber, const char* name,
    GuestFunction<void, std::uint64_t, std::uint64_t> entry,
    std::uint64_t argument_on_initialize, void* stack, std::uint64_t stack_size,
    const void* options, std::uint32_t build_version) {
    return FiberRuntime::instance().initialize(fiber, name, entry,
        argument_on_initialize, stack, stack_size, options, build_version);
}

std::int32_t NBA16_GUEST_SYSV_ABI fiber_finalize_import(void* fiber) {
    return FiberRuntime::instance().finalize(fiber);
}

std::int32_t NBA16_GUEST_SYSV_ABI fiber_run_import(
    void* fiber, std::uint64_t argument_on_run, std::uint64_t* argument_on_return) {
    return FiberRuntime::instance().run(fiber, argument_on_run, argument_on_return);
}

std::int32_t NBA16_GUEST_SYSV_ABI fiber_return_to_thread_import(
    std::uint64_t argument_on_return, std::uint64_t* argument_on_run) {
    return FiberRuntime::instance().return_to_thread(argument_on_return, argument_on_run);
}

} // namespace

FiberRuntime& FiberRuntime::instance() {
    static FiberRuntime runtime;
    return runtime;
}

FiberRuntime::ThreadContext& FiberRuntime::thread_context() {
    thread_local ThreadContext context;
    return context;
}

std::shared_ptr<FiberRuntime::Fiber> FiberRuntime::find(void* fiber) const {
    std::lock_guard lock(mutex_);
    const auto found = fibers_.find(fiber);
    return found == fibers_.end() ? nullptr : found->second;
}

std::int32_t FiberRuntime::initialize(
    void* fiber, const char* name,
    GuestFunction<void, std::uint64_t, std::uint64_t> entry,
    std::uint64_t argument_on_initialize, void* stack, std::uint64_t stack_size,
    const void* options, std::uint32_t build_version) {
    static_assert(offsetof(GuestCpuContext, stack_pointer) == 0);
    static_assert(offsetof(GuestCpuContext, rbx) == 8);
    static_assert(offsetof(GuestCpuContext, r15) == 48);
    static_assert(sizeof(GuestCpuContext) == 56);
    (void)name;
    (void)options;
    (void)build_version;
    if (fiber == nullptr || name == nullptr || entry == nullptr) return fiber_error_null;
    if ((reinterpret_cast<std::uintptr_t>(fiber) & 7U) != 0 ||
        (stack != nullptr && (reinterpret_cast<std::uintptr_t>(stack) & 15U) != 0) ||
        (options != nullptr && (reinterpret_cast<std::uintptr_t>(options) & 7U) != 0)) {
        return fiber_error_alignment;
    }
    if ((stack == nullptr) != (stack_size == 0)) return fiber_error_invalid;
    if (stack_size != 0 && (stack_size < minimum_stack_size || (stack_size & 15U) != 0)) {
        return fiber_error_invalid;
    }
    if (stack_size > maximum_stack_size || stack_size > std::numeric_limits<std::size_t>::max()) {
        return fiber_error_range;
    }

    auto created = std::make_shared<Fiber>();
    created->guest_handle = fiber;
    created->entry = entry;
    created->argument_on_initialize = argument_on_initialize;
    if (stack == nullptr) {
        try {
            created->owned_stack.resize(static_cast<std::size_t>(default_stack_size));
        } catch (const std::bad_alloc&) {
            return fiber_error_range;
        }
        created->stack = reinterpret_cast<std::uint8_t*>(created->owned_stack.data());
        created->stack_size = created->owned_stack.size();
    } else {
        created->stack = static_cast<std::uint8_t*>(stack);
        created->stack_size = static_cast<std::size_t>(stack_size);
    }

    const auto stack_begin = reinterpret_cast<std::uintptr_t>(created->stack);
    if (created->stack_size > std::numeric_limits<std::uintptr_t>::max() - stack_begin) {
        return fiber_error_range;
    }
    const auto stack_top = (stack_begin + created->stack_size) & ~std::uintptr_t{15};
    if (stack_top < stack_begin || stack_top - stack_begin < 32) return fiber_error_range;
    auto* initial_stack = reinterpret_cast<std::uint64_t*>(stack_top - 16);
    initial_stack[0] = reinterpret_cast<std::uintptr_t>(&nba16_fiber_entry_trampoline);
    initial_stack[1] = reinterpret_cast<std::uintptr_t>(&fiber_return_trap);
    created->cpu.stack_pointer = reinterpret_cast<std::uintptr_t>(initial_stack);

    std::lock_guard lock(mutex_);
    if (fibers_.contains(fiber)) return fiber_error_state;
    fibers_.emplace(fiber, std::move(created));
    return 0;
}

std::int32_t FiberRuntime::finalize(void* fiber) {
    if (fiber == nullptr) return fiber_error_null;
    if ((reinterpret_cast<std::uintptr_t>(fiber) & 7U) != 0) return fiber_error_alignment;
    std::lock_guard lock(mutex_);
    const auto found = fibers_.find(fiber);
    if (found == fibers_.end()) return fiber_error_invalid;
    if (found->second->state == State::running || found->second->state == State::suspended) {
        return fiber_error_state;
    }
    fibers_.erase(found);
    return 0;
}

std::int32_t FiberRuntime::switch_to(Fiber& target, std::uint64_t argument_on_run,
                                     std::uint64_t* argument_on_return) {
    auto& thread = thread_context();
    auto* source = thread.current;
    {
        std::lock_guard lock(mutex_);
        const auto registered = fibers_.find(target.guest_handle);
        if (registered == fibers_.end() || registered->second.get() != &target) {
            return fiber_error_invalid;
        }
        if (source == &target || target.state == State::finished || target.state == State::running) {
            return fiber_error_state;
        }
        const auto current_thread = std::this_thread::get_id();
        if (target.owner_thread != std::thread::id{} && target.owner_thread != current_thread) {
            return fiber_error_permission;
        }
        target.owner_thread = current_thread;
        target.previous = source;
        target.argument_on_run = argument_on_run;
        target.state = State::running;
        if (source != nullptr) source->state = State::suspended;
        else thread.argument_on_return = 0;
    }
    thread.current = &target;

    auto* source_context = source != nullptr ? static_cast<void*>(&source->cpu)
                                             : static_cast<void*>(&thread.root);
    nba16_fiber_swap_context(source_context, &target.cpu);

    thread.current = source;
    if (source != nullptr) {
        {
            std::lock_guard lock(mutex_);
            source->state = State::running;
        }
        if (argument_on_return != nullptr) *argument_on_return = source->argument_on_run;
    } else if (argument_on_return != nullptr) {
        *argument_on_return = thread.argument_on_return;
    }
    return 0;
}

std::int32_t FiberRuntime::run(void* fiber, std::uint64_t argument_on_run,
                               std::uint64_t* argument_on_return) {
    if (fiber == nullptr) return fiber_error_null;
    if ((argument_on_return != nullptr &&
         (reinterpret_cast<std::uintptr_t>(argument_on_return) & 7U) != 0)) {
        return fiber_error_alignment;
    }
    auto target = find(fiber);
    if (!target) return fiber_error_invalid;
    return switch_to(*target, argument_on_run, argument_on_return);
}

std::int32_t FiberRuntime::return_to_thread(std::uint64_t argument_on_return,
                                           std::uint64_t* argument_on_run) {
    if (argument_on_run != nullptr &&
        (reinterpret_cast<std::uintptr_t>(argument_on_run) & 7U) != 0) {
        return fiber_error_alignment;
    }
    auto& thread = thread_context();
    auto* source = thread.current;
    if (source == nullptr) return fiber_error_permission;
    {
        std::lock_guard lock(mutex_);
        source->state = State::suspended;
    }
    thread.argument_on_return = argument_on_return;
    thread.current = nullptr;
    nba16_fiber_swap_context(&source->cpu, &thread.root);

    thread.current = source;
    {
        std::lock_guard lock(mutex_);
        source->state = State::running;
    }
    if (argument_on_run != nullptr) *argument_on_run = source->argument_on_run;
    return 0;
}

[[noreturn]] void FiberRuntime::enter_current_fiber() {
    auto& thread = thread_context();
    auto* current = thread.current;
    if (current == nullptr || current->entry == nullptr) std::abort();
    current->started = true;
    current->entry(current->argument_on_initialize, current->argument_on_run);
    finish_current();
}

[[noreturn]] void FiberRuntime::finish_current() {
    auto& thread = thread_context();
    auto* current = thread.current;
    if (current == nullptr) std::abort();
    auto* previous = current->previous;
    {
        std::lock_guard lock(mutex_);
        current->state = State::finished;
        if (previous != nullptr) previous->state = State::running;
    }
    if (previous != nullptr) {
        previous->argument_on_run = 0;
        thread.current = previous;
        nba16_fiber_swap_context(&current->cpu, &previous->cpu);
    } else {
        thread.argument_on_return = 0;
        thread.current = nullptr;
        nba16_fiber_swap_context(&current->cpu, &thread.root);
    }
    std::abort();
}

extern "C" [[noreturn]] void NBA16_GUEST_SYSV_ABI nba16_fiber_entry_trampoline() {
    FiberRuntime::instance().enter_current_fiber();
}

bool register_native_fiber_imports(ImportResolver& resolver, std::string& error) {
    if (!guest_sysv_abi_available) {
        error = "A ABI SysV x86-64 é necessária para registrar libSceFiber.";
        return false;
    }
    return resolver.register_function("libSceFiber", "libSceFiber", "hVYD7Ou2pCQ",
                                      &fiber_initialize_import, error) &&
           resolver.register_function("libSceFiber", "libSceFiber", "JeNX5F-NzQU",
                                      &fiber_finalize_import, error) &&
           resolver.register_function("libSceFiber", "libSceFiber", "a0LLrZWac0M",
                                      &fiber_run_import, error) &&
           resolver.register_function("libSceFiber", "libSceFiber", "B0ZX2hx9DMw",
                                      &fiber_return_to_thread_import, error);
}

} // namespace nba16
