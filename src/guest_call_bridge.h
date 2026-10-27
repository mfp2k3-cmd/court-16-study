#pragma once

#include "guest_abi.h"
#include "guest_image_map.h"
#include "guest_image_memory.h"
#include "guest_process_context.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <exception>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace nba16 {

#ifdef _WIN32
using GuestFiberCallback = void (*)(void*);
inline thread_local void* nba16_guest_active_return_fiber{};
extern "C" inline void nba16_guest_run_on_fiber(GuestFiberCallback callback,
                                                  void* context) {
    struct FiberCall {
        GuestFiberCallback callback;
        void* context;
        void* return_fiber;
    } call{callback, context, nullptr};
    const bool converted_thread = IsThreadAFiber() == FALSE;
    void* caller_fiber = converted_thread
        ? ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH)
        : GetCurrentFiber();
    if (caller_fiber == nullptr) std::terminate();
    call.return_fiber = caller_fiber;
    const auto guest_fiber = CreateFiberEx(64U * 1024U, 16U * 1024U * 1024U,
        FIBER_FLAG_FLOAT_SWITCH,
        [](void* parameter) {
            const auto* invocation = static_cast<FiberCall*>(parameter);
            if (auto* process = current_guest_process_context()) {
                ULONG_PTR stack_low{};
                ULONG_PTR stack_high{};
                GetCurrentThreadStackLimits(&stack_low, &stack_high);
                std::string stack_error;
                if (stack_high > stack_low && !process->memory().add_host_region(
                        static_cast<std::uint64_t>(stack_low),
                        static_cast<std::size_t>(stack_high - stack_low), stack_error)) {
                    std::fprintf(stderr, "Guest fiber stack registration failed: %s\n",
                                 stack_error.c_str());
                }
            }
            invocation->callback(invocation->context);
            SwitchToFiber(invocation->return_fiber);
        }, &call);
    if (guest_fiber == nullptr) {
        if (converted_thread) ConvertFiberToThread();
        std::terminate();
    }
    void* previous_return_fiber = nba16_guest_active_return_fiber;
    nba16_guest_active_return_fiber = caller_fiber;
    SwitchToFiber(guest_fiber);
    nba16_guest_active_return_fiber = previous_return_fiber;
    DeleteFiber(guest_fiber);
    if (converted_thread) ConvertFiberToThread();
}
[[noreturn]] inline void nba16_guest_return_to_caller_fiber() {
    if (nba16_guest_active_return_fiber != nullptr)
        SwitchToFiber(nba16_guest_active_return_fiber);
    std::terminate();
}
extern "C" void nba16_guest_jump_to_entry(void* entry, void* parameters,
    void* exit_function, void* argv, std::uint64_t argc, void* stack_top);
extern "C" inline void nba16_guest_run_process_entry(void* entry,
    void* parameters, void* exit_function, void* argv, std::uint64_t argc) {
    struct Invocation {
        void* entry;
        void* parameters;
        void* exit_function;
        void* argv;
        std::uint64_t argc;
    } invocation{entry, parameters, exit_function, argv, argc};
    nba16_guest_run_on_fiber([](void* opaque) {
        auto& start = *static_cast<Invocation*>(opaque);
        ULONG_PTR stack_low{};
        ULONG_PTR stack_high{};
        GetCurrentThreadStackLimits(&stack_low, &stack_high);
        if (stack_high <= stack_low + 0x1000U) std::terminate();
        nba16_guest_jump_to_entry(start.entry, start.parameters,
            start.exit_function, start.argv, start.argc,
            reinterpret_cast<void*>(stack_high - 0x1000U));
    }, &invocation);
}
extern "C" inline void nba16_guest_call_void_on_stack(void* raw_function, void* stack_top) {
    (void)stack_top;
    nba16_guest_run_on_fiber([](void* function) {
        reinterpret_cast<GuestEntryPoint>(function)();
    }, raw_function);
}
#else
extern "C" void nba16_guest_call_void_on_stack(void* function, void* stack_top);
#endif

// Converts an explicitly typed PS4 SysV function address into the reserved host
// image. This bridge is deliberately opt-in; constructing it never executes code.
class GuestCallBridge {
public:
    GuestCallBridge(const GuestImageMap& map, const GuestImageMemory& memory,
                    GuestProcessContext* context = nullptr,
                    void* guest_stack_top = nullptr) noexcept
        : map_(map), memory_(memory), context_(context), guest_stack_top_(guest_stack_top) {}

    template <typename Return, typename... Arguments>
    bool call(std::uint64_t guest_address, Return& result, std::string& error,
              Arguments... arguments) const {
        static_assert(!std::is_void_v<Return>, "Use call_void for void guest functions.");
        static_assert(std::is_trivially_copyable_v<Return>,
                      "Guest return value must be trivially copyable.");
        GuestFunction<Return, Arguments...> function{};
        if (!resolve(guest_address, function, error)) return false;
        ScopedGuestProcessContext process_scope(context_);
#ifdef _WIN32
        if (guest_stack_top_ != nullptr) {
            struct Invocation {
                GuestFunction<Return, Arguments...> function;
                Return* result;
                std::tuple<Arguments...> arguments;
            } invocation{function, &result, std::tuple<Arguments...>(arguments...)};
            nba16_guest_run_on_fiber([](void* opaque) {
                auto& call = *static_cast<Invocation*>(opaque);
                *call.result = std::apply(call.function, call.arguments);
            }, &invocation);
            return true;
        }
#endif
        result = function(arguments...);
        return true;
    }

    template <typename... Arguments>
    bool call_void(std::uint64_t guest_address, std::string& error,
                   Arguments... arguments) const {
        GuestFunction<void, Arguments...> function{};
        if (!resolve(guest_address, function, error)) return false;
        ScopedGuestProcessContext process_scope(context_);
#ifdef _WIN32
        if (guest_stack_top_ != nullptr) {
            struct Invocation {
                GuestFunction<void, Arguments...> function;
                std::tuple<Arguments...> arguments;
            } invocation{function, std::tuple<Arguments...>(arguments...)};
            nba16_guest_run_on_fiber([](void* opaque) {
                auto& call = *static_cast<Invocation*>(opaque);
                std::apply(call.function, call.arguments);
            }, &invocation);
            return true;
        }
#endif
        if (guest_stack_top_ != nullptr && sizeof...(Arguments) == 0) {
            nba16_guest_call_void_on_stack(reinterpret_cast<void*>(function), guest_stack_top_);
        } else {
            function(arguments...);
        }
        return true;
    }

private:
    template <typename Function>
    bool resolve(std::uint64_t guest_address, Function& function, std::string& error) const {
        static_assert(is_guest_function_pointer_v<Function>);
        if constexpr (!guest_sysv_abi_available) {
            error = "O compilador/arquitetura atual não oferece chamadas diretas com ABI SysV x86-64.";
            return false;
        }
        if (!memory_.is_reserved() || !memory_.is_finalized() ||
            !map_.relative_relocations_applied || !map_.imported_relocations_applied) {
            error = "A imagem precisa estar carregada, relocada e protegida antes de chamar código convidado.";
            return false;
        }
        if (guest_address > std::numeric_limits<std::uint64_t>::max() - memory_.load_bias()) {
            error = "Endereço convidado excede o espaço virtual do host.";
            return false;
        }
        const auto runtime_address = memory_.load_bias() + guest_address;
        if (!validate_guest_execute_access(map_, runtime_address, 1, error)) return false;
        auto* host_address = memory_.translate_executable(map_, runtime_address, 1, error);
        if (host_address == nullptr) return false;
        function = reinterpret_cast<Function>(host_address);
        return true;
    }

    const GuestImageMap& map_;
    const GuestImageMemory& memory_;
    GuestProcessContext* context_{};
    void* guest_stack_top_{};
};

} // namespace nba16
