#pragma once

#include "import_resolver.h"

#include <cstdint>
#include <cstddef>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace nba16 {

class FiberRuntime {
public:
    static FiberRuntime& instance();

    std::int32_t initialize(void* fiber, const char* name,
                            GuestFunction<void, std::uint64_t, std::uint64_t> entry,
                            std::uint64_t argument_on_initialize, void* stack,
                            std::uint64_t stack_size, const void* options,
                            std::uint32_t build_version);
    std::int32_t finalize(void* fiber);
    std::int32_t run(void* fiber, std::uint64_t argument_on_run,
                     std::uint64_t* argument_on_return);
    std::int32_t return_to_thread(std::uint64_t argument_on_return,
                                  std::uint64_t* argument_on_run);
    [[noreturn]] void enter_current_fiber();

private:
    struct GuestCpuContext {
        std::uint64_t stack_pointer{};
        std::uint64_t rbx{};
        std::uint64_t rbp{};
        std::uint64_t r12{};
        std::uint64_t r13{};
        std::uint64_t r14{};
        std::uint64_t r15{};
    };

    struct Fiber;
    struct ThreadContext {
        GuestCpuContext root;
        Fiber* current{};
        std::uint64_t argument_on_return{};
    };

    enum class State : std::uint8_t { ready, running, suspended, finished };
    struct Fiber {
        void* guest_handle{};
        GuestFunction<void, std::uint64_t, std::uint64_t> entry{};
        std::uint64_t argument_on_initialize{};
        std::uint64_t argument_on_run{};
        std::uint8_t* stack{};
        std::size_t stack_size{};
        GuestCpuContext cpu;
        std::vector<std::byte> owned_stack;
        Fiber* previous{};
        std::thread::id owner_thread;
        State state{State::ready};
        bool started{};
    };

    std::shared_ptr<Fiber> find(void* fiber) const;
    static ThreadContext& thread_context();
    std::int32_t switch_to(Fiber& target, std::uint64_t argument_on_run,
                           std::uint64_t* argument_on_return);
    [[noreturn]] void finish_current();

    mutable std::mutex mutex_;
    std::unordered_map<void*, std::shared_ptr<Fiber>> fibers_;
};

bool register_native_fiber_imports(ImportResolver& resolver, std::string& error);

} // namespace nba16
