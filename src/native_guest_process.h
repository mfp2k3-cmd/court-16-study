#pragma once

#include "guest_execution_stack.h"
#include "guest_process_context.h"
#include "native_process_image.h"
#include "native_runtime_paths.h"

#include <cstddef>
#include <string>

namespace nba16 {

// Owns the per-run guest stack, VFS and address-space view. Preparation does
// not invoke module initializers or the game's entry point.
class NativeGuestProcess {
public:
    NativeGuestProcess() = default;
    NativeGuestProcess(const NativeGuestProcess&) = delete;
    NativeGuestProcess& operator=(const NativeGuestProcess&) = delete;

    bool initialize(const NativeRuntimePaths& paths,
                    const NativeExecutableImage& executable,
                    const NativeProcessModules& modules,
                    std::size_t stack_size,
                    std::string& error);

    [[nodiscard]] GuestExecutionStack& stack() noexcept;
    [[nodiscard]] GuestProcessContext& context() noexcept;
    [[nodiscard]] bool is_initialized() const noexcept;

private:
    GuestExecutionStack stack_;
    GuestProcessContext context_;
    bool initialized_{};
};

} // namespace nba16
