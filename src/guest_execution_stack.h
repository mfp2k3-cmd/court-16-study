#pragma once

#include <cstddef>
#include <string>

namespace nba16 {

// Owns a writable stack for calling PS4 guest code outside the host stack.
class GuestExecutionStack {
public:
    GuestExecutionStack() = default;
    ~GuestExecutionStack();
    GuestExecutionStack(const GuestExecutionStack&) = delete;
    GuestExecutionStack& operator=(const GuestExecutionStack&) = delete;
    GuestExecutionStack(GuestExecutionStack&& other) noexcept;
    GuestExecutionStack& operator=(GuestExecutionStack&& other) noexcept;

    bool reserve(std::size_t size, std::string& error);
    [[nodiscard]] void* bottom() const noexcept;
    [[nodiscard]] void* top() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    void release() noexcept;
    void* allocation_{};
    std::size_t allocation_size_{};
};

} // namespace nba16
