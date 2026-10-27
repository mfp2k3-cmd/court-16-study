#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace nba16 {

class VulkanPresenter {
public:
    VulkanPresenter();
    ~VulkanPresenter();
    VulkanPresenter(const VulkanPresenter&) = delete;
    VulkanPresenter& operator=(const VulkanPresenter&) = delete;
    VulkanPresenter(VulkanPresenter&&) noexcept;
    VulkanPresenter& operator=(VulkanPresenter&&) noexcept;

    bool create(const char* title, std::uint32_t width, std::uint32_t height,
                std::string& error);
    bool poll_events(bool& should_close, std::string& error);
    bool present_clear(const std::array<float, 4>& color, std::string& error);
    bool present_rgba8(std::span<const std::byte> pixels, std::uint32_t width,
                       std::uint32_t height, std::uint32_t pitch, std::string& error);
    bool present_bgra8(std::span<const std::byte> pixels, std::uint32_t width,
                       std::uint32_t height, std::uint32_t pitch, std::string& error);
    void shutdown() noexcept;

private:
    bool present_4byte_pixels(std::span<const std::byte> pixels, std::uint32_t width,
                              std::uint32_t height, std::uint32_t pitch,
                              bool source_bgra, std::string& error);
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace nba16
