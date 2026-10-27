#pragma once

#include "vulkan_presenter.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace nba16 {

// Owns the SDL/Vulkan window on the host thread. Guest services can later
// route VideoOut flips through this owner without creating a second window.
class NativeWindowHost {
public:
    bool initialize(const char* title, std::uint32_t width, std::uint32_t height,
                    std::string& error);
    bool pump_events(bool& should_close, std::string& error);
    bool present_clear(const std::array<float, 4>& color, std::string& error);
    bool present_rgba8(std::span<const std::byte> pixels, std::uint32_t width,
                       std::uint32_t height, std::uint32_t pitch, std::string& error);
    bool present_bgra8(std::span<const std::byte> pixels, std::uint32_t width,
                       std::uint32_t height, std::uint32_t pitch, std::string& error);
    void shutdown() noexcept;

private:
    VulkanPresenter presenter_;
    bool initialized_{};
};

} // namespace nba16
