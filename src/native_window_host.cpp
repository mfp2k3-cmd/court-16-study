#include "native_window_host.h"

namespace nba16 {

bool NativeWindowHost::initialize(const char* title, std::uint32_t width,
                                  std::uint32_t height, std::string& error) {
    shutdown();
    initialized_ = presenter_.create(title, width, height, error);
    return initialized_;
}

bool NativeWindowHost::pump_events(bool& should_close, std::string& error) {
    if (!initialized_) {
        error = "O host de janela ainda não foi inicializado.";
        return false;
    }
    return presenter_.poll_events(should_close, error);
}

bool NativeWindowHost::present_clear(const std::array<float, 4>& color,
                                     std::string& error) {
    if (!initialized_) {
        error = "O host de janela ainda não foi inicializado.";
        return false;
    }
    return presenter_.present_clear(color, error);
}

bool NativeWindowHost::present_rgba8(std::span<const std::byte> pixels,
                                     std::uint32_t width, std::uint32_t height,
                                     std::uint32_t pitch, std::string& error) {
    if (!initialized_) {
        error = "O host de janela ainda não foi inicializado.";
        return false;
    }
    return presenter_.present_rgba8(pixels, width, height, pitch, error);
}

bool NativeWindowHost::present_bgra8(std::span<const std::byte> pixels,
                                     std::uint32_t width, std::uint32_t height,
                                     std::uint32_t pitch, std::string& error) {
    if (!initialized_) {
        error = "O host de janela ainda não foi inicializado.";
        return false;
    }
    return presenter_.present_bgra8(pixels, width, height, pitch, error);
}

void NativeWindowHost::shutdown() noexcept {
    presenter_.shutdown();
    initialized_ = false;
}

} // namespace nba16
