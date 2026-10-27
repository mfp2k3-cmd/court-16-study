#include "pad_runtime.h"

#include "guest_image_memory.h"
#include "guest_process_context.h"

#include <SDL3/SDL_events.h>
#include <SDL3/SDL_gamepad.h>
#include <SDL3/SDL_init.h>
#include <SDL3/SDL_joystick.h>
#include <SDL3/SDL_stdinc.h>
#include <SDL3/SDL_timer.h>
#include <SDL3/SDL_haptic.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <span>
#include <type_traits>
#include <vector>

namespace nba16 {
namespace {

constexpr std::int32_t ok = 0;
constexpr std::int32_t pad_invalid_argument = static_cast<std::int32_t>(0x80920001U);
constexpr std::int32_t pad_invalid_port = static_cast<std::int32_t>(0x80920002U);
constexpr std::int32_t pad_invalid_handle = static_cast<std::int32_t>(0x80920003U);
constexpr std::int32_t pad_already_opened = static_cast<std::int32_t>(0x80920004U);
constexpr std::int32_t pad_not_initialized = static_cast<std::int32_t>(0x80920005U);
constexpr std::int32_t pad_invalid_lightbar = static_cast<std::int32_t>(0x80920006U);
constexpr std::int32_t pad_not_connected = static_cast<std::int32_t>(0x80920007U);
constexpr std::int32_t device_invalid_user = static_cast<std::int32_t>(0x809b0001U);
constexpr std::int32_t device_user_not_logged_in = static_cast<std::int32_t>(0x809b0081U);
constexpr std::int32_t first_handle = 1;
constexpr std::int32_t default_user_id = 1000;
constexpr std::int32_t standard_port = 0;
constexpr std::int32_t special_port = 2;

struct Quaternion { float x{}, y{}, z{}, w{1.0F}; };
struct Vector3 { float x{}, y{}, z{}; };
struct AnalogStick { std::uint8_t x{128}, y{128}; };
struct AnalogButtons { std::uint8_t l2{}, r2{}, padding[2]{}; };
struct Touch { std::uint16_t x{}, y{}; std::uint8_t id{}, reserve[3]{}; };
struct TouchData {
    std::uint8_t count{}, reserve[3]{};
    std::uint32_t time_since_held{};
    Touch touch[2]{};
};
struct ExtensionData {
    std::uint32_t id{};
    std::uint8_t reserve{}, length{}, data[10]{};
};
struct PadData {
    std::uint32_t buttons{};
    AnalogStick left_stick{}, right_stick{};
    AnalogButtons analog_buttons{};
    Quaternion orientation{};
    Vector3 acceleration{}, angular_velocity{};
    TouchData touch{};
    bool connected{};
    std::uint64_t timestamp{};
    ExtensionData extension{};
    std::uint8_t connected_count{}, reserve[2]{}, unique_data_length{}, unique_data[12]{};
};
struct PadControllerInformation {
    float touch_pixel_density{};
    std::uint16_t touch_width{}, touch_height{};
    std::uint8_t left_dead_zone{}, right_dead_zone{}, connection_type{}, connected_count{};
    bool connected{};
    std::uint8_t alignment_padding[3]{};
    std::int32_t device_class{};
    std::uint8_t reserve[8]{};
};
struct LightBarParam { std::uint8_t r{}, g{}, b{}, reserve{}; };
struct VibrationParam { std::uint8_t large_motor{}, small_motor{}; };

static_assert(std::is_trivially_copyable_v<PadData>);
static_assert(offsetof(PadData, timestamp) == 80);
static_assert(offsetof(PadData, extension) == 88);
static_assert(sizeof(PadData) == 120);
static_assert(sizeof(PadControllerInformation) == 28);

struct PadSession {
    std::int32_t user_id{};
    std::int32_t port_type{};
    std::int32_t index{};
    SDL_Gamepad* gamepad{};
};

std::mutex pad_mutex;
bool pad_initialized{};
std::int32_t next_handle{first_handle};
std::map<std::int32_t, PadSession> sessions;

GuestProcessContext* process_context() noexcept {
    return current_guest_process_context();
}

template <typename T>
bool read_guest_value(std::uint64_t address, T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    auto* context = process_context();
    if (context == nullptr || address == 0) return false;
    std::string error;
    return context->memory().read(address,
        std::span<std::byte>(reinterpret_cast<std::byte*>(&value), sizeof(value)), error);
}

template <typename T>
bool write_guest_value(std::uint64_t address, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    auto* context = process_context();
    if (context == nullptr || address == 0) return false;
    std::string error;
    return context->memory().write(address,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), sizeof(value)), error);
}

std::uint8_t stick_axis(Sint16 value) noexcept {
    const auto shifted = static_cast<std::int32_t>(value) + 32768;
    return static_cast<std::uint8_t>((shifted * 255 + 32767) / 65535);
}

std::uint8_t trigger_axis(Sint16 value) noexcept {
    const auto clamped = std::clamp<std::int32_t>(value, 0, 32767);
    return static_cast<std::uint8_t>((clamped * 255 + 16383) / 32767);
}

bool button(SDL_Gamepad* gamepad, SDL_GamepadButton value) noexcept {
    return SDL_GetGamepadButton(gamepad, value);
}

PadData read_state(SDL_Gamepad* gamepad) {
    SDL_PumpEvents();
    PadData state{};
    if (gamepad == nullptr || !SDL_GamepadConnected(gamepad)) {
        state.orientation.w = 1.0F;
        state.timestamp = SDL_GetTicksNS();
        return state;
    }
    const auto set = [&state, gamepad](SDL_GamepadButton host_button,
                                       std::uint32_t guest_button) {
        if (button(gamepad, host_button)) state.buttons |= guest_button;
    };
    set(SDL_GAMEPAD_BUTTON_LEFT_STICK, 0x00000002U);
    set(SDL_GAMEPAD_BUTTON_RIGHT_STICK, 0x00000004U);
    set(SDL_GAMEPAD_BUTTON_START, 0x00000008U);
    set(SDL_GAMEPAD_BUTTON_DPAD_UP, 0x00000010U);
    set(SDL_GAMEPAD_BUTTON_DPAD_RIGHT, 0x00000020U);
    set(SDL_GAMEPAD_BUTTON_DPAD_DOWN, 0x00000040U);
    set(SDL_GAMEPAD_BUTTON_DPAD_LEFT, 0x00000080U);
    set(SDL_GAMEPAD_BUTTON_LEFT_SHOULDER, 0x00000400U);
    set(SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER, 0x00000800U);
    set(SDL_GAMEPAD_BUTTON_NORTH, 0x00001000U);
    set(SDL_GAMEPAD_BUTTON_EAST, 0x00002000U);
    set(SDL_GAMEPAD_BUTTON_SOUTH, 0x00004000U);
    set(SDL_GAMEPAD_BUTTON_WEST, 0x00008000U);
    set(SDL_GAMEPAD_BUTTON_MISC1, 0x00100000U);
    state.left_stick.x = stick_axis(SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_LEFTX));
    state.left_stick.y = stick_axis(SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_LEFTY));
    state.right_stick.x = stick_axis(SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_RIGHTX));
    state.right_stick.y = stick_axis(SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_RIGHTY));
    state.analog_buttons.l2 = trigger_axis(SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_LEFT_TRIGGER));
    state.analog_buttons.r2 = trigger_axis(SDL_GetGamepadAxis(gamepad, SDL_GAMEPAD_AXIS_RIGHT_TRIGGER));
    if (state.analog_buttons.l2 != 0) state.buttons |= 0x00000100U;
    if (state.analog_buttons.r2 != 0) state.buttons |= 0x00000200U;
    state.orientation.w = 1.0F;
    state.connected = SDL_GamepadConnected(gamepad);
    state.connected_count = state.connected ? 1U : 0U;
    state.timestamp = SDL_GetTicksNS();
    return state;
}

std::map<std::int32_t, PadSession>::iterator find_session(std::int32_t handle) {
    return sessions.find(handle);
}

void refresh_gamepad(PadSession& session) {
    if (session.gamepad != nullptr) {
        if (SDL_GamepadConnected(session.gamepad)) return;
        SDL_CloseGamepad(session.gamepad);
        session.gamepad = nullptr;
    }
    int count{};
    SDL_JoystickID* ids = SDL_GetGamepads(&count);
    if (ids == nullptr) return;
    if (session.index < count) session.gamepad = SDL_OpenGamepad(ids[session.index]);
    SDL_free(ids);
}

std::int32_t NBA16_GUEST_SYSV_ABI pad_init() {
    std::lock_guard lock(pad_mutex);
    if (pad_initialized) return ok;
    if (!SDL_InitSubSystem(SDL_INIT_GAMEPAD)) return pad_not_connected;
    pad_initialized = true;
    return ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI pad_open(std::int32_t user_id, std::int32_t port_type,
                                          std::int32_t index, std::uint64_t) {
    std::lock_guard lock(pad_mutex);
    if (!pad_initialized) return pad_not_initialized;
    if (user_id < 0) return device_invalid_user;
    if (user_id != default_user_id) return device_user_not_logged_in;
    if ((port_type != standard_port && port_type != special_port) || index < 0)
        return pad_invalid_port;
    for (const auto& [handle, session] : sessions) {
        if (session.user_id == user_id && session.port_type == port_type &&
            session.index == index) return pad_already_opened;
        (void)handle;
    }

    if (next_handle <= 0 || next_handle == std::numeric_limits<std::int32_t>::max())
        next_handle = first_handle;
    const auto handle = next_handle++;
    auto [it, inserted] = sessions.emplace(handle, PadSession{user_id, port_type, index, nullptr});
    (void)inserted;
    refresh_gamepad(it->second);
    return handle;
}

std::int32_t NBA16_GUEST_SYSV_ABI pad_close(std::int32_t handle) {
    std::lock_guard lock(pad_mutex);
    auto it = find_session(handle);
    if (it == sessions.end()) return pad_invalid_handle;
    if (it->second.gamepad != nullptr) SDL_CloseGamepad(it->second.gamepad);
    sessions.erase(it);
    return ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI pad_read(std::int32_t handle,
                                           std::uint64_t guest_data,
                                           std::int32_t count) {
    if (count < 1 || count > 64 || guest_data == 0 || process_context() == nullptr)
        return pad_invalid_argument;
    std::lock_guard lock(pad_mutex);
    if (!pad_initialized) return pad_not_initialized;
    auto it = find_session(handle);
    if (it == sessions.end()) return pad_invalid_handle;
    refresh_gamepad(it->second);
    const PadData current = read_state(it->second.gamepad);
    std::vector<PadData> states(static_cast<std::size_t>(count), current);
    auto* context = process_context();
    std::string error;
    const auto bytes = std::as_bytes(std::span<const PadData>(states));
    if (!context->memory().write(guest_data, bytes, error)) return pad_invalid_argument;
    return count;
}

std::int32_t NBA16_GUEST_SYSV_ABI pad_read_state(std::int32_t handle,
                                                 std::uint64_t guest_data) {
    const auto result = pad_read(handle, guest_data, 1);
    return result < 0 ? result : ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI pad_get_controller_information(
    std::int32_t handle, std::uint64_t guest_information) {
    if (guest_information == 0 || process_context() == nullptr) return pad_invalid_argument;
    std::lock_guard lock(pad_mutex);
    if (!pad_initialized) return pad_not_initialized;
    auto it = find_session(handle);
    if (it == sessions.end()) return pad_invalid_handle;
    refresh_gamepad(it->second);
    PadControllerInformation information{};
    information.touch_pixel_density = 1.0F;
    information.touch_width = 1920;
    information.touch_height = 950;
    information.left_dead_zone = 1;
    information.right_dead_zone = 1;
    information.connection_type = 0;
    information.connected = it->second.gamepad != nullptr && SDL_GamepadConnected(it->second.gamepad);
    information.connected_count = information.connected ? 1U : 0U;
    information.device_class = 0;
    return write_guest_value(guest_information, information) ? ok : pad_invalid_argument;
}

std::int32_t NBA16_GUEST_SYSV_ABI pad_set_light_bar(std::int32_t handle,
                                                    std::uint64_t guest_parameter) {
    if (guest_parameter == 0 || process_context() == nullptr) return pad_invalid_argument;
    LightBarParam parameter{};
    if (!read_guest_value(guest_parameter, parameter)) return pad_invalid_argument;
    if (parameter.r < 0x0d && parameter.g < 0x0d && parameter.b < 0x0d)
        return pad_invalid_lightbar;
    std::lock_guard lock(pad_mutex);
    if (!pad_initialized) return pad_not_initialized;
    auto it = find_session(handle);
    if (it == sessions.end()) return pad_invalid_handle;
    refresh_gamepad(it->second);
    if (it->second.gamepad == nullptr) return ok;
    (void)SDL_SetGamepadLED(it->second.gamepad, parameter.r, parameter.g, parameter.b);
    return ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI pad_set_vibration(std::int32_t handle,
                                                    std::uint64_t guest_parameter) {
    if (guest_parameter == 0 || process_context() == nullptr) return pad_invalid_argument;
    VibrationParam parameter{};
    if (!read_guest_value(guest_parameter, parameter)) return pad_invalid_argument;
    std::lock_guard lock(pad_mutex);
    if (!pad_initialized) return pad_not_initialized;
    auto it = find_session(handle);
    if (it == sessions.end()) return pad_invalid_handle;
    refresh_gamepad(it->second);
    if (it->second.gamepad == nullptr) return ok;
    const auto large = static_cast<std::uint16_t>(parameter.large_motor * 257U);
    const auto small = static_cast<std::uint16_t>(parameter.small_motor * 257U);
    (void)SDL_RumbleGamepad(it->second.gamepad, large, small, SDL_HAPTIC_INFINITY);
    return ok;
}

} // namespace

bool register_native_pad_imports(ImportResolver& resolver, std::string& error) {
    constexpr const char* library = "libScePad";
    return resolver.register_function(library, library, "hv1luiJrqQM", &pad_init, error) &&
        resolver.register_function(library, library, "xk0AcarP3V4", &pad_open, error) &&
        resolver.register_function(library, library, "6ncge5+l5Qs", &pad_close, error) &&
        resolver.register_function(library, library, "q1cHNfGycLI", &pad_read, error) &&
        resolver.register_function(library, library, "YndgXqQVV7c", &pad_read_state, error) &&
        resolver.register_function(library, library, "gjP9-KQzoUk",
                                   &pad_get_controller_information, error) &&
        resolver.register_function(library, library, "RR4novUEENY", &pad_set_light_bar, error) &&
        resolver.register_function(library, library, "yFVnOdGxvZY", &pad_set_vibration, error);
}

} // namespace nba16
