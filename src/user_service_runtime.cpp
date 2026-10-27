#include "user_service_runtime.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace nba16 {
namespace {

constexpr std::int32_t user_id = 1000;
constexpr std::int32_t invalid_argument = static_cast<std::int32_t>(0x80960005U);
constexpr std::int32_t no_event = static_cast<std::int32_t>(0x80960007U);
constexpr std::int32_t buffer_too_short = static_cast<std::int32_t>(0x8096000aU);
constexpr char default_user_name[] = "NBA Player";

std::mutex user_service_mutex;
bool user_service_initialized{};
bool login_event_pending{};

std::int32_t NBA16_GUEST_SYSV_ABI user_service_initialize(const void*) {
    std::lock_guard lock(user_service_mutex);
    if (!user_service_initialized) login_event_pending = true;
    user_service_initialized = true;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI user_service_terminate() {
    std::lock_guard lock(user_service_mutex);
    user_service_initialized = false;
    login_event_pending = false;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI user_service_get_initial_user(std::int32_t* output) {
    if (output == nullptr) return invalid_argument;
    *output = user_id;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI user_service_get_login_user_ids(std::int32_t* output) {
    if (output == nullptr) return invalid_argument;
    output[0] = user_id;
    std::fill(output + 1, output + 4, -1);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI user_service_get_user_name(
    std::int32_t requested_user, char* output, std::uint64_t capacity) {
    if (requested_user != user_id || output == nullptr) return invalid_argument;
    if (capacity < sizeof(default_user_name)) return buffer_too_short;
    std::memcpy(output, default_user_name, sizeof(default_user_name));
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI user_service_get_event(std::int32_t* output) {
    if (output == nullptr) return invalid_argument;
    std::lock_guard lock(user_service_mutex);
    if (!user_service_initialized || !login_event_pending) return no_event;
    output[0] = 0; // login event
    output[1] = user_id;
    login_event_pending = false;
    return 0;
}

} // namespace

bool register_native_user_service_imports(ImportResolver& resolver,
                                          std::string& error) {
    constexpr const char* module = "libSceUserService";
    return resolver.register_function(module, module, "j3YMu1MVNNo",
               &user_service_initialize, error) &&
        resolver.register_function(module, module, "bwFjS+bX9mA",
               &user_service_terminate, error) &&
        resolver.register_function(module, module, "CdWp0oHWGr0",
               &user_service_get_initial_user, error) &&
        resolver.register_function(module, module, "fPhymKNvK-A",
               &user_service_get_login_user_ids, error) &&
        resolver.register_function(module, module, "1xxcMiGu2fo",
               &user_service_get_user_name, error) &&
        resolver.register_function(module, module, "yH17Q6NWtVg",
               &user_service_get_event, error);
}

} // namespace nba16
