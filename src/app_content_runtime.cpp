#include "app_content_runtime.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nba16 {
namespace {

constexpr std::int32_t invalid_argument = static_cast<std::int32_t>(0x80d90002U);
constexpr std::int32_t unsupported_parameter = static_cast<std::int32_t>(0x805a1000U);

std::int32_t NBA16_GUEST_SYSV_ABI app_content_initialize(const void* init, void* boot) {
    if (std::getenv("NBA16_TRACE_APP_CONTENT") != nullptr)
        std::fprintf(stderr, "APP-CONTENT initialize init=%p boot=%p\n", init, boot);
    if (init == nullptr || boot == nullptr) return invalid_argument;
    const auto* bytes = static_cast<const std::uint8_t*>(init);
    for (std::size_t index = 0; index < 32; ++index) {
        if (bytes[index] != 0) return invalid_argument;
    }
    std::memset(boot, 0, 40);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI app_content_mount_temporary_data(
    std::uint32_t option, char* mount_point) {
    if (std::getenv("NBA16_TRACE_APP_CONTENT") != nullptr)
        std::fprintf(stderr, "APP-CONTENT temporary-mount option=%u output=%p\n", option,
            static_cast<void*>(mount_point));
    if (mount_point == nullptr) return invalid_argument;
    std::memset(mount_point, 0, 16);
    std::memcpy(mount_point, "/temp0", 6);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI app_content_format_temporary_data(const char* mount_point) {
    if (std::getenv("NBA16_TRACE_APP_CONTENT") != nullptr)
        std::fprintf(stderr, "APP-CONTENT temporary-format path=%s\n",
            mount_point == nullptr ? "(null)" : mount_point);
    return mount_point == nullptr ? invalid_argument : 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI app_content_no_download_data() {
    if (std::getenv("NBA16_TRACE_APP_CONTENT") != nullptr)
        std::fprintf(stderr, "APP-CONTENT download-space unavailable (base-game profile)\n");
    return static_cast<std::int32_t>(0x80d90005U);
}

std::int32_t NBA16_GUEST_SYSV_ABI app_content_mount_addon(
    std::uint32_t service, const char* entitlement, char* mount_point) {
    if (std::getenv("NBA16_TRACE_APP_CONTENT") != nullptr)
        std::fprintf(stderr, "APP-CONTENT addon-mount service=%u entitlement=%s output=%p\n",
            service, entitlement == nullptr ? "(null)" : entitlement,
            static_cast<void*>(mount_point));
    return static_cast<std::int32_t>(0x80d90005U);
}

std::int32_t NBA16_GUEST_SYSV_ABI app_content_unmount_addon(const char* mount_point) {
    if (std::getenv("NBA16_TRACE_APP_CONTENT") != nullptr)
        std::fprintf(stderr, "APP-CONTENT addon-unmount path=%s\n",
            mount_point == nullptr ? "(null)" : mount_point);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI app_content_get_integer_parameter(
    std::uint32_t parameter, std::int32_t* output) {
    if (std::getenv("NBA16_TRACE_APP_CONTENT") != nullptr)
        std::fprintf(stderr, "APP-CONTENT integer-parameter id=%u output=%p\n", parameter,
            static_cast<void*>(output));
    if (output == nullptr) return invalid_argument;
    if (parameter != 0) return unsupported_parameter;
    *output = 3; // Offline base-game profile observed for CUSA01933.
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI app_content_list_addons(
    std::uint32_t service, void* entries, std::uint32_t capacity, std::uint32_t* count) {
    if (std::getenv("NBA16_TRACE_APP_CONTENT") != nullptr)
        std::fprintf(stderr, "APP-CONTENT list-addons service=%u entries=%p capacity=%u count=%p\n",
            service, entries, capacity, static_cast<void*>(count));
    if (service != 0 || ((entries == nullptr || capacity == 0) && count == nullptr))
        return invalid_argument;
    if (count != nullptr) *count = 0;
    return 0;
}

} // namespace

bool register_native_app_content_imports(ImportResolver& resolver, std::string& error) {
    constexpr const char* library = "libSceAppContent";
    constexpr const char* module = "libSceAppContentUtil";
    return resolver.register_function(library, module, "R9lA82OraNs",
               &app_content_initialize, error) &&
        resolver.register_function(library, module, "buYbeLOGWmA",
               &app_content_mount_temporary_data, error) &&
        resolver.register_function(library, module, "a5N7lAG0y2Q",
               &app_content_format_temporary_data, error) &&
        resolver.register_function(library, module, "99b82IKXpH4",
               &app_content_get_integer_parameter, error) &&
        resolver.register_function(library, module, "Gl6w5i0JokY",
               &app_content_no_download_data, error) &&
        resolver.register_function(library, module, "VANhIWcqYak",
               &app_content_mount_addon, error) &&
        resolver.register_function(library, module, "3rHWaV-1KC4",
               &app_content_unmount_addon, error) &&
        resolver.register_function(library, module, "xnd8BJzAxmk",
               &app_content_list_addons, error);
}

} // namespace nba16
