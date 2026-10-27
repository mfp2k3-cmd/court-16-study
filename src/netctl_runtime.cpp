#include "netctl_runtime.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <mutex>

namespace nba16 {
namespace {

constexpr std::int32_t netctl_ok = 0;
constexpr std::int32_t netctl_callback_max = static_cast<std::int32_t>(0x80412103U);
constexpr std::int32_t netctl_id_not_found = static_cast<std::int32_t>(0x80412104U);
constexpr std::int32_t netctl_invalid_address = static_cast<std::int32_t>(0x80412107U);
constexpr std::int32_t netctl_not_connected = static_cast<std::int32_t>(0x80412108U);
constexpr std::int32_t netctl_disconnected_state = 0;
constexpr std::int32_t netctl_disconnected_event = 1;

void trace_netctl(const char* message) {
    if (std::getenv("NBA16_TRACE_NETCTL") == nullptr) return;
    std::fprintf(stderr, "NETCTL-HLE %s\n", message);
    std::fflush(stderr);
}

using NetCtlCallback = GuestFunction<void, std::int32_t, std::uint64_t>;

struct CallbackEntry {
    NetCtlCallback callback{};
    std::uint64_t argument{};
};

std::array<CallbackEntry, 8> callbacks{};
std::mutex callbacks_mutex;

std::int32_t NBA16_GUEST_SYSV_ABI netctl_init() {
    trace_netctl("sceNetCtlInit -> OK (estado local offline)");
    return netctl_ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI netctl_term() {
    trace_netctl("sceNetCtlTerm -> OK");
    return netctl_ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI netctl_get_state(std::uint64_t state_address) {
    if (state_address == 0) return netctl_invalid_address;
    *reinterpret_cast<std::int32_t*>(static_cast<std::uintptr_t>(state_address)) =
        netctl_disconnected_state;
    trace_netctl("sceNetCtlGetState -> DISCONNECTED");
    return netctl_ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI netctl_get_info(std::int32_t, std::uint64_t) {
    return netctl_not_connected;
}

std::int32_t NBA16_GUEST_SYSV_ABI netctl_get_result(std::int32_t,
                                                    std::uint64_t error_address) {
    if (error_address == 0) return netctl_invalid_address;
    *reinterpret_cast<std::int32_t*>(static_cast<std::uintptr_t>(error_address)) = 0;
    return netctl_ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI netctl_register_callback(
    std::uint64_t callback_address, std::uint64_t argument,
    std::uint64_t callback_id_address) {
    if (callback_address == 0 || callback_id_address == 0) return netctl_invalid_address;
    std::scoped_lock lock(callbacks_mutex);
    for (std::size_t index = 0; index < callbacks.size(); ++index) {
        if (callbacks[index].callback != nullptr) continue;
        callbacks[index] = {
            reinterpret_cast<NetCtlCallback>(static_cast<std::uintptr_t>(callback_address)),
            argument};
        *reinterpret_cast<std::int32_t*>(static_cast<std::uintptr_t>(callback_id_address)) =
            static_cast<std::int32_t>(index);
        if (std::getenv("NBA16_TRACE_NETCTL") != nullptr) {
            std::fprintf(stderr, "NETCTL-HLE sceNetCtlRegisterCallback -> OK id=%zu\n", index);
            std::fflush(stderr);
        }
        return netctl_ok;
    }
    return netctl_callback_max;
}

std::int32_t NBA16_GUEST_SYSV_ABI netctl_unregister_callback(std::int32_t callback_id) {
    if (callback_id < 0 || static_cast<std::size_t>(callback_id) >= callbacks.size())
        return netctl_id_not_found;
    std::scoped_lock lock(callbacks_mutex);
    auto& entry = callbacks[static_cast<std::size_t>(callback_id)];
    if (entry.callback == nullptr) return netctl_id_not_found;
    entry = {};
    return netctl_ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI netctl_check_callback() {
    std::array<CallbackEntry, 8> snapshot{};
    {
        std::scoped_lock lock(callbacks_mutex);
        snapshot = callbacks;
    }
    for (const auto& entry : snapshot) {
        if (entry.callback != nullptr) {
            trace_netctl("sceNetCtlCheckCallback -> DISCONNECTED event");
            entry.callback(netctl_disconnected_event, entry.argument);
        }
    }
    return netctl_ok;
}

} // namespace

bool register_native_netctl_imports(ImportResolver& resolver, std::string& error) {
    if (std::getenv("NBA16_TRACE_NETCTL") != nullptr) {
        std::fprintf(stderr, "NETCTL-HLE registration begin\n");
        std::fflush(stderr);
    }
    const bool registered = resolver.register_function("libSceNetCtl", "libSceNetCtl", "gky0+oaNM4k",
               &netctl_init, error) &&
        resolver.register_function("libSceNetCtl", "libSceNetCtl", "Z4wwCFiBELQ",
               &netctl_term, error) &&
        resolver.register_function("libSceNetCtl", "libSceNetCtl", "uBPlr0lbuiI",
               &netctl_get_state, error) &&
        resolver.register_function("libSceNetCtl", "libSceNetCtl", "obuxdTiwkF8",
               &netctl_get_info, error) &&
        resolver.register_function("libSceNetCtl", "libSceNetCtl", "0cBgduPRR+M",
               &netctl_get_result, error) &&
        resolver.register_function("libSceNetCtl", "libSceNetCtl", "UJ+Z7Q+4ck0",
               &netctl_register_callback, error) &&
        resolver.register_function("libSceNetCtl", "libSceNetCtl", "Rqm2OnZMCz0",
               &netctl_unregister_callback, error) &&
        resolver.register_function("libSceNetCtl", "libSceNetCtl", "iQw3iQPhvUQ",
               &netctl_check_callback, error);
    if (registered && std::getenv("NBA16_TRACE_NETCTL") != nullptr) {
        std::fprintf(stderr, "NETCTL-HLE registrations active init=0x%llx callback=0x%llx\n",
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(&netctl_init)),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(
                &netctl_register_callback)));
        std::fflush(stderr);
    }
    return registered;
}

} // namespace nba16
