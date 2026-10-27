#include "video_out_runtime.h"

#include "guest_process_context.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <mutex>
#include <span>
#include <type_traits>
#include <vector>

namespace nba16 {
namespace {

constexpr std::int32_t ok = 0;
constexpr std::int32_t invalid_value = static_cast<std::int32_t>(0x80290001U);
constexpr std::int32_t invalid_address = static_cast<std::int32_t>(0x80290002U);
constexpr std::int32_t invalid_index = static_cast<std::int32_t>(0x8029000aU);
constexpr std::int32_t invalid_handle = static_cast<std::int32_t>(0x8029000bU);
constexpr std::int32_t invalid_event_queue = static_cast<std::int32_t>(0x8029000cU);
constexpr std::int32_t invalid_tiling = static_cast<std::int32_t>(0x80290007U);
constexpr std::int32_t first_handle = 1;
// PS4's system user ID is 0xFF (255), the value observed in this title's
// sceVideoOutOpen call and defined by shadPS4's public userservice headers.
constexpr std::int32_t system_user_id = 0xff;
constexpr std::int32_t main_bus = 0;
constexpr std::size_t max_buffers = 16;

struct BufferAttribute {
    std::uint32_t pixel_format{};
    std::int32_t tiling_mode{};
    std::int32_t aspect_ratio{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t pitch_in_pixel{};
    std::uint32_t option{};
    std::uint32_t reserved0{};
    std::uint64_t reserved1{};
};

struct FlipStatus {
    std::uint64_t count{};
    std::uint64_t process_time{};
    std::uint64_t tsc{};
    std::int64_t flip_arg{-1};
    std::uint64_t submit_tsc{};
    std::uint64_t reserved0{};
    std::int32_t gc_queue_num{};
    std::int32_t flip_pending_num{};
    std::int32_t current_buffer{-1};
    std::uint32_t reserved1{};
};

static_assert(sizeof(BufferAttribute) == 40);
static_assert(sizeof(FlipStatus) == 64);
static_assert(offsetof(FlipStatus, current_buffer) == 56);

struct VideoPort {
    std::array<std::uint64_t, max_buffers> addresses{};
    std::array<std::int32_t, max_buffers> attribute_group{};
    std::map<std::int32_t, BufferAttribute> attributes;
    FlipStatus flip{};
    std::int32_t flip_rate{1};
    std::int32_t top_margin{};
    std::int32_t bottom_margin{};
    bool open{true};

    VideoPort() { attribute_group.fill(-1); }
};

std::mutex video_mutex;
std::map<std::int32_t, VideoPort> ports;
std::int32_t next_handle{first_handle};
std::atomic_bool trace_video_out_calls{};

void trace_video_out(const char* name, const char* arguments) {
    if (!trace_video_out_calls.load(std::memory_order_relaxed)) return;
    std::fprintf(stderr, "VIDEOOUT-TRACE %s %s\n", name, arguments);
    std::fflush(stderr);
}

GuestProcessContext* process_context() noexcept {
    return current_guest_process_context();
}

template <typename T>
bool read_guest(std::uint64_t address, T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    auto* context = process_context();
    if (address == 0 || context == nullptr) return false;
    std::string error;
    return context->memory().read(address,
        std::span<std::byte>(reinterpret_cast<std::byte*>(&value), sizeof(value)), error);
}

template <typename T>
bool write_guest(std::uint64_t address, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    auto* context = process_context();
    if (address == 0 || context == nullptr) return false;
    std::string error;
    return context->memory().write(address,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), sizeof(value)), error);
}

std::uint64_t now_ticks() noexcept {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<nanoseconds>(
        steady_clock::now().time_since_epoch()).count());
}

void NBA16_GUEST_SYSV_ABI set_buffer_attribute(std::uint64_t guest_attribute,
        std::uint32_t pixel_format, std::uint32_t tiling_mode, std::uint32_t aspect_ratio,
        std::uint32_t width, std::uint32_t height, std::uint32_t pitch) {
    BufferAttribute attribute{};
    attribute.pixel_format = pixel_format;
    attribute.tiling_mode = static_cast<std::int32_t>(tiling_mode);
    attribute.aspect_ratio = static_cast<std::int32_t>(aspect_ratio);
    attribute.width = width;
    attribute.height = height;
    attribute.pitch_in_pixel = pitch;
    (void)write_guest(guest_attribute, attribute);
}

std::int32_t NBA16_GUEST_SYSV_ABI video_open(std::int32_t requested_user,
        std::int32_t bus_type, std::int32_t index, std::uint64_t parameters) {
    std::int32_t handle = invalid_value;
    if (requested_user == system_user_id && bus_type == main_bus && index == 0) {
        std::lock_guard lock(video_mutex);
        if (next_handle <= 0) next_handle = first_handle;
        handle = next_handle++;
        ports.emplace(handle, VideoPort{});
    }
    char args[192]{};
    std::snprintf(args, sizeof(args),
        "user=%d bus=%d index=%d params=0x%llx result=%d", requested_user,
        bus_type, index, static_cast<unsigned long long>(parameters), handle);
    trace_video_out("sceVideoOutOpen", args);
    return handle;
}

std::int32_t NBA16_GUEST_SYSV_ABI video_close(std::int32_t handle) {
    std::lock_guard lock(video_mutex);
    return ports.erase(handle) == 1 ? ok : invalid_handle;
}

std::int32_t NBA16_GUEST_SYSV_ABI set_flip_rate(std::int32_t handle, std::int32_t rate) {
    std::lock_guard lock(video_mutex);
    const auto it = ports.find(handle);
    if (it == ports.end()) return invalid_handle;
    it->second.flip_rate = rate;
    return ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI set_margins(std::int32_t handle,
        std::int32_t top, std::int32_t bottom) {
    std::lock_guard lock(video_mutex);
    const auto it = ports.find(handle);
    if (it == ports.end()) return invalid_handle;
    it->second.top_margin = top;
    it->second.bottom_margin = bottom;
    return ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI register_buffers(std::int32_t handle,
        std::int32_t start_index, std::uint64_t guest_addresses,
        std::int32_t count, std::uint64_t guest_attribute) {
    const auto finish = [](std::int32_t result, const char* detail) {
        char message[256]{};
        std::snprintf(message, sizeof(message), "result=%d %s", result, detail);
        trace_video_out("sceVideoOutRegisterBuffers.result", message);
        return result;
    };
    if (trace_video_out_calls.load(std::memory_order_relaxed)) {
        char args[224]{};
        std::snprintf(args, sizeof(args),
            "handle=%d start=%d address_array=0x%llx count=%d attribute=0x%llx",
            handle, start_index, static_cast<unsigned long long>(guest_addresses), count,
            static_cast<unsigned long long>(guest_attribute));
        trace_video_out("sceVideoOutRegisterBuffers", args);
    }
    if (guest_addresses == 0 || guest_attribute == 0 || process_context() == nullptr)
        return finish(invalid_address, "invalid input address/context");
    if (start_index < 0 || count < 1 || count > static_cast<std::int32_t>(max_buffers) ||
        start_index > static_cast<std::int32_t>(max_buffers) - count)
        return finish(invalid_index, "invalid buffer range");

    BufferAttribute attribute{};
    std::vector<std::uint64_t> addresses(static_cast<std::size_t>(count));
    auto* context = process_context();
    std::string error;
    if (!read_guest(guest_attribute, attribute) ||
        !context->memory().read(guest_addresses,
            std::as_writable_bytes(std::span<std::uint64_t>(addresses)), error))
        return finish(invalid_address, "guest attribute/address read failed");
    if (attribute.tiling_mode < 0 || attribute.tiling_mode > 1)
        return finish(invalid_tiling, "unsupported tiling mode");

    std::lock_guard lock(video_mutex);
    const auto it = ports.find(handle);
    if (it == ports.end()) return finish(invalid_handle, "invalid handle");
    auto& port = it->second;
    for (std::int32_t i = 0; i < count; ++i) {
        const auto slot = static_cast<std::size_t>(start_index + i);
        if (port.attribute_group[slot] != -1)
            return finish(static_cast<std::int32_t>(0x80290010U), "buffer slot already registered");
    }
    const auto group = start_index;
    port.attributes[group] = attribute;
    for (std::int32_t i = 0; i < count; ++i) {
        const auto slot = static_cast<std::size_t>(start_index + i);
        port.addresses[slot] = addresses[static_cast<std::size_t>(i)];
        port.attribute_group[slot] = group;
    }
    char detail[224]{};
    std::snprintf(detail, sizeof(detail),
        "width=%u height=%u pitch=%u format=0x%x tiling=%d buffers=%d first=0x%llx",
        attribute.width, attribute.height, attribute.pitch_in_pixel, attribute.pixel_format,
        attribute.tiling_mode, count, static_cast<unsigned long long>(addresses.front()));
    return finish(ok, detail);
}

std::int32_t NBA16_GUEST_SYSV_ABI unregister_buffers(std::int32_t handle,
        std::int32_t group) {
    std::lock_guard lock(video_mutex);
    const auto it = ports.find(handle);
    if (it == ports.end()) return invalid_handle;
    auto& port = it->second;
    if (!port.attributes.erase(group)) return invalid_index;
    for (std::size_t i = 0; i < max_buffers; ++i) {
        if (port.attribute_group[i] == group) {
            port.attribute_group[i] = -1;
            port.addresses[i] = 0;
        }
    }
    return ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI submit_flip(std::int32_t handle,
        std::int32_t buffer_index, std::int32_t flip_mode, std::int64_t flip_argument) {
    if (trace_video_out_calls.load(std::memory_order_relaxed)) {
        char args[192]{};
        std::snprintf(args, sizeof(args),
            "handle=%d buffer=%d mode=%d arg=%lld", handle, buffer_index,
            flip_mode, static_cast<long long>(flip_argument));
        trace_video_out("sceVideoOutSubmitFlip", args);
    }
    std::lock_guard lock(video_mutex);
    const auto it = ports.find(handle);
    if (it == ports.end()) return invalid_handle;
    auto& port = it->second;
    if (buffer_index < -1 || buffer_index >= static_cast<std::int32_t>(max_buffers))
        return invalid_index;
    if (buffer_index >= 0 && port.attribute_group[static_cast<std::size_t>(buffer_index)] < 0)
        return invalid_index;
    ++port.flip.count;
    port.flip.process_time = now_ticks();
    port.flip.tsc = port.flip.process_time;
    port.flip.submit_tsc = port.flip.process_time;
    port.flip.flip_arg = flip_argument;
    port.flip.current_buffer = buffer_index;
    port.flip.flip_pending_num = 0;
    return ok;
}

std::int32_t NBA16_GUEST_SYSV_ABI get_flip_status(std::int32_t handle,
        std::uint64_t guest_status) {
    if (guest_status == 0 || process_context() == nullptr) return invalid_address;
    std::lock_guard lock(video_mutex);
    const auto it = ports.find(handle);
    if (it == ports.end()) return invalid_handle;
    return write_guest(guest_status, it->second.flip) ? ok : invalid_address;
}

std::int32_t NBA16_GUEST_SYSV_ABI add_flip_event(std::int32_t, std::int32_t, std::uint64_t) {
    return invalid_event_queue;
}

std::int32_t NBA16_GUEST_SYSV_ABI delete_flip_event(std::int32_t, std::int32_t) {
    return invalid_event_queue;
}

} // namespace

bool register_native_video_out_imports(ImportResolver& resolver, std::string& error) {
    constexpr const char* library = "libSceVideoOut";
    return resolver.register_function(library, library, "Up36PTk687E", &video_open, error) &&
        resolver.register_function(library, library, "uquVH4-Du78", &video_close, error) &&
        resolver.register_function(library, library, "i6-sR91Wt-4", &set_buffer_attribute, error) &&
        resolver.register_function(library, library, "w3BY+tAEiQY", &register_buffers, error) &&
        resolver.register_function(library, library, "N5KDtkIjjJ4", &unregister_buffers, error) &&
        resolver.register_function(library, library, "CBiu4mCE1DA", &set_flip_rate, error) &&
        resolver.register_function(library, library, "MTxxrOCeSig", &set_margins, error) &&
        resolver.register_function(library, library, "U46NwOiJpys", &submit_flip, error) &&
        resolver.register_function(library, library, "SbU3dwp80lQ", &get_flip_status, error) &&
        resolver.register_function(library, library, "HXzjK9yI30k", &add_flip_event, error) &&
        resolver.register_function(library, library, "-Ozn0F1AFRg", &delete_flip_event, error);
}

void set_native_video_out_trace_enabled(bool enabled) noexcept {
    trace_video_out_calls.store(enabled, std::memory_order_relaxed);
}

} // namespace nba16
