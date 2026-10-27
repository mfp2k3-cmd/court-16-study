#include "playgo_runtime.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <utility>
#include <vector>

namespace nba16 {
namespace {

constexpr std::int32_t bad_handle = static_cast<std::int32_t>(0x80b20009U);
constexpr std::int32_t bad_pointer = static_cast<std::int32_t>(0x80b2000aU);
constexpr std::int32_t bad_size = static_cast<std::int32_t>(0x80b2000bU);
constexpr std::int32_t bad_chunk = static_cast<std::int32_t>(0x80b2000cU);
constexpr std::int32_t not_initialized = static_cast<std::int32_t>(0x80b20005U);
constexpr std::int32_t already_initialized = static_cast<std::int32_t>(0x80b20006U);
constexpr std::int32_t bad_argument = static_cast<std::int32_t>(0x80b20004U);
constexpr std::int32_t bad_speed = static_cast<std::int32_t>(0x80b2000dU);
constexpr std::int32_t bad_locus = static_cast<std::int32_t>(0x80b20010U);
constexpr std::int32_t no_playgo_data = static_cast<std::int32_t>(0x80b2000eU);
constexpr std::int32_t handle_value = 1;
constexpr std::int32_t full_install_speed = 2;
constexpr std::int8_t local_fast_locus = 3;

std::mutex state_mutex;
std::filesystem::path configured_game_root;
std::uint32_t installed_chunks{};
std::int32_t active_handle{};
std::int32_t install_speed{full_install_speed};
bool initialized{};

bool read_installed_chunk_count(std::uint32_t& count) {
    std::filesystem::path root;
    {
        std::lock_guard lock(state_mutex);
        root = configured_game_root;
    }
    if (root.empty()) return false;
    std::ifstream input(root / "sce_sys" / "playgo-chunk.dat", std::ios::binary);
    std::array<unsigned char, 12> header{};
    if (!input.read(reinterpret_cast<char*>(header.data()),
                    static_cast<std::streamsize>(header.size())) ||
        header[0] != 'p' || header[1] != 'l' || header[2] != 'g' || header[3] != 'o') {
        return false;
    }
    const auto parsed = static_cast<std::uint32_t>(header[10]) |
                        (static_cast<std::uint32_t>(header[11]) << 8U);
    if (parsed == 0 || parsed > 4096) return false;
    count = parsed;
    return true;
}

struct PlayGoInitParameters {
    const void* buffer;
    std::uint32_t buffer_size;
    std::uint32_t reserved;
};

std::int32_t NBA16_GUEST_SYSV_ABI playgo_initialize(const PlayGoInitParameters* parameters) {
    if (parameters == nullptr || parameters->buffer == nullptr) return bad_pointer;
    if (parameters->buffer_size < 0x200000U) return bad_size;
    {
        std::lock_guard lock(state_mutex);
        if (initialized) return already_initialized;
    }
    std::uint32_t count{};
    if (!read_installed_chunk_count(count)) return no_playgo_data;
    std::lock_guard lock(state_mutex);
    if (initialized) return already_initialized;
    installed_chunks = count;
    active_handle = 0;
    install_speed = full_install_speed;
    initialized = true;
    if (std::getenv("NBA16_TRACE_PLAYGO") != nullptr)
        std::fprintf(stderr, "PLAYGO initialized: %u local chunks\n", installed_chunks);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_open(std::int32_t* output, const void* parameters) {
    if (output == nullptr) return bad_pointer;
    if (parameters != nullptr) return bad_argument;
    std::lock_guard lock(state_mutex);
    if (!initialized) return not_initialized;
    active_handle = handle_value;
    *output = active_handle;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_close(std::int32_t handle) {
    std::lock_guard lock(state_mutex);
    if (handle != handle_value || handle != active_handle) return bad_handle;
    if (!initialized) return not_initialized;
    active_handle = 0;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_terminate() {
    std::lock_guard lock(state_mutex);
    if (!initialized) return not_initialized;
    initialized = false;
    active_handle = 0;
    installed_chunks = 0;
    return 0;
}

std::int32_t validate_handle(std::int32_t handle) {
    if (handle != handle_value || handle != active_handle) return bad_handle;
    if (!initialized) return not_initialized;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_get_chunk_ids(
    std::int32_t handle, std::uint16_t* ids, std::uint32_t capacity,
    std::uint32_t* written) {
    std::lock_guard lock(state_mutex);
    const auto valid = validate_handle(handle);
    if (valid != 0) return valid;
    if (written == nullptr) return bad_pointer;
    if (ids != nullptr && capacity == 0) return bad_size;
    if (ids == nullptr) {
        *written = installed_chunks;
        return 0;
    }
    const auto count = std::min(capacity, installed_chunks);
    for (std::uint32_t index = 0; index < count; ++index)
        ids[index] = static_cast<std::uint16_t>(index);
    *written = count;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_get_locus(
    std::int32_t handle, const std::uint16_t* ids, std::uint32_t count,
    std::int8_t* loci) {
    std::lock_guard lock(state_mutex);
    const auto valid = validate_handle(handle);
    if (valid != 0) return valid;
    if (ids == nullptr || loci == nullptr) return bad_pointer;
    if (count == 0) return bad_size;
    for (std::uint32_t index = 0; index < count; ++index) {
        if (ids[index] >= installed_chunks) return bad_chunk;
        loci[index] = local_fast_locus;
    }
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_get_progress(
    std::int32_t handle, const std::uint16_t* ids, std::uint32_t count,
    std::uint64_t* progress) {
    std::lock_guard lock(state_mutex);
    const auto valid = validate_handle(handle);
    if (valid != 0) return valid;
    if (ids == nullptr || progress == nullptr) return bad_pointer;
    if (count == 0) return bad_size;
    for (std::uint32_t index = 0; index < count; ++index)
        if (ids[index] >= installed_chunks) return bad_chunk;
    progress[0] = 1;
    progress[1] = 1;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_get_eta(
    std::int32_t handle, const std::uint16_t* ids, std::uint32_t count,
    std::uint64_t* eta) {
    std::lock_guard lock(state_mutex);
    const auto valid = validate_handle(handle);
    if (valid != 0) return valid;
    if (ids == nullptr || eta == nullptr) return bad_pointer;
    if (count == 0) return bad_size;
    for (std::uint32_t index = 0; index < count; ++index)
        if (ids[index] >= installed_chunks) return bad_chunk;
    *eta = 0;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_set_install_speed(
    std::int32_t handle, std::int32_t speed) {
    std::lock_guard lock(state_mutex);
    const auto valid = validate_handle(handle);
    if (valid != 0) return valid;
    if (speed < 0 || speed > 2) return bad_speed;
    install_speed = speed;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_get_install_speed(
    std::int32_t handle, std::int32_t* speed) {
    std::lock_guard lock(state_mutex);
    const auto valid = validate_handle(handle);
    if (valid != 0) return valid;
    if (speed == nullptr) return bad_pointer;
    *speed = install_speed;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_set_todo_list(
    std::int32_t handle, const void* list, std::uint32_t count) {
    std::lock_guard lock(state_mutex);
    const auto valid = validate_handle(handle);
    if (valid != 0) return valid;
    if (list == nullptr) return bad_pointer;
    if (count == 0) return bad_size;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI playgo_prefetch(
    std::int32_t handle, const std::uint16_t* ids, std::uint32_t count,
    std::int32_t minimum_locus) {
    std::lock_guard lock(state_mutex);
    const auto valid = validate_handle(handle);
    if (valid != 0) return valid;
    if (ids == nullptr) return bad_pointer;
    if (count == 0) return bad_size;
    if (minimum_locus != 0 && minimum_locus != 2 && minimum_locus != 3)
        return bad_locus;
    for (std::uint32_t index = 0; index < count; ++index)
        if (ids[index] >= installed_chunks) return bad_chunk;
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI shareplay_initialize(void*, std::uint64_t) {
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI shareplay_terminate() {
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI shareplay_set_prohibition(std::int32_t) {
    return 0;
}

} // namespace

void set_native_playgo_game_root(std::filesystem::path game_root) {
    std::lock_guard lock(state_mutex);
    configured_game_root = std::move(game_root);
}

bool register_native_playgo_imports(ImportResolver& resolver, std::string& error) {
    constexpr const char* module = "libScePlayGo";
    return resolver.register_function(module, module, "ts6GlZOKRrE", &playgo_initialize, error) &&
        resolver.register_function(module, module, "M1Gma1ocrGE", &playgo_open, error) &&
        resolver.register_function(module, module, "rvBSfTimejE", &playgo_get_install_speed, error) &&
        resolver.register_function(module, module, "4AAcTU9R3XM", &playgo_set_install_speed, error) &&
        resolver.register_function(module, module, "gUPGiOQ1tmQ", &playgo_set_todo_list, error) &&
        resolver.register_function(module, module, "uWIYLFkkwqk", &playgo_get_locus, error) &&
        resolver.register_function(module, module, "-RJWNMK3fC8", &playgo_get_progress, error) &&
        resolver.register_function(module, module, "v6EZ-YWRdMs", &playgo_get_eta, error) &&
        resolver.register_function(module, module, "-Q1-u1a7p0g", &playgo_prefetch, error) &&
        resolver.register_function(module, module, "Uco1I0dlDi8", &playgo_close, error) &&
        resolver.register_function(module, module, "MPe0EeBGM-E", &playgo_terminate, error) &&
        resolver.register_function(module, module, "73fF1MFU8hA", &playgo_get_chunk_ids, error);
}

bool register_native_shareplay_imports(ImportResolver& resolver, std::string& error) {
    constexpr const char* module = "libSceSharePlay";
    return resolver.register_function(module, module, "isruqthpYcw",
               &shareplay_initialize, error) &&
        resolver.register_function(module, module, "UaLjloJinow",
               &shareplay_terminate, error) &&
        resolver.register_function(module, module, "co2NCj--pnc",
               &shareplay_set_prohibition, error);
}

} // namespace nba16
