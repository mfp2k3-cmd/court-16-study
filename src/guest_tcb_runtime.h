#pragma once

#include "guest_image_map.h"
#include "guest_image_memory.h"

#include <cstdint>
#include <string>

namespace nba16 {

// Bridges the PS4's FS-based thread-control-block reads to Windows TEB TLS slots.
bool initialize_guest_tcb(std::string& error);
void clear_guest_tcb_for_current_thread() noexcept;
[[nodiscard]] std::uint64_t guest_tcb_patched_load_count() noexcept;
[[nodiscard]] void* guest_tcb_current_thread_record() noexcept;
[[nodiscard]] int* guest_tcb_errno_location() noexcept;
bool patch_guest_tcb_loads(GuestImageMap& map, GuestImageMemory& memory,
                           std::uint64_t& patched_loads, std::string& error);

} // namespace nba16
