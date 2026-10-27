#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include "guest_abi.h"

namespace nba16 {

// Installs a guest-visible low-address heap through the executable's
// PT_SCE_PROC_PARAM before libc-internal startup runs.
bool configure_guest_libc_allocator(void* process_parameter,
                                    std::string& error);
void* NBA16_GUEST_SYSV_ABI guest_sanitizer_malloc_replace();
bool guest_libc_arena_region(std::uint64_t& begin, std::size_t& size) noexcept;
void set_guest_libc_original_malloc(std::uintptr_t address) noexcept;
void* NBA16_GUEST_SYSV_ABI guest_libc_malloc_fallback(std::size_t size);
void NBA16_GUEST_SYSV_ABI guest_libc_free_fallback(void* pointer);

} // namespace nba16
