#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace nba16 {

class GuestMemoryAccess;

struct GnmCommandBufferView {
    std::span<const std::uint32_t> dcb;
    std::span<const std::uint32_t> ccb;
};

// Resolves the guest DCB/CCB address and byte-count arrays into validated
// zero-copy host spans. It does not submit commands or claim that a frame ran.
[[nodiscard]] bool resolve_gnm_submission(
    GuestMemoryAccess& memory, std::uint32_t count,
    std::uint64_t dcb_address_array, std::uint64_t dcb_size_array,
    std::uint64_t ccb_address_array, std::uint64_t ccb_size_array,
    std::vector<GnmCommandBufferView>& output, std::string& error);

} // namespace nba16
