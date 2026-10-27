#pragma once

#include <filesystem>
#include <string>

namespace nba16 {

// Read param.sfo and the ELF process parameter from a game dump, then seed
// shadPS4's metadata singleton before any HLE/kernel graphics services start.
[[nodiscard]] bool initialize_shadps4_game_metadata(
    const std::filesystem::path& game_root, std::string& error);

// Install the shadPS4 MemoryManager-backed direct-memory provider. Call only
// after upstream settings and ELF metadata are initialized, and before guest
// threads start. The core archive must be linked into the calling process.
[[nodiscard]] bool install_shadps4_direct_memory_provider() noexcept;

} // namespace nba16
