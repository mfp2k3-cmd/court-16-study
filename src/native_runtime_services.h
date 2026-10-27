#pragma once

#include "import_resolver.h"

#include <filesystem>
#include <string>

namespace nba16 {

// Registers the HLE services shared by the native runtime and diagnostic tools.
bool register_native_runtime_services(ImportResolver& resolver,
                                     const std::filesystem::path& game_root,
                                     std::string& error);

} // namespace nba16
