#pragma once

#include "import_resolver.h"

#include <filesystem>
#include <string>

namespace nba16 {

void set_native_playgo_game_root(std::filesystem::path game_root);
bool register_native_playgo_imports(ImportResolver& resolver, std::string& error);
bool register_native_shareplay_imports(ImportResolver& resolver, std::string& error);

} // namespace nba16
