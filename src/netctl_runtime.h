#pragma once

#include "import_resolver.h"

#include <string>

namespace nba16 {

// Provides the local, disconnected NetCtl surface used by the game. It does
// not create an external network connection.
bool register_native_netctl_imports(ImportResolver& resolver, std::string& error);

} // namespace nba16
