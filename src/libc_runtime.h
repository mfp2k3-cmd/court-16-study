#pragma once

#include "import_resolver.h"

#include <string>

namespace nba16 {

// Registers the small, ABI-compatible libc surface implemented by this project.
bool register_native_libc_imports(ImportResolver& resolver, std::string& error);

} // namespace nba16
