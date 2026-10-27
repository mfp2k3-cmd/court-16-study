#pragma once

#include "import_resolver.h"

#include <string>

namespace nba16 {

bool register_native_unsupported_posix_imports(ImportResolver& resolver,
                                               std::string& error);

} // namespace nba16
