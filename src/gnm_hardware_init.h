#pragma once

#include <string>

namespace nba16 {

class ImportResolver;
bool register_gnm_hardware_init_imports(ImportResolver& resolver, std::string& error);

} // namespace nba16
