#pragma once

#include "import_resolver.h"

#include <string>

namespace nba16 {

bool register_native_video_out_imports(ImportResolver& resolver, std::string& error);
void set_native_video_out_trace_enabled(bool enabled) noexcept;

} // namespace nba16
