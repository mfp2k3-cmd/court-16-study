#pragma once

#include "import_resolver.h"

namespace nba16 {

// Installs diagnostic-only GNM imports. Submit handlers log ABI arguments and
// return a negative sentinel without consuming commands. VideoOut remains on
// the native HLE handlers, which can be instrumented without replacing them.
bool register_graphics_call_trace(ImportResolver& resolver, std::string& error,
                                  bool submit_done_is_probed = false);
bool register_gnm_submit_done_probe(ImportResolver& resolver, std::string& error);

} // namespace nba16
