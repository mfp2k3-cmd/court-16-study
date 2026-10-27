#pragma once

#include <cstddef>
#include <string>

namespace nba16 {

class ImportResolver;

// Diagnostic-only fail-fast bindings for GNM imports without an implementation.
bool register_unimplemented_gnm_import_traps(ImportResolver& resolver,
                                              bool trace_handlers_present,
                                              std::size_t& registered,
                                              std::string& error);

} // namespace nba16
