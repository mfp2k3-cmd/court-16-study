#include "gnm_import_traps.h"

#include "guest_abi.h"
#include "import_resolver.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace nba16 {
namespace {

[[noreturn]] void stop_at_unimplemented_import(const char* library,
                                                const char* module,
                                                const char* nid,
                                                const char* function,
                                                std::uintptr_t caller) {
    std::fprintf(stderr,
        "GNM-HLE-MISSING %s/%s:%s (%s), guest caller=0x%llx; stopping without a fabricated result.\n",
        library, module, nid, function, static_cast<unsigned long long>(caller));
    std::fflush(stderr);
    std::abort();
}

#define NBA16_GNM_UNIMPLEMENTED(id, library, module, nid, function) \
    [[noreturn]] void NBA16_GUEST_SYSV_ABI gnm_unimplemented_##id(...) { \
        const auto caller = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0)); \
        stop_at_unimplemented_import(library, module, nid, function, caller); \
    }
#include "gnm_unimplemented_imports.inc"
#undef NBA16_GNM_UNIMPLEMENTED

struct TrapEntry {
    const char* library;
    const char* module;
    const char* nid;
    const char* function;
    std::uintptr_t address;
};

#define NBA16_GNM_UNIMPLEMENTED(id, library, module, nid, function) \
    TrapEntry{library, module, nid, function, \
        reinterpret_cast<std::uintptr_t>(&gnm_unimplemented_##id)},
const TrapEntry trap_entries[]{
#include "gnm_unimplemented_imports.inc"
};
#undef NBA16_GNM_UNIMPLEMENTED

bool is_trace_binding(const TrapEntry& entry) {
    return entry.library == std::string_view("libSceGnmDriver") &&
        entry.module == std::string_view("libSceGnmDriver") &&
        (entry.nid == std::string_view("0H2vBYbTLHI") ||
         entry.nid == std::string_view("bX5IbRvECXk") ||
         entry.nid == std::string_view("zwY0YV91TTI") ||
         entry.nid == std::string_view("gObODli-OH8") ||
         entry.nid == std::string_view("xbxNatawohc") ||
         entry.nid == std::string_view("yvZ73uQUqrk"));
}

} // namespace

bool register_unimplemented_gnm_import_traps(ImportResolver& resolver,
                                              bool trace_handlers_present,
                                              std::size_t& registered,
                                              std::string& error) {
    if (!guest_sysv_abi_available) {
        error = "As armadilhas GNM exigem chamadas host SysV x86-64.";
        return false;
    }
    registered = 0;
    for (const auto& entry : trap_entries) {
        if (entry.nid == std::string_view("0H2vBYbTLHI") ||
            entry.nid == std::string_view("29oKvKXzEZo") ||
            entry.nid == std::string_view("nF6bFRUBRAU")) continue;
        if (trace_handlers_present && is_trace_binding(entry)) continue;
        if (!resolver.register_symbol(entry.library, entry.module, entry.nid,
                GuestSymbolKind::function, static_cast<std::uint64_t>(entry.address), error))
            return false;
        ++registered;
    }
    error.clear();
    return true;
}

} // namespace nba16
