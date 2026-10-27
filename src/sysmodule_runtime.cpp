#include "sysmodule_runtime.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <unordered_map>

namespace nba16 {
namespace {

constexpr std::int32_t invalid_module_id = static_cast<std::int32_t>(0x805a1000U);
constexpr std::int32_t module_not_loaded = static_cast<std::int32_t>(0x805a1001U);

std::mutex module_refs_lock;
std::unordered_map<std::uint16_t, std::uint64_t> module_refs;

void trace_module_call(const char* operation, std::uint16_t module_id,
                       std::uint64_t references, std::int32_t result) {
    if (std::getenv("NBA16_TRACE_SYSMODULE") == nullptr) return;
    std::fprintf(stderr,
        "SYSMODULE %s id=0x%04x references=%llu result=0x%x\n",
        operation, static_cast<unsigned>(module_id),
        static_cast<unsigned long long>(references),
        static_cast<std::uint32_t>(result));
}

std::int32_t NBA16_GUEST_SYSV_ABI load_module(std::uint16_t module_id) {
    if (module_id == 0) return invalid_module_id;
    std::lock_guard lock(module_refs_lock);
    auto& references = module_refs[module_id];
    if (references != std::numeric_limits<std::uint64_t>::max()) ++references;
    trace_module_call("load", module_id, references, 0);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI is_module_loaded(std::uint16_t module_id) {
    if (module_id == 0) return invalid_module_id;
    std::lock_guard lock(module_refs_lock);
    const auto found = module_refs.find(module_id);
    if (found == module_refs.end() || found->second == 0) {
        trace_module_call("is-loaded", module_id, 0, module_not_loaded);
        return module_not_loaded;
    }
    trace_module_call("is-loaded", module_id, found->second, 0);
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI unload_module(std::uint16_t module_id) {
    if (module_id == 0) return invalid_module_id;
    std::lock_guard lock(module_refs_lock);
    const auto found = module_refs.find(module_id);
    if (found == module_refs.end() || found->second == 0) {
        trace_module_call("unload", module_id, 0, module_not_loaded);
        return module_not_loaded;
    }
    --found->second;
    const auto references = found->second;
    if (references == 0) module_refs.erase(found);
    trace_module_call("unload", module_id, references, 0);
    return 0;
}

} // namespace

bool register_native_sysmodule_imports(ImportResolver& resolver, std::string& error) {
    constexpr const char* library = "libSceSysmodule";
    constexpr const char* module = "libSceSysmodule";
    return resolver.register_function(library, module, "g8cM39EUZ6o",
               &load_module, error) &&
        resolver.register_function(library, module, "eR2bZFAAU0Q",
               &unload_module, error) &&
        resolver.register_function(library, module, "fMP5NHUOaMk",
               &is_module_loaded, error);
}

} // namespace nba16
