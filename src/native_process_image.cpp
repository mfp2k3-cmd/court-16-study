#include "native_process_image.h"

#include "ps4_module_loader.h"
#include "guest_tcb_runtime.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>
#include <vector>

namespace nba16 {

bool prepare_native_executable_image(const std::filesystem::path& executable_path,
                                     NativeExecutableImage& prepared,
                                     std::string& error) {
    NativeExecutableImage candidate{};
    if (!load_ps4_module_program_image(executable_path, candidate.image, error)) return false;
    if (!read_ps4_dynamic_link_info(candidate.image, candidate.dynamic, error)) return false;
    if (!build_guest_image_map(candidate.image, candidate.map, error) ||
        !candidate.memory.reserve_and_copy(candidate.map, error)) return false;
    if (!apply_relative_relocations(candidate.map, candidate.dynamic,
            candidate.memory.load_bias(), 1, candidate.relative_relocations, error))
        return false;
    prepared = std::move(candidate);
    error.clear();
    return true;
}

bool NativeExecutableImage::resolve_imports(const ImportResolver& resolver,
        ImportResolution& resolution, std::string& error) const {
    if (imported_relocations_applied) {
        error = "as importações do executável já foram aplicadas";
        return false;
    }
    return resolver.resolve(dynamic, resolution, error);
}

bool NativeExecutableImage::apply_imports(const ImportResolution& resolution,
        RelocationApplicationSummary& summary, std::string& error) {
    if (imported_relocations_applied) {
        error = "as importações do executável já foram aplicadas";
        return false;
    }
    if (!resolution.unresolved.empty()) {
        error = "não é possível aplicar imports enquanto houver símbolos pendentes";
        return false;
    }
    if (!apply_import_relocations(map, dynamic, resolution.symbol_addresses, summary, error))
        return false;
    imported_relocations_applied = true;
    return true;
}

bool NativeExecutableImage::patch_syscall_stubs(const ImportResolver& resolver,
        Ps4ModuleSetSummary& summary, std::string& error) {
    if (!imported_relocations_applied || memory_finalized || syscall_stubs_patched) {
        error = "stubs syscall exigem imports aplicados e só podem ser corrigidos uma vez";
        return false;
    }
    std::uint64_t sysctl_target{};
    std::uint64_t sysctlbyname_target{};
    for (const auto& item : resolver.code_interpositions()) {
        if (item.module != "libkernel.sprx" || !item.code_offset.has_value()) continue;
        if (*item.code_offset == 0x1010) sysctl_target = item.host_address;
        if (*item.code_offset == 0x1030) sysctlbyname_target = item.host_address;
    }

    constexpr std::array<std::byte, 12> sysctl_signature{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0xca},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05}};
    constexpr std::array<std::byte, 12> sysctlbyname_signature{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0xcb},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05}};
    struct Stub { std::uint64_t offset{}; std::uint64_t target{}; bool byname{}; };
    std::vector<Stub> stubs;
    for (const auto& region : map.regions) {
        if ((region.flags & 1U) == 0 || region.bytes.size() < sysctl_signature.size()) continue;
        for (std::size_t offset = 0; offset + sysctl_signature.size() <= region.bytes.size(); ++offset) {
            const auto* current = reinterpret_cast<const std::byte*>(region.bytes.data() + offset);
            if (std::equal(sysctl_signature.begin(), sysctl_signature.end(), current)) {
                stubs.push_back({region.virtual_address + offset, sysctl_target, false});
            } else if (std::equal(sysctlbyname_signature.begin(),
                                  sysctlbyname_signature.end(), current)) {
                stubs.push_back({region.virtual_address + offset, sysctlbyname_target, true});
            }
        }
    }
    for (const auto& stub : stubs) {
        if (stub.target == 0) {
            error = "destino do stub syscall do libkernel não está registrado";
            return false;
        }
        std::array<std::byte, 14> patch{
            std::byte{0xff}, std::byte{0x25}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}};
        std::memcpy(patch.data() + 6, &stub.target, sizeof(stub.target));
        if (!memory.write_loader_patch(map, memory.load_bias() + stub.offset, patch, error))
            return false;
        if (stub.byname) ++summary.sysctlbyname_stubs_redirected;
        else ++summary.sysctl_stubs_redirected;
    }
    syscall_stubs_patched = true;
    error.clear();
    return true;
}

bool NativeExecutableImage::finalize_memory(std::uint64_t& patched_tcb_loads,
        std::string& error) {
    if (!imported_relocations_applied || !syscall_stubs_patched || memory_finalized) {
        error = "finalização exige imports e stubs syscall aplicados e só pode ocorrer uma vez";
        return false;
    }
    if (!patch_guest_tcb_loads(map, memory, patched_tcb_loads, error) ||
        !memory.protect_after_relocations(map, error)) return false;
    memory_finalized = true;
    error.clear();
    return true;
}

bool NativeProcessModules::load_dependencies(
        const NativeExecutableImage& executable,
        const std::vector<std::filesystem::path>& module_directories,
        ImportResolver& resolver,
        const std::vector<std::string>& skip_missing_modules,
        const std::vector<std::string>& hle_modules,
        std::string& error) {
    if (dependencies_loaded_) {
        error = "as dependências do processo já foram carregadas";
        return false;
    }
    if (!modules_.load_dependencies(executable.dynamic.needed_modules, module_directories,
            resolver, summary_, error, skip_missing_modules, hle_modules)) return false;
    dependencies_loaded_ = true;
    return true;
}

bool NativeProcessModules::relocate(ImportResolver& resolver, std::string& error) {
    if (!dependencies_loaded_ || relocated_) {
        error = relocated_ ? "as dependências do processo já foram relocadas"
                           : "as dependências do processo ainda não foram carregadas";
        return false;
    }
    if (!modules_.relocate_all(resolver, summary_, error)) return false;
    relocated_ = true;
    return true;
}

Ps4ModuleSet& NativeProcessModules::modules() noexcept { return modules_; }
const Ps4ModuleSet& NativeProcessModules::modules() const noexcept { return modules_; }
Ps4ModuleSetSummary& NativeProcessModules::summary() noexcept { return summary_; }
const Ps4ModuleSetSummary& NativeProcessModules::summary() const noexcept { return summary_; }

} // namespace nba16
