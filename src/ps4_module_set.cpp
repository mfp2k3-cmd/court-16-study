#include "ps4_module_set.h"
#include "kernel_runtime.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <sstream>
#include <system_error>

namespace nba16 {
namespace {

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return character >= 'A' && character <= 'Z'
            ? static_cast<char>(character - 'A' + 'a') : static_cast<char>(character);
    });
    return value;
}

std::vector<std::string> module_stem_candidates(const std::string& name) {
    if (name == "libsceappcontentutil") return {"libSceAppContent"};
    if (name == "libgamecustomdatadialog") return {"libSceGameCustomDataDialog"};
    return {};
}

constexpr std::size_t missing_module = std::numeric_limits<std::size_t>::max();
constexpr std::size_t skipped_module = missing_module - 1U;

} // namespace

bool Ps4ModuleSet::load_dependencies(
    const std::vector<std::string>& roots,
    const std::vector<std::filesystem::path>& module_directories,
    ImportResolver& resolver,
    Ps4ModuleSetSummary& summary,
    std::string& error,
    const std::vector<std::string>& skip_missing_modules,
    const std::vector<std::string>& hle_modules) {
    if (!modules_.empty() || relocated_) {
        error = "Este conjunto de módulos já iniciou o carregamento.";
        return false;
    }
    if (module_directories.empty()) {
        error = "Nenhuma pasta de módulos PS4 foi informada.";
        return false;
    }
    std::map<std::string, std::filesystem::path> files;
    bool indexed_directory = false;
    for (const auto& module_directory : module_directories) {
        std::error_code filesystem_error;
        if (!std::filesystem::is_directory(module_directory, filesystem_error)) {
            if (filesystem_error) {
                error = "Falha ao acessar a pasta de módulos PS4: " + module_directory.string();
                return false;
            }
            continue;
        }
        indexed_directory = true;
        std::filesystem::recursive_directory_iterator iterator(
            module_directory, std::filesystem::directory_options::skip_permission_denied,
            filesystem_error);
        const std::filesystem::recursive_directory_iterator end;
        for (; !filesystem_error && iterator != end; iterator.increment(filesystem_error)) {
            if (!iterator->is_regular_file(filesystem_error) || filesystem_error) continue;
            const auto key = lower_ascii(iterator->path().stem().string());
            // Earlier directories have priority; the caller places game-bundled
            // modules before the external firmware module folder.
            files.try_emplace(key, iterator->path());
        }
        if (filesystem_error) {
            error = "Falha ao listar recursivamente a pasta de módulos PS4: " +
                    module_directory.string();
            return false;
        }
    }
    if (!indexed_directory) {
        error = "Nenhuma pasta de módulos PS4 existe ou pode ser lida.";
        return false;
    }
    std::set<std::string> skipped;
    std::set<std::string> hle;
    for (const auto& name : skip_missing_modules) {
        skipped.insert(lower_ascii(std::filesystem::path(name).stem().string()));
    }
    for (const auto& name : hle_modules) {
        hle.insert(lower_ascii(std::filesystem::path(name).stem().string()));
    }
    for (const auto& root : roots) {
        if (!load_one(root, files, skipped, hle, resolver, summary, error)) return false;
    }
    summary.modules_loaded = modules_.size();
    return true;
}

bool Ps4ModuleSet::load_one(
    const std::string& module_name,
    const std::map<std::string, std::filesystem::path>& files,
    const std::set<std::string>& skip_missing_modules,
    const std::set<std::string>& hle_modules,
    ImportResolver& resolver,
    Ps4ModuleSetSummary& summary,
    std::string& error) {
    const auto key = lower_ascii(std::filesystem::path(module_name).stem().string());
    if (const auto loaded = module_indices_.find(key); loaded != module_indices_.end()) {
        if (loaded->second == skipped_module) return true;
        if (loaded->second == missing_module) {
            error = "Dependência de módulo ausente: " + module_name;
            return false;
        }
        return true;
    }
    if (hle_modules.contains(key)) {
        module_indices_.emplace(key, skipped_module);
        ++summary.modules_skipped;
        summary.skipped_module_names.push_back(module_name + " (HLE)");
        return true;
    }
    auto file = files.find(key);
    if (file == files.end()) {
        for (const auto& candidate : module_stem_candidates(key)) {
            file = files.find(lower_ascii(candidate));
            if (file != files.end()) break;
        }
    }
    if (file == files.end()) {
        if (skip_missing_modules.contains(key)) {
            module_indices_.emplace(key, skipped_module);
            ++summary.modules_missing;
            ++summary.modules_skipped;
            summary.skipped_module_names.push_back(module_name);
            return true;
        }
        module_indices_.emplace(key, missing_module);
        ++summary.modules_missing;
        error = "Dependência de módulo ausente: " + module_name;
        return false;
    }

    SelfProgramImage module_image{};
    if (!load_ps4_module_program_image(file->second, module_image, error)) {
        error = "Falha ao inspecionar " + module_name + " antes da carga: " + error;
        return false;
    }
    const bool has_tls = std::any_of(module_image.program_headers.begin(),
                                     module_image.program_headers.end(),
        [](const ElfProgramHeaderSummary& header) { return header.type == 7U; });
    std::uint64_t tls_module_id = 0;
    if (has_tls) {
        if (next_tls_module_id_ == std::numeric_limits<std::uint64_t>::max()) {
            error = "A sequência de identificadores TLS excedeu o limite representável.";
            return false;
        }
        tls_module_id = ++next_tls_module_id_;
    }
    auto module = std::make_unique<Ps4LoadedModule>();
    if (!module->prepare(file->second, error, tls_module_id)) {
        module_indices_.emplace(key, missing_module);
        error = "Falha ao preparar " + module_name + ": " + error;
        return false;
    }
    const auto dependencies = module->dynamic_info().needed_modules;
    const auto export_module_name = std::filesystem::path(module_name).stem().string();
    const auto index = modules_.size();
    module_indices_.emplace(key, index);
    modules_.push_back({module_name, file->second, std::move(module)});

    std::vector<LoadedPs4Export> exports;
    if (!modules_.back().module->collect_exports(export_module_name, exports, error)) {
        error = "Falha ao catalogar exports de " + module_name + ": " + error;
        return false;
    }
    for (const auto& entry : exports) {
        const auto kind = entry.elf_symbol_kind == 1U
            ? GuestSymbolKind::object : GuestSymbolKind::function;
        if (!resolver.register_module_symbol(entry.library_name, entry.module_name,
                                             entry.nid, kind, entry.host_address, error,
                                             entry.library_version, entry.module_version)) {
            error = "Falha ao registrar export de " + module_name + ": " + error;
            return false;
        }
    }
    for (const auto& dependency : dependencies) {
        if (!load_one(dependency, files, skip_missing_modules, hle_modules,
                      resolver, summary, error)) {
            error = "Dependência requerida por " + module_name + ": " + error;
            return false;
        }
    }
    return true;
}

bool Ps4ModuleSet::relocate_all(ImportResolver& resolver,
                                Ps4ModuleSetSummary& summary,
                                std::string& error) {
    if (modules_.empty() || relocated_) {
        error = "A relocação exige um conjunto carregado e ainda não relocacionado.";
        return false;
    }
    std::vector<ImportResolution> resolutions;
    resolutions.reserve(modules_.size());
    summary.unresolved_symbols = 0;
    std::string unresolved_report;
    for (const auto& entry : modules_) {
        ImportResolution resolution{};
        if (!entry.module->resolve_imports(resolver, resolution, error)) {
            error = "Falha ao resolver imports de " + entry.module_name + ": " + error;
            return false;
        }
        summary.unresolved_symbols += resolution.unresolved.size();
        if (!resolution.unresolved.empty()) {
            unresolved_report += "\n" + entry.module_name + ": " +
                                 std::to_string(resolution.unresolved.size()) + " imports";
            for (const auto& item : resolution.unresolved) {
                unresolved_report += "\n  " + item.library + "/" + item.module + ": " + item.nid +
                         (item.expected_kind == GuestSymbolKind::function
                             ? " (função)" : " (objeto)") +
                         (item.kind_mismatch ? " (tipo incompatível)" : "") +
                         " refs=" + std::to_string(item.relocation_references);
                if (item.nid.empty()) {
                    unresolved_report += " [símbolo='" + item.symbol_name + "', índice=" +
                        std::to_string(item.symbol_index) + ", library_id=" +
                        std::to_string(item.library_id) + ", module_id=" +
                        std::to_string(item.module_id) + ", ELF info=0x";
                    std::ostringstream details;
                    details << std::hex << static_cast<unsigned>(item.elf_symbol_info)
                            << std::dec << ", referências=" << item.relocation_references;
                    unresolved_report += details.str() + "]";
                }
            }
        }
        resolutions.push_back(std::move(resolution));
    }
    if (!unresolved_report.empty()) {
        error = "Há " + std::to_string(summary.unresolved_symbols) +
                " imports pendentes no conjunto; nenhuma relocação importada ou proteção final foi aplicada." +
                unresolved_report;
        return false;
    }
    std::uint64_t sysctl_address{};
    std::uint64_t sysctlbyname_address{};
    for (const auto& item : resolver.code_interpositions()) {
        if (item.module != "libkernel.sprx" || !item.code_offset.has_value()) continue;
        if (*item.code_offset == 0x1010) sysctl_address = item.host_address;
        if (*item.code_offset == 0x1030) sysctlbyname_address = item.host_address;
    }
    if (sysctl_address == 0 || sysctlbyname_address == 0) {
        error = "destinos dos stubs sysctl do libkernel não foram registrados";
        return false;
    }
    summary.sysctl_stubs_redirected = 0;
    summary.sysctlbyname_stubs_redirected = 0;
    for (auto& entry : modules_) {
        const auto sysctl_before = summary.sysctl_stubs_redirected;
        const auto byname_before = summary.sysctlbyname_stubs_redirected;
        const auto query_before = summary.virtual_query_stubs_redirected;
        const auto virtual_query_address = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(&nba16_guest_virtual_query_thunk));
        if (!entry.module->redirect_sysctl_syscall_stubs(sysctl_address,
                sysctlbyname_address, virtual_query_address,
                summary.sysctl_stubs_redirected, summary.sysctlbyname_stubs_redirected,
                summary.virtual_query_stubs_redirected, error)) {
            error = "Falha ao localizar stubs de sysctl em " + entry.module_name + ": " + error;
            return false;
        }
        if (std::getenv("NBA16_TRACE_SYSCTL") != nullptr &&
            (summary.sysctl_stubs_redirected != sysctl_before ||
             summary.sysctlbyname_stubs_redirected != byname_before)) {
            std::fprintf(stderr, "SYSCTL stub scan module=%s sysctl=%zu byname=%zu\n",
                entry.module_name.c_str(),
                summary.sysctl_stubs_redirected - sysctl_before,
                summary.sysctlbyname_stubs_redirected - byname_before);
        }
        if (std::getenv("NBA16_TRACE_MEMORY") != nullptr &&
            summary.virtual_query_stubs_redirected != query_before) {
            std::fprintf(stderr, "MEM virtual-query stub scan module=%s count=%zu\n",
                entry.module_name.c_str(),
                summary.virtual_query_stubs_redirected - query_before);
        }
    }
    for (std::size_t index = 0; index < modules_.size(); ++index) {
        RelocationApplicationSummary relocation{};
        if (!modules_[index].module->apply_imports(
                resolutions[index].symbol_addresses, relocation, error)) {
            error = "Falha ao aplicar imports de " + modules_[index].module_name + ": " + error;
            return false;
        }
    }
    for (const auto& interposition : resolver.code_interpositions()) {
        if (interposition.code_offset.has_value() &&
            interposition.module == "libkernel.sprx" &&
            (*interposition.code_offset == 0x1010 || *interposition.code_offset == 0x1030)) {
            continue;
        }
        const auto module_key = lower_ascii(std::filesystem::path(interposition.module).stem().string());
        const auto found = module_indices_.find(module_key);
        if (found == module_indices_.end() || found->second >= modules_.size()) {
            error = "Módulo da interposição nativa não está carregado: " + interposition.module;
            return false;
        }
        auto& entry = modules_[found->second];
        const bool patched = interposition.code_offset.has_value()
            ? entry.module->redirect_function_offset(*interposition.code_offset,
                interposition.host_address, error)
            : entry.module->redirect_function_export(interposition.library,
                interposition.module, interposition.nid, interposition.host_address, error);
        if (!patched) {
            error = "Falha ao interpor export nativo em " + entry.module_name + ": " + error;
            return false;
        }
        if (std::getenv("NBA16_TRACE_FS") != nullptr &&
            interposition.module == "libkernel.sprx" &&
            (interposition.code_offset == 0x9d0 || interposition.code_offset == 0x11b0)) {
            const bool is_fstat = interposition.code_offset == 0x9d0;
            std::fprintf(stderr,
                "FS syscall stub redirected module=%s offset=0x%llx target=0x%llx (%s)\n",
                entry.module_name.c_str(),
                static_cast<unsigned long long>(*interposition.code_offset),
                static_cast<unsigned long long>(interposition.host_address),
                is_fstat ? "fstat/189" : "getdents/272");
        }
    }
    for (auto& entry : modules_) {
        if (!entry.module->finalize(error)) {
            error = "Falha ao finalizar " + entry.module_name + ": " + error;
            return false;
        }
        ++summary.modules_relocated;
    }
    relocated_ = true;
    return true;
}

std::size_t Ps4ModuleSet::size() const noexcept { return modules_.size(); }

std::vector<std::string> Ps4ModuleSet::loaded_module_names() const {
    std::vector<std::string> names;
    names.reserve(modules_.size());
    for (const auto& entry : modules_) names.push_back(entry.module_name);
    return names;
}

std::optional<std::filesystem::path> Ps4ModuleSet::loaded_module_path(
        std::string_view module_name) const {
    const auto found = module_indices_.find(lower_ascii(
        std::filesystem::path(module_name).stem().string()));
    if (found == module_indices_.end() || found->second >= modules_.size())
        return std::nullopt;
    return modules_[found->second].path;
}

const Ps4LoadedModule* Ps4ModuleSet::find(std::string_view module_name) const {
    const auto found = module_indices_.find(lower_ascii(std::filesystem::path(module_name).stem().string()));
    if (found == module_indices_.end() || found->second >= modules_.size()) return nullptr;
    return modules_[found->second].module.get();
}

std::vector<GuestTlsImage> Ps4ModuleSet::tls_images() const {
    std::vector<GuestTlsImage> images(static_cast<std::size_t>(next_tls_module_id_) + 1U);
    images[1].module_id = 1;
    for (const auto& entry : modules_) {
        const auto& image = entry.module->tls_image();
        if (image.module_id != 0 && image.module_id < images.size()) {
            images[static_cast<std::size_t>(image.module_id)] = image;
        }
    }
    return images;
}

bool Ps4ModuleSet::register_memory(GuestMemoryAccess& address_space,
                                   std::string& error) const {
    if (!relocated_) {
        error = "o espaço de endereços só pode registrar módulos após finalizar relocações e permissões";
        return false;
    }
    for (const auto& entry : modules_) {
        if (!address_space.add_image(entry.module->image_map(),
                                     entry.module->image_memory(), error)) {
            error = "falha ao registrar a memória ativa de " + entry.module_name + ": " + error;
            return false;
        }
    }
    error.clear();
    return true;
}

} // namespace nba16
