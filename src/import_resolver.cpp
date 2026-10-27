#include "import_resolver.h"

#include <algorithm>
#include <limits>
#include <map>
#include <ostream>
#include <tuple>
#include <vector>

namespace nba16 {
namespace {

const DynamicImportLibrary* find_library(const Ps4DynamicLinkInfo& link_info, std::uint32_t id) {
    const auto found = std::find_if(link_info.import_libraries.begin(), link_info.import_libraries.end(),
        [id](const DynamicImportLibrary& library) { return library.library_id == id; });
    return found == link_info.import_libraries.end() ? nullptr : &*found;
}

const DynamicImportModule* find_module(const Ps4DynamicLinkInfo& link_info, std::uint32_t id) {
    const auto found = std::find_if(link_info.import_modules.begin(), link_info.import_modules.end(),
        [id](const DynamicImportModule& module) { return module.module_id == id; });
    return found == link_info.import_modules.end() ? nullptr : &*found;
}

std::string nid_hash(const std::string& symbol_name) {
    const auto separator = symbol_name.find('#');
    return separator == std::string::npos ? symbol_name : symbol_name.substr(0, separator);
}

} // namespace

bool ImportResolver::register_symbol(const std::string& library,
                                     const std::string& module,
                                     const std::string& nid,
                                     GuestSymbolKind kind,
                                     std::uint64_t guest_address,
                                     std::string& error,
                                     std::uint16_t library_version,
                                     std::uint16_t module_version) {
    if (library.empty() || module.empty() || nid.empty() || guest_address == 0 ||
        (kind != GuestSymbolKind::object && kind != GuestSymbolKind::function)) {
        error = "Registro de import inválido: identidade, tipo ou endereço convidado vazio.";
        return false;
    }
    const auto [entry, inserted] = symbols_.emplace(
        Key{library, module, nid, library_version, module_version},
        RegisteredSymbol{kind, guest_address, true});
    if (!inserted) {
        if (!entry->second.native) {
            entry->second = RegisteredSymbol{kind, guest_address, true};
            return true;
        }
        error = "Identidade de import registrada mais de uma vez: " + library + "/" + module + "/" + nid;
        return false;
    }
    (void)entry;
    return true;
}

bool ImportResolver::register_module_symbol(const std::string& library,
                                           const std::string& module,
                                           const std::string& nid,
                                           GuestSymbolKind kind,
                                           std::uint64_t guest_address,
                                           std::string& error,
                                           std::uint16_t library_version,
                                           std::uint16_t module_version) {
    if (library.empty() || module.empty() || nid.empty() || guest_address == 0 ||
        (kind != GuestSymbolKind::object && kind != GuestSymbolKind::function)) {
        error = "Registro de export de módulo inválido: identidade, tipo ou endereço vazio.";
        return false;
    }
    const Key key{library, module, nid, library_version, module_version};
    const Key native_wildcard{library, module, nid, any_version, any_version};
    const auto wildcard_found = symbols_.find(native_wildcard);
    if (wildcard_found != symbols_.end() && wildcard_found->second.native) return true;
    const auto found = symbols_.find(key);
    if (found != symbols_.end()) {
        if (found->second.native) return true;
        if (found->second.kind == kind && found->second.guest_address == guest_address) return true;
        error = "Exports de módulo ambíguos para a identidade " + library + "/" + module + "/" + nid;
        return false;
    }
    symbols_.emplace(key, RegisteredSymbol{kind, guest_address, false});
    return true;
}

bool ImportResolver::register_code_interposition(const std::string& library,
                                                 const std::string& module,
                                                 const std::string& nid,
                                                 std::uint64_t host_address,
                                                 std::string& error) {
    if (library.empty() || module.empty() || nid.empty() || host_address == 0) {
        error = "Interposição de código exige biblioteca, módulo, NID e endereço válidos.";
        return false;
    }
    const auto duplicate = std::find_if(code_interpositions_.begin(), code_interpositions_.end(),
        [&](const NativeCodeInterposition& entry) {
            return entry.library == library && entry.module == module && entry.nid == nid;
        });
    if (duplicate != code_interpositions_.end()) {
        error = "Interposição de código duplicada para " + library + "/" + module + "/" + nid;
        return false;
    }
    code_interpositions_.push_back({library, module, nid, host_address, std::nullopt});
    return true;
}

bool ImportResolver::register_code_offset_interposition(const std::string& module,
                                                        std::uint64_t code_offset,
                                                        std::uint64_t host_address,
                                                        std::string& error) {
    if (module.empty() || host_address == 0) {
        error = "Interposição por endereço exige módulo e destino válidos.";
        return false;
    }
    const auto duplicate = std::find_if(code_interpositions_.begin(), code_interpositions_.end(),
        [&](const NativeCodeInterposition& entry) {
            return entry.module == module && entry.code_offset == code_offset;
        });
    if (duplicate != code_interpositions_.end()) {
        error = "Interposição por endereço duplicada em " + module + ".";
        return false;
    }
    code_interpositions_.push_back({{}, module, {}, host_address, code_offset});
    return true;
}

const std::vector<NativeCodeInterposition>& ImportResolver::code_interpositions() const noexcept {
    return code_interpositions_;
}

bool ImportResolver::resolve(const Ps4DynamicLinkInfo& link_info,
                             ImportResolution& result,
                             std::string& error,
                             std::uint64_t local_load_bias) const {
    ImportResolution parsed{};
    parsed.symbol_addresses.resize(link_info.symbols.size());
    std::map<std::uint32_t, std::uint64_t> referenced;
    for (const auto& relocation : link_info.relocations) {
        if (relocation.type == 1 || relocation.type == 6 || relocation.type == 7) {
            if (relocation.symbol_index >= link_info.symbols.size()) {
                error = "Relocation de import referencia índice de símbolo fora da tabela.";
                return false;
            }
            if (relocation.symbol_index != 0) {
                ++referenced[relocation.symbol_index];
            }
        }
    }

    for (const auto& [index, relocation_references] : referenced) {
        const auto& symbol = link_info.symbols[index];
        if (symbol.section_index != 0) {
            if (local_load_bias == 0 || symbol.value >
                    std::numeric_limits<std::uint64_t>::max() - local_load_bias) {
                error = "Relocation importada aponta para símbolo local, mas o load bias local "
                        "não foi informado ou excede o espaço de endereçamento.";
                return false;
            }
            parsed.symbol_addresses[index] = local_load_bias + symbol.value;
            ++parsed.resolved_count;
            parsed.resolved_relocation_references += relocation_references;
            continue;
        }
        // ELF STB_WEAK undefined references resolve to zero when no definition
        // exists. Preserve zero as a resolved address so relocations still
        // apply their ABI-defined addend instead of treating it as missing HLE.
        if ((symbol.info >> 4U) == 2U) {
            parsed.symbol_addresses[index] = 0;
            ++parsed.resolved_count;
            parsed.resolved_relocation_references += relocation_references;
            ++parsed.unresolved_weak_zero_count;
            continue;
        }
        UnresolvedImport unresolved{};
        unresolved.symbol_index = index;
        unresolved.relocation_references = relocation_references;
        unresolved.symbol_name = symbol.name;
        unresolved.elf_symbol_info = symbol.info;
        unresolved.elf_section_index = symbol.section_index;
        unresolved.expected_kind = static_cast<GuestSymbolKind>(symbol.info & 0x0fU);
        if (unresolved.expected_kind != GuestSymbolKind::object &&
            unresolved.expected_kind != GuestSymbolKind::function) {
            unresolved.kind_mismatch = true;
        }
        if (symbol.has_nid_indices) {
            unresolved.library_id = symbol.nid_library_index;
            unresolved.module_id = symbol.nid_module_index;
            const auto* library = find_library(link_info, symbol.nid_library_index);
            if (library != nullptr) {
                unresolved.library = library->name;
            }
            const auto* module = find_module(link_info, symbol.nid_module_index);
            if (module != nullptr) {
                unresolved.module = module->name;
            }
            unresolved.nid = nid_hash(symbol.name);
            const auto library_version = library == nullptr ? any_version : library->version;
            const auto module_version = module == nullptr ? any_version : module->version;
            const auto exact = symbols_.find(Key{unresolved.library, unresolved.module,
                unresolved.nid, library_version, module_version});
            const auto wildcard = symbols_.find(Key{unresolved.library, unresolved.module,
                unresolved.nid, any_version, any_version});
            const auto found = exact != symbols_.end() ? exact : wildcard;
            if (found != symbols_.end() && found->second.kind == unresolved.expected_kind) {
                parsed.symbol_addresses[index] = found->second.guest_address;
                ++parsed.resolved_count;
                parsed.resolved_relocation_references += relocation_references;
                continue;
            }
            if (found != symbols_.end()) {
                unresolved.kind_mismatch = true;
            }
        } else {
            unresolved.nid.clear();
        }
        parsed.unresolved.push_back(std::move(unresolved));
    }
    result = std::move(parsed);
    return true;
}

void print_summary(const ImportResolution& resolution, std::ostream& output) {
    std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> by_library;
    std::uint64_t unresolved_references = 0;
    std::uint64_t pending_functions = 0;
    std::uint64_t pending_function_references = 0;
    std::uint64_t pending_objects = 0;
    std::uint64_t pending_object_references = 0;
    for (const auto& item : resolution.unresolved) {
        auto& totals = by_library[item.library.empty() ? "(sem identidade NID)" : item.library];
        ++totals.first;
        totals.second += item.relocation_references;
        unresolved_references += item.relocation_references;
        if (item.expected_kind == GuestSymbolKind::function) {
            ++pending_functions;
            pending_function_references += item.relocation_references;
        } else if (item.expected_kind == GuestSymbolKind::object) {
            ++pending_objects;
            pending_object_references += item.relocation_references;
        }
    }
    output << "\nResumo de resolução de imports PS4:\n"
           << "  símbolos resolvidos=" << resolution.resolved_count
           << "; referências resolvidas=" << resolution.resolved_relocation_references
           << "; símbolos fracos indefinidos ligados a zero="
           << resolution.unresolved_weak_zero_count << '\n'
           << "  símbolos pendentes=" << resolution.unresolved.size()
           << "; referências pendentes=" << unresolved_references << '\n';
    output << "  funções pendentes=" << pending_functions << " (" << pending_function_references
           << " referências); objetos pendentes=" << pending_objects << " ("
           << pending_object_references << " referências)\n";
    std::vector<std::pair<std::string, std::pair<std::uint64_t, std::uint64_t>>> rows(
        by_library.begin(), by_library.end());
    std::sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) {
        if (left.second.second != right.second.second) {
            return left.second.second > right.second.second;
        }
        return left.first < right.first;
    });
    for (std::size_t index = 0; index < std::min<std::size_t>(rows.size(), 12U); ++index) {
        output << "  " << rows[index].first << ": " << rows[index].second.first
               << " símbolos, " << rows[index].second.second << " referências\n";
    }
}

} // namespace nba16
