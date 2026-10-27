#include "module_exports.h"

#include "elf64_inspector.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <map>
#include <ostream>
#include <tuple>

namespace nba16 {
namespace {

constexpr std::uint32_t pt_sce_dynlibdata = 0x61000000;
constexpr std::uint64_t maximum_module_size = 512ULL * 1024ULL * 1024ULL;

bool range_fits(std::uint64_t offset, std::uint64_t length, std::uint64_t total) {
    return offset <= total && length <= total - offset;
}

template <typename T>
bool read_le(const std::vector<std::uint8_t>& bytes, std::uint64_t offset, T& value) {
    if (!range_fits(offset, sizeof(T), bytes.size())) {
        return false;
    }
    value = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        value |= static_cast<T>(bytes[static_cast<std::size_t>(offset) + index])
                 << static_cast<unsigned>(index * 8U);
    }
    return true;
}

std::string ascii_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        if (character >= 'A' && character <= 'Z') {
            return static_cast<char>(character - 'A' + 'a');
        }
        return static_cast<char>(character);
    });
    return value;
}

std::vector<std::string> candidate_file_stems(const std::string& module_name) {
    if (module_name == "libSceAppContentUtil") {
        return {"libSceAppContent"};
    }
    if (module_name == "libGameCustomDataDialog") {
        return {"libSceGameCustomDataDialog"};
    }
    return {};
}

std::string nid_hash(const DynamicSymbol& symbol) {
    if (!symbol.has_nid_indices) {
        return {};
    }
    const auto separator = symbol.name.find('#');
    return separator == std::string::npos ? std::string{} : symbol.name.substr(0, separator);
}

bool read_raw_elf_image(const std::filesystem::path& path, SelfProgramImage& image, std::string& error) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        error = "Não foi possível abrir o ELF do módulo.";
        return false;
    }
    const auto end = input.tellg();
    if (end < 64 || static_cast<std::uint64_t>(end) > maximum_module_size) {
        error = "Tamanho de ELF de módulo inválido ou acima do limite de leitura.";
        return false;
    }
    const auto file_size = static_cast<std::uint64_t>(end);
    std::vector<std::uint8_t> header(64);
    input.seekg(0, std::ios::beg);
    if (!input.read(reinterpret_cast<char*>(header.data()), 64) ||
        header[0] != 0x7f || header[1] != 'E' || header[2] != 'L' || header[3] != 'F' ||
        header[4] != 2 || header[5] != 1 || header[6] != 1) {
        error = "O módulo não é um ELF64 little-endian reconhecível.";
        return false;
    }

    std::uint64_t phoff{};
    std::uint16_t ehsize{}, phentsize{}, phnum{};
    if (!read_le(header, 24, image.entry_point) ||
        !read_le(header, 32, phoff) ||
        !read_le(header, 52, ehsize) ||
        !read_le(header, 54, phentsize) ||
        !read_le(header, 56, phnum) ||
        ehsize < 64 || phentsize < 56 ||
        !range_fits(phoff, static_cast<std::uint64_t>(phentsize) * phnum, file_size)) {
        error = "Cabeçalho ou tabela de segmentos ELF do módulo inválidos.";
        return false;
    }
    image.elf_type = 0;
    if (!read_le(header, 16, image.elf_type) || !read_le(header, 18, image.machine)) {
        error = "Tipo ou arquitetura ELF do módulo truncados.";
        return false;
    }
    image.os_abi = header[7];
    image.program_headers.reserve(phnum);
    image.segments.reserve(phnum);
    for (std::uint16_t index = 0; index < phnum; ++index) {
        const auto base = phoff + static_cast<std::uint64_t>(index) * phentsize;
        std::vector<std::uint8_t> bytes(56);
        input.clear();
        input.seekg(static_cast<std::streamoff>(base), std::ios::beg);
        if (!input.read(reinterpret_cast<char*>(bytes.data()), 56)) {
            error = "Cabeçalho de segmento ELF de módulo truncado.";
            return false;
        }
        ElfProgramHeaderSummary program{};
        if (!read_le(bytes, 0, program.type) || !read_le(bytes, 4, program.flags) ||
            !read_le(bytes, 8, program.file_offset) || !read_le(bytes, 16, program.virtual_address) ||
            !read_le(bytes, 32, program.file_size) || !read_le(bytes, 40, program.memory_size) ||
            !read_le(bytes, 48, program.alignment) ||
            !range_fits(program.file_offset, program.file_size, file_size)) {
            error = "Segmento ELF de módulo aponta para fora do arquivo.";
            return false;
        }
        image.program_headers.push_back(program);
        if (program.file_size == 0) {
            continue;
        }
        ProgramSegmentImage segment{};
        segment.program_header_index = index;
        segment.program_header = program;
        if (program.file_size > std::numeric_limits<std::size_t>::max()) {
            error = "Segmento ELF de módulo excede a memória disponível.";
            return false;
        }
        segment.file_bytes.resize(static_cast<std::size_t>(program.file_size));
        input.clear();
        input.seekg(static_cast<std::streamoff>(program.file_offset), std::ios::beg);
        if (!input.read(reinterpret_cast<char*>(segment.file_bytes.data()),
                        static_cast<std::streamsize>(segment.file_bytes.size()))) {
            error = "Falha ao ler o payload de um segmento ELF de módulo.";
            return false;
        }
        image.total_payload_bytes += segment.file_bytes.size();
        image.segments.push_back(std::move(segment));
    }
    return std::any_of(image.program_headers.begin(), image.program_headers.end(), [](const auto& header_entry) {
        return header_entry.type == pt_sce_dynlibdata;
    });
}

bool read_module_image(const std::filesystem::path& path, SelfProgramImage& image, std::string& error) {
    std::ifstream probe(path, std::ios::binary);
    std::array<std::uint8_t, 4> magic{};
    if (!probe.read(reinterpret_cast<char*>(magic.data()), static_cast<std::streamsize>(magic.size()))) {
        error = "Arquivo de módulo curto demais.";
        return false;
    }
    if (magic == std::array<std::uint8_t, 4>{0x7f, 'E', 'L', 'F'}) {
        return read_raw_elf_image(path, image, error);
    }
    if (magic == std::array<std::uint8_t, 4>{0x4f, 0x15, 0x3d, 0x1d}) {
        SelfHeaderSummary self{};
        EmbeddedElfSummary elf{};
        if (!inspect_sce_self_header(path, self, error) ||
            !inspect_embedded_elf_header(path, self, elf, error)) {
            return false;
        }
        return load_clear_self_program_image(path, self, elf, image, error);
    }
    error = "Formato do arquivo de módulo não é ELF ou SELF PS4 reconhecido.";
    return false;
}

} // namespace

bool load_ps4_module_program_image(const std::filesystem::path& path,
                                  SelfProgramImage& image,
                                  std::string& error) {
    return read_module_image(path, image, error);
}

bool inspect_module_exports(const Ps4DynamicLinkInfo& executable,
                            const std::filesystem::path& module_directory,
                            ModuleExportSummary& summary,
                            std::string& error) {
    std::error_code filesystem_error;
    if (!std::filesystem::is_directory(module_directory, filesystem_error) || filesystem_error) {
        error = "A pasta externa de módulos não existe ou não pode ser acessada.";
        return false;
    }
    std::map<std::string, std::filesystem::path> files_by_stem;
    for (std::filesystem::directory_iterator iterator(module_directory, filesystem_error), end;
         !filesystem_error && iterator != end; iterator.increment(filesystem_error)) {
        if (iterator->is_regular_file(filesystem_error) && !filesystem_error) {
            files_by_stem.emplace(ascii_lower(iterator->path().stem().string()), iterator->path());
        }
    }
    if (filesystem_error) {
        error = "Falha ao listar a pasta externa de módulos.";
        return false;
    }

    ModuleExportSummary parsed{};
    std::map<std::string, std::map<std::string, std::uint64_t>> exports_by_module;
    std::map<std::string, std::map<std::pair<std::string, std::string>, std::vector<std::uint8_t>>>
        exports_by_module_library_and_hash;
    std::map<std::tuple<std::string, std::string, std::string>,
             std::vector<const ModuleExportRecord*>> export_records_by_identity;
    std::map<std::string, std::size_t> module_summary_indices;
    for (const auto& module_entry : executable.import_modules) {
        const auto& module_name = module_entry.name;
        const auto key = ascii_lower(module_name);
        if (module_summary_indices.contains(key)) {
            continue;
        }
        ++parsed.modules_requested;
        ModuleFileSummary module{};
        module.module_name = module_name;
        auto file = files_by_stem.find(key);
        bool alias_candidate = false;
        if (file == files_by_stem.end()) {
            for (const auto& candidate_stem : candidate_file_stems(module_name)) {
                file = files_by_stem.find(ascii_lower(candidate_stem));
                if (file != files_by_stem.end()) {
                    alias_candidate = true;
                    break;
                }
            }
        }
        if (file == files_by_stem.end()) {
            module.status = "arquivo ausente";
        } else {
            module.file_name = file->second.filename().string();
            ++parsed.modules_found;
            SelfProgramImage module_image{};
            Ps4DynamicLinkInfo dynamic{};
            std::string module_error;
            if (!read_module_image(file->second, module_image, module_error) ||
                !read_ps4_dynamic_link_info(module_image, dynamic, module_error)) {
                module.status = "não analisado: " + module_error;
            } else {
                ++parsed.modules_parsed;
                std::map<std::uint32_t, std::uint64_t> relocation_references;
                for (const auto& relocation : dynamic.relocations) {
                    if (relocation.symbol_index != 0) ++relocation_references[relocation.symbol_index];
                }
                std::map<std::string, std::pair<std::uint64_t, std::uint64_t>>
                    imports_by_module_name;
                for (std::size_t symbol_index = 1; symbol_index < dynamic.symbols.size(); ++symbol_index) {
                    const auto& symbol = dynamic.symbols[symbol_index];
                    if (symbol.section_index != 0 || !symbol.has_nid_indices) continue;
                    const auto imported_module = std::find_if(
                        dynamic.import_modules.begin(), dynamic.import_modules.end(),
                        [&symbol](const DynamicImportModule& candidate) {
                            return candidate.module_id == symbol.nid_module_index;
                        });
                    if (imported_module == dynamic.import_modules.end()) continue;
                    auto& counts = imports_by_module_name[ascii_lower(imported_module->name)];
                    ++counts.first;
                    const auto references = relocation_references.find(
                        static_cast<std::uint32_t>(symbol_index));
                    if (references != relocation_references.end()) counts.second += references->second;
                }
                for (const auto& dependency : dynamic.needed_modules) {
                    ModuleDependencySummary dependency_summary{};
                    dependency_summary.name = dependency;
                    const auto dependency_stem = ascii_lower(
                        std::filesystem::path(dependency).stem().string());
                    if (const auto imported = imports_by_module_name.find(dependency_stem);
                        imported != imports_by_module_name.end()) {
                        dependency_summary.imported_symbols = imported->second.first;
                        dependency_summary.imported_references = imported->second.second;
                    }
                    const auto dependency_file = files_by_stem.find(dependency_stem);
                    if (dependency_file != files_by_stem.end()) {
                        dependency_summary.file_name = dependency_file->second.filename().string();
                        ++parsed.module_dependency_files_found;
                    } else {
                        ++parsed.module_dependency_files_missing;
                    }
                    module.dependencies.push_back(std::move(dependency_summary));
                    ++parsed.module_dependencies;
                }
                std::map<std::uint32_t, std::string> exported_library_names;
                for (const auto& library : dynamic.export_libraries) {
                    exported_library_names.emplace(library.library_id, library.name);
                    module.exported_libraries.push_back(library.name);
                }
                for (const auto& symbol : dynamic.symbols) {
                    if (symbol.section_index == 0) {
                        continue;
                    }
                    const auto hash = nid_hash(symbol);
                    if (!hash.empty()) {
                        ++exports_by_module[key][hash];
                        ++module.defined_nid_exports;
                        const auto library_name = exported_library_names.find(symbol.nid_library_index);
                        if (library_name != exported_library_names.end()) {
                            exports_by_module_library_and_hash[key]
                                [{library_name->second, hash}].push_back(symbol.info & 0x0fU);
                            parsed.export_catalog.push_back({
                                module_name,
                                library_name->second,
                                hash,
                                module.file_name,
                                symbol.value,
                                symbol.size,
                                static_cast<std::uint8_t>(symbol.info & 0x0fU)});
                        }
                    }
                }
                module.status = alias_candidate ? "metadados lidos via alias candidato"
                                                : "metadados lidos";
            }
        }
        module_summary_indices.emplace(key, parsed.modules.size());
        parsed.modules.push_back(std::move(module));
    }

    const auto module_name_for_id = [&](std::uint32_t module_id) -> const std::string* {
        const auto module = std::find_if(executable.import_modules.begin(),
                                         executable.import_modules.end(),
            [module_id](const DynamicImportModule& entry) { return entry.module_id == module_id; });
        return module == executable.import_modules.end() ? nullptr : &module->name;
    };
    const auto library_name_for_id = [&](std::uint32_t library_id) -> const std::string* {
        const auto library = std::find_if(executable.import_libraries.begin(),
                                          executable.import_libraries.end(),
            [library_id](const DynamicImportLibrary& entry) {
                return entry.library_id == library_id;
            });
        return library == executable.import_libraries.end() ? nullptr : &library->name;
    };
    const auto has_export = [&](std::uint32_t module_id, const std::string& hash) {
        const auto* module_name = module_name_for_id(module_id);
        if (module_name == nullptr) {
            return std::uint64_t{};
        }
        const auto key = ascii_lower(*module_name);
        const auto module_exports = exports_by_module.find(key);
        if (module_exports == exports_by_module.end()) {
            return std::uint64_t{};
        }
        const auto exported = module_exports->second.find(hash);
        return exported == module_exports->second.end() ? std::uint64_t{} : exported->second;
    };
    for (const auto& record : parsed.export_catalog) {
        export_records_by_identity[{ascii_lower(record.module_name),
                                    ascii_lower(record.library_name), record.nid}].push_back(&record);
    }
    for (const auto& symbol : executable.symbols) {
        if (symbol.section_index != 0 || !symbol.has_nid_indices) {
            continue;
        }
        ++parsed.import_symbols_checked;
        const auto hash = nid_hash(symbol);
        const auto* module_name = module_name_for_id(symbol.nid_module_index);
        const auto* library_name = library_name_for_id(symbol.nid_library_index);
        if (module_name != nullptr) {
            ++parsed.imports_with_module_id;
        }
        if (library_name != nullptr) {
            ++parsed.imports_with_library_id;
        }
        if (module_name != nullptr && library_name != nullptr) {
            ++parsed.imports_with_library_and_module;
            const auto module_key = ascii_lower(*module_name);
            const auto module_summary = module_summary_indices.find(module_key);
            if (module_summary != module_summary_indices.end()) {
                const auto& module = parsed.modules[module_summary->second];
                const auto library_matches = std::find_if(
                    module.exported_libraries.begin(), module.exported_libraries.end(),
                    [&](const std::string& exported_library) {
                        return ascii_lower(exported_library) == ascii_lower(*library_name);
                    });
                if (library_matches != module.exported_libraries.end()) {
                    ++parsed.pairs_matching_module_export_library;
                }
            }
            const auto module_libraries = exports_by_module_library_and_hash.find(module_key);
            if (module_libraries != exports_by_module_library_and_hash.end()) {
                const auto export_match = module_libraries->second.find({*library_name, hash});
                if (export_match != module_libraries->second.end()) {
                    ++parsed.matches_by_library_module_and_hash;
                    const auto expected_kind = static_cast<std::uint8_t>(symbol.info & 0x0fU);
                    const auto& export_kinds = export_match->second;
                    const bool expected_kind_is_known = expected_kind == 1U || expected_kind == 2U;
                    if (expected_kind_is_known &&
                        std::find(export_kinds.begin(), export_kinds.end(), expected_kind) !=
                            export_kinds.end()) {
                        ++parsed.matches_with_export_kind;
                    } else if (expected_kind_is_known) {
                        const auto has_known_kind = std::any_of(
                            export_kinds.begin(), export_kinds.end(),
                            [](std::uint8_t kind) { return kind == 1U || kind == 2U; });
                        if (has_known_kind) ++parsed.export_kind_mismatches;
                    }
                }
            }
            const auto candidates = export_records_by_identity.find(
                {module_key, ascii_lower(*library_name), hash});
            const auto expected_kind = static_cast<std::uint8_t>(symbol.info & 0x0fU);
            if (candidates != export_records_by_identity.end() &&
                (expected_kind == 1U || expected_kind == 2U)) {
                const ModuleExportRecord* unique_match = nullptr;
                std::size_t matching_kind_count = 0;
                for (const auto* candidate : candidates->second) {
                    if (candidate->elf_symbol_kind == expected_kind) {
                        unique_match = candidate;
                        ++matching_kind_count;
                    }
                }
                if (matching_kind_count == 1U) {
                    parsed.unique_import_bindings.push_back({
                        static_cast<std::uint32_t>(&symbol - executable.symbols.data()),
                        unique_match->module_name,
                        unique_match->library_name,
                        unique_match->nid,
                        unique_match->file_name,
                        unique_match->guest_virtual_value,
                        unique_match->size,
                        unique_match->elf_symbol_kind});
                }
            }
        }
        const auto by_id = has_export(symbol.nid_module_index, hash);
        const auto by_id_minus_one = symbol.nid_module_index == 0
                                         ? 0
                                         : has_export(symbol.nid_module_index - 1U, hash);
        if (by_id_minus_one != 0) {
            ++parsed.matches_using_module_id_minus_one;
        }
        if (by_id != 0) {
            ++parsed.matches_using_module_id;
            if (by_id > 1) {
                ++parsed.ambiguous_module_id_matches;
            }
        }
        if (const auto* module_name = module_name_for_id(symbol.nid_module_index)) {
            const auto key = ascii_lower(*module_name);
            const auto module_summary = module_summary_indices.find(key);
            if (module_summary != module_summary_indices.end()) {
                auto& module = parsed.modules[module_summary->second];
                ++module.imports_checked;
                if (by_id != 0) {
                    ++module.imports_matched;
                }
            }
        }
    }
    summary = std::move(parsed);
    return true;
}

void print_summary(const ModuleExportSummary& summary, std::ostream& output) {
    output << "\nInventário local de exports PS4 (somente metadados):\n";
    output << "  módulos pedidos=" << summary.modules_requested << " encontrados=" << summary.modules_found
           << " analisados=" << summary.modules_parsed << '\n';
    output << "  imports com NID verificados=" << summary.import_symbols_checked
           << " biblioteca-ID=" << summary.imports_with_library_id
           << " módulo-ID=" << summary.imports_with_module_id
           << " par biblioteca/módulo=" << summary.imports_with_library_and_module
           << " pares presentes nos exports do módulo="
           << summary.pairs_matching_module_export_library
           << " NID hash confirmado pelos três campos="
           << summary.matches_by_library_module_and_hash
           << " tipo ELF compatível=" << summary.matches_with_export_kind
           << " tipo ELF divergente=" << summary.export_kind_mismatches
           << " hashes encontrados pelo ID de módulo=" << summary.matches_using_module_id
           << " usando ID-1=" << summary.matches_using_module_id_minus_one
           << " ambiguidades pelo ID=" << summary.ambiguous_module_id_matches << '\n';
    output << "  Dependências transitivas registradas=" << summary.module_dependencies
           << " arquivos encontrados=" << summary.module_dependency_files_found
           << " ausentes=" << summary.module_dependency_files_missing << '\n';
    for (const auto& module : summary.modules) {
        output << "    " << module.module_name;
        if (!module.file_name.empty()) {
            output << " -> " << module.file_name;
        }
        output << ": " << module.defined_nid_exports << " exports NID; imports NID "
               << module.imports_matched << '/' << module.imports_checked << "; "
               << module.status << '\n';
        for (const auto& dependency : module.dependencies) {
            output << "      depende de " << dependency.name;
            if (!dependency.file_name.empty()) output << " -> " << dependency.file_name;
            else output << " (arquivo ausente na pasta)";
            output << "; imports=" << dependency.imported_symbols
                   << ", referências=" << dependency.imported_references;
            output << '\n';
        }
        for (const auto& library_name : module.exported_libraries) {
            output << "      biblioteca exportada: " << library_name << '\n';
        }
    }
    output << "  Só correspondência de hash não prova que o import pode ser chamado com a ABI esperada.\n";
    output << "  Catálogo em memória: " << summary.export_catalog.size()
           << " exports com identidade, tipo e VA ELF relativo; não são endereços de host.\n";
    output << "  Imports com export único por identidade e tipo: "
           << summary.unique_import_bindings.size() << '/' << summary.import_symbols_checked
           << "; VAs ainda relativos ao módulo.\n";
}

void write_export_catalog(const ModuleExportSummary& summary, std::ostream& output) {
    output << "module\tlibrary\tnid\telf_symbol_kind\tsize\tguest_virtual_value\tfile\n";
    for (const auto& entry : summary.export_catalog) {
        output << entry.module_name << '\t' << entry.library_name << '\t' << entry.nid << '\t'
               << static_cast<unsigned>(entry.elf_symbol_kind) << '\t' << entry.size << '\t'
               << "0x" << std::hex << entry.guest_virtual_value << std::dec << '\t'
               << entry.file_name << '\n';
    }
}

void write_unique_import_bindings(const ModuleExportSummary& summary, std::ostream& output) {
    output << "symbol_index\tmodule\tlibrary\tnid\telf_symbol_kind\tmodule_relative_value\tsize\tfile\n";
    for (const auto& binding : summary.unique_import_bindings) {
        output << binding.import_symbol_index << '\t' << binding.module_name << '\t'
               << binding.library_name << '\t' << binding.nid << '\t'
               << static_cast<unsigned>(binding.elf_symbol_kind) << '\t'
               << "0x" << std::hex << binding.module_relative_value << std::dec << '\t'
               << binding.size << '\t' << binding.file_name << '\n';
    }
}

} // namespace nba16
