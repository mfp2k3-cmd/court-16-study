#include "ps4_module_loader.h"

#include <fstream>
#include <algorithm>
#include <charconv>
#include <iostream>
#include <iomanip>
#include <map>
#include <string>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
    const bool write_imports = argc == 4 && std::string_view(argv[2]) == "--imports-tsv";
    const bool write_exports = argc == 4 && std::string_view(argv[2]) == "--exports-tsv";
    const bool write_relocations = argc == 4 && std::string_view(argv[2]) == "--relocations-tsv";
    const bool inspect_relocation_target = argc == 4 &&
        std::string_view(argv[2]) == "--relocation-target";
    std::uint64_t relocation_target{};
    if (inspect_relocation_target) {
        std::string_view value(argv[3]);
        if (value.starts_with("0x") || value.starts_with("0X")) value.remove_prefix(2);
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
                                            relocation_target, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
            std::cerr << "Endereço de relocação inválido.\n";
            return 2;
        }
    }
    if (argc < 2 || argc > 4 || argc == 3 ||
        (argc == 4 && !write_imports && !write_exports && !write_relocations && !inspect_relocation_target)) {
        std::cerr << "Uso: nba16-module-inspect <arquivo-prx-ou-self> "
                     "[--imports-tsv|--exports-tsv arquivo.tsv|--relocations-tsv arquivo.tsv|"
                     "--relocation-target endereço-hex]\n";
        return 2;
    }
    const std::filesystem::path path(argv[1]);
    const std::string module_name = path.stem().string();
    nba16::SelfProgramImage inspection_image{};
    std::string inspection_error;
    if (!nba16::load_ps4_module_program_image(path, inspection_image, inspection_error)) {
        std::cerr << "Imagem do módulo não lida: " << inspection_error << '\n';
        return 1;
    }
    const auto has_tls = std::any_of(inspection_image.program_headers.begin(),
                                     inspection_image.program_headers.end(),
        [](const nba16::ElfProgramHeaderSummary& header) { return header.type == 7U; });
    nba16::Ps4LoadedModule module{};
    std::string error;
    if (!module.prepare(path, error, has_tls ? 1U : 0U)) {
        std::cerr << "Módulo não preparado: " << error << '\n';
        // Preserve useful ELF/TLS diagnostics even when mapping stops at an
        // unsupported relocation. This is inspection only; no guest code runs.
        nba16::SelfProgramImage raw_image{};
        nba16::Ps4DynamicLinkInfo raw_dynamic{};
        std::string diagnostic_error;
        if (nba16::load_ps4_module_program_image(path, raw_image, diagnostic_error) &&
            nba16::read_ps4_dynamic_link_info(raw_image, raw_dynamic, diagnostic_error)) {
            std::map<std::uint32_t, std::uint64_t> counts;
            for (const auto& relocation : raw_dynamic.relocations) ++counts[relocation.type];
            std::cerr << "Diagnóstico da imagem sem relocar:\n";
            for (std::size_t i = 0; i < raw_image.program_headers.size(); ++i) {
                const auto& ph = raw_image.program_headers[i];
                if (ph.type == 7U) {
                    std::cerr << "  PT_TLS[" << i << "]: VA=0x" << std::hex << ph.virtual_address
                              << " filesz=0x" << ph.file_size << " memsz=0x" << ph.memory_size
                              << " align=0x" << ph.alignment << std::dec << '\n';
                }
            }
            for (const auto& [type, count] : counts)
                std::cerr << "  relocation type " << type << ": " << count << '\n';
            for (const auto& relocation : raw_dynamic.relocations) {
                const auto symbol_index = relocation.symbol_index;
                const bool tls_relocation = relocation.type >= 16U && relocation.type <= 23U;
                const bool symbol_relative_relocation = relocation.type == 8U && symbol_index != 0;
                if (!tls_relocation && !symbol_relative_relocation) continue;
                std::cerr << (tls_relocation ? "  TLS relocation type=" :
                                               "  Relative relocation with symbol type=")
                          << relocation.type << " symbol=" << symbol_index
                          << " target=0x" << std::hex << relocation.target << " addend=0x"
                          << relocation.addend_bits << std::dec;
                if (symbol_index < raw_dynamic.symbols.size()) {
                    const auto& symbol = raw_dynamic.symbols[symbol_index];
                    std::cerr << " name='" << symbol.name << "' value=0x" << std::hex << symbol.value
                              << " size=0x" << symbol.size << std::dec
                              << " shndx=" << symbol.section_index;
                }
                std::cerr << '\n';
            }
        } else {
            std::cerr << "Diagnóstico adicional indisponível: " << diagnostic_error << '\n';
        }
        return 1;
    }
    std::vector<nba16::LoadedPs4Export> exports;
    if (!module.collect_exports(module_name, exports, error)) {
        std::cerr << "Exports do módulo não validados: " << error << '\n';
        return 1;
    }
    const auto& image = module.image_map();
    const auto& dynamic = module.dynamic_info();
    if (inspect_relocation_target) {
        bool found = false;
        for (const auto& relocation : dynamic.relocations) {
            if (relocation.target != relocation_target) continue;
            found = true;
            std::cout << "Relocação em 0x" << std::hex << relocation.target << std::dec
                      << ": tipo=" << relocation.type << " PLT=" << relocation.is_plt
                      << " symbol_index=" << relocation.symbol_index;
            if (relocation.symbol_index < dynamic.symbols.size()) {
                const auto& symbol = dynamic.symbols[relocation.symbol_index];
                std::cout << " name='" << symbol.name << "' shndx=" << symbol.section_index;
                if (symbol.has_nid_indices) {
                    std::cout << " library_index=" << symbol.nid_library_index
                              << " module_index=" << symbol.nid_module_index;
                    for (const auto& library : dynamic.import_libraries) {
                        if (library.library_id == symbol.nid_library_index)
                            std::cout << " library='" << library.name << "'";
                    }
                    for (const auto& imported_module : dynamic.import_modules) {
                        if (imported_module.module_id == symbol.nid_module_index)
                            std::cout << " module='" << imported_module.name << "'";
                    }
                }
            }
            std::cout << '\n';
        }
        if (!found) std::cout << "Nenhuma relocação declarada no endereço indicado.\n";
        return 0;
    }
    nba16::print_summary(dynamic, std::cout);
    std::uint64_t relative_relocations = 0;
    std::uint64_t imported_relocations = 0;
    for (const auto& relocation : dynamic.relocations) {
        if (relocation.type == 8) ++relative_relocations;
        else if (relocation.type == 1 || relocation.type == 6 || relocation.type == 7)
            ++imported_relocations;
    }
    std::cout << "Módulo preparado sem executar código convidado.\n"
              << "  Regiões mapeadas: " << image.regions.size()
              << "; memória: " << image.mapped_memory_bytes << " bytes\n"
              << "  PT_TLS: módulo " << module.tls_image().module_id
              << "; imagem inicial=" << module.tls_image().initial_bytes.size()
              << "; memória=" << module.tls_image().memory_size
              << "; alinhamento=" << module.tls_image().alignment << " bytes\n"
              << "  Relocações relativas aplicadas: " << relative_relocations
              << "; imports ainda pendentes: " << imported_relocations << '\n'
              << "  Callbacks de inicialização validados (não executados): "
              << module.startup_plan().calls.size() << '\n'
              << "  Exports com VA convertido e segmento validado: " << exports.size() << '\n';
    std::cout << "  Módulos dependentes declarados: " << dynamic.needed_modules.size() << '\n';
    for (const auto& dependency : dynamic.needed_modules) {
        std::cout << "    " << dependency << '\n';
    }
    if (write_imports) {
        std::ofstream output(argv[3], std::ios::binary);
        if (!output) {
            std::cerr << "Não foi possível criar a tabela TSV de imports do módulo.\n";
            return 1;
        }
        nba16::write_import_nid_table(dynamic, output);
        if (!output) {
            std::cerr << "Falha ao gravar a tabela TSV de imports do módulo.\n";
            return 1;
        }
    }
    if (write_exports) {
        std::ofstream output(argv[3], std::ios::binary);
        if (!output) {
            std::cerr << "Não foi possível criar a tabela TSV de exports do módulo.\n";
            return 1;
        }
        output << "module\tlibrary\tnid\telf_symbol_kind\tsize\tmodule_relative_value\thost_address\n";
        for (const auto& entry : exports) {
            output << entry.module_name << '\t' << entry.library_name << '\t' << entry.nid << '\t'
                   << static_cast<unsigned>(entry.elf_symbol_kind) << '\t' << entry.size << '\t'
                   << "0x" << std::hex << entry.module_relative_value << '\t'
                   << "0x" << entry.host_address << std::dec << '\n';
        }
        if (!output) {
            std::cerr << "Falha ao gravar a tabela TSV de exports do módulo.\n";
            return 1;
        }
    }
    if (write_relocations) {
        std::ofstream output(argv[3], std::ios::binary);
        if (!output) {
            std::cerr << "Não foi possível criar a tabela TSV de relocações do módulo.\n";
            return 1;
        }
        output << "target\ttype\tplt\tsymbol_index\tsymbol\tlibrary\tmodule\taddend\n";
        for (const auto& relocation : dynamic.relocations) {
            output << "0x" << std::hex << relocation.target << '\t' << std::dec
                   << relocation.type << '\t' << relocation.is_plt << '\t'
                   << relocation.symbol_index << '\t';
            if (relocation.symbol_index < dynamic.symbols.size()) {
                const auto& symbol = dynamic.symbols[relocation.symbol_index];
                output << symbol.name << '\t';
                std::string_view library_name, module_name_for_symbol;
                if (symbol.has_nid_indices) {
                    for (const auto& library : dynamic.import_libraries)
                        if (library.library_id == symbol.nid_library_index) library_name = library.name;
                    for (const auto& imported_module : dynamic.import_modules)
                        if (imported_module.module_id == symbol.nid_module_index)
                            module_name_for_symbol = imported_module.name;
                }
                output << library_name << '\t' << module_name_for_symbol << '\t';
            } else {
                output << "\t\t\t";
            }
            output << "0x" << std::hex << relocation.addend_bits << std::dec << '\n';
        }
        if (!output) {
            std::cerr << "Falha ao gravar a tabela TSV de relocações do módulo.\n";
            return 1;
        }
    }
    nba16::ImportResolver empty_resolver{};
    nba16::ImportResolution unresolved{};
    if (!module.resolve_imports(empty_resolver, unresolved, error)) {
        std::cerr << "Imports do módulo não classificados: " << error << '\n';
        return 1;
    }
    nba16::print_summary(unresolved, std::cout);
    return 0;
}
