#include "elf64_inspector.h"
#include "fiber_runtime.h"
#include "libc_runtime.h"
#include "kernel_runtime.h"
#include "posix_aio_imports.h"
#include "posix_fs_imports.h"
#include "sanitizer_fiber_imports.h"
#include "unsupported_posix_imports.h"
#include "guest_image_map.h"
#include "guest_image_memory.h"
#include "guest_call_bridge.h"
#include "import_resolver.h"
#include "module_exports.h"
#include "ps4_dynamic_link.h"
#include "self_program_image.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
    const bool write_imports = argc == 5 && std::string_view(argv[3]) == "--imports-tsv";
    const bool write_exports = argc == 5 && std::string_view(argv[3]) == "--exports-tsv";
    const bool write_bindings = argc == 5 && std::string_view(argv[3]) == "--bindings-tsv";
    const bool write_relocations = argc == 5 && std::string_view(argv[3]) == "--relocations-tsv";
    const bool dump_executable = argc == 4 && std::string_view(argv[2]) == "--dump-executable";
    if (argc < 2 || (argc > 3 && !write_imports && !write_exports && !write_bindings &&
                     !write_relocations && !dump_executable)) {
        std::cerr << "Uso: nba16-inspect <eboot.bin> [pasta-sys_modules [--imports-tsv|--exports-tsv|--bindings-tsv|--relocations-tsv arquivo.tsv]]\n"
                     "     nba16-inspect <eboot.bin> --dump-executable <saida.bin>\n";
        return 2;
    }

    std::ifstream input(argv[1], std::ios::binary);
    std::array<unsigned char, 4> signature{};
    if (input.read(reinterpret_cast<char*>(signature.data()), static_cast<std::streamsize>(signature.size())) &&
        signature == std::array<unsigned char, 4>{0x4f, 0x15, 0x3d, 0x1d}) {
        nba16::SelfHeaderSummary self{};
        std::string self_error;
        if (!nba16::inspect_sce_self_header(argv[1], self, self_error)) {
            std::cerr << "Cabeçalho SELF inválido: " << self_error << '\n';
            return 1;
        }
        nba16::print_summary(self, std::cout);
        nba16::EmbeddedElfSummary embedded{};
        std::string embedded_error;
        if (nba16::inspect_embedded_elf_header(argv[1], self, embedded, embedded_error)) {
            nba16::print_summary(embedded, std::cout);
            nba16::Ps4DependencySummary dependencies{};
            const bool has_module_directory = argc == 3 || write_imports || write_exports ||
                                              write_bindings || write_relocations;
            const auto module_directory = has_module_directory
                ? std::filesystem::path(argv[2]) : std::filesystem::path{};
            std::string dependency_error;
            if (nba16::inspect_ps4_dependencies(argv[1], self, embedded, module_directory,
                                                dependencies, dependency_error)) {
                nba16::print_summary(dependencies, std::cout);
            } else {
                std::cerr << "Dependências PS4 não analisadas: " << dependency_error << '\n';
                return 1;
            }
            nba16::SelfProgramImage image{};
            std::string image_error;
            if (!nba16::load_clear_self_program_image(argv[1], self, embedded, image, image_error)) {
                std::cerr << "Imagem lógica SELF não montada: " << image_error << '\n';
                return 1;
            }
            if (dump_executable) {
                const nba16::ProgramSegmentImage* executable_segment{};
                for (const auto& segment : image.segments) {
                    if (segment.program_header.type != 1U ||
                        (segment.program_header.flags & 1U) == 0) continue;
                    if (executable_segment != nullptr) {
                        std::cerr << "Extração cancelada: o SELF contém mais de um PT_LOAD executável.\n";
                        return 1;
                    }
                    executable_segment = &segment;
                }
                if (executable_segment == nullptr || executable_segment->file_bytes.empty()) {
                    std::cerr << "O SELF não contém um PT_LOAD executável extraível.\n";
                    return 1;
                }
                std::ofstream output(argv[3], std::ios::binary | std::ios::trunc);
                if (!output || !output.write(
                        reinterpret_cast<const char*>(executable_segment->file_bytes.data()),
                        static_cast<std::streamsize>(executable_segment->file_bytes.size()))) {
                    std::cerr << "Não foi possível gravar o segmento executável extraído.\n";
                    return 1;
                }
                std::cout << "Segmento executável extraído apenas para análise: "
                          << executable_segment->file_bytes.size() << " bytes; VA base=0x"
                          << std::hex << executable_segment->program_header.virtual_address
                          << std::dec << ".\n";
                return 0;
            }
            nba16::print_summary(image, std::cout);
            nba16::GuestImageMap memory_map{};
            std::string memory_map_error;
            if (!nba16::build_guest_image_map(image, memory_map, memory_map_error)) {
                std::cerr << "Mapa virtual não montado: " << memory_map_error << '\n';
                return 1;
            }
            nba16::print_summary(memory_map, std::cout);
            nba16::Ps4DynamicLinkInfo link_info{};
            std::string link_error;
            if (!nba16::read_ps4_dynamic_link_info(image, link_info, link_error)) {
                std::cerr << "Tabelas dinâmicas não lidas da imagem SELF: " << link_error << '\n';
                return 1;
            }
            if (write_relocations) {
                std::ofstream output(argv[4], std::ios::trunc);
                if (!output) {
                    std::cerr << "Não foi possível criar a tabela de relocações.\n";
                    return 1;
                }
                output << "target_va\trelocation_type\tsymbol_index\tis_plt\taddend\tlibrary\tmodule\tnid\n";
                for (const auto& relocation : link_info.relocations) {
                    if (relocation.symbol_index >= link_info.symbols.size()) continue;
                    const auto& symbol = link_info.symbols[relocation.symbol_index];
                    std::string library_name;
                    std::string module_name;
                    if (symbol.has_nid_indices) {
                        const auto library = std::find_if(link_info.import_libraries.begin(),
                            link_info.import_libraries.end(), [&](const auto& entry) {
                                return entry.library_id == symbol.nid_library_index;
                            });
                        if (library != link_info.import_libraries.end()) library_name = library->name;
                        const auto module = std::find_if(link_info.import_modules.begin(),
                            link_info.import_modules.end(), [&](const auto& entry) {
                                return entry.module_id == symbol.nid_module_index;
                            });
                        if (module != link_info.import_modules.end()) module_name = module->name;
                    }
                    const auto separator = symbol.name.find('#');
                    const auto nid = separator == std::string::npos
                        ? std::string{} : symbol.name.substr(0, separator);
                    output << std::hex << relocation.target << std::dec << '\t'
                           << relocation.type << '\t' << relocation.symbol_index << '\t'
                           << (relocation.is_plt ? 1 : 0) << '\t' << std::hex
                           << relocation.addend_bits << std::dec << '\t' << library_name << '\t'
                           << module_name << '\t' << nid << '\n';
                }
                if (!output) {
                    std::cerr << "Falha ao gravar a tabela de relocações.\n";
                    return 1;
                }
                std::cout << "Tabela de relocações gravada em " << argv[4] << ".\n";
                return 0;
            }
            nba16::print_summary(link_info, std::cout);
            if (link_info.initialization.init_function) {
                std::string initializer_error;
                if (!nba16::validate_guest_execute_access(memory_map,
                        *link_info.initialization.init_function, 1, initializer_error)) {
                    std::cerr << "DT_INIT não aponta para uma região executável: "
                              << initializer_error << '\n';
                    return 1;
                }
                std::cout << "  DT_INIT validado dentro de um PT_LOAD executável; ainda não chamado.\n";
            }
            nba16::ImportResolver import_resolver{};
            std::string fiber_registration_error;
            if (!nba16::register_native_fiber_imports(import_resolver,
                                                      fiber_registration_error)) {
                std::cerr << "Implementação nativa de libSceFiber indisponível: "
                          << fiber_registration_error << '\n';
            }
            std::string libc_registration_error;
            if (!nba16::register_native_libc_imports(import_resolver,
                                                     libc_registration_error)) {
                std::cerr << "Implementação nativa de libc indisponível: "
                          << libc_registration_error << '\n';
            }
            std::string kernel_registration_error;
            if (!nba16::register_native_kernel_runtime_imports(
                    import_resolver, kernel_registration_error)) {
                std::cerr << "Implementação nativa de runtime do kernel indisponível: "
                          << kernel_registration_error << '\n';
            }
            std::string aio_registration_error;
            if (!nba16::register_native_aio_imports(import_resolver,
                                                   aio_registration_error)) {
                std::cerr << "Implementação nativa AIO indisponível: "
                          << aio_registration_error << '\n';
            }
            std::string fs_registration_error;
            if (!nba16::register_native_posix_fs_imports(import_resolver,
                                                        fs_registration_error)) {
                std::cerr << "Implementação nativa POSIX de statfs indisponível: "
                          << fs_registration_error << '\n';
            }
            std::string sanitizer_registration_error;
            if (!nba16::register_native_sanitizer_fiber_imports(
                    import_resolver, sanitizer_registration_error)) {
                std::cerr << "Hooks de fibra do sanitizer indisponíveis: "
                          << sanitizer_registration_error << '\n';
            }
            std::string unavailable_registration_error;
            if (!nba16::register_native_unsupported_posix_imports(
                    import_resolver, unavailable_registration_error)) {
                std::cerr << "Bindings POSIX indisponíveis: "
                          << unavailable_registration_error << '\n';
            }
            if (write_imports) {
                std::ofstream imports_output(argv[4], std::ios::binary);
                if (!imports_output) {
                    std::cerr << "Não foi possível criar a tabela TSV de imports.\n";
                    return 1;
                }
                nba16::write_import_nid_table(link_info, imports_output);
                if (!imports_output) {
                    std::cerr << "Falha ao gravar a tabela TSV de imports.\n";
                    return 1;
                }
            }
            nba16::ImportResolution import_resolution{};
            std::string import_resolution_error;
            if (!import_resolver.resolve(link_info, import_resolution, import_resolution_error)) {
                std::cerr << "Inventário de imports falhou: " << import_resolution_error << '\n';
                return 1;
            }
            nba16::print_summary(import_resolution, std::cout);
            std::cout << "  ABI SysV x86-64 para callbacks convidados: "
                      << (nba16::guest_sysv_abi_available ? "disponível no compilador" : "exige thunk")
                      << " (nenhum callback foi chamado)\n";
            if (has_module_directory) {
                nba16::ModuleExportSummary module_exports{};
                std::string module_exports_error;
                if (nba16::inspect_module_exports(link_info, argv[2], module_exports,
                                                  module_exports_error)) {
                    nba16::print_summary(module_exports, std::cout);
                    if (write_exports) {
                        std::ofstream exports_output(argv[4], std::ios::binary);
                        if (!exports_output) {
                            std::cerr << "Não foi possível criar o catálogo TSV de exports.\n";
                            return 1;
                        }
                        nba16::write_export_catalog(module_exports, exports_output);
                        if (!exports_output) {
                            std::cerr << "Falha ao gravar o catálogo TSV de exports.\n";
                            return 1;
                        }
                    }
                    if (write_bindings) {
                        std::ofstream bindings_output(argv[4], std::ios::binary);
                        if (!bindings_output) {
                            std::cerr << "Não foi possível criar a tabela TSV de bindings.\n";
                            return 1;
                        }
                        nba16::write_unique_import_bindings(module_exports, bindings_output);
                        if (!bindings_output) {
                            std::cerr << "Falha ao gravar a tabela TSV de bindings.\n";
                            return 1;
                        }
                    }
                } else {
                    std::cerr << "Exports dos módulos locais não analisados: "
                              << module_exports_error << '\n';
                }
            }
            nba16::GuestImageMemory host_image{};
            std::string host_image_error;
            if (!host_image.reserve_and_copy(memory_map, host_image_error)) {
                std::cerr << "Reserva da imagem no espaço virtual do host falhou: "
                          << host_image_error << '\n';
                return 1;
            }
            nba16::RelocationApplicationSummary relocation_summary{};
            std::string relocation_error;
            if (!nba16::apply_relative_relocations(memory_map, link_info, host_image.load_bias(), 1,
                                                   relocation_summary, relocation_error)) {
                std::cerr << "Relocações relativas não aplicadas: " << relocation_error << '\n';
                return 1;
            }
            nba16::print_summary(relocation_summary, std::cout);
            nba16::GuestStartupPlan startup_plan{};
            std::string startup_plan_error;
            if (!nba16::build_guest_startup_plan(memory_map, link_info,
                                                  startup_plan, startup_plan_error)) {
                std::cerr << "Plano de inicialização ELF inválido: " << startup_plan_error << '\n';
                return 1;
            }
            std::cout << "  Callbacks ELF de inicialização validados="
                      << startup_plan.calls.size() << " (não executados)\n";
            for (const auto& call : startup_plan.calls) {
                std::cout << "    " << call.source << " em 0x" << std::hex
                          << call.guest_address << std::dec << '\n';
            }
            std::cout << "  Imagem copiada para reserva do host (RW/NX); entry point convidado=0x"
                      << std::hex << memory_map.entry_point << std::dec << '\n'
                      << "  Execução desabilitada: imports PS4 e inicialização de runtime ainda faltam.\n";
        } else {
            std::cerr << "ELF interno não analisado: " << embedded_error << '\n';
        }
        return 0;
    }

    nba16::ElfSummary summary{};
    std::string error;
    if (!nba16::inspect_elf64(argv[1], summary, error)) {
        std::cerr << "Não foi possível analisar o executável: " << error << '\n';
        return 1;
    }

    nba16::print_summary(summary, std::cout);
    return 0;
}
