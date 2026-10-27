#include "ps4_dynamic_link.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <map>
#include <ostream>
#include <set>
#include <string_view>

namespace nba16 {
namespace {

constexpr std::uint32_t pt_dynamic = 2;
constexpr std::uint32_t pt_sce_dynlibdata = 0x61000000;
constexpr std::uint64_t dt_null = 0;
constexpr std::uint64_t dt_needed = 1;
constexpr std::uint64_t dt_init = 12;
constexpr std::uint64_t dt_fini = 13;
constexpr std::uint64_t dt_preinit_array = 32;
constexpr std::uint64_t dt_preinit_array_size = 33;
constexpr std::uint64_t dt_init_array = 25;
constexpr std::uint64_t dt_init_array_size = 27;
constexpr std::uint64_t dt_fini_array = 26;
constexpr std::uint64_t dt_fini_array_size = 28;
constexpr std::uint64_t dt_sce_needed_module = 0x6100000f;
constexpr std::uint64_t dt_sce_module_info = 0x6100000d;
constexpr std::uint64_t dt_sce_export_lib = 0x61000013;
constexpr std::uint64_t dt_sce_import_lib = 0x61000015;
constexpr std::uint64_t dt_sce_jmprel = 0x61000029;
constexpr std::uint64_t dt_sce_pltrelsz = 0x6100002d;
constexpr std::uint64_t dt_sce_rela = 0x6100002f;
constexpr std::uint64_t dt_sce_relasz = 0x61000031;
constexpr std::uint64_t dt_sce_relaent = 0x61000033;
constexpr std::uint64_t dt_sce_strtab = 0x61000035;
constexpr std::uint64_t dt_sce_strsz = 0x61000037;
constexpr std::uint64_t dt_sce_symtab = 0x61000039;
constexpr std::uint64_t dt_sce_syment = 0x6100003b;
constexpr std::uint64_t dt_sce_symtabsz = 0x6100003f;
constexpr std::uint64_t dynamic_entry_size = 16;
constexpr std::uint64_t symbol_entry_size = 24;
constexpr std::uint64_t rela_entry_size = 24;

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

bool read_string(const std::vector<std::uint8_t>& strings, std::uint64_t offset, std::string& value) {
    if (offset >= strings.size()) {
        return false;
    }
    const auto begin = strings.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto end = std::find(begin, strings.end(), 0);
    if (end == strings.end()) {
        return false;
    }
    value.assign(begin, end);
    return !value.empty();
}

bool decode_nid_index(std::string_view encoded, std::uint32_t& index) {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
    if (encoded.empty()) {
        return false;
    }
    std::uint32_t decoded = 0;
    for (const char character : encoded) {
        const auto* found = std::find(std::begin(alphabet), std::end(alphabet) - 1, character);
        if (found == std::end(alphabet) - 1) {
            return false;
        }
        const auto digit = static_cast<std::uint32_t>(found - alphabet);
        if (decoded > (std::numeric_limits<std::uint32_t>::max() - digit) / 64U) {
            return false;
        }
        decoded = decoded * 64U + digit;
    }
    index = decoded;
    return true;
}

const char* relocation_name(std::uint32_t type) {
    switch (type) {
    case 1: return "R_X86_64_64";
    case 6: return "R_X86_64_GLOB_DAT";
    case 7: return "R_X86_64_JUMP_SLOT";
    case 8: return "R_X86_64_RELATIVE";
    case 16: return "R_X86_64_DTPMOD64";
    case 17: return "R_X86_64_DTPOFF64";
    case 18: return "R_X86_64_TPOFF64";
    case 19: return "R_X86_64_TLSGD";
    case 20: return "R_X86_64_TLSLD";
    case 21: return "R_X86_64_DTPOFF32";
    case 22: return "R_X86_64_GOTTPOFF";
    case 23: return "R_X86_64_TPOFF32";
    default: return "unknown";
    }
}

} // namespace

bool read_ps4_dynamic_link_info(const SelfProgramImage& image,
                                Ps4DynamicLinkInfo& info,
                                std::string& error) {
    const ElfProgramHeaderSummary* dynamic = nullptr;
    const ElfProgramHeaderSummary* dynlibdata = nullptr;
    std::size_t dynlibdata_index = 0;
    for (std::size_t index = 0; index < image.program_headers.size(); ++index) {
        const auto& header = image.program_headers[index];
        if (header.type == pt_dynamic) {
            dynamic = &header;
        } else if (header.type == pt_sce_dynlibdata) {
            dynlibdata = &header;
            dynlibdata_index = index;
        }
    }
    if (dynamic == nullptr || dynlibdata == nullptr || dynamic->file_offset < dynlibdata->file_offset) {
        error = "ELF não contém a relação esperada entre PT_DYNAMIC e PT_SCE_DYNLIBDATA.";
        return false;
    }
    const auto dyn_segment = std::find_if(image.segments.begin(), image.segments.end(),
        [dynlibdata_index](const ProgramSegmentImage& segment) {
            return segment.program_header_index == dynlibdata_index;
        });
    if (dyn_segment == image.segments.end() || dyn_segment->file_bytes.size() != dynlibdata->file_size) {
        error = "Payload PT_SCE_DYNLIBDATA não está presente na imagem SELF em memória.";
        return false;
    }
    const auto& data = dyn_segment->file_bytes;
    const auto dynamic_offset = dynamic->file_offset - dynlibdata->file_offset;
    if (dynamic->file_size == 0 || dynamic->file_size % dynamic_entry_size != 0 ||
        !range_fits(dynamic_offset, dynamic->file_size, data.size())) {
        error = "PT_DYNAMIC não cabe no payload PT_SCE_DYNLIBDATA.";
        return false;
    }

    std::uint64_t string_offset = 0, string_size = 0;
    std::uint64_t symbol_offset = 0, symbol_size = 0, symbol_size_entry = 0;
    std::uint64_t rela_offset = 0, rela_size = 0, rela_size_entry = 0;
    std::uint64_t plt_offset = 0, plt_size = 0;
    bool has_terminator = false, has_string_offset = false, has_string_size = false;
    bool has_symbol_offset = false, has_symbol_size = false, has_symbol_entry = false;
    bool has_rela_offset = false, has_rela_size = false, has_rela_entry = false;
    bool has_plt_offset = false, has_plt_size = false;
    std::vector<std::uint64_t> needed_offsets;
    std::optional<std::uint32_t> project_name_offset;
    std::vector<std::uint64_t> module_values;
    std::vector<std::uint64_t> export_lib_values;
    std::vector<std::uint64_t> import_lib_values;
    std::optional<std::uint64_t> project_metadata_value;
    DynamicInitializationInfo initialization{};
    for (std::uint64_t offset = 0; offset < dynamic->file_size; offset += dynamic_entry_size) {
        std::uint64_t tag{}, value{};
        if (!read_le(data, dynamic_offset + offset, tag) ||
            !read_le(data, dynamic_offset + offset + 8U, value)) {
            error = "Entrada truncada em PT_DYNAMIC.";
            return false;
        }
        if (tag == dt_null) {
            has_terminator = true;
            break;
        }
        switch (tag) {
        case dt_sce_module_info:
            if (project_name_offset.has_value()) {
                error = "PT_DYNAMIC contém mais de um DT_SCE_MODULE_INFO.";
                return false;
            }
            project_metadata_value = value;
            project_name_offset = static_cast<std::uint32_t>(value & 0xffffffffU);
            break;
        case dt_init: initialization.init_function = value; break;
        case dt_fini: initialization.fini_function = value; break;
        case dt_preinit_array: initialization.preinit_array = value; break;
        case dt_preinit_array_size: initialization.preinit_array_size = value; break;
        case dt_init_array: initialization.init_array = value; break;
        case dt_init_array_size: initialization.init_array_size = value; break;
        case dt_fini_array: initialization.fini_array = value; break;
        case dt_fini_array_size: initialization.fini_array_size = value; break;
        case dt_needed: needed_offsets.push_back(value); break;
        case dt_sce_needed_module: module_values.push_back(value); break;
        case dt_sce_export_lib: export_lib_values.push_back(value); break;
        case dt_sce_import_lib: import_lib_values.push_back(value); break;
        case dt_sce_strtab: string_offset = value; has_string_offset = true; break;
        case dt_sce_strsz: string_size = value; has_string_size = true; break;
        case dt_sce_symtab: symbol_offset = value; has_symbol_offset = true; break;
        case dt_sce_symtabsz: symbol_size = value; has_symbol_size = true; break;
        case dt_sce_syment: symbol_size_entry = value; has_symbol_entry = true; break;
        case dt_sce_rela: rela_offset = value; has_rela_offset = true; break;
        case dt_sce_relasz: rela_size = value; has_rela_size = true; break;
        case dt_sce_relaent: rela_size_entry = value; has_rela_entry = true; break;
        case dt_sce_jmprel: plt_offset = value; has_plt_offset = true; break;
        case dt_sce_pltrelsz: plt_size = value; has_plt_size = true; break;
        default: break;
        }
    }
    if (!has_terminator || !has_string_offset || !has_string_size ||
        !has_symbol_offset || !has_symbol_size || !has_symbol_entry ||
        !has_rela_offset || !has_rela_size || !has_rela_entry ||
        !has_plt_offset || !has_plt_size || symbol_size_entry != symbol_entry_size ||
        rela_size_entry != rela_entry_size || symbol_size % symbol_entry_size != 0 ||
        rela_size % rela_entry_size != 0 || plt_size % rela_entry_size != 0 ||
        !range_fits(string_offset, string_size, data.size()) ||
        !range_fits(symbol_offset, symbol_size, data.size()) ||
        !range_fits(rela_offset, rela_size, data.size()) ||
        !range_fits(plt_offset, plt_size, data.size())) {
        error = "Tags ou intervalos da tabela dinâmica PS4 estão incompletos ou fora do payload.";
        return false;
    }

    std::vector<std::uint8_t> strings(data.begin() + static_cast<std::ptrdiff_t>(string_offset),
                                      data.begin() + static_cast<std::ptrdiff_t>(string_offset + string_size));
    Ps4DynamicLinkInfo parsed{};
    if (project_metadata_value.has_value()) {
        parsed.project_version = static_cast<std::uint16_t>(
            (*project_metadata_value >> 32U) & 0xffffU);
    }
    if (project_name_offset.has_value() &&
        !read_string(strings, *project_name_offset, parsed.project_name)) {
        error = "DT_SCE_MODULE_INFO aponta para um nome de módulo inválido.";
        return false;
    }
    for (const auto value : module_values) {
        DynamicImportModule module{};
        module.raw_value = value;
        module.module_id = static_cast<std::uint32_t>(value >> 48U);
        module.version = static_cast<std::uint16_t>((value >> 32U) & 0xffffU);
        module.string_offset = static_cast<std::uint32_t>(value & 0xffffffffU);
        if (!read_string(strings, module.string_offset, module.name)) {
            error = "DT_SCE_NEEDED_MODULE aponta para um nome de módulo inválido.";
            return false;
        }
        parsed.import_modules.push_back(std::move(module));
    }
    for (const auto offset : needed_offsets) {
        std::string module;
        if (!read_string(strings, offset, module)) {
            error = "DT_NEEDED aponta para uma string inválida.";
            return false;
        }
        parsed.needed_modules.push_back(std::move(module));
    }
    for (const auto value : import_lib_values) {
        DynamicImportLibrary library{};
        library.raw_value = value;
        library.library_id = static_cast<std::uint32_t>(value >> 48U);
        library.version = static_cast<std::uint16_t>((value >> 32U) & 0xffffU);
        library.string_offset = static_cast<std::uint32_t>(value & 0xffffffffU);
        if (!read_string(strings, library.string_offset, library.name)) {
            error = "DT_SCE_IMPORT_LIB aponta para um nome de biblioteca inválido.";
            return false;
        }
        parsed.import_libraries.push_back(std::move(library));
    }
    for (const auto value : export_lib_values) {
        DynamicExportLibrary library{};
        library.raw_value = value;
        library.library_id = static_cast<std::uint32_t>(value >> 48U);
        library.version = static_cast<std::uint16_t>((value >> 32U) & 0xffffU);
        library.string_offset = static_cast<std::uint32_t>(value & 0xffffffffU);
        if (!read_string(strings, library.string_offset, library.name)) {
            error = "DT_SCE_EXPORT_LIB aponta para um nome de biblioteca inválido.";
            return false;
        }
        parsed.export_libraries.push_back(std::move(library));
    }

    const auto symbol_count = symbol_size / symbol_entry_size;
    parsed.symbols.reserve(static_cast<std::size_t>(symbol_count));
    for (std::uint64_t index = 0; index < symbol_count; ++index) {
        const auto base = symbol_offset + index * symbol_entry_size;
        std::uint32_t name_offset{};
        DynamicSymbol symbol{};
        if (!read_le(data, base, name_offset) ||
            !read_le(data, base + 4U, symbol.info) ||
            !read_le(data, base + 5U, symbol.other) ||
            !read_le(data, base + 6U, symbol.section_index) ||
            !read_le(data, base + 8U, symbol.value) ||
            !read_le(data, base + 16U, symbol.size)) {
            error = "Símbolo dinâmico truncado.";
            return false;
        }
        if (name_offset != 0 && !read_string(strings, name_offset, symbol.name)) {
            error = "Símbolo dinâmico referencia uma string inválida.";
            return false;
        }
        const auto last_separator = symbol.name.rfind('#');
        if (last_separator != std::string::npos && last_separator + 1U < symbol.name.size()) {
            const auto previous_separator = symbol.name.rfind('#', last_separator - 1U);
            if (previous_separator != std::string::npos && previous_separator + 1U < last_separator) {
                symbol.has_nid_indices = decode_nid_index(
                    std::string_view(symbol.name).substr(previous_separator + 1U,
                                                         last_separator - previous_separator - 1U),
                    symbol.nid_library_index) &&
                    decode_nid_index(std::string_view(symbol.name).substr(last_separator + 1U),
                                     symbol.nid_module_index);
            }
        }
        parsed.symbols.push_back(std::move(symbol));
    }

    const auto append_relocations = [&](std::uint64_t offset, std::uint64_t size, bool is_plt) -> bool {
        for (std::uint64_t cursor = 0; cursor < size; cursor += rela_entry_size) {
            const auto base = offset + cursor;
            std::uint64_t info{};
            DynamicRelocation relocation{};
            if (!read_le(data, base, relocation.target) ||
                !read_le(data, base + 8U, info) ||
                !read_le(data, base + 16U, relocation.addend_bits)) {
                return false;
            }
            relocation.type = static_cast<std::uint32_t>(info & 0xffffffffU);
            relocation.symbol_index = static_cast<std::uint32_t>(info >> 32U);
            relocation.is_plt = is_plt;
            if (relocation.symbol_index >= parsed.symbols.size()) {
                return false;
            }
            parsed.relocations.push_back(relocation);
        }
        return true;
    };
    parsed.relocations.reserve(static_cast<std::size_t>((rela_size + plt_size) / rela_entry_size));
    if (!append_relocations(rela_offset, rela_size, false) ||
        !append_relocations(plt_offset, plt_size, true)) {
        error = "Relocação truncada ou índice de símbolo fora da tabela.";
        return false;
    }

    const auto array_size_is_valid = [](const std::optional<std::uint64_t>& address,
                                        const std::optional<std::uint64_t>& size) {
        return address.has_value() == size.has_value() &&
               (!size.has_value() || *size % sizeof(std::uint64_t) == 0);
    };
    if (!array_size_is_valid(initialization.preinit_array, initialization.preinit_array_size) ||
        !array_size_is_valid(initialization.init_array, initialization.init_array_size) ||
        !array_size_is_valid(initialization.fini_array, initialization.fini_array_size)) {
        error = "Tabela de inicializadores ELF tem endereço/tamanho incompletos ou entradas desalinhadas.";
        return false;
    }

    parsed.initialization = initialization;
    info = std::move(parsed);
    return true;
}

void print_summary(const Ps4DynamicLinkInfo& info, std::ostream& output) {
    std::map<std::uint32_t, std::uint64_t> counts;
    std::map<std::uint32_t, std::uint64_t> unresolved;
    std::map<std::string, std::uint64_t> undefined_relocation_refs;
    std::set<std::uint32_t> referenced_undefined_symbols;
    for (const auto& relocation : info.relocations) {
        ++counts[relocation.type];
        if (relocation.symbol_index != 0 &&
            info.symbols[relocation.symbol_index].section_index == 0) {
            ++unresolved[relocation.type];
            referenced_undefined_symbols.insert(relocation.symbol_index);
            const auto& symbol = info.symbols[relocation.symbol_index];
            const std::string category = symbol.name.empty() ? "sem nome" :
                (symbol.has_nid_indices ? "nome+NID" : "nome sem NID");
            ++undefined_relocation_refs[category];
        }
    }
    std::uint64_t undefined_symbols = 0;
    std::uint64_t undefined_empty_names = 0;
    std::uint64_t undefined_named_nid = 0;
    std::uint64_t undefined_named_no_nid = 0;
    std::map<std::pair<std::uint32_t, std::uint32_t>, std::uint64_t> nid_pairs;
    for (std::size_t index = 1; index < info.symbols.size(); ++index) {
        if (info.symbols[index].section_index == 0) {
            ++undefined_symbols;
            if (info.symbols[index].has_nid_indices) {
                ++undefined_named_nid;
                ++nid_pairs[{info.symbols[index].nid_library_index, info.symbols[index].nid_module_index}];
            } else if (info.symbols[index].name.empty()) {
                ++undefined_empty_names;
            } else {
                ++undefined_named_no_nid;
            }
        }
    }
    output << "\nMetadados dinâmicos independentes: " << info.needed_modules.size()
           << " bibliotecas, " << info.symbols.size() << " símbolos ("
           << undefined_symbols << " indefinidos), " << info.relocations.size() << " relocações.\n";
    for (const auto& [type, count] : counts) {
        output << "  R_X86-64 type " << type << " (" << relocation_name(type) << "): "
               << count << "; símbolos importados/indefinidos: " << unresolved[type] << '\n';
    }
    output << "  Símbolos indefinidos classificados: " << undefined_empty_names << " sem nome, "
           << undefined_named_nid << " com nome+NID, " << undefined_named_no_nid
           << " com nome sem NID; " << referenced_undefined_symbols.size()
           << " índices indefinidos são referenciados por relocações.\n";
    output << "  Relocações de símbolos indefinidos por categoria:";
    for (const auto& [category, count] : undefined_relocation_refs) {
        output << " " << category << "=" << count;
    }
    output << '\n';
    output << "  Amostra de símbolos importados:";
    std::size_t shown = 0;
    for (std::size_t index = 1; index < info.symbols.size() && shown < 12; ++index) {
        const auto& symbol = info.symbols[index];
        if (symbol.section_index == 0 && !symbol.name.empty()) {
            output << " " << symbol.name;
            ++shown;
        }
    }
    output << '\n';
    output << "  Amostra de imports nomeados sem índices NID:";
    shown = 0;
    for (std::size_t index = 1; index < info.symbols.size() && shown < 20; ++index) {
        const auto& symbol = info.symbols[index];
        if (symbol.section_index == 0 && !symbol.name.empty() && !symbol.has_nid_indices) {
            output << " " << symbol.name;
            ++shown;
        }
    }
    if (shown == 0) {
        output << " (nenhum)";
    }
    output << '\n';
    output << "  Bibliotecas DT_SCE_IMPORT_LIB: " << info.import_libraries.size() << '\n';
    output << "  Bibliotecas DT_SCE_EXPORT_LIB: " << info.export_libraries.size() << '\n';
    output << "  Projeto DT_SCE_MODULE_INFO: "
           << (info.project_name.empty() ? "(não declarado)" : info.project_name)
           << " versão=0x" << std::hex << info.project_version << std::dec << '\n';
    output << "  Módulos DT_SCE_NEEDED_MODULE: " << info.import_modules.size() << '\n';
    output << "  Inicialização ELF: DT_INIT=";
    if (info.initialization.init_function) {
        output << "0x" << std::hex << *info.initialization.init_function << std::dec;
    } else {
        output << "ausente";
    }
    output << "; DT_FINI=";
    if (info.initialization.fini_function) {
        output << "0x" << std::hex << *info.initialization.fini_function << std::dec;
    } else {
        output << "ausente";
    }
    output << "; init_array="
           << (info.initialization.init_array_size.value_or(0) / sizeof(std::uint64_t))
           << " entradas; preinit_array="
           << (info.initialization.preinit_array_size.value_or(0) / sizeof(std::uint64_t))
           << " entradas\n";
    output << "  Identificadores das tabelas (biblioteca/módulo no campo alto das tags):\n";
    for (std::size_t index = 0; index < info.import_modules.size(); ++index) {
        output << "    módulo id=" << info.import_modules[index].module_id
               << " versão=0x" << std::hex << info.import_modules[index].version << std::dec
               << " nome=" << info.import_modules[index].name << '\n';
    }
    for (const auto& library : info.import_libraries) {
        output << "    biblioteca id=" << library.library_id
               << " versão=0x" << std::hex << library.version << std::dec
               << " nome=" << library.name << '\n';
    }
    for (const auto& library : info.export_libraries) {
        output << "    export-library id=" << library.library_id
               << " versão=0x" << std::hex << library.version << std::dec
               << " nome=" << library.name << '\n';
    }
    output << "  Pares NID observados (índices codificados):\n";
    for (const auto& [pair, count] : nid_pairs) {
        output << "    lib-id=" << pair.first << " module-id=" << pair.second << ":" << count;
        const auto module = std::find_if(info.import_modules.begin(), info.import_modules.end(),
            [&pair](const DynamicImportModule& entry) { return entry.module_id == pair.second; });
        if (module != info.import_modules.end()) {
            output << " module=" << module->name;
        }
        const auto library = std::find_if(info.import_libraries.begin(), info.import_libraries.end(),
            [&pair](const DynamicImportLibrary& entry) { return entry.library_id == pair.first; });
        if (library != info.import_libraries.end()) {
            output << " library=" << library->name;
        }
        output << '\n';
    }
    output << "  A resolução dos símbolos importados ainda não foi executada.\n";
}

void write_import_nid_table(const Ps4DynamicLinkInfo& info, std::ostream& output) {
    std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>> relocation_counts;
    for (const auto& relocation : info.relocations) {
        if (relocation.symbol_index != 0 && relocation.symbol_index < info.symbols.size()) {
            ++relocation_counts[relocation.symbol_index][relocation.type];
        }
    }
    output << "symbol_index\telf_symbol_type\tsymbol_size\trelocation_refs\trelocation_types"
              "\tlibrary_id\tlibrary\tmodule_id\tmodule\tnid\n";
    for (std::size_t index = 1; index < info.symbols.size(); ++index) {
        const auto& symbol = info.symbols[index];
        if (symbol.section_index != 0 || !symbol.has_nid_indices) {
            continue;
        }
        const auto library = std::find_if(info.import_libraries.begin(), info.import_libraries.end(),
            [&symbol](const DynamicImportLibrary& entry) {
                return entry.library_id == symbol.nid_library_index;
            });
        const auto module = std::find_if(info.import_modules.begin(), info.import_modules.end(),
            [&symbol](const DynamicImportModule& entry) {
                return entry.module_id == symbol.nid_module_index;
            });
        const auto separator = symbol.name.find('#');
        const auto refs = relocation_counts.find(static_cast<std::uint32_t>(index));
        std::uint64_t reference_count = 0;
        if (refs != relocation_counts.end()) {
            for (const auto& [type, count] : refs->second) {
                (void)type;
                reference_count += count;
            }
        }
        output << index << '\t' << static_cast<unsigned>(symbol.info & 0x0fU) << '\t'
               << symbol.size << '\t' << reference_count << '\t';
        if (refs != relocation_counts.end()) {
            bool first_type = true;
            for (const auto& [type, count] : refs->second) {
                if (!first_type) output << ',';
                output << type << ':' << count;
                first_type = false;
            }
        }
        output << '\t' << symbol.nid_library_index << '\t'
               << (library == info.import_libraries.end() ? "?" : library->name) << '\t'
               << symbol.nid_module_index << '\t'
               << (module == info.import_modules.end() ? "?" : module->name) << '\t'
               << symbol.name.substr(0, separator) << '\n';
    }
}

} // namespace nba16
