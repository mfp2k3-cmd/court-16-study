#include "elf64_inspector.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <limits>
#include <ostream>
#include <set>
#include <utility>

namespace nba16 {
namespace {

bool range_fits(std::uint64_t offset, std::uint64_t length, std::uint64_t total) {
    return offset <= total && length <= total - offset;
}

bool is_power_of_two(std::uint64_t value) {
    return value != 0 && (value & (value - 1U)) == 0;
}

template <typename T>
bool read_little_endian(const std::vector<std::uint8_t>& bytes, std::uint64_t offset, T& value) {
    if (!range_fits(offset, sizeof(T), bytes.size())) {
        return false;
    }

    value = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        const auto shift = static_cast<unsigned>(index * 8U);
        value |= static_cast<T>(bytes[static_cast<std::size_t>(offset) + index]) << shift;
    }
    return true;
}

bool read_file_range(std::ifstream& file, std::uint64_t offset, std::uint64_t length,
                     std::vector<std::uint8_t>& bytes, std::string& error) {
    if (length > std::numeric_limits<std::size_t>::max() ||
        offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
        length > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        error = "A faixa solicitada é grande demais para esta plataforma.";
        return false;
    }
    bytes.resize(static_cast<std::size_t>(length));
    file.clear();
    file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!bytes.empty() && !file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        error = "Não foi possível ler a faixa indicada no contêiner.";
        return false;
    }
    return true;
}

bool read_c_string(const std::vector<std::uint8_t>& table, std::uint64_t offset, std::string& value) {
    if (offset >= table.size()) {
        return false;
    }
    const auto begin = table.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto end = std::find(begin, table.end(), 0);
    if (end == table.end()) {
        return false;
    }
    value.assign(begin, end);
    return !value.empty();
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

} // namespace

bool inspect_elf64(const std::filesystem::path& path, ElfSummary& summary, std::string& error) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        error = "Não foi possível abrir o arquivo.";
        return false;
    }

    const auto end = file.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) > std::numeric_limits<std::size_t>::max()) {
        error = "Tamanho de arquivo inválido ou grande demais para esta plataforma.";
        return false;
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    file.seekg(0, std::ios::beg);
    if (!bytes.empty() && !file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        error = "Falha ao ler o arquivo inteiro.";
        return false;
    }
    if (bytes.size() < 64) {
        error = "Arquivo pequeno demais para conter um cabeçalho ELF64.";
        return false;
    }

    constexpr std::array<std::uint8_t, 4> magic{0x7f, 'E', 'L', 'F'};
    if (!std::equal(magic.begin(), magic.end(), bytes.begin())) {
        constexpr std::array<std::uint8_t, 4> sce_self_magic{0x4f, 0x15, 0x3d, 0x1d};
        if (std::equal(sce_self_magic.begin(), sce_self_magic.end(), bytes.begin())) {
            error = "Contêiner SCE SELF do PS4 detectado. Esta ferramenta não descriptografa nem extrai executáveis.";
            return false;
        }
        error = "Assinatura ELF ausente. O arquivo pode ser SELF criptografado ou não ser um ELF.";
        return false;
    }
    if (bytes[4] != 2) {
        error = "O arquivo ELF não é de 64 bits.";
        return false;
    }
    if (bytes[5] != 1) {
        error = "Somente ELF little-endian é suportado nesta etapa.";
        return false;
    }
    if (bytes[6] != 1) {
        error = "Versão ELF no identificador inválida ou não suportada.";
        return false;
    }

    ElfSummary parsed{};
    parsed.os_abi = bytes[7];
    std::uint16_t header_size{};
    std::uint16_t program_entry_size{};
    std::uint16_t program_count{};
    std::uint32_t elf_version{};
    std::uint64_t program_offset{};
    if (!read_little_endian(bytes, 16, parsed.type) ||
        !read_little_endian(bytes, 18, parsed.machine) ||
        !read_little_endian(bytes, 24, parsed.entry_point) ||
        !read_little_endian(bytes, 32, program_offset) ||
        !read_little_endian(bytes, 20, elf_version) ||
        !read_little_endian(bytes, 52, header_size) ||
        !read_little_endian(bytes, 54, program_entry_size) ||
        !read_little_endian(bytes, 56, program_count)) {
        error = "Cabeçalho ELF truncado.";
        return false;
    }
    if (header_size < 64 || program_entry_size < 56) {
        error = "Tamanho de cabeçalho ou de entrada de programa inválido.";
        return false;
    }
    if (elf_version != 1) {
        error = "Versão ELF no cabeçalho inválida ou não suportada.";
        return false;
    }
    const auto table_size = static_cast<std::uint64_t>(program_entry_size) * program_count;
    if (!range_fits(program_offset, table_size, bytes.size())) {
        error = "Tabela de segmentos ELF fora dos limites do arquivo.";
        return false;
    }

    for (std::uint16_t index = 0; index < program_count; ++index) {
        const auto base = program_offset + static_cast<std::uint64_t>(index) * program_entry_size;
        std::uint32_t segment_type{};
        if (!read_little_endian(bytes, base, segment_type)) {
            error = "Entrada de segmento ELF truncada.";
            return false;
        }
        if (segment_type != 1) { // PT_LOAD
            continue;
        }

        LoadSegment segment{};
        if (!read_little_endian(bytes, base + 4, segment.flags) ||
            !read_little_endian(bytes, base + 8, segment.file_offset) ||
            !read_little_endian(bytes, base + 16, segment.virtual_address) ||
            !read_little_endian(bytes, base + 32, segment.file_size) ||
            !read_little_endian(bytes, base + 40, segment.memory_size) ||
            !read_little_endian(bytes, base + 48, segment.alignment)) {
            error = "Campos do segmento ELF truncados.";
            return false;
        }
        if (!range_fits(segment.file_offset, segment.file_size, bytes.size())) {
            error = "Dados de um segmento carregável ultrapassam o fim do arquivo.";
            return false;
        }
        if (segment.file_size > segment.memory_size) {
            error = "Um segmento declara mais bytes no arquivo do que na memória.";
            return false;
        }
        if (segment.virtual_address > std::numeric_limits<std::uint64_t>::max() - segment.memory_size) {
            error = "Intervalo virtual de um segmento carregável excede o limite de endereços.";
            return false;
        }
        if (segment.alignment > 1 &&
            (!is_power_of_two(segment.alignment) || segment.file_offset % segment.alignment !=
                                                       segment.virtual_address % segment.alignment)) {
            parsed.warnings.emplace_back("Um segmento PT_LOAD tem alinhamento incompatível com as regras ELF.");
        }
        if ((segment.flags & 0x3U) == 0x3U) {
            parsed.warnings.emplace_back("Um segmento PT_LOAD é gravável e executável ao mesmo tempo.");
        }
        if ((segment.flags & 0x1U) != 0 && parsed.entry_point >= segment.virtual_address &&
            parsed.entry_point < segment.virtual_address + segment.memory_size) {
            parsed.entry_point_in_executable_segment = true;
        }
        parsed.load_segments.push_back(segment);
    }

    if (parsed.load_segments.empty()) {
        error = "O ELF não contém segmentos PT_LOAD.";
        return false;
    }
    if (!parsed.entry_point_in_executable_segment) {
        parsed.warnings.emplace_back("O ponto de entrada não está dentro de um segmento PT_LOAD executável.");
    }
    summary = std::move(parsed);
    return true;
}

bool inspect_sce_self_header(const std::filesystem::path& path, SelfHeaderSummary& summary, std::string& error) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        error = "Não foi possível abrir o arquivo.";
        return false;
    }
    const auto end = file.tellg();
    if (end < 28) {
        error = "Arquivo curto demais para conter o cabeçalho SCE SELF.";
        return false;
    }
    const auto actual_size = static_cast<std::uint64_t>(static_cast<std::streamoff>(end));
    std::array<std::uint8_t, 28> header{};
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()))) {
        error = "Falha ao ler o cabeçalho SCE SELF.";
        return false;
    }

    constexpr std::array<std::uint8_t, 4> magic{0x4f, 0x15, 0x3d, 0x1d};
    if (!std::equal(magic.begin(), magic.end(), header.begin())) {
        error = "Assinatura SCE SELF ausente.";
        return false;
    }

    SelfHeaderSummary parsed{};
    parsed.version = header[4];
    parsed.mode = header[5];
    parsed.endian = header[6];
    parsed.attributes = header[7];
    const std::vector<std::uint8_t> header_bytes(header.begin(), header.end());
    if (!read_little_endian(header_bytes, 8, parsed.key_type) ||
        !read_little_endian(header_bytes, 12, parsed.header_size) ||
        !read_little_endian(header_bytes, 14, parsed.metadata_size) ||
        !read_little_endian(header_bytes, 16, parsed.declared_file_size) ||
        !read_little_endian(header_bytes, 24, parsed.entry_count) ||
        !read_little_endian(header_bytes, 26, parsed.flags)) {
        error = "Campos do cabeçalho SCE SELF incompletos.";
        return false;
    }
    if (parsed.header_size < header.size() || parsed.header_size > actual_size || parsed.metadata_size > actual_size) {
        error = "Tamanhos declarados no cabeçalho SCE SELF são inconsistentes com o arquivo.";
        return false;
    }
    const auto metadata_end = static_cast<std::uint64_t>(parsed.header_size) + parsed.metadata_size;
    constexpr std::uint64_t self_entry_size = 32;
    constexpr std::uint64_t entries_start = 32;
    const auto entries_size = self_entry_size * parsed.entry_count;
    if (metadata_end > actual_size || entries_start > metadata_end ||
        entries_size > metadata_end - entries_start) {
        error = "Tabela de entradas SELF ultrapassa a área de cabeçalho/metadata declarada.";
        return false;
    }

    parsed.entries.reserve(parsed.entry_count);
    for (std::uint16_t index = 0; index < parsed.entry_count; ++index) {
        const auto base = entries_start + static_cast<std::uint64_t>(index) * self_entry_size;
        std::array<std::uint8_t, 32> entry_bytes{};
        file.clear();
        file.seekg(static_cast<std::streamoff>(base), std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(entry_bytes.data()), static_cast<std::streamsize>(entry_bytes.size()))) {
            error = "Falha ao ler uma entrada da tabela SELF.";
            return false;
        }
        const std::vector<std::uint8_t> entry_data(entry_bytes.begin(), entry_bytes.end());
        SelfEntrySummary entry{};
        std::copy_n(entry_bytes.begin(), entry.properties.size(), entry.properties.begin());
        if (!read_little_endian(entry_data, 8, entry.offset) ||
            !read_little_endian(entry_data, 16, entry.encoded_size) ||
            !read_little_endian(entry_data, 24, entry.decoded_size)) {
            error = "Campos de uma entrada SELF estão truncados.";
            return false;
        }
        if (!range_fits(entry.offset, entry.encoded_size, actual_size)) {
            error = "Uma entrada SELF aponta para fora dos limites do arquivo.";
            return false;
        }
        if (!read_little_endian(entry_data, 0, entry.property_bits)) {
            error = "Propriedades de uma entrada SELF estão truncadas.";
            return false;
        }
        entry.ordered = (entry.property_bits & 0x1U) != 0;
        entry.encrypted = (entry.property_bits & 0x2U) != 0;
        entry.signed_data = (entry.property_bits & 0x4U) != 0;
        entry.compressed = (entry.property_bits & 0x8U) != 0;
        entry.window_bits = static_cast<std::uint8_t>((entry.property_bits >> 8U) & 0x7U);
        entry.has_blocks = (entry.property_bits & 0x800U) != 0;
        entry.block_bits = static_cast<std::uint8_t>((entry.property_bits >> 12U) & 0xfU);
        entry.has_digest = (entry.property_bits & 0x10000U) != 0;
        entry.has_extents = (entry.property_bits & 0x20000U) != 0;
        entry.segment_index = static_cast<std::uint16_t>((entry.property_bits >> 20U) & 0xffffU);
        parsed.entries.push_back(entry);
    }
    parsed.actual_file_size = actual_size;
    parsed.trailing_bytes = actual_size > parsed.declared_file_size ? actual_size - parsed.declared_file_size : 0;
    summary = parsed;
    return true;
}

bool inspect_embedded_elf_header(const std::filesystem::path& path, const SelfHeaderSummary& self,
                                 EmbeddedElfSummary& summary, std::string& error) {
    constexpr std::uint64_t self_header_struct_size = 32;
    constexpr std::uint64_t self_entry_size = 32;
    const auto elf_offset = self_header_struct_size + self_entry_size * self.entry_count;

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "Não foi possível reabrir o contêiner SELF.";
        return false;
    }
    std::array<std::uint8_t, 64> header{};
    file.seekg(static_cast<std::streamoff>(elf_offset), std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()))) {
        error = "Não há cabeçalho ELF completo após as entradas SELF.";
        return false;
    }
    constexpr std::array<std::uint8_t, 4> elf_magic{0x7f, 'E', 'L', 'F'};
    if (!std::equal(elf_magic.begin(), elf_magic.end(), header.begin()) || header[4] != 2 || header[5] != 1) {
        error = "A posição após a tabela SELF não contém um ELF64 little-endian reconhecível.";
        return false;
    }

    const std::vector<std::uint8_t> header_bytes(header.begin(), header.end());
    EmbeddedElfSummary parsed{};
    parsed.container_offset = elf_offset;
    parsed.os_abi = header[7];
    std::uint64_t program_offset{};
    std::uint16_t elf_header_size{};
    std::uint16_t program_count{};
    if (!read_little_endian(header_bytes, 16, parsed.type) ||
        !read_little_endian(header_bytes, 18, parsed.machine) ||
        !read_little_endian(header_bytes, 24, parsed.entry_point) ||
        !read_little_endian(header_bytes, 32, program_offset) ||
        !read_little_endian(header_bytes, 52, elf_header_size) ||
        !read_little_endian(header_bytes, 54, parsed.program_entry_size) ||
        !read_little_endian(header_bytes, 56, program_count)) {
        error = "Cabeçalho ELF interno truncado.";
        return false;
    }
    if (elf_header_size < 64 || parsed.program_entry_size < 56) {
        error = "Tamanhos do cabeçalho ELF interno inválidos.";
        return false;
    }
    const auto table_size = static_cast<std::uint64_t>(parsed.program_entry_size) * program_count;
    if (!range_fits(program_offset, table_size, self.actual_file_size - elf_offset)) {
        error = "Tabela de cabeçalhos de programa ELF fora dos limites do contêiner.";
        return false;
    }

    parsed.program_headers.reserve(program_count);
    for (std::uint16_t index = 0; index < program_count; ++index) {
        const auto relative = program_offset + static_cast<std::uint64_t>(index) * parsed.program_entry_size;
        std::array<std::uint8_t, 56> bytes{};
        file.clear();
        file.seekg(static_cast<std::streamoff>(elf_offset + relative), std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
            error = "Cabeçalho de programa ELF interno truncado.";
            return false;
        }
        const std::vector<std::uint8_t> fields(bytes.begin(), bytes.end());
        ElfProgramHeaderSummary program{};
        if (!read_little_endian(fields, 0, program.type) ||
            !read_little_endian(fields, 4, program.flags) ||
            !read_little_endian(fields, 8, program.file_offset) ||
            !read_little_endian(fields, 16, program.virtual_address) ||
            !read_little_endian(fields, 32, program.file_size) ||
            !read_little_endian(fields, 40, program.memory_size) ||
            !read_little_endian(fields, 48, program.alignment)) {
            error = "Campos de cabeçalho de programa ELF interno truncados.";
            return false;
        }
        if (program.type == 1 && program.virtual_address >
                                     std::numeric_limits<std::uint64_t>::max() - program.memory_size) {
            error = "Intervalo virtual de um cabeçalho PT_LOAD interno excede o limite de endereços.";
            return false;
        }
        if (program.type == 1 && program.memory_size < program.file_size) {
            error = "Cabeçalho PT_LOAD interno declara bytes de arquivo além do tamanho em memória.";
            return false;
        }
        if (program.type == 1 && program.alignment > 1 &&
            (!is_power_of_two(program.alignment) || program.file_offset % program.alignment !=
                                                       program.virtual_address % program.alignment)) {
            parsed.warnings.emplace_back("Um cabeçalho PT_LOAD interno tem alinhamento incompatível com as regras ELF.");
        }
        if (program.type == 1 && (program.flags & 0x1U) != 0 &&
            parsed.entry_point >= program.virtual_address &&
            parsed.entry_point < program.virtual_address + program.memory_size) {
            parsed.entry_point_in_executable_segment = true;
        }
        parsed.program_headers.push_back(program);
    }
    if (!parsed.entry_point_in_executable_segment) {
        parsed.warnings.emplace_back("O ponto de entrada do ELF interno não está em PT_LOAD executável.");
    }
    parsed.self_entry_mappings.reserve(self.entries.size());
    for (std::size_t index = 0; index < self.entries.size(); ++index) {
        const auto& entry = self.entries[index];
        SelfEntryMappingSummary mapping{};
        mapping.self_entry_index = index;
        mapping.program_header_index = entry.segment_index;
        mapping.has_program_header = entry.segment_index < parsed.program_headers.size();
        mapping.encrypted = entry.encrypted;
        mapping.compressed = entry.compressed;
        if (mapping.has_program_header) {
            mapping.decoded_size_matches_file_segment =
                entry.decoded_size == parsed.program_headers[entry.segment_index].file_size;
        }
        parsed.self_entry_mappings.push_back(mapping);
    }
    summary = std::move(parsed);
    return true;
}

bool inspect_ps4_dependencies(const std::filesystem::path& path, const SelfHeaderSummary& self,
                              const EmbeddedElfSummary& elf, const std::filesystem::path& module_directory,
                              Ps4DependencySummary& summary, std::string& error) {
    constexpr std::uint32_t pt_dynamic = 2;
    constexpr std::uint32_t pt_sce_dynlibdata = 0x61000000;
    constexpr std::uint64_t dt_needed = 1;
    constexpr std::uint64_t dt_sce_strtab = 0x61000035;
    constexpr std::uint64_t dt_sce_strsz = 0x61000037;
    constexpr std::uint64_t dt_sce_symtab = 0x61000039;
    constexpr std::uint64_t dt_sce_syment = 0x6100003b;
    constexpr std::uint64_t dt_sce_symtabsz = 0x6100003f;
    constexpr std::uint64_t dt_sce_rela = 0x6100002f;
    constexpr std::uint64_t dt_sce_relasz = 0x61000031;
    constexpr std::uint64_t dt_sce_relaent = 0x61000033;
    constexpr std::uint64_t dt_sce_jmprel = 0x61000029;
    constexpr std::uint64_t dt_sce_pltrelsz = 0x6100002d;
    constexpr std::uint64_t dt_null = 0;
    constexpr std::uint64_t dynamic_entry_size = 16;

    const ElfProgramHeaderSummary* dynamic = nullptr;
    const ElfProgramHeaderSummary* dynlibdata = nullptr;
    std::size_t dynlibdata_index = 0;
    for (std::size_t index = 0; index < elf.program_headers.size(); ++index) {
        const auto& program = elf.program_headers[index];
        if (program.type == pt_dynamic) {
            dynamic = &program;
        } else if (program.type == pt_sce_dynlibdata) {
            dynlibdata = &program;
            dynlibdata_index = index;
        }
    }
    if (dynamic == nullptr || dynlibdata == nullptr) {
        error = "O ELF não contém PT_DYNAMIC e PT_SCE_DYNLIBDATA reconhecíveis.";
        return false;
    }
    if (dynamic->file_size == 0 || dynamic->file_size % dynamic_entry_size != 0 ||
        dynamic->file_offset < dynlibdata->file_offset ||
        !range_fits(dynamic->file_offset - dynlibdata->file_offset, dynamic->file_size, dynlibdata->file_size)) {
        error = "PT_DYNAMIC não está contido em PT_SCE_DYNLIBDATA ou tem tamanho inválido.";
        return false;
    }

    const SelfEntrySummary* source_entry = nullptr;
    for (const auto& entry : self.entries) {
        if (entry.segment_index == dynlibdata_index && entry.decoded_size == dynlibdata->file_size &&
            !entry.encrypted && !entry.compressed && entry.encoded_size == entry.decoded_size) {
            if (source_entry != nullptr) {
                error = "Mais de uma entrada SELF corresponde exatamente a PT_SCE_DYNLIBDATA.";
                return false;
            }
            source_entry = &entry;
        }
    }
    if (source_entry == nullptr) {
        error = "Não foi encontrada uma entrada SELF simples e exata para PT_SCE_DYNLIBDATA.";
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "Não foi possível abrir o contêiner SELF.";
        return false;
    }
    const auto dynamic_relative = dynamic->file_offset - dynlibdata->file_offset;
    std::vector<std::uint8_t> dynamic_bytes;
    if (!read_file_range(file, source_entry->offset + dynamic_relative, dynamic->file_size, dynamic_bytes, error)) {
        return false;
    }

    bool has_terminator = false;
    bool has_string_table_offset = false;
    bool has_string_table_size = false;
    std::uint64_t string_table_offset = 0;
    std::uint64_t string_table_size = 0;
    std::uint64_t symbol_table_offset = 0;
    std::uint64_t symbol_table_size = 0;
    std::uint64_t symbol_entry_size = 0;
    std::uint64_t rela_table_offset = 0;
    std::uint64_t rela_table_size = 0;
    std::uint64_t rela_entry_size = 0;
    std::uint64_t plt_table_offset = 0;
    std::uint64_t plt_table_size = 0;
    bool has_symbol_table_offset = false;
    bool has_symbol_table_size = false;
    bool has_symbol_entry_size = false;
    bool has_rela_table_offset = false;
    bool has_rela_table_size = false;
    bool has_rela_entry_size = false;
    bool has_plt_table_offset = false;
    bool has_plt_table_size = false;
    std::vector<std::uint64_t> needed_offsets;
    for (std::uint64_t offset = 0; offset < dynamic_bytes.size(); offset += dynamic_entry_size) {
        std::uint64_t tag{};
        std::uint64_t value{};
        if (!read_little_endian(dynamic_bytes, offset, tag) ||
            !read_little_endian(dynamic_bytes, offset + 8, value)) {
            error = "Entrada truncada na tabela dinâmica PS4.";
            return false;
        }
        if (tag == dt_null) {
            has_terminator = true;
            break;
        }
        if (tag == dt_needed) {
            needed_offsets.push_back(value);
        } else if (tag == dt_sce_strtab) {
            string_table_offset = value;
            has_string_table_offset = true;
        } else if (tag == dt_sce_strsz) {
            string_table_size = value;
            has_string_table_size = true;
        } else if (tag == dt_sce_symtab) {
            symbol_table_offset = value;
            has_symbol_table_offset = true;
        } else if (tag == dt_sce_symtabsz) {
            symbol_table_size = value;
            has_symbol_table_size = true;
        } else if (tag == dt_sce_syment) {
            symbol_entry_size = value;
            has_symbol_entry_size = true;
        } else if (tag == dt_sce_rela) {
            rela_table_offset = value;
            has_rela_table_offset = true;
        } else if (tag == dt_sce_relasz) {
            rela_table_size = value;
            has_rela_table_size = true;
        } else if (tag == dt_sce_relaent) {
            rela_entry_size = value;
            has_rela_entry_size = true;
        } else if (tag == dt_sce_jmprel) {
            plt_table_offset = value;
            has_plt_table_offset = true;
        } else if (tag == dt_sce_pltrelsz) {
            plt_table_size = value;
            has_plt_table_size = true;
        }
    }
    if (!has_terminator || !has_string_table_offset || !has_string_table_size || needed_offsets.empty()) {
        error = "Tabela dinâmica sem terminador, tabela de strings ou dependências necessárias.";
        return false;
    }
    if (!range_fits(string_table_offset, string_table_size, dynlibdata->file_size)) {
        error = "Tabela de strings declarada fica fora de PT_SCE_DYNLIBDATA.";
        return false;
    }

    std::vector<std::uint8_t> string_table;
    if (!read_file_range(file, source_entry->offset + string_table_offset, string_table_size, string_table, error)) {
        return false;
    }
    Ps4DependencySummary parsed{};
    for (const auto string_offset : needed_offsets) {
        std::string name;
        if (!read_c_string(string_table, string_offset, name)) {
            error = "Uma dependência aponta para uma string inválida ou sem terminador.";
            return false;
        }
        parsed.needed_modules.push_back(std::move(name));
    }

    if (!has_symbol_table_offset || !has_symbol_table_size || !has_symbol_entry_size ||
        !has_rela_table_offset || !has_rela_table_size || !has_rela_entry_size ||
        !has_plt_table_offset || !has_plt_table_size || symbol_entry_size != 24 || rela_entry_size != 24 ||
        symbol_table_size % symbol_entry_size != 0 || rela_table_size % rela_entry_size != 0 ||
        plt_table_size % rela_entry_size != 0 ||
        !range_fits(symbol_table_offset, symbol_table_size, dynlibdata->file_size) ||
        !range_fits(rela_table_offset, rela_table_size, dynlibdata->file_size) ||
        !range_fits(plt_table_offset, plt_table_size, dynlibdata->file_size)) {
        error = "As tabelas de símbolos/relocações têm tags ausentes, tamanhos inválidos ou ficam fora de PT_SCE_DYNLIBDATA.";
        return false;
    }
    std::vector<std::uint8_t> symbol_bytes;
    if (!read_file_range(file, source_entry->offset + symbol_table_offset, symbol_table_size, symbol_bytes, error)) {
        return false;
    }
    parsed.dynamic_symbol_count = symbol_table_size / symbol_entry_size;
    std::vector<std::uint16_t> symbol_section_indices;
    symbol_section_indices.reserve(static_cast<std::size_t>(parsed.dynamic_symbol_count));
    for (std::uint64_t index = 0; index < parsed.dynamic_symbol_count; ++index) {
        std::uint16_t section_index{};
        if (!read_little_endian(symbol_bytes, index * symbol_entry_size + 6, section_index)) {
            error = "Entrada truncada na tabela de símbolos PS4.";
            return false;
        }
        symbol_section_indices.push_back(section_index);
        if (section_index == 0 && index != 0) {
            ++parsed.undefined_symbol_count;
        }
    }
    parsed.rela_relocation_count = rela_table_size / rela_entry_size;
    parsed.plt_relocation_count = plt_table_size / rela_entry_size;
    parsed.total_relocation_count = parsed.rela_relocation_count + parsed.plt_relocation_count;
    std::set<std::uint32_t> referenced_symbols;
    for (const auto table : {std::pair{rela_table_offset, rela_table_size},
                             std::pair{plt_table_offset, plt_table_size}}) {
        std::vector<std::uint8_t> relocation_bytes;
        if (!read_file_range(file, source_entry->offset + table.first, table.second, relocation_bytes, error)) {
            return false;
        }
        for (std::uint64_t offset = 0; offset < table.second; offset += rela_entry_size) {
            std::uint64_t target{};
            std::uint64_t info{};
            std::uint64_t addend{};
            if (!read_little_endian(relocation_bytes, offset, target) ||
                !read_little_endian(relocation_bytes, offset + 8, info) ||
                !read_little_endian(relocation_bytes, offset + 16, addend)) {
                error = "Entrada truncada em uma tabela de relocações PS4.";
                return false;
            }
            const auto relocation_type = static_cast<std::uint32_t>(info & 0xffffffffU);
            auto& type_counts = parsed.relocation_types[relocation_type];
            ++type_counts.count;
            bool target_in_image = false;
            for (const auto& program : elf.program_headers) {
                if ((program.type == 1 || program.type == 0x61000010) && target >= program.virtual_address &&
                    target - program.virtual_address < program.memory_size) {
                    target_in_image = true;
                    break;
                }
            }
            if (target_in_image) {
                ++parsed.relocation_targets_in_image;
            } else {
                ++parsed.relocation_targets_outside_image;
            }
            const auto symbol_index = static_cast<std::uint32_t>(info >> 32U);
            if (symbol_index != 0) {
                if (symbol_index >= symbol_section_indices.size()) {
                    error = "Relocação PS4 referencia um índice fora da tabela dinâmica de símbolos.";
                    return false;
                }
                referenced_symbols.insert(symbol_index);
                if (symbol_section_indices[symbol_index] == 0) {
                    ++type_counts.undefined_symbol;
                } else {
                    ++type_counts.defined_symbol;
                }
            } else {
                ++type_counts.no_symbol;
            }
            if (relocation_type == 8) {
                bool addend_in_image = false;
                for (const auto& program : elf.program_headers) {
                    if ((program.type == 1 || program.type == 0x61000010) &&
                        addend >= program.virtual_address && addend - program.virtual_address < program.memory_size) {
                        addend_in_image = true;
                        break;
                    }
                }
                if (addend_in_image) {
                    ++type_counts.relative_addends_in_image;
                } else {
                    ++type_counts.relative_addends_outside_image;
                }
            }
        }
    }
    parsed.distinct_relocation_symbol_count = referenced_symbols.size();

    if (!module_directory.empty()) {
        std::error_code filesystem_error;
        if (!std::filesystem::is_directory(module_directory, filesystem_error) || filesystem_error) {
            error = "A pasta de módulos informada não existe ou não pode ser acessada.";
            return false;
        }
        parsed.module_directory_checked = true;
        std::vector<std::string> available_stems;
        for (std::filesystem::directory_iterator iterator(module_directory, filesystem_error), end;
             !filesystem_error && iterator != end; iterator.increment(filesystem_error)) {
            if (iterator->is_regular_file(filesystem_error) && !filesystem_error) {
                available_stems.push_back(ascii_lower(iterator->path().stem().string()));
            }
        }
        if (filesystem_error) {
            error = "Falha ao listar a pasta de módulos.";
            return false;
        }
        for (const auto& name : parsed.needed_modules) {
            const auto stem = ascii_lower(std::filesystem::path(name).stem().string());
            if (std::find(available_stems.begin(), available_stems.end(), stem) == available_stems.end()) {
                parsed.missing_modules.push_back(name);
            }
        }
    }
    summary = std::move(parsed);
    return true;
}

void print_summary(const Ps4DependencySummary& summary, std::ostream& output) {
    output << "\nBibliotecas declaradas em DT_NEEDED: " << summary.needed_modules.size() << '\n';
    output << "Símbolos dinâmicos: " << summary.dynamic_symbol_count
           << " (símbolos com seção indefinida, exceto entrada nula: " << summary.undefined_symbol_count
           << "; índices distintos usados em relocações: " << summary.distinct_relocation_symbol_count << ")\n";
    output << "Relocações: RELA=" << summary.rela_relocation_count
           << ", PLT=" << summary.plt_relocation_count
           << ", total=" << summary.total_relocation_count << '\n';
    output << "Destinos: dentro de PT_LOAD/RELRO=" << summary.relocation_targets_in_image
           << ", fora=" << summary.relocation_targets_outside_image << '\n';
    output << "Tipos ELF64: tipo=count [sem símbolo/indefinido/definido]; RELATIVE também mostra addends internos/externos\n";
    for (const auto& [type, counts] : summary.relocation_types) {
        output << "  " << type << '=' << counts.count << " [" << counts.no_symbol << '/'
               << counts.undefined_symbol << '/' << counts.defined_symbol << ']';
        if (type == 8) {
            output << " addend_in/out=" << counts.relative_addends_in_image << '/'
                   << counts.relative_addends_outside_image;
        }
        output << '\n';
    }
    if (summary.module_directory_checked) {
        output << "Correspondências na pasta de módulos: "
               << summary.needed_modules.size() - summary.missing_modules.size() << '\n';
        output << "Sem arquivo de mesmo nome-base: " << summary.missing_modules.size() << '\n';
    } else {
        output << "Pasta externa de módulos não comparada.\n";
    }
    for (const auto& name : summary.needed_modules) {
        const auto stem = ascii_lower(std::filesystem::path(name).stem().string());
        const bool missing = summary.module_directory_checked &&
            std::any_of(summary.missing_modules.begin(), summary.missing_modules.end(), [&](const std::string& candidate) {
                return ascii_lower(std::filesystem::path(candidate).stem().string()) == stem;
            });
        output << "  " << (missing ? "[não encontrado] " : "[DT_NEEDED] ") << name << '\n';
    }
    output << "Nota: correspondência de nome-base não confirma ABI ou compatibilidade do módulo.\n";
}

void print_summary(const ElfSummary& summary, std::ostream& output) {
    output << "Formato: ELF64 little-endian\n";
    output << "Tipo: " << summary.type << '\n';
    output << "Máquina: " << summary.machine;
    if (summary.machine == 62) {
        output << " (x86-64)";
    }
    output << '\n';
    output << "ABI do sistema: " << static_cast<unsigned>(summary.os_abi);
    if (summary.os_abi == 9) {
        output << " (FreeBSD/PS4)";
    }
    output << '\n';
    output << "Ponto de entrada: 0x" << std::hex << summary.entry_point << std::dec << '\n';
    output << "Segmentos carregáveis: " << summary.load_segments.size() << '\n';
    output << "Ponto de entrada em segmento executável: "
           << (summary.entry_point_in_executable_segment ? "sim" : "não") << '\n';
    for (std::size_t index = 0; index < summary.load_segments.size(); ++index) {
        const auto& segment = summary.load_segments[index];
        output << "  [" << index << "] endereço=0x" << std::hex << segment.virtual_address
               << " arquivo=0x" << segment.file_offset << std::dec
               << " bytes-arquivo=" << segment.file_size
               << " bytes-memória=" << segment.memory_size
               << " permissões=" << ((segment.flags & 0x4U) ? 'R' : '-')
               << ((segment.flags & 0x2U) ? 'W' : '-')
               << ((segment.flags & 0x1U) ? 'X' : '-')
               << " alinhamento=" << segment.alignment << '\n';
    }
    for (const auto& warning : summary.warnings) {
        output << "Aviso: " << warning << '\n';
    }
    output << "\nEste relatório descreve a estrutura ELF; não confirma compatibilidade PS4 nem executa o jogo.\n";
}

void print_summary(const SelfHeaderSummary& summary, std::ostream& output) {
    output << "Formato: contêiner SCE SELF (PS4)\n";
    output << "Versão: " << static_cast<unsigned>(summary.version) << '\n';
    output << "Modo: " << static_cast<unsigned>(summary.mode) << '\n';
    output << "Endian: " << static_cast<unsigned>(summary.endian) << '\n';
    output << "Atributos: 0x" << std::hex << static_cast<unsigned>(summary.attributes) << std::dec << '\n';
    output << "Tipo de chave: 0x" << std::hex << summary.key_type << std::dec << '\n';
    output << "Tamanho do cabeçalho: " << summary.header_size << " bytes\n";
    output << "Tamanho da metadata: " << summary.metadata_size << " bytes\n";
    output << "Entradas de metadata declaradas: " << summary.entry_count << '\n';
    output << "Flags: 0x" << std::hex << summary.flags << std::dec << '\n';
    output << "Tamanho declarado: " << summary.declared_file_size << " bytes\n";
    output << "Tamanho real: " << summary.actual_file_size << " bytes\n";
    if (summary.declared_file_size != summary.actual_file_size) {
        output << "Bytes após o tamanho declarado: " << summary.trailing_bytes << "\n";
    }
    output << "\nEntradas SELF (propriedades em hexadecimal; não decodificadas):\n";
    for (std::size_t index = 0; index < summary.entries.size(); ++index) {
        const auto& entry = summary.entries[index];
        output << "  [" << index << "] props=";
        for (const auto byte : entry.properties) {
            output << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
        }
        output << std::setfill(' ') << " offset=0x" << std::hex << entry.offset << std::dec
               << " enc=" << entry.encoded_size << " dec=" << entry.decoded_size << " bytes\n";
        output << "       índice-ELF=" << entry.segment_index
               << " ordenada=" << (entry.ordered ? "sim" : "não")
               << " criptografada=" << (entry.encrypted ? "sim" : "não")
               << " assinada=" << (entry.signed_data ? "sim" : "não")
               << " comprimida=" << (entry.compressed ? "sim" : "não")
               << " blocos=" << (entry.has_blocks ? "sim" : "não")
               << " block_bits=" << static_cast<unsigned>(entry.block_bits)
               << " digest=" << (entry.has_digest ? "sim" : "não")
               << " extents=" << (entry.has_extents ? "sim" : "não") << '\n';
    }
    output << "\nSomente o cabeçalho foi analisado; nenhum payload foi extraído ou descriptografado.\n";
}

void print_summary(const EmbeddedElfSummary& summary, std::ostream& output) {
    output << "\nELF interno em 0x" << std::hex << summary.container_offset << std::dec << '\n';
    output << "Tipo: 0x" << std::hex << summary.type << std::dec;
    if (summary.type == 0xfe00) {
        output << " (ET_SCE_EXEC)";
    } else if (summary.type == 0xfe10) {
        output << " (ET_SCE_EXEC_ASLR)";
    }
    output << '\n';
    output << "ABI do sistema: " << static_cast<unsigned>(summary.os_abi);
    if (summary.os_abi == 9) {
        output << " (FreeBSD/PS4)";
    }
    output << '\n';
    output << "Máquina: " << summary.machine;
    if (summary.machine == 62) {
        output << " (x86-64)";
    }
    output << '\n';
    output << "Ponto de entrada: 0x" << std::hex << summary.entry_point << std::dec << '\n';
    output << "Ponto de entrada em PT_LOAD executável: "
           << (summary.entry_point_in_executable_segment ? "sim" : "não") << '\n';
    output << "Cabeçalhos de programa: " << summary.program_headers.size() << '\n';
    for (std::size_t index = 0; index < summary.program_headers.size(); ++index) {
        const auto& program = summary.program_headers[index];
        const char* type_name = "desconhecido";
        switch (program.type) {
        case 1: type_name = "PT_LOAD"; break;
        case 2: type_name = "PT_DYNAMIC"; break;
        case 3: type_name = "PT_INTERP"; break;
        case 7: type_name = "PT_TLS"; break;
        case 0x61000000: type_name = "PT_SCE_DYNLIBDATA"; break;
        case 0x61000001: type_name = "PT_SCE_PROC_PARAM"; break;
        case 0x61000010: type_name = "PT_SCE_RELRO"; break;
        case 0x6fffff00: type_name = "PT_SCE_COMMENT"; break;
        case 0x6fffff01: type_name = "PT_SCE_LIBVERSION"; break;
        case 0x6474e550: type_name = "PT_GNU_EH_FRAME"; break;
        default: break;
        }
        output << "  [" << index << "] " << type_name << " tipo=0x" << std::hex << program.type
               << " offset=0x" << program.file_offset << " vaddr=0x" << program.virtual_address
               << std::dec << " flags=" << program.flags << " arquivo=" << program.file_size
               << " memória=" << program.memory_size << " alinhamento=" << program.alignment << " bytes\n";
    }
    for (const auto& warning : summary.warnings) {
        output << "Aviso: " << warning << '\n';
    }
    output << "\nRelação candidata entre entradas SELF e cabeçalhos ELF (índice declarado):\n";
    for (const auto& mapping : summary.self_entry_mappings) {
        output << "  SELF[" << mapping.self_entry_index << "] -> PHDR[" << mapping.program_header_index << "]";
        if (!mapping.has_program_header) {
            output << " (índice sem cabeçalho correspondente)";
        } else {
            output << " tamanho=" << (mapping.decoded_size_matches_file_segment ? "igual" : "diferente");
        }
        output << " criptografada=" << (mapping.encrypted ? "sim" : "não")
               << " comprimida=" << (mapping.compressed ? "sim" : "não") << '\n';
    }
    output << "Nenhum segmento foi carregado ou executado.\n";
}

} // namespace nba16
