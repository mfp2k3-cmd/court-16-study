#include "self_program_image.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>

namespace nba16 {
namespace {

bool range_fits(std::uint64_t offset, std::uint64_t length, std::uint64_t total) {
    return offset <= total && length <= total - offset;
}

bool read_range(std::ifstream& input, std::uint64_t offset, std::uint64_t length,
                std::vector<std::uint8_t>& bytes, std::string& error) {
    if (length > std::numeric_limits<std::size_t>::max() ||
        offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
        length > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        error = "Trecho SELF excede os limites de leitura desta plataforma.";
        return false;
    }
    bytes.resize(static_cast<std::size_t>(length));
    input.clear();
    input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!bytes.empty() && !input.read(reinterpret_cast<char*>(bytes.data()),
                                      static_cast<std::streamsize>(bytes.size()))) {
        error = "Falha ao ler um trecho SELF validado.";
        return false;
    }
    return true;
}

} // namespace

bool load_clear_self_program_image(const std::filesystem::path& path,
                                   const SelfHeaderSummary& self,
                                   const EmbeddedElfSummary& elf,
                                   SelfProgramImage& image,
                                   std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "Não foi possível abrir o SELF para mapear seus trechos.";
        return false;
    }

    std::uint64_t blocked_source_end = 0;
    std::vector<bool> covered(elf.program_headers.size(), false);
    SelfProgramImage parsed{};
    parsed.elf_type = elf.type;
    parsed.machine = elf.machine;
    parsed.os_abi = elf.os_abi;
    parsed.entry_point = elf.entry_point;
    parsed.program_headers = elf.program_headers;
    parsed.segments.reserve(self.entries.size());
    const SelfEntrySummary* pending_digest_table = nullptr;

    for (std::size_t entry_index = 0; entry_index < self.entries.size(); ++entry_index) {
        const auto& entry = self.entries[entry_index];
        if (!entry.has_blocks) {
            if (!entry.has_digest || entry.has_extents) {
                error = "Entrada SELF sem blocos ou digest não tem regra de payload confirmada; mapeamento interrompido.";
                return false;
            }
            if (pending_digest_table != nullptr) {
                error = "Duas tabelas de digest consecutivas não têm uma associação confirmada.";
                return false;
            }
            pending_digest_table = &entry;
            continue;
        }
        if (entry.encrypted || entry.compressed || entry.has_extents) {
            error = "O portador SELF usa criptografia, compressão ou extents não suportados nesta etapa.";
            return false;
        }
        if (entry.segment_index >= elf.program_headers.size()) {
            error = "Entrada SELF aponta para um cabeçalho de programa inexistente.";
            return false;
        }
        if (covered[entry.segment_index]) {
            error = "Duas entradas SELF tentam fornecer o mesmo cabeçalho de programa.";
            return false;
        }

        const auto& program = elf.program_headers[entry.segment_index];
        if (entry.encoded_size != entry.decoded_size || entry.decoded_size != program.file_size) {
            error = "Tamanho SELF não coincide com o tamanho de arquivo do cabeçalho ELF associado.";
            return false;
        }
        if (entry.block_bits > 20) {
            error = "Expoente de bloco SELF excede o limite seguro desta etapa.";
            return false;
        }
        const auto block_bytes = std::uint64_t{1} << (12U + entry.block_bits);
        if (pending_digest_table != nullptr) {
            const auto digest_count = entry.decoded_size / block_bytes +
                                      (entry.decoded_size % block_bytes != 0 ? 1U : 0U);
            if (digest_count > std::numeric_limits<std::uint64_t>::max() / 32U ||
                pending_digest_table->encoded_size != digest_count * 32U ||
                pending_digest_table->offset + pending_digest_table->encoded_size != entry.offset) {
                error = "A tabela SELF anterior não coincide em tamanho/posição com os blocos do próximo segmento.";
                return false;
            }
            std::vector<std::uint8_t> digests;
            if (!read_range(input, pending_digest_table->offset, pending_digest_table->encoded_size,
                            digests, error)) {
                return false;
            }
            ++parsed.digest_table_count;
            parsed.digest_table_bytes += digests.size();
            if (std::all_of(digests.begin(), digests.end(), [](std::uint8_t value) { return value == 0; })) {
                ++parsed.zero_filled_digest_table_count;
            }
            pending_digest_table = nullptr;
        }
        if (!range_fits(entry.offset, entry.encoded_size, self.actual_file_size) ||
            !range_fits(program.file_offset, program.file_size, std::numeric_limits<std::uint64_t>::max())) {
            error = "Trecho SELF ou intervalo ELF fora dos limites representáveis.";
            return false;
        }

        ProgramSegmentImage segment{};
        segment.program_header_index = entry.segment_index;
        segment.program_header = program;
        if (!read_range(input, entry.offset, entry.encoded_size, segment.file_bytes, error)) {
            return false;
        }
        if (segment.file_bytes.size() != program.file_size) {
            error = "Leitura SELF retornou tamanho diferente do cabeçalho ELF.";
            return false;
        }
        parsed.total_payload_bytes += segment.file_bytes.size();
        blocked_source_end = std::max(blocked_source_end, entry.offset + entry.encoded_size);
        covered[entry.segment_index] = true;
        parsed.segments.push_back(std::move(segment));
    }

    if (pending_digest_table != nullptr) {
        error = "A última tabela SELF não é seguida por um segmento com blocos.";
        return false;
    }

    if (parsed.segments.empty()) {
        error = "O SELF não forneceu segmentos de programa sem criptografia e compressão.";
        return false;
    }

    // PS4 stores PT_SCE_LIBVERSION after the final blocked segment. Preserve it as
    // its own segment instead of flattening potentially overlapping ELF offsets.
    constexpr std::uint32_t pt_sce_libversion = 0x6fffff01;
    for (std::size_t index = 0; index < elf.program_headers.size(); ++index) {
        const auto& program = elf.program_headers[index];
        if (program.type != pt_sce_libversion || program.file_size == 0 || covered[index]) {
            continue;
        }
        if (blocked_source_end != self.declared_file_size ||
            self.actual_file_size < self.declared_file_size ||
            self.actual_file_size - self.declared_file_size != program.file_size) {
            error = "A posição/tamanho do segmento PT_SCE_LIBVERSION não coincide com a cauda declarada do SELF.";
            return false;
        }
        ProgramSegmentImage segment{};
        segment.program_header_index = index;
        segment.program_header = program;
        segment.read_from_self_trailer = true;
        if (!read_range(input, blocked_source_end, program.file_size, segment.file_bytes, error)) {
            return false;
        }
        parsed.total_payload_bytes += segment.file_bytes.size();
        covered[index] = true;
        parsed.segments.push_back(std::move(segment));
    }

    image = std::move(parsed);
    return true;
}

void print_summary(const SelfProgramImage& image, std::ostream& output) {
    output << "\nImagem lógica SELF em memória (sem criar arquivo):\n";
    output << "  ELF type=0x" << std::hex << image.elf_type << std::dec
           << " máquina=" << image.machine << " ABI=" << static_cast<unsigned>(image.os_abi)
           << " entrada=0x" << std::hex << image.entry_point << std::dec << '\n';
    output << "  Trechos preservados separadamente: " << image.segments.size()
           << "; dados lidos: " << image.total_payload_bytes << " bytes\n";
    output << "  Tabelas de digest adjacentes: " << image.digest_table_count << " ("
           << image.digest_table_bytes << " bytes); preenchidas com zero: "
           << image.zero_filled_digest_table_count << '\n';
    for (const auto& segment : image.segments) {
        output << "    PHDR[" << segment.program_header_index << "] tipo=0x"
               << std::hex << segment.program_header.type << " offset=0x"
               << segment.program_header.file_offset << " vaddr=0x"
               << segment.program_header.virtual_address << std::dec
               << " bytes=" << segment.file_bytes.size();
        if (segment.read_from_self_trailer) {
            output << " (cauda SELF)";
        }
        output << '\n';
    }
    output << "  Isso valida o mapeamento dos bytes declarados; não executa o jogo.\n";
}

} // namespace nba16
