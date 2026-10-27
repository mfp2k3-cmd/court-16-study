#include "big_archive.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <string_view>
#include <zlib.h>

namespace nba16 {
namespace {

std::uint16_t be16(const std::uint8_t* bytes) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8U) | bytes[1]);
}

std::uint32_t be32(const std::uint8_t* bytes) {
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) |
           static_cast<std::uint32_t>(bytes[3]);
}

std::uint64_t be64(const std::uint8_t* bytes) {
    return (static_cast<std::uint64_t>(be32(bytes)) << 32U) | be32(bytes + 4);
}

bool align_to(std::uint64_t value, std::uint64_t alignment, std::uint64_t& result) {
    if (alignment == 0 || (alignment & (alignment - 1U)) != 0 ||
        value > std::numeric_limits<std::uint64_t>::max() - (alignment - 1U)) {
        return false;
    }
    result = (value + alignment - 1U) & ~(alignment - 1U);
    return true;
}

bool decode_refpack(std::span<const std::byte> input, std::span<std::byte> output,
                    std::string& error) {
    const auto byte_at = [input](std::size_t offset) {
        return std::to_integer<std::uint8_t>(input[offset]);
    };
    if (input.size() < 5 || byte_at(0) != 0x10 || byte_at(1) != 0xfb) {
        error = "cabeçalho RefPack não suportado ou truncado";
        return false;
    }
    const auto declared_size = (static_cast<std::uint32_t>(byte_at(2)) << 16U) |
        (static_cast<std::uint32_t>(byte_at(3)) << 8U) | byte_at(4);
    if (declared_size != output.size()) {
        error = "tamanho RefPack diverge do tamanho lógico do bloco";
        return false;
    }

    std::size_t input_offset = 5;
    std::size_t output_offset = 0;
    bool reached_end = false;
    while (!reached_end) {
        if (input_offset >= input.size()) {
            error = "fluxo RefPack truncado antes do marcador final";
            return false;
        }
        const auto control = byte_at(input_offset);
        std::size_t literal_count = 0;
        std::size_t copy_count = 0;
        std::size_t displacement = 0;
        if ((control & 0x80U) == 0) {
            if (input.size() - input_offset < 2) {
                error = "comando RefPack curto truncado";
                return false;
            }
            literal_count = control & 0x03U;
            copy_count = ((control & 0x1cU) >> 2U) + 3U;
            displacement = ((control & 0x60U) << 3U) |
                byte_at(input_offset + 1U);
            displacement += 1U;
            input_offset += 2U;
        } else if ((control & 0x40U) == 0) {
            if (input.size() - input_offset < 3) {
                error = "comando RefPack médio truncado";
                return false;
            }
            literal_count = byte_at(input_offset + 1U) >> 6U;
            copy_count = (control & 0x3fU) + 4U;
            displacement = ((byte_at(input_offset + 1U) & 0x3fU) << 8U) |
                byte_at(input_offset + 2U);
            displacement += 1U;
            input_offset += 3U;
        } else if ((control & 0x20U) == 0) {
            if (input.size() - input_offset < 4) {
                error = "comando RefPack longo truncado";
                return false;
            }
            literal_count = control & 0x03U;
            copy_count = ((control & 0x0cU) << 6U) + byte_at(input_offset + 3U) + 5U;
            displacement = ((control & 0x10U) << 12U) |
                (static_cast<std::size_t>(byte_at(input_offset + 1U)) << 8U) |
                byte_at(input_offset + 2U);
            displacement += 1U;
            input_offset += 4U;
        } else if ((control & 0xfcU) == 0xfcU) {
            literal_count = control & 0x03U;
            reached_end = true;
            ++input_offset;
        } else {
            literal_count = (control & 0x1fU) * 4U + 4U;
            ++input_offset;
        }

        if (literal_count > input.size() - input_offset ||
            literal_count > output.size() - output_offset) {
            error = "literais RefPack excedem os limites do bloco";
            return false;
        }
        if (literal_count != 0) {
            std::memcpy(output.data() + output_offset, input.data() + input_offset, literal_count);
            input_offset += literal_count;
            output_offset += literal_count;
        }
        if (copy_count != 0) {
            if (displacement == 0 || displacement > output_offset ||
                copy_count > output.size() - output_offset) {
                error = "referência RefPack excede a janela ou o tamanho do bloco";
                return false;
            }
            for (std::size_t copied = 0; copied < copy_count; ++copied) {
                output[output_offset] = output[output_offset - displacement];
                ++output_offset;
            }
        }
    }
    if (output_offset != output.size() ||
        std::any_of(input.begin() + static_cast<std::ptrdiff_t>(input_offset), input.end(),
                    [](std::byte value) { return value != std::byte{0}; })) {
        error = "tamanho final RefPack diverge do bloco ou há dados residuais";
        return false;
    }
    return true;
}

std::uint32_t djb2(std::string_view value) {
    std::uint32_t hash = 5381;
    for (const char character : value) {
        hash = hash * 33U + static_cast<unsigned char>(character);
    }
    return hash;
}

bool read_at(std::ifstream& file, std::uint64_t offset, std::span<std::byte> output) {
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
        output.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        return false;
    }
    file.clear();
    file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    return file.read(reinterpret_cast<char*>(output.data()),
                     static_cast<std::streamsize>(output.size())).good();
}

BigCompression classify(std::span<const std::byte> prefix) {
    const auto starts_with = [prefix](std::string_view magic) {
        if (prefix.size() < magic.size()) {
            return false;
        }
        return std::equal(magic.begin(), magic.end(), prefix.begin(), [](char lhs, std::byte rhs) {
            return static_cast<unsigned char>(lhs) == std::to_integer<unsigned char>(rhs);
        });
    };
    if (prefix.size() >= 2 && std::to_integer<unsigned char>(prefix[0]) == 0x10 &&
        std::to_integer<unsigned char>(prefix[1]) == 0xfb) {
        return BigCompression::refpack;
    }
    if (starts_with("chunkzip")) return BigCompression::chunkzip;
    if (starts_with("chunkref")) return BigCompression::chunkref;
    if (starts_with("chunklzx")) return BigCompression::chunklzx;
    if (starts_with("chunlzma")) return BigCompression::chunlzma;
    if (starts_with("chunklz4")) return BigCompression::chunklz4;
    if (starts_with("chunkunc")) return BigCompression::chunkunc;
    if (starts_with("chunzstd")) return BigCompression::chunzstd;
    if (starts_with("chunoodl")) return BigCompression::chunoodl;
    return BigCompression::uncompressed_candidate;
}

} // namespace

bool BigArchive::open(const std::filesystem::path& path, std::string& error) {
    members_.clear();
    archive_path_.clear();
    archive_size_ = 0;

    std::error_code ec;
    archive_size_ = std::filesystem::file_size(path, ec);
    if (ec || archive_size_ < 48) {
        error = "arquivo BIG inacessível ou menor que o cabeçalho mínimo";
        return false;
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "não foi possível abrir o arquivo BIG";
        return false;
    }
    std::array<std::uint8_t, 32> header{};
    if (!file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()))) {
        error = "cabeçalho BIG truncado";
        return false;
    }
    if (header[0] != 'E' || header[1] != 'B' || header[2] != 0 || header[3] != 3) {
        error = "assinatura BIG não reconhecida (esperado EB 00 03)";
        return false;
    }

    const auto count = be32(header.data() + 4);
    const auto base_header_size = be32(header.data() + 12);
    const auto name_header_size = be32(header.data() + 16);
    const auto path_entry_size = header[20];
    const auto directory_entry_size = header[21];
    const auto directory_count = be16(header.data() + 22);
    const auto declared_size = be64(header.data() + 24);
    if (count == 0 || count > archive_size_ / 17U || path_entry_size < 3 || directory_entry_size == 0 ||
        declared_size != archive_size_) {
        error = "campos de tamanho ou contagem inválidos no cabeçalho BIG";
        return false;
    }

    std::uint64_t expected_base{};
    std::uint64_t path_end{};
    std::uint64_t directory_start{};
    std::uint64_t directory_end{};
    const auto base_unaligned = 48U + static_cast<std::uint64_t>(count) * 17U;
    if (!align_to(base_unaligned, 16, expected_base) ||
        static_cast<std::uint64_t>(count) >
            (std::numeric_limits<std::uint64_t>::max() - base_header_size) / path_entry_size) {
        error = "tabelas BIG excedem os limites de tamanho";
        return false;
    }
    path_end = base_header_size + static_cast<std::uint64_t>(count) * path_entry_size;
    if (!align_to(path_end, 16, directory_start) ||
        static_cast<std::uint64_t>(directory_count) >
            (std::numeric_limits<std::uint64_t>::max() - directory_start) / directory_entry_size ||
        !align_to(directory_start + static_cast<std::uint64_t>(directory_count) * directory_entry_size,
                  16, directory_end) ||
        base_header_size != expected_base || name_header_size != directory_end - base_header_size ||
        directory_end > archive_size_) {
        error = "geometria das tabelas BIG não confere com os tamanhos do cabeçalho";
        return false;
    }

    std::vector<std::string> directories;
    directories.reserve(directory_count);
    std::vector<std::uint8_t> directory_entry(directory_entry_size);
    for (std::uint64_t i = 0; i < directory_count; ++i) {
        if (!read_at(file, directory_start + i * directory_entry_size,
                     std::as_writable_bytes(std::span(directory_entry)))) {
            error = "tabela BIG de diretórios truncada";
            return false;
        }
        const auto terminator = std::find(directory_entry.begin(), directory_entry.end(), 0);
        if (terminator == directory_entry.end()) {
            error = "nome de diretório BIG sem terminador NUL";
            return false;
        }
        directories.emplace_back(directory_entry.begin(), terminator);
    }

    members_.reserve(count);
    std::vector<std::uint8_t> path_entry(path_entry_size);
    const auto alignment_shift = header[10];
    if (alignment_shift >= 32) {
        error = "expoente de alinhamento BIG inválido";
        return false;
    }
    const auto alignment = std::uint64_t{1} << alignment_shift;
    bool full_path_only_seen = false;
    bool filename_only_seen = false;
    for (std::uint64_t i = 0; i < count; ++i) {
        std::array<std::uint8_t, 16> index_record{};
        if (!read_at(file, 48U + i * 16U, std::as_writable_bytes(std::span(index_record))) ||
            !read_at(file, base_header_size + i * path_entry_size,
                     std::as_writable_bytes(std::span(path_entry)))) {
            error = "índice ou caminho BIG truncado";
            members_.clear();
            return false;
        }
        const auto directory_index = be16(path_entry.data());
        const auto name_end = std::find(path_entry.begin() + 2, path_entry.end(), 0);
        if (directory_index >= directories.size() || name_end == path_entry.end() || name_end == path_entry.begin() + 2) {
            error = "índice de diretório ou nome BIG inválido";
            members_.clear();
            return false;
        }
        const std::string_view filename(reinterpret_cast<const char*>(path_entry.data() + 2),
            static_cast<std::size_t>(name_end - (path_entry.begin() + 2)));
        std::string member_path = directories[directory_index];
        if (!member_path.empty()) {
            member_path.push_back('/');
        }
        member_path.append(filename);
        const auto stored_hash = be32(index_record.data() + 12);
        const bool full_match = djb2(member_path) == stored_hash;
        const bool filename_match = djb2(filename) == stored_hash;
        if (!full_match && !filename_match) {
            error = "hash DJB2 BIG não corresponde ao caminho nem ao nome";
            members_.clear();
            return false;
        }
        full_path_only_seen |= full_match && !filename_match;
        filename_only_seen |= filename_match && !full_match;
        if (full_path_only_seen && filename_only_seen) {
            error = "hash BIG mistura convenções de caminho incompatíveis no mesmo arquivo";
            members_.clear();
            return false;
        }

        const auto offset = static_cast<std::uint64_t>(be32(index_record.data())) * alignment;
        const auto refpack_size = be32(index_record.data() + 4);
        const auto data_size = be32(index_record.data() + 8);
        const auto prefix_size = static_cast<std::size_t>(std::min<std::uint32_t>(data_size, 8));
        std::array<std::byte, 8> prefix{};
        if (offset < directory_end || offset > archive_size_ || data_size > archive_size_ - offset ||
            !read_at(file, offset, std::span<std::byte>(prefix.data(), prefix_size))) {
            error = "offset ou tamanho de payload BIG inválido";
            members_.clear();
            return false;
        }
        auto compression = classify(std::span<const std::byte>(prefix.data(), prefix_size));
        const auto stored_size = compression == BigCompression::refpack ? refpack_size : data_size;
        if (stored_size > archive_size_ - offset || stored_size == 0) {
            error = "tamanho armazenado BIG excede o arquivo ou é zero";
            members_.clear();
            return false;
        }
        std::uint64_t logical_size = stored_size;
        if (compression == BigCompression::chunkzip || compression == BigCompression::chunkref) {
            if (stored_size < 16) {
                error = "cabeçalho Chunk comprimido menor que o campo de tamanho lógico";
                members_.clear();
                return false;
            }
            std::array<std::byte, 16> chunk_header{};
            if (!read_at(file, offset, chunk_header)) {
                error = "falha lendo o tamanho lógico do cabeçalho Chunk";
                members_.clear();
                return false;
            }
            logical_size = be32(reinterpret_cast<const std::uint8_t*>(chunk_header.data()) + 12);
        }
        members_.push_back(BigMember{std::move(member_path), offset, stored_size, data_size,
                                     logical_size, compression});
    }
    archive_path_ = path;
    return true;
}

const std::vector<BigMember>& BigArchive::members() const noexcept {
    return members_;
}

const BigMember* BigArchive::find(std::string_view path) const noexcept {
    const auto it = std::find_if(members_.begin(), members_.end(), [path](const BigMember& member) {
        return member.path == path;
    });
    return it == members_.end() ? nullptr : &*it;
}

bool BigArchive::read_candidate_range(const BigMember& member, std::uint64_t offset,
                                      std::span<std::byte> destination, std::size_t& bytes_read,
                                      std::string& error) const {
    if (member.compression != BigCompression::uncompressed_candidate) {
        bytes_read = 0;
        error = "leitura direta recusada: a entrada tem uma assinatura de compressão conhecida";
        return false;
    }
    return read_stored_range(member, offset, destination, bytes_read, error);
}

bool BigArchive::read_stored_range(const BigMember& member, std::uint64_t offset,
                                   std::span<std::byte> destination, std::size_t& bytes_read,
                                   std::string& error) const {
    bytes_read = 0;
    const auto* known_member = find(member.path);
    if (known_member == nullptr || known_member->data_offset != member.data_offset ||
        known_member->stored_size != member.stored_size || known_member->logical_size != member.logical_size ||
        known_member->compression != member.compression) {
        error = "a entrada não pertence a este arquivo BIG";
        return false;
    }
    if (offset > member.stored_size || member.data_offset > archive_size_ ||
        member.stored_size > archive_size_ - member.data_offset) {
        error = "intervalo de leitura BIG fora dos limites";
        return false;
    }
    const auto remaining = member.stored_size - offset;
    bytes_read = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, destination.size()));
    std::ifstream file(archive_path_, std::ios::binary);
    if (!file || !read_at(file, member.data_offset + offset, destination.first(bytes_read))) {
        bytes_read = 0;
        error = "falha lendo intervalo da entrada BIG";
        return false;
    }
    return true;
}

bool BigArchive::read_decoded_range(const BigMember& member, std::uint64_t offset,
                                    std::span<std::byte> destination, std::size_t& bytes_read,
                                    std::string& error) const {
    bytes_read = 0;
    if (member.compression == BigCompression::uncompressed_candidate) {
        return read_stored_range(member, offset, destination, bytes_read, error);
    }
    const auto* known_member = find(member.path);
    if (known_member == nullptr || known_member->data_offset != member.data_offset ||
        known_member->stored_size != member.stored_size || known_member->logical_size != member.logical_size ||
        known_member->compression != member.compression) {
        error = "a entrada não pertence a este arquivo BIG";
        return false;
    }
    if (member.compression != BigCompression::chunkzip && member.compression != BigCompression::chunkref) {
        error = "decodificador ainda não disponível para este formato BIG";
        return false;
    }
    constexpr std::uint64_t header_size = 48;
    if (member.stored_size < header_size || member.data_offset > archive_size_ ||
        member.stored_size > archive_size_ - member.data_offset) {
        error = "cabeçalho Chunk fora dos limites do arquivo BIG";
        return false;
    }

    std::ifstream file(archive_path_, std::ios::binary);
    std::array<std::byte, header_size> header{};
    if (!file || !read_at(file, member.data_offset, header)) {
        error = "falha lendo cabeçalho Chunk";
        return false;
    }
    const std::array<char, 8> magic = member.compression == BigCompression::chunkzip
        ? std::array<char, 8>{'c', 'h', 'u', 'n', 'k', 'z', 'i', 'p'}
        : std::array<char, 8>{'c', 'h', 'u', 'n', 'k', 'r', 'e', 'f'};
    for (std::size_t index = 0; index < magic.size(); ++index) {
        if (std::to_integer<unsigned char>(header[index]) !=
            static_cast<unsigned char>(magic[index])) {
            error = "assinatura Chunk não corresponde ao índice BIG";
            return false;
        }
    }
    const auto* header_bytes = reinterpret_cast<const std::uint8_t*>(header.data());
    const auto version = be32(header_bytes + 8);
    const auto uncompressed_size = be32(header_bytes + 12);
    const auto block_size = be32(header_bytes + 16);
    const auto block_count = be32(header_bytes + 20);
    const auto alignment = be32(header_bytes + 24);
    const auto expected_codec = member.compression == BigCompression::chunkzip ? 1U : 2U;
    if (version != 2 || block_size == 0 || block_count == 0 ||
        block_size > 16U * 1024U * 1024U ||
        alignment == 0 || (alignment & (alignment - 1U)) != 0 ||
        uncompressed_size != member.logical_size ||
        (static_cast<std::uint64_t>(uncompressed_size) + block_size - 1U) / block_size != block_count) {
        error = "cabeçalho Chunk inválido ou incoerente";
        return false;
    }
    if (offset > uncompressed_size) {
        error = "offset solicitado ultrapassa o conteúdo descomprimido";
        return false;
    }
    const auto wanted = static_cast<std::size_t>(std::min<std::uint64_t>(
        destination.size(), static_cast<std::uint64_t>(uncompressed_size) - offset));
    if (wanted == 0) return true;

    constexpr std::size_t io_buffer_size = 64U * 1024U;
    std::array<Bytef, io_buffer_size> input{};
    std::array<Bytef, io_buffer_size> output{};
    const std::uint64_t wanted_end = offset + wanted;
    std::uint64_t block_record_offset = header_size;
    std::uint64_t output_block_offset = 0;
    std::uint64_t previous_data_end = header_size;
    std::uint64_t first_compressed_size = be32(header_bytes + 40);
    std::uint32_t codec = be32(header_bytes + 44);

    for (std::uint32_t block = 0; block < block_count; ++block) {
        std::uint64_t compressed_size = first_compressed_size;
        std::uint64_t data_offset = header_size;
        if (block == 0) {
            if (codec != expected_codec) {
                error = "codec Chunk não corresponde ao formato do membro";
                return false;
            }
        } else {
            std::uint64_t record_end{};
            if (previous_data_end > std::numeric_limits<std::uint64_t>::max() - 8U ||
                !align_to(previous_data_end + 8U, alignment, data_offset)) {
                error = "offset de bloco excede os limites";
                bytes_read = 0;
                return false;
            }
            block_record_offset = data_offset - 8U;
            record_end = block_record_offset + 8U;
            if (record_end > member.stored_size) {
                error = "registro de bloco truncado";
                bytes_read = 0;
                return false;
            }
            std::array<std::byte, 8> block_header{};
            if (!read_at(file, member.data_offset + block_record_offset, block_header)) {
                error = "falha lendo registro de bloco";
                bytes_read = 0;
                return false;
            }
            const auto* block_bytes = reinterpret_cast<const std::uint8_t*>(block_header.data());
            compressed_size = be32(block_bytes);
            codec = be32(block_bytes + 4);
            if (codec != expected_codec) {
                error = "codec de bloco Chunk não corresponde ao formato do membro";
                bytes_read = 0;
                return false;
            }
        }
        if (compressed_size == 0 || data_offset > member.stored_size ||
            compressed_size > member.stored_size - data_offset) {
            error = "payload comprimido de bloco fora dos limites";
            bytes_read = 0;
            return false;
        }

        const auto block_output_size = std::min<std::uint64_t>(
            block_size, static_cast<std::uint64_t>(uncompressed_size) - output_block_offset);
        const auto block_output_end = output_block_offset + block_output_size;
        const bool intersects = offset < block_output_end && wanted_end > output_block_offset;
        if (intersects) {
            if (member.compression == BigCompression::chunkref) {
                if (compressed_size > 32U * 1024U * 1024U ||
                    block_output_size > std::numeric_limits<std::size_t>::max()) {
                    error = "bloco ChunkRef excede o limite seguro de memória";
                    bytes_read = 0;
                    return false;
                }
                std::vector<std::byte> compressed(static_cast<std::size_t>(compressed_size));
                std::vector<std::byte> decoded(static_cast<std::size_t>(block_output_size));
                if (!read_at(file, member.data_offset + data_offset, compressed)) {
                    error = "falha lendo bloco RefPack";
                    bytes_read = 0;
                    return false;
                }
                if (!decode_refpack(compressed, decoded, error)) {
                    bytes_read = 0;
                    return false;
                }
                const auto copy_begin = std::max(offset, output_block_offset);
                const auto copy_end = std::min(wanted_end, block_output_end);
                const auto source_offset = static_cast<std::size_t>(copy_begin - output_block_offset);
                const auto destination_offset = static_cast<std::size_t>(copy_begin - offset);
                const auto copy_size = static_cast<std::size_t>(copy_end - copy_begin);
                std::memcpy(destination.data() + destination_offset,
                            decoded.data() + source_offset, copy_size);
                bytes_read += copy_size;
            } else {
            z_stream stream{};
            if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
                error = "zlib não conseguiu iniciar DEFLATE bruto";
                bytes_read = 0;
                return false;
            }
            struct InflateCleanup {
                z_stream& stream;
                ~InflateCleanup() { inflateEnd(&stream); }
            } cleanup{stream};
            std::uint64_t input_read = 0;
            std::uint64_t output_produced = 0;
            file.clear();
            file.seekg(static_cast<std::streamoff>(member.data_offset + data_offset), std::ios::beg);
            if (!file) {
                error = "falha posicionando no fluxo DEFLATE ChunkZip";
                bytes_read = 0;
                return false;
            }
            while (true) {
                if (stream.avail_in == 0 && input_read < compressed_size) {
                    const auto amount = static_cast<std::size_t>(std::min<std::uint64_t>(
                        input.size(), compressed_size - input_read));
                    if (!file.read(reinterpret_cast<char*>(input.data()), static_cast<std::streamsize>(amount))) {
                        error = "fluxo DEFLATE truncado";
                        bytes_read = 0;
                        return false;
                    }
                    input_read += amount;
                    stream.next_in = input.data();
                    stream.avail_in = static_cast<uInt>(amount);
                }
                stream.next_out = output.data();
                stream.avail_out = static_cast<uInt>(output.size());
                const auto output_before = output_produced;
                const int result = inflate(&stream, Z_NO_FLUSH);
                const auto produced = output.size() - stream.avail_out;
                if (produced > block_output_size - std::min(output_before, block_output_size)) {
                        error = "bloco DEFLATE excede o tamanho lógico declarado";
                    bytes_read = 0;
                    return false;
                }
                output_produced += produced;
                if (produced != 0) {
                    const auto copy_begin = std::max<std::uint64_t>(
                        output_block_offset + output_before, offset);
                    const auto copy_end = std::min<std::uint64_t>(
                        output_block_offset + output_produced, wanted_end);
                    if (copy_begin < copy_end) {
                        const auto source_offset = static_cast<std::size_t>(
                            copy_begin - output_block_offset - output_before);
                        const auto destination_offset = static_cast<std::size_t>(copy_begin - offset);
                        const auto copy_size = static_cast<std::size_t>(copy_end - copy_begin);
                        std::memcpy(destination.data() + destination_offset,
                                    output.data() + source_offset, copy_size);
                        bytes_read += copy_size;
                    }
                }
                if (result == Z_STREAM_END) {
                    if (output_produced != block_output_size || stream.total_in != compressed_size) {
                        error = "tamanho final do bloco DEFLATE diverge do registro";
                        bytes_read = 0;
                        return false;
                    }
                    break;
                }
                if (result != Z_OK ||
                    (produced == 0 && stream.avail_in == 0 && input_read == compressed_size)) {
                    error = "fluxo DEFLATE inválido ou incompleto";
                    bytes_read = 0;
                    return false;
                }
            }
            }
        }
        previous_data_end = data_offset + compressed_size;
        output_block_offset = block_output_end;
        if (block == 0 && compressed_size != be32(header_bytes + 40)) {
            error = "tamanho do primeiro bloco inconsistente";
            bytes_read = 0;
            return false;
        }
    }
    return bytes_read == wanted;
}

} // namespace nba16
