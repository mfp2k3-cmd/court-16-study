#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

constexpr std::array<std::uint8_t, 4> kEbV3Magic{0x45, 0x42, 0x00, 0x03};

template <std::size_t Size>
std::uint16_t read_be_u16(const std::array<std::uint8_t, Size>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

template <std::size_t Size>
std::uint32_t read_be_u32(const std::array<std::uint8_t, Size>& bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

template <std::size_t Size>
std::uint64_t read_be_u64(const std::array<std::uint8_t, Size>& bytes, std::size_t offset) {
    return (static_cast<std::uint64_t>(read_be_u32(bytes, offset)) << 32U) |
           read_be_u32(bytes, offset + 4);
}

bool align_16(std::uint64_t value, std::uint64_t& aligned) {
    if (value > std::numeric_limits<std::uint64_t>::max() - 15U) {
        return false;
    }
    aligned = (value + 15U) & ~std::uint64_t{15U};
    return true;
}

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

struct ArchiveHeader {
    std::filesystem::path path;
    std::uint64_t file_size{};
    std::uint64_t declared_file_size{};
    std::uint64_t file_count{};
    std::uint64_t base_header_size{};
    std::uint64_t name_header_size{};
    std::uint64_t expected_name_header_size{};
    std::uint64_t path_table_offset{};
    std::uint64_t directory_table_offset{};
    std::uint64_t metadata_end{};
    std::uint16_t flags{};
    std::uint8_t alignment_shift{};
    std::uint8_t path_entry_size{};
    std::uint8_t directory_entry_size{};
    std::uint16_t unique_directory_count{};
    bool signature_matches{};
    bool structure_matches{};
};

struct IndexSummary {
    std::uint64_t entries{};
    std::uint64_t refpack_entries{};
    std::uint64_t chunkzip_entries{};
    std::uint64_t chunkref_entries{};
    std::uint64_t chunklzx_entries{};
    std::uint64_t chunlzma_entries{};
    std::uint64_t chunklz4_entries{};
    std::uint64_t chunkunc_entries{};
    std::uint64_t chunzstd_entries{};
    std::uint64_t chunoodl_entries{};
    std::uint64_t raw_entries{};
    std::uint64_t indexed_full_path_matches{};
    std::uint64_t indexed_filename_matches{};
    std::uint64_t unmatched_hashes{};
};

std::uint32_t djb2(std::string_view value) {
    std::uint32_t hash = 5381;
    for (const char character : value) {
        hash = hash * 33U + static_cast<unsigned char>(character);
    }
    return hash;
}

bool inspect_one(const std::filesystem::path& path, ArchiveHeader& header, std::string& error) {
    std::error_code filesystem_error;
    header.file_size = std::filesystem::file_size(path, filesystem_error);
    if (filesystem_error) {
        error = "não foi possível obter o tamanho do arquivo";
        return false;
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "não foi possível abrir o arquivo";
        return false;
    }
    std::array<std::uint8_t, 32> bytes{};
    if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        error = "arquivo menor que o cabeçalho de 16 bytes";
        return false;
    }

    header.path = path;
    header.signature_matches = std::equal(kEbV3Magic.begin(), kEbV3Magic.end(), bytes.begin());
    header.file_count = read_be_u32(bytes, 4);
    header.flags = read_be_u16(bytes, 8);
    header.alignment_shift = bytes[10];
    header.base_header_size = read_be_u32(bytes, 12);
    header.name_header_size = read_be_u32(bytes, 16);
    header.path_entry_size = bytes[20];
    header.directory_entry_size = bytes[21];
    header.unique_directory_count = read_be_u16(bytes, 22);
    header.declared_file_size = read_be_u64(bytes, 24);

    std::uint64_t expected_base_header_size{};
    std::uint64_t path_table_end{};
    std::uint64_t directory_table_end{};
    const bool base_size_fits = header.file_count <=
        (std::numeric_limits<std::uint64_t>::max() - 48U) / 17U;
    const bool path_size_fits = header.path_entry_size != 0 &&
        header.file_count <= (std::numeric_limits<std::uint64_t>::max() - header.base_header_size) /
                                 header.path_entry_size;
    if (!base_size_fits || !path_size_fits || header.alignment_shift >= 32 || header.path_entry_size < 2 ||
        header.directory_entry_size == 0 || header.file_count == 0) {
        return true;
    }

    const auto minimum_base = 48U + header.file_count * 17U;
    const auto path_end = header.base_header_size + header.file_count * header.path_entry_size;
    const bool directory_size_fits = header.unique_directory_count <=
        (std::numeric_limits<std::uint64_t>::max() - path_end) / header.directory_entry_size;
    const bool aligned_sizes_fit = directory_size_fits && align_16(minimum_base, expected_base_header_size) &&
        align_16(path_end, path_table_end) &&
        align_16(path_table_end + header.unique_directory_count * header.directory_entry_size,
                 directory_table_end);
    if (!aligned_sizes_fit || header.base_header_size > header.file_size ||
        directory_table_end < header.base_header_size) {
        return true;
    }
    header.expected_name_header_size = directory_table_end - header.base_header_size;
    header.metadata_end = directory_table_end;
    header.path_table_offset = header.base_header_size;
    header.directory_table_offset = path_table_end;
    header.structure_matches = header.signature_matches && header.declared_file_size == header.file_size &&
        header.base_header_size == expected_base_header_size &&
        header.name_header_size == header.expected_name_header_size &&
        header.metadata_end <= header.file_size;
    return true;
}

bool inspect_index(const ArchiveHeader& header, IndexSummary& summary, std::string& error) {
    constexpr std::uint64_t hash_index_offset = 48;
    constexpr std::uint64_t hash_index_entry_size = 16;
    std::ifstream file(header.path, std::ios::binary);
    if (!file) {
        error = "não foi possível reabrir o arquivo";
        return false;
    }
    const auto alignment = std::uint64_t{1} << header.alignment_shift;
    std::array<std::uint8_t, 16> record{};
    std::array<std::uint8_t, 8> prefix{};

    std::vector<std::uint8_t> path_entry(header.path_entry_size);
    std::vector<std::uint8_t> directory_entry(header.directory_entry_size);
    std::vector<std::string> directories;
    directories.reserve(header.unique_directory_count);
    for (std::uint64_t index = 0; index < header.unique_directory_count; ++index) {
        const auto directory_offset = header.directory_table_offset + index * header.directory_entry_size;
        file.clear();
        file.seekg(static_cast<std::streamoff>(directory_offset), std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(directory_entry.data()),
                       static_cast<std::streamsize>(directory_entry.size())) ||
            std::find(directory_entry.begin(), directory_entry.end(), 0) == directory_entry.end()) {
            error = "entrada truncada ou sem terminador na tabela de diretórios";
            return false;
        }
        const auto end = std::find(directory_entry.begin(), directory_entry.end(), 0);
        directories.emplace_back(directory_entry.begin(), end);
    }

    for (std::uint64_t index = 0; index < header.file_count; ++index) {
        const auto record_offset = hash_index_offset + index * hash_index_entry_size;
        if (record_offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
            error = "índice de hash excede o limite de offsets desta plataforma";
            return false;
        }
        file.clear();
        file.seekg(static_cast<std::streamoff>(record_offset), std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(record.data()), static_cast<std::streamsize>(record.size()))) {
            error = "entrada truncada no índice de hash";
            return false;
        }
        const auto path_offset = header.path_table_offset + index * header.path_entry_size;
        file.clear();
        file.seekg(static_cast<std::streamoff>(path_offset), std::ios::beg);
        if (!file.read(reinterpret_cast<char*>(path_entry.data()), static_cast<std::streamsize>(path_entry.size()))) {
            error = "entrada truncada na tabela de caminhos";
            return false;
        }
        const auto directory_index = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(path_entry[0]) << 8U) | static_cast<std::uint16_t>(path_entry[1]));
        if (directory_index >= header.unique_directory_count ||
            std::find(path_entry.begin() + 2, path_entry.end(), 0) == path_entry.end()) {
            error = "índice de diretório ou nome de arquivo inválido na tabela de caminhos";
            return false;
        }
        const auto name_end = std::find(path_entry.begin() + 2, path_entry.end(), 0);
        std::string member_path = directories[directory_index];
        if (!member_path.empty()) {
            member_path.push_back('/');
        }
        member_path.append(path_entry.begin() + 2, name_end);
        const auto full_path_hash = djb2(member_path);
        const std::string_view filename(reinterpret_cast<const char*>(path_entry.data() + 2),
            static_cast<std::size_t>(name_end - (path_entry.begin() + 2)));
        const auto member_hash = read_be_u32(record, 12);
        const bool full_path_matches = full_path_hash == member_hash;
        const bool filename_matches = djb2(filename) == member_hash;
        if (full_path_matches) {
            ++summary.indexed_full_path_matches;
        }
        if (filename_matches) {
            ++summary.indexed_filename_matches;
        }
        if (!full_path_matches && !filename_matches) {
            ++summary.unmatched_hashes;
        }
        const auto offset_units = read_be_u32(record, 0);
        const auto refpack_size = read_be_u32(record, 4);
        const auto stored_or_chunkzip_size = read_be_u32(record, 8);
        const auto data_offset = static_cast<std::uint64_t>(offset_units) * alignment;
        if (data_offset < header.metadata_end || data_offset > header.file_size) {
            error = "entrada aponta para fora da área de dados ou do arquivo";
            return false;
        }

        prefix.fill(0);
        const auto available = header.file_size - data_offset;
        const auto candidate_length = std::min<std::uint64_t>(available, stored_or_chunkzip_size);
        const auto prefix_length = static_cast<std::streamsize>(
            std::min<std::uint64_t>(prefix.size(), candidate_length));
        file.clear();
        file.seekg(static_cast<std::streamoff>(data_offset), std::ios::beg);
        if (prefix_length > 0 && !file.read(reinterpret_cast<char*>(prefix.data()), prefix_length)) {
            error = "não foi possível ler a assinatura de um payload";
            return false;
        }

        const bool is_refpack = prefix_length >= 2 && prefix[0] == 0x10 && prefix[1] == 0xfb;
        constexpr std::array<std::uint8_t, 8> chunkzip_magic{'c', 'h', 'u', 'n', 'k', 'z', 'i', 'p'};
        constexpr std::array<std::uint8_t, 8> chunkref_magic{'c', 'h', 'u', 'n', 'k', 'r', 'e', 'f'};
        constexpr std::array<std::uint8_t, 8> chunklzx_magic{'c', 'h', 'u', 'n', 'k', 'l', 'z', 'x'};
        constexpr std::array<std::uint8_t, 8> chunlzma_magic{'c', 'h', 'u', 'n', 'l', 'z', 'm', 'a'};
        constexpr std::array<std::uint8_t, 8> chunklz4_magic{'c', 'h', 'u', 'n', 'k', 'l', 'z', '4'};
        constexpr std::array<std::uint8_t, 8> chunkunc_magic{'c', 'h', 'u', 'n', 'k', 'u', 'n', 'c'};
        constexpr std::array<std::uint8_t, 8> chunzstd_magic{'c', 'h', 'u', 'n', 'z', 's', 't', 'd'};
        constexpr std::array<std::uint8_t, 8> chunoodl_magic{'c', 'h', 'u', 'n', 'o', 'o', 'd', 'l'};
        const bool is_chunkzip = prefix_length >= static_cast<std::streamsize>(chunkzip_magic.size()) &&
            std::equal(chunkzip_magic.begin(), chunkzip_magic.end(), prefix.begin());
        const auto starts_with = [&prefix, prefix_length](const auto& magic) {
            return prefix_length >= static_cast<std::streamsize>(magic.size()) &&
                std::equal(magic.begin(), magic.end(), prefix.begin());
        };
        const bool is_chunkref = starts_with(chunkref_magic);
        const bool is_chunklzx = starts_with(chunklzx_magic);
        const bool is_chunlzma = starts_with(chunlzma_magic);
        const bool is_chunklz4 = starts_with(chunklz4_magic);
        const bool is_chunkunc = starts_with(chunkunc_magic);
        const bool is_chunzstd = starts_with(chunzstd_magic);
        const bool is_chunoodl = starts_with(chunoodl_magic);
        const auto stored_size = is_refpack ? refpack_size : stored_or_chunkzip_size;
        if (stored_size > available) {
            error = "tamanho armazenado da entrada ultrapassa o fim do arquivo";
            return false;
        }
        if ((is_refpack && refpack_size == 0) || (!is_refpack && stored_or_chunkzip_size == 0)) {
            error = "entrada com payload não declara tamanho armazenado";
            return false;
        }
        ++summary.entries;
        if (is_refpack) {
            ++summary.refpack_entries;
        } else if (is_chunkzip) {
            ++summary.chunkzip_entries;
        } else if (is_chunkref) {
            ++summary.chunkref_entries;
        } else if (is_chunklzx) {
            ++summary.chunklzx_entries;
        } else if (is_chunlzma) {
            ++summary.chunlzma_entries;
        } else if (is_chunklz4) {
            ++summary.chunklz4_entries;
        } else if (is_chunkunc) {
            ++summary.chunkunc_entries;
        } else if (is_chunzstd) {
            ++summary.chunzstd_entries;
        } else if (is_chunoodl) {
            ++summary.chunoodl_entries;
        } else {
            ++summary.raw_entries;
        }
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Uso: nba16-big-inspect <pasta-do-jogo>\n";
        return 2;
    }

    const std::filesystem::path root(argv[1]);
    std::error_code filesystem_error;
    if (!std::filesystem::is_directory(root, filesystem_error) || filesystem_error) {
        std::cerr << "A pasta informada não existe ou não pode ser acessada.\n";
        return 2;
    }

    std::uint64_t archive_count = 0;
    std::uint64_t total_bytes = 0;
    std::uint64_t matching_signature_count = 0;
    std::uint64_t structurally_consistent_count = 0;
    std::uint64_t total_member_count = 0;
    std::uint64_t maximum_member_count = 0;
    std::uint64_t maximum_metadata_end = 0;
    std::uint64_t declared_size_mismatch_count = 0;
    std::uint64_t full_path_hash_archive_count = 0;
    std::uint64_t filename_hash_archive_count = 0;
    std::uint64_t mixed_hash_archive_count = 0;
    std::uint64_t unmatched_hash_archive_count = 0;
    IndexSummary index_summary{};
    std::uint8_t minimum_alignment_shift = std::numeric_limits<std::uint8_t>::max();
    std::uint8_t maximum_alignment_shift = 0;
    std::uint16_t minimum_flags = std::numeric_limits<std::uint16_t>::max();
    std::uint16_t maximum_flags = 0;
    std::vector<std::string> issues;
    std::vector<std::string> full_path_hash_samples;
    std::vector<std::string> filename_hash_samples;

    for (std::filesystem::recursive_directory_iterator iterator(root, filesystem_error), end;
         !filesystem_error && iterator != end; iterator.increment(filesystem_error)) {
        std::error_code entry_error;
        if (!iterator->is_regular_file(entry_error) || entry_error ||
            lower_ascii(iterator->path().extension().string()) != ".big") {
            continue;
        }

        ++archive_count;
        ArchiveHeader header{};
        std::string error;
        if (!inspect_one(iterator->path(), header, error)) {
            issues.push_back(iterator->path().string() + ": " + error);
            continue;
        }
        total_bytes += header.file_size;
        if (header.signature_matches) {
            ++matching_signature_count;
            total_member_count += header.file_count;
            maximum_member_count = std::max(maximum_member_count, header.file_count);
            maximum_metadata_end = std::max(maximum_metadata_end, header.metadata_end);
            minimum_alignment_shift = std::min(minimum_alignment_shift, header.alignment_shift);
            maximum_alignment_shift = std::max(maximum_alignment_shift, header.alignment_shift);
            minimum_flags = std::min(minimum_flags, header.flags);
            maximum_flags = std::max(maximum_flags, header.flags);
            if (header.declared_file_size != header.file_size) {
                ++declared_size_mismatch_count;
            }
        }
        if (header.structure_matches) {
            ++structurally_consistent_count;
            IndexSummary archive_index{};
            if (!inspect_index(header, archive_index, error)) {
                issues.push_back(iterator->path().string() + ": " + error);
            } else {
                if (archive_index.unmatched_hashes != 0) {
                    ++unmatched_hash_archive_count;
                } else if (archive_index.indexed_full_path_matches == archive_index.entries &&
                           archive_index.indexed_filename_matches < archive_index.entries) {
                    ++full_path_hash_archive_count;
                } else if (archive_index.indexed_filename_matches == archive_index.entries &&
                           archive_index.indexed_full_path_matches < archive_index.entries) {
                    ++filename_hash_archive_count;
                } else {
                    ++mixed_hash_archive_count;
                }
                if (archive_index.indexed_full_path_matches != 0 && full_path_hash_samples.size() < 5) {
                    full_path_hash_samples.push_back(iterator->path().filename().string() + ": " +
                        std::to_string(archive_index.indexed_full_path_matches) + "/" +
                        std::to_string(archive_index.entries));
                }
                if (archive_index.indexed_filename_matches != 0 && filename_hash_samples.size() < 5) {
                    filename_hash_samples.push_back(iterator->path().filename().string() + ": " +
                        std::to_string(archive_index.indexed_filename_matches) + "/" +
                        std::to_string(archive_index.entries));
                }
                index_summary.entries += archive_index.entries;
                index_summary.refpack_entries += archive_index.refpack_entries;
                index_summary.chunkzip_entries += archive_index.chunkzip_entries;
                index_summary.chunkref_entries += archive_index.chunkref_entries;
                index_summary.chunklzx_entries += archive_index.chunklzx_entries;
                index_summary.chunlzma_entries += archive_index.chunlzma_entries;
                index_summary.chunklz4_entries += archive_index.chunklz4_entries;
                index_summary.chunkunc_entries += archive_index.chunkunc_entries;
                index_summary.chunzstd_entries += archive_index.chunzstd_entries;
                index_summary.chunoodl_entries += archive_index.chunoodl_entries;
                index_summary.raw_entries += archive_index.raw_entries;
                index_summary.indexed_full_path_matches += archive_index.indexed_full_path_matches;
                index_summary.indexed_filename_matches += archive_index.indexed_filename_matches;
                index_summary.unmatched_hashes += archive_index.unmatched_hashes;
            }
        } else {
            issues.push_back(iterator->path().string() + ": cabeçalho, tamanhos ou limites estruturais não conferem");
        }
    }
    if (filesystem_error) {
        std::cerr << "Falha ao percorrer a pasta: " << filesystem_error.message() << '\n';
        return 1;
    }
    if (archive_count == 0) {
        std::cerr << "Nenhum arquivo .big foi encontrado.\n";
        return 1;
    }

    std::cout << "Arquivos .big: " << archive_count << '\n'
              << "Tamanho combinado: " << total_bytes << " bytes\n"
              << "Assinatura EB 00 03: " << matching_signature_count << '\n'
              << "Cabeçalhos compatíveis com a geometria NewBig: " << structurally_consistent_count << '\n'
              << "Entradas de índice declaradas: " << total_member_count << " (máximo por arquivo: "
              << maximum_member_count << ")\n"
              << "Flags: 0x" << std::hex << minimum_flags << "–0x" << maximum_flags << std::dec << '\n'
              << "Expoente de alinhamento: " << static_cast<unsigned>(minimum_alignment_shift) << "–"
              << static_cast<unsigned>(maximum_alignment_shift) << '\n'
              << "Diferenças entre tamanho declarado e real: " << declared_size_mismatch_count << '\n'
              << "Maior fim calculado das tabelas de metadados: " << maximum_metadata_end << " bytes\n"
              << "Entradas de hash verificadas: " << index_summary.entries << '\n'
              << "Payloads por assinatura: RefPack=" << index_summary.refpack_entries
              << ", ChunkZip=" << index_summary.chunkzip_entries
              << ", ChunkRef=" << index_summary.chunkref_entries
              << ", ChunkLZX=" << index_summary.chunklzx_entries
              << ", ChunLZMA=" << index_summary.chunlzma_entries
              << ", ChunkLZ4=" << index_summary.chunklz4_entries
              << ", ChunkUnc=" << index_summary.chunkunc_entries
              << ", ChunZstd=" << index_summary.chunzstd_entries
              << ", ChunOodle=" << index_summary.chunoodl_entries
              << ", sem assinatura reconhecida=" << index_summary.raw_entries << '\n'
              << "Hashes DJB2 que não correspondem ao caminho nem ao nome: "
              << index_summary.unmatched_hashes << '\n'
              << "Arquivos BIG: hash por caminho completo=" << full_path_hash_archive_count
              << ", por nome=" << filename_hash_archive_count
              << ", mistos/ambíguos=" << mixed_hash_archive_count
              << ", com hash não reconhecido=" << unmatched_hash_archive_count << '\n';
    std::cout << "Amostras de arquivos com hashes de caminho: ";
    for (std::size_t index = 0; index < full_path_hash_samples.size(); ++index) {
        std::cout << (index == 0 ? "" : "; ") << full_path_hash_samples[index];
    }
    std::cout << '\n' << "Amostras de arquivos com hashes de nome: ";
    for (std::size_t index = 0; index < filename_hash_samples.size(); ++index) {
        std::cout << (index == 0 ? "" : "; ") << filename_hash_samples[index];
    }
    std::cout << '\n';
    std::cout << "Nota: limites do índice e tamanhos armazenados conferidos; nenhum conteúdo foi descompactado.\n";
    for (const auto& issue : issues) {
        std::cout << "Atenção: " << issue << '\n';
    }
    return issues.empty() ? 0 : 1;
}
