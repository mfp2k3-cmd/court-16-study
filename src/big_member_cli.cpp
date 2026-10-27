#include "big_archive.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

const char* compression_name(nba16::BigCompression compression) {
    switch (compression) {
    case nba16::BigCompression::uncompressed_candidate: return "sem assinatura reconhecida";
    case nba16::BigCompression::chunkzip: return "ChunkZip";
    case nba16::BigCompression::chunkref: return "ChunkRef";
    case nba16::BigCompression::chunklzx: return "ChunkLZX";
    case nba16::BigCompression::chunlzma: return "ChunLZMA";
    case nba16::BigCompression::chunklz4: return "ChunkLZ4";
    case nba16::BigCompression::chunkunc: return "ChunkUnc";
    case nba16::BigCompression::chunzstd: return "ChunZstd";
    case nba16::BigCompression::chunoodl: return "ChunOodle";
    case nba16::BigCompression::refpack: return "RefPack";
    }
    return "desconhecida";
}

bool parse_u64(const char* value, std::uint64_t& result) {
    const std::string_view text(value);
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

} // namespace

int main(int argc, char** argv) {
    const auto list_argument = argc >= 3 ? std::string_view(argv[2]) : std::string_view{};
    const bool list_mode = list_argument == "--list" || list_argument == "--largest";
    const bool largest_mode = list_argument == "--largest";
    const bool stored_mode = argc > 3 && std::string_view(argv[argc - 1]) == "--stored";
    const bool decoded_mode = argc > 3 && std::string_view(argv[argc - 1]) == "--decoded";
    const int positional_count = argc - ((stored_mode || decoded_mode) ? 1 : 0);
    if (list_mode && (argc < 3 || argc > 5)) {
        std::cerr << "Uso: nba16-big-read <arquivo.big> [--list|--largest] [filtro-de-caminho] [--compression=ChunkZip|ChunkRef]\n";
        return 2;
    }
    if (!list_mode && (positional_count < 3 || positional_count > 5)) {
        std::cerr << "Uso: nba16-big-read <arquivo.big> <caminho-interno> [offset] [quantidade] [--stored|--decoded]\n";
        return 2;
    }
    std::uint64_t offset = 0;
    std::uint64_t requested = 32;
    if (!list_mode && ((positional_count >= 4 && !parse_u64(argv[3], offset)) ||
        (positional_count == 5 && !parse_u64(argv[4], requested)) || requested > 4096)) {
        std::cerr << "Offset inválido ou quantidade fora do limite de 4096 bytes.\n";
        return 2;
    }

    nba16::BigArchive archive;
    std::string error;
    if (!archive.open(argv[1], error)) {
        std::cerr << "Arquivo BIG inválido: " << error << '\n';
        return 1;
    }
    if (list_mode) {
        std::string_view path_filter;
        std::string_view compression_filter;
        for (int index = 3; index < argc; ++index) {
            const std::string_view argument(argv[index]);
            constexpr std::string_view compression_prefix = "--compression=";
            if (argument.starts_with(compression_prefix)) {
                if (!compression_filter.empty()) {
                    std::cerr << "Informe apenas um filtro de compressão.\n";
                    return 2;
                }
                compression_filter = argument.substr(compression_prefix.size());
                if (compression_filter != "ChunkZip" && compression_filter != "ChunkRef") {
                    std::cerr << "Compressão desconhecida; use ChunkZip ou ChunkRef.\n";
                    return 2;
                }
            } else if (path_filter.empty()) {
                path_filter = argument;
            } else {
                std::cerr << "Informe apenas um filtro de caminho.\n";
                return 2;
            }
        }
        std::vector<const nba16::BigMember*> matches;
        for (const auto& entry : archive.members()) {
            const bool path_matches = path_filter.empty() ||
                entry.path.find(path_filter) != std::string::npos;
            const bool compression_matches = compression_filter.empty() ||
                (compression_filter == "ChunkZip" && entry.compression == nba16::BigCompression::chunkzip) ||
                (compression_filter == "ChunkRef" && entry.compression == nba16::BigCompression::chunkref);
            if (path_matches && compression_matches) matches.push_back(&entry);
        }
        if (largest_mode) {
            std::stable_sort(matches.begin(), matches.end(), [](const auto* left, const auto* right) {
                return left->logical_size > right->logical_size;
            });
        }
        std::size_t matched = 0;
        std::size_t printed = 0;
        for (const auto* entry : matches) {
            ++matched;
            if (printed < 200) {
                std::cout << entry->path << "\t" << compression_name(entry->compression)
                          << "\tstored=" << entry->stored_size
                          << "\tlogical=" << entry->logical_size
                          << "\tsize-field=" << entry->size_field << '\n';
                ++printed;
            }
        }
        std::cout << "Correspondências: " << matched << "; listadas: " << printed
                  << (largest_mode ? " (maiores primeiro).\n" : ".\n");
        return 0;
    }
    const auto* member = archive.find(argv[2]);
    if (member == nullptr) {
        std::cerr << "Entrada não encontrada no índice BIG.\n";
        return 1;
    }

    std::cout << "Entrada: " << member->path << '\n'
              << "Compressão: " << compression_name(member->compression) << '\n'
              << "Offset no BIG: " << member->data_offset << '\n'
              << "Tamanho armazenado: " << member->stored_size << " bytes\n"
              << "Tamanho lógico: " << member->logical_size << " bytes\n";
    if (member->compression != nba16::BigCompression::uncompressed_candidate &&
        !stored_mode && !decoded_mode) {
        std::cout << "Leitura do conteúdo adiada: ainda não há decodificador para este formato.\n";
        return 0;
    }

    const auto readable_size = decoded_mode ? member->logical_size : member->stored_size;
    const auto amount = static_cast<std::size_t>(std::min<std::uint64_t>(
        requested, readable_size - std::min(offset, readable_size)));
    std::vector<std::byte> bytes(amount);
    std::size_t bytes_read = 0;
    const bool read_ok = stored_mode
        ? archive.read_stored_range(*member, offset, bytes, bytes_read, error)
        : decoded_mode
            ? archive.read_decoded_range(*member, offset, bytes, bytes_read, error)
            : archive.read_candidate_range(*member, offset, bytes, bytes_read, error);
    if (!read_ok) {
        std::cerr << "Falha lendo a entrada: " << error << '\n';
        return 1;
    }
    const auto label = stored_mode ? "Bytes armazenados lidos no offset "
        : decoded_mode ? "Bytes decodificados lidos no offset " : "Bytes lidos no offset ";
    std::cout << label << offset << ":";
    for (std::size_t index = 0; index < bytes_read; ++index) {
        std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<unsigned>(std::to_integer<std::uint8_t>(bytes[index]));
    }
    std::cout << std::dec << '\n';
    return 0;
}
