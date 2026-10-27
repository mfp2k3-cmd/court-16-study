#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::array<std::uint8_t, 16> nid_suffix{
    0x51, 0x8d, 0x64, 0xa6, 0x35, 0xde, 0xd8, 0xc1,
    0xe6, 0xb0, 0x39, 0xb1, 0xc3, 0xe5, 0x52, 0x30};
constexpr std::string_view base64_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::uint32_t rotate_left(std::uint32_t value, unsigned count) {
    return (value << count) | (value >> (32U - count));
}

std::array<std::uint8_t, 20> sha1(std::string_view text) {
    std::vector<std::uint8_t> bytes(text.begin(), text.end());
    bytes.insert(bytes.end(), nid_suffix.begin(), nid_suffix.end());
    const auto bit_length = static_cast<std::uint64_t>(bytes.size()) * 8U;
    bytes.push_back(0x80U);
    while ((bytes.size() % 64U) != 56U) bytes.push_back(0U);
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<std::uint8_t>((bit_length >> shift) & 0xffU));
    }

    std::uint32_t h0 = 0x67452301U;
    std::uint32_t h1 = 0xefcdab89U;
    std::uint32_t h2 = 0x98badcfeU;
    std::uint32_t h3 = 0x10325476U;
    std::uint32_t h4 = 0xc3d2e1f0U;
    for (std::size_t block = 0; block < bytes.size(); block += 64U) {
        std::array<std::uint32_t, 80> words{};
        for (std::size_t index = 0; index < 16U; ++index) {
            const auto offset = block + index * 4U;
            words[index] = (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
                           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
                           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
                           static_cast<std::uint32_t>(bytes[offset + 3U]);
        }
        for (std::size_t index = 16U; index < words.size(); ++index) {
            words[index] = rotate_left(words[index - 3U] ^ words[index - 8U] ^
                                       words[index - 14U] ^ words[index - 16U], 1U);
        }
        auto a = h0;
        auto b = h1;
        auto c = h2;
        auto d = h3;
        auto e = h4;
        for (std::size_t index = 0; index < words.size(); ++index) {
            std::uint32_t f{};
            std::uint32_t k{};
            if (index < 20U) {
                f = (b & c) | ((~b) & d);
                k = 0x5a827999U;
            } else if (index < 40U) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1U;
            } else if (index < 60U) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdcU;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6U;
            }
            const auto temp = rotate_left(a, 5U) + f + e + k + words[index];
            e = d;
            d = c;
            c = rotate_left(b, 30U);
            b = a;
            a = temp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    std::array<std::uint8_t, 20> digest{};
    const std::array<std::uint32_t, 5> state{h0, h1, h2, h3, h4};
    for (std::size_t word = 0; word < state.size(); ++word) {
        for (std::size_t byte = 0; byte < 4U; ++byte) {
            digest[word * 4U + byte] = static_cast<std::uint8_t>(
                (state[word] >> (24U - static_cast<unsigned>(byte * 8U))) & 0xffU);
        }
    }
    return digest;
}

std::string make_nid(std::string_view name) {
    auto digest = sha1(name);
    std::array<std::uint8_t, 8> encoded_bytes{};
    for (std::size_t index = 0; index < encoded_bytes.size(); ++index) {
        encoded_bytes[index] = digest[7U - index];
    }
    std::string result;
    result.reserve(11U);
    for (std::size_t index = 0; index < encoded_bytes.size(); index += 3U) {
        const auto remaining = encoded_bytes.size() - index;
        const std::uint32_t chunk = (static_cast<std::uint32_t>(encoded_bytes[index]) << 16U) |
            (remaining > 1U ? static_cast<std::uint32_t>(encoded_bytes[index + 1U]) << 8U : 0U) |
            (remaining > 2U ? static_cast<std::uint32_t>(encoded_bytes[index + 2U]) : 0U);
        result.push_back(base64_alphabet[(chunk >> 18U) & 0x3fU]);
        result.push_back(base64_alphabet[(chunk >> 12U) & 0x3fU]);
        if (remaining > 1U) result.push_back(base64_alphabet[(chunk >> 6U) & 0x3fU]);
        if (remaining > 2U) result.push_back(base64_alphabet[chunk & 0x3fU]);
    }
    for (auto& character : result) {
        if (character == '/') character = '-';
    }
    return result;
}

std::vector<std::string> split_tsv(const std::string& line) {
    std::vector<std::string> fields;
    std::istringstream input(line);
    std::string field;
    while (std::getline(input, field, '\t')) fields.push_back(field);
    return fields;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Uso: nba16-nid-match <imports.tsv> <lista-de-nomes.txt> <saida.tsv>\n"
                     "A lista deve conter um nome de símbolo por linha; ela não é distribuída com o port.\n";
        return 2;
    }
    std::ifstream candidates(argv[2]);
    if (!candidates) {
        std::cerr << "Não foi possível abrir a lista externa de nomes candidatos.\n";
        return 1;
    }
    std::map<std::string, std::string> name_by_nid;
    std::string line;
    while (std::getline(candidates, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) name_by_nid.try_emplace(make_nid(line), line);
    }
    if (!candidates.eof()) {
        std::cerr << "Falha ao ler a lista externa de nomes candidatos.\n";
        return 1;
    }

    std::ifstream imports(argv[1]);
    if (!imports || !std::getline(imports, line)) {
        std::cerr << "Não foi possível abrir o TSV de imports.\n";
        return 1;
    }
    const auto headers = split_tsv(line);
    std::map<std::string, std::size_t> column;
    for (std::size_t index = 0; index < headers.size(); ++index) column[headers[index]] = index;
    for (const auto required : {"nid", "library", "module", "symbol_index", "relocation_refs"}) {
        if (!column.contains(required)) {
            std::cerr << "TSV não contém a coluna necessária: " << required << '\n';
            return 1;
        }
    }

    std::ofstream output(argv[3], std::ios::binary);
    if (!output) {
        std::cerr << "Não foi possível criar o TSV de saída.\n";
        return 1;
    }
    output << "symbol_index\tlibrary\tmodule\tnid\trelocation_refs\tcandidate_name\n";
    std::uint64_t checked = 0;
    std::uint64_t matched = 0;
    while (std::getline(imports, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto fields = split_tsv(line);
        const auto at = [&](const char* name) -> const std::string& {
            static const std::string empty;
            const auto index = column.at(name);
            return index < fields.size() ? fields[index] : empty;
        };
        const auto found = name_by_nid.find(at("nid"));
        ++checked;
        if (found != name_by_nid.end()) ++matched;
        output << at("symbol_index") << '\t' << at("library") << '\t' << at("module") << '\t'
               << at("nid") << '\t' << at("relocation_refs") << '\t'
               << (found == name_by_nid.end() ? "" : found->second) << '\n';
    }
    if (!imports.eof() || !output) {
        std::cerr << "Falha ao processar ou gravar o relatório NID.\n";
        return 1;
    }
    std::cout << "NIDs analisados=" << checked << "; nomes candidatos encontrados=" << matched
              << "; nomes carregados=" << name_by_nid.size() << '\n';
    return 0;
}
