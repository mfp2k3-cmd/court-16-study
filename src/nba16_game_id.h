// SPDX-FileCopyrightText: Copyright 2026 NBA LIVE 16 independent port contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace NBA16 {

inline std::optional<std::wstring> ReadTitleId(const std::filesystem::path& game_root) {
    const auto sfo_path = game_root / L"sce_sys" / L"param.sfo";
    std::error_code ec;
    const auto size = std::filesystem::file_size(sfo_path, ec);
    if (ec || size < 20 || size > 4 * 1024 * 1024) {
        return std::nullopt;
    }

    std::ifstream input(sfo_path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    const std::vector<unsigned char> bytes(std::istreambuf_iterator<char>(input), {});
    if (bytes.size() != size || bytes[0] != 0 || bytes[1] != 'P' || bytes[2] != 'S' ||
        bytes[3] != 'F') {
        return std::nullopt;
    }

    const auto read_u16 = [&bytes](size_t offset, uint16_t& value) {
        if (offset > bytes.size() || bytes.size() - offset < 2) return false;
        value = static_cast<uint16_t>(bytes[offset]) |
                (static_cast<uint16_t>(bytes[offset + 1]) << 8);
        return true;
    };
    const auto read_u32 = [&bytes](size_t offset, uint32_t& value) {
        if (offset > bytes.size() || bytes.size() - offset < 4) return false;
        value = static_cast<uint32_t>(bytes[offset]) |
                (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
                (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
                (static_cast<uint32_t>(bytes[offset + 3]) << 24);
        return true;
    };

    uint32_t key_table_offset{}, data_table_offset{}, entry_count{};
    if (!read_u32(8, key_table_offset) || !read_u32(12, data_table_offset) ||
        !read_u32(16, entry_count) || entry_count > 8192 || key_table_offset > bytes.size() ||
        data_table_offset > bytes.size() || key_table_offset > data_table_offset ||
        entry_count > (bytes.size() - 20) / 16) {
        return std::nullopt;
    }

    for (uint32_t index = 0; index < entry_count; ++index) {
        const size_t entry = 20 + static_cast<size_t>(index) * 16;
        uint16_t key_offset{};
        uint32_t value_length{}, value_offset{};
        if (!read_u16(entry, key_offset) || !read_u32(entry + 4, value_length) ||
            !read_u32(entry + 12, value_offset)) {
            return std::nullopt;
        }

        const size_t key = static_cast<size_t>(key_table_offset) + key_offset;
        if (key >= data_table_offset) continue;
        size_t key_end = key;
        while (key_end < data_table_offset && bytes[key_end] != 0) ++key_end;
        if (key_end == data_table_offset || key_end - key != 8 ||
            std::string(bytes.begin() + key, bytes.begin() + key_end) != "TITLE_ID") {
            continue;
        }

        const size_t value = static_cast<size_t>(data_table_offset) + value_offset;
        if (value > bytes.size() || value_length > bytes.size() - value || value_length > 64) {
            return std::nullopt;
        }
        std::wstring title_id;
        title_id.reserve(value_length);
        for (size_t offset = 0; offset < value_length && bytes[value + offset] != 0; ++offset) {
            const auto ch = bytes[value + offset];
            if (ch > 0x7f) return std::nullopt;
            title_id.push_back(static_cast<wchar_t>(ch));
        }
        return title_id;
    }
    return std::nullopt;
}

inline bool IsSupportedTitleId(const std::wstring& title_id) {
    return title_id == L"CUSA01933" || title_id == L"CUSA01966";
}

} // namespace NBA16
