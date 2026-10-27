#pragma once

#include "elf64_inspector.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <string>
#include <vector>

namespace nba16 {

struct ProgramSegmentImage {
    std::size_t program_header_index{};
    ElfProgramHeaderSummary program_header{};
    std::vector<std::uint8_t> file_bytes;
    bool read_from_self_trailer{};
};

struct SelfProgramImage {
    std::uint16_t elf_type{};
    std::uint16_t machine{};
    std::uint8_t os_abi{};
    std::uint64_t entry_point{};
    std::vector<ElfProgramHeaderSummary> program_headers;
    std::vector<ProgramSegmentImage> segments;
    std::uint64_t total_payload_bytes{};
    std::size_t digest_table_count{};
    std::uint64_t digest_table_bytes{};
    std::size_t zero_filled_digest_table_count{};
};

// Reads an unencrypted, uncompressed SELF into separate program-header payloads.
// Overlapping ELF file ranges remain separate, as required by this dump's RELRO data.
bool load_clear_self_program_image(const std::filesystem::path& path,
                                   const SelfHeaderSummary& self,
                                   const EmbeddedElfSummary& elf,
                                   SelfProgramImage& image,
                                   std::string& error);

void print_summary(const SelfProgramImage& image, std::ostream& output);

} // namespace nba16
