#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <map>
#include <string>
#include <vector>

namespace nba16 {

struct LoadSegment {
    std::uint32_t flags{};
    std::uint64_t file_offset{};
    std::uint64_t virtual_address{};
    std::uint64_t file_size{};
    std::uint64_t memory_size{};
    std::uint64_t alignment{};
};

struct ElfSummary {
    std::uint16_t type{};
    std::uint16_t machine{};
    std::uint8_t os_abi{};
    std::uint64_t entry_point{};
    bool entry_point_in_executable_segment{};
    std::vector<LoadSegment> load_segments;
    std::vector<std::string> warnings;
};

struct SelfEntrySummary {
    std::array<std::uint8_t, 8> properties{};
    std::uint64_t property_bits{};
    std::uint16_t segment_index{};
    bool ordered{};
    bool encrypted{};
    bool signed_data{};
    bool compressed{};
    std::uint8_t window_bits{};
    bool has_blocks{};
    std::uint8_t block_bits{};
    bool has_digest{};
    bool has_extents{};
    std::uint64_t offset{};
    std::uint64_t encoded_size{};
    std::uint64_t decoded_size{};
};

struct SelfHeaderSummary {
    std::uint8_t version{};
    std::uint8_t mode{};
    std::uint8_t endian{};
    std::uint8_t attributes{};
    std::uint32_t key_type{};
    std::uint16_t header_size{};
    std::uint16_t metadata_size{};
    std::uint64_t declared_file_size{};
    std::uint16_t entry_count{};
    std::uint16_t flags{};
    std::uint64_t actual_file_size{};
    std::vector<SelfEntrySummary> entries;
    std::uint64_t trailing_bytes{};
};

struct ElfProgramHeaderSummary {
    std::uint32_t type{};
    std::uint32_t flags{};
    std::uint64_t file_offset{};
    std::uint64_t virtual_address{};
    std::uint64_t file_size{};
    std::uint64_t memory_size{};
    std::uint64_t alignment{};
};

struct SelfEntryMappingSummary {
    std::size_t self_entry_index{};
    std::uint16_t program_header_index{};
    bool has_program_header{};
    bool decoded_size_matches_file_segment{};
    bool encrypted{};
    bool compressed{};
};

struct EmbeddedElfSummary {
    std::uint64_t container_offset{};
    std::uint16_t type{};
    std::uint16_t machine{};
    std::uint8_t os_abi{};
    std::uint64_t entry_point{};
    std::uint16_t program_entry_size{};
    bool entry_point_in_executable_segment{};
    std::vector<ElfProgramHeaderSummary> program_headers;
    std::vector<SelfEntryMappingSummary> self_entry_mappings;
    std::vector<std::string> warnings;
};

struct Ps4DependencySummary {
    std::vector<std::string> needed_modules;
    std::vector<std::string> missing_modules;
    std::uint64_t dynamic_symbol_count{};
    std::uint64_t undefined_symbol_count{};
    std::uint64_t distinct_relocation_symbol_count{};
    std::uint64_t rela_relocation_count{};
    std::uint64_t plt_relocation_count{};
    std::uint64_t total_relocation_count{};
    std::uint64_t relocation_targets_in_image{};
    std::uint64_t relocation_targets_outside_image{};
    struct RelocationTypeCounts {
        std::uint64_t count{};
        std::uint64_t no_symbol{};
        std::uint64_t undefined_symbol{};
        std::uint64_t defined_symbol{};
        std::uint64_t relative_addends_in_image{};
        std::uint64_t relative_addends_outside_image{};
    };
    std::map<std::uint32_t, RelocationTypeCounts> relocation_types;
    bool module_directory_checked{};
};

bool inspect_elf64(const std::filesystem::path& path, ElfSummary& summary, std::string& error);
bool inspect_sce_self_header(const std::filesystem::path& path, SelfHeaderSummary& summary, std::string& error);
bool inspect_embedded_elf_header(const std::filesystem::path& path, const SelfHeaderSummary& self,
                                 EmbeddedElfSummary& summary, std::string& error);
bool inspect_ps4_dependencies(const std::filesystem::path& path, const SelfHeaderSummary& self,
                             const EmbeddedElfSummary& elf, const std::filesystem::path& module_directory,
                             Ps4DependencySummary& summary, std::string& error);
void print_summary(const ElfSummary& summary, std::ostream& output);
void print_summary(const SelfHeaderSummary& summary, std::ostream& output);
void print_summary(const EmbeddedElfSummary& summary, std::ostream& output);
void print_summary(const Ps4DependencySummary& summary, std::ostream& output);

} // namespace nba16
