#pragma once

#include "self_program_image.h"

#include <cstdint>
#include <ostream>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace nba16 {

struct DynamicSymbol {
    std::string name;
    std::uint64_t value{};
    std::uint64_t size{};
    std::uint8_t info{};
    std::uint8_t other{};
    std::uint16_t section_index{};
    bool has_nid_indices{};
    std::uint32_t nid_library_index{};
    std::uint32_t nid_module_index{};
};

struct DynamicImportLibrary {
    std::string name;
    std::uint32_t library_id{};
    std::uint16_t version{};
    std::uint32_t string_offset{};
    std::uint64_t raw_value{};
};

struct DynamicExportLibrary {
    std::string name;
    std::uint32_t library_id{};
    std::uint16_t version{};
    std::uint32_t string_offset{};
    std::uint64_t raw_value{};
};

struct DynamicImportModule {
    std::string name;
    std::uint32_t module_id{};
    std::uint16_t version{};
    std::uint32_t string_offset{};
    std::uint64_t raw_value{};
};

struct DynamicRelocation {
    std::uint64_t target{};
    std::uint32_t type{};
    std::uint32_t symbol_index{};
    std::uint64_t addend_bits{};
    bool is_plt{};
};

struct DynamicInitializationInfo {
    std::optional<std::uint64_t> init_function;
    std::optional<std::uint64_t> fini_function;
    std::optional<std::uint64_t> preinit_array;
    std::optional<std::uint64_t> preinit_array_size;
    std::optional<std::uint64_t> init_array;
    std::optional<std::uint64_t> init_array_size;
    std::optional<std::uint64_t> fini_array;
    std::optional<std::uint64_t> fini_array_size;
};

struct Ps4DynamicLinkInfo {
    std::string project_name;
    std::uint16_t project_version{};
    std::vector<std::string> needed_modules;
    std::vector<DynamicImportLibrary> import_libraries;
    std::vector<DynamicExportLibrary> export_libraries;
    std::vector<DynamicImportModule> import_modules;
    std::vector<DynamicSymbol> symbols;
    std::vector<DynamicRelocation> relocations;
    DynamicInitializationInfo initialization;
};

bool read_ps4_dynamic_link_info(const SelfProgramImage& image,
                                Ps4DynamicLinkInfo& info,
                                std::string& error);
void print_summary(const Ps4DynamicLinkInfo& info, std::ostream& output);
void write_import_nid_table(const Ps4DynamicLinkInfo& info, std::ostream& output);

} // namespace nba16
