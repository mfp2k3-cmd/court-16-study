#pragma once

#include "ps4_dynamic_link.h"

#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <string>
#include <vector>

namespace nba16 {

struct ModuleDependencySummary {
    std::string name;
    std::string file_name;
    std::uint64_t imported_symbols{};
    std::uint64_t imported_references{};
};

struct ModuleFileSummary {
    std::string module_name;
    std::string file_name;
    std::uint64_t defined_nid_exports{};
    std::uint64_t imports_checked{};
    std::uint64_t imports_matched{};
    std::vector<std::string> exported_libraries;
    std::vector<ModuleDependencySummary> dependencies;
    std::string status;
};

struct ModuleExportRecord {
    std::string module_name;
    std::string library_name;
    std::string nid;
    std::string file_name;
    std::uint64_t guest_virtual_value{};
    std::uint64_t size{};
    std::uint8_t elf_symbol_kind{};
};

struct ModuleImportBinding {
    std::uint32_t import_symbol_index{};
    std::string module_name;
    std::string library_name;
    std::string nid;
    std::string file_name;
    std::uint64_t module_relative_value{};
    std::uint64_t size{};
    std::uint8_t elf_symbol_kind{};
};

struct ModuleExportSummary {
    std::uint64_t modules_requested{};
    std::uint64_t modules_found{};
    std::uint64_t modules_parsed{};
    std::uint64_t import_symbols_checked{};
    std::uint64_t imports_with_library_id{};
    std::uint64_t imports_with_module_id{};
    std::uint64_t imports_with_library_and_module{};
    std::uint64_t pairs_matching_module_export_library{};
    std::uint64_t matches_by_library_module_and_hash{};
    std::uint64_t matches_with_export_kind{};
    std::uint64_t export_kind_mismatches{};
    std::uint64_t matches_using_module_id{};
    std::uint64_t matches_using_module_id_minus_one{};
    std::uint64_t ambiguous_module_id_matches{};
    std::uint64_t module_dependencies{};
    std::uint64_t module_dependency_files_found{};
    std::uint64_t module_dependency_files_missing{};
    std::vector<ModuleFileSummary> modules;
    std::vector<ModuleExportRecord> export_catalog;
    std::vector<ModuleImportBinding> unique_import_bindings;
};

// Reads an external raw ELF64 or clear PS4 SELF module into memory without extracting it.
bool load_ps4_module_program_image(const std::filesystem::path& path,
                                  SelfProgramImage& image,
                                  std::string& error);

bool inspect_module_exports(const Ps4DynamicLinkInfo& executable,
                            const std::filesystem::path& module_directory,
                            ModuleExportSummary& summary,
                            std::string& error);
void print_summary(const ModuleExportSummary& summary, std::ostream& output);
void write_export_catalog(const ModuleExportSummary& summary, std::ostream& output);
void write_unique_import_bindings(const ModuleExportSummary& summary, std::ostream& output);

} // namespace nba16
