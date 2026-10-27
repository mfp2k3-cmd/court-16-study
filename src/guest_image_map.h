#pragma once

#include "self_program_image.h"

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace nba16 {

struct Ps4DynamicLinkInfo;

struct GuestMemoryRegion {
    std::size_t program_header_index{};
    std::uint64_t virtual_address{};
    std::uint64_t file_size{};
    std::uint64_t memory_size{};
    std::uint64_t alignment{};
    std::uint32_t flags{};
    bool read_only_after_relocations{};
    std::vector<std::uint8_t> bytes;
};

struct GuestImageMap {
    std::uint64_t minimum_virtual_address{};
    std::uint64_t maximum_virtual_address{};
    std::uint64_t entry_point{};
    std::uint64_t mapped_memory_bytes{};
    std::uint64_t load_bias{};
    bool relative_relocations_applied{};
    bool imported_relocations_applied{};
    std::uint64_t tls_module_id{};
    std::vector<GuestMemoryRegion> regions;
};

// Builds a relative guest address map from PT_LOAD and PT_SCE_RELRO payloads.
// The image is not placed in host virtual memory and is not executable yet.
bool build_guest_image_map(const SelfProgramImage& image, GuestImageMap& map, std::string& error,
                           bool require_executable_entry = true);
void print_summary(const GuestImageMap& map, std::ostream& output);
bool validate_guest_memory_access(const GuestImageMap& map, std::uint64_t guest_address,
                                  std::size_t byte_count, bool write_access,
                                  std::string& error);
bool validate_guest_execute_access(const GuestImageMap& map, std::uint64_t guest_address,
                                   std::size_t byte_count, std::string& error);
bool read_guest_memory(const GuestImageMap& map, std::uint64_t guest_address,
                       std::span<std::byte> destination, std::string& error);
bool write_guest_memory(GuestImageMap& map, std::uint64_t guest_address,
                        std::span<const std::byte> source, std::string& error);

struct RelocationApplicationSummary {
    std::uint64_t relative_applied{};
    std::uint64_t imported_unresolved{};
    std::uint64_t imported_applied{};
    std::uint64_t relative_load_bias{};
    std::uint64_t tls_module_id{};
    std::uint64_t tls_module_relocations_applied{};
};

struct GuestStartupCall {
    std::uint64_t guest_address{};
    std::string source;
};

struct GuestStartupPlan {
    std::vector<GuestStartupCall> calls;
};

bool apply_relative_relocations(GuestImageMap& map,
                                const Ps4DynamicLinkInfo& link_info,
                                std::uint64_t load_bias,
                                std::uint64_t tls_module_id,
                                RelocationApplicationSummary& summary,
                                std::string& error);
bool apply_import_relocations(GuestImageMap& map,
                              const Ps4DynamicLinkInfo& link_info,
                              const std::vector<std::optional<std::uint64_t>>& symbol_addresses,
                              RelocationApplicationSummary& summary,
                              std::string& error);
bool build_guest_startup_plan(const GuestImageMap& map,
                              const Ps4DynamicLinkInfo& link_info,
                              GuestStartupPlan& plan,
                              std::string& error);
void print_summary(const RelocationApplicationSummary& summary, std::ostream& output);

} // namespace nba16
