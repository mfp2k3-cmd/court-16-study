#pragma once

#include "guest_image_map.h"
#include "guest_image_memory.h"
#include "import_resolver.h"
#include "module_exports.h"
#include "ps4_dynamic_link.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace nba16 {

struct LoadedPs4Export {
    std::string module_name;
    std::string library_name;
    std::string nid;
    std::uint16_t module_version{};
    std::uint16_t library_version{};
    std::uint64_t host_address{};
    std::uint64_t module_relative_value{};
    std::uint64_t size{};
    std::uint8_t elf_symbol_kind{};
};

struct GuestTlsImage {
    std::uint64_t module_id{};
    std::uint64_t alignment{1};
    std::uint64_t memory_size{};
    std::vector<std::uint8_t> initial_bytes;
};

// Owns one PRX/SELF image through the RW/NX, relocation, and final-protection phases.
// It never invokes module initializers or guest entry points.
class Ps4LoadedModule {
public:
    Ps4LoadedModule() = default;
    Ps4LoadedModule(const Ps4LoadedModule&) = delete;
    Ps4LoadedModule& operator=(const Ps4LoadedModule&) = delete;
    Ps4LoadedModule(Ps4LoadedModule&&) noexcept = default;
    Ps4LoadedModule& operator=(Ps4LoadedModule&&) noexcept = default;

    bool prepare(const std::filesystem::path& path, std::string& error,
                 std::uint64_t tls_module_id = 0);
    bool collect_exports(std::string_view module_name,
                         std::vector<LoadedPs4Export>& exports,
                         std::string& error) const;
    bool resolve_imports(const ImportResolver& resolver,
                         ImportResolution& resolution,
                         std::string& error) const;
    bool apply_imports(const std::vector<std::optional<std::uint64_t>>& symbol_addresses,
                       RelocationApplicationSummary& summary,
                       std::string& error);
    bool redirect_function_export(std::string_view library_name,
                                  std::string_view module_name,
                                  std::string_view nid,
                                  std::uint64_t host_address,
                                  std::string& error);
    bool redirect_function_offset(std::uint64_t code_offset,
                                  std::uint64_t host_address,
                                  std::string& error);
    bool redirect_sysctl_syscall_stubs(std::uint64_t sysctl_address,
                                       std::uint64_t sysctlbyname_address,
                                       std::uint64_t virtual_query_address,
                                       std::size_t& sysctl_count,
                                       std::size_t& sysctlbyname_count,
                                       std::size_t& virtual_query_count,
                                       std::string& error);
    bool finalize(std::string& error);

    [[nodiscard]] bool is_prepared() const noexcept;
    [[nodiscard]] bool is_finalized() const noexcept;
    [[nodiscard]] const Ps4DynamicLinkInfo& dynamic_info() const noexcept;
    [[nodiscard]] const GuestImageMap& image_map() const noexcept;
    [[nodiscard]] const GuestImageMemory& image_memory() const noexcept;
    [[nodiscard]] const GuestStartupPlan& startup_plan() const noexcept;
    [[nodiscard]] const GuestTlsImage& tls_image() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> process_parameter_address() const noexcept;

private:
    SelfProgramImage image_;
    Ps4DynamicLinkInfo dynamic_;
    GuestImageMap map_;
    GuestImageMemory memory_;
    GuestStartupPlan startup_plan_;
    GuestTlsImage tls_image_;
    std::optional<std::uint64_t> process_parameter_address_;
    std::uint64_t tls_virtual_address_{};
    std::size_t tls_file_size_{};
    bool prepared_{};
    bool finalized_{};
};

} // namespace nba16
