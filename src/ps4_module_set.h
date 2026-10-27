#pragma once

#include "import_resolver.h"
#include "ps4_module_loader.h"

#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <string_view>
#include <string>
#include <vector>

namespace nba16 {

struct Ps4ModuleSetSummary {
    std::size_t modules_loaded{};
    std::size_t modules_missing{};
    std::size_t modules_skipped{};
    std::size_t modules_relocated{};
    std::size_t sysctl_stubs_redirected{};
    std::size_t sysctlbyname_stubs_redirected{};
    std::size_t virtual_query_stubs_redirected{};
    std::size_t unresolved_symbols{};
    std::vector<std::string> skipped_module_names;
};

// Owns the transitive PRX dependency set and its mapped memories. It prepares
// modules and applies relocations, but deliberately does not call guest startup.
class Ps4ModuleSet {
public:
    Ps4ModuleSet() = default;
    Ps4ModuleSet(const Ps4ModuleSet&) = delete;
    Ps4ModuleSet& operator=(const Ps4ModuleSet&) = delete;
    Ps4ModuleSet(Ps4ModuleSet&&) noexcept = default;
    Ps4ModuleSet& operator=(Ps4ModuleSet&&) noexcept = default;

    bool load_dependencies(const std::vector<std::string>& roots,
                           const std::vector<std::filesystem::path>& module_directories,
                           ImportResolver& resolver,
                           Ps4ModuleSetSummary& summary,
                           std::string& error,
                           const std::vector<std::string>& skip_missing_modules = {},
                           const std::vector<std::string>& hle_modules = {});
    bool relocate_all(ImportResolver& resolver,
                      Ps4ModuleSetSummary& summary,
                      std::string& error);

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] std::vector<std::string> loaded_module_names() const;
    [[nodiscard]] std::optional<std::filesystem::path> loaded_module_path(
        std::string_view module_name) const;
    [[nodiscard]] const Ps4LoadedModule* find(std::string_view module_name) const;
    [[nodiscard]] std::vector<GuestTlsImage> tls_images() const;
    bool register_memory(GuestMemoryAccess& address_space, std::string& error) const;

private:
    struct Entry {
        std::string module_name;
        std::filesystem::path path;
        std::unique_ptr<Ps4LoadedModule> module;
    };

    bool load_one(const std::string& module_name,
                  const std::map<std::string, std::filesystem::path>& files,
                  const std::set<std::string>& skip_missing_modules,
                  const std::set<std::string>& hle_modules,
                  ImportResolver& resolver,
                  Ps4ModuleSetSummary& summary,
                  std::string& error);

    std::vector<Entry> modules_;
    std::map<std::string, std::size_t> module_indices_;
    // ID 1 belongs to the main executable, matching the guest loader's module list.
    std::uint64_t next_tls_module_id_{1};
    bool relocated_{};
};

} // namespace nba16
