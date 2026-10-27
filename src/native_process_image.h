#pragma once

#include "guest_image_map.h"
#include "guest_image_memory.h"
#include "ps4_module_set.h"
#include "ps4_dynamic_link.h"
#include "self_program_image.h"

#include <filesystem>
#include <string>

namespace nba16 {

// Holds the main guest image through parsing, mapping and relocations.
// Guest code remains unexecuted; final page protection is a separate phase.
struct NativeExecutableImage {
    SelfProgramImage image;
    Ps4DynamicLinkInfo dynamic;
    GuestImageMap map;
    GuestImageMemory memory;
    RelocationApplicationSummary relative_relocations;
    bool imported_relocations_applied{};
    bool syscall_stubs_patched{};
    bool memory_finalized{};

    NativeExecutableImage() = default;
    NativeExecutableImage(const NativeExecutableImage&) = delete;
    NativeExecutableImage& operator=(const NativeExecutableImage&) = delete;
    NativeExecutableImage(NativeExecutableImage&&) noexcept = default;
    NativeExecutableImage& operator=(NativeExecutableImage&&) noexcept = default;

    bool resolve_imports(const ImportResolver& resolver,
                         ImportResolution& resolution,
                         std::string& error) const;
    bool apply_imports(const ImportResolution& resolution,
                       RelocationApplicationSummary& summary,
                       std::string& error);
    bool patch_syscall_stubs(const ImportResolver& resolver,
                             Ps4ModuleSetSummary& summary,
                             std::string& error);
    bool finalize_memory(std::uint64_t& patched_tcb_loads,
                         std::string& error);
};

bool prepare_native_executable_image(const std::filesystem::path& executable_path,
                                     NativeExecutableImage& prepared,
                                     std::string& error);

class NativeProcessModules {
public:
    NativeProcessModules() = default;
    NativeProcessModules(const NativeProcessModules&) = delete;
    NativeProcessModules& operator=(const NativeProcessModules&) = delete;

    bool load_dependencies(const NativeExecutableImage& executable,
                           const std::vector<std::filesystem::path>& module_directories,
                           ImportResolver& resolver,
                           const std::vector<std::string>& skip_missing_modules,
                           const std::vector<std::string>& hle_modules,
                           std::string& error);
    bool relocate(ImportResolver& resolver, std::string& error);

    [[nodiscard]] Ps4ModuleSet& modules() noexcept;
    [[nodiscard]] const Ps4ModuleSet& modules() const noexcept;
    [[nodiscard]] Ps4ModuleSetSummary& summary() noexcept;
    [[nodiscard]] const Ps4ModuleSetSummary& summary() const noexcept;

private:
    Ps4ModuleSet modules_;
    Ps4ModuleSetSummary summary_;
    bool dependencies_loaded_{};
    bool relocated_{};
};

} // namespace nba16
