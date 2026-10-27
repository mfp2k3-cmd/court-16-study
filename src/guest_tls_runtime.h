#pragma once

#include "import_resolver.h"
#include "ps4_module_loader.h"

#include <cstdint>
#include <map>
#include <shared_mutex>
#include <string>
#include <vector>

namespace nba16 {

struct GuestTlsIndex {
    std::uint64_t module_id{};
    std::uint64_t offset{};
};

// Dynamic ELF TLS for guest threads. It never changes the Windows thread pointer.
class GuestTlsRuntime {
public:
    GuestTlsRuntime();
    GuestTlsRuntime(const GuestTlsRuntime&) = delete;
    GuestTlsRuntime& operator=(const GuestTlsRuntime&) = delete;
    ~GuestTlsRuntime();

    bool initialize(const std::vector<GuestTlsImage>& images, std::string& error);
    // May be registered before initialize(); guest code must not run until both finish.
    bool register_import(ImportResolver& resolver, std::string& error);
    [[nodiscard]] void* get_address(std::uint64_t module_id, std::uint64_t offset) noexcept;

private:
    struct ModuleTemplate {
        std::uint64_t alignment{1};
        std::uint64_t memory_size{};
        std::vector<std::uint8_t> initial_bytes;
    };

    static GuestTlsRuntime* active_runtime() noexcept;
    static void* NBA16_GUEST_SYSV_ABI tls_get_addr(const GuestTlsIndex* index) noexcept;

    const std::uint64_t runtime_id_;
    mutable std::shared_mutex lock_;
    std::map<std::uint64_t, ModuleTemplate> modules_;
    bool initialized_{};
};

} // namespace nba16
