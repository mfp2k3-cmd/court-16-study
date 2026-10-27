#pragma once

#include "aio_runtime.h"
#include "guest_image_memory.h"
#include "ps4_module_set.h"
#include "vfs.h"

#include <filesystem>
#include <string>

namespace nba16 {

// Owns the per-game services whose state must remain stable while guest code
// and its worker threads are running.
class GuestProcessContext {
public:
    GuestProcessContext() = default;
    GuestProcessContext(const GuestProcessContext&) = delete;
    GuestProcessContext& operator=(const GuestProcessContext&) = delete;

    bool initialize(const std::filesystem::path& game_root,
                    const std::filesystem::path& user_root,
                    const std::filesystem::path& save_root,
                    const GuestImageMap& executable_map,
                    const GuestImageMemory& executable_memory,
                    const Ps4ModuleSet& modules,
                    std::string& error);

    [[nodiscard]] VirtualFileSystem& vfs() noexcept;
    [[nodiscard]] VfsDescriptorTable& descriptors() noexcept;
    [[nodiscard]] GuestMemoryAccess& memory() noexcept;
    [[nodiscard]] GuestAioRuntime& aio() noexcept;
    [[nodiscard]] bool is_initialized() const noexcept;

private:
    VirtualFileSystem vfs_;
    VfsDescriptorTable descriptors_;
    GuestMemoryAccess memory_;
    GuestAioRuntime aio_;
    bool initialization_attempted_{};
    bool initialized_{};
};

[[nodiscard]] GuestProcessContext* current_guest_process_context() noexcept;

class ScopedGuestProcessContext {
public:
    explicit ScopedGuestProcessContext(GuestProcessContext* context) noexcept;
    ~ScopedGuestProcessContext();
    ScopedGuestProcessContext(const ScopedGuestProcessContext&) = delete;
    ScopedGuestProcessContext& operator=(const ScopedGuestProcessContext&) = delete;

private:
    GuestProcessContext* previous_{};
};

} // namespace nba16
