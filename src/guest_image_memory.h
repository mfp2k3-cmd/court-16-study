#pragma once

#include "guest_image_map.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace nba16 {

// Owns a reserved host address range containing a guest image. It starts RW/NX;
// executable/read-only page permissions are applied only after relocations finish.
class GuestImageMemory {
public:
    GuestImageMemory() = default;
    ~GuestImageMemory();
    GuestImageMemory(const GuestImageMemory&) = delete;
    GuestImageMemory& operator=(const GuestImageMemory&) = delete;
    GuestImageMemory(GuestImageMemory&& other) noexcept;
    GuestImageMemory& operator=(GuestImageMemory&& other) noexcept;

    bool reserve_and_copy(const GuestImageMap& map, std::string& error);
    bool protect_after_relocations(const GuestImageMap& map, std::string& error);
    bool write_loader_patch(GuestImageMap& map,
                            std::uint64_t guest_address,
                            std::span<const std::byte> patch,
                            std::string& error);

    [[nodiscard]] bool is_reserved() const noexcept;
    [[nodiscard]] bool is_finalized() const noexcept;
    [[nodiscard]] std::uint64_t load_bias() const noexcept;
    [[nodiscard]] void* translate(const GuestImageMap& map, std::uint64_t guest_address,
                                  std::size_t byte_count, bool write_access,
                                  std::string& error) const;
    [[nodiscard]] void* translate_executable(const GuestImageMap& map,
                                             std::uint64_t guest_address,
                                             std::size_t byte_count,
                                             std::string& error) const;

private:
    void release() noexcept;

    void* allocation_{};
    std::size_t allocation_size_{};
    std::uint64_t guest_base_{};
    std::uint64_t map_minimum_{};
    std::uint64_t map_maximum_{};
    std::uint64_t load_bias_{};
    bool finalized_{};
};

enum class GuestMemoryRegionOrigin : std::uint8_t {
    image,
    host_mapping,
};

struct GuestMemoryRegionView {
    std::uint64_t guest_address{};
    std::uint64_t host_address{};
    std::size_t size{};
    bool readable{};
    bool writable{};
    bool executable{};
    GuestMemoryRegionOrigin origin{};
};

// Non-owning process view over the live host allocations for the executable
// and loaded PRXs. Guest pointers contain each image's runtime address; this
// view resolves them back to the matching image and never touches the parser's
// byte-vector snapshot. Register all images before starting guest threads.
class GuestMemoryAccess {
public:
    bool add_image(const GuestImageMap& map, const GuestImageMemory& memory,
                   std::string& error);
    bool add_host_region(std::uint64_t begin, std::size_t size, std::string& error,
                        bool readable = true, bool writable = true);
    void remove_host_region(std::uint64_t begin, std::size_t size) noexcept;
    bool read(std::uint64_t guest_address, std::span<std::byte> destination,
              std::string& error) const;
    bool write(std::uint64_t guest_address, std::span<const std::byte> source,
               std::string& error) const;
    // Returns a direct host view only after validating that the entire guest
    // range belongs to a live readable/writable mapping. GPU HLE can use this
    // to pass command-buffer spans without copying them.
    [[nodiscard]] void* native_pointer(std::uint64_t guest_address,
                                       std::size_t byte_count, bool write_access,
                                       std::string& error) const;
    bool validate(std::uint64_t guest_address, std::size_t byte_count,
                  bool write_access, std::string& error) const;
    // Snapshot of currently registered live mappings. Addresses are the values
    // guest code passes at runtime; host_address is the backing pointer exposed
    // to an in-process graphics backend. Call before starting guest threads or
    // refresh after mapping changes; this is not a synchronization mechanism.
    [[nodiscard]] std::vector<GuestMemoryRegionView> snapshot_regions() const;

private:
    struct Image {
        const GuestImageMap* map{};
        const GuestImageMemory* memory{};
    };
    struct HostRegion {
        std::uint64_t begin{};
        std::size_t size{};
        bool readable{true};
        bool writable{true};
    };
    bool translate(std::uint64_t guest_address, std::size_t byte_count,
                   bool write_access, void*& result, std::string& error) const;
    std::vector<Image> images_;
    std::vector<HostRegion> host_regions_;
};

} // namespace nba16
