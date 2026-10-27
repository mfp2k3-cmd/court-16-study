#include "guest_image_memory.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace nba16 {
namespace {

constexpr std::uint32_t read_flag = 0x4U;
constexpr std::uint32_t write_flag = 0x2U;
constexpr std::uint32_t execute_flag = 0x1U;

std::size_t host_page_size() {
#ifdef _WIN32
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    return info.dwPageSize;
#else
    const auto value = sysconf(_SC_PAGESIZE);
    return value > 0 ? static_cast<std::size_t>(value) : 0;
#endif
}

bool align_size(std::size_t value, std::size_t alignment, std::size_t& result) {
    if (alignment == 0 || value > std::numeric_limits<std::size_t>::max() - (alignment - 1U)) {
        return false;
    }
    result = ((value + alignment - 1U) / alignment) * alignment;
    return true;
}

bool page_permissions(const GuestImageMap& map, std::uint64_t guest_base,
                      std::size_t page_size, std::vector<std::uint8_t>& permissions,
                      std::vector<bool>& occupied, std::string& error) {
    for (const auto& region : map.regions) {
        auto flags = region.flags & (read_flag | write_flag | execute_flag);
        if (region.read_only_after_relocations) flags &= ~write_flag;
        if ((flags & (write_flag | execute_flag)) == (write_flag | execute_flag)) {
            error = "segmento convidado solicita página gravável e executável simultaneamente";
            return false;
        }
        if (region.virtual_address < guest_base) {
            error = "região convidada começa antes do endereço reservado";
            return false;
        }
        const auto first_page = static_cast<std::size_t>(
            (region.virtual_address - guest_base) / page_size);
        const auto region_end = region.virtual_address + region.memory_size;
        const auto end_offset = region_end - guest_base;
        const auto last_page = static_cast<std::size_t>(end_offset / page_size +
            (end_offset % page_size == 0 ? 0U : 1U));
        if (last_page > permissions.size()) {
            error = "região convidada ultrapassa o intervalo de reserva";
            return false;
        }
        for (auto page = first_page; page < last_page; ++page) {
            if (occupied[page] && permissions[page] != flags) {
                error = "segmentos com permissões diferentes compartilham uma página do host";
                return false;
            }
            occupied[page] = true;
            permissions[page] = static_cast<std::uint8_t>(flags);
        }
    }
    return true;
}

} // namespace

GuestImageMemory::~GuestImageMemory() {
    release();
}

GuestImageMemory::GuestImageMemory(GuestImageMemory&& other) noexcept
    : allocation_(std::exchange(other.allocation_, nullptr)),
      allocation_size_(std::exchange(other.allocation_size_, 0)),
      guest_base_(std::exchange(other.guest_base_, 0)),
      map_minimum_(std::exchange(other.map_minimum_, 0)),
      map_maximum_(std::exchange(other.map_maximum_, 0)),
      load_bias_(std::exchange(other.load_bias_, 0)),
      finalized_(std::exchange(other.finalized_, false)) {}

GuestImageMemory& GuestImageMemory::operator=(GuestImageMemory&& other) noexcept {
    if (this != &other) {
        release();
        allocation_ = std::exchange(other.allocation_, nullptr);
        allocation_size_ = std::exchange(other.allocation_size_, 0);
        guest_base_ = std::exchange(other.guest_base_, 0);
        map_minimum_ = std::exchange(other.map_minimum_, 0);
        map_maximum_ = std::exchange(other.map_maximum_, 0);
        load_bias_ = std::exchange(other.load_bias_, 0);
        finalized_ = std::exchange(other.finalized_, false);
    }
    return *this;
}

void GuestImageMemory::release() noexcept {
    if (allocation_ == nullptr) return;
#ifdef _WIN32
    VirtualFree(allocation_, 0, MEM_RELEASE);
#else
    munmap(allocation_, allocation_size_);
#endif
    allocation_ = nullptr;
    allocation_size_ = 0;
    guest_base_ = 0;
    map_minimum_ = 0;
    map_maximum_ = 0;
    load_bias_ = 0;
    finalized_ = false;
}

bool GuestImageMemory::reserve_and_copy(const GuestImageMap& map, std::string& error) {
    release();
    const auto page_size = host_page_size();
    if (page_size == 0 || map.regions.empty() ||
        map.maximum_virtual_address <= map.minimum_virtual_address) {
        error = "mapa convidado vazio ou tamanho de página do host inválido";
        return false;
    }
    const auto page_mask = static_cast<std::uint64_t>(page_size - 1U);
    if ((page_size & (page_size - 1U)) != 0) {
        error = "alinhamento de página ou endereço mínimo convidado inválido";
        return false;
    }
    const auto aligned_guest_base = map.minimum_virtual_address & ~page_mask;
    const auto span = map.maximum_virtual_address - aligned_guest_base;
    if (span > std::numeric_limits<std::size_t>::max()) {
        error = "intervalo do mapa convidado excede o espaço endereçável do host";
        return false;
    }
    std::size_t aligned_span{};
    if (!align_size(static_cast<std::size_t>(span), page_size, aligned_span) || aligned_span == 0) {
        error = "falha alinhando o tamanho da reserva do mapa convidado";
        return false;
    }

    const auto page_count = aligned_span / page_size;
    std::vector<std::uint8_t> permissions(page_count, 0);
    std::vector<bool> occupied(page_count, false);
    if (!page_permissions(map, aligned_guest_base, page_size, permissions, occupied, error)) {
        return false;
    }

#ifdef _WIN32
    allocation_ = VirtualAlloc(nullptr, aligned_span, MEM_RESERVE, PAGE_NOACCESS);
#else
    allocation_ = mmap(nullptr, aligned_span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (allocation_ == MAP_FAILED) allocation_ = nullptr;
#endif
    if (allocation_ == nullptr) {
        error = "o host não conseguiu reservar o intervalo virtual convidado";
        return false;
    }
    allocation_size_ = aligned_span;
    guest_base_ = aligned_guest_base;
    map_minimum_ = map.minimum_virtual_address;
    map_maximum_ = map.maximum_virtual_address;
    const auto host_base = reinterpret_cast<std::uintptr_t>(allocation_);
    if (host_base < guest_base_) {
        error = "a reserva do host não permite representar o load bias convidado";
        release();
        return false;
    }
    load_bias_ = static_cast<std::uint64_t>(host_base) - guest_base_;

    for (std::size_t first = 0; first < page_count;) {
        if (!occupied[first]) {
            ++first;
            continue;
        }
        auto end = first + 1U;
        while (end < page_count && occupied[end]) ++end;
        auto* address = static_cast<std::byte*>(allocation_) + first * page_size;
        const auto length = (end - first) * page_size;
#ifdef _WIN32
        void* committed = VirtualAlloc(address, length, MEM_COMMIT, PAGE_READWRITE);
        if (committed != address) {
            error = "falha comprometendo páginas do mapa convidado no host";
            release();
            return false;
        }
#else
        if (mprotect(address, length, PROT_READ | PROT_WRITE) != 0) {
            error = "falha comprometendo páginas do mapa convidado no host";
            release();
            return false;
        }
#endif
        first = end;
    }

    for (const auto& region : map.regions) {
        if (region.bytes.size() != region.memory_size) {
            error = "buffer da região convidada não corresponde ao tamanho virtual";
            release();
            return false;
        }
        if (region.virtual_address < guest_base_ ||
            region.virtual_address - guest_base_ > allocation_size_ ||
            region.bytes.size() > allocation_size_ -
                static_cast<std::size_t>(region.virtual_address - guest_base_)) {
            error = "região convidada está fora da reserva antes da cópia";
            release();
            return false;
        }
        const auto offset = static_cast<std::size_t>(region.virtual_address - guest_base_);
        std::memcpy(static_cast<std::byte*>(allocation_) + offset,
                    region.bytes.data(), region.bytes.size());
    }
    return true;
}

bool GuestImageMemory::protect_after_relocations(const GuestImageMap& map, std::string& error) {
    if (finalized_ || allocation_ == nullptr || map.minimum_virtual_address != map_minimum_ ||
        map.maximum_virtual_address != map_maximum_ || !map.relative_relocations_applied ||
        !map.imported_relocations_applied) {
        error = finalized_
            ? "as permissões finais da imagem já foram aplicadas"
            : "proteção final exige uma imagem reservada e todas as relocações aplicadas";
        return false;
    }
    const auto page_size = host_page_size();
    const auto page_count = allocation_size_ / page_size;
    std::vector<std::uint8_t> permissions(page_count, 0);
    std::vector<bool> occupied(page_count, false);
    if (!page_permissions(map, guest_base_, page_size, permissions, occupied, error)) return false;

    for (const auto& region : map.regions) {
        if (region.bytes.size() != region.memory_size || region.virtual_address < guest_base_ ||
            region.virtual_address - guest_base_ > allocation_size_ ||
            region.bytes.size() > allocation_size_ -
                static_cast<std::size_t>(region.virtual_address - guest_base_)) {
            error = "região alterada não cabe na reserva durante a finalização";
            return false;
        }
        const auto offset = static_cast<std::size_t>(region.virtual_address - guest_base_);
        std::memcpy(static_cast<std::byte*>(allocation_) + offset,
                    region.bytes.data(), region.bytes.size());
    }

    for (std::size_t first = 0; first < page_count;) {
        if (!occupied[first]) {
            ++first;
            continue;
        }
        auto end = first + 1U;
        while (end < page_count && occupied[end] && permissions[end] == permissions[first]) ++end;
        const auto flags = permissions[first];
        const auto length = (end - first) * page_size;
        auto* address = static_cast<std::byte*>(allocation_) + first * page_size;
#ifdef _WIN32
        DWORD protection = PAGE_NOACCESS;
        if ((flags & execute_flag) != 0) {
            protection = (flags & read_flag) != 0 ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        } else if ((flags & write_flag) != 0) {
            protection = PAGE_READWRITE;
        } else if ((flags & read_flag) != 0) {
            protection = PAGE_READONLY;
        }
        DWORD old_protection{};
        if (!VirtualProtect(address, length, protection, &old_protection)) {
            error = "falha aplicando permissões finais ao mapa convidado";
            release();
            return false;
        }
#else
        int protection = PROT_NONE;
        if ((flags & read_flag) != 0) protection |= PROT_READ;
        if ((flags & write_flag) != 0) protection |= PROT_WRITE;
        if ((flags & execute_flag) != 0) protection |= PROT_EXEC;
        if (mprotect(address, length, protection) != 0) {
            error = "falha aplicando permissões finais ao mapa convidado";
            release();
            return false;
        }
#endif
        first = end;
    }
#ifdef _WIN32
    FlushInstructionCache(GetCurrentProcess(), allocation_, allocation_size_);
#else
    __builtin___clear_cache(static_cast<char*>(allocation_),
                            static_cast<char*>(allocation_) + allocation_size_);
#endif
    finalized_ = true;
    return true;
}

bool GuestImageMemory::write_loader_patch(GuestImageMap& map,
                                         std::uint64_t guest_address,
                                         std::span<const std::byte> patch,
                                         std::string& error) {
    if (allocation_ == nullptr || finalized_ || patch.empty()) {
        error = "patch do loader exige imagem reservada, ainda RW/NX e dados não vazios";
        return false;
    }
    if (map.minimum_virtual_address != map_minimum_ ||
        map.maximum_virtual_address != map_maximum_ || map.load_bias != load_bias_ ||
        guest_address < load_bias_) {
        error = "mapa ou endereço não corresponde à imagem ativa do patch";
        return false;
    }
    if (!validate_guest_execute_access(map, guest_address, patch.size(), error)) return false;
    const auto image_address = guest_address - load_bias_;
    if (image_address < guest_base_ || image_address - guest_base_ > allocation_size_ ||
        patch.size() > allocation_size_ - static_cast<std::size_t>(image_address - guest_base_)) {
        error = "patch ultrapassa a reserva da imagem do host";
        return false;
    }
    auto* destination = static_cast<std::byte*>(allocation_) +
        static_cast<std::size_t>(image_address - guest_base_);
    const auto region = std::find_if(map.regions.begin(), map.regions.end(),
        [&](const GuestMemoryRegion& candidate) {
            return image_address >= candidate.virtual_address &&
                   image_address - candidate.virtual_address <= candidate.memory_size &&
                   patch.size() <= candidate.memory_size -
                       static_cast<std::size_t>(image_address - candidate.virtual_address);
        });
    if (region == map.regions.end() || region->bytes.size() != region->memory_size) {
        error = "patch do loader não cabe numa região ELF contígua";
        return false;
    }
    const auto region_offset = static_cast<std::size_t>(image_address - region->virtual_address);
    std::memcpy(region->bytes.data() + region_offset, patch.data(), patch.size());
    std::memcpy(destination, patch.data(), patch.size());
    error.clear();
    return true;
}

bool GuestImageMemory::is_reserved() const noexcept {
    return allocation_ != nullptr;
}

bool GuestImageMemory::is_finalized() const noexcept {
    return finalized_;
}

std::uint64_t GuestImageMemory::load_bias() const noexcept {
    return load_bias_;
}

void* GuestImageMemory::translate(const GuestImageMap& map, std::uint64_t guest_address,
                                 std::size_t byte_count, bool write_access,
                                 std::string& error) const {
    if (allocation_ == nullptr) {
        error = "memória convidada ainda não foi reservada";
        return nullptr;
    }
    if (map.minimum_virtual_address != map_minimum_ || map.maximum_virtual_address != map_maximum_) {
        error = "o mapa convidado não corresponde à reserva ativa";
        return nullptr;
    }
    if (map.load_bias != load_bias_ || guest_address < load_bias_) {
        error = "endereço ou load bias não corresponde à imagem convidada ativa";
        return nullptr;
    }
    if (!validate_guest_memory_access(map, guest_address, byte_count, write_access, error)) {
        return nullptr;
    }
    const auto image_address = guest_address - load_bias_;
    if (image_address < guest_base_ || image_address - guest_base_ > allocation_size_ ||
        byte_count > allocation_size_ - static_cast<std::size_t>(image_address - guest_base_)) {
        error = "endereço convidado traduzido fora da reserva do host";
        return nullptr;
    }
    return static_cast<std::byte*>(allocation_) +
        static_cast<std::size_t>(image_address - guest_base_);
}

void* GuestImageMemory::translate_executable(const GuestImageMap& map,
                                             std::uint64_t guest_address,
                                             std::size_t byte_count,
                                             std::string& error) const {
    if (allocation_ == nullptr) {
        error = "memória convidada ainda não foi reservada";
        return nullptr;
    }
    if (!finalized_) {
        error = "permissões finais da imagem convidada ainda não foram aplicadas";
        return nullptr;
    }
    if (map.minimum_virtual_address != map_minimum_ || map.maximum_virtual_address != map_maximum_) {
        error = "o mapa convidado não corresponde à reserva ativa";
        return nullptr;
    }
    if (map.load_bias != load_bias_ || guest_address < load_bias_) {
        error = "endereço ou load bias não corresponde à imagem convidada ativa";
        return nullptr;
    }
    if (!validate_guest_execute_access(map, guest_address, byte_count, error)) return nullptr;
    const auto image_address = guest_address - load_bias_;
    if (image_address < guest_base_ || image_address - guest_base_ > allocation_size_ ||
        byte_count > allocation_size_ - static_cast<std::size_t>(image_address - guest_base_)) {
        error = "endereço executável traduzido fora da reserva do host";
        return nullptr;
    }
    return static_cast<std::byte*>(allocation_) +
        static_cast<std::size_t>(image_address - guest_base_);
}

bool GuestMemoryAccess::add_image(const GuestImageMap& map, const GuestImageMemory& memory,
                                  std::string& error) {
    if (!memory.is_reserved() || map.load_bias != memory.load_bias() ||
        map.minimum_virtual_address == map.maximum_virtual_address) {
        error = "imagem convidada sem reserva válida ou com load bias divergente";
        return false;
    }
    for (const auto& image : images_) {
        if (image.map == &map || image.memory == &memory) {
            error = "imagem convidada já registrada no espaço de endereços";
            return false;
        }
    }
    images_.push_back({&map, &memory});
    error.clear();
    return true;
}

bool GuestMemoryAccess::add_host_region(std::uint64_t begin, std::size_t size,
                                        std::string& error, bool readable,
                                        bool writable) {
    if (begin == 0 || size == 0 ||
        size > std::numeric_limits<std::uint64_t>::max() - begin) {
        error = "região host convidada tem endereço ou tamanho inválido";
        return false;
    }
    auto end = begin + size;
    for (std::size_t index = 0; index < host_regions_.size();) {
        const auto& region = host_regions_[index];
        const auto existing_end = region.begin + region.size;
        if (begin <= existing_end && region.begin <= end &&
            region.readable == readable && region.writable == writable) {
            begin = std::min(begin, region.begin);
            end = std::max(end, existing_end);
            host_regions_.erase(host_regions_.begin() +
                static_cast<std::ptrdiff_t>(index));
            index = 0;
            continue;
        }
        ++index;
    }
    host_regions_.push_back({begin, static_cast<std::size_t>(end - begin),
                              readable, writable});
    error.clear();
    return true;
}

void GuestMemoryAccess::remove_host_region(std::uint64_t begin,
                                           std::size_t size) noexcept {
    if (size == 0 || size > std::numeric_limits<std::uint64_t>::max() - begin) return;
    const auto end = begin + size;
    for (std::size_t index = 0; index < host_regions_.size();) {
        const auto region = host_regions_[index];
        const auto region_end = region.begin + region.size;
        if (begin >= region_end || region.begin >= end) {
            ++index;
            continue;
        }
        host_regions_.erase(host_regions_.begin() + static_cast<std::ptrdiff_t>(index));
        if (region.begin < begin)
            host_regions_.push_back({region.begin, static_cast<std::size_t>(begin - region.begin),
                                     region.readable, region.writable});
        if (end < region_end)
            host_regions_.push_back({end, static_cast<std::size_t>(region_end - end),
                                     region.readable, region.writable});
        index = 0;
    }
}

bool GuestMemoryAccess::translate(std::uint64_t guest_address, std::size_t byte_count,
                                  bool write_access, void*& result,
                                  std::string& error) const {
    result = nullptr;
    for (const auto& region : host_regions_) {
        if (guest_address < region.begin) continue;
        const auto offset = guest_address - region.begin;
        if (offset <= region.size && byte_count <= region.size - offset) {
            if ((write_access && !region.writable) || (!write_access && !region.readable)) {
                error = write_access
                    ? "região convidada não permite escrita"
                    : "região convidada não permite leitura";
                return false;
            }
            result = reinterpret_cast<void*>(static_cast<std::uintptr_t>(guest_address));
            error.clear();
            return true;
        }
    }
    std::string last_error = "endereço não pertence a nenhuma imagem convidada registrada";
    for (const auto& image : images_) {
        if (image.map == nullptr || image.memory == nullptr ||
            guest_address < image.memory->load_bias()) continue;
        std::string validation_error;
        if (!validate_guest_memory_access(*image.map, guest_address, byte_count,
                                          write_access, validation_error)) {
            last_error = std::move(validation_error);
            continue;
        }
        std::string image_error;
        auto* translated = image.memory->translate(*image.map, guest_address, byte_count,
                                                  write_access, image_error);
        if (translated != nullptr) {
            result = translated;
            error.clear();
            return true;
        }
        error = std::move(image_error);
        return false;
    }
    error = std::move(last_error);
    return false;
}

bool GuestMemoryAccess::read(std::uint64_t guest_address,
                             std::span<std::byte> destination,
                             std::string& error) const {
    void* source{};
    if (!translate(guest_address, destination.size(), false, source, error)) return false;
    if (!destination.empty()) std::memcpy(destination.data(), source, destination.size());
    return true;
}

bool GuestMemoryAccess::write(std::uint64_t guest_address,
                              std::span<const std::byte> source,
                              std::string& error) const {
    void* destination{};
    if (!translate(guest_address, source.size(), true, destination, error)) return false;
    if (!source.empty()) std::memcpy(destination, source.data(), source.size());
    return true;
}

void* GuestMemoryAccess::native_pointer(std::uint64_t guest_address,
                                        std::size_t byte_count, bool write_access,
                                        std::string& error) const {
    void* pointer{};
    if (!translate(guest_address, byte_count, write_access, pointer, error)) return nullptr;
    return pointer;
}

bool GuestMemoryAccess::validate(std::uint64_t guest_address, std::size_t byte_count,
                                 bool write_access, std::string& error) const {
    void* ignored{};
    return translate(guest_address, byte_count, write_access, ignored, error);
}

std::vector<GuestMemoryRegionView> GuestMemoryAccess::snapshot_regions() const {
    constexpr std::uint32_t read_flag = 0x4U;
    constexpr std::uint32_t write_flag = 0x2U;
    constexpr std::uint32_t execute_flag = 0x1U;
    std::vector<GuestMemoryRegionView> result;
    for (const auto& image : images_) {
        if (image.map == nullptr || image.memory == nullptr) continue;
        for (const auto& region : image.map->regions) {
            if (region.memory_size == 0 ||
                region.virtual_address > UINT64_MAX - image.memory->load_bias() ||
                region.memory_size > std::numeric_limits<std::size_t>::max()) continue;
            auto flags = region.flags & (read_flag | write_flag | execute_flag);
            if (region.read_only_after_relocations) flags &= ~write_flag;
            const auto address = image.memory->load_bias() + region.virtual_address;
            result.push_back({address, address,
                static_cast<std::size_t>(region.memory_size),
                (flags & read_flag) != 0, (flags & write_flag) != 0,
                (flags & execute_flag) != 0, GuestMemoryRegionOrigin::image});
        }
    }
    for (const auto& region : host_regions_) {
        result.push_back({region.begin, region.begin, region.size,
            region.readable, region.writable, false,
            GuestMemoryRegionOrigin::host_mapping});
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        if (left.guest_address != right.guest_address)
            return left.guest_address < right.guest_address;
        return left.size < right.size;
    });
    return result;
}

} // namespace nba16
