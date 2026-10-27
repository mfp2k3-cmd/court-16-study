#include "gnm_submission_runtime.h"

#include "guest_image_memory.h"

#include <cstddef>
#include <limits>
#include <span>
#include <type_traits>
#include <utility>

namespace nba16 {
namespace {

constexpr std::uint32_t max_submission_buffers = 4096;

template <typename T>
bool read_guest_array(GuestMemoryAccess& memory, std::uint64_t address,
                      std::uint32_t count, std::vector<T>& values,
                      std::string& error) {
    static_assert(std::is_trivially_copyable_v<T>);
    if (count == 0) {
        values.clear();
        return true;
    }
    if (address == 0 || count > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
        error = "arraya de submissão GNM nula ou grande demais";
        return false;
    }
    values.resize(count);
    return memory.read(address, std::as_writable_bytes(std::span(values)), error);
}

bool resolve_one(GuestMemoryAccess& memory, std::uint64_t address,
                 std::uint32_t byte_count, std::span<const std::uint32_t>& view,
                 std::string& error) {
    if ((byte_count % sizeof(std::uint32_t)) != 0) {
        error = "tamanho do command buffer GNM não é múltiplo de 4 bytes";
        return false;
    }
    if (byte_count == 0) {
        view = {};
        return true;
    }
    if (address == 0) {
        error = "endereço nulo em command buffer GNM não vazio";
        return false;
    }
    void* pointer = memory.native_pointer(address, byte_count, false, error);
    if (pointer == nullptr) return false;
    view = {static_cast<const std::uint32_t*>(pointer),
            byte_count / sizeof(std::uint32_t)};
    return true;
}

} // namespace

bool resolve_gnm_submission(GuestMemoryAccess& memory, std::uint32_t count,
                            std::uint64_t dcb_address_array,
                            std::uint64_t dcb_size_array,
                            std::uint64_t ccb_address_array,
                            std::uint64_t ccb_size_array,
                            std::vector<GnmCommandBufferView>& output,
                            std::string& error) {
    if (count > max_submission_buffers) {
        error = "quantidade de command buffers GNM excede o limite de segurança";
        return false;
    }
    if (count != 0 && (dcb_address_array == 0 || dcb_size_array == 0)) {
        error = "arrays DCB obrigatórios estão ausentes";
        return false;
    }

    std::vector<std::uint64_t> dcb_addresses;
    std::vector<std::uint32_t> dcb_sizes;
    std::vector<std::uint64_t> ccb_addresses;
    std::vector<std::uint32_t> ccb_sizes;
    if (!read_guest_array(memory, dcb_address_array, count, dcb_addresses, error) ||
        !read_guest_array(memory, dcb_size_array, count, dcb_sizes, error)) {
        return false;
    }
    const bool has_ccb = ccb_size_array != 0;
    if (has_ccb && count != 0 && ccb_address_array == 0) {
        error = "array de endereços CCB ausente apesar do array de tamanhos";
        return false;
    }
    if (has_ccb &&
        (!read_guest_array(memory, ccb_address_array, count, ccb_addresses, error) ||
         !read_guest_array(memory, ccb_size_array, count, ccb_sizes, error))) {
        return false;
    }

    std::vector<GnmCommandBufferView> resolved(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        auto& view = resolved[index];
        if (!resolve_one(memory, dcb_addresses[index], dcb_sizes[index], view.dcb, error))
            return false;
        if (has_ccb &&
            !resolve_one(memory, ccb_addresses[index], ccb_sizes[index], view.ccb, error))
            return false;
    }
    output = std::move(resolved);
    error.clear();
    return true;
}

} // namespace nba16
