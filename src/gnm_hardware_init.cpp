#include "gnm_hardware_init.h"

#include "guest_abi.h"
#include "guest_process_context.h"
#include "import_resolver.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace nba16 {
namespace {

// PM4 sequence follows the documented generic OpenGNM implementation
// (MIT; copyright notice retained in LICENSES/OPEN_GNM_MIT.txt), which in
// turn identifies the firmware-captured sequence. The independent runtime
// owns the packet assembly and guest-memory validation below.
constexpr std::array<std::uint32_t, 12> clear_context_state{
    0xc0012800U, 0x80000000U, 0x80000000U,
    0xc0001200U, 0U,
    0xc0055800U, 0x2ec47fc0U, 0xffffffffU, 0U, 0U, 0U, 10U,
};

constexpr std::uint32_t init_sequence_200[]{
    0xc0001200U, 0U,
    0xc0017600U, 0x216U, 0xffffffffU,
    0xc0017600U, 0x217U, 0xffffffffU,
    0xc0017600U, 0x215U, 0U,
    0xc0016900U, 0x2f9U, 0x2dU,
    0xc0016900U, 0x282U, 8U,
    0xc0016900U, 0x280U, 0x80008U,
    0xc0016900U, 0x281U, 0xffff0000U,
    0xc0016900U, 0x204U, 0U,
    0xc0016900U, 0x206U, 0x43fU,
    0xc0016900U, 0x83U, 0xffffU,
    0xc0016900U, 0x317U, 0x10U,
    0xc0016900U, 0x2faU, 0x3f800000U,
    0xc0016900U, 0x2fcU, 0x3f800000U,
    0xc0016900U, 0x2fbU, 0x3f800000U,
    0xc0016900U, 0x2fdU, 0x3f800000U,
    0xc0016900U, 0x202U, 0xcc0010U,
    0xc0016900U, 0x30eU, 0xffffffffU,
    0xc0016900U, 0x30fU, 0xffffffffU,
    0xc0002f00U, 1U,
    0xc0017600U, 7U, 0x1701ffU,
    0xc0017600U, 0x46U, 0x1701fdU,
    0xc0017600U, 0x87U, 0x1701ffU,
    0xc0017600U, 0xc7U, 0x1701fdU,
    0xc0017600U, 0x107U, 0x17U,
    0xc0017600U, 0x147U, 0x1701fdU,
    0xc0017600U, 0x47U, 0x1cU,
    0xc0016900U, 0x1b1U, 2U,
    0xc0016900U, 0x101U, 0U,
    0xc0016900U, 0x100U, 0xffffffffU,
    0xc0016900U, 0x103U, 0U,
    0xc0016900U, 0x284U, 0U,
    0xc0016900U, 0x290U, 0U,
    0xc0016900U, 0x2aeU, 0U,
    0xc0016900U, 0x292U, 0U,
    0xc0016900U, 0x293U, 0x6020000U,
    0xc0016900U, 0x2f8U, 0U,
    0xc0016900U, 0x2deU, 0x1e9U,
    0xc0036900U, 0x295U, 0x100U, 0x100U, 4U,
    0xc0017900U, 0x200U, 0xe0000000U,
};

constexpr std::size_t hardware_init_packet_dwords = 0x100;

struct ComputeQueue {
    std::uint64_t ring_address{};
    std::uint64_t read_pointer_address{};
    std::uint32_t ring_size_dwords{};
    std::uint32_t pipe{};
    std::uint32_t queue{};
};

std::mutex compute_queue_mutex;
std::array<std::optional<ComputeQueue>, 56> compute_queues;

std::uint32_t NBA16_GUEST_SYSV_ABI draw_init_default_hardware_state_200(
        std::uint32_t* command_buffer, std::uint32_t dword_capacity) {
    if (command_buffer == nullptr || dword_capacity < hardware_init_packet_dwords)
        return 0;
    auto* process = current_guest_process_context();
    if (process == nullptr) {
        if (std::getenv("NBA16_TRACE_GNM_INIT") != nullptr)
            std::fprintf(stderr, "GNM-HW-INIT rejected: no active guest process\n");
        return 0;
    }

    const auto address = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(command_buffer));
    std::string error;
    auto* output = static_cast<std::uint32_t*>(process->memory().native_pointer(
        address, hardware_init_packet_dwords * sizeof(std::uint32_t), true, error));
    if (output == nullptr) {
        if (std::getenv("NBA16_TRACE_GNM_INIT") != nullptr)
            std::fprintf(stderr,
                "GNM-HW-INIT rejected buffer=0x%llx capacity=%u reason=%s\n",
                static_cast<unsigned long long>(address), dword_capacity, error.c_str());
        return 0;
    }

    std::copy(clear_context_state.begin(), clear_context_state.end(), output);
    auto* cursor = output + clear_context_state.size();
    std::copy(std::begin(init_sequence_200) + 2,
        std::end(init_sequence_200), cursor);
    cursor += std::size(init_sequence_200) - 2;
    const auto remaining = hardware_init_packet_dwords -
        static_cast<std::size_t>(cursor - output);
    if (remaining < 2) return 0;
    cursor[0] = 0xc0001000U |
        (static_cast<std::uint32_t>(remaining - 2) << 16U);
    std::fill(cursor + 1, output + hardware_init_packet_dwords, 0U);
    if (std::getenv("NBA16_TRACE_GNM_INIT") != nullptr)
        std::fprintf(stderr,
            "GNM-HW-INIT sceGnmDrawInitDefaultHardwareState200 buffer=0x%llx capacity=%u returned=%zu\n",
            static_cast<unsigned long long>(address), dword_capacity,
            hardware_init_packet_dwords);
    return static_cast<std::uint32_t>(hardware_init_packet_dwords);
}

std::uint32_t NBA16_GUEST_SYSV_ABI dispatch_init_default_hardware_state(
        std::uint32_t* command_buffer, std::uint32_t dword_capacity) {
    if (command_buffer == nullptr || dword_capacity < hardware_init_packet_dwords)
        return 0;
    auto* process = current_guest_process_context();
    if (process == nullptr) return 0;
    const auto address = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(command_buffer));
    std::string error;
    auto* output = static_cast<std::uint32_t*>(process->memory().native_pointer(
        address, hardware_init_packet_dwords * sizeof(std::uint32_t), true, error));
    if (output == nullptr) return 0;

    constexpr std::array<std::uint32_t, 16> setup{
        0xc0017600U, 0x216U, 0xffffffffU,
        0xc0017600U, 0x217U, 0xffffffffU,
        0xc0017600U, 0x215U, 0x170U,
        0xc0055800U, 0x28000000U, 0U, 0U, 0U, 0U, 0xAU,
    };
    std::copy(setup.begin(), setup.end(), output);
    const auto remaining = hardware_init_packet_dwords - setup.size();
    output[setup.size()] = 0xc0001000U |
        (static_cast<std::uint32_t>(remaining - 2) << 16U);
    std::fill(output + setup.size() + 1, output + hardware_init_packet_dwords, 0U);
    if (std::getenv("NBA16_TRACE_GNM_INIT") != nullptr)
        std::fprintf(stderr,
            "GNM-HW-INIT sceGnmDispatchInitDefaultHardwareState buffer=0x%llx returned=%zu\n",
            static_cast<unsigned long long>(address), hardware_init_packet_dwords);
    return static_cast<std::uint32_t>(hardware_init_packet_dwords);
}

std::int32_t NBA16_GUEST_SYSV_ABI map_compute_queue(
        std::uint32_t pipe_id, std::uint32_t queue_id,
        std::uint64_t ring_base_address, std::uint32_t ring_size_dwords,
        std::uint32_t* read_pointer) {
    constexpr std::int32_t invalid_pipe = std::bit_cast<std::int32_t>(0x80d17000U);
    constexpr std::int32_t invalid_queue = std::bit_cast<std::int32_t>(0x80d17001U);
    constexpr std::int32_t invalid_ring_size = std::bit_cast<std::int32_t>(0x80d17002U);
    constexpr std::int32_t invalid_ring_base = std::bit_cast<std::int32_t>(0x80d17003U);
    constexpr std::int32_t invalid_read_pointer = std::bit_cast<std::int32_t>(0x80d17004U);
    if (pipe_id >= 7) return invalid_pipe;
    if (queue_id >= 8) return invalid_queue;
    if ((ring_base_address & 0xffU) != 0) return invalid_ring_base;
    if (ring_size_dwords == 0 || !std::has_single_bit(ring_size_dwords))
        return invalid_ring_size;
    const auto read_pointer_address = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(read_pointer));
    if (read_pointer == nullptr || (read_pointer_address & 3U) != 0)
        return invalid_read_pointer;

    auto* process = current_guest_process_context();
    if (process == nullptr) return invalid_read_pointer;
    std::string error;
    if (!process->memory().validate(read_pointer_address, sizeof(std::uint32_t), true, error))
        return invalid_read_pointer;
    const std::uint32_t initial_read_pointer = 0;
    if (!process->memory().write(read_pointer_address,
            std::as_bytes(std::span{&initial_read_pointer, 1}), error))
        return invalid_read_pointer;

    std::scoped_lock lock(compute_queue_mutex);
    for (std::size_t index = 0; index < compute_queues.size(); ++index) {
        const auto& existing = compute_queues[index];
        if (existing && existing->pipe == pipe_id && existing->queue == queue_id) {
            if (existing->ring_address != ring_base_address ||
                existing->ring_size_dwords != ring_size_dwords ||
                existing->read_pointer_address != read_pointer_address)
                return invalid_queue;
            return static_cast<std::int32_t>(index + 1);
        }
    }
    const auto available = std::find_if(compute_queues.begin(), compute_queues.end(),
        [](const auto& slot) { return !slot.has_value(); });
    if (available == compute_queues.end()) return invalid_queue;
    const auto index = static_cast<std::size_t>(available - compute_queues.begin());
    *available = ComputeQueue{ring_base_address, read_pointer_address,
        ring_size_dwords, pipe_id, queue_id};
    if (std::getenv("NBA16_TRACE_GNM_INIT") != nullptr)
        std::fprintf(stderr,
            "GNM-COMPUTE-QUEUE mapped pipe=%u queue=%u ring=0x%llx dwords=%u read_ptr=0x%llx vqid=%zu\n",
            pipe_id, queue_id, static_cast<unsigned long long>(ring_base_address),
            ring_size_dwords, static_cast<unsigned long long>(read_pointer_address),
            index + 1);
    return static_cast<std::int32_t>(index + 1);
}

} // namespace

bool register_gnm_hardware_init_imports(ImportResolver& resolver, std::string& error) {
    if (!resolver.register_function("libSceGnmDriver", "libSceGnmDriver",
            "0H2vBYbTLHI", &draw_init_default_hardware_state_200, error))
        return false;
    if (!resolver.register_function("libSceGnmDriver", "libSceGnmDriver",
            "29oKvKXzEZo", &map_compute_queue, error))
        return false;
    if (!resolver.register_function("libSceGnmDriver", "libSceGnmDriver",
            "nF6bFRUBRAU", &dispatch_init_default_hardware_state, error))
        return false;
    error.clear();
    return true;
}

} // namespace nba16
