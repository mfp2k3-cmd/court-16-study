#include "graphics_call_trace.h"

#include "gnm_submission_runtime.h"
#include "guest_process_context.h"

#include <algorithm>
#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>

#ifdef _WIN32
extern "C" void nba16_start_gnm_submitdone_instruction_trace();
#endif

namespace nba16 {
namespace {

constexpr std::int32_t trace_stop = -1;
std::atomic_uint64_t call_sequence{};

bool read_guest_bytes(std::uint64_t address, std::span<std::byte> output) {
    auto* context = current_guest_process_context();
    if (context == nullptr || address == 0 || output.empty()) return false;
    std::string error;
    return context->memory().read(address, output, error);
}

void trace_command_buffers(const char* label, std::uint32_t count,
                           const void* address_array, const std::uint32_t* size_array) {
    constexpr std::size_t max_logged_buffers = 4;
    const auto logged_count = std::min<std::size_t>(count, max_logged_buffers);
    std::array<std::uint64_t, max_logged_buffers> addresses{};
    std::array<std::uint32_t, max_logged_buffers> sizes{};
    const auto address_array_va = reinterpret_cast<std::uintptr_t>(address_array);
    const auto size_array_va = reinterpret_cast<std::uintptr_t>(size_array);
    const bool addresses_read = logged_count != 0 && read_guest_bytes(address_array_va,
        std::as_writable_bytes(std::span(addresses.data(), logged_count)));
    const bool sizes_read = logged_count != 0 && read_guest_bytes(size_array_va,
        std::as_writable_bytes(std::span(sizes.data(), logged_count)));
    for (std::size_t index = 0; index < logged_count; ++index) {
        std::fprintf(stderr,
            "GPU-TRACE %s[%zu] address=%s0x%llx size=%s%u",
            label, index, addresses_read ? "" : "unreadable/",
            static_cast<unsigned long long>(addresses[index]),
            sizes_read ? "" : "unreadable/", sizes[index]);
        std::array<std::uint32_t, 4> header{};
        if (addresses_read && sizes_read && sizes[index] >= sizeof(header) &&
            read_guest_bytes(addresses[index], std::as_writable_bytes(std::span(header)))) {
            std::fprintf(stderr, " head=%08x,%08x,%08x,%08x",
                header[0], header[1], header[2], header[3]);
        }
        std::fputc('\n', stderr);
    }
    if (count > logged_count) {
        std::fprintf(stderr, "GPU-TRACE %s: %u buffers total; first %zu shown\n",
            label, count, logged_count);
    }
    std::fflush(stderr);
}

void trace(const char* name, const char* arguments) {
    const auto sequence = call_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    std::fprintf(stderr, "GPU-TRACE #%llu %s %s; trace-only return=-1 (0xffffffff)\n",
        static_cast<unsigned long long>(sequence), name, arguments);
    std::fflush(stderr);
}

void NBA16_GUEST_SYSV_ABI trace_gnm_ding_dong(std::uint32_t vqid,
                                              std::uint32_t next_offset_dw) {
    char args[128]{};
    std::snprintf(args, sizeof(args), "vqid=%u next_offset_dw=%u", vqid, next_offset_dw);
    trace("sceGnmDingDong", args);
}

std::int32_t NBA16_GUEST_SYSV_ABI trace_gnm_submit(
    std::uint32_t count, const std::uint32_t* const* dcb_addresses,
    const std::uint32_t* dcb_sizes, const std::uint32_t* const* ccb_addresses,
    const std::uint32_t* ccb_sizes) {
    char args[256]{};
    std::snprintf(args, sizeof(args),
        "count=%u dcb_addresses=%p dcb_sizes=%p ccb_addresses=%p ccb_sizes=%p",
        count, static_cast<const void*>(dcb_addresses), static_cast<const void*>(dcb_sizes),
        static_cast<const void*>(ccb_addresses), static_cast<const void*>(ccb_sizes));
    trace("sceGnmSubmitCommandBuffers", args);
    if (auto* context = current_guest_process_context(); context != nullptr) {
        std::vector<GnmCommandBufferView> resolved;
        std::string resolve_error;
        const bool valid = resolve_gnm_submission(
            context->memory(), count,
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(dcb_addresses)),
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(dcb_sizes)),
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(ccb_addresses)),
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(ccb_sizes)),
            resolved, resolve_error);
        if (valid) {
            for (std::size_t index = 0; index < resolved.size(); ++index) {
                std::fprintf(stderr,
                    "GPU-TRACE resolved[%zu] DCB=%zu dwords CCB=%zu dwords\n",
                    index, resolved[index].dcb.size(), resolved[index].ccb.size());
            }
        } else {
            std::fprintf(stderr, "GPU-TRACE submission arrays could not be safely resolved: %s\n",
                         resolve_error.c_str());
        }
        std::fflush(stderr);
    }
    trace_command_buffers("DCB", count, dcb_addresses, dcb_sizes);
    if (ccb_addresses != nullptr && ccb_sizes != nullptr)
        trace_command_buffers("CCB", count, ccb_addresses, ccb_sizes);
    return trace_stop;
}

std::int32_t NBA16_GUEST_SYSV_ABI trace_gnm_submit_flip(
    std::uint32_t count, const std::uint32_t* const* dcb_addresses,
    const std::uint32_t* dcb_sizes, const std::uint32_t* const* ccb_addresses,
    const std::uint32_t* ccb_sizes, std::uint32_t video_handle,
    std::uint32_t buffer_index, std::uint32_t flip_mode, std::int64_t flip_argument) {
    char args[320]{};
    std::snprintf(args, sizeof(args),
        "count=%u dcb_addresses=%p dcb_sizes=%p ccb_addresses=%p ccb_sizes=%p "
        "video_handle=%u buffer_index=%u flip_mode=%u flip_argument=%lld",
        count, static_cast<const void*>(dcb_addresses), static_cast<const void*>(dcb_sizes),
        static_cast<const void*>(ccb_addresses), static_cast<const void*>(ccb_sizes),
        video_handle, buffer_index, flip_mode, static_cast<long long>(flip_argument));
    trace("sceGnmSubmitAndFlipCommandBuffers", args);
    trace_command_buffers("DCB", count, dcb_addresses, dcb_sizes);
    if (ccb_addresses != nullptr && ccb_sizes != nullptr)
        trace_command_buffers("CCB", count, ccb_addresses, ccb_sizes);
    return trace_stop;
}

std::int32_t NBA16_GUEST_SYSV_ABI trace_gnm_submit_done() {
    char args[80]{};
    std::snprintf(args, sizeof(args), "return_address=%p",
        __builtin_return_address(0));
    trace("sceGnmSubmitDone", args);
    return trace_stop;
}

std::int32_t NBA16_GUEST_SYSV_ABI probe_gnm_submit_done() {
    const auto sequence = call_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    std::fprintf(stderr,
        "GPU-PROBE #%llu sceGnmSubmitDone return_address=%p: retorno diagnóstico 0; "
        "nenhum comando GPU foi executado\n",
        static_cast<unsigned long long>(sequence), __builtin_return_address(0));
    std::fflush(stderr);
#ifdef _WIN32
    nba16_start_gnm_submitdone_instruction_trace();
#endif
    return 0;
}

std::int32_t NBA16_GUEST_SYSV_ABI trace_gnm_request_flip_submit_done() {
    trace("sceGnmRequestFlipAndSubmitDone", "");
    return trace_stop;
}

} // namespace

bool register_graphics_call_trace(ImportResolver& resolver, std::string& error,
                                 bool submit_done_is_probed) {
    constexpr const char* gnm_library = "libSceGnmDriver";
    const bool common_registered = resolver.register_function(
               gnm_library, gnm_library, "bX5IbRvECXk",
               &trace_gnm_ding_dong, error) &&
        resolver.register_function(gnm_library, gnm_library, "zwY0YV91TTI",
               &trace_gnm_submit, error) &&
        resolver.register_function(gnm_library, gnm_library, "gObODli-OH8",
               &trace_gnm_request_flip_submit_done, error) &&
        resolver.register_function(gnm_library, gnm_library, "xbxNatawohc",
               &trace_gnm_submit_flip, error);
    if (!common_registered || submit_done_is_probed) return common_registered;
    return resolver.register_function(gnm_library, gnm_library, "yvZ73uQUqrk",
                                      &trace_gnm_submit_done, error);
}

bool register_gnm_submit_done_probe(ImportResolver& resolver, std::string& error) {
    constexpr const char* module = "libSceGnmDriver";
    return resolver.register_function(module, module, "yvZ73uQUqrk",
               &probe_gnm_submit_done, error);
}

} // namespace nba16
