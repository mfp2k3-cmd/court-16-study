#pragma once

#include "import_resolver.h"

#include <cstdint>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace nba16 {

struct GuestThreadSnapshot {
    std::uint64_t entry{};
    std::uintptr_t argument{};
    bool is_guest_thread{};
};

// Optional in-process backend for PS4 direct memory. Install it before starting
// guest threads; remove it only after guest threads and mappings are fully torn down.
struct DirectMemoryProvider {
    void* context{};
    std::uint64_t (*get_size)(void*){};
    std::int32_t (*get_type)(void*, std::uint64_t, std::int32_t*, void**, void**){};
    std::int32_t (*allocate)(void*, std::int64_t, std::int64_t, std::uint64_t,
                             std::uint64_t, std::int32_t, std::int64_t*){};
    std::int32_t (*available)(void*, std::int64_t, std::int64_t, std::uint64_t,
                              std::int64_t*, std::uint64_t*){};
    std::int32_t (*map)(void*, void**, std::uint64_t, std::int32_t,
                        std::int32_t, std::int64_t, std::uint64_t){};
    // Required with a custom map callback. The runtime calls this for each
    // tracked mapping before releasing its physical backing.
    std::int32_t (*unmap)(void*, std::uint64_t, std::uint64_t){};
    std::int32_t (*release)(void*, std::int64_t, std::uint64_t){};
};

[[nodiscard]] bool install_direct_memory_provider(const DirectMemoryProvider& provider) noexcept;
void remove_direct_memory_provider() noexcept;

[[nodiscard]] GuestThreadSnapshot current_guest_thread_snapshot() noexcept;

void set_guest_errno(int error) noexcept;
void set_guest_usrstack_top(std::uint64_t address) noexcept;
void set_guest_process_parameter(void* parameter) noexcept;
void reset_guest_sysctl_diagnostics() noexcept;
[[nodiscard]] std::uint64_t guest_sysctl_call_count() noexcept;
[[nodiscard]] std::uint64_t guest_sysctl_thunk_return_value() noexcept;
[[nodiscard]] std::uint64_t guest_sysctl_last_caller() noexcept;
[[nodiscard]] std::uint64_t guest_sysctl_dispatch_result() noexcept;
[[nodiscard]] std::uint64_t guest_sysctl_dispatch_mib0() noexcept;
[[nodiscard]] std::uint64_t guest_sysctl_dispatch_mib1() noexcept;
struct GuestSysctlHistory { std::array<std::uint64_t, 32> values{}; std::size_t count{}; };
[[nodiscard]] GuestSysctlHistory guest_sysctl_dispatch_history() noexcept;
[[nodiscard]] std::uint64_t guest_sysctlbyname_call_count() noexcept;
[[nodiscard]] std::uint64_t guest_usrstack_sysctl_call_count() noexcept;
[[nodiscard]] std::uint64_t guest_mmap_call_count() noexcept;
[[nodiscard]] std::uint64_t guest_cpuset_call_count() noexcept;
struct GuestSysctlTrace {
    std::uint64_t mib0{}, mib1{}, mib_count{}, old_value{}, old_length_ptr{};
    std::uint64_t old_length{}, new_value{}, new_length{};
    std::uint64_t result{}, response_length{}, response_value{};
};
[[nodiscard]] GuestSysctlTrace guest_sysctl_last_trace() noexcept;
[[nodiscard]] GuestSysctlTrace guest_usrstack_sysctl_trace() noexcept;

bool register_native_kernel_runtime_imports(ImportResolver& resolver,
                                           std::string& error);
extern "C" std::int32_t NBA16_GUEST_SYSV_ABI guest_virtual_query(std::uint64_t address,
    std::uint64_t find_next, void* info, std::uint64_t info_size);
extern "C" std::int32_t NBA16_GUEST_SYSV_ABI nba16_guest_virtual_query_thunk(
    std::uint64_t address, std::uint64_t find_next, void* info, std::uint64_t info_size);
extern "C" std::int32_t NBA16_GUEST_SYSV_ABI nba16_guest_virtual_query_api(
    std::uint64_t address, std::uint64_t find_next, void* info, std::uint64_t info_size);
bool register_guest_query_region(std::uint64_t begin, std::uint64_t size,
    std::uint32_t protection, std::string_view name) noexcept;
void unregister_guest_query_region(std::uint64_t begin, std::uint64_t size) noexcept;
void set_guest_mspace_default_slot(void** slot) noexcept;
bool initialize_guest_mspace_default(std::uint64_t base, std::size_t size) noexcept;

} // namespace nba16
