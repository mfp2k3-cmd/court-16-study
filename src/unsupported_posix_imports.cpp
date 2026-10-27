#include "unsupported_posix_imports.h"

#include "guest_abi.h"
#include "kernel_runtime.h"

#include <cstdint>

namespace nba16 {
namespace {

constexpr int error_not_implemented = 78; // ENOSYS on the FreeBSD 9 ABI.
constexpr int error_operation_not_supported = 45;

int NBA16_GUEST_SYSV_ABI guest_fork_unavailable() {
    set_guest_errno(error_not_implemented);
    return -1;
}

int NBA16_GUEST_SYSV_ABI guest_vfork_unavailable() {
    set_guest_errno(error_not_implemented);
    return -1;
}

int NBA16_GUEST_SYSV_ABI guest_link_unavailable(std::uint64_t from_path,
                                                std::uint64_t to_path) {
    (void)from_path;
    (void)to_path;
    set_guest_errno(error_operation_not_supported);
    return -1;
}

int NBA16_GUEST_SYSV_ABI guest_chown_unavailable(std::uint64_t path,
                                                 std::uint32_t owner,
                                                 std::uint32_t group) {
    (void)path;
    (void)owner;
    (void)group;
    set_guest_errno(error_not_implemented);
    return -1;
}

int NBA16_GUEST_SYSV_ABI guest_setpgid_unavailable(int process_id,
                                                   int process_group_id) {
    (void)process_id;
    (void)process_group_id;
    set_guest_errno(error_not_implemented);
    return -1;
}

int NBA16_GUEST_SYSV_ABI guest_setsid_unavailable() {
    set_guest_errno(error_not_implemented);
    return -1;
}

} // namespace

bool register_native_unsupported_posix_imports(ImportResolver& resolver,
                                               std::string& error) {
    return resolver.register_function("libkernel", "libkernel", "cjt-4ySmYTs",
                                      &guest_fork_unavailable, error) &&
           resolver.register_function("libkernel", "libkernel", "Pd7KtJ1gybk",
                                      &guest_link_unavailable, error) &&
           resolver.register_function("libkernel", "libkernel", "8fryvN6BDtY",
                                      &guest_setpgid_unavailable, error) &&
           resolver.register_function("libkernel", "libkernel", "edJoqV2FIWs",
                                      &guest_setsid_unavailable, error) &&
           resolver.register_function("libkernel", "libkernel", "9jJTRrWCWK0",
                                      &guest_vfork_unavailable, error) &&
           resolver.register_function("libkernel", "libkernel", "+2HAuc7yVbc",
                                      &guest_chown_unavailable, error);
}

} // namespace nba16
