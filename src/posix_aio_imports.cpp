#include "posix_aio_imports.h"

#include "guest_process_context.h"
#include "guest_syscalls.h"
#include "kernel_runtime.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <vector>

namespace nba16 {
namespace {

// FreeBSD 9 x86-64 aiocb prefix. The NBA executable identifies ABI 9;
// Orbis-specific layout still needs confirmation against a live call.
struct AioControlBlockAbi9 {
    std::int32_t descriptor{};
    std::int32_t padding{};
    std::int64_t offset{};
    std::uint64_t buffer{};
    std::uint64_t byte_count{};
    std::int32_t spare[2]{};
    std::uint64_t spare2{};
    std::int32_t list_opcode{};
    std::int32_t request_priority{};
    std::int64_t status{};
    std::int64_t error{};
    std::uint64_t kernel_info{};
};
static_assert(sizeof(AioControlBlockAbi9) == 80);
static_assert(offsetof(AioControlBlockAbi9, descriptor) == 0);
static_assert(offsetof(AioControlBlockAbi9, offset) == 8);
static_assert(offsetof(AioControlBlockAbi9, buffer) == 16);
static_assert(offsetof(AioControlBlockAbi9, byte_count) == 24);
static_assert(offsetof(AioControlBlockAbi9, status) == 56);
static_assert(offsetof(AioControlBlockAbi9, error) == 64);

constexpr int err_bad_address = 14;
constexpr int err_bad_fd = 9;
constexpr int err_invalid = 22;
constexpr int err_in_progress = 36;
constexpr int err_again = 35;
constexpr int err_canceled = 85;
constexpr int aio_canceled = 1;
constexpr int aio_not_canceled = 2;
constexpr int aio_all_done = 3;
constexpr std::size_t max_suspend_entries = 16;

int error_number(Ps4Errno error) noexcept {
    return static_cast<int>(error);
}

bool read_control_block(GuestProcessContext& context, std::uint64_t address,
                        AioControlBlockAbi9& control, int& error_number_out) {
    std::string error;
    auto bytes = std::as_writable_bytes(std::span(&control, 1));
    if (address == 0 || !context.memory().read(address, bytes, error)) {
        error_number_out = err_bad_address;
        return false;
    }
    error_number_out = 0;
    return true;
}

bool write_control_result(GuestProcessContext& context, std::uint64_t address,
                          std::int64_t status, std::int64_t error_value) {
    std::string error;
    const auto status_bytes = std::as_bytes(std::span(&status, 1));
    const auto error_bytes = std::as_bytes(std::span(&error_value, 1));
    return context.memory().write(address + offsetof(AioControlBlockAbi9, status),
                                  status_bytes, error) &&
           context.memory().write(address + offsetof(AioControlBlockAbi9, error),
                                  error_bytes, error);
}

GuestProcessContext* active_context() noexcept {
    auto* context = current_guest_process_context();
    return context != nullptr && context->is_initialized() ? context : nullptr;
}

int NBA16_GUEST_SYSV_ABI guest_aio_read(std::uint64_t address) {
    auto* context = active_context();
    if (context == nullptr) { set_guest_errno(err_invalid); return -1; }
    AioControlBlockAbi9 control{};
    int failure{};
    if (!read_control_block(*context, address, control, failure)) {
        set_guest_errno(failure); return -1;
    }
    std::string validation_error;
    if (control.offset < 0 || control.byte_count > std::numeric_limits<std::size_t>::max() ||
        (control.byte_count != 0 &&
         !context->memory().validate(control.buffer,
             static_cast<std::size_t>(control.byte_count), true, validation_error))) {
        set_guest_errno(control.offset < 0 ? err_invalid : err_bad_address);
        return -1;
    }
    std::string message;
    if (!write_control_result(*context, address, -1, err_in_progress)) {
        set_guest_errno(err_bad_address); return -1;
    }
    const auto submitted = context->aio().submit(address, control.descriptor,
        [context, address, control] {
            std::size_t transferred{};
            std::string error;
            Ps4Errno syscall_error{};
            const bool ok = guest_pread(context->vfs(), context->descriptors(),
                context->memory(), control.descriptor, control.buffer,
                static_cast<std::size_t>(control.byte_count), control.offset,
                transferred, error, &syscall_error);
            const auto status = ok ? static_cast<std::int64_t>(transferred) : -1;
            const auto errno_value = ok ? 0 : error_number(syscall_error);
            if (!write_control_result(*context, address, status, errno_value))
                return GuestAioCompletion{-1, Ps4Errno::BadAddress};
            return GuestAioCompletion{status, ok ? Ps4Errno::Success : syscall_error};
        }, message);
    if (!submitted) { set_guest_errno(err_invalid); return -1; }
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_aio_write(std::uint64_t address) {
    auto* context = active_context();
    if (context == nullptr) { set_guest_errno(err_invalid); return -1; }
    AioControlBlockAbi9 control{};
    int failure{};
    if (!read_control_block(*context, address, control, failure)) {
        set_guest_errno(failure); return -1;
    }
    std::string validation_error;
    if (control.offset < 0 || control.byte_count > std::numeric_limits<std::size_t>::max() ||
        (control.byte_count != 0 && !context->memory().validate(control.buffer,
            static_cast<std::size_t>(control.byte_count), false, validation_error))) {
        set_guest_errno(control.offset < 0 ? err_invalid : err_bad_address);
        return -1;
    }
    if (!write_control_result(*context, address, -1, err_in_progress)) {
        set_guest_errno(err_bad_address); return -1;
    }
    std::string message;
    const auto submitted = context->aio().submit(address, control.descriptor,
        [context, address, control] {
            std::size_t transferred{};
            std::string error;
            Ps4Errno syscall_error{};
            const bool ok = guest_pwrite(context->vfs(), context->descriptors(),
                context->memory(), control.descriptor, control.buffer,
                static_cast<std::size_t>(control.byte_count), control.offset,
                transferred, error, &syscall_error);
            const auto status = ok ? static_cast<std::int64_t>(transferred) : -1;
            const auto errno_value = ok ? 0 : error_number(syscall_error);
            if (!write_control_result(*context, address, status, errno_value))
                return GuestAioCompletion{-1, Ps4Errno::BadAddress};
            return GuestAioCompletion{status, ok ? Ps4Errno::Success : syscall_error};
        }, message);
    if (!submitted) { set_guest_errno(err_invalid); return -1; }
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_aio_fsync(int operation, std::uint64_t address) {
    auto* context = active_context();
    if (context == nullptr) { set_guest_errno(err_invalid); return -1; }
    if (operation != 1 && operation != 2) { set_guest_errno(err_invalid); return -1; }
    AioControlBlockAbi9 control{};
    int failure{};
    if (!read_control_block(*context, address, control, failure)) {
        set_guest_errno(failure); return -1;
    }
    if (!write_control_result(*context, address, -1, err_in_progress)) {
        set_guest_errno(err_bad_address); return -1;
    }
    std::string message;
    const auto submitted = context->aio().submit(address, control.descriptor,
        [context, address, descriptor = control.descriptor] {
            std::string error;
            Ps4Errno syscall_error{};
            const bool ok = guest_fsync(context->vfs(), context->descriptors(),
                                        descriptor, error, &syscall_error);
            const auto status = ok ? 0 : -1;
            if (!write_control_result(*context, address, status,
                                      ok ? 0 : error_number(syscall_error)))
                return GuestAioCompletion{-1, Ps4Errno::BadAddress};
            return GuestAioCompletion{status, ok ? Ps4Errno::Success : syscall_error};
        }, message);
    if (!submitted) { set_guest_errno(err_invalid); return -1; }
    return 0;
}

int NBA16_GUEST_SYSV_ABI guest_aio_cancel(int descriptor, std::uint64_t address) {
    auto* context = active_context();
    if (context == nullptr) { set_guest_errno(err_invalid); return -1; }
    VfsMetadata metadata{};
    std::string message;
    if (!context->descriptors().stat_descriptor(descriptor, metadata, message)) {
        set_guest_errno(err_bad_fd); return -1;
    }
    GuestAioCancelDisposition disposition{};
    if (address != 0) {
        AioControlBlockAbi9 control{};
        int failure{};
        if (!read_control_block(*context, address, control, failure)) {
            set_guest_errno(failure); return -1;
        }
        if (control.descriptor != descriptor) { set_guest_errno(err_invalid); return -1; }
        if (!context->aio().cancel(address, descriptor, disposition, message)) {
            set_guest_errno(err_invalid); return -1;
        }
        if (disposition == GuestAioCancelDisposition::Cancelled &&
            !write_control_result(*context, address, -1, err_canceled)) {
            set_guest_errno(err_bad_address); return -1;
        }
    } else {
        std::vector<std::uint64_t> cancelled;
        if (!context->aio().cancel_descriptor(descriptor, disposition,
                                               cancelled, message)) {
            set_guest_errno(err_invalid); return -1;
        }
        for (const auto control : cancelled)
            (void)write_control_result(*context, control, -1, err_canceled);
    }
    switch (disposition) {
    case GuestAioCancelDisposition::Cancelled: return aio_canceled;
    case GuestAioCancelDisposition::InProgress: return aio_not_canceled;
    case GuestAioCancelDisposition::AlreadyComplete: return aio_all_done;
    }
    set_guest_errno(err_invalid);
    return -1;
}

int NBA16_GUEST_SYSV_ABI guest_aio_suspend(std::uint64_t list_address,
                                            int entry_count,
                                            std::uint64_t timeout_address) {
    auto* context = active_context();
    if (context == nullptr) { set_guest_errno(err_invalid); return -1; }
    if (entry_count <= 0 || static_cast<std::size_t>(entry_count) > max_suspend_entries ||
        list_address == 0) { set_guest_errno(err_invalid); return -1; }
    std::vector<std::uint64_t> controls(static_cast<std::size_t>(entry_count));
    std::string message;
    auto list_bytes = std::as_writable_bytes(std::span(controls));
    if (!context->memory().read(list_address, list_bytes, message)) {
        set_guest_errno(err_bad_address); return -1;
    }
    std::optional<std::chrono::nanoseconds> timeout;
    if (timeout_address != 0) {
        std::array<std::int64_t, 2> timespec{};
        auto timespec_bytes = std::as_writable_bytes(std::span(timespec));
        if (!context->memory().read(timeout_address, timespec_bytes, message) ||
            timespec[0] < 0 || timespec[1] < 0 || timespec[1] >= 1'000'000'000 ||
            timespec[0] > std::numeric_limits<std::int64_t>::max() / 1'000'000'000) {
            set_guest_errno(err_invalid); return -1;
        }
        timeout = std::chrono::seconds(timespec[0]) + std::chrono::nanoseconds(timespec[1]);
    }
    if (!context->aio().wait(controls, false, timeout, message)) {
        const bool timed_out = message.find("tempo limite") != std::string::npos;
        set_guest_errno(timed_out ? err_again : err_invalid);
        return -1;
    }
    return 0;
}

} // namespace

bool register_native_aio_imports(ImportResolver& resolver, std::string& error) {
    return resolver.register_function("libkernel", "libkernel", "phnjLKz4njM",
                                      &guest_aio_cancel, error) &&
           resolver.register_function("libkernel", "libkernel", "j64iXjsjnCY",
                                      &guest_aio_fsync, error) &&
           resolver.register_function("libkernel", "libkernel", "kaLFzWxqkFY",
                                      &guest_aio_read, error) &&
           resolver.register_function("libkernel", "libkernel", "52r68vPvrBA",
                                      &guest_aio_suspend, error) &&
           resolver.register_function("libkernel", "libkernel", "IiofFKEgSew",
                                      &guest_aio_write, error);
}

} // namespace nba16
