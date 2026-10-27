#pragma once

#include <bit>
#include <cstdint>

namespace nba16 {

// Orbis libkernel error numbers use 0x80020000 + the FreeBSD errno value.
// Keep the guest ABI values explicit; host errno numbering is not portable.
enum class Ps4Errno : std::uint32_t {
    Success = 0,
    OperationNotPermitted = 1,
    NoSuchFileOrDirectory = 2,
    Io = 5,
    OutOfMemory = 12,
    BadFileDescriptor = 9,
    InProgress = 36,
    TryAgain = 35,
    AccessDenied = 13,
    BadAddress = 14,
    Busy = 16,
    Canceled = 85,
    AlreadyExists = 17,
    NotDirectory = 20,
    IsDirectory = 21,
    InvalidArgument = 22,
    TooManyOpenFiles = 24,
    NoSpace = 28,
    ReadOnlyFilesystem = 30,
    TooManySymbolicLinks = 62,
    NameTooLong = 63,
    DirectoryNotEmpty = 66,
};

constexpr std::int32_t ps4_error(Ps4Errno error) noexcept {
    if (error == Ps4Errno::Success) return 0;
    return std::bit_cast<std::int32_t>(0x80020000U + static_cast<std::uint32_t>(error));
}

} // namespace nba16
