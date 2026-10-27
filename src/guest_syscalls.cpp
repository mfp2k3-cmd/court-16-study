#include "guest_syscalls.h"
#include "ps4_abi_errors.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <type_traits>
#include <vector>

namespace nba16 {
namespace {

static_assert(ps4_error(Ps4Errno::NoSuchFileOrDirectory) ==
              std::bit_cast<std::int32_t>(0x80020002U));
static_assert(ps4_error(Ps4Errno::InvalidArgument) ==
              std::bit_cast<std::int32_t>(0x80020016U));

Ps4Errno to_ps4_errno(VfsErrorCode code) {
    switch (code) {
    case VfsErrorCode::None: return Ps4Errno::Success;
    case VfsErrorCode::InvalidPath:
    case VfsErrorCode::InvalidArgument: return Ps4Errno::InvalidArgument;
    case VfsErrorCode::NotFound: return Ps4Errno::NoSuchFileOrDirectory;
    case VfsErrorCode::PermissionDenied: return Ps4Errno::AccessDenied;
    case VfsErrorCode::AlreadyExists: return Ps4Errno::AlreadyExists;
    case VfsErrorCode::NotDirectory: return Ps4Errno::NotDirectory;
    case VfsErrorCode::IsDirectory: return Ps4Errno::IsDirectory;
    case VfsErrorCode::TooManyFiles: return Ps4Errno::TooManyOpenFiles;
    case VfsErrorCode::NoSpace: return Ps4Errno::NoSpace;
    case VfsErrorCode::ReadOnly: return Ps4Errno::ReadOnlyFilesystem;
    case VfsErrorCode::NameTooLong: return Ps4Errno::NameTooLong;
    case VfsErrorCode::BadDescriptor: return Ps4Errno::BadFileDescriptor;
    case VfsErrorCode::Io: return Ps4Errno::Io;
    }
    return Ps4Errno::Io;
}

constexpr std::int32_t open_access_mask = 0x0003;
constexpr std::int32_t open_read_only = 0x0000;
constexpr std::int32_t open_write_only = 0x0001;
constexpr std::int32_t open_read_write = 0x0002;
constexpr std::int32_t open_append = 0x0008;
constexpr std::int32_t open_create = 0x0200;
constexpr std::int32_t open_truncate = 0x0400;
constexpr std::int32_t open_exclusive = 0x0800;

struct Ps4TimespecWire {
    std::int64_t seconds{};
    std::int64_t nanoseconds{};
};

struct Ps4StatWire {
    std::uint32_t device{};
    std::uint32_t inode{};
    std::uint16_t mode{};
    std::uint16_t links{};
    std::uint32_t uid{};
    std::uint32_t gid{};
    std::uint32_t rdevice{};
    Ps4TimespecWire access_time{};
    Ps4TimespecWire modify_time{};
    Ps4TimespecWire change_time{};
    std::int64_t size{};
    std::int64_t blocks{};
    std::uint32_t block_size{};
    std::uint32_t flags{};
    std::uint32_t generation{};
    std::int32_t spare{};
    Ps4TimespecWire birth_time{};
};

struct Ps4StatfsWire {
    std::uint32_t version{};
    std::uint32_t type{};
    std::uint64_t flags{};
    std::uint64_t block_size{};
    std::uint64_t io_size{};
    std::uint64_t blocks{};
    std::uint64_t blocks_free{};
    std::int64_t blocks_available{};
    std::uint64_t files{};
    std::int64_t files_free{};
    std::uint64_t sync_writes{};
    std::uint64_t async_writes{};
    std::uint64_t sync_reads{};
    std::uint64_t async_reads{};
    std::uint64_t spare[10]{};
    std::uint32_t name_max{};
    std::uint32_t owner{};
    std::int32_t fsid[2]{};
    char char_spare[80]{};
    char filesystem_type[16]{};
    char mounted_from[88]{};
    char mounted_on[88]{};
};

static_assert(std::is_trivially_copyable_v<Ps4StatWire>);
static_assert(sizeof(Ps4TimespecWire) == 16);
static_assert(sizeof(Ps4StatWire) == 120);
static_assert(offsetof(Ps4StatWire, access_time) == 24);
static_assert(offsetof(Ps4StatWire, size) == 72);
static_assert(offsetof(Ps4StatWire, birth_time) == 104);
static_assert(std::is_trivially_copyable_v<Ps4StatfsWire>);
static_assert(sizeof(Ps4StatfsWire) == 472);
static_assert(offsetof(Ps4StatfsWire, name_max) == 184);
static_assert(offsetof(Ps4StatfsWire, filesystem_type) == 280);
static_assert(offsetof(Ps4StatfsWire, mounted_from) == 296);
static_assert(offsetof(Ps4StatfsWire, mounted_on) == 384);

bool read_guest_path(const GuestMemoryAccess& memory, std::uint64_t address,
                     std::string& path, std::string& error,
                     Ps4Errno* syscall_error = nullptr) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    constexpr std::size_t maximum_path_length = 4096;
    path.clear();
    path.reserve(128);
    for (std::size_t index = 0; index < maximum_path_length; ++index) {
        if (index > std::numeric_limits<std::uint64_t>::max() - address) {
            error = "Caminho convidado excede o espaço de endereços.";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            return false;
        }
        std::byte character{};
        if (!memory.read( address + index, std::span<std::byte>(&character, 1), error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            return false;
        }
        const auto value = std::to_integer<unsigned char>(character);
        if (value == 0) {
            if (path.empty()) {
                error = "Caminho convidado vazio.";
                if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
                return false;
            }
            return true;
        }
        path.push_back(static_cast<char>(value));
    }
    error = "Caminho convidado excede o limite de 4096 bytes.";
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::NameTooLong;
    return false;
}

bool write_guest_statfs(const VirtualFileSystem& vfs,
                        const GuestMemoryAccess& memory,
                        std::string_view path, std::uint64_t destination,
                        std::string& error, Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    VfsFilesystemStats stats{};
    VfsErrorCode failure{};
    if (!vfs.stat_filesystem(path, stats, error, &failure)) {
        if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
        return false;
    }
    constexpr std::uint64_t block_size = 4096;
    Ps4StatfsWire wire{};
    wire.version = 0x20030518;
    wire.flags = stats.mounted_on == "/app0" || stats.mounted_on == "/download0" ? 1U : 0U;
    wire.block_size = block_size;
    wire.io_size = block_size;
    wire.blocks = stats.capacity / block_size;
    wire.blocks_free = stats.free_bytes / block_size;
    wire.blocks_available = static_cast<std::int64_t>(stats.available_bytes / block_size);
    wire.files = stats.file_count;
    wire.name_max = 255;
    const auto copy_text = [](char* output, std::size_t capacity, const std::string& input) {
        const auto amount = std::min(capacity - 1, input.size());
        std::memcpy(output, input.data(), amount);
    };
    copy_text(wire.filesystem_type, sizeof(wire.filesystem_type), stats.filesystem_type);
    copy_text(wire.mounted_from, sizeof(wire.mounted_from), stats.mounted_from);
    copy_text(wire.mounted_on, sizeof(wire.mounted_on), stats.mounted_on);
    if (!memory.write(destination, std::as_bytes(std::span(&wire, 1)), error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
        return false;
    }
    return true;
}

bool write_guest_stat(const GuestMemoryAccess& memory, std::uint64_t guest_address,
                      const VfsMetadata& metadata, std::string& error) {
    if (metadata.size > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        error = "tamanho não representável no stat PS4";
        return false;
    }
    Ps4StatWire stat{};
    const bool directory = metadata.kind == VfsMetadata::Kind::Directory;
    stat.mode = static_cast<std::uint16_t>((directory ? 0040000 : 0100000) | 0777);
    stat.links = directory ? 2 : 1;
    stat.size = static_cast<std::int64_t>(metadata.size);
    stat.blocks = static_cast<std::int64_t>((metadata.size + 511U) / 512U);
    stat.block_size = 512;
    return memory.write( guest_address,
                              std::as_bytes(std::span<const Ps4StatWire>(&stat, 1)), error);
}

int open_guest_path(VirtualFileSystem& vfs, VfsDescriptorTable& descriptors,
                    std::string_view path, std::int32_t flags,
                    std::string& error, Ps4Errno* syscall_error) {
    static std::atomic<unsigned> trace_sequence{};
    const bool trace_open = std::getenv("NBA16_TRACE_FS") != nullptr;
    const auto finish = [&](int descriptor) {
        if (trace_open) {
            const auto sequence = trace_sequence.fetch_add(1, std::memory_order_relaxed);
            if (sequence < 512) {
                const auto error_code = syscall_error == nullptr
                    ? 0 : static_cast<int>(*syscall_error);
                std::fprintf(stderr, "FS open[%u] path='%.*s' flags=0x%x -> fd=%d errno=%d detail='%s'\n",
                    sequence, static_cast<int>(path.size()), path.data(), flags,
                    descriptor, error_code, error.c_str());
            }
        }
        return descriptor;
    };
    const auto access = flags & open_access_mask;
    const auto supported = open_access_mask | open_append | open_create | open_truncate | open_exclusive;
    if ((access != open_read_only && access != open_write_only && access != open_read_write) ||
        (flags & ~supported) != 0 ||
        ((flags & open_truncate) != 0 && access == open_read_only) ||
        ((flags & open_append) != 0 && access == open_read_only) ||
        ((flags & open_exclusive) != 0 && (flags & open_create) == 0)) {
        error = "flags de open inválidas ou ainda não suportadas";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
        return finish(-1);
    }
    if (path.size() > 255) {
        error = "caminho excede o limite Orbis de 255 bytes";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::NameTooLong;
        return finish(-1);
    }
    if (path == "/dev/gc") {
        if (access != open_read_write || (flags & (open_append | open_create |
                open_truncate | open_exclusive)) != 0) {
            error = "flags incompatíveis para abertura do dispositivo GNM";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
            return finish(-1);
        }
        VfsErrorCode failure{};
        const int descriptor = descriptors.open_device(path, error, &failure);
        if (descriptor < 0 && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
        return finish(descriptor);
    }
    if (access == open_read_only) {
        if ((flags & (open_create | open_exclusive)) != 0) {
            error = "criação com acesso somente leitura não está implementada";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
            return finish(-1);
        }
        VfsErrorCode failure{};
        const int descriptor = descriptors.open_readonly(vfs, path, error, &failure);
        if (descriptor < 0 && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
        return finish(descriptor);
    }
    if (!path.starts_with("/savedata0/")) {
        error = "open para gravação só é permitido em /savedata0";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::ReadOnlyFilesystem;
        return finish(-1);
    }
    VfsErrorCode failure{};
    const int descriptor = descriptors.open_savedata(vfs, path, (flags & open_create) != 0,
        (flags & open_truncate) != 0, (flags & open_exclusive) != 0,
        (flags & open_append) != 0, access == open_read_write, error, &failure);
    if (descriptor < 0 && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
    return finish(descriptor);
}

bool resolve_at_path(const VirtualFileSystem& vfs,
                     const VfsDescriptorTable& descriptors,
                     int directory_descriptor,
                     std::string_view requested_path, std::string& resolved,
                     std::string& error, Ps4Errno* syscall_error) {
    constexpr int at_current_working_directory = -100;
    std::string base = "/app0";
    if (!requested_path.empty() && requested_path.front() != '/' &&
        requested_path.front() != '\\' && directory_descriptor != at_current_working_directory) {
        VfsMetadata metadata{};
        if (!descriptors.stat_descriptor(directory_descriptor, metadata, error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadFileDescriptor;
            return false;
        }
        if (metadata.kind != VfsMetadata::Kind::Directory) {
            error = "descritor-base não é um diretório";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::NotDirectory;
            return false;
        }
        if (!descriptors.descriptor_path(directory_descriptor, base, error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadFileDescriptor;
            return false;
        }
    }
    if (!vfs.resolve_guest_path(base, requested_path, resolved, error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
        return false;
    }
    return true;
}

} // namespace

int guest_open_readonly(VirtualFileSystem& vfs,
                        VfsDescriptorTable& descriptors,
                        const GuestMemoryAccess& memory,
                        std::uint64_t guest_path,
                        std::string& error) {
    std::string path;
    if (!read_guest_path(memory, guest_path, path, error)) {
        return -1;
    }
    return descriptors.open_readonly(vfs, path, error);
}

int guest_open_savedata(VirtualFileSystem& vfs,
                        VfsDescriptorTable& descriptors,
                        const GuestMemoryAccess& memory,
                        std::uint64_t guest_path,
                        bool create_if_missing,
                        bool truncate_existing,
                        bool exclusive_create,
                        bool append,
                        std::string& error) {
    std::string path;
    if (!read_guest_path(memory, guest_path, path, error)) {
        return -1;
    }
    return descriptors.open_savedata(vfs, path, create_if_missing, truncate_existing,
                                     exclusive_create, append, true, error);
}

int guest_open(VirtualFileSystem& vfs,
               VfsDescriptorTable& descriptors,
               const GuestMemoryAccess& memory,
               std::uint64_t guest_path,
               std::int32_t flags,
               std::uint16_t mode,
               std::string& error,
               Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    (void)mode;
    std::string path;
    Ps4Errno path_error{};
    if (!read_guest_path(memory, guest_path, path, error, &path_error)) {
        if (syscall_error != nullptr) *syscall_error = path_error;
        return -1;
    }
    return open_guest_path(vfs, descriptors, path, flags, error, syscall_error);
}

int guest_openat(VirtualFileSystem& vfs, VfsDescriptorTable& descriptors,
                 const GuestMemoryAccess& memory, int directory_descriptor,
                 std::uint64_t guest_path, std::int32_t flags,
                 std::uint16_t mode, std::string& error,
                 Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    (void)mode;
    std::string requested;
    Ps4Errno path_error{};
    if (!read_guest_path(memory, guest_path, requested, error, &path_error)) {
        if (syscall_error != nullptr) *syscall_error = path_error;
        return -1;
    }
    std::string resolved;
    if (!resolve_at_path(vfs, descriptors, directory_descriptor, requested,
                         resolved, error, syscall_error)) return -1;
    return open_guest_path(vfs, descriptors, resolved, flags, error, syscall_error);
}

bool guest_mkdir_savedata(VirtualFileSystem& vfs,
                          const GuestMemoryAccess& memory,
                          std::uint64_t guest_path,
                          std::string& error,
                          Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    std::string path;
    Ps4Errno path_error{};
    if (!read_guest_path(memory, guest_path, path, error, &path_error)) {
        if (syscall_error != nullptr) *syscall_error = path_error;
        return false;
    }
    VfsErrorCode failure{};
    const bool success = vfs.create_savedata_directory(path, error, &failure);
    if (!success && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
    return success;
}

bool guest_seek(VfsDescriptorTable& descriptors, int descriptor,
                std::int64_t offset, int whence, std::uint64_t& new_offset,
                std::string& error, Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    VfsErrorCode failure{};
    const bool success = descriptors.seek(descriptor, offset, whence, new_offset, error, &failure);
    if (!success && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
    return success;
}

bool guest_close(VfsDescriptorTable& descriptors, int descriptor, std::string& error,
                 Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    VfsErrorCode failure{};
    const bool success = descriptors.close(descriptor, error, &failure);
    if (!success && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
    return success;
}

bool guest_stat_path(const VirtualFileSystem& vfs,
                     const GuestMemoryAccess& memory,
                     std::uint64_t guest_path,
                     VfsMetadata& metadata,
                     std::string& error) {
    std::string path;
    return read_guest_path(memory, guest_path, path, error) &&
           vfs.stat_path(path, metadata, error);
}

bool guest_fstat(const VfsDescriptorTable& descriptors,
                 int descriptor,
                 VfsMetadata& metadata,
                 std::string& error) {
    return descriptors.stat_descriptor(descriptor, metadata, error);
}

bool guest_stat_to_memory(const VirtualFileSystem& vfs,
                          GuestMemoryAccess& memory,
                          std::uint64_t guest_path,
                          std::uint64_t guest_stat,
                          std::string& error,
                          Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    VfsMetadata metadata;
    std::string path;
    Ps4Errno path_error{};
    if (!read_guest_path(memory, guest_path, path, error, &path_error)) {
        if (syscall_error != nullptr) *syscall_error = path_error;
        return false;
    }
    VfsErrorCode failure{};
    if (!vfs.stat_path(path, metadata, error, &failure)) {
        if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
        return false;
    }
    if (!write_guest_stat(memory, guest_stat, metadata, error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
        return false;
    }
    return true;
}

bool guest_fstatat_to_memory(const VirtualFileSystem& vfs,
                             const VfsDescriptorTable& descriptors,
                             const GuestMemoryAccess& memory,
                             int directory_descriptor,
                             std::uint64_t guest_path,
                             std::uint64_t guest_stat, int flags,
                             std::string& error,
                             Ps4Errno* syscall_error) {
    constexpr int at_symlink_nofollow = 0x200;
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    if ((flags & ~at_symlink_nofollow) != 0) {
        error = "flags fstatat não suportadas";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
        return false;
    }
    std::string requested;
    Ps4Errno path_error{};
    if (!read_guest_path(memory, guest_path, requested, error, &path_error)) {
        if (syscall_error != nullptr) *syscall_error = path_error;
        return false;
    }
    std::string resolved;
    if (!resolve_at_path(vfs, descriptors, directory_descriptor, requested,
                         resolved, error, syscall_error)) return false;
    VfsMetadata metadata{};
    VfsErrorCode failure{};
    if (!vfs.stat_path(resolved, metadata, error, &failure)) {
        VfsFile file;
        std::string lookup_error;
        if (vfs.open_file(resolved, file, lookup_error)) {
            metadata.kind = VfsMetadata::Kind::RegularFile;
            metadata.size = file.size;
        } else {
            VfsDirectory directory;
            if (vfs.open_directory(resolved, directory, lookup_error)) {
                metadata.kind = VfsMetadata::Kind::Directory;
                metadata.size = 0;
            } else {
                if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
                return false;
            }
        }
    }
    if (!write_guest_stat(memory, guest_stat, metadata, error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
        return false;
    }
    error.clear();
    return true;
}

bool guest_fstat_to_memory(const VfsDescriptorTable& descriptors,
                           GuestMemoryAccess& memory,
                           int descriptor,
                           std::uint64_t guest_stat,
                           std::string& error,
                           Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    VfsMetadata metadata;
    VfsErrorCode failure{};
    if (!descriptors.stat_descriptor(descriptor, metadata, error, &failure)) {
        if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
        return false;
    }
    if (!write_guest_stat(memory, guest_stat, metadata, error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
        return false;
    }
    return true;
}

bool guest_ftruncate(const VirtualFileSystem& vfs,
                     VfsDescriptorTable& descriptors,
                     int descriptor,
                     std::int64_t size,
                     std::string& error,
                     Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    if (size < 0) {
        error = "tamanho negativo em ftruncate";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
        return false;
    }
    VfsErrorCode failure{};
    const bool success = descriptors.truncate(vfs, descriptor, static_cast<std::uint64_t>(size), error, &failure);
    if (!success && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
    return success;
}

bool guest_fsync(const VirtualFileSystem& vfs,
                 const VfsDescriptorTable& descriptors,
                 int descriptor,
                 std::string& error,
                 Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    VfsErrorCode failure{};
    const bool success = descriptors.sync(vfs, descriptor, error, &failure);
    if (!success && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
    return success;
}

bool guest_statfs(const VirtualFileSystem& vfs, const GuestMemoryAccess& memory,
                  std::uint64_t guest_path, std::uint64_t guest_statfs,
                  std::string& error, Ps4Errno* syscall_error) {
    std::string path;
    if (!read_guest_path(memory, guest_path, path, error, syscall_error)) return false;
    return write_guest_statfs(vfs, memory, path, guest_statfs, error, syscall_error);
}

bool guest_fstatfs(const VirtualFileSystem& vfs,
                   const VfsDescriptorTable& descriptors,
                   const GuestMemoryAccess& memory, int descriptor,
                   std::uint64_t guest_statfs, std::string& error,
                   Ps4Errno* syscall_error) {
    std::string path;
    if (!descriptors.descriptor_path(descriptor, path, error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadFileDescriptor;
        return false;
    }
    return write_guest_statfs(vfs, memory, path, guest_statfs, error, syscall_error);
}

bool guest_pathconf(const VirtualFileSystem& vfs,
                    const GuestMemoryAccess& memory,
                    std::uint64_t guest_path, int name,
                    std::int64_t& value, std::string& error,
                    Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    std::string path;
    if (!read_guest_path(memory, guest_path, path, error, syscall_error)) return false;
    VfsFilesystemStats stats{};
    VfsErrorCode failure{};
    if (!vfs.stat_filesystem(path, stats, error, &failure)) {
        if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
        return false;
    }
    switch (name) {
    case 1: value = 1; break;       // _PC_LINK_MAX: hard links are unsupported.
    case 4: value = 255; break;     // _PC_NAME_MAX
    case 5: value = 4096; break;    // _PC_PATH_MAX
    case 6: value = 512; break;     // _PC_PIPE_BUF
    case 7: value = 1; break;       // _PC_CHOWN_RESTRICTED
    case 8: value = 1; break;       // _PC_NO_TRUNC
    default:
        error = "opção pathconf não implementada pelo VFS";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
        return false;
    }
    error.clear();
    return true;
}

bool guest_readlink(const VirtualFileSystem& vfs,
                    const GuestMemoryAccess& memory,
                    std::uint64_t guest_path, std::uint64_t guest_buffer,
                    std::size_t buffer_size, std::size_t& bytes_read,
                    std::string& error, Ps4Errno* syscall_error) {
    bytes_read = 0;
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    std::string path;
    if (!read_guest_path(memory, guest_path, path, error, syscall_error)) return false;
    if (buffer_size != 0 && !memory.validate(guest_buffer, buffer_size, true, error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
        return false;
    }
    VfsFilesystemStats stats{};
    VfsErrorCode failure{};
    if (!vfs.stat_filesystem(path, stats, error, &failure)) {
        if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
        return false;
    }
    error = "o caminho virtual existe, mas não é um link simbólico";
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
    return false;
}

bool guest_unlink_savedata(const VirtualFileSystem& vfs,
                           const GuestMemoryAccess& memory,
                           std::uint64_t guest_path,
                           std::string& error,
                           Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    std::string path;
    Ps4Errno path_error{};
    if (!read_guest_path(memory, guest_path, path, error, &path_error)) {
        if (syscall_error != nullptr) *syscall_error = path_error;
        return false;
    }
    VfsErrorCode failure{};
    const bool success = vfs.remove_savedata_file(path, error, &failure);
    if (!success && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
    return success;
}

bool guest_rename_savedata(const VirtualFileSystem& vfs,
                           const GuestMemoryAccess& memory,
                           std::uint64_t guest_from_path,
                           std::uint64_t guest_to_path,
                           std::string& error,
                           Ps4Errno* syscall_error) {
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    std::string from_path;
    std::string to_path;
    Ps4Errno path_error{};
    if (!read_guest_path(memory, guest_from_path, from_path, error, &path_error) ||
        !read_guest_path(memory, guest_to_path, to_path, error, &path_error)) {
        if (syscall_error != nullptr) *syscall_error = path_error;
        return false;
    }
    VfsErrorCode failure{};
    const bool success = vfs.rename_savedata_file(from_path, to_path, error, &failure);
    if (!success && syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
    return success;
}

bool guest_getdents(VirtualFileSystem& vfs,
                    VfsDescriptorTable& descriptors,
                    GuestMemoryAccess& memory,
                    int descriptor,
                    std::uint64_t guest_buffer,
                    std::size_t buffer_size,
                    std::size_t& bytes_written,
                    std::string& error,
                    Ps4Errno* syscall_error) {
    bytes_written = 0;
    error.clear();
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    if (buffer_size == 0) {
        return true;
    }
    constexpr std::size_t staging_size = 64U * 1024U;
    std::vector<std::byte> staging;
    try {
        staging.resize(std::min(buffer_size, staging_size));
    } catch (const std::bad_alloc&) {
        error = "Memória temporária insuficiente para getdents.";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::OutOfMemory;
        return false;
    }

    while (bytes_written < buffer_size) {
        const auto remaining = buffer_size - bytes_written;
        const auto chunk_size = std::min(remaining, staging.size());
        if (bytes_written > std::numeric_limits<std::uint64_t>::max() - guest_buffer) {
            error = "Intervalo getdents excede o espaço de endereços convidado.";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_written != 0) {
                error.clear();
                if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
                return true;
            }
            return false;
        }
        if (!memory.validate( guest_buffer + bytes_written,
                                          chunk_size, true, error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_written != 0) {
                error.clear();
                if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
                return true;
            }
            return false;
        }
        std::size_t chunk_written = 0;
        VfsErrorCode failure{};
        if (!descriptors.getdents(vfs, descriptor,
                                  std::span<std::byte>(staging.data(), chunk_size),
                                  chunk_written, error, &failure)) {
            if (bytes_written != 0 && chunk_written == 0 &&
                error == "buffer getdents menor que o próximo registro completo") {
                error.clear();
                if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
                return true;
            }
            if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
            return false;
        }
        if (chunk_written == 0) {
            break;
        }
        if (!memory.write( guest_buffer + bytes_written,
                                std::span<const std::byte>(staging.data(), chunk_written), error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_written != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        bytes_written += chunk_written;
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
        if (chunk_written < chunk_size && chunk_size == remaining) {
            break;
        }
    }
    return true;
}

bool guest_read(VirtualFileSystem& vfs,
                VfsDescriptorTable& descriptors,
                GuestMemoryAccess& memory,
                int descriptor,
                std::uint64_t guest_buffer,
                std::size_t buffer_size,
                std::size_t& bytes_read,
                std::string& error,
                Ps4Errno* syscall_error) {
    bytes_read = 0;
    error.clear();
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    if (buffer_size == 0) {
        return true;
    }
    constexpr std::size_t staging_size = 64U * 1024U;
    std::vector<std::byte> staging;
    try {
        staging.resize(std::min(buffer_size, staging_size));
    } catch (const std::bad_alloc&) {
        error = "Memória temporária insuficiente para read.";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::OutOfMemory;
        return false;
    }
    while (bytes_read < buffer_size) {
        const auto remaining = buffer_size - bytes_read;
        const auto chunk_size = std::min(remaining, staging.size());
        if (bytes_read > std::numeric_limits<std::uint64_t>::max() - guest_buffer) {
            error = "Intervalo read excede o espaço de endereços convidado.";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_read != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        if (!memory.validate( guest_buffer + bytes_read,
                                          chunk_size, true, error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_read != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        std::size_t chunk_read = 0;
        VfsErrorCode failure{};
        if (!descriptors.read(vfs, descriptor, std::span<std::byte>(staging.data(), chunk_size),
                              chunk_read, error, &failure)) {
            if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
            if (bytes_read != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        if (chunk_read == 0) {
            break;
        }
        if (!memory.write( guest_buffer + bytes_read,
                                std::span<const std::byte>(staging.data(), chunk_read), error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_read != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        bytes_read += chunk_read;
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
        if (chunk_read < chunk_size) {
            break;
        }
    }
    return true;
}

bool guest_write(VirtualFileSystem& vfs,
                 VfsDescriptorTable& descriptors,
                 GuestMemoryAccess& memory,
                 int descriptor,
                 std::uint64_t guest_buffer,
                 std::size_t buffer_size,
                 std::size_t& bytes_written,
                 std::string& error,
                 Ps4Errno* syscall_error) {
    bytes_written = 0;
    error.clear();
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    if (buffer_size == 0) {
        return true;
    }
    constexpr std::size_t staging_size = 64U * 1024U;
    std::vector<std::byte> staging;
    try {
        staging.resize(std::min(buffer_size, staging_size));
    } catch (const std::bad_alloc&) {
        error = "Memória temporária insuficiente para write.";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::OutOfMemory;
        return false;
    }
    while (bytes_written < buffer_size) {
        const auto remaining = buffer_size - bytes_written;
        const auto chunk_size = std::min(remaining, staging.size());
        if (bytes_written > std::numeric_limits<std::uint64_t>::max() - guest_buffer) {
            error = "Intervalo write excede o espaço de endereços convidado.";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_written != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        if (!memory.validate( guest_buffer + bytes_written,
                                          chunk_size, false, error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_written != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        if (!memory.read( guest_buffer + bytes_written,
                               std::span<std::byte>(staging.data(), chunk_size), error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_written != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        std::size_t chunk_written = 0;
        VfsErrorCode failure{};
        if (!descriptors.write(vfs, descriptor,
                               std::span<const std::byte>(staging.data(), chunk_size),
                               chunk_written, error, &failure)) {
            if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
            if (bytes_written != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; return true; }
            return false;
        }
        bytes_written += chunk_written;
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
        if (chunk_written < chunk_size) {
            break;
        }
    }
    return true;
}

bool guest_pread(VirtualFileSystem& vfs,
                 VfsDescriptorTable& descriptors,
                 const GuestMemoryAccess& memory,
                 int descriptor,
                 std::uint64_t guest_buffer,
                 std::size_t buffer_size,
                 std::int64_t offset,
                 std::size_t& bytes_read,
                 std::string& error,
                 Ps4Errno* syscall_error) {
    bytes_read = 0;
    error.clear();
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    if (offset < 0) {
        error = "offset negativo em pread";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
        return false;
    }
    if (buffer_size == 0) return true;
    if (!memory.validate( guest_buffer, buffer_size, true, error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
        return false;
    }
    constexpr std::size_t staging_size = 64U * 1024U;
    std::vector<std::byte> staging;
    try {
        staging.resize(std::min(buffer_size, staging_size));
    } catch (const std::bad_alloc&) {
        error = "Memória temporária insuficiente para pread.";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::OutOfMemory;
        return false;
    }
    const auto unsigned_offset = static_cast<std::uint64_t>(offset);
    while (bytes_read < buffer_size) {
        if (bytes_read > std::numeric_limits<std::uint64_t>::max() - guest_buffer ||
            bytes_read > std::numeric_limits<std::uint64_t>::max() - unsigned_offset) {
            error = "Intervalo pread excede o espaço de endereços.";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_read != 0 && syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
            return bytes_read != 0;
        }
        const auto amount = std::min(buffer_size - bytes_read, staging.size());
        std::size_t chunk_read = 0;
        VfsErrorCode failure{};
        if (!descriptors.pread(vfs, descriptor, unsigned_offset + bytes_read,
                              std::span<std::byte>(staging.data(), amount), chunk_read, error,
                              &failure)) {
            if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
            if (bytes_read != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; }
            return bytes_read != 0;
        }
        if (chunk_read == 0) break;
        if (!memory.write( guest_buffer + bytes_read,
                                std::span<const std::byte>(staging.data(), chunk_read), error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_read != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; }
            return bytes_read != 0;
        }
        bytes_read += chunk_read;
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
        if (chunk_read < amount) break;
    }
    return true;
}

bool guest_pwrite(VirtualFileSystem& vfs,
                  VfsDescriptorTable& descriptors,
                  const GuestMemoryAccess& memory,
                  int descriptor,
                  std::uint64_t guest_buffer,
                  std::size_t buffer_size,
                  std::int64_t offset,
                  std::size_t& bytes_written,
                  std::string& error,
                  Ps4Errno* syscall_error) {
    bytes_written = 0;
    error.clear();
    if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
    if (offset < 0) {
        error = "offset negativo em pwrite";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::InvalidArgument;
        return false;
    }
    if (buffer_size == 0) return true;
    if (!memory.validate( guest_buffer, buffer_size, false, error)) {
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
        return false;
    }
    constexpr std::size_t staging_size = 64U * 1024U;
    std::vector<std::byte> staging;
    try {
        staging.resize(std::min(buffer_size, staging_size));
    } catch (const std::bad_alloc&) {
        error = "Memória temporária insuficiente para pwrite.";
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::OutOfMemory;
        return false;
    }
    const auto unsigned_offset = static_cast<std::uint64_t>(offset);
    while (bytes_written < buffer_size) {
        if (bytes_written > std::numeric_limits<std::uint64_t>::max() - guest_buffer ||
            bytes_written > std::numeric_limits<std::uint64_t>::max() - unsigned_offset) {
            error = "Intervalo pwrite excede o espaço de endereços.";
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_written != 0 && syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
            return bytes_written != 0;
        }
        const auto amount = std::min(buffer_size - bytes_written, staging.size());
        if (!memory.read( guest_buffer + bytes_written,
                               std::span<std::byte>(staging.data(), amount), error)) {
            if (syscall_error != nullptr) *syscall_error = Ps4Errno::BadAddress;
            if (bytes_written != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; }
            return bytes_written != 0;
        }
        std::size_t chunk_written = 0;
        VfsErrorCode failure{};
        if (!descriptors.pwrite(vfs, descriptor, unsigned_offset + bytes_written,
                                std::span<const std::byte>(staging.data(), amount),
                                chunk_written, error, &failure)) {
            if (syscall_error != nullptr) *syscall_error = to_ps4_errno(failure);
            if (bytes_written != 0) { error.clear(); if (syscall_error) *syscall_error = Ps4Errno::Success; }
            return bytes_written != 0;
        }
        bytes_written += chunk_written;
        if (syscall_error != nullptr) *syscall_error = Ps4Errno::Success;
        if (chunk_written < amount) break;
    }
    return true;
}

} // namespace nba16
