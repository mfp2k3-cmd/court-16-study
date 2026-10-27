#pragma once

#include "guest_image_map.h"
#include "guest_image_memory.h"
#include "ps4_abi_errors.h"
#include "vfs.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace nba16 {

int guest_open_readonly(VirtualFileSystem& vfs,
                        VfsDescriptorTable& descriptors,
                        const GuestMemoryAccess& memory,
                        std::uint64_t guest_path,
                        std::string& error);
int guest_open_savedata(VirtualFileSystem& vfs,
                       VfsDescriptorTable& descriptors,
                       const GuestMemoryAccess& memory,
                       std::uint64_t guest_path,
                       bool create_if_missing,
                       bool truncate_existing,
                       bool exclusive_create,
                       bool append,
                       std::string& error);
int guest_open(VirtualFileSystem& vfs,
               VfsDescriptorTable& descriptors,
               const GuestMemoryAccess& memory,
               std::uint64_t guest_path,
               std::int32_t flags,
               std::uint16_t mode,
               std::string& error,
               Ps4Errno* syscall_error = nullptr);
int guest_openat(VirtualFileSystem& vfs,
                 VfsDescriptorTable& descriptors,
                 const GuestMemoryAccess& memory,
                 int directory_descriptor, std::uint64_t guest_path,
                 std::int32_t flags, std::uint16_t mode,
                 std::string& error,
                 Ps4Errno* syscall_error = nullptr);
bool guest_mkdir_savedata(VirtualFileSystem& vfs,
                          const GuestMemoryAccess& memory,
                          std::uint64_t guest_path,
                          std::string& error,
                          Ps4Errno* syscall_error = nullptr);
bool guest_seek(VfsDescriptorTable& descriptors, int descriptor,
                std::int64_t offset, int whence, std::uint64_t& new_offset,
                std::string& error, Ps4Errno* syscall_error = nullptr);
bool guest_close(VfsDescriptorTable& descriptors, int descriptor,
                 std::string& error, Ps4Errno* syscall_error = nullptr);
bool guest_stat_path(const VirtualFileSystem& vfs,
                     const GuestMemoryAccess& memory,
                     std::uint64_t guest_path,
                     VfsMetadata& metadata,
                     std::string& error);
bool guest_fstat(const VfsDescriptorTable& descriptors,
                 int descriptor,
                 VfsMetadata& metadata,
                 std::string& error);
bool guest_stat_to_memory(const VirtualFileSystem& vfs,
                          const GuestMemoryAccess& memory,
                          std::uint64_t guest_path,
                          std::uint64_t guest_stat,
                          std::string& error,
                          Ps4Errno* syscall_error = nullptr);
bool guest_fstatat_to_memory(const VirtualFileSystem& vfs,
                             const VfsDescriptorTable& descriptors,
                             const GuestMemoryAccess& memory,
                             int directory_descriptor,
                             std::uint64_t guest_path,
                             std::uint64_t guest_stat, int flags,
                             std::string& error,
                             Ps4Errno* syscall_error = nullptr);
bool guest_fstat_to_memory(const VfsDescriptorTable& descriptors,
                           GuestMemoryAccess& memory,
                           int descriptor,
                           std::uint64_t guest_stat,
                           std::string& error,
                           Ps4Errno* syscall_error = nullptr);
bool guest_ftruncate(const VirtualFileSystem& vfs,
                     VfsDescriptorTable& descriptors,
                     int descriptor,
                     std::int64_t size,
                     std::string& error,
                     Ps4Errno* syscall_error = nullptr);
bool guest_fsync(const VirtualFileSystem& vfs,
                 const VfsDescriptorTable& descriptors,
                 int descriptor,
                 std::string& error,
                 Ps4Errno* syscall_error = nullptr);
bool guest_statfs(const VirtualFileSystem& vfs, const GuestMemoryAccess& memory,
                  std::uint64_t guest_path, std::uint64_t guest_statfs,
                  std::string& error, Ps4Errno* syscall_error = nullptr);
bool guest_fstatfs(const VirtualFileSystem& vfs,
                   const VfsDescriptorTable& descriptors,
                   const GuestMemoryAccess& memory, int descriptor,
                   std::uint64_t guest_statfs, std::string& error,
                   Ps4Errno* syscall_error = nullptr);
bool guest_pathconf(const VirtualFileSystem& vfs,
                    const GuestMemoryAccess& memory,
                    std::uint64_t guest_path, int name,
                    std::int64_t& value, std::string& error,
                    Ps4Errno* syscall_error = nullptr);
bool guest_readlink(const VirtualFileSystem& vfs,
                    const GuestMemoryAccess& memory,
                    std::uint64_t guest_path, std::uint64_t guest_buffer,
                    std::size_t buffer_size, std::size_t& bytes_read,
                    std::string& error,
                    Ps4Errno* syscall_error = nullptr);
bool guest_unlink_savedata(const VirtualFileSystem& vfs,
                           const GuestMemoryAccess& memory,
                           std::uint64_t guest_path,
                           std::string& error,
                           Ps4Errno* syscall_error = nullptr);
bool guest_rename_savedata(const VirtualFileSystem& vfs,
                           const GuestMemoryAccess& memory,
                           std::uint64_t guest_from_path,
                           std::uint64_t guest_to_path,
                           std::string& error,
                           Ps4Errno* syscall_error = nullptr);

// Implements the observed three-argument getdents service (PS4 syscall 272)
// over the independent VFS and guest-memory map. The libkernel syscall stub is
// redirected to a context-aware HLE wrapper during module relocation.
bool guest_getdents(VirtualFileSystem& vfs,
                    VfsDescriptorTable& descriptors,
                    GuestMemoryAccess& memory,
                    int descriptor,
                    std::uint64_t guest_buffer,
                    std::size_t buffer_size,
                    std::size_t& bytes_written,
                    std::string& error,
                    Ps4Errno* syscall_error = nullptr);
bool guest_read(VirtualFileSystem& vfs,
                VfsDescriptorTable& descriptors,
                GuestMemoryAccess& memory,
                int descriptor,
                std::uint64_t guest_buffer,
                std::size_t buffer_size,
                std::size_t& bytes_read,
                std::string& error,
                Ps4Errno* syscall_error = nullptr);
bool guest_write(VirtualFileSystem& vfs,
                 VfsDescriptorTable& descriptors,
                 GuestMemoryAccess& memory,
                 int descriptor,
                 std::uint64_t guest_buffer,
                 std::size_t buffer_size,
                 std::size_t& bytes_written,
                 std::string& error,
                 Ps4Errno* syscall_error = nullptr);
bool guest_pread(VirtualFileSystem& vfs,
                 VfsDescriptorTable& descriptors,
                 const GuestMemoryAccess& memory,
                 int descriptor,
                 std::uint64_t guest_buffer,
                 std::size_t buffer_size,
                 std::int64_t offset,
                 std::size_t& bytes_read,
                 std::string& error,
                 Ps4Errno* syscall_error = nullptr);
bool guest_pwrite(VirtualFileSystem& vfs,
                  VfsDescriptorTable& descriptors,
                  const GuestMemoryAccess& memory,
                  int descriptor,
                  std::uint64_t guest_buffer,
                  std::size_t buffer_size,
                  std::int64_t offset,
                  std::size_t& bytes_written,
                  std::string& error,
                  Ps4Errno* syscall_error = nullptr);

} // namespace nba16
