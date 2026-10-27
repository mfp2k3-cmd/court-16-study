#pragma once

#include "big_archive.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace nba16 {

enum class VfsErrorCode {
    None,
    InvalidPath,
    NotFound,
    PermissionDenied,
    AlreadyExists,
    NotDirectory,
    IsDirectory,
    InvalidArgument,
    TooManyFiles,
    NoSpace,
    ReadOnly,
    NameTooLong,
    Io,
    BadDescriptor,
};

struct VfsFile {
    std::string guest_path;
    std::filesystem::path host_path;
    std::shared_ptr<const BigArchive> archive;
    const BigMember* member{};
    std::uint64_t cursor{};
    std::uint64_t size{};
    bool readable{true};
    bool writable{};
    bool append{};
};

struct VfsDirectoryEntry {
    std::string name;
    bool is_directory{};
};

struct VfsDirectory {
    std::string guest_path;
    std::vector<VfsDirectoryEntry> entries;
    std::uint64_t cursor{};
};

struct VfsDevice {
    std::string guest_path;
};

struct VfsMetadata {
    enum class Kind { RegularFile, Directory } kind{Kind::RegularFile};
    std::uint64_t size{};
};

struct VfsFilesystemStats {
    std::uint64_t capacity{};
    std::uint64_t free_bytes{};
    std::uint64_t available_bytes{};
    std::uint64_t file_count{};
    std::string filesystem_type;
    std::string mounted_from;
    std::string mounted_on;
};

class VirtualFileSystem {
public:
    bool mount_app0(const std::filesystem::path& game_root, std::string& error);
    void mount_download0(const std::filesystem::path& user_root);
    void mount_savedata0(const std::filesystem::path& save_root);
    bool mount_temporary0(const std::filesystem::path& temporary_root, std::string& error);

    bool open_file(std::string_view guest_path, VfsFile& file, std::string& error,
                   VfsErrorCode* failure = nullptr) const;
    bool open_savedata_file(std::string_view guest_path, bool create_if_missing,
                            bool truncate_existing, bool exclusive_create, bool append,
                            bool readable,
                            VfsFile& file, std::string& error,
                            VfsErrorCode* failure = nullptr) const;
    bool read_file(VfsFile& file, std::span<std::byte> destination,
                   std::size_t& bytes_read, std::string& error,
                   VfsErrorCode* failure = nullptr) const;
    bool write_file(VfsFile& file, std::span<const std::byte> source,
                    std::size_t& bytes_written, std::string& error,
                    VfsErrorCode* failure = nullptr) const;
    bool truncate_file(VfsFile& file, std::uint64_t size, std::string& error,
                       VfsErrorCode* failure = nullptr) const;
    bool sync_file(const VfsFile& file, std::string& error,
                   VfsErrorCode* failure = nullptr) const;
    bool create_savedata_directory(std::string_view guest_path, std::string& error,
                                   VfsErrorCode* failure = nullptr) const;
    bool remove_savedata_file(std::string_view guest_path, std::string& error,
                              VfsErrorCode* failure = nullptr) const;
    bool rename_savedata_file(std::string_view from_guest_path,
                              std::string_view to_guest_path, std::string& error,
                              VfsErrorCode* failure = nullptr) const;
    bool open_directory(std::string_view guest_path, VfsDirectory& directory,
                        std::string& error) const;
    bool stat_path(std::string_view guest_path, VfsMetadata& metadata,
                   std::string& error, VfsErrorCode* failure = nullptr) const;
    bool stat_filesystem(std::string_view guest_path, VfsFilesystemStats& stats,
                         std::string& error,
                         VfsErrorCode* failure = nullptr) const;
    bool resolve_guest_path(std::string_view base_directory,
                            std::string_view input_path, std::string& output,
                            std::string& error) const;

    // FreeBSD-style x86-64 dirent records observed in the game: ino32, reclen16,
    // type8, namlen8, NUL-terminated name, padded to an 8-byte boundary.
    // Directory enumeration begins with synthetic "." and ".." entries.
    bool getdents(VfsDirectory& directory, std::span<std::byte> destination,
                  std::size_t& bytes_written, std::string& error,
                  VfsErrorCode* failure = nullptr) const;

private:
    struct FileBacking {
        std::filesystem::path host_path;
        std::shared_ptr<const BigArchive> archive;
        const BigMember* member{};
        std::uint64_t size{};
    };

    bool add_directory(std::string guest_path);
    void add_file(std::string guest_path, FileBacking backing);
    static bool normalize(std::string_view input, std::string& output);

    std::map<std::string, FileBacking, std::less<>> files_;
    std::map<std::string, std::map<std::string, bool, std::less<>>, std::less<>> directories_;
    std::filesystem::path download_root_;
    std::filesystem::path savedata_root_;
    std::filesystem::path temporary_root_;
    std::filesystem::path app_root_;
};

class VfsDescriptorTable {
public:
    int open_readonly(const VirtualFileSystem& vfs, std::string_view guest_path,
                      std::string& error, VfsErrorCode* failure = nullptr);
    int open_device(std::string_view guest_path, std::string& error,
                    VfsErrorCode* failure = nullptr);
    bool is_device(int descriptor, std::string& guest_path) const;
    int open_savedata(const VirtualFileSystem& vfs, std::string_view guest_path,
                      bool create_if_missing, bool truncate_existing, bool exclusive_create,
                      bool append, bool readable, std::string& error,
                      VfsErrorCode* failure = nullptr);
    bool read(const VirtualFileSystem& vfs, int descriptor, std::span<std::byte> destination,
              std::size_t& bytes_read, std::string& error,
              VfsErrorCode* failure = nullptr);
    bool write(const VirtualFileSystem& vfs, int descriptor, std::span<const std::byte> source,
               std::size_t& bytes_written, std::string& error,
               VfsErrorCode* failure = nullptr);
    bool pread(const VirtualFileSystem& vfs, int descriptor, std::uint64_t offset,
               std::span<std::byte> destination, std::size_t& bytes_read, std::string& error,
               VfsErrorCode* failure = nullptr);
    bool pwrite(const VirtualFileSystem& vfs, int descriptor, std::uint64_t offset,
                std::span<const std::byte> source, std::size_t& bytes_written,
                std::string& error, VfsErrorCode* failure = nullptr);
    bool getdents(const VirtualFileSystem& vfs, int descriptor, std::span<std::byte> destination,
                  std::size_t& bytes_written, std::string& error,
                  VfsErrorCode* failure = nullptr);
    bool seek(int descriptor, std::int64_t offset, int whence,
              std::uint64_t& new_offset, std::string& error,
              VfsErrorCode* failure = nullptr);
    bool close(int descriptor, std::string& error, VfsErrorCode* failure = nullptr);
    bool stat_descriptor(int descriptor, VfsMetadata& metadata, std::string& error,
                         VfsErrorCode* failure = nullptr) const;
    bool descriptor_path(int descriptor, std::string& guest_path,
                         std::string& error) const;
    bool descriptor_position(int descriptor, std::uint64_t& position,
                             std::uint64_t& size, std::string& error) const;
    bool truncate(const VirtualFileSystem& vfs, int descriptor, std::uint64_t size,
                  std::string& error, VfsErrorCode* failure = nullptr);
    bool sync(const VirtualFileSystem& vfs, int descriptor, std::string& error,
              VfsErrorCode* failure = nullptr) const;

private:
    using Handle = std::variant<VfsFile, VfsDirectory, VfsDevice>;
    // Serializes cursor and handle updates across guest worker threads. File I/O
    // remains inside the critical section so close/seek cannot race an operation.
    mutable std::mutex handles_mutex_;
    std::map<int, Handle> handles_;
};

} // namespace nba16
