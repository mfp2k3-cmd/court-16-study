#pragma once

#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nba16 {

enum class BigCompression {
    uncompressed_candidate,
    chunkzip,
    chunkref,
    chunklzx,
    chunlzma,
    chunklz4,
    chunkunc,
    chunzstd,
    chunoodl,
    refpack,
};

struct BigMember {
    std::string path;
    std::uint64_t data_offset{};
    std::uint64_t stored_size{};
    // The BIG index's size field; its exact meaning depends on compression kind.
    std::uint64_t size_field{};
    // Logical output size when it is available from the compressed-member header.
    std::uint64_t logical_size{};
    BigCompression compression{BigCompression::uncompressed_candidate};
};

class BigArchive {
public:
    bool open(const std::filesystem::path& path, std::string& error);
    [[nodiscard]] const std::vector<BigMember>& members() const noexcept;
    [[nodiscard]] const BigMember* find(std::string_view path) const noexcept;

    // Reads a byte range from entries that have no recognized compression header.
    // It never writes extracted files to disk.
    bool read_candidate_range(const BigMember& member, std::uint64_t offset,
                              std::span<std::byte> destination, std::size_t& bytes_read,
                              std::string& error) const;

    // Reads the stored bytes as they appear inside the archive, including compressed headers.
    // Intended for bounded format inspection; it never decompresses or writes extracted files.
    bool read_stored_range(const BigMember& member, std::uint64_t offset,
                           std::span<std::byte> destination, std::size_t& bytes_read,
                           std::string& error) const;

    // Decodes supported formats into a bounded output range without extracting the member.
    bool read_decoded_range(const BigMember& member, std::uint64_t offset,
                            std::span<std::byte> destination, std::size_t& bytes_read,
                            std::string& error) const;

private:
    std::filesystem::path archive_path_;
    std::uint64_t archive_size_{};
    std::vector<BigMember> members_;
};

} // namespace nba16
