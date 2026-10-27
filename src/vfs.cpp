#include "vfs.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <system_error>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace nba16 {
namespace {

std::uint64_t aligned_dirent_size(std::size_t name_size) {
    const auto unaligned = static_cast<std::uint64_t>(8U + name_size + 1U);
    return (unaligned + 7U) & ~std::uint64_t{7U};
}

void put_le16(std::span<std::byte> output, std::size_t offset, std::uint16_t value) {
    output[offset] = static_cast<std::byte>(value & 0xffU);
    output[offset + 1] = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void put_le32(std::span<std::byte> output, std::size_t offset, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        output[offset + shift / 8U] = static_cast<std::byte>((value >> shift) & 0xffU);
    }
}

bool path_below(std::string_view path, std::string_view prefix) {
    return path == prefix || (path.size() > prefix.size() && path.starts_with(prefix) &&
                              path[prefix.size()] == '/');
}

bool guest_to_host(const std::filesystem::path& root, std::string_view guest_path,
                   std::string_view mount, std::filesystem::path& output);
bool stays_below_root(const std::filesystem::path& root,
                      const std::filesystem::path& candidate);

const std::filesystem::path* mutable_root_for_guest_path(
    std::string_view guest_path, const std::filesystem::path& savedata_root,
    const std::filesystem::path& temporary_root, std::string_view& mount) {
    if (path_below(guest_path, "/savedata0")) {
        mount = "/savedata0";
        return &savedata_root;
    }
    if (path_below(guest_path, "/temp0")) {
        mount = "/temp0";
        return &temporary_root;
    }
    return nullptr;
}

bool resolve_mutable_guest_path(std::string_view guest_path,
                                const std::filesystem::path& savedata_root,
                                const std::filesystem::path& temporary_root,
                                std::filesystem::path& host_path,
                                const std::filesystem::path*& root_out) {
    std::string_view mount;
    root_out = mutable_root_for_guest_path(guest_path, savedata_root, temporary_root, mount);
    return root_out != nullptr && !root_out->empty() &&
        guest_to_host(*root_out, guest_path, mount, host_path) &&
        stays_below_root(*root_out, host_path);
}

bool guest_to_host(const std::filesystem::path& root, std::string_view guest_path,
                   std::string_view mount, std::filesystem::path& output) {
    if (!path_below(guest_path, mount)) {
        return false;
    }
    std::string_view relative = guest_path.substr(mount.size());
    if (!relative.empty() && relative.front() == '/') {
        relative.remove_prefix(1);
    }
    output = root;
    std::size_t start = 0;
    while (start < relative.size()) {
        const auto end = relative.find('/', start);
        const auto component = relative.substr(start, end == std::string_view::npos
            ? relative.size() - start : end - start);
        if (component.empty() || component == "." || component == ".." ||
            component.find(':') != std::string_view::npos) {
            return false;
        }
        output /= std::filesystem::path(std::string(component));
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }
    return true;
}

bool stays_below_root(const std::filesystem::path& root,
                      const std::filesystem::path& candidate) {
    std::error_code ec;
    const auto canonical_root = std::filesystem::weakly_canonical(root, ec);
    if (ec) {
        return false;
    }
    const auto canonical_candidate = std::filesystem::weakly_canonical(candidate, ec);
    if (ec) {
        return false;
    }
    const auto relative = canonical_candidate.lexically_relative(canonical_root);
    if (relative.empty()) {
        return canonical_candidate == canonical_root;
    }
    if (relative.is_absolute()) {
        return false;
    }
    return std::none_of(relative.begin(), relative.end(), [](const auto& component) {
        return component == "..";
    });
}

bool create_exclusive_file(const std::filesystem::path& path, std::string& error) {
#ifdef _WIN32
    const HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        error = "criação exclusiva falhou (arquivo já existe ou acesso negado)";
        return false;
    }
    CloseHandle(handle);
#else
    const int descriptor = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (descriptor < 0) {
        error = "criação exclusiva falhou (arquivo já existe ou acesso negado)";
        return false;
    }
    ::close(descriptor);
#endif
    return true;
}

bool fail(std::string& message, VfsErrorCode* code, VfsErrorCode value,
          std::string text) {
    if (code != nullptr) *code = value;
    message = std::move(text);
    return false;
}

} // namespace

bool VirtualFileSystem::normalize(std::string_view input, std::string& output) {
    output.clear();
    output.push_back('/');
    std::string component;
    std::vector<std::string> components;
    for (const char character : input) {
        if (character == '/' || character == '\\') {
            if (!component.empty()) {
                if (component == "..") {
                    return false;
                }
                if (component != ".") {
                    components.push_back(std::move(component));
                }
                component.clear();
            }
        } else {
            component.push_back(character);
        }
    }
    if (!component.empty()) {
        if (component == "..") {
            return false;
        }
        if (component != ".") {
            components.push_back(std::move(component));
        }
    }
    for (std::size_t index = 0; index < components.size(); ++index) {
        if (index != 0) {
            output.push_back('/');
        }
        output += components[index];
    }
    return true;
}

bool VirtualFileSystem::add_directory(std::string guest_path) {
    const auto [iterator, inserted] = directories_.try_emplace(guest_path);
    (void)iterator;
    if (inserted && guest_path != "/") {
        const auto slash = guest_path.find_last_of('/');
        const auto parent = slash == 0 ? std::string("/") : guest_path.substr(0, slash);
        const auto name = guest_path.substr(slash + 1);
        if (!directories_.contains(parent)) {
            add_directory(parent);
        }
        directories_[parent][name] = true;
    }
    return inserted;
}

void VirtualFileSystem::add_file(std::string guest_path, FileBacking backing) {
    const auto slash = guest_path.find_last_of('/');
    const auto parent = slash == 0 ? std::string("/") : guest_path.substr(0, slash);
    const auto name = guest_path.substr(slash + 1);
    add_directory(parent);
    directories_[parent][name] = false;
    files_.try_emplace(std::move(guest_path), std::move(backing));
}

bool VirtualFileSystem::mount_app0(const std::filesystem::path& game_root, std::string& error) {
    std::error_code ec;
    if (!std::filesystem::is_directory(game_root, ec) || ec) {
        error = "a pasta do jogo não existe ou não pode ser acessada";
        return false;
    }
    files_.clear();
    directories_.clear();
    app_root_ = game_root;
    add_directory("/");
    add_directory("/app0");
    if (!download_root_.empty()) {
        add_directory("/download0");
    }
    if (!savedata_root_.empty()) {
        add_directory("/savedata0");
    }
    if (!temporary_root_.empty()) {
        add_directory("/temp0");
    }

    std::vector<std::filesystem::path> archive_paths;
    for (std::filesystem::recursive_directory_iterator it(game_root, ec), end;
         !ec && it != end; it.increment(ec)) {
        std::error_code entry_error;
        const auto relative = std::filesystem::relative(it->path(), game_root, entry_error);
        if (entry_error) {
            continue;
        }
        const auto guest_path = "/app0/" + relative.generic_string();
        if (it->is_directory(entry_error) && !entry_error) {
            add_directory(guest_path);
        } else if (it->is_regular_file(entry_error) && !entry_error) {
            const auto size = it->file_size(entry_error);
            if (entry_error) {
                continue;
            }
            add_file(guest_path, FileBacking{it->path(), {}, nullptr, size});
            auto extension = it->path().extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            if (extension == ".big") {
                archive_paths.push_back(it->path());
            }
        }
    }
    if (ec) {
        error = "falha percorrendo a pasta do jogo: " + ec.message();
        files_.clear();
        directories_.clear();
        return false;
    }

    for (const auto& archive_path : archive_paths) {
        auto archive = std::make_shared<BigArchive>();
        if (!archive->open(archive_path, error)) {
            error = archive_path.filename().string() + ": " + error;
            files_.clear();
            directories_.clear();
            return false;
        }
        for (const auto& member : archive->members()) {
            add_file("/app0/" + member.path,
                     FileBacking{{}, archive, &member, member.logical_size});
        }
    }
    return true;
}

void VirtualFileSystem::mount_download0(const std::filesystem::path& user_root) {
    download_root_ = user_root;
    add_directory("/download0");
}

void VirtualFileSystem::mount_savedata0(const std::filesystem::path& save_root) {
    savedata_root_ = save_root;
    add_directory("/savedata0");
}

bool VirtualFileSystem::mount_temporary0(const std::filesystem::path& temporary_root,
                                         std::string& error) {
    std::error_code ec;
    std::filesystem::create_directories(temporary_root, ec);
    if (ec || !std::filesystem::is_directory(temporary_root, ec) || ec) {
        error = "a pasta temporária do jogo não pôde ser criada";
        return false;
    }
    temporary_root_ = temporary_root;
    add_directory("/temp0");
    error.clear();
    return true;
}

bool VirtualFileSystem::open_file(std::string_view guest_path, VfsFile& file,
                                  std::string& error, VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    std::string normalized;
    if (!normalize(guest_path, normalized)) {
        return fail(error, failure, VfsErrorCode::InvalidPath,
                    "caminho virtual contém um segmento inválido");
    }
    if (const auto it = files_.find(normalized); it != files_.end()) {
        file.guest_path = normalized;
        file.host_path = it->second.host_path;
        file.archive = it->second.archive;
        file.member = it->second.member;
        file.cursor = 0;
        file.size = it->second.size;
        file.writable = false;
        return true;
    }
    std::filesystem::path host_path;
    const auto open_host = [&](const std::filesystem::path& root, std::string_view mount) {
        std::error_code ec;
        return !root.empty() && guest_to_host(root, normalized, mount, host_path) &&
               stays_below_root(root, host_path) &&
               std::filesystem::is_regular_file(host_path, ec) && !ec;
    };
    if (open_host(download_root_, "/download0") || open_host(savedata_root_, "/savedata0") ||
        open_host(temporary_root_, "/temp0")) {
        std::error_code ec;
        file.host_path = host_path;
        file.guest_path = normalized;
        file.archive.reset();
        file.member = nullptr;
        file.cursor = 0;
        file.size = std::filesystem::file_size(host_path, ec);
        if (!ec) {
            file.writable = false;
            return true;
        }
    }
    return fail(error, failure, VfsErrorCode::NotFound,
                "arquivo virtual não encontrado: " + normalized);
}

bool VirtualFileSystem::open_savedata_file(std::string_view guest_path, bool create_if_missing,
                                           bool truncate_existing, bool exclusive_create,
                                           bool append, bool readable, VfsFile& file,
                                           std::string& error,
                                           VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    std::string normalized;
    if (!normalize(guest_path, normalized) || normalized == "/savedata0" ||
        normalized == "/temp0") {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "arquivo gravável deve ficar dentro de /savedata0 ou /temp0");
    }
    std::filesystem::path host_path;
    const std::filesystem::path* root{};
    if (!resolve_mutable_guest_path(normalized, savedata_root_, temporary_root_, host_path, root)) {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "caminho gravável inválido ou fora da pasta configurada");
    }

    std::error_code ec;
    const auto parent = host_path.parent_path();
    if (!std::filesystem::is_directory(parent, ec) || ec) {
        return fail(error, failure, VfsErrorCode::NotFound, "pasta pai do save não existe");
    }
    const auto link_status = std::filesystem::symlink_status(host_path, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        return fail(error, failure, VfsErrorCode::Io, "não foi possível verificar o arquivo de save");
    }
    if (!ec && std::filesystem::is_symlink(link_status)) {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "o caminho de save não pode ser um link simbólico");
    }
    ec.clear();
    const bool exists = std::filesystem::exists(link_status);
    if (exists && create_if_missing && exclusive_create) {
        return fail(error, failure, VfsErrorCode::AlreadyExists,
                    "arquivo já existe e a abertura pediu criação exclusiva");
    }
    if (exists && !std::filesystem::is_regular_file(host_path, ec)) {
        return fail(error, failure, VfsErrorCode::IsDirectory,
                    "o caminho de save existente não é um arquivo regular");
    }
    if (!exists && !create_if_missing) {
        return fail(error, failure, VfsErrorCode::NotFound, "arquivo de save não encontrado");
    }
    bool created_exclusively = false;
    if (!exists && create_if_missing && exclusive_create) {
        if (!create_exclusive_file(host_path, error)) {
            return false;
        }
        created_exclusively = true;
    }
    if ((truncate_existing && !created_exclusively) || (!exists && !created_exclusively)) {
        std::ofstream output(host_path, std::ios::binary | std::ios::trunc);
        if (!output) {
            return fail(error, failure, VfsErrorCode::Io,
                        "não foi possível criar ou truncar o arquivo de save");
        }
    }

    const auto size = std::filesystem::file_size(host_path, ec);
    if (ec) {
        return fail(error, failure, VfsErrorCode::Io,
                    "não foi possível ler o tamanho do arquivo de save");
    }
    file.host_path = host_path;
    file.guest_path = normalized;
    file.archive.reset();
    file.member = nullptr;
    file.cursor = 0;
    file.size = size;
    file.readable = readable;
    file.writable = true;
    file.append = append;
    return true;
}

bool VirtualFileSystem::read_file(VfsFile& file, std::span<std::byte> destination,
                                  std::size_t& bytes_read, std::string& error,
                                  VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    bytes_read = 0;
    if (!file.readable) {
        return fail(error, failure, VfsErrorCode::BadDescriptor,
                    "arquivo virtual não foi aberto para leitura");
    }
    if (file.cursor > file.size) {
        return fail(error, failure, VfsErrorCode::InvalidArgument,
                    "cursor do arquivo virtual fora dos limites");
    }
    const auto remaining = file.size - file.cursor;
    const auto request = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, destination.size()));
    if (file.archive && file.member != nullptr) {
        if (!file.archive->read_decoded_range(*file.member, file.cursor, destination.first(request),
                                              bytes_read, error)) {
            bytes_read = 0;
            auto detail = error;
            return fail(error, failure, VfsErrorCode::Io, std::move(detail));
        }
    } else {
        std::ifstream input(file.host_path, std::ios::binary);
        if (!input || file.cursor > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
            request > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
            return fail(error, failure, VfsErrorCode::Io,
                        "falha abrindo arquivo virtual ou cursor excessivo");
        }
        input.seekg(static_cast<std::streamoff>(file.cursor), std::ios::beg);
        if (!input.read(reinterpret_cast<char*>(destination.data()), static_cast<std::streamsize>(request)) &&
            request != 0) {
            return fail(error, failure, VfsErrorCode::Io,
                        "falha durante leitura do arquivo virtual");
        }
        bytes_read = request;
    }
    file.cursor += bytes_read;
    return true;
}

bool VirtualFileSystem::write_file(VfsFile& file, std::span<const std::byte> source,
                                   std::size_t& bytes_written, std::string& error,
                                   VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    bytes_written = 0;
    if (!file.writable || file.archive || file.member != nullptr) {
        return fail(error, failure, VfsErrorCode::BadDescriptor,
                    "arquivo virtual não foi aberto para gravação");
    }
    if (file.append) {
        file.cursor = file.size;
    }
    if (file.cursor > file.size ||
        source.size() > std::numeric_limits<std::uint64_t>::max() - file.cursor ||
        file.cursor > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
        source.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        return fail(error, failure, VfsErrorCode::InvalidArgument,
                    "cursor ou tamanho fora dos limites para gravação");
    }
    if (source.empty()) {
        return true;
    }
    std::filesystem::path checked_path;
    const std::filesystem::path* root{};
    if (!resolve_mutable_guest_path(file.guest_path, savedata_root_, temporary_root_,
                                    checked_path, root) || checked_path != file.host_path) {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "gravação fora das pastas graváveis do jogo");
    }
    std::fstream output(file.host_path, std::ios::binary | std::ios::in | std::ios::out);
    if (!output) {
        return fail(error, failure, VfsErrorCode::Io,
                    "não foi possível abrir o arquivo de save para gravação");
    }
    output.seekp(static_cast<std::streamoff>(file.cursor), std::ios::beg);
    output.write(reinterpret_cast<const char*>(source.data()),
                 static_cast<std::streamsize>(source.size()));
    output.flush();
    if (!output) {
        return fail(error, failure, VfsErrorCode::Io,
                    "falha durante gravação do arquivo de save");
    }
    bytes_written = source.size();
    file.cursor += bytes_written;
    file.size = std::max(file.size, file.cursor);
    return true;
}

bool VirtualFileSystem::truncate_file(VfsFile& file, std::uint64_t size,
                                      std::string& error, VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    if (!file.writable || file.archive || file.member != nullptr ||
        size > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        return fail(error, failure, file.writable ? VfsErrorCode::InvalidArgument
                                                  : VfsErrorCode::BadDescriptor,
                    "arquivo virtual não pode ser truncado com esse tamanho");
    }
    std::filesystem::path checked_path;
    const std::filesystem::path* root{};
    if (!resolve_mutable_guest_path(file.guest_path, savedata_root_, temporary_root_,
                                    checked_path, root) || checked_path != file.host_path) {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "truncamento escaparia das pastas graváveis do jogo");
    }
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(file.host_path, ec);
    if (ec || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        return fail(error, failure, ec ? VfsErrorCode::NotFound : VfsErrorCode::InvalidArgument,
                    "arquivo de save inválido para truncamento");
    }
    std::filesystem::resize_file(file.host_path, size, ec);
    if (ec) {
        return fail(error, failure, VfsErrorCode::Io,
                    "falha ao ajustar o tamanho do arquivo de save");
    }
    file.size = size;
    return true;
}

bool VirtualFileSystem::sync_file(const VfsFile& file, std::string& error,
                                  VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    std::filesystem::path checked_path;
    const std::filesystem::path* root{};
    if (!file.writable || !resolve_mutable_guest_path(file.guest_path, savedata_root_,
            temporary_root_, checked_path, root) || checked_path != file.host_path) {
        return fail(error, failure, VfsErrorCode::BadDescriptor,
                    "arquivo virtual não está numa pasta gravável");
    }
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(file.host_path, ec);
    if (ec || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        return fail(error, failure, ec ? VfsErrorCode::NotFound : VfsErrorCode::InvalidArgument,
                    "arquivo de save inválido para fsync");
    }
#ifdef _WIN32
    const HANDLE handle = CreateFileW(file.host_path.c_str(), GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return fail(error, failure, VfsErrorCode::Io, "não foi possível abrir save para fsync");
    }
    const bool success = FlushFileBuffers(handle) != 0;
    CloseHandle(handle);
    if (!success) {
        return fail(error, failure, VfsErrorCode::Io, "FlushFileBuffers falhou no save");
    }
#else
    const int descriptor = ::open(file.host_path.c_str(), O_WRONLY);
    if (descriptor < 0) {
        return fail(error, failure, VfsErrorCode::Io, "não foi possível abrir save para fsync");
    }
    const bool success = ::fsync(descriptor) == 0;
    ::close(descriptor);
    if (!success) {
        return fail(error, failure, VfsErrorCode::Io, "fsync falhou no save");
    }
#endif
    return true;
}

bool VirtualFileSystem::create_savedata_directory(std::string_view guest_path,
                                                  std::string& error,
                                                  VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    std::string normalized;
    if (!normalize(guest_path, normalized) || normalized == "/savedata0" ||
        normalized == "/temp0") {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "diretório gravável deve ficar dentro de /savedata0 ou /temp0");
    }
    std::filesystem::path host_path;
    const std::filesystem::path* root{};
    if (!resolve_mutable_guest_path(normalized, savedata_root_, temporary_root_, host_path, root)) {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "caminho de diretório gravável inválido");
    }
    std::error_code ec;
    if (!std::filesystem::is_directory(host_path.parent_path(), ec) || ec) {
        return fail(error, failure, VfsErrorCode::NotFound,
                    "pasta pai do diretório gravável não existe");
    }
    if (!std::filesystem::create_directory(host_path, ec)) {
        return fail(error, failure, ec ? VfsErrorCode::Io : VfsErrorCode::AlreadyExists,
                    ec ? "falha criando diretório gravável: " + ec.message()
                       : "diretório gravável já existe");
    }
    return true;
}

bool VirtualFileSystem::remove_savedata_file(std::string_view guest_path,
                                             std::string& error,
                                             VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    std::string normalized;
    std::filesystem::path host_path;
    const std::filesystem::path* root{};
    if (!normalize(guest_path, normalized) || normalized == "/savedata0" ||
        normalized == "/temp0" ||
        !resolve_mutable_guest_path(normalized, savedata_root_, temporary_root_, host_path, root)) {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "arquivo para unlink inválido ou fora das pastas graváveis");
    }
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(host_path, ec);
    if (ec || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        return fail(error, failure, ec ? VfsErrorCode::NotFound
                                       : (std::filesystem::is_directory(status)
                                              ? VfsErrorCode::IsDirectory
                                              : VfsErrorCode::PermissionDenied),
                    "unlink exige arquivo regular existente dentro das pastas graváveis");
    }
    if (!std::filesystem::remove(host_path, ec) || ec) {
        return fail(error, failure, VfsErrorCode::Io,
                    "não foi possível remover o arquivo gravável");
    }
    return true;
}

bool VirtualFileSystem::rename_savedata_file(std::string_view from_guest_path,
                                             std::string_view to_guest_path,
                                             std::string& error,
                                             VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    std::string from_normalized;
    std::string to_normalized;
    std::filesystem::path from_path;
    std::filesystem::path to_path;
    const std::filesystem::path* from_root{};
    const std::filesystem::path* to_root{};
    if (!normalize(from_guest_path, from_normalized) ||
        !normalize(to_guest_path, to_normalized) || from_normalized == "/savedata0" ||
        from_normalized == "/temp0" || to_normalized == "/savedata0" ||
        to_normalized == "/temp0" ||
        !resolve_mutable_guest_path(from_normalized, savedata_root_, temporary_root_,
                                    from_path, from_root) ||
        !resolve_mutable_guest_path(to_normalized, savedata_root_, temporary_root_,
                                    to_path, to_root) || from_root != to_root) {
        return fail(error, failure, VfsErrorCode::PermissionDenied,
                    "caminho de rename inválido ou entre pastas graváveis distintas");
    }
    std::error_code ec;
    const auto from_status = std::filesystem::symlink_status(from_path, ec);
    if (ec || std::filesystem::is_symlink(from_status) ||
        !std::filesystem::is_regular_file(from_status)) {
        return fail(error, failure, ec ? VfsErrorCode::NotFound
                                       : (std::filesystem::is_directory(from_status)
                                              ? VfsErrorCode::IsDirectory
                                              : VfsErrorCode::PermissionDenied),
                    "origem de rename deve ser um arquivo regular existente");
    }
    ec.clear();
    if (!std::filesystem::is_directory(to_path.parent_path(), ec) || ec) {
        return fail(error, failure, VfsErrorCode::NotFound,
                    "pasta de destino de rename não existe");
    }
    ec.clear();
    const auto to_status = std::filesystem::symlink_status(to_path, ec);
    if (!ec && (std::filesystem::is_symlink(to_status) ||
                !std::filesystem::is_regular_file(to_status))) {
        return fail(error, failure, std::filesystem::is_directory(to_status)
                    ? VfsErrorCode::IsDirectory : VfsErrorCode::PermissionDenied,
                    "destino de rename existente não é arquivo regular");
    }
#ifdef _WIN32
    if (!MoveFileExW(from_path.c_str(), to_path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return fail(error, failure, VfsErrorCode::Io,
                    "não foi possível renomear o arquivo de save");
    }
#else
    std::filesystem::rename(from_path, to_path, ec);
    if (ec) {
        return fail(error, failure, VfsErrorCode::Io,
                    "não foi possível renomear o arquivo de save: " + ec.message());
    }
#endif
    return true;
}

bool VirtualFileSystem::open_directory(std::string_view guest_path, VfsDirectory& directory,
                                       std::string& error) const {
    std::string normalized;
    if (!normalize(guest_path, normalized)) {
        error = "caminho virtual contém um segmento inválido";
        return false;
    }
    if (const auto it = directories_.find(normalized);
        it != directories_.end() && normalized != "/download0" && normalized != "/savedata0" &&
        normalized != "/temp0") {
        directory.guest_path = normalized;
        directory.entries.clear();
        directory.cursor = 0;
        directory.entries.reserve(it->second.size() + 2U);
        directory.entries.push_back({".", true});
        directory.entries.push_back({"..", true});
        for (const auto& [name, is_directory] : it->second) {
            directory.entries.push_back({name, is_directory});
        }
        return true;
    }

    std::filesystem::path host_path;
    std::string_view mount;
    const std::filesystem::path* root = nullptr;
    if (path_below(normalized, "/download0")) {
        mount = "/download0";
        root = &download_root_;
    } else if (path_below(normalized, "/savedata0")) {
        mount = "/savedata0";
        root = &savedata_root_;
    } else if (path_below(normalized, "/temp0")) {
        mount = "/temp0";
        root = &temporary_root_;
    }
    if (root == nullptr || root->empty() || !guest_to_host(*root, normalized, mount, host_path) ||
        !stays_below_root(*root, host_path)) {
        error = "diretório virtual não encontrado: " + normalized;
        return false;
    }
    std::error_code ec;
    if (!std::filesystem::is_directory(host_path, ec) || ec) {
        error = "diretório virtual não encontrado: " + normalized;
        return false;
    }
    directory.entries.clear();
    directory.guest_path = normalized;
    directory.cursor = 0;
    directory.entries.push_back({".", true});
    directory.entries.push_back({"..", true});
    for (std::filesystem::directory_iterator it(host_path, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code type_error;
        const bool is_directory = it->is_directory(type_error);
        if (type_error) {
            continue;
        }
        directory.entries.push_back({it->path().filename().string(), is_directory});
    }
    if (ec) {
        error = "falha lendo diretório virtual: " + ec.message();
        return false;
    }
    std::sort(directory.entries.begin(), directory.entries.end(), [](const auto& left, const auto& right) {
        return left.name < right.name;
    });
    return true;
}

bool VirtualFileSystem::stat_path(std::string_view guest_path, VfsMetadata& metadata,
                                  std::string& error, VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    std::string normalized;
    if (!normalize(guest_path, normalized)) {
        return fail(error, failure, VfsErrorCode::InvalidPath, "caminho virtual inválido para stat");
    }
    if (const auto file = files_.find(normalized); file != files_.end()) {
        metadata.kind = VfsMetadata::Kind::RegularFile;
        metadata.size = file->second.size;
        return true;
    }
    if (directories_.contains(normalized)) {
        metadata.kind = VfsMetadata::Kind::Directory;
        metadata.size = 0;
        return true;
    }
    const std::filesystem::path* root{};
    std::filesystem::path host_path;
    if (!resolve_mutable_guest_path(normalized, savedata_root_, temporary_root_, host_path, root)) {
        return fail(error, failure, VfsErrorCode::NotFound, "caminho virtual não encontrado");
    }
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(host_path, ec);
    if (ec || std::filesystem::is_symlink(status)) {
        return fail(error, failure, std::filesystem::is_symlink(status)
                    ? VfsErrorCode::PermissionDenied : VfsErrorCode::NotFound,
                    "caminho de save inexistente ou link simbólico recusado");
    }
    if (std::filesystem::is_directory(status)) {
        metadata.kind = VfsMetadata::Kind::Directory;
        metadata.size = 0;
        return true;
    }
    if (!std::filesystem::is_regular_file(status)) {
        return fail(error, failure, VfsErrorCode::InvalidArgument,
                    "tipo de arquivo não suportado por stat");
    }
    metadata.kind = VfsMetadata::Kind::RegularFile;
    metadata.size = std::filesystem::file_size(host_path, ec);
    if (ec) {
        return fail(error, failure, VfsErrorCode::Io,
                    "não foi possível ler tamanho do arquivo para stat");
    }
    return true;
}

bool VirtualFileSystem::stat_filesystem(std::string_view guest_path,
                                        VfsFilesystemStats& stats,
                                        std::string& error,
                                        VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    std::string normalized;
    if (!normalize(guest_path, normalized)) {
        return fail(error, failure, VfsErrorCode::InvalidPath,
                    "caminho virtual inválido para statfs");
    }
    VfsMetadata metadata{};
    if (!stat_path(normalized, metadata, error, failure)) {
        VfsFile file;
        VfsDirectory directory;
        std::string lookup_error;
        if (!open_file(normalized, file, lookup_error) &&
            !open_directory(normalized, directory, lookup_error)) {
            return false;
        }
        if (failure != nullptr) *failure = VfsErrorCode::None;
        error.clear();
    }

    const std::filesystem::path* root{};
    std::string_view mount;
    if (path_below(normalized, "/app0")) {
        root = &app_root_;
        mount = "/app0";
    } else if (path_below(normalized, "/download0")) {
        root = &download_root_;
        mount = "/download0";
    } else if (path_below(normalized, "/savedata0")) {
        root = &savedata_root_;
        mount = "/savedata0";
    } else if (path_below(normalized, "/temp0")) {
        root = &temporary_root_;
        mount = "/temp0";
    }
    if (root == nullptr || root->empty()) {
        return fail(error, failure, VfsErrorCode::NotFound,
                    "caminho sem sistema de arquivos montado");
    }
    std::error_code ec;
    const auto space = std::filesystem::space(*root, ec);
    if (ec) {
        return fail(error, failure, VfsErrorCode::Io,
                    "não foi possível consultar espaço do volume: " + ec.message());
    }
    stats.capacity = space.capacity;
    stats.free_bytes = space.free;
    stats.available_bytes = space.available;
    stats.file_count = files_.size() + directories_.size();
    stats.filesystem_type = "nba16vfs";
    stats.mounted_from = std::string(mount);
    stats.mounted_on = std::string(mount);
    error.clear();
    return true;
}

bool VirtualFileSystem::resolve_guest_path(std::string_view base_directory,
                                           std::string_view input_path,
                                           std::string& output,
                                           std::string& error) const {
    if (input_path.empty()) {
        error = "caminho virtual vazio";
        return false;
    }
    std::string combined;
    if (input_path.front() == '/' || input_path.front() == '\\') {
        combined.assign(input_path);
    } else {
        combined.assign(base_directory);
        if (combined.empty() || (combined.back() != '/' && combined.back() != '\\'))
            combined.push_back('/');
        combined.append(input_path);
    }
    std::vector<std::string> components;
    std::string component;
    for (const char character : combined) {
        if (character == '/' || character == '\\') {
            if (component == "..") {
                if (components.empty()) {
                    error = "caminho relativo escaparia da raiz virtual";
                    return false;
                }
                components.pop_back();
            } else if (!component.empty() && component != ".") {
                components.push_back(std::move(component));
            }
            component.clear();
        } else {
            component.push_back(character);
        }
    }
    if (component == "..") {
        if (components.empty()) {
            error = "caminho relativo escaparia da raiz virtual";
            return false;
        }
        components.pop_back();
    } else if (!component.empty() && component != ".") {
        components.push_back(std::move(component));
    }
    output = "/";
    for (std::size_t index = 0; index < components.size(); ++index) {
        if (index != 0) output.push_back('/');
        output += components[index];
    }
    error.clear();
    return true;
}

bool VirtualFileSystem::getdents(VfsDirectory& directory, std::span<std::byte> destination,
                                 std::size_t& bytes_written, std::string& error,
                                 VfsErrorCode* failure) const {
    if (failure != nullptr) *failure = VfsErrorCode::None;
    bytes_written = 0;
    while (directory.cursor < directory.entries.size()) {
        const auto& entry = directory.entries[static_cast<std::size_t>(directory.cursor)];
        const auto record_size = aligned_dirent_size(entry.name.size());
        if (entry.name.size() > std::numeric_limits<std::uint8_t>::max() ||
            record_size > std::numeric_limits<std::uint16_t>::max()) {
            return fail(error, failure, VfsErrorCode::NameTooLong,
                        "nome grande demais para o formato dirent observado");
        }
        if (record_size > destination.size() - bytes_written) {
            if (bytes_written == 0) {
                return fail(error, failure, VfsErrorCode::InvalidArgument,
                            "buffer getdents menor que o próximo registro completo");
            }
            break;
        }
        const auto start = bytes_written;
        const auto length = static_cast<std::size_t>(record_size);
        std::fill(destination.begin() + static_cast<std::ptrdiff_t>(start),
                  destination.begin() + static_cast<std::ptrdiff_t>(start + length), std::byte{0});
        const auto inode = static_cast<std::uint32_t>(directory.cursor + 1U);
        put_le32(destination, start, inode);
        put_le16(destination, start + 4U, static_cast<std::uint16_t>(record_size));
        destination[start + 6U] = entry.is_directory ? std::byte{4} : std::byte{8};
        destination[start + 7U] = static_cast<std::byte>(entry.name.size());
        std::transform(entry.name.begin(), entry.name.end(),
                       destination.begin() + static_cast<std::ptrdiff_t>(start + 8U),
                       [](char value) { return static_cast<std::byte>(static_cast<unsigned char>(value)); });
        bytes_written += length;
        ++directory.cursor;
    }
    return true;
}

int VfsDescriptorTable::open_readonly(const VirtualFileSystem& vfs, std::string_view guest_path,
                                      std::string& error, VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    VfsFile file;
    if (vfs.open_file(guest_path, file, error, failure)) {
        error.clear();
        // Choose the lowest unused descriptor at or above 3.
        int descriptor = 3;
        while (handles_.contains(descriptor)) {
            if (descriptor == std::numeric_limits<int>::max()) {
                fail(error, failure, VfsErrorCode::TooManyFiles, "tabela de descritores esgotada");
                return -1;
            }
            ++descriptor;
        }
        handles_.emplace(descriptor, std::move(file));
        return descriptor;
    }

    VfsDirectory directory;
    if (vfs.open_directory(guest_path, directory, error)) {
        error.clear();
        int descriptor = 3;
        while (handles_.contains(descriptor)) {
            if (descriptor == std::numeric_limits<int>::max()) {
                fail(error, failure, VfsErrorCode::TooManyFiles, "tabela de descritores esgotada");
                return -1;
            }
            ++descriptor;
        }
        handles_.emplace(descriptor, std::move(directory));
        return descriptor;
    }
    if (failure != nullptr && *failure == VfsErrorCode::None) *failure = VfsErrorCode::NotFound;
    return -1;
}

int VfsDescriptorTable::open_device(std::string_view guest_path, std::string& error,
                                    VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    if (guest_path != "/dev/gc") {
        fail(error, failure, VfsErrorCode::NotFound,
             "dispositivo convidado não reconhecido");
        return -1;
    }
    int descriptor = 3;
    while (handles_.contains(descriptor)) {
        if (descriptor == std::numeric_limits<int>::max()) {
            fail(error, failure, VfsErrorCode::TooManyFiles,
                 "tabela de descritores esgotada");
            return -1;
        }
        ++descriptor;
    }
    handles_.emplace(descriptor, VfsDevice{std::string(guest_path)});
    error.clear();
    return descriptor;
}

bool VfsDescriptorTable::is_device(int descriptor, std::string& guest_path) const {
    const std::lock_guard lock(handles_mutex_);
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) return false;
    const auto* device = std::get_if<VfsDevice>(&it->second);
    if (device == nullptr) return false;
    guest_path = device->guest_path;
    return true;
}

int VfsDescriptorTable::open_savedata(const VirtualFileSystem& vfs,
                                      std::string_view guest_path,
                                      bool create_if_missing,
                                      bool truncate_existing,
                                      bool exclusive_create,
                                      bool append,
                                      bool readable,
                                      std::string& error,
                                      VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    VfsFile file;
    if (!vfs.open_savedata_file(guest_path, create_if_missing, truncate_existing,
                                exclusive_create, append, readable, file, error, failure)) {
        return -1;
    }
    int descriptor = 3;
    while (handles_.contains(descriptor)) {
        if (descriptor == std::numeric_limits<int>::max()) {
            fail(error, failure, VfsErrorCode::TooManyFiles, "tabela de descritores esgotada");
            return -1;
        }
        ++descriptor;
    }
    handles_.emplace(descriptor, std::move(file));
    error.clear();
    return descriptor;
}

bool VfsDescriptorTable::read(const VirtualFileSystem& vfs, int descriptor,
                              std::span<std::byte> destination, std::size_t& bytes_read,
                              std::string& error, VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        bytes_read = 0;
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    auto* file = std::get_if<VfsFile>(&it->second);
    if (file == nullptr) {
        bytes_read = 0;
        return fail(error, failure, VfsErrorCode::IsDirectory,
                    "read solicitado em um descritor de diretório");
    }
    return vfs.read_file(*file, destination, bytes_read, error, failure);
}

bool VfsDescriptorTable::write(const VirtualFileSystem& vfs, int descriptor,
                               std::span<const std::byte> source,
                               std::size_t& bytes_written, std::string& error,
                               VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        bytes_written = 0;
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    auto* file = std::get_if<VfsFile>(&it->second);
    if (file == nullptr) {
        bytes_written = 0;
        return fail(error, failure, VfsErrorCode::IsDirectory,
                    "write solicitado em um descritor de diretório");
    }
    return vfs.write_file(*file, source, bytes_written, error, failure);
}

bool VfsDescriptorTable::pread(const VirtualFileSystem& vfs, int descriptor,
                               std::uint64_t offset, std::span<std::byte> destination,
                               std::size_t& bytes_read, std::string& error,
                               VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        bytes_read = 0;
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    const auto* current = std::get_if<VfsFile>(&it->second);
    if (current == nullptr || offset > current->size) {
        bytes_read = 0;
        return fail(error, failure, current == nullptr ? VfsErrorCode::IsDirectory
                                                       : VfsErrorCode::InvalidArgument,
                    "pread inválido para este descritor ou offset fora do arquivo");
    }
    auto positioned = *current;
    positioned.cursor = offset;
    positioned.append = false;
    return vfs.read_file(positioned, destination, bytes_read, error, failure);
}

bool VfsDescriptorTable::pwrite(const VirtualFileSystem& vfs, int descriptor,
                                std::uint64_t offset, std::span<const std::byte> source,
                                std::size_t& bytes_written, std::string& error,
                                VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        bytes_written = 0;
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    auto* current = std::get_if<VfsFile>(&it->second);
    if (current == nullptr || offset > current->size) {
        bytes_written = 0;
        return fail(error, failure, current == nullptr ? VfsErrorCode::IsDirectory
                                                       : VfsErrorCode::InvalidArgument,
                    "pwrite inválido para este descritor ou offset fora do arquivo");
    }
    auto positioned = *current;
    positioned.cursor = offset;
    positioned.append = false;
    if (!vfs.write_file(positioned, source, bytes_written, error, failure)) {
        return false;
    }
    current->size = std::max(current->size, positioned.size);
    return true;
}

bool VfsDescriptorTable::getdents(const VirtualFileSystem& vfs, int descriptor,
                                  std::span<std::byte> destination, std::size_t& bytes_written,
                                  std::string& error, VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        bytes_written = 0;
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    auto* directory = std::get_if<VfsDirectory>(&it->second);
    if (directory == nullptr) {
        bytes_written = 0;
        return fail(error, failure, VfsErrorCode::NotDirectory,
                    "getdents solicitado em um descritor de arquivo");
    }
    return vfs.getdents(*directory, destination, bytes_written, error, failure);
}

bool VfsDescriptorTable::seek(int descriptor, std::int64_t offset, int whence,
                              std::uint64_t& new_offset, std::string& error,
                              VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    new_offset = 0;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    auto* file = std::get_if<VfsFile>(&it->second);
    if (file == nullptr) {
        return fail(error, failure, VfsErrorCode::InvalidArgument,
                    "seek solicitado em um descritor que não é arquivo");
    }
    std::uint64_t base = 0;
    if (whence == 1) {
        base = file->cursor;
    } else if (whence == 2) {
        base = file->size;
    } else if (whence != 0) {
        return fail(error, failure, VfsErrorCode::InvalidArgument,
                    "valor whence inválido para seek");
    }
    std::uint64_t target = base;
    if (offset < 0) {
        const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1;
        if (magnitude > base) {
            return fail(error, failure, VfsErrorCode::InvalidArgument,
                        "seek resultaria em offset negativo");
        }
        target -= magnitude;
    } else {
        const auto positive = static_cast<std::uint64_t>(offset);
        if (positive > std::numeric_limits<std::uint64_t>::max() - base ||
            base + positive > file->size) {
            return fail(error, failure, VfsErrorCode::InvalidArgument,
                        "seek fora dos limites suportados pelo arquivo");
        }
        target += positive;
    }
    if (target > file->size) {
        return fail(error, failure, VfsErrorCode::InvalidArgument,
                    "seek fora dos limites suportados pelo arquivo");
    }
    file->cursor = target;
    new_offset = target;
    return true;
}

bool VfsDescriptorTable::close(int descriptor, std::string& error, VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    if (handles_.erase(descriptor) == 0) {
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    return true;
}

bool VfsDescriptorTable::stat_descriptor(int descriptor, VfsMetadata& metadata,
                                         std::string& error, VfsErrorCode* failure) const {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    if (const auto* file = std::get_if<VfsFile>(&it->second)) {
        metadata.kind = VfsMetadata::Kind::RegularFile;
        metadata.size = file->size;
        return true;
    }
    if (std::holds_alternative<VfsDevice>(it->second)) {
        metadata.kind = VfsMetadata::Kind::RegularFile;
        metadata.size = 0;
        return true;
    }
    metadata.kind = VfsMetadata::Kind::Directory;
    metadata.size = 0;
    return true;
}

bool VfsDescriptorTable::descriptor_path(int descriptor, std::string& guest_path,
                                         std::string& error) const {
    const std::lock_guard lock(handles_mutex_);
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        return fail(error, nullptr, VfsErrorCode::BadDescriptor,
                    "descritor virtual inválido");
    }
    if (const auto* file = std::get_if<VfsFile>(&it->second)) {
        guest_path = file->guest_path;
    } else if (const auto* device = std::get_if<VfsDevice>(&it->second)) {
        guest_path = device->guest_path;
    } else {
        guest_path = std::get<VfsDirectory>(it->second).guest_path;
    }
    error.clear();
    return true;
}

bool VfsDescriptorTable::descriptor_position(int descriptor, std::uint64_t& position,
                                             std::uint64_t& size,
                                             std::string& error) const {
    const std::lock_guard lock(handles_mutex_);
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        return fail(error, nullptr, VfsErrorCode::BadDescriptor,
                    "descritor virtual inválido");
    }
    if (const auto* file = std::get_if<VfsFile>(&it->second)) {
        position = file->cursor;
        size = file->size;
    } else if (std::holds_alternative<VfsDevice>(it->second)) {
        position = 0;
        size = 0;
    } else {
        const auto& directory = std::get<VfsDirectory>(it->second);
        position = directory.cursor;
        size = static_cast<std::uint64_t>(directory.entries.size());
    }
    error.clear();
    return true;
}

bool VfsDescriptorTable::truncate(const VirtualFileSystem& vfs, int descriptor,
                                  std::uint64_t size, std::string& error,
                                  VfsErrorCode* failure) {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    auto* file = std::get_if<VfsFile>(&it->second);
    if (file == nullptr) {
        return fail(error, failure, VfsErrorCode::IsDirectory,
                    "ftruncate solicitado em um descritor que não é arquivo");
    }
    return vfs.truncate_file(*file, size, error, failure);
}

bool VfsDescriptorTable::sync(const VirtualFileSystem& vfs, int descriptor,
                              std::string& error, VfsErrorCode* failure) const {
    const std::lock_guard lock(handles_mutex_);
    if (failure != nullptr) *failure = VfsErrorCode::None;
    const auto it = handles_.find(descriptor);
    if (it == handles_.end()) {
        return fail(error, failure, VfsErrorCode::BadDescriptor, "descritor virtual inválido");
    }
    const auto* file = std::get_if<VfsFile>(&it->second);
    if (file == nullptr) {
        return fail(error, failure, VfsErrorCode::IsDirectory,
                    "fsync solicitado em um descritor que não é arquivo");
    }
    return vfs.sync_file(*file, error, failure);
}

} // namespace nba16
