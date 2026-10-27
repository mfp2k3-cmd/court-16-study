#include "native_runtime_paths.h"

#include <system_error>

namespace nba16 {

bool resolve_native_runtime_paths(const std::filesystem::path& executable_path,
                                 const std::filesystem::path& requested_user_root,
                                 const std::string& title_id,
                                 NativeRuntimePaths& paths,
                                 std::string& error) {
    if (executable_path.empty() || title_id.empty() || title_id == "." ||
        title_id == ".." || title_id.find_first_of("/\\") != std::string::npos) {
        error = "caminho do executável ou identificador do título inválido";
        return false;
    }

    std::error_code filesystem_error;
    paths.game_root = std::filesystem::absolute(executable_path, filesystem_error).parent_path();
    if (filesystem_error || paths.game_root.empty()) {
        error = filesystem_error ? filesystem_error.message()
                                 : "não foi possível determinar a pasta do jogo";
        return false;
    }

    if (requested_user_root.empty()) {
        const auto temporary_root = std::filesystem::temp_directory_path(filesystem_error);
        if (filesystem_error) {
            error = filesystem_error.message();
            return false;
        }
        paths.user_root = temporary_root / "nba16-independent-user";
    } else {
        paths.user_root = std::filesystem::absolute(requested_user_root, filesystem_error);
        if (filesystem_error) {
            error = filesystem_error.message();
            return false;
        }
    }

    paths.save_root = paths.user_root / "savedata" / "1" / title_id;
    error.clear();
    return true;
}

} // namespace nba16
