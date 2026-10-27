#pragma once

#include <filesystem>
#include <string>

namespace nba16 {

struct NativeRuntimePaths {
    std::filesystem::path game_root;
    std::filesystem::path user_root;
    std::filesystem::path save_root;
};

bool resolve_native_runtime_paths(const std::filesystem::path& executable_path,
                                 const std::filesystem::path& requested_user_root,
                                 const std::string& title_id,
                                 NativeRuntimePaths& paths,
                                 std::string& error);

} // namespace nba16
