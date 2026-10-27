#include "native_runtime_services.h"

#include "app_content_runtime.h"
#include "fiber_runtime.h"
#include "gnm_hardware_init.h"
#include "kernel_runtime.h"
#include "libc_runtime.h"
#include "netctl_runtime.h"
#include "pad_runtime.h"
#include "playgo_runtime.h"
#include "posix_aio_imports.h"
#include "posix_fs_imports.h"
#include "sanitizer_fiber_imports.h"
#include "sysmodule_runtime.h"
#include "unsupported_posix_imports.h"
#include "user_service_runtime.h"
#include "video_out_runtime.h"

namespace nba16 {

bool register_native_runtime_services(ImportResolver& resolver,
                                      const std::filesystem::path& game_root,
                                      std::string& error) {
    set_native_playgo_game_root(game_root);
    return register_native_fiber_imports(resolver, error) &&
        register_native_sysmodule_imports(resolver, error) &&
        register_native_app_content_imports(resolver, error) &&
        register_native_playgo_imports(resolver, error) &&
        register_native_shareplay_imports(resolver, error) &&
        register_gnm_hardware_init_imports(resolver, error) &&
        register_native_user_service_imports(resolver, error) &&
        register_native_pad_imports(resolver, error) &&
        register_native_netctl_imports(resolver, error) &&
        register_native_video_out_imports(resolver, error) &&
        register_native_libc_imports(resolver, error) &&
        register_native_kernel_runtime_imports(resolver, error) &&
        register_native_aio_imports(resolver, error) &&
        register_native_posix_fs_imports(resolver, error) &&
        register_native_sanitizer_fiber_imports(resolver, error) &&
        register_native_unsupported_posix_imports(resolver, error);
}

} // namespace nba16
