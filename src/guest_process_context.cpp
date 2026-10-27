#include "guest_process_context.h"

namespace nba16 {
namespace {

thread_local GuestProcessContext* active_guest_process_context{};

} // namespace

bool GuestProcessContext::initialize(const std::filesystem::path& game_root,
                                     const std::filesystem::path& user_root,
                                     const std::filesystem::path& save_root,
                                     const GuestImageMap& executable_map,
                                     const GuestImageMemory& executable_memory,
                                     const Ps4ModuleSet& modules,
                                     std::string& error) {
    if (initialization_attempted_) {
        error = "a inicialização do contexto já foi tentada; descarte-o antes de tentar novamente";
        return false;
    }
    initialization_attempted_ = true;
    if (!executable_memory.is_reserved() || !executable_memory.is_finalized() ||
        !executable_map.relative_relocations_applied ||
        !executable_map.imported_relocations_applied) {
        error = "o executável principal precisa estar carregado, relocado e protegido";
        return false;
    }
    if (!vfs_.mount_app0(game_root, error)) return false;
    vfs_.mount_download0(user_root);
    vfs_.mount_savedata0(save_root);
    if (!vfs_.mount_temporary0(user_root / "temp", error)) return false;
    if (!memory_.add_image(executable_map, executable_memory, error)) {
        error = "falha ao registrar a memória ativa do executável: " + error;
        return false;
    }
    if (!modules.register_memory(memory_, error)) {
        error = "falha ao registrar a memória dos módulos do processo: " + error;
        return false;
    }
    initialized_ = true;
    error.clear();
    return true;
}

VirtualFileSystem& GuestProcessContext::vfs() noexcept { return vfs_; }
VfsDescriptorTable& GuestProcessContext::descriptors() noexcept { return descriptors_; }
GuestMemoryAccess& GuestProcessContext::memory() noexcept { return memory_; }
GuestAioRuntime& GuestProcessContext::aio() noexcept { return aio_; }
bool GuestProcessContext::is_initialized() const noexcept { return initialized_; }

GuestProcessContext* current_guest_process_context() noexcept {
    return active_guest_process_context;
}

ScopedGuestProcessContext::ScopedGuestProcessContext(GuestProcessContext* context) noexcept
    : previous_(active_guest_process_context) {
    if (context != nullptr) active_guest_process_context = context;
}

ScopedGuestProcessContext::~ScopedGuestProcessContext() {
    active_guest_process_context = previous_;
}

} // namespace nba16
