#include "native_guest_process.h"

#include "guest_libc_allocator.h"
#include "kernel_runtime.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <system_error>

namespace nba16 {
namespace {

bool register_image_regions(const GuestImageMap& map, std::string_view name,
                            std::string& error) {
    for (const auto& region : map.regions) {
        std::uint32_t protection = 0;
        if ((region.flags & 4U) != 0) protection |= 1U;
        if ((region.flags & 2U) != 0) protection |= 2U;
        if ((region.flags & 1U) != 0) protection |= 4U;
        if (!register_guest_query_region(map.load_bias + region.virtual_address,
                region.memory_size, protection, name)) {
            error = "região de memória convidada não pôde ser registrada: " +
                    std::string(name);
            return false;
        }
    }
    return true;
}

} // namespace

bool NativeGuestProcess::initialize(const NativeRuntimePaths& paths,
        const NativeExecutableImage& executable, const NativeProcessModules& modules,
        std::size_t stack_size, std::string& error) {
    if (initialized_) {
        error = "o processo convidado já foi inicializado";
        return false;
    }
    if (!executable.memory_finalized || !executable.imported_relocations_applied) {
        error = "a imagem principal ainda não foi finalizada";
        return false;
    }
    if (!stack_.reserve(stack_size, error)) return false;

    std::error_code directory_error;
    std::filesystem::create_directories(paths.save_root, directory_error);
    if (directory_error) {
        error = directory_error.message();
        return false;
    }
    if (!context_.initialize(paths.game_root, paths.user_root, paths.save_root,
            executable.map, executable.memory, modules.modules(), error)) return false;

    if (!register_image_regions(executable.map, "eboot.bin", error)) return false;
    for (const auto& name : modules.modules().loaded_module_names()) {
        const auto* module = modules.modules().find(name);
        if (module != nullptr && !register_image_regions(module->image_map(), name, error))
            return false;
    }

    const auto stack_begin = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(stack_.bottom()));
    if (!context_.memory().add_host_region(stack_begin, stack_.size(), error)) {
        error = "pilha convidada não pôde ser registrada: " + error;
        return false;
    }
    if (!register_guest_query_region(stack_begin, stack_.size(), 3U, "main stack")) {
        error = "pilha convidada não pôde ser registrada para consulta";
        return false;
    }

    std::uint64_t heap_begin{};
    std::size_t heap_size{};
    if (guest_libc_arena_region(heap_begin, heap_size)) {
        if (!context_.memory().add_host_region(heap_begin, heap_size, error)) {
            error = "heap convidado não pôde ser registrado: " + error;
            return false;
        }
        if (!register_guest_query_region(heap_begin, heap_size, 3U, "main heap")) {
            error = "heap convidado não pôde ser registrado para consulta";
            return false;
        }
    }

    set_guest_usrstack_top(static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(stack_.top())));
    initialized_ = true;
    if (std::getenv("NBA16_TRACE_GPU_MEMORY") != nullptr) {
        for (const auto& region : context_.memory().snapshot_regions()) {
            std::fprintf(stderr,
                "GPU-MEM-REGION guest=0x%llx host=0x%llx size=0x%zx "
                "r=%u w=%u x=%u origin=%u\n",
                static_cast<unsigned long long>(region.guest_address),
                static_cast<unsigned long long>(region.host_address), region.size,
                region.readable ? 1U : 0U, region.writable ? 1U : 0U,
                region.executable ? 1U : 0U, static_cast<unsigned>(region.origin));
        }
    }
    error.clear();
    return true;
}

GuestExecutionStack& NativeGuestProcess::stack() noexcept { return stack_; }
GuestProcessContext& NativeGuestProcess::context() noexcept { return context_; }
bool NativeGuestProcess::is_initialized() const noexcept { return initialized_; }

} // namespace nba16
