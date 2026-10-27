#include "guest_tls_runtime.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>
#include <utility>

namespace nba16 {
namespace {

std::atomic<GuestTlsRuntime*> current_runtime{};
std::atomic<std::uint64_t> next_runtime_id{1};

struct AlignedTlsBlock {
    void* address{};
    std::size_t alignment{};

    AlignedTlsBlock() = default;
    AlignedTlsBlock(const AlignedTlsBlock&) = delete;
    AlignedTlsBlock& operator=(const AlignedTlsBlock&) = delete;
    AlignedTlsBlock(AlignedTlsBlock&& other) noexcept
        : address(std::exchange(other.address, nullptr)),
          alignment(std::exchange(other.alignment, 0)) {}
    AlignedTlsBlock& operator=(AlignedTlsBlock&& other) noexcept {
        if (this == &other) return *this;
        reset();
        address = std::exchange(other.address, nullptr);
        alignment = std::exchange(other.alignment, 0);
        return *this;
    }
    ~AlignedTlsBlock() { reset(); }

    void reset() noexcept {
        if (address != nullptr) {
            ::operator delete(address, std::align_val_t(alignment));
            address = nullptr;
            alignment = 0;
        }
    }
};

struct ThreadTlsBlocks {
    std::unordered_map<std::uint64_t, AlignedTlsBlock> modules;
};

thread_local std::unordered_map<std::uint64_t, ThreadTlsBlocks> thread_tls_blocks;

bool is_power_of_two(std::uint64_t value) noexcept {
    return value != 0 && (value & (value - 1U)) == 0;
}

} // namespace

GuestTlsRuntime::~GuestTlsRuntime() {
    auto* expected = this;
    current_runtime.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
}

GuestTlsRuntime::GuestTlsRuntime()
    : runtime_id_(next_runtime_id.fetch_add(1, std::memory_order_relaxed)) {}

bool GuestTlsRuntime::initialize(const std::vector<GuestTlsImage>& images,
                                 std::string& error) {
    std::unique_lock lock(lock_);
    if (initialized_) {
        error = "O runtime TLS já foi inicializado.";
        return false;
    }
    std::map<std::uint64_t, ModuleTemplate> parsed;
    for (const auto& image : images) {
        if (image.module_id == 0) continue;
        if (!is_power_of_two(image.alignment) ||
            image.alignment > (1U << 20U) ||
            image.memory_size > std::numeric_limits<std::size_t>::max() ||
            image.memory_size > (512U * 1024U * 1024U) ||
            image.initial_bytes.size() > image.memory_size) {
            error = "Metadados PT_TLS inválidos ou acima do limite seguro no módulo " +
                    std::to_string(image.module_id) + ".";
            return false;
        }
        ModuleTemplate module{};
        module.alignment = image.alignment;
        module.memory_size = image.memory_size;
        module.initial_bytes = image.initial_bytes;
        if (!parsed.emplace(image.module_id, std::move(module)).second) {
            error = "ID de módulo TLS duplicado: " + std::to_string(image.module_id) + ".";
            return false;
        }
    }
    if (!parsed.contains(1)) {
        error = "A tabela TLS precisa reservar o módulo 1 do executável principal.";
        return false;
    }
    modules_ = std::move(parsed);
    initialized_ = true;
    return true;
}

bool GuestTlsRuntime::register_import(ImportResolver& resolver, std::string& error) {
    auto* expected = static_cast<GuestTlsRuntime*>(nullptr);
    if (!current_runtime.compare_exchange_strong(expected, this, std::memory_order_acq_rel) &&
        expected != this) {
        error = "Outro runtime TLS já está ativo neste processo.";
        return false;
    }
    if (!resolver.register_function("libkernel", "libkernel", "vNe1w4diLCs",
                                    &GuestTlsRuntime::tls_get_addr, error)) {
        expected = this;
        current_runtime.compare_exchange_strong(expected, nullptr, std::memory_order_acq_rel);
        return false;
    }
    return true;
}

void* GuestTlsRuntime::get_address(std::uint64_t module_id, std::uint64_t offset) noexcept {
    try {
        std::shared_lock lock(lock_);
        const auto module = modules_.find(module_id);
        if (!initialized_ || module == modules_.end() || offset > module->second.memory_size) {
            return nullptr;
        }

        constexpr auto minimum_alignment = alignof(std::max_align_t);
        const auto alignment = static_cast<std::size_t>(
            std::max<std::uint64_t>(module->second.alignment, minimum_alignment));
        auto& thread_blocks = thread_tls_blocks[runtime_id_].modules;
        auto block = thread_blocks.find(module_id);
        if (block == thread_blocks.end()) {
            AlignedTlsBlock created{};
            created.alignment = alignment;
            const auto allocation_size = static_cast<std::size_t>(
                std::max<std::uint64_t>(module->second.memory_size, 1));
            created.address = ::operator new(allocation_size, std::align_val_t(alignment));
            std::memset(created.address, 0, allocation_size);
            if (!module->second.initial_bytes.empty()) {
                std::memcpy(created.address, module->second.initial_bytes.data(),
                            module->second.initial_bytes.size());
            }
            block = thread_blocks.emplace(module_id, std::move(created)).first;
        }
        return static_cast<std::byte*>(block->second.address) +
               static_cast<std::size_t>(offset);
    } catch (...) {
        return nullptr;
    }
}

GuestTlsRuntime* GuestTlsRuntime::active_runtime() noexcept {
    return current_runtime.load(std::memory_order_acquire);
}

void* NBA16_GUEST_SYSV_ABI GuestTlsRuntime::tls_get_addr(const GuestTlsIndex* index) noexcept {
    if (index == nullptr) return nullptr;
    auto* runtime = active_runtime();
    return runtime == nullptr ? nullptr : runtime->get_address(index->module_id, index->offset);
}

} // namespace nba16
