#include "guest_execution_stack.h"

#include <cstdint>
#include <limits>
#include <utility>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace nba16 {

GuestExecutionStack::~GuestExecutionStack() { release(); }

GuestExecutionStack::GuestExecutionStack(GuestExecutionStack&& other) noexcept
    : allocation_(std::exchange(other.allocation_, nullptr)),
      allocation_size_(std::exchange(other.allocation_size_, 0)) {}

GuestExecutionStack& GuestExecutionStack::operator=(GuestExecutionStack&& other) noexcept {
    if (this != &other) {
        release();
        allocation_ = std::exchange(other.allocation_, nullptr);
        allocation_size_ = std::exchange(other.allocation_size_, 0);
    }
    return *this;
}

void GuestExecutionStack::release() noexcept {
    if (allocation_ == nullptr) return;
#ifdef _WIN32
    VirtualFree(allocation_, 0, MEM_RELEASE);
#else
    munmap(allocation_, allocation_size_);
#endif
    allocation_ = nullptr;
    allocation_size_ = 0;
}

bool GuestExecutionStack::reserve(std::size_t size, std::string& error) {
    release();
    if (size == 0) {
        error = "o tamanho da pilha convidada não pode ser zero";
        return false;
    }
#ifdef _WIN32
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const auto granularity = static_cast<std::uint64_t>(system_info.dwAllocationGranularity);
    if (granularity == 0 || size > std::numeric_limits<std::uint64_t>::max() - granularity) {
        error = "granularidade de alocação do Windows inválida";
        return false;
    }
    constexpr std::uint64_t low_start = 0x0800000000ULL;
    constexpr std::uint64_t low_end = 0x1000000000ULL;
    auto candidate = low_start;
    const auto requested = static_cast<std::uint64_t>(size);
    while (candidate <= low_end && requested <= low_end - candidate) {
        auto* result = VirtualAlloc(reinterpret_cast<void*>(candidate), size,
                                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (result != nullptr) {
            allocation_ = result;
            allocation_size_ = size;
            return true;
        }
        candidate += granularity;
    }
    error = "não foi possível reservar uma pilha convidada na faixa baixa de endereços do PS4";
    return false;
#else
    const auto page_value = sysconf(_SC_PAGESIZE);
    if (page_value <= 0) {
        error = "tamanho de página do host inválido ao reservar pilha convidada";
        return false;
    }
    const auto page = static_cast<std::size_t>(page_value);
    if (size > std::numeric_limits<std::size_t>::max() - (page - 1U)) {
        error = "tamanho da pilha convidada excede o espaço endereçável";
        return false;
    }
    const auto aligned_size = ((size + page - 1U) / page) * page;
    auto* result = mmap(nullptr, aligned_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED) {
        error = "mmap falhou ao reservar pilha convidada";
        return false;
    }
    allocation_ = result;
    allocation_size_ = aligned_size;
    return true;
#endif
}

void* GuestExecutionStack::bottom() const noexcept { return allocation_; }

void* GuestExecutionStack::top() const noexcept {
    if (allocation_ == nullptr) return nullptr;
    return static_cast<std::byte*>(allocation_) + allocation_size_;
}

std::size_t GuestExecutionStack::size() const noexcept { return allocation_size_; }

} // namespace nba16
