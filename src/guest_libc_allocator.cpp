#include "guest_libc_allocator.h"

#include "guest_abi.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <limits>
#include <mutex>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace nba16 {
namespace {

constexpr std::size_t arena_size = 128U * 1024U * 1024U;
struct Range {
    std::size_t offset;
    std::size_t span;
    std::size_t requested;
};

struct MallocReplacement {
    std::uint64_t size;
    std::uint64_t flags;
    void* init;
    void* finalize;
    void* malloc_fn;
    void* free_fn;
    void* calloc_fn;
    void* realloc_fn;
    void* memalign_fn;
    void* reallocalign_fn;
    void* posix_memalign_fn;
    void* stats_fn;
    void* stats_fast_fn;
    void* usable_size_fn;
};
struct ProcessLibcParameters {
    std::uint64_t size;
    std::uint32_t entry_count;
    std::uint32_t internal_heap;
    std::uint64_t heap_size;
    std::uint64_t delayed_alloc;
    std::uint64_t extended_alloc;
    std::uint64_t initial_size;
    MallocReplacement* selector;
    void* next;
};
static_assert(sizeof(MallocReplacement) == 0x70);
static_assert(sizeof(ProcessLibcParameters) == 0x40);

std::mutex allocator_mutex;
std::byte* arena{};
std::vector<Range> free_ranges;
std::vector<Range> used_ranges;
std::uintptr_t original_libc_malloc{};
std::atomic_size_t fallback_log_count{};

std::size_t align_up(std::size_t value, std::size_t alignment) {
    if (alignment < 16) alignment = 16;
    if ((alignment & (alignment - 1)) != 0 ||
        value > std::numeric_limits<std::size_t>::max() - (alignment - 1)) return 0;
    return (value + alignment - 1) & ~(alignment - 1);
}

void* allocate_locked(std::size_t bytes, std::size_t alignment) {
    if (!arena || free_ranges.empty()) return nullptr;
    if (bytes == 0) bytes = 1;
    if (alignment < 16) alignment = 16;
    if ((alignment & (alignment - 1)) != 0) return nullptr;
    const auto rounded = align_up(bytes, 16);
    if (!rounded) return nullptr;
    const auto base = reinterpret_cast<std::uintptr_t>(arena);
    for (std::size_t index = 0; index < free_ranges.size(); ++index) {
        const auto range = free_ranges[index];
        if (range.span < rounded) continue;
        const auto aligned_address = align_up(base + range.offset, alignment);
        if (!aligned_address || aligned_address < base) continue;
        const auto offset = aligned_address - base;
        if (offset < range.offset || offset - range.offset > range.span ||
            rounded > range.span - (offset - range.offset)) continue;
        const auto prefix = offset - range.offset;
        const auto suffix = range.span - prefix - rounded;
        try {
            used_ranges.push_back({offset, rounded, bytes});
            if (prefix != 0 && suffix != 0) {
                free_ranges[index] = {range.offset, prefix, 0};
                free_ranges.insert(free_ranges.begin() + static_cast<std::ptrdiff_t>(index + 1),
                                   {offset + rounded, suffix, 0});
            } else if (prefix != 0) {
                free_ranges[index] = {range.offset, prefix, 0};
            } else if (suffix != 0) {
                free_ranges[index] = {offset + rounded, suffix, 0};
            } else {
                free_ranges.erase(free_ranges.begin() + static_cast<std::ptrdiff_t>(index));
            }
        } catch (...) {
            if (!used_ranges.empty() && used_ranges.back().offset == offset)
                used_ranges.pop_back();
            return nullptr;
        }
        return arena + offset;
    }
    return nullptr;
}

void free_locked(void* ptr) {
    if (!arena || !ptr) return;
    const auto address = reinterpret_cast<std::uintptr_t>(ptr);
    const auto base = reinterpret_cast<std::uintptr_t>(arena);
    if (address < base || address - base >= arena_size) return;
    const auto offset = static_cast<std::size_t>(address - base);
    const auto used = std::find_if(used_ranges.begin(), used_ranges.end(),
        [offset](const Range& range) { return range.offset == offset; });
    if (used == used_ranges.end()) return;
    const Range released = *used;
    used_ranges.erase(used);
    const auto position = std::lower_bound(free_ranges.begin(), free_ranges.end(), released.offset,
        [](const Range& range, std::size_t target) { return range.offset < target; });
    try {
        free_ranges.insert(position, {released.offset, released.span, 0});
    } catch (...) {
        used_ranges.push_back(released);
        return;
    }
    for (std::size_t index = 0; index + 1 < free_ranges.size();) {
        if (free_ranges[index].offset + free_ranges[index].span == free_ranges[index + 1].offset) {
            free_ranges[index].span += free_ranges[index + 1].span;
            free_ranges.erase(free_ranges.begin() + static_cast<std::ptrdiff_t>(index + 1));
        } else {
            ++index;
        }
    }
}

int NBA16_GUEST_SYSV_ABI replacement_init() { return arena ? 0 : 12; }
int NBA16_GUEST_SYSV_ABI replacement_finalize() { return 0; }
void* NBA16_GUEST_SYSV_ABI replacement_malloc(std::size_t size) {
    std::lock_guard lock(allocator_mutex); return allocate_locked(size, 16);
}
void NBA16_GUEST_SYSV_ABI replacement_free(void* ptr) {
    std::lock_guard lock(allocator_mutex); free_locked(ptr);
}
void* NBA16_GUEST_SYSV_ABI replacement_calloc(std::size_t count, std::size_t size) {
    if (size && count > std::numeric_limits<std::size_t>::max() / size) return nullptr;
    const auto bytes = count * size;
    auto* ptr = replacement_malloc(bytes);
    if (ptr) std::memset(ptr, 0, bytes);
    if (getenv("NBA16_TRACE_MEMORY") != nullptr && bytes >= 0x1000)
        std::fprintf(stderr, "MEM libc-calloc count=%zu size=0x%zx -> %p\n", count, size, ptr);
    return ptr;
}
void* NBA16_GUEST_SYSV_ABI replacement_realloc(void* ptr, std::size_t size) {
    if (!ptr) return replacement_malloc(size);
    if (!size) { replacement_free(ptr); return nullptr; }
    std::size_t old_size{};
    {
        std::lock_guard lock(allocator_mutex);
        const auto address = reinterpret_cast<std::uintptr_t>(ptr);
        const auto base = reinterpret_cast<std::uintptr_t>(arena);
        if (!arena || address < base || address - base >= arena_size) return nullptr;
        const auto offset = static_cast<std::size_t>(address - base);
        const auto block = std::find_if(used_ranges.begin(), used_ranges.end(),
            [offset](const Range& range) { return range.offset == offset; });
        if (block == used_ranges.end()) return nullptr;
        old_size = block->requested;
        if (size <= old_size) { block->requested = size; return ptr; }
    }
    auto* replacement = replacement_malloc(size);
    if (!replacement) return nullptr;
    std::memcpy(replacement, ptr, old_size);
    replacement_free(ptr);
    return replacement;
}
void* NBA16_GUEST_SYSV_ABI replacement_memalign(std::size_t alignment, std::size_t size) {
    std::lock_guard lock(allocator_mutex);
    auto* result = allocate_locked(size, alignment);
    if (getenv("NBA16_TRACE_MEMORY") != nullptr && size >= 0x1000)
        std::fprintf(stderr, "MEM libc-memalign alignment=0x%zx size=0x%zx -> %p\n",
            alignment, size, result);
    return result;
}
void* NBA16_GUEST_SYSV_ABI replacement_reallocalign(void* ptr, std::size_t size,
                                                     std::size_t alignment) {
    if (!ptr) return replacement_memalign(alignment, size);
    std::size_t old_size{};
    {
        std::lock_guard lock(allocator_mutex);
        const auto address = reinterpret_cast<std::uintptr_t>(ptr);
        const auto base = reinterpret_cast<std::uintptr_t>(arena);
        if (!arena || address < base || address - base >= arena_size) return nullptr;
        const auto offset = static_cast<std::size_t>(address - base);
        const auto block = std::find_if(used_ranges.begin(), used_ranges.end(),
            [offset](const Range& range) { return range.offset == offset; });
        if (block == used_ranges.end()) return nullptr;
        old_size = block->requested;
        if (size <= old_size && (reinterpret_cast<std::uintptr_t>(ptr) & (alignment - 1)) == 0) {
            block->requested = size; return ptr;
        }
    }
    auto* replacement = replacement_memalign(alignment, size);
    if (!replacement) return nullptr;
    std::memcpy(replacement, ptr, std::min(old_size, size));
    replacement_free(ptr);
    return replacement;
}
int NBA16_GUEST_SYSV_ABI replacement_posix_memalign(void** output,
                                                    std::size_t alignment,
                                                    std::size_t size) {
    if (!output || alignment < sizeof(void*) || (alignment & (alignment - 1))) return 22;
    auto* ptr = replacement_memalign(alignment, size);
    if (!ptr) return 12;
    *output = ptr; return 0;
}
int NBA16_GUEST_SYSV_ABI replacement_stats(void*) { return 0; }
int NBA16_GUEST_SYSV_ABI replacement_stats_fast(void*) { return 0; }
std::size_t NBA16_GUEST_SYSV_ABI replacement_usable_size(void* ptr) {
    std::lock_guard lock(allocator_mutex);
    if (!arena || !ptr) return 0;
    const auto address = reinterpret_cast<std::uintptr_t>(ptr);
    const auto base = reinterpret_cast<std::uintptr_t>(arena);
    if (address < base || address - base >= arena_size) return 0;
    const auto offset = static_cast<std::size_t>(address - base);
    const auto block = std::find_if(used_ranges.begin(), used_ranges.end(),
        [offset](const Range& range) { return range.offset == offset; });
    return block == used_ranges.end() ? 0 : block->requested;
}

MallocReplacement api_table{
    sizeof(MallocReplacement), 1,
    reinterpret_cast<void*>(&replacement_init), reinterpret_cast<void*>(&replacement_finalize),
    reinterpret_cast<void*>(&replacement_malloc), reinterpret_cast<void*>(&replacement_free),
    reinterpret_cast<void*>(&replacement_calloc), reinterpret_cast<void*>(&replacement_realloc),
    reinterpret_cast<void*>(&replacement_memalign), reinterpret_cast<void*>(&replacement_reallocalign),
    reinterpret_cast<void*>(&replacement_posix_memalign), reinterpret_cast<void*>(&replacement_stats),
    reinterpret_cast<void*>(&replacement_stats_fast), reinterpret_cast<void*>(&replacement_usable_size)
};
// The procparam selector identifies the replacement mechanism; the kernel
// callback sceKernelGetSanitizerMallocReplace supplies api_table separately.
MallocReplacement selector{sizeof(MallocReplacement), 1};
ProcessLibcParameters libc_parameters{sizeof(ProcessLibcParameters), 2, 0, 0, 0, 0, 0,
                                      &selector, nullptr};

bool reserve_low_arena() {
#ifdef _WIN32
    constexpr std::uintptr_t start = 0x10000000;
    constexpr std::uintptr_t limit = 0x70000000;
    constexpr std::uintptr_t step = 0x01000000;
    for (auto address = start; address + arena_size < limit; address += step) {
        auto* memory = static_cast<std::byte*>(VirtualAlloc(reinterpret_cast<void*>(address),
            arena_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (memory) {
            arena = memory;
            try {
                free_ranges.clear();
                used_ranges.clear();
                free_ranges.reserve(65536);
                used_ranges.reserve(65536);
                free_ranges.push_back({0, arena_size, 0});
            } catch (...) {
                VirtualFree(arena, 0, MEM_RELEASE);
                arena = nullptr;
                free_ranges.clear();
                used_ranges.clear();
                return false;
            }
            return reinterpret_cast<std::uintptr_t>(arena) + arena_size <= 0x80000000ULL;
        }
    }
#endif
    return false;
}

} // namespace

bool configure_guest_libc_allocator(void* process_parameter, std::string& error) {
    if constexpr (!guest_sysv_abi_available) {
        error = "A ABI SysV x86-64 é necessária para o allocator do guest.";
        return false;
    }
    if (!process_parameter) { error = "PT_SCE_PROC_PARAM ausente."; return false; }
    if (!arena && !reserve_low_arena()) {
        error = "Não foi possível reservar 128 MiB abaixo de 2 GiB para o allocator do guest.";
        return false;
    }
    auto* parameters = &libc_parameters;
    std::memcpy(static_cast<std::byte*>(process_parameter) + 0x38,
                &parameters, sizeof(parameters));
    std::fprintf(stderr, "Guest allocator setup procparam=%p param=%p size=%llu entries=%u heap=%u selector=%p api=%p arena=%p..%p\n",
        process_parameter, static_cast<void*>(parameters),
        static_cast<unsigned long long>(parameters->size), parameters->entry_count,
        parameters->internal_heap, static_cast<void*>(parameters->selector),
        static_cast<void*>(&api_table), static_cast<void*>(arena),
        static_cast<void*>(arena + arena_size));
    error.clear();
    return true;
}

void* NBA16_GUEST_SYSV_ABI guest_sanitizer_malloc_replace() {
    std::fprintf(stderr, "Guest sanitizer allocator callback -> %p\n", static_cast<void*>(&api_table));
    return &api_table;
}

bool guest_libc_arena_region(std::uint64_t& begin, std::size_t& size) noexcept {
    std::lock_guard lock(allocator_mutex);
    if (!arena) {
        begin = 0;
        size = 0;
        return false;
    }
    begin = reinterpret_cast<std::uintptr_t>(arena);
    size = arena_size;
    return true;
}

void set_guest_libc_original_malloc(std::uintptr_t address) noexcept {
    original_libc_malloc = address;
}

void* NBA16_GUEST_SYSV_ABI guest_libc_malloc_fallback(std::size_t size) {
    using GuestMalloc = void* (NBA16_GUEST_SYSV_ABI *)(std::size_t);
    void* original_result = original_libc_malloc == 0 ? nullptr :
        reinterpret_cast<GuestMalloc>(original_libc_malloc)(size);
    void* result = original_result;
    if (result == nullptr) result = replacement_malloc(size);
    const auto call_number = fallback_log_count.fetch_add(1, std::memory_order_relaxed);
    if (call_number < 32 || call_number >= 700 || size == 0x1c8 ||
        (getenv("NBA16_TRACE_MEMORY") != nullptr && size >= 0x1000))
        std::fprintf(stderr, "Guest libc malloc fallback-call=%zu size=%zu original=%p final=%p\n",
                     call_number, size, original_result, result);
    return result;
}

void NBA16_GUEST_SYSV_ABI guest_libc_free_fallback(void* pointer) {
    replacement_free(pointer);
}

} // namespace nba16
