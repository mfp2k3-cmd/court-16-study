#include "guest_tcb_runtime.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace nba16 {
namespace {
std::atomic<std::uint64_t> total_patched_loads{};

#ifdef _WIN32
struct GuestTcbStorage {
    std::array<std::uint64_t, 3> tcb{};
    // The PS4 tcb_thread field points to a GuestThread record, whose first
    // field is the TCB pointer. Keep a guest-visible record instead of a
    // separate scratch context buffer (as done by the initial stub).
    // libkernel's initial-thread setup clears/reads fields through +0x3f8;
    // reserve a full 0x400-byte record even before the HLE thread layer owns it.
    alignas(16) std::array<std::uint64_t, 128> guest_thread{};
};
static_assert(sizeof(GuestTcbStorage::guest_thread) == 0x400);

DWORD tcb_slot = TLS_OUT_OF_INDEXES;
DWORD thread_slot = TLS_OUT_OF_INDEXES;
std::once_flag tls_slots_once;
bool tls_slots_ready{};
std::string tls_slots_error;
thread_local std::unique_ptr<GuestTcbStorage> current_thread_storage;

bool prepare_slots(std::string& error) {
    std::call_once(tls_slots_once, [] {
        tcb_slot = TlsAlloc();
        thread_slot = TlsAlloc();
        tls_slots_ready = tcb_slot != TLS_OUT_OF_INDEXES &&
            thread_slot != TLS_OUT_OF_INDEXES && tcb_slot < 64 && thread_slot < 64;
        if (!tls_slots_ready) {
            tls_slots_error = "Não foi possível reservar dois slots TLS baixos do TEB para o TCB PS4.";
        }
    });
    if (!tls_slots_ready) {
        error = tls_slots_error;
        return false;
    }
    if (current_thread_storage == nullptr) {
        current_thread_storage.reset(new (std::nothrow) GuestTcbStorage{});
        if (current_thread_storage == nullptr) {
            error = "Sem memória para criar o TCB da thread principal do guest.";
            return false;
        }
        auto* storage = current_thread_storage.get();
        storage->tcb[0] = reinterpret_cast<std::uint64_t>(storage->tcb.data());
        storage->tcb[1] = 0; // DTV: o TLS dinâmico é servido separadamente pelo runtime.
        storage->guest_thread[0] = reinterpret_cast<std::uint64_t>(storage->tcb.data());
        storage->tcb[2] = reinterpret_cast<std::uint64_t>(storage->guest_thread.data());
        // libkernel represents this waiter list as a tail queue: +0x1a0 is
        // the first link and +0x1a8 points to the field where the last link
        // belongs. For an empty list, the tail points to the first-link slot.
        constexpr std::size_t waiter_queue_head_index = 0x1a0 / sizeof(std::uint64_t);
        constexpr std::size_t waiter_queue_tail_index = 0x1a8 / sizeof(std::uint64_t);
        storage->guest_thread[waiter_queue_tail_index] = reinterpret_cast<std::uint64_t>(
            &storage->guest_thread[waiter_queue_head_index]);
    }
    if (!TlsSetValue(tcb_slot, current_thread_storage->tcb.data()) ||
        !TlsSetValue(thread_slot, current_thread_storage->guest_thread.data())) {
        error = "TlsSetValue falhou ao instalar o TCB PS4 na thread atual (erro " +
                std::to_string(GetLastError()) + ").";
        return false;
    }
    return true;
}
#else
bool prepare_slots(std::string& error) {
    error.clear();
    return true;
}
#endif

} // namespace

std::uint64_t guest_tcb_patched_load_count() noexcept {
    return total_patched_loads.load(std::memory_order_relaxed);
}

void* guest_tcb_current_thread_record() noexcept {
#ifdef _WIN32
    if (thread_slot == TLS_OUT_OF_INDEXES) return nullptr;
    return TlsGetValue(thread_slot);
#else
    return nullptr;
#endif
}

int* guest_tcb_errno_location() noexcept {
    // The guest's __error accessor resolves errno at thread-record +0x188.
    constexpr std::size_t errno_offset = 0x188;
    auto* record = static_cast<std::byte*>(guest_tcb_current_thread_record());
    return record == nullptr ? nullptr : reinterpret_cast<int*>(record + errno_offset);
}

bool initialize_guest_tcb(std::string& error) {
    return prepare_slots(error);
}

void clear_guest_tcb_for_current_thread() noexcept {
#ifdef _WIN32
    if (tcb_slot != TLS_OUT_OF_INDEXES) (void)TlsSetValue(tcb_slot, nullptr);
    if (thread_slot != TLS_OUT_OF_INDEXES) (void)TlsSetValue(thread_slot, nullptr);
    current_thread_storage.reset();
#endif
}

bool patch_guest_tcb_loads(GuestImageMap& map, GuestImageMemory& memory,
                           std::uint64_t& patched_loads, std::string& error) {
    patched_loads = 0;
    if (!prepare_slots(error)) return false;
#ifdef _WIN32
    const auto tcb_displacement = static_cast<std::uint32_t>(0x1480U + 8U * tcb_slot);
    const auto thread_displacement = static_cast<std::uint32_t>(0x1480U + 8U * thread_slot);
    constexpr std::size_t load_size = 9;
    for (auto& region : map.regions) {
        if ((region.flags & 1U) == 0 || region.bytes.size() < load_size) continue;
        for (std::size_t offset = 0; offset <= region.bytes.size() - load_size; ++offset) {
            auto* instruction = region.bytes.data() + offset;
            if (instruction[0] != 0x64 || (instruction[1] & 0xf8U) != 0x48 ||
                instruction[2] != 0x8b || (instruction[3] & 0xc7U) != 0x04 ||
                instruction[4] != 0x25) continue;
            std::uint32_t fs_offset{};
            std::memcpy(&fs_offset, instruction + 5, sizeof(fs_offset));
            if (fs_offset != 0 && fs_offset != 0x10) continue;

            std::array<std::byte, load_size> patch{};
            patch[0] = std::byte{0x65}; // GS addresses the Windows TEB.
            std::memcpy(patch.data() + 1, instruction + 1, load_size - 1);
            const auto displacement = fs_offset == 0 ? tcb_displacement : thread_displacement;
            std::memcpy(patch.data() + 5, &displacement, sizeof(displacement));
            const auto guest_address = map.load_bias + region.virtual_address + offset;
            if (!memory.write_loader_patch(map, guest_address, patch, error)) {
                error = "Falha ao redirecionar leitura FS do TCB em 0x" +
                        std::to_string(guest_address) + ": " + error;
                return false;
            }
            ++patched_loads;
            offset += load_size - 1;
        }
    }
    total_patched_loads.fetch_add(patched_loads, std::memory_order_relaxed);
    error.clear();
    return true;
#else
    (void)map;
    (void)memory;
    error.clear();
    return true;
#endif
}

} // namespace nba16
