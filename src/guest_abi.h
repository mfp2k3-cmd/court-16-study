#pragma once

#include <cstdint>
#include <type_traits>

// PS4 user code uses the System V AMD64 calling convention. Windows x64
// normally uses Microsoft x64, so callbacks must opt into SysV explicitly.
#if defined(__x86_64__) || defined(_M_X64)
    #if defined(__clang__) || defined(__GNUC__)
        #define NBA16_GUEST_SYSV_ABI __attribute__((sysv_abi))
        #define NBA16_HAS_GUEST_SYSV_ABI 1
    #elif defined(_WIN32)
        // Tooling still builds with MSVC, but direct guest calls require a thunk.
        #define NBA16_GUEST_SYSV_ABI
        #define NBA16_HAS_GUEST_SYSV_ABI 0
    #else
        #define NBA16_GUEST_SYSV_ABI
        #define NBA16_HAS_GUEST_SYSV_ABI 1
    #endif
#else
    #define NBA16_GUEST_SYSV_ABI
    #define NBA16_HAS_GUEST_SYSV_ABI 0
#endif

namespace nba16 {

inline constexpr bool guest_sysv_abi_available = NBA16_HAS_GUEST_SYSV_ABI != 0;

template <typename Return, typename... Arguments>
using GuestFunction = Return (NBA16_GUEST_SYSV_ABI *)(Arguments...);

using GuestEntryPoint = GuestFunction<void>;
using GuestNullaryFunction = GuestFunction<std::uint64_t>;

template <typename Function>
inline constexpr bool is_guest_function_pointer_v =
    std::is_pointer_v<Function> && std::is_function_v<std::remove_pointer_t<Function>>;

} // namespace nba16
