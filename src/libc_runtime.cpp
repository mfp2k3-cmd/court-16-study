#include "libc_runtime.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <thread>

namespace nba16 {
namespace {

void* NBA16_GUEST_SYSV_ABI guest_memcpy(void* destination, const void* source,
                                       std::size_t size) {
    return std::memcpy(destination, source, size);
}

void* NBA16_GUEST_SYSV_ABI guest_memset(void* destination, int value,
                                       std::size_t size) {
    return std::memset(destination, value, size);
}

int NBA16_GUEST_SYSV_ABI guest_memcmp(const void* left, const void* right,
                                     std::size_t size) {
    return std::memcmp(left, right, size);
}

void* NBA16_GUEST_SYSV_ABI guest_memmove(void* destination, const void* source,
                                        std::size_t size) {
    return std::memmove(destination, source, size);
}

void* NBA16_GUEST_SYSV_ABI guest_memchr(const void* data, int value,
                                       std::size_t size) {
    return const_cast<void*>(std::memchr(data, value, size));
}

std::size_t NBA16_GUEST_SYSV_ABI guest_strlen(const char* text) {
    return std::strlen(text);
}

int NBA16_GUEST_SYSV_ABI guest_strcmp(const char* left, const char* right) {
    return std::strcmp(left, right);
}

int NBA16_GUEST_SYSV_ABI guest_strncmp(const char* left, const char* right,
                                       std::size_t count) {
    return std::strncmp(left, right, count);
}

char* NBA16_GUEST_SYSV_ABI guest_strcpy(char* destination, const char* source) {
    return std::strcpy(destination, source);
}

char* NBA16_GUEST_SYSV_ABI guest_strncpy(char* destination, const char* source,
                                         std::size_t count) {
    return std::strncpy(destination, source, count);
}

char* NBA16_GUEST_SYSV_ABI guest_strcat(char* destination, const char* source) {
    return std::strcat(destination, source);
}

char* NBA16_GUEST_SYSV_ABI guest_strncat(char* destination, const char* source,
                                         std::size_t count) {
    return std::strncat(destination, source, count);
}

char* NBA16_GUEST_SYSV_ABI guest_strchr(const char* text, int value) {
    return const_cast<char*>(std::strchr(text, value));
}

char* NBA16_GUEST_SYSV_ABI guest_strrchr(const char* text, int value) {
    return const_cast<char*>(std::strrchr(text, value));
}

char* NBA16_GUEST_SYSV_ABI guest_strstr(const char* text, const char* needle) {
    return const_cast<char*>(std::strstr(text, needle));
}

std::size_t NBA16_GUEST_SYSV_ABI guest_strcspn(const char* text,
                                               const char* rejected) {
    return std::strcspn(text, rejected);
}

char* NBA16_GUEST_SYSV_ABI guest_strpbrk(const char* text,
                                        const char* accepted) {
    return const_cast<char*>(std::strpbrk(text, accepted));
}

double NBA16_GUEST_SYSV_ABI guest_acos(double value) { return std::acos(value); }
float NBA16_GUEST_SYSV_ABI guest_acosf(float value) { return std::acos(value); }
double NBA16_GUEST_SYSV_ABI guest_asin(double value) { return std::asin(value); }
float NBA16_GUEST_SYSV_ABI guest_asinf(float value) { return std::asin(value); }
double NBA16_GUEST_SYSV_ABI guest_atan(double value) { return std::atan(value); }
float NBA16_GUEST_SYSV_ABI guest_atanf(float value) { return std::atan(value); }
double NBA16_GUEST_SYSV_ABI guest_atan2(double y, double x) { return std::atan2(y, x); }
float NBA16_GUEST_SYSV_ABI guest_atan2f(float y, float x) { return std::atan2(y, x); }
double NBA16_GUEST_SYSV_ABI guest_cosh(double value) { return std::cosh(value); }
double NBA16_GUEST_SYSV_ABI guest_exp(double value) { return std::exp(value); }
float NBA16_GUEST_SYSV_ABI guest_expf(float value) { return std::exp(value); }
float NBA16_GUEST_SYSV_ABI guest_exp2f(float value) { return std::exp2(value); }
int NBA16_GUEST_SYSV_ABI guest_isfinite(double value) { return std::isfinite(value) ? 1 : 0; }
int NBA16_GUEST_SYSV_ABI guest_isfinitef(float value) { return std::isfinite(value) ? 1 : 0; }
int NBA16_GUEST_SYSV_ABI guest_isinf(double value) { return std::isinf(value) ? 1 : 0; }
int NBA16_GUEST_SYSV_ABI guest_isinff(float value) { return std::isinf(value) ? 1 : 0; }
int NBA16_GUEST_SYSV_ABI guest_isnan(double value) { return std::isnan(value) ? 1 : 0; }
int NBA16_GUEST_SYSV_ABI guest_isnanf(float value) { return std::isnan(value) ? 1 : 0; }
int NBA16_GUEST_SYSV_ABI guest_signbit(double value) { return std::signbit(value) ? 1 : 0; }
int NBA16_GUEST_SYSV_ABI guest_signbitf(float value) { return std::signbit(value) ? 1 : 0; }
int NBA16_GUEST_SYSV_ABI guest_fpclassifyd(double value) {
    if (std::isnan(value)) return 0x02;    // FP_NAN in the guest FreeBSD ABI.
    if (std::isinf(value)) return 0x01;    // FP_INFINITE.
    if (value == 0.0) return 0x10;        // FP_ZERO.
    if (std::fpclassify(value) == FP_SUBNORMAL) return 0x08;
    return 0x04;                           // FP_NORMAL.
}
double NBA16_GUEST_SYSV_ABI guest_fmod(double left, double right) {
    return std::fmod(left, right);
}
float NBA16_GUEST_SYSV_ABI guest_fmodf(float left, float right) {
    return std::fmod(left, right);
}
double NBA16_GUEST_SYSV_ABI guest_frexp(double value, int* exponent) {
    return std::frexp(value, exponent);
}
double NBA16_GUEST_SYSV_ABI guest_ldexp(double value, int exponent) {
    return std::ldexp(value, exponent);
}
double NBA16_GUEST_SYSV_ABI guest_pow(double base, double exponent) {
    return std::pow(base, exponent);
}
float NBA16_GUEST_SYSV_ABI guest_powf(float base, float exponent) {
    return std::pow(base, exponent);
}
double NBA16_GUEST_SYSV_ABI guest_tan(double value) { return std::tan(value); }
float NBA16_GUEST_SYSV_ABI guest_tanf(float value) { return std::tan(value); }
double NBA16_GUEST_SYSV_ABI guest_tanh(double value) { return std::tanh(value); }

[[noreturn]] void NBA16_GUEST_SYSV_ABI guest_cxa_pure_virtual() {
    std::abort();
}

int NBA16_GUEST_SYSV_ABI guest_cxa_guard_acquire(std::uint64_t* guard) {
    if (guard == nullptr) return 0;
    std::atomic_ref<std::uint64_t> state(*guard);
    std::uint64_t observed = state.load(std::memory_order_acquire);
    for (;;) {
        if ((observed & 1U) != 0) return 0;
        if ((observed & 2U) != 0) {
            std::this_thread::yield();
            observed = state.load(std::memory_order_acquire);
            continue;
        }
        const auto desired = observed | std::uint64_t{2};
        if (state.compare_exchange_weak(observed, desired,
                                        std::memory_order_acquire,
                                        std::memory_order_relaxed)) {
            return 1;
        }
    }
}

void NBA16_GUEST_SYSV_ABI guest_cxa_guard_release(std::uint64_t* guard) {
    if (guard == nullptr) return;
    std::atomic_ref<std::uint64_t> state(*guard);
    std::uint64_t observed = state.load(std::memory_order_relaxed);
    for (;;) {
        const auto desired = (observed | std::uint64_t{1}) & ~std::uint64_t{2};
        if (state.compare_exchange_weak(observed, desired,
                                        std::memory_order_release,
                                        std::memory_order_relaxed)) {
            return;
        }
    }
}

} // namespace

bool register_native_libc_imports(ImportResolver& resolver, std::string& error) {
    if constexpr (!guest_sysv_abi_available) {
        error = "A ABI SysV x86-64 é necessária para registrar os imports de libc.";
        return false;
    }
    return resolver.register_function("libc", "libc", "Q3VBxCXhUHs",
                                      &guest_memcpy, error) &&
           resolver.register_function("libc", "libc", "8zTFvBIAIN8",
                                      &guest_memset, error) &&
           resolver.register_function("libc", "libc", "DfivPArhucg",
                                      &guest_memcmp, error) &&
           resolver.register_function("libc", "libc", "+P6FRGH4LfA",
                                      &guest_memmove, error) &&
           resolver.register_function("libc", "libc", "8u8lPzUEq+U",
                                      &guest_memchr, error) &&
           resolver.register_function("libc", "libc", "j4ViWNHEgww",
                                      &guest_strlen, error) &&
           resolver.register_function("libc", "libc", "Ovb2dSJOAuE",
                                      &guest_strcmp, error) &&
           resolver.register_function("libc", "libc", "aesyjrHVWy4",
                                      &guest_strncmp, error) &&
           resolver.register_function("libc", "libc", "kiZSXIWd9vg",
                                      &guest_strcpy, error) &&
           resolver.register_function("libc", "libc", "6sJWiWSRuqk",
                                      &guest_strncpy, error) &&
           resolver.register_function("libc", "libc", "Ls4tzzhimqQ",
                                      &guest_strcat, error) &&
           resolver.register_function("libc", "libc", "kHg45qPC6f0",
                                      &guest_strncat, error) &&
           resolver.register_function("libc", "libc", "ob5xAW4ln-0",
                                      &guest_strchr, error) &&
           resolver.register_function("libc", "libc", "9yDWMxEFdJU",
                                      &guest_strrchr, error) &&
           resolver.register_function("libc", "libc", "viiwFMaNamA",
                                      &guest_strstr, error) &&
           resolver.register_function("libc", "libc", "q0F6yS-rCms",
                                      &guest_strcspn, error) &&
           resolver.register_function("libc", "libc", "kDZvoVssCgQ",
                                      &guest_strpbrk, error) &&
           resolver.register_function("libc", "libc", "JBcgYuW8lPU",
                                      &guest_acos, error) &&
           resolver.register_function("libc", "libc", "QI-x0SL8jhw",
                                      &guest_acosf, error) &&
           resolver.register_function("libc", "libc", "7Ly52zaL44Q",
                                      &guest_asin, error) &&
           resolver.register_function("libc", "libc", "GZWjF-YIFFk",
                                      &guest_asinf, error) &&
           resolver.register_function("libc", "libc", "OXmauLdQ8kY",
                                      &guest_atan, error) &&
           resolver.register_function("libc", "libc", "HUbZmOnT-Dg",
                                      &guest_atan2, error) &&
           resolver.register_function("libc", "libc", "EH-x713A99c",
                                      &guest_atan2f, error) &&
           resolver.register_function("libc", "libc", "weDug8QD-lE",
                                      &guest_atanf, error) &&
           resolver.register_function("libc", "libc", "KeOZ19X8-Ug",
                                      &guest_cosh, error) &&
           resolver.register_function("libc", "libc", "NVadfnzQhHQ",
                                      &guest_exp, error) &&
           resolver.register_function("libc", "libc", "8zsu04XNsZ4",
                                      &guest_expf, error) &&
           resolver.register_function("libc", "libc", "wuAQt-j+p4o",
                                      &guest_exp2f, error) &&
           resolver.register_function("libc", "libc", "pKwslsMUmSk",
                                      &guest_fmod, error) &&
           resolver.register_function("libc", "libc", "88Vv-AzHVj8",
                                      &guest_fmodf, error) &&
           resolver.register_function("libc", "libc", "kA-TdiOCsaY",
                                      &guest_frexp, error) &&
           resolver.register_function("libc", "libc", "JrwFIMzKNr0",
                                      &guest_ldexp, error) &&
           resolver.register_function("libc", "libc", "9LCjpWyQ5Zc",
                                      &guest_pow, error) &&
           resolver.register_function("libc", "libc", "1D0H2KNjshE",
                                      &guest_powf, error) &&
           resolver.register_function("libc", "libc", "T7uyNqP7vQA",
                                      &guest_tan, error) &&
           resolver.register_function("libc", "libc", "ZE6RNL+eLbk",
                                      &guest_tanf, error) &&
           resolver.register_function("libc", "libc", "JM4EBvWT9rc",
                                      &guest_tanh, error) &&
           resolver.register_function("libc", "libc", "Q8pvJimUWis",
                                      &guest_isfinitef, error) &&
           resolver.register_function("libc", "libc", "GfxAp9Xyiqs",
                                      &guest_isnan, error) &&
           resolver.register_function("libc", "libc", "Rw4J-22tu1U",
                                      &guest_signbit, error) &&
           resolver.register_function("libc", "libc", "dhK16CKwhQg",
                                      &guest_isfinite, error) &&
           resolver.register_function("libc", "libc", "V02oFv+-JzA",
                                      &guest_isinf, error) &&
           resolver.register_function("libc", "libc", "lA94ZgT+vMM",
                                      &guest_isnanf, error) &&
           resolver.register_function("libc", "libc", "rDMyAf1Jhug",
                                      &guest_isinff, error) &&
           resolver.register_function("libc", "libc", "CjQROLB88a4",
                                      &guest_signbitf, error) &&
           resolver.register_function("libc", "libc", "qlWiRfOJx1A",
                                      &guest_fpclassifyd, error) &&
           resolver.register_function("libc", "libc", "3GPpjQdAMTw",
                                      &guest_cxa_guard_acquire, error) &&
           resolver.register_function("libc", "libc", "9rAeANT2tyE",
                                      &guest_cxa_guard_release, error) &&
           resolver.register_function("libc", "libc", "zr094EQ39Ww",
                                      &guest_cxa_pure_virtual, error);
}

} // namespace nba16
