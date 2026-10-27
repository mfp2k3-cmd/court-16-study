#include "sanitizer_fiber_imports.h"

#include "guest_process_context.h"
#include "guest_abi.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace nba16 {
namespace {

void store_null(GuestProcessContext* context, std::uint64_t output) {
    if (context == nullptr || output == 0 || !context->is_initialized()) return;
    const std::uint64_t null_value{};
    std::string error;
    (void)context->memory().write(output, std::as_bytes(std::span(&null_value, 1)), error);
}

void NBA16_GUEST_SYSV_ABI guest_sanitizer_start_switch_fiber(
    std::uint64_t fake_stack_save, std::uint64_t stack_bottom,
    std::uint64_t stack_size) {
    (void)stack_bottom;
    (void)stack_size;
    store_null(current_guest_process_context(), fake_stack_save);
}

void NBA16_GUEST_SYSV_ABI guest_sanitizer_finish_switch_fiber(
    std::uint64_t fake_stack_save, std::uint64_t old_stack_bottom,
    std::uint64_t old_stack_size) {
    (void)fake_stack_save;
    auto* context = current_guest_process_context();
    store_null(context, old_stack_bottom);
    store_null(context, old_stack_size);
}

void NBA16_GUEST_SYSV_ABI guest_asan_destroy_fake_stack(std::uint64_t fake_stack) {
    (void)fake_stack;
}

} // namespace

bool register_native_sanitizer_fiber_imports(ImportResolver& resolver,
                                             std::string& error) {
    return resolver.register_function(
               "libSceDbgAddressSanitizer", "libSceDbgAddressSanitizer",
               "jachrbjpHnM", &guest_asan_destroy_fake_stack, error) &&
           resolver.register_function(
               "libSceDbgAddressSanitizer", "libSceDbgAddressSanitizer",
               "cYlYsDQY500", &guest_sanitizer_finish_switch_fiber, error) &&
           resolver.register_function(
               "libSceDbgAddressSanitizer", "libSceDbgAddressSanitizer",
               "AM5dbXp3qbI", &guest_sanitizer_start_switch_fiber, error);
}

} // namespace nba16
