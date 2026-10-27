#pragma once

#include "guest_abi.h"
#include "ps4_dynamic_link.h"

#include <cstdint>
#include <iosfwd>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace nba16 {

enum class GuestSymbolKind : std::uint8_t {
    object = 1,
    function = 2,
};

struct UnresolvedImport {
    std::uint32_t symbol_index{};
    std::uint32_t library_id{};
    std::uint32_t module_id{};
    std::uint8_t elf_symbol_info{};
    std::uint16_t elf_section_index{};
    std::string library;
    std::string module;
    std::string nid;
    std::string symbol_name;
    GuestSymbolKind expected_kind{GuestSymbolKind::function};
    bool kind_mismatch{};
    std::uint64_t relocation_references{};
};

struct ImportResolution {
    std::vector<std::optional<std::uint64_t>> symbol_addresses;
    std::uint64_t resolved_count{};
    std::uint64_t resolved_relocation_references{};
    std::uint64_t unresolved_weak_zero_count{};
    std::vector<UnresolvedImport> unresolved;
};

struct NativeCodeInterposition {
    std::string library;
    std::string module;
    std::string nid;
    std::uint64_t host_address{};
    std::optional<std::uint64_t> code_offset;
};

void print_summary(const ImportResolution& resolution, std::ostream& output);

// Maps exact PS4 import identities to guest virtual addresses supplied by
// independently implemented guest-side functions or objects.
class ImportResolver {
public:
    static constexpr std::uint16_t any_version = 0xffffU;

    bool register_symbol(const std::string& library,
                         const std::string& module,
                         const std::string& nid,
                         GuestSymbolKind kind,
                         std::uint64_t guest_address,
                         std::string& error,
                         std::uint16_t library_version = any_version,
                         std::uint16_t module_version = any_version);

    // Loaded PRX exports are lower priority than explicit native HLE bindings.
    // Repeated identical module exports are harmless; conflicting ones fail closed.
    bool register_module_symbol(const std::string& library,
                                const std::string& module,
                                const std::string& nid,
                                GuestSymbolKind kind,
                                std::uint64_t guest_address,
                                std::string& error,
                                std::uint16_t library_version = any_version,
                                std::uint16_t module_version = any_version);

    bool register_code_interposition(const std::string& library,
                                     const std::string& module,
                                     const std::string& nid,
                                     std::uint64_t host_address,
                                     std::string& error);
    bool register_code_offset_interposition(const std::string& module,
                                            std::uint64_t code_offset,
                                            std::uint64_t host_address,
                                            std::string& error);

    [[nodiscard]] const std::vector<NativeCodeInterposition>& code_interpositions() const noexcept;

    template <typename Return, typename... Arguments>
    bool register_function(const std::string& library,
                           const std::string& module,
                           const std::string& nid,
                           GuestFunction<Return, Arguments...> function,
                           std::string& error,
                           std::uint16_t library_version = any_version,
                           std::uint16_t module_version = any_version) {
        if constexpr (!guest_sysv_abi_available) {
            error = "O compilador do host não oferece chamadas SysV x86-64 diretas; é necessário um thunk.";
            return false;
        } else {
            if (function == nullptr) {
                error = "Registro de função convidada inválido: ponteiro nulo.";
                return false;
            }
            const auto address = reinterpret_cast<std::uintptr_t>(function);
            return register_symbol(library, module, nid, GuestSymbolKind::function,
                                   static_cast<std::uint64_t>(address), error,
                                   library_version, module_version);
        }
    }

    bool resolve(const Ps4DynamicLinkInfo& link_info,
                 ImportResolution& result,
                 std::string& error,
                 std::uint64_t local_load_bias = 0) const;

private:
    struct RegisteredSymbol {
        GuestSymbolKind kind{};
        std::uint64_t guest_address{};
        bool native{};
    };

    using Key = std::tuple<std::string, std::string, std::string,
                           std::uint16_t, std::uint16_t>;
    std::map<Key, RegisteredSymbol> symbols_;
    std::vector<NativeCodeInterposition> code_interpositions_;
};

} // namespace nba16
