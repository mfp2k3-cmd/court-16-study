#include "ps4_module_loader.h"
#include "guest_tcb_runtime.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>

namespace nba16 {
namespace {

std::string nid_hash(const std::string& symbol_name) {
    const auto separator = symbol_name.find('#');
    return separator == std::string::npos ? symbol_name : symbol_name.substr(0, separator);
}

} // namespace

bool Ps4LoadedModule::prepare(const std::filesystem::path& path, std::string& error,
                              std::uint64_t tls_module_id) {
    if (prepared_) {
        error = "Este objeto já possui um módulo preparado.";
        return false;
    }
    SelfProgramImage image{};
    Ps4DynamicLinkInfo dynamic{};
    GuestImageMap map{};
    GuestImageMemory memory{};
    if (!load_ps4_module_program_image(path, image, error) ||
        image.machine != 62 ||
        !read_ps4_dynamic_link_info(image, dynamic, error) ||
        !build_guest_image_map(image, map, error, false) ||
        !memory.reserve_and_copy(map, error)) {
        if (image.machine != 62 && error.empty()) {
            error = "O módulo não é uma imagem ELF x86-64.";
        }
        return false;
    }
    GuestTlsImage tls_image{};
    tls_image.module_id = tls_module_id;
    bool has_tls_segment = false;
    std::optional<std::uint64_t> process_parameter_address;
    for (const auto& program : image.program_headers) {
        if (program.type == 0x61000001U) {
            if (process_parameter_address || program.memory_size < 0x40 ||
                program.virtual_address > std::numeric_limits<std::uint64_t>::max() -
                                              memory.load_bias()) {
                error = "PT_SCE_PROC_PARAM duplicado, curto ou com endereço inválido.";
                return false;
            }
            const auto runtime_address = memory.load_bias() + program.virtual_address;
            if (!validate_guest_memory_access(map, runtime_address, 0x40, false, error)) {
                error = "PT_SCE_PROC_PARAM fora de memória mapeada: " + error;
                return false;
            }
            process_parameter_address = runtime_address;
        }
        if (program.type != 7U) continue;
        if (has_tls_segment) {
            error = "O ELF declara mais de um segmento PT_TLS; suporte interrompido.";
            return false;
        }
        has_tls_segment = true;
        if (tls_module_id == 0) {
            error = "PT_TLS exige um identificador de módulo TLS atribuído pelo conjunto.";
            return false;
        }
        if (program.file_size > program.memory_size ||
            program.file_size > std::numeric_limits<std::size_t>::max()) {
            error = "Tamanhos do segmento PT_TLS são inconsistentes ou excedem esta plataforma.";
            return false;
        }
        tls_image.alignment = std::max<std::uint64_t>(program.alignment, 1);
        tls_image.memory_size = program.memory_size;
        tls_virtual_address_ = program.virtual_address;
        tls_file_size_ = static_cast<std::size_t>(program.file_size);
        tls_image.initial_bytes.resize(static_cast<std::size_t>(program.file_size));
    }
    RelocationApplicationSummary relocation_summary{};
    if (!apply_relative_relocations(map, dynamic, memory.load_bias(), tls_module_id,
                                    relocation_summary, error)) {
        return false;
    }
    if (tls_file_size_ != 0 &&
        !read_guest_memory(map, memory.load_bias() + tls_virtual_address_,
            std::span<std::byte>(reinterpret_cast<std::byte*>(tls_image.initial_bytes.data()),
                                 tls_image.initial_bytes.size()), error)) {
        error = "A imagem inicial do PT_TLS não está coberta pelo mapa relocacionado: " + error;
        return false;
    }
    GuestStartupPlan startup_plan{};
    if (!build_guest_startup_plan(map, dynamic, startup_plan, error)) return false;
    image_ = std::move(image);
    dynamic_ = std::move(dynamic);
    map_ = std::move(map);
    memory_ = std::move(memory);
    startup_plan_ = std::move(startup_plan);
    tls_image_ = std::move(tls_image);
    process_parameter_address_ = process_parameter_address;
    prepared_ = true;
    return true;
}

bool Ps4LoadedModule::collect_exports(std::string_view module_name,
                                      std::vector<LoadedPs4Export>& exports,
                                      std::string& error) const {
    if (!prepared_) {
        error = "Exports exigem módulo preparado.";
        return false;
    }
    std::map<std::uint32_t, DynamicExportLibrary> libraries;
    for (const auto& library : dynamic_.export_libraries) {
        libraries.emplace(library.library_id, library);
    }
    const std::string resolved_module_name = dynamic_.project_name.empty()
        ? std::string(module_name) : dynamic_.project_name;
    std::vector<LoadedPs4Export> parsed;
    for (const auto& symbol : dynamic_.symbols) {
        if (symbol.section_index == 0 || !symbol.has_nid_indices) continue;
        const auto kind = static_cast<std::uint8_t>(symbol.info & 0x0fU);
        if (kind != 1U && kind != 2U) continue;
        const auto library = libraries.find(symbol.nid_library_index);
        if (library == libraries.end()) continue;
        if (symbol.value > std::numeric_limits<std::uint64_t>::max() - memory_.load_bias()) {
            error = "VA de export excede o espaço virtual do host: " + symbol.name;
            return false;
        }
        const auto host_address = memory_.load_bias() + symbol.value;
        const auto runtime_address = memory_.load_bias() + symbol.value;
        const auto access_size = kind == 1U && symbol.size != 0 ? symbol.size : 1U;
        if (access_size > std::numeric_limits<std::size_t>::max()) {
            error = "Tamanho de export excede o espaço de endereçamento do host: " + symbol.name;
            return false;
        }
        std::string validation_error;
        const bool valid_address = kind == 2U
            ? validate_guest_execute_access(map_, runtime_address, 1, validation_error)
            : validate_guest_memory_access(map_, runtime_address,
                  static_cast<std::size_t>(access_size), false, validation_error);
        if (!valid_address) {
            error = "Export fora de região compatível no módulo " + std::string(module_name) +
                    ": " + symbol.name + " (" + validation_error + ")";
            return false;
        }
        parsed.push_back({resolved_module_name, library->second.name, nid_hash(symbol.name),
                          dynamic_.project_version, library->second.version, host_address,
                          symbol.value, symbol.size, kind});
    }
    exports = std::move(parsed);
    return true;
}

bool Ps4LoadedModule::resolve_imports(const ImportResolver& resolver,
                                      ImportResolution& resolution,
                                      std::string& error) const {
    if (!prepared_ || finalized_) {
        error = "Resolução exige módulo preparado e ainda em fase de relocação.";
        return false;
    }
    return resolver.resolve(dynamic_, resolution, error, map_.load_bias);
}

bool Ps4LoadedModule::apply_imports(
    const std::vector<std::optional<std::uint64_t>>& symbol_addresses,
    RelocationApplicationSummary& summary,
    std::string& error) {
    if (!prepared_ || finalized_) {
        error = "Imports exigem módulo preparado e ainda não finalizado.";
        return false;
    }
    return apply_import_relocations(map_, dynamic_, symbol_addresses, summary, error);
}

bool Ps4LoadedModule::redirect_function_export(std::string_view library_name,
                                              std::string_view module_name,
                                              std::string_view nid,
                                              std::uint64_t host_address,
                                              std::string& error) {
    if (!prepared_ || finalized_ || host_address == 0) {
        error = "interposição exige módulo preparado, ainda não finalizado e destino válido";
        return false;
    }
    std::vector<LoadedPs4Export> exports;
    if (!collect_exports(module_name, exports, error)) return false;
    const auto found = std::find_if(exports.begin(), exports.end(),
        [&](const LoadedPs4Export& entry) {
            return entry.library_name == library_name && entry.nid == nid &&
                   entry.elf_symbol_kind == 2;
        });
    if (found == exports.end()) {
        error = "export de função alvo da interposição não encontrado: " +
                std::string(library_name) + "/" + std::string(module_name) + "/" +
                std::string(nid);
        return false;
    }
    constexpr std::size_t patch_size = 14;
    if (found->size < patch_size) {
        error = "export é curto demais para uma transferência absoluta segura";
        return false;
    }
    std::array<std::byte, patch_size> patch{
        std::byte{0xff}, std::byte{0x25}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0},
    };
    std::memcpy(patch.data() + 6, &host_address, sizeof(host_address));
    if (!memory_.write_loader_patch(map_, found->host_address, patch, error)) {
        error = "não foi possível aplicar interposição em " + std::string(module_name) +
                ": " + error;
        return false;
    }
    error.clear();
    return true;
}

bool Ps4LoadedModule::redirect_function_offset(std::uint64_t code_offset,
                                               std::uint64_t host_address,
                                               std::string& error) {
    if (!prepared_ || finalized_ || host_address == 0) {
        error = "interposição por endereço exige módulo preparado, ainda não finalizado e destino válido";
        return false;
    }
    constexpr std::array<std::byte, 12> expected_sysctl{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0xca},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05},
    };
    constexpr std::array<std::byte, 12> expected_sysctlbyname{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0xcb},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05},
    };
    constexpr std::array<std::byte, 12> expected_virtual_query{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0x3c},
        std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05},
    };
    constexpr std::array<std::byte, 12> expected_virtual_query_api{
        std::byte{0x55}, std::byte{0x48}, std::byte{0x89}, std::byte{0xe5},
        std::byte{0xe8}, std::byte{0x57}, std::byte{0x9a}, std::byte{0xfe},
        std::byte{0xff}, std::byte{0x89}, std::byte{0xc1}, std::byte{0x31},
    };
    constexpr std::array<std::byte, 12> expected_getdents{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0x10},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05},
    };
    constexpr std::array<std::byte, 12> expected_fstat{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0xbd},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05},
    };
    constexpr std::array<std::array<std::byte, 12>, 3> expected_cpuset{{
        {std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0xdd},
         std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
         std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05}},
        {std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0x59},
         std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
         std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05}},
        {std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0x5a},
         std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
         std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05}},
    }};
    const auto region = std::find_if(map_.regions.begin(), map_.regions.end(),
        [&](const GuestMemoryRegion& candidate) {
            return code_offset >= candidate.virtual_address &&
                   code_offset - candidate.virtual_address <= candidate.memory_size &&
                   expected_sysctl.size() <= candidate.memory_size -
                       static_cast<std::size_t>(code_offset - candidate.virtual_address);
        });
    if (region == map_.regions.end() || region->bytes.size() != region->memory_size) {
        error = "endereço de interposição fora de uma região mapeada";
        return false;
    }
    const auto offset = static_cast<std::size_t>(code_offset - region->virtual_address);
    const auto matches = [&](const auto& expected) {
        for (std::size_t index = 0; index < expected.size(); ++index) {
            if (region->bytes[offset + index] !=
                std::to_integer<std::uint8_t>(expected[index])) return false;
        }
        return true;
    };
    const bool signature_matches = matches(expected_sysctl) || matches(expected_sysctlbyname) ||
        matches(expected_virtual_query) ||
        (code_offset == 0x181b0 && matches(expected_virtual_query_api)) ||
        matches(expected_getdents) || matches(expected_fstat) ||
        std::any_of(expected_cpuset.begin(), expected_cpuset.end(), matches);
    if (!signature_matches) {
        error = "stub syscall não corresponde a uma assinatura PS4 validada";
        return false;
    }
    constexpr std::size_t patch_size = 14;
    std::array<std::byte, patch_size> patch{
        std::byte{0xff}, std::byte{0x25}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0},
    };
    std::memcpy(patch.data() + 6, &host_address, sizeof(host_address));
    if (!memory_.write_loader_patch(map_, map_.load_bias + code_offset, patch, error)) {
        error = "não foi possível interpor o stub syscall PS4: " + error;
        return false;
    }
    error.clear();
    return true;
}

bool Ps4LoadedModule::redirect_sysctl_syscall_stubs(
    std::uint64_t sysctl_address, std::uint64_t sysctlbyname_address,
    std::uint64_t virtual_query_address,
    std::size_t& sysctl_count, std::size_t& sysctlbyname_count,
    std::size_t& virtual_query_count,
    std::string& error) {
    if (!prepared_ || finalized_ || sysctl_address == 0 || sysctlbyname_address == 0 ||
        virtual_query_address == 0) {
        error = "busca de stubs sysctl exige módulo preparado e destinos válidos";
        return false;
    }
    constexpr std::array<std::byte, 12> sysctl_signature{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0xca},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05}};
    constexpr std::array<std::byte, 12> sysctlbyname_signature{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0xcb},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05}};
    constexpr std::array<std::byte, 12> virtual_query_signature{
        std::byte{0x48}, std::byte{0xc7}, std::byte{0xc0}, std::byte{0x3c},
        std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
        std::byte{0x89}, std::byte{0xca}, std::byte{0x0f}, std::byte{0x05}};
    struct Stub { std::uint64_t offset; std::uint64_t target; bool byname; bool query; };
    std::vector<Stub> stubs;
    for (const auto& region : map_.regions) {
        if (region.bytes.size() < sysctl_signature.size()) continue;
        for (std::size_t offset = 0;
             offset + sysctl_signature.size() <= region.bytes.size(); ++offset) {
            const auto* current = reinterpret_cast<const std::byte*>(
                region.bytes.data() + offset);
            const bool executable = (region.flags & 1U) != 0;
            if (executable && std::equal(sysctl_signature.begin(), sysctl_signature.end(), current)) {
                stubs.push_back({region.virtual_address + offset, sysctl_address, false, false});
            } else if (executable && std::equal(sysctlbyname_signature.begin(),
                                  sysctlbyname_signature.end(), current)) {
                stubs.push_back({region.virtual_address + offset, sysctlbyname_address, true, false});
            } else if (std::equal(virtual_query_signature.begin(), virtual_query_signature.end(), current)) {
                if (!executable && std::getenv("NBA16_TRACE_MEMORY") != nullptr)
                    std::fprintf(stderr, "MEM virtual-query signature found outside executable region va=%llx flags=%x\n",
                        static_cast<unsigned long long>(region.virtual_address + offset), region.flags);
                if (!executable) continue;
                stubs.push_back({region.virtual_address + offset, virtual_query_address, false, true});
            }
        }
    }
    for (const auto& stub : stubs) {
        if (!redirect_function_offset(stub.offset, stub.target, error)) return false;
        if (stub.query) ++virtual_query_count;
        else if (stub.byname) ++sysctlbyname_count;
        else ++sysctl_count;
    }
    error.clear();
    return true;
}

bool Ps4LoadedModule::finalize(std::string& error) {
    if (!prepared_ || finalized_ || !map_.imported_relocations_applied) {
        error = "Finalização exige módulo preparado e todas as relocações de imports aplicadas.";
        return false;
    }
    if (tls_file_size_ != 0 &&
        !read_guest_memory(map_, memory_.load_bias() + tls_virtual_address_,
            std::span<std::byte>(reinterpret_cast<std::byte*>(tls_image_.initial_bytes.data()),
                                 tls_image_.initial_bytes.size()), error)) {
        error = "A imagem inicial do PT_TLS não pôde ser atualizada após imports: " + error;
        return false;
    }
    std::uint64_t tcb_loads{};
    if (!patch_guest_tcb_loads(map_, memory_, tcb_loads, error)) {
        error = "Não foi possível adaptar acessos FS ao TCB em um módulo PS4: " + error;
        return false;
    }
    if (!memory_.protect_after_relocations(map_, error)) return false;
    finalized_ = true;
    return true;
}

bool Ps4LoadedModule::is_prepared() const noexcept { return prepared_; }
bool Ps4LoadedModule::is_finalized() const noexcept { return finalized_; }
const Ps4DynamicLinkInfo& Ps4LoadedModule::dynamic_info() const noexcept { return dynamic_; }
const GuestImageMap& Ps4LoadedModule::image_map() const noexcept { return map_; }
const GuestImageMemory& Ps4LoadedModule::image_memory() const noexcept { return memory_; }
const GuestStartupPlan& Ps4LoadedModule::startup_plan() const noexcept { return startup_plan_; }
const GuestTlsImage& Ps4LoadedModule::tls_image() const noexcept { return tls_image_; }
std::optional<std::uint64_t> Ps4LoadedModule::process_parameter_address() const noexcept {
    return process_parameter_address_;
}

} // namespace nba16
