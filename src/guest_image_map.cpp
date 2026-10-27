#include "guest_image_map.h"
#include "ps4_dynamic_link.h"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <ostream>
#include <sstream>
#include <string>

namespace nba16 {
namespace {

constexpr std::uint32_t pt_load = 1;
constexpr std::uint32_t pt_sce_relro = 0x61000010;
constexpr std::uint64_t maximum_image_memory = 1024ULL * 1024ULL * 1024ULL;

struct MemorySlice {
    std::size_t region_index{};
    std::size_t region_offset{};
    std::size_t buffer_offset{};
    std::size_t length{};
};

bool locate_memory_slices(const GuestImageMap& map, std::uint64_t guest_address,
                          std::size_t byte_count, std::uint32_t required_flag,
                          std::vector<MemorySlice>& slices, std::string& error) {
    slices.clear();
    if (byte_count > std::numeric_limits<std::uint64_t>::max() - guest_address) {
        error = "Intervalo de memória convidada excede o espaço de endereços.";
        return false;
    }
    std::size_t copied = 0;
    while (copied < byte_count) {
        const auto current_address = guest_address + static_cast<std::uint64_t>(copied);
        if (current_address < map.load_bias) {
            error = "Endereço convidado anterior ao load bias da imagem.";
            return false;
        }
        const auto relative_address = current_address - map.load_bias;
        const auto region = std::find_if(map.regions.begin(), map.regions.end(),
            [relative_address](const GuestMemoryRegion& candidate) {
                return relative_address >= candidate.virtual_address &&
                       relative_address - candidate.virtual_address < candidate.bytes.size();
            });
        if (region == map.regions.end()) {
            error = "Intervalo acessa memória convidada não mapeada.";
            return false;
        }
        if (required_flag == 0x2U && region->read_only_after_relocations &&
            map.imported_relocations_applied) {
            error = "Tentativa de escrita em região RELRO após concluir as relocações.";
            return false;
        }
        if ((region->flags & required_flag) == 0) {
            error = required_flag == 0x2U
                ? "Tentativa de escrita em região convidada sem permissão de escrita."
                : "Tentativa de leitura em região convidada sem permissão de leitura.";
            return false;
        }
        const auto region_index = static_cast<std::size_t>(region - map.regions.begin());
        const auto region_offset = static_cast<std::size_t>(relative_address - region->virtual_address);
        const auto available = region->bytes.size() - region_offset;
        const auto length = std::min(available, byte_count - copied);
        slices.push_back({region_index, region_offset, copied, length});
        copied += length;
    }
    return true;
}

const ProgramSegmentImage* find_segment(const SelfProgramImage& image, std::size_t phdr_index) {
    const auto found = std::find_if(image.segments.begin(), image.segments.end(),
                                    [phdr_index](const ProgramSegmentImage& segment) {
                                        return segment.program_header_index == phdr_index;
                                    });
    return found == image.segments.end() ? nullptr : &*found;
}

} // namespace

bool build_guest_image_map(const SelfProgramImage& image, GuestImageMap& map, std::string& error,
                           bool require_executable_entry) {
    GuestImageMap parsed{};
    parsed.entry_point = image.entry_point;
    parsed.minimum_virtual_address = std::numeric_limits<std::uint64_t>::max();

    for (std::size_t index = 0; index < image.program_headers.size(); ++index) {
        const auto& program = image.program_headers[index];
        if ((program.type != pt_load && program.type != pt_sce_relro) || program.memory_size == 0) {
            continue;
        }
        if (program.memory_size < program.file_size ||
            program.virtual_address > std::numeric_limits<std::uint64_t>::max() - program.memory_size ||
            program.memory_size > maximum_image_memory ||
            parsed.mapped_memory_bytes > maximum_image_memory - program.memory_size) {
            error = "Região ELF excede limites ou declara p_filesz maior que p_memsz.";
            return false;
        }
        const auto* source = find_segment(image, index);
        if (source == nullptr || source->file_bytes.size() != program.file_size) {
            error = "Falta o payload SELF correspondente a uma região PT_LOAD/PT_SCE_RELRO.";
            return false;
        }

        GuestMemoryRegion region{};
        region.program_header_index = index;
        region.virtual_address = program.virtual_address;
        region.file_size = program.file_size;
        region.memory_size = program.memory_size;
        region.alignment = program.alignment;
        region.flags = program.flags;
        region.read_only_after_relocations = program.type == pt_sce_relro;
        region.bytes.assign(static_cast<std::size_t>(program.memory_size), 0);
        std::copy(source->file_bytes.begin(), source->file_bytes.end(), region.bytes.begin());
        parsed.minimum_virtual_address = std::min(parsed.minimum_virtual_address, region.virtual_address);
        parsed.maximum_virtual_address = std::max(parsed.maximum_virtual_address,
                                                   region.virtual_address + region.memory_size);
        parsed.mapped_memory_bytes += program.memory_size;
        parsed.regions.push_back(std::move(region));
    }

    if (parsed.regions.empty()) {
        error = "O ELF não contém PT_LOAD ou PT_SCE_RELRO com payload disponível.";
        return false;
    }
    std::sort(parsed.regions.begin(), parsed.regions.end(), [](const GuestMemoryRegion& left,
                                                               const GuestMemoryRegion& right) {
        return left.virtual_address < right.virtual_address;
    });
    for (std::size_t index = 1; index < parsed.regions.size(); ++index) {
        const auto& previous = parsed.regions[index - 1];
        const auto previous_end = previous.virtual_address + previous.memory_size;
        if (parsed.regions[index].virtual_address < previous_end) {
            error = "As regiões PT_LOAD/PT_SCE_RELRO se sobrepõem em memória; precedência ainda não está definida.";
            return false;
        }
    }

    bool executable_entry = false;
    bool executable_region = false;
    for (const auto& region : parsed.regions) {
        if (region.program_header_index < image.program_headers.size() &&
            image.program_headers[region.program_header_index].type == pt_load &&
            (region.flags & 0x1U) != 0) {
            executable_region = true;
            if (parsed.entry_point >= region.virtual_address &&
                parsed.entry_point < region.virtual_address + region.memory_size) {
                executable_entry = true;
            }
        }
    }
    if (!executable_region) {
        error = "A imagem não contém um PT_LOAD executável.";
        return false;
    }
    if (require_executable_entry && !executable_entry) {
        error = "O ponto de entrada não está dentro de uma região PT_LOAD executável.";
        return false;
    }
    map = std::move(parsed);
    return true;
}

void print_summary(const GuestImageMap& map, std::ostream& output) {
    output << "\nMapa relativo de memória convidada (sem reserva no Windows):\n";
    output << "  intervalo=[0x" << std::hex << map.minimum_virtual_address << ", 0x"
           << map.maximum_virtual_address << ") entrada=0x" << map.entry_point << std::dec << '\n';
    output << "  regiões: " << map.regions.size() << "; memória comprometida no modelo: "
           << map.mapped_memory_bytes << " bytes\n";
    for (const auto& region : map.regions) {
        output << "    PHDR[" << region.program_header_index << "] vaddr=0x"
               << std::hex << region.virtual_address << std::dec
               << " file=" << region.file_size << " mem=" << region.memory_size
               << " align=" << region.alignment
               << " perm=" << ((region.flags & 0x4U) ? 'R' : '-')
               << ((region.flags & 0x2U) ? 'W' : '-')
               << ((region.flags & 0x1U) ? 'X' : '-')
               << (region.read_only_after_relocations ? " RELRO" : "")
               << "\n";
    }
    output << "  Layout validado; ainda sem carga em memória do host, relocações ou execução.\n";
}

bool validate_guest_memory_access(const GuestImageMap& map, std::uint64_t guest_address,
                                  std::size_t byte_count, bool write_access,
                                  std::string& error) {
    std::vector<MemorySlice> slices;
    return locate_memory_slices(map, guest_address, byte_count,
                                write_access ? 0x2U : 0x4U, slices, error);
}

bool validate_guest_execute_access(const GuestImageMap& map, std::uint64_t guest_address,
                                   std::size_t byte_count, std::string& error) {
    std::vector<MemorySlice> slices;
    return locate_memory_slices(map, guest_address, byte_count, 0x1U, slices, error);
}

bool read_guest_memory(const GuestImageMap& map, std::uint64_t guest_address,
                       std::span<std::byte> destination, std::string& error) {
    std::vector<MemorySlice> slices;
    if (!locate_memory_slices(map, guest_address, destination.size(), 0x4U, slices, error)) {
        return false;
    }
    for (const auto& slice : slices) {
        const auto& bytes = map.regions[slice.region_index].bytes;
        for (std::size_t index = 0; index < slice.length; ++index) {
            destination[slice.buffer_offset + index] =
                static_cast<std::byte>(bytes[slice.region_offset + index]);
        }
    }
    return true;
}

bool write_guest_memory(GuestImageMap& map, std::uint64_t guest_address,
                        std::span<const std::byte> source, std::string& error) {
    std::vector<MemorySlice> slices;
    if (!locate_memory_slices(map, guest_address, source.size(), 0x2U, slices, error)) {
        return false;
    }
    for (const auto& slice : slices) {
        auto& bytes = map.regions[slice.region_index].bytes;
        for (std::size_t index = 0; index < slice.length; ++index) {
            bytes[slice.region_offset + index] =
                std::to_integer<std::uint8_t>(source[slice.buffer_offset + index]);
        }
    }
    return true;
}

bool apply_relative_relocations(GuestImageMap& map,
                                const Ps4DynamicLinkInfo& link_info,
                                std::uint64_t load_bias,
                                std::uint64_t tls_module_id,
                                RelocationApplicationSummary& summary,
                                std::string& error) {
    if (map.relative_relocations_applied) {
        error = "Relocações relativas já foram aplicadas a este mapa.";
        return false;
    }
    std::uint64_t maximum_alignment = 1;
    for (const auto& region : map.regions) {
        if (region.alignment > maximum_alignment) {
            maximum_alignment = region.alignment;
        }
    }
    if (maximum_alignment > 1 && load_bias % maximum_alignment != 0) {
        error = "Load bias não respeita o maior alinhamento declarado pelo ELF.";
        return false;
    }

    RelocationApplicationSummary parsed{};
    parsed.relative_load_bias = load_bias;
    parsed.tls_module_id = tls_module_id;
    for (const auto& relocation : link_info.relocations) {
        if (relocation.type == 1 || relocation.type == 6 || relocation.type == 7) {
            ++parsed.imported_unresolved;
            continue;
        }
        if (relocation.type == 16) {
            if (tls_module_id == 0) {
                error = "R_X86_64_DTPMOD64 exige identificador TLS atribuído pelo conjunto de módulos.";
                return false;
            }
            const auto target = std::find_if(map.regions.begin(), map.regions.end(),
                [&relocation](const GuestMemoryRegion& candidate) {
                    return relocation.target >= candidate.virtual_address &&
                           relocation.target - candidate.virtual_address <= candidate.memory_size &&
                           candidate.memory_size - (relocation.target - candidate.virtual_address) >=
                               sizeof(std::uint64_t);
                });
            if (target == map.regions.end()) {
                error = "Destino de R_X86_64_DTPMOD64 fora das regiões mapeadas.";
                return false;
            }
            continue;
        }
        if (relocation.type != 8) {
            error = "A imagem usa o tipo de relocação ELF " +
                    std::to_string(relocation.type) + " ainda não reconhecido (símbolo " +
                    std::to_string(relocation.symbol_index) + ", destino 0x";
            std::ostringstream address;
            address << std::hex << relocation.target;
            error += address.str() + ").";
            return false;
        }
        // ELF defines RELATIVE as B + A; the symbol field is not used by
        // the relocation. Some PS4/OpenOrbis-produced images nevertheless
        // carry a nonzero, in-range section-symbol index here.
        auto region = std::find_if(map.regions.begin(), map.regions.end(), [&](const GuestMemoryRegion& candidate) {
            return relocation.target >= candidate.virtual_address &&
                   relocation.target - candidate.virtual_address <= candidate.memory_size &&
                   candidate.memory_size - (relocation.target - candidate.virtual_address) >= sizeof(std::uint64_t);
        });
        if (region == map.regions.end()) {
            error = "Destino de relocação relativa não cabe em nenhuma região do mapa virtual.";
            return false;
        }
    }

    for (const auto& relocation : link_info.relocations) {
        if (relocation.type == 16) {
            const auto region = std::find_if(map.regions.begin(), map.regions.end(),
                [&relocation](const GuestMemoryRegion& candidate) {
                    return relocation.target >= candidate.virtual_address &&
                           relocation.target - candidate.virtual_address <= candidate.memory_size &&
                           candidate.memory_size - (relocation.target - candidate.virtual_address) >=
                               sizeof(std::uint64_t);
                });
            const auto value = tls_module_id;
            const auto destination = static_cast<std::size_t>(relocation.target - region->virtual_address);
            for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
                region->bytes[destination + byte] =
                    static_cast<std::uint8_t>((value >> (byte * 8U)) & 0xffU);
            }
            ++parsed.tls_module_relocations_applied;
            continue;
        }
        if (relocation.type != 8) {
            continue;
        }
        auto region = std::find_if(map.regions.begin(), map.regions.end(), [&](const GuestMemoryRegion& candidate) {
            return relocation.target >= candidate.virtual_address &&
                   relocation.target - candidate.virtual_address <= candidate.memory_size &&
                   candidate.memory_size - (relocation.target - candidate.virtual_address) >= sizeof(std::uint64_t);
        });
        const auto value = load_bias + relocation.addend_bits;
        auto destination = static_cast<std::size_t>(relocation.target - region->virtual_address);
        for (std::size_t byte = 0; byte < sizeof(value); ++byte) {
            region->bytes[destination + byte] = static_cast<std::uint8_t>((value >> (byte * 8U)) & 0xffU);
        }
        ++parsed.relative_applied;
    }
    map.load_bias = load_bias;
    map.tls_module_id = tls_module_id;
    map.relative_relocations_applied = true;
    summary = parsed;
    return true;
}

bool apply_import_relocations(GuestImageMap& map,
                              const Ps4DynamicLinkInfo& link_info,
                              const std::vector<std::optional<std::uint64_t>>& symbol_addresses,
                              RelocationApplicationSummary& summary,
                              std::string& error) {
    if (!map.relative_relocations_applied) {
        error = "Relocações relativas devem ser aplicadas antes das relocações de imports.";
        return false;
    }
    if (map.imported_relocations_applied) {
        error = "Relocações de imports já foram aplicadas a este mapa.";
        return false;
    }

    struct PendingWrite {
        std::size_t region_index{};
        std::size_t offset{};
        std::uint64_t value{};
    };
    std::vector<PendingWrite> writes;
    RelocationApplicationSummary parsed = summary;
    parsed.imported_applied = 0;
    parsed.imported_unresolved = 0;

    for (const auto& relocation : link_info.relocations) {
        if (relocation.type == 8 || relocation.type == 16) {
            continue;
        }
        if (relocation.type != 1 && relocation.type != 6 && relocation.type != 7) {
            error = "A imagem usa um tipo de relocação importada ainda não reconhecido.";
            return false;
        }
        if (relocation.symbol_index == 0 || relocation.symbol_index >= symbol_addresses.size() ||
            !symbol_addresses[relocation.symbol_index].has_value()) {
            ++parsed.imported_unresolved;
            error = "Import sem endereço convidado resolvido no índice de símbolo " +
                    std::to_string(relocation.symbol_index) + ".";
            return false;
        }
        const auto region = std::find_if(map.regions.begin(), map.regions.end(),
            [&relocation](const GuestMemoryRegion& candidate) {
                return relocation.target >= candidate.virtual_address &&
                       relocation.target - candidate.virtual_address <= candidate.memory_size &&
                       candidate.memory_size - (relocation.target - candidate.virtual_address) >=
                           sizeof(std::uint64_t);
            });
        if (region == map.regions.end()) {
            error = "Destino de relocation importada fora das regiões mapeadas.";
            return false;
        }
        const auto region_index = static_cast<std::size_t>(region - map.regions.begin());
        const auto destination_offset = static_cast<std::size_t>(relocation.target - region->virtual_address);
        if (destination_offset > region->bytes.size() ||
            region->bytes.size() - destination_offset < sizeof(std::uint64_t)) {
            error = "Destino de relocation importada excede os bytes reservados para a região.";
            return false;
        }

        const auto symbol = *symbol_addresses[relocation.symbol_index];
        // x86-64 ABI: R_X86_64_64 is S+A; GLOB_DAT and JUMP_SLOT are S.
        const auto value = relocation.type == 1
            ? symbol + static_cast<std::uint64_t>(std::bit_cast<std::int64_t>(relocation.addend_bits))
            : symbol;
        writes.push_back({region_index, destination_offset, value});
    }

    for (const auto& write : writes) {
        auto& bytes = map.regions[write.region_index].bytes;
        for (std::size_t byte = 0; byte < sizeof(write.value); ++byte) {
            bytes[write.offset + byte] =
                static_cast<std::uint8_t>((write.value >> (byte * 8U)) & 0xffU);
        }
    }
    parsed.imported_applied = writes.size();
    map.imported_relocations_applied = true;
    summary = parsed;
    return true;
}

bool build_guest_startup_plan(const GuestImageMap& map,
                              const Ps4DynamicLinkInfo& link_info,
                              GuestStartupPlan& plan,
                              std::string& error) {
    if (!map.relative_relocations_applied) {
        error = "O plano de inicialização exige relocações relativas aplicadas.";
        return false;
    }
    GuestStartupPlan parsed{};
    const auto add_function = [&](std::uint64_t guest_address, const std::string& source,
                                  bool zero_is_address = false) {
        if (guest_address == 0 && !zero_is_address) return true;
        if (guest_address > std::numeric_limits<std::uint64_t>::max() - map.load_bias) {
            error = "Endereço de callback excede o espaço virtual do host.";
            return false;
        }
        if (!validate_guest_execute_access(map, map.load_bias + guest_address, 1, error)) return false;
        parsed.calls.push_back({guest_address, source});
        return true;
    };
    const auto add_array = [&](const std::optional<std::uint64_t>& guest_address,
                               const std::optional<std::uint64_t>& byte_size,
                               const std::string& source) {
        if (!guest_address && !byte_size) return true;
        if (!guest_address || !byte_size || *byte_size % sizeof(std::uint64_t) != 0 ||
            *byte_size / sizeof(std::uint64_t) > 65536U) {
            error = "Tabela de inicializadores ausente, desalinhada ou acima do limite seguro.";
            return false;
        }
        if (*guest_address > std::numeric_limits<std::uint64_t>::max() - map.load_bias) {
            error = "Endereço da tabela de inicializadores excede o espaço virtual do host.";
            return false;
        }
        const auto runtime_array_address = map.load_bias + *guest_address;
        if (!validate_guest_memory_access(map, runtime_array_address,
                static_cast<std::size_t>(*byte_size), false, error)) return false;
        for (std::uint64_t offset = 0; offset < *byte_size; offset += sizeof(std::uint64_t)) {
            std::array<std::byte, sizeof(std::uint64_t)> bytes{};
            if (!read_guest_memory(map, runtime_array_address + offset, bytes, error)) return false;
            std::uint64_t host_address = 0;
            for (std::size_t byte = 0; byte < bytes.size(); ++byte) {
                host_address |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[byte]))
                                << static_cast<unsigned>(byte * 8U);
            }
            if (host_address == 0) continue;
            if (host_address < map.load_bias) {
                error = "Entrada de inicializador não pode ser convertida de volta para endereço convidado.";
                return false;
            }
            if (!add_function(host_address - map.load_bias, source)) return false;
        }
        return true;
    };

    // PS4 PRXs commonly encode DT_INIT=0 as the module-start entry at image VA
    // zero. That entry is called only after an explicit load/start-module request;
    // it is not a process-wide ELF constructor to run for every dependency.
    if (!add_array(link_info.initialization.preinit_array,
                   link_info.initialization.preinit_array_size, "DT_PREINIT_ARRAY") ||
        (link_info.initialization.init_function &&
         *link_info.initialization.init_function != 0 &&
         !add_function(*link_info.initialization.init_function, "DT_INIT", true)) ||
        !add_array(link_info.initialization.init_array,
                   link_info.initialization.init_array_size, "DT_INIT_ARRAY")) {
        return false;
    }
    plan = std::move(parsed);
    return true;
}

void print_summary(const RelocationApplicationSummary& summary, std::ostream& output) {
    output << "\nPlano de relocação local (sem resolver bibliotecas):\n";
    output << "  R_X86_64_RELATIVE aplicadas: " << summary.relative_applied
           << " com load bias 0x" << std::hex << summary.relative_load_bias << std::dec << '\n';
    output << "  R_X86_64_DTPMOD64 aplicadas: " << summary.tls_module_relocations_applied
           << " com módulo TLS " << summary.tls_module_id << '\n';
    output << "  Relocações de símbolos importados ainda pendentes: "
           << summary.imported_unresolved << '\n';
    output << "  Relocações de imports aplicadas: " << summary.imported_applied << '\n';
}

} // namespace nba16
