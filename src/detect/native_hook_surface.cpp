#include "prts/native_hook_surface.hpp"

extern "C" {
#include "Zydis.h"
}

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace prts {
namespace {

struct Decoded {
    std::uint32_t rva = 0;
    ZydisDecodedInstruction instruction{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
};

struct FunctionHit {
    std::uint32_t begin = 0;
    bool entry_window = false;
    std::vector<std::uint32_t> iat_writes;
    std::vector<std::string> iat_targets;
    std::vector<std::uint32_t> executable_writes;
    std::vector<std::string> bridge_apis;
    std::vector<std::uint32_t> bridge_rvas;
};

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string hex_rva(std::uint32_t rva) {
    std::ostringstream out;
    out << "0x" << std::hex << rva;
    return out.str();
}

std::optional<std::size_t> rva_offset(const PeInfo& pe, std::uint32_t rva, std::size_t file_size) {
    if (rva < pe.headers_size && rva < file_size) return static_cast<std::size_t>(rva);
    for (const auto& section : pe.sections) {
        const auto span = std::max(section.vsize, section.raw_size);
        if (rva < section.rva || std::uint64_t(rva) >= std::uint64_t(section.rva) + span) continue;
        const auto delta = std::uint64_t(rva) - section.rva;
        if (delta >= section.raw_size) return std::nullopt;
        const auto offset = std::uint64_t(section.raw_offset) + delta;
        if (offset >= file_size) return std::nullopt;
        return static_cast<std::size_t>(offset);
    }
    return std::nullopt;
}

bool executable_rva(const PeInfo& pe, std::uint32_t rva) {
    for (const auto& section : pe.sections) {
        const auto span = std::max(section.vsize, section.raw_size);
        if (rva >= section.rva && std::uint64_t(rva) < std::uint64_t(section.rva) + span)
            return (section.characteristics & 0x20000000u) != 0;
    }
    return false;
}

bool decode_one(std::span<const std::uint8_t> data, const PeInfo& pe, ZydisDecoder& decoder,
                std::uint32_t rva, std::size_t limit, Decoded& out) {
    const auto offset = rva_offset(pe, rva, data.size());
    if (!offset || *offset >= data.size()) return false;
    const auto available = std::min<std::size_t>(data.size() - *offset, limit);
    if (!available) return false;
    out = {};
    out.rva = rva;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data.data() + *offset, available,
                                             &out.instruction, out.operands.data()))) return false;
    return out.instruction.length != 0;
}

std::vector<Decoded> decode_range(std::span<const std::uint8_t> data, const PeInfo& pe,
                                  std::uint32_t begin, std::uint32_t end) {
    std::vector<Decoded> out;
    if (end <= begin || end - begin > 64u * 1024u) return out;
    const auto mode = pe.pe64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    const auto width = pe.pe64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    ZydisDecoder decoder{};
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, width))) return out;
    for (std::uint32_t cursor = begin; cursor < end && out.size() < 4096;) {
        Decoded decoded;
        const auto remaining = static_cast<std::size_t>(end - cursor);
        if (!decode_one(data, pe, decoder, cursor, remaining, decoded)) break;
        const auto next = cursor + decoded.instruction.length;
        if (next <= cursor || next > end) break;
        out.push_back(decoded);
        cursor = next;
    }
    return out;
}

std::optional<std::uint32_t> entry_window(const PeInfo& pe, std::size_t file_size) {
    if (!pe.entry_rva) return std::nullopt;
    for (const auto& section : pe.sections) {
        const auto span = std::max(section.vsize, section.raw_size);
        if ((section.characteristics & 0x20000000u) == 0 || pe.entry_rva < section.rva ||
            std::uint64_t(pe.entry_rva) >= std::uint64_t(section.rva) + span) continue;
        const auto delta = std::uint64_t(pe.entry_rva) - section.rva;
        if (delta >= section.raw_size) return std::nullopt;
        const auto available = std::min<std::uint64_t>(section.raw_size - delta, 0x2000u);
        if (!available || std::uint64_t(section.raw_offset) + delta >= file_size) return std::nullopt;
        const auto file_available = file_size - (std::uint64_t(section.raw_offset) + delta);
        const auto bounded = std::min<std::uint64_t>(available, file_available);
        if (!bounded || std::uint64_t(pe.entry_rva) + bounded > 0xffffffffu) return std::nullopt;
        return static_cast<std::uint32_t>(pe.entry_rva + bounded);
    }
    return std::nullopt;
}

std::optional<std::uint32_t> memory_rva(const Decoded& decoded, const PeInfo& pe) {
    for (std::uint8_t index = 0; index < decoded.instruction.operand_count_visible; ++index) {
        const auto& operand = decoded.operands[index];
        if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY || !operand.mem.disp.has_displacement ||
            operand.mem.index != ZYDIS_REGISTER_NONE) continue;
        std::uint64_t address = 0;
        if (operand.mem.base == ZYDIS_REGISTER_RIP && pe.pe64) {
            const auto next = std::uint64_t(pe.image_base) + decoded.rva + decoded.instruction.length;
            const auto displacement = operand.mem.disp.value;
            const auto signed_next = static_cast<std::int64_t>(next);
            const auto signed_address = signed_next + displacement;
            if (signed_address < static_cast<std::int64_t>(pe.image_base)) continue;
            address = static_cast<std::uint64_t>(signed_address);
        } else if (operand.mem.base == ZYDIS_REGISTER_NONE && !pe.pe64) {
            address = static_cast<std::uint64_t>(operand.mem.disp.value);
        } else if (operand.mem.base == ZYDIS_REGISTER_NONE && pe.pe64) {
            address = static_cast<std::uint64_t>(operand.mem.disp.value);
        } else {
            continue;
        }
        if (address < pe.image_base || address - pe.image_base > 0xffffffffull) continue;
        return static_cast<std::uint32_t>(address - pe.image_base);
    }
    return std::nullopt;
}

std::string import_label(const PeImportFunction& function, const std::string& module) {
    if (function.by_ordinal) return module + "!#" + std::to_string(function.ordinal);
    return module + "!" + function.name;
}

std::map<std::uint32_t, std::string> import_slots(const PeInfo& pe, std::uint32_t pointer_size) {
    std::map<std::uint32_t, std::string> out;
    for (const auto& module : pe.imports) {
        if (!module.iat_rva) continue;
        for (std::size_t index = 0; index < module.functions.size(); ++index) {
            const auto delta = std::uint64_t(index) * pointer_size;
            if (delta > 0xffffffffull - module.iat_rva) break;
            out.emplace(module.iat_rva + static_cast<std::uint32_t>(delta),
                        import_label(module.functions[index], module.name));
        }
    }
    return out;
}

bool bridge_api(std::string_view name) {
    const auto lower = lower_ascii(std::string(name));
    static constexpr std::array<std::string_view, 12> names = {
        "virtualprotect", "virtualprotectex", "ntprotectvirtualmemory", "zwprotectvirtualmemory",
        "writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory", "getprocaddress",
        "ldrgetprocedureaddress", "flushinstructioncache", "loadlibrarya", "loadlibraryw",
    };
    return std::find(names.begin(), names.end(), lower) != names.end();
}

FunctionHit inspect_function(std::span<const std::uint8_t> data, const PeInfo& pe,
                              std::uint32_t begin, std::uint32_t end, bool entry) {
    FunctionHit hit;
    hit.begin = begin;
    hit.entry_window = entry;
    const auto slots = import_slots(pe, pe.pe64 ? 8u : 4u);
    if (slots.empty()) return hit;
    const auto decoded = decode_range(data, pe, begin, end);
    if (decoded.empty()) return hit;
    std::set<std::string> targets;
    std::set<std::string> bridges;
    for (const auto& instruction : decoded) {
        for (std::uint8_t index = 0; index < instruction.instruction.operand_count_visible; ++index) {
            const auto& operand = instruction.operands[index];
            if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
            const auto target = memory_rva(instruction, pe);
            if (!target) continue;
            const bool writes = (operand.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;
            if (writes && slots.find(*target) != slots.end()) {
                hit.iat_writes.push_back(instruction.rva);
                targets.insert(slots.at(*target));
            } else if (writes && executable_rva(pe, *target)) {
                hit.executable_writes.push_back(instruction.rva);
            }
            if (!writes && (instruction.instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                            instruction.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR)) {
                const auto found = slots.find(*target);
                if (found != slots.end()) {
                    const auto separator = found->second.find('!');
                    const auto name = separator == std::string::npos ? found->second : found->second.substr(separator + 1);
                    if (bridge_api(name)) {
                        bridges.insert(name);
                        hit.bridge_rvas.push_back(instruction.rva);
                    }
                }
            }
        }
    }
    hit.iat_targets.assign(targets.begin(), targets.end());
    hit.bridge_apis.assign(bridges.begin(), bridges.end());
    return hit;
}

} // namespace

NativeHookSurfaceInfo analyze_native_hook_surface(std::span<const std::uint8_t> data, const PeInfo& pe) {
    NativeHookSurfaceInfo out;
    if (!pe.valid || pe.imports.empty() || data.empty()) return out;

    std::vector<FunctionHit> hits;
    if (!pe.exception.runtime_functions.empty()) {
        for (const auto& function : pe.exception.runtime_functions) {
            if (function.end_rva <= function.begin_rva) continue;
            auto hit = inspect_function(data, pe, function.begin_rva, function.end_rva, false);
            ++out.function_count;
            if (!hit.iat_writes.empty() || !hit.executable_writes.empty()) hits.push_back(std::move(hit));
            if (out.function_count >= 4096) break;
        }
    } else if (const auto end = entry_window(pe, data.size())) {
        auto hit = inspect_function(data, pe, pe.entry_rva, *end, true);
        out.entry_window = true;
        out.function_count = 1;
        if (!hit.iat_writes.empty() || !hit.executable_writes.empty()) hits.push_back(std::move(hit));
    }
    for (const auto& hit : hits) {
        out.iat_write_count = static_cast<std::uint32_t>(std::min<std::size_t>(
            0xffffffffu, static_cast<std::size_t>(out.iat_write_count) + hit.iat_writes.size()));
        out.executable_write_count = static_cast<std::uint32_t>(std::min<std::size_t>(
            0xffffffffu, static_cast<std::size_t>(out.executable_write_count) + hit.executable_writes.size()));
        out.bridge_call_count = static_cast<std::uint32_t>(std::min<std::size_t>(
            0xffffffffu, static_cast<std::size_t>(out.bridge_call_count) + hit.bridge_rvas.size()));
        for (const auto rva : hit.iat_writes) if (out.write_rvas.size() < 64) out.write_rvas.push_back(rva);
        for (const auto rva : hit.executable_writes) if (out.write_rvas.size() < 64) out.write_rvas.push_back(rva);
        for (const auto rva : hit.bridge_rvas) if (out.bridge_call_rvas.size() < 64) out.bridge_call_rvas.push_back(rva);
        for (const auto& target : hit.iat_targets) if (out.iat_targets.size() < 64 &&
                std::find(out.iat_targets.begin(), out.iat_targets.end(), target) == out.iat_targets.end())
            out.iat_targets.push_back(target);
        for (const auto& api : hit.bridge_apis) if (out.bridge_apis.size() < 32 &&
                std::find(out.bridge_apis.begin(), out.bridge_apis.end(), api) == out.bridge_apis.end())
            out.bridge_apis.push_back(api);
    }
    if (!out.iat_write_count && !out.executable_write_count) return out;
    out.candidate = true;
    const bool bridge = out.bridge_call_count != 0;
    if (out.iat_write_count && out.executable_write_count && bridge)
        out.variant = "iat-and-executable-write-with-loader-bridge";
    else if (out.iat_write_count && bridge)
        out.variant = "iat-slot-write-with-loader-bridge";
    else if (out.executable_write_count && bridge)
        out.variant = "executable-range-write-with-loader-bridge";
    else if (out.iat_write_count)
        out.variant = "iat-slot-write";
    else
        out.variant = "executable-range-write";
    out.state = bridge ? "LIKELY" : "SUSPECTED";
    return out;
}

std::optional<Finding> native_hook_surface_finding(const NativeHookSurfaceInfo& info) {
    if (!info.candidate) return std::nullopt;
    Finding finding;
    finding.kind = "native_hook_surface";
    finding.family = "Native import hook surface";
    finding.variant = info.variant;
    finding.state = info.state;
    finding.confidence = info.state == "LIKELY" ? 0.84 : 0.68;
    finding.evidence.push_back("file-backed native instructions write an import slot or executable image range");
    if (info.iat_write_count)
        finding.evidence.push_back(std::to_string(info.iat_write_count) +
            " bounded write(s) target an exact PE import-address-table slot");
    if (info.executable_write_count)
        finding.evidence.push_back(std::to_string(info.executable_write_count) +
            " bounded write(s) target a file-backed executable image range");
    if (info.bridge_call_count)
        finding.evidence.push_back(std::to_string(info.bridge_call_count) +
            " call(s) reach loader/patch bridge APIs in the same bounded native function(s)");
    if (info.entry_window) {
        finding.evidence.push_back("the image lacks usable exception-function boundaries; the route is limited to the bounded entry-section window");
        finding.negative_evidence.push_back("entry-window classification has no validated function boundary and remains static triage only");
    }
    finding.negative_evidence.push_back("the written function pointer or bytes were not recovered, so the final hook/patch target is unresolved");
    finding.negative_evidence.push_back("static writes do not prove that the containing function is reachable or that a hook was installed at runtime");
    finding.negative_evidence.push_back("normal custom allocators, loaders and instrumentation can share protection or address-resolution APIs");
    finding.fields["iat_write_count"] = std::to_string(info.iat_write_count);
    finding.fields["executable_write_count"] = std::to_string(info.executable_write_count);
    finding.fields["bridge_call_count"] = std::to_string(info.bridge_call_count);
    finding.fields["function_count"] = std::to_string(info.function_count);
    finding.fields["function_boundary_state"] = info.entry_window ? "ENTRY_SECTION_WINDOW" : "RUNTIME_FUNCTION";
    finding.fields["runtime_reachability"] = "NOT_RESOLVED_STATIC_ONLY";
    finding.fields["hook_target_identity"] = "NOT_RESOLVED";
    finding.fields["patch_scope"] = info.iat_write_count && info.executable_write_count ? "IAT_AND_EXECUTABLE_RANGE" :
        (info.iat_write_count ? "IAT_SLOT" : "EXECUTABLE_RANGE");
    auto join = [](const std::vector<std::string>& values) {
        std::string out;
        for (const auto& value : values) { if (!out.empty()) out += ","; out += value; }
        return out;
    };
    finding.fields["iat_targets"] = join(info.iat_targets);
    finding.fields["bridge_apis"] = join(info.bridge_apis);
    if (!info.write_rvas.empty()) {
        std::string values;
        for (const auto value : info.write_rvas) { if (!values.empty()) values += ","; values += hex_rva(value); }
        finding.fields["write_rvas"] = values;
    }
    if (!info.bridge_call_rvas.empty()) {
        std::string values;
        for (const auto value : info.bridge_call_rvas) { if (!values.empty()) values += ","; values += hex_rva(value); }
        finding.fields["bridge_call_rvas"] = values;
    }
    for (const auto rva : info.write_rvas) finding.ranges.push_back(rva_range(rva, 1, "native import/code write instruction"));
    for (const auto rva : info.bridge_call_rvas) finding.ranges.push_back(rva_range(rva, 1, "native loader/patch bridge call"));
    finding.suggested_actions = {
        "inspect:iat-slot-writers-and-resolved-targets",
        "compare:disk-iAT-with-runtime-iAT",
        "trace:loader-or-hook-initialization-only-when-runtime-evidence-is-required",
    };
    return finding;
}

} // namespace prts
