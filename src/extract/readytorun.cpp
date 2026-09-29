#include "prts/readytorun.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>

namespace prts {
namespace {

constexpr std::uint32_t kReadyToRunSignature = 0x00525452u;  // "RTR\0"
constexpr std::uint32_t kKnownFlags = 0x00001fffu;
constexpr std::uint32_t kMaxSections = 4096;
constexpr std::uint64_t kHeaderPrefixSize = 16;
constexpr std::uint64_t kSectionSize = 12;

std::uint16_t u16(std::span<const std::uint8_t> data, std::uint64_t offset) {
    if (offset > data.size() || data.size() - offset < 2) return 0;
    return static_cast<std::uint16_t>(data[static_cast<std::size_t>(offset)]) |
           (static_cast<std::uint16_t>(data[static_cast<std::size_t>(offset + 1)]) << 8);
}

std::uint32_t u32(std::span<const std::uint8_t> data, std::uint64_t offset) {
    if (offset > data.size() || data.size() - offset < 4) return 0;
    const auto p = static_cast<std::size_t>(offset);
    return static_cast<std::uint32_t>(data[p]) |
           (static_cast<std::uint32_t>(data[p + 1]) << 8) |
           (static_cast<std::uint32_t>(data[p + 2]) << 16) |
           (static_cast<std::uint32_t>(data[p + 3]) << 24);
}

bool add_ok(std::uint64_t left, std::uint64_t right, std::uint64_t& result) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) return false;
    result = left + right;
    return true;
}

bool span_ok(std::span<const std::uint8_t> data, std::uint64_t offset,
             std::uint64_t size) {
    return offset <= data.size() && size <= static_cast<std::uint64_t>(data.size()) - offset;
}

std::optional<std::uint64_t> rva_to_file(const PeInfo& pe, std::uint32_t rva,
                                         std::uint32_t size,
                                         std::span<const std::uint8_t> data) {
    if (size == 0) return std::nullopt;
    if (rva < pe.headers_size && static_cast<std::uint64_t>(rva) + size <= pe.headers_size &&
        span_ok(data, rva, size)) {
        return rva;
    }
    for (const auto& section : pe.sections) {
        if (rva < section.rva) continue;
        const auto delta = static_cast<std::uint64_t>(rva) - section.rva;
        if (delta > section.raw_size || size > static_cast<std::uint64_t>(section.raw_size) - delta)
            continue;
        std::uint64_t offset = 0;
        if (!add_ok(section.raw_offset, delta, offset) || !span_ok(data, offset, size)) continue;
        return offset;
    }
    return std::nullopt;
}

std::uint32_t file_to_rva(const PeInfo& pe, std::uint64_t offset) {
    if (offset < pe.headers_size) return static_cast<std::uint32_t>(offset);
    for (const auto& section : pe.sections) {
        if (offset < section.raw_offset || offset - section.raw_offset >= section.raw_size) continue;
        const auto delta = offset - section.raw_offset;
        if (delta > std::numeric_limits<std::uint32_t>::max() - section.rva) return 0;
        return section.rva + static_cast<std::uint32_t>(delta);
    }
    return 0;
}

std::string section_name(std::uint32_t type) {
    switch (type) {
        case 100: return "CompilerIdentifier";
        case 101: return "ImportSections";
        case 102: return "RuntimeFunctions";
        case 103: return "MethodDefEntryPoints";
        case 104: return "ExceptionInfo";
        case 105: return "DebugInfo";
        case 106: return "DelayLoadMethodCallThunks";
        case 107: return "AvailableTypesLegacy";
        case 108: return "AvailableTypes";
        case 109: return "InstanceMethodEntryPoints";
        case 110: return "InliningInfo";
        case 111: return "ProfileDataInfo";
        case 112: return "ManifestMetadata";
        case 113: return "AttributePresence";
        case 114: return "InliningInfo2";
        case 115: return "ComponentAssemblies";
        case 116: return "OwnerCompositeExecutable";
        case 117: return "PgoInstrumentationData";
        case 118: return "ManifestAssemblyMvids";
        case 119: return "CrossModuleInlineInfo";
        case 120: return "HotColdMap";
        case 121: return "MethodIsGenericMap";
        case 122: return "EnclosingTypeMap";
        case 123: return "TypeGenericInfoMap";
        case 124: return "ExternalTypeMaps";
        case 125: return "ProxyTypeMaps";
        case 126: return "TypeMapAssemblyTargets";
        case 127: return "WasmAsyncResumeInfo";
        default: {
            std::ostringstream out;
            out << "Unknown(" << type << ")";
            return out.str();
        }
    }
}

struct HeaderLocation {
    std::uint32_t rva = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t directory_size = 0;
    std::string source;
};

std::optional<HeaderLocation> managed_native_location(std::span<const std::uint8_t> data,
                                                      const PeInfo& pe,
                                                      ReadyToRunInfo& out) {
    if (!pe.clr.present) return std::nullopt;
    const auto clr_offset = rva_to_file(pe, pe.clr.rva, 1, data);
    if (!clr_offset || !span_ok(data, *clr_offset, 72)) {
        out.candidate = true;
        out.source = "CLI_MANAGED_NATIVE_HEADER";
        out.error = "CLI header does not contain the ManagedNativeHeader directory";
        return std::nullopt;
    }
    const auto native_rva = u32(data, *clr_offset + 64);
    const auto native_size = u32(data, *clr_offset + 68);
    out.managed_native_rva = native_rva;
    out.managed_native_size = native_size;
    if (native_rva == 0 && native_size == 0) return std::nullopt;
    out.candidate = true;
    out.source = "CLI_MANAGED_NATIVE_HEADER";
    if (native_rva == 0 || native_size == 0) {
        out.error = "CLI ManagedNativeHeader directory has an incomplete RVA/size pair";
        return std::nullopt;
    }
    const auto header_offset = rva_to_file(pe, native_rva, 1, data);
    if (!header_offset) {
        out.error = "CLI ManagedNativeHeader directory is not file-backed";
        return std::nullopt;
    }
    return HeaderLocation{native_rva, *header_offset, native_size, out.source};
}

std::optional<HeaderLocation> export_location(std::span<const std::uint8_t> data,
                                               const PeInfo& pe,
                                               ReadyToRunInfo& out) {
    for (const auto& export_row : pe.exports) {
        if (export_row.name != "RTR_HEADER" || !export_row.forwarder.empty() || !export_row.rva)
            continue;
        const auto offset = rva_to_file(pe, export_row.rva, 1, data);
        out.candidate = true;
        out.source = "RTR_HEADER_EXPORT";
        if (!offset) {
            out.error = "RTR_HEADER export does not point to file-backed data";
            return std::nullopt;
        }
        return HeaderLocation{export_row.rva, *offset, 0, out.source};
    }
    return std::nullopt;
}

std::optional<HeaderLocation> unique_magic_location(std::span<const std::uint8_t> data,
                                                    const PeInfo& pe,
                                                    ReadyToRunInfo& out) {
    if (!pe.clr.present) return std::nullopt;
    std::vector<std::uint64_t> matches;
    for (std::uint64_t offset = 0; offset + 4 <= data.size(); ++offset) {
        if (u32(data, offset) != kReadyToRunSignature) continue;
        bool in_image = false;
        for (const auto& section : pe.sections) {
            if (offset >= section.raw_offset && offset - section.raw_offset < section.raw_size) {
                in_image = true;
                break;
            }
        }
        if (in_image) matches.push_back(offset);
    }
    if (matches.size() != 1) return std::nullopt;
    out.candidate = true;
    out.source = "UNIQUE_RTR_MAGIC_SCAN";
    return HeaderLocation{file_to_rva(pe, matches.front()), matches.front(), 0, out.source};
}

ReadyToRunInfo fail(ReadyToRunInfo info, std::string error) {
    info.valid = false;
    info.state = "FAILED";
    info.error = std::move(error);
    return info;
}

}  // namespace

ReadyToRunInfo detect_ready_to_run(std::span<const std::uint8_t> data, const PeInfo& pe) {
    ReadyToRunInfo out;
    if (!pe.valid) return out;

    auto location = managed_native_location(data, pe, out);
    if (!location && out.error.empty()) location = export_location(data, pe, out);
    if (!location && out.error.empty()) location = unique_magic_location(data, pe, out);
    if (!location) {
        if (out.candidate) out.state = "FAILED";
        return out;
    }

    out.header_offset = location->file_offset;
    out.header_rva = location->rva;
    if (!span_ok(data, out.header_offset, kHeaderPrefixSize))
        return fail(out, "ReadyToRun header prefix is truncated");
    if (u32(data, out.header_offset) != kReadyToRunSignature)
        return fail(out, "ManagedNativeHeader location does not contain the RTR signature");

    out.major_version = u16(data, out.header_offset + 4);
    out.minor_version = u16(data, out.header_offset + 6);
    out.flags = u32(data, out.header_offset + 8);
    out.unknown_flags = out.flags & ~kKnownFlags;
    out.section_count = u32(data, out.header_offset + 12);
    if (out.major_version == 0) return fail(out, "ReadyToRun major version is zero");
    if (out.section_count == 0 || out.section_count > kMaxSections)
        return fail(out, "ReadyToRun section count is zero or exceeds the bounded limit");
    const auto section_count = static_cast<std::uint64_t>(out.section_count);
    if (section_count > (std::numeric_limits<std::uint64_t>::max() - kHeaderPrefixSize) / kSectionSize)
        return fail(out, "ReadyToRun section table size overflows");
    out.header_size = kHeaderPrefixSize + section_count * kSectionSize;
    if (!span_ok(data, out.header_offset, out.header_size))
        return fail(out, "ReadyToRun section table is truncated");
    if (location->directory_size && out.header_size > location->directory_size)
        return fail(out, "CLI ManagedNativeHeader directory ends before the ReadyToRun section table");

    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    ranges.reserve(out.section_count);
    std::uint32_t previous_type = 0;
    for (std::uint32_t index = 0; index < out.section_count; ++index) {
        const auto row = out.header_offset + kHeaderPrefixSize + static_cast<std::uint64_t>(index) * kSectionSize;
        const auto type = u32(data, row);
        const auto rva = u32(data, row + 4);
        const auto size = u32(data, row + 8);
        if (index && type <= previous_type)
            return fail(out, "ReadyToRun section types are not strictly sorted");
        previous_type = type;
        if (size == 0) return fail(out, "ReadyToRun section has an empty data range");
        const auto file_offset = rva_to_file(pe, rva, size, data);
        if (!file_offset) return fail(out, "ReadyToRun section is not file-backed");
        std::uint64_t end = 0;
        if (!add_ok(*file_offset, size, end)) return fail(out, "ReadyToRun section range overflows");
        ranges.emplace_back(*file_offset, end);
        ReadyToRunSection section;
        section.type = type;
        section.rva = rva;
        section.size = size;
        section.file_offset = *file_offset;
        section.type_name = section_name(type);
        out.sections.push_back(std::move(section));
        switch (type) {
            case 101: ++out.import_section_count; break;
            case 102: ++out.runtime_function_section_count; break;
            case 103: ++out.method_entrypoint_section_count; break;
            case 104: ++out.exception_section_count; break;
            default: break;
        }
    }
    std::sort(ranges.begin(), ranges.end());
    for (std::size_t i = 1; i < ranges.size(); ++i) {
        if (ranges[i].first < ranges[i - 1].second)
            return fail(out, "ReadyToRun section ranges overlap");
    }

    out.composite = (out.flags & 0x00000002u) != 0;
    out.partial = (out.flags & 0x00000004u) != 0;
    out.embedded_msil = (out.flags & 0x00000010u) != 0;
    out.component = (out.flags & 0x00000020u) != 0;
    out.platform_native_image = (out.flags & 0x00000100u) != 0;
    out.stripped_il_bodies = (out.flags & 0x00000200u) != 0;
    out.stripped_inlining_info = (out.flags & 0x00000400u) != 0;
    out.stripped_debug_info = (out.flags & 0x00000800u) != 0;
    out.valid = true;
    out.state = location->source == "UNIQUE_RTR_MAGIC_SCAN" ? "LIKELY" : "CONFIRMED";
    return out;
}

Finding ready_to_run_finding(const ReadyToRunInfo& info) {
    Finding finding;
    finding.kind = "runtime";
    finding.family = ".NET ReadyToRun";
    finding.variant = info.major_version ? "R2R " + std::to_string(info.major_version) + "." + std::to_string(info.minor_version) : "header-candidate";
    finding.state = info.state;
    if (!info.valid) {
        if (!info.error.empty()) finding.negative_evidence.push_back(info.error);
        return finding;
    }
    finding.confidence = info.state == "CONFIRMED" ? std::optional<double>(.96) : std::optional<double>(.82);
    finding.evidence = {
        "READYTORUN_HEADER signature and version/core-header geometry validated",
        "sorted section directory entries map to non-overlapping file-backed PE ranges",
    };
    if (info.source == "CLI_MANAGED_NATIVE_HEADER")
        finding.evidence.push_back("CLI ManagedNativeHeader points to the R2R header");
    else if (info.source == "RTR_HEADER_EXPORT")
        finding.evidence.push_back("RTR_HEADER export points to the R2R header");
    else
        finding.evidence.push_back("a unique RTR header was found inside the validated PE image");
    finding.fields["source"] = info.source;
    finding.fields["version"] = std::to_string(info.major_version) + "." + std::to_string(info.minor_version);
    finding.fields["flags"] = std::to_string(info.flags);
    finding.fields["sections"] = std::to_string(info.section_count);
    finding.fields["runtime_function_sections"] = std::to_string(info.runtime_function_section_count);
    finding.fields["method_entrypoint_sections"] = std::to_string(info.method_entrypoint_section_count);
    finding.fields["import_sections"] = std::to_string(info.import_section_count);
    finding.fields["exception_sections"] = std::to_string(info.exception_section_count);
    finding.fields["composite"] = info.composite ? "true" : "false";
    finding.fields["component"] = info.component ? "true" : "false";
    finding.fields["stripped_il_bodies"] = info.stripped_il_bodies ? "true" : "false";
    finding.fields["unknown_flags"] = std::to_string(info.unknown_flags);
    finding.ranges.push_back(file_offset_range(info.header_offset, info.header_size,
                                                "ReadyToRun header and section directory"));
    constexpr std::size_t kRangeCap = 128;
    for (std::size_t i = 0; i < info.sections.size() && i < kRangeCap; ++i) {
        const auto& section = info.sections[i];
        finding.ranges.push_back(file_offset_range(section.file_offset, section.size,
                                                    "R2R " + section.type_name));
    }
    if (info.sections.size() > kRangeCap)
        finding.fields["section_ranges_omitted"] = std::to_string(info.sections.size() - kRangeCap);
    finding.negative_evidence = {
        "native ReadyToRun methods and fixups were not disassembled",
        "runtime acceptance and method reachability remain unresolved",
    };
    finding.suggested_actions = {
        "inspect RuntimeFunctions and MethodDefEntryPoints with an R2R-aware tool",
        "compare the embedded IL metadata with the native entrypoint tables",
    };
    return finding;
}

}  // namespace prts
