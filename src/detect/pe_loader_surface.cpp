#include "prts/pe_loader_surface.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <set>
#include <sstream>
#include <string_view>
#include <optional>

namespace prts {
namespace {

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool resolver_api(std::string_view name) {
    static constexpr std::string_view names[] = {
        "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
        "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress",
        "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
        "virtualfree", "ntallocatevirtualmemory", "ntprotectvirtualmemory",
    };
    const auto low = lower_ascii(std::string(name));
    return std::find(std::begin(names), std::end(names), low) != std::end(names);
}

bool ordinary_code_section(std::string_view name) {
    const auto low = lower_ascii(std::string(name));
    return low == ".text" || low.rfind(".text", 0) == 0 || low == "code";
}

std::uint32_t le32(std::span<const std::uint8_t> data, std::size_t offset) {
    if (offset > data.size() || data.size() - offset < 4) return 0;
    return std::uint32_t(data[offset]) |
        (std::uint32_t(data[offset + 1]) << 8) |
        (std::uint32_t(data[offset + 2]) << 16) |
        (std::uint32_t(data[offset + 3]) << 24);
}

std::optional<std::size_t> rva_offset(const PeInfo& pe, std::uint32_t rva, std::size_t file_size) {
    if (rva < pe.headers_size && rva < file_size) return static_cast<std::size_t>(rva);
    for (const auto& section : pe.sections) {
        const auto span = std::max(section.vsize, section.raw_size);
        if (rva < section.rva || std::uint64_t(rva) >= std::uint64_t(section.rva) + span) continue;
        const auto delta = std::uint64_t(rva) - section.rva;
        if (delta >= section.raw_size) return std::nullopt;
        const auto offset = std::uint64_t(section.raw_offset) + delta;
        if (offset < file_size) return static_cast<std::size_t>(offset);
        return std::nullopt;
    }
    return std::nullopt;
}

void validate_relocations(std::span<const std::uint8_t> data, const PeInfo& pe, PeLoaderSurfaceInfo& out) {
    if (!out.relocation_directory) return;
    const auto start = rva_offset(pe, out.relocation_rva, data.size());
    if (!start || out.relocation_size < 8 || out.relocation_size > data.size() - *start) return;
    const auto end = *start + out.relocation_size;
    auto cursor = *start;
    while (cursor < end) {
        if (end - cursor < 8) return;
        const auto block_size = le32(data, cursor + 4);
        if (block_size < 8 || (block_size & 1u) != 0 || block_size > end - cursor) return;
        const auto entries = (block_size - 8) / 2;
        if (entries > 0xffffffffu - out.relocation_entry_count) return;
        ++out.relocation_block_count;
        out.relocation_entry_count += entries;
        cursor += block_size;
        if (out.relocation_block_count > 4096) return;
    }
    out.relocation_geometry_valid = out.relocation_block_count != 0 && cursor == end;
}

} // namespace

PeLoaderSurfaceInfo analyze_pe_loader_surface(std::span<const std::uint8_t> data, const PeInfo& pe) {
    PeLoaderSurfaceInfo out;
    if (!pe.valid) return out;

    out.entry_rva = pe.entry_rva;
    out.relocation_directory = pe.relocations.present;
    out.relocation_rva = pe.relocations.rva;
    out.relocation_size = pe.relocations.size;
    out.tls_directory_rva = static_cast<std::uint32_t>(std::min<std::uint64_t>(
        pe.tls.directory_rva, 0xffffffffu));
    out.tls_callback_count = static_cast<std::uint32_t>(std::min<std::size_t>(
        pe.tls.callback_vas.size(), 0xffffffffu));
    out.import_modules = static_cast<std::uint32_t>(std::min<std::size_t>(
        pe.imports.size(), 0xffffffffu));

    std::set<std::string> resolver_modules;
    for (const auto& module : pe.imports) {
        out.import_functions = static_cast<std::uint32_t>(std::min<std::uint64_t>(
            0xffffffffu, static_cast<std::uint64_t>(out.import_functions) + module.functions.size()));
        bool module_has_resolver = false;
        for (const auto& function : module.functions) {
            if (function.by_ordinal || function.name.empty() || !resolver_api(function.name)) continue;
            ++out.resolver_api_count;
            module_has_resolver = true;
            if (out.resolver_apis.size() < 32) out.resolver_apis.push_back(module.name + "!" + function.name);
        }
        if (module_has_resolver) resolver_modules.insert(lower_ascii(module.name));
        if (module_has_resolver && out.ranges.size() < 16) {
            out.ranges.push_back(rva_range(module.descriptor_rva, 20,
                "resolver import descriptor " + module.name));
        }
    }
    out.resolver_module_count = static_cast<std::uint32_t>(std::min<std::size_t>(
        resolver_modules.size(), 0xffffffffu));
    out.low_import_surface = out.import_functions <= 8;
    validate_relocations(data, pe, out);

    for (const auto& section : pe.sections) {
        const auto span = std::max(section.vsize, section.raw_size);
        if (out.entry_rva < section.rva || std::uint64_t(out.entry_rva) >=
                std::uint64_t(section.rva) + span) continue;
        out.entry_section = section.name;
        const bool executable = (section.characteristics & 0x20000000u) != 0;
        const bool writable = (section.characteristics & 0x80000000u) != 0;
        out.entrypoint_writable_executable = executable && writable;
        out.entrypoint_nonstandard_section = !ordinary_code_section(section.name);
        break;
    }

    const bool resolver_surface = out.resolver_api_count != 0;
    const bool altered_entry = out.entrypoint_nonstandard_section || out.entrypoint_writable_executable;
    const bool relocation_and_sparse_imports = out.relocation_geometry_valid && out.low_import_surface;
    const bool pre_entry_geometry = out.tls_callback_count != 0 && altered_entry &&
        (out.relocation_geometry_valid || resolver_surface);

    // Require a dynamic-resolution or pre-entry geometry signal together with
    // loader-facing image facts. A relocation directory alone is ordinary PE
    // metadata, and a LoadLibrary import alone is common in plugin hosts.
    if ((resolver_surface && relocation_and_sparse_imports) || pre_entry_geometry) {
        out.candidate = true;
        out.state = "SUSPECTED";
        if (out.tls_callback_count && altered_entry && out.relocation_directory)
            out.variant = "tls-altered-entry-relocation-surface";
        else
            out.variant = "resolver-relocation-low-import-surface";
    }

    if (resolver_surface) ++out.evidence_categories;
    if (out.relocation_geometry_valid) ++out.evidence_categories;
    if (out.tls_callback_count) ++out.evidence_categories;
    if (altered_entry) ++out.evidence_categories;
    if (out.low_import_surface) ++out.evidence_categories;
    if (out.candidate && out.evidence_categories >= 4 &&
        (out.tls_callback_count || out.entrypoint_writable_executable)) {
        out.state = "LIKELY";
    }
    return out;
}

Finding pe_loader_surface_finding(const PeLoaderSurfaceInfo& info) {
    Finding finding;
    finding.kind = "loader_surface";
    finding.family = "PE custom loader surface";
    finding.variant = info.variant;
    finding.state = info.state;
    finding.confidence = info.state == "LIKELY" ? 0.70 : 0.58;
    finding.evidence = {
        "bounded PE loader-facing facts form multiple independent custom-loading signals",
        "the route is intended to prioritize entrypoint, resolver and image-mapping review",
    };
    if (info.resolver_api_count) {
        finding.evidence.push_back("import surface contains " + std::to_string(info.resolver_api_count) +
            " bounded DLL/export or virtual-memory resolver API(s)");
    }
    if (info.relocation_geometry_valid)
        finding.evidence.push_back("relocation directory is present, so image-base mapping metadata is available");
    if (info.tls_callback_count)
        finding.evidence.push_back(std::to_string(info.tls_callback_count) +
            " TLS callback(s) form a loader pre-entry execution surface");
    if (info.entrypoint_writable_executable)
        finding.evidence.push_back("PE entrypoint is in a section marked writable and executable");
    if (info.entrypoint_nonstandard_section && !info.entry_section.empty())
        finding.evidence.push_back("PE entrypoint is in non-standard section " + info.entry_section);
    if (info.low_import_surface)
        finding.evidence.push_back("ordinary import surface is small enough that runtime resolution may carry the missing dependency set");

    finding.negative_evidence = {
        "these static signals do not prove reflective/manual mapping or a protector identity",
        "ordinary plugin hosts, unpackers and self-updaters can share resolver imports and relocation metadata",
        "runtime DLL search paths, memory permissions and the final mapped image were not observed",
    };
    finding.fields["evidence_categories"] = std::to_string(info.evidence_categories);
    finding.fields["import_modules"] = std::to_string(info.import_modules);
    finding.fields["import_functions"] = std::to_string(info.import_functions);
    finding.fields["resolver_api_count"] = std::to_string(info.resolver_api_count);
    finding.fields["resolver_module_count"] = std::to_string(info.resolver_module_count);
    finding.fields["resolver_apis"] = info.resolver_apis.empty() ? "" : [&] {
        std::string value;
        for (const auto& api : info.resolver_apis) {
            if (!value.empty()) value += ",";
            value += api;
        }
        return value;
    }();
    finding.fields["relocation_directory"] = info.relocation_directory ? "true" : "false";
    finding.fields["relocation_geometry_valid"] = info.relocation_geometry_valid ? "true" : "false";
    finding.fields["relocation_blocks"] = std::to_string(info.relocation_block_count);
    finding.fields["relocation_entries"] = std::to_string(info.relocation_entry_count);
    finding.fields["tls_callback_count"] = std::to_string(info.tls_callback_count);
    finding.fields["low_import_surface"] = info.low_import_surface ? "true" : "false";
    finding.fields["entrypoint_rva"] = "0x" + [&] {
        std::ostringstream value;
        value << std::hex << info.entry_rva;
        return value.str();
    }();
    finding.fields["entrypoint_section"] = info.entry_section;
    finding.fields["entrypoint_nonstandard_section"] = info.entrypoint_nonstandard_section ? "true" : "false";
    finding.fields["entrypoint_writable_executable"] = info.entrypoint_writable_executable ? "true" : "false";
    finding.fields["runtime_resolution"] = "NOT_ATTEMPTED_STATIC_ONLY";
    if (info.entry_rva) finding.ranges.push_back(rva_range(info.entry_rva, 1, "PE optional-header entrypoint"));
    if (info.relocation_geometry_valid)
        finding.ranges.push_back(rva_range(info.relocation_rva, info.relocation_size, "PE base-relocation directory"));
    if (info.tls_callback_count)
        finding.ranges.push_back(rva_range(info.tls_directory_rva, 1, "PE TLS directory"));
    finding.ranges.insert(finding.ranges.end(), info.ranges.begin(), info.ranges.end());
    finding.suggested_actions = {
        "inspect:entrypoint-and-tls-callbacks",
        "map:resolver-imports-against-supplied-DLLs",
        "compare:relocations-and-section-permissions-with-a-memory-image",
    };
    return finding;
}

} // namespace prts
