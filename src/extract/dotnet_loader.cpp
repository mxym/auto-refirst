#include "prts/dotnet_loader.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <utility>

namespace prts {
namespace {

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool is_mscoree(std::string value) {
    value = lower_ascii(std::move(value));
    const auto slash = value.find_last_of("/\\");
    if (slash != std::string::npos) value.erase(0, slash + 1);
    return value == "mscoree.dll" || value == "mscoree";
}

bool is_standard(std::string_view name) {
    return name == "_CorExeMain" || name == "_CorDllMain";
}

bool is_host_api(std::string_view name) {
    return name == "CorBindToRuntime" || name == "CorBindToRuntimeEx" ||
           name == "CLRCreateInstance" || name == "GetCORVersion" ||
           name == "_CorValidateImage";
}

} // namespace

DotNetLoaderInfo analyze_dotnet_loader(const PeInfo& pe, bool metadata_valid) {
    DotNetLoaderInfo out;
    if (!pe.valid) return out;
    out.clr_directory = pe.clr.present;
    out.metadata_valid = metadata_valid;
    out.image_dll = pe.dll;

    for (const auto& module : pe.imports) {
        if (!is_mscoree(module.name)) continue;
        ++out.mscoree_module_count;
        if (!out.first_descriptor_rva) out.first_descriptor_rva = module.descriptor_rva;
        for (const auto& fn : module.functions) {
            ++out.mscoree_import_count;
            if (fn.by_ordinal || fn.name.empty()) {
                ++out.malformed_import_count;
                continue;
            }
            if (!is_standard(fn.name) && !is_host_api(fn.name)) continue;
            ++out.recognized_import_count;
            if (out.recognized_imports.size() < 32) out.recognized_imports.push_back(fn.name);
            if (is_standard(fn.name)) {
                ++out.standard_bootstrap_count;
                const bool expected_dll = fn.name == "_CorDllMain";
                if (expected_dll != pe.dll) out.contract_mismatch = true;
            } else {
                ++out.host_api_count;
            }
        }
    }

    if (!out.clr_directory && out.mscoree_module_count == 0) return out;
    out.candidate = true;
    if (out.clr_directory && out.mscoree_module_count == 0) {
        out.contract = "CLR_DIRECTORY_WITHOUT_MSCOREE_IMPORT";
        out.state = "PARTIAL";
        out.anomalies.push_back("validated PE CLR directory has no mscoree import module");
    } else if (!out.clr_directory) {
        out.contract = "MSCOREE_IMPORT_WITHOUT_CLR_DIRECTORY";
        out.state = "PARTIAL";
        out.anomalies.push_back("mscoree import module is present but the PE CLR directory is absent");
    } else if (out.standard_bootstrap_count == 0 && out.host_api_count != 0) {
        out.contract = "CUSTOM_CLR_HOST_API_IMPORTS";
        out.state = metadata_valid ? "LIKELY" : "PARTIAL";
        out.anomalies.push_back("mscoree exposes host APIs without the standard _CorExeMain/_CorDllMain bootstrap import");
    } else if (out.standard_bootstrap_count != 0) {
        out.contract = out.image_dll ? "STANDARD_DLL_BOOTSTRAP" : "STANDARD_EXE_BOOTSTRAP";
        out.standard_bootstrap = !out.contract_mismatch && metadata_valid;
        out.state = out.standard_bootstrap ? "CONFIRMED" : "PARTIAL";
        if (!metadata_valid) out.anomalies.push_back("PE CLR directory is present but ECMA-335 metadata was not independently validated");
        if (out.contract_mismatch) out.anomalies.push_back("standard CLR bootstrap import does not match the PE DLL image flag");
    } else {
        out.contract = "MSCOREE_IMPORT_WITHOUT_KNOWN_ENTRYPOINT";
        out.state = "PARTIAL";
        out.anomalies.push_back("mscoree import module has no recognized bounded CLR bootstrap or host API");
    }
    return out;
}

Finding dotnet_loader_finding(const DotNetLoaderInfo& i) {
    Finding f;
    f.kind = "loader_relation";
    f.family = "CLR bootstrap import contract";
    f.variant = i.contract;
    f.state = i.state;
    f.fields["clr_directory"] = i.clr_directory ? "true" : "false";
    f.fields["metadata_valid"] = i.metadata_valid ? "true" : "false";
    f.fields["image_kind"] = i.image_dll ? "DLL" : "EXE";
    f.fields["mscoree_modules"] = std::to_string(i.mscoree_module_count);
    f.fields["mscoree_imports"] = std::to_string(i.mscoree_import_count);
    f.fields["recognized_imports"] = std::to_string(i.recognized_import_count);
    f.fields["standard_bootstrap_imports"] = std::to_string(i.standard_bootstrap_count);
    f.fields["host_api_imports"] = std::to_string(i.host_api_count);
    f.fields["malformed_imports"] = std::to_string(i.malformed_import_count);
    f.fields["runtime_resolution"] = "NOT_ATTEMPTED_STATIC_ONLY";
    if (i.first_descriptor_rva) {
        f.ranges.push_back(rva_range(i.first_descriptor_rva, 20, "mscoree import descriptor"));
    }
    if (i.state == "CONFIRMED") {
        f.evidence = {
            "PE CLR directory and mscoree import module were both present",
            "standard _CorExeMain/_CorDllMain bootstrap matched the PE EXE/DLL image kind",
            "CLR metadata had already passed the bounded ECMA-335 parser",
        };
    } else if (i.clr_directory) {
        f.evidence.push_back("PE CLR directory was present and the mscoree import surface was bounded");
    } else {
        f.evidence.push_back("mscoree import module was parsed from the bounded PE import directory");
    }
    for (const auto& anomaly : i.anomalies) f.negative_evidence.push_back(anomaly);
    f.negative_evidence.push_back("static import evidence does not resolve the CLR host version, loader search path, or runtime call order");
    f.suggested_actions = {
        "compare the PE entry RVA with the CLR bootstrap contract before tracing",
        "inspect mscoree host APIs and sibling runtime files when the standard import is absent",
    };
    return f;
}

} // namespace prts
