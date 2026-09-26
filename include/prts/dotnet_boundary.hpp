#pragma once

#include "prts/dotnet.hpp"
#include "prts/finding.hpp"
#include "prts/pe.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {

// A bounded, static inventory of the point where a CLR image can hand work to
// native code.  It intentionally records evidence and unresolved edges; it
// does not execute the image or claim to recover native/managed logic.
struct DotNetBoundaryMethod {
    std::uint32_t token=0;
    std::uint32_t rva=0;
    std::uint64_t file_offset=0;
    std::uint64_t code_size=0;
    bool body_file_backed=false;
    bool pinvoke=false;
    std::string type_name;
    std::string name;
    std::string import_module;
    std::string import_name;
    std::string state;
};

struct DotNetBoundaryDependency {
    std::string source;
    std::string module;
    std::string name;
    std::uint32_t token=0;
    std::uint64_t file_offset=0;
};

struct DotNetBoundaryInfo {
    bool candidate=false;
    bool valid=false;
    bool partial=false;
    bool truncated=false;
    bool clr_range_file_backed=false;
    bool native_entrypoint=false;
    bool native_entry_file_backed=false;
    bool native_entry_executable=false;
    bool pe_entry_file_backed=false;
    bool entry_rva_diverges=false;
    bool execution_refused=true;
    std::string state="ABSENT";
    std::string boundary_kind;
    std::string error;
    std::uint32_t clr_rva=0,clr_size=0;
    std::uint64_t clr_file_offset=0;
    std::uint32_t native_entry_rva=0,pe_entry_rva=0;
    std::uint64_t native_entry_file_offset=0,pe_entry_file_offset=0;
    std::string clr_section,native_entry_section,pe_entry_section;
    std::uint32_t managed_method_count=0,non_file_backed_method_count=0,pinvoke_method_count=0;
    std::uint32_t native_import_module_count=0,native_import_count=0,native_export_count=0;
    std::vector<DotNetBoundaryMethod> bridge_methods;
    std::vector<DotNetBoundaryDependency> dependencies;
    std::vector<RangeRef> ranges;
};

DotNetBoundaryInfo analyze_dotnet_boundary(std::span<const std::uint8_t> data,
                                           const PeInfo& pe,
                                           const DotNetInfo& dotnet);
Finding dotnet_boundary_finding(const DotNetBoundaryInfo& info);

} // namespace prts
