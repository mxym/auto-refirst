#pragma once

#include "prts/finding.hpp"
#include "prts/pe.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace prts {

// A bounded view of the PE/CLR bootstrap import contract.  This deliberately
// records only import-directory evidence; it does not resolve a CLR host or
// infer which runtime will satisfy a native import at execution time.
struct DotNetLoaderInfo {
    bool candidate = false;
    bool clr_directory = false;
    bool metadata_valid = false;
    bool image_dll = false;
    bool standard_bootstrap = false;
    bool contract_mismatch = false;
    std::string state = "NOT_PRESENT";
    std::string contract = "NONE";
    std::uint32_t mscoree_module_count = 0;
    std::uint32_t mscoree_import_count = 0;
    std::uint32_t recognized_import_count = 0;
    std::uint32_t standard_bootstrap_count = 0;
    std::uint32_t host_api_count = 0;
    std::uint32_t malformed_import_count = 0;
    std::uint32_t first_descriptor_rva = 0;
    std::vector<std::string> recognized_imports;
    std::vector<std::string> anomalies;
};

DotNetLoaderInfo analyze_dotnet_loader(const PeInfo& pe, bool metadata_valid);
Finding dotnet_loader_finding(const DotNetLoaderInfo& info);

} // namespace prts
