#pragma once
#include "prts/cpython_extension.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct CPythonCythonFunction {
    std::string name;
    std::string doc;
    std::string source;            // module_method / runtime_bound
    std::string constructor_kind;  // PyModuleDef.m_methods / CPython_method_constructor / local_method_constructor
    std::uint32_t flags=0;
    std::uint32_t methoddef_rva=0;
    std::uint32_t callback_rva=0;
    std::uint32_t constructor_rva=0;
    std::uint32_t constructor_call_rva=0;
    std::uint32_t bind_call_rva=0;
};

struct CPythonCythonTypeMethod {
    std::string name;
    std::string doc;
    std::uint32_t flags=0;
    std::uint32_t methoddef_rva=0;
    std::uint32_t callback_rva=0;
};

struct CPythonCythonRuntimeTypeMethod {
    std::string name;
    std::string doc;
    std::string constructor_kind;
    std::uint32_t flags=0;
    std::uint32_t methoddef_rva=0;
    std::uint32_t callback_rva=0;
    std::uint32_t constructor_rva=0;
    std::uint32_t constructor_call_rva=0;
    std::uint32_t bind_helper_rva=0;
    std::uint32_t bind_call_rva=0;
};

struct CPythonCythonType {
    std::string name;
    std::uint32_t type_rva=0;
    std::uint32_t methods_rva=0;
    std::uint32_t ready_call_rva=0;
    std::uint32_t bind_call_rva=0;
    std::vector<CPythonCythonTypeMethod> methods;
    std::vector<CPythonCythonRuntimeTypeMethod> runtime_methods;
};

struct CPythonCythonCAPIExport {
    std::string name;
    std::string signature;
    std::string recovery_kind;
    std::uint32_t callback_rva=0;
    std::uint32_t export_helper_rva=0;
    std::uint32_t export_call_rva=0;
    std::uint32_t capsule_call_rva=0;
    std::uint32_t dict_set_call_rva=0;
    std::uint32_t compressed_table_rva=0;
    std::uint32_t compressed_size=0;
    std::uint32_t decompressed_size=0;
};

struct CPythonCythonInfo {
    bool valid=false;
    std::string state; // NOT_CPYTHON_EXTENSION / NO_PEP489_EXEC / NO_GENERATED_RELATIONS / STRUCTURAL_RELATIONS / CONFIRMED_CYTHON
    std::string error;
    std::string module_name;
    std::uint32_t moduledef_rva=0;
    std::uint32_t exec_rva=0;
    bool marker_support=false;
    std::vector<std::string> markers;
    std::vector<CPythonCythonFunction> functions;
    std::vector<CPythonCythonType> types;
    std::vector<CPythonCythonCAPIExport> c_api_exports;
};

CPythonCythonInfo analyze_cpython_cython(std::span<const std::uint8_t> data,
                                         const PeInfo& pe,
                                         const CPythonExtensionInfo& extension);

}
