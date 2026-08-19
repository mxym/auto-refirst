#pragma once
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {
struct CPythonExtensionMethod {
    std::string name;
    std::string doc;
    std::uint32_t flags=0;
    std::uint32_t record_rva=0;
    std::uint32_t name_rva=0;
    std::uint32_t doc_rva=0;
    std::uint32_t callback_rva=0;
};

struct CPythonExtensionSlot {
    std::int32_t slot=0;
    std::uint32_t record_rva=0;
    std::uint64_t raw_value=0;
    std::uint32_t value_rva=0;
    std::string value_kind; // CALLBACK_RVA / ENUM_VALUE / RAW_UNSUPPORTED
};

struct CPythonExtensionModule {
    std::string export_name;
    std::string registration_source;
    std::string registration_name;
    std::string module_name;
    std::string name_relation; // EXACT / ALIAS
    std::string doc;
    std::string init_api;
    std::string state;         // CONFIRMED / PARTIAL
    std::string methods_state; // NONE / CONFIRMED / UNAVAILABLE_NON_FILE_BACKED
    std::string slots_state;   // NONE / CONFIRMED / UNAVAILABLE_NON_FILE_BACKED / UNSUPPORTED_SLOT
    std::uint32_t init_rva=0;
    std::uint32_t moduledef_rva=0;
    std::uint32_t methods_rva=0;
    std::uint32_t slots_rva=0;
    std::uint32_t api_version=0;
    std::int64_t module_size=0;
    std::vector<CPythonExtensionMethod> methods;
    std::vector<CPythonExtensionSlot> slots;
};

struct CPythonInittabEntry {
    std::string name;
    std::uint32_t record_rva=0;
    std::uint32_t init_rva=0;
    bool init_is_null=false;
    bool module_recovered=false;
    std::string reject_reason;
};

struct CPythonExtensionRejected {
    std::string export_name;
    std::uint32_t init_rva=0;
    std::string reason;
};

struct CPythonExtensionInfo {
    bool valid=false;
    std::string state;
    std::uint32_t pyinit_export_count=0;
    std::string inittab_state;
    std::uint32_t inittab_export_rva=0;
    std::uint32_t inittab_table_rva=0;
    std::vector<CPythonInittabEntry> inittab;
    std::vector<CPythonExtensionModule> modules;
    std::vector<CPythonExtensionRejected> rejected;
};

CPythonExtensionInfo analyze_cpython_extension(std::span<const std::uint8_t> data,
                                               const PeInfo& pe);
}
