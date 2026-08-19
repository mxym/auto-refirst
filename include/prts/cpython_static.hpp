#pragma once
#include "prts/cpython.hpp"
#include "prts/cpython_cython.hpp"
#include "prts/cpython_extension.hpp"
#include "prts/cpython_frozen.hpp"
#include "prts/cpython_frozen_gate.hpp"
#include "prts/cpython_frozen_priority.hpp"
#include "prts/pe.hpp"
#include <span>
#include <string>

namespace prts {
struct CPythonStaticInfo {
    bool valid=false;
    std::string state="NO_CPYTHON_STATIC"; // NO_CPYTHON_STATIC / CPYTHON_RUNTIME / CPYTHON_RUNTIME_WITH_REGISTRATIONS / CPYTHON_EXTENSION / CYTHON_EXTENSION
    CPythonInfo runtime;
    CPythonExtensionInfo extension;
    CPythonCythonInfo cython;
    CPythonFrozenInfo frozen;
    CPythonFrozenReferenceGate frozen_reference_gate;
    CPythonFrozenPriorityInfo priority;
};

CPythonStaticInfo analyze_cpython_static(std::span<const std::uint8_t> data,
                                         const PeInfo& pe,
                                         bool pyinstaller_user_payload_present=false,
                                         const std::string& source={});
}
