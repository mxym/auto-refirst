#pragma once
#include "prts/cpython.hpp"
#include "prts/cpython_frozen.hpp"
#include <string>
namespace prts {
struct CPythonFrozenReferenceGate {
    bool allowed=false;
    std::string state; // REFERENCE_READY_EXACT / REFERENCE_READY_SEMANTIC_COMPARABLE / UNAVAILABLE_*
    std::string reference_version;
};
CPythonFrozenReferenceGate apply_cpython_frozen_reference_if_comparable(CPythonFrozenInfo& frozen,
                                                                         const CPythonInfo& cpython);
}
