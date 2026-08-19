#pragma once
#include "prts/cpython.hpp"
#include "prts/cpython_frozen.hpp"
#include "prts/model_trust.hpp"

namespace prts {

// Adapt the existing independent CPython reference/probe planes into the
// generic trust contract.  The returned report is derived on demand so it can
// include a compiler probe that may have run after static analysis.
ModelTrustReport build_cpython_model_trust(const CPythonInfo& cpython,
                                           const CPythonFrozenInfo* frozen=nullptr);

}
