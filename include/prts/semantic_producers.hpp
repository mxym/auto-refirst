#pragma once

#include "prts/godot.hpp"
#include "prts/semantic_composition.hpp"

#include <vector>

namespace prts {

struct SemanticProducerClaim {
    SemanticCompositionClaim claim;
    SemanticCompositionAssessment assessment;
};

struct GodotSemanticProducerResult {
    std::vector<SemanticProducerClaim> l3_claims;
    std::vector<SemanticProducerClaim> l4_claims;
};

// Convert mechanism-specific, already computed Godot oracle evidence into the
// generic AB semantic-composition envelope.  This constructor never discovers
// targets from paths/names and never upgrades an unresolved key reduction.
GodotSemanticProducerResult produce_godot_semantic_composition(
    const GodotExternalPckValidation& validation,
    std::span<const GodotExternalPckMaterializedChild> children={});

} // namespace prts
