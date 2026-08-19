#pragma once

#include "prts/model_trust.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace prts {

// ArtifactRelationship owns L1/L2 identity, containment and structural-reference
// facts.  This contract starts at L3: a scoped value/rule/runtime semantic from
// one artifact is used to interpret another artifact.  L4 additionally records
// a deterministic produced artifact.
enum class SemanticRelationLevel : std::uint8_t {
    Unspecified=0,
    SemanticValue=3,
    TransformationProvenance=4,
};

enum class SemanticRelationKind : std::uint8_t {
    Unspecified=0,
    ValueInterpretation,
    RuntimeSemanticDependency,
    ProtocolSemanticDependency,
    SourceSemanticDelta,
    DeterministicTransformation,
};

enum class SemanticCompositionState : std::uint8_t {
    Unresolved=0,
    ModelOnly,
    Bounded,
    Confirmed,
};

// Ambiguity is explicit rather than inferred from filenames or directory
// layout.  Any ambiguity bit fails closed to UNRESOLVED; a producer may emit a
// narrower separate claim after independently resolving the ambiguity.
enum class SemanticAmbiguity : std::uint32_t {
    None=0,
    SourceCandidate=1u<<0,
    TargetCandidate=1u<<1,
    Direction=1u<<2,
    Producer=1u<<3,
    RuntimeBinding=1u<<4,
    VersionMismatch=1u<<5,
    Transformation=1u<<6,
};

constexpr SemanticAmbiguity operator|(SemanticAmbiguity a,SemanticAmbiguity b) {
    return static_cast<SemanticAmbiguity>(static_cast<std::uint32_t>(a)|static_cast<std::uint32_t>(b));
}
constexpr SemanticAmbiguity& operator|=(SemanticAmbiguity& a,SemanticAmbiguity b) {
    a=a|b;return a;
}

struct SemanticProvenanceStep {
    std::filesystem::path artifact;
    std::string coordinate;
    std::string operation;
    ModelEvidenceLevel evidence_level=ModelEvidenceLevel::None;
    std::string reference_or_model_id;
};

// `evidence_level` is the evidence level that closes the semantic bridge, not
// merely the strongest unrelated fact about either endpoint.  It must be
// represented by at least one provenance-chain step.  `scope_complete` means
// complete for the exact semantic_scope stated here; it does not claim that all
// semantics of either artifact are modeled.
//
// Producers are expected to feed Q/model-trust-reduced evidence into this
// contract.  `contradicted_by_higher_evidence` is a final fail-closed guard so a
// model-internal/offline transformation can never override stronger native or
// exact-reference contradiction.
struct SemanticCompositionClaim {
    std::filesystem::path source_artifact;
    std::filesystem::path target_artifact;
    std::filesystem::path result_artifact; // required only for L4
    std::string semantic_scope;
    SemanticRelationLevel relation_level=SemanticRelationLevel::Unspecified;
    SemanticRelationKind relation_kind=SemanticRelationKind::Unspecified;
    ModelEvidenceLevel evidence_level=ModelEvidenceLevel::None;
    std::string reference_or_model_id;
    std::string source_coordinate;
    std::string target_coordinate;
    std::string transformation_description;
    SemanticAmbiguity ambiguity=SemanticAmbiguity::None;
    std::vector<std::string> ambiguity_reasons;
    bool scope_complete=false;
    bool contradicted_by_higher_evidence=false;
    std::vector<SemanticProvenanceStep> provenance_chain;
};

struct SemanticCompositionAssessment {
    SemanticCompositionState state=SemanticCompositionState::Unresolved;
    ModelEvidenceLevel evidence_ceiling=ModelEvidenceLevel::None;
    std::vector<std::string> reasons;
};

bool semantic_composition_has_ambiguity(const SemanticCompositionClaim& claim);
SemanticCompositionAssessment assess_semantic_composition(const SemanticCompositionClaim& claim);

std::string_view to_string(SemanticRelationLevel value);
std::string_view to_string(SemanticRelationKind value);
std::string_view to_string(SemanticCompositionState value);

} // namespace prts
