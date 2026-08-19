#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace prts {

// Numeric order is deliberate: larger values are stronger evidence.  This is
// the N2 evidence hierarchy expressed as an ordering that can be compared.
enum class ModelEvidenceLevel : std::uint8_t {
    None=0,
    ModelInternalRoundTrip=1,
    OfflineModel=2,
    ChosenInputOracle=3,
    ExactKnownGoodReference=4,
    LowDisturbanceNativeBoundary=5,
    OriginalNativeResult=6,
};

enum class ModelReferenceRelation : std::uint8_t {
    NotApplicable,
    ExactMatch,
    SemanticMatch,
    ExactDifference,
    Unavailable,
};

enum class ModelSemanticState : std::uint8_t {
    Unresolved,
    ModelOnly,
    StockCompatiblePartial,
    StockConfirmed,
    ModifiedUnresolved,
    ExactDeltaRecovered,
};

enum class ModelRelation : std::uint8_t {
    None,
    Supports,
    Contradicts,
};

enum class ModelTrustState : std::uint8_t {
    Unresolved,
    ReferenceUnavailable,
    ModelOnly,
    StockModelPartial,
    StockModelSafe,
    ExactModifiedSemantics,
    UnresolvedModifiedRuntime,
    EvidenceConflictUnresolved,
    StaticModelContradictedByHigherEvidence,
};

// A fact is intentionally scoped.  A REFERENCE_MATCH in one plane says
// nothing about another semantic_scope unless a separate fact covers it.
struct ModelTrustFact {
    std::string plane;
    std::string semantic_scope;
    std::string reference_scope;
    std::string model_id;
    ModelEvidenceLevel evidence_level=ModelEvidenceLevel::None;
    ModelReferenceRelation reference_relation=ModelReferenceRelation::NotApplicable;
    ModelSemanticState semantic_state=ModelSemanticState::Unresolved;
    ModelRelation model_relation=ModelRelation::None;
    bool scope_complete=false;
    std::uint32_t delta_items=0;
    std::string evidence;
};

struct ModelTrustAssessment {
    std::string semantic_scope;
    std::string model_id;
    ModelTrustState state=ModelTrustState::Unresolved;
    ModelEvidenceLevel evidence_ceiling=ModelEvidenceLevel::None;
    std::vector<std::size_t> fact_indices;
};

struct ModelTrustReport {
    std::vector<ModelTrustFact> facts;
    std::vector<ModelTrustAssessment> assessments;
    ModelTrustState guidance=ModelTrustState::Unresolved;
    std::uint32_t stock_safe_scopes=0;
    std::uint32_t stock_partial_scopes=0;
    std::uint32_t exact_modified_scopes=0;
    std::uint32_t unresolved_modified_scopes=0;
    std::uint32_t model_only_scopes=0;
    std::uint32_t reference_unavailable_scopes=0;
    std::uint32_t contradicted_model_scopes=0;
    std::uint32_t evidence_conflict_scopes=0;
    std::uint32_t unresolved_scopes=0;
};

// Contract for an upstream coordinator that has already authenticated an exact
// supplied reference/patch.  Strings such as filenames or version banners are
// deliberately insufficient: without exact_reference_confirmed and an
// independently established modification, no fact is returned.
struct ExactReferenceDeltaEvidence {
    std::string plane;
    std::string semantic_scope;
    std::string reference_scope;
    std::string model_id;
    bool exact_reference_confirmed=false;
    bool modification_proven=false;
    bool exact_semantic_delta_recovered=false;
    bool delta_complete=false;
    std::uint32_t delta_items=0;
    std::string evidence;
};

std::optional<ModelTrustFact> model_trust_fact_from_exact_reference_delta(const ExactReferenceDeltaEvidence& evidence);
ModelTrustReport build_model_trust_report(std::vector<ModelTrustFact> facts);
const ModelTrustAssessment* find_model_trust_assessment(const ModelTrustReport& report,
                                                         std::string_view semantic_scope,
                                                         std::string_view model_id={});

std::string_view to_string(ModelEvidenceLevel value);
std::string_view to_string(ModelReferenceRelation value);
std::string_view to_string(ModelSemanticState value);
std::string_view to_string(ModelRelation value);
std::string_view to_string(ModelTrustState value);

}
