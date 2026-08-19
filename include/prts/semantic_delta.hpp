#pragma once
#include "prts/model_trust.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace prts {

enum class SemanticDeltaClassification : std::uint8_t {
    Unresolved,
    ExactDeclarativeDelta,
    BoundedStructuralDelta,
    ReferenceOnlyNoPayloadBinding,
    PayloadBoundButSemanticsTooGeneral,
    RequiresVmExecution,
    RequiresNativeRuntimeOracle,
};

enum class SemanticDeltaReferenceAuth : std::uint8_t { None, IdentityOnly, ExactKnownGoodReference };
enum class SemanticDeltaKind : std::uint8_t { Unknown, OpcodePermutation, SourcePatch, InterpreterDefinition, RuntimeBehaviorOverride, RuntimeMetadata };
enum class SemanticDeltaCompleteness : std::uint8_t { None, MechanismOnly, Partial, CompleteForDeclaredScope };
enum class SemanticDeltaRecoverability : std::uint8_t { Unknown, Declarative, BoundedStructural, SemanticsTooGeneral, VmExecution, NativeRuntimeOracle };
enum class SemanticDeltaPayloadRelation : std::uint8_t { Unproven, SameBundleOnly, DirectArtifactReference, WrapperInvocation, EmbeddedPayload, RuntimeConsumesPayload };
enum class SemanticDeltaApplicationProof : std::uint8_t { None, RelationOnly, ExactStaticScope, ExactTransformClosure, NativeOracle, ProvenOutsideDeltaScope };

struct SemanticDeltaArtifactIdentity {
    std::string artifact_id;
    std::string sha256;
    bool exact_bytes=false;
};

struct SemanticDeltaItem {
    std::string key;
    std::string reference_value;
    std::string modified_value;
    std::string evidence;
};

// Contract for a bounded claim about how one identified semantic scope differs.
// It intentionally has no "whole runtime understood" switch: completeness is
// always relative to semantic_scope and never promotes to a parent scope.
struct SemanticDeltaEvidence {
    std::string plane;
    std::string family;
    std::string semantic_scope;
    std::string model_id;

    SemanticDeltaArtifactIdentity reference;
    SemanticDeltaReferenceAuth reference_auth=SemanticDeltaReferenceAuth::None;
    std::string reference_authentication;
    SemanticDeltaArtifactIdentity modified_artifact;

    SemanticDeltaKind delta_kind=SemanticDeltaKind::Unknown;
    std::vector<SemanticDeltaItem> delta_items;
    SemanticDeltaCompleteness delta_completeness=SemanticDeltaCompleteness::None;
    SemanticDeltaRecoverability recoverability=SemanticDeltaRecoverability::Unknown;
    bool modification_proven=false;

    SemanticDeltaArtifactIdentity payload;
    SemanticDeltaPayloadRelation payload_relation=SemanticDeltaPayloadRelation::Unproven;
    std::string payload_relation_evidence;
    SemanticDeltaApplicationProof application_proof=SemanticDeltaApplicationProof::None;
    std::string application_evidence;

    ModelEvidenceLevel evidence_ceiling=ModelEvidenceLevel::None;
    bool native_contradiction=false;
    ModelEvidenceLevel native_contradiction_level=ModelEvidenceLevel::OriginalNativeResult;
    std::string native_contradiction_evidence;
    std::string limitations;
};

struct SemanticDeltaAssessment {
    bool valid=false;
    SemanticDeltaClassification classification=SemanticDeltaClassification::Unresolved;
    bool exact_delta_for_scope=false;
    bool payload_binding_proven=false;
    bool payload_applicable=false;
    bool scope_complete=false;
    std::string claim_scope;
    std::string error;
};

SemanticDeltaAssessment assess_semantic_delta(const SemanticDeltaEvidence& evidence);
std::vector<ModelTrustFact> model_trust_facts_from_semantic_delta(const SemanticDeltaEvidence& evidence);
const char* to_string(SemanticDeltaClassification value);

}
