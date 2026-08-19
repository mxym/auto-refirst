#include "prts/semantic_delta.hpp"
#include <utility>

namespace prts { namespace {
bool exact_identity(const SemanticDeltaArtifactIdentity& x){return x.exact_bytes&&!x.artifact_id.empty()&&!x.sha256.empty();}
bool payload_bound(SemanticDeltaPayloadRelation x){
    return x==SemanticDeltaPayloadRelation::DirectArtifactReference||x==SemanticDeltaPayloadRelation::WrapperInvocation||
           x==SemanticDeltaPayloadRelation::EmbeddedPayload||x==SemanticDeltaPayloadRelation::RuntimeConsumesPayload;
}
bool application_exact(SemanticDeltaApplicationProof x){
    return x==SemanticDeltaApplicationProof::ExactStaticScope||x==SemanticDeltaApplicationProof::ExactTransformClosure||x==SemanticDeltaApplicationProof::NativeOracle;
}
}

SemanticDeltaAssessment assess_semantic_delta(const SemanticDeltaEvidence&e){
    SemanticDeltaAssessment a;a.claim_scope=e.semantic_scope;
    if(e.semantic_scope.empty()||e.model_id.empty()){a.error="semantic delta requires an explicit semantic_scope and model_id";return a;}
    a.valid=true;a.scope_complete=e.delta_completeness==SemanticDeltaCompleteness::CompleteForDeclaredScope;
    a.payload_binding_proven=payload_bound(e.payload_relation)&&exact_identity(e.payload)&&!e.payload_relation_evidence.empty();
    a.payload_applicable=a.payload_binding_proven&&application_exact(e.application_proof)&&!e.application_evidence.empty();
    if(e.native_contradiction&&e.native_contradiction_evidence.empty()){a.valid=false;a.error="native contradiction requires concrete evidence";return a;}

    // Higher native contradiction always blocks promotion of reference/model evidence.
    if(e.native_contradiction||e.recoverability==SemanticDeltaRecoverability::NativeRuntimeOracle){
        a.classification=SemanticDeltaClassification::RequiresNativeRuntimeOracle;return a;
    }
    if(e.recoverability==SemanticDeltaRecoverability::VmExecution){
        a.classification=SemanticDeltaClassification::RequiresVmExecution;return a;
    }
    if(!a.payload_binding_proven){
        if(e.reference_auth!=SemanticDeltaReferenceAuth::None||e.modification_proven||!e.delta_items.empty())
            a.classification=SemanticDeltaClassification::ReferenceOnlyNoPayloadBinding;
        return a;
    }
    if(e.recoverability==SemanticDeltaRecoverability::SemanticsTooGeneral){
        a.classification=SemanticDeltaClassification::PayloadBoundButSemanticsTooGeneral;return a;
    }
    if(e.recoverability==SemanticDeltaRecoverability::BoundedStructural){
        if(exact_identity(e.modified_artifact)&&e.modification_proven&&!e.delta_items.empty())
            a.classification=SemanticDeltaClassification::BoundedStructuralDelta;
        return a;
    }
    if(e.recoverability==SemanticDeltaRecoverability::Declarative){
        const bool exact_reference=e.reference_auth==SemanticDeltaReferenceAuth::ExactKnownGoodReference&&exact_identity(e.reference)&&!e.reference_authentication.empty();
        const bool exact_modified=exact_identity(e.modified_artifact);
        const bool complete=e.delta_completeness==SemanticDeltaCompleteness::CompleteForDeclaredScope;
        const bool exact_ceiling=static_cast<int>(e.evidence_ceiling)>=static_cast<int>(ModelEvidenceLevel::ExactKnownGoodReference);
        if(exact_reference&&exact_modified&&e.modification_proven&&complete&&!e.delta_items.empty()&&a.payload_applicable&&exact_ceiling){
            a.classification=SemanticDeltaClassification::ExactDeclarativeDelta;a.exact_delta_for_scope=true;
        }
    }
    return a;
}

std::vector<ModelTrustFact> model_trust_facts_from_semantic_delta(const SemanticDeltaEvidence&e){
    std::vector<ModelTrustFact> out;auto a=assess_semantic_delta(e);if(!a.valid)return out;
    if(e.reference_auth==SemanticDeltaReferenceAuth::ExactKnownGoodReference&&exact_identity(e.reference)&&!e.reference_authentication.empty()&&e.modification_proven){
        ModelTrustFact f;f.plane=e.plane;f.semantic_scope=e.semantic_scope;f.reference_scope=e.reference.artifact_id;f.model_id=e.model_id;
        f.evidence_level=ModelEvidenceLevel::ExactKnownGoodReference;f.reference_relation=ModelReferenceRelation::ExactDifference;
        f.semantic_state=a.exact_delta_for_scope?ModelSemanticState::ExactDeltaRecovered:ModelSemanticState::ModifiedUnresolved;
        f.scope_complete=a.exact_delta_for_scope;f.delta_items=a.exact_delta_for_scope?static_cast<std::uint32_t>(e.delta_items.size()):0;
        f.evidence=a.exact_delta_for_scope?e.application_evidence:(!e.limitations.empty()?e.limitations:(!e.application_evidence.empty()?e.application_evidence:e.reference_authentication));out.push_back(std::move(f));
    }
    if(e.native_contradiction){
        ModelTrustFact f;f.plane=e.plane.empty()?"native_contradiction":e.plane+".native";f.semantic_scope=e.semantic_scope;f.model_id=e.model_id;
        f.evidence_level=e.native_contradiction_level;f.semantic_state=ModelSemanticState::Unresolved;f.model_relation=ModelRelation::Contradicts;
        f.evidence=e.native_contradiction_evidence;out.push_back(std::move(f));
    }
    return out;
}

const char* to_string(SemanticDeltaClassification v){switch(v){
 case SemanticDeltaClassification::ExactDeclarativeDelta:return "EXACT_DECLARATIVE_DELTA";
 case SemanticDeltaClassification::BoundedStructuralDelta:return "BOUNDED_STRUCTURAL_DELTA";
 case SemanticDeltaClassification::ReferenceOnlyNoPayloadBinding:return "REFERENCE_ONLY_NO_PAYLOAD_BINDING";
 case SemanticDeltaClassification::PayloadBoundButSemanticsTooGeneral:return "PAYLOAD_BOUND_BUT_SEMANTICS_TOO_GENERAL";
 case SemanticDeltaClassification::RequiresVmExecution:return "REQUIRES_VM_EXECUTION";
 case SemanticDeltaClassification::RequiresNativeRuntimeOracle:return "REQUIRES_NATIVE_RUNTIME_ORACLE";
 default:return "UNRESOLVED";
}}
}
