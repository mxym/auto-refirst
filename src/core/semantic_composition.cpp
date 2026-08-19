#include "prts/semantic_composition.hpp"

#include <algorithm>
#include <utility>

namespace prts {
namespace {

bool same_artifact(const std::filesystem::path&a,const std::filesystem::path&b) {
    if(a.empty()||b.empty())return false;
    return a.lexically_normal()==b.lexically_normal();
}

void reason(SemanticCompositionAssessment&out,std::string value) {
    out.reasons.push_back(std::move(value));
}

} // namespace

bool semantic_composition_has_ambiguity(const SemanticCompositionClaim&claim) {
    return claim.ambiguity!=SemanticAmbiguity::None||!claim.ambiguity_reasons.empty();
}

SemanticCompositionAssessment assess_semantic_composition(const SemanticCompositionClaim&claim) {
    SemanticCompositionAssessment out;
    for(const auto&step:claim.provenance_chain)
        out.evidence_ceiling=std::max(out.evidence_ceiling,step.evidence_level);

    if(claim.source_artifact.empty())reason(out,"source artifact is missing");
    if(claim.target_artifact.empty())reason(out,"target artifact is missing");
    if(same_artifact(claim.source_artifact,claim.target_artifact))reason(out,"L3/L4 composition requires distinct source and target artifacts");
    if(claim.semantic_scope.empty())reason(out,"semantic scope is missing");
    if(claim.relation_level==SemanticRelationLevel::Unspecified)reason(out,"semantic relation level is missing");
    if(claim.relation_kind==SemanticRelationKind::Unspecified)reason(out,"semantic relation kind is missing");
    if(claim.relation_kind==SemanticRelationKind::DeterministicTransformation&&
       claim.relation_level!=SemanticRelationLevel::TransformationProvenance)
        reason(out,"deterministic transformation kind requires L4 transformation provenance");
    if(claim.reference_or_model_id.empty())reason(out,"reference/model id is missing");
    if(claim.source_coordinate.empty())reason(out,"source coordinate is missing");
    if(claim.target_coordinate.empty())reason(out,"target coordinate is missing");
    if(claim.transformation_description.empty())reason(out,"transformation description is missing");
    if(claim.provenance_chain.empty())reason(out,"provenance chain is missing");
    if(claim.relation_level==SemanticRelationLevel::TransformationProvenance&&claim.result_artifact.empty())
        reason(out,"L4 transformation provenance requires a result artifact");

    for(std::size_t i=0;i<claim.provenance_chain.size();++i){
        const auto&step=claim.provenance_chain[i];
        const auto prefix="provenance step "+std::to_string(i)+" ";
        if(step.artifact.empty())reason(out,prefix+"artifact is missing");
        if(step.coordinate.empty())reason(out,prefix+"coordinate is missing");
        if(step.operation.empty())reason(out,prefix+"operation is missing");
        if(step.evidence_level==ModelEvidenceLevel::None)reason(out,prefix+"evidence level is missing");
        if(step.reference_or_model_id.empty())reason(out,prefix+"reference/model id is missing");
    }

    if(claim.evidence_level==ModelEvidenceLevel::None)reason(out,"bridge evidence level is missing");
    else if(claim.evidence_level>out.evidence_ceiling)
        reason(out,"bridge evidence level exceeds provenance-chain evidence ceiling");

    if(semantic_composition_has_ambiguity(claim)){
        reason(out,"semantic ambiguity is unresolved");
        for(const auto&r:claim.ambiguity_reasons)if(!r.empty())reason(out,"ambiguity: "+r);
    }
    if(claim.contradicted_by_higher_evidence)
        reason(out,"semantic claim is contradicted by higher-level evidence");

    if(!out.reasons.empty())return out;

    if(claim.evidence_level<=ModelEvidenceLevel::OfflineModel){
        out.state=SemanticCompositionState::ModelOnly;
        reason(out,"model/self-consistency evidence cannot confirm a cross-file semantic bridge");
        return out;
    }
    if(!claim.scope_complete){
        out.state=SemanticCompositionState::Bounded;
        reason(out,"semantic bridge is evidenced but the stated scope is incomplete");
        return out;
    }

    out.state=SemanticCompositionState::Confirmed;
    reason(out,"semantic bridge is independently evidenced and complete for the stated scope");
    return out;
}

std::string_view to_string(SemanticRelationLevel value) {
    switch(value){
        case SemanticRelationLevel::Unspecified:return "UNSPECIFIED";
        case SemanticRelationLevel::SemanticValue:return "L3_SEMANTIC_VALUE";
        case SemanticRelationLevel::TransformationProvenance:return "L4_TRANSFORMATION_PROVENANCE";
    }
    return "UNSPECIFIED";
}

std::string_view to_string(SemanticRelationKind value) {
    switch(value){
        case SemanticRelationKind::Unspecified:return "UNSPECIFIED";
        case SemanticRelationKind::ValueInterpretation:return "VALUE_INTERPRETATION";
        case SemanticRelationKind::RuntimeSemanticDependency:return "RUNTIME_SEMANTIC_DEPENDENCY";
        case SemanticRelationKind::ProtocolSemanticDependency:return "PROTOCOL_SEMANTIC_DEPENDENCY";
        case SemanticRelationKind::SourceSemanticDelta:return "SOURCE_SEMANTIC_DELTA";
        case SemanticRelationKind::DeterministicTransformation:return "DETERMINISTIC_TRANSFORMATION";
    }
    return "UNSPECIFIED";
}

std::string_view to_string(SemanticCompositionState value) {
    switch(value){
        case SemanticCompositionState::Unresolved:return "UNRESOLVED";
        case SemanticCompositionState::ModelOnly:return "MODEL_ONLY";
        case SemanticCompositionState::Bounded:return "BOUNDED";
        case SemanticCompositionState::Confirmed:return "CONFIRMED";
    }
    return "UNRESOLVED";
}

} // namespace prts
