#include "prts/model_trust.hpp"
#include <algorithm>
#include <map>
#include <utility>

namespace prts { namespace {
int strength(ModelEvidenceLevel v){return static_cast<int>(v);}

ModelTrustAssessment assess_group(const std::vector<ModelTrustFact>& facts,
                                  const std::vector<std::size_t>& indices){
    ModelTrustAssessment out;
    if(indices.empty())return out;
    out.semantic_scope=facts[indices.front()].semantic_scope;
    out.model_id=facts[indices.front()].model_id;
    out.fact_indices=indices;

    int ceiling=0,strongest_support=0,strongest_contradiction=0;
    for(auto i:indices){
        const auto&f=facts[i];
        ceiling=std::max(ceiling,strength(f.evidence_level));
        if(f.model_relation==ModelRelation::Supports||f.semantic_state==ModelSemanticState::StockConfirmed||
           f.semantic_state==ModelSemanticState::StockCompatiblePartial||f.semantic_state==ModelSemanticState::ModelOnly){
            strongest_support=std::max(strongest_support,strength(f.evidence_level));
        }
        if(f.model_relation==ModelRelation::Contradicts)strongest_contradiction=std::max(strongest_contradiction,strength(f.evidence_level));
    }
    out.evidence_ceiling=static_cast<ModelEvidenceLevel>(ceiling);

    // A higher-level oracle can invalidate a lower-level model conclusion.
    // Equal-level disagreement remains unresolved; lower evidence never wins.
    if(strongest_contradiction>0&&strongest_contradiction==ceiling&&strongest_contradiction>strongest_support){
        out.state=ModelTrustState::StaticModelContradictedByHigherEvidence;
        return out;
    }
    if(strongest_contradiction>0&&strongest_contradiction==ceiling&&strongest_contradiction==strongest_support){
        out.state=ModelTrustState::EvidenceConflictUnresolved;
        return out;
    }

    bool stock=false,stock_partial=false,modified=false,exact_delta=false,model_only=false;
    bool stock_complete=false,reference_unavailable=false;
    for(auto i:indices){
        const auto&f=facts[i];
        if(strength(f.evidence_level)!=ceiling)continue;
        reference_unavailable|=f.reference_relation==ModelReferenceRelation::Unavailable;
        switch(f.semantic_state){
            case ModelSemanticState::StockConfirmed: stock=true;stock_complete|=f.scope_complete;break;
            case ModelSemanticState::StockCompatiblePartial: stock_partial=true;break;
            case ModelSemanticState::ModifiedUnresolved: modified=true;break;
            case ModelSemanticState::ExactDeltaRecovered: exact_delta=true;break;
            case ModelSemanticState::ModelOnly: model_only=true;break;
            case ModelSemanticState::Unresolved: break;
        }
    }
    if((stock||stock_partial)&&(modified||exact_delta)){
        out.state=ModelTrustState::EvidenceConflictUnresolved;
    }else if(modified){
        out.state=ModelTrustState::UnresolvedModifiedRuntime;
    }else if(exact_delta){
        out.state=ModelTrustState::ExactModifiedSemantics;
    }else if(stock){
        out.state=stock_complete?ModelTrustState::StockModelSafe:ModelTrustState::StockModelPartial;
    }else if(stock_partial){
        out.state=ModelTrustState::StockModelPartial;
    }else if(model_only){
        out.state=ModelTrustState::ModelOnly;
    }else if(reference_unavailable){
        out.state=ModelTrustState::ReferenceUnavailable;
    }else{
        out.state=ModelTrustState::Unresolved;
    }
    return out;
}

void count_state(ModelTrustReport&out,ModelTrustState s){
    switch(s){
        case ModelTrustState::StockModelSafe:++out.stock_safe_scopes;break;
        case ModelTrustState::StockModelPartial:++out.stock_partial_scopes;break;
        case ModelTrustState::ExactModifiedSemantics:++out.exact_modified_scopes;break;
        case ModelTrustState::UnresolvedModifiedRuntime:++out.unresolved_modified_scopes;break;
        case ModelTrustState::ModelOnly:++out.model_only_scopes;break;
        case ModelTrustState::ReferenceUnavailable:++out.reference_unavailable_scopes;break;
        case ModelTrustState::StaticModelContradictedByHigherEvidence:++out.contradicted_model_scopes;break;
        case ModelTrustState::EvidenceConflictUnresolved:++out.evidence_conflict_scopes;break;
        case ModelTrustState::Unresolved:++out.unresolved_scopes;break;
    }
}

ModelTrustState aggregate_guidance(const ModelTrustReport&out){
    if(out.contradicted_model_scopes)return ModelTrustState::StaticModelContradictedByHigherEvidence;
    if(out.unresolved_modified_scopes)return ModelTrustState::UnresolvedModifiedRuntime;
    if(out.evidence_conflict_scopes)return ModelTrustState::EvidenceConflictUnresolved;
    const bool weak_or_partial=out.unresolved_scopes||out.model_only_scopes||out.reference_unavailable_scopes||out.stock_partial_scopes;
    if(out.exact_modified_scopes&&!weak_or_partial)return ModelTrustState::ExactModifiedSemantics;
    if(weak_or_partial){
        if(out.stock_safe_scopes||out.stock_partial_scopes)return ModelTrustState::StockModelPartial;
        if(out.model_only_scopes&&!out.reference_unavailable_scopes)return ModelTrustState::ModelOnly;
        return ModelTrustState::Unresolved;
    }
    if(out.stock_safe_scopes)return ModelTrustState::StockModelSafe;
    return ModelTrustState::Unresolved;
}
}

std::optional<ModelTrustFact> model_trust_fact_from_exact_reference_delta(const ExactReferenceDeltaEvidence&e){
    if(!e.exact_reference_confirmed||!e.modification_proven||e.semantic_scope.empty())return std::nullopt;
    ModelTrustFact f;
    f.plane=e.plane;
    f.semantic_scope=e.semantic_scope;
    f.reference_scope=e.reference_scope;
    f.model_id=e.model_id;
    f.evidence_level=ModelEvidenceLevel::ExactKnownGoodReference;
    f.reference_relation=ModelReferenceRelation::ExactDifference;
    const bool complete_delta=e.exact_semantic_delta_recovered&&e.delta_complete;
    f.semantic_state=complete_delta?ModelSemanticState::ExactDeltaRecovered:ModelSemanticState::ModifiedUnresolved;
    f.scope_complete=complete_delta;
    f.delta_items=e.delta_items;
    f.evidence=e.evidence;
    return f;
}

ModelTrustReport build_model_trust_report(std::vector<ModelTrustFact> facts){
    ModelTrustReport out;out.facts=std::move(facts);
    std::map<std::pair<std::string,std::string>,std::vector<std::size_t>> groups;
    for(std::size_t i=0;i<out.facts.size();++i){
        const auto&f=out.facts[i];
        if(f.semantic_scope.empty())continue;
        groups[{f.semantic_scope,f.model_id}].push_back(i);
    }
    out.assessments.reserve(groups.size());
    for(const auto&[key,indices]:groups){
        (void)key;
        auto a=assess_group(out.facts,indices);count_state(out,a.state);out.assessments.push_back(std::move(a));
    }
    out.guidance=aggregate_guidance(out);
    return out;
}

const ModelTrustAssessment* find_model_trust_assessment(const ModelTrustReport&r,std::string_view scope,std::string_view model){
    const ModelTrustAssessment*match=nullptr;
    for(const auto&a:r.assessments){
        if(a.semantic_scope!=scope||(!model.empty()&&a.model_id!=model))continue;
        if(match&&model.empty())return nullptr; // ambiguous across model candidates
        match=&a;
    }
    return match;
}

std::string_view to_string(ModelEvidenceLevel v){switch(v){
    case ModelEvidenceLevel::OriginalNativeResult:return "ORIGINAL_NATIVE_RESULT";
    case ModelEvidenceLevel::LowDisturbanceNativeBoundary:return "LOW_DISTURBANCE_NATIVE_BOUNDARY";
    case ModelEvidenceLevel::ExactKnownGoodReference:return "EXACT_KNOWN_GOOD_REFERENCE";
    case ModelEvidenceLevel::ChosenInputOracle:return "CHOSEN_INPUT_ORACLE";
    case ModelEvidenceLevel::OfflineModel:return "OFFLINE_MODEL";
    case ModelEvidenceLevel::ModelInternalRoundTrip:return "MODEL_INTERNAL_ROUND_TRIP";
    case ModelEvidenceLevel::None:return "NONE";
}return "NONE";}
std::string_view to_string(ModelReferenceRelation v){switch(v){
    case ModelReferenceRelation::NotApplicable:return "NOT_APPLICABLE";
    case ModelReferenceRelation::ExactMatch:return "EXACT_MATCH";
    case ModelReferenceRelation::SemanticMatch:return "SEMANTIC_MATCH";
    case ModelReferenceRelation::ExactDifference:return "EXACT_DIFFERENCE";
    case ModelReferenceRelation::Unavailable:return "REFERENCE_UNAVAILABLE";
}return "NOT_APPLICABLE";}
std::string_view to_string(ModelSemanticState v){switch(v){
    case ModelSemanticState::Unresolved:return "UNRESOLVED";
    case ModelSemanticState::ModelOnly:return "MODEL_ONLY";
    case ModelSemanticState::StockCompatiblePartial:return "STOCK_COMPATIBLE_PARTIAL";
    case ModelSemanticState::StockConfirmed:return "STOCK_CONFIRMED";
    case ModelSemanticState::ModifiedUnresolved:return "MODIFIED_UNRESOLVED";
    case ModelSemanticState::ExactDeltaRecovered:return "EXACT_DELTA_RECOVERED";
}return "UNRESOLVED";}
std::string_view to_string(ModelRelation v){switch(v){
    case ModelRelation::None:return "NONE";
    case ModelRelation::Supports:return "SUPPORTS_MODEL";
    case ModelRelation::Contradicts:return "CONTRADICTS_MODEL";
}return "NONE";}
std::string_view to_string(ModelTrustState v){switch(v){
    case ModelTrustState::Unresolved:return "UNRESOLVED_SEMANTICS";
    case ModelTrustState::ReferenceUnavailable:return "NO_EXACT_REFERENCE";
    case ModelTrustState::ModelOnly:return "MODEL_ONLY_CONCLUSION";
    case ModelTrustState::StockModelPartial:return "STOCK_MODEL_PARTIAL";
    case ModelTrustState::StockModelSafe:return "STOCK_MODEL_SAFE";
    case ModelTrustState::ExactModifiedSemantics:return "EXACT_MODIFIED_SEMANTICS";
    case ModelTrustState::UnresolvedModifiedRuntime:return "UNRESOLVED_MODIFIED_RUNTIME";
    case ModelTrustState::EvidenceConflictUnresolved:return "EVIDENCE_CONFLICT_UNRESOLVED";
    case ModelTrustState::StaticModelContradictedByHigherEvidence:return "STATIC_MODEL_CONTRADICTED_BY_HIGHER_EVIDENCE";
}return "UNRESOLVED_SEMANTICS";}
}
