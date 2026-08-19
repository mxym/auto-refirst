#include "prts/model_trust.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

namespace {
prts::ModelTrustFact fact(std::string plane,std::string scope,std::string model,
                          prts::ModelEvidenceLevel level,prts::ModelSemanticState semantic,
                          prts::ModelReferenceRelation reference=prts::ModelReferenceRelation::NotApplicable,
                          prts::ModelRelation relation=prts::ModelRelation::None,bool complete=false){
    prts::ModelTrustFact f;f.plane=std::move(plane);f.semantic_scope=std::move(scope);f.model_id=std::move(model);f.evidence_level=level;f.semantic_state=semantic;f.reference_relation=reference;f.model_relation=relation;f.scope_complete=complete;return f;
}
}

int main(){
    using namespace prts;

    static_assert(static_cast<int>(ModelEvidenceLevel::OriginalNativeResult)>static_cast<int>(ModelEvidenceLevel::LowDisturbanceNativeBoundary));
    static_assert(static_cast<int>(ModelEvidenceLevel::LowDisturbanceNativeBoundary)>static_cast<int>(ModelEvidenceLevel::ExactKnownGoodReference));
    static_assert(static_cast<int>(ModelEvidenceLevel::ExactKnownGoodReference)>static_cast<int>(ModelEvidenceLevel::ChosenInputOracle));
    static_assert(static_cast<int>(ModelEvidenceLevel::ChosenInputOracle)>static_cast<int>(ModelEvidenceLevel::OfflineModel));
    static_assert(static_cast<int>(ModelEvidenceLevel::OfflineModel)>static_cast<int>(ModelEvidenceLevel::ModelInternalRoundTrip));

    // N2 P0 oracle: an offline/static model concludes "not executable", but
    // original native execution succeeds.  The stronger native fact wins.
    {
        std::vector<ModelTrustFact> fs;
        fs.push_back(fact("static_elf_parser","program.execution","static-elf-loader",ModelEvidenceLevel::OfflineModel,ModelSemanticState::ModelOnly,ModelReferenceRelation::NotApplicable,ModelRelation::Supports));
        auto native=fact("native_execution","program.execution","static-elf-loader",ModelEvidenceLevel::OriginalNativeResult,ModelSemanticState::Unresolved,ModelReferenceRelation::NotApplicable,ModelRelation::Contradicts);
        native.evidence="same SHA executes successfully and exits 0";fs.push_back(std::move(native));
        auto r=build_model_trust_report(std::move(fs));auto*a=find_model_trust_assessment(r,"program.execution","static-elf-loader");
        assert(a&&a->state==ModelTrustState::StaticModelContradictedByHigherEvidence);
        assert(a->evidence_ceiling==ModelEvidenceLevel::OriginalNativeResult);
        assert(r.guidance==ModelTrustState::StaticModelContradictedByHigherEvidence&&r.contradicted_model_scopes==1);
        assert(to_string(r.guidance)=="STATIC_MODEL_CONTRADICTED_BY_HIGHER_EVIDENCE");
    }

    // Lower model-internal self-consistency or an explicit lower-level
    // contradiction cannot overturn an exact reference.
    {
        std::vector<ModelTrustFact> fs;
        fs.push_back(fact("exact_ref","component.semantic","stock",ModelEvidenceLevel::ExactKnownGoodReference,ModelSemanticState::StockConfirmed,ModelReferenceRelation::ExactMatch,ModelRelation::None,true));
        fs.push_back(fact("roundtrip","component.semantic","stock",ModelEvidenceLevel::ModelInternalRoundTrip,ModelSemanticState::ModifiedUnresolved));
        fs.push_back(fact("weak_model","component.semantic","stock",ModelEvidenceLevel::OfflineModel,ModelSemanticState::Unresolved,ModelReferenceRelation::NotApplicable,ModelRelation::Contradicts));
        auto r=build_model_trust_report(std::move(fs));auto*a=find_model_trust_assessment(r,"component.semantic","stock");
        assert(a&&a->state==ModelTrustState::StockModelSafe&&a->evidence_ceiling==ModelEvidenceLevel::ExactKnownGoodReference);
    }

    // Same-strength disagreement is preserved rather than arbitrarily won.
    {
        std::vector<ModelTrustFact> fs;
        fs.push_back(fact("plane_a","same.scope","stock",ModelEvidenceLevel::ExactKnownGoodReference,ModelSemanticState::StockConfirmed,ModelReferenceRelation::ExactMatch,ModelRelation::None,true));
        fs.push_back(fact("plane_b","same.scope","stock",ModelEvidenceLevel::ExactKnownGoodReference,ModelSemanticState::ModifiedUnresolved,ModelReferenceRelation::ExactDifference));
        auto r=build_model_trust_report(std::move(fs));auto*a=find_model_trust_assessment(r,"same.scope","stock");
        assert(a&&a->state==ModelTrustState::EvidenceConflictUnresolved&&r.evidence_conflict_scopes==1);
    }

    // Plane scoping: a match in one scope must not cover a mismatch in another.
    {
        std::vector<ModelTrustFact> fs;
        fs.push_back(fact("image","runtime.image","stock",ModelEvidenceLevel::ExactKnownGoodReference,ModelSemanticState::StockConfirmed,ModelReferenceRelation::ExactMatch,ModelRelation::None,true));
        fs.push_back(fact("opcode","runtime.opcodes","stock",ModelEvidenceLevel::ExactKnownGoodReference,ModelSemanticState::ModifiedUnresolved,ModelReferenceRelation::ExactDifference));
        auto r=build_model_trust_report(std::move(fs));auto*image=find_model_trust_assessment(r,"runtime.image","stock");auto*op=find_model_trust_assessment(r,"runtime.opcodes","stock");
        assert(image&&image->state==ModelTrustState::StockModelSafe);
        assert(op&&op->state==ModelTrustState::UnresolvedModifiedRuntime);
        assert(r.guidance==ModelTrustState::UnresolvedModifiedRuntime&&r.stock_safe_scopes==1&&r.unresolved_modified_scopes==1);
    }

    // Explicit no-reference and pure model-only conclusions stay weak.
    {
        auto unavailable=fact("reference","runtime.semantic","stock",ModelEvidenceLevel::None,ModelSemanticState::Unresolved,ModelReferenceRelation::Unavailable);
        auto r=build_model_trust_report({unavailable});auto*a=find_model_trust_assessment(r,"runtime.semantic","stock");assert(a&&a->state==ModelTrustState::ReferenceUnavailable);
        auto model=fact("offline_emulator","vm.semantic","stock-vm",ModelEvidenceLevel::OfflineModel,ModelSemanticState::ModelOnly,ModelReferenceRelation::NotApplicable,ModelRelation::Supports);
        r=build_model_trust_report({model});a=find_model_trust_assessment(r,"vm.semantic","stock-vm");assert(a&&a->state==ModelTrustState::ModelOnly&&r.guidance==ModelTrustState::ModelOnly);
    }

    // Exact supplied-reference deltas separate "modification proven" from
    // "concrete semantics recovered".  This is the Mixed-style contract.
    {
        ExactReferenceDeltaEvidence e;e.plane="supplied_patch";e.semantic_scope="cpython.opcode_numbering";e.reference_scope="authenticated CPython source patch";e.model_id="stock-cpython";e.exact_reference_confirmed=true;e.modification_proven=true;e.evidence="build-time opcode permutation patch";
        auto f=model_trust_fact_from_exact_reference_delta(e);assert(f&&f->semantic_state==ModelSemanticState::ModifiedUnresolved&&f->reference_relation==ModelReferenceRelation::ExactDifference);
        auto r=build_model_trust_report({*f});auto*a=find_model_trust_assessment(r,e.semantic_scope,e.model_id);assert(a&&a->state==ModelTrustState::UnresolvedModifiedRuntime);
        e.exact_semantic_delta_recovered=true;e.delta_complete=false;e.delta_items=12;f=model_trust_fact_from_exact_reference_delta(e);assert(f&&f->semantic_state==ModelSemanticState::ModifiedUnresolved&&!f->scope_complete);
        r=build_model_trust_report({*f});a=find_model_trust_assessment(r,e.semantic_scope,e.model_id);assert(a&&a->state==ModelTrustState::UnresolvedModifiedRuntime);
        e.delta_complete=true;e.delta_items=37;f=model_trust_fact_from_exact_reference_delta(e);assert(f&&f->semantic_state==ModelSemanticState::ExactDeltaRecovered&&f->scope_complete&&f->delta_items==37);
        r=build_model_trust_report({*f});a=find_model_trust_assessment(r,e.semantic_scope,e.model_id);assert(a&&a->state==ModelTrustState::ExactModifiedSemantics);
    }

    // An exact modified delta in one plane does not erase an unresolved
    // independent plane.  Scope-specific assessment stays exact; aggregate
    // guidance remains conservative.
    {
        std::vector<ModelTrustFact> fs;
        fs.push_back(fact("opcode","runtime.opcodes","stock",ModelEvidenceLevel::ExactKnownGoodReference,ModelSemanticState::ExactDeltaRecovered,ModelReferenceRelation::ExactDifference,ModelRelation::None,true));
        fs.push_back(fact("image","runtime.image","stock",ModelEvidenceLevel::None,ModelSemanticState::Unresolved,ModelReferenceRelation::Unavailable));
        auto r=build_model_trust_report(std::move(fs));
        auto*op=find_model_trust_assessment(r,"runtime.opcodes","stock");
        assert(op&&op->state==ModelTrustState::ExactModifiedSemantics);
        assert(r.guidance==ModelTrustState::Unresolved);
    }

    // Omitting model_id is allowed only when the semantic scope is unique.
    {
        std::vector<ModelTrustFact> fs;
        fs.push_back(fact("a","shared.scope","model-a",ModelEvidenceLevel::OfflineModel,ModelSemanticState::ModelOnly));
        fs.push_back(fact("b","shared.scope","model-b",ModelEvidenceLevel::OfflineModel,ModelSemanticState::ModelOnly));
        auto r=build_model_trust_report(std::move(fs));
        assert(!find_model_trust_assessment(r,"shared.scope"));
        assert(find_model_trust_assessment(r,"shared.scope","model-a"));
    }

    // Filename/version/runtime-string bait cannot manufacture an exact delta.
    {
        ExactReferenceDeltaEvidence bait;bait.plane="filename";bait.semantic_scope="runtime";bait.reference_scope="looks_like_patch.diff Python 3.11 V8 opcode table";bait.model_id="stock";bait.evidence="patch filename + Python/V8/version/opcode-like strings only";
        assert(!model_trust_fact_from_exact_reference_delta(bait));
        bait.exact_reference_confirmed=true;assert(!model_trust_fact_from_exact_reference_delta(bait));
    }

    std::cout<<"PASS\n";
}
