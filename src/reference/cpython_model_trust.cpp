#include "prts/cpython_model_trust.hpp"
#include <algorithm>
#include <string>
#include <utility>

namespace prts { namespace {
std::string model_id(const CPythonInfo&c){return "stock-cpython:"+(c.version.empty()?std::string("unknown"):c.version);}
std::string base_ref_scope(const CPythonInfo&c){return c.reference_version.empty()?std::string("python.org exact CPython reference"):"python.org CPython "+c.reference_version;}
std::string scoped_ref(const CPythonInfo&c,std::string_view suffix){return base_ref_scope(c)+" "+std::string(suffix);}
void push(std::vector<ModelTrustFact>&facts,std::string plane,std::string scope,std::string reference_scope,const CPythonInfo&c,
          ModelEvidenceLevel level,ModelReferenceRelation relation,ModelSemanticState semantic,
          bool complete,std::uint32_t delta_items,std::string evidence){
    ModelTrustFact f;f.plane=std::move(plane);f.semantic_scope=std::move(scope);f.reference_scope=std::move(reference_scope);f.model_id=model_id(c);f.evidence_level=level;f.reference_relation=relation;f.semantic_state=semantic;f.scope_complete=complete;f.delta_items=delta_items;f.evidence=std::move(evidence);facts.push_back(std::move(f));
}
std::uint32_t modified_function_count(const CPythonInfo&c){return static_cast<std::uint32_t>(std::count_if(c.function_diffs.begin(),c.function_diffs.end(),[](const auto&f){return f.state=="MODIFIED_CANDIDATE";}));}
std::uint32_t dispatch_change_count(const CPythonInfo&c){return c.dispatch.permuted_slots+c.dispatch.handler_modified+c.dispatch.ambiguous+c.dispatch.unmapped;}
std::uint32_t dispatch_exact_delta_count(const CPythonInfo&c){
    std::uint32_t n=0;for(const auto&m:c.dispatch.mappings){if((m.state=="PERMUTED"||m.state=="SEMANTIC_PERMUTED")&&m.reference_opcodes.size()==1&&m.reference_opcodes.front()!=m.target_opcode)++n;}return n;
}
std::string frozen_scope(const CPythonFrozenTable&t,const CPythonFrozenModule&m){return "cpython.frozen_module:"+t.export_name+":"+m.name;}
}

ModelTrustReport build_cpython_model_trust(const CPythonInfo&c,const CPythonFrozenInfo*frozen){
    std::vector<ModelTrustFact> facts;
    if(!c.valid)return build_model_trust_report(std::move(facts));

    // Plane 1: exact native runtime image identity.  A full-file SHA match is
    // complete only for this image-identity scope, not for unrelated planes.
    if(c.reference_status=="REFERENCE_MATCH"){
        push(facts,"cpython.runtime_image","cpython.runtime_image",scoped_ref(c,"runtime image"),c,ModelEvidenceLevel::ExactKnownGoodReference,
             ModelReferenceRelation::ExactMatch,ModelSemanticState::StockConfirmed,true,0,
             "full runtime SHA-256 matches the exact same-version official reference");
    }else if(c.reference_status=="DIFFERS_FROM_OFFICIAL_REFERENCE"){
        push(facts,"cpython.runtime_image","cpython.runtime_image",scoped_ref(c,"runtime image"),c,ModelEvidenceLevel::ExactKnownGoodReference,
             ModelReferenceRelation::ExactDifference,ModelSemanticState::Unresolved,false,0,
             "full runtime image differs from the exact same-version official reference; byte difference alone does not prove a semantic modification");
    }else if(c.reference_status=="NO_EXACT_REFERENCE"){
        push(facts,"cpython.runtime_image","cpython.runtime_image",scoped_ref(c,"runtime image"),c,ModelEvidenceLevel::None,
             ModelReferenceRelation::Unavailable,ModelSemanticState::Unresolved,false,0,
             "no exact same-version native runtime reference is available");
    }

    // Plane 2: bounded native function-semantic comparison.  COMPARABLE is a
    // gate, not a global reference match.
    if(c.semantic_reference_status=="REFERENCE_MATCH"){
        push(facts,"cpython.native_semantic_reference","cpython.native_function_semantics",scoped_ref(c,"native function-semantic probe set"),c,ModelEvidenceLevel::ExactKnownGoodReference,
             ModelReferenceRelation::ExactMatch,ModelSemanticState::StockConfirmed,true,0,
             "native runtime image exactly matches the reference that owns the semantic function set");
    }else if(c.semantic_reference_status=="COMPARABLE"){
        const auto modified=modified_function_count(c);
        if(modified){
            push(facts,"cpython.native_semantic_reference","cpython.native_function_semantics",scoped_ref(c,"native function-semantic probe set"),c,ModelEvidenceLevel::ExactKnownGoodReference,
                 ModelReferenceRelation::ExactDifference,ModelSemanticState::ModifiedUnresolved,false,modified,
                 "comparable exact native-function references contain modified candidates; changed behavior is not reconstructed by this plane");
        }else{
            push(facts,"cpython.native_semantic_reference","cpython.native_function_semantics",scoped_ref(c,"native function-semantic probe set"),c,ModelEvidenceLevel::ExactKnownGoodReference,
                 ModelReferenceRelation::SemanticMatch,ModelSemanticState::StockCompatiblePartial,false,0,
                 "bounded native semantic probes are comparable with no modified function candidate, but they do not cover the whole runtime");
        }
    }else if(c.semantic_reference_status=="NO_SEMANTIC_REFERENCE"){
        push(facts,"cpython.native_semantic_reference","cpython.native_function_semantics",scoped_ref(c,"native function-semantic probe set"),c,ModelEvidenceLevel::None,
             ModelReferenceRelation::Unavailable,ModelSemanticState::Unresolved,false,0,"no exact native semantic reference exists for this runtime");
    }else if(!c.semantic_reference_status.empty()&&c.semantic_reference_status!="REFERENCE_MATCH"){
        push(facts,"cpython.native_semantic_reference","cpython.native_function_semantics",scoped_ref(c,"native function-semantic probe set"),c,ModelEvidenceLevel::ExactKnownGoodReference,
             ModelReferenceRelation::NotApplicable,ModelSemanticState::Unresolved,false,0,
             "native semantic reference exists but this build/observation is not comparable enough for a semantic conclusion");
    }

    // Plane 3: same-relative .text chunks.  This is code-image evidence, not a
    // claim about compiler output or frozen modules.
    if(c.text_reference_status=="MATCH"){
        push(facts,"cpython.text_reference","cpython.native_text",scoped_ref(c,"native .text layout"),c,ModelEvidenceLevel::ExactKnownGoodReference,
             ModelReferenceRelation::ExactMatch,ModelSemanticState::StockConfirmed,true,0,"bounded official .text reference matches the target .text scope");
    }else if(c.text_reference_status=="DIFF"){
        push(facts,"cpython.text_reference","cpython.native_text",scoped_ref(c,"native .text layout"),c,ModelEvidenceLevel::ExactKnownGoodReference,
             ModelReferenceRelation::ExactDifference,ModelSemanticState::ModifiedUnresolved,false,static_cast<std::uint32_t>(c.region_diffs.size()),
             "official .text reference differs; byte regions are localized but changed semantics are not reconstructed");
    }else if(c.text_reference_status=="NO_REFERENCE"){
        push(facts,"cpython.text_reference","cpython.native_text",scoped_ref(c,"native .text layout"),c,ModelEvidenceLevel::None,
             ModelReferenceRelation::Unavailable,ModelSemanticState::Unresolved,false,0,"no usable .text reference for this plane");
    }else if(!c.text_reference_status.empty()){
        push(facts,"cpython.text_reference","cpython.native_text",scoped_ref(c,"native .text layout"),c,ModelEvidenceLevel::ExactKnownGoodReference,
             ModelReferenceRelation::NotApplicable,ModelSemanticState::Unresolved,false,0,".text comparison was suppressed because the selected native reference is not comparable");
    }

    // Plane 4: opcode dispatch.  Only the existing validated normalization map
    // may upgrade an opcode permutation to exact bounded semantics.
    if(c.dispatch.attempted){
        const auto&s=c.dispatch.reference_status;
        if(s=="REFERENCE_MATCH"){
            push(facts,"cpython.opcode_dispatch","cpython.opcode_dispatch_semantics",scoped_ref(c,"opcode dispatch table"),c,ModelEvidenceLevel::ExactKnownGoodReference,
                 ModelReferenceRelation::ExactMatch,ModelSemanticState::StockConfirmed,true,0,"opcode dispatch mapping matches the exact official reference for the recovered table scope");
        }else if(s=="OPCODE_PERMUTATION"){
            auto map=cpython_validated_opcode_map(c);
            if(map){
                push(facts,"cpython.opcode_dispatch","cpython.opcode_dispatch_semantics",scoped_ref(c,"opcode dispatch table"),c,ModelEvidenceLevel::ExactKnownGoodReference,
                     ModelReferenceRelation::ExactDifference,ModelSemanticState::ExactDeltaRecovered,true,dispatch_exact_delta_count(c),
                     "strict recovered dispatch permutation provides an exact target-to-official opcode normalization for the recovered table");
            }else{
                push(facts,"cpython.opcode_dispatch","cpython.opcode_dispatch_semantics",scoped_ref(c,"opcode dispatch table"),c,ModelEvidenceLevel::ExactKnownGoodReference,
                     ModelReferenceRelation::ExactDifference,ModelSemanticState::ModifiedUnresolved,false,dispatch_change_count(c),
                     "opcode dispatch differs but no validated complete normalization map is available");
            }
        }else if(s=="HANDLER_MODIFIED"||s=="OPCODE_AND_HANDLER_MODIFIED"||s=="PARTIAL_OPCODE_MAPPING"){
            push(facts,"cpython.opcode_dispatch","cpython.opcode_dispatch_semantics",scoped_ref(c,"opcode dispatch table"),c,ModelEvidenceLevel::ExactKnownGoodReference,
                 ModelReferenceRelation::ExactDifference,ModelSemanticState::ModifiedUnresolved,false,dispatch_change_count(c),
                 "opcode dispatch/reference differences are proven, but handler or partial mapping semantics remain unresolved");
        }else if(s=="TABLE_RECOVERED_NO_REFERENCE"){
            push(facts,"cpython.opcode_dispatch","cpython.opcode_dispatch_semantics",scoped_ref(c,"opcode dispatch table"),c,ModelEvidenceLevel::None,
                 ModelReferenceRelation::Unavailable,ModelSemanticState::Unresolved,false,0,"dispatch table recovered but no exact opcode reference is available");
        }else if(!s.empty()){
            push(facts,"cpython.opcode_dispatch","cpython.opcode_dispatch_semantics",scoped_ref(c,"opcode dispatch table"),c,ModelEvidenceLevel::ExactKnownGoodReference,
                 ModelReferenceRelation::NotApplicable,ModelSemanticState::Unresolved,false,0,"opcode dispatch plane is not comparable enough for a stock/modified semantic conclusion");
        }
    }

    // Plane 5: target compiler probe.  This is explicitly a chosen-input
    // oracle; even an exact match is scoped to the probe output, never promoted
    // to native-runtime stock semantics.
    if(c.compiler_probe.attempted){
        const auto&s=c.compiler_probe.state;
        if(s=="REFERENCE_MATCH"){
            push(facts,"cpython.compiler_probe","cpython.compiler_probe_output",scoped_ref(c,"chosen compiler-probe corpus"),c,ModelEvidenceLevel::ChosenInputOracle,
                 ModelReferenceRelation::ExactMatch,ModelSemanticState::StockConfirmed,true,0,
                 "chosen compiler-probe code objects match the exact same-version reference outputs");
        }else if(s=="OPCODE_PERMUTATION_RECOVERED"&&c.compiler_probe.success){
            push(facts,"cpython.compiler_probe","cpython.compiler_probe_observed_opcode_semantics",scoped_ref(c,"chosen compiler-probe observed opcodes"),c,ModelEvidenceLevel::ChosenInputOracle,
                 ModelReferenceRelation::ExactDifference,ModelSemanticState::ExactDeltaRecovered,true,c.compiler_probe.changed_opcodes,
                 "strict chosen-input compiler oracle recovered a bijective target-to-official map for every opcode observed in the probe corpus");
        }else if(s=="COMPILER_DIFFERENT"){
            push(facts,"cpython.compiler_probe","cpython.compiler_probe_output",scoped_ref(c,"chosen compiler-probe corpus"),c,ModelEvidenceLevel::ChosenInputOracle,
                 ModelReferenceRelation::ExactDifference,ModelSemanticState::ModifiedUnresolved,false,0,
                 "chosen compiler-probe output differs from the exact reference outside the accepted strict permutation contract");
        }else if(s=="NO_REFERENCE"){
            push(facts,"cpython.compiler_probe","cpython.compiler_probe_output",scoped_ref(c,"chosen compiler-probe corpus"),c,ModelEvidenceLevel::None,
                 ModelReferenceRelation::Unavailable,ModelSemanticState::Unresolved,false,0,"no exact compiler-probe reference exists for the target version");
        }else{
            push(facts,"cpython.compiler_probe","cpython.compiler_probe_output",scoped_ref(c,"chosen compiler-probe corpus"),c,ModelEvidenceLevel::ChosenInputOracle,
                 ModelReferenceRelation::NotApplicable,ModelSemanticState::Unresolved,false,0,"compiler probe did not produce a validated semantic comparison");
        }
    }

    // Plane 6: frozen modules are assessed independently per module.  A
    // semantic hash match does not become an exact raw-reference match.
    if(frozen){
        for(const auto&t:frozen->tables)for(const auto&m:t.modules){
            ModelTrustFact f;f.plane="cpython.frozen_reference";f.semantic_scope=frozen_scope(t,m);f.reference_scope=m.reference_version.empty()?scoped_ref(c,"frozen module"):"CPython frozen "+m.reference_version+" "+t.export_name+":"+m.name;f.model_id=model_id(c);f.evidence=m.name;
            if(m.reference_state=="REFERENCE_MATCH"&&m.reference_match_mode=="EXACT"){
                f.evidence_level=ModelEvidenceLevel::ExactKnownGoodReference;f.reference_relation=ModelReferenceRelation::ExactMatch;f.semantic_state=ModelSemanticState::StockConfirmed;f.scope_complete=true;
            }else if(m.reference_state=="REFERENCE_MATCH"&&m.reference_match_mode=="SEMANTIC"){
                f.evidence_level=ModelEvidenceLevel::ExactKnownGoodReference;f.reference_relation=ModelReferenceRelation::SemanticMatch;f.semantic_state=ModelSemanticState::StockCompatiblePartial;
            }else if(m.reference_state=="REFERENCE_DIFF"){
                f.evidence_level=ModelEvidenceLevel::ExactKnownGoodReference;f.reference_relation=ModelReferenceRelation::ExactDifference;f.semantic_state=ModelSemanticState::ModifiedUnresolved;f.delta_items=1;
            }else if(m.reference_state=="NO_REFERENCE"){
                f.reference_relation=ModelReferenceRelation::Unavailable;f.semantic_state=ModelSemanticState::Unresolved;
            }else if(!m.reference_state.empty()){
                f.evidence_level=ModelEvidenceLevel::ExactKnownGoodReference;f.reference_relation=ModelReferenceRelation::NotApplicable;f.semantic_state=ModelSemanticState::Unresolved;
            }else continue;
            facts.push_back(std::move(f));
        }
    }
    return build_model_trust_report(std::move(facts));
}
}
