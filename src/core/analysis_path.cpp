#include "prts/analysis_path.hpp"
#include "prts/report.hpp"
#include <algorithm>
#include <iomanip>
#include <set>
#include <sstream>
#include <tuple>

namespace prts { namespace {
std::string hex32(std::uint32_t v){std::ostringstream o;o<<"0x"<<std::hex<<v;return o.str();}
std::string fmt3(double v){std::ostringstream o;o<<std::fixed<<std::setprecision(3)<<v;return o.str();}
int runtime_score(const CPythonInfo& c){
    if(c.semantic_reference_status=="COMPARABLE"){
        bool diff=false;
        for(const auto&f:c.function_diffs)if(f.state=="MODIFIED_CANDIDATE")diff=true;
        if(!c.region_diffs.empty())diff=true;
        return diff?50:30;
    }
    if(c.semantic_reference_status=="BUILD_INCOMPARABLE")return 40;
    if(c.reference_status=="DIFFERS_FROM_OFFICIAL_REFERENCE")return 35;
    if(c.reference_status=="REFERENCE_MATCH")return 10;
    return 20;
}
void add_unique_range(Finding&f,std::set<std::tuple<std::uint64_t,std::uint64_t,std::string>>&seen,std::uint64_t rva,std::uint64_t size,std::string label,CoordinateBasis basis,const std::string&artifact_identity){
    if(!size)return;
    auto key=std::make_tuple(rva,size,label);
    if(seen.insert(key).second)f.ranges.push_back(rva_range(rva,size,std::move(label),basis,artifact_identity));
}
void add_guidance(std::vector<std::string>&out,std::set<std::string>&seen,std::string value,std::size_t cap=8){if(value.empty()||out.size()>=cap||!seen.insert(value).second)return;out.push_back(std::move(value));}
std::string event_field(const TimelineEvent&e,const char*key){auto it=e.fields.find(key);return it==e.fields.end()?std::string{}:it->second;}
std::string implicit_target(const ImplicitExecutionFact&f){if(!f.target_name.empty())return f.target_name;if(f.target_va){std::ostringstream o;o<<"VA 0x"<<std::hex<<f.target_va;return o.str();}if(f.target_token){std::ostringstream o;o<<"token 0x"<<std::hex<<f.target_token;return o.str();}if(f.target_function_index)return "function #"+std::to_string(f.target_function_index);return f.target_kind;}
}

std::optional<Finding> build_pyinstaller_cpython_path(const AnalysisReport& r){
    if(!r.pyinstaller.valid||r.pyinstaller.bootstrap_reference_status!="REFERENCE_MATCH"||r.cpython_runtimes.empty())return std::nullopt;
    Finding f;f.kind="analysis_path";f.family="PyInstaller -> CPython";f.state="CONFIRMED";f.variant=r.pyinstaller.bootstrap_reference_label;
    f.fields["bootstrap_reference"]=r.pyinstaller.bootstrap_reference_label;
    f.fields["bootstrap_match_mode"]=r.pyinstaller.bootstrap_match_mode;
    f.fields["bootstrap_hypothesis"]="ELIMINATED";
    f.fields["cpython_runtime_count"]=std::to_string(r.cpython_runtimes.size());
    int owned=0,all=0;bool struct_match=false;
    for(const auto&m:r.pyinstaller.bootstrap_modules){
        const bool matched=m.state=="EXACT_MATCH"||m.state=="SEMANTIC_MATCH"||m.state=="OPCODE_NORMALIZED_SEMANTIC_MATCH";
        if(matched)++all;
        if(m.name=="struct")struct_match=matched;
        else if(m.name=="pyimod01_archive"||m.name=="pyimod02_importers"||m.name=="pyimod03_ctypes"||m.name=="pyimod04_pywin32")owned+=matched?1:0;
    }
    f.fields["pyinstaller_loader_modules_matched"]=std::to_string(owned)+"/4";
    f.fields["preload_modules_matched"]=std::to_string(all)+"/5";
    f.evidence.push_back("all four PyInstaller-owned preload modules match one official loader generation");
    if(struct_match)f.evidence.push_back("stdlib bootstrap module struct also matches the known reference payload");
    f.evidence.push_back("bootstrap-loader modification hypothesis is eliminated by reference validation");

    const CPythonInfo* best=&r.cpython_runtimes.front();
    for(const auto&c:r.cpython_runtimes)if(runtime_score(c)>runtime_score(*best))best=&c;
    std::set<std::tuple<std::uint64_t,std::uint64_t,std::string>> seen;
    const auto&c=*best;
    const bool embedded_artifact=c.source.rfind("CArchive:",0)==0;
    const auto cp_basis=embedded_artifact?CoordinateBasis::ARTIFACT_IMAGE:CoordinateBasis::CURRENT_INPUT_IMAGE;
    const auto cp_identity=embedded_artifact?c.source:std::string{};
    auto add_cp_range=[&](std::uint64_t rva,std::uint64_t size,std::string label){add_unique_range(f,seen,rva,size,std::move(label),cp_basis,cp_identity);};
    f.fields["cpython_source"]=c.source;
    f.fields["cpython_version"]=c.version;
    f.fields["cpython_reference_status"]=c.reference_status;
    f.fields["cpython_semantic_status"]=c.semantic_reference_status;
    if(c.semantic_probe_count)f.fields["cpython_semantic_probe_median"]=fmt3(c.semantic_probe_median);
    if(c.compiler_probe.attempted){f.fields["cpython_compiler_probe_state"]=c.compiler_probe.state;f.fields["cpython_compiler_probe_observed_opcodes"]=std::to_string(c.compiler_probe.observed_opcodes);f.fields["cpython_compiler_probe_changed_opcodes"]=std::to_string(c.compiler_probe.changed_opcodes);}
    const bool compiler_permutation=c.compiler_probe.success&&c.compiler_probe.state=="OPCODE_PERMUTATION_RECOVERED";
    const bool compiler_match=c.compiler_probe.success&&c.compiler_probe.state=="REFERENCE_MATCH";

    if(c.reference_status=="REFERENCE_MATCH"){
        f.fields["next_priority"]="PyInstaller archive/user-code payload";
        f.evidence.push_back("selected CPython runtime exactly matches the official same-version reference");
        f.suggested_actions.push_back("prioritize entry script/PYZ/user modules because both bootstrap loader and CPython runtime match references");
        return f;
    }

    if(c.semantic_reference_status=="BUILD_INCOMPARABLE"){
        if(compiler_permutation){
            f.fields["next_priority"]="CPython compiler opcode mapping / extracted bytecode";
            f.evidence.push_back("native CPython build lineage is not comparable to python.org, but the target compiler probe recovered a strict opcode permutation with identical code-object shape and opargs");
            for(const auto&m:c.compiler_probe.mappings)if(m.target_opcode!=m.reference_opcode)f.evidence.push_back("compiler opcode "+std::to_string(m.target_opcode)+" -> official "+std::to_string(m.reference_opcode)+" observations="+std::to_string(m.observations));
            f.suggested_actions.push_back("normalize only bytecode whose used opcodes are covered by the compiler-probe mapping; leave unmapped opcodes untouched/refused");
        }else if(compiler_match){
            f.fields["next_priority"]="native CPython build lineage; compiler bytecode is reference-matched";
            f.evidence.push_back("dynamic compiler probe matches the official same-version bytecode exactly despite the native DLL being build-incomparable");
            f.suggested_actions.push_back("deprioritize compiler/opcode mutation and resolve vendor/native build lineage only if native code remains relevant");
        }else{
            f.fields["next_priority"]="identify exact CPython distribution/build lineage";
            f.suggested_actions.push_back("match the runtime against a sibling/vendor/PyInstaller distribution build before interpreting native differences");
            f.suggested_actions.push_back("if no sibling reference exists, use --run=python-probe to test compiler bytecode without relying on native layout");
        }
        f.negative_evidence.push_back("CPython DLL differs structurally from python.org, but native semantic probes show that this build lineage is not comparable to the python.org reference");
        f.negative_evidence.push_back("function/region differences are therefore not labeled as challenge modifications");
        return f;
    }

    if(c.semantic_reference_status=="COMPARABLE"){
        const bool dispatch_actionable=c.dispatch.reference_status=="OPCODE_PERMUTATION"||c.dispatch.reference_status=="HANDLER_MODIFIED"||c.dispatch.reference_status=="OPCODE_AND_HANDLER_MODIFIED"||c.dispatch.reference_status=="PARTIAL_OPCODE_MAPPING";
        const bool opcode_actionable=dispatch_actionable||compiler_permutation;
        if(c.dispatch.table_found){f.fields["cpython_dispatch_status"]=c.dispatch.reference_status;f.fields["opcode_permuted_slots"]=std::to_string(c.dispatch.permuted_slots);f.fields["opcode_handler_modified"]=std::to_string(c.dispatch.handler_modified);}
        if(dispatch_actionable){
            std::ostringstream de;de<<"CPython opcode dispatch differs from the comparable official reference: "<<c.dispatch.reference_status<<" (permuted="<<c.dispatch.permuted_slots<<", handler_modified="<<c.dispatch.handler_modified<<")";f.evidence.push_back(de.str());
            if(c.dispatch.permuted_slots&&c.dispatch.table_rva)add_cp_range(c.dispatch.table_rva,std::uint64_t(c.dispatch.table_entry_count)*4,"CPython opcode dispatch table");
            for(const auto&m:c.dispatch.mappings){if(m.state=="SLOT_MATCH")continue;std::ostringstream x;x<<"opcode "<<m.target_opcode<<" "<<m.state;if(!m.reference_names.empty()){x<<" -> official ";for(std::size_t z=0;z<m.reference_names.size();++z){if(z)x<<'|';x<<m.reference_opcodes[z]<<':'<<m.reference_names[z];}}f.evidence.push_back(x.str());if(m.state.find("HANDLER_MODIFIED")!=std::string::npos)add_cp_range(m.target_handler_rva,0x40,"CPython opcode handler modified candidate");}
        }
        std::size_t modified=0,new_regions=0;
        for(const auto&fd:c.function_diffs){
            if(fd.state!="MODIFIED_CANDIDATE")continue;
            ++modified;
            f.evidence.push_back(fd.name+" differs from the comparable official native-function reference (coverage "+fmt3(fd.reference_coverage)+")");
            for(const auto&rg:fd.changed_ranges)add_cp_range(rg.offset,rg.size,"CPython function diff: "+fd.name);
        }
        for(const auto&rg:c.region_diffs){
            if(rg.kind=="NEW_EXECUTABLE_TAIL"||rg.kind=="NEW_EXECUTABLE_SECTION")++new_regions;
            add_cp_range(rg.rva,rg.size,"CPython "+rg.kind+" "+rg.section);
        }
        for(const auto&x:c.new_region_xrefs)add_cp_range(x.source_rva,x.size,"incoming "+x.kind+" to new CPython executable region -> "+hex32(x.target_rva));
        f.fields["modified_function_candidates"]=std::to_string(modified);
        f.fields["new_executable_regions"]=std::to_string(new_regions);
        f.fields["incoming_refs_to_new_regions"]=std::to_string(c.new_region_xrefs.size());
        if(opcode_actionable){
            f.fields["next_priority"]=dispatch_actionable?"CPython opcode dispatch / handler mutation":"CPython compiler opcode mapping / extracted bytecode";
            f.suggested_actions.push_back("use the recovered opcode mapping before decompiling extracted .pyc/PYZ code; refuse normalization for any used opcode not covered by a validated mapping");
        }else if(modified||!c.region_diffs.empty()){
            f.fields["next_priority"]="CPython/native mutation ranges";
            f.evidence.push_back("same-version CPython build is semantically comparable, so the listed native differences are actionable mutation candidates");
            f.suggested_actions.push_back("start reverse engineering at the listed modified-function/new-executable/incoming-xref ranges");
        }else{
            f.fields["next_priority"]="PyInstaller archive/user-code payload";
            f.evidence.push_back("CPython build differs at file level but comparable native probes/regions/dispatch did not identify an actionable mutation");
            f.suggested_actions.push_back("continue with entry script/PYZ/user modules while retaining CPython structural differences as secondary evidence");
        }
        return f;
    }

    if(c.reference_status=="DIFFERS_FROM_OFFICIAL_REFERENCE"){
        f.fields["next_priority"]="CPython/native runtime reference resolution";
        f.negative_evidence.push_back("CPython differs from an official same-version reference, but semantic comparability was not established");
        f.suggested_actions.push_back("resolve a closer runtime reference before treating section/export deltas as challenge modifications");
    }else{
        f.fields["next_priority"]="resolve exact CPython reference";
        f.negative_evidence.push_back("no exact official CPython reference is available for the selected runtime");
    }
    return f;
}

AnalysisGuidance build_analysis_guidance(const AnalysisReport&r){
    AnalysisGuidance g;
    if(!r.analysis_guidance.runtime_modality.requirements.empty())g.runtime_modality=r.analysis_guidance.runtime_modality;
    else g.runtime_modality=build_runtime_modality_guidance(r);
    std::set<std::string> contradiction_seen,alternate_seen,unresolved_seen,priority_seen;
    unresolved_seen.insert(g.unresolved_alternatives.front());
    for(const auto&x:g.runtime_modality.priority_guidance)add_guidance(g.priority_reasons,priority_seen,x);
    bool runtime_strong=false,implicit_strong=false,frozen_strong=false,static_surface=false,static_surface_high=false,interpreter_boundary=false;

    for(const auto&e:r.runtime.timeline){
        if(e.kind==TimelineKind::PreEntryExecute){
            ++g.runtime_pre_entry_count;runtime_strong=true;
            std::ostringstream q;q<<"confirmed runtime pre-entry execution occurred in process "<<e.process_uid;
            if(!e.subject.empty())q<<" at "<<e.subject;
            add_guidance(g.contradictory_evidence,contradiction_seen,q.str());
            add_guidance(g.alternate_execution_paths,alternate_seen,"runtime pre-entry execution -> "+(e.subject.empty()?std::string("loader/pre-entry target"):e.subject));
        }
        if(e.kind!=TimelineKind::MaterializedExecute||event_field(e,"phase")!="execute")continue;
        ++g.runtime_first_exec_count;runtime_strong=true;
        const auto transition=event_field(e,"transition"),relation=event_field(e,"image_relation");
        std::string q="confirmed first execution of materialized code";
        if(!transition.empty())q+=" transition="+transition;
        if(!relation.empty())q+=" image_relation="+relation;
        if(!e.subject.empty())q+=" at "+e.subject;
        add_guidance(g.contradictory_evidence,contradiction_seen,q);
        add_guidance(g.alternate_execution_paths,alternate_seen,"runtime materialization -> first execution"+(transition.empty()?std::string{}:" ("+transition+")"));
    }

    for(const auto&f:r.implicit_exec.facts){
        if(f.priority!="HIGH")continue;
        ++g.high_implicit_count;implicit_strong=true;
        std::ostringstream q;q<<"HIGH implicit execution fact #"<<f.index<<" "<<f.format<<" "<<f.phase<<" "<<f.trigger;
        if(!f.anomaly_class.empty()&&f.anomaly_class!="NONE")q<<" anomaly="<<f.anomaly_class;
        add_guidance(g.contradictory_evidence,contradiction_seen,q.str());
        auto target=implicit_target(f);std::string path=f.format+" "+f.phase+" "+f.trigger;if(!target.empty())path+=" -> "+target;
        add_guidance(g.alternate_execution_paths,alternate_seen,std::move(path));
        if(!f.priority_reason.empty())add_guidance(g.priority_reasons,priority_seen,f.priority_reason);
    }
    if(r.implicit_exec.unresolved_runtime_semantics){
        add_guidance(g.unresolved_alternatives,unresolved_seen,std::to_string(r.implicit_exec.unresolved_runtime_semantics)+" implicit execution fact(s) retain unresolved runtime semantics; static analysis did not execute them");
    }

    for(const auto&f:r.findings){
        if(f.family!="Exceptional execution surface")continue;
        const auto si=f.fields.find("surface_state");if(si==f.fields.end()||(si->second!="REVIEW_ALTERNATE_SURFACE"&&si->second!="HIGH_ALTERNATE_SURFACE"))continue;
        static_surface=true;static_surface_high=static_surface_high||si->second=="HIGH_ALTERNATE_SURFACE";
        add_guidance(g.contradictory_evidence,contradiction_seen,si->second+" "+f.variant+" contradicts treating declared entry/main as the complete execution model");
        add_guidance(g.alternate_execution_paths,alternate_seen,"static exceptional surface -> "+f.variant+" ["+si->second+"]");
        for(const auto&q:f.evidence)add_guidance(g.priority_reasons,priority_seen,q);
        const auto sem=f.fields.find("semantic_state");if(sem!=f.fields.end()&&(sem->second.rfind("UNRESOLVED_",0)==0||sem->second.rfind("REQUIRES_",0)==0))add_guidance(g.unresolved_alternatives,unresolved_seen,f.variant+": "+sem->second+"; static composition does not execute the missing semantics");
    }

    if(r.interpreter_boundary.state=="CONFIRMED") {
        interpreter_boundary=true;
        const auto& b=r.interpreter_boundary;
        std::string family=b.runtime_family.empty()?b.boundary_kind:(b.runtime_family+" runtime");
        add_guidance(g.priority_reasons,priority_seen,"confirmed interpreter/program boundary ("+family+"): stop treating the host declared entry as the final reverse-analysis target; recover/define interpreter opcode/state semantics and analyze the program payload");
        add_guidance(g.unresolved_alternatives,unresolved_seen,"interpreter identity does not mean VM semantics are solved; "+b.semantic_requirement+" remains a manual/static semantic requirement");
        if(!b.exact_program_target_bound) {
            if(b.external_program_argument_required)add_guidance(g.unresolved_alternatives,unresolved_seen,"the host requires an external program argument, but the runtime argv value is statically unknown; sibling endpoint selection remains unresolved");
            else if(!b.exact_program_target_state.empty())add_guidance(g.unresolved_alternatives,unresolved_seen,"interpreter/runtime family is recognized, but the concrete program/image endpoint remains "+b.exact_program_target_state);
        }
    }

    for(const auto&f:r.findings){
        if(f.family=="CPython bytecode"&&f.state=="CONFIRMED"){
            auto v=f.fields.find("version_family");
            add_guidance(g.priority_reasons,priority_seen,"authenticated direct CPython "+(v==f.fields.end()?std::string("bytecode"):v->second+" bytecode")+" is the decisive reverse-analysis surface; use its bounded code-object map before generic native/runtime hypotheses");
        }else if(f.family=="CPython marshal ingress"&&(f.state=="CONFIRMED"||f.state=="LIKELY")){
            auto rel=f.fields.find("payload_relation_state"),runtime=f.fields.find("runtime_payload_relation");
            if(rel!=f.fields.end()&&rel->second=="SOURCE_TO_MARSHAL_LOADS_CONFIRMED")add_guidance(g.priority_reasons,priority_seen,"follow the statically bound source/transform -> marshal.loads payload path before generic CPython-family speculation");
            if(runtime!=f.fields.end()&&runtime->second=="REQUIRES_NATIVE_RUNTIME_BYTECODE_OBSERVATION")add_guidance(g.unresolved_alternatives,unresolved_seen,"marshal payload ingress is statically bound, but concrete bytecode/runtime semantics require native observation at the marshal boundary; auto-refirst does not patch or execute arbitrary marshal data");
        }
    }

    if(r.cpython_static.frozen_reference_gate.allowed&&r.cpython_static.priority.preferred_target=="FROZEN_REFERENCE_DIFF"&&r.cpython_static.priority.mismatch_count){
        g.frozen_reference_diff_count=r.cpython_static.priority.mismatch_count;frozen_strong=true;
        add_guidance(g.contradictory_evidence,contradiction_seen,"comparable same-version CPython frozen-module reference differs in "+std::to_string(g.frozen_reference_diff_count)+" module(s)");
        for(const auto&c:r.cpython_static.priority.candidates){
            add_guidance(g.priority_reasons,priority_seen,"modified comparable frozen module "+c.module+" is an evidence-backed reverse priority");
        }
    }

    if(runtime_strong){
        g.declared_entry_default=false;g.decoy_risk="HIGH";
        g.visible_hypothesis="declared entry remains visible but is not the sole/default execution hypothesis because alternate execution was confirmed at runtime";
        add_guidance(g.priority_reasons,priority_seen,"inspect confirmed pre-entry/materialized first-execution paths before committing to declared entry/main");
    }else if(implicit_strong){
        g.declared_entry_default=false;g.decoy_risk="REVIEW";
        g.visible_hypothesis="declared entry remains visible but is not the sole/default execution hypothesis because HIGH implicit loader/runtime evidence exists";
        add_guidance(g.priority_reasons,priority_seen,"inspect HIGH implicit loader/runtime semantics before committing to declared entry/main");
    }else if(static_surface){
        g.declared_entry_default=false;g.decoy_risk=static_surface_high?"HIGH":"REVIEW";
        g.visible_hypothesis="declared entry remains visible but is not the sole/default execution hypothesis because a bounded static exceptional surface was composed from independent evidence planes";
        add_guidance(g.priority_reasons,priority_seen,"inspect the composed exceptional execution surface before committing to declared entry/main; runtime confirmation, if needed, belongs to the runtime evidence plane");
    }else if(frozen_strong){
        g.decoy_risk="REVIEW";
        g.visible_hypothesis="declared entry remains the default execution hypothesis, but a comparable frozen-module difference is a higher static reverse priority";
    }else if(interpreter_boundary){
        // AW changes the semantic/preprocessing target, not the execution-entry fact.
        // Keeping declared_entry_default=true avoids calling a real host entry a decoy.
        g.visible_hypothesis="declared entry remains the host execution root, but the confirmed interpreter boundary makes the interpreted program/image plus interpreter semantics the decisive reverse-analysis surface";
    }
    return g;
}
}
