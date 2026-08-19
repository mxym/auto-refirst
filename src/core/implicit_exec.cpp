#include "prts/implicit_exec.hpp"

#include <fstream>
#include <map>
#include <sstream>

namespace prts {
namespace {
std::string csvq(const std::string& s) {
    std::string out(1, '"');
    for (const auto c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += '"';
    return out;
}
}

ImplicitExecutionInfo merge_implicit_execution(const std::vector<ImplicitExecutionPlaneRef>&planes){
    ImplicitExecutionInfo out;bool saw_partial=false,saw_failed=false,saw_unsupported=false;
    std::size_t total_facts=0,active_planes=0;
    for(const auto&p:planes)if(p.info&&p.info->state!="NOT_PRESENT"){total_facts+=p.info->facts.size();++active_planes;}
    out.facts.reserve_shared_view(total_facts,active_planes);
    auto append_error=[&](const std::string&source,const std::string&error){if(error.empty())return;if(!out.error.empty())out.error+="; ";out.error+=(source.empty()?std::string("implicit"):source)+": "+error;};
    for(const auto&p:planes){
        if(!p.info||p.info->state=="NOT_PRESENT")continue;
        const auto&in=*p.info;
        out.analysis_limited=out.analysis_limited||in.analysis_limited;
        out.deterministic_effect_count+=in.deterministic_effect_count;out.raw_loader_symbol_count+=in.raw_loader_symbol_count;
        if(in.state!="RESOLVED"){
            if(in.state=="PARTIAL")saw_partial=true;
            else if(in.state=="FAILED")saw_failed=true;
            else if(in.state=="UNSUPPORTED")saw_unsupported=true;
            else if(!in.state.empty())saw_partial=true;
        }
        append_error(p.source,in.error);
        const auto base=static_cast<std::uint32_t>(out.facts.size());std::map<std::uint32_t,std::uint32_t>remap;bool duplicate=false;
        for(std::size_t i=0;i<in.facts.size();++i){
            const auto ni=base+static_cast<std::uint32_t>(i);
            if(!remap.emplace(in.fact_index(i),ni).second)duplicate=true;
        }
        if(duplicate){saw_partial=true;append_error(p.source,"duplicate local fact index");}
        std::vector<std::int64_t>dependencies;dependencies.reserve(in.facts.size());
        for(std::size_t i=0;i<in.facts.size();++i){
            const auto&fact=in.facts[i];std::int64_t dependency=-1;
            const auto local_dependency=in.fact_dependency(i);
            if(local_dependency>=0){
                const auto it=remap.find(static_cast<std::uint32_t>(local_dependency));
                if(it!=remap.end())dependency=it->second;
                else{saw_partial=true;append_error(p.source,"missing dependency fact index "+std::to_string(local_dependency));}
            }
            dependencies.push_back(dependency);
            if(fact.priority=="HIGH")++out.high_priority_count;else if(fact.priority=="REVIEW")++out.review_count;else ++out.informational_count;
            if(!fact.anomaly_class.empty()&&fact.anomaly_class!="NONE")++out.anomaly_count;
            if(fact.evidence_state=="UNRESOLVED_RUNTIME_SEMANTICS")++out.unresolved_runtime_semantics;
        }
        out.facts.append_shared_view(in.facts,dependencies);
    }
    if(!out.facts.empty())out.state=(saw_partial||saw_failed||saw_unsupported||out.analysis_limited)?"PARTIAL":"RESOLVED";
    else if(saw_failed)out.state="FAILED";else if(saw_partial)out.state="PARTIAL";else if(saw_unsupported)out.state="UNSUPPORTED";else out.state="NOT_PRESENT";
    return out;
}

ImplicitExecutionExtractResult extract_implicit_execution(
    const ImplicitExecutionInfo& info,
    const std::filesystem::path& csv) {
    ImplicitExecutionExtractResult out;
    if (info.state == "NOT_PRESENT") {
        out.error = "implicit execution plane is not present";
        return out;
    }
    std::ofstream f(csv, std::ios::binary | std::ios::trunc);
    if (!f) {
        out.error = "cannot create implicit execution CSV";
        return out;
    }
    f << "fact_index,depends_on_fact_index,format,ecosystem,phase,trigger,relation,source_kind,source_index,"
         "source_file_backed,source_file_offset,source_va,source_size,target_kind,target_va,target_file_backed,"
         "target_file_offset,target_token,target_function_index,target_name,evidence_state,mutability,"
         "execution_condition,anomaly_class,priority,priority_reason,detail\n";
    for (std::size_t i=0;i<info.facts.size();++i) {
        const auto& x=info.facts[i];
        f << info.fact_index(i) << ',';
        const auto dependency=info.fact_dependency(i);
        if (dependency >= 0) f << dependency;
        f << ',' << csvq(x.format) << ',' << csvq(x.ecosystem) << ',' << csvq(x.phase) << ','
          << csvq(x.trigger) << ',' << csvq(x.relation) << ',' << csvq(x.source_kind) << ',' << x.source_index << ','
          << (x.source_file_backed ? 1 : 0) << ',';
        if (x.source_file_backed) f << "0x" << std::hex << x.source_file_offset << std::dec;
        f << ',';
        if (x.source_va) f << "0x" << std::hex << x.source_va << std::dec;
        f << ',' << x.source_size << ',' << csvq(x.target_kind) << ',';
        if (x.target_va) f << "0x" << std::hex << x.target_va << std::dec;
        f << ',' << (x.target_file_backed ? 1 : 0) << ',';
        if (x.target_file_backed) f << "0x" << std::hex << x.target_file_offset << std::dec;
        f << ',';
        if (x.target_token) f << "0x" << std::hex << x.target_token << std::dec;
        f << ',' << x.target_function_index << ',' << csvq(x.target_name) << ','
          << csvq(x.evidence_state) << ',' << csvq(x.mutability) << ','
          << csvq(x.execution_condition) << ',' << csvq(x.anomaly_class) << ','
          << csvq(x.priority) << ',' << csvq(x.priority_reason) << ',' << csvq(x.detail) << "\n";
    }
    f.close();
    if (!f) {
        out.error = "write implicit execution CSV failed";
        std::error_code ec;
        std::filesystem::remove(csv, ec);
        return out;
    }
    out.success = true;
    out.csv = csv;
    out.fact_count = info.facts.size();
    return out;
}
} // namespace prts
