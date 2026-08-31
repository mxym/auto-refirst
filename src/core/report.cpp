#include "prts/report.hpp"
#include "prts/path_utf8.hpp"
#include "prts/report_schema.hpp"
#include <iomanip>
#include <limits>
#include <sstream>

namespace prts {

const char* timeline_kind_name(TimelineKind k) {
    switch (k) {
        case TimelineKind::ProcessStart: return "process_start";
        case TimelineKind::ProcessExit: return "process_exit";
        case TimelineKind::ModuleLoad: return "module_load";
        case TimelineKind::ModuleUnload: return "module_unload";
        case TimelineKind::FileCreate: return "file_create";
        case TimelineKind::FileOpen: return "file_open";
        case TimelineKind::FileWrite: return "file_write";
        case TimelineKind::FileRename: return "file_rename";
        case TimelineKind::FileDelete: return "file_delete";
        case TimelineKind::MemoryAllocate: return "memory_allocate";
        case TimelineKind::MemoryProtect: return "memory_protect";
        case TimelineKind::MemoryWrite: return "memory_write";
        case TimelineKind::MaterializedExecute: return "materialized_execute";
        case TimelineKind::PreEntryExecute: return "pre_entry_execute";
        case TimelineKind::OepCandidate: return "oep_candidate";
        case TimelineKind::DumpCreated: return "dump_created";
        case TimelineKind::ConsoleStdout: return "stdout";
        case TimelineKind::ConsoleStderr: return "stderr";
    }
    return "unknown";
}

namespace {
std::vector<const GDExtensionLibraryMatchInfo*> gdextension_render_libraries(const GDExtensionBundleInfo& b,std::size_t cap){std::vector<const GDExtensionLibraryMatchInfo*>out;out.reserve(std::min(cap,b.libraries.size()));for(const auto&l:b.libraries)if((l.exact_path_match||l.native_analyzed)&&out.size()<cap)out.push_back(&l);for(const auto&l:b.libraries)if(!l.exact_path_match&&!l.native_analyzed&&out.size()<cap)out.push_back(&l);return out;}
std::string esc(const std::string& s) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string o;
    o.reserve(s.size());
    auto escape_byte = [&](unsigned char c) {
        o += "\\u00";
        o += hex[(c >> 4) & 0x0f];
        o += hex[c & 0x0f];
    };
    auto continuation = [&](std::size_t i) {
        return i < s.size() && (static_cast<unsigned char>(s[i]) & 0xc0u) == 0x80u;
    };
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        switch (c) {
            case '\\': o += "\\\\"; ++i; continue;
            case '"': o += "\\\""; ++i; continue;
            case '\b': o += "\\b"; ++i; continue;
            case '\f': o += "\\f"; ++i; continue;
            case '\n': o += "\\n"; ++i; continue;
            case '\r': o += "\\r"; ++i; continue;
            case '\t': o += "\\t"; ++i; continue;
            default: break;
        }
        if (c < 0x20u) {
            escape_byte(c);
            ++i;
            continue;
        }
        if (c < 0x80u) {
            o += static_cast<char>(c);
            ++i;
            continue;
        }

        // Preserve valid UTF-8 verbatim. Binary-derived strings can also contain
        // arbitrary high bytes; encode those byte values as U+00XX so the report
        // remains valid UTF-8 JSON instead of emitting malformed text.
        std::size_t n = 0;
        if (c >= 0xc2u && c <= 0xdfu) n = 2;
        else if (c >= 0xe0u && c <= 0xefu) n = 3;
        else if (c >= 0xf0u && c <= 0xf4u) n = 4;
        bool valid = n != 0 && i + n <= s.size();
        for (std::size_t z = 1; valid && z < n; ++z) valid = continuation(i + z);
        if (valid && n == 3) {
            const auto c1 = static_cast<unsigned char>(s[i + 1]);
            if ((c == 0xe0u && c1 < 0xa0u) || (c == 0xedu && c1 >= 0xa0u)) valid = false;
        } else if (valid && n == 4) {
            const auto c1 = static_cast<unsigned char>(s[i + 1]);
            if ((c == 0xf0u && c1 < 0x90u) || (c == 0xf4u && c1 >= 0x90u)) valid = false;
        }
        if (!valid) {
            escape_byte(c);
            ++i;
            continue;
        }
        o.append(s, i, n);
        i += n;
    }
    return o;
}

struct RenderedRangeProvenance {
    std::string coordinate_space;
    std::string basis;
    std::string artifact_identity;
    std::optional<std::uint64_t> process_uid;
    std::optional<std::uint64_t> image_base;
};

RenderedRangeProvenance resolve_range_provenance(const AnalysisReport& report,const RangeRef& range,const RuntimeArtifact* runtime_artifact=nullptr) {
    RenderedRangeProvenance out;
    out.coordinate_space=coordinate_space_name(range.coordinate_space);
    out.basis=coordinate_basis_name(range.basis);
    out.artifact_identity=range.artifact_identity;
    out.process_uid=range.process_uid;
    out.image_base=range.image_base;
    // Only resolve identity from an explicit basis. UNKNOWN never inherits a path.
    if(out.artifact_identity.empty()&&(range.basis==CoordinateBasis::CURRENT_INPUT_FILE||range.basis==CoordinateBasis::CURRENT_INPUT_IMAGE))
        out.artifact_identity=path_utf8(report.artifact.offset_basis.empty()?report.input:report.artifact.offset_basis);
    if(runtime_artifact){
        if(out.artifact_identity.empty()&&(range.basis==CoordinateBasis::ARTIFACT_FILE||range.basis==CoordinateBasis::ARTIFACT_IMAGE))
            out.artifact_identity=path_utf8(runtime_artifact->path);
        if(!out.process_uid&&(range.basis==CoordinateBasis::ARTIFACT_FILE||range.basis==CoordinateBasis::ARTIFACT_IMAGE||range.basis==CoordinateBasis::PROCESS_IMAGE||range.basis==CoordinateBasis::MEMORY_REGION))
            out.process_uid=runtime_artifact->process_uid;
    }
    return out;
}

void render_range_text(std::ostringstream& o,const AnalysisReport& report,const RangeRef& range,const char* prefix,const RuntimeArtifact* runtime_artifact=nullptr) {
    const auto p=resolve_range_provenance(report,range,runtime_artifact);
    o<<prefix<<"coordinate_space="<<p.coordinate_space<<" value=0x"<<std::hex<<range.offset<<std::dec
     <<" size="<<range.size<<" basis="<<p.basis;
    if(!p.artifact_identity.empty())o<<" artifact="<<p.artifact_identity;
    if(p.process_uid)o<<" process_uid="<<*p.process_uid;
    if(p.image_base)o<<" image_base=0x"<<std::hex<<*p.image_base<<std::dec;
    if(!range.label.empty())o<<" label="<<range.label;
    o<<"\n";
}

void render_range_json(std::ostream& o,const AnalysisReport& report,const RangeRef& range,const RuntimeArtifact* runtime_artifact=nullptr) {
    const auto p=resolve_range_provenance(report,range,runtime_artifact);
    // offset is retained as a compatibility alias; value + coordinate_space is the typed contract.
    o<<"{\"offset\":"<<range.offset<<",\"value\":"<<range.offset<<",\"size\":"<<range.size
     <<",\"coordinate_space\":\""<<p.coordinate_space<<"\",\"basis\":\""<<esc(p.basis)<<"\""
     <<",\"artifact_identity\":\""<<esc(p.artifact_identity)<<"\"";
    if(p.process_uid)o<<",\"process_uid\":"<<*p.process_uid;
    if(p.image_base)o<<",\"image_base\":"<<*p.image_base;
    o<<",\"label\":\""<<esc(range.label)<<"\"}";
}

std::string changed(const RuntimeReport& r) {
    if (!r.requested) return "not_run";
    if (!r.before.exists && !r.after.exists) return "missing_before_and_after";
    if (r.before.exists && !r.after.exists) return "deleted";
    if (!r.before.exists && r.after.exists) return "created";
    return (r.before.size != r.after.size || r.before.sha256 != r.after.sha256)
        ? "changed" : "unchanged";
}

bool timestamp_changed(const RuntimeReport& r) {
    if (!r.before.write_time || !r.after.write_time) return false;
    return *r.before.write_time != *r.after.write_time;
}

std::string perms(std::uint32_t c) {
    std::string p;
    p += (c & 0x40000000) ? 'R' : '-';
    p += (c & 0x80000000) ? 'W' : '-';
    p += (c & 0x20000000) ? 'X' : '-';
    return p;
}

std::vector<const ApkEntryInfo*> apk_render_entries(const ApkInfo& apk,std::size_t cap) {
    std::vector<const ApkEntryInfo*> out;
    out.reserve(std::min(cap,apk.entries.size()));
    std::vector<bool> used(apk.entries.size(),false);
    auto add=[&](auto pred,std::size_t limit){
        std::size_t added=0;
        for(std::size_t i=0;i<apk.entries.size()&&out.size()<cap&&added<limit;++i){
            if(used[i]||!pred(apk.entries[i]))continue;
            used[i]=true;out.push_back(&apk.entries[i]);++added;
        }
    };
    // Category quotas prevent a large early resource directory from hiding the structural
    // entries that most directly change downstream analysis. These are renderer priorities,
    // not parser/detector confidence changes.
    add([](const auto&e){return e.manifest;},4);
    add([](const auto&e){return e.hermes_magic;},32);
    add([](const auto&e){return e.native_elf&&e.jni_onload_export;},16);
    add([](const auto&e){return e.dex&&e.dex_magic;},32);
    add([](const auto&e){return e.native_elf;},32);
    add([](const auto&e){return e.resources_arsc&&e.resources_table;},8);
    add([](const auto&e){return e.nested_archive;},16);
    add([](const auto&e){return e.native_library;},16);
    add([](const auto&e){return e.dex;},16);
    add([](const auto&e){return !e.safe_path||e.symlink||e.encrypted||!e.supported||e.duplicate_path;},16);
    for(const auto priority:{std::uint8_t(100),std::uint8_t(99),std::uint8_t(95),std::uint8_t(80),std::uint8_t(75),std::uint8_t(65),std::uint8_t(60)})
        add([&](const auto&e){return e.analysis_priority==priority;},cap);
    add([](const auto&){return true;},cap);
    return out;
}

template<class T,class Pred>
std::vector<const T*> prioritized_render_rows(const std::vector<T>& rows,std::size_t cap,Pred priority) {
    std::vector<const T*> out;out.reserve(std::min(cap,rows.size()));std::vector<bool> used(rows.size(),false);
    for(std::size_t i=0;i<rows.size()&&out.size()<cap;++i)if(priority(rows[i])){used[i]=true;out.push_back(&rows[i]);}
    for(std::size_t i=0;i<rows.size()&&out.size()<cap;++i)if(!used[i])out.push_back(&rows[i]);
    return out;
}

std::vector<std::size_t> implicit_render_fact_positions(const ImplicitExecutionInfo& info) {
    constexpr std::size_t kCap=24,kHighFirst=12,kReviewFirst=6,kAnomalyFirst=4,kInfoFirst=2;
    std::vector<std::size_t> out;out.reserve(std::min(kCap,info.facts.size()));
    std::vector<bool> used(info.facts.size(),false);
    auto add=[&](auto pred,std::size_t limit){std::size_t n=0;for(std::size_t i=0;i<info.facts.size()&&out.size()<kCap&&n<limit;++i){if(used[i]||!pred(info.facts[i]))continue;used[i]=true;out.push_back(i);++n;}};
    auto high=[](const auto&f){return f.priority=="HIGH";};
    auto review=[](const auto&f){return f.priority=="REVIEW";};
    auto anomaly=[](const auto&f){return !f.anomaly_class.empty()&&f.anomaly_class!="NONE";};
    auto informational=[](const auto&f){return f.priority!="HIGH"&&f.priority!="REVIEW";};
    add(high,kHighFirst);add(review,kReviewFirst);add([&](const auto&f){return anomaly(f)&&!high(f)&&!review(f);},kAnomalyFirst);add(informational,kInfoFirst);
    // Fill remaining budget only with actionable facts; ordinary informational rows stay deliberately sparse.
    add(high,kCap);add(review,kCap);add([&](const auto&f){return anomaly(f)&&!high(f)&&!review(f);},kCap);
    return out;
}

void render_implicit_fact_json(std::ostream& o,const ImplicitExecutionFact& x,std::uint32_t index,std::int64_t dependency) {
    o<<"{\"index\":"<<index<<",\"depends_on_fact_index\":"<<dependency
     <<",\"format\":\""<<esc(x.format)<<"\",\"ecosystem\":\""<<esc(x.ecosystem)<<"\""
     <<",\"phase\":\""<<esc(x.phase)<<"\",\"trigger\":\""<<esc(x.trigger)<<"\",\"relation\":\""<<esc(x.relation)<<"\""
     <<",\"source_kind\":\""<<esc(x.source_kind)<<"\",\"source_index\":"<<x.source_index
     <<",\"source_file_backed\":"<<(x.source_file_backed?"true":"false")<<",\"source_file_offset\":"<<x.source_file_offset
     <<",\"source_va\":"<<x.source_va<<",\"source_size\":"<<x.source_size
     <<",\"target_kind\":\""<<esc(x.target_kind)<<"\",\"target_va\":"<<x.target_va
     <<",\"target_file_backed\":"<<(x.target_file_backed?"true":"false")<<",\"target_file_offset\":"<<x.target_file_offset
     <<",\"target_token\":"<<x.target_token<<",\"target_function_index\":"<<x.target_function_index<<",\"target_name\":\""<<esc(x.target_name)<<"\""
     <<",\"evidence_state\":\""<<esc(x.evidence_state)<<"\",\"mutability\":\""<<esc(x.mutability)<<"\""
     <<",\"execution_condition\":\""<<esc(x.execution_condition)<<"\",\"anomaly_class\":\""<<esc(x.anomaly_class)<<"\""
     <<",\"priority\":\""<<esc(x.priority)<<"\",\"priority_reason\":\""<<esc(x.priority_reason)<<"\",\"detail\":\""<<esc(x.detail)<<"\"}";
}

void render_cpython_static_json(std::ostream& o,const CPythonStaticInfo& x) {
    constexpr std::size_t kModuleRender=8,kMethodRender=4,kFunctionRender=16,kTypeRender=8,kTypeMethodRender=4,kCapiRender=8,kTableRender=4,kFrozenModuleRender=8,kPriorityRender=8;
    std::size_t static_type_methods=0,runtime_type_methods=0;
    for(const auto&t:x.cython.types){static_type_methods+=t.methods.size();runtime_type_methods+=t.runtime_methods.size();}
    o<<"{\"valid\":"<<(x.valid?"true":"false")<<",\"state\":\""<<esc(x.state)<<"\""
     <<",\"coordinate_contract\":{\"native_rva\":\"CURRENT_INPUT_IMAGE\",\"file_offset\":\"CURRENT_INPUT_FILE\"}"
     <<",\"runtime\":{\"valid\":"<<(x.runtime.valid?"true":"false")<<",\"version\":\""<<esc(x.runtime.version)<<"\",\"version_hex\":"<<x.runtime.version_hex
     <<",\"reference_status\":\""<<esc(x.runtime.reference_status)<<"\",\"semantic_reference_status\":\""<<esc(x.runtime.semantic_reference_status)<<"\"}"
     <<",\"extension\":{\"valid\":"<<(x.extension.valid?"true":"false")<<",\"state\":\""<<esc(x.extension.state)<<"\",\"pyinit_export_count\":"<<x.extension.pyinit_export_count
     <<",\"inittab_state\":\""<<esc(x.extension.inittab_state)<<"\",\"inittab_entry_count\":"<<x.extension.inittab.size()<<",\"module_count\":"<<x.extension.modules.size()
     <<",\"rejected_count\":"<<x.extension.rejected.size()<<",\"modules_rendered\":"<<std::min(x.extension.modules.size(),kModuleRender)<<",\"modules_truncated\":"<<(x.extension.modules.size()>kModuleRender?"true":"false")<<",\"modules\":[";
    for(std::size_t i=0;i<x.extension.modules.size()&&i<kModuleRender;++i){if(i)o<<',';const auto&m=x.extension.modules[i];o<<"{\"export_name\":\""<<esc(m.export_name)<<"\",\"registration_source\":\""<<esc(m.registration_source)<<"\",\"registration_name\":\""<<esc(m.registration_name)<<"\",\"module_name\":\""<<esc(m.module_name)<<"\",\"name_relation\":\""<<esc(m.name_relation)<<"\",\"state\":\""<<esc(m.state)<<"\",\"methods_state\":\""<<esc(m.methods_state)<<"\",\"slots_state\":\""<<esc(m.slots_state)<<"\",\"init_api\":\""<<esc(m.init_api)<<"\",\"init_rva\":"<<m.init_rva<<",\"moduledef_rva\":"<<m.moduledef_rva<<",\"method_count\":"<<m.methods.size()<<",\"slot_count\":"<<m.slots.size()<<",\"methods_rendered\":"<<std::min(m.methods.size(),kMethodRender)<<",\"methods_truncated\":"<<(m.methods.size()>kMethodRender?"true":"false")<<",\"methods\":[";for(std::size_t z=0;z<m.methods.size()&&z<kMethodRender;++z){if(z)o<<',';const auto&q=m.methods[z];o<<"{\"name\":\""<<esc(q.name)<<"\",\"flags\":"<<q.flags<<",\"record_rva\":"<<q.record_rva<<",\"callback_rva\":"<<q.callback_rva<<"}";}o<<"]}";}
    o<<"]},\"cython\":{\"valid\":"<<(x.cython.valid?"true":"false")<<",\"state\":\""<<esc(x.cython.state)<<"\",\"error\":\""<<esc(x.cython.error)<<"\",\"module_name\":\""<<esc(x.cython.module_name)<<"\",\"moduledef_rva\":"<<x.cython.moduledef_rva<<",\"exec_rva\":"<<x.cython.exec_rva
     <<",\"function_count\":"<<x.cython.functions.size()<<",\"type_count\":"<<x.cython.types.size()<<",\"static_type_method_count\":"<<static_type_methods<<",\"runtime_type_method_count\":"<<runtime_type_methods<<",\"c_api_export_count\":"<<x.cython.c_api_exports.size()
     <<",\"functions_rendered\":"<<std::min(x.cython.functions.size(),kFunctionRender)<<",\"functions_truncated\":"<<(x.cython.functions.size()>kFunctionRender?"true":"false")<<",\"functions\":[";
    for(std::size_t i=0;i<x.cython.functions.size()&&i<kFunctionRender;++i){if(i)o<<',';const auto&f=x.cython.functions[i];o<<"{\"name\":\""<<esc(f.name)<<"\",\"source\":\""<<esc(f.source)<<"\",\"constructor_kind\":\""<<esc(f.constructor_kind)<<"\",\"flags\":"<<f.flags<<",\"methoddef_rva\":"<<f.methoddef_rva<<",\"callback_rva\":"<<f.callback_rva<<",\"bind_call_rva\":"<<f.bind_call_rva<<"}";}
    o<<"],\"types_rendered\":"<<std::min(x.cython.types.size(),kTypeRender)<<",\"types_truncated\":"<<(x.cython.types.size()>kTypeRender?"true":"false")<<",\"types\":[";
    for(std::size_t i=0;i<x.cython.types.size()&&i<kTypeRender;++i){if(i)o<<',';const auto&t=x.cython.types[i];o<<"{\"name\":\""<<esc(t.name)<<"\",\"type_rva\":"<<t.type_rva<<",\"methods_rva\":"<<t.methods_rva<<",\"static_method_count\":"<<t.methods.size()<<",\"runtime_method_count\":"<<t.runtime_methods.size()<<",\"static_methods_rendered\":"<<std::min(t.methods.size(),kTypeMethodRender)<<",\"static_methods_truncated\":"<<(t.methods.size()>kTypeMethodRender?"true":"false")<<",\"static_methods\":[";for(std::size_t z=0;z<t.methods.size()&&z<kTypeMethodRender;++z){if(z)o<<',';const auto&m=t.methods[z];o<<"{\"name\":\""<<esc(m.name)<<"\",\"flags\":"<<m.flags<<",\"methoddef_rva\":"<<m.methoddef_rva<<",\"callback_rva\":"<<m.callback_rva<<"}";}o<<"],\"runtime_methods_rendered\":"<<std::min(t.runtime_methods.size(),kTypeMethodRender)<<",\"runtime_methods_truncated\":"<<(t.runtime_methods.size()>kTypeMethodRender?"true":"false")<<",\"runtime_methods\":[";for(std::size_t z=0;z<t.runtime_methods.size()&&z<kTypeMethodRender;++z){if(z)o<<',';const auto&m=t.runtime_methods[z];o<<"{\"name\":\""<<esc(m.name)<<"\",\"flags\":"<<m.flags<<",\"methoddef_rva\":"<<m.methoddef_rva<<",\"callback_rva\":"<<m.callback_rva<<",\"bind_call_rva\":"<<m.bind_call_rva<<"}";}o<<"]}";}
    o<<"],\"c_api_exports_rendered\":"<<std::min(x.cython.c_api_exports.size(),kCapiRender)<<",\"c_api_exports_truncated\":"<<(x.cython.c_api_exports.size()>kCapiRender?"true":"false")<<",\"c_api_exports\":[";
    for(std::size_t i=0;i<x.cython.c_api_exports.size()&&i<kCapiRender;++i){if(i)o<<',';const auto&q=x.cython.c_api_exports[i];o<<"{\"name\":\""<<esc(q.name)<<"\",\"signature\":\""<<esc(q.signature)<<"\",\"recovery_kind\":\""<<esc(q.recovery_kind)<<"\",\"callback_rva\":"<<q.callback_rva<<",\"export_call_rva\":"<<q.export_call_rva<<"}";}
    o<<"]},\"frozen\":{\"valid\":"<<(x.frozen.valid?"true":"false")<<",\"state\":\""<<esc(x.frozen.state)<<"\",\"error\":\""<<esc(x.frozen.error)<<"\",\"python_minor\":"<<x.frozen.python_minor
     <<",\"raw_module_count\":"<<x.frozen.raw_module_count<<",\"deep_frozen_module_count\":"<<x.frozen.deep_frozen_module_count<<",\"unavailable_module_count\":"<<x.frozen.unavailable_module_count
     <<",\"reference_version\":\""<<esc(x.frozen.reference_version)<<"\",\"reference_match_count\":"<<x.frozen.reference_match_count<<",\"reference_diff_count\":"<<x.frozen.reference_diff_count<<",\"reference_no_reference_count\":"<<x.frozen.reference_no_reference_count<<",\"reference_unavailable_count\":"<<x.frozen.reference_unavailable_count
     <<",\"tables_rendered\":"<<std::min(x.frozen.tables.size(),kTableRender)<<",\"tables_truncated\":"<<(x.frozen.tables.size()>kTableRender?"true":"false")<<",\"tables\":[";
    for(std::size_t i=0;i<x.frozen.tables.size()&&i<kTableRender;++i){if(i)o<<',';const auto&t=x.frozen.tables[i];o<<"{\"export_name\":\""<<esc(t.export_name)<<"\",\"state\":\""<<esc(t.state)<<"\",\"error\":\""<<esc(t.error)<<"\",\"export_rva\":"<<t.export_rva<<",\"table_rva\":"<<t.table_rva<<",\"record_size\":"<<t.record_size<<",\"module_count\":"<<t.modules.size()<<",\"modules_rendered\":"<<std::min(t.modules.size(),kFrozenModuleRender)<<",\"modules_truncated\":"<<(t.modules.size()>kFrozenModuleRender?"true":"false")<<",\"modules\":[";for(std::size_t z=0;z<t.modules.size()&&z<kFrozenModuleRender;++z){if(z)o<<',';const auto&m=t.modules[z];o<<"{\"name\":\""<<esc(m.name)<<"\",\"state\":\""<<esc(m.state)<<"\",\"marshal_state\":\""<<esc(m.marshal_state)<<"\",\"record_rva\":"<<m.record_rva<<",\"raw_code_rva\":"<<m.raw_code_rva<<",\"raw_code_file_offset\":"<<m.raw_code_file_offset<<",\"raw_code_size\":"<<m.raw_code_size<<",\"reference_state\":\""<<esc(m.reference_state)<<"\",\"reference_match_mode\":\""<<esc(m.reference_match_mode)<<"\",\"marshal_code_object_count\":"<<m.marshal_code_object_count<<"}";}o<<"]}";}
    o<<"]},\"reference_gate\":{\"allowed\":"<<(x.frozen_reference_gate.allowed?"true":"false")<<",\"state\":\""<<esc(x.frozen_reference_gate.state)<<"\",\"reference_version\":\""<<esc(x.frozen_reference_gate.reference_version)<<"\"}"
     <<",\"priority\":{\"preferred_target\":\""<<esc(x.priority.preferred_target)<<"\",\"mismatch_count\":"<<x.priority.mismatch_count<<",\"candidates_rendered\":"<<std::min(x.priority.candidates.size(),kPriorityRender)<<",\"candidates_truncated\":"<<(x.priority.candidates_truncated||x.priority.candidates.size()>kPriorityRender?"true":"false")<<",\"candidates\":[";
    for(std::size_t i=0;i<x.priority.candidates.size()&&i<kPriorityRender;++i){if(i)o<<',';const auto&c=x.priority.candidates[i];o<<"{\"table\":\""<<esc(c.table)<<"\",\"module\":\""<<esc(c.module)<<"\",\"reference_version\":\""<<esc(c.reference_version)<<"\",\"file_offset\":"<<c.file_offset<<",\"rva\":"<<c.rva<<",\"size\":"<<c.size<<",\"current_raw_sha256\":\""<<esc(c.current_raw_sha256)<<"\",\"reference_raw_sha256\":\""<<esc(c.reference_raw_sha256)<<"\",\"current_semantic_sha256\":\""<<esc(c.current_semantic_sha256)<<"\",\"reference_semantic_sha256\":\""<<esc(c.reference_semantic_sha256)<<"\"}";}
    o<<"]}}";
}

void render_dart_kernel_json(std::ostream& o,const DartKernelInfo& k) {
    constexpr std::size_t kStringRender=128,kSourceRender=32,kCanonicalRender=128,kConstantRender=128,kLibraryRender=32,kRangeRender=128,kLineRender=256,kHintRender=32;
    o<<"{\"candidate\":"<<(k.candidate?"true":"false")
     <<",\"valid\":"<<(k.valid?"true":"false")
     <<",\"deep_metadata_supported\":"<<(k.deep_metadata_supported?"true":"false")
     <<",\"deep_metadata_complete\":"<<(k.deep_metadata_complete?"true":"false")
     <<",\"format_version\":"<<k.format_version<<",\"sdk_hash\":\""<<esc(k.sdk_hash)<<"\""
     <<",\"string_count\":"<<k.string_count<<",\"constant_count\":"<<k.constant_count<<",\"source_count\":"<<k.source_count<<",\"canonical_name_count\":"<<k.canonical_name_count<<",\"library_count\":"<<k.library_count
     <<",\"component_index_words\":"<<k.component_index_words<<",\"component_file_size\":"<<k.component_file_size<<",\"component_index_offset\":"<<k.component_index_offset
     <<",\"source_table_offset\":"<<k.source_table_offset<<",\"constant_table_offset\":"<<k.constant_table_offset<<",\"constant_table_index_offset\":"<<k.constant_table_index_offset
     <<",\"canonical_name_table_offset\":"<<k.canonical_name_table_offset<<",\"metadata_payloads_offset\":"<<k.metadata_payloads_offset<<",\"metadata_mappings_offset\":"<<k.metadata_mappings_offset<<",\"string_table_offset\":"<<k.string_table_offset<<",\"main_method_reference\":"<<k.main_method_reference
     <<",\"deep_metadata_error\":\""<<esc(k.deep_metadata_error)<<"\",\"deep_metadata_error_offset\":"<<k.deep_metadata_error_offset<<",\"error\":\""<<esc(k.error)<<"\",\"error_offset\":"<<k.error_offset;
    o<<",\"library_offsets\":[";for(std::size_t i=0;i<k.library_offsets.size();++i){if(i)o<<',';o<<k.library_offsets[i];}o<<']';
    o<<",\"strings_rendered\":"<<std::min(k.strings.size(),kStringRender)<<",\"strings_truncated\":"<<(k.strings.size()>kStringRender?"true":"false")<<",\"strings\":[";
    for(std::size_t i=0;i<k.strings.size()&&i<kStringRender;++i){if(i)o<<',';const auto&x=k.strings[i];o<<"{\"index\":"<<x.index<<",\"file_offset\":"<<x.file_offset<<",\"byte_size\":"<<x.byte_size<<",\"wtf8_surrogate_escaped\":"<<(x.wtf8_surrogate_escaped?"true":"false")<<",\"text\":\""<<esc(x.text)<<"\"}";}o<<']';
    o<<",\"sources_rendered\":"<<std::min(k.sources.size(),kSourceRender)<<",\"sources_truncated\":"<<(k.sources.size()>kSourceRender?"true":"false")<<",\"sources\":[";
    for(std::size_t i=0;i<k.sources.size()&&i<kSourceRender;++i){if(i)o<<',';const auto&x=k.sources[i];o<<"{\"index\":"<<x.index<<",\"file_offset\":"<<x.file_offset<<",\"source_code_offset\":"<<x.source_code_offset<<",\"source_code_size\":"<<x.source_code_size<<",\"line_count\":"<<x.line_count<<",\"coverage_reference_count\":"<<x.coverage_reference_count<<",\"uri_wtf8_surrogate_escaped\":"<<(x.uri_wtf8_surrogate_escaped?"true":"false")<<",\"import_uri_wtf8_surrogate_escaped\":"<<(x.import_uri_wtf8_surrogate_escaped?"true":"false")<<",\"uri\":\""<<esc(x.uri)<<"\",\"import_uri\":\""<<esc(x.import_uri)<<"\",\"line_starts_rendered\":"<<std::min(x.line_starts.size(),kLineRender)<<",\"line_starts_truncated\":"<<(x.line_starts.size()>kLineRender?"true":"false")<<",\"line_starts\":[";for(std::size_t z=0;z<x.line_starts.size()&&z<kLineRender;++z){if(z)o<<',';o<<x.line_starts[z];}o<<"]}";}o<<']';
    o<<",\"canonical_names_rendered\":"<<std::min(k.canonical_names.size(),kCanonicalRender)<<",\"canonical_names_truncated\":"<<(k.canonical_names.size()>kCanonicalRender?"true":"false")<<",\"canonical_names\":[";
    for(std::size_t i=0;i<k.canonical_names.size()&&i<kCanonicalRender;++i){if(i)o<<',';const auto&x=k.canonical_names[i];o<<"{\"index\":"<<x.index<<",\"file_offset\":"<<x.file_offset<<",\"parent_reference\":"<<x.parent_reference<<",\"string_reference\":"<<x.string_reference<<",\"path_truncated\":"<<(x.path_truncated?"true":"false")<<",\"name\":\""<<esc(x.name)<<"\",\"path\":\""<<esc(x.path)<<"\"}";}o<<']';
    o<<",\"constants_rendered\":"<<std::min(k.constants.size(),kConstantRender)<<",\"constants_truncated\":"<<(k.constants.size()>kConstantRender?"true":"false")<<",\"constants\":[";
    for(std::size_t i=0;i<k.constants.size()&&i<kConstantRender;++i){if(i)o<<',';const auto&x=k.constants[i];o<<"{\"index\":"<<x.index<<",\"file_offset\":"<<x.file_offset<<",\"end_offset\":"<<x.end_offset<<",\"tag\":"<<unsigned(x.tag)<<",\"tag_name\":\""<<esc(x.tag_name)<<"\",\"simple_value_decoded\":"<<(x.simple_value_decoded?"true":"false")<<",\"value\":\""<<esc(x.value)<<"\"}";}o<<']';
    o<<",\"libraries_rendered\":"<<std::min(k.libraries.size(),kLibraryRender)<<",\"libraries_truncated\":"<<(k.libraries.size()>kLibraryRender?"true":"false")<<",\"libraries\":[";
    for(std::size_t i=0;i<k.libraries.size()&&i<kLibraryRender;++i){if(i)o<<',';const auto&x=k.libraries[i];o<<"{\"index\":"<<x.index<<",\"file_offset\":"<<x.file_offset<<",\"end_offset\":"<<x.end_offset<<",\"index_offset\":"<<x.index_offset<<",\"prefix_end_offset\":"<<x.prefix_end_offset<<",\"flags\":"<<unsigned(x.flags)<<",\"language_major\":"<<x.language_major<<",\"language_minor\":"<<x.language_minor<<",\"canonical_reference\":"<<x.canonical_reference<<",\"name_reference\":"<<x.name_reference<<",\"file_uri_reference\":"<<x.file_uri_reference<<",\"problem_count\":"<<x.problem_count<<",\"class_count\":"<<x.class_count<<",\"procedure_count\":"<<x.procedure_count<<",\"import_uri\":\""<<esc(x.import_uri)<<"\",\"name\":\""<<esc(x.name)<<"\",\"file_uri\":\""<<esc(x.file_uri)<<"\",\"class_ranges_rendered\":"<<std::min(x.class_ranges.size(),kRangeRender)<<",\"class_ranges_truncated\":"<<(x.class_ranges.size()>kRangeRender?"true":"false")<<",\"class_ranges\":[";for(std::size_t z=0;z<x.class_ranges.size()&&z<kRangeRender;++z){if(z)o<<',';const auto&r=x.class_ranges[z];o<<"{\"index\":"<<r.index<<",\"file_offset\":"<<r.file_offset<<",\"end_offset\":"<<r.end_offset<<"}";}o<<"],\"procedure_ranges_rendered\":"<<std::min(x.procedure_ranges.size(),kRangeRender)<<",\"procedure_ranges_truncated\":"<<(x.procedure_ranges.size()>kRangeRender?"true":"false")<<",\"procedure_ranges\":[";for(std::size_t z=0;z<x.procedure_ranges.size()&&z<kRangeRender;++z){if(z)o<<',';const auto&r=x.procedure_ranges[z];o<<"{\"index\":"<<r.index<<",\"file_offset\":"<<r.file_offset<<",\"end_offset\":"<<r.end_offset<<"}";}o<<"],\"procedures_rendered\":"<<std::min(x.procedures.size(),kRangeRender)<<",\"procedures_truncated\":"<<(x.procedures.size()>kRangeRender?"true":"false")<<",\"procedures\":[";for(std::size_t z=0;z<x.procedures.size()&&z<kRangeRender;++z){if(z)o<<',';const auto&q=x.procedures[z];o<<"{\"index\":"<<q.index<<",\"file_offset\":"<<q.file_offset<<",\"end_offset\":"<<q.end_offset<<",\"prefix_end_offset\":"<<q.prefix_end_offset<<",\"canonical_reference\":"<<q.canonical_reference<<",\"file_uri_reference\":"<<q.file_uri_reference<<",\"source_start_offset\":"<<q.source_start_offset<<",\"source_name_offset\":"<<q.source_name_offset<<",\"source_end_offset\":"<<q.source_end_offset<<",\"kind\":"<<unsigned(q.kind)<<",\"stub_kind\":"<<unsigned(q.stub_kind)<<",\"flags\":"<<q.flags<<",\"canonical_path\":\""<<esc(q.canonical_path)<<"\",\"name\":\""<<esc(q.name)<<"\",\"file_uri\":\""<<esc(q.file_uri)<<"\"}";}o<<"]}";}o<<']';
    o<<",\"string_hints_rendered\":"<<std::min(k.string_hints.size(),kHintRender)<<",\"string_hints_truncated\":"<<(k.string_hints.size()>kHintRender?"true":"false")<<",\"string_hints\":[";for(std::size_t i=0;i<k.string_hints.size()&&i<kHintRender;++i){if(i)o<<',';o<<"{\"file_offset\":"<<k.string_hints[i].file_offset<<",\"text\":\""<<esc(k.string_hints[i].text)<<"\"}";}o<<"]}";
}

void render_unity_json(std::ostream& o,const UnityInfo& u,const UnityExtractResult& ex) {
    constexpr std::size_t kTypeRender=128,kFieldRender=64,kMemberFieldRender=128,kMemberMethodRender=64,kMethodParamRender=16,kGenericContainerRender=64,kGenericParameterRender=128,kGenericConstraintRender=32,kGenericRender=64,kGenericArgRender=16,kGenericClassRender=64,kGenericMethodRender=64,kRgctxModuleRender=32,kRgctxRangeRender=64,kRgctxEntryRender=128,kStringLiteralRender=64,kStringValueRender=512,kDispatchMethodRender=64,kStaticInitRender=64,kMetadataUsageRender=64,kMetadataUsageResolvedRender=512,kDefaultValueRender=64,kDefaultValueTextRender=512,kMetadataXrefRender=64,kMetadataXrefResolvedRender=512,kPInvokeRender=32;
    std::size_t enriched_types=0;for(const auto&t:u.types)if(t.type_sizes_resolved||t.field_offsets_resolved||t.field_offsets_runtime_only||t.field_offsets_pointer_va)++enriched_types;
    std::vector<const UnityMetadataUsageInfo*> usage_render;usage_render.reserve(std::min(u.metadata_usages.size(),kMetadataUsageRender));bool usage_kind_seen[8]={false,false,false,false,false,false,false,false};auto add_usage=[&](const UnityMetadataUsageInfo&x){if(usage_render.size()>=kMetadataUsageRender)return;for(const auto*p:usage_render)if(p->index==x.index)return;usage_render.push_back(&x);};for(const auto&x:u.metadata_usages)if(x.usage_kind>=1&&x.usage_kind<=7&&!usage_kind_seen[x.usage_kind]){usage_kind_seen[x.usage_kind]=true;add_usage(x);}for(const auto&x:u.metadata_usages)add_usage(x);
    std::vector<const UnityDefaultValueInfo*> default_render;default_render.reserve(std::min(u.default_values.size(),kDefaultValueRender));auto add_default=[&](const UnityDefaultValueInfo&x){if(default_render.size()>=kDefaultValueRender)return;for(const auto*p:default_render)if(p->index==x.index)return;default_render.push_back(&x);};bool default_kind_field=false,default_kind_param=false,default_kind_rva=false,default_string=false,default_null=false,default_unresolved=false;for(const auto&x:u.default_values){if(!default_kind_field&&x.record_kind=="field_constant"){default_kind_field=true;add_default(x);}if(!default_kind_param&&x.record_kind=="parameter_default"){default_kind_param=true;add_default(x);}if(!default_kind_rva&&x.record_kind=="field_rva"){default_kind_rva=true;add_default(x);}if(!default_string&&x.value_type=="System.String"&&x.value_resolved&&!x.data_index_null){default_string=true;add_default(x);}if(!default_null&&x.data_index_null){default_null=true;add_default(x);}if(!default_unresolved&&!x.value_resolved){default_unresolved=true;add_default(x);}}for(const auto&x:u.default_values)add_default(x);
    std::vector<const UnityMethodUsageXrefInfo*> xref_render;xref_render.reserve(std::min(u.metadata_xrefs.size(),kMetadataXrefRender));auto add_xref=[&](const UnityMethodUsageXrefInfo&x){if(xref_render.size()>=kMetadataXrefRender||x.usage_index>=u.metadata_usages.size())return;for(const auto*p:xref_render)if(p->body_rva==x.body_rva&&p->usage_index==x.usage_index)return;xref_render.push_back(&x);};bool xref_kind_seen[8]={false,false,false,false,false,false,false,false},xref_alias_seen=false;for(const auto&x:u.metadata_xrefs){if(x.usage_index>=u.metadata_usages.size())continue;const auto kind=u.metadata_usages[x.usage_index].usage_kind;if(kind>=1&&kind<=7&&!xref_kind_seen[kind]){xref_kind_seen[kind]=true;add_xref(x);}if(!xref_alias_seen&&x.alias_count>1){xref_alias_seen=true;add_xref(x);}}for(const auto&x:u.metadata_xrefs)add_xref(x);
    std::vector<const UnityPInvokeInfo*> pinvoke_render;pinvoke_render.reserve(std::min(u.pinvokes.size(),kPInvokeRender));auto add_pinvoke=[&](const UnityPInvokeInfo&x){if(pinvoke_render.size()>=kPInvokeRender)return;for(const auto*p:pinvoke_render)if(p->method_index==x.method_index)return;pinvoke_render.push_back(&x);};bool pinvoke_resolved_seen=false,pinvoke_unresolved_seen=false;for(const auto&x:u.pinvokes){if(x.resolved&&!pinvoke_resolved_seen){pinvoke_resolved_seen=true;add_pinvoke(x);}if(!x.resolved&&!pinvoke_unresolved_seen){pinvoke_unresolved_seen=true;add_pinvoke(x);}}for(const auto&x:u.pinvokes)add_pinvoke(x);
    o<<"{\"valid\":"<<(u.valid?"true":"false")<<",\"il2cpp\":"<<(u.il2cpp?"true":"false")<<",\"mono\":"<<(u.mono?"true":"false")
     <<",\"backend_state\":\""<<esc(u.backend_state)<<"\",\"unity_generic\":"<<(u.unity_generic?"true":"false")<<",\"unity_player_import\":"<<(u.unity_player_import?"true":"false")<<",\"il2cpp_export_evidence\":"<<(u.il2cpp_export_evidence?"true":"false")<<",\"il2cpp_string_evidence\":"<<(u.il2cpp_string_evidence?"true":"false")<<",\"game_assembly_validated\":"<<(u.game_assembly_validated?"true":"false")<<",\"mono_runtime_validated\":"<<(u.mono_runtime_validated?"true":"false")
     <<",\"metadata_valid\":"<<(u.metadata_valid?"true":"false")<<",\"metadata_version\":"<<u.metadata_version<<",\"metadata_layout\":\""<<esc(u.metadata_layout)<<"\""
     <<",\"metadata_path\":\""<<esc(path_utf8(u.metadata_path))<<"\",\"game_assembly_path\":\""<<esc(path_utf8(u.game_assembly_path))<<"\",\"managed_path\":\""<<esc(path_utf8(u.managed_path))<<"\",\"mono_runtime_path\":\""<<esc(path_utf8(u.mono_runtime_path))<<"\""
     <<",\"registration_resolved\":"<<(u.registration_resolved?"true":"false")<<",\"registration_variant\":\""<<esc(u.registration_variant)<<"\",\"registration_error\":\""<<esc(u.registration_error)<<"\""
     <<",\"code_registration_va\":"<<u.code_registration_va<<",\"codegen_modules_va\":"<<u.codegen_modules_va<<",\"registration_thunk_va\":"<<u.registration_thunk_va<<",\"registration_target_va\":"<<u.registration_target_va<<",\"registration_third_argument_va\":"<<u.registration_third_argument_va
     <<",\"codegen_module_count\":"<<u.codegen_module_count<<",\"mapped_method_count\":"<<u.mapped_method_count
     <<",\"metadata_registration_resolved\":"<<(u.metadata_registration_resolved?"true":"false")<<",\"metadata_registration_va\":"<<u.metadata_registration_va<<",\"metadata_registration_profile\":\""<<esc(u.metadata_registration_profile)<<"\",\"metadata_registration_error\":\""<<esc(u.metadata_registration_error)<<"\""
     <<",\"registered_types_resolved\":"<<(u.registered_types_resolved?"true":"false")<<",\"registered_type_count\":"<<u.registered_type_count<<",\"registered_types_error\":\""<<esc(u.registered_types_error)<<"\""
     <<",\"metadata_type_definition_count\":"<<u.metadata_type_definition_count<<",\"metadata_method_definition_count\":"<<u.metadata_method_definition_count<<",\"metadata_field_count\":"<<u.metadata_field_count<<",\"metadata_parameter_count\":"<<u.metadata_parameter_count
     <<",\"string_literals_valid\":"<<(u.string_literals_valid?"true":"false")<<",\"string_literals_error\":\""<<esc(u.string_literals_error)<<"\",\"string_literal_count\":"<<u.string_literal_count<<",\"string_literal_total_bytes\":"<<u.string_literal_total_bytes<<",\"string_literal_record_size\":"<<u.string_literal_record_size<<",\"string_literal_empty_count\":"<<u.string_literal_empty_count<<",\"string_literal_invalid_utf8_count\":"<<u.string_literal_invalid_utf8_count<<",\"string_literal_max_length\":"<<u.string_literal_max_length<<",\"string_literal_table_offset\":"<<u.string_literal_table_offset<<",\"string_literal_data_offset\":"<<u.string_literal_data_offset
     <<",\"metadata_usages_resolved\":"<<(u.metadata_usages_resolved?"true":"false")<<",\"metadata_usage_state\":\""<<esc(u.metadata_usage_state)<<"\",\"metadata_usage_profile\":\""<<esc(u.metadata_usage_profile)<<"\",\"metadata_usage_error\":\""<<esc(u.metadata_usage_error)<<"\",\"metadata_usage_declared_count\":"<<u.metadata_usage_declared_count<<",\"metadata_usage_effective_storage_count\":"<<u.metadata_usage_effective_storage_count<<",\"metadata_usage_count\":"<<u.metadata_usage_count<<",\"metadata_usage_pair_reference_count\":"<<u.metadata_usage_pair_reference_count<<",\"metadata_usage_file_backed_storage_count\":"<<u.metadata_usage_file_backed_storage_count<<",\"metadata_usage_max_reference_count\":"<<u.metadata_usage_max_reference_count<<",\"metadata_usage_typeinfo_count\":"<<u.metadata_usage_typeinfo_count<<",\"metadata_usage_type_count\":"<<u.metadata_usage_type_count<<",\"metadata_usage_methoddef_count\":"<<u.metadata_usage_methoddef_count<<",\"metadata_usage_field_count\":"<<u.metadata_usage_field_count<<",\"metadata_usage_string_count\":"<<u.metadata_usage_string_count<<",\"metadata_usage_methodref_count\":"<<u.metadata_usage_methodref_count
     <<",\"metadata_usage_field_rva_count\":"<<u.metadata_usage_field_rva_count<<",\"runtime_metadata_usage_count\":"<<u.runtime_metadata_usage_count<<",\"always_init_metadata_usage_count\":"<<u.always_init_metadata_usage_count<<",\"runtime_metadata_wrapper_count\":"<<u.runtime_metadata_wrapper_count<<",\"runtime_metadata_initializer_va\":"<<u.runtime_metadata_initializer_va
     <<",\"method_bounds_resolved\":"<<(u.method_bounds_resolved?"true":"false")<<",\"method_bounds_state\":\""<<esc(u.method_bounds_state)<<"\",\"method_bounds_profile\":\""<<esc(u.method_bounds_profile)<<"\",\"method_bounds_error\":\""<<esc(u.method_bounds_error)<<"\",\"method_bound_count\":"<<u.method_bound_count<<",\"method_unbound_count\":"<<u.method_unbound_count<<",\"native_body_count\":"<<u.native_body_count<<",\"native_alias_extra_count\":"<<u.native_alias_extra_count<<",\"native_max_alias_count\":"<<u.native_max_alias_count
     <<",\"pinvoke_resolved\":"<<(u.pinvoke_resolved?"true":"false")<<",\"pinvoke_state\":\""<<esc(u.pinvoke_state)<<"\",\"pinvoke_profile\":\""<<esc(u.pinvoke_profile)<<"\",\"pinvoke_error\":\""<<esc(u.pinvoke_error)<<"\",\"pinvoke_method_count\":"<<u.pinvoke_method_count<<",\"pinvoke_resolved_count\":"<<u.pinvoke_resolved_count<<",\"pinvoke_unresolved_count\":"<<u.pinvoke_unresolved_count<<",\"pinvoke_resolver_va\":"<<u.pinvoke_resolver_va
     <<",\"metadata_xrefs_resolved\":"<<(u.metadata_xrefs_resolved?"true":"false")<<",\"metadata_xrefs_state\":\""<<esc(u.metadata_xrefs_state)<<"\",\"metadata_xrefs_profile\":\""<<esc(u.metadata_xrefs_profile)<<"\",\"metadata_xrefs_error\":\""<<esc(u.metadata_xrefs_error)<<"\",\"metadata_xref_relation_count\":"<<u.metadata_xref_relation_count<<",\"metadata_xref_instruction_count\":"<<u.metadata_xref_instruction_count<<",\"metadata_xref_method_count\":"<<u.metadata_xref_method_count<<",\"metadata_xref_slot_count\":"<<u.metadata_xref_slot_count
     <<",\"default_values_resolved\":"<<(u.default_values_resolved?"true":"false")<<",\"default_values_state\":\""<<esc(u.default_values_state)<<"\",\"default_values_profile\":\""<<esc(u.default_values_profile)<<"\",\"default_values_error\":\""<<esc(u.default_values_error)<<"\",\"field_default_record_count\":"<<u.field_default_record_count<<",\"field_constant_count\":"<<u.field_constant_count<<",\"parameter_default_count\":"<<u.parameter_default_count<<",\"field_rva_count\":"<<u.field_rva_count<<",\"field_rva_sized_count\":"<<u.field_rva_sized_count<<",\"decoded_default_count\":"<<u.decoded_default_count<<",\"unresolved_default_count\":"<<u.unresolved_default_count<<",\"null_default_count\":"<<u.null_default_count<<",\"default_dummy_count\":"<<u.default_dummy_count<<",\"default_data_offset\":"<<u.default_data_offset<<",\"default_data_size\":"<<u.default_data_size
     <<",\"member_metadata_valid\":"<<(u.member_metadata_valid?"true":"false")<<",\"member_metadata_error\":\""<<esc(u.member_metadata_error)<<"\",\"member_signatures_resolved\":"<<(u.member_signatures_resolved?"true":"false")<<",\"member_signatures_error\":\""<<esc(u.member_signatures_error)<<"\",\"resolved_field_type_count\":"<<u.resolved_field_type_count<<",\"resolved_parameter_type_count\":"<<u.resolved_parameter_type_count<<",\"resolved_method_signature_count\":"<<u.resolved_method_signature_count
     <<",\"generic_parameter_metadata_valid\":"<<(u.generic_parameter_metadata_valid?"true":"false")<<",\"generic_parameter_metadata_error\":\""<<esc(u.generic_parameter_metadata_error)<<"\",\"generic_parameter_constraints_resolved\":"<<(u.generic_parameter_constraints_resolved?"true":"false")<<",\"generic_parameter_constraints_error\":\""<<esc(u.generic_parameter_constraints_error)<<"\",\"generic_container_count\":"<<u.generic_container_count<<",\"generic_parameter_count\":"<<u.generic_parameter_count<<",\"generic_constraint_count\":"<<u.generic_constraint_count<<",\"resolved_generic_constraint_count\":"<<u.resolved_generic_constraint_count
     <<",\"field_offset_type_count\":"<<u.field_offset_type_count<<",\"field_offset_runtime_only_type_count\":"<<u.field_offset_runtime_only_type_count<<",\"field_offset_null_type_count\":"<<u.field_offset_null_type_count<<",\"type_size_type_count\":"<<u.type_size_type_count
     <<",\"generic_insts_resolved\":"<<(u.generic_insts_resolved?"true":"false")<<",\"generic_insts_error\":\""<<esc(u.generic_insts_error)<<"\",\"generic_inst_count\":"<<u.generic_inst_count<<",\"generic_type_arg_count\":"<<u.generic_type_arg_count<<",\"generic_max_argc\":"<<u.generic_max_argc
     <<",\"generic_classes_resolved\":"<<(u.generic_classes_resolved?"true":"false")<<",\"generic_classes_profile\":\""<<esc(u.generic_classes_profile)<<"\",\"generic_classes_error\":\""<<esc(u.generic_classes_error)<<"\",\"generic_class_count\":"<<u.generic_class_count<<",\"generic_class_unique_struct_count\":"<<u.generic_class_unique_struct_count<<",\"generic_class_duplicate_ref_count\":"<<u.generic_class_duplicate_ref_count<<",\"generic_class_unique_type_definition_count\":"<<u.generic_class_unique_type_definition_count<<",\"generic_class_max_argc\":"<<u.generic_class_max_argc<<",\"generic_class_tail_nonzero_count\":"<<u.generic_class_tail_nonzero_count<<",\"generic_class_tail_image_pointer_count\":"<<u.generic_class_tail_image_pointer_count<<",\"generic_class_tail_small_value_count\":"<<u.generic_class_tail_small_value_count
     <<",\"generic_methods_resolved\":"<<(u.generic_methods_resolved?"true":"false")<<",\"generic_methods_state\":\""<<esc(u.generic_methods_state)<<"\",\"generic_methods_error\":\""<<esc(u.generic_methods_error)<<"\",\"generic_method_record_count\":"<<u.generic_method_record_count<<",\"method_spec_count\":"<<u.method_spec_count<<",\"generic_method_pointer_count\":"<<u.generic_method_pointer_count<<",\"invoker_pointer_count\":"<<u.invoker_pointer_count<<",\"generic_method_native_count\":"<<u.generic_method_native_count<<",\"generic_method_null_count\":"<<u.generic_method_null_count<<",\"generic_invoker_missing_count\":"<<u.generic_invoker_missing_count<<",\"generic_invoker_null_count\":"<<u.generic_invoker_null_count<<",\"generic_adjustor_count\":"<<u.generic_adjustor_count<<",\"generic_adjustor_null_count\":"<<u.generic_adjustor_null_count
     <<",\"rgctx_resolved\":"<<(u.rgctx_resolved?"true":"false")<<",\"rgctx_state\":\""<<esc(u.rgctx_state)<<"\",\"rgctx_profile\":\""<<esc(u.rgctx_profile)<<"\",\"rgctx_error\":\""<<esc(u.rgctx_error)<<"\",\"rgctx_module_count\":"<<u.rgctx_module_count<<",\"rgctx_module_with_data_count\":"<<u.rgctx_module_with_data_count<<",\"rgctx_range_count\":"<<u.rgctx_range_count<<",\"rgctx_entry_count\":"<<u.rgctx_entry_count<<",\"rgctx_resolved_entry_count\":"<<u.rgctx_resolved_entry_count<<",\"rgctx_constrained_count\":"<<u.rgctx_constrained_count
     <<",\"method_dispatch_resolved\":"<<(u.method_dispatch_resolved?"true":"false")<<",\"method_dispatch_state\":\""<<esc(u.method_dispatch_state)<<"\",\"method_dispatch_profile\":\""<<esc(u.method_dispatch_profile)<<"\",\"method_dispatch_error\":\""<<esc(u.method_dispatch_error)<<"\",\"method_dispatch_method_count\":"<<u.method_dispatch_method_count<<",\"method_invoker_resolved_count\":"<<u.method_invoker_resolved_count<<",\"method_invoker_missing_count\":"<<u.method_invoker_missing_count<<",\"method_adjustor_count\":"<<u.method_adjustor_count<<",\"static_init_type_count\":"<<u.static_init_type_count<<",\"static_init_with_cctor_count\":"<<u.static_init_with_cctor_count
     <<",\"error\":\""<<esc(u.error)<<"\"";
    o<<",\"metadata_registration_pairs\":[";for(std::size_t i=0;i<u.metadata_registration_pairs.size();++i){if(i)o<<',';const auto&p=u.metadata_registration_pairs[i];o<<"{\"role\":\""<<esc(p.role)<<"\",\"count\":"<<p.count<<",\"pointer_va\":"<<p.pointer_va<<"}";}o<<']';
    o<<",\"string_literals_rendered\":"<<std::min(u.string_literals.size(),kStringLiteralRender)<<",\"string_literals_truncated\":"<<(u.string_literals.size()>kStringLiteralRender?"true":"false")<<",\"string_literals\":[";for(std::size_t i=0;i<u.string_literals.size()&&i<kStringLiteralRender;++i){if(i)o<<',';const auto&x=u.string_literals[i];const auto keep=std::min(x.value.size(),kStringValueRender);const auto value=x.value.substr(0,keep);o<<"{\"index\":"<<x.index<<",\"data_index\":"<<x.data_index<<",\"length\":"<<x.length<<",\"record_file_offset\":"<<x.record_file_offset<<",\"data_file_offset\":"<<x.data_file_offset<<",\"utf8_valid\":"<<(x.utf8_valid?"true":"false")<<",\"value_truncated\":"<<(x.value.size()>keep?"true":"false")<<",\"value\":\""<<esc(value)<<"\"}";}o<<']';
    o<<",\"metadata_usages_rendered\":"<<usage_render.size()<<",\"metadata_usages_truncated\":"<<(u.metadata_usages.size()>usage_render.size()?"true":"false")<<",\"metadata_usages\":[";for(std::size_t i=0;i<usage_render.size();++i){if(i)o<<',';const auto&x=*usage_render[i];const auto keep=std::min(x.resolved.size(),kMetadataUsageResolvedRender);o<<"{\"index\":"<<x.index<<",\"destination_index\":"<<x.destination_index<<",\"raw_usage_kind\":"<<x.raw_usage_kind<<",\"usage_kind\":"<<x.usage_kind<<",\"usage_name\":\""<<esc(x.usage_name)<<"\",\"source_index\":"<<x.source_index<<",\"reference_count\":"<<x.reference_count<<",\"encoded_source\":"<<x.encoded_source<<",\"storage_va\":"<<x.storage_va<<",\"storage_rva\":"<<x.storage_rva<<",\"storage_file_backed\":"<<(x.storage_file_backed?"true":"false")<<",\"storage_file_offset\":"<<x.storage_file_offset<<",\"always_init\":"<<(x.always_init?"true":"false")<<",\"runtime_discovered\":"<<(x.runtime_discovered?"true":"false")<<",\"init_site_count\":"<<x.init_site_count<<",\"resolved_truncated\":"<<(x.resolved.size()>keep?"true":"false")<<",\"resolved\":\""<<esc(x.resolved.substr(0,keep))<<"\"}";}o<<']';
    o<<",\"metadata_xrefs_rendered\":"<<xref_render.size()<<",\"metadata_xrefs_truncated\":"<<(u.metadata_xrefs.size()>xref_render.size()?"true":"false")<<",\"metadata_xrefs\":[";for(std::size_t i=0;i<xref_render.size();++i){if(i)o<<',';const auto&x=*xref_render[i];const auto&mu=u.metadata_usages[x.usage_index];const auto keep=std::min(mu.resolved.size(),kMetadataXrefResolvedRender);o<<"{\"body_rva\":"<<x.body_rva<<",\"body_end_rva\":"<<x.body_end_rva<<",\"method_index\":"<<x.method_index<<",\"method\":\""<<esc(x.method)<<"\",\"alias_count\":"<<x.alias_count<<",\"usage_index\":"<<x.usage_index<<",\"usage_kind\":"<<mu.usage_kind<<",\"usage_name\":\""<<esc(mu.usage_name)<<"\",\"source_index\":"<<mu.source_index<<",\"storage_va\":"<<mu.storage_va<<",\"first_instruction_rva\":"<<x.first_instruction_rva<<",\"xref_count\":"<<x.xref_count<<",\"init_site_seen\":"<<(x.init_site_seen?"true":"false")<<",\"resolved_truncated\":"<<(mu.resolved.size()>keep?"true":"false")<<",\"resolved\":\""<<esc(mu.resolved.substr(0,keep))<<"\"}";}o<<']';
    o<<",\"pinvokes_rendered\":"<<pinvoke_render.size()<<",\"pinvokes_truncated\":"<<(u.pinvokes.size()>pinvoke_render.size()?"true":"false")<<",\"pinvokes\":[";for(std::size_t i=0;i<pinvoke_render.size();++i){if(i)o<<',';const auto&x=*pinvoke_render[i];o<<"{\"method_index\":"<<x.method_index<<",\"method\":\""<<esc(x.method)<<"\",\"body_rva\":"<<x.body_rva<<",\"method_flags\":"<<x.method_flags<<",\"impl_flags\":"<<x.impl_flags<<",\"resolved\":"<<(x.resolved?"true":"false")<<",\"state\":\""<<esc(x.state)<<"\",\"module_va\":"<<x.module_va<<",\"module_length\":"<<x.module_length<<",\"module\":\""<<esc(x.module)<<"\",\"entry_va\":"<<x.entry_va<<",\"entry_length\":"<<x.entry_length<<",\"entry\":\""<<esc(x.entry)<<"\",\"charset\":"<<x.charset<<",\"calling_convention\":"<<x.calling_convention<<",\"parameter_size\":"<<x.parameter_size<<",\"no_mangle\":"<<(x.no_mangle?"true":"false")<<",\"resolver_va\":"<<x.resolver_va<<",\"resolver_call_rva\":"<<x.resolver_call_rva<<",\"cache_va\":"<<x.cache_va<<",\"cache_rva\":"<<x.cache_rva<<",\"error\":\""<<esc(x.error)<<"\"}";}o<<']';
    o<<",\"default_values_rendered\":"<<default_render.size()<<",\"default_values_truncated\":"<<(u.default_values.size()>default_render.size()?"true":"false")<<",\"default_values\":[";for(std::size_t i=0;i<default_render.size();++i){if(i)o<<',';const auto&x=*default_render[i];const auto keep=std::min(x.value.size(),kDefaultValueTextRender);o<<"{\"index\":"<<x.index<<",\"record_kind\":\""<<esc(x.record_kind)<<"\",\"record_file_offset\":"<<x.record_file_offset<<",\"owner_index\":"<<x.owner_index<<",\"owner_name\":\""<<esc(x.owner_name)<<"\",\"declared_type\":\""<<esc(x.declared_type)<<"\",\"default_type_index\":"<<x.default_type_index<<",\"value_type\":\""<<esc(x.value_type)<<"\",\"data_index\":"<<x.data_index<<",\"data_index_null\":"<<(x.data_index_null?"true":"false")<<",\"data_file_offset\":"<<x.data_file_offset<<",\"data_size\":"<<x.data_size<<",\"value_resolved\":"<<(x.value_resolved?"true":"false")<<",\"value_truncated\":"<<(x.value.size()>keep?"true":"false")<<",\"value\":\""<<esc(x.value.substr(0,keep))<<"\",\"blob_preview_hex\":\""<<esc(x.blob_preview_hex)<<"\"}";}o<<']';
    o<<",\"enriched_type_count\":"<<enriched_types<<",\"types_rendered\":"<<std::min(enriched_types,kTypeRender)<<",\"types_truncated\":"<<(enriched_types>kTypeRender?"true":"false")<<",\"types\":[";
    std::size_t shown=0;for(const auto&t:u.types){if(!(t.type_sizes_resolved||t.field_offsets_resolved||t.field_offsets_runtime_only||t.field_offsets_pointer_va)||shown>=kTypeRender)continue;if(shown++)o<<',';std::string state=t.field_count==0?"no_fields":t.field_offsets_resolved?"resolved":t.field_offsets_runtime_only?"runtime_only":t.field_offsets_pointer_va?"unresolved":"null_pointer";o<<"{\"index\":"<<t.index<<",\"full_name\":\""<<esc(t.full_name)<<"\",\"image_name\":\""<<esc(t.image_name)<<"\",\"first_field\":"<<t.first_field<<",\"field_count\":"<<t.field_count<<",\"field_offset_state\":\""<<state<<"\",\"field_offsets_pointer_va\":"<<t.field_offsets_pointer_va<<",\"type_sizes_resolved\":"<<(t.type_sizes_resolved?"true":"false")<<",\"instance_size\":"<<t.instance_size<<",\"native_size\":"<<t.native_size<<",\"static_fields_size\":"<<t.static_fields_size<<",\"thread_static_fields_size\":"<<t.thread_static_fields_size<<",\"field_offsets_rendered\":"<<std::min(t.field_offsets.size(),kFieldRender)<<",\"field_offsets_truncated\":"<<(t.field_offsets.size()>kFieldRender?"true":"false")<<",\"field_offsets\":[";for(std::size_t z=0;z<t.field_offsets.size()&&z<kFieldRender;++z){if(z)o<<',';o<<t.field_offsets[z];}o<<"]}";}o<<']';
    o<<",\"fields_rendered\":"<<std::min(u.fields.size(),kMemberFieldRender)<<",\"fields_truncated\":"<<(u.fields.size()>kMemberFieldRender?"true":"false")<<",\"fields\":[";
    for(std::size_t i=0;i<u.fields.size()&&i<kMemberFieldRender;++i){if(i)o<<',';const auto&f=u.fields[i];o<<"{\"index\":"<<f.index<<",\"token\":"<<f.token<<",\"declaring_type\":"<<f.declaring_type<<",\"declaring_type_name\":\""<<esc(f.declaring_type_name)<<"\",\"name\":\""<<esc(f.name)<<"\",\"full_name\":\""<<esc(f.full_name)<<"\",\"type_index\":"<<f.type_index<<",\"type_name\":\""<<esc(f.type_name)<<"\",\"offset_resolved\":"<<(f.offset_resolved?"true":"false")<<",\"offset_runtime_only\":"<<(f.offset_runtime_only?"true":"false")<<",\"offset\":"<<f.offset<<"}";}o<<']';
    o<<",\"methods_rendered\":"<<std::min(u.methods.size(),kMemberMethodRender)<<",\"methods_truncated\":"<<(u.methods.size()>kMemberMethodRender?"true":"false")<<",\"methods\":[";
    for(std::size_t i=0;i<u.methods.size()&&i<kMemberMethodRender;++i){if(i)o<<',';const auto&m=u.methods[i];o<<"{\"index\":"<<m.index<<",\"token\":"<<m.token<<",\"rva\":"<<m.rva<<",\"declaring_type\":"<<m.declaring_type<<",\"type_name\":\""<<esc(m.type_name)<<"\",\"name\":\""<<esc(m.name)<<"\",\"full_name\":\""<<esc(m.full_name)<<"\",\"return_type_index\":"<<m.return_type_index<<",\"return_type\":\""<<esc(m.return_type)<<"\",\"signature\":\""<<esc(m.signature)<<"\",\"parameter_count\":"<<m.parameter_count<<",\"native_bound_resolved\":"<<(m.native_bound_resolved?"true":"false")<<",\"native_end_rva\":"<<m.native_end_rva<<",\"native_size\":"<<m.native_size<<",\"native_alias_count\":"<<m.native_alias_count<<",\"flags\":"<<m.flags<<",\"impl_flags\":"<<m.impl_flags<<",\"vtable_slot\":"<<m.vtable_slot<<",\"pinvoke_impl\":"<<(m.pinvoke_impl?"true":"false")<<",\"parameters_rendered\":"<<std::min(m.parameters.size(),kMethodParamRender)<<",\"parameters_truncated\":"<<(m.parameters.size()>kMethodParamRender?"true":"false")<<",\"parameters\":[";for(std::size_t z=0;z<m.parameters.size()&&z<kMethodParamRender;++z){if(z)o<<',';const auto&a=m.parameters[z];o<<"{\"index\":"<<a.index<<",\"token\":"<<a.token<<",\"type_index\":"<<a.type_index<<",\"name\":\""<<esc(a.name)<<"\",\"type_name\":\""<<esc(a.type_name)<<"\"}";}o<<"]}";}o<<']';
    o<<",\"method_dispatch_methods_rendered\":"<<std::min<std::size_t>(u.method_dispatch_method_count,kDispatchMethodRender)<<",\"method_dispatch_methods_truncated\":"<<(u.method_dispatch_method_count>kDispatchMethodRender?"true":"false")<<",\"method_dispatch_methods\":[";{std::size_t shown_dispatch=0;for(const auto&m:u.methods){if(!(m.invoker_resolved||m.adjustor_thunk_resolved))continue;if(shown_dispatch>=kDispatchMethodRender)break;if(shown_dispatch++)o<<',';o<<"{\"index\":"<<m.index<<",\"token\":"<<m.token<<",\"signature\":\""<<esc(m.signature)<<"\",\"rva\":"<<m.rva<<",\"invoker_index\":"<<m.invoker_index<<",\"invoker_rva\":"<<m.invoker_rva<<",\"invoker_resolved\":"<<(m.invoker_resolved?"true":"false")<<",\"adjustor_thunk_rva\":"<<m.adjustor_thunk_rva<<",\"adjustor_thunk_resolved\":"<<(m.adjustor_thunk_resolved?"true":"false")<<"}";}}o<<']';
    o<<",\"static_init_types_rendered\":"<<std::min<std::size_t>(u.static_init_type_count,kStaticInitRender)<<",\"static_init_types_truncated\":"<<(u.static_init_type_count>kStaticInitRender?"true":"false")<<",\"static_init_types\":[";{std::size_t shown_static=0;for(const auto&t:u.types){if(!t.static_init_listed)continue;if(shown_static>=kStaticInitRender)break;if(shown_static++)o<<',';o<<"{\"index\":"<<t.index<<",\"full_name\":\""<<esc(t.full_name)<<"\",\"image_name\":\""<<esc(t.image_name)<<"\",\"static_constructor_method_index\":"<<t.static_constructor_method_index<<",\"static_constructor_resolved\":"<<(t.static_constructor_resolved?"true":"false")<<",\"static_constructor_rva\":"<<t.static_constructor_rva<<"}";}}o<<']';
    o<<",\"generic_containers_rendered\":"<<std::min(u.generic_containers.size(),kGenericContainerRender)<<",\"generic_containers_truncated\":"<<(u.generic_containers.size()>kGenericContainerRender?"true":"false")<<",\"generic_containers\":[";
    for(std::size_t i=0;i<u.generic_containers.size()&&i<kGenericContainerRender;++i){if(i)o<<',';const auto&c=u.generic_containers[i];o<<"{\"index\":"<<c.index<<",\"owner_index\":"<<c.owner_index<<",\"parameter_start\":"<<c.parameter_start<<",\"parameter_count\":"<<c.parameter_count<<",\"is_method\":"<<(c.is_method?"true":"false")<<",\"owner_name\":\""<<esc(c.owner_name)<<"\"}";}o<<']';
    o<<",\"generic_parameters_rendered\":"<<std::min(u.generic_parameters.size(),kGenericParameterRender)<<",\"generic_parameters_truncated\":"<<(u.generic_parameters.size()>kGenericParameterRender?"true":"false")<<",\"generic_parameters\":[";
    for(std::size_t i=0;i<u.generic_parameters.size()&&i<kGenericParameterRender;++i){if(i)o<<',';const auto&g=u.generic_parameters[i];o<<"{\"index\":"<<g.index<<",\"owner_container\":"<<g.owner_container<<",\"number\":"<<g.number<<",\"flags\":"<<g.flags<<",\"name\":\""<<esc(g.name)<<"\",\"constraint_start\":"<<g.constraint_start<<",\"constraint_count\":"<<g.constraint_count<<",\"constraints_rendered\":"<<std::min(g.constraints.size(),kGenericConstraintRender)<<",\"constraints_truncated\":"<<(g.constraints.size()>kGenericConstraintRender?"true":"false")<<",\"constraint_type_indices\":[";for(std::size_t z=0;z<g.constraint_type_indices.size()&&z<kGenericConstraintRender;++z){if(z)o<<',';o<<g.constraint_type_indices[z];}o<<"],\"constraints\":[";for(std::size_t z=0;z<g.constraints.size()&&z<kGenericConstraintRender;++z){if(z)o<<',';o<<"\""<<esc(g.constraints[z])<<"\"";}o<<"]}";}o<<']';
    o<<",\"generic_insts_rendered\":"<<std::min(u.generic_insts.size(),kGenericRender)<<",\"generic_insts_truncated\":"<<(u.generic_insts.size()>kGenericRender?"true":"false")<<",\"generic_insts\":[";
    for(std::size_t i=0;i<u.generic_insts.size()&&i<kGenericRender;++i){if(i)o<<',';const auto&g=u.generic_insts[i];o<<"{\"index\":"<<g.index<<",\"va\":"<<g.va<<",\"argc\":"<<g.argc<<",\"argv_va\":"<<g.argv_va<<",\"args_rendered\":"<<std::min(g.args.size(),kGenericArgRender)<<",\"args_truncated\":"<<(g.args.size()>kGenericArgRender?"true":"false")<<",\"args\":[";for(std::size_t z=0;z<g.args.size()&&z<kGenericArgRender;++z){if(z)o<<',';const auto&a=g.args[z];o<<"{\"va\":"<<a.va<<",\"data\":"<<a.data<<",\"attrs\":"<<a.attrs<<",\"type_code\":"<<unsigned(a.type_code)<<",\"raw_flags\":"<<unsigned(a.raw_flags)<<",\"type_name\":\""<<esc(a.type_name)<<"\",\"type_definition_index\":"<<a.type_definition_index<<",\"generic_class_index\":"<<a.generic_class_index<<",\"resolved_name\":\""<<esc(a.resolved_name)<<"\"}";}o<<"]}";}o<<']';
    o<<",\"generic_classes_rendered\":"<<std::min(u.generic_classes.size(),kGenericClassRender)<<",\"generic_classes_truncated\":"<<(u.generic_classes.size()>kGenericClassRender?"true":"false")<<",\"generic_classes\":[";
    for(std::size_t i=0;i<u.generic_classes.size()&&i<kGenericClassRender;++i){if(i)o<<',';const auto&g=u.generic_classes[i];o<<"{\"index\":"<<g.index<<",\"va\":"<<g.va<<",\"type_va\":"<<g.type_va<<",\"type_definition_index\":"<<g.type_definition_index<<",\"class_inst_index\":"<<g.class_inst_index<<",\"method_inst_index\":"<<g.method_inst_index<<",\"type_code\":"<<unsigned(g.type_code)<<",\"tail_qword\":"<<g.tail_qword<<",\"duplicate_struct\":"<<(g.duplicate_struct?"true":"false")<<",\"type_full_name\":\""<<esc(g.type_full_name)<<"\"}";}o<<']';
    o<<",\"generic_methods_rendered\":"<<std::min(u.generic_methods.size(),kGenericMethodRender)<<",\"generic_methods_truncated\":"<<(u.generic_methods.size()>kGenericMethodRender?"true":"false")<<",\"generic_methods\":[";
    for(std::size_t i=0;i<u.generic_methods.size()&&i<kGenericMethodRender;++i){if(i)o<<',';const auto&g=u.generic_methods[i];o<<"{\"index\":"<<g.index<<",\"method_spec_index\":"<<g.method_spec_index<<",\"method_definition_index\":"<<g.method_definition_index<<",\"class_inst_index\":"<<g.class_inst_index<<",\"method_inst_index\":"<<g.method_inst_index<<",\"method_pointer_index\":"<<g.method_pointer_index<<",\"invoker_index\":"<<g.invoker_index<<",\"adjustor_thunk_index\":"<<g.adjustor_thunk_index<<",\"method_pointer_va\":"<<g.method_pointer_va<<",\"invoker_pointer_va\":"<<g.invoker_pointer_va<<",\"adjustor_thunk_va\":"<<g.adjustor_thunk_va<<",\"method_rva\":"<<g.method_rva<<",\"invoker_rva\":"<<g.invoker_rva<<",\"adjustor_thunk_rva\":"<<g.adjustor_thunk_rva<<",\"method_pointer_resolved\":"<<(g.method_pointer_resolved?"true":"false")<<",\"invoker_pointer_resolved\":"<<(g.invoker_pointer_resolved?"true":"false")<<",\"adjustor_thunk_resolved\":"<<(g.adjustor_thunk_resolved?"true":"false")<<",\"method_full_name\":\""<<esc(g.method_full_name)<<"\"}";}o<<']';
    o<<",\"codegen_modules_rendered\":"<<std::min(u.codegen_modules.size(),kRgctxModuleRender)<<",\"codegen_modules_truncated\":"<<(u.codegen_modules.size()>kRgctxModuleRender?"true":"false")<<",\"codegen_modules\":[";
    for(std::size_t i=0;i<u.codegen_modules.size()&&i<kRgctxModuleRender;++i){if(i)o<<',';const auto&m=u.codegen_modules[i];o<<"{\"index\":"<<m.index<<",\"va\":"<<m.va<<",\"name\":\""<<esc(m.name)<<"\",\"rgctx_valid\":"<<(m.rgctx_valid?"true":"false")<<",\"rgctx_range_count\":"<<m.rgctx_range_count<<",\"rgctx_entry_count\":"<<m.rgctx_entry_count<<",\"ranges_rendered\":"<<std::min(m.ranges.size(),kRgctxRangeRender)<<",\"ranges_truncated\":"<<(m.ranges.size()>kRgctxRangeRender?"true":"false")<<",\"ranges\":[";for(std::size_t z=0;z<m.ranges.size()&&z<kRgctxRangeRender;++z){if(z)o<<',';const auto&r=m.ranges[z];o<<"{\"index\":"<<r.index<<",\"token\":"<<r.token<<",\"start\":"<<r.start<<",\"length\":"<<r.length<<",\"owner_kind\":\""<<esc(r.owner_kind)<<"\",\"owner_name\":\""<<esc(r.owner_name)<<"\"}";}o<<"],\"entries_rendered\":"<<std::min(m.entries.size(),kRgctxEntryRender)<<",\"entries_truncated\":"<<(m.entries.size()>kRgctxEntryRender?"true":"false")<<",\"entries\":[";for(std::size_t z=0;z<m.entries.size()&&z<kRgctxEntryRender;++z){if(z)o<<',';const auto&e=m.entries[z];o<<"{\"index\":"<<e.index<<",\"kind\":"<<e.kind<<",\"kind_name\":\""<<esc(e.kind_name)<<"\",\"range_index\":"<<e.range_index<<",\"owner_token\":"<<e.owner_token<<",\"owner_kind\":\""<<esc(e.owner_kind)<<"\",\"owner_name\":\""<<esc(e.owner_name)<<"\",\"raw_index\":"<<e.raw_index<<",\"type_index\":"<<e.type_index<<",\"generic_method_index\":"<<e.generic_method_index<<",\"constrained_type_index\":"<<e.constrained_type_index<<",\"data_va\":"<<e.data_va<<",\"encoded_method_index\":"<<e.encoded_method_index<<",\"encoded_method_usage\":"<<e.encoded_method_usage<<",\"encoded_method_decoded_index\":"<<e.encoded_method_decoded_index<<",\"resolved\":\""<<esc(e.resolved)<<"\",\"constrained_method\":\""<<esc(e.constrained_method)<<"\"}";}o<<"]}";}o<<']';
    o<<",\"extraction\":{\"success\":"<<(ex.success?"true":"false")<<",\"budget_exhausted\":"<<(ex.budget_exhausted?"true":"false")<<",\"callgraph_requested\":"<<(ex.callgraph_requested?"true":"false")<<",\"row_budget\":"<<ex.row_budget<<",\"materialized_rows\":"<<ex.materialized_rows<<",\"omitted_rows\":"<<ex.omitted_rows<<",\"omitted_planes\":[";for(std::size_t i=0;i<ex.omitted_planes.size();++i){if(i)o<<',';o<<"\""<<esc(ex.omitted_planes[i])<<"\"";}o<<"],\"symbols_csv\":\""<<esc(path_utf8(ex.symbols_csv))<<"\",\"symbol_count\":"<<ex.symbol_count<<",\"layouts_csv\":\""<<esc(path_utf8(ex.layouts_csv))<<"\",\"layout_row_count\":"<<ex.layout_row_count<<",\"generics_csv\":\""<<esc(path_utf8(ex.generics_csv))<<"\",\"generic_row_count\":"<<ex.generic_row_count<<",\"rgctx_csv\":\""<<esc(path_utf8(ex.rgctx_csv))<<"\",\"rgctx_row_count\":"<<ex.rgctx_row_count<<",\"strings_csv\":\""<<esc(path_utf8(ex.strings_csv))<<"\",\"string_row_count\":"<<ex.string_row_count<<",\"usages_csv\":\""<<esc(path_utf8(ex.usages_csv))<<"\",\"usage_row_count\":"<<ex.usage_row_count<<",\"defaults_csv\":\""<<esc(path_utf8(ex.defaults_csv))<<"\",\"default_row_count\":"<<ex.default_row_count<<",\"xrefs_csv\":\""<<esc(path_utf8(ex.xrefs_csv))<<"\",\"xref_row_count\":"<<ex.xref_row_count<<",\"pinvoke_csv\":\""<<esc(path_utf8(ex.pinvoke_csv))<<"\",\"pinvoke_row_count\":"<<ex.pinvoke_row_count<<",\"dispatch_csv\":\""<<esc(path_utf8(ex.dispatch_csv))<<"\",\"dispatch_row_count\":"<<ex.dispatch_row_count<<",\"dispatch_calls_csv\":\""<<esc(path_utf8(ex.dispatch_calls_csv))<<"\",\"dispatch_targets_csv\":\""<<esc(path_utf8(ex.dispatch_targets_csv))<<"\",\"dispatch_callsite_state\":\""<<esc(ex.dispatch_callsite_state)<<"\",\"dispatch_callsite_count\":"<<ex.dispatch_callsite_count<<",\"dispatch_virtual_callsite_count\":"<<ex.dispatch_virtual_callsite_count<<",\"dispatch_interface_callsite_count\":"<<ex.dispatch_interface_callsite_count<<",\"dispatch_exact_count\":"<<ex.dispatch_exact_count<<",\"dispatch_bounded_count\":"<<ex.dispatch_bounded_count<<",\"dispatch_unresolved_count\":"<<ex.dispatch_unresolved_count<<",\"dispatch_candidate_set_count\":"<<ex.dispatch_candidate_set_count<<",\"dispatch_candidate_row_count\":"<<ex.dispatch_candidate_row_count<<",\"dispatch_callsite_error\":\""<<esc(ex.dispatch_callsite_error)<<"\",\"callgraph_csv\":\""<<esc(path_utf8(ex.callgraph_csv))<<"\",\"call_edge_count\":"<<ex.call_edge_count<<",\"callgraph_body_count\":"<<ex.callgraph_body_count<<",\"callgraph_partial_body_count\":"<<ex.callgraph_partial_body_count<<",\"callgraph_instruction_count\":"<<ex.callgraph_instruction_count<<",\"callgraph_unresolved_direct_count\":"<<ex.callgraph_unresolved_direct_count<<",\"callgraph_unresolved_indirect_count\":"<<ex.callgraph_unresolved_indirect_count<<",\"callgraph_error\":\""<<esc(ex.callgraph_error)<<"\",\"error\":\""<<esc(ex.error)<<"\"}}";
}
}

std::string render_text(const AnalysisReport& r) {
    std::ostringstream o;
    o << "auto-refirst Analysis\n"
      << "Input: " << path_utf8(r.input) << "\n"
      << "SHA256: " << r.input_snapshot.sha256 << "\n"
      << "Size: " << r.input_snapshot.size << "\n";
    if(r.artifact.graph_member){o<<"Artifact: depth="<<r.artifact.depth<<(r.artifact.root?" root":" child")<<" relation="<<(r.artifact.relation.empty()?"input":r.artifact.relation)<<"\n";if(!r.artifact.parent.empty())o<<"  parent: "<<path_utf8(r.artifact.parent)<<"\n";o<<"  root_input: "<<path_utf8(r.artifact.root_input)<<"\n"<<"  offset_basis: "<<path_utf8(r.artifact.offset_basis)<<" ("<<r.artifact.offset_space<<")\n";}
    if(r.artifact_graph.enabled){o<<"Artifact graph: nodes="<<r.artifact_graph.nodes<<" materialized_files="<<r.artifact_graph.materialized_files<<" materialized_bytes="<<r.artifact_graph.materialized_bytes<<" admitted_bytes="<<r.artifact_graph.admitted_bytes<<" deduplicated="<<r.artifact_graph.deduplicated<<" skipped_limits="<<r.artifact_graph.skipped_limits<<" skipped_unsafe="<<r.artifact_graph.skipped_unsafe<<" max_depth="<<r.artifact_graph.max_depth<<" max_nodes="<<r.artifact_graph.max_nodes<<" max_total_bytes="<<r.artifact_graph.max_total_bytes<<(r.artifact_graph.truncated?" PARTIAL":"")<<"\n";for(const auto&e:r.artifact_graph.edges)o<<"  ["<<e.state<<"] depth="<<e.depth<<" "<<e.relation<<" "<<path_utf8(e.parent)<<" -> "<<path_utf8(e.child)<<" size="<<e.size<<(e.sha256.empty()?"":" sha256="+e.sha256)<<(e.duplicate_of.empty()?"":" duplicate_of="+path_utf8(e.duplicate_of))<<"\n";for(const auto&w:r.artifact_graph.warnings)o<<"  warning: "<<w<<"\n";}
    if(!r.artifact_relationships.empty()){o<<"Artifact relationships:\n";for(const auto&x:r.artifact_relationships)o<<"  ["<<x.state<<"] "<<x.kind<<" "<<path_utf8(x.first)<<(x.directed?" -> ":" <-> ")<<path_utf8(x.second)<<" evidence="<<x.evidence_level<<" ambiguity="<<x.ambiguity<<"\n    basis: "<<x.evidence_basis<<"\n    scope: "<<x.provenance_scope<<"\n";}
    if(!r.artifacts.empty()||r.materialization.partial){
        o<<"Analysis artifacts:\n  root: "<<path_utf8(r.materialization.root)<<"\n";
        for(const auto&a:r.artifacts){o<<"  ["<<a.state<<"] "<<a.kind<<" role="<<a.role<<" priority="<<a.priority<<"\n    path: "<<path_utf8(a.path)<<"\n";if(!a.parent.empty())o<<"    parent: "<<path_utf8(a.parent)<<" relation="<<a.relation<<"\n";o<<"    size="<<a.size<<(a.sha256.empty()?"":" sha256="+a.sha256)<<" normalized="<<(a.normalized?"yes":"no")<<" runtime_confirmed="<<(a.runtime_confirmed?"yes":"no")<<"\n";}
        if(r.materialization.partial)o<<"  AUTO_MATERIALIZATION_PARTIAL omitted_count="<<r.materialization.omitted_count<<" omitted_bytes="<<r.materialization.omitted_bytes<<"\n";
        for(const auto&reason:r.materialization.reasons)o<<"  reason: "<<reason<<"\n";
    }

    if (r.pe.valid) {
        o << "Format: " << (r.pe.pe64 ? "PE64" : "PE32") << ' '
          << pe_machine_name(r.pe.machine) << "\n"
          << "Subsystem: " << pe_subsystem_name(r.pe.subsystem) << "\n"
          << "Entry RVA: 0x" << std::hex << r.pe.entry_rva << std::dec << "\n"
          << "Image Size: " << r.pe.image_size << "\n"
          << "Sections:\n"
          << "  Name       RVA       VSize      RawOff     RawSize    Used       Entropy Perm\n";

        for (const auto& s : r.pe.sections) {
            o << "  " << std::left << std::setw(10) << s.name << std::right
              << std::hex << std::setw(8) << s.rva << "  "
              << std::setw(8) << s.vsize << "  "
              << std::setw(8) << s.raw_offset << "  "
              << std::setw(8) << s.raw_size << "  "
              << std::setw(8) << s.used_size << std::dec << "  "
              << std::fixed << std::setprecision(3) << std::setw(7) << s.entropy
              << ' ' << perms(s.characteristics) << "\n";
        }
        if (r.pe.overlay_size) {
            o << "Overlay: offset=0x" << std::hex << r.pe.overlay_offset << std::dec
              << " size=" << r.pe.overlay_size << "\n";
        }
        if (!r.pe.imports.empty()) {
            std::size_t fn_count=0; for(const auto&m:r.pe.imports) fn_count+=m.functions.size();
            o << "Imports: modules=" << r.pe.imports.size() << " functions=" << fn_count << "\n";
            for(const auto&m:r.pe.imports){o<<"  "<<m.name<<" ("<<m.functions.size()<<")";std::size_t shown=0;for(const auto&f:m.functions){if(shown++>=12){o<<" ...";break;}o<<" "<<(f.by_ordinal?("#"+std::to_string(f.ordinal)):f.name);}o<<"\n";}
        }
        if (!r.pe.exports.empty()) {
            o << "Exports: " << r.pe.exports.size() << " named/ordinal entries\n";
            std::size_t shown=0; for(const auto&e:r.pe.exports){if(e.name.empty())continue;if(shown++>=40){o<<"  ...\n";break;}o<<"  "<<e.name<<" RVA=0x"<<std::hex<<e.rva<<std::dec;if(!e.forwarder.empty())o<<" -> "<<e.forwarder;o<<"\n";}
        }
        if(r.pe.resources.present||r.pe.clr.present||r.pe.load_config.present){
            o<<"PE directories:\n";
            if(r.pe.resources.present)o<<"  Resources RVA=0x"<<std::hex<<r.pe.resources.rva<<std::dec<<" size="<<r.pe.resources.size<<"\n";
            if(r.pe.clr.present)o<<"  CLR/.NET RVA=0x"<<std::hex<<r.pe.clr.rva<<std::dec<<" size="<<r.pe.clr.size<<"\n";
            if(r.pe.load_config.present)o<<"  LoadConfig RVA=0x"<<std::hex<<r.pe.load_config.rva<<std::dec<<" size="<<r.pe.load_config.size<<" guard_flags=0x"<<std::hex<<r.pe.load_config.guard_flags<<std::dec<<"\n";
        }
        if(r.authenticode.present||r.authenticode.state=="FAILED"){
            const auto&a=r.authenticode;o<<"Authenticode: "<<a.state<<"\n";
            if(a.present)o<<"  certificate_table: off=0x"<<std::hex<<a.certificate_table_offset<<std::dec<<" size="<<a.certificate_table_size<<" entries="<<a.signatures.size()<<"\n";
            o<<"  covered_bytes="<<a.covered_bytes<<" post_section_unhashed="<<a.post_section_bytes<<" pre_certificate_unhashed="<<a.pre_certificate_unhashed_bytes<<" post_certificate_unhashed="<<a.post_certificate_unhashed_bytes<<"\n";
            for(std::size_t ai=0;ai<a.signatures.size();++ai){const auto&x=a.signatures[ai];o<<"  signature["<<ai<<"] source="<<x.source<<" depth="<<x.nesting_depth;if(x.parent_signature_index>=0)o<<" parent="<<x.parent_signature_index;o<<" type=0x"<<std::hex<<x.certificate_type<<" revision=0x"<<x.revision<<std::dec<<" state="<<x.state;if(!x.digest_algorithm.empty())o<<" digest="<<x.digest_algorithm;if(!x.signed_digest.empty())o<<" signed="<<x.signed_digest;if(!x.computed_digest.empty())o<<" computed="<<x.computed_digest;o<<"\n";
                o<<"    signer_metadata="<<(x.signer_metadata_state.empty()?"NOT_PARSED":x.signer_metadata_state)<<" signers="<<x.signers.size()<<" certificates="<<x.certificates.size()<<"\n";
                if(x.page_hashes_present){o<<"    page_hashes="<<x.page_hash_state<<" algorithm="<<x.page_hash_algorithm<<" page_size="<<x.page_size<<" entries="<<x.page_hashes.size()<<" mismatches="<<x.page_hash_mismatch_count<<"\n";std::size_t shown=0;for(const auto&ph:x.page_hashes){if(ph.match)continue;if(shown++>=32){o<<"      ...\n";break;}o<<"      signed_off=0x"<<std::hex<<ph.signed_file_offset<<" current_off=0x"<<ph.current_file_offset<<" rva=0x"<<ph.current_rva<<std::dec<<" region="<<ph.region<<" offset_match="<<(ph.offset_match?"true":"false")<<" digest_match="<<(ph.digest_match?"true":"false")<<"\n";}if(!x.page_hash_error.empty())o<<"      page-hash warning: "<<x.page_hash_error<<"\n";}
                for(std::size_t si=0;si<x.signers.size();++si){const auto&sg=x.signers[si];o<<"    signer["<<si<<"] id="<<sg.identifier_type<<" serial="<<sg.serial<<" digest="<<sg.digest_algorithm<<" signature="<<sg.signature_algorithm<<(sg.certificate_matched?" cert=matched":" cert=unmatched");if(!sg.signing_time.empty())o<<" signing_time="<<sg.signing_time;if(sg.countersignature_count)o<<" countersignatures="<<sg.countersignature_count;if(sg.rfc3161_timestamp_count)o<<" rfc3161_timestamps="<<sg.rfc3161_timestamp_count;o<<"\n";if(sg.certificate_matched&&sg.certificate_index>=0&&std::size_t(sg.certificate_index)<x.certificates.size()){const auto&c=x.certificates[std::size_t(sg.certificate_index)];o<<"      subject: "<<c.subject<<"\n"<<"      issuer: "<<c.issuer<<"\n"<<"      valid: "<<c.not_before<<" .. "<<c.not_after<<"\n"<<"      cert_sha256: "<<c.sha256_fingerprint<<" role="<<c.role_hint;if(c.extended_key_usage_present)o<<" eku_critical="<<(c.extended_key_usage_critical?"true":"false");o<<"\n";}for(std::size_t ti=0;ti<sg.timestamps.size();++ti){const auto&t=sg.timestamps[ti];o<<"      timestamp["<<ti<<"] "<<t.kind<<" state="<<t.state;if(!t.gen_time.empty())o<<" gen_time="<<t.gen_time;if(!t.policy.empty())o<<" policy="<<t.policy;if(!t.message_imprint_algorithm.empty())o<<" imprint="<<t.message_imprint_algorithm<<':'<<t.message_imprint;if(t.message_imprint_binding_checked)o<<" signature_binding="<<(t.message_imprint_matches_signature_value?"MATCH":"MISMATCH");if(!t.serial.empty())o<<" serial="<<t.serial;o<<"\n";if(t.signer_certificate_matched){o<<"        TSA subject: "<<t.signer_subject<<"\n"<<"        TSA issuer: "<<t.signer_issuer<<"\n"<<"        TSA serial: "<<t.signer_serial<<" cert_sha256="<<t.signer_certificate_sha256<<" role="<<t.signer_role_state<<"\n";}if(!t.error.empty())o<<"        timestamp warning: "<<t.error<<"\n";}}
                if(!x.signer_metadata_error.empty())o<<"    signer metadata warning: "<<x.signer_metadata_error<<"\n";
                if(!x.error.empty())o<<"    warning: "<<x.error<<"\n";
            }
            if(!a.error.empty())o<<"  error: "<<a.error<<"\n";
            o<<"  signer cryptographic/trust verification: not performed by the cross-platform static digest layer\n";
        }
        if (r.pe.tls.present || r.pe.exception.present || r.pe.init.has_crt_section || r.pe.init.references_initterm) {
            o << "Pre-entry / initialization:\n";
            if(r.pe.tls.present){o<<"  TLS directory RVA=0x"<<std::hex<<r.pe.tls.directory_rva<<std::dec<<" callbacks="<<r.pe.tls.callback_vas.size()<<"\n";for(auto va:r.pe.tls.callback_vas)o<<"    TLS callback VA=0x"<<std::hex<<va<<std::dec<<"\n";}
            if(r.pe.exception.present){o<<"  Exception directory RVA=0x"<<std::hex<<r.pe.exception.rva<<std::dec<<" size="<<r.pe.exception.size<<" runtime_functions="<<r.pe.exception.runtime_function_count<<" handlers="<<r.pe.exception.handler_rvas.size()<<"\n";std::size_t hn=0;for(auto h:r.pe.exception.handler_rvas){if(hn++>=32){o<<"    handler ...\n";break;}o<<"    handler RVA=0x"<<std::hex<<h<<std::dec<<"\n";}}
            for(const auto&x:r.pe.init.crt_sections)o<<"  CRT section: "<<x<<"\n";
            if(r.pe.init.references_initterm)o<<"  CRT initializer helper reference: _initterm"<<(r.pe.init.references_initterm_e?" / _initterm_e":"")<<"\n";
        }
    } else if (r.elf.valid) {
        o << "Format: " << (r.elf.elf64 ? "ELF64" : "ELF32") << ' '
          << elf_machine_name(r.elf.machine) << ' ' << elf_type_name(r.elf.type) << "\n"
          << "Endian: " << (r.elf.little_endian ? "little" : "big") << "\n"
          << "Entry: 0x" << std::hex << r.elf.entry << std::dec << "\n";
        if (!r.elf.interpreter.empty()) o << "Interpreter: " << r.elf.interpreter << "\n";
        o << "ELF ordinary dynamic: state=" << r.elf.dynamic.state << " symbols=" << r.elf.dynamic.symbols.size() << " relocations=" << r.elf.dynamic.relocations.size() << "\n";
        if(!r.elf.dynamic.error.empty())o<<"  dynamic error: "<<r.elf.dynamic.error<<"\n";
        if (!r.elf.needed.empty()){o<<"Needed libraries:";for(const auto&n:r.elf.needed)o<<" "<<n;o<<"\n";}
        o << "Program headers: " << r.elf.program_header_count << ", section headers: " << r.elf.section_header_count << "\n";
        if(!r.elf.segments.empty()){o<<"Segments:\n  Type Flags Address          Offset      File        Memory      Entropy\n";for(const auto&seg:r.elf.segments){o<<"  "<<std::setw(4)<<seg.type<<" 0x"<<std::hex<<std::setw(2)<<seg.flags<<" "<<std::setw(16)<<seg.address<<"  "<<std::setw(10)<<seg.offset<<"  "<<std::setw(10)<<seg.file_size<<"  "<<std::setw(10)<<seg.memory_size<<std::dec<<"  "<<std::fixed<<std::setprecision(3)<<seg.entropy<<"\n";}}
        o << "Sections:\n"
          << "  Name               Address           Offset      Size        Used        Entropy Flags\n";
        for (const auto& sec : r.elf.sections) {
            o << "  " << std::left << std::setw(18) << sec.name << std::right
              << std::hex << std::setw(16) << sec.address << "  "
              << std::setw(10) << sec.offset << "  "
              << std::setw(10) << sec.size << "  "
              << std::setw(10) << sec.used_size << std::dec << "  "
              << std::fixed << std::setprecision(3) << std::setw(7) << sec.entropy
              << " 0x" << std::hex << sec.flags << std::dec << "\n";
        }
        if (r.elf.overlay_size) {
            o << "Overlay: offset=0x" << std::hex << r.elf.overlay_offset << std::dec
              << " size=" << r.elf.overlay_size << "\n";
        }
        if (!r.elf.init.arrays.empty() || r.elf.init.has_init || r.elf.init.has_fini || r.elf.init.has_ctors || r.elf.init.has_dtors || r.elf.init.dt_init || r.elf.init.dt_fini) {
            o << "Pre-entry / initialization:\n";
            if(r.elf.init.has_init) o<<"  section .init present\n";
            if(r.elf.init.has_fini) o<<"  section .fini present\n";
            if(r.elf.init.has_ctors) o<<"  section .ctors present\n";
            if(r.elf.init.has_dtors) o<<"  section .dtors present\n";
            for(const auto&a:r.elf.init.arrays){o<<"  "<<a.kind<<" address=0x"<<std::hex<<a.address<<std::dec<<" entries="<<a.entries.size()<<"\n";for(auto v:a.entries)o<<"    entry=0x"<<std::hex<<v<<std::dec<<"\n";}
            if(r.elf.init.dt_init) o<<"  DT_INIT=0x"<<std::hex<<r.elf.init.dt_init<<std::dec<<"\n";
            if(r.elf.init.dt_fini) o<<"  DT_FINI=0x"<<std::hex<<r.elf.init.dt_fini<<std::dec<<"\n";
            if(r.elf.init.dt_preinit_array)o<<"  DT_PREINIT_ARRAY=0x"<<std::hex<<r.elf.init.dt_preinit_array<<std::dec<<" size="<<r.elf.init.dt_preinit_arraysz<<"\n";
            if(r.elf.init.dt_init_array)o<<"  DT_INIT_ARRAY=0x"<<std::hex<<r.elf.init.dt_init_array<<std::dec<<" size="<<r.elf.init.dt_init_arraysz<<"\n";
            if(r.elf.init.dt_fini_array)o<<"  DT_FINI_ARRAY=0x"<<std::hex<<r.elf.init.dt_fini_array<<std::dec<<" size="<<r.elf.init.dt_fini_arraysz<<"\n";
        }
        if(r.elf_extract.success||!r.elf_extract.error.empty()){
            o<<"ELF dynamic extraction: "<<(r.elf_extract.success?"EXTRACTED_VALIDATED":"UNAVAILABLE")<<"\n";
            if(r.elf_extract.success)o<<"  symbols CSV: "<<path_utf8(r.elf_extract.symbols_csv)<<" ("<<r.elf_extract.symbol_count<<")\n  relocations CSV: "<<path_utf8(r.elf_extract.relocations_csv)<<" ("<<r.elf_extract.relocation_count<<")\n";
            if(!r.elf_extract.error.empty())o<<"  error: "<<r.elf_extract.error<<"\n";
        }
        if(r.elf_unwind_extract.success||!r.elf_unwind_extract.error.empty()){
            o<<"ELF unwind extraction: "<<(r.elf_unwind_extract.success?"EXTRACTED_VALIDATED":"UNAVAILABLE")<<"\n";
            if(r.elf_unwind_extract.success)o<<"  CIE CSV: "<<path_utf8(r.elf_unwind_extract.cies_csv)<<" ("<<r.elf_unwind_extract.cie_count<<")\n  FDE CSV: "<<path_utf8(r.elf_unwind_extract.fdes_csv)<<" ("<<r.elf_unwind_extract.fde_count<<")\n";
            if(!r.elf_unwind_extract.error.empty())o<<"  error: "<<r.elf_unwind_extract.error<<"\n";
        }
    } else if (r.macho.valid) {
        o << "Format: Mach-O";
        if(r.macho.fat)o<<" Universal"<<(r.macho.fat64?"64":"")<<" slices="<<r.macho.slices.size();
        o<<"\n";
        o<<"File-offset basis: "<<path_utf8(r.artifact.offset_basis)<<" (current input artifact)\n";
        o<<"Slice policy: "<<r.macho.slice_policy<<" selected="<<r.macho.selected_slice<<" (architecture inventory only)\n";
        for(std::size_t si=0;si<r.macho.slices.size();++si){
            const auto&m=r.macho.slices[si];
            o<<"Slice "<<si<<": "<<(m.macho64?"Mach-O64":"Mach-O32")<<' '<<macho_cpu_name(m.cpu_type)<<' '<<macho_filetype_name(m.filetype)<<" endian="<<(m.little_endian?"little":"big")<<" file_off=0x"<<std::hex<<m.slice_offset<<std::dec<<" size="<<m.slice_size<<"\n";
            o<<"  Architecture: "<<m.architecture<<" subtype_base="<<m.cpu_subtype_base;
            if(m.arm64e)o<<" ptrauth_versioned="<<(m.ptrauth_versioned?"true":"false")<<" ptrauth_kernel="<<(m.ptrauth_kernel?"true":"false")<<" ptrauth_abi_version="<<m.ptrauth_abi_version;
            o<<"\n  Coverage: "<<m.coverage_state<<" load_commands="<<m.load_command_coverage_state<<" retained="<<m.load_commands.size()<<"/"<<m.load_command_count<<(m.load_commands_truncated?" truncated":"")<<"\n";
            for(const auto& command:m.unknown_load_commands)o<<"    Unknown load command cmd=0x"<<std::hex<<command.command<<" offset=0x"<<command.offset<<std::dec<<" size="<<command.size<<"\n";
            if(m.unknown_load_commands_truncated)o<<"    Unknown load commands truncated: retained="<<m.unknown_load_commands.size()<<" total="<<m.unknown_load_command_count<<"\n";
            for(const auto& reason:m.coverage_reasons)o<<"    coverage reason: "<<reason<<"\n";
            if(m.bitcode_present)o<<"  Bitcode: "<<m.bitcode_state<<" (__LLVM,__bundle inventory only)\n";
            o<<"  Code signature state: "<<m.code_signature_state<<"\n";
            if(m.entry_file_offset)o<<"  Entry file offset=0x"<<std::hex<<m.entry_file_offset<<" VA=0x"<<m.entry_va<<std::dec<<"\n";
            if(m.platform)o<<"  Build: "<<macho_platform_name(m.platform)<<" min="<<macho_version_string(m.min_os)<<" sdk="<<macho_version_string(m.sdk)<<"\n";
            if(!m.uuid.empty())o<<"  UUID: "<<m.uuid<<"\n";
            if(m.code_signature)o<<"    blob offset=0x"<<std::hex<<m.code_signature_offset<<std::dec<<" size="<<m.code_signature_size<<" (cryptographic verification not performed)\n";
            if(m.crypt_size)o<<"  Encryption info: cryptid="<<m.cryptid<<" offset=0x"<<std::hex<<m.crypt_offset<<std::dec<<" size="<<m.crypt_size<<(m.encrypted?" encrypted":" not-encrypted")<<"\n";
            if(!m.dylibs.empty()){o<<"  Dylibs:";for(const auto&x:m.dylibs)o<<" "<<x;o<<"\n";}
            o<<"  Sections:\n";for(const auto&sec:m.sections)o<<"    "<<sec.segment<<','<<sec.name<<" VA=0x"<<std::hex<<sec.address<<" off=0x"<<sec.offset<<std::dec<<" size="<<sec.size<<" used="<<sec.used_size<<" entropy="<<std::fixed<<std::setprecision(3)<<sec.entropy<<" flags=0x"<<std::hex<<sec.flags<<std::dec<<"\n";
            if(!m.symbols.empty()){o<<"  Symbols: "<<m.symbols.size()<<"\n";std::size_t shown=0;for(const auto&x:m.symbols){if(shown++>=80){o<<"    ...\n";break;}o<<"    "<<(x.defined?"defined":"undefined")<<(x.external?" external":"")<<(x.private_external?" private-external":"")<<" VA=0x"<<std::hex<<x.value;if(x.file_offset)o<<" file_off=0x"<<x.file_offset;o<<std::dec<<" "<<x.name<<"\n";}}
            if(m.swift.present){
                o<<"  Swift metadata: "<<m.swift.state<<" evidence="<<m.swift.evidence_level<<" coverage="<<m.swift.coverage_state<<" source_or_semantic_recovery="<<m.swift.source_or_semantic_recovery<<"\n";
                for(const auto& section:m.swift.sections)o<<"    section "<<section.segment<<','<<section.name<<" off=0x"<<std::hex<<section.offset<<std::dec<<" size="<<section.size<<" state="<<section.state<<"\n";
                for(const auto& type:m.swift.types){
                    o<<"    "<<type.kind<<' '<<type.module_name<<'.'<<type.type_name;
                    if(type.mangled_type_plain_text)o<<" mangled_text="<<type.mangled_type_name;
                    else if(type.mangled_type_present)o<<" mangled_bytes_sha256="<<type.mangled_type_sha256<<" byte_length="<<type.mangled_type_byte_length<<" symbolic_references="<<type.mangled_type_symbolic_references;
                    else o<<" mangled=absent";
                    o<<" fields="<<type.fields.size()<<"\n";
                    for(const auto& field:type.fields){o<<"      "<<field.name;
                        if(field.mangled_type_plain_text)o<<" : "<<field.mangled_type_name;
                        else if(field.mangled_type_present)o<<" : bytes_sha256="<<field.mangled_type_sha256<<" byte_length="<<field.mangled_type_byte_length<<" symbolic_references="<<field.mangled_type_symbolic_references;
                        else o<<" : mangled_type=absent";
                        o<<" flags=0x"<<std::hex<<field.flags<<std::dec<<"\n";}
                }
                o<<"    budgets: types="<<m.swift.type_records_used<<"/4096 field_descriptors="<<m.swift.field_descriptors_used<<"/4096 fields="<<m.swift.field_records_used<<"/65536 pointers="<<m.swift.relative_pointers_used<<"/131072 strings="<<m.swift.strings_used<<"/65536 string_bytes="<<m.swift.string_bytes_used<<"/4194304\n";
                o<<"    outcomes: complete_type_closures="<<m.swift.complete_type_closures<<" type_skipped="<<m.swift.type_records_skipped<<" type_partial="<<m.swift.type_records_partial<<" type_unsupported="<<m.swift.type_records_unsupported<<" field_descriptors_skipped="<<m.swift.field_descriptors_skipped<<" field_descriptors_partial="<<m.swift.field_descriptors_partial<<" fields_skipped="<<m.swift.field_records_skipped<<" fields_partial="<<m.swift.field_records_partial<<" mangled_absent="<<m.swift.mangled_type_names_absent<<" mangled_symbolic="<<m.swift.mangled_type_names_symbolic<<"\n";
                if(!m.swift.error.empty())o<<"    Swift coverage reason: "<<m.swift.error<<"\n";
            }
            if(!m.function_starts.empty()){o<<"  Function starts: "<<m.function_starts.size()<<"\n";std::size_t shown=0;for(const auto&x:m.function_starts){if(shown++>=120){o<<"    ...\n";break;}o<<"    VA=0x"<<std::hex<<x.address<<" file_off=0x"<<x.file_offset<<std::dec;if(!x.symbol.empty())o<<" "<<x.symbol;o<<"\n";}}
            if(m.routine_init_address||!m.init_functions.empty()||!m.term_functions.empty()||!m.thread_init_functions.empty()){o<<"  Pre-entry / initialization:\n";if(m.routine_init_address)o<<"    LC_ROUTINES init=0x"<<std::hex<<m.routine_init_address<<std::dec<<"\n";for(auto x:m.init_functions)o<<"    init=0x"<<std::hex<<x<<std::dec<<"\n";for(auto x:m.thread_init_functions)o<<"    thread-init=0x"<<std::hex<<x<<std::dec<<"\n";for(auto x:m.term_functions)o<<"    term=0x"<<std::hex<<x<<std::dec<<"\n";}
        }
    } else if (r.python_bytecode.valid) {
        o << "Format: CPython bytecode " << r.python_bytecode.magic.version_family << " .pyc\n"
          << "  magic: " << r.python_bytecode.magic.magic_number << " (minor-family authenticated; patch ambiguous)\n"
          << "  header: " << r.python_bytecode.header_kind << " marshal_offset=" << r.python_bytecode.marshal_offset << "\n"
          << "  marshal: objects=" << r.python_bytecode.marshal.object_count << " code_objects=" << r.python_bytecode.marshal.code_object_count << " root_code_bytes=" << r.python_bytecode.root.code.size() << "\n";
    } else {
        o << "Format: unknown (" << r.pe.error << "; " << r.elf.error << "; " << r.macho.error << ")\n";
    }

    if (r.golang.valid) {
        o << "Go runtime:\n"
          << "  state: " << (r.golang.functions.empty()?"LIKELY":"CONFIRMED") << "\n"
          << "  version: " << (r.golang.version.empty()?"unknown":r.golang.version) << "\n"
          << "  module: " << (r.golang.module_path.empty()?"(none/legacy)":r.golang.module_path) << "\n"
          << "  pclntab: layout=" << r.golang.pclntab_layout << " file_off=0x" << std::hex << r.golang.pclntab_offset << " va=0x" << r.golang.pclntab_va << " text_base=0x" << r.golang.pclntab_text_base << std::dec
          << " text_base_source=" << r.golang.pclntab_text_base_source << " ptr=" << r.golang.pointer_size << " quantum=" << r.golang.quantum << "\n"
          << "  functions recovered: " << r.golang.functions.size() << "\n"
          << "  runtime types recovered: " << r.golang.types.size() << "\n";
        if(r.golang.moduledata_va)o<<"  moduledata: va=0x"<<std::hex<<r.golang.moduledata_va<<" types=0x"<<r.golang.types_va<<" typelinks=0x"<<r.golang.typelinks_va<<std::dec<<" count="<<r.golang.typelinks_count<<" layout="<<r.golang.moduledata_layout<<"\n";
        if(!r.golang.modules.empty()){o<<"  modules:";std::size_t mn=0;for(const auto&m:r.golang.modules){if(mn++>=20){o<<" ...";break;}o<<" "<<m;}o<<"\n";}
        std::size_t shown=0;for(const auto&f:r.golang.functions){if(!f.user_like)continue;if(shown++==0)o<<"  user/module functions:\n";if(shown>100){o<<"    ...\n";break;}o<<"    RVA 0x"<<std::hex<<f.start_rva<<"-0x"<<f.end_rva<<std::dec<<" "<<f.name<<"\n";}
        shown=0;for(const auto&t:r.golang.types){if(!t.user_like)continue;if(shown++==0)o<<"  user/runtime types:\n";if(shown>100){o<<"    ...\n";break;}o<<"    VA 0x"<<std::hex<<t.va<<std::dec<<" "<<t.kind<<" "<<t.name<<" size="<<t.size<<"\n";for(const auto&sf:t.fields)o<<"      +"<<sf.offset<<" "<<sf.name<<" "<<sf.type_name<<(sf.embedded?" embedded":"")<<(sf.tag.empty()?"":" tag=`"+sf.tag+"`")<<"\n";}
        if(r.golang_extract.success){o<<"  symbols CSV: "<<path_utf8(r.golang_extract.symbols_csv)<<" ("<<r.golang_extract.symbol_count<<")\n";if(!r.golang_extract.types_csv.empty())o<<"  types CSV: "<<path_utf8(r.golang_extract.types_csv)<<" ("<<r.golang_extract.type_count<<")\n";}
        if(!r.golang.type_error.empty())o<<"  type warning: "<<r.golang.type_error<<"\n";
        if(!r.golang.error.empty())o<<"  warning: "<<r.golang.error<<"\n";
    }

    if(r.cpython_static.valid){
        const auto&x=r.cpython_static;std::size_t static_type_methods=0,runtime_type_methods=0;for(const auto&t:x.cython.types){static_type_methods+=t.methods.size();runtime_type_methods+=t.runtime_methods.size();}
        o<<"CPython static composition:\n  state: "<<x.state<<"\n";
        if(x.runtime.valid)o<<"  runtime: version="<<x.runtime.version<<" reference="<<x.runtime.reference_status<<" semantic="<<x.runtime.semantic_reference_status<<"\n";
        o<<"  extension: state="<<x.extension.state<<" modules="<<x.extension.modules.size()<<" PyInit_exports="<<x.extension.pyinit_export_count<<" inittab="<<x.extension.inittab.size()<<"\n";
        std::size_t shown_modules=0,shown_methods=0;for(const auto&m:x.extension.modules){if(shown_modules++>=8)break;o<<"    module "<<(m.module_name.empty()?m.registration_name:m.module_name)<<" source="<<m.registration_source<<" init_rva=0x"<<std::hex<<m.init_rva<<" moduledef_rva=0x"<<m.moduledef_rva<<std::dec<<" state="<<m.state<<" methods="<<m.methods.size()<<" slots="<<m.slots.size()<<"\n";for(const auto&q:m.methods){if(shown_methods>=24)break;o<<"      method "<<q.name<<" callback_rva=0x"<<std::hex<<q.callback_rva<<std::dec<<" flags="<<q.flags<<"\n";++shown_methods;}}
        if(x.extension.modules.size()>8)o<<"    ... "<<(x.extension.modules.size()-8)<<" more extension modules\n";
        if(shown_methods>=24)o<<"    ... extension method callback sample capped at 24\n";
        o<<"  Cython: state="<<x.cython.state<<" functions="<<x.cython.functions.size()<<" types="<<x.cython.types.size()<<" static_type_methods="<<static_type_methods<<" runtime_type_methods="<<runtime_type_methods<<" c_api_exports="<<x.cython.c_api_exports.size()<<"\n";
        for(std::size_t i=0;i<x.cython.functions.size()&&i<12;++i){const auto&f=x.cython.functions[i];o<<"    function "<<f.name<<" callback_rva=0x"<<std::hex<<f.callback_rva<<std::dec<<" source="<<f.source<<"\n";}
        for(std::size_t i=0;i<x.cython.types.size()&&i<6;++i){const auto&t=x.cython.types[i];o<<"    type "<<t.name<<" type_rva=0x"<<std::hex<<t.type_rva<<std::dec<<" methods="<<t.methods.size()<<" runtime_methods="<<t.runtime_methods.size()<<"\n";}
        for(std::size_t i=0;i<x.cython.c_api_exports.size()&&i<8;++i){const auto&q=x.cython.c_api_exports[i];o<<"    C-API "<<q.name<<" callback_rva=0x"<<std::hex<<q.callback_rva<<std::dec<<" "<<q.signature<<"\n";}
        o<<"  frozen: state="<<x.frozen.state<<" raw="<<x.frozen.raw_module_count<<" deep="<<x.frozen.deep_frozen_module_count<<" unavailable="<<x.frozen.unavailable_module_count<<"\n"
         <<"  frozen reference: gate="<<x.frozen_reference_gate.state<<" allowed="<<(x.frozen_reference_gate.allowed?"true":"false")<<" match="<<x.frozen.reference_match_count<<" diff="<<x.frozen.reference_diff_count<<" unavailable="<<x.frozen.reference_unavailable_count<<"\n"
         <<"  priority: "<<x.priority.preferred_target<<" mismatches="<<x.priority.mismatch_count<<"\n";
        for(std::size_t i=0;i<x.priority.candidates.size()&&i<8;++i){const auto&c=x.priority.candidates[i];o<<"    candidate "<<c.module<<" file_offset=0x"<<std::hex<<c.file_offset<<" rva=0x"<<c.rva<<std::dec<<" size="<<c.size<<" reference="<<c.reference_version<<"\n";}
        if(x.priority.candidates_truncated||x.priority.candidates.size()>8)o<<"    ... priority candidates truncated\n";
    }

    for (const auto &cp : r.cpython_runtimes) {
        o << "CPython runtime:\n"
          << "  state: CONFIRMED\n"
          << "  source: " << cp.source << "\n"
          << "  version: " << cp.version << " (0x" << std::hex << cp.version_hex << std::dec << ")\n"
          << "  size: " << cp.file_size << "\n"
          << "  sha256: " << cp.sha256 << "\n"
          << "  exports: " << cp.named_export_count << "\n"
          << "  reference: " << cp.reference_status << "\n"
          << "  semantic reference: " << cp.semantic_reference_status;
        if(cp.semantic_probe_count)o<<" probes="<<cp.semantic_probe_count<<" median_coverage="<<std::fixed<<std::setprecision(3)<<cp.semantic_probe_median;
        o<<"\n";
        if (cp.exact_reference_available) {
            auto delta=static_cast<std::int64_t>(cp.file_size)-static_cast<std::int64_t>(cp.reference_size);
            o << "  official reference: " << cp.reference_version << " size=" << cp.reference_size << " delta=" << (delta>=0?"+":"") << delta << "\n";
            if(cp.reference_status=="DIFFERS_FROM_OFFICIAL_REFERENCE"){
                o << "  section differences:\n";
                for(const auto&x:cp.section_diffs){o<<"    "<<x.name<<" target_v="<<x.target_virtual<<" ref_v="<<x.reference_virtual<<" delta_v="<<(x.virtual_delta>=0?"+":"")<<x.virtual_delta<<" target_raw="<<x.target_raw<<" ref_raw="<<x.reference_raw<<" delta_raw="<<(x.raw_delta>=0?"+":"")<<x.raw_delta<<"\n";}
                o << "  export differences: added="<<cp.added_exports.size()<<" missing="<<cp.missing_exports.size()<<"\n";
                std::size_t n=0;for(const auto&e:cp.added_exports){if(n++>=20){o<<"    + ...\n";break;}o<<"    + "<<e<<"\n";}n=0;for(const auto&e:cp.missing_exports){if(n++>=20){o<<"    - ...\n";break;}o<<"    - "<<e<<"\n";}
            }
        }
        if(!cp.function_diffs.empty()){
            o<<"  semantic probes:\n";
            for(const auto&fd:cp.function_diffs){o<<"    "<<fd.state<<" "<<fd.name<<" RVA=0x"<<std::hex<<fd.target_rva<<std::dec<<" coverage="<<std::fixed<<std::setprecision(3)<<fd.reference_coverage<<" blocks="<<fd.matched_blocks<<"/"<<fd.reference_blocks<<" ref, target="<<fd.target_blocks<<"\n";if(fd.state=="MODIFIED_CANDIDATE")for(const auto&diff_range:fd.changed_ranges)o<<"      diff RVA=0x"<<std::hex<<diff_range.offset<<std::dec<<" size="<<diff_range.size<<" "<<diff_range.label<<"\n";}
        }
        if(!cp.text_reference_status.empty()){o<<"  text reference: "<<cp.text_reference_status;if(cp.text_chunks_reference)o<<" chunks="<<cp.text_chunks_matched<<"/"<<cp.text_chunks_reference<<" ratio="<<std::fixed<<std::setprecision(3)<<cp.text_chunk_match_ratio;o<<"\n";}
        if(!cp.region_diffs.empty()){o<<"  native region differences:\n";for(const auto&region_diff:cp.region_diffs)o<<"    "<<region_diff.kind<<" "<<region_diff.section<<" RVA=0x"<<std::hex<<region_diff.rva<<std::dec<<" size="<<region_diff.size<<" "<<region_diff.detail<<"\n";}
        if(!cp.new_region_xrefs.empty()){o<<"  incoming references to new executable regions:\n";for(const auto&x:cp.new_region_xrefs)o<<"    "<<x.kind<<" RVA=0x"<<std::hex<<x.source_rva<<" -> 0x"<<x.target_rva<<std::dec<<" size="<<x.size<<"\n";}
        if(cp.compiler_probe.attempted){o<<"  compiler probe: "<<cp.compiler_probe.state<<" launched="<<(cp.compiler_probe.launched?"yes":"no")<<" code_objects="<<cp.compiler_probe.code_objects<<" code_units="<<cp.compiler_probe.code_units<<" observed_opcodes="<<cp.compiler_probe.observed_opcodes<<" changed_opcodes="<<cp.compiler_probe.changed_opcodes<<"\n";for(const auto&m:cp.compiler_probe.mappings)if(m.target_opcode!=m.reference_opcode)o<<"    compiler opcode "<<m.target_opcode<<" -> official "<<m.reference_opcode<<" observations="<<m.observations<<"\n";if(!cp.compiler_probe.error.empty())o<<"    error: "<<cp.compiler_probe.error<<"\n";}
        if(cp.dispatch.attempted){
            o<<"  opcode dispatch: "<<cp.dispatch.state;
            if(cp.dispatch.table_found)o<<" table_rva=0x"<<std::hex<<cp.dispatch.table_rva<<std::dec<<" first_opcode="<<cp.dispatch.table_first_opcode<<" entry_count="<<cp.dispatch.table_entry_count<<" unique_handlers="<<cp.dispatch.unique_handler_count;
            if(!cp.dispatch.reference_status.empty())o<<" reference="<<cp.dispatch.reference_status;
            if(!cp.dispatch.reference_version.empty())o<<" ref_version="<<cp.dispatch.reference_version;
            o<<"\n";
            if(cp.dispatch.table_found&&!cp.dispatch.reference_status.empty())o<<"    slots_match="<<cp.dispatch.slot_matches<<" permuted="<<cp.dispatch.permuted_slots<<" handler_modified="<<cp.dispatch.handler_modified<<" semantic_mapped="<<cp.dispatch.semantic_mapped<<" ambiguous="<<cp.dispatch.ambiguous<<" unmapped="<<cp.dispatch.unmapped<<"\n";
            for(const auto&m:cp.dispatch.mappings){if(m.state=="SLOT_MATCH")continue;o<<"    opcode "<<m.target_opcode<<" "<<m.state<<" target=0x"<<std::hex<<m.target_handler_rva<<" expected=0x"<<m.expected_handler_rva<<std::dec;if(!m.reference_names.empty()){o<<" official=";for(std::size_t z=0;z<m.reference_names.size();++z){if(z)o<<'|';o<<m.reference_opcodes[z]<<':'<<m.reference_names[z];}}o<<"\n";}
        }
    }

    if(r.godot_legacy_config.valid){
        const auto&c=r.godot_legacy_config;
        o<<"Godot legacy engine.cfb:\n  state: CONFIRMED\n  application: "<<c.application_name<<"\n  main_scene: "<<c.main_scene<<"\n  properties: "<<c.property_count<<" remaps="<<c.remaps.size()<<" autoloads="<<c.autoloads.size()<<"\n";
        for(std::size_t i=0;i<c.remaps.size()&&i<16;++i)o<<"    remap "<<c.remaps[i].source<<" -> "<<c.remaps[i].target<<"\n";
        for(std::size_t i=0;i<c.autoloads.size()&&i<16;++i)o<<"    autoload "<<c.autoloads[i].name<<" -> "<<(c.autoloads[i].singleton?"*":"")<<c.autoloads[i].path<<"\n";
    }

    if(r.gdextension_descriptor.valid){
        const auto&d=r.gdextension_descriptor;o<<"Godot GDExtension descriptor:\n  state: CONFIRMED\n  entry_symbol: "<<d.entry_symbol<<"\n  compatibility_minimum: "<<d.compatibility_minimum<<"\n  libraries: "<<d.libraries.size()<<"\n";
        for(std::size_t i=0;i<d.libraries.size()&&i<16;++i)o<<"    "<<d.libraries[i].feature_key<<" -> "<<d.libraries[i].path<<"\n";
        if(d.libraries.size()>16)o<<"    ... "<<(d.libraries.size()-16)<<" more\n";
    }

    if (r.godot.valid) {
        o << "Godot PCK:\n"
          << "  state: " << (r.godot.validated?"CONFIRMED":"LIKELY") << "\n"
          << "  offset: 0x" << std::hex << r.godot.pck_offset << std::dec << (r.godot.modified_magic?" (magic modified)":"") << "\n"
          << "  format: v" << r.godot.format_version << "\n"
          << "  engine: " << r.godot.engine_major << '.' << r.godot.engine_minor << '.' << r.godot.engine_patch << "\n"
          << "  flags: 0x" << std::hex << r.godot.flags << std::dec << " encrypted_directory=" << (r.godot.encrypted_directory?"yes":"no") << "\n"
          << "  file_count: " << r.godot.file_count << "\n";
        if(r.godot.key.found){const auto&k=r.godot.key;o<<"  key: "<<godot_key_hex(k)<<"  state="<<godot_key_state(k)<<" decryption_validated="<<(k.confirmed?"yes":"no")<<" candidates="<<k.native_candidate_count<<" attempts="<<k.candidate_validation_attempts<<" probes="<<k.encrypted_probe_count<<" scripts="<<k.validated_script_count<<'/'<<k.encrypted_script_count<<(k.candidate_budget_exhausted?" candidate-budget-exhausted":"")<<(k.script_validation_truncated?" script-validation-truncated":"")<<"\n"<<"  key anchor: "<<k.anchor<<"\n";if(!k.validated_script_path.empty())o<<"  validated encrypted script: "<<k.validated_script_path<<"\n";}
        for(std::size_t i=0;i<r.godot.entries.size()&&i<40;i++){const auto&e=r.godot.entries[i];o<<"    "<<e.path<<" off=0x"<<std::hex<<e.offset<<std::dec<<" size="<<e.size<<(e.encrypted?" encrypted":"")<<"\n";}
        if(r.godot.entries.size()>40)o<<"    ... "<<(r.godot.entries.size()-40)<<" more\n";
        if(r.godot.gdextension_descriptor_candidates){
            o<<"Godot GDExtension:\n  state: "<<r.godot.gdextension_state<<" descriptors="<<r.godot.gdextension_descriptor_candidates<<" processed="<<r.godot.gdextension_descriptor_processed<<" limited="<<(r.godot.gdextension_analysis_limited?"yes":"no")<<" bundles="<<r.godot.gdextension_bundle_valid_count<<" native="<<r.godot.gdextension_native_analyzed_count<<" links="<<r.godot.gdextension_script_links.size()<<" ambiguous_links="<<r.godot.gdextension_script_link_ambiguous_count<<"\n";
            for(std::size_t bi=0;bi<r.godot.gdextensions.size()&&bi<8;++bi){const auto&b=r.godot.gdextensions[bi];o<<"  descriptor "<<b.descriptor_path<<" state="<<b.state;if(!b.descriptor.entry_symbol.empty())o<<" entry="<<b.descriptor.entry_symbol;if(!b.error.empty())o<<" error="<<b.error;o<<"\n";auto text_libs=gdextension_render_libraries(b,8);for(const auto*lp:text_libs){const auto&l=*lp;if(!l.exact_path_match&&!l.native_analyzed)continue;o<<"    library "<<l.feature_key<<" "<<(l.matched_child_path.empty()?l.normalized_declared_path:l.matched_child_path)<<" state="<<l.state;if(l.native_analyzed)o<<" entry_rva=0x"<<std::hex<<l.native.entry_rva<<" resolver_rva=0x"<<l.native.resolver_function_rva<<std::dec;o<<"\n";for(std::size_t ci=0;ci<l.native.classes.size()&&ci<8;++ci){const auto&c=l.native.classes[ci];o<<"      class "<<c.class_name;if(!c.parent_class_name.empty())o<<" : "<<c.parent_class_name;o<<" state="<<c.evidence_state<<" call_rva=0x"<<std::hex<<c.registration_call_rva<<std::dec<<"\n";}for(std::size_t mi=0;mi<l.native.methods.size()&&mi<16;++mi){const auto&m=l.native.methods[mi];o<<"      method "<<m.class_name<<'.'<<m.method_name<<" state="<<m.evidence_state<<" call_rva=0x"<<std::hex<<m.registration_call_rva<<std::dec;if(m.method_flags_known)o<<" flags=0x"<<std::hex<<m.method_flags<<std::dec;if(m.argument_count_known)o<<" argc="<<m.argument_count;if(m.has_return_value_known)o<<" has_return="<<(m.has_return_value?"true":"false");if(m.return_variant_type_known)o<<" return="<<m.return_variant_type_name;if(m.return_value_metadata_known)o<<" return_meta="<<m.return_value_metadata;if(m.method_userdata_known)o<<" userdata=0x"<<std::hex<<m.method_userdata_va<<std::dec;if(m.call_func_known)o<<" call_func=0x"<<std::hex<<m.call_func_va<<std::dec;if(m.ptrcall_func_known)o<<" ptrcall_func=0x"<<std::hex<<m.ptrcall_func_va<<std::dec;o<<" bridges="<<m.bridge_candidates.size();if(m.argument_types_complete){o<<" args=[";for(std::size_t ai=0;ai<m.argument_variant_type_names.size();++ai){if(ai)o<<',';o<<m.argument_variant_type_names[ai];if(m.argument_metadata_complete&&ai<m.argument_metadata.size())o<<":"<<m.argument_metadata[ai];}o<<']';}o<<"\n";}}}
            if(r.godot.gdextensions.size()>8)o<<"  ... "<<(r.godot.gdextensions.size()-8)<<" more descriptors\n";
            for(std::size_t si=0;si<r.godot.gdextension_script_links.size()&&si<16;++si){const auto&x=r.godot.gdextension_script_links[si];o<<"  script_link "<<x.script_path<<" "<<x.base_class<<'.'<<x.method_name<<" -> "<<x.descriptor_path<<" / "<<x.library_path<<" registration="<<x.registration_state<<" call_rva=0x"<<std::hex<<x.registration_call_rva<<std::dec<<" bridges="<<x.bridge_candidate_count;if(x.effective_line_known)o<<" line="<<x.effective_line;o<<"\n";}
            if(r.godot.gdextension_script_links.size()>16)o<<"  ... "<<(r.godot.gdextension_script_links.size()-16)<<" more script links\n";
        }
    }
    if (r.godot_extract.success || !r.godot_extract.error.empty()) {
        o << "Godot extraction:\n  status: " << (r.godot_extract.success?"EXTRACTED_VALIDATED":"FAILED") << "\n";
        if(r.godot_extract.success)o<<"  output: "<<path_utf8(r.godot_extract.output_dir)<<"\n  files: "<<r.godot_extract.files.size()<<"\n";
        if(!r.godot_extract.error.empty())o<<"  error: "<<r.godot_extract.error<<"\n";
        for(const auto&w:r.godot_extract.warnings)o<<"  warning: "<<w<<"\n";
    }

    if (r.pyinstaller.valid) {
        o << "PyInstaller CArchive:\n"
          << "  state: CONFIRMED\n"
          << "  cookie: 0x" << std::hex << r.pyinstaller.cookie_offset << std::dec << (r.pyinstaller.heuristic_cookie?" (recovered; magic modified/absent)":"") << "\n"
          << "  archive: off=0x" << std::hex << r.pyinstaller.archive_start << std::dec << " size=" << r.pyinstaller.archive_length << "\n"
          << "  python: " << (r.pyinstaller.python_version>=100?r.pyinstaller.python_version/100:r.pyinstaller.python_version/10) << '.' << (r.pyinstaller.python_version>=100?r.pyinstaller.python_version%100:r.pyinstaller.python_version%10) << "\n"
          << "  runtime: " << r.pyinstaller.python_library << "\n"
          << "  entries: " << r.pyinstaller.entries.size() << "\n";
        if(!r.pyinstaller.bootstrap_reference_status.empty()){
            o<<"  bootstrap reference: "<<r.pyinstaller.bootstrap_reference_status;
            if(!r.pyinstaller.bootstrap_profile.empty())o<<" profile="<<r.pyinstaller.bootstrap_profile;
            if(!r.pyinstaller.bootstrap_reference_label.empty())o<<" reference="<<r.pyinstaller.bootstrap_reference_label;
            if(!r.pyinstaller.bootstrap_match_mode.empty())o<<" mode="<<r.pyinstaller.bootstrap_match_mode;
            o<<"\n";
            for(const auto&m:r.pyinstaller.bootstrap_modules){o<<"    "<<m.name<<": "<<m.state;if(!m.reference_label.empty())o<<" "<<m.reference_label;if(!m.semantic_error.empty())o<<" error=+0x"<<std::hex<<m.semantic_error_offset<<std::dec<<" "<<m.semantic_error;o<<"\n";}
        }
        for(const auto&e:r.pyinstaller.entries){if(e.typecode=='s'||e.typecode=='m'||e.typecode=='M'||e.typecode=='z')o<<"    ["<<e.typecode<<"] "<<e.name<<" off=0x"<<std::hex<<e.offset<<std::dec<<" size="<<e.compressed_size<<(e.compression_flag?" zlib":"")<<"\n";}
    }
    if (r.pyinstaller_extract.success || !r.pyinstaller_extract.error.empty()) {
        const auto&x=r.pyinstaller_extract;o << "PyInstaller extraction:\n  status: " << (x.budget_exhausted?"PARTIAL":(x.success?"EXTRACTED_VALIDATED":"FAILED")) << " mode="<<(x.mode==PyInstExtractMode::AutoCore?"AUTO_CORE":"BULK_EXPLICIT")<<"\n";
        if(x.success){o<<"  output: "<<path_utf8(x.output_dir)<<"\n  files: "<<x.files.size()<<" bytes="<<x.output_bytes<<" user="<<x.user_files<<" bootstrap="<<x.bootstrap_files<<" runtime="<<x.runtime_files<<" bulk="<<x.bulk_files<<"\n  PYZ: entries="<<x.pyz_entry_count<<" materialized="<<x.pyz_selected_count<<"\n";if(!x.carchive_inventory.empty())o<<"  CArchive inventory: "<<path_utf8(x.carchive_inventory)<<"\n";if(!x.pyz_inventory.empty())o<<"  PYZ inventory: "<<path_utf8(x.pyz_inventory)<<"\n";if(x.normalized_files)o<<"  normalized_pyc: "<<x.normalized_files<<" code_units_rewritten="<<x.normalized_code_units<<" target_preserved="<<x.target_preserved_files<<"\n";if(x.policy_omitted_count)o<<"  bulk explicit only: files="<<x.policy_omitted_count<<" bytes="<<x.policy_omitted_bytes<<"\n";if(x.omitted_count)o<<"  budget omitted: files="<<x.omitted_count<<" bytes="<<x.omitted_bytes<<"\n";}
        if(!x.error.empty())o<<"  error: "<<x.error<<"\n";
        for(const auto&w:x.warnings)o<<"  warning: "<<w<<"\n";
    }

    if (r.crypto.valid) {
        o << "Crypto key-use recovery:\n";
        for(const auto&x:r.crypto.uses){
            o<<"  "<<x.algorithm<<" state="<<x.state<<" function_rva=0x"<<std::hex<<x.function_rva<<std::dec<<" key_arg="<<x.key_arg;
            if(x.callsite_rva)o<<" callsite_rva=0x"<<std::hex<<x.callsite_rva<<std::dec;
            if(!x.api_source.empty())o<<" api="<<x.api_source;
            if(!x.mode.empty())o<<" mode="<<x.mode;
            if(!x.operation.empty())o<<" operation="<<x.operation;
            if(!x.key_length_arg.empty())o<<" key_length_arg="<<x.key_length_arg;
            if(x.key_length_resolved)o<<" key_length="<<x.key_length;
            o<<"\n";
            o<<"    evidence: delta="<<x.delta_constants<<" shift4="<<x.shift4<<" shift5="<<x.shift5<<" xor="<<x.xor_ops<<" addsub="<<x.addsub_ops<<" back_edges="<<x.back_edges<<" fixed_key_offsets="<<x.fixed_key_offsets<<" dynamic_key_accesses="<<x.dynamic_key_accesses<<"\n";
            if(x.key_resolved){o<<"    key: ";if(x.key_rva)o<<"rva=0x"<<std::hex<<x.key_rva<<std::dec<<" ";o<<"size="<<x.key_size<<" section="<<x.key_section<<" source="<<x.key_source<<" hex="<<x.key_hex<<"\n";}if(x.iv_resolved){o<<"    iv: ";if(x.iv_rva)o<<"rva=0x"<<std::hex<<x.iv_rva<<std::dec<<" ";o<<"size="<<x.iv_size<<" section="<<x.iv_section<<" source="<<x.iv_source<<" hex="<<x.iv_hex<<"\n";}
        }
    }

    if (r.autoit.valid) {
        o << "AutoIt:\n"
          << "  state: CONFIRMED\n"
          << "  version: " << r.autoit.version << "\n"
          << "  container: " << r.autoit.container << " marker=" << (r.autoit.standard_marker?"standard":"modified/absent") << "\n"
          << "  stream: off=0x" << std::hex << r.autoit.stream_offset << " end=0x" << r.autoit.stream_end << std::dec << "\n"
          << "  records: " << r.autoit.records.size() << " pseudo=" << r.autoit.pseudo_records << "\n";
        if(!r.autoit.resource_name.empty())o<<"  resource: "<<r.autoit.resource_type<<"/"<<r.autoit.resource_name<<"\n";
        if(r.autoit.script_found){o<<"  script: "<<(r.autoit.script_tokenized?"tokenized":"text")<<" lines="<<r.autoit.token_lines<<" token_bytes="<<r.autoit.token_bytes<<" state="<<(r.autoit.token_valid?"REFERENCE_COMPATIBLE":"CUSTOM_OPCODE_CANDIDATE")<<"\n";if(!r.autoit.token_error.empty())o<<"  token error: decoded+0x"<<std::hex<<r.autoit.token_error_offset<<std::dec<<" "<<r.autoit.token_error<<"\n";}
        if(!r.autoit.script_source.empty()){o<<"  script preview:\n";std::istringstream src(r.autoit.script_source.substr(0,2048));std::string line;int n=0;while(n<12&&std::getline(src,line)){if(!line.empty()&&line.back()=='\r')line.pop_back();o<<"    "<<line<<"\n";++n;}if(src.good()||r.autoit.script_source.size()>2048)o<<"    ...\n";}
        for(const auto&x:r.autoit.records)o<<"    ["<<x.kind<<"] "<<x.output_name<<" stored="<<x.compressed_size<<" output="<<x.output_size<<(x.compressed?" compressed":"")<<(x.compressed&&!x.compressed_magic_standard?" modified-compression-magic":"")<<"\n";
    }
    if (r.autoit_extract.success || !r.autoit_extract.error.empty()) {
        o << "AutoIt extraction:\n  status: " << (r.autoit_extract.success?"EXTRACTED_VALIDATED":"FAILED") << "\n";
        if(r.autoit_extract.success)o<<"  output: "<<path_utf8(r.autoit_extract.output_dir)<<"\n  files: "<<r.autoit_extract.files.size()<<" records_verified="<<r.autoit_extract.records_verified<<" resources="<<r.autoit_extract.resources_written<<" scripts="<<r.autoit_extract.scripts_written<<"\n";
        if(!r.autoit_extract.error.empty())o<<"  error: "<<r.autoit_extract.error<<"\n";
        for(const auto&w:r.autoit_extract.warnings)o<<"  warning: "<<w<<"\n";
    }

    if (r.asar.valid) {
        o << "Electron ASAR:\n"
          << "  state: CONFIRMED\n"
          << "  header: size=" << r.asar.header_size << " data_offset=0x" << std::hex << r.asar.data_offset << std::dec << "\n"
          << "  files: " << r.asar.file_count << " packed=" << r.asar.packed_file_count << " unpacked=" << r.asar.unpacked_file_count << " dirs=" << r.asar.directory_count << " links=" << r.asar.link_count << "\n"
          << "  integrity entries: " << r.asar.integrity_count << "\n";
        if(!r.asar.package_name.empty()){o<<"  package: "<<r.asar.package_name;if(!r.asar.package_version.empty())o<<" "<<r.asar.package_version;o<<"\n";}
        if(!r.asar.package_main.empty()){o<<"  main: "<<r.asar.package_main;if(!r.asar.package_main_resolved.empty())o<<" -> "<<r.asar.package_main_resolved;o<<"\n";}
        if(r.asar.trailing_bytes)o<<"  trailing bytes: "<<r.asar.trailing_bytes<<"\n";
        if(!r.asar.interesting_paths.empty()){o<<"  priority paths:\n";for(std::size_t i=0;i<r.asar.interesting_paths.size()&&i<16;i++)o<<"    "<<r.asar.interesting_paths[i]<<"\n";if(r.asar.interesting_paths.size()>16)o<<"    ... "<<(r.asar.interesting_paths.size()-16)<<" more\n";}
    }
    if (r.asar_extract.success || !r.asar_extract.error.empty()) {
        o << "ASAR extraction:\n  status: " << (r.asar_extract.success?"EXTRACTED_VALIDATED":"FAILED") << "\n";
        if(r.asar_extract.success)o<<"  output: "<<path_utf8(r.asar_extract.output_dir)<<"\n  packed_files: "<<r.asar_extract.packed_files<<" unpacked_files: "<<r.asar_extract.unpacked_files<<" links_skipped: "<<r.asar_extract.links_skipped<<"\n  integrity_verified: "<<r.asar_extract.integrity_verified<<" mismatches: "<<r.asar_extract.integrity_mismatches<<"\n";
        if(!r.asar_extract.error.empty())o<<"  error: "<<r.asar_extract.error<<"\n";
        for(const auto&w:r.asar_extract.warnings)o<<"  warning: "<<w<<"\n";
    }

    if (r.unity.valid || r.unity.metadata_valid) {
        const auto&u=r.unity;
        o<<"Unity:\n  state: "<<((u.metadata_valid||u.mono||u.unity_player_import)?"CONFIRMED":(u.valid?"LIKELY":"FAILED"))<<"\n"
         <<"  backend: "<<u.backend_state<<" IL2CPP="<<(u.il2cpp?"true":"false")<<" Mono="<<(u.mono?"true":"false")<<"\n"
         <<"  evidence: UnityPlayer_import="<<(u.unity_player_import?"true":"false")<<" il2cpp_exports="<<(u.il2cpp_export_evidence?"true":"false")<<" il2cpp_strings="<<(u.il2cpp_string_evidence?"true":"false")<<" metadata="<<(u.metadata_valid?"validated":"not_validated")<<"\n";
        if(!u.metadata_valid){
            if(!u.managed_path.empty())o<<"  managed payload: "<<path_utf8(u.managed_path)<<"\n";
            if(!u.mono_runtime_path.empty())o<<"  Mono runtime: "<<path_utf8(u.mono_runtime_path)<<"\n";
            if(!u.error.empty())o<<"  note: "<<u.error<<"\n";
        }else{
        o<<"  metadata_version="<<u.metadata_version<<" layout="<<u.metadata_layout<<"\n"
         <<"  CodeRegistration: resolved="<<(u.registration_resolved?"true":"false")<<" VA=0x"<<std::hex<<u.code_registration_va<<" modules=0x"<<u.codegen_modules_va<<std::dec<<" module_count="<<u.codegen_module_count<<" mapped_methods="<<u.mapped_method_count<<" variant="<<u.registration_variant<<"\n"
         <<"  MetadataRegistration: resolved="<<(u.metadata_registration_resolved?"true":"false")<<" VA=0x"<<std::hex<<u.metadata_registration_va<<std::dec<<" profile="<<u.metadata_registration_profile<<" registered_types="<<(u.registered_types_resolved?"validated":"failed")<<':'<<u.registered_type_count<<" field_offsets="<<u.field_offset_type_count<<" runtime_only="<<u.field_offset_runtime_only_type_count<<" type_sizes="<<u.type_size_type_count<<"\n"
         <<"  Members: metadata="<<(u.member_metadata_valid?"validated":"failed")<<" fields="<<u.metadata_field_count<<" params="<<u.metadata_parameter_count<<" signatures="<<(u.member_signatures_resolved?"resolved":"failed")<<" field_types="<<u.resolved_field_type_count<<" param_types="<<u.resolved_parameter_type_count<<" methods="<<u.resolved_method_signature_count<<"\n"
         <<"  Managed strings: state="<<(u.string_literals_valid?"validated":"failed")<<" count="<<u.string_literal_count<<" bytes="<<u.string_literal_total_bytes<<" empty="<<u.string_literal_empty_count<<" invalid_utf8="<<u.string_literal_invalid_utf8_count<<" max_length="<<u.string_literal_max_length<<" record_size="<<u.string_literal_record_size<<"\n"
         <<"  Metadata usages: state="<<u.metadata_usage_state<<" profile="<<u.metadata_usage_profile<<" usages="<<u.metadata_usage_count<<" declared="<<u.metadata_usage_declared_count<<" effective_storage="<<u.metadata_usage_effective_storage_count<<" pair_refs="<<u.metadata_usage_pair_reference_count<<" file_backed="<<u.metadata_usage_file_backed_storage_count<<" max_refs="<<u.metadata_usage_max_reference_count<<" kinds="<<u.metadata_usage_typeinfo_count<<'/'<<u.metadata_usage_type_count<<'/'<<u.metadata_usage_methoddef_count<<'/'<<u.metadata_usage_field_count<<'/'<<u.metadata_usage_string_count<<'/'<<u.metadata_usage_methodref_count<<'/'<<u.metadata_usage_field_rva_count<<" runtime="<<u.runtime_metadata_usage_count<<" eager="<<u.always_init_metadata_usage_count<<" wrappers="<<u.runtime_metadata_wrapper_count<<"\n"
         <<"  Method bounds: state="<<u.method_bounds_state<<" profile="<<u.method_bounds_profile<<" bounded="<<u.method_bound_count<<" unbounded="<<u.method_unbound_count<<" bodies="<<u.native_body_count<<" alias_extra="<<u.native_alias_extra_count<<" max_alias="<<u.native_max_alias_count<<"\n"
         <<"  P/Invoke: state="<<u.pinvoke_state<<" profile="<<u.pinvoke_profile<<" methods="<<u.pinvoke_method_count<<" resolved="<<u.pinvoke_resolved_count<<" unresolved="<<u.pinvoke_unresolved_count<<" resolver=0x"<<std::hex<<u.pinvoke_resolver_va<<std::dec<<"\n"
         <<"  Metadata xrefs: state="<<u.metadata_xrefs_state<<" profile="<<u.metadata_xrefs_profile<<" relations="<<u.metadata_xref_relation_count<<" init_sites="<<u.metadata_xref_instruction_count<<" methods="<<u.metadata_xref_method_count<<" slots="<<u.metadata_xref_slot_count<<" initializer=0x"<<std::hex<<u.runtime_metadata_initializer_va<<std::dec<<"\n"
         <<"  Default values: state="<<u.default_values_state<<" profile="<<u.default_values_profile<<" rows="<<u.default_values.size()<<" field_constants="<<u.field_constant_count<<" parameter_defaults="<<u.parameter_default_count<<" field_rva="<<u.field_rva_sized_count<<'/'<<u.field_rva_count<<" decoded="<<u.decoded_default_count<<" unresolved="<<u.unresolved_default_count<<" null="<<u.null_default_count<<" dummy="<<u.default_dummy_count<<" data_bytes="<<u.default_data_size<<"\n"
         <<"  Generic parameters: metadata="<<(u.generic_parameter_metadata_valid?"validated":"failed")<<" containers="<<u.generic_container_count<<" parameters="<<u.generic_parameter_count<<" constraints="<<u.resolved_generic_constraint_count<<'/'<<u.generic_constraint_count<<"\n"
         <<"  Generics: resolved="<<(u.generic_insts_resolved?"true":"false")<<" insts="<<u.generic_inst_count<<" type_args="<<u.generic_type_arg_count<<" max_argc="<<u.generic_max_argc<<" classes="<<(u.generic_classes_resolved?"validated":"failed")<<':'<<u.generic_class_count<<" unique="<<u.generic_class_unique_struct_count<<" methods="<<u.generic_methods_state<<':'<<u.generic_method_record_count<<" native="<<u.generic_method_native_count<<" method_specs="<<u.method_spec_count<<"\n"
         <<"  RGCTX: state="<<u.rgctx_state<<" profile="<<u.rgctx_profile<<" modules="<<u.rgctx_module_with_data_count<<'/'<<u.rgctx_module_count<<" ranges="<<u.rgctx_range_count<<" entries="<<u.rgctx_resolved_entry_count<<'/'<<u.rgctx_entry_count<<" constrained="<<u.rgctx_constrained_count<<"\n";
        if(u.metadata_version==108)o<<"  MethodDef dispatch: state="<<u.method_dispatch_state<<" profile="<<u.method_dispatch_profile<<" methods="<<u.method_dispatch_method_count<<" invokers="<<u.method_invoker_resolved_count<<" missing="<<u.method_invoker_missing_count<<" adjustors="<<u.method_adjustor_count<<" static_init="<<u.static_init_with_cctor_count<<'/'<<u.static_init_type_count<<"\n";
        if(!u.metadata_registration_pairs.empty()){o<<"  MetadataRegistration pairs:\n";for(const auto&p:u.metadata_registration_pairs)o<<"    "<<p.role<<" count="<<p.count<<" pointer=0x"<<std::hex<<p.pointer_va<<std::dec<<"\n";}
        for(std::size_t i=0;i<u.string_literals.size()&&i<8;++i){const auto&x=u.string_literals[i];const auto keep=std::min<std::size_t>(x.value.size(),128);o<<"  string_literal["<<x.index<<"] current-file+0x"<<std::hex<<x.data_file_offset<<std::dec<<" len="<<x.length<<" utf8="<<(x.utf8_valid?"valid":"invalid")<<" value=\""<<esc(x.value.substr(0,keep))<<(x.value.size()>keep?"...":"")<<"\"\n";}
        {bool shown_usage_kind[8]={false,false,false,false,false,false,false,false};for(const auto&x:u.metadata_usages){if(x.usage_kind<1||x.usage_kind>7||shown_usage_kind[x.usage_kind])continue;shown_usage_kind[x.usage_kind]=true;const auto keep=std::min<std::size_t>(x.resolved.size(),128);o<<"  metadata_usage["<<x.index<<"] "<<x.usage_name<<" dest="<<x.destination_index<<" source="<<x.source_index<<" refs="<<x.reference_count<<" storage=0x"<<std::hex<<x.storage_va<<std::dec<<(x.storage_file_backed?" file-backed":" virtual-only")<<(x.runtime_discovered?" runtime-discovered":"")<<(x.always_init?" eager":"")<<" init_sites="<<x.init_site_count<<" resolved=\""<<esc(x.resolved.substr(0,keep))<<(x.resolved.size()>keep?"...":"")<<"\"\n";}}
        {bool kind_seen[8]={false,false,false,false,false,false,false,false};std::size_t shown_xrefs=0;for(const auto&x:u.metadata_xrefs){if(x.usage_index>=u.metadata_usages.size())continue;const auto&mu=u.metadata_usages[x.usage_index];const bool representative=mu.usage_kind>=1&&mu.usage_kind<=7&&!kind_seen[mu.usage_kind];if(!representative&&shown_xrefs>=8)continue;if(representative)kind_seen[mu.usage_kind]=true;const auto keep=std::min<std::size_t>(mu.resolved.size(),128);o<<"  metadata_xref body=0x"<<std::hex<<x.body_rva<<"..0x"<<x.body_end_rva<<" site=0x"<<x.first_instruction_rva<<std::dec<<" method["<<x.method_index<<"] "<<x.method<<" -> "<<mu.usage_name<<'['<<mu.source_index<<"] slot=0x"<<std::hex<<mu.storage_va<<std::dec<<" refs="<<x.xref_count<<" aliases="<<x.alias_count<<" resolved=\""<<esc(mu.resolved.substr(0,keep))<<(mu.resolved.size()>keep?"...":"")<<"\"\n";++shown_xrefs;if(shown_xrefs>=12)break;}}
        {std::size_t shown=0;bool shown_resolved=false,shown_unresolved=false;for(const auto&x:u.pinvokes){const bool special=(x.resolved&&!shown_resolved)||(!x.resolved&&!shown_unresolved);if(!special&&shown>=8)continue;if(x.resolved)shown_resolved=true;else shown_unresolved=true;o<<"  pinvoke["<<x.method_index<<"] "<<x.method<<" state="<<x.state<<" flags=0x"<<std::hex<<x.method_flags<<" impl=0x"<<x.impl_flags<<std::dec;if(x.resolved)o<<" "<<x.module<<'!'<<x.entry<<" charset="<<x.charset<<" cc="<<x.calling_convention<<" params="<<x.parameter_size<<" no_mangle="<<(x.no_mangle?"true":"false")<<" resolver=0x"<<std::hex<<x.resolver_va<<" call=0x"<<x.resolver_call_rva<<" cache=0x"<<x.cache_va<<std::dec;else if(!x.error.empty())o<<" error="<<x.error;o<<"\n";++shown;if(shown>=12&&shown_resolved&&shown_unresolved)break;}}
        {bool shown_field=false,shown_param=false,shown_rva=false,shown_string=false,shown_null=false;std::size_t shown_defaults=0;for(const auto&x:u.default_values){const bool special=(!shown_field&&x.record_kind=="field_constant")||(!shown_param&&x.record_kind=="parameter_default")||(!shown_rva&&x.record_kind=="field_rva")||(!shown_string&&x.value_type=="System.String"&&x.value_resolved&&!x.data_index_null)||(!shown_null&&x.data_index_null);if(!special&&shown_defaults>=8)continue;if(x.record_kind=="field_constant")shown_field=true;if(x.record_kind=="parameter_default")shown_param=true;if(x.record_kind=="field_rva")shown_rva=true;if(x.value_type=="System.String"&&x.value_resolved&&!x.data_index_null)shown_string=true;if(x.data_index_null)shown_null=true;const auto keep=std::min<std::size_t>(x.value.size(),128);o<<"  default["<<x.index<<"] "<<x.record_kind<<" "<<x.owner_name<<" declared="<<x.declared_type<<" value_type="<<x.value_type;if(x.data_index_null)o<<" value=null";else if(x.value_resolved&&!x.value.empty())o<<" value=\""<<esc(x.value.substr(0,keep))<<(x.value.size()>keep?"...":"")<<"\"";if(x.data_size)o<<" bytes="<<x.data_size;if(!x.blob_preview_hex.empty())o<<" blob="<<x.blob_preview_hex;o<<"\n";++shown_defaults;if(shown_defaults>=12&&shown_field&&shown_param&&shown_rva&&shown_string&&shown_null)break;}}
        std::size_t shown_types=0;for(const auto&t:u.types){if(!(t.type_sizes_resolved||t.field_offsets_resolved||t.field_offsets_runtime_only||t.field_offsets_pointer_va))continue;if(shown_types++==0)o<<"  Recovered layouts:\n";if(shown_types>24){o<<"    ...\n";break;}auto state=t.field_count==0?"no_fields":t.field_offsets_resolved?"resolved":t.field_offsets_runtime_only?"runtime_only":t.field_offsets_pointer_va?"unresolved":"null_pointer";o<<"    ["<<t.index<<"] "<<t.full_name<<" fields="<<t.field_count<<" state="<<state;if(t.type_sizes_resolved)o<<" instance="<<t.instance_size<<" native="<<t.native_size<<" static="<<t.static_fields_size<<" thread_static="<<t.thread_static_fields_size;if(t.field_offsets_resolved){o<<" offsets=";for(std::size_t z=0;z<t.field_offsets.size()&&z<16;++z){if(z)o<<',';o<<t.field_offsets[z];}if(t.field_offsets.size()>16)o<<",...";}o<<"\n";}
        for(std::size_t i=0;i<u.fields.size()&&i<16;++i){const auto&f=u.fields[i];o<<"  field["<<f.index<<"] "<<f.full_name<<" : "<<f.type_name;if(f.offset_resolved)o<<" offset="<<f.offset;else if(f.offset_runtime_only)o<<" offset=runtime_only";o<<"\n";}
        for(std::size_t i=0;i<u.methods.size()&&i<12;++i){const auto&m=u.methods[i];o<<"  method["<<m.index<<"] "<<(m.signature.empty()?m.full_name:m.signature);if(m.rva)o<<" RVA=0x"<<std::hex<<m.rva<<std::dec;if(m.native_bound_resolved)o<<" native_end=0x"<<std::hex<<m.native_end_rva<<std::dec<<" size="<<m.native_size<<" aliases="<<m.native_alias_count;o<<" flags=0x"<<std::hex<<m.flags<<" impl=0x"<<m.impl_flags<<std::dec<<" slot="<<m.vtable_slot;if(m.pinvoke_impl)o<<" P/Invoke";if(m.invoker_resolved)o<<" invoker=0x"<<std::hex<<m.invoker_rva<<std::dec;if(m.adjustor_thunk_resolved)o<<" adjustor=0x"<<std::hex<<m.adjustor_thunk_rva<<std::dec;o<<"\n";}
        {std::size_t shown_static=0;for(const auto&t:u.types){if(!t.static_init_listed)continue;if(shown_static++>=8){o<<"  static_init: ...\n";break;}o<<"  static_init["<<t.index<<"] "<<t.full_name;if(t.static_constructor_resolved)o<<" .cctor_method="<<t.static_constructor_method_index<<" RVA=0x"<<std::hex<<t.static_constructor_rva<<std::dec;else o<<" no_resolved_cctor";o<<"\n";}}
        for(std::size_t i=0;i<u.generic_containers.size()&&i<8;++i){const auto&c=u.generic_containers[i];o<<"  generic_container["<<c.index<<"] "<<(c.is_method?"method":"type")<<" owner="<<c.owner_name<<" params="<<c.parameter_count<<" start="<<c.parameter_start<<"\n";}
        for(std::size_t i=0;i<u.generic_parameters.size()&&i<12;++i){const auto&g=u.generic_parameters[i];o<<"  generic_parameter["<<g.index<<"] "<<g.name<<" owner="<<g.owner_container<<" ordinal="<<g.number<<" flags=0x"<<std::hex<<g.flags<<std::dec;if(!g.constraints.empty()){o<<" constraints=";for(std::size_t z=0;z<g.constraints.size()&&z<6;++z){if(z)o<<',';o<<g.constraints[z];}if(g.constraints.size()>6)o<<",...";}o<<"\n";}
        for(std::size_t i=0;i<u.generic_insts.size()&&i<12;++i){const auto&g=u.generic_insts[i];o<<"  generic["<<g.index<<"] argc="<<g.argc<<" VA=0x"<<std::hex<<g.va<<std::dec<<" args=";for(std::size_t z=0;z<g.args.size()&&z<8;++z){if(z)o<<',';o<<(g.args[z].resolved_name.empty()?g.args[z].type_name:g.args[z].resolved_name);}if(g.args.size()>8)o<<",...";o<<"\n";}
        for(std::size_t i=0;i<u.generic_classes.size()&&i<12;++i){const auto&g=u.generic_classes[i];o<<"  generic_class["<<g.index<<"] "<<g.type_full_name<<" typedef="<<g.type_definition_index<<" class_inst="<<g.class_inst_index<<" type_code="<<unsigned(g.type_code)<<" VA=0x"<<std::hex<<g.va<<std::dec<<(g.duplicate_struct?" duplicate_ref":"")<<"\n";}
        for(std::size_t i=0;i<u.generic_methods.size()&&i<12;++i){const auto&g=u.generic_methods[i];o<<"  generic_method["<<g.index<<"] "<<g.method_full_name<<" spec="<<g.method_spec_index<<" method_def="<<g.method_definition_index<<" native_rva=0x"<<std::hex<<g.method_rva<<" invoker_rva=0x"<<g.invoker_rva<<" adjustor_rva=0x"<<g.adjustor_thunk_rva<<std::dec<<"\n";}
        std::size_t shown_rgctx=0;for(const auto&m:u.codegen_modules){if(!m.rgctx_entry_count)continue;if(shown_rgctx++>=6){o<<"  rgctx: ...\n";break;}o<<"  rgctx_module["<<m.index<<"] "<<m.name<<" ranges="<<m.rgctx_range_count<<" entries="<<m.rgctx_entry_count<<"\n";for(std::size_t z=0;z<m.ranges.size()&&z<3;++z)o<<"    range["<<m.ranges[z].index<<"] token=0x"<<std::hex<<m.ranges[z].token<<std::dec<<" "<<m.ranges[z].owner_kind<<' '<<m.ranges[z].owner_name<<" entries="<<m.ranges[z].start<<'+'<<m.ranges[z].length<<"\n";for(std::size_t z=0;z<m.entries.size()&&z<5;++z)o<<"    entry["<<m.entries[z].index<<"] "<<m.entries[z].kind_name<<" "<<m.entries[z].resolved<<"\n";}
        if(!u.registration_error.empty())o<<"  CodeRegistration warning: "<<u.registration_error<<"\n";
        if(!u.metadata_registration_error.empty())o<<"  MetadataRegistration warning: "<<u.metadata_registration_error<<"\n";
        if(!u.registered_types_error.empty())o<<"  registered types warning: "<<u.registered_types_error<<"\n";
        if(!u.member_metadata_error.empty())o<<"  member metadata warning: "<<u.member_metadata_error<<"\n";
        if(!u.member_signatures_error.empty())o<<"  member signature warning: "<<u.member_signatures_error<<"\n";
        if(!u.generic_parameter_metadata_error.empty())o<<"  generic parameter metadata warning: "<<u.generic_parameter_metadata_error<<"\n";
        if(!u.generic_parameter_constraints_error.empty())o<<"  generic constraint warning: "<<u.generic_parameter_constraints_error<<"\n";
        if(!u.generic_insts_error.empty())o<<"  generic warning: "<<u.generic_insts_error<<"\n";
        if(!u.generic_classes_error.empty())o<<"  generic classes warning: "<<u.generic_classes_error<<"\n";
        if(!u.generic_methods_error.empty())o<<"  generic methods: "<<u.generic_methods_state<<" "<<u.generic_methods_error<<"\n";
        if(!u.rgctx_error.empty())o<<"  RGCTX: "<<u.rgctx_state<<" "<<u.rgctx_error<<"\n";
        if(!u.string_literals_error.empty())o<<"  managed strings warning: "<<u.string_literals_error<<"\n";
        if(u.metadata_usage_state!="NOT_PRESENT_V27_PLUS"&&!u.metadata_usage_error.empty())o<<"  metadata usages: "<<u.metadata_usage_state<<" "<<u.metadata_usage_error<<"\n";
        if(!u.default_values_error.empty())o<<"  default values: "<<u.default_values_state<<" "<<u.default_values_error<<"\n";
        if(!u.method_bounds_error.empty())o<<"  method bounds: "<<u.method_bounds_state<<" "<<u.method_bounds_error<<"\n";
        if(u.pinvoke_state!="NOT_PRESENT"&&!u.pinvoke_error.empty())o<<"  P/Invoke: "<<u.pinvoke_state<<" "<<u.pinvoke_error<<"\n";
        if(u.metadata_xrefs_state!="NOT_AVAILABLE_LEGACY"&&!u.metadata_xrefs_error.empty())o<<"  metadata xrefs: "<<u.metadata_xrefs_state<<" "<<u.metadata_xrefs_error<<"\n";
        if(!u.method_dispatch_error.empty())o<<"  MethodDef dispatch: "<<u.method_dispatch_state<<" "<<u.method_dispatch_error<<"\n";
        if(r.unity_extract.success||r.unity_extract.budget_exhausted||!r.unity_extract.error.empty()){o<<"  extraction: "<<(r.unity_extract.budget_exhausted?"PARTIAL":(r.unity_extract.success?"success":"failed"))<<" rows="<<r.unity_extract.materialized_rows<<" row_budget="<<r.unity_extract.row_budget<<" callgraph_requested="<<(r.unity_extract.callgraph_requested?"yes":"no")<<" symbols="<<path_utf8(r.unity_extract.symbols_csv)<<" layouts="<<path_utf8(r.unity_extract.layouts_csv)<<" generics="<<path_utf8(r.unity_extract.generics_csv)<<" rgctx="<<path_utf8(r.unity_extract.rgctx_csv)<<" strings="<<path_utf8(r.unity_extract.strings_csv)<<" string_rows="<<r.unity_extract.string_row_count<<" usages="<<path_utf8(r.unity_extract.usages_csv)<<" usage_rows="<<r.unity_extract.usage_row_count<<" defaults="<<path_utf8(r.unity_extract.defaults_csv)<<" default_rows="<<r.unity_extract.default_row_count<<" xrefs="<<path_utf8(r.unity_extract.xrefs_csv)<<" xref_rows="<<r.unity_extract.xref_row_count<<" pinvokes="<<path_utf8(r.unity_extract.pinvoke_csv)<<" pinvoke_rows="<<r.unity_extract.pinvoke_row_count<<" callgraph="<<path_utf8(r.unity_extract.callgraph_csv)<<" call_edges="<<r.unity_extract.call_edge_count<<" call_bodies="<<r.unity_extract.callgraph_body_count<<" partial_bodies="<<r.unity_extract.callgraph_partial_body_count<<" unresolved_direct="<<r.unity_extract.callgraph_unresolved_direct_count<<" unresolved_indirect="<<r.unity_extract.callgraph_unresolved_indirect_count<<(r.unity_extract.callgraph_error.empty()?"":(" callgraph_error="+r.unity_extract.callgraph_error))<<"\n";if(!r.unity_extract.omitted_planes.empty()){o<<"  Unity AUTO_ANALYSIS omitted whole planes:";for(const auto&x:r.unity_extract.omitted_planes)o<<' '<<x;o<<"\n";}}
        }
    }

    if (r.dart.candidate || r.dart.valid) {
        o << "Dart:\n"
          << "  state: " << (r.dart.valid?"CONFIRMED":"FAILED") << "\n"
          << "  offset_space: current_input_file\n";
        if(r.dart.aot.valid){const auto&a=r.dart.aot;o<<"  variant: "<<a.variant<<" arch="<<a.architecture<<" standalone="<<(a.standalone?"true":"false")<<" flutter_symbols="<<(a.flutter_symbols?"true":"false")<<" dynsym="<<a.dynamic_symbol_count<<"\n";if(!a.build_id_hex.empty())o<<"  build-id: "<<a.build_id_hex<<"\n";o<<"  target symbols: "<<a.symbols.size()<<" snapshots="<<a.snapshots.size()<<"\n";for(std::size_t z=0;z<a.symbols.size()&&z<16;++z){const auto&x=a.symbols[z];o<<"    "<<x.name<<" VA 0x"<<std::hex<<x.value<<" current-file+0x"<<x.file_offset<<std::dec<<" size="<<x.size<<"\n";}if(a.symbols.size()>16)o<<"    ... "<<(a.symbols.size()-16)<<" more symbols\n";for(std::size_t z=0;z<a.snapshots.size()&&z<8;++z){const auto&x=a.snapshots[z];o<<"    snapshot["<<z<<"] "<<x.kind_name<<" current-file+0x"<<std::hex<<x.file_offset<<std::dec<<" len="<<x.length<<" hash="<<x.snapshot_hash<<" features="<<x.features<<"\n";}for(const auto&x:a.anomalies)o<<"  warning: "<<x<<"\n";}
        if(r.dart.kernel.valid){const auto&k=r.dart.kernel;o<<"  Kernel: version="<<k.format_version<<" libraries="<<k.library_count<<" size="<<k.component_file_size<<" index=current-file+0x"<<std::hex<<k.component_index_offset<<" strings=current-file+0x"<<k.string_table_offset<<std::dec<<"\n"<<"  deep metadata: supported="<<(k.deep_metadata_supported?"true":"false")<<" complete="<<(k.deep_metadata_complete?"true":"false")<<" sdk_hash="<<k.sdk_hash<<" strings="<<k.string_count<<" constants="<<k.constant_count<<" sources="<<k.source_count<<" canonical="<<k.canonical_name_count<<"\n";if(!k.deep_metadata_error.empty())o<<"  deep metadata warning: current-file+0x"<<std::hex<<k.deep_metadata_error_offset<<std::dec<<" "<<k.deep_metadata_error<<"\n";for(std::size_t z=0;z<k.sources.size()&&z<16;++z){const auto&x=k.sources[z];o<<"    source["<<x.index<<"] "<<x.uri<<" code=current-file+0x"<<std::hex<<x.source_code_offset<<std::dec<<"+"<<x.source_code_size<<" lines="<<x.line_count<<" coverage_refs="<<x.coverage_reference_count<<"\n";}for(std::size_t z=0;z<k.canonical_names.size()&&z<48;++z){const auto&x=k.canonical_names[z];if(!x.path.empty())o<<"    canonical["<<x.index<<"] current-file+0x"<<std::hex<<x.file_offset<<std::dec<<" "<<x.path<<(x.path_truncated?" [truncated]":"")<<"\n";}for(std::size_t z=0;z<k.constants.size()&&z<32;++z){const auto&x=k.constants[z];o<<"    constant["<<x.index<<"] "<<x.tag_name;if(x.simple_value_decoded)o<<" value="<<x.value;o<<" current-file+0x"<<std::hex<<x.file_offset<<"..0x"<<x.end_offset<<std::dec<<"\n";}for(std::size_t z=0;z<k.libraries.size()&&z<16;++z){const auto&x=k.libraries[z];o<<"    library["<<x.index<<"] lang="<<x.language_major<<'.'<<x.language_minor<<" uri="<<x.file_uri<<" classes="<<x.class_count<<" procedures="<<x.procedure_count<<" serialized=current-file+0x"<<std::hex<<x.file_offset<<"..0x"<<x.end_offset<<std::dec<<"\n";for(std::size_t q=0;q<x.procedures.size()&&q<32;++q){const auto&v=x.procedures[q];o<<"      procedure["<<v.index<<"] "<<v.name<<" serialized=current-file+0x"<<std::hex<<v.file_offset<<"..0x"<<v.end_offset<<std::dec<<" source="<<v.source_start_offset<<".."<<v.source_end_offset<<" kind="<<unsigned(v.kind)<<" stub="<<unsigned(v.stub_kind)<<" flags="<<v.flags<<"\n";if(!v.canonical_path.empty())o<<"        canonical: "<<v.canonical_path<<"\n";}}for(std::size_t z=0;z<k.string_hints.size()&&z<16;++z)o<<"    hint current-file+0x"<<std::hex<<k.string_hints[z].file_offset<<std::dec<<": "<<k.string_hints[z].text<<"\n";if(k.string_hints.size()>16)o<<"    ... "<<(k.string_hints.size()-16)<<" more hints\n";}
        if(r.dart.raw_snapshot.valid&&!r.dart.aot.valid){const auto&x=r.dart.raw_snapshot;o<<"  raw snapshot: "<<x.kind_name<<" current-file+0x"<<std::hex<<x.file_offset<<std::dec<<" len="<<x.length<<" hash="<<x.snapshot_hash<<" features="<<x.features<<"\n";}
        if(!r.dart.valid&&!r.dart.error.empty())o<<"  error: current-file+0x"<<std::hex<<r.dart.error_offset<<std::dec<<" "<<r.dart.error<<"\n";
    }

    if (r.flutter_asset_manifest.candidate || r.flutter_asset_manifest.valid) {
        const auto&m=r.flutter_asset_manifest;
        o<<"Flutter AssetManifest:\n  state: "<<(m.valid?(m.nonempty?"CONFIRMED":"STRUCTURE_VALID_EMPTY"):"FAILED")<<"\n"
         <<"  entries="<<m.entry_count<<" variants="<<m.variant_count<<" legacy="<<(m.legacy_string_variants?"true":"false")<<" modern="<<(m.modern_metadata_variants?"true":"false")<<" decoded_nodes="<<m.decoded_node_count<<" string_bytes="<<m.decoded_string_bytes<<"\n";
        if(m.valid){for(std::size_t z=0;z<m.entries.size()&&z<24;++z){const auto&e=m.entries[z];o<<"    "<<e.key<<" ->";for(std::size_t q=0;q<e.variants.size()&&q<8;++q){o<<" "<<e.variants[q].asset;if(e.variants[q].device_pixel_ratio)o<<"@"<<*e.variants[q].device_pixel_ratio<<"x";}if(e.variants.size()>8)o<<" ...";o<<"\n";}if(m.entries.size()>24)o<<"    ... "<<(m.entries.size()-24)<<" more entries\n";for(const auto&a:m.anomalies)o<<"  warning: "<<a<<"\n";}else if(!m.error.empty())o<<"  error: current-file+0x"<<std::hex<<m.error_offset<<std::dec<<" "<<m.error<<"\n";
    }

    if (r.apk.candidate || r.apk.valid) {
        o << "Android APK:\n"
          << "  state: " << (r.apk.valid?"CONFIRMED":"FAILED") << "\n"
          << "  ZIP: entries=" << r.apk.entry_count << " compressed=" << r.apk.total_compressed << " uncompressed=" << r.apk.total_uncompressed
          << " central_dir=current-file+0x" << std::hex << r.apk.central_directory_offset << std::dec << "\n"
          << "  offset_space: current_input_file\n";
        if(r.apk.valid){
            if(!r.apk.manifest.package_name.empty()){
                o << "  package: " << r.apk.manifest.package_name;
                if(!r.apk.manifest.version_name.empty())o<<" versionName="<<r.apk.manifest.version_name;
                if(r.apk.manifest.version_code_known)o<<" versionCode="<<r.apk.manifest.version_code;
                o << "\n";
            }
            o << "  payloads: dex=" << r.apk.validated_dex_count << "/" << r.apk.dex_count
              << " native_elf=" << r.apk.validated_native_elf_count << "/" << r.apk.native_library_count
              << " resources.arsc=" << (r.apk.resources_table_valid?"validated":"absent/unvalidated")
              << " assets=" << r.apk.asset_count << " res_files=" << r.apk.resource_count << " nested=" << r.apk.nested_archive_count << "\n";
            o << "  JNI static relations: state=" << r.apk.jni_relations_state
              << " packaged=" << r.apk.jni_packaged_count << " referenced=" << r.apk.jni_referenced_count
              << " declared=" << r.apk.jni_declared_count << " exported=" << r.apk.jni_exported_count
              << " registration_confirmed=" << r.apk.jni_registration_confirmed_count
              << " (static evidence only; loading/invocation not observed)\n";
            for(std::size_t z=0;z<r.apk.jni_relations.size()&&z<24;++z){const auto&j=r.apk.jni_relations[z];o<<"    "<<j.evidence_level;if(!j.dex_entry.empty())o<<" dex="<<j.dex_entry;if(!j.native_entry.empty())o<<" native="<<j.native_entry;if(!j.class_descriptor.empty())o<<" "<<j.class_descriptor<<"->"<<j.method_name<<j.method_descriptor;o<<"\n";}
            if(r.apk.jni_relations.size()>24)o<<"    ... "<<(r.apk.jni_relations.size()-24)<<" more static relations\n";
            if(!r.apk.jni_relations_error.empty())o<<"  JNI relation warning: "<<r.apk.jni_relations_error<<"\n";
            o << "  manifest: strings=" << r.apk.manifest.string_count << " elements=" << r.apk.manifest.start_element_count
              << " permissions=" << r.apk.manifest.permissions.size() << " components=" << r.apk.manifest.components.size();
            if(r.apk.manifest.min_sdk_known)o<<" minSdk="<<r.apk.manifest.min_sdk;
            if(r.apk.manifest.target_sdk_known)o<<" targetSdk="<<r.apk.manifest.target_sdk;
            if(r.apk.manifest.debuggable_known)o<<" debuggable="<<(r.apk.manifest.debuggable?"true":"false")<<(r.apk.manifest.debuggable_reference_resolved?" (resolved resource reference)":"");
            else if(r.apk.manifest.debuggable_reference)o<<" debuggable=@0x"<<std::hex<<r.apk.manifest.debuggable_reference_id<<std::dec<<" (unresolved resource reference)";
            o<<"\n";
            if(!r.apk.manifest.application_name.empty())o<<"  application: "<<r.apk.manifest.application_name<<"\n";
            if(r.apk.resource_table.valid){
                o << "  resources: packages=" << r.apk.resource_table.parsed_package_count << " typeSpecs=" << r.apk.resource_table.type_spec_count
                  << " configs=" << r.apk.resource_table.type_config_count << " default_scalars=" << r.apk.resource_table.default_scalar_count
                  << " complex=" << r.apk.resource_table.complex_entry_count << " nondefault_configs=" << r.apk.resource_table.nondefault_config_count << "\n";
            }
            if(r.apk.signing_block.present){
                o << "  APK Signing Block: " << (r.apk.signing_block.valid?"STRUCTURE_VALID":"MALFORMED")
                  << " current-file+0x" << std::hex << r.apk.signing_block.block_offset << std::dec << " size=" << r.apk.signing_block.block_size
                  << " pairs=" << r.apk.signing_block.pairs.size() << " cryptographic_verification=NOT_PERFORMED\n";
                for(std::size_t z=0;z<r.apk.signing_block.pairs.size()&&z<32;++z){const auto&q=r.apk.signing_block.pairs[z];o<<"    id=0x"<<std::hex<<q.id<<std::dec<<" value_size="<<q.value_size<<" pair=current-file+0x"<<std::hex<<q.pair_offset<<std::dec;if(!q.label.empty())o<<" "<<q.label;o<<"\n";}
                if(r.apk.signing_block.pairs.size()>32)o<<"    ... "<<(r.apk.signing_block.pairs.size()-32)<<" more pairs\n";
            }
            if(r.apk.has_v1_signature_files)o<<"  v1/JAR signature files: present (inventory only)\n";
            if(r.apk.unsafe_path_count||r.apk.duplicate_path_entry_count||r.apk.encrypted_entry_count||r.apk.unsupported_entry_count){
                o<<"  refused/nonportable entries: unsafe="<<r.apk.unsafe_path_count<<" path_collision_entries="<<r.apk.duplicate_path_entry_count<<" encrypted="<<r.apk.encrypted_entry_count<<" unsupported="<<r.apk.unsupported_entry_count<<"\n";
            }
            if(!r.apk.manifest.permissions.empty()){o<<"  permissions:\n";for(std::size_t z=0;z<r.apk.manifest.permissions.size()&&z<32;++z)o<<"    "<<r.apk.manifest.permissions[z]<<"\n";if(r.apk.manifest.permissions.size()>32)o<<"    ... "<<(r.apk.manifest.permissions.size()-32)<<" more\n";}
            if(!r.apk.manifest.components.empty()){o<<"  components:\n";for(std::size_t z=0;z<r.apk.manifest.components.size()&&z<32;++z){const auto&c=r.apk.manifest.components[z];o<<"    "<<c.kind<<" "<<c.name;if(!c.process.empty())o<<" process="<<c.process;if(c.exported_known)o<<" exported="<<(c.exported?"true":"false");else if(c.exported_reference)o<<" exported=@0x"<<std::hex<<c.exported_reference_id<<std::dec;o<<"\n";}if(r.apk.manifest.components.size()>32)o<<"    ... "<<(r.apk.manifest.components.size()-32)<<" more\n";}
            if(!r.apk.interesting_entries.empty()){o<<"  priority archive entries:\n";for(std::size_t z=0;z<r.apk.interesting_entries.size()&&z<32;++z)o<<"    "<<r.apk.interesting_entries[z]<<"\n";if(r.apk.interesting_entries.size()>32)o<<"    ... "<<(r.apk.interesting_entries.size()-32)<<" more\n";}
            for(const auto&a:r.apk.anomalies)o<<"  warning: "<<a<<"\n";
            if(r.apk.anomaly_samples_truncated)o<<"  warning: additional APK anomaly samples omitted\n";
            if(r.apk_extract.success||r.apk_extract.budget_exhausted||!r.apk_extract.error.empty()){
                o<<"  extraction: "<<(r.apk_extract.budget_exhausted?"PARTIAL":(r.apk_extract.success?"EXTRACTED_VALIDATED":"FAILED"))
                 <<" mode="<<(r.apk_extract.analysis_only?"analysis-only":"full")<<" files="<<r.apk_extract.file_count<<" bytes="<<r.apk_extract.output_bytes;
                if(!r.apk_extract.output_dir.empty()) o<<" output="<<path_utf8(r.apk_extract.output_dir);
                o<<"\n";
                if(!r.apk_extract.error.empty())o<<"    error: "<<r.apk_extract.error<<"\n";
                for(const auto&w:r.apk_extract.warnings)o<<"    warning: "<<w<<"\n";
            }
        } else if(!r.apk.error.empty()) o<<"  error: "<<r.apk.error<<"\n";
    }

    if(r.unreal.candidate){
        o<<"Unreal Engine container:\n  kind: "<<r.unreal.kind<<" state: "<<r.unreal.state<<"\n";
        if(r.unreal.kind=="pak"){
            const auto&x=r.unreal.pak;
            o<<"  Pak: version="<<x.version<<" footer_profile="<<x.footer_profile
             <<" footer=current-file+0x"<<std::hex<<x.footer_offset<<std::dec
             <<" index=current-file+0x"<<std::hex<<x.index_offset<<std::dec<<"+"<<x.index_size
             <<" entries="<<x.entry_count<<" SHA1="<<(x.index_hash_checked?(x.index_hash_matches?"match":"MISMATCH"):"not-checked")
             <<" encrypted="<<(x.encrypted_index?"true":"false")<<" frozen="<<(x.frozen_index?"true":"false")<<"\n";
        }else{
            const auto&x=r.unreal.iostore;
            o<<"  IoStore: version="<<unsigned(x.version)<<" header_size="<<x.header_size
             <<" entries="<<x.entry_count<<" blocks="<<x.compressed_block_count
             <<" partitions="<<x.partition_count<<" toc_valid="<<(x.toc_valid?"true":"false")
             <<" pair_valid="<<(x.pair_valid?"true":"false")<<" encrypted="<<(x.encrypted?"true":"false")
             <<" signature_table="<<(x.signature_table_structurally_present?"STRUCTURALLY_PRESENT":"NOT_PRESENT_OR_UNVALIDATED")
             <<" cryptographic_verification=NOT_PERFORMED\n";
            for(const auto&p:x.partitions)o<<"    partition["<<p.index<<"] "<<path_utf8(p.path)<<" state="<<p.state<<" required="<<p.required_bytes<<" size="<<p.file_size<<(p.error.empty()?"":(" error="+p.error))<<"\n";
        }
        if(!r.unreal.error.empty())o<<"  error: "<<r.unreal.error<<"\n";
        o<<"  scope: static structural recognition only; no asset semantics, decryption, decompression, or extraction claimed\n";
    }
    if (r.dex.candidate) {
        o << "Android DEX:\n"
          << "  state: " << (r.dex.valid?"CONFIRMED":"FAILED") << "\n"
          << "  version: " << r.dex.version << (r.dex.container_v41?" (container v041)":"") << "\n"
          << "  offset_space: current_input_file\n";
        if(r.dex.valid){
            o << "  ids: strings=" << r.dex.strings.size() << " types=" << r.dex.types.size() << " protos=" << r.dex.protos.size()
              << " fields=" << r.dex.fields.size() << " methods=" << r.dex.methods.size() << " classes=" << r.dex.classes.size() << "\n"
              << "  definitions: fields=" << r.dex.defined_field_count << " methods=" << r.dex.defined_method_count
              << " code_items=" << r.dex.code_item_count << " debug_info=" << r.dex.debug_info_count << "\n"
              << "  dynamic: method_handles=" << r.dex.method_handles.size() << " call_sites=" << r.dex.call_sites.size() << "\n"
              << "  JNI static surface: state=" << (r.dex.jni_surface_scan_complete?"RESOLVED":"PARTIAL")
              << " loadLibrary_references=" << r.dex.library_loads.size() << " (loading not observed)\n";
            if(!r.dex.jni_surface_scan_error.empty())o<<"  JNI surface warning: "<<r.dex.jni_surface_scan_error<<"\n";
            if(r.dex.checksum_checked)o<<"  Adler-32: "<<(r.dex.checksum_matches?"match":"MISMATCH")<<"\n";
            if(r.dex.signature_checked)o<<"  SHA-1 signature: "<<(r.dex.signature_matches?"match":"MISMATCH")<<"\n";
            if(!r.dex.classes.empty()){o<<"  classes:\n";for(std::size_t z=0;z<r.dex.classes.size()&&z<64;++z){const auto&c=r.dex.classes[z];o<<"    "<<c.name;if(!c.superclass.empty())o<<" extends "<<c.superclass;if(!c.source_file.empty())o<<" source="<<c.source_file;o<<"\n";}if(r.dex.classes.size()>64)o<<"    ... "<<(r.dex.classes.size()-64)<<" more\n";}
            std::size_t shown=0;for(const auto&m:r.dex.methods){if(!m.defined)continue;if(shown++==0)o<<"  defined methods:\n";if(shown>80){o<<"    ...\n";break;}o<<"    #"<<m.index<<" "<<m.signature;if(m.code_off)o<<" current-file+0x"<<std::hex<<m.code_off<<std::dec;o<<"\n";}
            if(!r.dex.call_sites.empty()){o<<"  invoke-custom call sites:\n";for(std::size_t z=0;z<r.dex.call_sites.size()&&z<64;++z){const auto&c=r.dex.call_sites[z];o<<"    #"<<c.index<<" current-file+0x"<<std::hex<<c.call_site_off<<std::dec<<" "<<c.method_name<<c.method_type<<" bootstrap="<<c.bootstrap_target<<" extra_args="<<c.extra_argument_count<<"\n";}if(r.dex.call_sites.size()>64)o<<"    ... "<<(r.dex.call_sites.size()-64)<<" more\n";}
            for(std::size_t z=0;z<r.dex.anomalies.size()&&z<32;++z)o<<"  warning: "<<r.dex.anomalies[z]<<"\n";
            if(r.dex_extract.success)o<<"  maps: "<<path_utf8(r.dex_extract.methods_csv)<<" / "<<path_utf8(r.dex_extract.classes_csv)<<" / "<<path_utf8(r.dex_extract.fields_csv)<<" / "<<path_utf8(r.dex_extract.callsites_csv)<<"\n";
        } else if(!r.dex.error.empty()) {
            o << "  error: current-file+0x" << std::hex << r.dex.error_offset << std::dec << " " << r.dex.error << "\n";
        }
    }

    if (r.jvm_class.candidate) {
        o << "JVM Class:\n"
          << "  state: " << (r.jvm_class.valid?"CONFIRMED":"FAILED") << "\n"
          << "  version: " << r.jvm_class.major << "." << r.jvm_class.minor << " " << r.jvm_class.java_release << (r.jvm_class.preview?" preview":"") << "\n";
        if(r.jvm_class.valid){
            o << "  class: " << r.jvm_class.class_name << (r.jvm_class.super_name.empty()?"":" extends "+r.jvm_class.super_name) << "\n"
              << "  members: fields=" << r.jvm_class.fields.size() << " methods=" << r.jvm_class.methods.size() << " references=" << r.jvm_class.references.size() << " strings=" << r.jvm_class.string_constants.size() << "\n"
              << "  dynamic: invokedynamic=" << r.jvm_class.invokedynamic_count << " condy=" << r.jvm_class.dynamic_count << " bootstrap_methods=" << r.jvm_class.bootstrap_method_count << "\n";
            if(!r.jvm_class.source_file.empty())o<<"  source: "<<r.jvm_class.source_file<<"\n";
            if(r.jvm_class.kotlin_metadata)o<<"  Kotlin metadata: yes\n";
            if(!r.jvm_class.interfaces.empty()){o<<"  interfaces: ";for(std::size_t z=0;z<r.jvm_class.interfaces.size();++z){if(z)o<<", ";o<<r.jvm_class.interfaces[z];}o<<"\n";}
            std::size_t shown=0;for(const auto&m:r.jvm_class.methods){if(shown++==0)o<<"  methods:\n";if(shown>80){o<<"    ...\n";break;}o<<"    "<<m.name<<m.signature;if(m.code_size)o<<" file+0x"<<std::hex<<m.code_offset<<std::dec<<" size="<<m.code_size;if(!m.generic_signature.empty())o<<" generic="<<m.generic_signature;o<<"\n";}
            for(const auto&h:r.jvm_class.obfuscation_hints)o<<"  obfuscation hint: "<<h<<"\n";
            for(std::size_t z=0;z<r.jvm_class.anomalies.size()&&z<32;z++)o<<"  warning: "<<r.jvm_class.anomalies[z]<<"\n";
            if(r.jvm_extract.success)o<<"  maps: "<<path_utf8(r.jvm_extract.methods_csv)<<" / "<<path_utf8(r.jvm_extract.fields_csv)<<" / "<<path_utf8(r.jvm_extract.references_csv)<<"\n";
        }else if(!r.jvm_class.error.empty())o<<"  error: file+0x"<<std::hex<<r.jvm_class.error_offset<<std::dec<<" "<<r.jvm_class.error<<"\n";
    }
    if (r.jar.valid) {
        o << "Java/JVM archive:\n"
          << "  variant: " << r.jar.variant << " entries=" << r.jar.entry_count << " classes=" << r.jar.class_count << " nested_archives=" << r.jar.nested_archive_count << " native_libraries=" << r.jar.native_library_count << "\n"
          << "  sizes: compressed=" << r.jar.total_compressed << " uncompressed=" << r.jar.total_uncompressed << "\n";
        if(!r.jar.main_class.empty())o<<"  Main-Class: "<<r.jar.main_class<<"\n";
        if(!r.jar.automatic_module_name.empty())o<<"  Automatic-Module-Name: "<<r.jar.automatic_module_name<<"\n";
        if(!r.jar.implementation_version.empty())o<<"  Implementation-Version: "<<r.jar.implementation_version<<"\n";
        for(const auto&a:r.jar.anomalies)o<<"  warning: "<<a<<"\n";
        if(r.jar_extract.success||r.jar_extract.budget_exhausted)o<<"  extraction: "<<(r.jar_extract.success?"EXTRACTED_VALIDATED":"PARTIAL")<<" files="<<r.jar_extract.file_count<<" bytes="<<r.jar_extract.output_bytes<<" output="<<path_utf8(r.jar_extract.output_dir)<<"\n";
    }

    if (r.dotnet_bundle.candidate) {
        const auto& b=r.dotnet_bundle;
        o << ".NET single-file bundle:\n"
          << "  state: " << b.state << " version=" << b.major_version << '.' << b.minor_version << " files=" << b.file_count << "\n";
        if(b.valid)o << "  bundle_id: " << b.bundle_id << " compressed_files=" << b.compressed_file_count << " integrity=" << b.integrity_state << "\n";
        if(!b.error.empty())o << "  note: " << b.error << "\n";
    }
    if (r.native_aot.candidate) {
        const auto& n=r.native_aot;
        o << ".NET NativeAOT:\n"
          << "  state: " << n.state << " platform=" << n.platform << " R2R=" << n.major_version << '.' << n.minor_version << " sections=" << n.section_count << "\n";
        if(n.valid)o << "  evidence: __modules + __managedcode + .dotnet_eh_table + .hydrated; raw_RTR=" << n.raw_rtr_magic_count << " valid_headers=" << n.valid_rtr_header_count << "\n";
        if(!n.error.empty())o << "  note: " << n.error << "\n";
    }

    if (r.pe.clr.present) {
        o << ".NET metadata:\n"
          << "  state: " << (r.dotnet.valid?"CONFIRMED":"FAILED") << "\n";
        if(r.dotnet.valid){
            o << "  runtime: " << r.dotnet.runtime_version << (r.dotnet.unity_mono?" (Unity Mono backend payload)":(r.dotnet.unity_managed?" (Unity managed payload; backend unresolved here)":"")) << "\n"
              << "  tables: types=" << r.dotnet.types.size() << " typerefs=" << r.dotnet.type_refs.size() << " fields=" << r.dotnet.fields.size() << " methods=" << r.dotnet.methods.size() << " params=" << r.dotnet.params.size() << "\n"
              << "  references: memberrefs=" << r.dotnet.member_refs.size() << " assemblyrefs=" << r.dotnet.assembly_refs.size() << " methodspecs=" << r.dotnet.method_specs.size() << "\n"
              << "  managed members: properties=" << r.dotnet.properties.size() << " events=" << r.dotnet.events.size() << " generic_params=" << r.dotnet.generic_params.size() << " resources=" << r.dotnet.resources.size() << "\n"
              << "  signatures: " << (r.dotnet.signature_parse_complete?"complete":"PARTIAL") << "\n";
            if(!r.dotnet.assembly_refs.empty()){o<<"  assembly refs:\n";for(const auto&a:r.dotnet.assembly_refs)o<<"    "<<a.name<<" "<<a.version<<(a.culture.empty()?"":" culture="+a.culture)<<"\n";}
            std::size_t shown_types=0;for(const auto&t:r.dotnet.types){if(t.name=="<Module>")continue;if(shown_types++==0)o<<"  types:\n";if(shown_types>32){o<<"    ...\n";break;}o<<"    "<<t.full_name;if(!t.base_type.empty())o<<" : "<<t.base_type;if(!t.generic_params.empty()){o<<" <";for(std::size_t z=0;z<t.generic_params.size();++z){if(z)o<<',';o<<t.generic_params[z];}o<<'>';}o<<"\n";}
            std::size_t shown_methods=0;for(const auto&m:r.dotnet.methods){if(m.type_name=="<Module>"||m.name.empty())continue;if(shown_methods++==0)o<<"  priority methods:\n";if(shown_methods>64){o<<"    ...\n";break;}o<<"    "<<m.full_name;if(m.rva)o<<" RVA 0x"<<std::hex<<m.rva<<std::dec;if(m.pinvoke)o<<" P/Invoke "<<m.import_module<<'!'<<m.import_name;o<<"\n";}
            for(const auto&h:r.dotnet.obfuscation_hints)o<<"  obfuscation hint: "<<h<<"\n";
            for(std::size_t z=0;z<r.dotnet.anomalies.size()&&z<32;++z)o<<"  warning: "<<r.dotnet.anomalies[z]<<"\n";
            if(r.dotnet_extract.success){o<<"  symbols: "<<path_utf8(r.dotnet_extract.symbols_csv)<<" ("<<r.dotnet_extract.symbol_count<<")\n"<<"  types CSV: "<<path_utf8(r.dotnet_extract.types_csv)<<" ("<<r.dotnet_extract.type_count<<")\n"<<"  members CSV: "<<path_utf8(r.dotnet_extract.members_csv)<<" ("<<r.dotnet_extract.member_count<<")\n";}
        } else if(!r.dotnet.error.empty()) o << "  error: " << r.dotnet.error << "\n";
    }

    if (r.wasm.candidate) {
        o << "WebAssembly:\n"
          << "  state: " << (r.wasm.valid?"CONFIRMED":"FAILED") << "\n"
          << "  version: " << r.wasm.version << " sections=" << r.wasm.section_count << "\n";
        if(r.wasm.valid){
            o << "  functions: " << r.wasm.functions.size() << " (imports=" << r.wasm.imported_function_count << " defined=" << r.wasm.defined_function_count << ") names=" << r.wasm.named_function_count << "\n"
              << "  imports/exports: " << r.wasm.imports.size() << "/" << r.wasm.exports.size() << " data_segments=" << r.wasm.data_segments.size() << "\n";
            if(!r.wasm.custom_sections.empty()){o<<"  custom sections:";for(const auto&x:r.wasm.custom_sections)o<<" "<<x.name;o<<"\n";}
            std::size_t shown=0;for(const auto&f:r.wasm.functions){if(!f.user_like)continue;if(shown++==0)o<<"  priority functions:\n";if(shown>80){o<<"    ...\n";break;}o<<"    #"<<f.index<<" "<<(f.name.empty()?"(unnamed)":f.name)<<f.signature;if(f.code_offset)o<<" file+0x"<<std::hex<<f.code_offset<<std::dec<<" size="<<f.code_size;if(!f.exports.empty()){o<<" export=";for(std::size_t z=0;z<f.exports.size();++z){if(z)o<<'|';o<<f.exports[z];}}o<<"\n";}
            if(r.wasm_extract.success){o<<"  function map: "<<path_utf8(r.wasm_extract.functions_csv)<<" ("<<r.wasm_extract.function_count<<")\n";if(!r.wasm_extract.strings_txt.empty())o<<"  strings: "<<path_utf8(r.wasm_extract.strings_txt)<<" ("<<r.wasm_extract.string_count<<")\n";}
        }
        if(!r.wasm.error.empty())o<<"  error: file+0x"<<std::hex<<r.wasm.error_offset<<std::dec<<" "<<r.wasm.error<<"\n";
        for(const auto&a:r.wasm.anomalies)o<<"  warning: "<<a<<"\n";
    }

    if (r.hermes.candidate) {
        const auto state=!r.hermes.supported_epoch?"PARTIAL":((!r.hermes.valid&&!r.hermes.budget_limited)?"FAILED":(r.hermes.parse_complete?"CONFIRMED":"PARTIAL"));
        o << "Hermes bytecode:\n"
          << "  state: " << state << " version=" << r.hermes.version << " epoch=" << r.hermes.epoch << "\n";
        if(r.hermes.supported_epoch){
            o << "  functions/strings/identifiers: " << r.hermes.function_count << "/" << r.hermes.string_count << "/" << r.hermes.identifier_count << "\n"
              << "  footer SHA-1: " << (r.hermes.footer_hash_matches?"validated":"failed") << " debug=" << (r.hermes.debug.valid?"validated":"failed") << "\n";
            std::size_t shown=0;for(const auto&f:r.hermes.functions){if(f.function_name.empty())continue;if(shown++==0)o<<"  named functions:\n";if(shown>64){o<<"    ...\n";break;}o<<"    #"<<f.index<<" "<<f.function_name<<" file+0x"<<std::hex<<f.bytecode_offset<<std::dec<<" size="<<f.bytecode_size<<" instructions="<<f.instruction_count<<"\n";}
            if(r.hermes_extract.success)o<<"  maps: "<<path_utf8(r.hermes_extract.functions_csv)<<", "<<path_utf8(r.hermes_extract.strings_csv)<<", "<<path_utf8(r.hermes_extract.opcodes_csv)<<"\n";
        }
        if(!r.hermes.error.empty())o<<"  error: file+0x"<<std::hex<<r.hermes.error_offset<<std::dec<<" "<<r.hermes.error<<"\n";
        for(const auto&a:r.hermes.anomalies)o<<"  warning: "<<a<<"\n";
    }

    if(r.implicit_exec.state!="NOT_PRESENT"){
        const auto facts=implicit_render_fact_positions(r.implicit_exec);
        o<<"Implicit execution: state="<<r.implicit_exec.state<<" facts="<<r.implicit_exec.facts.size()
         <<" rendered="<<facts.size()<<" high="<<r.implicit_exec.high_priority_count<<" review="<<r.implicit_exec.review_count
         <<" anomalies="<<r.implicit_exec.anomaly_count<<" informational="<<r.implicit_exec.informational_count
         <<" unresolved_runtime_semantics="<<r.implicit_exec.unresolved_runtime_semantics
         <<" analysis_limited="<<(r.implicit_exec.analysis_limited?"true":"false")<<"\n";
        if(!r.implicit_exec.error.empty())o<<"  error: "<<r.implicit_exec.error<<"\n";
        for(const auto pos:facts){
            const auto&x=r.implicit_exec.facts[pos];
            const auto index=r.implicit_exec.fact_index(pos);
            const auto dependency=r.implicit_exec.fact_dependency(pos);
            o<<"  fact #"<<index<<" ["<<x.priority<<"] "<<x.format<<" "<<x.phase<<" "<<x.trigger;
            if(!x.target_name.empty())o<<" -> "<<x.target_name;else if(!x.target_kind.empty())o<<" -> "<<x.target_kind;
            if(!x.anomaly_class.empty()&&x.anomaly_class!="NONE")o<<" anomaly="<<x.anomaly_class;
            o<<"\n";
            o<<"    relation="<<x.relation<<" evidence="<<x.evidence_state<<" source="<<x.source_kind<<"["<<x.source_index<<"]";
            if(x.source_file_backed)o<<" file_offset=0x"<<std::hex<<x.source_file_offset<<std::dec;
            if(x.source_va)o<<" va=0x"<<std::hex<<x.source_va<<std::dec;
            o<<" size="<<x.source_size<<"\n";
            o<<"    target_kind="<<x.target_kind;
            if(x.target_va)o<<" va=0x"<<std::hex<<x.target_va<<std::dec;
            if(x.target_file_backed)o<<" file_offset=0x"<<std::hex<<x.target_file_offset<<std::dec;
            if(x.target_token)o<<" token=0x"<<std::hex<<x.target_token<<std::dec;
            if(x.target_function_index)o<<" function_index="<<x.target_function_index;
            o<<"\n";
            if(dependency>=0)o<<"    depends_on_fact_index="<<dependency<<"\n";
            if(!x.priority_reason.empty())o<<"    reason: "<<x.priority_reason<<"\n";
            if(!x.execution_condition.empty())o<<"    condition: "<<x.execution_condition<<"\n";
            if(!x.detail.empty())o<<"    detail: "<<x.detail<<"\n";
        }
        if(r.implicit_exec.facts.size()>facts.size()){
            if(r.implicit_exec_extract.success)o<<"  ... default implicit fact table truncated; complete CSV: "<<path_utf8(r.implicit_exec_extract.csv)<<"\n";
            else o<<"  ... default implicit fact table truncated; complete CSV omitted by the default artifact budget; use --extract for the full supported map\n";
        }
        if(r.implicit_exec_extract.success)o<<"  extraction: "<<path_utf8(r.implicit_exec_extract.csv)<<" ("<<r.implicit_exec_extract.fact_count<<" facts)\n";
        else if(!r.implicit_exec_extract.error.empty())o<<"  extraction error: "<<r.implicit_exec_extract.error<<"\n";
    }

    if (!r.static_scan.high_entropy.empty()) {
        o << "High entropy ranges:\n";
        for (const auto& x : r.static_scan.high_entropy) o << "  off=0x" << std::hex << x.offset << std::dec << " size=" << x.size << " entropy=" << std::fixed << std::setprecision(3) << x.entropy << "\n";
    }
    if (!r.static_scan.embedded.empty()) {
        o << "Embedded objects:\n";
        for (const auto& e : r.static_scan.embedded) o << "  " << e.kind << " off=0x" << std::hex << e.offset << std::dec << " size=" << e.size << " state=" << e.state << (e.confidence?" confidence=":"") << (e.confidence?std::to_string(*e.confidence):std::string()) << " " << e.detail << "\n";
    }
    {
        const auto&g=r.analysis_guidance;
        o<<"Analysis guidance:\n"
         <<"  visible_hypothesis: "<<g.visible_hypothesis<<"\n"
         <<"  declared_entry_default: "<<(g.declared_entry_default?"true":"false")<<"\n"
         <<"  decoy_risk: "<<g.decoy_risk<<"\n"
         <<"  strong_evidence_counts: runtime_pre_entry="<<g.runtime_pre_entry_count<<" runtime_first_exec="<<g.runtime_first_exec_count<<" high_implicit="<<g.high_implicit_count<<" frozen_reference_diff="<<g.frozen_reference_diff_count<<"\n"
         <<"  runtime_modality_policy: "<<g.runtime_modality.policy<<" static_evidence_only="<<(g.runtime_modality.static_evidence_only?"true":"false")<<" runtime_execution_authorized="<<(g.runtime_modality.runtime_execution_authorized?"true":"false")<<"\n";
        for(const auto&x:g.runtime_modality.priority_guidance)o<<"  runtime_modality_priority: "<<x<<"\n";
        for(const auto&x:g.runtime_modality.requirements){
            o<<"  runtime_modality: "<<x.modality<<" state="<<x.state<<" confidence="<<x.confidence<<" gate="<<x.evidence_gate<<"\n";
            if(!x.reason.empty())o<<"    reason: "<<x.reason<<"\n";
            for(const auto&e:x.evidence)o<<"    evidence: "<<e<<"\n";
            for(const auto&e:x.negative_evidence)o<<"    negative_evidence: "<<e<<"\n";
            for(const auto&a:x.artifacts)o<<"    artifact: "<<path_utf8(a)<<"\n";
        }
        for(const auto&x:g.contradictory_evidence)o<<"  contradictory_evidence: "<<x<<"\n";
        for(const auto&x:g.alternate_execution_paths)o<<"  alternate_execution_path: "<<x<<"\n";
        for(const auto&x:g.unresolved_alternatives)o<<"  unresolved_alternative: "<<x<<"\n";
        for(const auto&x:g.priority_reasons)o<<"  priority_reason: "<<x<<"\n";
    }

    if (!r.findings.empty()) o << "Findings:\n";
    for (const auto& f : r.findings) {
        o << "  [" << f.kind << "] " << f.family; if (!f.variant.empty()) o << " / " << f.variant; o << "  state=" << f.state; if(f.confidence) o << " confidence=" << std::fixed << std::setprecision(2) << *f.confidence; o << "\n";
        for (const auto& e : f.evidence) o << "    + " << e << "\n";
        for (const auto& e : f.negative_evidence) o << "    - " << e << "\n";
        for (const auto& kv : f.fields) o << "    " << kv.first << ": " << kv.second << "\n";
        for (const auto& range : f.ranges) render_range_text(o,r,range,"    range: ");
        for (const auto& a : f.suggested_actions) o << "    -> " << a << "\n";
    }

    if(r.runtime_plan.requested){
        o << "\nOrchestration runtime plan\n"
          << "  policy: " << r.runtime_plan.policy << "\n"
          << "  apply_requested: " << (r.runtime_plan.apply_requested?"true":"false") << "\n"
          << "  runtime_eligible: " << (r.runtime_plan.runtime_eligible?"true":"false") << "\n"
          << "  runtime_eligibility_reason: " << r.runtime_plan.runtime_eligibility_reason << "\n";
        for(const auto& x:r.runtime_plan.steps){
            o << "  [" << (x.selected?"selected":"skipped") << "] " << x.analyzer << " state=" << x.state << " destructive=" << (x.destructive?"true":"false");
            if(x.timeout_ms)o << " timeout_ms=" << x.timeout_ms;
            if(x.elapsed_ms)o << " elapsed_ms=" << x.elapsed_ms;
            o << "\n    reason: " << x.reason << "\n";
            for(const auto&e:x.evidence)o << "    evidence: " << e << "\n";
            if(!x.result.empty())o << "    result: " << x.result << "\n";
            if(!x.refusal.empty())o << "    refusal: " << x.refusal << "\n";
        }
    }

    if (r.runtime.requested) {
        o << "\nRuntime\n"
          << "  launched: " << (r.runtime.launched ? "yes" : "no") << "\n"
          << "  timed_out: " << (r.runtime.timed_out ? "yes" : "no") << "\n"
          << "  target_file_after_run: " << changed(r.runtime) << "\n"
          << "  target_write_time_changed: " << (timestamp_changed(r.runtime) ? "yes" : "no") << "\n";
        if (r.runtime.before.exists) {
            o << "  before: size=" << r.runtime.before.size
              << " sha256=" << r.runtime.before.sha256 << "\n";
        }
        if (r.runtime.after.exists) {
            o << "  after:  size=" << r.runtime.after.size
              << " sha256=" << r.runtime.after.sha256 << "\n";
        }
        if (r.runtime.exit_code) o << "  exit_code: " << *r.runtime.exit_code << "\n";
        if (!r.runtime.stdout_text.empty()) o << "  stdout:\n" << r.runtime.stdout_text << "\n";
        if (!r.runtime.stderr_text.empty()) o << "  stderr:\n" << r.runtime.stderr_text << "\n";
        if (!r.runtime.console_expected && r.runtime.stdout_text.empty() && r.runtime.stderr_text.empty()) {
            o << "  console_output: not_applicable\n";
        }

        if (!r.runtime.timeline.empty()) {
            o << "\nTimeline (relative)\n";
            for (const auto& e : r.runtime.timeline) {
                o << "  +" << std::fixed << std::setprecision(3)
                  << (double(e.t_us) / 1000.0) << "ms"
                  << "  proc=" << e.process_uid
                  << " pid=" << e.pid;
                if (e.parent_uid) o << " parent=" << e.parent_uid;
                if (e.ppid) o << " ppid=" << e.ppid;
                o << "  " << timeline_kind_name(e.kind);
                if (!e.subject.empty()) o << "  " << e.subject;
                if(!e.fields.empty()){o<<"  [";bool first=true;for(const auto&kv:e.fields){if(!first)o<<", ";first=false;o<<kv.first<<'='<<kv.second;}o<<']';}
                o << "\n";
            }
        }
        if (!r.runtime.artifacts.empty()) {
            o << "\nRuntime artifacts\n";
            for (const auto& a : r.runtime.artifacts) {
                o << "  [" << a.state << "] " << a.kind
                  << " proc=" << a.process_uid << " pid=" << a.pid;
                if (a.oep_va) o << " oep_va=0x" << std::hex << a.oep_va << std::dec;
                o << "\n    path: " << path_utf8(a.path) << "\n";
                if (!a.detail.empty()) o << "    " << a.detail << "\n";
                for(const auto&kv:a.fields)o<<"    "<<kv.first<<": "<<kv.second<<"\n";
                for(const auto&rng:a.priority_ranges)render_range_text(o,r,rng,"    priority_range: ",&a);
            }
        }
    }

    if (r.replacement.performed) {
        o << "\nUnpack replacement\n"
          << "  target: " << path_utf8(r.replacement.target) << "\n"
          << "  backup: " << path_utf8(r.replacement.backup) << "\n"
          << "  source: " << path_utf8(r.replacement.unpacked_source) << "\n"
          << "  original_sha256: " << r.replacement.original_sha256 << "\n"
          << "  new_sha256: " << r.replacement.new_sha256 << "\n"
          << "  validation: " << r.replacement.validation << "\n";
    }
    return o.str();
}

namespace {
std::string localize_semantic_zh(std::string_view text) {
    static constexpr std::pair<std::string_view,std::string_view> exact[] = {
        {"declared entry remains the default hypothesis", "声明入口仍是默认分析假设"},
        {"absence of alternate evidence is not proof that hidden execution is impossible", "没有发现替代路径证据，并不能证明隐藏执行路径不存在"},
        {"No evidence-gated runtime observation modality was established; continue with static analysis unless later evidence proves a runtime dependency.", "尚未建立由证据触发的运行时观测需求；继续静态分析，除非后续证据证明必须依赖运行时行为。"},
        {"STATIC_SUFFICIENT is a routing statement, not proof that runtime behavior is impossible or irrelevant.", "STATIC_SUFFICIENT 只是分析路由结论，并不证明运行时行为不可能发生或与分析无关。"},
        {"Python runtime string anchor", "发现 Python 运行时字符串锚点"},
        {"Nuitka string anchor", "发现 Nuitka 字符串锚点"},
        {"official CPython release-family magic matched exactly", "与官方 CPython 发布系列的 magic 值精确匹配"},
        {"PEP 552-era 16-byte header geometry and defined flag bits validated", "已验证 PEP 552 时代的 16 字节头部结构及已定义标志位"},
        {"bytes after the header parse completely as exactly one top-level marshal code object under the authenticated minor-family layout", "头部之后的数据可按已认证的小版本系列布局完整解析为且仅为一个顶层 marshal 代码对象"},
        {"root co_code/co_consts/co_names structure validated without executing marshal data", "无需执行 marshal 数据即可验证根代码对象的 co_code/co_consts/co_names 结构"},
        {"Nuitka constant_bin directory structurally parsed", "已按结构解析 Nuitka constant_bin 目录"},
        {".bytecode and module constant blocks recovered", "已恢复 .bytecode 与模块常量块"},
        {"constant tag streams decoded and validated against declared counts/END tags", "常量标签流已解码，并依据声明计数与 END 标签完成验证"},
        {"Nuitka __compiled__ named-tuple descriptor and major/minor/micro/releaselevel initializers were structurally recovered from bounded ELF64/x86-64 generated code", "已从有界 ELF64/x86-64 生成代码中按结构恢复 Nuitka __compiled__ 命名元组描述符，以及 major/minor/micro/releaselevel 初始化逻辑"},
        {"KA[X/Y] payload located and contained-file stream structurally parsed", "已定位 KA[X/Y] 载荷，并按结构解析其内含文件流"},
        {"Zstandard payload successfully decompressed", "Zstandard 载荷已成功解压"},
        {"KAY marker followed by a structurally bounded Zstandard frame", "KAY 标记之后存在结构边界明确的 Zstandard 帧"},
        {"deep parser entered because Unity family/backend route evidence", "由于存在 Unity 家族/后端路由证据，已进入深度解析器"},
        {"Unity route produced no backend-specific or generic structural evidence", "Unity 路由未产生后端专属或通用结构证据"},
        {"loader/runtime invokes a structurally declared target outside the explicit entry CFG", "加载器/运行时会调用显式入口 CFG 之外、由结构元数据声明的目标"},
        {"dynamic loader processes DT_INIT before transferring to the program entry path", "动态加载器会在转入程序入口路径之前处理 DT_INIT"},
        {"initializer slot is an ordinary implicit execution surface", "初始化槽位属于常规的隐式执行面"},
        {"loader consumes DT_INIT_ARRAY_SLOT slot", "加载器会消费 DT_INIT_ARRAY_SLOT 槽位"},
        {"identifier string is not independent structural evidence; family classification intentionally withheld", "标识字符串不构成独立结构证据；因此有意不提升到具体家族分类"},
        {"raw GDPC bytes can occur in executable code/data and are not structural PCK confirmation", "原始 GDPC 字节可能自然出现在可执行代码/数据中，不能作为 PCK 的结构确认"},
        {"budget exhaustion is not evidence that runtime execution is required; no modality was guessed from truncated analysis", "预算耗尽并不能证明必须执行运行时分析；不会根据被截断的分析猜测运行时模态"},
    };
    for(const auto&[from,to]:exact)if(text==from)return std::string(to);

    std::string s(text);
    constexpr std::string_view pyc_priority_prefix="authenticated direct CPython ";
    constexpr std::string_view pyc_priority_suffix=" bytecode is the decisive reverse-analysis surface; use its bounded code-object map before generic native/runtime hypotheses";
    if(s.starts_with(pyc_priority_prefix)&&s.ends_with(pyc_priority_suffix)){
        auto version=s.substr(pyc_priority_prefix.size(),s.size()-pyc_priority_prefix.size()-pyc_priority_suffix.size());
        return "经认证的直接 CPython "+version+" 字节码是决定性的逆向分析面；应先使用其有界代码对象映射，再考虑通用原生/运行时假设";
    }
    constexpr std::string_view dis_prefix="use the emitted code-object/name/constant map and a CPython ";
    constexpr std::string_view dis_suffix="-compatible disassembler/decompiler for selected code objects";
    if(s.starts_with(dis_prefix)&&s.ends_with(dis_suffix)){
        auto version=s.substr(dis_prefix.size(),s.size()-dis_prefix.size()-dis_suffix.size());
        return "使用已生成的代码对象/名称/常量映射，并用兼容 CPython "+version+" 的反汇编器/反编译器处理选定代码对象";
    }
    if(s=="treat decompiled source as a derived aid; serialized code-object structure and authenticated bytecode family remain the authoritative evidence")
        return "将反编译源码视为派生辅助信息；序列化代码对象结构与已认证的字节码系列仍是权威证据";
    if(s=="inspect the failed structure as a possible modified, corrupt, or unsupported variant before applying ecosystem-specific tooling")
        return "在使用生态专用工具前，先检查失败结构是否属于被修改、损坏或暂未支持的变体";
    if(s=="raise explicit artifact byte budget only if the input is trusted enough to justify it")
        return "仅当输入足够可信且确有必要时，才显式提高产物字节预算";
    return s;
}

std::string localize_text_zh(std::string_view text) {
    static constexpr std::pair<std::string_view,std::string_view> prefixes[] = {
        {"auto-refirst Analysis", "auto-refirst 分析报告"},
        {"Input: ", "输入: "},
        {"Size: ", "大小: "},
        {"Artifact graph: ", "产物图: "},
        {"Analysis artifacts:", "分析产物:"},
        {"Artifact: ", "产物: "},
        {"Format: ", "格式: "},
        {"Subsystem: ", "子系统: "},
        {"Entry RVA: ", "入口 RVA: "},
        {"Image Size: ", "映像大小: "},
        {"Sections:", "节区:"},
        {"Overlay: ", "附加数据: "},
        {"Imports: ", "导入: "},
        {"Exports: ", "导出: "},
        {"PE directories:", "PE 数据目录:"},
        {"Authenticode: ", "Authenticode 签名: "},
        {"Pre-entry / initialization:", "入口前 / 初始化:"},
        {"Endian: ", "字节序: "},
        {"Entry: ", "入口: "},
        {"Interpreter: ", "解释器: "},
        {"ELF ordinary dynamic: ", "ELF 常规动态元数据: "},
        {"ELF dynamic extraction: ", "ELF 动态元数据提取: "},
        {"ELF unwind extraction: ", "ELF 展开信息提取: "},
        {"  symbols CSV: ", "  符号 CSV: "},
        {"  relocations CSV: ", "  重定位 CSV: "},
        {"  CIE CSV: ", "  CIE CSV: "},
        {"  FDE CSV: ", "  FDE CSV: "},
        {"Needed libraries:", "依赖库:"},
        {"Program headers: ", "程序头: "},
        {"Segments:", "段:"},
        {"File-offset basis: ", "文件偏移基准: "},
        {"Slice ", "切片 "},
        {"Go runtime:", "Go 运行时:"},
        {"CPython static composition:", "CPython 静态组合分析:"},
        {"CPython runtime:", "CPython 运行时:"},
        {"Unity:", "Unity:"},
        {"Dart:", "Dart:"},
        {"Flutter AssetManifest:", "Flutter AssetManifest:"},
        {"JVM class:", "JVM 类:"},
        {"JAR:", "JAR:"},
        {".NET metadata:", ".NET 元数据:"},
        {"WeChat wxapkg:", "微信 wxapkg:"},
        {"Electron ASAR:", "Electron ASAR:"},
        {"AutoIt:", "AutoIt:"},
        {"Ren'Py RPYC:", "Ren'Py RPYC:"},
        {"Ren'Py RPA:", "Ren'Py RPA:"},
        {"Godot PCK:", "Godot PCK:"},
        {"Godot extraction:", "Godot 提取:"},
        {"PyInstaller CArchive:", "PyInstaller CArchive:"},
        {"PyInstaller extraction:", "PyInstaller 提取:"},
        {"Crypto key-use recovery:", "密码学密钥使用恢复:"},
        {"Implicit execution: ", "隐式执行: "},
        {"  fact #", "  事实 #"},
        {"    reason: ", "    原因: "},
        {"    condition: ", "    条件: "},
        {"    detail: ", "    详情: "},
        {"    evidence: ", "    证据: "},
        {"    negative_evidence: ", "    负证据: "},
        {"    artifact: ", "    产物: "},
        {"  extraction: ", "  提取结果: "},
        {"  extraction error: ", "  提取错误: "},
        {"Analysis guidance:", "分析指引:"},
        {"  visible_hypothesis: ", "  可见假设: "},
        {"  declared_entry_default: ", "  声明入口仍为默认: "},
        {"  decoy_risk: ", "  误导风险: "},
        {"  strong_evidence_counts: ", "  强证据计数: "},
        {"  runtime_modality_policy: ", "  运行时模态策略: "},
        {"  runtime_modality_priority: ", "  运行时模态优先级: "},
        {"  runtime_modality: ", "  运行时模态: "},
        {"  contradictory_evidence: ", "  矛盾证据: "},
        {"  alternate_execution_path: ", "  替代执行路径: "},
        {"  unresolved_alternative: ", "  未决替代路径: "},
        {"  priority_reason: ", "  优先理由: "},
        {"High entropy ranges:", "高熵范围:"},
        {"Embedded objects:", "嵌入对象:"},
        {"Findings:", "发现:"},
        {"Orchestration runtime plan", "编排运行时计划"},
        {"  policy: ", "  策略: "},
        {"  apply_requested: ", "  已请求应用替换: "},
        {"  runtime_eligible: ", "  可执行运行时分析: "},
        {"  runtime_eligibility_reason: ", "  运行时资格原因: "},
        {"    result: ", "    结果: "},
        {"    refusal: ", "    拒绝原因: "},
        {"Timeline (relative)", "时间线（相对时间）"},
        {"Runtime artifacts", "运行时产物"},
        {"Unpack replacement", "脱壳替换"},
        {"Runtime", "运行时"},
        {"  MetadataRegistration: ", "  MetadataRegistration: "},
        {"  Managed strings: ", "  托管字符串: "},
        {"  Metadata usages: ", "  元数据用法: "},
        {"  Method bounds: ", "  方法边界: "},
        {"  P/Invoke: ", "  P/Invoke: "},
        {"  Metadata xrefs: ", "  元数据交叉引用: "},
        {"  Default values: ", "  默认值: "},
        {"  Generic parameters: ", "  泛型参数: "},
        {"  Generics: ", "  泛型: "},
        {"  RGCTX: ", "  RGCTX: "},
        {"  MethodDef dispatch: ", "  MethodDef 分派: "},
        {"  Recovered layouts:", "  恢复的布局:"},
        {"  user/module functions:", "  用户/模块函数:"},
        {"  user/runtime types:", "  用户/运行时类型:"},
        {"  native region differences:", "  原生区域差异:"},
        {"  incoming references to new executable regions:", "  指向新可执行区域的传入引用:"},
        {"  semantic probes:", "  语义探针:"},
        {"  section differences:", "  节区差异:"},
        {"  root: ", "  产物根目录: "},
        {"  parent: ", "  父产物: "},
        {"    parent: ", "    父产物: "},
        {"  root_input: ", "  根输入: "},
        {"  offset_basis: ", "  偏移基准: "},
        {"  state: ", "  状态: "},
        {"  version: ", "  版本: "},
        {"  source: ", "  来源: "},
        {"  output: ", "  输出: "},
        {"  files: ", "  文件数: "},
        {"  warning: ", "  警告: "},
        {"  error: ", "  错误: "},
        {"    warning: ", "    警告: "},
        {"    error: ", "    错误: "},
        {"    path: ", "    路径: "},
        {"    range: ", "    范围: "},
        {"    priority_range: ", "    优先范围: "},
        {"  launched: ", "  已启动: "},
        {"  timed_out: ", "  已超时: "},
        {"  target_file_after_run: ", "  运行后目标文件: "},
        {"  target_write_time_changed: ", "  目标写入时间已变化: "},
        {"  before: ", "  运行前: "},
        {"  after:  ", "  运行后:  "},
        {"  exit_code: ", "  退出码: "},
        {"  console_output: ", "  控制台输出: "},
        {"  target: ", "  目标: "},
        {"  backup: ", "  备份: "},
        {"  validation: ", "  验证: "},
    };
    auto replace_all=[](std::string&line,std::string_view from,std::string_view to){
        std::size_t pos=0;
        while((pos=line.find(from,pos))!=std::string::npos){line.replace(pos,from.size(),to);pos+=to.size();}
    };
    auto localize_payload=[](std::string&line,std::string_view prefix){
        if(line.rfind(prefix,0)!=0)return false;
        line.replace(prefix.size(),line.size()-prefix.size(),localize_semantic_zh(std::string_view(line).substr(prefix.size())));
        return true;
    };
    std::ostringstream out;
    std::size_t pos=0;
    while(pos<text.size()){
        const auto nl=text.find('\n',pos);
        const auto end=nl==std::string_view::npos?text.size():nl;
        std::string line(text.substr(pos,end-pos));
        for(const auto&[from,to]:prefixes){
            if(line.rfind(from,0)==0){line.replace(0,from.size(),to);break;}
        }
        if(line.rfind("    + ",0)==0)line.replace(0,6,"    证据 + ");
        else if(line.rfind("    - ",0)==0)line.replace(0,6,"    负证据 - ");
        else if(line.rfind("    -> ",0)==0)line.replace(0,7,"    建议 -> ");

        for(const auto prefix:{std::string_view("    证据 + "),std::string_view("    负证据 - "),std::string_view("    建议 -> "),
                               std::string_view("    原因: "),std::string_view("    条件: "),std::string_view("    证据: "),
                               std::string_view("    负证据: "),std::string_view("  可见假设: "),std::string_view("  未决替代路径: "),
                               std::string_view("  优先理由: "),std::string_view("  运行时模态优先级: ")}){
            if(localize_payload(line,prefix))break;
        }

        if(line.rfind("  [",0)==0){
            replace_all(line," state="," 状态=");replace_all(line," confidence="," 置信度=");
            replace_all(line," role="," 角色=");replace_all(line," priority="," 优先级=");
        }
        if(line.rfind("    size=",0)==0){
            line.replace(4,5,"大小=");replace_all(line," normalized="," 已规范化=");replace_all(line," runtime_confirmed="," 运行时已确认=");
        }
        replace_all(line,", section headers: ",", 节区头: ");
        if(line.rfind("隐式执行: ",0)==0){
            replace_all(line,"state=","状态=");replace_all(line,"facts=","事实数=");replace_all(line,"rendered=","已展示=");
            replace_all(line,"high=","高优先级=");replace_all(line,"review=","需复核=");replace_all(line,"anomalies=","异常=");
            replace_all(line,"informational=","信息项=");replace_all(line,"unresolved_runtime_semantics=","未决运行时语义=");replace_all(line,"analysis_limited=","分析受限=");
        }else if(line.rfind("  运行时模态: ",0)==0){
            replace_all(line," state="," 状态=");replace_all(line," confidence="," 置信度=");replace_all(line," gate="," 证据门槛=");
        }
        constexpr std::string_view implicit_truncated="  ... default implicit fact table truncated; complete CSV: ";
        if(line.rfind(implicit_truncated,0)==0)
            line.replace(0,implicit_truncated.size(),"  ... 默认隐式执行事实表已截断；完整 CSV: ");
        else if(line=="  ... default implicit fact table truncated; complete CSV omitted by the default artifact budget; use --extract for the full supported map")
            line="  ... 默认隐式执行事实表已截断；完整 CSV 因默认产物预算而省略，可使用 --extract 获取完整受支持映射";
        else if(line.rfind("  section ",0)==0&&line.ends_with(" present")){
            line.replace(0,10,"  节区 ");line.replace(line.size()-8,8," 存在");
        }
        if(line.rfind("  Type Flags Address",0)==0)line="  类型 标志 地址             偏移        文件大小    内存大小    熵";
        else if(line.rfind("  Name       RVA",0)==0)line="  名称       RVA       虚拟大小    原始偏移    原始大小    有效大小    熵      权限";
        else if(line.rfind("  Name               Address",0)==0)line="  名称               地址              偏移        大小        有效大小    熵      标志";
        out<<line;
        if(nl!=std::string_view::npos)out<<'\n';
        if(nl==std::string_view::npos)break;
        pos=nl+1;
    }
    return out.str();
}
}

std::string render_text(const AnalysisReport& r,ReportLanguage language) {
    auto text=render_text(r);
    if(language==ReportLanguage::Chinese)return localize_text_zh(text);
    return text;
}

namespace {
struct ChildJsonPlaneLimit {
    std::string name;
    std::size_t total=0,cap=0,retained=std::numeric_limits<std::size_t>::max();
    std::size_t rendered()const{return std::min(total,std::min(cap,retained));}
};
constexpr std::size_t kChildDexMapItems=128,kChildDexTypes=128,kChildDexProtos=128,kChildDexFields=128,kChildDexMethods=256,kChildDexCodeItems=128,kChildDexClasses=64,kChildDexMethodHandles=64,kChildDexCallSites=64,kChildDexLibraryLoads=128,kChildDexStrings=256,kChildDexStringHints=256,kChildDexAnomalies=64;
constexpr std::size_t kChildDotnetTableRows=64,kChildDotnetAssemblyRefs=64,kChildDotnetTypeRefs=128,kChildDotnetTypes=128,kChildDotnetFields=128,kChildDotnetParams=128,kChildDotnetMethods=256,kChildDotnetMemberRefs=128,kChildDotnetProperties=64,kChildDotnetEvents=64,kChildDotnetGenericParams=64,kChildDotnetMethodSpecs=64,kChildDotnetResources=64,kChildDotnetObfuscationHints=64,kChildDotnetAnomalies=64;
constexpr std::size_t kChildDotnetBundleEntries=64,kChildNativeAotSections=64;
constexpr std::size_t kChildSwiftTypes=64,kChildSwiftFields=64;

struct SwiftSliceRenderPlan {
    std::size_t types_total=0,types_rendered=0,fields_total=0,fields_rendered=0;
    std::vector<std::size_t> fields_rendered_per_type;
};

SwiftSliceRenderPlan swift_slice_render_plan(const MachOSwiftInfo&swift,std::size_t&types_remaining,std::size_t&fields_remaining){
    SwiftSliceRenderPlan plan;plan.types_total=swift.types.size();plan.types_rendered=std::min(plan.types_total,types_remaining);types_remaining-=plan.types_rendered;
    plan.fields_rendered_per_type.reserve(plan.types_rendered);
    for(const auto&type:swift.types)plan.fields_total+=type.fields.size();
    for(std::size_t i=0;i<plan.types_rendered;++i){const auto retained=std::min(swift.types[i].fields.size(),fields_remaining);plan.fields_rendered_per_type.push_back(retained);plan.fields_rendered+=retained;fields_remaining-=retained;}
    return plan;
}

std::vector<ChildJsonPlaneLimit> child_json_plane_limits(const AnalysisReport&r){
    std::vector<ChildJsonPlaneLimit> x={{"dex.map_items",r.dex.map_items.size(),kChildDexMapItems},{"dex.types",r.dex.types.size(),kChildDexTypes},{"dex.protos",r.dex.protos.size(),kChildDexProtos},{"dex.fields",r.dex.fields.size(),kChildDexFields},{"dex.methods",r.dex.methods.size(),kChildDexMethods},{"dex.code_items",r.dex.code_items.size(),kChildDexCodeItems},{"dex.classes",r.dex.classes.size(),kChildDexClasses},{"dex.method_handles",r.dex.method_handles.size(),kChildDexMethodHandles},{"dex.call_sites",r.dex.call_sites.size(),kChildDexCallSites},{"dex.library_loads",r.dex.library_loads.size(),kChildDexLibraryLoads},{"dex.strings",r.dex.strings.size(),kChildDexStrings},{"dex.string_hints",r.dex.string_hints.size(),kChildDexStringHints},{"dex.anomalies",r.dex.anomalies.size(),kChildDexAnomalies},
        {"dotnet.table_rows",r.dotnet.table_rows.size(),kChildDotnetTableRows},{"dotnet.assembly_refs",r.dotnet.assembly_refs.size(),kChildDotnetAssemblyRefs},{"dotnet.type_refs",r.dotnet.type_refs.size(),kChildDotnetTypeRefs},{"dotnet.types",r.dotnet.types.size(),kChildDotnetTypes},{"dotnet.fields",r.dotnet.fields.size(),kChildDotnetFields},{"dotnet.params",r.dotnet.params.size(),kChildDotnetParams},{"dotnet.methods",r.dotnet.methods.size(),kChildDotnetMethods},{"dotnet.member_refs",r.dotnet.member_refs.size(),kChildDotnetMemberRefs},{"dotnet.properties",r.dotnet.properties.size(),kChildDotnetProperties},{"dotnet.events",r.dotnet.events.size(),kChildDotnetEvents},{"dotnet.generic_params",r.dotnet.generic_params.size(),kChildDotnetGenericParams},{"dotnet.method_specs",r.dotnet.method_specs.size(),kChildDotnetMethodSpecs},{"dotnet.resources",r.dotnet.resources.size(),kChildDotnetResources},{"dotnet.obfuscation_hints",r.dotnet.obfuscation_hints.size(),kChildDotnetObfuscationHints},{"dotnet.anomalies",r.dotnet.anomalies.size(),kChildDotnetAnomalies}};
    x.push_back({"dotnet_bundle.entries",r.dotnet_bundle.entries.size(),kChildDotnetBundleEntries});
    x.push_back({"native_aot.sections",r.native_aot.sections.size(),kChildNativeAotSections});
    x.push_back({"hermes.functions",r.hermes.functions.size(),256});
    x.push_back({"hermes.strings",r.hermes.strings.size(),512});
    std::size_t swift_types_remaining=kChildSwiftTypes,swift_fields_remaining=kChildSwiftFields;
    std::size_t swift_types_total=0,swift_types_rendered=0,swift_fields_total=0,swift_fields_rendered=0;
    for(const auto&slice:r.macho.slices){const auto plan=swift_slice_render_plan(slice.swift,swift_types_remaining,swift_fields_remaining);swift_types_total+=plan.types_total;swift_types_rendered+=plan.types_rendered;swift_fields_total+=plan.fields_total;swift_fields_rendered+=plan.fields_rendered;}
    x.push_back({"macho.swift.types",swift_types_total,kChildSwiftTypes,swift_types_rendered});
    x.push_back({"macho.swift.fields",swift_fields_total,kChildSwiftFields,swift_fields_rendered});
    return x;
}

void render_cardinality(std::ostream&o,const char*name,std::size_t total,std::size_t cap){const auto rendered=std::min(total,cap);o<<"\""<<name<<"_total\":"<<total<<",\""<<name<<"_rendered\":"<<rendered<<",\""<<name<<"_omitted\":"<<(total-rendered)<<",\""<<name<<"_truncated\":"<<(total>rendered?"true":"false");}

void render_automatic_child_retention(std::ostream&o,const AnalysisReport&r){
    auto limits=child_json_plane_limits(r);std::uint64_t omitted=0;std::vector<std::string>planes;
    for(const auto&x:limits){const auto rendered=x.rendered();if(x.total>rendered){omitted+=static_cast<std::uint64_t>(x.total-rendered);planes.emplace_back(x.name);}}
    o<<"  \"report_retention\": {\"profile\":\"automatic_child_summary\",\"analysis_execution_profile\":\"full\",\"analysis_completed_before_persistence\":true,\"persisted_full_detail\":false,\"summary_omission_means_evidence_absent\":false,\"sampling_policy\":\"deterministic_parser_order_prefix\",\"omitted_rows\":"<<omitted<<",\"omitted_planes\":[";
    for(std::size_t i=0;i<planes.size();++i){if(i)o<<',';o<<"\""<<esc(planes[i])<<"\"";}
    o<<"],\"full_evidence_retrieval\":{\"mode\":\"reanalyze_persisted_input\",\"input\":\""<<esc(path_utf8(r.input))<<"\",\"input_sha256\":\""<<esc(r.input_snapshot.sha256)<<"\",\"required_option\":\"--json\",\"result_profile\":\"full\"}},\n";
}

void render_dex_summary_json(std::ostream&o,const AnalysisReport&r){
    const auto&d=r.dex;
    o << "  \"dex\": {\"candidate\":"<<(d.candidate?"true":"false")<<",\"valid\":"<<(d.valid?"true":"false")<<",\"state\":\""<<(d.candidate?(d.valid?"CONFIRMED":"FAILED"):"ABSENT")<<"\",\"version\":\""<<esc(d.version)<<"\",\"offset_space\":\"current_input_file\",\"reverse_endian\":"<<(d.reverse_endian?"true":"false")<<",\"container_v41\":"<<(d.container_v41?"true":"false")<<",\"header_size\":"<<d.header_size<<",\"file_size\":"<<d.file_size<<",\"container_size\":"<<d.container_size<<",\"header_offset\":"<<d.header_offset<<",\"map_off\":"<<d.map_off<<",\"string_ids_size\":"<<d.string_ids_size<<",\"string_ids_off\":"<<d.string_ids_off<<",\"type_ids_size\":"<<d.type_ids_size<<",\"type_ids_off\":"<<d.type_ids_off<<",\"proto_ids_size\":"<<d.proto_ids_size<<",\"proto_ids_off\":"<<d.proto_ids_off<<",\"field_ids_size\":"<<d.field_ids_size<<",\"field_ids_off\":"<<d.field_ids_off<<",\"method_ids_size\":"<<d.method_ids_size<<",\"method_ids_off\":"<<d.method_ids_off<<",\"class_defs_size\":"<<d.class_defs_size<<",\"class_defs_off\":"<<d.class_defs_off<<",\"data_size\":"<<d.data_size<<",\"data_off\":"<<d.data_off<<",\"defined_field_count\":"<<d.defined_field_count<<",\"defined_method_count\":"<<d.defined_method_count<<",\"code_item_count\":"<<d.code_item_count<<",\"debug_info_count\":"<<d.debug_info_count<<",\"map_complete\":"<<(d.map_complete?"true":"false")<<",\"descriptor_parse_complete\":"<<(d.descriptor_parse_complete?"true":"false")<<",\"jni_surface_scan_complete\":"<<(d.jni_surface_scan_complete?"true":"false")<<",\"jni_surface_scan_error\":\""<<esc(d.jni_surface_scan_error)<<"\",\"library_load_count\":"<<d.library_loads.size()<<",\"checksum_checked\":"<<(d.checksum_checked?"true":"false")<<",\"checksum_matches\":"<<(d.checksum_matches?"true":"false")<<",\"signature_checked\":"<<(d.signature_checked?"true":"false")<<",\"signature_matches\":"<<(d.signature_matches?"true":"false")<<",\"error_offset\":"<<d.error_offset<<",\"error\":\""<<esc(d.error)<<"\",";
    render_cardinality(o,"map_items",d.map_items.size(),kChildDexMapItems);o<<",\"map_items\":[";for(std::size_t i=0;i<d.map_items.size()&&i<kChildDexMapItems;++i){if(i)o<<',';const auto&m=d.map_items[i];o<<"{\"type\":"<<m.type<<",\"name\":\""<<esc(m.name)<<"\",\"size\":"<<m.size<<",\"offset\":"<<m.offset<<",\"offset_space\":\"current_input_file\"}";}
    o<<"],";render_cardinality(o,"types",d.types.size(),kChildDexTypes);o<<",\"types\":[";for(std::size_t i=0;i<d.types.size()&&i<kChildDexTypes;++i){if(i)o<<',';o<<"\""<<esc(d.types[i])<<"\"";}
    o<<"],";render_cardinality(o,"protos",d.protos.size(),kChildDexProtos);o<<",\"protos\":[";for(std::size_t i=0;i<d.protos.size()&&i<kChildDexProtos;++i){if(i)o<<',';const auto&p=d.protos[i];o<<"{\"index\":"<<p.index<<",\"shorty\":\""<<esc(p.shorty)<<"\",\"return_type\":\""<<esc(p.return_type)<<"\",\"signature\":\""<<esc(p.signature)<<"\",\"descriptor\":\""<<esc(p.descriptor)<<"\",\"parameters_off\":"<<p.parameters_off<<",\"offset_space\":\"current_input_file\",\"parameter_types\":[";for(std::size_t z=0;z<p.parameter_types.size();++z){if(z)o<<',';o<<"\""<<esc(p.parameter_types[z])<<"\"";}o<<"]}";}
    o<<"],";render_cardinality(o,"fields",d.fields.size(),kChildDexFields);o<<",\"fields\":[";for(std::size_t i=0;i<d.fields.size()&&i<kChildDexFields;++i){if(i)o<<',';const auto&f=d.fields[i];o<<"{\"index\":"<<f.index<<",\"defined\":"<<(f.defined?"true":"false")<<",\"owner\":\""<<esc(f.owner)<<"\",\"name\":\""<<esc(f.name)<<"\",\"type\":\""<<esc(f.type)<<"\",\"signature\":\""<<esc(f.signature)<<"\",\"access_flags\":"<<f.access_flags<<"}";}
    o<<"],";render_cardinality(o,"methods",d.methods.size(),kChildDexMethods);o<<",\"methods\":[";for(std::size_t i=0;i<d.methods.size()&&i<kChildDexMethods;++i){if(i)o<<',';const auto&m=d.methods[i];o<<"{\"index\":"<<m.index<<",\"defined\":"<<(m.defined?"true":"false")<<",\"owner\":\""<<esc(m.owner)<<"\",\"owner_descriptor\":\""<<esc(m.owner_descriptor)<<"\",\"name\":\""<<esc(m.name)<<"\",\"signature\":\""<<esc(m.signature)<<"\",\"descriptor\":\""<<esc(m.descriptor)<<"\",\"access_flags\":"<<m.access_flags<<",\"code_off\":"<<m.code_off<<",\"offset_space\":\"current_input_file\"}";}
    o<<"],";render_cardinality(o,"code_items",d.code_items.size(),kChildDexCodeItems);o<<",\"code_items\":[";for(std::size_t i=0;i<d.code_items.size()&&i<kChildDexCodeItems;++i){if(i)o<<',';const auto&c=d.code_items[i];o<<"{\"method_idx\":"<<c.method_idx<<",\"code_off\":"<<c.code_off<<",\"code_size_bytes\":"<<c.code_size_bytes<<",\"debug_info_off\":"<<c.debug_info_off<<",\"registers_size\":"<<c.registers_size<<",\"ins_size\":"<<c.ins_size<<",\"outs_size\":"<<c.outs_size<<",\"tries_size\":"<<c.tries_size<<",\"insns_size\":"<<c.insns_size<<",\"debug_line_start\":"<<c.debug_line_start<<",\"debug_position_count\":"<<c.debug_position_count<<",\"offset_space\":\"current_input_file\",\"parameter_names\":[";for(std::size_t z=0;z<c.parameter_names.size();++z){if(z)o<<',';o<<"\""<<esc(c.parameter_names[z])<<"\"";}o<<"]}";}
    o<<"],";render_cardinality(o,"classes",d.classes.size(),kChildDexClasses);o<<",\"classes\":[";for(std::size_t i=0;i<d.classes.size()&&i<kChildDexClasses;++i){if(i)o<<',';const auto&c=d.classes[i];o<<"{\"class_idx\":"<<c.class_idx<<",\"name\":\""<<esc(c.name)<<"\",\"superclass\":\""<<esc(c.superclass)<<"\",\"source_file\":\""<<esc(c.source_file)<<"\",\"access_flags\":"<<c.access_flags<<",\"interfaces_off\":"<<c.interfaces_off<<",\"class_data_off\":"<<c.class_data_off<<",\"static_values_off\":"<<c.static_values_off<<",\"static_field_count\":"<<c.static_field_count<<",\"instance_field_count\":"<<c.instance_field_count<<",\"direct_method_count\":"<<c.direct_method_count<<",\"virtual_method_count\":"<<c.virtual_method_count<<",\"offset_space\":\"current_input_file\",\"interfaces\":[";for(std::size_t z=0;z<c.interfaces.size();++z){if(z)o<<',';o<<"\""<<esc(c.interfaces[z])<<"\"";}o<<"]}";}
    o<<"],";render_cardinality(o,"method_handles",d.method_handles.size(),kChildDexMethodHandles);o<<",\"method_handles\":[";for(std::size_t i=0;i<d.method_handles.size()&&i<kChildDexMethodHandles;++i){if(i)o<<',';const auto&h=d.method_handles[i];o<<"{\"index\":"<<h.index<<",\"handle_type\":"<<h.handle_type<<",\"field_or_method_id\":"<<h.field_or_method_id<<",\"references_field\":"<<(h.references_field?"true":"false")<<",\"target\":\""<<esc(h.target)<<"\"}";}
    o<<"],";render_cardinality(o,"call_sites",d.call_sites.size(),kChildDexCallSites);o<<",\"call_sites\":[";for(std::size_t i=0;i<d.call_sites.size()&&i<kChildDexCallSites;++i){if(i)o<<',';const auto&c=d.call_sites[i];o<<"{\"index\":"<<c.index<<",\"call_site_off\":"<<c.call_site_off<<",\"bootstrap_method_handle_idx\":"<<c.bootstrap_method_handle_idx<<",\"method_name_idx\":"<<c.method_name_idx<<",\"method_type_idx\":"<<c.method_type_idx<<",\"extra_argument_count\":"<<c.extra_argument_count<<",\"method_name\":\""<<esc(c.method_name)<<"\",\"method_type\":\""<<esc(c.method_type)<<"\",\"bootstrap_target\":\""<<esc(c.bootstrap_target)<<"\",\"offset_space\":\"current_input_file\"}";}
    o<<"],";render_cardinality(o,"library_loads",d.library_loads.size(),kChildDexLibraryLoads);o<<",\"library_loads\":[";for(std::size_t i=0;i<d.library_loads.size()&&i<kChildDexLibraryLoads;++i){if(i)o<<',';const auto&x=d.library_loads[i];o<<"{\"caller_method_idx\":"<<x.caller_method_idx<<",\"target_method_idx\":"<<x.target_method_idx<<",\"string_idx\":"<<x.string_idx<<",\"pc_code_units\":"<<x.pc_code_units<<",\"instruction_file_offset\":"<<x.instruction_file_offset<<",\"offset_space\":\"current_input_file\",\"library_name\":\""<<esc(x.library_name)<<"\"}";}
    o<<"],";render_cardinality(o,"strings",d.strings.size(),kChildDexStrings);o<<",\"strings\":[";for(std::size_t i=0;i<d.strings.size()&&i<kChildDexStrings;++i){if(i)o<<',';o<<"\""<<esc(d.strings[i])<<"\"";}
    o<<"],";render_cardinality(o,"string_hints",d.string_hints.size(),kChildDexStringHints);o<<",\"string_hints\":[";for(std::size_t i=0;i<d.string_hints.size()&&i<kChildDexStringHints;++i){if(i)o<<',';o<<"\""<<esc(d.string_hints[i])<<"\"";}
    o<<"],";render_cardinality(o,"anomalies",d.anomalies.size(),kChildDexAnomalies);o<<",\"anomalies\":[";for(std::size_t i=0;i<d.anomalies.size()&&i<kChildDexAnomalies;++i){if(i)o<<',';o<<"\""<<esc(d.anomalies[i])<<"\"";}
    o<<"],\"extraction\":{\"success\":"<<(r.dex_extract.success?"true":"false")<<",\"methods_csv\":\""<<esc(path_utf8(r.dex_extract.methods_csv))<<"\",\"method_count\":"<<r.dex_extract.method_count<<",\"classes_csv\":\""<<esc(path_utf8(r.dex_extract.classes_csv))<<"\",\"class_count\":"<<r.dex_extract.class_count<<",\"fields_csv\":\""<<esc(path_utf8(r.dex_extract.fields_csv))<<"\",\"field_count\":"<<r.dex_extract.field_count<<",\"callsites_csv\":\""<<esc(path_utf8(r.dex_extract.callsites_csv))<<"\",\"callsite_count\":"<<r.dex_extract.callsite_count<<",\"error\":\""<<esc(r.dex_extract.error)<<"\"}},\n";
}

void render_dotnet_summary_json(std::ostream&o,const AnalysisReport&r){
    const auto&d=r.dotnet;
    o << "  \"dotnet\": {\"candidate\":"<<(r.pe.clr.present?"true":"false")<<",\"valid\":"<<(d.valid?"true":"false")<<",\"state\":\""<<(r.pe.clr.present?(d.valid?"CONFIRMED":"FAILED"):"ABSENT")<<"\",\"unity_managed\":"<<(d.unity_managed?"true":"false")<<",\"unity_mono\":"<<(d.unity_mono?"true":"false")<<",\"unity_path_hint\":"<<(d.unity_path_hint?"true":"false")<<",\"unity_engine_reference\":"<<(d.unity_engine_reference?"true":"false")<<",\"runtime_version\":\""<<esc(d.runtime_version)<<"\",\"metadata_offset\":"<<d.metadata_offset<<",\"metadata_size\":"<<d.metadata_size<<",\"blob_heap_size\":"<<d.blob_heap_size<<",\"resources_offset\":"<<d.resources_offset<<",\"resources_size\":"<<d.resources_size<<",\"signature_parse_complete\":"<<(d.signature_parse_complete?"true":"false")<<",\"error\":\""<<esc(d.error)<<"\",";
    render_cardinality(o,"table_rows",d.table_rows.size(),kChildDotnetTableRows);o<<",\"table_rows\":[";for(std::size_t i=0;i<d.table_rows.size()&&i<kChildDotnetTableRows;++i){if(i)o<<',';o<<d.table_rows[i];}
    o<<"],";render_cardinality(o,"assembly_refs",d.assembly_refs.size(),kChildDotnetAssemblyRefs);o<<",\"assembly_refs\":[";for(std::size_t i=0;i<d.assembly_refs.size()&&i<kChildDotnetAssemblyRefs;++i){if(i)o<<',';const auto&a=d.assembly_refs[i];o<<"{\"token\":"<<a.token<<",\"name\":\""<<esc(a.name)<<"\",\"version\":\""<<esc(a.version)<<"\",\"culture\":\""<<esc(a.culture)<<"\"}";}
    o<<"],";render_cardinality(o,"type_refs",d.type_refs.size(),kChildDotnetTypeRefs);o<<",\"type_refs\":[";for(std::size_t i=0;i<d.type_refs.size()&&i<kChildDotnetTypeRefs;++i){if(i)o<<',';const auto&t=d.type_refs[i];o<<"{\"token\":"<<t.token<<",\"namespace\":\""<<esc(t.namespc)<<"\",\"name\":\""<<esc(t.name)<<"\",\"full_name\":\""<<esc(t.full_name)<<"\",\"resolution_scope\":"<<t.resolution_scope<<",\"scope_name\":\""<<esc(t.scope_name)<<"\"}";}
    o<<"],";render_cardinality(o,"types",d.types.size(),kChildDotnetTypes);o<<",\"types\":[";for(std::size_t i=0;i<d.types.size()&&i<kChildDotnetTypes;++i){if(i)o<<',';const auto&t=d.types[i];o<<"{\"token\":"<<t.token<<",\"flags\":"<<t.flags<<",\"namespace\":\""<<esc(t.namespc)<<"\",\"name\":\""<<esc(t.name)<<"\",\"full_name\":\""<<esc(t.full_name)<<"\",\"base_type\":\""<<esc(t.base_type)<<"\",\"extends_token\":"<<t.extends_token<<",\"enclosing_type\":\""<<esc(t.enclosing_type)<<"\",\"interfaces\":[";for(std::size_t z=0;z<t.interfaces.size();++z){if(z)o<<',';o<<"\""<<esc(t.interfaces[z])<<"\"";}o<<"],\"generic_params\":[";for(std::size_t z=0;z<t.generic_params.size();++z){if(z)o<<',';o<<"\""<<esc(t.generic_params[z])<<"\"";}o<<"]}";}
    o<<"],";render_cardinality(o,"fields",d.fields.size(),kChildDotnetFields);o<<",\"fields\":[";for(std::size_t i=0;i<d.fields.size()&&i<kChildDotnetFields;++i){if(i)o<<',';const auto&f=d.fields[i];o<<"{\"token\":"<<f.token<<",\"flags\":"<<f.flags<<",\"declaring_type\":\""<<esc(f.declaring_type)<<"\",\"name\":\""<<esc(f.name)<<"\",\"type\":\""<<esc(f.type_name)<<"\",\"signature\":\""<<esc(f.signature)<<"\",\"has_layout\":"<<(f.has_layout?"true":"false")<<",\"offset\":"<<f.offset<<",\"has_rva\":"<<(f.has_rva?"true":"false")<<",\"rva\":"<<f.rva<<"}";}
    o<<"],";render_cardinality(o,"params",d.params.size(),kChildDotnetParams);o<<",\"params\":[";for(std::size_t i=0;i<d.params.size()&&i<kChildDotnetParams;++i){if(i)o<<',';const auto&p=d.params[i];o<<"{\"token\":"<<p.token<<",\"flags\":"<<p.flags<<",\"sequence\":"<<p.sequence<<",\"name\":\""<<esc(p.name)<<"\"}";}
    o<<"],";render_cardinality(o,"methods",d.methods.size(),kChildDotnetMethods);o<<",\"methods\":[";for(std::size_t i=0;i<d.methods.size()&&i<kChildDotnetMethods;++i){if(i)o<<',';const auto&m=d.methods[i];o<<"{\"token\":"<<m.token<<",\"rva\":"<<m.rva<<",\"impl_flags\":"<<m.impl_flags<<",\"flags\":"<<m.flags<<",\"declaring_type\":\""<<esc(m.type_name)<<"\",\"name\":\""<<esc(m.name)<<"\",\"signature\":\""<<esc(m.signature)<<"\",\"return_type\":\""<<esc(m.return_type)<<"\",\"full_name\":\""<<esc(m.full_name)<<"\",\"calling_convention\":\""<<esc(m.calling_convention)<<"\",\"has_this\":"<<(m.has_this?"true":"false")<<",\"explicit_this\":"<<(m.explicit_this?"true":"false")<<",\"generic_arity\":"<<m.generic_arity<<",\"param_types\":[";for(std::size_t z=0;z<m.param_types.size();++z){if(z)o<<',';o<<"\""<<esc(m.param_types[z])<<"\"";}o<<"],\"param_names\":[";for(std::size_t z=0;z<m.param_names.size();++z){if(z)o<<',';o<<"\""<<esc(m.param_names[z])<<"\"";}o<<"],\"generic_params\":[";for(std::size_t z=0;z<m.generic_params.size();++z){if(z)o<<',';o<<"\""<<esc(m.generic_params[z])<<"\"";}o<<"],\"pinvoke\":"<<(m.pinvoke?"true":"false")<<",\"import_module\":\""<<esc(m.import_module)<<"\",\"import_name\":\""<<esc(m.import_name)<<"\"}";}
    o<<"],";render_cardinality(o,"member_refs",d.member_refs.size(),kChildDotnetMemberRefs);o<<",\"member_refs\":[";for(std::size_t i=0;i<d.member_refs.size()&&i<kChildDotnetMemberRefs;++i){if(i)o<<',';const auto&m=d.member_refs[i];o<<"{\"token\":"<<m.token<<",\"parent_token\":"<<m.parent_token<<",\"parent\":\""<<esc(m.parent)<<"\",\"name\":\""<<esc(m.name)<<"\",\"kind\":\""<<esc(m.kind)<<"\",\"signature\":\""<<esc(m.signature)<<"\"}";}
    o<<"],";render_cardinality(o,"properties",d.properties.size(),kChildDotnetProperties);o<<",\"properties\":[";for(std::size_t i=0;i<d.properties.size()&&i<kChildDotnetProperties;++i){if(i)o<<',';const auto&p=d.properties[i];o<<"{\"token\":"<<p.token<<",\"declaring_type\":\""<<esc(p.declaring_type)<<"\",\"name\":\""<<esc(p.name)<<"\",\"type\":\""<<esc(p.type_name)<<"\",\"signature\":\""<<esc(p.signature)<<"\",\"getter\":\""<<esc(p.getter)<<"\",\"setter\":\""<<esc(p.setter)<<"\"}";}
    o<<"],";render_cardinality(o,"events",d.events.size(),kChildDotnetEvents);o<<",\"events\":[";for(std::size_t i=0;i<d.events.size()&&i<kChildDotnetEvents;++i){if(i)o<<',';const auto&e=d.events[i];o<<"{\"token\":"<<e.token<<",\"declaring_type\":\""<<esc(e.declaring_type)<<"\",\"name\":\""<<esc(e.name)<<"\",\"event_type\":\""<<esc(e.event_type)<<"\",\"adder\":\""<<esc(e.adder)<<"\",\"remover\":\""<<esc(e.remover)<<"\",\"raiser\":\""<<esc(e.raiser)<<"\"}";}
    o<<"],";render_cardinality(o,"generic_params",d.generic_params.size(),kChildDotnetGenericParams);o<<",\"generic_params\":[";for(std::size_t i=0;i<d.generic_params.size()&&i<kChildDotnetGenericParams;++i){if(i)o<<',';const auto&g=d.generic_params[i];o<<"{\"token\":"<<g.token<<",\"owner_token\":"<<g.owner_token<<",\"number\":"<<g.number<<",\"flags\":"<<g.flags<<",\"name\":\""<<esc(g.name)<<"\",\"owner\":\""<<esc(g.owner)<<"\",\"constraints\":[";for(std::size_t z=0;z<g.constraints.size();++z){if(z)o<<',';o<<"\""<<esc(g.constraints[z])<<"\"";}o<<"]}";}
    o<<"],";render_cardinality(o,"method_specs",d.method_specs.size(),kChildDotnetMethodSpecs);o<<",\"method_specs\":[";for(std::size_t i=0;i<d.method_specs.size()&&i<kChildDotnetMethodSpecs;++i){if(i)o<<',';const auto&m=d.method_specs[i];o<<"{\"token\":"<<m.token<<",\"method_token\":"<<m.method_token<<",\"method\":\""<<esc(m.method)<<"\",\"signature\":\""<<esc(m.signature)<<"\",\"type_args\":[";for(std::size_t z=0;z<m.type_args.size();++z){if(z)o<<',';o<<"\""<<esc(m.type_args[z])<<"\"";}o<<"]}";}
    o<<"],";render_cardinality(o,"resources",d.resources.size(),kChildDotnetResources);o<<",\"resources\":[";for(std::size_t i=0;i<d.resources.size()&&i<kChildDotnetResources;++i){if(i)o<<',';const auto&x=d.resources[i];o<<"{\"token\":"<<x.token<<",\"name\":\""<<esc(x.name)<<"\",\"flags\":"<<x.flags<<",\"implementation_token\":"<<x.implementation_token<<",\"implementation\":\""<<esc(x.implementation)<<"\",\"embedded\":"<<(x.embedded?"true":"false")<<",\"size_known\":"<<(x.size_known?"true":"false")<<",\"data_offset\":"<<x.data_offset<<",\"size\":"<<x.size<<"}";}
    o<<"],";render_cardinality(o,"obfuscation_hints",d.obfuscation_hints.size(),kChildDotnetObfuscationHints);o<<",\"obfuscation_hints\":[";for(std::size_t i=0;i<d.obfuscation_hints.size()&&i<kChildDotnetObfuscationHints;++i){if(i)o<<',';o<<"\""<<esc(d.obfuscation_hints[i])<<"\"";}
    o<<"],";render_cardinality(o,"anomalies",d.anomalies.size(),kChildDotnetAnomalies);o<<",\"anomalies\":[";for(std::size_t i=0;i<d.anomalies.size()&&i<kChildDotnetAnomalies;++i){if(i)o<<',';o<<"\""<<esc(d.anomalies[i])<<"\"";}
    o<<"],\"extraction\":{\"success\":"<<(r.dotnet_extract.success?"true":"false")<<",\"symbols_csv\":\""<<esc(path_utf8(r.dotnet_extract.symbols_csv))<<"\",\"symbol_count\":"<<r.dotnet_extract.symbol_count<<",\"types_csv\":\""<<esc(path_utf8(r.dotnet_extract.types_csv))<<"\",\"type_count\":"<<r.dotnet_extract.type_count<<",\"members_csv\":\""<<esc(path_utf8(r.dotnet_extract.members_csv))<<"\",\"member_count\":"<<r.dotnet_extract.member_count<<"}},\n";
}
}


void render_dotnet_native_json(std::ostream&o,const AnalysisReport&r,bool compact){
    const auto&b=r.dotnet_bundle;
    o<<"  \"dotnet_bundle\": {\"candidate\":"<<(b.candidate?"true":"false")<<",\"valid\":"<<(b.valid?"true":"false")
     <<",\"state\":\""<<esc(b.state)<<"\",\"error\":\""<<esc(b.error)<<"\",\"version\":\""<<b.major_version<<'.'<<b.minor_version
     <<"\",\"locator_offset\":"<<b.locator_offset<<",\"header_offset\":"<<b.header_offset<<",\"manifest_end\":"<<b.manifest_end
     <<",\"trailing_bytes\":"<<b.trailing_bytes<<",\"file_count\":"<<b.file_count<<",\"bundle_id\":\""<<esc(b.bundle_id)
     <<"\",\"deps_json_offset\":"<<b.deps_json_offset<<",\"deps_json_size\":"<<b.deps_json_size
     <<",\"runtimeconfig_json_offset\":"<<b.runtimeconfig_json_offset<<",\"runtimeconfig_json_size\":"<<b.runtimeconfig_json_size
     <<",\"flags\":"<<b.flags<<",\"stored_bytes\":"<<b.stored_bytes<<",\"uncompressed_bytes\":"<<b.uncompressed_bytes
     <<",\"compressed_file_count\":"<<b.compressed_file_count<<",\"integrity_state\":\""<<esc(b.integrity_state)<<"\",\"entries_total\":"<<b.entries.size()<<",\"entries_rendered\":"<<std::min<std::size_t>(b.entries.size(),compact?64:512)<<",\"entries_omitted\":"<<(b.entries.size()-std::min<std::size_t>(b.entries.size(),compact?64:512))<<",\"entries_truncated\":"<<(b.entries.size()>(compact?64:512)?"true":"false")<<",\"entries\":[";
    for(std::size_t x=0;x<b.entries.size()&&x<(compact?64:512);++x){if(x)o<<',';const auto&e=b.entries[x];o<<"{\"index\":"<<e.index<<",\"offset\":"<<e.offset<<",\"size\":"<<e.size<<",\"compressed_size\":"<<e.compressed_size<<",\"stored_size\":"<<e.stored_size<<",\"compressed\":"<<(e.compressed?"true":"false")<<",\"type\":"<<static_cast<unsigned>(e.type)<<",\"type_name\":\""<<esc(e.type_name)<<"\",\"relative_path\":\""<<esc(e.relative_path)<<"\"}";}
    o<<"]},\n";
    const auto&n=r.native_aot;
    o<<"  \"native_aot\": {\"candidate\":"<<(n.candidate?"true":"false")<<",\"valid\":"<<(n.valid?"true":"false")
     <<",\"state\":\""<<esc(n.state)<<"\",\"platform\":\""<<esc(n.platform)<<"\",\"error\":\""<<esc(n.error)
     <<"\",\"modules_offset\":"<<n.modules_offset<<",\"modules_size\":"<<n.modules_size<<",\"header_offset\":"<<n.header_offset
     <<",\"header_va\":"<<n.header_va<<",\"version\":\""<<n.major_version<<'.'<<n.minor_version<<"\",\"section_count\":"<<n.section_count
     <<",\"entry_size\":"<<static_cast<unsigned>(n.entry_size)<<",\"entry_type\":"<<static_cast<unsigned>(n.entry_type)
     <<",\"raw_rtr_magic_count\":"<<n.raw_rtr_magic_count<<",\"valid_rtr_header_count\":"<<n.valid_rtr_header_count
     <<",\"native_section_id_count\":"<<n.native_section_id_count<<",\"has_managed_code_section\":"<<(n.has_managed_code_section?"true":"false")
     <<",\"has_dotnet_eh_table\":"<<(n.has_dotnet_eh_table?"true":"false")<<",\"has_hydrated_section\":"<<(n.has_hydrated_section?"true":"false")<<",\"sections_total\":"<<n.sections.size()<<",\"sections_rendered\":"<<std::min<std::size_t>(n.sections.size(),compact?64:512)<<",\"sections_omitted\":"<<(n.sections.size()-std::min<std::size_t>(n.sections.size(),compact?64:512))<<",\"sections_truncated\":"<<(n.sections.size()>(compact?64:512)?"true":"false")<<",\"sections\":[";
    for(std::size_t x=0;x<n.sections.size()&&x<(compact?64:512);++x){if(x)o<<',';const auto&e=n.sections[x];o<<"{\"id\":"<<e.id<<",\"flags\":"<<e.flags<<",\"start_va\":"<<e.start_va<<",\"end_va\":"<<e.end_va<<"}";}
    o<<"]},\n";
}

void render_json_impl(std::ostream& o,const AnalysisReport& r,bool automatic_child_summary) {
    o << "{\n"
      << "  \"report_schema_version\": \"" << kReportSchemaVersion << "\",\n"
      << "  \"input\": \"" << esc(path_utf8(r.input)) << "\",\n"
      << "  \"sha256\": \"" << r.input_snapshot.sha256 << "\",\n"
      << "  \"size\": " << r.input_snapshot.size << ",\n";
    if(automatic_child_summary)render_automatic_child_retention(o,r);
    o << "  \"artifact\": {\"graph_member\":"<<(r.artifact.graph_member?"true":"false")<<",\"root\":"<<(r.artifact.root?"true":"false")<<",\"depth\":"<<r.artifact.depth<<",\"parent\":\""<<esc(path_utf8(r.artifact.parent))<<"\",\"root_input\":\""<<esc(path_utf8(r.artifact.root_input))<<"\",\"offset_basis\":\""<<esc(path_utf8(r.artifact.offset_basis))<<"\",\"offset_space\":\""<<esc(r.artifact.offset_space)<<"\",\"relation\":\""<<esc(r.artifact.relation)<<"\"},\n"
      << "  \"artifact_graph\": {\"enabled\":"<<(r.artifact_graph.enabled?"true":"false")<<",\"truncated\":"<<(r.artifact_graph.truncated?"true":"false")<<",\"max_depth\":"<<r.artifact_graph.max_depth<<",\"max_nodes\":"<<r.artifact_graph.max_nodes<<",\"max_total_bytes\":"<<r.artifact_graph.max_total_bytes<<",\"nodes\":"<<r.artifact_graph.nodes<<",\"materialized_files\":"<<r.artifact_graph.materialized_files<<",\"materialized_bytes\":"<<r.artifact_graph.materialized_bytes<<",\"admitted_bytes\":"<<r.artifact_graph.admitted_bytes<<",\"deduplicated\":"<<r.artifact_graph.deduplicated<<",\"skipped_limits\":"<<r.artifact_graph.skipped_limits<<",\"skipped_unsafe\":"<<r.artifact_graph.skipped_unsafe<<",\"edges\":[";
    for(std::size_t i=0;i<r.artifact_graph.edges.size();++i){if(i)o<<',';const auto&e=r.artifact_graph.edges[i];o<<"{\"parent\":\""<<esc(path_utf8(e.parent))<<"\",\"child\":\""<<esc(path_utf8(e.child))<<"\",\"relation\":\""<<esc(e.relation)<<"\",\"depth\":"<<e.depth<<",\"size\":"<<e.size<<",\"sha256\":\""<<esc(e.sha256)<<"\",\"state\":\""<<esc(e.state)<<"\",\"duplicate_of\":\""<<esc(path_utf8(e.duplicate_of))<<"\"}";}
    o<<"],\"warnings\":[";for(std::size_t i=0;i<r.artifact_graph.warnings.size();++i){if(i)o<<',';o<<"\""<<esc(r.artifact_graph.warnings[i])<<"\"";}o<<"]},\n";
    o<<"  \"artifact_relationships\": [";for(std::size_t i=0;i<r.artifact_relationships.size();++i){if(i)o<<',';const auto&x=r.artifact_relationships[i];o<<"{\"first\":\""<<esc(path_utf8(x.first))<<"\",\"second\":\""<<esc(path_utf8(x.second))<<"\",\"directed\":"<<(x.directed?"true":"false")<<",\"kind\":\""<<esc(x.kind)<<"\",\"state\":\""<<esc(x.state)<<"\",\"first_role\":\""<<esc(x.first_role)<<"\",\"second_role\":\""<<esc(x.second_role)<<"\",\"first_relation_role\":\""<<esc(x.first_relation_role)<<"\",\"second_relation_role\":\""<<esc(x.second_relation_role)<<"\",\"evidence_basis\":\""<<esc(x.evidence_basis)<<"\",\"evidence_source\":\""<<esc(x.evidence_source)<<"\",\"source_coordinate\":\""<<esc(x.source_coordinate)<<"\",\"target_coordinate\":\""<<esc(x.target_coordinate)<<"\",\"provenance_scope\":\""<<esc(x.provenance_scope)<<"\",\"evidence_level\":\""<<esc(x.evidence_level)<<"\",\"ambiguity\":\""<<esc(x.ambiguity)<<"\",\"semantic_relevance\":\""<<esc(x.semantic_relevance)<<"\",\"priority_eligible\":"<<(x.priority_eligible?"true":"false")<<",\"first_priority_delta\":"<<x.first_priority_delta<<",\"second_priority_delta\":"<<x.second_priority_delta<<",\"reason\":\""<<esc(x.reason)<<"\"}";}o<<"],\n";
    o<<"  \"materialization\": {\"root\":\""<<esc(path_utf8(r.materialization.root))<<"\",\"partial\":"<<(r.materialization.partial?"true":"false")<<",\"omitted_count\":"<<r.materialization.omitted_count<<",\"omitted_bytes\":"<<r.materialization.omitted_bytes<<",\"reasons\":[";for(std::size_t i=0;i<r.materialization.reasons.size();++i){if(i)o<<',';o<<"\""<<esc(r.materialization.reasons[i])<<"\"";}o<<"]},\n";
    o<<"  \"artifacts\": [";for(std::size_t i=0;i<r.artifacts.size();++i){if(i)o<<',';const auto&a=r.artifacts[i];o<<"{\"kind\":\""<<esc(a.kind)<<"\",\"role\":\""<<esc(a.role)<<"\",\"source\":\""<<esc(a.source)<<"\",\"path\":\""<<esc(path_utf8(a.path))<<"\",\"state\":\""<<esc(a.state)<<"\",\"size\":"<<a.size<<",\"sha256\":\""<<esc(a.sha256)<<"\",\"parent\":\""<<esc(path_utf8(a.parent))<<"\",\"relation\":\""<<esc(a.relation)<<"\",\"priority\":\""<<esc(a.priority)<<"\",\"normalized\":"<<(a.normalized?"true":"false")<<",\"runtime_confirmed\":"<<(a.runtime_confirmed?"true":"false")<<"}";}o<<"],\n"
      << "  \"format\": {";
    if (r.pe.valid) {
        o << "\"kind\":\"PE\",\"bits\":" << (r.pe.pe64?64:32)
          << ",\"machine\":\"" << esc(pe_machine_name(r.pe.machine)) << "\""
          << ",\"entry\":" << r.pe.entry_rva
          << ",\"subsystem\":\"" << esc(pe_subsystem_name(r.pe.subsystem)) << "\"";
    } else if (r.elf.valid) {
        o << "\"kind\":\"ELF\",\"bits\":" << (r.elf.elf64?64:32)
          << ",\"machine\":\"" << esc(elf_machine_name(r.elf.machine)) << "\""
          << ",\"type\":\"" << esc(elf_type_name(r.elf.type)) << "\""
          << ",\"entry\":" << r.elf.entry
          << ",\"interpreter\":\"" << esc(r.elf.interpreter) << "\""
          << ",\"program_headers\":" << r.elf.program_header_count
          << ",\"section_headers\":" << r.elf.section_header_count
          << ",\"section_table_present\":" << (r.elf.section_table_present?"true":"false");
    } else if (r.macho.valid) {
        o << "\"kind\":\"Mach-O\",\"fat\":"<<(r.macho.fat?"true":"false")<<",\"fat64\":"<<(r.macho.fat64?"true":"false")<<",\"slice_count\":"<<r.macho.slices.size()<<",\"file_offset_scope\":\"current_input_file\"";
        o<<",\"slice_policy\":\""<<esc(r.macho.slice_policy)<<"\",\"selected_slice\":"<<r.macho.selected_slice<<",\"selection_basis\":\"ARCHITECTURE_INVENTORY_ONLY\"";
        if(!r.macho.fat&&!r.macho.slices.empty()){const auto&m=r.macho.slices.front();o<<",\"bits\":"<<(m.macho64?64:32)<<",\"machine\":\""<<esc(macho_cpu_name(m.cpu_type))<<"\",\"type\":\""<<esc(macho_filetype_name(m.filetype))<<"\",\"entry\":"<<m.entry_va;}
    } else if (r.python_bytecode.valid) {
        o << "\"kind\":\"CPython bytecode\",\"container\":\"pyc\",\"version_family\":\""<<esc(r.python_bytecode.magic.version_family)<<"\",\"version_authentication\":\"MAGIC_MINOR_FAMILY_AUTHENTICATED\",\"patch_version_state\":\"AMBIGUOUS_WITHIN_MINOR_FAMILY\",\"magic_number\":"<<r.python_bytecode.magic.magic_number<<",\"header_kind\":\""<<esc(r.python_bytecode.header_kind)<<"\",\"marshal_offset\":"<<r.python_bytecode.marshal_offset<<",\"code_objects\":"<<r.python_bytecode.marshal.code_object_count;
    } else {
        o << "\"kind\":\"unknown\"";
    }
    o << "},\n";

    o << "  \"sections\": [";
    if (r.pe.valid) {
        for (std::size_t i = 0; i < r.pe.sections.size(); ++i) {
            const auto& sec = r.pe.sections[i]; if (i) o << ',';
            o << "{\"name\":\"" << esc(sec.name) << "\",\"address\":" << sec.rva
              << ",\"virtual_size\":" << sec.vsize << ",\"offset\":" << sec.raw_offset
              << ",\"raw_size\":" << sec.raw_size << ",\"used_size\":" << sec.used_size
              << ",\"characteristics\":" << sec.characteristics
              << ",\"entropy\":" << std::fixed << std::setprecision(4) << sec.entropy << '}';
        }
    } else if (r.elf.valid) {
        for (std::size_t i = 0; i < r.elf.sections.size(); ++i) {
            const auto& sec = r.elf.sections[i]; if (i) o << ',';
            o << "{\"name\":\"" << esc(sec.name) << "\",\"address\":" << sec.address
              << ",\"offset\":" << sec.offset << ",\"raw_size\":" << sec.size
              << ",\"used_size\":" << sec.used_size << ",\"entropy\":" << std::fixed << std::setprecision(4) << sec.entropy << '}';
        }
    } else if(r.macho.valid) {
        bool first=true;for(std::size_t si=0;si<r.macho.slices.size();++si)for(const auto&sec:r.macho.slices[si].sections){if(!first)o<<',';first=false;o<<"{\"slice\":"<<si<<",\"segment\":\""<<esc(sec.segment)<<"\",\"name\":\""<<esc(sec.name)<<"\",\"address\":"<<sec.address<<",\"offset\":"<<sec.offset<<",\"raw_size\":"<<sec.size<<",\"used_size\":"<<sec.used_size<<",\"entropy\":"<<std::fixed<<std::setprecision(4)<<sec.entropy<<",\"flags\":"<<sec.flags<<'}';}
    }
    o << "],\n";
    o << "  \"elf_segments\": [";for(std::size_t i=0;i<r.elf.segments.size();++i){if(i)o<<',';const auto&s=r.elf.segments[i];o<<"{\"type\":"<<s.type<<",\"flags\":"<<s.flags<<",\"address\":"<<s.address<<",\"offset\":"<<s.offset<<",\"file_size\":"<<s.file_size<<",\"memory_size\":"<<s.memory_size<<",\"align\":"<<s.align<<",\"used_size\":"<<s.used_size<<",\"entropy\":"<<std::fixed<<std::setprecision(4)<<s.entropy<<'}';}o<<"],\n";
    o << "  \"elf_needed\": [";for(std::size_t i=0;i<r.elf.needed.size();++i){if(i)o<<',';o<<"\""<<esc(r.elf.needed[i])<<"\"";}o<<"],\n";
    o << "  \"elf_dynamic\": {\"state\":\""<<esc(r.elf.dynamic.state)<<"\",\"error\":\""<<esc(r.elf.dynamic.error)<<"\",\"symbol_count_source\":\""<<esc(r.elf.dynamic.symbol_count_source)<<"\",\"symbol_count\":"<<r.elf.dynamic.symbols.size()<<",\"relocation_count\":"<<r.elf.dynamic.relocations.size()<<"},\n";
    o << "  \"elf_extraction\": {\"dynamic\":{\"success\":"<<(r.elf_extract.success?"true":"false")<<",\"symbols_csv\":\""<<esc(path_utf8(r.elf_extract.symbols_csv))<<"\",\"symbol_count\":"<<r.elf_extract.symbol_count<<",\"relocations_csv\":\""<<esc(path_utf8(r.elf_extract.relocations_csv))<<"\",\"relocation_count\":"<<r.elf_extract.relocation_count<<",\"error\":\""<<esc(r.elf_extract.error)<<"\"},\"unwind\":{\"success\":"<<(r.elf_unwind_extract.success?"true":"false")<<",\"cies_csv\":\""<<esc(path_utf8(r.elf_unwind_extract.cies_csv))<<"\",\"cie_count\":"<<r.elf_unwind_extract.cie_count<<",\"fdes_csv\":\""<<esc(path_utf8(r.elf_unwind_extract.fdes_csv))<<"\",\"fde_count\":"<<r.elf_unwind_extract.fde_count<<",\"error\":\""<<esc(r.elf_unwind_extract.error)<<"\"}},\n";
    o << "  \"macho_slices\": [";
    std::size_t swift_types_remaining=automatic_child_summary?kChildSwiftTypes:std::numeric_limits<std::size_t>::max();
    std::size_t swift_fields_remaining=automatic_child_summary?kChildSwiftFields:std::numeric_limits<std::size_t>::max();
    for(std::size_t i=0;i<r.macho.slices.size();++i){
        if(i)o<<',';
        const auto&m=r.macho.slices[i];
        const auto swift_plan=swift_slice_render_plan(m.swift,swift_types_remaining,swift_fields_remaining);
        o<<"{\"index\":"<<i<<",\"bits\":"<<(m.macho64?64:32)<<",\"little_endian\":"<<(m.little_endian?"true":"false")
         <<",\"machine\":\""<<esc(macho_cpu_name(m.cpu_type))<<"\",\"cpu_type\":"<<m.cpu_type<<",\"cpu_subtype\":"<<m.cpu_subtype
         <<",\"architecture\":\""<<esc(m.architecture)<<"\",\"cpu_subtype_base\":"<<m.cpu_subtype_base
         <<",\"arm64e\":"<<(m.arm64e?"true":"false")<<",\"ptrauth_versioned\":"<<(m.ptrauth_versioned?"true":"false")
         <<",\"ptrauth_kernel\":"<<(m.ptrauth_kernel?"true":"false")<<",\"ptrauth_abi_version\":"<<m.ptrauth_abi_version
         <<",\"architecture_claim_scope\":\"REPORT_ONLY_NO_SLICE_SELECTION\""
         <<",\"type\":\""<<esc(macho_filetype_name(m.filetype))<<"\",\"slice_offset\":"<<m.slice_offset<<",\"slice_size\":"<<m.slice_size
         <<",\"entry_file_offset\":"<<m.entry_file_offset<<",\"entry_va\":"<<m.entry_va<<",\"uuid\":\""<<esc(m.uuid)<<"\""
         <<",\"platform\":\""<<esc(macho_platform_name(m.platform))<<"\",\"min_os\":\""<<esc(macho_version_string(m.min_os))<<"\",\"sdk\":\""<<esc(macho_version_string(m.sdk))<<"\""
         <<",\"encrypted\":"<<(m.encrypted?"true":"false")<<",\"cryptid\":"<<m.cryptid<<",\"crypt_offset\":"<<m.crypt_offset<<",\"crypt_size\":"<<m.crypt_size
         <<",\"code_signature\":"<<(m.code_signature?"true":"false")<<",\"code_signature_offset\":"<<m.code_signature_offset<<",\"code_signature_size\":"<<m.code_signature_size
         <<",\"symbol_count\":"<<m.symbols.size()<<",\"function_start_count\":"<<m.function_starts.size();
         o<<",\"code_signature_state\":\""<<esc(m.code_signature_state)<<"\",\"code_signature_verification\":\"NOT_PERFORMED\""
          <<",\"bitcode_present\":"<<(m.bitcode_present?"true":"false")<<",\"bitcode_state\":\""<<esc(m.bitcode_state)<<"\""
          <<",\"coverage_state\":\""<<esc(m.coverage_state)<<"\",\"load_command_coverage_state\":\""<<esc(m.load_command_coverage_state)<<"\""
          <<",\"load_command_count\":"<<m.load_command_count<<",\"load_commands_retained\":"<<m.load_commands.size()<<",\"load_commands_truncated\":"<<(m.load_commands_truncated?"true":"false")
          <<",\"unknown_load_command_count\":"<<m.unknown_load_command_count<<",\"unknown_load_commands_truncated\":"<<(m.unknown_load_commands_truncated?"true":"false")
          <<",\"load_commands\":[";
        for(std::size_t z=0;z<m.load_commands.size();++z){if(z)o<<',';const auto&x=m.load_commands[z];o<<"{\"name\":\""<<esc(x.name)<<"\",\"cmd\":"<<x.command<<",\"offset\":"<<x.offset<<",\"size\":"<<x.size<<",\"known\":"<<(x.known?"true":"false")<<'}';}
        o<<"],\"unknown_load_commands\":[";
        for(std::size_t z=0;z<m.unknown_load_commands.size();++z){if(z)o<<',';const auto&x=m.unknown_load_commands[z];o<<"{\"cmd\":"<<x.command<<",\"offset\":"<<x.offset<<",\"size\":"<<x.size<<'}';}
        o<<"],\"coverage_reasons\":[";for(std::size_t z=0;z<m.coverage_reasons.size();++z){if(z)o<<',';o<<'\"'<<esc(m.coverage_reasons[z])<<'\"';}
        o<<"],\"swift\":{\"present\":"<<(m.swift.present?"true":"false")<<",\"structured\":"<<(m.swift.structured?"true":"false")
         <<",\"state\":\""<<esc(m.swift.state)<<"\",\"evidence_level\":\""<<esc(m.swift.evidence_level)<<"\",\"coverage_state\":\""<<esc(m.swift.coverage_state)<<"\""
         <<",\"source_or_semantic_recovery\":\""<<esc(m.swift.source_or_semantic_recovery)<<"\",\"analysis_limited\":"<<(m.swift.analysis_limited?"true":"false")
         <<",\"error\":\""<<esc(m.swift.error)<<"\",\"complete_type_closures\":"<<m.swift.complete_type_closures
         <<",\"record_outcomes\":{\"type_records_skipped\":"<<m.swift.type_records_skipped<<",\"type_records_partial\":"<<m.swift.type_records_partial<<",\"type_records_unsupported\":"<<m.swift.type_records_unsupported
         <<",\"field_descriptors_skipped\":"<<m.swift.field_descriptors_skipped<<",\"field_descriptors_partial\":"<<m.swift.field_descriptors_partial<<",\"field_records_skipped\":"<<m.swift.field_records_skipped<<",\"field_records_partial\":"<<m.swift.field_records_partial
         <<",\"mangled_type_names_absent\":"<<m.swift.mangled_type_names_absent<<",\"mangled_type_names_symbolic\":"<<m.swift.mangled_type_names_symbolic<<"}"
         <<",\"budgets\":{\"type_records_used\":"<<m.swift.type_records_used<<",\"type_records_limit\":4096"
         <<",\"field_descriptors_used\":"<<m.swift.field_descriptors_used<<",\"field_descriptors_limit\":4096,\"field_records_used\":"<<m.swift.field_records_used<<",\"field_records_limit\":65536"
         <<",\"relative_pointers_used\":"<<m.swift.relative_pointers_used<<",\"relative_pointers_limit\":131072,\"strings_used\":"<<m.swift.strings_used<<",\"strings_limit\":65536"
         <<",\"string_bytes_used\":"<<m.swift.string_bytes_used<<",\"string_bytes_limit\":4194304},\"reasons\":[";
        for(std::size_t z=0;z<m.swift.reasons.size();++z){if(z)o<<',';o<<'\"'<<esc(m.swift.reasons[z])<<'\"';}
        o<<"],\"sections\":[";
        for(std::size_t z=0;z<m.swift.sections.size();++z){if(z)o<<',';const auto&x=m.swift.sections[z];o<<"{\"segment\":\""<<esc(x.segment)<<"\",\"name\":\""<<esc(x.name)<<"\",\"offset\":"<<x.offset<<",\"size\":"<<x.size<<",\"state\":\""<<esc(x.state)<<"\",\"encrypted_overlap\":"<<(x.encrypted_overlap?"true":"false")<<'}';}
        o<<"],";render_cardinality(o,"types",swift_plan.types_total,swift_plan.types_rendered);o<<",";render_cardinality(o,"fields",swift_plan.fields_total,swift_plan.fields_rendered);o<<",\"types\":[";
        for(std::size_t z=0;z<swift_plan.types_rendered;++z){if(z)o<<',';const auto&x=m.swift.types[z];const auto fields_rendered=swift_plan.fields_rendered_per_type[z];o<<"{\"module\":\""<<esc(x.module_name)<<"\",\"name\":\""<<esc(x.type_name)<<"\",\"mangled_type_name\":\""<<esc(x.mangled_type_name)<<"\",\"mangled_type_present\":"<<(x.mangled_type_present?"true":"false")<<",\"mangled_type_plain_text\":"<<(x.mangled_type_plain_text?"true":"false")<<",\"mangled_type_byte_length\":"<<x.mangled_type_byte_length<<",\"mangled_type_symbolic_references\":"<<x.mangled_type_symbolic_references<<",\"mangled_type_sha256\":\""<<esc(x.mangled_type_sha256)<<"\",\"kind\":\""<<esc(x.kind)<<"\",\"type_descriptor_offset\":"<<x.type_descriptor_offset<<",\"field_descriptor_offset\":"<<x.field_descriptor_offset<<",";render_cardinality(o,"fields",x.fields.size(),fields_rendered);o<<",\"fields\":[";for(std::size_t q=0;q<fields_rendered;++q){if(q)o<<',';const auto&f=x.fields[q];o<<"{\"name\":\""<<esc(f.name)<<"\",\"mangled_type_name\":\""<<esc(f.mangled_type_name)<<"\",\"mangled_type_present\":"<<(f.mangled_type_present?"true":"false")<<",\"mangled_type_plain_text\":"<<(f.mangled_type_plain_text?"true":"false")<<",\"mangled_type_byte_length\":"<<f.mangled_type_byte_length<<",\"mangled_type_symbolic_references\":"<<f.mangled_type_symbolic_references<<",\"mangled_type_sha256\":\""<<esc(f.mangled_type_sha256)<<"\",\"record_offset\":"<<f.record_offset<<",\"flags\":"<<f.flags<<'}';}o<<"]}";}
        o<<"]}";
        o<<",\"dylibs\":[";
        for(std::size_t z=0;z<m.dylibs.size();++z){if(z)o<<',';o<<"\""<<esc(m.dylibs[z])<<"\"";}o<<"],\"symbols\":[";
        for(std::size_t z=0;z<m.symbols.size();++z){if(z)o<<',';const auto&x=m.symbols[z];o<<"{\"name\":\""<<esc(x.name)<<"\",\"value\":"<<x.value<<",\"file_offset\":"<<x.file_offset<<",\"type\":"<<unsigned(x.type)<<",\"section\":"<<unsigned(x.section)<<",\"desc\":"<<x.desc<<",\"external\":"<<(x.external?"true":"false")<<",\"private_external\":"<<(x.private_external?"true":"false")<<",\"defined\":"<<(x.defined?"true":"false")<<'}';}
        o<<"],\"function_starts\":[";
        for(std::size_t z=0;z<m.function_starts.size();++z){if(z)o<<',';const auto&x=m.function_starts[z];o<<"{\"address\":"<<x.address<<",\"file_offset\":"<<x.file_offset<<",\"symbol\":\""<<esc(x.symbol)<<"\"}";}
        o<<"]}";
    }
    o<<"],\n";
    o << "  \"authenticode\": {\"present\":"<<(r.authenticode.present?"true":"false")<<",\"state\":\""<<esc(r.authenticode.state)<<"\",\"certificate_table_valid\":"<<(r.authenticode.certificate_table_valid?"true":"false")<<",\"certificate_table_offset\":"<<r.authenticode.certificate_table_offset<<",\"certificate_table_size\":"<<r.authenticode.certificate_table_size<<",\"checksum_offset\":"<<r.authenticode.checksum_offset<<",\"certificate_directory_entry_offset\":"<<r.authenticode.certificate_directory_entry_offset<<",\"headers_size\":"<<r.authenticode.headers_size<<",\"last_section_end\":"<<r.authenticode.last_section_end<<",\"covered_bytes\":"<<r.authenticode.covered_bytes<<",\"post_section_unhashed_bytes\":"<<r.authenticode.post_section_bytes<<",\"pre_certificate_unhashed_bytes\":"<<r.authenticode.pre_certificate_unhashed_bytes<<",\"post_certificate_unhashed_bytes\":"<<r.authenticode.post_certificate_unhashed_bytes<<",\"cryptographic_signer_verification\":\"NOT_PERFORMED_STATIC_DIGEST_LAYER\",\"catalog_signature_verification\":\"NOT_CHECKED\",\"signatures\":[";
    for(std::size_t i=0;i<r.authenticode.signatures.size();++i){if(i)o<<',';const auto&x=r.authenticode.signatures[i];o<<"{\"certificate_offset\":"<<x.certificate_offset<<",\"certificate_size\":"<<x.certificate_size<<",\"revision\":"<<x.revision<<",\"certificate_type\":"<<x.certificate_type<<",\"source\":\""<<esc(x.source)<<"\",\"nesting_depth\":"<<x.nesting_depth<<",\"parent_signature_index\":"<<x.parent_signature_index<<",\"nested_signature_count\":"<<x.nested_signature_count<<",\"nested_signature_error\":\""<<esc(x.nested_signature_error)<<"\",\"pkcs7\":"<<(x.pkcs7?"true":"false")<<",\"spc_indirect_data\":"<<(x.spc_indirect_data?"true":"false")<<",\"signer_infos_present\":"<<(x.signer_infos_present?"true":"false")<<",\"signer_info_count\":"<<x.signer_info_count<<",\"signer_metadata_state\":\""<<esc(x.signer_metadata_state)<<"\",\"signer_metadata_error\":\""<<esc(x.signer_metadata_error)<<"\",\"digest_extracted\":"<<(x.digest_extracted?"true":"false")<<",\"digest_match\":"<<(x.digest_match?"true":"false")<<",\"digest_algorithm\":\""<<esc(x.digest_algorithm)<<"\",\"signed_digest\":\""<<esc(x.signed_digest)<<"\",\"computed_digest\":\""<<esc(x.computed_digest)<<"\",\"page_hashes_present\":"<<(x.page_hashes_present?"true":"false")<<",\"page_hashes_verified\":"<<(x.page_hashes_verified?"true":"false")<<",\"page_hash_algorithm\":\""<<esc(x.page_hash_algorithm)<<"\",\"page_hash_state\":\""<<esc(x.page_hash_state)<<"\",\"page_hash_error\":\""<<esc(x.page_hash_error)<<"\",\"page_size\":"<<x.page_size<<",\"page_hash_mismatch_count\":"<<x.page_hash_mismatch_count<<",\"page_hashes\":[";for(std::size_t ph_i=0;ph_i<x.page_hashes.size();++ph_i){if(ph_i)o<<',';const auto&ph=x.page_hashes[ph_i];o<<"{\"signed_file_offset\":"<<ph.signed_file_offset<<",\"current_file_offset\":"<<ph.current_file_offset<<",\"current_rva\":"<<ph.current_rva<<",\"current_file_bytes\":"<<ph.current_file_bytes<<",\"region\":\""<<esc(ph.region)<<"\",\"signed_digest\":\""<<esc(ph.signed_digest)<<"\",\"computed_digest\":\""<<esc(ph.computed_digest)<<"\",\"offset_match\":"<<(ph.offset_match?"true":"false")<<",\"digest_match\":"<<(ph.digest_match?"true":"false")<<",\"match\":"<<(ph.match?"true":"false")<<",\"terminator\":"<<(ph.terminator?"true":"false")<<'}';}o<<"],\"certificates\":[";for(std::size_t z=0;z<x.certificates.size();++z){if(z)o<<',';const auto&c=x.certificates[z];o<<"{\"subject\":\""<<esc(c.subject)<<"\",\"issuer\":\""<<esc(c.issuer)<<"\",\"serial\":\""<<esc(c.serial)<<"\",\"not_before\":\""<<esc(c.not_before)<<"\",\"not_after\":\""<<esc(c.not_after)<<"\",\"sha256_fingerprint\":\""<<esc(c.sha256_fingerprint)<<"\",\"role_hint\":\""<<esc(c.role_hint)<<"\",\"extensions_present\":"<<(c.extensions_present?"true":"false")<<",\"extended_key_usage_present\":"<<(c.extended_key_usage_present?"true":"false")<<",\"extended_key_usage_critical\":"<<(c.extended_key_usage_critical?"true":"false")<<",\"eku_code_signing\":"<<(c.eku_code_signing?"true":"false")<<",\"eku_time_stamping\":"<<(c.eku_time_stamping?"true":"false")<<",\"basic_constraints_present\":"<<(c.basic_constraints_present?"true":"false")<<",\"basic_constraints_ca\":"<<(c.basic_constraints_ca?"true":"false")<<",\"extended_key_usage_oids\":[";for(std::size_t u=0;u<c.extended_key_usage_oids.size();++u){if(u)o<<',';o<<"\""<<esc(c.extended_key_usage_oids[u])<<"\"";}o<<"],\"matched_primary_signer\":"<<(c.matched_primary_signer?"true":"false")<<'}';}o<<"],\"signers\":[";for(std::size_t z=0;z<x.signers.size();++z){if(z)o<<',';const auto&sg=x.signers[z];o<<"{\"identifier_type\":\""<<esc(sg.identifier_type)<<"\",\"issuer\":\""<<esc(sg.issuer)<<"\",\"serial\":\""<<esc(sg.serial)<<"\",\"digest_algorithm\":\""<<esc(sg.digest_algorithm)<<"\",\"signature_algorithm\":\""<<esc(sg.signature_algorithm)<<"\",\"signing_time\":\""<<esc(sg.signing_time)<<"\",\"certificate_matched\":"<<(sg.certificate_matched?"true":"false")<<",\"certificate_index\":"<<sg.certificate_index<<",\"countersignature_count\":"<<sg.countersignature_count<<",\"rfc3161_timestamp_count\":"<<sg.rfc3161_timestamp_count<<",\"signature_value_size\":"<<sg.signature_value_size<<",\"signature_value_sha256\":\""<<esc(sg.signature_value_sha256)<<"\",\"timestamps\":[";for(std::size_t q=0;q<sg.timestamps.size();++q){if(q)o<<',';const auto&t=sg.timestamps[q];o<<"{\"kind\":\""<<esc(t.kind)<<"\",\"state\":\""<<esc(t.state)<<"\",\"gen_time\":\""<<esc(t.gen_time)<<"\",\"policy\":\""<<esc(t.policy)<<"\",\"message_imprint_algorithm\":\""<<esc(t.message_imprint_algorithm)<<"\",\"message_imprint\":\""<<esc(t.message_imprint)<<"\",\"computed_signature_value_imprint\":\""<<esc(t.computed_signature_value_imprint)<<"\",\"message_imprint_binding_checked\":"<<(t.message_imprint_binding_checked?"true":"false")<<",\"message_imprint_matches_signature_value\":"<<(t.message_imprint_matches_signature_value?"true":"false")<<",\"serial\":\""<<esc(t.serial)<<"\",\"signer_certificate_matched\":"<<(t.signer_certificate_matched?"true":"false")<<",\"signer_subject\":\""<<esc(t.signer_subject)<<"\",\"signer_issuer\":\""<<esc(t.signer_issuer)<<"\",\"signer_serial\":\""<<esc(t.signer_serial)<<"\",\"signer_certificate_sha256\":\""<<esc(t.signer_certificate_sha256)<<"\",\"signer_role_state\":\""<<esc(t.signer_role_state)<<"\",\"signer_eku_time_stamping\":"<<(t.signer_eku_time_stamping?"true":"false")<<",\"signer_extended_key_usage_critical\":"<<(t.signer_extended_key_usage_critical?"true":"false")<<",\"error\":\""<<esc(t.error)<<"\"}";}o<<"]}";}o<<"],\"state\":\""<<esc(x.state)<<"\",\"error\":\""<<esc(x.error)<<"\"}";}
    o<<"],\"error\":\""<<esc(r.authenticode.error)<<"\"},\n";
    o << "  \"pre_entry\": {";
    if(r.pe.valid){o<<"\"tls_present\":"<<(r.pe.tls.present?"true":"false")<<",\"tls_callbacks\":[";for(std::size_t i=0;i<r.pe.tls.callback_vas.size();++i){if(i)o<<',';o<<r.pe.tls.callback_vas[i];}o<<"],\"exception_rva\":"<<r.pe.exception.rva<<",\"exception_size\":"<<r.pe.exception.size<<",\"runtime_function_count\":"<<r.pe.exception.runtime_function_count<<",\"exception_handlers\":[";for(std::size_t i=0;i<r.pe.exception.handler_rvas.size();++i){if(i)o<<',';o<<r.pe.exception.handler_rvas[i];}o<<"],\"initterm\":"<<(r.pe.init.references_initterm?"true":"false");}
    else if(r.elf.valid){o<<"\"init\":"<<(r.elf.init.has_init?"true":"false")<<",\"fini\":"<<(r.elf.init.has_fini?"true":"false")<<",\"ctors\":"<<(r.elf.init.has_ctors?"true":"false")<<",\"dtors\":"<<(r.elf.init.has_dtors?"true":"false")<<",\"arrays\":[";for(std::size_t i=0;i<r.elf.init.arrays.size();++i){if(i)o<<',';const auto&a=r.elf.init.arrays[i];o<<"{\"kind\":\""<<esc(a.kind)<<"\",\"address\":"<<a.address<<",\"size\":"<<a.size<<",\"entries\":[";for(std::size_t j=0;j<a.entries.size();++j){if(j)o<<',';o<<a.entries[j];}o<<"]}";}o<<"]";}
    else if(r.macho.valid){o<<"\"slices\":[";for(std::size_t i=0;i<r.macho.slices.size();++i){if(i)o<<',';const auto&m=r.macho.slices[i];o<<"{\"index\":"<<i<<",\"routine_init_address\":"<<m.routine_init_address<<",\"init_functions\":[";for(std::size_t z=0;z<m.init_functions.size();++z){if(z)o<<',';o<<m.init_functions[z];}o<<"],\"thread_init_functions\":[";for(std::size_t z=0;z<m.thread_init_functions.size();++z){if(z)o<<',';o<<m.thread_init_functions[z];}o<<"],\"term_functions\":[";for(std::size_t z=0;z<m.term_functions.size();++z){if(z)o<<',';o<<m.term_functions[z];}o<<"]}";}o<<"]";}
    o << "},\n";

    constexpr std::size_t kGoFunctionRender=256,kGoTypeRender=128,kGoFieldRender=64;
    const auto go_functions=prioritized_render_rows(r.golang.functions,kGoFunctionRender,[](const auto&x){return x.user_like;});
    const auto go_types=prioritized_render_rows(r.golang.types,kGoTypeRender,[](const auto&x){return x.user_like;});
    o << "  \"golang\": {\"valid\":"<<(r.golang.valid?"true":"false")<<",\"state\":\""<<(r.golang.valid?(r.golang.functions.empty()?"LIKELY":"CONFIRMED"):"FAILED")<<"\",\"version\":\""<<esc(r.golang.version)<<"\",\"module_path\":\""<<esc(r.golang.module_path)<<"\",\"pclntab_layout\":\""<<esc(r.golang.pclntab_layout)<<"\",\"pclntab_offset\":"<<r.golang.pclntab_offset<<",\"pclntab_va\":"<<r.golang.pclntab_va<<",\"pclntab_text_base\":"<<r.golang.pclntab_text_base<<",\"pclntab_text_base_source\":\""<<esc(r.golang.pclntab_text_base_source)<<"\",\"pointer_size\":"<<r.golang.pointer_size<<",\"quantum\":"<<r.golang.quantum<<",\"moduledata_va\":"<<r.golang.moduledata_va<<",\"moduledata_layout\":\""<<esc(r.golang.moduledata_layout)<<"\",\"types_va\":"<<r.golang.types_va<<",\"etypes_va\":"<<r.golang.etypes_va<<",\"typelinks_va\":"<<r.golang.typelinks_va<<",\"typelinks_count\":"<<r.golang.typelinks_count<<",\"itablinks_va\":"<<r.golang.itablinks_va<<",\"itablinks_count\":"<<r.golang.itablinks_count<<",\"function_count\":"<<r.golang.functions.size()<<",\"type_count\":"<<r.golang.types.size()<<",\"modules\":[";
    for(std::size_t i=0;i<r.golang.modules.size();++i){if(i)o<<',';o<<"\""<<esc(r.golang.modules[i])<<"\"";}
    o<<"],\"build_settings\":[";for(std::size_t i=0;i<r.golang.build_settings.size();++i){if(i)o<<',';o<<"\""<<esc(r.golang.build_settings[i])<<"\"";}
    o<<"],\"functions_rendered\":"<<go_functions.size()<<",\"functions_truncated\":"<<(r.golang.functions.size()>go_functions.size()?"true":"false")<<",\"functions\":[";for(std::size_t i=0;i<go_functions.size();++i){const auto&f=*go_functions[i];if(i)o<<',';o<<"{\"start_va\":"<<f.start_va<<",\"end_va\":"<<f.end_va<<",\"start_rva\":"<<f.start_rva<<",\"end_rva\":"<<f.end_rva<<",\"package\":\""<<esc(f.package)<<"\",\"name\":\""<<esc(f.name)<<"\",\"user_like\":"<<(f.user_like?"true":"false")<<'}';}
    o<<"],\"types_rendered\":"<<go_types.size()<<",\"types_truncated\":"<<(r.golang.types.size()>go_types.size()?"true":"false")<<",\"types\":[";for(std::size_t i=0;i<go_types.size();++i){const auto&t=*go_types[i];if(i)o<<',';o<<"{\"va\":"<<t.va<<",\"size\":"<<t.size<<",\"name\":\""<<esc(t.name)<<"\",\"kind\":\""<<esc(t.kind)<<"\",\"tflag\":"<<unsigned(t.tflag)<<",\"user_like\":"<<(t.user_like?"true":"false")<<",\"fields_rendered\":"<<std::min(t.fields.size(),kGoFieldRender)<<",\"fields_truncated\":"<<(t.fields.size()>kGoFieldRender?"true":"false")<<",\"fields\":[";for(std::size_t j=0;j<t.fields.size()&&j<kGoFieldRender;++j){const auto&sf=t.fields[j];if(j)o<<',';o<<"{\"name\":\""<<esc(sf.name)<<"\",\"type_name\":\""<<esc(sf.type_name)<<"\",\"type_va\":"<<sf.type_va<<",\"offset\":"<<sf.offset<<",\"embedded\":"<<(sf.embedded?"true":"false")<<",\"tag\":\""<<esc(sf.tag)<<"\"}";}o<<"]}";}
    o<<"],\"extraction\":{\"success\":"<<(r.golang_extract.success?"true":"false")<<",\"symbols_csv\":\""<<esc(path_utf8(r.golang_extract.symbols_csv))<<"\",\"symbol_count\":"<<r.golang_extract.symbol_count<<",\"types_csv\":\""<<esc(path_utf8(r.golang_extract.types_csv))<<"\",\"type_count\":"<<r.golang_extract.type_count<<"},\"type_error\":\""<<esc(r.golang.type_error)<<"\",\"error\":\""<<esc(r.golang.error)<<"\"},\n";

    o << "  \"cpython_static\": ";render_cpython_static_json(o,r.cpython_static);o<<",\n";
    o << "  \"cpython_runtimes\": [";
    for(std::size_t i=0;i<r.cpython_runtimes.size();++i){
        const auto&cp=r.cpython_runtimes[i];if(i)o<<',';
        o<<"{\"state\":\"CONFIRMED\",\"source\":\""<<esc(cp.source)<<"\",\"version\":\""<<esc(cp.version)<<"\",\"version_hex\":"<<cp.version_hex
         <<",\"size\":"<<cp.file_size<<",\"sha256\":\""<<cp.sha256<<"\",\"export_count\":"<<cp.named_export_count
         <<",\"reference_status\":\""<<esc(cp.reference_status)<<"\",\"reference_size\":"<<cp.reference_size
         <<",\"semantic_reference_status\":\""<<esc(cp.semantic_reference_status)<<"\",\"semantic_probe_median\":"<<cp.semantic_probe_median<<",\"semantic_probe_count\":"<<cp.semantic_probe_count
         <<",\"text_reference_status\":\""<<esc(cp.text_reference_status)<<"\",\"text_chunk_match_ratio\":"<<cp.text_chunk_match_ratio<<",\"text_chunks_matched\":"<<cp.text_chunks_matched<<",\"text_chunks_reference\":"<<cp.text_chunks_reference<<",\"text_chunks_target\":"<<cp.text_chunks_target;
        o<<",\"compiler_probe\":{\"attempted\":"<<(cp.compiler_probe.attempted?"true":"false")<<",\"launched\":"<<(cp.compiler_probe.launched?"true":"false")<<",\"success\":"<<(cp.compiler_probe.success?"true":"false")<<",\"state\":\""<<esc(cp.compiler_probe.state)<<"\",\"reference_version\":\""<<esc(cp.compiler_probe.reference_version)<<"\",\"code_objects\":"<<cp.compiler_probe.code_objects<<",\"code_units\":"<<cp.compiler_probe.code_units<<",\"oparg_matches\":"<<cp.compiler_probe.oparg_matches<<",\"observed_opcodes\":"<<cp.compiler_probe.observed_opcodes<<",\"changed_opcodes\":"<<cp.compiler_probe.changed_opcodes<<",\"error\":\""<<esc(cp.compiler_probe.error)<<"\",\"mappings\":[";{bool first_probe_mapping=true;for(const auto&m:cp.compiler_probe.mappings){if(m.target_opcode==m.reference_opcode)continue;if(!first_probe_mapping)o<<',';first_probe_mapping=false;o<<"{\"target_opcode\":"<<m.target_opcode<<",\"reference_opcode\":"<<m.reference_opcode<<",\"observations\":"<<m.observations<<"}";}}o<<"]}";
        o<<",\"dispatch\":{\"attempted\":"<<(cp.dispatch.attempted?"true":"false")<<",\"table_found\":"<<(cp.dispatch.table_found?"true":"false")<<",\"state\":\""<<esc(cp.dispatch.state)<<"\",\"reference_status\":\""<<esc(cp.dispatch.reference_status)<<"\",\"reference_version\":\""<<esc(cp.dispatch.reference_version)<<"\",\"evaluator_rva\":"<<cp.dispatch.evaluator_rva<<",\"table_load_rva\":"<<cp.dispatch.table_load_rva<<",\"table_rva\":"<<cp.dispatch.table_rva<<",\"table_first_opcode\":"<<cp.dispatch.table_first_opcode<<",\"table_entry_count\":"<<cp.dispatch.table_entry_count<<",\"executable_entries\":"<<cp.dispatch.executable_entries<<",\"unique_handlers\":"<<cp.dispatch.unique_handler_count<<",\"slot_matches\":"<<cp.dispatch.slot_matches<<",\"permuted_slots\":"<<cp.dispatch.permuted_slots<<",\"handler_modified\":"<<cp.dispatch.handler_modified<<",\"semantic_mapped\":"<<cp.dispatch.semantic_mapped<<",\"ambiguous\":"<<cp.dispatch.ambiguous<<",\"unmapped\":"<<cp.dispatch.unmapped<<",\"changes\":[";
        bool first_change=true;for(const auto&m:cp.dispatch.mappings){if(m.state=="SLOT_MATCH")continue;if(!first_change)o<<',';first_change=false;o<<"{\"target_opcode\":"<<m.target_opcode<<",\"state\":\""<<esc(m.state)<<"\",\"target_handler_rva\":"<<m.target_handler_rva<<",\"expected_handler_rva\":"<<m.expected_handler_rva<<",\"reference_opcodes\":[";for(std::size_t z=0;z<m.reference_opcodes.size();++z){if(z)o<<',';o<<m.reference_opcodes[z];}o<<"],\"reference_names\":[";for(std::size_t z=0;z<m.reference_names.size();++z){if(z)o<<',';o<<"\""<<esc(m.reference_names[z])<<"\"";}o<<"]}";}o<<"]}";
        o<<",\"region_diffs\":[";for(std::size_t z=0;z<cp.region_diffs.size();++z){if(z)o<<',';const auto&rg=cp.region_diffs[z];o<<"{\"kind\":\""<<esc(rg.kind)<<"\",\"section\":\""<<esc(rg.section)<<"\",\"rva\":"<<rg.rva<<",\"size\":"<<rg.size<<",\"detail\":\""<<esc(rg.detail)<<"\"}";}o<<"]";
        o<<",\"new_region_xrefs\":[";for(std::size_t z=0;z<cp.new_region_xrefs.size();++z){if(z)o<<',';const auto&x=cp.new_region_xrefs[z];o<<"{\"source_rva\":"<<x.source_rva<<",\"target_rva\":"<<x.target_rva<<",\"size\":"<<x.size<<",\"kind\":\""<<esc(x.kind)<<"\"}";}o<<"]";
        o<<",\"section_diffs\":[";for(std::size_t z=0;z<cp.section_diffs.size();++z){if(z)o<<',';const auto&x=cp.section_diffs[z];o<<"{\"name\":\""<<esc(x.name)<<"\",\"target_virtual\":"<<x.target_virtual<<",\"reference_virtual\":"<<x.reference_virtual<<",\"virtual_delta\":"<<x.virtual_delta<<",\"target_raw\":"<<x.target_raw<<",\"reference_raw\":"<<x.reference_raw<<",\"raw_delta\":"<<x.raw_delta<<"}";}o<<"]";
        o<<",\"added_exports\":[";for(std::size_t z=0;z<cp.added_exports.size();++z){if(z)o<<',';o<<"\""<<esc(cp.added_exports[z])<<"\"";}o<<"],\"missing_exports\":[";for(std::size_t z=0;z<cp.missing_exports.size();++z){if(z)o<<',';o<<"\""<<esc(cp.missing_exports[z])<<"\"";}o<<"]";
        o<<",\"function_diffs\":[";for(std::size_t z=0;z<cp.function_diffs.size();++z){if(z)o<<',';const auto&fd=cp.function_diffs[z];o<<"{\"name\":\""<<esc(fd.name)<<"\",\"state\":\""<<esc(fd.state)<<"\",\"target_rva\":"<<fd.target_rva<<",\"reference_coverage\":"<<fd.reference_coverage<<",\"matched_blocks\":"<<fd.matched_blocks<<",\"reference_blocks\":"<<fd.reference_blocks<<",\"target_blocks\":"<<fd.target_blocks<<",\"changed_ranges\":[";for(std::size_t k=0;k<fd.changed_ranges.size();++k){if(k)o<<',';const auto&rng=fd.changed_ranges[k];o<<"{\"offset\":"<<rng.offset<<",\"size\":"<<rng.size<<",\"label\":\""<<esc(rng.label)<<"\"}";}o<<"]}";}o<<"]}";
    }
    o << "],\n";

    o << "  \"godot\": {\"valid\":"<<(r.godot.valid?"true":"false");
    if(r.godot.valid){o<<",\"state\":\""<<(r.godot.validated?"CONFIRMED":"LIKELY")<<"\",\"pck_offset\":"<<r.godot.pck_offset<<",\"format_version\":"<<r.godot.format_version<<",\"engine\":\""<<r.godot.engine_major<<'.'<<r.godot.engine_minor<<'.'<<r.godot.engine_patch<<"\",\"encrypted_directory\":"<<(r.godot.encrypted_directory?"true":"false")<<",\"file_count\":"<<r.godot.file_count;if(r.godot.key.found){const auto&k=r.godot.key;o<<",\"key\":\""<<godot_key_hex(k)<<"\",\"key_state\":\""<<godot_key_state(k)<<"\",\"key_decryption_validated\":"<<(k.confirmed?"true":"false")<<",\"key_directory_validated\":"<<(k.directory_validated?"true":"false")<<",\"key_encrypted_file_validated\":"<<(k.encrypted_file_validated?"true":"false")<<",\"key_script_validated\":"<<(k.script_validated?"true":"false")<<",\"key_native_candidate_count\":"<<k.native_candidate_count<<",\"key_candidate_budget_exhausted\":"<<(k.candidate_budget_exhausted?"true":"false")<<",\"key_candidate_validation_attempts\":"<<k.candidate_validation_attempts<<",\"key_encrypted_probe_count\":"<<k.encrypted_probe_count<<",\"key_encrypted_script_count\":"<<k.encrypted_script_count<<",\"key_validated_script_count\":"<<k.validated_script_count<<",\"key_script_validation_truncated\":"<<(k.script_validation_truncated?"true":"false")<<",\"key_validated_script_path\":\""<<esc(k.validated_script_path)<<"\"";}}
    {constexpr std::size_t kGdextBundleRender=8,kGdextLibraryRender=8,kGdextClassRender=16,kGdextMethodRender=32,kGdextBridgeRender=8,kGdextLinkRender=32;const auto&g=r.godot;o<<",\"gdextension\":{\"state\":\""<<esc(g.gdextension_state)<<"\",\"descriptor_candidates\":"<<g.gdextension_descriptor_candidates<<",\"descriptor_processed\":"<<g.gdextension_descriptor_processed<<",\"script_candidate_count\":"<<g.gdextension_script_candidate_count<<",\"script_candidate_bytes\":"<<g.gdextension_script_candidate_bytes<<",\"analysis_limited\":"<<(g.gdextension_analysis_limited?"true":"false")<<",\"bundle_valid_count\":"<<g.gdextension_bundle_valid_count<<",\"native_analyzed_count\":"<<g.gdextension_native_analyzed_count<<",\"exact_registration_bundles\":"<<g.gdextension_exact_registration_count<<",\"bounded_bridge_bundles\":"<<g.gdextension_bounded_bridge_count<<",\"unresolved_bundles\":"<<g.gdextension_unresolved_count<<",\"failed_bundles\":"<<g.gdextension_failed_count<<",\"script_analysis_count\":"<<g.gdextension_script_analysis_count<<",\"native_super_call_count\":"<<g.gdextension_super_call_count<<",\"script_link_ambiguous_count\":"<<g.gdextension_script_link_ambiguous_count<<",\"bundles_rendered\":"<<std::min(g.gdextensions.size(),kGdextBundleRender)<<",\"bundles_truncated\":"<<(g.gdextensions.size()>kGdextBundleRender?"true":"false")<<",\"bundles\":[";for(std::size_t bi=0;bi<g.gdextensions.size()&&bi<kGdextBundleRender;++bi){if(bi)o<<',';const auto&b=g.gdextensions[bi];o<<"{\"valid\":"<<(b.valid?"true":"false")<<",\"state\":\""<<esc(b.state)<<"\",\"descriptor_path\":\""<<esc(b.descriptor_path)<<"\",\"descriptor_entry_index\":"<<b.descriptor_entry_index<<",\"descriptor_child_validated\":"<<(b.descriptor_child_validated?"true":"false")<<",\"entry_symbol\":\""<<esc(b.descriptor.entry_symbol)<<"\",\"compatibility_minimum\":\""<<esc(b.descriptor.compatibility_minimum)<<"\",\"error\":\""<<esc(b.error)<<"\",\"libraries_rendered\":"<<std::min(b.libraries.size(),kGdextLibraryRender)<<",\"libraries_truncated\":"<<(b.libraries.size()>kGdextLibraryRender?"true":"false")<<",\"libraries\":[";auto render_libs=gdextension_render_libraries(b,kGdextLibraryRender);for(std::size_t li=0;li<render_libs.size();++li){if(li)o<<',';const auto&l=*render_libs[li];const auto&n=l.native;o<<"{\"feature\":\""<<esc(l.feature_key)<<"\",\"declared_path\":\""<<esc(l.normalized_declared_path)<<"\",\"matched_child_path\":\""<<esc(l.matched_child_path)<<"\",\"matched_entry_index\":"<<l.matched_entry_index<<",\"exact_path_match\":"<<(l.exact_path_match?"true":"false")<<",\"child_validated\":"<<(l.child_validated?"true":"false")<<",\"native_analyzed\":"<<(l.native_analyzed?"true":"false")<<",\"state\":\""<<esc(l.state)<<"\",\"error\":\""<<esc(l.error)<<"\",\"native\":{\"valid\":"<<(n.valid?"true":"false")<<",\"state\":\""<<esc(n.state)<<"\",\"architecture\":\""<<esc(n.architecture)<<"\",\"entry_symbol\":\""<<esc(n.entry_symbol)<<"\",\"entry_rva\":"<<n.entry_rva<<",\"entry_export_validated\":"<<(n.entry_export_validated?"true":"false")<<",\"get_proc_relationship_validated\":"<<(n.get_proc_relationship_validated?"true":"false")<<",\"resolver_function_rva\":"<<n.resolver_function_rva<<",\"reachable_function_count\":"<<n.reachable_function_count<<",\"classes_rendered\":"<<std::min(n.classes.size(),kGdextClassRender)<<",\"classes_truncated\":"<<(n.classes.size()>kGdextClassRender?"true":"false")<<",\"classes\":[";for(std::size_t ci=0;ci<n.classes.size()&&ci<kGdextClassRender;++ci){if(ci)o<<',';const auto&c=n.classes[ci];o<<"{\"state\":\""<<esc(c.evidence_state)<<"\",\"class\":\""<<esc(c.class_name)<<"\",\"parent\":\""<<esc(c.parent_class_name)<<"\",\"registration_function_rva\":"<<c.registration_function_rva<<",\"registration_call_rva\":"<<c.registration_call_rva<<'}';}o<<"],\"methods_rendered\":"<<std::min(n.methods.size(),kGdextMethodRender)<<",\"methods_truncated\":"<<(n.methods.size()>kGdextMethodRender?"true":"false")<<",\"methods\":[";for(std::size_t mi=0;mi<n.methods.size()&&mi<kGdextMethodRender;++mi){if(mi)o<<',';const auto&m=n.methods[mi];o<<"{\"state\":\""<<esc(m.evidence_state)<<"\",\"class\":\""<<esc(m.class_name)<<"\",\"method\":\""<<esc(m.method_name)<<"\",\"registration_function_rva\":"<<m.registration_function_rva<<",\"registration_call_rva\":"<<m.registration_call_rva<<",\"method_flags_known\":"<<(m.method_flags_known?"true":"false")<<",\"method_flags\":"<<m.method_flags<<",\"has_return_value_known\":"<<(m.has_return_value_known?"true":"false")<<",\"has_return_value\":"<<(m.has_return_value?"true":"false")<<",\"return_variant_type_known\":"<<(m.return_variant_type_known?"true":"false")<<",\"return_variant_type\":"<<m.return_variant_type<<",\"return_variant_type_name\":\""<<esc(m.return_variant_type_name)<<"\",\"return_value_metadata_known\":"<<(m.return_value_metadata_known?"true":"false")<<",\"return_value_metadata\":"<<m.return_value_metadata<<",\"argument_count_known\":"<<(m.argument_count_known?"true":"false")<<",\"argument_count\":"<<m.argument_count<<",\"argument_types_complete\":"<<(m.argument_types_complete?"true":"false")<<",\"argument_metadata_complete\":"<<(m.argument_metadata_complete?"true":"false")<<",\"argument_variant_type_names\":[";for(std::size_t ai=0;ai<m.argument_variant_type_names.size();++ai){if(ai)o<<',';o<<"\""<<esc(m.argument_variant_type_names[ai])<<"\"";}o<<"],\"argument_metadata\":[";for(std::size_t ai=0;ai<m.argument_metadata.size();++ai){if(ai)o<<',';o<<m.argument_metadata[ai];}o<<"],\"default_argument_count_known\":"<<(m.default_argument_count_known?"true":"false")<<",\"default_argument_count\":"<<m.default_argument_count<<",\"method_userdata_known\":"<<(m.method_userdata_known?"true":"false")<<",\"method_userdata_va\":"<<m.method_userdata_va<<",\"call_func_known\":"<<(m.call_func_known?"true":"false")<<",\"call_func_va\":"<<m.call_func_va<<",\"ptrcall_func_known\":"<<(m.ptrcall_func_known?"true":"false")<<",\"ptrcall_func_va\":"<<m.ptrcall_func_va<<",\"bridge_candidates_rendered\":"<<std::min(m.bridge_candidates.size(),kGdextBridgeRender)<<",\"bridge_candidates_truncated\":"<<(m.bridge_candidates.size()>kGdextBridgeRender?"true":"false")<<",\"bridge_candidates\":[";for(std::size_t q=0;q<m.bridge_candidates.size()&&q<kGdextBridgeRender;++q){if(q)o<<',';const auto&bc=m.bridge_candidates[q];o<<"{\"va\":"<<bc.va<<",\"rva\":"<<bc.rva<<",\"source\":\""<<esc(bc.source)<<"\"}";}o<<"],\"detail\":\""<<esc(m.detail)<<"\"}";}o<<"],\"error\":\""<<esc(n.error)<<"\"}}";}o<<"]}";}o<<"],\"script_links_rendered\":"<<std::min(g.gdextension_script_links.size(),kGdextLinkRender)<<",\"script_links_truncated\":"<<(g.gdextension_script_links.size()>kGdextLinkRender?"true":"false")<<",\"script_links\":[";for(std::size_t si=0;si<g.gdextension_script_links.size()&&si<kGdextLinkRender;++si){if(si)o<<',';const auto&x=g.gdextension_script_links[si];o<<"{\"state\":\""<<esc(x.state)<<"\",\"script_path\":\""<<esc(x.script_path)<<"\",\"script_entry_index\":"<<x.script_entry_index<<",\"analysis_set_id\":\""<<esc(x.analysis_set_id)<<"\",\"base_class\":\""<<esc(x.base_class)<<"\",\"method\":\""<<esc(x.method_name)<<"\",\"extends_keyword_token_index\":"<<x.extends_keyword_token_index<<",\"extends_identifier_token_index\":"<<x.extends_identifier_token_index<<",\"super_token_index\":"<<x.super_token_index<<",\"method_identifier_token_index\":"<<x.method_identifier_token_index<<",\"effective_line_known\":"<<(x.effective_line_known?"true":"false")<<",\"effective_line\":"<<x.effective_line<<",\"descriptor_path\":\""<<esc(x.descriptor_path)<<"\",\"library_path\":\""<<esc(x.library_path)<<"\",\"registration_state\":\""<<esc(x.registration_state)<<"\",\"registration_call_rva\":"<<x.registration_call_rva<<",\"bridge_candidate_count\":"<<x.bridge_candidate_count<<'}';}o<<"]}";}
    o<<",\"extraction\":{\"success\":"<<(r.godot_extract.success?"true":"false")<<",\"output_dir\":\""<<esc(path_utf8(r.godot_extract.output_dir))<<"\",\"file_count\":"<<r.godot_extract.files.size()<<"}},\n";

    {const auto&c=r.godot_legacy_config;o<<"  \"godot_legacy_config\":{\"candidate\":"<<(c.candidate?"true":"false")<<",\"valid\":"<<(c.valid?"true":"false")<<",\"property_count\":"<<c.property_count<<",\"application_name\":\""<<esc(c.application_name)<<"\",\"main_scene\":\""<<esc(c.main_scene)<<"\",\"icon\":\""<<esc(c.icon)<<"\",\"remap_count\":"<<c.remaps.size()<<",\"autoload_count\":"<<c.autoloads.size()<<",\"error_offset\":"<<c.error_offset<<",\"error\":\""<<esc(c.error)<<"\",\"remaps\":[";for(std::size_t i=0;i<c.remaps.size()&&i<64;++i){if(i)o<<',';o<<"{\"source\":\""<<esc(c.remaps[i].source)<<"\",\"target\":\""<<esc(c.remaps[i].target)<<"\"}";}o<<"],\"autoloads\":[";for(std::size_t i=0;i<c.autoloads.size()&&i<32;++i){if(i)o<<',';o<<"{\"name\":\""<<esc(c.autoloads[i].name)<<"\",\"path\":\""<<esc(c.autoloads[i].path)<<"\",\"singleton\":"<<(c.autoloads[i].singleton?"true":"false")<<'}';}o<<"]},\n";}

    {const auto&d=r.gdextension_descriptor;o<<"  \"gdextension_descriptor\":{\"valid\":"<<(d.valid?"true":"false");if(d.valid){o<<",\"entry_symbol\":\""<<esc(d.entry_symbol)<<"\",\"compatibility_minimum\":\""<<esc(d.compatibility_minimum)<<"\",\"reloadable_present\":"<<(d.reloadable_present?"true":"false")<<",\"reloadable\":"<<(d.reloadable?"true":"false")<<",\"library_count\":"<<d.libraries.size()<<",\"libraries_rendered\":"<<std::min<std::size_t>(d.libraries.size(),32)<<",\"libraries_truncated\":"<<(d.libraries.size()>32?"true":"false")<<",\"libraries\":[";for(std::size_t i=0;i<d.libraries.size()&&i<32;++i){if(i)o<<',';const auto&l=d.libraries[i];o<<"{\"feature\":\""<<esc(l.feature_key)<<"\",\"path\":\""<<esc(l.path)<<"\",\"line\":"<<l.line<<'}';}o<<']';}else if(!d.error.empty())o<<",\"error\":\""<<esc(d.error)<<"\",\"error_line\":"<<d.error_line;o<<"},\n";}

    o << "  \"pyinstaller\": {\"valid\":"<<(r.pyinstaller.valid?"true":"false");
    if(r.pyinstaller.valid){
        o<<",\"state\":\"CONFIRMED\",\"modified_cookie\":"<<(r.pyinstaller.heuristic_cookie?"true":"false")<<",\"cookie_offset\":"<<r.pyinstaller.cookie_offset<<",\"archive_start\":"<<r.pyinstaller.archive_start<<",\"archive_length\":"<<r.pyinstaller.archive_length<<",\"python_version\":"<<r.pyinstaller.python_version<<",\"python_library\":\""<<esc(r.pyinstaller.python_library)<<"\",\"entry_count\":"<<r.pyinstaller.entries.size()
         <<",\"bootstrap_profile\":\""<<esc(r.pyinstaller.bootstrap_profile)<<"\",\"bootstrap_reference_status\":\""<<esc(r.pyinstaller.bootstrap_reference_status)<<"\",\"bootstrap_reference_label\":\""<<esc(r.pyinstaller.bootstrap_reference_label)<<"\",\"bootstrap_match_mode\":\""<<esc(r.pyinstaller.bootstrap_match_mode)<<"\",\"bootstrap_modules\":[";
        for(std::size_t i=0;i<r.pyinstaller.bootstrap_modules.size();++i){if(i)o<<',';const auto&m=r.pyinstaller.bootstrap_modules[i];o<<"{\"name\":\""<<esc(m.name)<<"\",\"state\":\""<<esc(m.state)<<"\",\"reference_available\":"<<(m.reference_available?"true":"false")<<",\"reference_label\":\""<<esc(m.reference_label)<<"\",\"size\":"<<m.size<<",\"sha256\":\""<<esc(m.sha256)<<"\",\"semantic_sha256\":\""<<esc(m.semantic_sha256)<<"\",\"normalized_semantic_sha256\":\""<<esc(m.normalized_semantic_sha256)<<"\",\"normalized_code_units\":"<<m.normalized_code_units<<",\"normalization_source\":\""<<esc(m.normalization_source)<<"\",\"semantic_error_offset\":"<<m.semantic_error_offset<<",\"semantic_error\":\""<<esc(m.semantic_error)<<"\",\"normalize_error\":\""<<esc(m.normalize_error)<<"\"}";}o<<"]";
    }
    {const auto&x=r.pyinstaller_extract;o<<",\"extraction\":{\"success\":"<<(x.success?"true":"false")<<",\"mode\":\""<<(x.mode==PyInstExtractMode::AutoCore?"AUTO_CORE":"BULK_EXPLICIT")<<"\",\"output_dir\":\""<<esc(path_utf8(x.output_dir))<<"\",\"file_count\":"<<x.files.size()<<",\"normalized_files\":"<<x.normalized_files<<",\"target_preserved_files\":"<<x.target_preserved_files<<",\"normalized_code_units\":"<<x.normalized_code_units<<",\"output_bytes\":"<<x.output_bytes<<",\"budget_exhausted\":"<<(x.budget_exhausted?"true":"false")<<",\"omitted_count\":"<<x.omitted_count<<",\"omitted_bytes\":"<<x.omitted_bytes<<",\"policy_omitted_count\":"<<x.policy_omitted_count<<",\"policy_omitted_bytes\":"<<x.policy_omitted_bytes<<",\"user_files\":"<<x.user_files<<",\"bootstrap_files\":"<<x.bootstrap_files<<",\"runtime_files\":"<<x.runtime_files<<",\"bulk_files\":"<<x.bulk_files<<",\"pyz_entry_count\":"<<x.pyz_entry_count<<",\"pyz_selected_count\":"<<x.pyz_selected_count<<",\"carchive_inventory\":\""<<esc(path_utf8(x.carchive_inventory))<<"\",\"pyz_inventory\":\""<<esc(path_utf8(x.pyz_inventory))<<"\"}},\n";}

    o << "  \"crypto\": [";
    for(std::size_t i=0;i<r.crypto.uses.size();++i){if(i)o<<',';const auto&x=r.crypto.uses[i];o<<"{\"algorithm\":\""<<esc(x.algorithm)<<"\",\"state\":\""<<esc(x.state)<<"\",\"function_rva\":"<<x.function_rva<<",\"function_end_rva\":"<<x.function_end_rva<<",\"callsite_rva\":"<<x.callsite_rva<<",\"key_arg\":\""<<esc(x.key_arg)<<"\",\"key_length_arg\":\""<<esc(x.key_length_arg)<<"\",\"key_length_resolved\":"<<(x.key_length_resolved?"true":"false")<<",\"key_length\":"<<x.key_length<<",\"key_resolved\":"<<(x.key_resolved?"true":"false")<<",\"key_source\":\""<<esc(x.key_source)<<"\",\"key_section\":\""<<esc(x.key_section)<<"\",\"key_rva\":"<<x.key_rva<<",\"key_size\":"<<x.key_size<<",\"key_hex\":\""<<esc(x.key_hex)<<"\",\"api_source\":\""<<esc(x.api_source)<<"\",\"mode\":\""<<esc(x.mode)<<"\",\"operation\":\""<<esc(x.operation)<<"\",\"iv_arg\":\""<<esc(x.iv_arg)<<"\",\"iv_length_arg\":\""<<esc(x.iv_length_arg)<<"\",\"iv_length_resolved\":"<<(x.iv_length_resolved?"true":"false")<<",\"iv_length\":"<<x.iv_length<<",\"iv_resolved\":"<<(x.iv_resolved?"true":"false")<<",\"iv_source\":\""<<esc(x.iv_source)<<"\",\"iv_section\":\""<<esc(x.iv_section)<<"\",\"iv_rva\":"<<x.iv_rva<<",\"iv_size\":"<<x.iv_size<<",\"iv_hex\":\""<<esc(x.iv_hex)<<"\",\"fixed_key_offsets\":"<<x.fixed_key_offsets<<",\"dynamic_key_accesses\":"<<x.dynamic_key_accesses<<",\"shift4\":"<<x.shift4<<",\"shift5\":"<<x.shift5<<",\"xor_ops\":"<<x.xor_ops<<",\"addsub_ops\":"<<x.addsub_ops<<",\"back_edges\":"<<x.back_edges<<",\"delta_constants\":"<<x.delta_constants<<",\"evidence\":[";for(std::size_t z=0;z<x.evidence.size();++z){if(z)o<<',';o<<"\""<<esc(x.evidence[z])<<"\"";}o<<"]}";}
    o << "],\n";

    o << "  \"autoit\": {\"valid\":"<<(r.autoit.valid?"true":"false");
    if(r.autoit.valid){o<<",\"state\":\"CONFIRMED\",\"version\":\""<<esc(r.autoit.version)<<"\",\"container\":\""<<esc(r.autoit.container)<<"\",\"standard_marker\":"<<(r.autoit.standard_marker?"true":"false")<<",\"container_offset\":"<<r.autoit.container_offset<<",\"container_size\":"<<r.autoit.container_size<<",\"stream_offset\":"<<r.autoit.stream_offset<<",\"stream_end\":"<<r.autoit.stream_end<<",\"resource_type\":\""<<esc(r.autoit.resource_type)<<"\",\"resource_name\":\""<<esc(r.autoit.resource_name)<<"\",\"pseudo_records\":"<<r.autoit.pseudo_records<<",\"script_found\":"<<(r.autoit.script_found?"true":"false")<<",\"script_tokenized\":"<<(r.autoit.script_tokenized?"true":"false")<<",\"token_valid\":"<<(r.autoit.token_valid?"true":"false")<<",\"token_lines\":"<<r.autoit.token_lines<<",\"token_bytes\":"<<r.autoit.token_bytes<<",\"token_error_offset\":"<<r.autoit.token_error_offset<<",\"token_unknown_opcode\":"<<r.autoit.token_unknown_opcode<<",\"token_error\":\""<<esc(r.autoit.token_error)<<"\",\"script_preview\":\""<<esc(r.autoit.script_source.substr(0,4096))<<"\",\"records\":[";for(std::size_t z=0;z<r.autoit.records.size();++z){if(z)o<<',';const auto&x=r.autoit.records[z];o<<"{\"kind\":\""<<esc(x.kind)<<"\",\"subtype\":\""<<esc(x.subtype)<<"\",\"source_path\":\""<<esc(x.source_path)<<"\",\"output_name\":\""<<esc(x.output_name)<<"\",\"record_offset\":"<<x.record_offset<<",\"stored_data_offset\":"<<x.stored_data_offset<<",\"compressed_size\":"<<x.compressed_size<<",\"output_size\":"<<x.output_size<<",\"compressed\":"<<(x.compressed?"true":"false")<<",\"crc_valid\":"<<(x.crc_valid?"true":"false")<<",\"compressed_magic_standard\":"<<(x.compressed_magic_standard?"true":"false")<<",\"decoded_sha256\":\""<<esc(x.decoded_sha256)<<"\"}";}o<<"]";}
    o<<",\"extraction\":{\"success\":"<<(r.autoit_extract.success?"true":"false")<<",\"output_dir\":\""<<esc(path_utf8(r.autoit_extract.output_dir))<<"\",\"file_count\":"<<r.autoit_extract.files.size()<<",\"records_verified\":"<<r.autoit_extract.records_verified<<",\"resources_written\":"<<r.autoit_extract.resources_written<<",\"scripts_written\":"<<r.autoit_extract.scripts_written<<"}},\n";

    o << "  \"asar\": {\"valid\":"<<(r.asar.valid?"true":"false");
    if(r.asar.valid){o<<",\"state\":\"CONFIRMED\",\"header_size\":"<<r.asar.header_size<<",\"data_offset\":"<<r.asar.data_offset<<",\"packed_bytes\":"<<r.asar.packed_bytes<<",\"trailing_bytes\":"<<r.asar.trailing_bytes<<",\"file_count\":"<<r.asar.file_count<<",\"directory_count\":"<<r.asar.directory_count<<",\"link_count\":"<<r.asar.link_count<<",\"packed_file_count\":"<<r.asar.packed_file_count<<",\"unpacked_file_count\":"<<r.asar.unpacked_file_count<<",\"integrity_count\":"<<r.asar.integrity_count<<",\"package_json_valid\":"<<(r.asar.package_json_valid?"true":"false")<<",\"package_name\":\""<<esc(r.asar.package_name)<<"\",\"package_version\":\""<<esc(r.asar.package_version)<<"\",\"package_main\":\""<<esc(r.asar.package_main)<<"\",\"package_main_resolved\":\""<<esc(r.asar.package_main_resolved)<<"\",\"interesting_paths\":[";for(std::size_t i=0;i<r.asar.interesting_paths.size();++i){if(i)o<<',';o<<"\""<<esc(r.asar.interesting_paths[i])<<"\"";}o<<"]";}
    o<<",\"extraction\":{\"success\":"<<(r.asar_extract.success?"true":"false")<<",\"output_dir\":\""<<esc(path_utf8(r.asar_extract.output_dir))<<"\",\"packed_files\":"<<r.asar_extract.packed_files<<",\"unpacked_files\":"<<r.asar_extract.unpacked_files<<",\"directories\":"<<r.asar_extract.directories<<",\"links_skipped\":"<<r.asar_extract.links_skipped<<",\"integrity_verified\":"<<r.asar_extract.integrity_verified<<",\"integrity_mismatches\":"<<r.asar_extract.integrity_mismatches<<"}},\n";

    o<<"  \"unity\":";render_unity_json(o,r.unity,r.unity_extract);o<<",\n";

    {
        constexpr std::size_t kSymRender=32,kSnapRender=8,kFlutterEntryRender=256,kFlutterVariantRender=16;
        const auto&d=r.dart;const auto&a=d.aot;const auto&k=d.kernel;const auto&raw=d.raw_snapshot;
        o<<"  \"dart\": {\"candidate\":"<<(d.candidate?"true":"false")<<",\"valid\":"<<(d.valid?"true":"false")<<",\"state\":\""<<(d.valid?"CONFIRMED":(d.candidate?"FAILED":"ABSENT"))<<"\",\"offset_space\":\"current_input_file\",\"error\":\""<<esc(d.error)<<"\",\"error_offset\":"<<d.error_offset
         <<",\"raw_snapshot\":{\"candidate\":"<<(raw.candidate?"true":"false")<<",\"valid\":"<<(raw.valid?"true":"false")<<",\"file_offset\":"<<raw.file_offset<<",\"length\":"<<raw.length<<",\"kind\":"<<raw.kind<<",\"kind_name\":\""<<esc(raw.kind_name)<<"\",\"snapshot_hash\":\""<<esc(raw.snapshot_hash)<<"\",\"features\":\""<<esc(raw.features)<<"\",\"error\":\""<<esc(raw.error)<<"\",\"error_offset\":"<<raw.error_offset<<"}"
         <<",\"kernel\":";
        render_dart_kernel_json(o,k);
        o<<",\"aot\":{\"candidate\":"<<(a.candidate?"true":"false")<<",\"valid\":"<<(a.valid?"true":"false")<<",\"variant\":\""<<esc(a.variant)<<"\",\"architecture\":\""<<esc(a.architecture)<<"\",\"standalone\":"<<(a.standalone?"true":"false")<<",\"flutter_symbols\":"<<(a.flutter_symbols?"true":"false")<<",\"section_table_independent\":"<<(a.section_table_independent?"true":"false")<<",\"dynamic_symbol_count\":"<<a.dynamic_symbol_count<<",\"build_id\":\""<<esc(a.build_id_hex)<<"\",\"symbols_rendered\":"<<std::min(a.symbols.size(),kSymRender)<<",\"symbols_truncated\":"<<(a.symbols.size()>kSymRender?"true":"false")<<",\"symbols\":[";for(std::size_t z=0;z<a.symbols.size()&&z<kSymRender;++z){if(z)o<<',';const auto&x=a.symbols[z];o<<"{\"name\":\""<<esc(x.name)<<"\",\"value\":"<<x.value<<",\"size\":"<<x.size<<",\"file_offset\":"<<x.file_offset<<",\"segment_flags\":"<<x.segment_flags<<",\"binding\":"<<unsigned(x.binding)<<",\"type\":"<<unsigned(x.type)<<",\"file_backed\":"<<(x.file_backed?"true":"false")<<"}";}o<<"],\"snapshots_rendered\":"<<std::min(a.snapshots.size(),kSnapRender)<<",\"snapshots_truncated\":"<<(a.snapshots.size()>kSnapRender?"true":"false")<<",\"snapshots\":[";for(std::size_t z=0;z<a.snapshots.size()&&z<kSnapRender;++z){if(z)o<<',';const auto&x=a.snapshots[z];o<<"{\"valid\":"<<(x.valid?"true":"false")<<",\"file_offset\":"<<x.file_offset<<",\"length\":"<<x.length<<",\"kind\":"<<x.kind<<",\"kind_name\":\""<<esc(x.kind_name)<<"\",\"snapshot_hash\":\""<<esc(x.snapshot_hash)<<"\",\"features\":\""<<esc(x.features)<<"\",\"error\":\""<<esc(x.error)<<"\"}";}o<<"],\"anomalies\":[";for(std::size_t z=0;z<a.anomalies.size();++z){if(z)o<<',';o<<"\""<<esc(a.anomalies[z])<<"\"";}o<<"]}},\n";
        const auto&m=r.flutter_asset_manifest;o<<"  \"flutter_asset_manifest\": {\"candidate\":"<<(m.candidate?"true":"false")<<",\"valid\":"<<(m.valid?"true":"false")<<",\"nonempty\":"<<(m.nonempty?"true":"false")<<",\"state\":\""<<(m.valid?(m.nonempty?"CONFIRMED":"STRUCTURE_VALID_EMPTY"):(m.candidate?"FAILED":"ABSENT"))<<"\",\"offset_space\":\"current_input_file\",\"legacy_string_variants\":"<<(m.legacy_string_variants?"true":"false")<<",\"modern_metadata_variants\":"<<(m.modern_metadata_variants?"true":"false")<<",\"entry_count\":"<<m.entry_count<<",\"variant_count\":"<<m.variant_count<<",\"unknown_metadata_key_count\":"<<m.unknown_metadata_key_count<<",\"decoded_node_count\":"<<m.decoded_node_count<<",\"decoded_string_bytes\":"<<m.decoded_string_bytes<<",\"error\":\""<<esc(m.error)<<"\",\"error_offset\":"<<m.error_offset<<",\"entries_rendered\":"<<std::min(m.entries.size(),kFlutterEntryRender)<<",\"entries_truncated\":"<<(m.entries.size()>kFlutterEntryRender?"true":"false")<<",\"entries\":[";for(std::size_t z=0;z<m.entries.size()&&z<kFlutterEntryRender;++z){if(z)o<<',';const auto&e=m.entries[z];o<<"{\"key\":\""<<esc(e.key)<<"\",\"variants_rendered\":"<<std::min(e.variants.size(),kFlutterVariantRender)<<",\"variants_truncated\":"<<(e.variants.size()>kFlutterVariantRender?"true":"false")<<",\"variants\":[";for(std::size_t q=0;q<e.variants.size()&&q<kFlutterVariantRender;++q){if(q)o<<',';const auto&v=e.variants[q];o<<"{\"asset\":\""<<esc(v.asset)<<"\",\"dpr\":";if(v.device_pixel_ratio)o<<*v.device_pixel_ratio;else o<<"null";o<<",\"unknown_metadata_keys\":[";for(std::size_t u=0;u<v.unknown_metadata_keys.size();++u){if(u)o<<',';o<<"\""<<esc(v.unknown_metadata_keys[u])<<"\"";}o<<"]}";}o<<"]}";}o<<"],\"anomalies\":[";for(std::size_t z=0;z<m.anomalies.size();++z){if(z)o<<',';o<<"\""<<esc(m.anomalies[z])<<"\"";}o<<"]},\n";
    }

    {
        constexpr std::size_t kEntryRender=256,kPermRender=128,kCompRender=128,kPairRender=64,kDexEntryRender=64,kJniRelationRender=512,kFileRender=512;
        o << "  \"apk\": {\"candidate\":"<<(r.apk.candidate?"true":"false")<<",\"valid\":"<<(r.apk.valid?"true":"false")<<",\"state\":\""<<(r.apk.valid?"CONFIRMED":(r.apk.candidate?"FAILED":"ABSENT"))
          <<"\",\"zip_valid\":"<<(r.apk.zip_valid?"true":"false")<<",\"zip64\":"<<(r.apk.zip64?"true":"false")<<",\"offset_space\":\"current_input_file\",\"central_directory_offset\":"<<r.apk.central_directory_offset
          <<",\"entry_count\":"<<r.apk.entry_count<<",\"total_compressed\":"<<r.apk.total_compressed<<",\"total_uncompressed\":"<<r.apk.total_uncompressed
          <<",\"extractable_files\":"<<r.apk.extractable_files<<",\"extractable_bytes\":"<<r.apk.extractable_bytes<<",\"analysis_candidate_files\":"<<r.apk.analysis_candidate_files<<",\"analysis_candidate_bytes\":"<<r.apk.analysis_candidate_bytes
          <<",\"dex_count\":"<<r.apk.dex_count<<",\"validated_dex_count\":"<<r.apk.validated_dex_count<<",\"native_library_count\":"<<r.apk.native_library_count<<",\"validated_native_elf_count\":"<<r.apk.validated_native_elf_count
          <<",\"deep_native_elf_count\":"<<r.apk.deep_native_elf_count<<",\"native_dynamic_resolved_count\":"<<r.apk.native_dynamic_resolved_count
          <<",\"native_unwind_resolved_count\":"<<r.apk.native_unwind_resolved_count<<",\"native_jni_onload_count\":"<<r.apk.native_jni_onload_count
          <<",\"native_abi_mismatch_count\":"<<r.apk.native_abi_mismatch_count<<",\"native_deep_skipped_budget_count\":"<<r.apk.native_deep_skipped_budget_count
          <<",\"native_import_count\":"<<r.apk.native_import_count<<",\"native_export_count\":"<<r.apk.native_export_count
          <<",\"native_relocation_count\":"<<r.apk.native_relocation_count<<",\"native_fde_count\":"<<r.apk.native_fde_count
          <<",\"dex_deep_resolved_count\":"<<r.apk.dex_deep_resolved_count<<",\"dex_deep_partial_count\":"<<r.apk.dex_deep_partial_count<<",\"jni_relations_state\":\""<<esc(r.apk.jni_relations_state)<<"\",\"jni_relations_limited\":"<<(r.apk.jni_relations_limited?"true":"false")<<",\"jni_relations_error\":\""<<esc(r.apk.jni_relations_error)<<"\",\"jni_packaged_count\":"<<r.apk.jni_packaged_count<<",\"jni_referenced_count\":"<<r.apk.jni_referenced_count<<",\"jni_declared_count\":"<<r.apk.jni_declared_count<<",\"jni_exported_count\":"<<r.apk.jni_exported_count<<",\"jni_registration_confirmed_count\":"<<r.apk.jni_registration_confirmed_count
          <<",\"asset_count\":"<<r.apk.asset_count<<",\"resource_count\":"<<r.apk.resource_count<<",\"nested_archive_count\":"<<r.apk.nested_archive_count
          <<",\"has_v1_signature_files\":"<<(r.apk.has_v1_signature_files?"true":"false")<<",\"unsafe_path_count\":"<<r.apk.unsafe_path_count<<",\"symlink_entry_count\":"<<r.apk.symlink_entry_count
          <<",\"encrypted_entry_count\":"<<r.apk.encrypted_entry_count<<",\"unsupported_entry_count\":"<<r.apk.unsupported_entry_count<<",\"path_collision_entry_count\":"<<r.apk.duplicate_path_entry_count
          <<",\"invalid_dex_entry_count\":"<<r.apk.invalid_dex_entry_count<<",\"invalid_native_entry_count\":"<<r.apk.invalid_native_entry_count<<",\"godot_legacy_engine_config_candidate_count\":"<<r.apk.godot_legacy_engine_config_candidate_count<<",\"godot_legacy_engine_config_valid_count\":"<<r.apk.godot_legacy_engine_config_valid_count<<",\"unity_il2cpp_metadata_candidate_count\":"<<r.apk.unity_il2cpp_metadata_candidate_count<<",\"unity_il2cpp_metadata_valid_count\":"<<r.apk.unity_il2cpp_metadata_valid_count<<",\"unity_il2cpp_metadata_parse_count\":"<<r.apk.unity_il2cpp_metadata_parse_count<<",\"unity_il2cpp_metadata_parse_bytes\":"<<r.apk.unity_il2cpp_metadata_parse_bytes<<",\"unity_il2cpp_metadata_parse_budget_exhausted\":"<<(r.apk.unity_il2cpp_metadata_parse_budget_exhausted?"true":"false")<<",\"hermes_probe_entry_count\":"<<r.apk.hermes_probe_entry_count<<",\"hermes_magic_count\":"<<r.apk.hermes_magic_count<<",\"hermes_integrity_valid_count\":"<<r.apk.hermes_integrity_valid_count<<",\"hermes_supported_epoch_count\":"<<r.apk.hermes_supported_epoch_count<<",\"hermes_parse_complete_count\":"<<r.apk.hermes_parse_complete_count<<",\"hermes_integrity_failure_count\":"<<r.apk.hermes_integrity_failure_count<<",\"hermes_probe_skipped_budget_count\":"<<r.apk.hermes_probe_skipped_budget_count<<",\"hermes_probe_budget_exhausted\":"<<(r.apk.hermes_probe_budget_exhausted?"true":"false")<<",\"hermes_probe_validated_bytes\":"<<r.apk.hermes_probe_validated_bytes<<",\"hermes_probe_entry_limit\":512,\"hermes_probe_byte_limit\":67108864,\"anomaly_samples_truncated\":"<<(r.apk.anomaly_samples_truncated?"true":"false")
          <<",\"manifest_path_ambiguous\":"<<(r.apk.manifest_path_ambiguous?"true":"false")<<",\"resources_path_ambiguous\":"<<(r.apk.resources_path_ambiguous?"true":"false")<<",\"dex_path_ambiguous\":"<<(r.apk.dex_path_ambiguous?"true":"false")<<",\"error\":\""<<esc(r.apk.error)<<"\",";
        {const auto&g=r.apk.godot_legacy_config;o<<"\"godot_legacy_config\":{\"candidate\":"<<(g.candidate?"true":"false")<<",\"valid\":"<<(g.valid?"true":"false")<<",\"property_count\":"<<g.property_count<<",\"application_name\":\""<<esc(g.application_name)<<"\",\"main_scene\":\""<<esc(g.main_scene)<<"\",\"icon\":\""<<esc(g.icon)<<"\",\"remap_count\":"<<g.remaps.size()<<",\"autoload_count\":"<<g.autoloads.size()<<",\"error_offset\":"<<g.error_offset<<",\"error\":\""<<esc(g.error)<<"\"},";}
        const auto&m=r.apk.manifest;
        o<<"\"manifest\":{\"candidate\":"<<(m.candidate?"true":"false")<<",\"valid\":"<<(m.valid?"true":"false")<<",\"parse_complete\":"<<(m.parse_complete?"true":"false")<<",\"string_pool_utf8\":"<<(m.string_pool_utf8?"true":"false")
         <<",\"string_count\":"<<m.string_count<<",\"resource_id_count\":"<<m.resource_id_count<<",\"start_element_count\":"<<m.start_element_count<<",\"package_name\":\""<<esc(m.package_name)<<"\",\"version_name\":\""<<esc(m.version_name)<<"\",\"application_name\":\""<<esc(m.application_name)<<"\""
         <<",\"version_code_known\":"<<(m.version_code_known?"true":"false")<<",\"version_code\":"<<m.version_code<<",\"min_sdk_known\":"<<(m.min_sdk_known?"true":"false")<<",\"min_sdk\":"<<m.min_sdk<<",\"target_sdk_known\":"<<(m.target_sdk_known?"true":"false")<<",\"target_sdk\":"<<m.target_sdk
         <<",\"debuggable_known\":"<<(m.debuggable_known?"true":"false")<<",\"debuggable\":"<<(m.debuggable?"true":"false")<<",\"debuggable_reference\":"<<(m.debuggable_reference?"true":"false")<<",\"debuggable_reference_resolved\":"<<(m.debuggable_reference_resolved?"true":"false")<<",\"debuggable_reference_id\":"<<m.debuggable_reference_id
         <<",\"permission_count\":"<<m.permissions.size()<<",\"permissions_rendered\":"<<std::min(m.permissions.size(),kPermRender)<<",\"permissions_truncated\":"<<(m.permissions.size()>kPermRender?"true":"false")<<",\"permissions\":[";
        for(std::size_t z=0;z<m.permissions.size()&&z<kPermRender;++z){if(z)o<<',';o<<"\""<<esc(m.permissions[z])<<"\"";}o<<"],\"component_count\":"<<m.components.size()<<",\"components_rendered\":"<<std::min(m.components.size(),kCompRender)<<",\"components_truncated\":"<<(m.components.size()>kCompRender?"true":"false")<<",\"components\":[";
        for(std::size_t z=0;z<m.components.size()&&z<kCompRender;++z){if(z)o<<',';const auto&c=m.components[z];o<<"{\"kind\":\""<<esc(c.kind)<<"\",\"name\":\""<<esc(c.name)<<"\",\"process\":\""<<esc(c.process)<<"\",\"exported_known\":"<<(c.exported_known?"true":"false")<<",\"exported\":"<<(c.exported?"true":"false")<<",\"exported_reference\":"<<(c.exported_reference?"true":"false")<<",\"exported_reference_id\":"<<c.exported_reference_id<<"}";}
        o<<"],\"anomalies\":[";for(std::size_t z=0;z<m.anomalies.size();++z){if(z)o<<',';o<<"\""<<esc(m.anomalies[z])<<"\"";}o<<"],\"error_offset\":"<<m.error_offset<<",\"error\":\""<<esc(m.error)<<"\"},";
        const auto&rt=r.apk.resource_table;
        o<<"\"resource_table\":{\"candidate\":"<<(rt.candidate?"true":"false")<<",\"valid\":"<<(rt.valid?"true":"false")<<",\"parse_complete\":"<<(rt.parse_complete?"true":"false")<<",\"declared_package_count\":"<<rt.declared_package_count<<",\"parsed_package_count\":"<<rt.parsed_package_count<<",\"type_spec_count\":"<<rt.type_spec_count<<",\"type_config_count\":"<<rt.type_config_count<<",\"default_scalar_count\":"<<rt.default_scalar_count<<",\"complex_entry_count\":"<<rt.complex_entry_count<<",\"nondefault_config_count\":"<<rt.nondefault_config_count<<",\"package_names\":[";
        for(std::size_t z=0;z<rt.package_names.size();++z){if(z)o<<',';o<<"\""<<esc(rt.package_names[z])<<"\"";}o<<"],\"anomalies\":[";for(std::size_t z=0;z<rt.anomalies.size();++z){if(z)o<<',';o<<"\""<<esc(rt.anomalies[z])<<"\"";}o<<"],\"error_offset\":"<<rt.error_offset<<",\"error\":\""<<esc(rt.error)<<"\"},";
        const auto&sb=r.apk.signing_block;
        o<<"\"signing_block\":{\"present\":"<<(sb.present?"true":"false")<<",\"valid\":"<<(sb.valid?"true":"false")<<",\"cryptographic_verification_performed\":"<<(sb.cryptographic_verification_performed?"true":"false")<<",\"block_offset\":"<<sb.block_offset<<",\"block_size\":"<<sb.block_size<<",\"offset_space\":\"current_input_file\",\"has_v2\":"<<(sb.has_v2?"true":"false")<<",\"has_v3\":"<<(sb.has_v3?"true":"false")<<",\"has_v31\":"<<(sb.has_v31?"true":"false")<<",\"has_v32\":"<<(sb.has_v32?"true":"false")<<",\"has_source_stamp_v1\":"<<(sb.has_source_stamp_v1?"true":"false")<<",\"has_source_stamp_v2\":"<<(sb.has_source_stamp_v2?"true":"false")<<",\"has_verity_padding\":"<<(sb.has_verity_padding?"true":"false")<<",\"has_unknown_pairs\":"<<(sb.has_unknown_pairs?"true":"false")<<",\"pair_count\":"<<sb.pairs.size()<<",\"pairs_rendered\":"<<std::min(sb.pairs.size(),kPairRender)<<",\"pairs_truncated\":"<<(sb.pairs.size()>kPairRender?"true":"false")<<",\"pairs\":[";
        for(std::size_t z=0;z<sb.pairs.size()&&z<kPairRender;++z){if(z)o<<',';const auto&q=sb.pairs[z];o<<"{\"id\":"<<q.id<<",\"value_size\":"<<q.value_size<<",\"pair_offset\":"<<q.pair_offset<<",\"offset_space\":\"current_input_file\",\"label\":\""<<esc(q.label)<<"\"}";}o<<"],\"anomalies\":[";for(std::size_t z=0;z<sb.anomalies.size();++z){if(z)o<<',';o<<"\""<<esc(sb.anomalies[z])<<"\"";}o<<"],\"error_offset\":"<<sb.error_offset<<",\"error\":\""<<esc(sb.error)<<"\"},";
        o<<"\"dex_entries_rendered\":"<<std::min(r.apk.dex_entries.size(),kDexEntryRender)<<",\"dex_entries_truncated\":"<<(r.apk.dex_entries.size()>kDexEntryRender?"true":"false")<<",\"dex_entries\":[";for(std::size_t z=0;z<r.apk.dex_entries.size()&&z<kDexEntryRender;++z){if(z)o<<',';o<<"\""<<esc(r.apk.dex_entries[z])<<"\"";}o<<"],\"native_abis\":[";for(std::size_t z=0;z<r.apk.native_abis.size();++z){if(z)o<<',';o<<"\""<<esc(r.apk.native_abis[z])<<"\"";}o<<"],\"interesting_entries\":[";for(std::size_t z=0;z<r.apk.interesting_entries.size();++z){if(z)o<<',';o<<"\""<<esc(r.apk.interesting_entries[z])<<"\"";}o<<"],\"anomalies\":[";for(std::size_t z=0;z<r.apk.anomalies.size();++z){if(z)o<<',';o<<"\""<<esc(r.apk.anomalies[z])<<"\"";}o<<"],";
        {
            constexpr std::size_t kNativeDeepRender=256;
            std::vector<const ApkEntryInfo*> native_entries;
            for(const auto&e:r.apk.entries)if(e.native_library)native_entries.push_back(&e);
            o<<"\"native_deep_entries_total\":"<<native_entries.size()
             <<",\"native_deep_entries_rendered\":"<<std::min(native_entries.size(),kNativeDeepRender)
             <<",\"native_deep_entries_truncated\":"<<(native_entries.size()>kNativeDeepRender?"true":"false")
             <<",\"native_deep_entries\":[";
            for(std::size_t z=0;z<native_entries.size()&&z<kNativeDeepRender;++z){
                if(z)o<<',';
                const auto&e=*native_entries[z];
                o<<"{\"index\":"<<e.index<<",\"name\":\""<<esc(e.normalized_name)
                 <<"\",\"duplicate_path\":"<<(e.duplicate_path?"true":"false")
                 <<",\"abi\":\""<<esc(e.abi)<<"\",\"native_elf\":"<<(e.native_elf?"true":"false")
                 <<",\"native_deep_state\":\""<<esc(e.native_deep_state)<<"\",\"native_deep_error\":\""<<esc(e.native_deep_error)
                 <<"\",\"native_dynamic_state\":\""<<esc(e.native_dynamic_state)<<"\",\"native_dynamic_error\":\""<<esc(e.native_dynamic_error)
                 <<"\",\"native_unwind_state\":\""<<esc(e.native_unwind_state)<<"\",\"native_unwind_error\":\""<<esc(e.native_unwind_error)
                 <<"\",\"native_machine\":"<<e.native_machine<<",\"native_elf64\":"<<(e.native_elf64?"true":"false")
                 <<",\"native_abi_consistent_known\":"<<(e.native_abi_consistent_known?"true":"false")
                 <<",\"native_abi_consistent\":"<<(e.native_abi_consistent?"true":"false")
                 <<",\"native_import_count\":"<<e.native_import_count<<",\"native_export_count\":"<<e.native_export_count
                 <<",\"native_relocation_count\":"<<e.native_relocation_count<<",\"native_fde_count\":"<<e.native_fde_count
                 <<",\"native_jni_evidence_limited\":"<<(e.native_jni_evidence_limited?"true":"false")
                 <<",\"native_jni_evidence_error\":\""<<esc(e.native_jni_evidence_error)
                 <<"\",\"jni_onload_export\":"<<(e.jni_onload_export?"true":"false")
                 <<",\"jni_onload_symbol_file_offset\":"<<e.jni_onload_symbol_file_offset<<",\"jni_onload_va\":"<<e.jni_onload_va
                 <<",\"jni_onload_file_backed\":"<<(e.jni_onload_file_backed?"true":"false")
                 <<",\"jni_onload_file_offset\":"<<e.jni_onload_file_offset<<"}";
            }
            o<<"],";
        }
        o<<"\"jni_relations_rendered\":"<<std::min(r.apk.jni_relations.size(),kJniRelationRender)<<",\"jni_relations_truncated\":"<<(r.apk.jni_relations.size()>kJniRelationRender?"true":"false")<<",\"jni_relations\":[";
        for(std::size_t z=0;z<r.apk.jni_relations.size()&&z<kJniRelationRender;++z){if(z)o<<',';const auto&j=r.apk.jni_relations[z];o<<"{\"index\":"<<j.index<<",\"state\":\""<<esc(j.state)<<"\",\"evidence_level\":\""<<esc(j.evidence_level)<<"\",\"dex_entry\":\""<<esc(j.dex_entry)<<"\",\"native_entry\":\""<<esc(j.native_entry)<<"\",\"abi\":\""<<esc(j.abi)<<"\",\"library_name\":\""<<esc(j.library_name)<<"\",\"class_descriptor\":\""<<esc(j.class_descriptor)<<"\",\"method_name\":\""<<esc(j.method_name)<<"\",\"method_descriptor\":\""<<esc(j.method_descriptor)<<"\",\"jni_symbol\":\""<<esc(j.jni_symbol)<<"\",\"packaged\":"<<(j.packaged?"true":"false")<<",\"load_library_referenced\":"<<(j.load_library_referenced?"true":"false")<<",\"native_declared\":"<<(j.native_declared?"true":"false")<<",\"exported\":"<<(j.exported?"true":"false")<<",\"registration_confirmed\":"<<(j.registration_confirmed?"true":"false")<<",\"abi_consistent\":"<<(j.abi_consistent?"true":"false")<<",\"fde_boundary_confirmed\":"<<(j.fde_boundary_confirmed?"true":"false")<<",\"dex_method_index\":"<<j.dex_method_index<<",\"dex_load_instruction_offset\":"<<j.dex_load_instruction_offset<<",\"elf_symbol_index\":"<<j.elf_symbol_index<<",\"function_va\":"<<j.function_va<<",\"function_file_offset\":"<<j.function_file_offset<<",\"function_end_va\":"<<j.function_end_va<<",\"offset_spaces\":{\"dex_load_instruction_offset\":\"child_dex\",\"function_file_offset\":\"child_elf\",\"function_va\":\"child_elf_va\"},\"detail\":\""<<esc(j.detail)<<"\"}";}o<<"],";
        constexpr std::size_t kHermesEntryRender=32;
        std::vector<const ApkEntryInfo*> hermes_entries;
        for(const auto&e:r.apk.entries)if(e.hermes_magic&&hermes_entries.size()<kHermesEntryRender)hermes_entries.push_back(&e);
        o<<"\"hermes_entries_rendered\":"<<hermes_entries.size()<<",\"hermes_entries_truncated\":"<<(r.apk.hermes_magic_count>hermes_entries.size()?"true":"false")<<",\"hermes_entries\":[";
        for(std::size_t z=0;z<hermes_entries.size();++z){if(z)o<<',';const auto&e=*hermes_entries[z];o<<"{\"index\":"<<e.index<<",\"name\":\""<<esc(e.name)<<"\",\"normalized_name\":\""<<esc(e.normalized_name)<<"\",\"central_directory_offset\":"<<e.central_directory_offset<<",\"local_header_offset\":"<<e.local_header_offset<<",\"data_offset\":"<<e.data_offset<<",\"compressed_size\":"<<e.compressed_size<<",\"uncompressed_size\":"<<e.uncompressed_size<<",\"crc32\":"<<e.crc32<<",\"offset_space\":\"current_input_file\",\"duplicate_path\":"<<(e.duplicate_path?"true":"false")<<",\"integrity_valid\":"<<(e.hermes_integrity_valid?"true":"false")<<",\"probe_skipped_budget\":"<<(e.hermes_probe_skipped_budget?"true":"false")<<",\"version\":"<<e.hermes_version<<",\"supported_epoch\":"<<(e.hermes_supported_epoch?"true":"false")<<",\"valid\":"<<(e.hermes_valid?"true":"false")<<",\"parse_complete\":"<<(e.hermes_parse_complete?"true":"false")<<",\"sha256\":\""<<esc(e.hermes_sha256)<<"\",\"error\":\""<<esc(e.hermes_error)<<"\"}";}
        o<<"],";
        const auto rendered_entries=apk_render_entries(r.apk,kEntryRender);o<<"\"entries_sample_policy\":\"STRUCTURAL_CATEGORIES_THEN_ANALYSIS_PRIORITY_THEN_ARCHIVE_ORDER\",\"entries_rendered\":"<<rendered_entries.size()<<",\"entries_truncated\":"<<(r.apk.entries.size()>rendered_entries.size()?"true":"false")<<",\"entries\":[";
        for(std::size_t z=0;z<rendered_entries.size();++z){if(z)o<<',';const auto&e=*rendered_entries[z];o<<"{\"index\":"<<e.index<<",\"name\":\""<<esc(e.name)<<"\",\"normalized_name\":\""<<esc(e.normalized_name)<<"\",\"compressed_size\":"<<e.compressed_size<<",\"uncompressed_size\":"<<e.uncompressed_size<<",\"crc32\":"<<e.crc32<<",\"method\":"<<e.method<<",\"flags\":"<<e.flags<<",\"local_header_offset\":"<<e.local_header_offset<<",\"data_offset\":"<<e.data_offset<<",\"central_directory_offset\":"<<e.central_directory_offset<<",\"offset_space\":\"current_input_file\",\"directory\":"<<(e.directory?"true":"false")<<",\"encrypted\":"<<(e.encrypted?"true":"false")<<",\"supported\":"<<(e.supported?"true":"false")<<",\"safe_path\":"<<(e.safe_path?"true":"false")<<",\"symlink\":"<<(e.symlink?"true":"false")<<",\"duplicate_path\":"<<(e.duplicate_path?"true":"false")<<",\"manifest\":"<<(e.manifest?"true":"false")<<",\"manifest_binary_xml\":"<<(e.manifest_binary_xml?"true":"false")<<",\"dex\":"<<(e.dex?"true":"false")<<",\"dex_magic\":"<<(e.dex_magic?"true":"false")<<",\"dex_deep_state\":\""<<esc(e.dex_deep_state)<<"\",\"dex_deep_error\":\""<<esc(e.dex_deep_error)<<"\",\"dex_native_declaration_count\":"<<e.dex_native_declaration_count<<",\"dex_load_library_count\":"<<e.dex_load_library_count<<",\"resources_arsc\":"<<(e.resources_arsc?"true":"false")<<",\"resources_table\":"<<(e.resources_table?"true":"false")<<",\"native_library\":"<<(e.native_library?"true":"false")<<",\"native_elf\":"<<(e.native_elf?"true":"false")<<",\"godot_legacy_engine_config_candidate\":"<<(e.godot_legacy_engine_config_candidate?"true":"false")<<",\"godot_legacy_engine_config_valid\":"<<(e.godot_legacy_engine_config_valid?"true":"false")<<",\"godot_legacy_engine_config_error\":\""<<esc(e.godot_legacy_engine_config_error)<<"\",\"unity_il2cpp_metadata_candidate\":"<<(e.unity_il2cpp_metadata_candidate?"true":"false")<<",\"unity_il2cpp_metadata_valid\":"<<(e.unity_il2cpp_metadata_valid?"true":"false")<<",\"unity_il2cpp_metadata_parse_skipped_budget\":"<<(e.unity_il2cpp_metadata_parse_skipped_budget?"true":"false")<<",\"unity_il2cpp_metadata_version\":"<<e.unity_il2cpp_metadata_version<<",\"unity_il2cpp_metadata_layout\":\""<<esc(e.unity_il2cpp_metadata_layout)<<"\",\"unity_il2cpp_metadata_error\":\""<<esc(e.unity_il2cpp_metadata_error)<<"\",\"asset\":"<<(e.asset?"true":"false")<<",\"resource\":"<<(e.resource?"true":"false")<<",\"v1_signature_file\":"<<(e.v1_signature_file?"true":"false")<<",\"nested_archive\":"<<(e.nested_archive?"true":"false")<<",\"analysis_priority\":"<<unsigned(e.analysis_priority)<<",\"abi\":\""<<esc(e.abi)<<"\"}";}
        const auto&ex=r.apk_extract;o<<"],\"extraction\":{\"success\":"<<(ex.success?"true":"false")<<",\"budget_exhausted\":"<<(ex.budget_exhausted?"true":"false")<<",\"analysis_only\":"<<(ex.analysis_only?"true":"false")<<",\"output_dir\":\""<<esc(path_utf8(ex.output_dir))<<"\",\"file_count\":"<<ex.file_count<<",\"output_bytes\":"<<ex.output_bytes<<",\"files_rendered\":"<<std::min(ex.files.size(),kFileRender)<<",\"files_truncated\":"<<(ex.files.size()>kFileRender?"true":"false")<<",\"files\":[";for(std::size_t z=0;z<ex.files.size()&&z<kFileRender;++z){if(z)o<<',';o<<"\""<<esc(path_utf8(ex.files[z]))<<"\"";}o<<"],\"warnings\":[";for(std::size_t z=0;z<ex.warnings.size();++z){if(z)o<<',';o<<"\""<<esc(ex.warnings[z])<<"\"";}o<<"],\"error\":\""<<esc(ex.error)<<"\"}},\n";
    }

    {
        const auto&u=r.unreal;const auto&p=u.pak;const auto&i=u.iostore;
        o<<"  \"unreal_container\":{\"candidate\":"<<(u.candidate?"true":"false")<<",\"valid\":"<<(u.valid?"true":"false")
         <<",\"kind\":\""<<esc(u.kind)<<"\",\"state\":\""<<esc(u.state)<<"\",\"error\":\""<<esc(u.error)<<"\""
         <<",\"capability_scope\":\"STATIC_STRUCTURAL_RECOGNITION_ONLY\""
         <<",\"pak\":{\"candidate\":"<<(p.candidate?"true":"false")<<",\"valid\":"<<(p.valid?"true":"false")
         <<",\"supported_version\":"<<(p.supported_version?"true":"false")<<",\"state\":\""<<esc(p.state)<<"\",\"footer_profile\":\""<<esc(p.footer_profile)
         <<"\",\"version\":"<<p.version<<",\"footer_offset\":"<<p.footer_offset<<",\"footer_size\":"<<p.footer_size
         <<",\"index_offset\":"<<p.index_offset<<",\"index_size\":"<<p.index_size<<",\"entry_count\":"<<p.entry_count
         <<",\"mount_point\":\""<<esc(p.mount_point)<<"\",\"encrypted_index\":"<<(p.encrypted_index?"true":"false")
         <<",\"secondary_index_count\":"<<p.secondary_index_count
         <<",\"secondary_index_hashes_checked\":"<<(p.secondary_index_hashes_checked?"true":"false")
         <<",\"secondary_index_hashes_match\":"<<(p.secondary_index_hashes_match?"true":"false")
         <<",\"encoded_entry_bytes\":"<<p.encoded_entry_bytes<<",\"non_encoded_entry_count\":"<<p.non_encoded_entry_count
         <<",\"frozen_index\":"<<(p.frozen_index?"true":"false")<<",\"index_hash_checked\":"<<(p.index_hash_checked?"true":"false")
         <<",\"index_hash_matches\":"<<(p.index_hash_matches?"true":"false")<<",\"index_header_valid\":"<<(p.index_header_valid?"true":"false")
         <<",\"budget_exhausted\":"<<(p.budget_exhausted?"true":"false")<<",\"compression_methods\":[";
        for(std::size_t z=0;z<p.compression_methods.size();++z){if(z)o<<',';o<<"\""<<esc(p.compression_methods[z])<<"\"";}
        o<<"],\"error\":\""<<esc(p.error)<<"\"}"
         <<",\"iostore\":{\"candidate\":"<<(i.candidate?"true":"false")<<",\"valid\":"<<(i.valid?"true":"false")
         <<",\"toc_valid\":"<<(i.toc_valid?"true":"false")<<",\"supported_version\":"<<(i.supported_version?"true":"false")
         <<",\"state\":\""<<esc(i.state)<<"\",\"version\":"<<unsigned(i.version)<<",\"container_flags\":"<<unsigned(i.container_flags)
         <<",\"header_size\":"<<i.header_size<<",\"entry_count\":"<<i.entry_count<<",\"compressed_block_count\":"<<i.compressed_block_count
         <<",\"compression_block_size\":"<<i.compression_block_size<<",\"directory_index_size\":"<<i.directory_index_size
         <<",\"partition_count\":"<<i.partition_count<<",\"partition_size\":"<<i.partition_size
         <<",\"perfect_hash_seed_count\":"<<i.perfect_hash_seed_count<<",\"chunks_without_perfect_hash_count\":"<<i.chunks_without_perfect_hash_count
         <<",\"encrypted\":"<<(i.encrypted?"true":"false")<<",\"signed_flag\":"<<(i.signed_container?"true":"false")
         <<",\"signature_table_structurally_present\":"<<(i.signature_table_structurally_present?"true":"false")
         <<",\"signature_verification_performed\":false,\"content_readable\":false"
         <<",\"indexed\":"<<(i.indexed?"true":"false")<<",\"pair_checked\":"<<(i.pair_checked?"true":"false")
         <<",\"pair_valid\":"<<(i.pair_valid?"true":"false")<<",\"budget_exhausted\":"<<(i.budget_exhausted?"true":"false")
         <<",\"duplicate_chunk_ids\":"<<(i.duplicate_chunk_ids?"true":"false")<<",\"sibling_inventory_truncated\":"<<(i.sibling_inventory_truncated?"true":"false")
         <<",\"compression_methods\":[";
        for(std::size_t z=0;z<i.compression_methods.size();++z){if(z)o<<',';o<<"\""<<esc(i.compression_methods[z])<<"\"";}
        o<<"],\"partitions\":[";
        for(std::size_t z=0;z<i.partitions.size();++z){if(z)o<<',';const auto&x=i.partitions[z];o<<"{\"index\":"<<x.index<<",\"path\":\""<<esc(path_utf8(x.path))<<"\",\"required_bytes\":"<<x.required_bytes<<",\"file_size\":"<<x.file_size<<",\"state\":\""<<esc(x.state)<<"\",\"error\":\""<<esc(x.error)<<"\"}";}
        o<<"],\"error\":\""<<esc(i.error)<<"\"}},\n";
    }
    if(automatic_child_summary)render_dex_summary_json(o,r);
    else {
    o << "  \"dex\": {\"candidate\":"<<(r.dex.candidate?"true":"false")<<",\"valid\":"<<(r.dex.valid?"true":"false")<<",\"state\":\""<<(r.dex.candidate?(r.dex.valid?"CONFIRMED":"FAILED"):"ABSENT")<<"\",\"version\":\""<<esc(r.dex.version)<<"\",\"offset_space\":\"current_input_file\",\"reverse_endian\":"<<(r.dex.reverse_endian?"true":"false")<<",\"container_v41\":"<<(r.dex.container_v41?"true":"false")<<",\"header_size\":"<<r.dex.header_size<<",\"file_size\":"<<r.dex.file_size<<",\"container_size\":"<<r.dex.container_size<<",\"header_offset\":"<<r.dex.header_offset<<",\"map_off\":"<<r.dex.map_off<<",\"string_ids_size\":"<<r.dex.string_ids_size<<",\"string_ids_off\":"<<r.dex.string_ids_off<<",\"type_ids_size\":"<<r.dex.type_ids_size<<",\"type_ids_off\":"<<r.dex.type_ids_off<<",\"proto_ids_size\":"<<r.dex.proto_ids_size<<",\"proto_ids_off\":"<<r.dex.proto_ids_off<<",\"field_ids_size\":"<<r.dex.field_ids_size<<",\"field_ids_off\":"<<r.dex.field_ids_off<<",\"method_ids_size\":"<<r.dex.method_ids_size<<",\"method_ids_off\":"<<r.dex.method_ids_off<<",\"class_defs_size\":"<<r.dex.class_defs_size<<",\"class_defs_off\":"<<r.dex.class_defs_off<<",\"data_size\":"<<r.dex.data_size<<",\"data_off\":"<<r.dex.data_off<<",\"defined_field_count\":"<<r.dex.defined_field_count<<",\"defined_method_count\":"<<r.dex.defined_method_count<<",\"code_item_count\":"<<r.dex.code_item_count<<",\"debug_info_count\":"<<r.dex.debug_info_count<<",\"map_complete\":"<<(r.dex.map_complete?"true":"false")<<",\"descriptor_parse_complete\":"<<(r.dex.descriptor_parse_complete?"true":"false")<<",\"jni_surface_scan_complete\":"<<(r.dex.jni_surface_scan_complete?"true":"false")<<",\"jni_surface_scan_error\":\""<<esc(r.dex.jni_surface_scan_error)<<"\",\"library_load_count\":"<<r.dex.library_loads.size()<<",\"checksum_checked\":"<<(r.dex.checksum_checked?"true":"false")<<",\"checksum_matches\":"<<(r.dex.checksum_matches?"true":"false")<<",\"signature_checked\":"<<(r.dex.signature_checked?"true":"false")<<",\"signature_matches\":"<<(r.dex.signature_matches?"true":"false")<<",\"error_offset\":"<<r.dex.error_offset<<",\"error\":\""<<esc(r.dex.error)<<"\",\"map_items\":[";
    for(std::size_t i=0;i<r.dex.map_items.size();++i){if(i)o<<',';const auto&m=r.dex.map_items[i];o<<"{\"type\":"<<m.type<<",\"name\":\""<<esc(m.name)<<"\",\"size\":"<<m.size<<",\"offset\":"<<m.offset<<",\"offset_space\":\"current_input_file\"}";}
    o<<"],\"types\":[";for(std::size_t i=0;i<r.dex.types.size();++i){if(i)o<<',';o<<"\""<<esc(r.dex.types[i])<<"\"";}
    o<<"],\"protos\":[";for(std::size_t i=0;i<r.dex.protos.size();++i){if(i)o<<',';const auto&p=r.dex.protos[i];o<<"{\"index\":"<<p.index<<",\"shorty\":\""<<esc(p.shorty)<<"\",\"return_type\":\""<<esc(p.return_type)<<"\",\"signature\":\""<<esc(p.signature)<<"\",\"descriptor\":\""<<esc(p.descriptor)<<"\",\"parameters_off\":"<<p.parameters_off<<",\"offset_space\":\"current_input_file\",\"parameter_types\":[";for(std::size_t z=0;z<p.parameter_types.size();++z){if(z)o<<',';o<<"\""<<esc(p.parameter_types[z])<<"\"";}o<<"]}";}
    o<<"],\"fields\":[";for(std::size_t i=0;i<r.dex.fields.size();++i){if(i)o<<',';const auto&f=r.dex.fields[i];o<<"{\"index\":"<<f.index<<",\"defined\":"<<(f.defined?"true":"false")<<",\"owner\":\""<<esc(f.owner)<<"\",\"name\":\""<<esc(f.name)<<"\",\"type\":\""<<esc(f.type)<<"\",\"signature\":\""<<esc(f.signature)<<"\",\"access_flags\":"<<f.access_flags<<"}";}
    o<<"],\"methods\":[";for(std::size_t i=0;i<r.dex.methods.size();++i){if(i)o<<',';const auto&m=r.dex.methods[i];o<<"{\"index\":"<<m.index<<",\"defined\":"<<(m.defined?"true":"false")<<",\"owner\":\""<<esc(m.owner)<<"\",\"owner_descriptor\":\""<<esc(m.owner_descriptor)<<"\",\"name\":\""<<esc(m.name)<<"\",\"signature\":\""<<esc(m.signature)<<"\",\"descriptor\":\""<<esc(m.descriptor)<<"\",\"access_flags\":"<<m.access_flags<<",\"code_off\":"<<m.code_off<<",\"offset_space\":\"current_input_file\"}";}
    o<<"],\"code_items\":[";for(std::size_t i=0;i<r.dex.code_items.size();++i){if(i)o<<',';const auto&c=r.dex.code_items[i];o<<"{\"method_idx\":"<<c.method_idx<<",\"code_off\":"<<c.code_off<<",\"code_size_bytes\":"<<c.code_size_bytes<<",\"debug_info_off\":"<<c.debug_info_off<<",\"registers_size\":"<<c.registers_size<<",\"ins_size\":"<<c.ins_size<<",\"outs_size\":"<<c.outs_size<<",\"tries_size\":"<<c.tries_size<<",\"insns_size\":"<<c.insns_size<<",\"debug_line_start\":"<<c.debug_line_start<<",\"debug_position_count\":"<<c.debug_position_count<<",\"offset_space\":\"current_input_file\",\"parameter_names\":[";for(std::size_t z=0;z<c.parameter_names.size();++z){if(z)o<<',';o<<"\""<<esc(c.parameter_names[z])<<"\"";}o<<"]}";}
    o<<"],\"classes\":[";for(std::size_t i=0;i<r.dex.classes.size();++i){if(i)o<<',';const auto&c=r.dex.classes[i];o<<"{\"class_idx\":"<<c.class_idx<<",\"name\":\""<<esc(c.name)<<"\",\"superclass\":\""<<esc(c.superclass)<<"\",\"source_file\":\""<<esc(c.source_file)<<"\",\"access_flags\":"<<c.access_flags<<",\"interfaces_off\":"<<c.interfaces_off<<",\"class_data_off\":"<<c.class_data_off<<",\"static_values_off\":"<<c.static_values_off<<",\"static_field_count\":"<<c.static_field_count<<",\"instance_field_count\":"<<c.instance_field_count<<",\"direct_method_count\":"<<c.direct_method_count<<",\"virtual_method_count\":"<<c.virtual_method_count<<",\"offset_space\":\"current_input_file\",\"interfaces\":[";for(std::size_t z=0;z<c.interfaces.size();++z){if(z)o<<',';o<<"\""<<esc(c.interfaces[z])<<"\"";}o<<"]}";}
    o<<"],\"method_handles\":[";for(std::size_t i=0;i<r.dex.method_handles.size();++i){if(i)o<<',';const auto&h=r.dex.method_handles[i];o<<"{\"index\":"<<h.index<<",\"handle_type\":"<<h.handle_type<<",\"field_or_method_id\":"<<h.field_or_method_id<<",\"references_field\":"<<(h.references_field?"true":"false")<<",\"target\":\""<<esc(h.target)<<"\"}";}
    o<<"],\"call_sites\":[";for(std::size_t i=0;i<r.dex.call_sites.size();++i){if(i)o<<',';const auto&c=r.dex.call_sites[i];o<<"{\"index\":"<<c.index<<",\"call_site_off\":"<<c.call_site_off<<",\"bootstrap_method_handle_idx\":"<<c.bootstrap_method_handle_idx<<",\"method_name_idx\":"<<c.method_name_idx<<",\"method_type_idx\":"<<c.method_type_idx<<",\"extra_argument_count\":"<<c.extra_argument_count<<",\"method_name\":\""<<esc(c.method_name)<<"\",\"method_type\":\""<<esc(c.method_type)<<"\",\"bootstrap_target\":\""<<esc(c.bootstrap_target)<<"\",\"offset_space\":\"current_input_file\"}";}
    o<<"],\"library_loads\":[";for(std::size_t i=0;i<r.dex.library_loads.size();++i){if(i)o<<',';const auto&x=r.dex.library_loads[i];o<<"{\"caller_method_idx\":"<<x.caller_method_idx<<",\"target_method_idx\":"<<x.target_method_idx<<",\"string_idx\":"<<x.string_idx<<",\"pc_code_units\":"<<x.pc_code_units<<",\"instruction_file_offset\":"<<x.instruction_file_offset<<",\"offset_space\":\"current_input_file\",\"library_name\":\""<<esc(x.library_name)<<"\"}";}
    o<<"],\"strings\":[";for(std::size_t i=0;i<r.dex.strings.size();++i){if(i)o<<',';o<<"\""<<esc(r.dex.strings[i])<<"\"";}
    o<<"],\"string_hints\":[";for(std::size_t i=0;i<r.dex.string_hints.size();++i){if(i)o<<',';o<<"\""<<esc(r.dex.string_hints[i])<<"\"";}
    o<<"],\"anomalies\":[";for(std::size_t i=0;i<r.dex.anomalies.size();++i){if(i)o<<',';o<<"\""<<esc(r.dex.anomalies[i])<<"\"";}
    o<<"],\"extraction\":{\"success\":"<<(r.dex_extract.success?"true":"false")<<",\"methods_csv\":\""<<esc(path_utf8(r.dex_extract.methods_csv))<<"\",\"method_count\":"<<r.dex_extract.method_count<<",\"classes_csv\":\""<<esc(path_utf8(r.dex_extract.classes_csv))<<"\",\"class_count\":"<<r.dex_extract.class_count<<",\"fields_csv\":\""<<esc(path_utf8(r.dex_extract.fields_csv))<<"\",\"field_count\":"<<r.dex_extract.field_count<<",\"callsites_csv\":\""<<esc(path_utf8(r.dex_extract.callsites_csv))<<"\",\"callsite_count\":"<<r.dex_extract.callsite_count<<",\"error\":\""<<esc(r.dex_extract.error)<<"\"}},\n";

    }

    o << "  \"jvm_class\": {\"candidate\":"<<(r.jvm_class.candidate?"true":"false")<<",\"valid\":"<<(r.jvm_class.valid?"true":"false")<<",\"state\":\""<<(r.jvm_class.candidate?(r.jvm_class.valid?"CONFIRMED":"FAILED"):"ABSENT")<<"\",\"major\":"<<r.jvm_class.major<<",\"minor\":"<<r.jvm_class.minor<<",\"preview\":"<<(r.jvm_class.preview?"true":"false")<<",\"java_release\":\""<<esc(r.jvm_class.java_release)<<"\",\"class_name\":\""<<esc(r.jvm_class.class_name)<<"\",\"super_name\":\""<<esc(r.jvm_class.super_name)<<"\",\"source_file\":\""<<esc(r.jvm_class.source_file)<<"\",\"generic_signature\":\""<<esc(r.jvm_class.generic_signature)<<"\",\"module_name\":\""<<esc(r.jvm_class.module_name)<<"\",\"constant_pool_count\":"<<r.jvm_class.constant_pool_count<<",\"bootstrap_method_count\":"<<r.jvm_class.bootstrap_method_count<<",\"invokedynamic_count\":"<<r.jvm_class.invokedynamic_count<<",\"dynamic_count\":"<<r.jvm_class.dynamic_count<<",\"kotlin_metadata\":"<<(r.jvm_class.kotlin_metadata?"true":"false")<<",\"descriptor_parse_complete\":"<<(r.jvm_class.descriptor_parse_complete?"true":"false")<<",\"error_offset\":"<<r.jvm_class.error_offset<<",\"error\":\""<<esc(r.jvm_class.error)<<"\",\"interfaces\":[";
    for(std::size_t i=0;i<r.jvm_class.interfaces.size();++i){if(i)o<<',';o<<"\""<<esc(r.jvm_class.interfaces[i])<<"\"";}
    o<<"],\"fields\":[";for(std::size_t i=0;i<r.jvm_class.fields.size();++i){if(i)o<<',';const auto&f=r.jvm_class.fields[i];o<<"{\"access_flags\":"<<f.access_flags<<",\"name\":\""<<esc(f.name)<<"\",\"descriptor\":\""<<esc(f.descriptor)<<"\",\"type\":\""<<esc(f.type_name)<<"\",\"generic_signature\":\""<<esc(f.generic_signature)<<"\",\"constant_value\":\""<<esc(f.constant_value)<<"\",\"annotations\":[";for(std::size_t z=0;z<f.annotations.size();++z){if(z)o<<',';o<<"\""<<esc(f.annotations[z])<<"\"";}o<<"]}";}
    o<<"],\"methods\":[";for(std::size_t i=0;i<r.jvm_class.methods.size();++i){if(i)o<<',';const auto&m=r.jvm_class.methods[i];o<<"{\"access_flags\":"<<m.access_flags<<",\"name\":\""<<esc(m.name)<<"\",\"descriptor\":\""<<esc(m.descriptor)<<"\",\"signature\":\""<<esc(m.signature)<<"\",\"return_type\":\""<<esc(m.return_type)<<"\",\"generic_signature\":\""<<esc(m.generic_signature)<<"\",\"code_offset\":"<<m.code_offset<<",\"code_size\":"<<m.code_size<<",\"max_stack\":"<<m.max_stack<<",\"max_locals\":"<<m.max_locals<<",\"line_number_count\":"<<m.line_number_count<<",\"parameter_types\":[";for(std::size_t z=0;z<m.parameter_types.size();++z){if(z)o<<',';o<<"\""<<esc(m.parameter_types[z])<<"\"";}o<<"],\"parameter_names\":[";for(std::size_t z=0;z<m.parameter_names.size();++z){if(z)o<<',';o<<"\""<<esc(m.parameter_names[z])<<"\"";}o<<"],\"exceptions\":[";for(std::size_t z=0;z<m.exceptions.size();++z){if(z)o<<',';o<<"\""<<esc(m.exceptions[z])<<"\"";}o<<"],\"annotations\":[";for(std::size_t z=0;z<m.annotations.size();++z){if(z)o<<',';o<<"\""<<esc(m.annotations[z])<<"\"";}o<<"]}";}
    o<<"],\"references\":[";for(std::size_t i=0;i<r.jvm_class.references.size();++i){if(i)o<<',';const auto&x=r.jvm_class.references[i];o<<"{\"kind\":\""<<esc(x.kind)<<"\",\"owner\":\""<<esc(x.owner)<<"\",\"name\":\""<<esc(x.name)<<"\",\"descriptor\":\""<<esc(x.descriptor)<<"\",\"signature\":\""<<esc(x.signature)<<"\"}";}
    o<<"],\"string_constants\":[";for(std::size_t i=0;i<r.jvm_class.string_constants.size();++i){if(i)o<<',';o<<"\""<<esc(r.jvm_class.string_constants[i])<<"\"";}o<<"],\"annotations\":[";for(std::size_t i=0;i<r.jvm_class.annotations.size();++i){if(i)o<<',';o<<"\""<<esc(r.jvm_class.annotations[i])<<"\"";}o<<"],\"obfuscation_hints\":[";for(std::size_t i=0;i<r.jvm_class.obfuscation_hints.size();++i){if(i)o<<',';o<<"\""<<esc(r.jvm_class.obfuscation_hints[i])<<"\"";}o<<"],\"anomalies\":[";for(std::size_t i=0;i<r.jvm_class.anomalies.size();++i){if(i)o<<',';o<<"\""<<esc(r.jvm_class.anomalies[i])<<"\"";}o<<"],\"extraction\":{\"success\":"<<(r.jvm_extract.success?"true":"false")<<",\"methods_csv\":\""<<esc(path_utf8(r.jvm_extract.methods_csv))<<"\",\"method_count\":"<<r.jvm_extract.method_count<<",\"fields_csv\":\""<<esc(path_utf8(r.jvm_extract.fields_csv))<<"\",\"field_count\":"<<r.jvm_extract.field_count<<",\"references_csv\":\""<<esc(path_utf8(r.jvm_extract.references_csv))<<"\",\"reference_count\":"<<r.jvm_extract.reference_count<<"}},\n";
    o << "  \"jar\": {\"candidate\":"<<(r.jar.candidate?"true":"false")<<",\"valid\":"<<(r.jar.valid?"true":"false")<<",\"state\":\""<<(r.jar.valid?"CONFIRMED":(r.jar.candidate?"FAILED":"ABSENT"))<<"\",\"variant\":\""<<esc(r.jar.variant)<<"\",\"entry_count\":"<<r.jar.entry_count<<",\"class_count\":"<<r.jar.class_count<<",\"nested_archive_count\":"<<r.jar.nested_archive_count<<",\"native_library_count\":"<<r.jar.native_library_count<<",\"total_uncompressed\":"<<r.jar.total_uncompressed<<",\"total_compressed\":"<<r.jar.total_compressed<<",\"multi_release\":"<<(r.jar.multi_release?"true":"false")<<",\"spring_boot\":"<<(r.jar.spring_boot?"true":"false")<<",\"fat_jar\":"<<(r.jar.fat_jar?"true":"false")<<",\"zip64\":"<<(r.jar.zip64?"true":"false")<<",\"main_class\":\""<<esc(r.jar.main_class)<<"\",\"automatic_module_name\":\""<<esc(r.jar.automatic_module_name)<<"\",\"implementation_version\":\""<<esc(r.jar.implementation_version)<<"\",\"error\":\""<<esc(r.jar.error)<<"\",\"entries\":[";
    for(std::size_t i=0;i<r.jar.entries.size();++i){if(i)o<<',';const auto&e=r.jar.entries[i];o<<"{\"name\":\""<<esc(e.name)<<"\",\"compressed_size\":"<<e.compressed_size<<",\"uncompressed_size\":"<<e.uncompressed_size<<",\"crc32\":"<<e.crc32<<",\"method\":"<<e.method<<",\"directory\":"<<(e.directory?"true":"false")<<",\"encrypted\":"<<(e.encrypted?"true":"false")<<",\"supported\":"<<(e.supported?"true":"false")<<",\"safe_path\":"<<(e.safe_path?"true":"false")<<",\"symlink\":"<<(e.symlink?"true":"false")<<",\"class_file\":"<<(e.class_file?"true":"false")<<",\"nested_archive\":"<<(e.nested_archive?"true":"false")<<"}";}
    o<<"],\"manifest_lines\":[";for(std::size_t i=0;i<r.jar.manifest_lines.size();++i){if(i)o<<',';o<<"\""<<esc(r.jar.manifest_lines[i])<<"\"";}o<<"],\"interesting_entries\":[";for(std::size_t i=0;i<r.jar.interesting_entries.size();++i){if(i)o<<',';o<<"\""<<esc(r.jar.interesting_entries[i])<<"\"";}o<<"],\"anomalies\":[";for(std::size_t i=0;i<r.jar.anomalies.size();++i){if(i)o<<',';o<<"\""<<esc(r.jar.anomalies[i])<<"\"";}o<<"],\"extraction\":{\"success\":"<<(r.jar_extract.success?"true":"false")<<",\"budget_exhausted\":"<<(r.jar_extract.budget_exhausted?"true":"false")<<",\"output_dir\":\""<<esc(path_utf8(r.jar_extract.output_dir))<<"\",\"file_count\":"<<r.jar_extract.file_count<<",\"output_bytes\":"<<r.jar_extract.output_bytes<<",\"error\":\""<<esc(r.jar_extract.error)<<"\"}},\n";

    render_dotnet_native_json(o,r,automatic_child_summary);
    if(automatic_child_summary)render_dotnet_summary_json(o,r);
    else {
    o << "  \"dotnet\": {\"candidate\":"<<(r.pe.clr.present?"true":"false")<<",\"valid\":"<<(r.dotnet.valid?"true":"false")<<",\"state\":\""<<(r.pe.clr.present?(r.dotnet.valid?"CONFIRMED":"FAILED"):"ABSENT")<<"\",\"unity_managed\":"<<(r.dotnet.unity_managed?"true":"false")<<",\"unity_mono\":"<<(r.dotnet.unity_mono?"true":"false")<<",\"unity_path_hint\":"<<(r.dotnet.unity_path_hint?"true":"false")<<",\"unity_engine_reference\":"<<(r.dotnet.unity_engine_reference?"true":"false")<<",\"runtime_version\":\""<<esc(r.dotnet.runtime_version)<<"\",\"metadata_offset\":"<<r.dotnet.metadata_offset<<",\"metadata_size\":"<<r.dotnet.metadata_size<<",\"blob_heap_size\":"<<r.dotnet.blob_heap_size<<",\"resources_offset\":"<<r.dotnet.resources_offset<<",\"resources_size\":"<<r.dotnet.resources_size<<",\"signature_parse_complete\":"<<(r.dotnet.signature_parse_complete?"true":"false")<<",\"error\":\""<<esc(r.dotnet.error)<<"\",\"table_rows\":[";
    for(std::size_t i=0;i<r.dotnet.table_rows.size();++i){if(i)o<<',';o<<r.dotnet.table_rows[i];}
    o<<"],\"assembly_refs\":[";for(std::size_t i=0;i<r.dotnet.assembly_refs.size();++i){if(i)o<<',';const auto&a=r.dotnet.assembly_refs[i];o<<"{\"token\":"<<a.token<<",\"name\":\""<<esc(a.name)<<"\",\"version\":\""<<esc(a.version)<<"\",\"culture\":\""<<esc(a.culture)<<"\"}";}
    o<<"],\"type_refs\":[";for(std::size_t i=0;i<r.dotnet.type_refs.size();++i){if(i)o<<',';const auto&t=r.dotnet.type_refs[i];o<<"{\"token\":"<<t.token<<",\"namespace\":\""<<esc(t.namespc)<<"\",\"name\":\""<<esc(t.name)<<"\",\"full_name\":\""<<esc(t.full_name)<<"\",\"resolution_scope\":"<<t.resolution_scope<<",\"scope_name\":\""<<esc(t.scope_name)<<"\"}";}
    o<<"],\"types\":[";for(std::size_t i=0;i<r.dotnet.types.size();++i){if(i)o<<',';const auto&t=r.dotnet.types[i];o<<"{\"token\":"<<t.token<<",\"flags\":"<<t.flags<<",\"namespace\":\""<<esc(t.namespc)<<"\",\"name\":\""<<esc(t.name)<<"\",\"full_name\":\""<<esc(t.full_name)<<"\",\"base_type\":\""<<esc(t.base_type)<<"\",\"extends_token\":"<<t.extends_token<<",\"enclosing_type\":\""<<esc(t.enclosing_type)<<"\",\"interfaces\":[";for(std::size_t z=0;z<t.interfaces.size();++z){if(z)o<<',';o<<"\""<<esc(t.interfaces[z])<<"\"";}o<<"],\"generic_params\":[";for(std::size_t z=0;z<t.generic_params.size();++z){if(z)o<<',';o<<"\""<<esc(t.generic_params[z])<<"\"";}o<<"]}";}
    o<<"],\"fields\":[";for(std::size_t i=0;i<r.dotnet.fields.size();++i){if(i)o<<',';const auto&f=r.dotnet.fields[i];o<<"{\"token\":"<<f.token<<",\"flags\":"<<f.flags<<",\"declaring_type\":\""<<esc(f.declaring_type)<<"\",\"name\":\""<<esc(f.name)<<"\",\"type\":\""<<esc(f.type_name)<<"\",\"signature\":\""<<esc(f.signature)<<"\",\"has_layout\":"<<(f.has_layout?"true":"false")<<",\"offset\":"<<f.offset<<",\"has_rva\":"<<(f.has_rva?"true":"false")<<",\"rva\":"<<f.rva<<"}";}
    o<<"],\"params\":[";for(std::size_t i=0;i<r.dotnet.params.size();++i){if(i)o<<',';const auto&p=r.dotnet.params[i];o<<"{\"token\":"<<p.token<<",\"flags\":"<<p.flags<<",\"sequence\":"<<p.sequence<<",\"name\":\""<<esc(p.name)<<"\"}";}
    o<<"],\"methods\":[";for(std::size_t i=0;i<r.dotnet.methods.size();++i){if(i)o<<',';const auto&m=r.dotnet.methods[i];o<<"{\"token\":"<<m.token<<",\"rva\":"<<m.rva<<",\"impl_flags\":"<<m.impl_flags<<",\"flags\":"<<m.flags<<",\"declaring_type\":\""<<esc(m.type_name)<<"\",\"name\":\""<<esc(m.name)<<"\",\"signature\":\""<<esc(m.signature)<<"\",\"return_type\":\""<<esc(m.return_type)<<"\",\"full_name\":\""<<esc(m.full_name)<<"\",\"calling_convention\":\""<<esc(m.calling_convention)<<"\",\"has_this\":"<<(m.has_this?"true":"false")<<",\"explicit_this\":"<<(m.explicit_this?"true":"false")<<",\"generic_arity\":"<<m.generic_arity<<",\"param_types\":[";for(std::size_t z=0;z<m.param_types.size();++z){if(z)o<<',';o<<"\""<<esc(m.param_types[z])<<"\"";}o<<"],\"param_names\":[";for(std::size_t z=0;z<m.param_names.size();++z){if(z)o<<',';o<<"\""<<esc(m.param_names[z])<<"\"";}o<<"],\"generic_params\":[";for(std::size_t z=0;z<m.generic_params.size();++z){if(z)o<<',';o<<"\""<<esc(m.generic_params[z])<<"\"";}o<<"],\"pinvoke\":"<<(m.pinvoke?"true":"false")<<",\"import_module\":\""<<esc(m.import_module)<<"\",\"import_name\":\""<<esc(m.import_name)<<"\"}";}
    o<<"],\"member_refs\":[";for(std::size_t i=0;i<r.dotnet.member_refs.size();++i){if(i)o<<',';const auto&m=r.dotnet.member_refs[i];o<<"{\"token\":"<<m.token<<",\"parent_token\":"<<m.parent_token<<",\"parent\":\""<<esc(m.parent)<<"\",\"name\":\""<<esc(m.name)<<"\",\"kind\":\""<<esc(m.kind)<<"\",\"signature\":\""<<esc(m.signature)<<"\"}";}
    o<<"],\"properties\":[";for(std::size_t i=0;i<r.dotnet.properties.size();++i){if(i)o<<',';const auto&p=r.dotnet.properties[i];o<<"{\"token\":"<<p.token<<",\"declaring_type\":\""<<esc(p.declaring_type)<<"\",\"name\":\""<<esc(p.name)<<"\",\"type\":\""<<esc(p.type_name)<<"\",\"signature\":\""<<esc(p.signature)<<"\",\"getter\":\""<<esc(p.getter)<<"\",\"setter\":\""<<esc(p.setter)<<"\"}";}
    o<<"],\"events\":[";for(std::size_t i=0;i<r.dotnet.events.size();++i){if(i)o<<',';const auto&e=r.dotnet.events[i];o<<"{\"token\":"<<e.token<<",\"declaring_type\":\""<<esc(e.declaring_type)<<"\",\"name\":\""<<esc(e.name)<<"\",\"event_type\":\""<<esc(e.event_type)<<"\",\"adder\":\""<<esc(e.adder)<<"\",\"remover\":\""<<esc(e.remover)<<"\",\"raiser\":\""<<esc(e.raiser)<<"\"}";}
    o<<"],\"generic_params\":[";for(std::size_t i=0;i<r.dotnet.generic_params.size();++i){if(i)o<<',';const auto&g=r.dotnet.generic_params[i];o<<"{\"token\":"<<g.token<<",\"owner_token\":"<<g.owner_token<<",\"number\":"<<g.number<<",\"flags\":"<<g.flags<<",\"name\":\""<<esc(g.name)<<"\",\"owner\":\""<<esc(g.owner)<<"\",\"constraints\":[";for(std::size_t z=0;z<g.constraints.size();++z){if(z)o<<',';o<<"\""<<esc(g.constraints[z])<<"\"";}o<<"]}";}
    o<<"],\"method_specs\":[";for(std::size_t i=0;i<r.dotnet.method_specs.size();++i){if(i)o<<',';const auto&m=r.dotnet.method_specs[i];o<<"{\"token\":"<<m.token<<",\"method_token\":"<<m.method_token<<",\"method\":\""<<esc(m.method)<<"\",\"signature\":\""<<esc(m.signature)<<"\",\"type_args\":[";for(std::size_t z=0;z<m.type_args.size();++z){if(z)o<<',';o<<"\""<<esc(m.type_args[z])<<"\"";}o<<"]}";}
    o<<"],\"resources\":[";for(std::size_t i=0;i<r.dotnet.resources.size();++i){if(i)o<<',';const auto&x=r.dotnet.resources[i];o<<"{\"token\":"<<x.token<<",\"name\":\""<<esc(x.name)<<"\",\"flags\":"<<x.flags<<",\"implementation_token\":"<<x.implementation_token<<",\"implementation\":\""<<esc(x.implementation)<<"\",\"embedded\":"<<(x.embedded?"true":"false")<<",\"size_known\":"<<(x.size_known?"true":"false")<<",\"data_offset\":"<<x.data_offset<<",\"size\":"<<x.size<<"}";}
    o<<"],\"obfuscation_hints\":[";for(std::size_t i=0;i<r.dotnet.obfuscation_hints.size();++i){if(i)o<<',';o<<"\""<<esc(r.dotnet.obfuscation_hints[i])<<"\"";}o<<"],\"anomalies\":[";for(std::size_t i=0;i<r.dotnet.anomalies.size();++i){if(i)o<<',';o<<"\""<<esc(r.dotnet.anomalies[i])<<"\"";}o<<"],\"extraction\":{\"success\":"<<(r.dotnet_extract.success?"true":"false")<<",\"symbols_csv\":\""<<esc(path_utf8(r.dotnet_extract.symbols_csv))<<"\",\"symbol_count\":"<<r.dotnet_extract.symbol_count<<",\"types_csv\":\""<<esc(path_utf8(r.dotnet_extract.types_csv))<<"\",\"type_count\":"<<r.dotnet_extract.type_count<<",\"members_csv\":\""<<esc(path_utf8(r.dotnet_extract.members_csv))<<"\",\"member_count\":"<<r.dotnet_extract.member_count<<"}},\n";

    }

    o << "  \"wasm\": {\"candidate\":"<<(r.wasm.candidate?"true":"false")<<",\"valid\":"<<(r.wasm.valid?"true":"false")<<",\"state\":\""<<(r.wasm.candidate?(r.wasm.valid?"CONFIRMED":"FAILED"):"ABSENT")<<"\",\"version\":"<<r.wasm.version<<",\"section_count\":"<<r.wasm.section_count<<",\"type_parse_complete\":"<<(r.wasm.type_parse_complete?"true":"false")<<",\"name_parse_complete\":"<<(r.wasm.name_parse_complete?"true":"false")<<",\"data_parse_complete\":"<<(r.wasm.data_parse_complete?"true":"false")<<",\"has_data_count\":"<<(r.wasm.has_data_count?"true":"false")<<",\"data_count\":"<<r.wasm.data_count<<",\"error_offset\":"<<r.wasm.error_offset<<",\"error\":\""<<esc(r.wasm.error)<<"\",\"types\":[";
    for(std::size_t i=0;i<r.wasm.types.size();++i){if(i)o<<',';const auto&t=r.wasm.types[i];o<<"{\"index\":"<<t.index<<",\"signature\":\""<<esc(t.signature)<<"\",\"params\":[";for(std::size_t z=0;z<t.params.size();++z){if(z)o<<',';o<<"\""<<esc(t.params[z])<<"\"";}o<<"],\"results\":[";for(std::size_t z=0;z<t.results.size();++z){if(z)o<<',';o<<"\""<<esc(t.results[z])<<"\"";}o<<"]}";}
    o<<"],\"imports\":[";for(std::size_t i=0;i<r.wasm.imports.size();++i){if(i)o<<',';const auto&x=r.wasm.imports[i];o<<"{\"module\":\""<<esc(x.module)<<"\",\"name\":\""<<esc(x.name)<<"\",\"kind\":\""<<esc(x.kind)<<"\",\"index\":"<<x.index<<",\"type_index\":"<<x.type_index<<"}";}
    o<<"],\"exports\":[";for(std::size_t i=0;i<r.wasm.exports.size();++i){if(i)o<<',';const auto&x=r.wasm.exports[i];o<<"{\"name\":\""<<esc(x.name)<<"\",\"kind\":\""<<esc(x.kind)<<"\",\"index\":"<<x.index<<"}";}
    o<<"],\"functions\":[";for(std::size_t i=0;i<r.wasm.functions.size();++i){if(i)o<<',';const auto&f=r.wasm.functions[i];o<<"{\"index\":"<<f.index<<",\"type_index\":"<<f.type_index<<",\"imported\":"<<(f.imported?"true":"false")<<",\"user_like\":"<<(f.user_like?"true":"false")<<",\"name\":\""<<esc(f.name)<<"\",\"signature\":\""<<esc(f.signature)<<"\",\"import_module\":\""<<esc(f.import_module)<<"\",\"import_name\":\""<<esc(f.import_name)<<"\",\"code_offset\":"<<f.code_offset<<",\"code_size\":"<<f.code_size<<",\"exports\":[";for(std::size_t z=0;z<f.exports.size();++z){if(z)o<<',';o<<"\""<<esc(f.exports[z])<<"\"";}o<<"]}";}
    o<<"],\"custom_sections\":[";for(std::size_t i=0;i<r.wasm.custom_sections.size();++i){if(i)o<<',';const auto&x=r.wasm.custom_sections[i];o<<"{\"name\":\""<<esc(x.name)<<"\",\"offset\":"<<x.offset<<",\"size\":"<<x.size<<"}";}
    o<<"],\"data_segments\":[";for(std::size_t i=0;i<r.wasm.data_segments.size();++i){if(i)o<<',';const auto&x=r.wasm.data_segments[i];o<<"{\"index\":"<<x.index<<",\"memory_index\":"<<x.memory_index<<",\"passive\":"<<(x.passive?"true":"false")<<",\"offset_known\":"<<(x.offset_known?"true":"false")<<",\"offset\":"<<x.offset<<",\"data_offset\":"<<x.data_offset<<",\"size\":"<<x.size<<"}";}
    o<<"],\"string_hints\":[";for(std::size_t i=0;i<r.wasm.string_hints.size();++i){if(i)o<<',';o<<"\""<<esc(r.wasm.string_hints[i])<<"\"";}o<<"],\"dwarf_sections\":[";for(std::size_t i=0;i<r.wasm.dwarf_sections.size();++i){if(i)o<<',';o<<"\""<<esc(r.wasm.dwarf_sections[i])<<"\"";}o<<"],\"anomalies\":[";for(std::size_t i=0;i<r.wasm.anomalies.size();++i){if(i)o<<',';o<<"\""<<esc(r.wasm.anomalies[i])<<"\"";}o<<"],\"extraction\":{\"success\":"<<(r.wasm_extract.success?"true":"false")<<",\"functions_csv\":\""<<esc(path_utf8(r.wasm_extract.functions_csv))<<"\",\"function_count\":"<<r.wasm_extract.function_count<<",\"strings_txt\":\""<<esc(path_utf8(r.wasm_extract.strings_txt))<<"\",\"string_count\":"<<r.wasm_extract.string_count<<"}},\n";

    {
        const auto state=!r.hermes.candidate?"ABSENT":(!r.hermes.supported_epoch?"PARTIAL":((!r.hermes.valid&&!r.hermes.budget_limited)?"FAILED":(r.hermes.parse_complete?"CONFIRMED":"PARTIAL")));
        const std::size_t function_cap=automatic_child_summary?256:r.hermes.functions.size();
        const std::size_t string_cap=automatic_child_summary?512:r.hermes.strings.size();
        o<<"  \"hermes\": {\"candidate\":"<<(r.hermes.candidate?"true":"false")<<",\"supported_epoch\":"<<(r.hermes.supported_epoch?"true":"false")
         <<",\"valid\":"<<(r.hermes.valid?"true":"false")<<",\"parse_complete\":"<<(r.hermes.parse_complete?"true":"false")<<",\"state\":\""<<state
         <<"\",\"version\":"<<r.hermes.version<<",\"epoch\":\""<<esc(r.hermes.epoch)<<"\",\"file_size\":"<<r.hermes.file_size
         <<",\"declared_file_length\":"<<r.hermes.declared_file_length<<",\"source_hash\":\""<<esc(r.hermes.source_hash)<<"\",\"file_hash\":\""<<esc(r.hermes.file_hash)
         <<"\",\"footer_hash_checked\":"<<(r.hermes.footer_hash_checked?"true":"false")<<",\"footer_hash_matches\":"<<(r.hermes.footer_hash_matches?"true":"false")
         <<",\"budget_limited\":"<<(r.hermes.budget_limited?"true":"false")<<",\"function_count\":"<<r.hermes.function_count<<",\"string_kind_count\":"<<r.hermes.string_kind_count
         <<",\"identifier_count\":"<<r.hermes.identifier_count<<",\"string_count\":"<<r.hermes.string_count<<",\"overflow_string_count\":"<<r.hermes.overflow_string_count
         <<",\"string_storage_size\":"<<r.hermes.string_storage_size<<",\"bigint_count\":"<<r.hermes.bigint_count<<",\"regexp_count\":"<<r.hermes.regexp_count
         <<",\"cjs_module_count\":"<<r.hermes.cjs_module_count<<",\"function_source_count\":"<<r.hermes.function_source_count<<",\"deduplicated_function_bodies\":"<<r.hermes.deduplicated_function_bodies
         <<",\"function_table_offset\":"<<r.hermes.function_table_offset<<",\"string_kind_table_offset\":"<<r.hermes.string_kind_table_offset<<",\"identifier_hash_table_offset\":"<<r.hermes.identifier_hash_table_offset
         <<",\"string_table_offset\":"<<r.hermes.string_table_offset<<",\"overflow_string_table_offset\":"<<r.hermes.overflow_string_table_offset<<",\"string_storage_offset\":"<<r.hermes.string_storage_offset
         <<",\"function_bytecode_begin\":"<<r.hermes.function_bytecode_begin<<",\"function_bytecode_end\":"<<r.hermes.function_bytecode_end<<",\"error_offset\":"<<r.hermes.error_offset<<",\"error\":\""<<esc(r.hermes.error)
         <<"\",\"debug\":{\"present\":"<<(r.hermes.debug.present?"true":"false")<<",\"valid\":"<<(r.hermes.debug.valid?"true":"false")<<",\"offset\":"<<r.hermes.debug.offset
         <<",\"filename_count\":"<<r.hermes.debug.filename_count<<",\"filename_storage_size\":"<<r.hermes.debug.filename_storage_size<<",\"file_region_count\":"<<r.hermes.debug.file_region_count
         <<",\"debug_data_size\":"<<r.hermes.debug.debug_data_size<<",\"lexical_data_offset\":"<<r.hermes.debug.lexical_data_offset<<",\"scope_desc_data_offset\":"<<r.hermes.debug.scope_desc_data_offset
         <<",\"textified_callee_offset\":"<<r.hermes.debug.textified_callee_offset<<",\"string_table_offset\":"<<r.hermes.debug.string_table_offset<<",\"end_offset\":"<<r.hermes.debug.end_offset<<"},\"functions\":[";
        for(std::size_t i=0;i<r.hermes.functions.size()&&i<function_cap;++i){if(i)o<<',';const auto&f=r.hermes.functions[i];o<<"{\"index\":"<<f.index<<",\"header_offset\":"<<f.header_offset<<",\"bytecode_offset\":"<<f.bytecode_offset<<",\"bytecode_size\":"<<f.bytecode_size<<",\"info_offset\":"<<f.info_offset<<",\"function_name_id\":"<<f.function_name_id<<",\"function_name\":\""<<esc(f.function_name)<<"\",\"param_count\":"<<f.param_count<<",\"frame_size\":"<<f.frame_size<<",\"environment_size\":"<<f.environment_size<<",\"instruction_count\":"<<f.instruction_count<<",\"overflow_header\":"<<(f.overflow_header?"true":"false")<<",\"strict_mode\":"<<(f.strict_mode?"true":"false")<<",\"has_exception_handler\":"<<(f.has_exception_handler?"true":"false")<<",\"has_debug_info\":"<<(f.has_debug_info?"true":"false")<<",\"opcodes\":[";for(std::size_t z=0;z<f.opcodes.size();++z){if(z)o<<',';const auto&x=f.opcodes[z];o<<"{\"opcode\":"<<x.opcode<<",\"name\":\""<<esc(x.name)<<"\",\"count\":"<<x.count<<"}";}o<<"]}";}
        o<<"],\"functions_total\":"<<r.hermes.functions.size()<<",\"functions_rendered\":"<<std::min(function_cap,r.hermes.functions.size())<<",\"functions_omitted\":"<<(r.hermes.functions.size()-std::min(function_cap,r.hermes.functions.size()))<<",\"functions_truncated\":"<<(r.hermes.functions.size()>function_cap?"true":"false")<<",\"strings\":[";
        for(std::size_t i=0;i<r.hermes.strings.size()&&i<string_cap;++i){if(i)o<<',';const auto&s=r.hermes.strings[i];o<<"{\"index\":"<<s.index<<",\"storage_offset\":"<<s.storage_offset<<",\"length\":"<<s.length<<",\"utf16\":"<<(s.utf16?"true":"false")<<",\"identifier\":"<<(s.identifier?"true":"false")<<",\"value\":\""<<esc(s.value)<<"\"}";}
        o<<"],\"strings_total\":"<<r.hermes.strings.size()<<",\"strings_rendered\":"<<std::min(string_cap,r.hermes.strings.size())<<",\"strings_omitted\":"<<(r.hermes.strings.size()-std::min(string_cap,r.hermes.strings.size()))<<",\"strings_truncated\":"<<(r.hermes.strings.size()>string_cap?"true":"false")<<",\"opcodes\":[";
        for(std::size_t i=0;i<r.hermes.opcodes.size();++i){if(i)o<<',';const auto&x=r.hermes.opcodes[i];o<<"{\"opcode\":"<<x.opcode<<",\"name\":\""<<esc(x.name)<<"\",\"count\":"<<x.count<<"}";}
        o<<"],\"anomalies\":[";for(std::size_t i=0;i<r.hermes.anomalies.size();++i){if(i)o<<',';o<<"\""<<esc(r.hermes.anomalies[i])<<"\"";}o<<"],\"extraction\":{\"success\":"<<(r.hermes_extract.success?"true":"false")<<",\"functions_csv\":\""<<esc(path_utf8(r.hermes_extract.functions_csv))<<"\",\"strings_csv\":\""<<esc(path_utf8(r.hermes_extract.strings_csv))<<"\",\"opcodes_csv\":\""<<esc(path_utf8(r.hermes_extract.opcodes_csv))<<"\"}},\n";
    }

    {
        const auto facts=implicit_render_fact_positions(r.implicit_exec);
        o<<"  \"implicit_execution\": {\"state\":\""<<esc(r.implicit_exec.state)<<"\",\"error\":\""<<esc(r.implicit_exec.error)<<"\""
         <<",\"analysis_limited\":"<<(r.implicit_exec.analysis_limited?"true":"false")<<",\"fact_count\":"<<r.implicit_exec.facts.size()
         <<",\"informational_count\":"<<r.implicit_exec.informational_count<<",\"review_count\":"<<r.implicit_exec.review_count
         <<",\"high_priority_count\":"<<r.implicit_exec.high_priority_count<<",\"anomaly_count\":"<<r.implicit_exec.anomaly_count
         <<",\"unresolved_runtime_semantics\":"<<r.implicit_exec.unresolved_runtime_semantics<<",\"deterministic_effect_count\":"<<r.implicit_exec.deterministic_effect_count
         <<",\"raw_loader_symbol_count\":"<<r.implicit_exec.raw_loader_symbol_count<<",\"facts_rendered\":"<<facts.size()
         <<",\"facts_truncated\":"<<(r.implicit_exec.facts.size()>facts.size()?"true":"false")<<",\"facts\":[";
        for(std::size_t i=0;i<facts.size();++i){if(i)o<<',';const auto pos=facts[i];render_implicit_fact_json(o,r.implicit_exec.facts[pos],r.implicit_exec.fact_index(pos),r.implicit_exec.fact_dependency(pos));}
        o<<"],\"extraction\":{\"success\":"<<(r.implicit_exec_extract.success?"true":"false")<<",\"csv\":\""<<esc(path_utf8(r.implicit_exec_extract.csv))
         <<"\",\"fact_count\":"<<r.implicit_exec_extract.fact_count<<",\"error\":\""<<esc(r.implicit_exec_extract.error)<<"\"}},\n";
    }
    o << "  \"scan\": {\"ascii_strings\":" << r.static_scan.ascii_strings << ",\"utf16_strings\":" << r.static_scan.utf16_strings << ",\"high_entropy\":[";
    for (std::size_t i=0;i<r.static_scan.high_entropy.size();++i){const auto& x=r.static_scan.high_entropy[i];if(i)o<<',';o<<"{\"offset\":"<<x.offset<<",\"size\":"<<x.size<<",\"entropy\":"<<std::fixed<<std::setprecision(4)<<x.entropy<<'}';}
    o << "],\"embedded\":[";
    for(std::size_t i=0;i<r.static_scan.embedded.size();++i){const auto&e=r.static_scan.embedded[i];if(i)o<<',';o<<"{\"kind\":\""<<esc(e.kind)<<"\",\"offset\":"<<e.offset<<",\"size\":"<<e.size<<",\"validated\":"<<(e.validated?"true":"false")<<",\"state\":\""<<esc(e.state)<<"\",\"confidence\":";if(e.confidence)o<<*e.confidence;else o<<"null";o<<'}';}
    o << "]},\n";
    {
        const auto&g=r.analysis_guidance;
        o<<"  \"analysis_guidance\": {\"visible_hypothesis\":\""<<esc(g.visible_hypothesis)<<"\",\"declared_entry_default\":"<<(g.declared_entry_default?"true":"false")
         <<",\"decoy_risk\":\""<<esc(g.decoy_risk)<<"\",\"runtime_pre_entry_count\":"<<g.runtime_pre_entry_count<<",\"runtime_first_exec_count\":"<<g.runtime_first_exec_count
         <<",\"high_implicit_count\":"<<g.high_implicit_count<<",\"frozen_reference_diff_count\":"<<g.frozen_reference_diff_count
         <<",\"runtime_modality\":{\"policy\":\""<<esc(g.runtime_modality.policy)<<"\",\"static_evidence_only\":"<<(g.runtime_modality.static_evidence_only?"true":"false")<<",\"runtime_execution_authorized\":"<<(g.runtime_modality.runtime_execution_authorized?"true":"false")<<",\"priority_guidance\":[";
        for(std::size_t i=0;i<g.runtime_modality.priority_guidance.size();++i){if(i)o<<',';o<<"\""<<esc(g.runtime_modality.priority_guidance[i])<<"\"";}
        o<<"],\"requirements\":[";for(std::size_t i=0;i<g.runtime_modality.requirements.size();++i){if(i)o<<',';const auto&x=g.runtime_modality.requirements[i];o<<"{\"modality\":\""<<esc(x.modality)<<"\",\"state\":\""<<esc(x.state)<<"\",\"confidence\":"<<x.confidence<<",\"evidence_gate\":\""<<esc(x.evidence_gate)<<"\",\"reason\":\""<<esc(x.reason)<<"\",\"evidence\":[";for(std::size_t j=0;j<x.evidence.size();++j){if(j)o<<',';o<<"\""<<esc(x.evidence[j])<<"\"";}o<<"],\"negative_evidence\":[";for(std::size_t j=0;j<x.negative_evidence.size();++j){if(j)o<<',';o<<"\""<<esc(x.negative_evidence[j])<<"\"";}o<<"],\"artifacts\":[";for(std::size_t j=0;j<x.artifacts.size();++j){if(j)o<<',';o<<"\""<<esc(path_utf8(x.artifacts[j]))<<"\"";}o<<"]}";}o<<"]},\"contradictory_evidence\":[";
        for(std::size_t i=0;i<g.contradictory_evidence.size();++i){if(i)o<<',';o<<"\""<<esc(g.contradictory_evidence[i])<<"\"";}
        o<<"],\"alternate_execution_paths\":[";for(std::size_t i=0;i<g.alternate_execution_paths.size();++i){if(i)o<<',';o<<"\""<<esc(g.alternate_execution_paths[i])<<"\"";}
        o<<"],\"unresolved_alternatives\":[";for(std::size_t i=0;i<g.unresolved_alternatives.size();++i){if(i)o<<',';o<<"\""<<esc(g.unresolved_alternatives[i])<<"\"";}
        o<<"],\"priority_reasons\":[";for(std::size_t i=0;i<g.priority_reasons.size();++i){if(i)o<<',';o<<"\""<<esc(g.priority_reasons[i])<<"\"";}
        o<<"]},\n";
    }
    o << "  \"findings\": [";
    for(std::size_t i=0;i<r.findings.size();++i){const auto&f=r.findings[i];if(i)o<<',';o<<"{\"kind\":\""<<esc(f.kind)<<"\",\"family\":\""<<esc(f.family)<<"\",\"variant\":\""<<esc(f.variant)<<"\",\"state\":\""<<esc(f.state)<<"\",\"confidence\":";if(f.confidence)o<<*f.confidence;else o<<"null";o<<",\"evidence\":[";for(std::size_t j=0;j<f.evidence.size();++j){if(j)o<<',';o<<"\""<<esc(f.evidence[j])<<"\"";}o<<"],\"negative_evidence\":[";for(std::size_t j=0;j<f.negative_evidence.size();++j){if(j)o<<',';o<<"\""<<esc(f.negative_evidence[j])<<"\"";}o<<"],\"fields\":{";bool first=true;for(const auto&kv:f.fields){if(!first)o<<',';first=false;o<<"\""<<esc(kv.first)<<"\":\""<<esc(kv.second)<<"\"";}o<<"},\"ranges\":[";for(std::size_t j=0;j<f.ranges.size();++j){if(j)o<<',';render_range_json(o,r,f.ranges[j]);}o<<"],\"suggested_actions\":[";for(std::size_t j=0;j<f.suggested_actions.size();++j){if(j)o<<',';o<<"\""<<esc(f.suggested_actions[j])<<"\"";}o<<"]}";}
    o << "],\n";

    {
        const auto&p=r.runtime_plan;
        o << "  \"orchestration\": {\"runtime_plan\":{\"requested\":"<<(p.requested?"true":"false")
          <<",\"apply_requested\":"<<(p.apply_requested?"true":"false")<<",\"runtime_eligible\":"<<(p.runtime_eligible?"true":"false")
          <<",\"runtime_eligibility_reason\":\""<<esc(p.runtime_eligibility_reason)<<"\",\"policy\":\""<<esc(p.policy)<<"\",\"timeout_ms\":"<<p.timeout_ms<<",\"steps\":[";
        for(std::size_t i=0;i<p.steps.size();++i){if(i)o<<',';const auto&x=p.steps[i];o<<"{\"analyzer\":\""<<esc(x.analyzer)<<"\",\"selected\":"<<(x.selected?"true":"false")<<",\"reason\":\""<<esc(x.reason)<<"\",\"evidence\":[";for(std::size_t j=0;j<x.evidence.size();++j){if(j)o<<',';o<<"\""<<esc(x.evidence[j])<<"\"";}o<<"],\"timeout_ms\":"<<x.timeout_ms<<",\"budget_ms\":"<<x.budget_ms<<",\"destructive\":"<<(x.destructive?"true":"false")<<",\"state\":\""<<esc(x.state)<<"\",\"result\":\""<<esc(x.result)<<"\",\"refusal\":\""<<esc(x.refusal)<<"\",\"elapsed_ms\":"<<x.elapsed_ms<<'}';}
        o<<"]}},\n";
    }

    o << "  \"runtime\": {"
      << "\"requested\": " << (r.runtime.requested ? "true" : "false")
      << ", \"launched\": " << (r.runtime.launched ? "true" : "false")
      << ", \"timed_out\": " << (r.runtime.timed_out ? "true" : "false")
      << ", \"console_expected\": " << (r.runtime.console_expected ? "true" : "false")
      << ", \"target_file_after_run\": \"" << changed(r.runtime) << "\""
      << ", \"target_write_time_changed\": " << (timestamp_changed(r.runtime) ? "true" : "false")
      << ", \"before\": {\"exists\":" << (r.runtime.before.exists?"true":"false") << ",\"size\":" << r.runtime.before.size << ",\"sha256\":\"" << esc(r.runtime.before.sha256) << "\"}"
      << ", \"after\": {\"exists\":" << (r.runtime.after.exists?"true":"false") << ",\"size\":" << r.runtime.after.size << ",\"sha256\":\"" << esc(r.runtime.after.sha256) << "\"}"
      << ", \"exit_code\": ";
    if (r.runtime.exit_code) o << *r.runtime.exit_code; else o << "null";
    o << ", \"stdout\": \"" << esc(r.runtime.stdout_text) << "\""
      << ", \"stderr\": \"" << esc(r.runtime.stderr_text) << "\""
      << ", \"timeline\": [";
    for (std::size_t i = 0; i < r.runtime.timeline.size(); ++i) {
        const auto& e = r.runtime.timeline[i];
        if (i) o << ',';
        o << "{\"seq\":" << e.seq
          << ",\"t_us\":" << e.t_us
          << ",\"process_uid\":" << e.process_uid
          << ",\"parent_uid\":" << e.parent_uid
          << ",\"pid\":" << e.pid
          << ",\"ppid\":" << e.ppid
          << ",\"kind\":\"" << timeline_kind_name(e.kind) << "\""
          << ",\"process\":\"" << esc(e.process_image) << "\""
          << ",\"subject\":\"" << esc(e.subject) << "\",\"fields\":{";bool first=true;for(const auto&kv:e.fields){if(!first)o<<',';first=false;o<<"\""<<esc(kv.first)<<"\":\""<<esc(kv.second)<<"\"";}o<<"}}";
    }
    o << "],\"artifacts\":[";
    for (std::size_t i=0;i<r.runtime.artifacts.size();++i) {
        const auto &a=r.runtime.artifacts[i]; if(i)o<<',';
        o << "{\"kind\":\""<<esc(a.kind)<<"\",\"state\":\""<<esc(a.state)
          <<"\",\"path\":\""<<esc(path_utf8(a.path))<<"\",\"process_uid\":"<<a.process_uid
          <<",\"pid\":"<<a.pid<<",\"oep_va\":"<<a.oep_va<<",\"detail\":\""<<esc(a.detail)<<"\",\"fields\":{";
        bool afirst=true;for(const auto&kv:a.fields){if(!afirst)o<<',';afirst=false;o<<"\""<<esc(kv.first)<<"\":\""<<esc(kv.second)<<"\"";}
        o<<"},\"priority_ranges\":[";for(std::size_t j=0;j<a.priority_ranges.size();++j){if(j)o<<',';render_range_json(o,r,a.priority_ranges[j],&a);}o<<"]}";
    }
    o << "]},\n";

    o << "  \"replacement\": {"
      << "\"performed\": " << (r.replacement.performed ? "true" : "false")
      << ", \"target\": \"" << esc(path_utf8(r.replacement.target)) << "\""
      << ", \"backup\": \"" << esc(path_utf8(r.replacement.backup)) << "\""
      << ", \"unpacked_source\": \"" << esc(path_utf8(r.replacement.unpacked_source)) << "\""
      << ", \"original_sha256\": \"" << esc(r.replacement.original_sha256) << "\""
      << ", \"new_sha256\": \"" << esc(r.replacement.new_sha256) << "\""
      << ", \"validation\": \"" << esc(r.replacement.validation) << "\"}\n"
      << "}";
}

bool automatic_child_json_uses_summary(const AnalysisReport&r){for(const auto&x:child_json_plane_limits(r))if(x.total>x.rendered())return true;return false;}

void render_json(std::ostream&o,const AnalysisReport&r){render_json_impl(o,r,false);}

void render_automatic_child_json(std::ostream&o,const AnalysisReport&r){render_json_impl(o,r,automatic_child_json_uses_summary(r));}

std::string render_json(const AnalysisReport& r) {
    std::ostringstream o;
    render_json(o,r);
    o << '\n';
    return o.str();
}

} // namespace prts
