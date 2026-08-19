#include "prts/orchestration.hpp"
#include "prts/path_utf8.hpp"
#include "prts/report.hpp"
#include "prts/relationship_evidence.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <functional>
#include <limits>
#include <set>
#include <sstream>
#include <system_error>
#ifdef _WIN32
#include <windows.h>
#endif

namespace prts {
namespace {

std::string directory_json_escape(std::string_view v){
    static const char hex[]="0123456789abcdef";std::string o;o.reserve(v.size()+16);
    for(unsigned char c:v){switch(c){case '"':o+="\\\"";break;case '\\':o+="\\\\";break;case '\b':o+="\\b";break;case '\f':o+="\\f";break;case '\n':o+="\\n";break;case '\r':o+="\\r";break;case '\t':o+="\\t";break;default:if(c<0x20){o+="\\u00";o.push_back(hex[c>>4]);o.push_back(hex[c&15]);}else o.push_back(static_cast<char>(c));}}
    return o;
}
RuntimePlanStep make_step(std::string analyzer,bool selected,std::string reason,std::uint32_t timeout,bool destructive=false) {
    RuntimePlanStep s;
    s.analyzer=std::move(analyzer);
    s.selected=selected;
    s.reason=std::move(reason);
    s.timeout_ms=selected?timeout:0;
    s.budget_ms=s.timeout_ms;
    s.destructive=destructive;
    s.state=selected?"PLANNED":"SKIPPED";
    return s;
}

bool file_has_execute_permission(const std::filesystem::path& p){
    std::error_code ec;auto perms=std::filesystem::status(p,ec).permissions();if(ec)return false;using P=std::filesystem::perms;return (perms&(P::owner_exec|P::group_exec|P::others_exec))!=P::none;
}

bool platform_runtime_eligible(const AnalysisReport& report,std::string& reason) {
#ifdef _WIN32
    if(report.pe.valid&&!report.pe.dll){reason="validated PE executable supported by the Windows runtime backend";return true;}
    reason=report.pe.valid&&report.pe.dll?"validated PE DLL is a loadable sidecar, not a direct runtime root":"no validated direct PE executable for this runtime backend";
#elif defined(__linux__)
    const bool exec_mode=file_has_execute_permission(report.input);
    const bool direct=report.elf.valid&&(report.elf.type==2||(report.elf.type==3&&(!report.elf.interpreter.empty()||(report.elf.entry!=0&&exec_mode))));
    if(direct){reason=report.elf.type==3&&report.elf.interpreter.empty()?"validated executable ET_DYN has a nonzero entry and executable file mode (static/packed PIE root)":"validated ELF executable supported by the Linux runtime backend";return true;}
    reason=report.elf.valid?"validated ELF lacks direct execution evidence (ET_EXEC or executable ET_DYN entry/interpreter root)":"no validated direct ELF executable for this runtime backend";
#else
    (void)report;
    reason="runtime execution backend is unavailable on this platform";
#endif
    return false;
}

#ifdef _WIN32
const CPythonInfo* auto_probe_candidate(const AnalysisReport& report,std::string& reason) {
    for(const auto& cp:report.cpython_runtimes){
        if(!cp.valid)continue;
        const bool embedded=cp.source.rfind("CArchive:",0)==0;
        if(cp.semantic_reference_status=="REFERENCE_MATCH"||cp.reference_status=="REFERENCE_MATCH"){
            reason="exact/semantic official CPython reference already matches; runtime compiler probe has no information gain";
            continue;
        }
        if(cp.semantic_reference_status=="BUILD_INCOMPARABLE"){
            reason=embedded?"validated PyInstaller embedded CPython is BUILD_INCOMPARABLE; compiler probe can resolve currently incomparable opcode/compiler semantics":"validated CPython runtime is BUILD_INCOMPARABLE; compiler probe can resolve currently incomparable compiler/opcode semantics";
            return &cp;
        }
        if(cp.dispatch.reference_status=="BUILD_INCOMPARABLE"){
            reason=embedded?"validated PyInstaller embedded CPython dispatch semantics are BUILD_INCOMPARABLE; compiler probe can provide a runtime normalization reference":"validated CPython runtime dispatch semantics are BUILD_INCOMPARABLE; compiler probe can provide a runtime normalization reference";
            return &cp;
        }
        if(cp.dispatch.attempted&&cp.dispatch.reference_status!="REFERENCE_MATCH"&&cp.dispatch.reference_status!=""){
            reason="native CPython dispatch was recovered but compiler semantics are not an exact reference match; compiler probe can provide independent runtime evidence";
            return &cp;
        }
        reason="validated CPython runtime has no unresolved compiler-semantic question that the runtime probe is known to answer";
    }
    if(reason.empty())reason="no validated CPython runtime requires compiler-semantic disambiguation";
    return nullptr;
}
#endif

void set_tier(DirectoryCandidate& c){
    if(c.priority_score>=100)c.priority_tier="Tier 1";
    else if(c.priority_score>=50)c.priority_tier="Tier 2";
    else c.priority_tier="Tier 3";
}

void add_reason(DirectoryCandidate& c,int score,const std::string& reason){
    c.priority_score+=score;
    if(std::find(c.priority_reasons.begin(),c.priority_reasons.end(),reason)==c.priority_reasons.end())c.priority_reasons.push_back(reason);
    set_tier(c);
}

bool directory_candidate_better(const DirectoryCandidate&a,const DirectoryCandidate&b){
    if(a.priority_score!=b.priority_score)return a.priority_score>b.priority_score;
    return path_utf8(a.path)<path_utf8(b.path);
}

std::uint16_t u16le(const std::vector<unsigned char>& b,std::size_t o){return o+2<=b.size()?std::uint16_t(b[o]|(std::uint16_t(b[o+1])<<8)):0;}
std::uint32_t u32le(const std::vector<unsigned char>& b,std::size_t o){return o+4<=b.size()?std::uint32_t(b[o]|(std::uint32_t(b[o+1])<<8)|(std::uint32_t(b[o+2])<<16)|(std::uint32_t(b[o+3])<<24)):0;}
std::string lower_ext(const std::filesystem::path& p){auto s=path_utf8(p.extension());std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}
std::string path_key(const std::filesystem::path& p){std::error_code ec;auto q=std::filesystem::weakly_canonical(p,ec);if(ec)q=std::filesystem::absolute(p,ec);return path_utf8(ec?p.lexically_normal():q.lexically_normal());}
std::string lower_ascii(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}
bool path_component_ieq(const std::filesystem::path& p,std::string_view expected){return lower_ascii(path_utf8(p.filename()))==lower_ascii(std::string(expected));}
bool path_is_under(const std::filesystem::path& child,const std::filesystem::path& parent){std::error_code ec;auto rel=std::filesystem::relative(child,parent,ec);if(ec||rel.empty())return false;for(const auto&part:rel)if(part=="..")return false;return true;}
bool unity_executable_root(const AnalysisReport& r){if(!r.unity.valid)return false;if(r.pe.valid&&!r.pe.dll)return true;if(r.elf.valid){const bool exec_mode=file_has_execute_permission(r.input);return r.elf.type==2||(r.elf.type==3&&(!r.elf.interpreter.empty()||(r.elf.entry!=0&&exec_mode)));}return false;}
bool exact_mono_runtime_exports(const AnalysisReport& r){std::set<std::string> names;if(r.pe.valid)for(const auto&e:r.pe.exports)if(!e.name.empty())names.insert(e.name);if(r.elf.valid)for(const auto&e:r.elf.dynamic.symbols)if(e.exported&&!e.name.empty())names.insert(e.name);const bool init=names.count("mono_jit_init")||names.count("mono_jit_init_version");return init&&names.count("mono_runtime_invoke")&&names.count("mono_thread_attach")&&names.count("mono_domain_get");}
void refresh_unity_finding(AnalysisReport& r){r.findings.erase(std::remove_if(r.findings.begin(),r.findings.end(),[](const Finding&f){return f.family=="Unity";}),r.findings.end());r.findings.push_back(unity_finding(r.unity));}
void refresh_dotnet_finding(AnalysisReport& r){r.findings.erase(std::remove_if(r.findings.begin(),r.findings.end(),[](const Finding&f){return f.family==".NET metadata"||f.family=="Unity managed/.NET"||f.family=="Unity Mono/.NET";}),r.findings.end());if(r.pe.clr.present||r.dotnet.valid)r.findings.push_back(dotnet_finding(r.dotnet));}

bool directory_link_or_reparse(const std::filesystem::path& p){
    std::error_code ec;auto st=std::filesystem::symlink_status(p,ec);if(!ec&&st.type()==std::filesystem::file_type::symlink)return true;
#ifdef _WIN32
    auto a=GetFileAttributesW(p.c_str());if(a!=INVALID_FILE_ATTRIBUTES&&(a&FILE_ATTRIBUTE_REPARSE_POINT))return true;
#endif
    return false;
}

bool auto_refirst_artifact_directory(const std::filesystem::path& p){
    auto name=path_utf8(p.filename());
    std::transform(name.begin(),name.end(),name.begin(),[](unsigned char c){return char(std::tolower(c));});
    constexpr std::string_view suffix=".auto-refirst";
    return name.size()>=suffix.size()&&name.compare(name.size()-suffix.size(),suffix.size(),suffix)==0;
}

}

RuntimePlan build_runtime_plan(const AnalysisReport& report,const RuntimePlanningRequest& request){
    RuntimePlan plan;
    plan.requested=request.requested;
    plan.apply_requested=request.apply_requested;
    plan.timeout_ms=request.timeout_ms;
    plan.runtime_eligible=platform_runtime_eligible(report,plan.runtime_eligibility_reason);
    if(!request.requested){
        plan.policy="static_only";
        plan.steps.push_back(make_step("generic_runtime_trace",false,"runtime execution was not authorized; static analysis only",request.timeout_ms));
        plan.steps.push_back(make_step("materialization_tracking",false,"runtime execution was not authorized",request.timeout_ms));
        plan.steps.push_back(make_step("unpack_reconstruction",false,"runtime execution was not authorized",request.timeout_ms));
        plan.steps.push_back(make_step("cpython_compiler_probe",false,"runtime execution was not authorized",request.timeout_ms));
        plan.steps.push_back(make_step("post_unpack_static_reanalysis",false,"no runtime reconstruction was requested",request.timeout_ms));
        plan.steps.push_back(make_step("exceptional_runtime_correlation",false,"standalone static evidence plane; no runtime correlation consumer is integrated",request.timeout_ms));
        plan.steps.push_back(make_step("validated_transactional_install",false,"--apply was not requested",request.timeout_ms,true));
        return plan;
    }

    const bool python_only=request.forced_python_probe;
    const bool deep=!request.legacy_trace&&!python_only;
    const bool install=request.apply_requested;
    if(request.legacy_trace)plan.policy="legacy_trace";
    else if(request.legacy_unpack&&request.apply_requested)plan.policy="legacy_unpack_apply";
    else if(request.legacy_unpack)plan.policy="legacy_unpack_non_destructive";
    else if(python_only)plan.policy="legacy_python_probe";
    else if(request.apply_requested)plan.policy="auto_deep_apply";
    else plan.policy="auto_deep_non_destructive";

    const bool generic=!python_only&&plan.runtime_eligible;
    plan.steps.push_back(make_step("generic_runtime_trace",generic,generic?"validated executable is eligible for the platform runtime backend":(python_only?"forced python-probe compatibility mode does not execute the generic runtime tracer":plan.runtime_eligibility_reason),request.timeout_ms));
    auto& trace=plan.steps.back();
    if(generic)trace.evidence.push_back(plan.runtime_eligibility_reason);

    const bool materialize=deep&&plan.runtime_eligible;
    plan.steps.push_back(make_step("materialization_tracking",materialize,materialize?"deep runtime analysis is enabled by --run; track executable materialization and first execution without requiring installation":(request.legacy_trace?"legacy trace compatibility mode intentionally keeps shallow tracing":plan.runtime_eligibility_reason),request.timeout_ms));
    plan.steps.push_back(make_step("unpack_reconstruction",materialize,materialize?"deep runtime analysis may reconstruct and independently validate PE/ELF candidates without modifying the input":(request.legacy_trace?"legacy trace compatibility mode does not request reconstruction":plan.runtime_eligibility_reason),request.timeout_ms));

    std::string probe_reason;
    bool probe_selected=false;
#ifdef _WIN32
    if(python_only){probe_selected=!report.cpython_runtimes.empty();probe_reason=probe_selected?"legacy --run=python-probe explicitly forces the CPython compiler probe":"forced python-probe requested, but static analysis found no CPython runtime to probe";}
    else if(!request.legacy_trace){probe_selected=auto_probe_candidate(report,probe_reason)!=nullptr;}
    else probe_reason="legacy trace compatibility mode does not request the CPython compiler probe";
#else
    if(python_only)probe_reason="legacy python-probe was requested, but this build has no Windows CPython compiler-probe runtime backend";
    else probe_reason="CPython compiler probe runtime is Windows-only on this build";
#endif
    plan.steps.push_back(make_step("cpython_compiler_probe",probe_selected,probe_reason,request.timeout_ms));
    if(probe_selected)plan.steps.back().evidence.push_back("probe is auxiliary; failure does not invalidate the main runtime run");

    plan.steps.push_back(make_step("post_unpack_static_reanalysis",materialize,materialize?"if runtime produces a validated installed image, rerun static/ecosystem analysis against the authoritative bytes":"no deep reconstruction is selected",request.timeout_ms));
    plan.steps.push_back(make_step("exceptional_runtime_correlation",false,"standalone static evidence plane; no runtime correlation consumer is integrated",request.timeout_ms));
    plan.steps.push_back(make_step("validated_transactional_install",install&&materialize,install&&materialize?"--apply explicitly authorizes transactional installation after strict validation":(request.apply_requested?plan.runtime_eligibility_reason:"installation is not authorized; reconstructed/standalone-validated candidates remain separate artifacts"),request.timeout_ms,true));
    return plan;
}

RuntimePlanStep* runtime_plan_step(RuntimePlan& plan,const std::string& analyzer){for(auto& s:plan.steps)if(s.analyzer==analyzer)return &s;return nullptr;}
const RuntimePlanStep* runtime_plan_step(const RuntimePlan& plan,const std::string& analyzer){for(const auto& s:plan.steps)if(s.analyzer==analyzer)return &s;return nullptr;}


DirectoryPlan inventory_directory(const std::filesystem::path& root,std::uint32_t max_depth){
    DirectoryPlan plan;plan.root=root;plan.max_depth=max_depth;std::error_code ec;
    if(directory_link_or_reparse(root)){plan.traversal_skips.push_back({root,"input directory is a symlink/reparse point; following it is disabled by default"});return plan;}
    if(!std::filesystem::is_directory(root,ec)){plan.traversal_skips.push_back({root,ec?"directory status failed: "+ec.message():"input is not a directory"});return plan;}
    std::filesystem::recursive_directory_iterator it(root,std::filesystem::directory_options::skip_permission_denied,ec),end;
    if(ec){plan.traversal_skips.push_back({root,"cannot enumerate directory: "+ec.message()});return plan;}
    while(it!=end){
        const auto path=it->path();const auto depth=static_cast<std::uint32_t>(it.depth());std::error_code sec;auto st=it->symlink_status(sec);
        if(sec){plan.traversal_skips.push_back({path,"symlink/status query failed: "+sec.message()});}
        else if(directory_link_or_reparse(path)){plan.traversal_skips.push_back({path,"file/directory symlink or reparse point skipped"});it.disable_recursion_pending();}
        else if(st.type()==std::filesystem::file_type::directory){
            if(auto_refirst_artifact_directory(path)){plan.traversal_skips.push_back({path,"auto-refirst generated artifact directory skipped from user-input inventory"});it.disable_recursion_pending();}
            else if(depth>=max_depth)it.disable_recursion_pending();
        }else if(st.type()==std::filesystem::file_type::regular){
            ++plan.regular_files_seen;auto candidate=preflight_directory_candidate(path);
            if(plan.candidates.size()<plan.max_candidates)plan.candidates.push_back(std::move(candidate));
            else{
                plan.candidate_admission_budget_exhausted=true;++plan.candidate_omitted_count;
                auto worst=std::max_element(plan.candidates.begin(),plan.candidates.end(),directory_candidate_better);
                if(worst!=plan.candidates.end()&&directory_candidate_better(candidate,*worst))*worst=std::move(candidate);
            }
        }
        auto before=path;it.increment(ec);if(ec){plan.traversal_skips.push_back({before,"directory iteration failed: "+ec.message()});ec.clear();}
    }
    sort_directory_candidates(plan);return plan;
}

DirectoryCandidate preflight_directory_candidate(const std::filesystem::path& path){
    DirectoryCandidate c;c.path=path;c.priority_score=5;c.priority_reasons.push_back("regular files are eligible for bounded priority admission; extension never filters analysis");
    std::error_code ec;c.size=std::filesystem::file_size(path,ec);if(ec){c.readable=false;c.analysis_state="SKIPPED";c.skipped_reason="file size/stat failed: "+ec.message();return c;}
    std::ifstream f(path,std::ios::binary);if(!f){c.readable=false;c.analysis_state="SKIPPED";c.skipped_reason="file cannot be opened for bounded preflight";return c;}
    constexpr std::size_t cap=64*1024;std::vector<unsigned char>b(static_cast<std::size_t>(std::min<std::uint64_t>(c.size,cap)));if(!b.empty())f.read(reinterpret_cast<char*>(b.data()),static_cast<std::streamsize>(b.size()));b.resize(static_cast<std::size_t>(std::max<std::streamsize>(0,f.gcount())));
    auto starts=[&](std::initializer_list<unsigned char>x){return b.size()>=x.size()&&std::equal(x.begin(),x.end(),b.begin());};
    if(b.size()>=64&&b[0]=='M'&&b[1]=='Z'){
        auto peoff=u32le(b,0x3c);if(peoff+24<=b.size()&&b[peoff]=='P'&&b[peoff+1]=='E'&&b[peoff+2]==0&&b[peoff+3]==0){auto ch=u16le(b,peoff+22);bool dll=(ch&0x2000)!=0;c.type_hint=dll?"PE DLL":"PE executable";c.structural_confidence="high";c.role=dll?"shared_library":"executable_root";add_reason(c,dll?60:100,"bounded PE/COFF header validates in preflight");
#ifdef _WIN32
            c.runtime_eligible=!dll;c.runtime_eligibility_reason=dll?"PE DLL is a sidecar/loadable image, not a direct execution root":"PE executable header is directly runnable by the Windows backend";
#else
            c.runtime_eligibility_reason="PE executable is not directly runnable by this platform backend";
#endif
        }else{c.type_hint="MZ/DOS-like";c.structural_confidence="low";add_reason(c,5,"MZ prefix is only a route hint; PE structure did not fit the bounded preflight");}
    }else if(starts({0x7f,'E','L','F'})){
        c.type_hint="ELF";c.structural_confidence="high";std::uint16_t type=0;if(b.size()>=18){if(b[5]==2)type=std::uint16_t((b[16]<<8)|b[17]);else type=u16le(b,16);}bool exec=type==2;bool dyn=type==3;c.role=exec?"executable_root":(dyn?"elf_dynamic_image":"object");add_reason(c,exec?100:(dyn?65:45),"ELF identity and header type validate in bounded preflight");
#ifdef __linux__
        c.runtime_eligible=exec;c.runtime_eligibility_reason=exec?"ET_EXEC is directly runnable by the Linux backend":"ELF requires full analysis before deciding direct runtime eligibility";
#else
        c.runtime_eligibility_reason="ELF is not directly runnable by this platform backend";
#endif
    }else if(starts({0x00,'a','s','m'})){c.type_hint="WebAssembly";c.structural_confidence="high";c.role="bytecode_module";add_reason(c,55,"WebAssembly magic is structurally recognized");}
    else if(b.size()>=8&&b[0]=='d'&&b[1]=='e'&&b[2]=='x'&&b[3]=='\n'){c.type_hint="DEX";c.structural_confidence="high";c.role="bytecode_module";add_reason(c,55,"DEX header magic/version prefix is recognized for full validation");}
    else if(starts({'P','K',0x03,0x04})||starts({'P','K',0x05,0x06})||starts({'P','K',0x07,0x08})){c.type_hint="ZIP/container";c.structural_confidence="medium";c.role="container";add_reason(c,50,"ZIP container signature routes later APK/JAR/container validation");}
    else if(starts({'G','D','P','C'})){c.type_hint="Godot PCK";c.structural_confidence="medium";c.role="container";add_reason(c,50,"Godot PCK magic routes full structural validation");}
    else if(starts({'#','!'})){c.type_hint="script";c.structural_confidence="medium";c.role="script";add_reason(c,30,"shebang identifies a script; it remains static-only by default");}
    else{
        std::size_t printable=0;for(unsigned char x:b)if(x==9||x==10||x==13||(x>=32&&x<127))++printable;if(!b.empty()&&printable*100/b.size()>90){c.type_hint="text";c.role="text";add_reason(c,5,"bounded prefix is predominantly text");}else{c.type_hint="unknown binary";c.role="data";add_reason(c,10,"unknown binary is retained for full static analysis");}
    }
    auto ext=lower_ext(path);if(!ext.empty()&&(ext==".exe"||ext==".dll"||ext==".so"||ext==".pck"||ext==".apk"||ext==".jar"||ext==".dex"||ext==".wasm"))add_reason(c,2,"filename extension is weak ordering evidence only");
    set_tier(c);return c;
}

void refine_directory_candidate(DirectoryCandidate& c,const AnalysisReport& r){
    if(!c.readable)return;
    c.analysis_state="ANALYZED";
    if(r.pe.valid){c.type_hint=r.pe.dll?"PE DLL":"PE executable";c.structural_confidence="validated";c.role=r.pe.dll?"shared_library":"executable_root";
#ifdef _WIN32
        c.runtime_eligible=!r.pe.dll;c.runtime_eligibility_reason=r.pe.dll?"validated PE DLL is not a direct runtime root":"validated PE executable is supported by the Windows runtime backend";
#endif
    }
    if(r.elf.valid){c.type_hint="ELF";c.structural_confidence="validated";const bool exec_mode=file_has_execute_permission(c.path);bool direct=r.elf.type==2||(r.elf.type==3&&(!r.elf.interpreter.empty()||(r.elf.entry!=0&&exec_mode)));c.role=direct?"executable_root":"shared_library";if(direct)add_reason(c,40,"full ELF validation confirms a directly executable root (ET_EXEC, interpreter-backed PIE, or executable nonzero-entry static/packed PIE)");
#ifdef __linux__
        c.runtime_eligible=direct;c.runtime_eligibility_reason=direct?(r.elf.type==3&&r.elf.interpreter.empty()?"validated executable ET_DYN has nonzero entry plus executable file mode":"validated ELF executable/interpreter relationship is supported by the Linux runtime backend"):"validated ELF has no direct executable-root semantics";
#endif
    }
    if(r.pyinstaller.valid){add_reason(c,35,"validated PyInstaller CArchive/embedded-runtime relationship");c.role="executable_root";}
    if(r.python_bytecode.valid){add_reason(c,35,"authenticated direct CPython .pyc with structurally validated root code object");c.role="bytecode_payload";}
    if(r.cpython_marshal_loader.loader_confirmed){add_reason(c,r.cpython_marshal_loader.payload_relation_confirmed?25:10,r.cpython_marshal_loader.payload_relation_confirmed?"explicit marshal.loads path is statically bound to an embedded/transformed payload":"explicit marshal.loads path is present but payload source remains unresolved");if(c.role.empty()||c.role=="unknown")c.role="bytecode_loader";}
    if(r.interpreter_boundary.state=="CONFIRMED"){
        const auto&b=r.interpreter_boundary;
        if(b.host_role=="INTERPRETER_DEFINITION_SOURCE")c.role="interpreter_definition_source";
        else if(b.host_role=="INTERPRETER_HOST")c.role="interpreter_host";
        add_reason(c,20,"confirmed interpreter/program semantic boundary; program semantics, not host entry alone, are the next reverse-analysis surface");
    }
    if(r.unity.metadata_valid){add_reason(c,35,"validated Unity IL2CPP metadata structure");if(path_key(c.path)==path_key(r.unity.metadata_path))c.role="metadata_sidecar";}
    else if(r.unity.il2cpp&&r.unity.il2cpp_export_evidence)add_reason(c,25,"validated native image exposes exact il2cpp_* exports; metadata/native closure remains unconfirmed");
    else if(r.unity.valid)add_reason(c,10,"Unity family evidence is present but backend-specific structure is unresolved in this file");
    if(r.dotnet.valid&&r.dotnet.unity_managed){add_reason(c,40,"validated Unity-managed CLR payload (ECMA-335 plus UnityEngine AssemblyRef)");c.role="managed_payload_candidate";}
    if(r.godot.valid)add_reason(c,30,"validated Godot PCK structure");
    if(r.apk.valid)add_reason(c,25,"validated APK structure");
    if(r.jar.valid)add_reason(c,20,"validated JAR/JVM container structure");
    if(r.dex.valid)add_reason(c,20,"validated DEX structure");
    if(r.wasm.valid)add_reason(c,20,"validated WebAssembly structure");
    if(r.nuitka.valid)add_reason(c,30,"validated Nuitka structure");
    if(r.analysis_guidance.decoy_risk=="HIGH")add_reason(c,25,"analysis guidance reports HIGH decoy/alternate-execution risk");
    else if(r.analysis_guidance.decoy_risk=="REVIEW")add_reason(c,10,"analysis guidance requests review of alternate execution evidence");
    if(r.implicit_exec.high_priority_count)add_reason(c,20+int(std::min<std::uint64_t>(20,r.implicit_exec.high_priority_count)),"high-priority implicit/pre-entry execution evidence is present");
    bool packed=false;for(const auto& f:r.findings)if(f.kind=="packer"&&(f.state=="CONFIRMED"||f.state=="LIKELY")){packed=true;break;}if(packed)add_reason(c,30,"validated/likely packed executable evidence raises reverse-analysis priority");
    set_tier(c);
}

DirectoryReportIndex make_directory_report_index(const AnalysisReport& r){
    DirectoryReportIndex x;x.input=r.input;
    x.pe_valid=r.pe.valid;x.pe_dll=r.pe.dll;
    x.pe_imports.reserve(r.pe.imports.size());for(const auto&m:r.pe.imports)x.pe_imports.push_back({m.name,m.descriptor_rva});
    x.elf_valid=r.elf.valid;x.elf_type=r.elf.type;x.elf_entry=r.elf.entry;x.elf_interpreter=r.elf.interpreter;x.elf_soname=r.elf.abi.soname;x.elf_soname_file_offset=r.elf.abi.soname_file_offset;x.elf_needed=r.elf.needed;
    x.mono_runtime_export_surface=exact_mono_runtime_exports(r);
    x.pyinstaller_valid=r.pyinstaller.valid;x.godot_valid=r.godot.valid;x.apk_valid=r.apk.valid;x.jar_valid=r.jar.valid;x.nuitka_valid=r.nuitka.valid;x.cpython_runtime_present=!r.cpython_runtimes.empty();x.implicit_high_priority_count=r.implicit_exec.high_priority_count;
    x.interpreter_boundary_confirmed=r.interpreter_boundary.state=="CONFIRMED";x.interpreter_external_program_argument=r.interpreter_boundary.external_program_argument_required;x.interpreter_program_buffer_chain=r.interpreter_boundary.program_buffer_chain_confirmed;x.interpreter_exact_program_target_bound=r.interpreter_boundary.exact_program_target_bound;x.interpreter_boundary_kind=r.interpreter_boundary.boundary_kind;x.interpreter_host_role=r.interpreter_boundary.host_role;x.interpreter_target_role=r.interpreter_boundary.target_role;x.interpreter_semantic_requirement=r.interpreter_boundary.semantic_requirement;x.interpreter_runtime_family=r.interpreter_boundary.runtime_family;x.interpreter_exact_program_target_state=r.interpreter_boundary.exact_program_target_state;
    for(const auto&f:r.findings){if(f.state=="FAILED")++x.failure_count;else if(f.state=="PARTIAL")++x.partial_count;}
    x.unity_valid=r.unity.valid;x.unity_player_import=r.unity.unity_player_import;x.unity_metadata_valid=r.unity.metadata_valid;x.unity_il2cpp=r.unity.il2cpp;x.unity_il2cpp_export_evidence=r.unity.il2cpp_export_evidence;x.unity_registration_resolved=r.unity.registration_resolved;x.unity_game_assembly_validated=r.unity.game_assembly_validated;x.unity_mono=r.unity.mono;x.unity_mono_runtime_validated=r.unity.mono_runtime_validated;x.unity_metadata_path=r.unity.metadata_path;x.unity_game_assembly_path=r.unity.game_assembly_path;x.unity_managed_path=r.unity.managed_path;x.unity_mono_runtime_path=r.unity.mono_runtime_path;x.unity_backend_state=r.unity.backend_state;
    x.dotnet_valid=r.dotnet.valid;x.dotnet_unity_managed=r.dotnet.unity_managed;x.dotnet_unity_mono=r.dotnet.unity_mono;
    {std::set<std::string> mods;for(const auto&m:r.dotnet.methods)if(m.pinvoke&&!m.import_module.empty())mods.insert(lower_ascii(m.import_module));x.dotnet_pinvoke_modules.assign(mods.begin(),mods.end());}
    x.relationship_references=extract_relationship_reference_evidence(r);
    std::map<std::string,const ArtifactGraphEdge*> graph_edge;if(r.artifact_graph.enabled)for(const auto&e:r.artifact_graph.edges)graph_edge[path_key(e.child)]=&e;
    for(const auto&a:r.artifacts){
        if(a.path.empty()||a.parent.empty())continue;
        const bool child_report=a.role=="static_child_report";const bool high_value=a.priority=="HIGH"&&a.relation!="analysis_of";if(!child_report&&!high_value&&!a.runtime_confirmed)continue;
        DirectoryArtifactFact f;f.path=a.path;f.parent=a.parent;f.role=a.role;f.relation=a.relation;f.priority=a.priority;f.source=a.source;f.sha256=a.sha256;f.runtime_confirmed=a.runtime_confirmed;
        if(auto it=graph_edge.find(path_key(a.path));it!=graph_edge.end()){f.graph_linked=true;f.graph_depth=it->second->depth;f.graph_state=it->second->state;}x.artifacts.push_back(std::move(f));
    }
    if(r.godot.valid&&!r.godot_extract.output_dir.empty())for(const auto&bundle:r.godot.gdextensions){
        if(!bundle.valid||!bundle.descriptor_child_validated)continue;
        auto desc_rel=bundle.descriptor_path;if(desc_rel.rfind("res://",0)==0)desc_rel.erase(0,6);auto desc=r.godot_extract.output_dir/path_from_utf8(desc_rel);
        for(const auto&lib:bundle.libraries){if(!lib.exact_path_match||!lib.child_validated||lib.matched_child_path.empty())continue;auto lp=lib.matched_child_path;if(lp.rfind("res://",0)==0)lp.erase(0,6);x.godot_library_refs.push_back({desc,r.godot_extract.output_dir/path_from_utf8(lp),bundle.descriptor_path,lib.matched_child_path});}
    }
    return x;
}

bool directory_report_requires_post_relationship_retention(const AnalysisReport& r){
    if(unity_executable_root(r))return true;
    if(r.dotnet.valid&&r.dotnet.unity_managed&&path_component_ieq(r.input,"Assembly-CSharp.dll")&&path_component_ieq(r.input.parent_path(),"Managed"))return true;
    if(r.godot.valid&&r.godot.encrypted_directory)return true; // retained only until the exact external source->PCK oracle is attempted
    return false;
}

void apply_directory_report_index_mutations(AnalysisReport& r,const DirectoryReportIndex& x){
    if(!x.post_relationship_mutated)return;
    if(x.unity_mono){
        r.unity.mono=true;r.unity.mono_runtime_validated=x.unity_mono_runtime_validated;r.unity.managed_path=x.unity_managed_path;r.unity.mono_runtime_path=x.unity_mono_runtime_path;r.unity.backend_state=x.unity_backend_state;if(!r.unity.il2cpp)r.unity.error.clear();refresh_unity_finding(r);
    }
    if(x.dotnet_unity_mono){r.dotnet.unity_mono=true;refresh_dotnet_finding(r);}
}

namespace {
bool index_unity_executable_root(const DirectoryReportIndex&r){if(!r.unity_valid)return false;if(r.pe_valid&&!r.pe_dll)return true;if(r.elf_valid){const bool exec_mode=file_has_execute_permission(r.input);return r.elf_type==2||(r.elf_type==3&&(!r.elf_interpreter.empty()||(r.elf_entry!=0&&exec_mode)));}return false;}
bool index_unity_managed_matches_executable(const std::filesystem::path&executable,const DirectoryReportIndex&managed){if(!managed.dotnet_valid||!managed.dotnet_unity_managed)return false;const auto&p=managed.input;if(!path_component_ieq(p,"Assembly-CSharp.dll")||!path_component_ieq(p.parent_path(),"Managed"))return false;auto data=p.parent_path().parent_path();auto expected=lower_ascii(path_utf8(executable.stem())+"_Data");return lower_ascii(path_utf8(data.filename()))==expected&&path_key(data.parent_path())==path_key(executable.parent_path());}
bool index_exact_mono_runtime_exports(const DirectoryReportIndex&r){return r.mono_runtime_export_surface;}
}

void build_directory_relationships(DirectoryPlan& plan,std::vector<DirectoryReportIndex>& reports){
    plan.relationships.clear();plan.relationship_candidate_lookups=0;plan.relationship_ambiguous_reference_count=0;plan.relationship_omitted_count=0;plan.related_file_omitted_count=0;plan.relationship_budget_exhausted=false;
    for(auto&c:plan.candidates){c.related_files.clear();c.relationship_priority_boost=0;}

    std::map<std::string,std::size_t> index;
    std::map<std::string,DirectoryReportIndex*> report_index;
    std::map<std::string,std::vector<std::size_t>> same_stem,elf_soname,elf_basename,pe_basename,candidate_basename;
    for(std::size_t i=0;i<plan.candidates.size();++i){
        const auto&c=plan.candidates[i];const auto key=path_key(c.path);index[key]=i;
        same_stem[path_key(c.path.parent_path())+"\n"+path_utf8(c.path.stem())].push_back(i);
        candidate_basename[lower_ascii(path_utf8(c.path.filename()))].push_back(i);
    }
    for(auto&r:reports){
        auto ci=index.find(path_key(r.input));if(ci==index.end())continue;report_index[path_key(r.input)]=&r;const auto idx=ci->second;
        if(r.elf_valid){
            if(!r.elf_soname.empty())elf_soname[r.elf_soname].push_back(idx);
            elf_basename[path_utf8(r.input.filename())].push_back(idx);
        }
        if(r.pe_valid&&r.pe_dll)pe_basename[lower_ascii(path_utf8(r.input.filename()))].push_back(idx);
    }

    std::set<std::string> seen;
    auto role_for=[&](const std::filesystem::path&p,std::string fallback){auto it=index.find(path_key(p));return it==index.end()?fallback:plan.candidates[it->second].role;};
    auto add_related_bounded=[&](std::size_t a,const std::filesystem::path&b){
        auto&v=plan.candidates[a].related_files;if(std::find(v.begin(),v.end(),b)!=v.end())return;
        if(v.size()>=plan.max_related_files_per_artifact){++plan.related_file_omitted_count;return;}v.push_back(b);
    };
    auto apply_boost=[&](std::size_t idx,int requested,bool strong,int relationship_cap,const std::string&reason){
        if(requested<=0)return 0;
        int actual=requested;
        if(!strong){
            actual=std::max(0,std::min(requested,relationship_cap-plan.candidates[idx].relationship_priority_boost));
            // R2/R3 relations may elevate a low-value sibling for review, but only
            // an independently strong R4/product-specific proof may create Tier 1.
            if(plan.candidates[idx].priority_score<100)actual=std::min(actual,std::max(0,99-plan.candidates[idx].priority_score));
        }
        if(!actual)return 0;
        plan.candidates[idx].relationship_priority_boost+=actual;add_reason(plan.candidates[idx],actual,reason);return actual;
    };
    auto emit=[&](DirectoryRelationship x,int boost_first=0,int boost_second=0,bool strong_priority=false,int relationship_cap=20){
        if(x.first.empty()||x.second.empty()||path_key(x.first)==path_key(x.second))return false;
        if(!artifact_relationship_state_allows_priority(x.state)){x.priority_eligible=false;boost_first=boost_second=0;}
        if(!x.priority_eligible)boost_first=boost_second=0;
        auto ak=path_key(x.first),bk=path_key(x.second);std::string dk1=ak,dk2=bk;if(!x.directed&&dk2<dk1)std::swap(dk1,dk2);
        auto key=x.kind+"\n"+(x.directed?"D\n":"U\n")+dk1+"\n"+dk2;if(!seen.insert(key).second)return false;
        if(plan.relationships.size()>=plan.max_relationships){plan.relationship_budget_exhausted=true;++plan.relationship_omitted_count;return false;}
        auto ai=index.find(ak),bi=index.find(bk);
        if(ai!=index.end())add_related_bounded(ai->second,x.second);
        if(bi!=index.end())add_related_bounded(bi->second,x.first);
        if(ai!=index.end())x.first_priority_delta=apply_boost(ai->second,boost_first,strong_priority,relationship_cap,x.reason);
        if(bi!=index.end())x.second_priority_delta=apply_boost(bi->second,boost_second,strong_priority,relationship_cap,x.reason);
        plan.relationships.push_back(std::move(x));return true;
    };
    auto make_relation=[&](const std::filesystem::path&a,const std::filesystem::path&b,bool directed,std::string kind,std::string state,std::string arole,std::string brole,std::string basis,std::string source,std::string scoord,std::string tcoord,std::string scope,bool priority,std::string reason){
        DirectoryRelationship x;x.first=a;x.second=b;x.directed=directed;x.kind=std::move(kind);x.state=std::move(state);x.first_role=std::move(arole);x.second_role=std::move(brole);
        if(x.kind=="artifact_materialization"||x.kind=="runtime_recovered_artifact"){x.first_relation_role="producer_parent";x.second_relation_role="produced_child";}
        else if(x.kind=="artifact_analysis_derivative"){x.first_relation_role="analyzed_artifact";x.second_relation_role="analysis_derivative";}
        else if(x.kind=="elf_loader_dependency"||x.kind=="elf_interpreter_dependency"||x.kind=="pe_loader_dependency"||x.kind=="dotnet_pinvoke_dependency"){x.first_relation_role="reference_consumer";x.second_relation_role="reference_target";}
        else if(x.kind=="godot_gdextension_library_reference"){x.first_relation_role="descriptor_reference_source";x.second_relation_role="native_reference_target";}
        else if(x.kind=="unity_mono_managed_payload"){x.first_relation_role="unity_runtime_root";x.second_relation_role="consumed_managed_payload";}
        else if(x.kind=="unity_mono_runtime"){x.first_relation_role="unity_runtime_root";x.second_relation_role="runtime_provider";}
        else if(x.kind=="unity_il2cpp_pair"){x.first_relation_role="validated_pair_member";x.second_relation_role="validated_pair_member";}
        else{x.first_relation_role="route_peer";x.second_relation_role="route_peer";}
        if(x.state=="ROUTE_HINT"){x.evidence_level="R1_ROUTING_HINT";x.semantic_relevance="ROUTING";}
        else if(x.kind=="unity_il2cpp_pair"||x.kind=="unity_mono_managed_payload"||x.kind=="unity_mono_runtime"){x.evidence_level="R4_SEMANTIC_APPLICATION_RELATION";x.semantic_relevance="APPLICATION";}
        else{x.evidence_level="R2_STRUCTURAL_RELATION";x.semantic_relevance="STRUCTURAL";}
        x.evidence_basis=std::move(basis);x.evidence_source=std::move(source);x.source_coordinate=std::move(scoord);x.target_coordinate=std::move(tcoord);x.provenance_scope=std::move(scope);x.priority_eligible=priority;x.reason=std::move(reason);return x;
    };
    auto hx=[](std::uint64_t v){std::ostringstream o;o<<"0x"<<std::hex<<v;return o.str();};

    auto declared_leaf=[](std::string_view v){auto p=v.find_last_of("/\\");return std::string(p==std::string_view::npos?v:v.substr(p+1));};
    auto validated_image=[&](std::size_t i){const auto&c=plan.candidates[i];return c.analysis_state=="ANALYZED"&&c.structural_confidence=="validated"&&(c.role=="executable_root"||c.role=="interpreter_host"||c.role=="shared_library"||c.role=="object");};
    auto emit_ambiguous=[&](const std::filesystem::path&source_path,const std::vector<std::size_t>&matches,std::string kind,std::string source_role,std::string basis,std::string evidence_source,std::string source_coord,std::string level,std::string relevance,std::string reason){
        if(matches.size()<2)return;
        ++plan.relationship_ambiguous_reference_count;
        for(auto dst:matches){auto x=make_relation(source_path,plan.candidates[dst].path,true,kind,"UNRESOLVED",source_role,plan.candidates[dst].role,basis,evidence_source,source_coord,"candidate:"+path_utf8(plan.candidates[dst].path),"multiple admitted targets satisfy the same exact source reference; endpoint selection is withheld",false,reason);x.evidence_level=level;x.semantic_relevance=relevance;x.ambiguity="MULTIPLE_VALIDATED_TARGETS";emit(std::move(x));}
    };

    // Preserve existing Unity IL2CPP closure, now with explicit evidence/provenance semantics.
    for(const auto&r:reports){
        if(!r.unity_metadata_valid||!r.unity_registration_resolved||!r.unity_game_assembly_validated)continue;
        auto mi=index.find(path_key(r.unity_metadata_path)),gi=index.find(path_key(r.unity_game_assembly_path));plan.relationship_candidate_lookups+=2;
        if(mi==index.end()||gi==index.end())continue;
        auto x=make_relation(plan.candidates[mi->second].path,plan.candidates[gi->second].path,false,"unity_il2cpp_pair","CONFIRMED","il2cpp_metadata","native_code","validated Unity metadata structure plus recovered CodeRegistration/codegen-module closure","Unity IL2CPP parser/registration recovery","current_input_file:validated IL2CPP metadata tables","current_input_file:validated GameAssembly registration/codegen modules","directory input; each endpoint retains its own current_input_file coordinate basis",true,"validated IL2CPP metadata and native image close through the recovered CodeRegistration/codegen-module relationship");
        emit(std::move(x),25,25,true);
    }

    // Preserve existing Unity Mono closure and its strong managed-payload priority behavior.
    for(auto&root:reports){
        if(!index_unity_executable_root(root))continue;
        DirectoryReportIndex*managed=nullptr;DirectoryReportIndex*runtime=nullptr;
        for(auto&r:reports)if(&r!=&root&&index_unity_managed_matches_executable(root.input,r)){managed=&r;break;}
        if(!managed)continue;
        for(auto&r:reports){if(&r==&root||&r==managed)continue;if(!path_is_under(r.input,root.input.parent_path()))continue;if(index_exact_mono_runtime_exports(r)){runtime=&r;break;}}
        if(!runtime)continue;
        auto ri=index.find(path_key(root.input)),mi=index.find(path_key(managed->input)),xi=index.find(path_key(runtime->input));plan.relationship_candidate_lookups+=3;if(ri==index.end()||mi==index.end()||xi==index.end())continue;
        root.unity_mono=true;root.unity_mono_runtime_validated=true;root.unity_managed_path=managed->input;root.unity_mono_runtime_path=runtime->input;root.unity_backend_state=root.unity_il2cpp?"HYBRID_OR_AMBIGUOUS":"MONO_CONFIRMED";root.post_relationship_mutated=true;
        managed->dotnet_unity_mono=true;managed->post_relationship_mutated=true;plan.candidates[mi->second].role="managed_payload";plan.candidates[xi->second].role="mono_runtime";
        auto m=make_relation(root.input,managed->input,true,"unity_mono_managed_payload","CONFIRMED","unity_executable","managed_payload","exact executable-stem _Data/Managed layout + ECMA-335 UnityEngine AssemblyRefs + independent Mono runtime export closure","Unity/.NET/PE-or-ELF validated metadata","directory:Unity executable root","current_input_file:validated Assembly-CSharp CLR metadata","same Unity product directory; managed payload coordinate basis is its own file",true,"Unity executable layout closes to a validated Assembly-CSharp CLR payload with UnityEngine AssemblyRefs and an independently validated exact Mono runtime export surface");
        emit(std::move(m),10,55,true);
        auto rt=make_relation(root.input,runtime->input,true,"unity_mono_runtime","CONFIRMED","unity_executable","mono_runtime","independently validated exact Mono runtime export set","PE/ELF export tables","directory:Unity executable root","current_input_file:Mono export surface","same Unity product directory; runtime coordinate basis is its own file",true,"exact Mono runtime exports independently validate the Mono scripting runtime used by this Unity executable/managed-payload relationship");
        emit(std::move(rt),5,10,true);
    }

    // Exact materialization provenance was compacted while the owning report was live.
    for(const auto&r:reports){
        for(const auto&a:r.artifacts){
            std::string scope="producer_report="+path_utf8(r.input);if(a.graph_linked)scope+="; artifact_graph_depth="+std::to_string(a.graph_depth)+"; artifact_graph_state="+a.graph_state;
            std::string basis="persisted regular artifact registered after producer validation; relation="+a.relation;if(!a.sha256.empty())basis+="; sha256="+a.sha256;
            std::string kind=a.relation=="analysis_of"?"artifact_analysis_derivative":(a.relation=="runtime_recovered_image"?"runtime_recovered_artifact":"artifact_materialization");
            std::string reason=a.relation=="analysis_of"?"persisted analysis derivative has an exact parent artifact and file identity":"validated producer materialized this child at an exact path with recorded file identity";
            auto x=make_relation(a.parent,a.path,true,std::move(kind),"CONFIRMED",role_for(a.parent,"producer_artifact"),a.role,basis,a.source,"artifact_path:"+path_utf8(a.parent),"artifact_path:"+path_utf8(a.path)+(a.sha256.empty()?"":";sha256="+a.sha256),scope,false,reason);emit(std::move(x));
        }
        for(const auto&g:r.godot_library_refs){
            auto x=make_relation(g.descriptor,g.target,true,"godot_gdextension_library_reference","CONFIRMED","gdextension_descriptor","native_extension","validated .gdextension descriptor library path exactly matches a validated PCK child","Godot GDExtension descriptor/bundle analysis","PCK entry:"+g.descriptor_entry,"PCK entry:"+g.target_entry,"validated PCK child namespace; extracted files retain independent current_input_file offsets",false,"validated GDExtension descriptor explicitly references this exact validated native child path");emit(std::move(x));
        }
    }

    // AR source-reference closure. Source evidence is extracted without looking at
    // sibling names; endpoint resolution happens here against the complete admitted set.
    // Exact relative paths bind by canonical directory location. Absolute runner deployment
    // paths may bind by their explicitly named basename only when exactly one validated
    // executable image supplies that runtime path component; ambiguity fails closed.
    for(const auto&r:reports){
        auto si=index.find(path_key(r.input));if(si==index.end())continue;const auto src=si->second;
        for(const auto&ref:r.relationship_references){
            std::vector<std::size_t> matches;
            if(ref.resolution_mode=="EXACT_RELATIVE_PATH"){
                auto target=r.input.parent_path()/path_from_utf8(ref.reference);auto it=index.find(path_key(target));++plan.relationship_candidate_lookups;if(it!=index.end()&&it->second!=src)matches.push_back(it->second);
            }else if(ref.resolution_mode=="EXACT_ABSOLUTE_PATH"){
                auto it=index.find(path_key(path_from_utf8(ref.reference)));++plan.relationship_candidate_lookups;if(it!=index.end()&&it->second!=src)matches.push_back(it->second);
            }else if(ref.resolution_mode=="DECLARED_BASENAME_VALIDATED_IMAGE"){
                auto it=candidate_basename.find(lower_ascii(declared_leaf(ref.reference)));if(it!=candidate_basename.end())matches=it->second;matches.erase(std::remove(matches.begin(),matches.end(),src),matches.end());matches.erase(std::remove_if(matches.begin(),matches.end(),[&](auto i){return path_key(plan.candidates[i].path.parent_path())!=path_key(r.input.parent_path());}),matches.end());if(ref.target_must_be_validated_image)matches.erase(std::remove_if(matches.begin(),matches.end(),[&](auto i){return !validated_image(i);}),matches.end());plan.relationship_candidate_lookups+=matches.size();
            }
            std::sort(matches.begin(),matches.end());matches.erase(std::unique(matches.begin(),matches.end()),matches.end());
            if(matches.size()>1){emit_ambiguous(r.input,matches,ref.kind,plan.candidates[src].role,ref.evidence_basis,ref.evidence_source,ref.source_coordinate,ref.evidence_level,ref.semantic_relevance,"exact source reference has multiple admissible targets; automatic relationship priority is refused");continue;}
            if(matches.empty())continue;const auto dst=matches.front();
            std::string target_coord=ref.resolution_mode=="DECLARED_BASENAME_VALIDATED_IMAGE"?"validated_direct_sibling_basename:"+path_utf8(plan.candidates[dst].path.filename())+";declared_runtime_path="+ref.reference:"artifact_path:"+path_utf8(plan.candidates[dst].path);
            std::string scope="static source relationship only; referenced sidecar/stage is not executed and runtime success is not asserted";
            auto x=make_relation(r.input,plan.candidates[dst].path,true,ref.kind,"BOUNDED",plan.candidates[src].role,plan.candidates[dst].role,ref.evidence_basis,ref.evidence_source,ref.source_coordinate,target_coord,scope,true,"structured source evidence closes to exactly one admitted target; prioritize the relationship before incidental secondary findings");
            x.evidence_level=ref.evidence_level;x.semantic_relevance=ref.semantic_relevance;x.first_relation_role=ref.source_relation_role;x.second_relation_role=ref.target_relation_role;x.ambiguity="NONE";
            emit(std::move(x),ref.source_priority_delta,ref.target_priority_delta,false,ref.priority_cap);
        }
    }

    // Structured loader references are exact source facts, but actual loader search and
    // runtime selection are environment-dependent. A unique in-directory validated target
    // is therefore BOUNDED, never runtime-confirmed.
    for(const auto&r:reports){
        auto si=index.find(path_key(r.input));if(si==index.end())continue;const auto src=si->second;
        if(r.elf_valid){
            if(!r.elf_interpreter.empty()){
                const auto interp_name=declared_leaf(r.elf_interpreter);std::vector<std::size_t> matches;bool soname_match=false;
                if(auto it=elf_soname.find(interp_name);it!=elf_soname.end()){matches=it->second;soname_match=true;}else if(auto it=elf_basename.find(interp_name);it!=elf_basename.end())matches=it->second;
                matches.erase(std::remove(matches.begin(),matches.end(),src),matches.end());std::sort(matches.begin(),matches.end());matches.erase(std::unique(matches.begin(),matches.end()),matches.end());plan.relationship_candidate_lookups+=matches.size();
                if(matches.size()>1)emit_ambiguous(r.input,matches,"elf_interpreter_dependency",plan.candidates[src].role,"validated PT_INTERP exact loader path + validated in-directory ELF identity","ELF PT_INTERP + target DT_SONAME/basename","current_input_file:PT_INTERP("+r.elf_interpreter+")","R2_STRUCTURAL_RELATION","STRUCTURAL","PT_INTERP names multiple admissible loader targets; loader choice is unresolved");
                else if(matches.size()==1){const auto dst=matches.front();const auto*tr=report_index.count(path_key(plan.candidates[dst].path))?report_index[path_key(plan.candidates[dst].path)]:nullptr;if(tr&&tr->elf_valid){std::string tc="artifact_basename:"+path_utf8(plan.candidates[dst].path.filename());if(soname_match&&!tr->elf_soname.empty())tc="current_input_file+"+hx(tr->elf_soname_file_offset)+":DT_SONAME("+tr->elf_soname+")";auto x=make_relation(r.input,plan.candidates[dst].path,true,"elf_interpreter_dependency","BOUNDED",plan.candidates[src].role,plan.candidates[dst].role,"validated PT_INTERP exact loader path + one validated in-directory ELF target"+(soname_match?std::string(" with exact DT_SONAME match"):std::string(" with exact artifact basename match")),"ELF PT_INTERP / target ELF identity","current_input_file:PT_INTERP("+r.elf_interpreter+")",tc,"directory candidate set only; host loader path and runtime namespace are not asserted",true,"validated PT_INTERP names exactly one supplied loader identity; supplied loader should be reviewed with this executable");emit(std::move(x),0,10,false);}}
            }
            std::set<std::string> emitted_names;
            for(const auto&needed:r.elf_needed){if(needed.empty()||!emitted_names.insert(needed).second)continue;std::vector<std::size_t> matches;bool soname_match=false;
                if(auto it=elf_soname.find(needed);it!=elf_soname.end()){matches=it->second;soname_match=true;}else if(auto it=elf_basename.find(needed);it!=elf_basename.end())matches=it->second;
                std::sort(matches.begin(),matches.end());matches.erase(std::unique(matches.begin(),matches.end()),matches.end());matches.erase(std::remove(matches.begin(),matches.end(),src),matches.end());plan.relationship_candidate_lookups+=matches.size();
                if(matches.size()>1){emit_ambiguous(r.input,matches,"elf_loader_dependency",plan.candidates[src].role,"validated DT_NEEDED exact module reference has multiple validated in-directory targets","ELF PT_DYNAMIC / dynamic string table","current_input_file:DT_NEEDED("+needed+")","R2_STRUCTURAL_RELATION","STRUCTURAL","DT_NEEDED target set is ambiguous; automatic loader target priority is refused");continue;}if(matches.empty())continue;const auto dst=matches.front();const auto*tr=report_index.count(path_key(plan.candidates[dst].path))?report_index[path_key(plan.candidates[dst].path)]:nullptr;if(!tr||!tr->elf_valid)continue;
                std::string target_coord="artifact_basename:"+path_utf8(plan.candidates[dst].path.filename());if(soname_match&&!tr->elf_soname.empty())target_coord="current_input_file+"+hx(tr->elf_soname_file_offset)+":DT_SONAME("+tr->elf_soname+")";
                auto x=make_relation(r.input,plan.candidates[dst].path,true,"elf_loader_dependency","BOUNDED",plan.candidates[src].role,plan.candidates[dst].role,std::string("validated DT_NEEDED exact module reference + one validated in-directory ELF target")+(soname_match?" with exact DT_SONAME match":" with exact artifact basename match"),"ELF PT_DYNAMIC / dynamic string table","current_input_file:DT_NEEDED("+needed+")",target_coord,"directory candidate set only; runtime loader search/RPATH/namespace is not asserted",true,"validated ELF loader metadata references exactly one in-directory validated target; runtime loader selection remains unobserved");emit(std::move(x),0,8,false);
            }
        }
        if(r.pe_valid){
            std::set<std::string> modules;for(const auto&m:r.pe_imports){auto mod=lower_ascii(m.name);if(mod.empty()||!modules.insert(mod).second)continue;auto it=pe_basename.find(mod);if(it==pe_basename.end())continue;auto matches=it->second;matches.erase(std::remove(matches.begin(),matches.end(),src),matches.end());plan.relationship_candidate_lookups+=matches.size();if(matches.size()>1){emit_ambiguous(r.input,matches,"pe_loader_dependency",plan.candidates[src].role,"validated PE import descriptor exact module reference has multiple validated DLL targets","PE import table","current_input_file:IMPORT_MODULE("+m.name+")","R2_STRUCTURAL_RELATION","STRUCTURAL","PE import target set is ambiguous; automatic loader target priority is refused");continue;}if(matches.empty())continue;const auto dst=matches.front();const auto&desc=*std::find_if(r.pe_imports.begin(),r.pe_imports.end(),[&](const auto&x){return lower_ascii(x.name)==mod;});auto x=make_relation(r.input,plan.candidates[dst].path,true,"pe_loader_dependency","BOUNDED",plan.candidates[src].role,plan.candidates[dst].role,"validated PE import descriptor module name + one validated in-directory PE DLL target","PE import table","current_input_file:RVA="+hx(desc.descriptor_rva)+":IMPORT_MODULE("+desc.name+")","artifact_basename:"+path_utf8(plan.candidates[dst].path.filename()),"directory candidate set only; Windows loader/SxS/search order is not asserted",true,"validated PE import metadata references exactly one in-directory validated DLL target; runtime loader selection remains unobserved");emit(std::move(x),0,8,false);}
            for(const auto&mod:r.dotnet_pinvoke_modules){auto it=pe_basename.find(mod);if(it==pe_basename.end())continue;auto matches=it->second;matches.erase(std::remove(matches.begin(),matches.end(),src),matches.end());plan.relationship_candidate_lookups+=matches.size();if(matches.size()>1){emit_ambiguous(r.input,matches,"dotnet_pinvoke_dependency",plan.candidates[src].role,"validated ECMA-335 P/Invoke module reference has multiple validated DLL targets",".NET ImplMap/PInvoke metadata","current_input_file:ECMA-335 PInvoke("+mod+")","R2_STRUCTURAL_RELATION","STRUCTURAL","P/Invoke target set is ambiguous; automatic native target priority is refused");continue;}if(matches.empty())continue;const auto dst=matches.front();auto x=make_relation(r.input,plan.candidates[dst].path,true,"dotnet_pinvoke_dependency","BOUNDED",plan.candidates[src].role,plan.candidates[dst].role,"validated ECMA-335 P/Invoke module reference + one validated in-directory PE DLL target",".NET ImplMap/PInvoke metadata","current_input_file:ECMA-335 PInvoke("+mod+")","artifact_basename:"+path_utf8(plan.candidates[dst].path.filename()),"directory candidate set only; CLR/native loader resolution is not asserted",true,"validated .NET P/Invoke metadata references exactly one in-directory validated DLL target; runtime loader selection remains unobserved");emit(std::move(x),0,8,false);}
        }
    }

    // AW interpreter/program candidate routing.  The interpreter identity/requirement is
    // proven in the source report, but an unknown runtime argv value (or a generic runtime
    // image selection such as Janet) is not an exact cross-file reference.  Therefore this
    // block can only expose R1 candidates / explicit ambiguity; it never changes priority.
    for(const auto&r:reports){
        if(!r.interpreter_boundary_confirmed||r.interpreter_exact_program_target_bound)continue;
        auto si=index.find(path_key(r.input));if(si==index.end())continue;const auto src=si->second;
        if(r.interpreter_target_role!="BYTECODE_PROGRAM"&&r.interpreter_target_role!="RUNTIME_IMAGE")continue;
        std::vector<std::size_t> candidates;
        for(std::size_t i=0;i<plan.candidates.size();++i){
            if(i==src)continue;
            const auto&c=plan.candidates[i];
            if(path_key(c.path.parent_path())!=path_key(r.input.parent_path()))continue;
            if(c.analysis_state!="ANALYZED"||!c.readable)continue;
            // Only opaque/data siblings are admitted as unresolved program candidates.
            // Executables, libraries, containers, scripts and recognized bytecode formats
            // need independent evidence rather than being swept in by proximity.
            if(c.role!="data")continue;
            candidates.push_back(i);
        }
        plan.relationship_candidate_lookups+=candidates.size();
        const std::string endpoint=r.interpreter_target_role=="RUNTIME_IMAGE"?"runtime_image_candidate":"bytecode_program_candidate";
        const std::string source_coord=r.interpreter_external_program_argument?"current_input_image:confirmed argv[1] -> file-read -> interpreter-dispatch chain":"current_input_image:ecosystem-wide "+r.interpreter_runtime_family+" runtime/interpreter identity";
        const std::string basis=r.interpreter_external_program_argument?"confirmed external-program requirement plus opaque direct-sibling inventory; runtime argv value itself is unknown":"confirmed runtime/interpreter family plus opaque direct-sibling inventory; no load-path binding was recovered";
        if(candidates.size()==1){const auto dst=candidates.front();plan.candidates[dst].role=endpoint;auto x=make_relation(r.input,plan.candidates[dst].path,true,"interpreter_program_candidate","ROUTE_HINT",plan.candidates[src].role,plan.candidates[dst].role,basis,"AW bounded interpreter boundary + directory inventory",source_coord,"candidate:"+path_utf8(plan.candidates[dst].path),"same direct parent only; filename/suffix is not semantic proof and the endpoint is not asserted",false,"one admitted opaque sibling is a routing candidate for the already-confirmed interpreter/program boundary; exact target selection is withheld");x.first_relation_role="interpreter_host";x.second_relation_role=endpoint;x.ambiguity=r.interpreter_external_program_argument?"RUNTIME_ARGUMENT_VALUE_UNRESOLVED":"RUNTIME_IMAGE_SELECTION_UNRESOLVED";emit(std::move(x));}
        else if(candidates.size()>1){
            ++plan.relationship_ambiguous_reference_count;
            for(auto dst:candidates){auto x=make_relation(r.input,plan.candidates[dst].path,true,"interpreter_program_candidate","UNRESOLVED",plan.candidates[src].role,plan.candidates[dst].role,basis,"AW bounded interpreter boundary + directory inventory",source_coord,"candidate:"+path_utf8(plan.candidates[dst].path),"multiple opaque direct siblings are admissible; endpoint selection is withheld",false,"multiple siblings could satisfy the external program/image role; automatic selection is refused");x.evidence_level="R1_ROUTING_HINT";x.semantic_relevance="ROUTING";x.first_relation_role="interpreter_host";x.second_relation_role=endpoint;x.ambiguity="MULTIPLE_PROGRAM_CANDIDATES";emit(std::move(x));}
        }
    }

    // Weak same-stem routing remains available for Godot/ordinary sidecar workflows,
    // but keyed lookup replaces the old executable x every-file pair scan and no weak
    // hint is allowed to change a candidate's score/tier.
    for(std::size_t i=0;i<plan.candidates.size();++i){const auto&c=plan.candidates[i];if(c.role!="executable_root"&&c.role!="interpreter_host")continue;auto it=same_stem.find(path_key(c.path.parent_path())+"\n"+path_utf8(c.path.stem()));if(it==same_stem.end())continue;plan.relationship_candidate_lookups+=it->second.size();for(auto j:it->second){if(i==j)continue;const auto&d=plan.candidates[j];if(d.type_hint=="Godot PCK"){auto x=make_relation(c.path,d.path,false,"executable_pck_sibling","ROUTE_HINT",c.role,d.role,"same stem + recognized/validated PCK are routing evidence only","bounded directory inventory","artifact_basename:"+path_utf8(c.path.filename()),"artifact_basename:"+path_utf8(d.path.filename()),"same parent directory; no consumer/producer semantics inferred",false,"validated/recognized PCK plus structurally executable same-stem sibling; filename relationship is not ecosystem confirmation");emit(std::move(x));}else if(d.role=="shared_library"){auto x=make_relation(c.path,d.path,false,"executable_sidecar","ROUTE_HINT",c.role,d.role,"same stem + validated shared-library identity are routing evidence only","bounded directory inventory","artifact_basename:"+path_utf8(c.path.filename()),"artifact_basename:"+path_utf8(d.path.filename()),"same parent directory; no load/reference semantics inferred",false,"structural executable and same-stem shared-library sibling; name is weak relationship evidence only");emit(std::move(x));}}}
}

void build_directory_relationships(DirectoryPlan& plan,std::vector<AnalysisReport>& reports){
    std::vector<DirectoryReportIndex> compact;compact.reserve(reports.size());for(const auto&r:reports)compact.push_back(make_directory_report_index(r));
    build_directory_relationships(plan,compact);
    std::map<std::string,const DirectoryReportIndex*> by_input;for(const auto&r:compact)by_input[path_key(r.input)]=&r;
    for(auto&r:reports){auto it=by_input.find(path_key(r.input));if(it!=by_input.end())apply_directory_report_index_mutations(r,*it->second);}
}

void sort_directory_candidates(DirectoryPlan& plan){std::sort(plan.candidates.begin(),plan.candidates.end(),directory_candidate_better);}

DirectorySummary summarize_directory(const DirectoryPlan& plan,const std::vector<DirectoryReportIndex>& reports,std::uint64_t elapsed_ms){
    DirectorySummary s;s.total_files=plan.candidates.size();s.discovered_regular_files=plan.regular_files_seen;s.candidate_omitted_count=plan.candidate_omitted_count;s.elapsed_ms=elapsed_ms;s.artifact_relationship_count=plan.relationships.size();
    s.runtime_modality=build_directory_runtime_modality_guidance(plan,reports);
    s.relationship_omitted_count=plan.relationship_omitted_count;
    s.relationship_ambiguous_reference_count=plan.relationship_ambiguous_reference_count;
    s.relationship_budget_exhausted=plan.relationship_budget_exhausted;
    if(plan.candidate_admission_budget_exhausted){s.partial=true;s.partial_reasons.push_back("directory regular-file admission exceeded the 1024-candidate default priority budget; lower-priority files are deferred and counted");}
    if(plan.relationship_budget_exhausted){s.partial=true;s.partial_reasons.push_back("directory relationship construction hit its explicit relationship budget; omitted relations are counted");}
    for(const auto&c:plan.candidates){s.total_bytes+=c.size;++s.type_counts[c.type_hint];if(c.analysis_state=="ANALYZED")++s.analyzed_files;else if(c.analysis_state=="SKIPPED")++s.skipped_files;}
    std::set<std::string> eco;bool unity_seen=false,unity_engine_confirmed=false,il2cpp_confirmed=false,il2cpp_likely=false,mono_confirmed=false;
    for(const auto&r:reports){
        s.high_priority_evidence_count+=r.implicit_high_priority_count;if(r.pyinstaller_valid)eco.insert("PyInstaller");
        if(r.unity_valid){unity_seen=true;if(r.unity_player_import||r.unity_metadata_valid||r.unity_mono)unity_engine_confirmed=true;if(r.unity_metadata_valid)il2cpp_confirmed=true;if(r.unity_il2cpp&&r.unity_il2cpp_export_evidence)il2cpp_likely=true;if(r.unity_mono)mono_confirmed=true;}
        if(r.godot_valid)eco.insert("Godot");
        if(r.apk_valid)eco.insert("Android APK");
        if(r.jar_valid)eco.insert("JAR/JVM");
        if(r.nuitka_valid)eco.insert("Nuitka");
        if(r.cpython_runtime_present)eco.insert("CPython");
        s.failures+=r.failure_count;s.partials+=r.partial_count;
    }
    for(const auto&r:plan.relationships){if(r.kind=="unity_mono_managed_payload"&&r.state=="CONFIRMED")++s.unity_mono_relationship_count;else if(r.kind=="unity_il2cpp_pair"&&r.state=="CONFIRMED")++s.unity_il2cpp_relationship_count;}
    s.unity_engine_state=unity_engine_confirmed?"CONFIRMED":(unity_seen?"CANDIDATE":"ABSENT");
    if(mono_confirmed&&(il2cpp_confirmed||il2cpp_likely))s.unity_backend_state="HYBRID_OR_AMBIGUOUS";else if(mono_confirmed)s.unity_backend_state="MONO_CONFIRMED";else if(il2cpp_confirmed)s.unity_backend_state="IL2CPP_CONFIRMED";else if(il2cpp_likely)s.unity_backend_state="IL2CPP_LIKELY";else if(unity_seen)s.unity_backend_state="BACKEND_UNRESOLVED";
    if(mono_confirmed)eco.insert("Unity/Mono");
    if(il2cpp_confirmed)eco.insert("Unity/IL2CPP");
    if(unity_engine_confirmed&&!mono_confirmed&&!il2cpp_confirmed)eco.insert("Unity (backend unresolved)");
    if(mono_confirmed&&il2cpp_confirmed)eco.insert("Unity hybrid/ambiguous");
    auto managed=std::find_if(plan.candidates.begin(),plan.candidates.end(),[](const auto&c){return c.role=="managed_payload";});auto ilpair=std::find_if(plan.relationships.begin(),plan.relationships.end(),[](const auto&r){return r.kind=="unity_il2cpp_pair"&&r.state=="CONFIRMED";});
    if(s.unity_backend_state=="MONO_CONFIRMED"&&managed!=plan.candidates.end())s.unity_next_priority="Managed/Assembly-CSharp.dll: "+path_utf8(managed->path);
    else if(s.unity_backend_state=="IL2CPP_CONFIRMED"&&ilpair!=plan.relationships.end())s.unity_next_priority="validated GameAssembly/global-metadata pair: "+path_utf8(ilpair->first)+" + "+path_utf8(ilpair->second);
    else if(s.unity_backend_state=="HYBRID_OR_AMBIGUOUS"){s.unity_next_priority="both independent backend surfaces are present; inspect the Mono managed payload and validated IL2CPP pair without suppressing either";if(managed!=plan.candidates.end())s.unity_next_priority+="; managed payload: "+path_utf8(managed->path);}
    else if(s.unity_backend_state=="BACKEND_UNRESOLVED"||s.unity_backend_state=="IL2CPP_LIKELY")s.unity_next_priority="backend unresolved; do not invent Mono or IL2CPP without backend-specific structural evidence";
    s.confirmed_ecosystems.assign(eco.begin(),eco.end());return s;
}

DirectorySummary summarize_directory(const DirectoryPlan& plan,const std::vector<AnalysisReport>& reports,std::uint64_t elapsed_ms){
    std::vector<DirectoryReportIndex> compact;compact.reserve(reports.size());for(const auto&r:reports)compact.push_back(make_directory_report_index(r));
    return summarize_directory(plan,compact,elapsed_ms);
}

static bool render_directory_json_impl(std::ostream& o,const DirectoryPlan& plan,const DirectorySummary& summary,std::size_t report_count,const std::function<bool(std::ostream&,std::size_t,std::string&)>& write_report,const DirectoryReportRendering* rendering,const DirectoryArtifactRendering* artifact_rendering,std::string& error){
    auto q=[](const std::string&v){return directory_json_escape(v);};
    auto render_modality=[&](std::ostream&out,const RuntimeModalityGuidance&m){
        out<<"{\"policy\":\""<<q(m.policy)<<"\",\"static_evidence_only\":"<<(m.static_evidence_only?"true":"false")
           <<",\"runtime_execution_authorized\":"<<(m.runtime_execution_authorized?"true":"false")<<",\"priority_guidance\":[";
        for(std::size_t i=0;i<m.priority_guidance.size();++i){if(i)out<<',';out<<'"'<<q(m.priority_guidance[i])<<'"';}
        out<<"],\"requirements\":[";
        for(std::size_t i=0;i<m.requirements.size();++i){
            if(i)out<<',';
            const auto&r=m.requirements[i];
            out<<"{\"modality\":\""<<q(r.modality)<<"\",\"state\":\""<<q(r.state)<<"\",\"confidence\":"<<r.confidence
               <<",\"evidence_gate\":\""<<q(r.evidence_gate)<<"\",\"reason\":\""<<q(r.reason)<<"\",\"evidence\":[";
            for(std::size_t j=0;j<r.evidence.size();++j){if(j)out<<',';out<<'"'<<q(r.evidence[j])<<'"';}
            out<<"],\"negative_evidence\":[";for(std::size_t j=0;j<r.negative_evidence.size();++j){if(j)out<<',';out<<'"'<<q(r.negative_evidence[j])<<'"';}
            out<<"],\"artifacts\":[";for(std::size_t j=0;j<r.artifacts.size();++j){if(j)out<<',';out<<'"'<<q(path_utf8(r.artifacts[j]))<<'"';}out<<"]}";
        }
        out<<"]}";
    };
    constexpr std::size_t top_cap=12,skip_cap=64,per_file_relation_cap=8;
    const std::size_t relation_cap=plan.max_rendered_relationships;

    auto relation_render_priority=[](const DirectoryRelationship&r){
        if(r.kind.rfind("unity_",0)==0||r.kind=="godot_gdextension_library_reference")return 0;
        if(r.evidence_level=="R4_SEMANTIC_APPLICATION_RELATION"||r.evidence_level=="R3_EXACT_DATA_DEPENDENCY")return 0;
        if(r.kind=="elf_loader_dependency"||r.kind=="elf_interpreter_dependency"||r.kind=="pe_loader_dependency"||r.kind=="dotnet_pinvoke_dependency"||r.kind=="script_runner_argv"||r.kind=="manifest_declared_member"||r.kind=="runtime_recovered_artifact")return 1;
        if(r.kind=="artifact_materialization")return 2;
        if(r.kind=="artifact_analysis_derivative")return 3;
        if(r.state=="ROUTE_HINT")return 5;
        return 4;
    };
    std::set<std::string> candidate_keys;
    for(const auto&c:plan.candidates)candidate_keys.insert(path_key(c.path));
    std::map<std::string,std::vector<const DirectoryRelationship*>> relation_refs;
    auto add_ref=[&](const std::filesystem::path&p,const DirectoryRelationship&r){
        auto k=path_key(p);if(!candidate_keys.count(k))return;auto&v=relation_refs[k];
        if(v.size()<per_file_relation_cap){v.push_back(&r);return;}
        auto worst=std::max_element(v.begin(),v.end(),[&](const auto*a,const auto*b){return relation_render_priority(*a)<relation_render_priority(*b);});
        if(worst!=v.end()&&relation_render_priority(r)<relation_render_priority(**worst))*worst=&r;
    };
    for(const auto&r:plan.relationships){add_ref(r.first,r);add_ref(r.second,r);}
    for(auto&kv:relation_refs)std::stable_sort(kv.second.begin(),kv.second.end(),[&](const auto*a,const auto*b){return relation_render_priority(*a)<relation_render_priority(*b);});
    std::vector<const DirectoryRelationship*> rendered_relationships;rendered_relationships.reserve(plan.relationships.size());
    for(const auto&r:plan.relationships)rendered_relationships.push_back(&r);
    std::stable_sort(rendered_relationships.begin(),rendered_relationships.end(),[&](const auto*a,const auto*b){return relation_render_priority(*a)<relation_render_priority(*b);});

    auto render_relation=[&](std::ostream&o,const DirectoryRelationship&r){
        o<<"{\"first\":\""<<q(path_utf8(r.first))<<"\",\"second\":\""<<q(path_utf8(r.second))
         <<"\",\"directed\":"<<(r.directed?"true":"false")
         <<",\"kind\":\""<<q(r.kind)<<"\",\"state\":\""<<q(r.state)
         <<"\",\"first_role\":\""<<q(r.first_role)<<"\",\"second_role\":\""<<q(r.second_role)
         <<"\",\"first_relation_role\":\""<<q(r.first_relation_role)<<"\",\"second_relation_role\":\""<<q(r.second_relation_role)
         <<"\",\"evidence_basis\":\""<<q(r.evidence_basis)<<"\",\"evidence_source\":\""<<q(r.evidence_source)
         <<"\",\"source_coordinate\":\""<<q(r.source_coordinate)<<"\",\"target_coordinate\":\""<<q(r.target_coordinate)
         <<"\",\"provenance_scope\":\""<<q(r.provenance_scope)<<"\",\"evidence_level\":\""<<q(r.evidence_level)<<"\",\"ambiguity\":\""<<q(r.ambiguity)<<"\",\"semantic_relevance\":\""<<q(r.semantic_relevance)<<"\",\"priority_eligible\":"<<(r.priority_eligible?"true":"false")
         <<",\"first_priority_delta\":"<<r.first_priority_delta<<",\"second_priority_delta\":"<<r.second_priority_delta
         <<",\"reason\":\""<<q(r.reason)<<"\"}";
    };
    auto render_file_relation_refs=[&](std::ostream&o,const DirectoryCandidate&c){
        o<<"[";
        auto it=relation_refs.find(path_key(c.path));if(it!=relation_refs.end())for(std::size_t i=0;i<it->second.size();++i){
            if(i)o<<',';
            const auto&r=*it->second[i];const bool is_first=path_key(r.first)==path_key(c.path);const auto&other=is_first?r.second:r.first;
            const char*direction=!r.directed?"UNDIRECTED":(is_first?"OUTBOUND":"INBOUND");
            const auto&relation_role=is_first?r.first_relation_role:r.second_relation_role;const int delta=is_first?r.first_priority_delta:r.second_priority_delta;
            o<<"{\"other\":\""<<q(path_utf8(other))<<"\",\"kind\":\""<<q(r.kind)<<"\",\"state\":\""<<q(r.state)
             <<"\",\"direction\":\""<<direction<<"\",\"relation_role\":\""<<q(relation_role)<<"\",\"evidence_level\":\""<<q(r.evidence_level)<<"\",\"ambiguity\":\""<<q(r.ambiguity)<<"\",\"semantic_relevance\":\""<<q(r.semantic_relevance)<<"\",\"priority_delta\":"<<delta<<"}";
        }
        o<<"]";
    };

    o<<"{\n  \"directory_summary\": {\"root\":\""<<q(path_utf8(plan.root))
     <<"\",\"total_files\":"<<summary.total_files<<",\"discovered_regular_files\":"<<summary.discovered_regular_files<<",\"candidate_omitted_count\":"<<summary.candidate_omitted_count
     <<",\"partial\":"<<(summary.partial?"true":"false")<<",\"partial_reasons\":[";for(std::size_t i=0;i<summary.partial_reasons.size();++i){if(i)o<<',';o<<'"'<<q(summary.partial_reasons[i])<<'"';}o<<"]"
     <<",\"analyzed_files\":"<<summary.analyzed_files<<",\"skipped_files\":"<<summary.skipped_files<<",\"total_bytes\":"<<summary.total_bytes
     <<",\"unity_engine_state\":\""<<q(summary.unity_engine_state)<<"\",\"unity_backend_state\":\""<<q(summary.unity_backend_state)
     <<"\",\"unity_next_priority\":\""<<q(summary.unity_next_priority)<<"\",\"unity_mono_relationship_count\":"<<summary.unity_mono_relationship_count
     <<",\"unity_il2cpp_relationship_count\":"<<summary.unity_il2cpp_relationship_count<<",\"high_priority_evidence_count\":"<<summary.high_priority_evidence_count
     <<",\"artifact_relationship_count\":"<<summary.artifact_relationship_count<<",\"relationship_omitted_count\":"<<summary.relationship_omitted_count
     <<",\"relationship_ambiguous_reference_count\":"<<summary.relationship_ambiguous_reference_count
     <<",\"relationship_budget_exhausted\":"<<(summary.relationship_budget_exhausted?"true":"false")
     <<",\"failures\":"<<summary.failures<<",\"partials\":"<<summary.partials<<",\"elapsed_ms\":"<<summary.elapsed_ms<<",\"type_counts\":{";
    bool first=true;for(const auto&kv:summary.type_counts){if(!first)o<<',';first=false;o<<'"'<<q(kv.first)<<"\":"<<kv.second;}
    o<<"},\"confirmed_ecosystems\":[";for(std::size_t i=0;i<summary.confirmed_ecosystems.size();++i){if(i)o<<',';o<<'"'<<q(summary.confirmed_ecosystems[i])<<'"';}
    o<<"],\"runtime_modality\":";render_modality(o,summary.runtime_modality);o<<"},\n";

    o<<"  \"directory_plan\": {\"max_depth\":"<<plan.max_depth<<",\"max_candidates\":"<<plan.max_candidates<<",\"regular_files_seen\":"<<plan.regular_files_seen
     <<",\"candidate_omitted_count\":"<<plan.candidate_omitted_count<<",\"candidate_admission_budget_exhausted\":"<<(plan.candidate_admission_budget_exhausted?"true":"false")
     <<",\"candidate_admission_policy\":\"bounded preflight semantic priority; score descending, deterministic path tie-break; all admitted files retain compact state\""
     <<",\"candidate_detail_retrieval\":{\"mode\":\"reanalyze_file\",\"command\":\"auto-refirst <deferred-file> --json\"},\"max_runtime_targets\":"<<plan.max_runtime_targets
     <<",\"total_runtime_budget_ms\":"<<plan.total_runtime_budget_ms<<",\"per_target_timeout_ms\":"<<plan.per_target_timeout_ms
     <<",\"run_all\":"<<(plan.run_all?"true":"false")<<",\"max_relationships\":"<<plan.max_relationships
     <<",\"max_related_files_per_artifact\":"<<plan.max_related_files_per_artifact<<",\"max_rendered_relationships\":"<<plan.max_rendered_relationships
     <<",\"relationship_candidate_lookups\":"<<plan.relationship_candidate_lookups<<",\"relationship_ambiguous_reference_count\":"<<plan.relationship_ambiguous_reference_count
     <<",\"relationship_omitted_count\":"<<plan.relationship_omitted_count<<",\"related_file_omitted_count\":"<<plan.related_file_omitted_count
     <<",\"relationship_budget_exhausted\":"<<(plan.relationship_budget_exhausted?"true":"false")
     <<",\"relationships_rendered\":"<<std::min<std::size_t>(rendered_relationships.size(),relation_cap)
     <<",\"relationships_truncated\":"<<(rendered_relationships.size()>relation_cap?"true":"false")<<",\"top_priority_files\":[";
    for(std::size_t i=0;i<plan.candidates.size()&&i<top_cap;++i){
        if(i)o<<',';
        const auto&c=plan.candidates[i];o<<"{\"rank\":"<<(i+1)<<",\"path\":\""<<q(path_utf8(c.path))
         <<"\",\"size\":"<<c.size<<",\"type_hint\":\""<<q(c.type_hint)<<"\",\"role\":\""<<q(c.role)
         <<"\",\"tier\":\""<<q(c.priority_tier)<<"\",\"score\":"<<c.priority_score<<",\"relationship_priority_boost\":"<<c.relationship_priority_boost<<",\"reasons\":[";
        for(std::size_t j=0;j<c.priority_reasons.size();++j){if(j)o<<',';o<<'"'<<q(c.priority_reasons[j])<<'"';}
        o<<"],\"related_files\":[";for(std::size_t j=0;j<c.related_files.size();++j){if(j)o<<',';o<<'"'<<q(path_utf8(c.related_files[j]))<<'"';}
        o<<"],\"analysis_state\":\""<<q(c.analysis_state)<<"\",\"runtime_eligible\":"<<(c.runtime_eligible?"true":"false")
         <<",\"runtime_selected\":"<<(c.runtime_selected?"true":"false")<<",\"runtime_state\":\""<<q(c.runtime_state)
         <<"\",\"runtime_skip_reason\":\""<<q(c.runtime_skip_reason)<<"\"}";
    }

    o<<"],\"file_states\":[";
    for(std::size_t i=0;i<plan.candidates.size();++i){
        if(i)o<<',';
        const auto&c=plan.candidates[i];o<<"{\"rank\":"<<(i+1)<<",\"path\":\""<<q(path_utf8(c.path))
         <<"\",\"size\":"<<c.size<<",\"type_hint\":\""<<q(c.type_hint)<<"\",\"structural_confidence\":\""<<q(c.structural_confidence)
         <<"\",\"role\":\""<<q(c.role)<<"\",\"tier\":\""<<q(c.priority_tier)<<"\",\"score\":"<<c.priority_score
         <<",\"relationship_priority_boost\":"<<c.relationship_priority_boost<<",\"related_files\":[";
        for(std::size_t j=0;j<c.related_files.size();++j){if(j)o<<',';o<<'"'<<q(path_utf8(c.related_files[j]))<<'"';}
        o<<"],\"relationship_refs\":";render_file_relation_refs(o,c);
        o<<",\"analysis_state\":\""<<q(c.analysis_state)<<"\",\"skipped_reason\":\""<<q(c.skipped_reason)
         <<"\",\"analysis_elapsed_ms\":"<<c.analysis_elapsed_ms<<",\"runtime_eligible\":"<<(c.runtime_eligible?"true":"false")
         <<",\"runtime_eligibility_reason\":\""<<q(c.runtime_eligibility_reason)<<"\",\"runtime_selected\":"<<(c.runtime_selected?"true":"false")
         <<",\"runtime_state\":\""<<q(c.runtime_state)<<"\",\"runtime_skip_reason\":\""<<q(c.runtime_skip_reason)
         <<"\",\"runtime_elapsed_ms\":"<<c.runtime_elapsed_ms;
        if(rendering)o<<",\"report_detail_state\":\""<<q(c.report_detail_state)<<"\",\"report_full_bytes\":"<<c.report_full_bytes
                      <<",\"report_detail_reason\":\""<<q(c.report_detail_reason)<<"\"";
        if(artifact_rendering)o<<",\"artifact_materialization_state\":\""<<q(c.artifact_materialization_state)<<"\",\"artifact_materialized_bytes\":"<<c.artifact_materialized_bytes
                               <<",\"artifact_materialized_files\":"<<c.artifact_materialized_files<<",\"artifact_materialization_reason\":\""<<q(c.artifact_materialization_reason)<<"\"";
        o<<"}";
    }

    o<<"],\"runtime_selected\":[";first=true;for(const auto&c:plan.candidates)if(c.runtime_selected){if(!first)o<<',';first=false;o<<"{\"path\":\""<<q(path_utf8(c.path))<<"\",\"score\":"<<c.priority_score<<",\"tier\":\""<<q(c.priority_tier)<<"\",\"state\":\""<<q(c.runtime_state)<<"\",\"elapsed_ms\":"<<c.runtime_elapsed_ms<<"}";}
    o<<"],\"runtime_skipped\":[";first=true;std::size_t sk=0;for(const auto&c:plan.candidates)if(!c.runtime_selected&&(!c.runtime_skip_reason.empty()||c.runtime_eligible)){if(sk++>=skip_cap)break;if(!first)o<<',';first=false;o<<"{\"path\":\""<<q(path_utf8(c.path))<<"\",\"runtime_eligible\":"<<(c.runtime_eligible?"true":"false")<<",\"state\":\""<<q(c.runtime_state)<<"\",\"reason\":\""<<q(c.runtime_skip_reason.empty()?c.runtime_eligibility_reason:c.runtime_skip_reason)<<"\"}";}
    o<<"],\"relationships\":[";for(std::size_t i=0;i<rendered_relationships.size()&&i<relation_cap;++i){if(i)o<<',';render_relation(o,*rendered_relationships[i]);}
    o<<"],\"traversal_skips_total\":"<<plan.traversal_skips.size()<<",\"traversal_skips_rendered\":"<<std::min<std::size_t>(plan.traversal_skips.size(),skip_cap)
     <<",\"traversal_skips_truncated\":"<<(plan.traversal_skips.size()>skip_cap?"true":"false")<<",\"traversal_skips\":[";for(std::size_t i=0;i<plan.traversal_skips.size()&&i<skip_cap;++i){if(i)o<<',';o<<"{\"path\":\""<<q(path_utf8(plan.traversal_skips[i].path))<<"\",\"reason\":\""<<q(plan.traversal_skips[i].reason)<<"\"}";}
    o<<"]},\n";
    if(rendering){
        o<<"  \"report_rendering\": {\"profile\":\""<<q(rendering->profile)<<"\",\"partial\":"<<(rendering->partial?"true":"false")
         <<",\"truncated\":"<<(rendering->truncated?"true":"false")<<",\"full_report_count\":"<<rendering->full_report_count
         <<",\"full_reports_rendered\":"<<rendering->full_reports_rendered<<",\"full_reports_deferred\":"<<rendering->full_reports_deferred
         <<",\"known_full_report_bytes\":"<<rendering->known_full_report_bytes<<",\"inline_report_bytes\":"<<rendering->inline_report_bytes
         <<",\"known_deferred_report_bytes\":"<<rendering->known_deferred_report_bytes
         <<",\"inline_report_budget_bytes\":"<<rendering->inline_report_budget_bytes<<",\"per_report_max_bytes\":"<<rendering->per_report_max_bytes
         <<",\"spool_hard_budget_bytes\":"<<rendering->spool_hard_budget_bytes<<",\"spool_peak_bytes\":"<<rendering->spool_peak_bytes
         <<",\"selection_policy\":\""<<q(rendering->selection_policy)<<"\",\"reason\":\""<<q(rendering->reason)
         <<"\",\"detail_retrieval\":{\"mode\":\""<<q(rendering->detail_retrieval_mode)<<"\",\"command\":\""<<q(rendering->detail_retrieval_command)<<"\"}},\n";
    }
    if(artifact_rendering){
        o<<"  \"artifact_materialization\": {\"profile\":\""<<q(artifact_rendering->profile)<<"\",\"partial\":"<<(artifact_rendering->partial?"true":"false")
         <<",\"max_bytes\":"<<artifact_rendering->max_bytes<<",\"max_files\":"<<artifact_rendering->max_files
         <<",\"pre_relationship_max_bytes\":"<<artifact_rendering->pre_relationship_max_bytes<<",\"pre_relationship_max_files\":"<<artifact_rendering->pre_relationship_max_files
         <<",\"post_relationship_reserve_bytes\":"<<artifact_rendering->post_relationship_reserve_bytes<<",\"post_relationship_reserve_files\":"<<artifact_rendering->post_relationship_reserve_files
         <<",\"materialized_bytes\":"<<artifact_rendering->materialized_bytes<<",\"materialized_files\":"<<artifact_rendering->materialized_files
         <<",\"retained_candidate_roots\":"<<artifact_rendering->retained_candidate_roots<<",\"deferred_candidate_count\":"<<artifact_rendering->deferred_candidate_count
         <<",\"known_omitted_bytes\":"<<artifact_rendering->known_omitted_bytes<<",\"known_omitted_files\":"<<artifact_rendering->known_omitted_files
         <<",\"unknown_omitted_candidate_count\":"<<artifact_rendering->unknown_omitted_candidate_count
         <<",\"selection_policy\":\""<<q(artifact_rendering->selection_policy)<<"\",\"reason\":\""<<q(artifact_rendering->reason)
         <<"\",\"detail_retrieval\":{\"mode\":\""<<q(artifact_rendering->detail_retrieval_mode)<<"\",\"command\":\""<<q(artifact_rendering->detail_retrieval_command)<<"\"}},\n";
    }
    o<<"  \"reports\": [";
    for(std::size_t i=0;i<report_count;++i){if(i)o<<",\n";if(!write_report(o,i,error))return false;}
    o<<"]\n}\n";
    if(!o){error="directory report output write failed";return false;}return true;
}

void render_directory_json(std::ostream& o,const DirectoryPlan& plan,const DirectorySummary& summary,const std::vector<AnalysisReport>& reports){
    std::string error;
    const auto writer=[&](std::ostream&out,std::size_t i,std::string&){render_json(out,reports[i]);return bool(out);};
    (void)render_directory_json_impl(o,plan,summary,reports.size(),writer,nullptr,nullptr,error);
}

bool render_directory_json_spooled(std::ostream& o,const DirectoryPlan& plan,const DirectorySummary& summary,const std::vector<std::filesystem::path>& report_paths,const DirectoryReportRendering& rendering,const DirectoryArtifactRendering& artifact_rendering,std::string& error){
    const auto writer=[&](std::ostream&out,std::size_t i,std::string&why){
        if(i>=report_paths.size()){why="directory report spool index is out of range";return false;}
        std::ifstream in(report_paths[i],std::ios::binary);if(!in){why="cannot open directory report spool: "+path_utf8(report_paths[i]);return false;}
        out<<in.rdbuf();if(!out){why="directory report spool output failed: "+path_utf8(report_paths[i]);return false;}return true;
    };
    return render_directory_json_impl(o,plan,summary,report_paths.size(),writer,&rendering,&artifact_rendering,error);
}

std::string render_directory_json(const DirectoryPlan& plan,const DirectorySummary& summary,const std::vector<AnalysisReport>& reports){
    std::ostringstream o;
    render_directory_json(o,plan,summary,reports);
    return o.str();
}

}
