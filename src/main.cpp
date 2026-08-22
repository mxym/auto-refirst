#include "prts/cpython.hpp"
#include "prts/cpython_reference_pairing.hpp"
#include "prts/cpython_static.hpp"
#include "prts/cpython_probe.hpp"
#include "prts/elf.hpp"
#include "prts/macho.hpp"
#include "prts/dotnet.hpp"
#include "prts/file_snapshot.hpp"
#include "prts/godot.hpp"
#include "prts/gdextension.hpp"
#include "prts/semantic_producers.hpp"
#include "prts/repair.hpp"
#include "prts/gdscript.hpp"
#include "prts/golang.hpp"
#include "prts/mapped_file.hpp"
#include "prts/lua.hpp"
#include "prts/wasm.hpp"
#include "prts/jvm.hpp"
#include "prts/android.hpp"
#include "prts/apk.hpp"
#include "prts/dart.hpp"
#include "prts/flutter.hpp"
#include "prts/nuitka.hpp"
#include "prts/nested_executable.hpp"
#include "prts/pe.hpp"
#include "prts/packed_pe.hpp"
#include "prts/pyinstaller.hpp"
#include "prts/python_bytecode.hpp"
#include "prts/report.hpp"
#include "prts/analysis_path.hpp"
#include "prts/interpreter_boundary.hpp"
#include "prts/authenticode.hpp"
#include "prts/antidebug.hpp"
#include "prts/execution_prerequisite.hpp"
#include "prts/manual_resolver.hpp"
#include "prts/runtime.hpp"
#include "prts/renpy.hpp"
#include "prts/rust.hpp"
#include "prts/search.hpp"
#include "prts/sha256.hpp"
#include "prts/static_scan.hpp"
#include "prts/upx.hpp"
#include "prts/unity.hpp"
#include "prts/wxapkg.hpp"
#include "prts/asar.hpp"
#include "prts/autoit.hpp"
#include "prts/crypto.hpp"
#include "prts/exception_flow.hpp"
#include "prts/continuation.hpp"
#include "prts/control_record.hpp"
#include "prts/path_utf8.hpp"
#include "prts/build_metadata.hpp"
#include "prts/report_schema.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <filesystem>
#include <future>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

namespace {
struct Options {
    bool json=false;
    prts::ReportLanguage report_language=prts::ReportLanguage::English;
    bool extract=false;
    bool recursive=false; // explicit recursive artifact graph compatibility flag
    bool run_requested=false;
    bool apply=false;
    bool run_all=false;
    bool help=false;
    bool version=false;
    std::string search;
    bool search_ignore_case=false;
    std::string wxid;
    std::string run_mode; // auto / trace / unpack / python-probe
    std::uint32_t timeout_ms=15000;
    std::uint32_t directory_max_depth=std::numeric_limits<std::uint32_t>::max();
    std::uint32_t max_runtime_targets=4;
    std::uint64_t total_runtime_budget_ms=45000;
    std::uint32_t artifact_max_depth=4;
    std::uint32_t artifact_max_nodes=1024;
    std::uint64_t artifact_max_bytes=512ull*1024*1024;
    // Internal per-analysis extraction budget. Normal non-graph extraction remains unlimited.
    std::uint64_t extract_budget_bytes=std::numeric_limits<std::uint64_t>::max();
    std::uint32_t extract_budget_files=std::numeric_limits<std::uint32_t>::max();
    // Internal only: recursive graph nodes use selective APK child materialization.
    bool artifact_graph_node=false;
    // Internal only: keep all materialized output for a derived child under the root input artifact tree.
    std::filesystem::path artifact_root_override;
    // Internal only: a parent BFS owns high-value child admission; suppress nested independent graph creation.
    bool suppress_auto_child_analysis=false;
    // Internal only: directory aggregate output budget may defer all automatic
    // materialization for a candidate while retaining static semantic analysis.
    bool suppress_auto_materialization=false;
};

enum class ExitCode : int {
    Success = 0,
    SearchNoMatch = 1,
    Usage = 2,
    Input = 3,
    Internal = 4,
};

constexpr int exit_code(ExitCode code){return static_cast<int>(code);}

int finish_standard_output(ExitCode code){
    std::cout.flush();
    if(!std::cout){
        std::cerr<<"standard output write failed\n";
        return exit_code(ExitCode::Internal);
    }
    return exit_code(code);
}


void print_version(std::ostream& o){
    o << "auto-refirst " << prts::kProductVersion << "\n"
      << "git_commit=" << prts::kBuildId << "\n"
      << "build_platform=" << prts::kBuildPlatform << "\n"
      << "report_schema_version=" << prts::kReportSchemaVersion << "\n";
}

void print_help(std::ostream& o){
    o << "auto-refirst " << prts::kProductVersion << "\n"
      << "Usage: auto-refirst <file|directory> [options]\n\n"
      << "Common options:\n"
      << "  -h, --help                 Show this help and exit\n"
      << "  --version                  Show version and exit\n"
      << "  --json                     Emit structured JSON\n"
      << "  --report-lang=en|zh        Human-readable report language\n"
      << "  --extract                  Additionally materialize full/bulk static artifacts and heavy maps\n"
      << "  --run                      Run the automatic deep runtime plan (non-destructive)\n"
      << "  --apply                    With --run, allow validated transactional replacement\n"
      << "  --timeout=MS               Per-target runtime timeout (default 15000)\n\n"
      << "Directory options (directories recurse by default):\n"
      << "  --max-depth=N              Maximum directory recursion depth (0 = root files only)\n"
      << "  --max-runtime-targets=N    Maximum automatically executed targets (default 4)\n"
      << "  --total-runtime-budget=MS  Total directory runtime budget (default 45000)\n"
      << "  --run-all                  Run every static-confirmed executable within the total budget\n\n"
      << "Static/artifact options:\n"
      << "  --recursive                Compatibility flag: with --extract, emit the full recursive artifact report array\n"
      << "  --artifact-depth=N         Automatic/extracted static-child depth limit (default 4)\n"
      << "  --artifact-nodes=N         Automatic/extracted static-child node limit (default 1024)\n"
      << "  --artifact-bytes=N         Automatic/extracted static-child byte limit (default 512 MiB)\n"
      << "  --search=TEXT              Fast directory string hunt (ASCII/UTF-16LE)\n"
      << "  --search-ignore-case       ASCII case-insensitive search\n"
      << "  --wxid=wx...               Optional WeChat cache decryption identity\n\n"
      << "Artifact policy:\n"
      << "  Default analysis automatically materializes bounded high-value code/scripts/maps under\n"
      << "  <input>.auto-refirst/ and statically re-analyzes HIGH-priority children. Strict validated\n"
      << "  static repairs and uniquely oracle-closed cross-file semantic children use the same non-runtime path.\n"
      << "  --extract adds\n"
      << "  complete container/resource expansion and explicitly heavy analysis planes; it never\n"
      << "  authorizes child execution. --apply only controls validated native replacement.\n\n"
      << "Compatibility runtime modes:\n"
      << "  --run=trace                DEPRECATED: shallow runtime trace compatibility mode\n"
      << "  --run=unpack               DEPRECATED: non-destructive deep-runtime compatibility alias; use --run\n"
      << "  --run=python-probe         DEPRECATED: force the CPython compiler probe only\n\n"
      << "Safety levels:\n"
      << "  Level 0  default static analysis: target code is not executed\n"
      << "  Level 1  --run: target executes; runtime evidence/dumps are collected; input is not replaced\n"
      << "  Level 2  --run may reconstruct and independently validate a separate artifact\n"
      << "  Level 3  --run --apply: only a strictly validated candidate may be transactionally installed with backup/rollback gates\n\n"
      << "auto-refirst is not a sandbox. Use runtime analysis only in an isolated environment.\n";
}

#ifdef _WIN32
std::string utf8_from_wide(const wchar_t* w){
    if(!w)return {};int n=WideCharToMultiByte(CP_UTF8,0,w,-1,nullptr,0,nullptr,nullptr);if(n<=1)return {};std::string s(static_cast<std::size_t>(n),'\0');WideCharToMultiByte(CP_UTF8,0,w,-1,s.data(),n,nullptr,nullptr);s.resize(static_cast<std::size_t>(n-1));return s;
}
std::vector<std::string> windows_utf8_args(){
    int n=0;LPWSTR* w=CommandLineToArgvW(GetCommandLineW(),&n);std::vector<std::string> out;if(!w)return out;out.reserve(static_cast<std::size_t>(n));for(int i=0;i<n;++i)out.push_back(utf8_from_wide(w[i]));LocalFree(w);return out;
}
#endif

std::filesystem::path cli_path(std::string_view s){
#ifdef _WIN32
    if(s.empty())return {};
    int n=MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(n<=0)return std::filesystem::path(std::string(s));
    std::wstring w(static_cast<std::size_t>(n),L'\0');
    MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),w.data(),n);
    return std::filesystem::path(w);
#else
    return std::filesystem::path(s);
#endif
}

std::string lower_path_string(const std::filesystem::path&p){auto s=prts::path_utf8(p);std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}
bool ext_is(const std::filesystem::path&p,std::string_view e){auto x=prts::path_utf8(p.extension());std::transform(x.begin(),x.end(),x.begin(),[](unsigned char c){return char(std::tolower(c));});return x==e;}
bool has_export_prefix(const prts::PeInfo&pe,std::string_view p){return std::any_of(pe.exports.begin(),pe.exports.end(),[&](const auto&e){return e.name.rfind(p,0)==0;});}
bool route_renpy_rpyc(const std::filesystem::path&p,const prts::StaticScanReport&s){return s.hints.renpy||ext_is(p,".rpyc")||ext_is(p,".rpymc");}
bool route_unity(const std::filesystem::path&p,const prts::PeInfo&pe,const prts::StaticScanReport&s){auto l=lower_path_string(p);return s.hints.unity||l.find("global-metadata.dat")!=std::string::npos||l.find("gameassembly")!=std::string::npos||has_export_prefix(pe,"il2cpp_");}
bool route_pyinstaller(const prts::PeInfo&pe,const prts::StaticScanReport&s){return s.hints.pyinstaller||(pe.valid&&pe.overlay_size>=64*1024);}
bool starts_with(std::span<const std::uint8_t>d,std::string_view s){return d.size()>=s.size()&&std::equal(s.begin(),s.end(),d.begin());}
bool contains_ascii(std::span<const std::uint8_t>d,std::string_view s){if(s.empty()||d.size()<s.size())return false;return std::search(d.begin(),d.end(),s.begin(),s.end())!=d.end();}
bool route_wxapkg_failure(const std::filesystem::path&p,std::span<const std::uint8_t>d){return ext_is(p,".wxapkg")||starts_with(d,"V1MMWX")||(d.size()>13&&d[0]==0xbe&&d[13]==0xed);}
bool route_asar_failure(const std::filesystem::path&p,std::span<const std::uint8_t>d){return ext_is(p,".asar")||(d.size()>=4&&d[0]==4&&d[1]==0&&d[2]==0&&d[3]==0);}
bool route_godot_pck_failure(const std::filesystem::path&p,std::span<const std::uint8_t>d){return ext_is(p,".pck")||starts_with(d,"GDPC");}
void add_validation_failure(std::vector<prts::Finding>&out,std::string family,std::string route,std::string error){
    if(error.empty())return;
    prts::Finding f;f.kind="validation";f.family=std::move(family);f.state="FAILED";
    f.fields["validation_stage"]="deep_parser";f.fields["route"]=route;
    f.evidence.push_back("deep parser entered because "+route);
    f.negative_evidence.push_back(std::move(error));
    f.suggested_actions.push_back("inspect the failed structure as a possible modified, corrupt, or unsupported variant before applying ecosystem-specific tooling");
    out.push_back(std::move(f));
}

prts::Finding godot_legacy_config_finding(const prts::GodotLegacyEngineConfigInfo&c){
    prts::Finding f;f.kind="engine_config";f.family="Godot legacy engine.cfb";f.state="CONFIRMED";f.variant="ECFG";
    f.evidence={"ECFG property table closed exactly over the input using supported Godot 2.x Variant encodings","all retained application/remap/autoload resource paths passed strict res:// path validation"};
    f.fields["property_count"]=std::to_string(c.property_count);f.fields["application_name"]=c.application_name;f.fields["main_scene"]=c.main_scene;f.fields["remap_count"]=std::to_string(c.remaps.size());f.fields["autoload_count"]=std::to_string(c.autoloads.size());if(!c.icon.empty())f.fields["icon"]=c.icon;
    f.suggested_actions={"resolve main_scene through remap/all before inspecting lower-priority resources","treat legacy .gdc tokenizer semantics as a separate capability from project packaging"};return f;
}

prts::Finding gdextension_descriptor_finding(const prts::GDExtensionDescriptorInfo&d){
    prts::Finding f;f.kind="native_bridge_descriptor";f.family="Godot GDExtension descriptor";f.state="CONFIRMED";
    f.evidence={"strict UTF-8 descriptor syntax validated configuration.entry_symbol","libraries declarations use bounded feature keys and safe res:// resource paths"};
    f.fields["entry_symbol"]=d.entry_symbol;f.fields["compatibility_minimum"]=d.compatibility_minimum;f.fields["library_count"]=std::to_string(d.libraries.size());
    if(d.reloadable_present)f.fields["reloadable"]=d.reloadable?"true":"false";
    f.suggested_actions={"resolve declared native library paths and validate the configured entry export"};
    return f;
}

bool artifact_path_link_or_reparse(const std::filesystem::path&p){
    std::error_code ec;auto st=std::filesystem::symlink_status(p,ec);
    if(!ec&&st.type()==std::filesystem::file_type::symlink)return true;
#ifdef _WIN32
    auto attrs=GetFileAttributesW(p.c_str());
    if(attrs!=INVALID_FILE_ATTRIBUTES&&(attrs&FILE_ATTRIBUTE_REPARSE_POINT))return true;
#endif
    return false;
}

std::filesystem::path artifact_root_for_input(const std::filesystem::path&input){
    return prts::path_with_ascii_suffix(input,".auto-refirst");
}

bool ensure_artifact_subdirectory(const std::filesystem::path&root,const std::filesystem::path&dir,std::string&error){
    if(root.empty()||dir.empty()){error="artifact root/directory is empty";return false;}
    const auto nr=root.lexically_normal(),nd=dir.lexically_normal();
    auto rel=nd.lexically_relative(nr);
    if(rel.empty()&&nd!=nr){error="artifact directory is outside the per-input root";return false;}
    for(const auto&part:rel)if(part==".."){error="artifact directory escapes the per-input root";return false;}
    std::error_code ec;
    auto ensure_one=[&](const std::filesystem::path&p)->bool{
        auto st=std::filesystem::symlink_status(p,ec);
        if(!ec&&st.type()!=std::filesystem::file_type::not_found){
            if(artifact_path_link_or_reparse(p)){error="artifact path component is a symlink/reparse point: "+prts::path_utf8(p);return false;}
            if(st.type()!=std::filesystem::file_type::directory){error="artifact path component is not a directory: "+prts::path_utf8(p);return false;}
            return true;
        }
        ec.clear();if(!std::filesystem::create_directory(p,ec)&&ec){error="cannot create artifact directory: "+prts::path_utf8(p)+": "+ec.message();return false;}
        ec.clear();st=std::filesystem::symlink_status(p,ec);if(ec||st.type()!=std::filesystem::file_type::directory||artifact_path_link_or_reparse(p)){error="artifact path component did not resolve to a real non-reparse directory: "+prts::path_utf8(p);return false;}return true;
    };
    if(!ensure_one(nr))return false;
    auto cur=nr;
    for(const auto&part:rel){if(part.empty()||part==".")continue;cur/=part;if(!ensure_one(cur))return false;}
    return true;
}

bool write_artifact_report_json(const std::filesystem::path&root,const std::filesystem::path&path,const prts::AnalysisReport&report,std::string&error,bool automatic_child_summary=false){
    if(!ensure_artifact_subdirectory(root,path.parent_path(),error))return false;
    std::error_code ec;auto st=std::filesystem::symlink_status(path,ec);
    if(!ec&&st.type()!=std::filesystem::file_type::not_found&&artifact_path_link_or_reparse(path)){error="refusing artifact output symlink/reparse point: "+prts::path_utf8(path);return false;}
    if(!ec&&st.type()!=std::filesystem::file_type::not_found&&st.type()!=std::filesystem::file_type::regular){
        error="refusing non-regular artifact output: "+prts::path_utf8(path);return false;
    }
    std::ofstream out(path,std::ios::binary|std::ios::trunc);if(!out){error="cannot create artifact file: "+prts::path_utf8(path);return false;}
    if(automatic_child_summary)prts::render_automatic_child_json(out,report);else prts::render_json(out,report);out.put('\n');
    if(!out){error="artifact write failed: "+prts::path_utf8(path);return false;}return true;
}

bool same_regular_file(const std::filesystem::path&a,const std::filesystem::path&b){
    std::error_code ec;if(a.empty()||b.empty()||!std::filesystem::is_regular_file(a,ec)||ec)return false;ec.clear();if(!std::filesystem::is_regular_file(b,ec)||ec)return false;ec.clear();return std::filesystem::equivalent(a,b,ec)&&!ec;
}

void register_artifact_file(prts::AnalysisReport&report,const std::filesystem::path&path,std::string kind,std::string role,std::string source,const std::filesystem::path&parent,std::string relation,std::string priority,bool normalized=false,bool runtime_confirmed=false,std::string state="MATERIALIZED"){
    if(path.empty())return;
    std::error_code ec;auto st=std::filesystem::symlink_status(path,ec);
    if(ec||st.type()==std::filesystem::file_type::symlink||st.type()!=std::filesystem::file_type::regular)return;
    for(auto&existing:report.artifacts)if(same_regular_file(existing.path,path)){existing.runtime_confirmed=existing.runtime_confirmed||runtime_confirmed;existing.normalized=existing.normalized||normalized;if(!state.empty())existing.state=std::move(state);return;}
    prts::AnalysisArtifact a;a.kind=std::move(kind);a.role=std::move(role);a.source=std::move(source);a.state=std::move(state);a.relation=std::move(relation);a.priority=std::move(priority);a.path=path;a.parent=parent;a.normalized=normalized;a.runtime_confirmed=runtime_confirmed;
    a.size=std::filesystem::file_size(path,ec);if(ec)a.size=0;a.sha256=prts::sha256_file(path);report.artifacts.push_back(std::move(a));
}

bool runtime_artifact_static_child(const prts::RuntimeArtifact&a){
    if(a.path.empty())return false;
    if(a.kind=="unpacked_pe")return a.state=="RECONSTRUCTED_STANDALONE_VALIDATED"||a.state=="UNPACKED_VALIDATED";
    if(a.kind=="reconstructed_elf")return a.state=="RECONSTRUCTED_STANDALONE_VALIDATED"||a.state=="RECONSTRUCTED_NOT_STANDALONE_VALIDATED"||a.state=="UNPACKED_VALIDATED";
    if(a.kind=="runtime_backing_elf")return a.state=="RUNTIME_BACKING_EXEC_HANDOFF_STANDALONE_VALIDATED"||a.state=="RUNTIME_BACKING_CHILD_EXEC_HANDOFF_STANDALONE_VALIDATED"||a.state=="RUNTIME_BACKING_EXEC_HANDOFF_CONFIRMED"||a.state=="RUNTIME_BACKING_CHILD_EXEC_HANDOFF_CONFIRMED"||a.state=="UNPACKED_VALIDATED";
    return false;
}

void register_runtime_artifacts(prts::AnalysisReport&report,const std::filesystem::path&input){
    for(const auto&a:report.runtime.artifacts){
        if(a.path.empty())continue;
        const bool native=a.kind=="unpacked_pe"||a.kind=="reconstructed_elf"||a.kind=="runtime_backing_elf";
        const bool map=a.kind=="materialization_graph";
        register_artifact_file(report,a.path,a.kind,native?"recovered_native_image":(map?"runtime_analysis_map":"runtime_materialization"),"runtime",input,native?"runtime_recovered_image":"runtime_artifact",native?"HIGH":(map?"ANALYSIS":"REVIEW"),false,true,a.state.empty()?"MATERIALIZED":a.state);
        if(map){auto it=a.fields.find("edges_path");if(it!=a.fields.end())register_artifact_file(report,std::filesystem::path(it->second),"materialization_graph_edges","runtime_analysis_map","runtime",input,"runtime_artifact","ANALYSIS",false,true,a.state.empty()?"MATERIALIZED":a.state);}
    }
}

bool filename_is(const std::filesystem::path&p,std::string_view name){auto x=prts::path_utf8(p.filename());std::transform(x.begin(),x.end(),x.begin(),[](unsigned char c){return char(std::tolower(c));});std::string n(name);std::transform(n.begin(),n.end(),n.begin(),[](unsigned char c){return char(std::tolower(c));});return x==n;}
prts::Finding dart_finding(const prts::DartInfo& d) {
    prts::Finding f;
    f.kind = "language/runtime";
    f.family = "Dart";
    f.state = "CONFIRMED";
    f.confidence.reset();
    f.fields["offset_space"] = "current_input_file";

    if (d.aot.valid) {
        const auto& aot = d.aot;
        f.variant = aot.variant;
        f.evidence.push_back("loader-visible Dart AOT symbol/segment relationships and product AOT/code snapshot structure validate across the known Snapshot::Kind enum epochs");
        f.fields["architecture"] = aot.architecture;
        f.fields["standalone"] = aot.standalone ? "true" : "false";
        f.fields["flutter_symbols"] = aot.flutter_symbols ? "true" : "false";
        f.fields["dynamic_symbols"] = std::to_string(aot.dynamic_symbol_count);
        f.fields["snapshot_count"] = std::to_string(aot.snapshots.size());
        f.fields["target_symbol_count"] = std::to_string(aot.symbols.size());
        if (!aot.build_id_hex.empty()) f.fields["build_id"] = aot.build_id_hex;
        for (const auto& x : aot.symbols) {
            if (x.file_backed && x.size) {
                f.ranges.push_back({x.file_offset, std::min<std::uint64_t>(x.size, 4096), "Dart AOT symbol " + x.name});
            }
        }
        for (const auto& x : aot.snapshots) {
            if (x.valid && x.length) {
                f.ranges.push_back({x.file_offset, std::min<std::uint64_t>(x.length, 4096), "Dart AOT/code snapshot header/reference"});
            }
        }
    } else if (d.kernel.valid) {
        const auto& k = d.kernel;
        f.variant = "Kernel component";
        f.evidence.push_back("Dart Kernel magic and self-describing footer/index/library/table geometry validate");
        f.fields["format_version"] = std::to_string(k.format_version);
        f.fields["library_count"] = std::to_string(k.library_count);
        f.fields["component_file_size"] = std::to_string(k.component_file_size);
        f.fields["component_index_offset"] = std::to_string(k.component_index_offset);
        f.fields["string_table_offset"] = std::to_string(k.string_table_offset);
        f.fields["deep_metadata_supported"] = k.deep_metadata_supported ? "true" : "false";
        f.fields["deep_metadata_complete"] = k.deep_metadata_complete ? "true" : "false";
        f.fields["sdk_hash"] = k.sdk_hash;
        f.fields["string_count"] = std::to_string(k.string_count);
        f.fields["constant_count"] = std::to_string(k.constant_count);
        f.fields["source_count"] = std::to_string(k.source_count);
        f.fields["canonical_name_count"] = std::to_string(k.canonical_name_count);
        f.fields["member_range_space"] = "current_input_file_serialized_kernel";

        if (k.component_file_size > k.component_index_offset) {
            f.ranges.push_back({k.component_index_offset, k.component_file_size - k.component_index_offset, "Dart Kernel component index/footer"});
        }
        std::size_t retained = 0;
        for (const auto& src : k.sources) {
            if (src.source_code_size && retained++ < 16) {
                f.ranges.push_back({src.source_code_offset, src.source_code_size, "Dart Kernel serialized source bytes: " + src.uri});
            }
        }
        retained = 0;
        for (const auto& lib : k.libraries) {
            if (!lib.procedures.empty()) {
                for (const auto& proc : lib.procedures) {
                    if (retained++ >= 64) break;
                    if (proc.end_offset <= proc.file_offset) continue;
                    auto label = std::string("Dart Kernel serialized procedure: ") +
                                 (proc.name.empty() ? ("member#" + std::to_string(proc.index)) : proc.name);
                    f.ranges.push_back({proc.file_offset, proc.end_offset - proc.file_offset, std::move(label)});
                }
            } else {
                for (const auto& range : lib.procedure_ranges) {
                    if (retained++ >= 64) break;
                    if (range.end_offset <= range.file_offset) continue;
                    f.ranges.push_back({range.file_offset, range.end_offset - range.file_offset,
                                        "Dart Kernel serialized procedure range library#" + std::to_string(lib.index) +
                                        " member#" + std::to_string(range.index)});
                }
            }
            if (retained >= 64) break;
        }
        if (k.deep_metadata_supported && !k.deep_metadata_complete) {
            f.negative_evidence.push_back(k.deep_metadata_error.empty() ? "deep Kernel metadata recovery is incomplete" : k.deep_metadata_error);
        }
    } else {
        const auto& raw = d.raw_snapshot;
        f.variant = "raw snapshot";
        f.evidence.push_back("Dart snapshot magic, declared length, kind, version hash and bounded feature string validate");
        f.fields["kind"] = raw.kind_name;
        f.fields["snapshot_hash"] = raw.snapshot_hash;
        f.fields["features"] = raw.features;
        f.fields["length"] = std::to_string(raw.length);
        if (raw.length) {
            f.ranges.push_back({raw.file_offset, std::min<std::uint64_t>(raw.length, 4096), "Dart raw snapshot header/reference"});
        }
    }

    for (const auto& x : d.aot.anomalies) f.negative_evidence.push_back(x);
    return f;
}
prts::Finding flutter_asset_finding(const prts::FlutterAssetManifestInfo&m){prts::Finding f;f.kind="ecosystem";f.family="Flutter";f.variant="AssetManifest.bin";f.fields["offset_space"]="current_input_file";f.fields["entries"]=std::to_string(m.entry_count);f.fields["variants"]=std::to_string(m.variant_count);f.fields["legacy_variants"]=m.legacy_string_variants?"true":"false";f.fields["modern_variants"]=m.modern_metadata_variants?"true":"false";if(m.valid&&m.nonempty){f.state="CONFIRMED";f.evidence.push_back("AssetManifest.bin routing plus complete bounded StandardMessageCodec and Flutter asset-schema validation");}else{f.state="SUSPECTED";f.confidence=.45;f.evidence.push_back("AssetManifest.bin filename route and structurally valid empty StandardMessageCodec map");f.negative_evidence.push_back("empty manifest has no asset entries and is not independent Flutter confirmation");}for(const auto&a:m.anomalies)f.negative_evidence.push_back(a);return f;}

bool parse_u64_arg(std::string_view text,std::uint64_t&out){
    if(text.empty())return false;
    std::uint64_t v=0;
    for(char c:text){if(c<'0'||c>'9')return false;auto d=std::uint64_t(c-'0');if(v>(std::numeric_limits<std::uint64_t>::max()-d)/10)return false;v=v*10+d;}
    out=v;return true;
}
std::uint64_t sat_add(std::uint64_t a,std::uint64_t b){return b>std::numeric_limits<std::uint64_t>::max()-a?std::numeric_limits<std::uint64_t>::max():a+b;}
template<class C,class F> std::uint64_t sum_bytes(const C&c,F f){std::uint64_t n=0;for(const auto&x:c)n=sat_add(n,f(x));return n;}
std::uint32_t cap_count(std::uint64_t n){return n>std::numeric_limits<std::uint32_t>::max()?std::numeric_limits<std::uint32_t>::max():static_cast<std::uint32_t>(n);}

struct DirectoryArtifactTreeStats {
    std::uint64_t bytes=0;
    std::uint64_t files=0;
};

bool inspect_directory_artifact_tree(const std::filesystem::path&root,DirectoryArtifactTreeStats&stats,std::string&error){
    stats={};error.clear();std::error_code ec;auto st=std::filesystem::symlink_status(root,ec);
    if(ec==std::errc::no_such_file_or_directory){ec.clear();return true;}
    if(ec){error="cannot inspect directory artifact root: "+ec.message();return false;}
    if(st.type()==std::filesystem::file_type::not_found)return true;
    if(artifact_path_link_or_reparse(root)){error="directory artifact root is a symlink/reparse point; refusing traversal: "+prts::path_utf8(root);return false;}
    if(st.type()!=std::filesystem::file_type::directory){error="directory artifact root is occupied by a non-directory path: "+prts::path_utf8(root);return false;}
    std::filesystem::recursive_directory_iterator it(root,std::filesystem::directory_options::skip_permission_denied,ec),end;
    if(ec){error="cannot enumerate directory artifact root: "+ec.message();return false;}
    while(it!=end){
        auto path=it->path();auto est=it->symlink_status(ec);if(ec){error="cannot stat directory artifact output: "+ec.message();return false;}
        if(artifact_path_link_or_reparse(path)){if(est.type()==std::filesystem::file_type::directory)it.disable_recursion_pending();error="directory artifact output contains a symlink/reparse point: "+prts::path_utf8(path);return false;}
        if(est.type()==std::filesystem::file_type::regular){auto n=std::filesystem::file_size(path,ec);if(ec){error="cannot size directory artifact output: "+ec.message();return false;}stats.bytes=sat_add(stats.bytes,n);stats.files=sat_add(stats.files,1);}
        it.increment(ec);if(ec){error="directory artifact iteration failed: "+ec.message();return false;}
    }
    return true;
}

bool reset_directory_artifact_root(const std::filesystem::path&root,std::string&error){
    error.clear();std::error_code ec;auto st=std::filesystem::symlink_status(root,ec);
    if(ec==std::errc::no_such_file_or_directory){ec.clear();return true;}
    if(ec){error="cannot inspect prior directory artifact root: "+ec.message();return false;}
    if(st.type()==std::filesystem::file_type::not_found)return true;
    if(artifact_path_link_or_reparse(root)){error="prior directory artifact root is a symlink/reparse point; refusing removal: "+prts::path_utf8(root);return false;}
    if(st.type()!=std::filesystem::file_type::directory){error="prior directory artifact root is not a directory; refusing removal: "+prts::path_utf8(root);return false;}
    // The root is product-owned (`<input>.auto-refirst`) and has just been proven
    // to be a real directory.  Refuse any nested link/reparse before remove_all.
    DirectoryArtifactTreeStats ignored;if(!inspect_directory_artifact_tree(root,ignored,error))return false;
    std::filesystem::remove_all(root,ec);if(ec){error="cannot reset prior product-owned directory artifact root: "+ec.message();return false;}return true;
}

void note_directory_artifact_deferred(prts::AnalysisReport&report,std::uint64_t files,std::uint64_t bytes,const std::string&reason){
    report.materialization.partial=true;
    report.materialization.omitted_count=sat_add(report.materialization.omitted_count,files);
    report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,bytes);
    report.materialization.reasons.push_back(reason+"; rerun this file directly to restore its normal single-file automatic materialization contract");
}

struct ArtifactCandidate { std::filesystem::path path; std::string relation; };
struct PendingArtifact { std::filesystem::path path,parent,root_input; std::string relation; std::uint32_t depth=0; bool root=false; };

bool has_extractable_child_container(const prts::AnalysisReport&r){
    return r.pyinstaller.valid||r.godot.valid||r.autoit.valid||r.renpy_rpa.valid||r.renpy_rpyc.valid||
           (r.wxapkg.valid&&!r.wxapkg.entries.empty())||r.asar.valid||r.apk.valid||r.jar.valid||(r.nuitka.valid&&(r.nuitka.onefile||r.nuitka.decompression_limited));
}

std::vector<ArtifactCandidate> extracted_artifacts(const prts::AnalysisReport&r){
    std::vector<ArtifactCandidate> out;std::set<std::string>seen;
    auto add=[&](const std::filesystem::path&p,std::string rel){if(p.empty())return;auto key=prts::path_utf8(p.lexically_normal());if(seen.insert(key).second)out.push_back({p,std::move(rel)});};
    for(const auto&m:r.pyinstaller_extract.materialized)if(m.recursive_candidate)add(m.path,"extracted:pyinstaller:"+m.role);
    for(const auto&p:r.godot_extract.files)add(p,"extracted:godot-pck");
    for(const auto&p:r.autoit_extract.files)add(p,"extracted:autoit");
    for(const auto&p:r.renpy_rpa_extract.files)add(p,"extracted:renpy-rpa");
    if(!r.renpy_extract.pickle_path.empty())add(r.renpy_extract.pickle_path,"decoded:renpy-rpyc-pickle");
    for(const auto&p:r.wxapkg_extract.files)add(p,"extracted:wxapkg");
    for(const auto&p:r.asar_extract.files)add(p,"extracted:asar");
    for(const auto&p:r.apk_extract.files)add(p,"extracted:apk");
    for(const auto&p:r.jar_extract.files)add(p,"extracted:jar");
    // Standalone Nuitka constant manifests are analysis derivatives, not child input artifacts.
    if(r.nuitka.onefile)for(const auto&p:r.nuitka_extract.files)add(p,"extracted:nuitka-onefile");
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return prts::path_utf8(a.path)<prts::path_utf8(b.path);});return out;
}

bool parse_options(int argc,char**argv,Options&opt){
    for(int i=2;i<argc;++i){
        std::string arg=argv[i];
        if(arg=="-h"||arg=="--help")opt.help=true;
        else if(arg=="--version")opt.version=true;
        else if(arg=="--json")opt.json=true;
        else if(arg.rfind("--report-lang=",0)==0){auto v=arg.substr(14);if(v=="en")opt.report_language=prts::ReportLanguage::English;else if(v=="zh")opt.report_language=prts::ReportLanguage::Chinese;else{std::cerr<<"unsupported report language (use en or zh): "<<v<<"\n";return false;}}
        else if(arg=="--extract")opt.extract=true;
        else if(arg=="--recursive")opt.recursive=true;
        else if(arg=="--run"){opt.run_requested=true;opt.run_mode="auto";}
        else if(arg=="--apply")opt.apply=true;
        else if(arg=="--run-all")opt.run_all=true;
        else if(arg=="--search-ignore-case")opt.search_ignore_case=true;
        else if(arg.rfind("--search=",0)==0){opt.search=arg.substr(9);if(opt.search.empty()){std::cerr<<"--search requires non-empty text\n";return false;}}
        else if(arg.rfind("--wxid=",0)==0)opt.wxid=arg.substr(7);
        else if(arg.rfind("--run=",0)==0){opt.run_requested=true;opt.run_mode=arg.substr(6);}
        else if(arg.rfind("--timeout=",0)==0){std::uint64_t v=0;if(!parse_u64_arg(arg.substr(10),v)||v==0||v>3600000){std::cerr<<"invalid timeout (1..3600000 ms): "<<arg<<"\n";return false;}opt.timeout_ms=static_cast<std::uint32_t>(v);}
        else if(arg.rfind("--max-depth=",0)==0){std::uint64_t v=0;if(!parse_u64_arg(arg.substr(12),v)||v>1024){std::cerr<<"invalid directory max depth (0..1024): "<<arg<<"\n";return false;}opt.directory_max_depth=static_cast<std::uint32_t>(v);}
        else if(arg.rfind("--max-runtime-targets=",0)==0){std::uint64_t v=0;if(!parse_u64_arg(arg.substr(22),v)||v==0||v>100000){std::cerr<<"invalid max runtime targets (1..100000): "<<arg<<"\n";return false;}opt.max_runtime_targets=static_cast<std::uint32_t>(v);}
        else if(arg.rfind("--total-runtime-budget=",0)==0){std::uint64_t v=0;if(!parse_u64_arg(arg.substr(23),v)||v==0||v>86400000){std::cerr<<"invalid total runtime budget (1..86400000 ms): "<<arg<<"\n";return false;}opt.total_runtime_budget_ms=v;}
        else if(arg.rfind("--artifact-depth=",0)==0){std::uint64_t v=0;if(!parse_u64_arg(arg.substr(17),v)||v>32){std::cerr<<"invalid artifact depth (0..32): "<<arg<<"\n";return false;}opt.artifact_max_depth=static_cast<std::uint32_t>(v);}
        else if(arg.rfind("--artifact-nodes=",0)==0){std::uint64_t v=0;if(!parse_u64_arg(arg.substr(17),v)||v==0||v>1000000){std::cerr<<"invalid artifact node limit (1..1000000): "<<arg<<"\n";return false;}opt.artifact_max_nodes=static_cast<std::uint32_t>(v);}
        else if(arg.rfind("--artifact-bytes=",0)==0){std::uint64_t v=0;if(!parse_u64_arg(arg.substr(17),v)||v==0){std::cerr<<"invalid artifact byte limit: "<<arg<<"\n";return false;}opt.artifact_max_bytes=v;}
        else {std::cerr<<"unknown option: "<<arg<<"\n";return false;}
    }
    if(opt.run_requested&&opt.run_mode.empty())opt.run_mode="auto";
    if(opt.run_requested&&opt.run_mode!="auto"&&opt.run_mode!="trace"&&opt.run_mode!="unpack"&&opt.run_mode!="python-probe"){
        std::cerr<<"unsupported run mode: "<<opt.run_mode<<"\n";return false;
    }
    if(opt.apply&&!opt.run_requested){std::cerr<<"--apply requires --run; static analysis never authorizes writeback\n";return false;}
    if(opt.run_all&&!opt.run_requested){std::cerr<<"--run-all requires --run\n";return false;}
    if(opt.apply&&(opt.run_mode=="trace"||opt.run_mode=="python-probe")){std::cerr<<"--apply is incompatible with --run="<<opt.run_mode<<"; use bare --run --apply for validated reconstruction/install\n";return false;}
    return true;
}

void finalize_implicit_execution(prts::AnalysisReport& report,const std::filesystem::path& input,const Options& opt){
    std::vector<prts::ImplicitExecutionPlaneRef> planes;
    auto add=[&](std::string source,const prts::ImplicitExecutionInfo& info){planes.push_back({std::move(source),&info});};
    add("PE",report.pe.implicit_exec);
    add("ELF",report.elf.implicit_exec);
    for(std::size_t i=0;i<report.macho.slices.size();++i)add("Mach-O slice "+std::to_string(i),report.macho.slices[i].implicit_exec);
    add("JVM",report.jvm_class.implicit_exec);
    add("DEX",report.dex.implicit_exec);
    add("WebAssembly",report.wasm.implicit_exec);
    add(".NET",report.dotnet.implicit_exec);
    add("APK/JNI",report.apk.implicit_exec);
    report.implicit_exec=prts::merge_implicit_execution(planes);
    (void)input;(void)opt;
}

prts::AnalysisReport analyze_file(const std::filesystem::path&input,const Options&opt);

constexpr std::uint64_t kAutoMaterializationBytes=64ull*1024*1024;
constexpr std::uint32_t kAutoMaterializationFiles=256;
constexpr std::uint64_t kAutoAnalysisRows=100000;
constexpr std::uint64_t kAutoAnalysisEstimatedBytes=16ull*1024*1024;

std::filesystem::path analysis_map_dir(const prts::AnalysisReport&report,std::string_view family){
    return report.materialization.root/prts::path_from_utf8("maps")/prts::path_from_utf8(family);
}

bool prepare_artifact_targets(prts::AnalysisReport&report,const std::string&family,const std::vector<std::filesystem::path>&targets){
    std::set<std::filesystem::path>parents;for(const auto&p:targets)if(!p.empty())parents.insert(p.parent_path());std::string why;for(const auto&dir:parents)if(!ensure_artifact_subdirectory(report.materialization.root,dir,why)){prts::Finding f;f.kind="artifact";f.family=family+" artifact output";f.state="FAILED";f.negative_evidence.push_back(why);report.findings.push_back(std::move(f));return false;}
    for(const auto&p:targets){if(p.empty())continue;std::error_code ec;auto st=std::filesystem::symlink_status(p,ec);if(!ec&&st.type()!=std::filesystem::file_type::not_found&&artifact_path_link_or_reparse(p)){prts::Finding f;f.kind="artifact";f.family=family+" artifact output";f.state="FAILED";f.negative_evidence.push_back("refusing sidecar output symlink/reparse point: "+prts::path_utf8(p));report.findings.push_back(std::move(f));return false;}if(!ec&&st.type()!=std::filesystem::file_type::not_found&&st.type()!=std::filesystem::file_type::regular){prts::Finding f;f.kind="artifact";f.family=family+" artifact output";f.state="FAILED";f.negative_evidence.push_back("refusing non-regular sidecar output: "+prts::path_utf8(p));report.findings.push_back(std::move(f));return false;}}return true;
}

bool auto_analysis_allowed(prts::AnalysisReport&report,const Options&opt,std::string_view family,std::uint64_t rows,std::uint64_t estimated_row_bytes=192){
    if(opt.extract)return true;
    const auto estimated=rows>std::numeric_limits<std::uint64_t>::max()/std::max<std::uint64_t>(estimated_row_bytes,1)?std::numeric_limits<std::uint64_t>::max():rows*estimated_row_bytes;
    if(opt.suppress_auto_materialization){report.materialization.partial=true;report.materialization.omitted_count=sat_add(report.materialization.omitted_count,rows);report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,estimated);report.materialization.reasons.push_back(std::string(family)+" automatic analysis sidecar deferred by the directory aggregate artifact budget; rerun this file directly for its normal per-file materialization contract");return false;}
    if(rows<=kAutoAnalysisRows&&estimated<=kAutoAnalysisEstimatedBytes)return true;
    report.materialization.partial=true;report.materialization.omitted_count=sat_add(report.materialization.omitted_count,rows);report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,estimated);report.materialization.reasons.push_back(std::string(family)+" AUTO_ANALYSIS sidecar omitted by default row/size budget: rows="+std::to_string(rows)+" estimated_bytes="+std::to_string(estimated)+"; --extract exports the full supported map");return false;
}

void register_analysis_sidecars(prts::AnalysisReport&report,const std::filesystem::path&input){
    auto add=[&](const std::filesystem::path&p,std::string kind,std::string source){register_artifact_file(report,p,std::move(kind),"analysis_map",std::move(source),input,"analysis_of","ANALYSIS");};
    if(report.elf_extract.success){add(report.elf_extract.symbols_csv,"symbol_map","ELF");add(report.elf_extract.relocations_csv,"relocation_map","ELF");}
    if(report.elf_unwind_extract.success){add(report.elf_unwind_extract.cies_csv,"unwind_cie_map","ELF");add(report.elf_unwind_extract.fdes_csv,"unwind_fde_map","ELF");}
    if(report.golang_extract.success){add(report.golang_extract.symbols_csv,"symbol_map","Go");add(report.golang_extract.types_csv,"type_map","Go");}
    if(report.dotnet_extract.success){add(report.dotnet_extract.symbols_csv,"method_map",".NET");add(report.dotnet_extract.types_csv,"type_map",".NET");add(report.dotnet_extract.members_csv,"member_map",".NET");}
    if(report.dex_extract.success){add(report.dex_extract.methods_csv,"method_map","DEX");add(report.dex_extract.classes_csv,"class_map","DEX");add(report.dex_extract.fields_csv,"field_map","DEX");add(report.dex_extract.callsites_csv,"callsite_map","DEX");}
    if(report.jvm_extract.success){add(report.jvm_extract.methods_csv,"method_map","JVM");add(report.jvm_extract.fields_csv,"field_map","JVM");add(report.jvm_extract.references_csv,"reference_map","JVM");}
    if(report.wasm_extract.success){add(report.wasm_extract.functions_csv,"function_map","WebAssembly");add(report.wasm_extract.strings_txt,"strings_map","WebAssembly");}
    if(report.lua_extract.success)add(report.lua_extract.disasm_path,"bytecode_disassembly","Lua");
    if(report.python_bytecode_extract.success){add(report.python_bytecode_extract.code_objects_csv,"python_code_object_map","CPython bytecode");add(report.python_bytecode_extract.root_symbols_csv,"python_root_symbol_map","CPython bytecode");add(report.python_bytecode_extract.opcode_inventory_csv,"python_opcode_inventory","CPython bytecode");}
    if(report.implicit_exec_extract.success)add(report.implicit_exec_extract.csv,"implicit_execution_map","Implicit execution");
    if(report.gdscript_extract.success){add(report.gdscript_extract.info_json,"gdscript_info","Godot GDScript");add(report.gdscript_extract.identifiers_csv,"identifier_map","Godot GDScript");add(report.gdscript_extract.constants_csv,"constant_map","Godot GDScript");add(report.gdscript_extract.lines_csv,"line_map","Godot GDScript");add(report.gdscript_extract.tokens_csv,"token_map","Godot GDScript");}
    if(report.unity_extract.success){add(report.unity_extract.symbols_csv,"method_map","Unity");add(report.unity_extract.layouts_csv,"layout_map","Unity");add(report.unity_extract.generics_csv,"generic_map","Unity");add(report.unity_extract.rgctx_csv,"rgctx_map","Unity");add(report.unity_extract.strings_csv,"managed_string_map","Unity");add(report.unity_extract.usages_csv,"metadata_usage_map","Unity");add(report.unity_extract.defaults_csv,"default_value_map","Unity");add(report.unity_extract.xrefs_csv,"metadata_xref_map","Unity");add(report.unity_extract.pinvoke_csv,"pinvoke_map","Unity");add(report.unity_extract.dispatch_csv,"dispatch_map","Unity");add(report.unity_extract.dispatch_calls_csv,"dispatch_callsite_map","Unity");add(report.unity_extract.dispatch_targets_csv,"dispatch_target_map","Unity");add(report.unity_extract.callgraph_csv,"native_callgraph","Unity");}
}

void materialize_structured_sidecars(prts::AnalysisReport&report,const Options&opt){
    auto ready=[&](std::string family,std::uint64_t rows,const std::vector<std::filesystem::path>&targets,std::uint64_t row_bytes=192){
        return auto_analysis_allowed(report,opt,family,rows,row_bytes)&&prepare_artifact_targets(report,family,targets);
    };
    if(report.elf.valid){
        auto dir=analysis_map_dir(report,"elf");
        const auto dynamic_rows=sat_add(report.elf.dynamic.symbols.size(),report.elf.dynamic.relocations.size());
        auto symbols=dir/"elf-symbols.csv",relocs=dir/"elf-relocations.csv";
        if(report.elf.dynamic.state=="RESOLVED"&&ready("ELF dynamic",dynamic_rows,{symbols,relocs},224))report.elf_extract=prts::extract_elf_dynamic(report.elf,symbols);
        const auto unwind_rows=sat_add(report.elf.unwind.cies.size(),report.elf.unwind.fdes.size());
        auto fdes=dir/"elf-fdes.csv",cies=dir/"elf-cies.csv";
        if(report.elf.unwind.state=="RESOLVED"&&ready("ELF unwind",unwind_rows,{fdes,cies},240))report.elf_unwind_extract=prts::extract_elf_unwind(report.elf,fdes);
    }
    if(report.golang.valid&&!report.golang.functions.empty()){
        std::uint64_t rows=report.golang.functions.size();for(const auto&t:report.golang.types)rows=sat_add(rows,std::max<std::size_t>(1,t.fields.size()));
        auto dir=analysis_map_dir(report,"go"),symbols=dir/"symbols.csv",types=dir/"symbols-types.csv";
        if(ready("Go",rows,{symbols,types},224))report.golang_extract=prts::extract_go_symbols(report.golang,symbols);
    }
    if(report.dotnet.valid){
        auto rows=sat_add(report.dotnet.methods.size(),sat_add(report.dotnet.types.size(),sat_add(report.dotnet.fields.size(),sat_add(report.dotnet.properties.size(),sat_add(report.dotnet.events.size(),sat_add(report.dotnet.member_refs.size(),report.dotnet.method_specs.size()))))));
        auto dir=analysis_map_dir(report,"dotnet"),symbols=dir/"symbols.csv",types=dir/"symbols-types.csv",members=dir/"symbols-members.csv";
        if(ready(".NET",rows,{symbols,types,members},256))report.dotnet_extract=prts::extract_dotnet_symbols(report.dotnet,symbols);
    }
    if(report.dex.valid){
        auto rows=sat_add(report.dex.methods.size(),sat_add(report.dex.classes.size(),sat_add(report.dex.fields.size(),report.dex.call_sites.size())));
        auto dir=analysis_map_dir(report,"dex"),methods=dir/"dex.methods.csv",classes=dir/"dex.classes.csv",fields=dir/"dex.fields.csv",calls=dir/"dex.callsites.csv";
        if(ready("DEX",rows,{methods,classes,fields,calls},224))report.dex_extract=prts::extract_dex_maps(report.dex,methods);
    }
    if(report.jvm_class.valid){
        auto rows=sat_add(report.jvm_class.methods.size(),sat_add(report.jvm_class.fields.size(),report.jvm_class.references.size()));
        auto dir=analysis_map_dir(report,"jvm"),methods=dir/"methods.csv",fields=dir/"methods-fields.csv",refs=dir/"methods-references.csv";
        if(ready("JVM",rows,{methods,fields,refs},256))report.jvm_extract=prts::extract_jvm_maps(report.jvm_class,methods);
    }
    if(report.wasm.valid){
        auto rows=sat_add(report.wasm.functions.size(),report.wasm.string_hints.size());auto dir=analysis_map_dir(report,"wasm"),functions=dir/"functions.csv",strings=dir/"functions.strings.txt";
        if(ready("WebAssembly",rows,{functions,strings},224))report.wasm_extract=prts::extract_wasm(report.wasm,functions);
    }
    if(report.lua.valid){
        std::uint64_t rows=0;for(const auto&p:report.lua.protos)rows=sat_add(rows,p.instructions.size());auto out=analysis_map_dir(report,"lua")/"disassembly.txt";
        if(ready("Lua",rows,{out},96))report.lua_extract=prts::extract_lua_disasm(report.lua,out);
    }
    if(report.python_bytecode.valid){
        std::uint64_t opcode_rows=0;for(auto n:report.python_bytecode.opcode_counts)if(n)++opcode_rows;
        auto rows=sat_add(opcode_rows,sat_add(report.python_bytecode.marshal.code_ranges.size(),sat_add(report.python_bytecode.root.names.size(),report.python_bytecode.root.constants.size())));
        auto dir=analysis_map_dir(report,"python-bytecode"),code=dir/"code-objects.csv",symbols=dir/"root-symbols.csv",opcodes=dir/"opcode-inventory.csv";
        if(ready("CPython bytecode",rows,{code,symbols,opcodes},224))report.python_bytecode_extract=prts::extract_python_bytecode_maps(report.python_bytecode,code);
    }
    if(!report.implicit_exec.facts.empty()){
        auto out=report.materialization.root/prts::path_from_utf8("maps")/"implicit-exec.csv";
        if(ready("Implicit execution",report.implicit_exec.facts.size(),{out},320))report.implicit_exec_extract=prts::extract_implicit_execution(report.implicit_exec,out);
    }
}

std::pair<std::uint64_t,std::uint32_t> auto_core_budget(const Options&opt){
    if(opt.suppress_auto_materialization)return {0,0};
    return {std::min({kAutoMaterializationBytes,opt.artifact_max_bytes,opt.extract_budget_bytes}),std::min({kAutoMaterializationFiles,opt.artifact_max_nodes,opt.extract_budget_files})};
}
std::pair<std::uint64_t,std::uint32_t> pyinstaller_auto_budget(const Options&opt){return auto_core_budget(opt);}

std::filesystem::path container_output_dir(const prts::AnalysisReport&report,std::string_view family){
    return report.materialization.root/prts::path_from_utf8("static")/prts::path_from_utf8(family);
}
bool prepare_container_output(prts::AnalysisReport&report,const std::filesystem::path&out,const std::string&family){
    std::string why;if(ensure_artifact_subdirectory(report.materialization.root,out,why))return true;prts::Finding f;f.kind="artifact";f.family=family+" automatic materialization";f.state="FAILED";f.negative_evidence.push_back(why);report.findings.push_back(std::move(f));return false;
}

bool validated_structured_member_artifact(const prts::AnalysisArtifact&a){
    const bool structured=a.relation=="materialized_from_container"||a.relation=="materialized_from_carchive";
    const bool materialized=a.state=="MATERIALIZED"||a.state=="MATERIALIZED_NORMALIZED"||a.state=="VALIDATED_EXACT_STRUCTURED_MEMBER";
    return structured&&materialized&&!a.runtime_confirmed&&a.role!="analysis_map"&&a.role!="static_child_report"&&a.kind!="analysis_report";
}

std::vector<prts::NestedExecutableArtifactCandidate> nested_reuse_candidates(const prts::AnalysisReport&report){
    std::vector<prts::NestedExecutableArtifactCandidate> out;out.reserve(report.artifacts.size());
    for(const auto&a:report.artifacts){prts::NestedExecutableArtifactCandidate c;c.path=a.path;c.source=a.source;c.relation=a.relation;c.priority=a.priority;c.state=a.state;c.sha256=a.sha256;c.size=a.size;c.validated_structured_member=validated_structured_member_artifact(a);out.push_back(std::move(c));}
    return out;
}

std::string joined_structured_paths(const prts::AnalysisReport&report,const prts::NestedExecutableReuseDecision&reuse){
    std::string out;std::size_t kept=0;for(const auto idx:reuse.matching_indexes){if(idx>=report.artifacts.size()||kept++>=8)break;if(!out.empty())out+=';';out+=prts::path_utf8(report.artifacts[idx].path);}if(reuse.matching_indexes.size()>8)out+=";...";return out;
}

const prts::AsarEntry* exact_unmaterialized_asar_member(const prts::AnalysisReport&report,const prts::NestedExecutableInfo&nested,std::size_t&matches){
    matches=0;const prts::AsarEntry*hit=nullptr;if(!report.asar.valid)return nullptr;
    for(const auto&e:report.asar.entries){if(e.kind!=prts::AsarEntryKind::File||e.unpacked||e.size!=nested.exact_size)continue;if(e.offset>std::numeric_limits<std::uint64_t>::max()-report.asar.data_offset)continue;const auto off=report.asar.data_offset+e.offset;if(off!=nested.parent_offset)continue;++matches;hit=&e;}
    return matches==1?hit:nullptr;
}

bool materialize_exact_asar_member(prts::AnalysisReport&report,std::span<const std::uint8_t>data,const prts::NestedExecutableInfo&nested,const prts::AsarEntry&entry,prts::AsarExtractResult&ex,std::filesystem::path&path,std::string&error){
    error.clear();auto out=container_output_dir(report,"asar");if(!prepare_container_output(report,out,"Electron ASAR")){error="ASAR structured-member output root was refused";return false;}
    prts::AsarInfo one=report.asar;one.entries.clear();one.entries.push_back(entry);one.interesting_paths.clear();one.interesting_paths.push_back(entry.path);
    ex=prts::extract_asar(data,one,out,true,nested.exact_size,1);if(!ex.success||ex.files.size()!=1){error=ex.error.empty()?"exact ASAR member materialization did not produce one file":ex.error;return false;}
    path=ex.files.front();std::error_code ec;const auto st=std::filesystem::symlink_status(path,ec);if(ec||st.type()==std::filesystem::file_type::symlink||st.type()!=std::filesystem::file_type::regular){error="exact ASAR member output is not a regular non-symlink file";return false;}
    const auto n=std::filesystem::file_size(path,ec);if(ec||n!=nested.exact_size||prts::sha256_file(path)!=nested.child_sha256){error="exact ASAR member output size/SHA-256 disagrees with AP exact span";return false;}return true;
}

void commit_exact_asar_member(prts::AnalysisReport&report,const std::filesystem::path&input,const prts::AsarExtractResult&ex,const std::filesystem::path&path){
    const bool had_extract=!report.asar_extract.output_dir.empty();if(!had_extract)report.asar_extract.output_dir=ex.output_dir;
    bool known=false;for(const auto&p:report.asar_extract.files)if(same_regular_file(p,path)){known=true;break;}if(!known){report.asar_extract.files.push_back(path);report.asar_extract.packed_files+=ex.packed_files;report.asar_extract.unpacked_files+=ex.unpacked_files;report.asar_extract.output_bytes=sat_add(report.asar_extract.output_bytes,ex.output_bytes);report.asar_extract.integrity_verified+=ex.integrity_verified;report.asar_extract.integrity_mismatches+=ex.integrity_mismatches;}
    if(!had_extract)report.asar_extract.success=ex.success;
    register_artifact_file(report,path,"asar_member","analysis_child","Electron ASAR",input,"materialized_from_container","HIGH",false,false,"VALIDATED_EXACT_STRUCTURED_MEMBER");
}

void materialize_nested_executables(prts::AnalysisReport&report,const std::filesystem::path&input,const Options&opt,std::span<const std::uint8_t>data,std::uint64_t&extract_bytes_left,std::uint32_t&extract_files_left){
    if(opt.suppress_auto_materialization){report.materialization.partial=true;report.materialization.reasons.push_back("validated nested executable automatic materialization deferred by the directory aggregate artifact budget; rerun this file directly for its normal per-file materialization contract");return;}
    constexpr std::uint32_t kMaxCandidates=256;
    constexpr std::uint64_t kMaxOneChildBytes=64ull*1024*1024;
    constexpr std::uint64_t kMaxAggregateChildBytes=64ull*1024*1024;
    const auto aggregate_limit=std::min({kMaxAggregateChildBytes,opt.artifact_max_bytes,extract_bytes_left});
    const auto one_child_limit=kMaxOneChildBytes;
    std::uint32_t routed=0;std::uint64_t materialized_bytes=0;
    bool candidate_limit_noted=false;
    for(const auto&embedded:report.static_scan.embedded){
        if(embedded.offset==0||(embedded.kind!="PE"&&embedded.kind!="ELF"))continue;
        if(routed>=kMaxCandidates){
            if(!candidate_limit_noted){report.materialization.partial=true;report.materialization.reasons.push_back("Validated nested executable candidate validation stopped at the 256-candidate bound; no remaining MZ/ELF markers were carved or guessed");candidate_limit_noted=true;}
            break;
        }
        ++routed;
        prts::NestedExecutableLimits limits;limits.max_child_bytes=one_child_limit;
        auto nested=prts::validate_nested_executable(data,embedded.offset,embedded.kind,limits);
        auto finding=[&](){
            prts::Finding f;f.kind="artifact";f.family="Validated nested executable";f.variant=embedded.kind;f.fields["offset_space"]="current_input_file";f.fields["parent_sha256"]=report.input_snapshot.sha256;f.fields["parent_offset"]=std::to_string(embedded.offset);f.fields["format"]=nested.format;f.fields["architecture"]=nested.architecture;f.fields["endianness"]=nested.endianness;f.fields["machine"]=std::to_string(nested.machine);f.fields["validation_state"]=nested.validation_state;f.fields["relation"]="embedded_executable";f.fields["automatic_runtime_execution"]="false";if(nested.exact_size)f.fields["child_size"]=std::to_string(nested.exact_size);if(!nested.child_sha256.empty())f.fields["child_sha256"]=nested.child_sha256;return f;
        };
        if(!nested.valid){
            auto f=finding();f.state="LOCATED_NOT_MATERIALIZED";f.evidence.push_back("existing static MZ/ELF candidate routing reached the exact nested-image validator");f.negative_evidence.push_back(nested.error.empty()?"candidate did not close to one exact self-describing executable extent":nested.error);f.ranges.push_back(prts::file_offset_range(embedded.offset,std::min<std::uint64_t>(64,data.size()-static_cast<std::size_t>(embedded.offset)),embedded.kind+" candidate header",prts::CoordinateBasis::CURRENT_INPUT_FILE,prts::path_utf8(input)));report.findings.push_back(std::move(f));continue;
        }

        // Higher-level structured member provenance owns equal exact bytes. SHA equality
        // alone is insufficient: the selector independently checks provenance quality,
        // regular-file safety, current size, and a fresh SHA-256 before reuse.
        auto reuse_candidates=nested_reuse_candidates(report);auto reuse=prts::select_nested_executable_reuse(nested,reuse_candidates);
        if(reuse.reuse&&reuse.preferred_index<report.artifacts.size()){
            const auto parent_now=prts::sha256_file(input);auto f=finding();if(parent_now!=report.input_snapshot.sha256){f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="POST_VALIDATION_PARENT_CHANGED";f.fields["parent_unchanged"]="false";f.negative_evidence.push_back("parent SHA-256 changed before structured-member reuse");report.findings.push_back(std::move(f));continue;}
            auto&preferred=report.artifacts[reuse.preferred_index];const auto prior_priority=preferred.priority;if(reuse.priority_upgrade_required)preferred.priority="HIGH";
            f.state="CONFIRMED";f.fields["validation_state"]="VALIDATED_EXACT_REUSED";f.fields["parent_unchanged"]="true";f.fields["provenance_precedence"]="STRUCTURED_CONTAINER_MEMBER";f.fields["preferred_artifact_path"]=prts::path_utf8(preferred.path);f.fields["preferred_artifact_source"]=preferred.source;f.fields["preferred_relation"]=preferred.relation;f.fields["preferred_priority_before"]=prior_priority;f.fields["preferred_priority_after"]=preferred.priority;f.fields["structured_match_count"]=std::to_string(reuse.matching_indexes.size());f.fields["structured_match_paths"]=joined_structured_paths(report,reuse);f.fields["route_upgraded_to_high"]=reuse.priority_upgrade_required?"true":"false";
            f.evidence={"AP exact PE/ELF validation independently corroborated bytes already owned by a validated structured container member","structured member provenance supersedes raw embedded-carve provenance, so no second payload file was written","the preferred existing member is routed HIGH through the existing static artifact graph; nested runtime execution remains disabled"};f.ranges.push_back(prts::file_offset_range(nested.parent_offset,nested.exact_size,"validated embedded executable exact extent (structured member reused)",prts::CoordinateBasis::CURRENT_INPUT_FILE,prts::path_utf8(input)));report.findings.push_back(std::move(f));continue;
        }

        // A validated ASAR may exactly own the AP span even when AUTO_CORE policy did
        // not materialize that member (for example a nested executable under
        // node_modules). In that case the structured member takes over delivery.
        std::size_t asar_matches=0;const auto*asar_member=exact_unmaterialized_asar_member(report,nested,asar_matches);
        if(asar_matches>1){auto f=finding();f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="AMBIGUOUS_STRUCTURED_MEMBER_OWNERSHIP";f.fields["provenance_precedence"]="STRUCTURED_CONTAINER_MEMBER";f.negative_evidence.push_back("multiple validated ASAR member identities claim the exact AP span; no owner was guessed");report.findings.push_back(std::move(f));continue;}
        if(asar_member){
            auto f=finding();f.fields["provenance_precedence"]="STRUCTURED_CONTAINER_MEMBER";f.fields["preferred_artifact_source"]="Electron ASAR";f.fields["preferred_relation"]="materialized_from_container";f.fields["structured_member_path"]=asar_member->path;
            if(!extract_files_left||nested.exact_size>aggregate_limit-materialized_bytes){f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="VALIDATED_EXACT_STRUCTURED_MEMBER_BUDGET_REFUSED";f.negative_evidence.push_back(!extract_files_left?"recursive artifact file budget is exhausted":"aggregate nested-executable byte ceiling would be exceeded");report.findings.push_back(std::move(f));report.materialization.partial=true;report.materialization.omitted_count=sat_add(report.materialization.omitted_count,1);report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,nested.exact_size);continue;}
            const auto parent_before=prts::sha256_file(input);if(parent_before!=report.input_snapshot.sha256){f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="POST_VALIDATION_PARENT_CHANGED";f.fields["parent_unchanged"]="false";f.negative_evidence.push_back("parent SHA-256 changed before structured-member materialization");report.findings.push_back(std::move(f));continue;}
            prts::AsarExtractResult structured_extract;std::filesystem::path structured_path;std::string error;if(!materialize_exact_asar_member(report,data,nested,*asar_member,structured_extract,structured_path,error)){f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="VALIDATED_EXACT_STRUCTURED_MEMBER_WRITE_FAILED";f.negative_evidence.push_back(error);report.findings.push_back(std::move(f));continue;}
            const auto parent_now=prts::sha256_file(input);if(parent_now!=report.input_snapshot.sha256){std::error_code ec;std::filesystem::remove(structured_path,ec);f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="POST_WRITE_PROVENANCE_FAILED";f.fields["parent_unchanged"]="false";f.negative_evidence.push_back("parent SHA-256 changed during structured-member materialization");report.findings.push_back(std::move(f));continue;}
            commit_exact_asar_member(report,input,structured_extract,structured_path);f.state="CONFIRMED";f.fields["validation_state"]="VALIDATED_EXACT_SUPERSEDED_BY_STRUCTURED_MEMBER";f.fields["parent_unchanged"]="true";f.fields["preferred_artifact_path"]=prts::path_utf8(structured_path);f.fields["preferred_priority_after"]="HIGH";f.fields["route_upgraded_to_high"]="true";f.evidence={"AP exact span matches one complete validated ASAR member identity by absolute offset and size","the member was omitted only by ASAR AUTO_CORE policy, so Electron ASAR provenance took over bounded materialization","no opaque raw-carve payload was written; the structured member is routed HIGH for static child analysis"};f.ranges.push_back(prts::file_offset_range(nested.parent_offset,nested.exact_size,"validated embedded executable exact extent (ASAR member takeover)",prts::CoordinateBasis::CURRENT_INPUT_FILE,prts::path_utf8(input)));report.findings.push_back(std::move(f));materialized_bytes=sat_add(materialized_bytes,nested.exact_size);extract_bytes_left=nested.exact_size>extract_bytes_left?0:extract_bytes_left-nested.exact_size;--extract_files_left;continue;
        }

        if(!extract_files_left||nested.exact_size>aggregate_limit-materialized_bytes){
            auto f=finding();f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="VALIDATED_EXACT_BUDGET_REFUSED";f.evidence.push_back("candidate closed to one exact PE/ELF extent");f.negative_evidence.push_back(!extract_files_left?"recursive artifact file budget is exhausted":"aggregate nested-executable byte ceiling would be exceeded");f.ranges.push_back(prts::file_offset_range(nested.parent_offset,nested.exact_size,"validated embedded executable (not materialized)",prts::CoordinateBasis::CURRENT_INPUT_FILE,prts::path_utf8(input)));report.findings.push_back(std::move(f));report.materialization.partial=true;report.materialization.omitted_count=sat_add(report.materialization.omitted_count,1);report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,nested.exact_size);report.materialization.reasons.push_back("validated nested "+nested.format+" at parent offset "+std::to_string(nested.parent_offset)+" was not materialized by aggregate recursive artifact budget");continue;
        }
        std::ostringstream stem;stem<<(nested.format=="PE"?"pe":"elf")<<'-'<<std::hex<<std::setw(16)<<std::setfill('0')<<nested.parent_offset<<'-'<<nested.child_sha256.substr(0,16);
        const auto out=report.materialization.root/prts::path_from_utf8("static")/prts::path_from_utf8("nested-executable")/prts::path_from_utf8(stem.str()+(nested.format=="PE"?".exe":".elf"));
        auto f=finding();
        if(!prepare_artifact_targets(report,"Validated nested executable",{out})){f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="VALIDATED_EXACT_OUTPUT_REFUSED";f.evidence.push_back("candidate closed to one exact PE/ELF extent");f.negative_evidence.push_back("per-input artifact path safety gate refused the materialization target");report.findings.push_back(std::move(f));continue;}
        std::string error;if(!prts::materialize_nested_executable(data,nested,out,error)){f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="VALIDATED_EXACT_WRITE_FAILED";f.evidence.push_back("candidate closed to one exact PE/ELF extent");f.negative_evidence.push_back(error);report.findings.push_back(std::move(f));continue;}
        std::error_code ec;const auto written_size=std::filesystem::file_size(out,ec);const auto written_sha=ec?std::string{}:prts::sha256_file(out);
        const auto parent_now=prts::sha256_file(input);
        if(ec||written_size!=nested.exact_size||written_sha!=nested.child_sha256||parent_now!=report.input_snapshot.sha256){
            std::filesystem::remove(out,ec);f.state="LOCATED_NOT_MATERIALIZED";f.fields["validation_state"]="POST_WRITE_PROVENANCE_FAILED";f.fields["parent_unchanged"]=(parent_now==report.input_snapshot.sha256)?"true":"false";f.evidence.push_back("candidate closed to one exact PE/ELF extent");f.negative_evidence.push_back(parent_now!=report.input_snapshot.sha256?"parent SHA-256 changed during nested artifact materialization":"materialized child size/SHA-256 did not match the validated exact span");report.findings.push_back(std::move(f));continue;
        }
        f.state="CONFIRMED";f.fields["validation_state"]="VALIDATED_EXACT";f.fields["parent_unchanged"]="true";f.fields["output"]=prts::path_utf8(out);f.evidence={"self-describing executable header/table geometry closed to one unique file extent","only structurally declared file-backed bytes were materialized; arbitrary parent trailing bytes were not treated as PE/ELF overlay","materialized child registered HIGH for the existing static artifact graph; nested child execution remains disabled"};f.ranges.push_back(prts::file_offset_range(nested.parent_offset,nested.exact_size,"validated embedded executable exact extent",prts::CoordinateBasis::CURRENT_INPUT_FILE,prts::path_utf8(input)));report.findings.push_back(std::move(f));
        register_artifact_file(report,out,"embedded_executable","nested_executable","Validated nested "+nested.format,input,"embedded_executable","HIGH",false,false,"VALIDATED_EXACT");
        materialized_bytes=sat_add(materialized_bytes,nested.exact_size);extract_bytes_left=nested.exact_size>extract_bytes_left?0:extract_bytes_left-nested.exact_size;--extract_files_left;
    }
}
void note_auto_core_partial(prts::AnalysisReport&report,const std::string&family,std::uint64_t omitted_count,std::uint64_t omitted_bytes){
    if(!omitted_count&&!omitted_bytes)return;
    report.materialization.partial=true;
    report.materialization.omitted_count=sat_add(report.materialization.omitted_count,omitted_count);
    report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,omitted_bytes);
    report.materialization.reasons.push_back(family+" AUTO_CORE budget omitted "+std::to_string(omitted_count)+" artifact(s), "+std::to_string(omitted_bytes)+" bytes; --extract additionally requests full/bulk expansion");
}

void record_pyinstaller_materialization_finding(prts::AnalysisReport&report,const Options&opt){
    const auto&x=report.pyinstaller_extract;if(x.output_dir.empty())return;prts::Finding f;f.kind="artifact";f.family="PyInstaller automatic materialization";f.state=x.budget_exhausted?"PARTIAL":(x.success?"CONFIRMED":"FAILED");f.variant=x.mode==prts::PyInstExtractMode::AutoCore?"AUTO_CORE":"BULK_EXPLICIT";
    if(x.success)f.evidence.push_back(x.mode==prts::PyInstExtractMode::AutoCore?"validated CArchive automatically materialized reverse-ready Python user/bootstrap/PYZ artifacts under the per-input artifact root":"--extract materialized the complete supported PyInstaller container payload under the same per-input artifact root");
    if(x.user_files)f.evidence.push_back("high-priority top-level/PYZ user-code artifacts were materialized before lower-priority stdlib/runtime content");
    if(x.pyz_entry_count)f.evidence.push_back("PYZ module inventory was parsed before priority-ordered materialization; bounded selection is not alphabetical");
    if(x.budget_exhausted)f.negative_evidence.push_back("AUTO_MATERIALIZATION_PARTIAL: byte/file budget omitted one or more lower-priority artifacts");
    if(!x.error.empty())f.negative_evidence.push_back(x.error);
    f.fields["mode"]=x.mode==prts::PyInstExtractMode::AutoCore?"AUTO_CORE":"BULK_EXPLICIT";f.fields["output_dir"]=prts::path_utf8(x.output_dir);f.fields["files"]=std::to_string(x.files.size());f.fields["bytes"]=std::to_string(x.output_bytes);f.fields["user_files"]=std::to_string(x.user_files);f.fields["bootstrap_files"]=std::to_string(x.bootstrap_files);f.fields["runtime_files"]=std::to_string(x.runtime_files);f.fields["bulk_files"]=std::to_string(x.bulk_files);f.fields["pyz_entries"]=std::to_string(x.pyz_entry_count);f.fields["pyz_selected"]=std::to_string(x.pyz_selected_count);f.fields["omitted_count"]=std::to_string(x.omitted_count);f.fields["omitted_bytes"]=std::to_string(x.omitted_bytes);f.fields["bulk_explicit_count"]=std::to_string(x.policy_omitted_count);f.fields["bulk_explicit_bytes"]=std::to_string(x.policy_omitted_bytes);if(!x.carchive_inventory.empty())f.fields["carchive_inventory"]=prts::path_utf8(x.carchive_inventory);if(!x.pyz_inventory.empty())f.fields["pyz_inventory"]=prts::path_utf8(x.pyz_inventory);
    if(!opt.extract&&x.policy_omitted_count)f.suggested_actions.push_back("use --extract only if complete/bulk PyInstaller runtime/data expansion is also needed");
    report.findings.push_back(std::move(f));
}

void materialize_pyinstaller(prts::AnalysisReport&report,const std::filesystem::path&input,const Options&opt,std::span<const std::uint8_t>data,const prts::CPythonInfo*cp,std::uint64_t max_bytes,std::uint32_t max_files,prts::PyInstExtractMode mode){
    if(!opt.extract&&opt.suppress_auto_materialization){report.materialization.partial=true;report.materialization.reasons.push_back("PyInstaller AUTO_CORE materialization deferred by the directory aggregate artifact budget; rerun this file directly for its normal per-file materialization contract");return;}
    auto out=report.materialization.root/prts::path_from_utf8("static")/prts::path_from_utf8("pyinstaller");std::string why;if(!ensure_artifact_subdirectory(report.materialization.root,out,why)){prts::Finding f;f.kind="artifact";f.family="PyInstaller automatic materialization";f.state="FAILED";f.negative_evidence.push_back(why);report.findings.push_back(std::move(f));return;}
    report.pyinstaller_extract=prts::extract_pyinstaller(data,report.pyinstaller,out,cp,max_bytes,max_files,mode);
    if(mode==prts::PyInstExtractMode::AutoCore&&report.pyinstaller_extract.budget_exhausted){report.materialization.partial=true;report.materialization.omitted_count=sat_add(report.materialization.omitted_count,report.pyinstaller_extract.omitted_count);report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,report.pyinstaller_extract.omitted_bytes);report.materialization.reasons.push_back("PyInstaller AUTO_CORE budget omitted "+std::to_string(report.pyinstaller_extract.omitted_count)+" artifact(s); --extract additionally requests full/bulk expansion");}
    record_pyinstaller_materialization_finding(report,opt);
    (void)input;
}


void integrate_validated_static_repair(prts::AnalysisReport&report,const std::filesystem::path&input,const Options&opt,std::span<const std::uint8_t>data,bool upx_candidate){
    if(!upx_candidate||!report.pe.valid)return;
    auto proposal=prts::assess_upx_metadata_repair(input,data,report.pe);
    if(proposal.state!=prts::RepairState::Validated)return;
    if(!opt.extract&&opt.suppress_auto_materialization){report.materialization.partial=true;report.materialization.omitted_count=sat_add(report.materialization.omitted_count,1);report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,report.input_snapshot.size);report.materialization.reasons.push_back("validated static repair artifact deferred by the directory aggregate artifact budget; rerun this file directly for its normal per-file materialization contract");return;}
    auto out=report.materialization.root/prts::path_from_utf8("static")/prts::path_from_utf8("repair");
    std::string why;
    prts::Finding f;f.kind="artifact";f.family="Validated static repair";f.variant=proposal.mechanism;
    f.fields["repair_class"]=std::string(prts::to_string(proposal.repair_class));
    f.fields["repair_state"]=std::string(prts::to_string(proposal.state));
    f.fields["semantic_scope"]=proposal.semantic_scope;
    f.fields["evidence_ceiling"]=std::string(prts::repair_evidence_level_name(proposal.evidence_ceiling));
    f.fields["changed_range_count"]=std::to_string(proposal.changed_ranges.size());
    f.fields["automatic_runtime_execution_eligible"]="false";
    for(const auto&e:proposal.evidence)f.evidence.push_back(e);
    for(const auto&r:proposal.changed_ranges)f.ranges.push_back(prts::file_offset_range(r.file_offset,r.before_bytes.size(),"validated repair range: "+r.reason,prts::CoordinateBasis::CURRENT_INPUT_FILE,prts::path_utf8(input)));
    if(!ensure_artifact_subdirectory(report.materialization.root,out,why)){
        f.state="FAILED";f.negative_evidence.push_back(why);report.findings.push_back(std::move(f));return;
    }
    if(!prts::materialize_validated_repair(proposal,data,out)){
        f.state="FAILED";f.negative_evidence.push_back(proposal.materialization_error.empty()?"validated repair artifact could not be materialized":proposal.materialization_error);report.findings.push_back(std::move(f));return;
    }
    f.state="CONFIRMED";
    f.evidence.push_back("strict R1 metadata repair was materialized non-destructively; the parent SHA-256 was rechecked unchanged before admission");
    f.evidence.push_back("the derived artifact is admitted only for static child analysis; automatic runtime execution remains forbidden");
    f.fields["result_path"]=prts::path_utf8(proposal.result_path);f.fields["result_sha256"]=proposal.result_sha256;
    f.fields["provenance_path"]=prts::path_utf8(proposal.provenance_path);f.fields["original_unchanged"]=proposal.original_unchanged?"true":"false";
    f.fields["static_reanalysis_eligible"]=proposal.static_reanalysis_eligible?"true":"false";
    register_artifact_file(report,proposal.result_path,"repaired_image","validated_repair","Validated repair",input,"repaired_from","HIGH",true,false,"VALIDATED_REPAIR");
    register_artifact_file(report,proposal.provenance_path,"repair_provenance","analysis_map","Validated repair",proposal.result_path,"analysis_of","ANALYSIS",true,false,"MATERIALIZED");
    report.findings.push_back(std::move(f));
    (void)opt;
}

void register_pyinstaller_artifacts(prts::AnalysisReport&report,const std::filesystem::path&input){
    for(const auto&m:report.pyinstaller_extract.materialized){std::string kind="pyinstaller_member";if(m.role=="user"||m.role=="pyz_user")kind="python_bytecode";else if(m.role=="bootstrap"||m.role=="pyz_bootstrap")kind="python_bootstrap";else if(m.role=="runtime_hook")kind="python_runtime_hook";else if(m.role=="pyz_archive")kind="pyinstaller_pyz";else if(m.role=="inventory")kind="inventory";else if(m.role=="runtime_binary")kind="python_runtime_binary";register_artifact_file(report,m.path,kind,m.role,"PyInstaller",input,"materialized_from_carchive",m.priority,m.normalized,false,m.normalized?"MATERIALIZED_NORMALIZED":"MATERIALIZED");}
}
void register_container_artifacts(prts::AnalysisReport&report,const std::filesystem::path&input){
    auto lower=[](std::string x){std::transform(x.begin(),x.end(),x.begin(),[](unsigned char c){return char(std::tolower(c));});return x;};
    auto reltext=[&](const std::filesystem::path&p,const std::filesystem::path&root){auto r=p.lexically_normal().lexically_relative(root.lexically_normal());return lower(prts::path_utf8(r));};
    auto add=[&](const std::filesystem::path&p,std::string kind,std::string role,std::string source,std::string priority){register_artifact_file(report,p,std::move(kind),std::move(role),std::move(source),input,"materialized_from_container",std::move(priority));};
    for(const auto&p:report.renpy_rpa_extract.files){auto r=reltext(p,report.renpy_rpa_extract.output_dir);const bool code=r.ends_with(".rpyc")||r.ends_with(".rpymc")||r.ends_with(".rpy");add(p,"renpy_rpa_member",code?"user_script":"container_member","Ren'Py RPA",code?"HIGH":"BULK");}
    if(report.renpy_extract.success)add(report.renpy_extract.pickle_path,"renpy_rpyc_pickle","decoded_script_data","Ren'Py RPYC","HIGH");
    for(const auto&p:report.wxapkg_extract.files){auto r=reltext(p,report.wxapkg_extract.output_dir);const bool code=r.ends_with(".js")||r.ends_with(".wxs")||r.ends_with(".wxml")||r.ends_with(".wxss")||r.ends_with(".json");add(p,"wxapkg_member",code?"app_code":"container_member","wxapkg",code?"HIGH":"BULK");}
    for(const auto&p:report.asar_extract.files){auto r=prts::path_utf8(p.lexically_normal().lexically_relative(report.asar_extract.output_dir.lexically_normal()));const bool interesting=std::find(report.asar.interesting_paths.begin(),report.asar.interesting_paths.end(),r)!=report.asar.interesting_paths.end();add(p,"asar_member",interesting?"app_code":"container_member","Electron ASAR",interesting?"HIGH":"BULK");}
    for(const auto&p:report.autoit_extract.files){auto r=reltext(p,report.autoit_extract.output_dir);const bool code=r=="script.au3"||r=="script.tok";add(p,"autoit_member",code?"user_script":"container_member","AutoIt",code?"HIGH":"BULK");}
    std::set<std::string>apk_unity_metadata;for(const auto&e:report.apk.entries)if(e.unity_il2cpp_metadata_valid&&!e.normalized_name.empty())apk_unity_metadata.insert(lower(e.normalized_name));
    for(const auto&p:report.apk_extract.files){auto r=reltext(p,report.apk_extract.output_dir);const bool unity_metadata=apk_unity_metadata.count(r)!=0;const bool code=r.ends_with(".dex")||r.ends_with(".so")||r.ends_with(".wasm")||r.ends_with(".jar")||r.ends_with(".zip")||unity_metadata;const bool manifest=r=="androidmanifest.xml";add(p,unity_metadata?"unity_il2cpp_metadata":"apk_member",unity_metadata?"il2cpp_metadata":(code?"analysis_child":(manifest?"manifest":"container_member")),"Android APK",code?"HIGH":(manifest?"ANALYSIS":"BULK"));}
    for(const auto&p:report.jar_extract.files){auto r=reltext(p,report.jar_extract.output_dir);const bool code=r.ends_with(".class")||r.ends_with(".jar")||r.ends_with(".zip");const bool manifest=r=="meta-inf/manifest.mf";add(p,"jar_member",code?"analysis_child":(manifest?"manifest":"container_member"),"Java/JVM archive",code?"HIGH":(manifest?"ANALYSIS":"BULK"));}
    for(const auto&p:report.nuitka_extract.files){auto r=reltext(p,report.nuitka_extract.output_dir);const bool main=r=="main.bin"||r=="__main__.bin"||r.ends_with(".exe");const bool map=r.ends_with(".nuitka-const.txt");add(p,"nuitka_member",main?"main_payload":(map?"analysis_map":"container_member"),"Nuitka",main?"HIGH":(map?"ANALYSIS":"BULK"));}
    std::set<std::string>godot_validated_native;for(const auto&b:report.godot.gdextensions)for(const auto&l:b.libraries)if(l.child_validated&&!l.matched_child_path.empty()){auto q=lower(l.matched_child_path);if(q.rfind("res://",0)==0)q.erase(0,6);godot_validated_native.insert(q);}
    for(const auto&p:report.godot_extract.files){auto r=reltext(p,report.godot_extract.output_dir);const bool code=r.ends_with(".gdc")||r.ends_with(".gd")||r.ends_with(".gdextension")||r=="project.binary"||r=="project.godot";const bool native=godot_validated_native.count(r)!=0;add(p,"godot_member",native?"native_extension":(code?"script_or_project":"container_member"),"Godot PCK",(code||native)?"HIGH":"BULK");if(r.ends_with(".gdc"))for(const auto*suf:{".godot-script-info.json",".godot-identifiers.csv",".godot-constants.csv",".godot-lines.csv",".godot-tokens.csv"}){auto q=prts::path_with_ascii_suffix(p,suf);register_artifact_file(report,q,"gdscript_analysis","analysis_map","Godot GDScript",p,"analysis_of","ANALYSIS");}}
}

void integrate_apk_godot2_direct_assets(prts::AnalysisReport&report){
    if(!report.apk.valid||!report.apk_extract.success||report.apk_extract.output_dir.empty()||!report.apk.godot_legacy_config.valid)return;
    auto artifact_for=[&](const std::filesystem::path&p)->prts::AnalysisArtifact*{for(auto&a:report.artifacts)if(same_regular_file(a.path,p))return &a;return nullptr;};
    const prts::ApkEntryInfo*config_entry=nullptr;
    for(const auto&e:report.apk.entries)if(e.godot_legacy_engine_config_candidate&&e.godot_legacy_engine_config_valid&&!e.duplicate_path&&e.safe_path&&!e.symlink&&!e.encrypted&&e.supported){if(config_entry){config_entry=nullptr;break;}config_entry=&e;}
    if(!config_entry)return;
    const auto config_path=report.apk_extract.output_dir/prts::path_from_utf8(config_entry->normalized_name);auto*config_artifact=artifact_for(config_path);
    prts::Finding f;f.kind="artifact_relationship";f.family="Godot 2.x Android direct assets";f.fields["application_name"]=report.apk.godot_legacy_config.application_name;f.fields["main_scene"]=report.apk.godot_legacy_config.main_scene;f.fields["remap_count"]=std::to_string(report.apk.godot_legacy_config.remaps.size());f.fields["autoload_count"]=std::to_string(report.apk.godot_legacy_config.autoloads.size());f.fields["legacy_gdscript_semantics"]="SEPARATE_STATIC_CHILD_ANALYSIS";
    if(!config_artifact){f.state="PARTIAL";f.negative_evidence.push_back("validated canonical assets/engine.cfb was not materialized under the current APK analysis budget");report.findings.push_back(std::move(f));return;}
    config_artifact->kind="godot_legacy_engine_config";config_artifact->role="godot_project_config";config_artifact->priority="HIGH";
    std::map<std::string,std::string>remap;for(const auto&r:report.apk.godot_legacy_config.remaps)remap.emplace(r.source,r.target);
    auto resolve=[&](const std::string&source){auto it=remap.find(source);return it==remap.end()?source:it->second;};
    auto asset_name=[&](const std::string&resource)->std::string{if(resource.rfind("res://",0)!=0)return{};return "assets/"+resource.substr(6);};
    auto exact_entry=[&](const std::string&name)->const prts::ApkEntryInfo*{const prts::ApkEntryInfo*hit=nullptr;for(const auto&e:report.apk.entries){if(e.normalized_name!=name||e.duplicate_path||!e.safe_path||e.symlink||e.encrypted||!e.supported)continue;if(hit)return nullptr;hit=&e;}return hit;};
    auto add_relation=[&](const std::string&kind,const std::string&role,const std::string&source_key,const std::string&source_resource,const std::string&target_resource,const prts::ApkEntryInfo&target,const std::filesystem::path&target_path,const std::string&reason){
        prts::ArtifactRelationship x;x.first=config_path;x.second=target_path;x.directed=true;x.kind=kind;x.state="CONFIRMED";x.first_role="godot_project_config";x.second_role=role;x.first_relation_role="resource_reference_source";x.second_relation_role="resource_reference_target";
        x.evidence_basis="validated Godot 2.x ECFG "+source_key+" exact res:// reference"+(source_resource==target_resource?std::string{}:" plus exact remap/all source->target mapping")+" closes to one safe non-duplicate APK asset member under the canonical Android res:// -> assets/ export/read mapping";
        x.evidence_source="Godot 2.x ECFG parser + APK central/local member integrity + canonical Godot 2.1.5 Android asset mapping";
        x.source_coordinate="APK_member:"+config_entry->normalized_name+";central_directory_offset="+std::to_string(config_entry->central_directory_offset)+";ECFG:"+source_key+"="+source_resource+(source_resource==target_resource?std::string{}:";remap_target="+target_resource);
        x.target_coordinate="APK_member:"+target.normalized_name+";central_directory_offset="+std::to_string(target.central_directory_offset)+";local_header_offset="+std::to_string(target.local_header_offset);
        x.provenance_scope="same validated APK; exact Godot 2.x startup-resource dependency only; target RSRC/GDSC semantics are not claimed unless their independent parsers validate";x.evidence_level="R3_EXACT_DATA_DEPENDENCY";x.ambiguity="NONE";x.semantic_relevance="DATA_DEPENDENCY";x.priority_eligible=false;x.reason=reason;
        report.artifact_relationships.push_back(std::move(x));
    };
    std::size_t main_relations=0,autoload_relations=0,autoload_missing=0;
    const auto main_target_resource=resolve(report.apk.godot_legacy_config.main_scene);const auto main_asset=asset_name(main_target_resource);const auto*main_entry=exact_entry(main_asset);
    if(main_entry){auto main_path=report.apk_extract.output_dir/prts::path_from_utf8(main_entry->normalized_name);if(auto*ma=artifact_for(main_path)){ma->kind="godot_legacy_resource";ma->role="godot_main_scene";ma->priority="HIGH";add_relation("godot2_android_main_scene","godot_main_scene","application/main_scene",report.apk.godot_legacy_config.main_scene,main_target_resource,*main_entry,main_path,"validated Godot project config selects this exact startup scene asset");++main_relations;f.fields["resolved_main_scene_member"]=main_entry->normalized_name;}}
    for(const auto&a:report.apk.godot_legacy_config.autoloads){const auto target_resource=resolve(a.path);const auto target_asset=asset_name(target_resource);const auto*entry=exact_entry(target_asset);if(!entry){++autoload_missing;continue;}auto target_path=report.apk_extract.output_dir/prts::path_from_utf8(entry->normalized_name);auto*aa=artifact_for(target_path);if(!aa){++autoload_missing;continue;}aa->kind="godot_legacy_script";aa->role="godot_autoload_script";aa->priority="HIGH";add_relation("godot2_android_autoload","godot_autoload_script","autoload/"+a.name,a.path,target_resource,*entry,target_path,"validated Godot autoload configuration selects this exact packaged script asset");++autoload_relations;}
    f.fields["main_scene_relations"]=std::to_string(main_relations);f.fields["autoload_relations"]=std::to_string(autoload_relations);f.fields["autoload_unresolved"]=std::to_string(autoload_missing);
    if(main_relations==1&&autoload_missing==0){f.state="CONFIRMED";f.evidence={"canonical assets/engine.cfb passed bounded Godot 2.x ECFG property/Variant validation","application/main_scene closed through exact remap/all and the canonical Android res:// -> assets/ mapping to one APK member","every configured autoload closed to one exact packaged target under the same mapping"};f.negative_evidence.push_back("exact .gdc delivery does not itself imply script semantics or source decompilation; the delivered child is analyzed independently by the versioned GDScript parser");}
    else{f.state="PARTIAL";if(!main_relations)f.negative_evidence.push_back("configured main_scene/remap target did not close to one materialized safe APK member");if(autoload_missing)f.negative_evidence.push_back(std::to_string(autoload_missing)+" configured autoload target(s) did not close uniquely under the current package/budget");}
    report.findings.push_back(std::move(f));
}

void integrate_apk_unity_il2cpp_delivery(prts::AnalysisReport&report){
    if(!report.apk.valid||!report.apk_extract.success||report.apk_extract.output_dir.empty())return;
    auto lower=[](std::string x){std::transform(x.begin(),x.end(),x.begin(),[](unsigned char c){return char(std::tolower(c));});return x;};
    auto basename=[](const std::string&s){auto p=s.find_last_of("/\\");return p==std::string::npos?s:s.substr(p+1);};
    std::vector<const prts::ApkEntryInfo*>metadata,natives;
    for(const auto&e:report.apk.entries){
        if(e.duplicate_path||!e.safe_path||e.symlink||e.encrypted||!e.supported)continue;
        if(e.unity_il2cpp_metadata_valid)metadata.push_back(&e);
        if(e.native_library&&e.native_elf&&e.native_deep_state=="ELF_VALID"&&e.native_abi_consistent_known&&e.native_abi_consistent&&lower(basename(e.normalized_name))=="libil2cpp.so")natives.push_back(&e);
    }
    if(metadata.empty()&&!report.apk.unity_il2cpp_metadata_parse_budget_exhausted)return;
    prts::Finding f;f.kind="artifact_relationship";f.family="Unity IL2CPP APK delivery";f.fields["metadata_candidates"]=std::to_string(metadata.size());f.fields["native_candidates"]=std::to_string(natives.size());f.fields["registration_state"]="UNRESOLVED";
    if(report.apk.unity_il2cpp_metadata_parse_budget_exhausted){f.state="UNRESOLVED";f.negative_evidence.push_back("IL2CPP metadata candidate parse budget was exhausted; unparsed candidates prevent endpoint uniqueness from being established");report.findings.push_back(std::move(f));return;}
    if(metadata.size()!=1){f.state="UNRESOLVED";f.negative_evidence.push_back("multiple independently validated IL2CPP metadata members exist in the same APK; no unique metadata endpoint is selected");report.findings.push_back(std::move(f));return;}
    const auto*md=metadata.front();auto mdpath=report.apk_extract.output_dir/prts::path_from_utf8(md->normalized_name);
    auto artifact_for=[&](const std::filesystem::path&p)->prts::AnalysisArtifact*{for(auto&a:report.artifacts)if(same_regular_file(a.path,p))return &a;return nullptr;};
    auto*ma=artifact_for(mdpath);if(!ma){f.state="PARTIAL";f.negative_evidence.push_back("validated IL2CPP metadata member was not materialized under the current APK analysis budget");report.findings.push_back(std::move(f));return;}
    ma->kind="unity_il2cpp_metadata";ma->role="il2cpp_metadata";ma->priority="HIGH";
    std::size_t related=0;std::set<std::string>abis;
    for(const auto*n:natives){
        auto np=report.apk_extract.output_dir/prts::path_from_utf8(n->normalized_name);auto*na=artifact_for(np);if(!na)continue;
        na->role="il2cpp_runtime";na->priority="HIGH";abis.insert(n->abi);
        prts::ArtifactRelationship x;x.first=mdpath;x.second=np;x.directed=false;x.kind="unity_il2cpp_apk_delivery_pair";x.state="CONFIRMED";x.first_role="il2cpp_metadata";x.second_role="il2cpp_runtime";x.first_relation_role="validated_package_member";x.second_relation_role="validated_package_member";
        x.evidence_basis="one structurally validated IL2CPP global-metadata member and one validated ABI-consistent ELF libil2cpp.so are exact members of the same validated APK";x.evidence_source="APK central-directory/local-header integrity + Unity IL2CPP metadata parser + ELF/ABI validation";
        x.source_coordinate="APK_member:"+md->normalized_name+";central_directory_offset="+std::to_string(md->central_directory_offset)+";local_header_offset="+std::to_string(md->local_header_offset);
        x.target_coordinate="APK_member:"+n->normalized_name+";central_directory_offset="+std::to_string(n->central_directory_offset)+";local_header_offset="+std::to_string(n->local_header_offset)+";abi="+n->abi;
        x.provenance_scope="same validated APK delivery package; confirms a structural IL2CPP metadata/runtime pair only; CodeRegistration, MetadataRegistration and managed-method-to-native mapping remain unresolved unless independently proven";
        x.evidence_level="R2_STRUCTURAL_RELATION";x.ambiguity="NONE";x.semantic_relevance="STRUCTURAL";x.priority_eligible=false;x.reason="validated APK packaging closes a Unity IL2CPP delivery pair without claiming registration semantics";
        bool duplicate=false;for(const auto&prior:report.artifact_relationships)if(prior.kind==x.kind&&((same_regular_file(prior.first,x.first)&&same_regular_file(prior.second,x.second))||(same_regular_file(prior.first,x.second)&&same_regular_file(prior.second,x.first)))){duplicate=true;break;}
        if(!duplicate){report.artifact_relationships.push_back(std::move(x));++related;}
    }
    f.fields["metadata_member"]=md->normalized_name;f.fields["metadata_version"]=std::to_string(md->unity_il2cpp_metadata_version);f.fields["metadata_layout"]=md->unity_il2cpp_metadata_layout;f.fields["delivery_relation_count"]=std::to_string(related);
    std::string abi_text;for(const auto&a:abis){if(!abi_text.empty())abi_text+=',';abi_text+=a;}f.fields["native_abis"]=abi_text;
    if(related){f.state="CONFIRMED";f.evidence={"global-metadata.dat passed the existing Unity IL2CPP metadata parser before child admission","lib/<abi>/libil2cpp.so passed APK member integrity, ELF parsing and ABI-consistency validation","both endpoints are exact materialized members of the same validated APK"};f.negative_evidence.push_back("delivery pairing does not establish CodeRegistration or managed MethodDef native RVAs");}
    else{f.state="PARTIAL";f.negative_evidence.push_back("validated IL2CPP metadata is present, but no materialized ABI-consistent ELF libil2cpp.so endpoint closed under the current evidence/budget");}
    report.findings.push_back(std::move(f));
}

std::vector<std::size_t> bounded_exact_ascii_offsets(std::span<const std::uint8_t>d,std::string_view needle,std::size_t cap=2){
    std::vector<std::size_t> hits;if(needle.empty()||d.size()<needle.size())return hits;
    std::size_t pos=0;auto hex=[](unsigned char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');};
    while(pos+needle.size()<=d.size()&&hits.size()<cap){
        auto it=std::search(d.begin()+static_cast<std::ptrdiff_t>(pos),d.end(),needle.begin(),needle.end());if(it==d.end())break;
        auto off=static_cast<std::size_t>(it-d.begin());const bool left=off==0||!hex(d[off-1]);const bool right=off+needle.size()==d.size()||!hex(d[off+needle.size()]);if(left&&right)hits.push_back(off);pos=off+1;
    }return hits;
}

bool bytes_contain_ascii(std::span<const std::uint8_t>d,std::string_view needle){return !needle.empty()&&d.size()>=needle.size()&&std::search(d.begin(),d.end(),needle.begin(),needle.end())!=d.end();}

void integrate_apk_flutter_aot_delivery(prts::AnalysisReport&report){
    if(!report.apk.valid||!report.apk_extract.success||report.apk_extract.output_dir.empty())return;
    auto lower=[](std::string x){std::transform(x.begin(),x.end(),x.begin(),[](unsigned char c){return char(std::tolower(c));});return x;};
    auto leaf=[](const std::string&s){auto p=s.find_last_of("/\\");return p==std::string::npos?s:s.substr(p+1);};
    auto artifact_for=[&](const std::filesystem::path&p)->prts::AnalysisArtifact*{for(auto&a:report.artifacts)if(same_regular_file(a.path,p))return &a;return nullptr;};
    std::map<std::string,const prts::ApkEntryInfo*>apps,engines;
    const prts::ApkEntryInfo*manifest_entry=nullptr;std::size_t manifest_candidates=0;
    for(const auto&e:report.apk.entries){
        if(e.duplicate_path||!e.safe_path||e.symlink||e.encrypted||!e.supported)continue;
        auto low=lower(e.normalized_name);
        if(low=="assets/flutter_assets/assetmanifest.bin"){manifest_entry=&e;++manifest_candidates;continue;}
        if(!e.native_library||!e.native_elf||e.native_deep_state!="ELF_VALID"||!e.native_abi_consistent_known||!e.native_abi_consistent)continue;
        auto name=lower(leaf(low));if(name=="libapp.so")apps.emplace(e.abi,&e);else if(name=="libflutter.so")engines.emplace(e.abi,&e);
    }
    if(apps.empty()&&engines.empty()&&!manifest_entry)return;
    prts::Finding f;f.kind="artifact_relationship";f.family="Flutter APK AOT delivery";f.fields["app_candidates"]=std::to_string(apps.size());f.fields["engine_candidates"]=std::to_string(engines.size());f.fields["asset_manifest_candidates"]=std::to_string(manifest_candidates);
    std::size_t compatible=0,manifest_relations=0,structural_apps=0;std::set<std::string>abis,hashes;bool hash_mismatch=false,engine_marker_failure=false;
    for(const auto&[abi,ae]:apps){
        auto ai=engines.find(abi);if(ai==engines.end())continue;const auto*ee=ai->second;
        auto ap=report.apk_extract.output_dir/prts::path_from_utf8(ae->normalized_name);auto ep=report.apk_extract.output_dir/prts::path_from_utf8(ee->normalized_name);auto*aa=artifact_for(ap);auto*ea=artifact_for(ep);if(!aa||!ea)continue;
        prts::MappedFile am(ap),em(ep);if(!am.valid()||!em.valid())continue;auto aelf=prts::parse_elf(am.bytes());auto eelf=prts::parse_elf(em.bytes());if(!aelf.valid||!eelf.valid)continue;
        auto dart=prts::detect_dart(am.bytes(),aelf);if(!dart.valid||!dart.aot.valid||!dart.aot.flutter_symbols)continue;
        std::set<std::string>local_hashes;for(const auto&snap:dart.aot.snapshots)if(snap.valid&&!snap.snapshot_hash.empty())local_hashes.insert(snap.snapshot_hash);
        if(local_hashes.size()!=1)continue;
        ++structural_apps;const auto hash=*local_hashes.begin();
        const bool engine_markers=bytes_contain_ascii(em.bytes(),"Dart_Initialize")&&bytes_contain_ascii(em.bytes(),"FlutterEngine")&&bytes_contain_ascii(em.bytes(),"flutter/shell/platform/android");
        if(!engine_markers){engine_marker_failure=true;continue;}auto hash_hits=bounded_exact_ascii_offsets(em.bytes(),hash,2);if(hash_hits.size()!=1){hash_mismatch=true;continue;}
        aa->kind="dart_aot_app";aa->role="dart_aot_app";aa->priority="HIGH";ea->kind="flutter_engine";ea->role="flutter_engine";ea->priority="HIGH";abis.insert(abi);hashes.insert(hash);
        prts::ArtifactRelationship x;x.first=ep;x.second=ap;x.directed=true;x.kind="flutter_engine_snapshot_compatibility";x.state="CONFIRMED";x.first_role="flutter_engine";x.second_role="dart_aot_app";x.first_relation_role="snapshot_version_consumer";x.second_relation_role="snapshot_version_provider";
        x.evidence_basis="validated same-ABI Flutter engine ELF contains exactly one boundary-delimited copy of the exact 32-byte Dart snapshot version hash recovered independently from the structurally validated libapp.so VM/isolate data snapshots";x.evidence_source="APK member integrity + ELF dynamic-symbol/load-segment validation + Dart snapshot parser + exact engine byte dependency";
        x.source_coordinate="APK_member:"+ee->normalized_name+";engine_file_offset="+std::to_string(hash_hits.front())+";engine_snapshot_hash="+hash;x.target_coordinate="APK_member:"+ae->normalized_name+";dart_snapshot_hash="+hash;
        x.provenance_scope="same validated APK and ABI="+abi+"; confirms exact engine/app snapshot-version compatibility and AOT delivery identity only; it does not deserialize Dart heap objects or execute the app";x.evidence_level="R3_EXACT_DATA_DEPENDENCY";x.ambiguity="NONE";x.semantic_relevance="DATA_DEPENDENCY";x.priority_eligible=false;x.reason="Flutter engine embeds the exact snapshot compatibility hash required by this structurally validated Dart AOT app payload";
        report.artifact_relationships.push_back(std::move(x));++compatible;
    }
    prts::FlutterAssetManifestInfo manifest;
    std::filesystem::path mp;
    if(manifest_entry&&manifest_candidates==1){mp=report.apk_extract.output_dir/prts::path_from_utf8(manifest_entry->normalized_name);if(auto*ma=artifact_for(mp)){prts::MappedFile mm(mp);if(mm.valid()){manifest=prts::parse_flutter_asset_manifest(mm.bytes());if(manifest.valid&&manifest.nonempty){ma->kind="flutter_asset_manifest";ma->role="flutter_asset_manifest";ma->priority="HIGH";for(const auto&[abi,ae]:apps){auto ap=report.apk_extract.output_dir/prts::path_from_utf8(ae->normalized_name);auto*aa=artifact_for(ap);if(!aa||aa->role!="dart_aot_app")continue;prts::ArtifactRelationship x;x.first=ap;x.second=mp;x.directed=false;x.kind="flutter_apk_asset_delivery";x.state="CONFIRMED";x.first_role="dart_aot_app";x.second_role="flutter_asset_manifest";x.first_relation_role="validated_package_member";x.second_relation_role="validated_package_member";x.evidence_basis="structurally validated Flutter Dart AOT app member and non-empty StandardMessageCodec AssetManifest.bin are exact canonical members of the same validated APK";x.evidence_source="APK member integrity + Dart AOT parser + Flutter AssetManifest codec/schema parser";x.source_coordinate="APK_member:"+ae->normalized_name;x.target_coordinate="APK_member:"+manifest_entry->normalized_name;x.provenance_scope="same validated APK delivery package; structural asset-delivery relation only";x.evidence_level="R2_STRUCTURAL_RELATION";x.ambiguity="NONE";x.semantic_relevance="STRUCTURAL";x.priority_eligible=false;x.reason="validated canonical Flutter app and asset manifest are co-delivered by the same APK";report.artifact_relationships.push_back(std::move(x));++manifest_relations;}}}}
    }
    f.fields["compatible_app_engine_pairs"]=std::to_string(compatible);f.fields["structural_app_payloads"]=std::to_string(structural_apps);f.fields["asset_manifest_state"]=(manifest.valid&&manifest.nonempty)?"CONFIRMED":(manifest.candidate?"UNRESOLVED":"ABSENT");f.fields["asset_manifest_relations"]=std::to_string(manifest_relations);
    std::string abi_text;for(const auto&a:abis){if(!abi_text.empty())abi_text+=',';abi_text+=a;}f.fields["validated_abis"]=abi_text;std::string hash_text;for(const auto&h:hashes){if(!hash_text.empty())hash_text+=',';hash_text+=h;}f.fields["snapshot_hashes"]=hash_text;
    if(compatible){f.state="CONFIRMED";f.evidence={"libapp.so exposes complete loader-visible Flutter Dart snapshot pairs whose read-only data snapshots and executable instruction spans validate","same-ABI libflutter.so independently validates as ELF and contains the exact app snapshot compatibility hash once, alongside independent Flutter/Dart engine markers","all related endpoints are exact materialized members of the same validated APK"};if(manifest.valid&&manifest.nonempty)f.evidence.push_back("canonical AssetManifest.bin independently passes bounded StandardMessageCodec and Flutter asset-schema validation");f.negative_evidence.push_back("snapshot compatibility/delivery confirmation does not imply deep Dart object, class, or function deserialization");}
    else{f.state=structural_apps?"PARTIAL":"UNRESOLVED";if(hash_mismatch)f.negative_evidence.push_back("Flutter engine/app snapshot hash dependency did not close uniquely");if(engine_marker_failure)f.negative_evidence.push_back("candidate libflutter.so lacked the bounded independent Flutter/Dart engine marker set");if(!structural_apps)f.negative_evidence.push_back("no same-ABI structurally validated Flutter Dart AOT app payload was available under the current extraction budget");}
    report.findings.push_back(std::move(f));
}

void cleanup_empty_container_outputs(const prts::AnalysisReport&report){
    static constexpr std::string_view leaves[]={"renpy/rpa","renpy/rpyc","wxapkg","asar","autoit","apk","jar","nuitka","godot"};
    std::error_code ec;
    for(auto leaf:leaves){auto p=container_output_dir(report,leaf);ec.clear();std::filesystem::remove(p,ec);}
    auto renpy=report.materialization.root/prts::path_from_utf8("static")/prts::path_from_utf8("renpy");ec.clear();std::filesystem::remove(renpy,ec);
}

struct AutoStaticChildPending {
    prts::AnalysisArtifact artifact;
    std::filesystem::path parent;
    std::uint32_t depth=0;
};

bool automatic_static_child_candidate(const prts::AnalysisArtifact&a){
    if(a.priority!="HIGH"||a.path.empty()||a.runtime_confirmed)return false;
    if(a.role=="analysis_map"||a.role=="static_child_report"||a.kind=="analysis_report"||a.kind=="pyinstaller_pyz")return false;
    return true;
}

void merge_child_artifacts(prts::AnalysisReport&root,const prts::AnalysisReport&child){
    for(const auto&a:child.artifacts){
        bool seen=false;for(const auto&existing:root.artifacts){if(existing.path==a.path||same_regular_file(existing.path,a.path)){seen=true;break;}}
        if(!seen)root.artifacts.push_back(a);
    }
}

void note_static_child_skip(prts::AnalysisReport&report,const std::string&reason,std::uint64_t bytes=0){
    report.materialization.partial=true;
    report.materialization.omitted_count=sat_add(report.materialization.omitted_count,1);
    report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,bytes);
    report.materialization.reasons.push_back(reason);
}

void analyze_static_artifact_children(prts::AnalysisReport&report,const std::filesystem::path&input,const Options&opt){
    std::deque<AutoStaticChildPending>queue;
    for(const auto&a:report.artifacts)if(automatic_static_child_candidate(a))queue.push_back({a,input,1});
    if(queue.empty())return;
    prts::ArtifactGraphInfo graph;graph.enabled=true;graph.max_depth=opt.artifact_max_depth;graph.max_nodes=opt.artifact_max_nodes;graph.max_total_bytes=opt.artifact_max_bytes;graph.nodes=1;
    std::map<std::string,std::filesystem::path>first_by_sha;if(!report.input_snapshot.sha256.empty())first_by_sha.emplace(report.input_snapshot.sha256,input);
    std::size_t analyzed=0,report_failures=0;
    while(!queue.empty()){
        auto cur=std::move(queue.front());queue.pop_front();prts::ArtifactGraphEdge edge;edge.parent=cur.parent;edge.child=cur.artifact.path;edge.relation=cur.artifact.relation.empty()?"auto_high_value":cur.artifact.relation;edge.depth=cur.depth;
        std::error_code ec;auto st=std::filesystem::symlink_status(cur.artifact.path,ec);
        if(ec||st.type()==std::filesystem::file_type::symlink||st.type()!=std::filesystem::file_type::regular){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"automatic static child analysis refused a non-regular/symlink artifact: "+prts::path_utf8(cur.artifact.path));continue;}
        edge.size=std::filesystem::file_size(cur.artifact.path,ec);if(ec){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"automatic static child analysis could not read artifact size: "+prts::path_utf8(cur.artifact.path));continue;}
        edge.sha256=prts::sha256_file(cur.artifact.path);if(edge.sha256.empty()){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"automatic static child analysis could not hash artifact: "+prts::path_utf8(cur.artifact.path),edge.size);continue;}
        ++graph.materialized_files;graph.materialized_bytes=sat_add(graph.materialized_bytes,edge.size);
        if(cur.depth>graph.max_depth){edge.state="SKIPPED_DEPTH";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"automatic static child depth limit reached for "+prts::path_utf8(cur.artifact.path),edge.size);continue;}
        if(graph.admitted_bytes>graph.max_total_bytes||edge.size>graph.max_total_bytes-graph.admitted_bytes){edge.state="SKIPPED_BYTE_LIMIT";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"automatic static child byte budget omitted "+prts::path_utf8(cur.artifact.path),edge.size);continue;}
        if(graph.nodes>=graph.max_nodes){edge.state="SKIPPED_NODE_LIMIT";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"automatic static child node budget omitted "+prts::path_utf8(cur.artifact.path),edge.size);continue;}
        if(auto it=first_by_sha.find(edge.sha256);it!=first_by_sha.end()){edge.state="DUPLICATE_SKIPPED";edge.duplicate_of=it->second;++graph.deduplicated;graph.edges.push_back(std::move(edge));continue;}
        first_by_sha.emplace(edge.sha256,cur.artifact.path);graph.admitted_bytes=sat_add(graph.admitted_bytes,edge.size);++graph.nodes;
        auto child_root=report.materialization.root/prts::path_from_utf8("children")/prts::path_from_utf8(edge.sha256);
        std::string child_root_error;if(!ensure_artifact_subdirectory(report.materialization.root,child_root,child_root_error)){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,child_root_error,edge.size);continue;}
        Options child_opt=opt;child_opt.run_requested=false;child_opt.run_mode.clear();child_opt.apply=false;child_opt.run_all=false;child_opt.recursive=false;child_opt.extract=false;child_opt.artifact_graph_node=false;child_opt.suppress_auto_child_analysis=true;child_opt.artifact_root_override=child_root;
        child_opt.extract_budget_bytes=graph.admitted_bytes<graph.max_total_bytes?graph.max_total_bytes-graph.admitted_bytes:0;
        child_opt.extract_budget_files=graph.nodes<graph.max_nodes?graph.max_nodes-graph.nodes:0;
        auto child=analyze_file(cur.artifact.path,child_opt);child.artifact.graph_member=true;child.artifact.root=false;child.artifact.depth=cur.depth;child.artifact.parent=cur.parent;child.artifact.root_input=input;child.artifact.offset_basis=cur.artifact.path;child.artifact.offset_space="current_input_file";child.artifact.relation=edge.relation;
        auto report_path=child_root/prts::path_from_utf8("analysis.json");std::string write_error;
        if(!write_artifact_report_json(report.materialization.root,report_path,child,write_error,true)){edge.state="ANALYZED_REPORT_WRITE_FAILED";++report_failures;graph.truncated=true;report.materialization.partial=true;report.materialization.reasons.push_back(write_error);}else{edge.state="ANALYZED_STATIC";register_artifact_file(report,report_path,"analysis_report","static_child_report","auto-refirst",cur.artifact.path,"analysis_of","ANALYSIS");++analyzed;}
        merge_child_artifacts(report,child);
        for(const auto&a:child.artifacts)if(automatic_static_child_candidate(a))queue.push_back({a,cur.artifact.path,cur.depth+1});
        graph.edges.push_back(std::move(edge));
    }
    report.artifact_graph=graph;
    prts::Finding f;f.kind="artifact_graph";f.family="Automatic static artifact graph";f.state=graph.truncated?"PARTIAL":"CONFIRMED";
    f.evidence={"default HIGH-priority artifacts produced by validated extractors are automatically admitted for complete static/ecosystem analysis","automatic child analysis never authorizes runtime execution or --apply","SHA-256 de-duplication plus depth/node/byte budgets bound recursive materialization analysis","analysis derivatives and raw PyInstaller PYZ archives are never admitted as executable/static child inputs"};
    f.fields["nodes"]=std::to_string(graph.nodes);f.fields["analyzed_children"]=std::to_string(analyzed);f.fields["deduplicated"]=std::to_string(graph.deduplicated);f.fields["materialized_files"]=std::to_string(graph.materialized_files);f.fields["materialized_bytes"]=std::to_string(graph.materialized_bytes);f.fields["admitted_bytes"]=std::to_string(graph.admitted_bytes);f.fields["max_depth"]=std::to_string(graph.max_depth);f.fields["max_nodes"]=std::to_string(graph.max_nodes);f.fields["max_total_bytes"]=std::to_string(graph.max_total_bytes);f.fields["report_write_failures"]=std::to_string(report_failures);
    for(const auto&w:graph.warnings)f.negative_evidence.push_back(w);
    report.findings.push_back(std::move(f));
}


void analyze_selected_static_artifact_children_bounded(prts::AnalysisReport&report,const std::filesystem::path&input,const Options&opt,const std::vector<prts::AnalysisArtifact>&selected,std::uint64_t&directory_bytes_used,std::uint64_t&directory_files_used,std::uint64_t directory_max_bytes,std::uint64_t directory_max_files){
    if(selected.empty())return;
    auto&graph=report.artifact_graph;
    if(!graph.enabled){graph.enabled=true;graph.max_depth=opt.artifact_max_depth;graph.max_nodes=opt.artifact_max_nodes;graph.max_total_bytes=opt.artifact_max_bytes;graph.nodes=1;}
    std::map<std::string,std::filesystem::path>first_by_sha;
    if(!report.input_snapshot.sha256.empty())first_by_sha.emplace(report.input_snapshot.sha256,input);
    for(const auto&e:graph.edges)if(!e.sha256.empty())first_by_sha.emplace(e.sha256,e.child);
    for(const auto&a:selected){
        if(!automatic_static_child_candidate(a))continue;
        prts::ArtifactGraphEdge edge;edge.parent=input;edge.child=a.path;edge.relation=a.relation.empty()?"auto_high_value":a.relation;edge.depth=1;
        std::error_code ec;auto st=std::filesystem::symlink_status(a.path,ec);
        if(ec||st.type()==std::filesystem::file_type::symlink||st.type()!=std::filesystem::file_type::regular){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory static child analysis refused a non-regular/symlink artifact: "+prts::path_utf8(a.path));continue;}
        edge.size=std::filesystem::file_size(a.path,ec);if(ec){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory static child analysis could not read artifact size: "+prts::path_utf8(a.path));continue;}
        edge.sha256=a.sha256.empty()?prts::sha256_file(a.path):a.sha256;if(edge.sha256.empty()){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory static child analysis could not hash artifact: "+prts::path_utf8(a.path),edge.size);continue;}
        ++graph.materialized_files;graph.materialized_bytes=sat_add(graph.materialized_bytes,edge.size);
        if(auto it=first_by_sha.find(edge.sha256);it!=first_by_sha.end()){edge.state="DUPLICATE_SKIPPED";edge.duplicate_of=it->second;++graph.deduplicated;graph.edges.push_back(std::move(edge));continue;}
        if(graph.nodes>=graph.max_nodes){edge.state="SKIPPED_NODE_LIMIT";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory static child node budget omitted "+prts::path_utf8(a.path),edge.size);continue;}
        if(graph.admitted_bytes>graph.max_total_bytes||edge.size>graph.max_total_bytes-graph.admitted_bytes){edge.state="SKIPPED_BYTE_LIMIT";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory static child input-byte budget omitted "+prts::path_utf8(a.path),edge.size);continue;}
        if(directory_files_used>=directory_max_files||directory_bytes_used>=directory_max_bytes){edge.state="SKIPPED_DIRECTORY_ARTIFACT_BUDGET";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory aggregate artifact budget deferred static child report for "+prts::path_utf8(a.path));continue;}
        first_by_sha.emplace(edge.sha256,a.path);graph.admitted_bytes=sat_add(graph.admitted_bytes,edge.size);++graph.nodes;
        auto child_root=report.materialization.root/prts::path_from_utf8("children")/prts::path_from_utf8(edge.sha256);
        std::string cleanup_error;if(!reset_directory_artifact_root(child_root,cleanup_error)){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,cleanup_error,edge.size);continue;}
        Options child_opt=opt;child_opt.run_requested=false;child_opt.run_mode.clear();child_opt.apply=false;child_opt.run_all=false;child_opt.recursive=false;child_opt.extract=false;child_opt.artifact_graph_node=false;child_opt.suppress_auto_child_analysis=true;child_opt.suppress_auto_materialization=true;child_opt.artifact_root_override=child_root;child_opt.extract_budget_bytes=0;child_opt.extract_budget_files=0;child_opt.artifact_max_bytes=0;child_opt.artifact_max_nodes=0;
        auto child=analyze_file(a.path,child_opt);child.artifact.graph_member=true;child.artifact.root=false;child.artifact.depth=1;child.artifact.parent=input;child.artifact.root_input=input;child.artifact.offset_basis=a.path;child.artifact.offset_space="current_input_file";child.artifact.relation=edge.relation;
        DirectoryArtifactTreeStats unexpected;std::string inspect_error;if(!inspect_directory_artifact_tree(child_root,unexpected,inspect_error)){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,inspect_error,edge.size);continue;}
        if(unexpected.files||unexpected.bytes){reset_directory_artifact_root(child_root,cleanup_error);edge.state="SKIPPED_OUTPUT_INVARIANT";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory static child suppression produced unexpected derivative output and was rolled back",unexpected.bytes);continue;}
        std::ostringstream rendered;prts::render_automatic_child_json(rendered,child);rendered.put('\n');auto payload=rendered.str();
        const auto remaining_bytes=directory_bytes_used<directory_max_bytes?directory_max_bytes-directory_bytes_used:0;const auto remaining_files=directory_files_used<directory_max_files?directory_max_files-directory_files_used:0;
        if(!remaining_files||payload.size()>remaining_bytes){reset_directory_artifact_root(child_root,cleanup_error);edge.state="SKIPPED_DIRECTORY_ARTIFACT_BUDGET";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory aggregate artifact budget deferred static child report for "+prts::path_utf8(a.path),payload.size());continue;}
        std::string root_error;if(!ensure_artifact_subdirectory(report.materialization.root,child_root,root_error)){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,root_error,edge.size);continue;}
        auto report_path=child_root/prts::path_from_utf8("analysis.json");auto pst=std::filesystem::symlink_status(report_path,ec);if(!ec&&pst.type()!=std::filesystem::file_type::not_found){reset_directory_artifact_root(child_root,cleanup_error);edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory child report path unexpectedly existed before write: "+prts::path_utf8(report_path));continue;}
        std::ofstream out(report_path,std::ios::binary|std::ios::trunc);if(!out){reset_directory_artifact_root(child_root,cleanup_error);edge.state="ANALYZED_REPORT_WRITE_FAILED";graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"cannot create bounded directory static child report: "+prts::path_utf8(report_path));continue;}out.write(payload.data(),static_cast<std::streamsize>(payload.size()));out.flush();if(!out){out.close();reset_directory_artifact_root(child_root,cleanup_error);edge.state="ANALYZED_REPORT_WRITE_FAILED";graph.truncated=true;graph.edges.push_back(std::move(edge));note_static_child_skip(report,"bounded directory static child report write failed: "+prts::path_utf8(report_path),payload.size());continue;}
        directory_bytes_used=sat_add(directory_bytes_used,payload.size());directory_files_used=sat_add(directory_files_used,1);edge.state="ANALYZED_STATIC";register_artifact_file(report,report_path,"analysis_report","static_child_report","auto-refirst",a.path,"analysis_of","ANALYSIS");graph.edges.push_back(std::move(edge));
    }
    std::size_t analyzed=0,failures=0;for(const auto&e:graph.edges){if(e.state=="ANALYZED_STATIC")++analyzed;if(e.state=="ANALYZED_REPORT_WRITE_FAILED")++failures;}
    auto it=std::find_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="Automatic static artifact graph";});
    if(it==report.findings.end()){prts::Finding f;f.kind="artifact_graph";f.family="Automatic static artifact graph";f.evidence={"HIGH-priority validated artifacts are admitted for bounded static/ecosystem analysis","directory aggregate mode meters persisted child-report derivatives under the same shared byte/file budget","automatic child analysis never authorizes runtime execution or --apply"};report.findings.push_back(std::move(f));it=std::prev(report.findings.end());}
    it->state=graph.truncated?"PARTIAL":"CONFIRMED";it->fields["nodes"]=std::to_string(graph.nodes);it->fields["analyzed_children"]=std::to_string(analyzed);it->fields["deduplicated"]=std::to_string(graph.deduplicated);it->fields["materialized_files"]=std::to_string(graph.materialized_files);it->fields["materialized_bytes"]=std::to_string(graph.materialized_bytes);it->fields["admitted_bytes"]=std::to_string(graph.admitted_bytes);it->fields["max_depth"]=std::to_string(graph.max_depth);it->fields["max_nodes"]=std::to_string(graph.max_nodes);it->fields["max_total_bytes"]=std::to_string(graph.max_total_bytes);it->fields["report_write_failures"]=std::to_string(failures);
}

std::string report_format_label(const prts::AnalysisReport&r){
    if(r.pe.valid)return "PE";
    if(r.elf.valid)return "ELF";
    if(r.macho.valid)return "Mach-O";
    if(r.pyinstaller.valid)return "PyInstaller";
    if(r.apk.valid)return "APK";
    if(r.jar.valid)return "JAR";
    if(r.dex.valid)return "DEX";
    if(r.jvm_class.valid)return "JVM";
    if(r.dotnet.valid)return ".NET";
    if(r.wasm.valid)return "Wasm";
    if(r.lua.valid)return "Lua";
    return "unknown";
}

void analyze_runtime_children(prts::AnalysisReport&report,const std::filesystem::path&input,const Options&opt){
    register_runtime_artifacts(report,input);
    if(report.runtime.artifacts.empty())return;
    std::map<std::string,std::filesystem::path> analyzed_by_sha;
    if(!report.input_snapshot.sha256.empty())analyzed_by_sha.emplace(report.input_snapshot.sha256,input);
    std::size_t completed=0,deduped=0,failed=0,root_reused=0;
    for(auto&a:report.runtime.artifacts){
        if(!runtime_artifact_static_child(a))continue;
        if(same_regular_file(a.path,input)){
            a.fields["static_child_analysis"]="ROOT_REPORT_ALREADY_REANALYZED";a.fields["static_child_format"]=report_format_label(report);++root_reused;continue;
        }
        auto snap=prts::snapshot_file(a.path);
        if(!snap.exists||snap.sha256.empty()){a.fields["static_child_analysis"]="FAILED_ARTIFACT_UNAVAILABLE";++failed;report.materialization.partial=true;report.materialization.reasons.push_back("runtime recovered artifact could not be reopened for mandatory static analysis: "+prts::path_utf8(a.path));continue;}
        if(auto it=analyzed_by_sha.find(snap.sha256);it!=analyzed_by_sha.end()){a.fields["static_child_analysis"]="DEDUPLICATED_STATIC_ANALYSIS";a.fields["static_child_duplicate_of"]=prts::path_utf8(it->second);++deduped;continue;}
        analyzed_by_sha.emplace(snap.sha256,a.path);
        auto child_root=report.materialization.root/"children"/snap.sha256;
        std::string child_root_error;if(!ensure_artifact_subdirectory(report.materialization.root,child_root,child_root_error)){a.fields["static_child_analysis"]="FAILED_ARTIFACT_ROOT";a.fields["static_child_report_error"]=child_root_error;++failed;report.materialization.partial=true;report.materialization.reasons.push_back(child_root_error);continue;}
        Options child_opt=opt;child_opt.run_requested=false;child_opt.run_mode.clear();child_opt.apply=false;child_opt.run_all=false;child_opt.recursive=false;child_opt.extract=false;child_opt.artifact_graph_node=false;child_opt.artifact_root_override=child_root;
        auto child=analyze_file(a.path,child_opt);child.artifact.graph_member=true;child.artifact.root=false;child.artifact.depth=1;child.artifact.parent=input;child.artifact.root_input=input;child.artifact.offset_basis=a.path;child.artifact.offset_space="current_input_file";child.artifact.relation="runtime_recovered_image";
        merge_child_artifacts(report,child);
        auto report_path=child_root/"analysis.json";std::string write_error;
        if(!write_artifact_report_json(report.materialization.root,report_path,child,write_error)){
            a.fields["static_child_analysis"]="COMPLETED_REPORT_WRITE_FAILED";a.fields["static_child_format"]=report_format_label(child);a.fields["static_child_report_error"]=write_error;++failed;report.materialization.partial=true;report.materialization.reasons.push_back(write_error);
            register_artifact_file(report,a.path,a.kind,"recovered_native_image","runtime",input,"runtime_recovered_image","HIGH",false,true,"ANALYZED_STATIC_REPORT_WRITE_FAILED");continue;
        }
        a.fields["static_child_analysis"]="COMPLETED";a.fields["static_child_format"]=report_format_label(child);a.fields["static_child_report"]=prts::path_utf8(report_path);a.fields["static_child_sha256"]=snap.sha256;
        register_artifact_file(report,a.path,a.kind,"recovered_native_image","runtime",input,"runtime_recovered_image","HIGH",false,true,"ANALYZED_STATIC");
        register_artifact_file(report,report_path,"analysis_report","static_child_report","auto-refirst",a.path,"analysis_of","ANALYSIS",false,true,"MATERIALIZED");++completed;
    }
    if(completed||deduped||failed||root_reused){
        prts::Finding f;f.kind="artifact";f.family="Runtime recovered artifact static analysis";f.state=failed?(completed||deduped||root_reused?"PARTIAL":"FAILED"):"CONFIRMED";
        f.evidence.push_back("high-confidence persisted runtime recovered images are statically re-analyzed independently of --apply");
        f.evidence.push_back("runtime-derived children are never automatically executed; --apply controls only validated transactional installation at the original input path");
        f.fields["completed"]=std::to_string(completed);f.fields["deduplicated"]=std::to_string(deduped);f.fields["root_reused_after_apply"]=std::to_string(root_reused);f.fields["failed"]=std::to_string(failed);f.fields["artifact_root"]=prts::path_utf8(report.materialization.root);
        if(failed)f.negative_evidence.push_back("one or more recovered runtime artifacts could not persist their mandatory static child report; see runtime artifact fields/materialization reasons");
        report.findings.push_back(std::move(f));
    }
}

#ifdef _WIN32
void refresh_cpython_product_findings(prts::AnalysisReport&report){
    report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="CPython-derived"||f.family=="PyInstaller -> CPython"||f.family=="PyInstaller bootstrap";}),report.findings.end());
    if(report.pyinstaller.valid)report.findings.push_back(prts::pyinstaller_bootstrap_finding(report.pyinstaller));
    for(const auto&cp:report.cpython_runtimes)report.findings.push_back(prts::cpython_finding(cp));
    if(auto path=prts::build_pyinstaller_cpython_path(report))report.findings.push_back(std::move(*path));
}

bool auto_probe_runtime_candidate(const prts::CPythonInfo&cp){
    if(!cp.valid)return false;
    if(cp.semantic_reference_status=="BUILD_INCOMPARABLE"||cp.dispatch.reference_status=="BUILD_INCOMPARABLE")return true;
    return cp.dispatch.attempted&&!cp.dispatch.reference_status.empty()&&cp.dispatch.reference_status!="REFERENCE_MATCH";
}

#endif

void execute_cpython_probe_step(prts::AnalysisReport&report,const std::filesystem::path&input,const Options&opt){
    auto*step=prts::runtime_plan_step(report.runtime_plan,"cpython_compiler_probe");if(!step||!step->selected)return;
#ifndef _WIN32
    (void)input;(void)opt;step->state="SKIPPED";step->refusal="CPython compiler probe runtime is Windows-only on this build";return;
#else
    const auto begin=std::chrono::steady_clock::now();bool any=false,success=false;std::vector<std::string>errors;
    for(auto&cp:report.cpython_runtimes){
        if(opt.run_mode!="python-probe"&&!auto_probe_runtime_candidate(cp))continue;
        any=true;std::string err;
        if(prts::run_cpython_compiler_probe_for_input(input,report.pyinstaller.valid?&report.pyinstaller:nullptr,cp,opt.timeout_ms,err))success=true;
        else if(!err.empty())errors.push_back(err);
    }
    prts::CPythonInfo*embedded_cp=nullptr;for(auto&cp:report.cpython_runtimes)if(cp.source.rfind("CArchive:",0)==0){embedded_cp=&cp;break;}
    if(report.pyinstaller.valid&&embedded_cp){prts::MappedFile remap(input);if(remap.valid()){prts::analyze_pyinstaller_bootstrap(remap.bytes(),report.pyinstaller,embedded_cp);report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="PyInstaller automatic materialization";}),report.findings.end());if(opt.extract)materialize_pyinstaller(report,input,opt,remap.bytes(),embedded_cp,opt.extract_budget_bytes,opt.extract_budget_files,prts::PyInstExtractMode::Full);else{auto [bytes,files]=pyinstaller_auto_budget(opt);materialize_pyinstaller(report,input,opt,remap.bytes(),embedded_cp,bytes,files,prts::PyInstExtractMode::AutoCore);}}}
    refresh_cpython_product_findings(report);
    if(!any){prts::Finding f;f.kind="dynamic_probe";f.family="CPython compiler probe";f.state="FAILED";f.evidence.push_back("runtime plan selected CPython compiler probe but no eligible CPython runtime remained");report.findings.push_back(std::move(f));step->state="FAILED";step->result="no eligible CPython runtime";}
    else if(errors.empty()){step->state="COMPLETED";step->result="compiler probe completed; main runtime validity remains independent";}
    else{for(const auto&e:errors){prts::Finding f;f.kind="dynamic_probe";f.family="CPython compiler probe";f.state="FAILED";f.evidence.push_back(e);report.findings.push_back(std::move(f));}step->state=success?"PARTIAL":"FAILED";step->result=success?"some compiler probes completed":"compiler probe failed";step->refusal=errors.front();}
    step->elapsed_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count());
#endif
}

void update_runtime_step_results(prts::AnalysisReport&report,bool runtime_ok,const std::string&error,std::uint64_t elapsed_ms){
    if(auto*s=prts::runtime_plan_step(report.runtime_plan,"generic_runtime_trace");s&&s->selected){s->elapsed_ms=elapsed_ms;s->state=runtime_ok?"COMPLETED":"FAILED";s->result=runtime_ok?"runtime process/timeline collection completed":"runtime backend failed";if(!runtime_ok)s->refusal=error;}
    std::size_t memory_artifacts=0,reconstructed=0;for(const auto&a:report.runtime.artifacts){if(a.kind=="materialized_region")++memory_artifacts;if(a.kind=="unpacked_pe"||a.kind=="reconstructed_elf"||a.kind=="runtime_backing_elf")++reconstructed;if(a.kind=="materialization_graph"){if(auto*s=prts::runtime_plan_step(report.runtime_plan,"materialization_tracking")){auto it=a.fields.find("deepest_confirmed_generation");if(it!=a.fields.end())s->evidence.push_back("deepest confirmed materialization generation="+it->second);}}}
    if(auto*s=prts::runtime_plan_step(report.runtime_plan,"materialization_tracking");s&&s->selected){s->elapsed_ms=elapsed_ms;s->state=runtime_ok?"COMPLETED":"FAILED";s->result=runtime_ok?("memory artifacts="+std::to_string(memory_artifacts)):"runtime materialization analysis failed";if(!runtime_ok)s->refusal=error;}
    if(auto*s=prts::runtime_plan_step(report.runtime_plan,"unpack_reconstruction");s&&s->selected){s->elapsed_ms=elapsed_ms;s->state=runtime_ok?"COMPLETED":"FAILED";s->result=runtime_ok?("runtime-derived image artifacts="+std::to_string(reconstructed)):"reconstruction pipeline unavailable after runtime failure";if(!runtime_ok)s->refusal=error;}
    if(auto*s=prts::runtime_plan_step(report.runtime_plan,"validated_transactional_install");s&&s->selected){s->elapsed_ms=elapsed_ms;if(!runtime_ok){s->state="FAILED";s->refusal=error;}else if(report.replacement.performed){s->state="COMPLETED";s->result="validated candidate transactionally installed; backup/rollback contract retained";}else{s->state="SKIPPED";s->result="no candidate reached the strict final installation gate";}}
}

void execute_runtime_plan(prts::AnalysisReport&report,const std::filesystem::path&input,const Options&opt){
    prts::RuntimePlanningRequest req;req.requested=opt.run_requested;req.apply_requested=opt.apply;req.legacy_trace=opt.run_mode=="trace";req.legacy_unpack=opt.run_mode=="unpack";req.forced_python_probe=opt.run_mode=="python-probe";req.timeout_ms=opt.timeout_ms;
    report.runtime_plan=prts::build_runtime_plan(report,req);if(!opt.run_requested)return;
    auto*trace=prts::runtime_plan_step(report.runtime_plan,"generic_runtime_trace");
    if(trace&&trace->selected){
        auto pre_runtime_findings=report.findings;prts::RuntimeOptions ro;ro.deep_materialization_analysis=prts::runtime_plan_step(report.runtime_plan,"materialization_tracking")&&prts::runtime_plan_step(report.runtime_plan,"materialization_tracking")->selected;ro.allow_validated_install=prts::runtime_plan_step(report.runtime_plan,"validated_transactional_install")&&prts::runtime_plan_step(report.runtime_plan,"validated_transactional_install")->selected;ro.timeout_ms=opt.timeout_ms;ro.artifact_dir=report.materialization.root/"runtime";
        std::string artifact_dir_error;if(!ensure_artifact_subdirectory(report.materialization.root,ro.artifact_dir,artifact_dir_error)){prts::Finding f;f.kind="runtime";f.family="runtime artifact directory";f.state="FAILED";f.negative_evidence.push_back(artifact_dir_error);report.findings.push_back(std::move(f));update_runtime_step_results(report,false,artifact_dir_error,0);execute_cpython_probe_step(report,input,opt);return;}
        const auto begin=std::chrono::steady_clock::now();std::string err;const bool ok=prts::run_target(input,report.pe,ro,report,err);const auto elapsed=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count());
        if(!ok){prts::Finding f;f.kind="runtime";f.family="runtime execution";f.state="FAILED";f.evidence.push_back(err.empty()?"runtime execution failed":err);report.findings.push_back(std::move(f));}
        update_runtime_step_results(report,ok,err,elapsed);
        std::filesystem::path probe_input=input;if(report.replacement.performed&&!report.replacement.backup.empty())probe_input=report.replacement.backup;
        execute_cpython_probe_step(report,probe_input,opt);
        if(report.replacement.performed&&report.replacement.validation=="UNPACKED_VALIDATED"){
            auto saved_runtime=std::move(report.runtime);auto saved_replacement=std::move(report.replacement);auto saved_plan=std::move(report.runtime_plan);auto original_snapshot=report.input_snapshot;auto preserved_findings=report.findings;
            Options post_opt=opt;post_opt.run_requested=false;post_opt.run_mode.clear();post_opt.apply=false;post_opt.run_all=false;post_opt.extract=false;post_opt.search.clear();auto post=analyze_file(input,post_opt);
            for(auto&f:preserved_findings){if(f.kind=="packer"||f.family=="UPX-like"||f.family=="CPython-derived"||f.family=="PyInstaller -> CPython"||f.family=="PyInstaller bootstrap"||f.family=="CPython compiler probe"){f.fields["scope"]="pre_unpack";f.kind="pre_unpack_"+f.kind;post.findings.push_back(std::move(f));}}
            post.input_snapshot=original_snapshot;post.runtime=std::move(saved_runtime);post.replacement=std::move(saved_replacement);post.runtime_plan=std::move(saved_plan);report=std::move(post);
            if(auto*s=prts::runtime_plan_step(report.runtime_plan,"post_unpack_static_reanalysis")){s->state="COMPLETED";s->result="static/ecosystem pipeline rerun against installed validated image";}
        }else if(auto*s=prts::runtime_plan_step(report.runtime_plan,"post_unpack_static_reanalysis");s&&s->selected){s->state="SKIPPED";s->result="input was not replaced; original static report remains authoritative";}
        (void)pre_runtime_findings;
    }else{
        execute_cpython_probe_step(report,input,opt);
        if(auto*s=prts::runtime_plan_step(report.runtime_plan,"post_unpack_static_reanalysis");s&&s->selected){s->state="SKIPPED";s->result="generic runtime analyzer was not selected";}
    }
}

prts::AnalysisReport analyze_file(const std::filesystem::path&input,const Options&opt){
    prts::AnalysisReport report;
    report.input=input;
    report.materialization.root=opt.artifact_root_override.empty()?artifact_root_for_input(input):opt.artifact_root_override;
    report.artifact.root_input=input;report.artifact.offset_basis=input;
    report.input_snapshot=prts::snapshot_file(input);
    if(!report.input_snapshot.exists){
        prts::Finding f;f.kind="input";f.family="file";f.state="FAILED";f.evidence.push_back("input is not a regular file");report.findings.push_back(std::move(f));return report;
    }

    std::uint64_t extract_bytes_left=opt.extract_budget_bytes;
    std::uint32_t extract_files_left=opt.extract_budget_files;
    auto permit_extract=[&](std::string family,std::uint64_t bytes,std::uint32_t files)->bool{
        if(!opt.extract)return false;
        if(bytes>extract_bytes_left||files>extract_files_left){
            prts::Finding f;f.kind="safety";f.family="Artifact extraction budget";f.state="REFUSED";
            f.evidence.push_back("validated container was not materialized because declared output exceeds the recursive extraction budget");
            f.fields["ecosystem"]=std::move(family);f.fields["declared_bytes"]=std::to_string(bytes);f.fields["declared_files"]=std::to_string(files);f.fields["remaining_bytes"]=std::to_string(extract_bytes_left);f.fields["remaining_files"]=std::to_string(extract_files_left);
            report.findings.push_back(std::move(f));return false;
        }
        extract_bytes_left-=bytes;extract_files_left-=files;return true;
    };

    {
        prts::MappedFile mapped(input);
        if(!mapped.valid()){
            prts::Finding f;f.kind="input";f.family="mapping";f.state="FAILED";f.evidence.push_back(mapped.error());report.findings.push_back(std::move(f));return report;
        }
        report.pe=prts::parse_pe(mapped.bytes());
        if(report.pe.valid){report.authenticode=prts::analyze_authenticode(mapped.bytes(),report.pe);if(report.authenticode.present||report.authenticode.state=="FAILED")report.findings.push_back(prts::authenticode_finding(report.authenticode));}
        if(!report.pe.valid){report.elf=prts::parse_elf(mapped.bytes());if(!report.elf.valid)report.macho=prts::parse_macho(mapped.bytes());}
        report.static_scan=prts::scan_static(mapped.bytes());
        report.python_bytecode=prts::detect_python_bytecode(mapped.bytes(),ext_is(input,".pyc"));
        if(report.python_bytecode.candidate)report.findings.push_back(prts::python_bytecode_finding(report.python_bytecode));
        report.cpython_marshal_loader=prts::inspect_cpython_marshal_loader_source(mapped.bytes());
        if(report.cpython_marshal_loader.loader_confirmed)report.findings.push_back(prts::cpython_marshal_loader_finding(report.cpython_marshal_loader));
        if(starts_with(mapped.bytes(),"ECFG")){report.godot_legacy_config=prts::parse_godot_legacy_engine_config(mapped.bytes());if(report.godot_legacy_config.valid)report.findings.push_back(godot_legacy_config_finding(report.godot_legacy_config));else add_validation_failure(report.findings,"Godot legacy engine.cfb","ECFG binary project-settings magic",report.godot_legacy_config.error);}
        const bool gdscript_routed=ext_is(input,".gdc")||starts_with(mapped.bytes(),"GDSC");
        if(gdscript_routed){
            auto materialize_gdscript=[&](prts::Finding&f){
                auto analysis=prts::analyze_gdscript_buffer(mapped.bytes());
                if(!analysis.valid){f.negative_evidence.push_back("normalized GDScript analysis did not close: "+analysis.error);return;}
                const auto rows=sat_add(analysis.identifiers.size(),sat_add(analysis.constants.size(),sat_add(analysis.lines.size(),analysis.tokens.size())));
                if(!auto_analysis_allowed(report,opt,"Godot GDScript",rows,256))return;
                auto base=analysis_map_dir(report,"godot")/"gdscript";
                std::vector<std::filesystem::path>targets={prts::path_with_ascii_suffix(base,".godot-script-info.json"),prts::path_with_ascii_suffix(base,".godot-identifiers.csv"),prts::path_with_ascii_suffix(base,".godot-constants.csv"),prts::path_with_ascii_suffix(base,".godot-lines.csv"),prts::path_with_ascii_suffix(base,".godot-tokens.csv")};
                if(!prepare_artifact_targets(report,"Godot GDScript",targets))return;
                for(const auto&t:targets){std::error_code ec;std::filesystem::remove(t,ec);if(ec){f.negative_evidence.push_back("cannot replace prior GDScript sidecar: "+prts::path_utf8(t)+": "+ec.message());return;}}
                report.gdscript_extract=prts::materialize_gdscript_analysis(analysis,base);
                if(!report.gdscript_extract.success){f.negative_evidence.push_back("normalized GDScript artifact materialization failed: "+report.gdscript_extract.error);return;}
                f.evidence.push_back("five normalized GDScript analysis sidecars were materialized under the per-input artifact root; no .gd source decompilation was claimed");
                f.fields["analysis_artifacts"]="5";f.fields["source_decompilation"]="false";f.fields["analysis_root"]=prts::path_utf8(base.parent_path());
            };
            auto gd=prts::validate_gdscript_buffer_versioned(mapped.bytes());
            if(gd.structurally_valid){
                prts::Finding f;f.kind="bytecode";f.family="Godot GDScript";f.state="CONFIRMED";f.variant="official-tokenizer-v"+std::to_string(gd.tokenizer_version);
                f.evidence={"GDSC header/version passed an explicit official tokenizer profile","identifier, Variant constant, source-position map, token records, and payload closure all validated"};
                f.fields["format_state"]="official-compatible";f.fields["tokenizer_version"]=std::to_string(gd.tokenizer_version);f.fields["official_profile"]=gd.tokenizer_version==10?"Godot 2 tokenizer-v10 (verified 2.1.1/2.1.5; token epoch resolved by terminal EOF)":(gd.tokenizer_version==13?"Godot 3 tokenizer-v13 (verified 3.2.1/3.3.2/3.4.4)":(gd.tokenizer_version==100?"Godot 4.3/4.4 tokenizer-v100":"Godot 4.5 tokenizer-v101"));f.fields["compression"]=gd.compression;f.fields["identifier_count"]=std::to_string(gd.identifier_count);f.fields["constant_count"]=std::to_string(gd.constant_count);f.fields["token_line_count"]=std::to_string(gd.token_line_count);f.fields["token_count"]=std::to_string(gd.token_count);f.fields["payload_bytes"]=std::to_string(gd.payload_bytes);
                const auto gdscript_header_bytes=(gd.tokenizer_version==10||gd.tokenizer_version==13)?24ull:12ull;f.ranges.push_back(prts::file_offset_range(0,std::min<std::uint64_t>(mapped.bytes().size(),gdscript_header_bytes),"GDScript tokenizer-buffer header"));materialize_gdscript(f);report.findings.push_back(std::move(f));
            }else{
                auto layout=prts::infer_gdscript_layout(mapped.bytes());
                if(layout.state=="CONFIRMED"&&!layout.official_compatible){
                    prts::Finding f;f.kind="bytecode";f.family="Godot GDScript";f.state="CONFIRMED";f.variant=layout.variant;
                    f.evidence={"official tokenizer parsing did not close, but exactly one bounded fixed-record candidate closed structurally","identifier and Variant constant planes were parsed before line/token layout solving"};
                    if(layout.variant=="custom-token-layout")f.evidence.push_back("layout geometry is confirmed while custom token semantics remain opaque");
                    f.fields["format_state"]=layout.variant;f.fields["tokenizer_version"]=std::to_string(layout.tokenizer_version);f.fields["token_record_size"]=std::to_string(layout.token_record_size);f.fields["line_record_size"]=std::to_string(layout.line_record_size);f.fields["size_fit_candidates"]=std::to_string(layout.size_fit_candidates);f.fields["structurally_valid_candidates"]=std::to_string(layout.structurally_valid_candidates);
                    for(const auto&c:layout.candidates)if(c.structurally_valid){f.fields["identifier_valid"]=c.identifier_valid?"true":"false";f.fields["constant_valid"]=c.constant_valid?"true":"false";f.fields["custom_token_count"]=std::to_string(c.custom_token_count);f.fields["token_domain_ratio"]=std::to_string(c.token_domain_ratio);f.fields["token_reference_ratio"]=std::to_string(c.token_reference_ratio);f.fields["line_token_reference_ratio"]=std::to_string(c.line_token_reference_ratio);f.fields["line_monotonic_ratio"]=std::to_string(c.line_monotonic_ratio);f.fields["reserved_zero_ratio"]=std::to_string(c.reserved_zero_ratio);break;}
                    f.ranges.push_back(prts::file_offset_range(0,std::min<std::uint64_t>(mapped.bytes().size(),12),"GDScript tokenizer-buffer header"));materialize_gdscript(f);report.findings.push_back(std::move(f));
                }else if(layout.state=="AMBIGUOUS_LAYOUT"){
                    prts::Finding f;f.kind="bytecode";f.family="Godot GDScript";f.state="AMBIGUOUS_LAYOUT";f.variant="unknown-variant";f.evidence={"multiple bounded fixed-record layouts remain structurally valid; no layout was selected"};f.negative_evidence.push_back(layout.error);f.fields["tokenizer_version"]=std::to_string(layout.tokenizer_version);f.fields["size_fit_candidates"]=std::to_string(layout.size_fit_candidates);f.fields["structurally_valid_candidates"]=std::to_string(layout.structurally_valid_candidates);f.ranges.push_back(prts::file_offset_range(0,std::min<std::uint64_t>(mapped.bytes().size(),12),"GDScript tokenizer-buffer header"));report.findings.push_back(std::move(f));
                }else{
                    std::string why=gd.failure_stage+": "+gd.error;if(!layout.error.empty())why+="; layout: "+layout.error;add_validation_failure(report.findings,"Godot GDScript",ext_is(input,".gdc")?".gdc filename extension":"GDSC header marker",why);
                }
            }
        }
        {auto common=prts::detect_common(mapped.bytes(),report.pe,report.elf,report.static_scan);report.findings.insert(report.findings.end(),std::make_move_iterator(common.begin()),std::make_move_iterator(common.end()));}
        if(ext_is(input,".gdextension")){
            report.gdextension_descriptor=prts::parse_gdextension_descriptor(mapped.bytes());
            if(report.gdextension_descriptor.valid)report.findings.push_back(gdextension_descriptor_finding(report.gdextension_descriptor));
            else add_validation_failure(report.findings,"Godot GDExtension descriptor",".gdextension filename extension",report.gdextension_descriptor.error.empty()?"descriptor did not pass strict configuration/libraries validation":report.gdextension_descriptor.error);
        }
        const bool unity_routed=route_unity(input,report.pe,report.static_scan);std::future<prts::UnityInfo> unity_future;if(unity_routed)unity_future=std::async(std::launch::async,[&](){return prts::detect_unity(input,mapped.bytes(),report.pe);});
        if(report.pe.valid){auto anti=prts::detect_antidebug(mapped.bytes(),report.pe);report.findings.insert(report.findings.end(),std::make_move_iterator(anti.begin()),std::make_move_iterator(anti.end()));}
        if(report.pe.valid){auto prereq=prts::detect_execution_prerequisites(mapped.bytes(),report.pe);report.findings.insert(report.findings.end(),std::make_move_iterator(prereq.begin()),std::make_move_iterator(prereq.end()));}
        if(report.pe.valid){auto manual=prts::detect_manual_resolvers(mapped.bytes(),report.pe);report.findings.insert(report.findings.end(),std::make_move_iterator(manual.begin()),std::make_move_iterator(manual.end()));}

        auto packed=prts::detect_packed_pe(report.pe,report.input_snapshot.size);
        if(packed.candidate)report.findings.push_back(prts::packed_pe_finding(packed,report.pe));
        auto protector_structures=prts::detect_pe_protector_structures(mapped.bytes(),report.pe,&packed);
        report.findings.insert(report.findings.end(),protector_structures.begin(),protector_structures.end());

        auto upx=prts::detect_upx(mapped.bytes(),report.pe,report.elf);
        if(upx.candidate)report.findings.push_back(prts::upx_finding(upx));
        integrate_validated_static_repair(report,input,opt,mapped.bytes(),upx.candidate);

        if(report.static_scan.hints.crypto||prts::has_crypto_api_imports(report.pe))report.crypto=prts::detect_crypto_key_uses(mapped.bytes(),report.pe,report.static_scan);
        if(report.crypto.valid)report.findings.push_back(prts::crypto_finding(report.crypto));

        report.renpy_rpa=prts::detect_rpa(mapped.bytes(),input);
        if(report.renpy_rpa.valid){report.findings.push_back(prts::renpy_rpa_finding(report.renpy_rpa));auto out=container_output_dir(report,"renpy/rpa");if(prepare_container_output(report,out,"Ren'Py RPA")){if(opt.extract){auto bytes=sum_bytes(report.renpy_rpa.entries,[](const auto&e){return e.length;});auto files=cap_count(report.renpy_rpa.entries.size());if(permit_extract("Ren'Py RPA",bytes,files))report.renpy_rpa_extract=prts::extract_rpa(mapped.bytes(),report.renpy_rpa,out,false,bytes,files);}else{auto [bytes,files]=auto_core_budget(opt);report.renpy_rpa_extract=prts::extract_rpa(mapped.bytes(),report.renpy_rpa,out,true,bytes,files);if(report.renpy_rpa_extract.budget_exhausted)note_auto_core_partial(report,"Ren'Py RPA",report.renpy_rpa_extract.omitted_count,report.renpy_rpa_extract.omitted_bytes);}}}
        else if(!report.renpy_rpa.error.empty())add_validation_failure(report.findings,"Ren'Py RPA","recognized RPA-2.0/RPA-3.x header",report.renpy_rpa.error);

        const bool renpy_rpyc_routed=!report.renpy_rpa.valid&&route_renpy_rpyc(input,report.static_scan);
        if(renpy_rpyc_routed){
            report.renpy_rpyc=prts::detect_rpyc(mapped.bytes(),input);
            if(report.renpy_rpyc.valid){report.findings.push_back(prts::renpy_rpyc_finding(report.renpy_rpyc));auto dir=container_output_dir(report,"renpy/rpyc");if(prepare_container_output(report,dir,"Ren'Py RPYC")){auto out=dir/"decoded.pickle";if(opt.extract){if(permit_extract("Ren'Py RPYC",report.renpy_rpyc.pickle_payload.size(),1))report.renpy_extract=prts::extract_rpyc(report.renpy_rpyc,out);}else{auto [bytes,files]=auto_core_budget(opt);if(files&&report.renpy_rpyc.pickle_payload.size()<=bytes)report.renpy_extract=prts::extract_rpyc(report.renpy_rpyc,out);else note_auto_core_partial(report,"Ren'Py RPYC",1,report.renpy_rpyc.pickle_payload.size());}}}
            else if(!report.renpy_rpyc.error.empty())add_validation_failure(report.findings,"Ren'Py RPYC",ext_is(input,".rpyc")||ext_is(input,".rpymc")?"RPYC/RPYMC filename extension":"Ren'Py static evidence",report.renpy_rpyc.error);
        }

        const bool wxapkg_failure_routed=route_wxapkg_failure(input,mapped.bytes());
        report.wxapkg=prts::detect_wxapkg(mapped.bytes(),input,opt.wxid);
        if(report.wxapkg.valid){report.findings.push_back(prts::wxapkg_finding(report.wxapkg));auto out=container_output_dir(report,"wxapkg");if(prepare_container_output(report,out,"wxapkg")){if(opt.extract){auto bytes=sum_bytes(report.wxapkg.entries,[](const auto&e){return std::uint64_t(e.size);});auto files=cap_count(report.wxapkg.entries.size());if(!report.wxapkg.entries.empty()&&permit_extract("wxapkg",bytes,files))report.wxapkg_extract=prts::extract_wxapkg(mapped.bytes(),report.wxapkg,out,false,bytes,files);}else{auto [bytes,files]=auto_core_budget(opt);report.wxapkg_extract=prts::extract_wxapkg(mapped.bytes(),report.wxapkg,out,true,bytes,files);if(report.wxapkg_extract.budget_exhausted)note_auto_core_partial(report,"wxapkg",report.wxapkg_extract.omitted_count,report.wxapkg_extract.omitted_bytes);}}}
        else if(wxapkg_failure_routed)add_validation_failure(report.findings,"WeChat Mini Program",ext_is(input,".wxapkg")?".wxapkg filename extension":"wxapkg header marker",report.wxapkg.error);

        const bool asar_failure_routed=route_asar_failure(input,mapped.bytes());
        report.asar=prts::detect_asar(mapped.bytes(),input);
        if(report.asar.valid){report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="Electron"||f.family=="ASAR";}),report.findings.end());report.findings.push_back(prts::asar_finding(report.asar));auto out=container_output_dir(report,"asar");if(prepare_container_output(report,out,"Electron ASAR")){if(opt.extract){auto bytes=sum_bytes(report.asar.entries,[](const auto&e){return e.kind==prts::AsarEntryKind::File?e.size:0;});auto files=cap_count(std::count_if(report.asar.entries.begin(),report.asar.entries.end(),[](const auto&e){return e.kind==prts::AsarEntryKind::File;}));if(permit_extract("Electron ASAR",bytes,files))report.asar_extract=prts::extract_asar(mapped.bytes(),report.asar,out,false,bytes,files);}else{auto [bytes,files]=auto_core_budget(opt);report.asar_extract=prts::extract_asar(mapped.bytes(),report.asar,out,true,bytes,files);if(report.asar_extract.budget_exhausted)note_auto_core_partial(report,"Electron ASAR",report.asar_extract.omitted_count,report.asar_extract.omitted_bytes);}}}
        else if(asar_failure_routed)add_validation_failure(report.findings,"Electron ASAR",ext_is(input,".asar")?".asar filename extension":"Chromium Pickle size marker",report.asar.error);

        const bool autoit_routed=report.static_scan.hints.autoit||ext_is(input,".a3x");
        if(autoit_routed)report.autoit=prts::detect_autoit(mapped.bytes(),report.pe,input,report.static_scan.hints.autoit);
        if(report.autoit.valid){report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="AutoIt";}),report.findings.end());report.findings.push_back(prts::autoit_finding(report.autoit));auto out=container_output_dir(report,"autoit");if(prepare_container_output(report,out,"AutoIt")){if(opt.extract){auto bytes=sum_bytes(report.autoit.records,[](const auto&e){return e.output_size;});bytes=sat_add(bytes,report.autoit.script_tokenized?report.autoit.script_source.size():0);auto files=cap_count(report.autoit.records.size()+1);if(permit_extract("AutoIt",bytes,files))report.autoit_extract=prts::extract_autoit(mapped.bytes(),report.autoit,out,false);}else{auto [bytes,files]=auto_core_budget(opt);auto script_bytes=sat_add(report.autoit.script_source.size(),report.autoit.script_tokenized?report.autoit.token_bytes:0);auto script_files=report.autoit.script_tokenized?2u:1u;if(script_files<=files&&script_bytes<=bytes)report.autoit_extract=prts::extract_autoit(mapped.bytes(),report.autoit,out,true);else note_auto_core_partial(report,"AutoIt",script_files,script_bytes);}}}
        else if(autoit_routed)add_validation_failure(report.findings,"AutoIt",ext_is(input,".a3x")?".a3x filename extension":"AutoIt/EA06 static evidence",report.autoit.error);

        report.dotnet=prts::detect_dotnet(mapped.bytes(),report.pe,input);
        if(report.dotnet.valid){report.findings.push_back(prts::dotnet_finding(report.dotnet));}
        else if(report.pe.valid&&report.pe.clr.present)add_validation_failure(report.findings,".NET metadata","PE CLR data directory",report.dotnet.error);

        if(unity_routed)report.unity=unity_future.get();
        if(report.unity.valid){
            report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="Unity";}),report.findings.end());report.findings.push_back(prts::unity_finding(report.unity));
            if(report.unity.metadata_valid&&!opt.suppress_auto_materialization){
                auto dir=analysis_map_dir(report,"unity"),out=dir/"unity-symbols.csv";
                std::vector<std::filesystem::path>targets={out,dir/"unity-layouts.csv",dir/"unity-generics.csv",dir/"unity-rgctx.csv",dir/"unity-strings.csv",dir/"unity-usages.csv",dir/"unity-defaults.csv",dir/"unity-xrefs.csv",dir/"unity-pinvoke.csv",dir/"unity-dispatch.csv"};
                if(opt.extract){targets.push_back(dir/"unity-callgraph.csv");targets.push_back(dir/"unity-dispatch-calls.csv");targets.push_back(dir/"unity-dispatch-targets.csv");}
                if(prepare_artifact_targets(report,"Unity",targets)){
                    const auto unity_rows=opt.extract?std::numeric_limits<std::uint64_t>::max():kAutoAnalysisRows;
                    report.unity_extract=prts::extract_unity_symbols(report.unity,out,opt.extract,unity_rows);
                    if(!opt.extract&&report.unity_extract.budget_exhausted){
                        const auto estimated=report.unity_extract.omitted_rows>std::numeric_limits<std::uint64_t>::max()/192?std::numeric_limits<std::uint64_t>::max():report.unity_extract.omitted_rows*192;
                        report.materialization.partial=true;report.materialization.omitted_count=sat_add(report.materialization.omitted_count,report.unity_extract.omitted_rows);report.materialization.omitted_bytes=sat_add(report.materialization.omitted_bytes,estimated);
                        std::string planes;for(const auto&x:report.unity_extract.omitted_planes){if(!planes.empty())planes+=',';planes+=x;}report.materialization.reasons.push_back("Unity AUTO_ANALYSIS kept whole high-value tables within the default 100k-row budget; omitted planes="+planes+" omitted_rows="+std::to_string(report.unity_extract.omitted_rows)+"; --extract exports all supported Unity tables and the native call graph");
                    }
                }
            }else if(report.unity.metadata_valid&&opt.suppress_auto_materialization){report.materialization.partial=true;report.materialization.omitted_count=sat_add(report.materialization.omitted_count,1);report.materialization.reasons.push_back("Unity automatic analysis maps deferred by the directory aggregate artifact budget; rerun this file directly for its normal per-file materialization contract");}
        }
        else if(unity_routed&&!report.unity.error.empty())add_validation_failure(report.findings,"Unity","Unity family/backend route evidence",report.unity.error);

        report.wasm=prts::parse_wasm(mapped.bytes());
        if(report.wasm.candidate){report.findings.push_back(prts::wasm_finding(report.wasm));}

        report.dart=prts::detect_dart(mapped.bytes(),report.elf);
        const bool dart_routed=report.dart.candidate||ext_is(input,".dill");
        if(report.dart.valid)report.findings.push_back(dart_finding(report.dart));
        else if(dart_routed){std::ostringstream detail;if(!report.dart.error.empty())detail<<report.dart.error;else detail<<"Dart structural magic/AOT loader-visible symbol geometry is missing or unsupported";if(report.dart.candidate&&report.dart.error_offset)detail<<" at current-file offset 0x"<<std::hex<<report.dart.error_offset;add_validation_failure(report.findings,"Dart",report.dart.candidate?"Dart snapshot/Kernel magic or AOT loader-visible symbols":".dill filename extension",detail.str());}

        const bool flutter_asset_routed=filename_is(input,"AssetManifest.bin");
        if(flutter_asset_routed)report.flutter_asset_manifest=prts::parse_flutter_asset_manifest(mapped.bytes());
        if(report.flutter_asset_manifest.valid){report.findings.push_back(flutter_asset_finding(report.flutter_asset_manifest));}
        else if(flutter_asset_routed){auto detail=report.flutter_asset_manifest.error.empty()?std::string("AssetManifest.bin does not contain a complete supported StandardMessageCodec Flutter asset manifest"):report.flutter_asset_manifest.error;if(report.flutter_asset_manifest.candidate&&report.flutter_asset_manifest.error_offset){std::ostringstream x;x<<detail<<" at current-file offset 0x"<<std::hex<<report.flutter_asset_manifest.error_offset;detail=x.str();}add_validation_failure(report.findings,"Flutter","AssetManifest.bin filename route",detail);}

        report.dex=prts::parse_dex(mapped.bytes());
        const bool dex_routed=report.dex.candidate||ext_is(input,".dex");
        if(report.dex.valid){report.findings.push_back(prts::dex_finding(report.dex));}
        else if(dex_routed){std::ostringstream detail;if(report.dex.error.empty())detail<<"DEX magic dex\nNNN\0 is missing or unsupported";else detail<<report.dex.error;if(report.dex.candidate)detail<<" at current-file offset 0x"<<std::hex<<report.dex.error_offset;add_validation_failure(report.findings,"Android DEX",report.dex.candidate?"DEX magic/version header":".dex filename extension",detail.str());}

        const bool apk_ext=ext_is(input,".apk");
        const bool apk_routed=apk_ext||contains_ascii(mapped.bytes(),"AndroidManifest.xml");
        if(apk_routed)report.apk=prts::detect_apk(mapped.bytes());
        if(report.apk.valid){
            report.findings.push_back(prts::apk_finding(report.apk));
            auto out=container_output_dir(report,"apk");
            if(prepare_container_output(report,out,"Android APK")){
                if(opt.artifact_graph_node){
                    report.apk_extract=prts::extract_apk(mapped.bytes(),report.apk,out,extract_bytes_left,extract_files_left,true);
                    extract_bytes_left=report.apk_extract.output_bytes>extract_bytes_left?0:extract_bytes_left-report.apk_extract.output_bytes;
                    auto used=std::min<std::uint64_t>(report.apk_extract.file_count,extract_files_left);extract_files_left-=static_cast<std::uint32_t>(used);
                }else if(opt.extract){
                    if(report.apk.extractable_files&&permit_extract("Android APK",report.apk.extractable_bytes,cap_count(report.apk.extractable_files)))report.apk_extract=prts::extract_apk(mapped.bytes(),report.apk,out,report.apk.extractable_bytes,report.apk.extractable_files,false);
                }else{
                    auto [bytes,files]=auto_core_budget(opt);report.apk_extract=prts::extract_apk(mapped.bytes(),report.apk,out,bytes,files,true);if(report.apk_extract.budget_exhausted)note_auto_core_partial(report,"Android APK",report.apk.analysis_candidate_files>report.apk_extract.file_count?report.apk.analysis_candidate_files-report.apk_extract.file_count:0,report.apk.analysis_candidate_bytes>report.apk_extract.output_bytes?report.apk.analysis_candidate_bytes-report.apk_extract.output_bytes:0);
                }
            }
        }else if(apk_routed){
            auto detail=report.apk.error.empty()?std::string("no deeply validated AndroidManifest.xml plus DEX/resource-table/native-ELF payload was found in the ZIP structure"):report.apk.error;
            add_validation_failure(report.findings,"Android APK",report.apk.candidate?"ZIP central directory with Android payload paths":".apk filename extension",detail);
        }

        report.jvm_class=prts::parse_jvm_class(mapped.bytes());
        const bool jvm_class_routed=report.jvm_class.candidate||ext_is(input,".class");
        if(report.jvm_class.valid){report.findings.push_back(prts::jvm_class_finding(report.jvm_class));}
        else if(jvm_class_routed){std::ostringstream detail;if(report.jvm_class.error.empty())detail<<"ClassFile magic CAFEBABE is missing";else detail<<report.jvm_class.error;if(report.jvm_class.candidate)detail<<" at file offset 0x"<<std::hex<<report.jvm_class.error_offset;add_validation_failure(report.findings,"JVM Class",report.jvm_class.candidate?"CAFEBABE ClassFile magic":".class filename extension",detail.str());}

        if(!report.apk.valid)report.jar=prts::detect_jar(mapped.bytes(),input);
        const bool jar_ext=ext_is(input,".jar")||ext_is(input,".war")||ext_is(input,".ear");
        if(report.jar.valid){report.findings.push_back(prts::jar_finding(report.jar));auto out=container_output_dir(report,"jar");if(prepare_container_output(report,out,"Java/JVM archive")){if(opt.artifact_graph_node){report.jar_extract=prts::extract_jar(mapped.bytes(),report.jar,out,extract_bytes_left,extract_files_left,true);extract_bytes_left=report.jar_extract.output_bytes>extract_bytes_left?0:extract_bytes_left-report.jar_extract.output_bytes;auto used=std::min<std::uint64_t>(report.jar_extract.file_count,extract_files_left);extract_files_left-=static_cast<std::uint32_t>(used);}else if(opt.extract){auto files=cap_count(std::count_if(report.jar.entries.begin(),report.jar.entries.end(),[](const auto&e){return !e.directory&&!e.symlink&&e.safe_path&&e.supported&&!e.encrypted;}));if(permit_extract("Java/JVM archive",report.jar.total_uncompressed,files))report.jar_extract=prts::extract_jar(mapped.bytes(),report.jar,out,report.jar.total_uncompressed,files,false);}else{auto [bytes,files]=auto_core_budget(opt);report.jar_extract=prts::extract_jar(mapped.bytes(),report.jar,out,bytes,files,true);if(report.jar_extract.budget_exhausted)note_auto_core_partial(report,"Java/JVM archive",report.jar_extract.omitted_count,report.jar_extract.omitted_bytes);}}}
        else if(jar_ext)add_validation_failure(report.findings,"Java/JVM archive",".jar/.war/.ear filename extension",report.jar.error);

        report.lua=prts::parse_luac(mapped.bytes());
        const bool lua_magic=mapped.bytes().size()>=4&&mapped.bytes()[0]==0x1b&&mapped.bytes()[1]=='L'&&mapped.bytes()[2]=='u'&&mapped.bytes()[3]=='a';
        if(report.lua.valid||lua_magic){report.findings.push_back(prts::lua_finding(report.lua));}

        if(report.static_scan.hints.nuitka)report.nuitka=prts::detect_nuitka(mapped.bytes(),report.pe,report.elf,std::min<std::uint64_t>(opt.extract_budget_bytes,512ull*1024*1024));
        if(report.nuitka.valid){report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="Nuitka";}),report.findings.end());report.findings.push_back(prts::nuitka_finding(report.nuitka));auto out=container_output_dir(report,"nuitka");if(report.nuitka.decompression_limited){if(opt.extract){prts::Finding f;f.kind="safety";f.family="Artifact extraction budget";f.state="REFUSED";f.evidence.push_back("Nuitka KAY payload was not decompressed because its validated Zstandard expansion bound exceeds the static byte budget");f.fields["ecosystem"]="Nuitka";f.fields["declared_bytes"]=std::to_string(report.nuitka.zstd_decompressed_bound);f.fields["declared_files"]="unknown";f.fields["remaining_bytes"]=std::to_string(opt.extract_budget_bytes);f.fields["remaining_files"]=std::to_string(opt.extract_budget_files);report.findings.push_back(std::move(f));}else note_auto_core_partial(report,"Nuitka",1,report.nuitka.zstd_decompressed_bound);}else if((report.nuitka.onefile||!report.nuitka.constant_blocks.empty())&&prepare_container_output(report,out,"Nuitka")){if(opt.extract){auto bytes=report.nuitka.onefile?sum_bytes(report.nuitka.entries,[](const auto&e){return e.size;}):sum_bytes(report.nuitka.constant_blocks,[](const auto&e){return e.size;});auto files=cap_count(report.nuitka.onefile?report.nuitka.entries.size():report.nuitka.constant_blocks.size());if(permit_extract("Nuitka",bytes,files))report.nuitka_extract=prts::extract_nuitka(mapped.bytes(),report.nuitka,out,false,bytes,files);}else{auto [bytes,files]=auto_core_budget(opt);report.nuitka_extract=prts::extract_nuitka(mapped.bytes(),report.nuitka,out,true,bytes,files);if(report.nuitka_extract.budget_exhausted)note_auto_core_partial(report,"Nuitka",report.nuitka_extract.omitted_count,report.nuitka_extract.omitted_bytes);}}}

        if(report.static_scan.hints.rust)report.rust=prts::detect_rust(mapped.bytes(),report.pe,report.elf);
        if(report.rust.valid){report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="Rust";}),report.findings.end());report.findings.push_back(prts::rust_finding(report.rust));}

        {auto surfaces=prts::compose_exception_execution_surfaces(mapped.bytes(),report.pe,report.elf,prts::path_utf8(input));report.findings.insert(report.findings.end(),std::make_move_iterator(surfaces.begin()),std::make_move_iterator(surfaces.end()));}

        if(report.static_scan.hints.golang)report.golang=prts::detect_golang(mapped.bytes(),report.pe,report.elf);
        if(report.golang.valid){
            report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="Go";}),report.findings.end());
            report.findings.push_back(prts::golang_finding(report.golang));
        }

        report.interpreter_boundary=prts::analyze_interpreter_boundary(mapped.bytes(),report.elf,input);
        if(report.interpreter_boundary.state=="CONFIRMED")report.findings.push_back(prts::interpreter_boundary_finding(report.interpreter_boundary));

        report.cpython_static=prts::analyze_cpython_static(mapped.bytes(),report.pe,false,prts::path_utf8(input));
        if(report.cpython_static.runtime.valid){
            report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="CPython-derived";}),report.findings.end());
            report.findings.push_back(prts::cpython_finding(report.cpython_static.runtime));
            report.cpython_runtimes.push_back(report.cpython_static.runtime);
        }

        const bool godot_routed=report.static_scan.hints.godot||ext_is(input,".pck");
        if(godot_routed)report.godot=prts::detect_godot(mapped.bytes(),report.pe);
        if(report.godot.valid){
            prts::analyze_godot_gdextensions(mapped.bytes(),report.godot);
            report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="Godot"||f.family=="Godot PCK";}),report.findings.end());
            report.findings.push_back(prts::godot_finding(report.godot));
            if(report.godot.gdextension_descriptor_candidates)report.findings.push_back(prts::godot_gdextension_finding(report.godot));
            {auto out=container_output_dir(report,"godot");if(prepare_container_output(report,out,"Godot PCK")){if(opt.artifact_graph_node){report.godot_extract=prts::extract_godot(mapped.bytes(),report.godot,out,false,false,extract_bytes_left,extract_files_left);extract_bytes_left=report.godot_extract.output_bytes>extract_bytes_left?0:extract_bytes_left-report.godot_extract.output_bytes;auto used=std::min<std::uint64_t>(report.godot_extract.files.size(),extract_files_left);extract_files_left-=static_cast<std::uint32_t>(used);}else if(opt.extract){auto bytes=sum_bytes(report.godot.entries,[](const auto&e){return (!e.removal&&!e.delta)?e.size:0;});auto files=cap_count(std::count_if(report.godot.entries.begin(),report.godot.entries.end(),[](const auto&e){return !e.removal&&!e.delta;}));if(permit_extract("Godot PCK",bytes,files))report.godot_extract=prts::extract_godot(mapped.bytes(),report.godot,out,true,false,bytes,files);}else{auto [bytes,files]=auto_core_budget(opt);report.godot_extract=prts::extract_godot(mapped.bytes(),report.godot,out,!opt.suppress_auto_child_analysis,true,bytes,files);if(report.godot_extract.budget_exhausted)note_auto_core_partial(report,"Godot PCK",report.godot_extract.omitted_count,report.godot_extract.omitted_bytes);}if(report.godot_extract.script_analysis_count||report.godot_extract.script_analysis_failures){prts::Finding f;f.kind="artifact";f.family="Godot GDScript normalized analysis";f.state=report.godot_extract.script_analysis_failures?(report.godot_extract.script_analysis_count?"PARTIAL":"FAILED"):"CONFIRMED";if(report.godot_extract.script_analysis_count)f.evidence.push_back("validated GDSC children produced normalized analysis sidecars during PCK materialization");if(report.godot_extract.script_analysis_failures)f.negative_evidence.push_back("one or more GDSC children could not produce sidecars; see Godot extraction warnings");f.fields["script_analysis_count"]=std::to_string(report.godot_extract.script_analysis_count);f.fields["script_artifact_count"]=std::to_string(report.godot_extract.script_artifact_count);f.fields["script_analysis_failures"]=std::to_string(report.godot_extract.script_analysis_failures);f.fields["source_decompilation"]="false";f.fields["core_only"]=report.godot_extract.core_only?"true":"false";report.findings.push_back(std::move(f));}}}
        }else if(godot_routed&&route_godot_pck_failure(input,mapped.bytes()))add_validation_failure(report.findings,"Godot PCK",ext_is(input,".pck")?".pck filename extension":"GDPC PCK header marker","no supported Godot PCK v0-v4 structure passed geometry validation");

        const bool pyinstaller_routed=route_pyinstaller(report.pe,report.static_scan);
        if(pyinstaller_routed)report.pyinstaller=prts::detect_pyinstaller(mapped.bytes());
        if(report.pyinstaller.valid){
            const prts::PyInstEntry*runtime_entry=nullptr;
            if(!report.pyinstaller.python_library.empty()){
                auto it=std::find_if(report.pyinstaller.entries.begin(),report.pyinstaller.entries.end(),[&](const prts::PyInstEntry&e){return e.name==report.pyinstaller.python_library;});
                if(it!=report.pyinstaller.entries.end())runtime_entry=&*it;
            }
            std::optional<prts::CPythonInfo> embedded_cp;
            if(runtime_entry){
                if(auto bytes=prts::pyinstaller_entry_bytes(mapped.bytes(),report.pyinstaller,*runtime_entry)){
                    auto runtime_pe=prts::parse_pe(std::span<const std::uint8_t>(*bytes));
                    auto cp=prts::detect_cpython(std::span<const std::uint8_t>(*bytes),runtime_pe,"CArchive:"+runtime_entry->name);
                    if(cp.valid)embedded_cp=std::move(cp);
                }
            }
            prts::analyze_pyinstaller_bootstrap(mapped.bytes(),report.pyinstaller,embedded_cp?&*embedded_cp:nullptr);
            report.findings.push_back(prts::pyinstaller_bootstrap_finding(report.pyinstaller));
            if(embedded_cp){
                auto pairing=prts::pair_cpython_pyinstaller_reference(mapped.bytes(),report.pe,report.pyinstaller,*embedded_cp);
                // Emit the bounded reference-pairing plane whenever the registry is applicable
                // or when an attempted exact pairing fails closed; it never rewrites the native
                // CPython reference_status/dispatch plane.
                if(pairing.attempted)report.findings.push_back(prts::cpython_reference_pairing_finding(pairing));
            }
            report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="PyInstaller";}),report.findings.end());
            report.findings.push_back(prts::pyinstaller_finding(report.pyinstaller));
            if(opt.extract){auto bytes=sum_bytes(report.pyinstaller.entries,[](const auto&e){return std::uint64_t(e.compression_flag?e.uncompressed_size:e.compressed_size);});auto declared_files=cap_count(report.pyinstaller.entries.size());auto allowance_bytes=extract_bytes_left;auto allowance_files=extract_files_left;if(permit_extract("PyInstaller",bytes,declared_files)){allowance_bytes=sat_add(extract_bytes_left,bytes);auto file_sum=std::uint64_t(extract_files_left)+declared_files;allowance_files=cap_count(file_sum);materialize_pyinstaller(report,input,opt,mapped.bytes(),embedded_cp?&*embedded_cp:nullptr,allowance_bytes,allowance_files,prts::PyInstExtractMode::Full);if(report.pyinstaller_extract.output_bytes>bytes){auto extra=report.pyinstaller_extract.output_bytes-bytes;extract_bytes_left=extra>extract_bytes_left?0:extract_bytes_left-extra;}else extract_bytes_left=sat_add(extract_bytes_left,bytes-report.pyinstaller_extract.output_bytes);auto actual_files=cap_count(report.pyinstaller_extract.files.size());if(actual_files>declared_files){auto extra=actual_files-declared_files;extract_files_left=extra>extract_files_left?0:extract_files_left-extra;}else extract_files_left=cap_count(std::uint64_t(extract_files_left)+(declared_files-actual_files));}}else{auto [bytes,files]=pyinstaller_auto_budget(opt);materialize_pyinstaller(report,input,opt,mapped.bytes(),embedded_cp?&*embedded_cp:nullptr,bytes,files,prts::PyInstExtractMode::AutoCore);}
            if(embedded_cp){
                report.findings.erase(std::remove_if(report.findings.begin(),report.findings.end(),[](const prts::Finding&f){return f.family=="CPython-derived";}),report.findings.end());
                report.findings.push_back(prts::cpython_finding(*embedded_cp));
                report.cpython_runtimes.push_back(std::move(*embedded_cp));
            }
        }else if(pyinstaller_routed&&report.static_scan.hints.pyinstaller)add_validation_failure(report.findings,"PyInstaller CArchive","PyInstaller/PYIMOD/PYZ static evidence",report.pyinstaller.error);

        // G/I are deliberately explicit heavy planes. K measured unacceptable default cost on
        // large Unity/native inputs, so --extract is their product reachability boundary.
        if(opt.extract&&(report.pe.valid||report.elf.valid)){
            auto emit_heavy=[&](const std::string&family,const std::filesystem::path&path,std::uint64_t rows,bool limited,const std::string&state,const std::string&error){
                prts::Finding f;f.kind="analysis_artifact";f.family=family;f.state=error.empty()?(limited?"PARTIAL":"CONFIRMED"):"FAILED";f.evidence.push_back("explicit --extract requested an existing bounded heavy analysis plane; default zero-config analysis intentionally does not run this detector");f.fields["rows"]=std::to_string(rows);f.fields["output"]=prts::path_utf8(path);f.fields["analysis_state"]=state;f.fields["analysis_limited"]=limited?"true":"false";if(!error.empty())f.negative_evidence.push_back(error);report.findings.push_back(std::move(f));
            };
            {
                auto info=report.pe.valid?prts::analyze_pe_exception_flow(mapped.bytes(),report.pe,prts::path_utf8(input)):prts::analyze_elf_exception_flow(mapped.bytes(),report.elf,prts::path_utf8(input));
                if(!info.facts.empty()){
                    auto out=analysis_map_dir(report,"exceptional-flow")/"exceptional-flow.csv";
                    if(prepare_artifact_targets(report,"Exceptional execution",{out})){
                        auto ex=prts::extract_exceptional_execution(info,out);emit_heavy("Exceptional execution explicit materialization",ex.csv,ex.fact_count,info.analysis_limited,info.state,ex.error);if(ex.success)register_artifact_file(report,ex.csv,"exceptional_flow_map","analysis_map","Exceptional execution",input,"analysis_of","ANALYSIS");
                    }
                }
            }
            if(report.elf.valid){
                auto ci=prts::detect_cpp20_continuations(mapped.bytes(),report.elf);
                if(!ci.entries.empty()){
                    auto out=analysis_map_dir(report,"continuation")/"continuations.csv";
                    if(prepare_artifact_targets(report,"C++20 continuation",{out})){
                        auto ex=prts::extract_continuations(ci,out);emit_heavy("C++20 continuation explicit materialization",ex.csv,ex.row_count,ci.analysis_limited,ci.state,ex.error);if(ex.success)register_artifact_file(report,ex.csv,"continuation_map","analysis_map","C++20 continuation",input,"analysis_of","ANALYSIS");
                    }
                }
                auto cr=prts::detect_control_records(mapped.bytes(),report.elf);
                if(!cr.tables.empty()){
                    auto out=analysis_map_dir(report,"control-record")/"control-records.csv";
                    if(prepare_artifact_targets(report,"Control record",{out})){
                        auto ex=prts::extract_control_records(cr,out);emit_heavy("Control record explicit materialization",ex.csv,ex.row_count,cr.analysis_limited,cr.state,ex.error);if(ex.success)register_artifact_file(report,ex.csv,"control_record_map","analysis_map","Control record",input,"analysis_of","ANALYSIS");
                    }
                }
            }
        }
        register_container_artifacts(report,input);
        register_pyinstaller_artifacts(report,input);
        materialize_nested_executables(report,input,opt,mapped.bytes(),extract_bytes_left,extract_files_left);
        finalize_implicit_execution(report,input,opt);
    }

    if(auto path=prts::build_pyinstaller_cpython_path(report))report.findings.push_back(std::move(*path));
    materialize_structured_sidecars(report,opt);
    register_analysis_sidecars(report,input);
    register_container_artifacts(report,input);
    register_pyinstaller_artifacts(report,input);
    integrate_apk_unity_il2cpp_delivery(report);
    integrate_apk_flutter_aot_delivery(report);
    integrate_apk_godot2_direct_assets(report);
    cleanup_empty_container_outputs(report);
    if(!opt.suppress_auto_child_analysis&&!opt.suppress_auto_materialization)analyze_static_artifact_children(report,input,opt);

    report.analysis_guidance=prts::build_analysis_guidance(report);
    execute_runtime_plan(report,input,opt);
    analyze_runtime_children(report,input,opt);
    register_pyinstaller_artifacts(report,input);
    report.analysis_guidance=prts::build_analysis_guidance(report);
    return report;
}

bool root_input_analysis_failed(const prts::AnalysisReport&report){
    if(!report.input_snapshot.exists)return true;
    return std::any_of(report.findings.begin(),report.findings.end(),[](const auto&f){return f.kind=="input"&&f.state=="FAILED";});
}



std::string directory_report_key(const std::filesystem::path&p);

std::string csv_cell(std::string_view s){std::string out="\"";for(char c:s){if(c=='\"')out+="\"\"";else out+=c;}out+='\"';return out;}

constexpr std::uint64_t kDirectoryArtifactBytes=64ull*1024*1024;
constexpr std::uint32_t kDirectoryArtifactFiles=512;
// Keep a generic reserve for post-relationship decisive materialization so
// low-value early candidates cannot consume the entire directory allowance.
constexpr std::uint64_t kDirectoryPreRelationshipArtifactBytes=56ull*1024*1024;
constexpr std::uint32_t kDirectoryPreRelationshipArtifactFiles=384;


void set_directory_tier(prts::DirectoryCandidate&c){if(c.priority_score>=100)c.priority_tier="Tier 1";else if(c.priority_score>=50)c.priority_tier="Tier 2";else c.priority_tier="Tier 3";}

void add_directory_semantic_priority(prts::DirectoryPlan&plan,const std::filesystem::path&path,int delta,const std::string&reason,const std::filesystem::path&related){
    for(auto&c:plan.candidates){if(directory_report_key(c.path)!=directory_report_key(path))continue;c.priority_score+=delta;c.relationship_priority_boost+=delta;if(std::find(c.priority_reasons.begin(),c.priority_reasons.end(),reason)==c.priority_reasons.end())c.priority_reasons.push_back(reason);if(!related.empty()&&std::find(c.related_files.begin(),c.related_files.end(),related)==c.related_files.end()&&c.related_files.size()<plan.max_related_files_per_artifact)c.related_files.push_back(related);set_directory_tier(c);break;}
}

bool reset_owned_artifact_subdirectory(const std::filesystem::path&root,const std::filesystem::path&dir,std::string&error){
    if(!ensure_artifact_subdirectory(root,dir.parent_path(),error))return false;
    std::error_code ec;auto st=std::filesystem::symlink_status(dir,ec);
    if(!ec&&st.type()!=std::filesystem::file_type::not_found){std::filesystem::remove_all(dir,ec);if(ec){error="cannot reset prior product-owned semantic artifact directory: "+ec.message();return false;}}
    return ensure_artifact_subdirectory(root,dir,error);
}

bool write_godot_semantic_provenance(const std::filesystem::path&root,const std::filesystem::path&path,const prts::GodotSemanticProducerResult&claims,const prts::GodotExternalPckMaterializeResult&materialized,std::uint64_t max_bytes,bool file_allowed,std::uint64_t&required_bytes,bool&budget_refused,std::string&error){
    std::ostringstream rendered;
    rendered<<"level,state,source,target,result,scope,source_coordinate,target_coordinate,result_sha256\n";
    auto emit=[&](const prts::SemanticProducerClaim&x){
        std::string sha;for(const auto&c:materialized.children)if(c.output_path==x.claim.result_artifact){sha=c.sha256;break;}
        rendered<<csv_cell(prts::to_string(x.claim.relation_level))<<','<<csv_cell(prts::to_string(x.assessment.state))<<','<<csv_cell(prts::path_utf8(x.claim.source_artifact))<<','<<csv_cell(prts::path_utf8(x.claim.target_artifact))<<','<<csv_cell(prts::path_utf8(x.claim.result_artifact))<<','<<csv_cell(x.claim.semantic_scope)<<','<<csv_cell(x.claim.source_coordinate)<<','<<csv_cell(x.claim.target_coordinate)<<','<<csv_cell(sha)<<"\n";
    };
    for(const auto&x:claims.l3_claims)emit(x);
    for(const auto&x:claims.l4_claims)emit(x);
    auto text=rendered.str();required_bytes=text.size();budget_refused=false;
    if(!file_allowed||required_bytes>max_bytes){budget_refused=true;error="Godot semantic provenance deferred by directory aggregate artifact budget";return false;}
    if(!ensure_artifact_subdirectory(root,path.parent_path(),error))return false;
    std::ofstream out(path,std::ios::binary|std::ios::trunc);if(!out){error="cannot create Godot semantic provenance CSV";return false;}
    out.write(text.data(),static_cast<std::streamsize>(text.size()));
    if(!out){error="Godot semantic provenance CSV write failed";return false;}return true;
}

void add_godot_semantic_relationship(prts::DirectoryPlan&plan,const prts::GodotExternalPckValidation&v){
    prts::DirectoryRelationship x;x.first=v.source.path;x.second=v.target.path;x.directed=true;x.kind="godot_external_pck_semantic_key";x.state="CONFIRMED";x.first_role="semantic_key_source";x.second_role="semantic_payload";x.first_relation_role="semantic_value_source";x.second_relation_role="semantic_value_target";x.evidence_basis="unique bounded native 256-bit value validated by exact PCK AES-CFB/plaintext-MD5/directory-structure oracle";x.evidence_source="Godot external semantic producer";x.source_coordinate=v.source_coordinate;x.target_coordinate=v.target_coordinate;x.provenance_scope="exact source artifact -> exact target encrypted PCK; directory/name proximity is routing only, not semantic evidence";x.evidence_level="R4_SEMANTIC_APPLICATION_RELATION";x.ambiguity="NONE";x.semantic_relevance="APPLICATION";x.priority_eligible=true;x.first_priority_delta=0;x.second_priority_delta=50;x.reason="exact source key value uniquely validates this encrypted PCK and closes a semantic source->target relation";
    bool duplicate=false;for(const auto&r:plan.relationships)if(r.kind==x.kind&&directory_report_key(r.first)==directory_report_key(x.first)&&directory_report_key(r.second)==directory_report_key(x.second)){duplicate=true;break;}if(!duplicate&&plan.relationships.size()<plan.max_relationships)plan.relationships.push_back(x);
    add_directory_semantic_priority(plan,v.target.path,50,x.reason,v.source.path);
    for(auto&c:plan.candidates)if(directory_report_key(c.path)==directory_report_key(v.source.path)){if(std::find(c.related_files.begin(),c.related_files.end(),v.target.path)==c.related_files.end()&&c.related_files.size()<plan.max_related_files_per_artifact)c.related_files.push_back(v.target.path);break;}
}

void integrate_directory_godot_semantics(prts::DirectoryPlan&plan,std::vector<prts::DirectoryReportIndex>&compact,std::vector<prts::AnalysisReport>&retained,const Options&static_opt,std::uint64_t*directory_artifact_bytes_used=nullptr,std::uint64_t*directory_artifact_files_used=nullptr,prts::DirectoryArtifactRendering*artifact_rendering=nullptr){
    constexpr std::size_t kMaxSourceRoutesPerTarget=16,kMaxTargets=8;
    std::map<std::string,std::size_t>compact_by_path;for(std::size_t i=0;i<compact.size();++i)compact_by_path[directory_report_key(compact[i].input)]=i;
    std::size_t target_count=0;
    for(auto&target_report:retained){
        if(!target_report.godot.valid||!target_report.godot.encrypted_directory)continue;
        if(target_count++>=kMaxTargets){prts::Finding f;f.kind="semantic_composition";f.family="Godot external semantic composition";f.state="PARTIAL";f.negative_evidence.push_back("directory encrypted-PCK semantic target budget exceeded; no source value was guessed");target_report.findings.push_back(std::move(f));continue;}
        prts::MappedFile tm(target_report.input);if(!tm.valid())continue;auto ts=prts::snapshot_file(target_report.input);if(!ts.exists||ts.sha256.empty())continue;
        auto inspection=prts::inspect_godot_external_pck(tm.bytes(),{target_report.input,ts.sha256});if(!inspection.valid||!inspection.encrypted_directory)continue;
        struct Match{prts::GodotExternalPckValidation validation;std::size_t candidate_count=0;};std::vector<Match>matches;
        std::size_t routed_sources=0;bool route_budget_exhausted=false,candidate_budget_exhausted=false;
        for(const auto&src:compact){
            if(!src.pe_valid||src.pe_dll||directory_report_key(src.input)==directory_report_key(target_report.input))continue;
            if(directory_report_key(src.input.parent_path())!=directory_report_key(target_report.input.parent_path()))continue;
            if(routed_sources++>=kMaxSourceRoutesPerTarget){route_budget_exhausted=true;break;}
            prts::MappedFile sm(src.input);if(!sm.valid())continue;auto spe=prts::parse_pe(sm.bytes());if(!spe.valid||spe.dll)continue;auto ss=prts::snapshot_file(src.input);if(!ss.exists||ss.sha256.empty())continue;
            auto cands=prts::discover_godot_native_key_candidates(sm.bytes(),spe,{src.input,ss.sha256});candidate_budget_exhausted=candidate_budget_exhausted||cands.budget_exhausted;if(cands.candidates.empty())continue;
            auto v=prts::validate_godot_key_candidates_against_pck(tm.bytes(),inspection,cands);if(v.matching_candidate_count)matches.push_back({std::move(v),cands.candidates.size()});
        }
        if(matches.empty())continue;
        if(route_budget_exhausted||candidate_budget_exhausted||matches.size()!=1||!matches.front().validation.resolved){
            prts::Finding f;f.kind="semantic_composition";f.family="Godot external semantic composition";f.state="UNRESOLVED";f.variant="external-native-key-to-encrypted-pck";f.evidence.push_back("one or more bounded native key candidates reached the exact encrypted-PCK oracle, but directory-level source ambiguity/budget coverage did not close");f.fields["matching_source_artifacts"]=std::to_string(matches.size());f.fields["source_route_budget_exhausted"]=route_budget_exhausted?"true":"false";f.fields["candidate_budget_exhausted"]=candidate_budget_exhausted?"true":"false";f.negative_evidence.push_back("automatic materialization is withheld unless exactly one source artifact has a fully resolved unique value/coordinate proof");target_report.findings.push_back(std::move(f));continue;
        }
        auto&v=matches.front().validation;
        const bool aggregate_bounded=directory_artifact_bytes_used&&directory_artifact_files_used&&artifact_rendering;
        std::uint64_t remaining_bytes=std::numeric_limits<std::uint64_t>::max();std::uint64_t remaining_files=std::numeric_limits<std::uint64_t>::max();
        if(aggregate_bounded){remaining_bytes=*directory_artifact_bytes_used<kDirectoryArtifactBytes?kDirectoryArtifactBytes-*directory_artifact_bytes_used:0;remaining_files=*directory_artifact_files_used<kDirectoryArtifactFiles?kDirectoryArtifactFiles-*directory_artifact_files_used:0;}
        auto out=target_report.materialization.root/prts::path_from_utf8("static")/prts::path_from_utf8("godot-external")/prts::path_from_utf8(v.source.sha256);
        prts::GodotExternalPckMaterializeResult materialized;materialized.output_dir=out;
        std::string why;
        if(!aggregate_bounded||remaining_files>1){
            if(!reset_owned_artifact_subdirectory(target_report.materialization.root,out,why)){prts::Finding f;f.kind="semantic_composition";f.family="Godot external semantic composition";f.state="FAILED";f.negative_evidence.push_back(why);target_report.findings.push_back(std::move(f));continue;}
            auto [max_bytes,max_files]=auto_core_budget(static_opt);
            if(aggregate_bounded){
                // Keep one file slot for the exact provenance map. Bytes remain
                // fail-closed: provenance is rendered in memory and written only
                // if it fits after decisive children.
                max_bytes=std::min(max_bytes,remaining_bytes);max_files=static_cast<std::uint32_t>(std::min<std::uint64_t>(max_files,remaining_files-1));
            }
            materialized=prts::materialize_godot_external_pck_core(tm.bytes(),v,out,max_bytes,max_files);
        }else{
            materialized.budget_exhausted=true;materialized.error="decisive post-relationship materialization deferred by directory aggregate artifact file budget";
        }
        auto claims=prts::produce_godot_semantic_composition(v,materialized.children);
        std::size_t l3=0,l4=0;for(const auto&x:claims.l3_claims)if(x.assessment.state==prts::SemanticCompositionState::Confirmed)++l3;for(const auto&x:claims.l4_claims)if(x.assessment.state==prts::SemanticCompositionState::Confirmed)++l4;
        std::uint64_t prov_required=0;bool prov_budget_refused=false;auto prov=out/"semantic-composition.csv";std::string prov_error;
        const auto prov_remaining=aggregate_bounded?(materialized.output_bytes<remaining_bytes?remaining_bytes-materialized.output_bytes:0):std::numeric_limits<std::uint64_t>::max();
        const bool prov_file_allowed=!aggregate_bounded||(materialized.children.size()<remaining_files);
        const bool prov_ok=write_godot_semantic_provenance(target_report.materialization.root,prov,claims,materialized,prov_remaining,prov_file_allowed,prov_required,prov_budget_refused,prov_error);
        std::vector<prts::AnalysisArtifact> bounded_post_relationship_children;
        for(const auto&child:materialized.children){
            register_artifact_file(target_report,child.output_path,"godot_semantic_child",child.script?"script_or_project":"validated_project_data","Godot external semantic composition",target_report.input,"semantic_transformation","HIGH",false,false,child.validation_state);
            if(aggregate_bounded){auto ai=std::find_if(target_report.artifacts.begin(),target_report.artifacts.end(),[&](const auto&a){return same_regular_file(a.path,child.output_path);});if(ai!=target_report.artifacts.end())bounded_post_relationship_children.push_back(*ai);}
        }
        if(prov_ok)register_artifact_file(target_report,prov,"semantic_composition_map","analysis_map","Godot external semantic composition",target_report.input,"analysis_of","ANALYSIS");
        const std::uint64_t added_bytes=sat_add(materialized.output_bytes,prov_ok?prov_required:0);const std::uint64_t added_files=materialized.children.size()+(prov_ok?1:0);
        if(aggregate_bounded){
            *directory_artifact_bytes_used=sat_add(*directory_artifact_bytes_used,added_bytes);*directory_artifact_files_used=sat_add(*directory_artifact_files_used,added_files);
            if(*directory_artifact_bytes_used>kDirectoryArtifactBytes||*directory_artifact_files_used>kDirectoryArtifactFiles){std::cerr<<"internal directory post-relationship artifact budget invariant failed\n";return;}
            if(materialized.budget_exhausted){artifact_rendering->partial=true;artifact_rendering->known_omitted_bytes=sat_add(artifact_rendering->known_omitted_bytes,materialized.omitted_bytes);artifact_rendering->known_omitted_files=sat_add(artifact_rendering->known_omitted_files,materialized.omitted_count);}
            if(prov_budget_refused){artifact_rendering->partial=true;artifact_rendering->known_omitted_bytes=sat_add(artifact_rendering->known_omitted_bytes,prov_required);artifact_rendering->known_omitted_files=sat_add(artifact_rendering->known_omitted_files,1);}
            const auto before_child_bytes=*directory_artifact_bytes_used,before_child_files=*directory_artifact_files_used,before_omitted_bytes=target_report.materialization.omitted_bytes,before_omitted_count=target_report.materialization.omitted_count;
            analyze_selected_static_artifact_children_bounded(target_report,target_report.input,static_opt,bounded_post_relationship_children,*directory_artifact_bytes_used,*directory_artifact_files_used,kDirectoryArtifactBytes,kDirectoryArtifactFiles);
            const auto child_derivative_bytes=*directory_artifact_bytes_used-before_child_bytes,child_derivative_files=*directory_artifact_files_used-before_child_files;
            const auto child_omitted_bytes=target_report.materialization.omitted_bytes>=before_omitted_bytes?target_report.materialization.omitted_bytes-before_omitted_bytes:0,child_omitted_count=target_report.materialization.omitted_count>=before_omitted_count?target_report.materialization.omitted_count-before_omitted_count:0;
            if(child_omitted_bytes||child_omitted_count){artifact_rendering->partial=true;artifact_rendering->known_omitted_bytes=sat_add(artifact_rendering->known_omitted_bytes,child_omitted_bytes);artifact_rendering->known_omitted_files=sat_add(artifact_rendering->known_omitted_files,child_omitted_count);}
            const auto candidate_added_bytes=sat_add(added_bytes,child_derivative_bytes),candidate_added_files=sat_add(added_files,child_derivative_files);
            for(auto&c:plan.candidates)if(directory_report_key(c.path)==directory_report_key(target_report.input)){const bool had=c.artifact_materialized_files!=0;c.artifact_materialized_bytes=sat_add(c.artifact_materialized_bytes,candidate_added_bytes);c.artifact_materialized_files=sat_add(c.artifact_materialized_files,candidate_added_files);if(candidate_added_files&&!had)++artifact_rendering->retained_candidate_roots;if(materialized.budget_exhausted||prov_budget_refused||child_omitted_bytes||child_omitted_count){c.artifact_materialization_state="MATERIALIZED_PARTIAL";c.artifact_materialization_reason="post-relationship decisive materialization/child-report derivatives were bounded by the shared directory aggregate allowance";}else if(candidate_added_files){c.artifact_materialization_state="MATERIALIZED";c.artifact_materialization_reason="preflight and post-relationship decisive materialization/child reports fit the shared directory aggregate allowance";}break;}
        }
        prts::Finding f;f.kind="semantic_composition";f.family="Godot external semantic composition";f.state=(l3&&l4&&!materialized.budget_exhausted)?"CONFIRMED":(l3?"PARTIAL":"FAILED");f.variant="external-native-key-to-encrypted-pck";for(const auto&e:v.evidence)f.evidence.push_back(e);f.evidence.push_back("host filesystem proximity was used only to bound candidate routing; the semantic relationship is emitted only after the exact target oracle closes uniquely");if(l4)f.evidence.push_back(std::to_string(l4)+" independently integrity-validated decisive child artifact(s) were materialized and admitted as HIGH static-analysis children");
        f.fields["source_artifact"]=prts::path_utf8(v.source.path);f.fields["target_artifact"]=prts::path_utf8(v.target.path);f.fields["source_sha256"]=v.source.sha256;f.fields["target_sha256"]=v.target.sha256;f.fields["source_coordinate"]=v.source_coordinate;f.fields["target_coordinate"]=v.target_coordinate;f.fields["key_state"]=v.pack.key.script_validated?"KEY_VALIDATED_FOR_SCRIPT":(v.pack.key.directory_validated?"DIRECTORY_KEY_VALIDATED":"ENCRYPTED_FILE_KEY_VALIDATED");f.fields["source_candidate_count"]=std::to_string(matches.front().candidate_count);f.fields["validation_attempts"]=std::to_string(v.validation_attempts);f.fields["l3_confirmed"]=std::to_string(l3);f.fields["l4_confirmed"]=std::to_string(l4);f.fields["materialized_children"]=std::to_string(materialized.children.size());f.fields["materialized_bytes"]=std::to_string(materialized.output_bytes);if(prov_ok)f.fields["provenance_map"]=prts::path_utf8(prov);if(materialized.budget_exhausted)f.negative_evidence.push_back("decisive-child materialization hit the default static byte/file budget");for(const auto&w:materialized.warnings)f.negative_evidence.push_back(w);if(!materialized.error.empty())f.negative_evidence.push_back(materialized.error);if(!prov_ok)f.negative_evidence.push_back(prov_error);
        target_report.findings.push_back(std::move(f));
        add_godot_semantic_relationship(plan,v);
        if(!aggregate_bounded&&!static_opt.suppress_auto_child_analysis)analyze_static_artifact_children(target_report,target_report.input,static_opt);
        auto it=compact_by_path.find(directory_report_key(target_report.input));if(it!=compact_by_path.end()){const bool mutated=compact[it->second].post_relationship_mutated;auto refreshed=prts::make_directory_report_index(target_report);refreshed.post_relationship_mutated=mutated;compact[it->second]=std::move(refreshed);}
    }
}

std::string directory_report_key(const std::filesystem::path&p);

constexpr std::uint64_t kDirectoryInlineReportBytes=16ull*1024*1024;
constexpr std::uint64_t kDirectoryPerReportBytes=8ull*1024*1024;
constexpr std::uint64_t kDirectoryReportSpoolHardBytes=kDirectoryInlineReportBytes+kDirectoryPerReportBytes;

struct DirectorySpoolRecord {
    std::filesystem::path input;
    std::filesystem::path payload;
    std::uint64_t full_bytes=0;
    std::int64_t detail_priority=0;
    bool selected=false;
    std::string deferred_reason;
};

class CappedSpoolStreambuf final:public std::streambuf {
    std::ofstream&out_;
    std::uint64_t cap_=0,total_=0,written_=0;
    bool failed_=false;
protected:
    std::streamsize xsputn(const char*s,std::streamsize n)override{
        if(n<=0)return n;
        const auto add=static_cast<std::uint64_t>(n);total_=sat_add(total_,add);
        if(written_<cap_){
            const auto room=cap_-written_;const auto take=static_cast<std::streamsize>(std::min<std::uint64_t>(room,add));
            if(take>0){out_.write(s,take);if(!out_){failed_=true;return 0;}written_=sat_add(written_,static_cast<std::uint64_t>(take));}
        }
        return n;
    }
    int_type overflow(int_type ch)override{
        if(traits_type::eq_int_type(ch,traits_type::eof()))return traits_type::not_eof(ch);
        const char c=traits_type::to_char_type(ch);return xsputn(&c,1)==1?ch:traits_type::eof();
    }
    int sync()override{out_.flush();if(!out_){failed_=true;return -1;}return 0;}
public:
    CappedSpoolStreambuf(std::ofstream&out,std::uint64_t cap):out_(out),cap_(cap){}
    std::uint64_t total()const{return total_;}
    std::uint64_t written()const{return written_;}
    bool failed()const{return failed_;}
};

std::int64_t directory_report_detail_priority(const prts::DirectoryCandidate&c,const prts::DirectoryReportIndex&idx){
    std::int64_t score=static_cast<std::int64_t>(c.priority_score)*1000;
    if(c.priority_tier=="Tier 1")score+=1000000;
    else if(c.priority_tier=="Tier 2")score+=100000;
    if(c.role=="managed_payload"||c.role=="managed_payload_candidate"||c.role=="metadata_sidecar")score+=500000;
    if(idx.implicit_high_priority_count)score+=400000;
    if(idx.failure_count)score+=300000;
    if(idx.partial_count)score+=200000;
    if(idx.post_relationship_mutated)score+=600000;
    return score;
}

class DirectoryReportSpool {
    std::filesystem::path root_;
    bool json_=false;
    prts::ReportLanguage language_=prts::ReportLanguage::English;
    std::vector<DirectorySpoolRecord> records_;
    std::string error_;
    std::uint64_t selected_bytes_=0;
    std::uint64_t peak_bytes_=0;
    std::uint64_t known_full_bytes_=0;

    bool record_better(const DirectorySpoolRecord&a,const DirectorySpoolRecord&b)const{
        if(a.detail_priority!=b.detail_priority)return a.detail_priority>b.detail_priority;
        if(a.full_bytes!=b.full_bytes)return a.full_bytes<b.full_bytes;
        return directory_report_key(a.input)<directory_report_key(b.input);
    }
    void drop_record(std::size_t i,const char*reason){
        if(i>=records_.size()||!records_[i].selected)return;
        auto&r=records_[i];r.selected=false;r.deferred_reason=reason;selected_bytes_=r.full_bytes>selected_bytes_?0:selected_bytes_-r.full_bytes;
        std::error_code ec;std::filesystem::remove(r.payload,ec);r.payload.clear();
    }
    void enforce_inline_budget(){
        while(selected_bytes_>kDirectoryInlineReportBytes){
            std::optional<std::size_t>worst;
            for(std::size_t i=0;i<records_.size();++i)if(records_[i].selected&&(!worst||record_better(records_[*worst],records_[i])))worst=i;
            if(!worst)break;
            drop_record(*worst,"DIRECTORY_INLINE_REPORT_BUDGET");
        }
    }
public:
    DirectoryReportSpool(bool json,prts::ReportLanguage language):json_(json),language_(language){
        std::error_code ec;auto base=std::filesystem::temp_directory_path(ec);if(ec){error_="cannot locate temporary directory for report spool: "+ec.message();return;}
        const auto nonce=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        for(unsigned attempt=0;attempt<128;++attempt){
            auto name="auto-refirst-report-spool-"+std::to_string(nonce)+"-"+std::to_string(attempt);auto candidate=base/prts::path_from_utf8(name);ec.clear();
            if(std::filesystem::create_directory(candidate,ec)){root_=std::move(candidate);break;}
            if(ec){error_="cannot create temporary report spool: "+ec.message();return;}
        }
        if(root_.empty()){error_="cannot create unique temporary report spool";return;}
#ifndef _WIN32
        ec.clear();std::filesystem::permissions(root_,std::filesystem::perms::owner_all,std::filesystem::perm_options::replace,ec);if(ec){error_="cannot restrict temporary report spool permissions: "+ec.message();std::filesystem::remove_all(root_,ec);root_.clear();return;}
#endif
    }
    ~DirectoryReportSpool(){if(root_.empty())return;std::error_code ec;std::filesystem::remove_all(root_,ec);}
    DirectoryReportSpool(const DirectoryReportSpool&)=delete;
    DirectoryReportSpool& operator=(const DirectoryReportSpool&)=delete;
    bool ready()const{return !root_.empty()&&error_.empty();}
    const std::string& error()const{return error_;}
    std::vector<DirectorySpoolRecord>& records(){return records_;}
    const std::vector<DirectorySpoolRecord>& records()const{return records_;}
    bool add(const prts::AnalysisReport&report,std::int64_t detail_priority,std::string&error){
        if(!ready()){error=error_;return false;}
        auto payload=root_/prts::path_from_utf8(std::to_string(records_.size())+(json_?".json":".txt"));
        std::ofstream out(payload,std::ios::binary|std::ios::trunc);if(!out){error="cannot create temporary directory report spool file";return false;}
        std::uint64_t full_bytes=0,staged_bytes=0;
        if(json_){
            CappedSpoolStreambuf buf(out,kDirectoryPerReportBytes);std::ostream bounded(&buf);prts::render_json(bounded,report);bounded.flush();full_bytes=buf.total();staged_bytes=buf.written();if(buf.failed()){error="temporary directory report spool write failed";return false;}
        }else{
            auto text=prts::render_text(report,language_);full_bytes=text.size();staged_bytes=std::min<std::uint64_t>(full_bytes,kDirectoryPerReportBytes);if(staged_bytes)out.write(text.data(),static_cast<std::streamsize>(staged_bytes));
        }
        out.flush();if(!out){error="temporary directory report spool write failed";return false;}
        peak_bytes_=std::max(peak_bytes_,sat_add(selected_bytes_,staged_bytes));
        if(peak_bytes_>kDirectoryReportSpoolHardBytes){error="internal directory report spool hard-budget invariant failed";return false;}
        known_full_bytes_=sat_add(known_full_bytes_,full_bytes);
        DirectorySpoolRecord rec;rec.input=report.input;rec.payload=payload;rec.full_bytes=full_bytes;rec.detail_priority=detail_priority;
        if(full_bytes>kDirectoryPerReportBytes){
            rec.deferred_reason="PER_REPORT_BYTE_BUDGET";std::error_code ec;std::filesystem::remove(payload,ec);rec.payload.clear();records_.push_back(std::move(rec));return true;
        }
        rec.selected=true;selected_bytes_=sat_add(selected_bytes_,full_bytes);records_.push_back(std::move(rec));enforce_inline_budget();return true;
    }
    bool validate(std::string&error)const{
        std::uint64_t on_disk=0;
        for(const auto&r:records_)if(r.selected){
            std::error_code ec;auto st=std::filesystem::symlink_status(r.payload,ec);if(ec||st.type()!=std::filesystem::file_type::regular){error="temporary directory report spool is unavailable or non-regular";return false;}
            auto n=std::filesystem::file_size(r.payload,ec);if(ec||n!=r.full_bytes){error="temporary directory report spool size changed after bounded selection";return false;}on_disk=sat_add(on_disk,n);
            std::ifstream in(r.payload,std::ios::binary);if(!in){error="cannot reopen temporary directory report spool";return false;}
        }
        if(on_disk!=selected_bytes_||on_disk>kDirectoryInlineReportBytes||peak_bytes_>kDirectoryReportSpoolHardBytes){error="internal directory report spool accounting invariant failed";return false;}
        return true;
    }
    void annotate_plan(prts::DirectoryPlan&plan)const{
        std::map<std::string,const DirectorySpoolRecord*>by_input;for(const auto&r:records_)by_input[directory_report_key(r.input)]=&r;
        for(auto&c:plan.candidates){auto it=by_input.find(directory_report_key(c.path));if(it==by_input.end()){c.report_detail_state=c.analysis_state=="ANALYZED"?"DEFERRED":"NOT_ANALYZED";c.report_detail_reason=c.analysis_state=="ANALYZED"?"REPORT_METADATA_UNAVAILABLE":"file was not analyzed";continue;}const auto&r=*it->second;c.report_full_bytes=r.full_bytes;c.report_detail_state=r.selected?"INLINE_FULL":"DEFERRED";c.report_detail_reason=r.selected?"selected by semantic priority within bounded default directory detail budget":r.deferred_reason;}
    }
    std::vector<std::filesystem::path> selected_paths()const{std::vector<std::filesystem::path>out;for(const auto&r:records_)if(r.selected)out.push_back(r.payload);return out;}
    prts::DirectoryReportRendering rendering()const{
        prts::DirectoryReportRendering x;x.profile="bounded_default";x.full_report_count=records_.size();for(const auto&r:records_)if(r.selected)++x.full_reports_rendered;x.full_reports_deferred=x.full_report_count-x.full_reports_rendered;x.partial=x.full_reports_deferred!=0;x.truncated=x.partial;x.known_full_report_bytes=known_full_bytes_;x.inline_report_bytes=selected_bytes_;x.known_deferred_report_bytes=known_full_bytes_>=selected_bytes_?known_full_bytes_-selected_bytes_:0;x.inline_report_budget_bytes=kDirectoryInlineReportBytes;x.per_report_max_bytes=kDirectoryPerReportBytes;x.spool_hard_budget_bytes=kDirectoryReportSpoolHardBytes;x.spool_peak_bytes=peak_bytes_;x.selection_policy="semantic priority: Tier 1/2 and decisive application roles, high-priority evidence, failures/partials, then candidate score; per-report and aggregate byte budgets are hard";x.reason=x.partial?"one or more complete per-file reports were deferred by the default bounded directory rendering budget":"all complete per-file reports fit the bounded default directory rendering budget";x.detail_retrieval_mode="reanalyze_file";x.detail_retrieval_command="auto-refirst <file-from-directory_plan.file_states> --json";return x;
    }
};

std::string directory_report_key(const std::filesystem::path&p){return prts::path_utf8(p.lexically_normal());}

void render_directory_modality_text(const prts::RuntimeModalityGuidance&m){
    std::cout<<"Runtime modality guidance: policy="<<m.policy
             <<" static_evidence_only="<<(m.static_evidence_only?"true":"false")
             <<" runtime_execution_authorized="<<(m.runtime_execution_authorized?"true":"false")<<"\n";
    for(const auto&x:m.priority_guidance)std::cout<<"  priority: "<<x<<"\n";
    for(const auto&r:m.requirements){
        std::cout<<"  modality: "<<r.modality<<" state="<<r.state<<" confidence="<<r.confidence<<" gate="<<r.evidence_gate<<"\n";
        if(!r.reason.empty())std::cout<<"    reason: "<<r.reason<<"\n";
        for(const auto&e:r.evidence)std::cout<<"    evidence: "<<e<<"\n";
        for(const auto&e:r.negative_evidence)std::cout<<"    negative_evidence: "<<e<<"\n";
        for(const auto&a:r.artifacts)std::cout<<"    artifact: "<<prts::path_utf8(a)<<"\n";
    }
}

void render_directory_text(const prts::DirectoryPlan&plan,const prts::DirectorySummary&summary,const std::vector<prts::AnalysisReport>&reports,prts::ReportLanguage lang){
    std::cout<<"Directory summary: files="<<summary.total_files<<" analyzed="<<summary.analyzed_files<<" skipped="<<summary.skipped_files<<" bytes="<<summary.total_bytes<<" relationships="<<summary.artifact_relationship_count<<" failures="<<summary.failures<<" partials="<<summary.partials<<" elapsed_ms="<<summary.elapsed_ms<<"\n";
    if(!summary.type_counts.empty()){std::cout<<"  types:";for(const auto&kv:summary.type_counts)std::cout<<' '<<kv.first<<'='<<kv.second;std::cout<<"\n";}if(!summary.confirmed_ecosystems.empty()){std::cout<<"  ecosystems:";for(const auto&x:summary.confirmed_ecosystems)std::cout<<' '<<x;std::cout<<"\n";}
    render_directory_modality_text(summary.runtime_modality);
    if(summary.unity_engine_state!="ABSENT"){std::cout<<"  Unity: engine="<<summary.unity_engine_state<<" backend="<<summary.unity_backend_state<<" mono_relationships="<<summary.unity_mono_relationship_count<<" il2cpp_relationships="<<summary.unity_il2cpp_relationship_count<<"\n";if(!summary.unity_next_priority.empty())std::cout<<"  next priority: "<<summary.unity_next_priority<<"\n";}
    std::cout<<"Directory plan: max_depth="<<plan.max_depth<<" runtime_targets="<<plan.max_runtime_targets<<" total_runtime_budget_ms="<<plan.total_runtime_budget_ms<<" per_target_timeout_ms="<<plan.per_target_timeout_ms<<(plan.run_all?" run_all":"")<<"\n";constexpr std::size_t cap=128;for(std::size_t i=0;i<plan.candidates.size()&&i<cap;++i){const auto&c=plan.candidates[i];std::cout<<"  ["<<c.priority_tier<<" score="<<c.priority_score<<"] "<<prts::path_utf8(c.path)<<" type="<<c.type_hint<<" role="<<c.role<<" runtime="<<c.runtime_state<<"\n";for(std::size_t z=0;z<c.priority_reasons.size()&&z<4;++z)std::cout<<"    reason: "<<c.priority_reasons[z]<<"\n";if(!c.runtime_skip_reason.empty())std::cout<<"    runtime_skip: "<<c.runtime_skip_reason<<"\n";}if(plan.candidates.size()>cap)std::cout<<"  ... "<<(plan.candidates.size()-cap)<<" more candidates; use --json for the complete structured report\n";for(std::size_t i=0;i<plan.relationships.size()&&i<64;++i){const auto&r=plan.relationships[i];std::cout<<"  relationship["<<r.state<<"] "<<r.kind<<": "<<prts::path_utf8(r.first)<<" <-> "<<prts::path_utf8(r.second)<<" -- "<<r.reason<<"\n";}for(std::size_t i=0;i<plan.traversal_skips.size()&&i<32;++i)std::cout<<"  traversal_skip: "<<prts::path_utf8(plan.traversal_skips[i].path)<<" -- "<<plan.traversal_skips[i].reason<<"\n";
    std::size_t shown=0;for(const auto&c:plan.candidates){if(c.priority_tier=="Tier 3")continue;auto it=std::find_if(reports.begin(),reports.end(),[&](const auto&r){return r.input==c.path;});if(it==reports.end())continue;if(shown++>=32)break;std::cout<<"\n============================================================\n\n"<<prts::render_text(*it,lang);}if(shown==0&&!reports.empty())std::cout<<"\nNo Tier 1/2 detailed report was selected for text output; --json contains every analyzed file.\n";else if(shown>=32)std::cout<<"\nDetailed text reports capped at 32 prioritized files; --json contains every analyzed file.\n";
}

bool render_directory_text_spooled(const prts::DirectoryPlan&plan,const prts::DirectorySummary&summary,const std::vector<DirectorySpoolRecord>&records,const prts::DirectoryReportRendering&rendering,const prts::DirectoryArtifactRendering&artifact_rendering,std::string&error){
    std::cout<<"Directory summary: files="<<summary.total_files<<" discovered_regular_files="<<summary.discovered_regular_files<<" omitted_candidates="<<summary.candidate_omitted_count<<" partial="<<(summary.partial?"true":"false")<<" analyzed="<<summary.analyzed_files<<" skipped="<<summary.skipped_files<<" bytes="<<summary.total_bytes<<" relationships="<<summary.artifact_relationship_count<<" failures="<<summary.failures<<" partials="<<summary.partials<<" elapsed_ms="<<summary.elapsed_ms<<"\n";
    for(const auto&reason:summary.partial_reasons)std::cout<<"  partial_reason: "<<reason<<"\n";
    std::cout<<"  report_detail: rendered="<<rendering.full_reports_rendered<<" deferred="<<rendering.full_reports_deferred<<" inline_bytes="<<rendering.inline_report_bytes<<"/"<<rendering.inline_report_budget_bytes<<" spool_peak_bytes="<<rendering.spool_peak_bytes<<"/"<<rendering.spool_hard_budget_bytes<<" partial="<<(rendering.partial?"true":"false")<<"\n";
    std::cout<<"  artifact_output: bytes="<<artifact_rendering.materialized_bytes<<"/"<<artifact_rendering.max_bytes<<" files="<<artifact_rendering.materialized_files<<"/"<<artifact_rendering.max_files<<" deferred_candidates="<<artifact_rendering.deferred_candidate_count<<" partial="<<(artifact_rendering.partial?"true":"false")<<"\n";
    if(!summary.type_counts.empty()){std::cout<<"  types:";for(const auto&kv:summary.type_counts)std::cout<<' '<<kv.first<<'='<<kv.second;std::cout<<"\n";}if(!summary.confirmed_ecosystems.empty()){std::cout<<"  ecosystems:";for(const auto&x:summary.confirmed_ecosystems)std::cout<<' '<<x;std::cout<<"\n";}
    render_directory_modality_text(summary.runtime_modality);
    if(summary.unity_engine_state!="ABSENT"){std::cout<<"  Unity: engine="<<summary.unity_engine_state<<" backend="<<summary.unity_backend_state<<" mono_relationships="<<summary.unity_mono_relationship_count<<" il2cpp_relationships="<<summary.unity_il2cpp_relationship_count<<"\n";if(!summary.unity_next_priority.empty())std::cout<<"  next priority: "<<summary.unity_next_priority<<"\n";}
    std::cout<<"Directory plan: max_depth="<<plan.max_depth<<" runtime_targets="<<plan.max_runtime_targets<<" total_runtime_budget_ms="<<plan.total_runtime_budget_ms<<" per_target_timeout_ms="<<plan.per_target_timeout_ms<<(plan.run_all?" run_all":"")<<"\n";constexpr std::size_t cap=128;for(std::size_t i=0;i<plan.candidates.size()&&i<cap;++i){const auto&c=plan.candidates[i];std::cout<<"  ["<<c.priority_tier<<" score="<<c.priority_score<<"] "<<prts::path_utf8(c.path)<<" type="<<c.type_hint<<" role="<<c.role<<" runtime="<<c.runtime_state<<"\n";for(std::size_t z=0;z<c.priority_reasons.size()&&z<4;++z)std::cout<<"    reason: "<<c.priority_reasons[z]<<"\n";if(!c.runtime_skip_reason.empty())std::cout<<"    runtime_skip: "<<c.runtime_skip_reason<<"\n";}if(plan.candidates.size()>cap)std::cout<<"  ... "<<(plan.candidates.size()-cap)<<" more candidates; use --json for the complete structured report\n";for(std::size_t i=0;i<plan.relationships.size()&&i<64;++i){const auto&r=plan.relationships[i];std::cout<<"  relationship["<<r.state<<"] "<<r.kind<<": "<<prts::path_utf8(r.first)<<" <-> "<<prts::path_utf8(r.second)<<" -- "<<r.reason<<"\n";}for(std::size_t i=0;i<plan.traversal_skips.size()&&i<32;++i)std::cout<<"  traversal_skip: "<<prts::path_utf8(plan.traversal_skips[i].path)<<" -- "<<plan.traversal_skips[i].reason<<"\n";
    std::map<std::string,std::filesystem::path> payload_by_input;for(const auto&r:records)if(r.selected)payload_by_input[directory_report_key(r.input)]=r.payload;
    std::size_t shown=0;for(const auto&c:plan.candidates){if(c.priority_tier=="Tier 3")continue;auto it=payload_by_input.find(directory_report_key(c.path));if(it==payload_by_input.end())continue;if(shown++>=32)break;std::cout<<"\n============================================================\n\n";std::ifstream in(it->second,std::ios::binary);if(!in){error="cannot reopen temporary directory text report spool";return false;}std::cout<<in.rdbuf();if(!std::cout){error="directory text report output write failed";return false;}}
    if(shown==0&&!records.empty())std::cout<<"\nNo Tier 1/2 full detail fit the bounded default directory report budget; rerun a file directly for complete detail.\n";else if(shown>=32)std::cout<<"\nDetailed text reports capped at 32 prioritized files; rerun a file directly for complete detail.\n";
    if(!std::cout){error="directory text report output write failed";return false;}return true;
}

int analyze_directory_static_spooled(const std::filesystem::path&input,const Options&opt){
    const auto begin=std::chrono::steady_clock::now();auto plan=prts::inventory_directory(input,opt.directory_max_depth);plan.max_runtime_targets=opt.max_runtime_targets;plan.total_runtime_budget_ms=opt.total_runtime_budget_ms;plan.per_target_timeout_ms=opt.timeout_ms;plan.run_all=opt.run_all;
    if(plan.candidates.empty()){for(const auto&s:plan.traversal_skips)std::cerr<<prts::path_utf8(s.path)<<": "<<s.reason<<"\n";std::cerr<<"no regular input files found\n";return exit_code(ExitCode::Input);}
    DirectoryReportSpool spool(opt.json,opt.report_language);if(!spool.ready()){std::cerr<<spool.error()<<"\n";return exit_code(ExitCode::Internal);}
    Options static_opt=opt;static_opt.run_requested=false;static_opt.run_mode.clear();static_opt.apply=false;static_opt.run_all=false;static_opt.recursive=false;
    const bool bounded_artifacts=!opt.extract;
    prts::DirectoryArtifactRendering artifact_rendering;
    artifact_rendering.profile=bounded_artifacts?"bounded_default":"explicit_extract_per_file";
    artifact_rendering.max_bytes=bounded_artifacts?kDirectoryArtifactBytes:0;
    artifact_rendering.max_files=bounded_artifacts?kDirectoryArtifactFiles:0;
    artifact_rendering.pre_relationship_max_bytes=bounded_artifacts?kDirectoryPreRelationshipArtifactBytes:0;
    artifact_rendering.pre_relationship_max_files=bounded_artifacts?kDirectoryPreRelationshipArtifactFiles:0;
    artifact_rendering.post_relationship_reserve_bytes=bounded_artifacts?kDirectoryArtifactBytes-kDirectoryPreRelationshipArtifactBytes:0;
    artifact_rendering.post_relationship_reserve_files=bounded_artifacts?kDirectoryArtifactFiles-kDirectoryPreRelationshipArtifactFiles:0;
    artifact_rendering.selection_policy=bounded_artifacts?"preflight semantic priority order uses at most 56 MiB / 384 files, reserving 8 MiB / 128 files inside the 64 MiB / 512 total hard cap for post-relationship decisive materialization and bounded HIGH-child reports; an over-budget candidate root is rolled back atomically and reanalyzed without automatic materialization":"explicit --extract keeps the established per-file extraction contract; the default directory aggregate cap is not applied";
    artifact_rendering.detail_retrieval_mode="reanalyze_file";
    artifact_rendering.detail_retrieval_command="auto-refirst <file-from-directory_plan.file_states> --json";
    std::uint64_t artifact_bytes_used=0,artifact_files_used=0;
    std::vector<prts::DirectoryReportIndex> compact;compact.reserve(plan.candidates.size());std::vector<prts::AnalysisReport> retained;std::uint64_t spool_elapsed_ms=0;std::size_t successful_inputs=0;
    auto spool_report=[&](const prts::AnalysisReport&r,const prts::DirectoryCandidate&c,const prts::DirectoryReportIndex&idx){std::string why;auto st=std::chrono::steady_clock::now();const bool ok=spool.add(r,directory_report_detail_priority(c,idx),why);spool_elapsed_ms=sat_add(spool_elapsed_ms,static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-st).count()));if(!ok)std::cerr<<why<<"\n";return ok;};
    for(auto&c:plan.candidates){
        if(!c.readable)continue;
        auto st=std::chrono::steady_clock::now();Options candidate_opt=static_opt;bool forced_deferred=false,unsafe_prior_root=false;
        const auto artifact_root=artifact_root_for_input(c.path);
        std::uint64_t remaining_bytes=bounded_artifacts&&artifact_bytes_used<kDirectoryPreRelationshipArtifactBytes?kDirectoryPreRelationshipArtifactBytes-artifact_bytes_used:0;
        std::uint64_t remaining_files=bounded_artifacts&&artifact_files_used<kDirectoryPreRelationshipArtifactFiles?kDirectoryPreRelationshipArtifactFiles-artifact_files_used:0;
        if(bounded_artifacts){
            std::string reset_error;if(!reset_directory_artifact_root(artifact_root,reset_error)){unsafe_prior_root=true;forced_deferred=true;c.artifact_materialization_state="REFUSED_UNSAFE_ROOT";c.artifact_materialization_reason=reset_error;}
            if(!unsafe_prior_root&&(!remaining_bytes||!remaining_files)){forced_deferred=true;c.artifact_materialization_state="DEFERRED";c.artifact_materialization_reason="directory aggregate artifact byte/file budget is exhausted";}
            if(forced_deferred){candidate_opt.suppress_auto_materialization=true;candidate_opt.suppress_auto_child_analysis=true;candidate_opt.extract_budget_bytes=0;candidate_opt.extract_budget_files=0;candidate_opt.artifact_max_bytes=0;candidate_opt.artifact_max_nodes=0;}
            else{candidate_opt.suppress_auto_child_analysis=true;candidate_opt.extract_budget_bytes=std::min(candidate_opt.extract_budget_bytes,remaining_bytes);candidate_opt.extract_budget_files=static_cast<std::uint32_t>(std::min<std::uint64_t>(candidate_opt.extract_budget_files,remaining_files));candidate_opt.artifact_max_bytes=std::min(candidate_opt.artifact_max_bytes,remaining_bytes);candidate_opt.artifact_max_nodes=static_cast<std::uint32_t>(std::min<std::uint64_t>(candidate_opt.artifact_max_nodes,remaining_files));}
        }
        auto r=analyze_file(c.path,candidate_opt);
        if(bounded_artifacts){
            if(unsafe_prior_root){artifact_rendering.partial=true;++artifact_rendering.deferred_candidate_count;++artifact_rendering.unknown_omitted_candidate_count;note_directory_artifact_deferred(r,0,0,"automatic directory materialization was refused because the pre-existing product artifact root was unsafe to reset");}
            else{
                DirectoryArtifactTreeStats stats;std::string artifact_error;if(!inspect_directory_artifact_tree(artifact_root,stats,artifact_error)){std::cerr<<artifact_error<<"\n";return exit_code(ExitCode::Internal);}
                if(forced_deferred){
                    if(stats.files||stats.bytes){std::cerr<<"internal directory artifact invariant failed: suppressed candidate still materialized output\n";return exit_code(ExitCode::Internal);}
                    std::string cleanup_error;if(!reset_directory_artifact_root(artifact_root,cleanup_error)){std::cerr<<cleanup_error<<"\n";return exit_code(ExitCode::Internal);}
                    artifact_rendering.partial=true;++artifact_rendering.deferred_candidate_count;++artifact_rendering.unknown_omitted_candidate_count;note_directory_artifact_deferred(r,0,0,"automatic materialization was deferred after the directory aggregate budget was exhausted");
                }else if(stats.bytes>remaining_bytes||stats.files>remaining_files){
                    artifact_rendering.partial=true;++artifact_rendering.deferred_candidate_count;artifact_rendering.known_omitted_bytes=sat_add(artifact_rendering.known_omitted_bytes,stats.bytes);artifact_rendering.known_omitted_files=sat_add(artifact_rendering.known_omitted_files,stats.files);
                    std::string cleanup_error;if(!reset_directory_artifact_root(artifact_root,cleanup_error)){std::cerr<<cleanup_error<<"\n";return exit_code(ExitCode::Internal);}
                    Options retry_opt=static_opt;retry_opt.suppress_auto_materialization=true;retry_opt.suppress_auto_child_analysis=true;retry_opt.extract_budget_bytes=0;retry_opt.extract_budget_files=0;retry_opt.artifact_max_bytes=0;retry_opt.artifact_max_nodes=0;
                    r=analyze_file(c.path,retry_opt);DirectoryArtifactTreeStats retry_stats;if(!inspect_directory_artifact_tree(artifact_root,retry_stats,artifact_error)){std::cerr<<artifact_error<<"\n";return exit_code(ExitCode::Internal);}if(retry_stats.files||retry_stats.bytes){std::cerr<<"internal directory artifact invariant failed: rollback reanalysis still materialized output\n";return exit_code(ExitCode::Internal);}if(!reset_directory_artifact_root(artifact_root,cleanup_error)){std::cerr<<cleanup_error<<"\n";return exit_code(ExitCode::Internal);}
                    c.artifact_materialization_state="DEFERRED";c.artifact_materialization_reason="candidate automatic output exceeded the remaining directory aggregate byte/file allowance and was atomically rolled back";note_directory_artifact_deferred(r,stats.files,stats.bytes,c.artifact_materialization_reason);
                }else{
                    artifact_bytes_used=sat_add(artifact_bytes_used,stats.bytes);artifact_files_used=sat_add(artifact_files_used,stats.files);c.artifact_materialized_bytes=stats.bytes;c.artifact_materialized_files=stats.files;
                    if(stats.files){
                        ++artifact_rendering.retained_candidate_roots;
                        std::vector<prts::AnalysisArtifact>bounded_children;for(const auto&a:r.artifacts)if(automatic_static_child_candidate(a))bounded_children.push_back(a);
                        if(!bounded_children.empty()){
                            const auto before_bytes=artifact_bytes_used,before_files=artifact_files_used;
                            analyze_selected_static_artifact_children_bounded(r,c.path,static_opt,bounded_children,artifact_bytes_used,artifact_files_used,kDirectoryPreRelationshipArtifactBytes,kDirectoryPreRelationshipArtifactFiles);
                            c.artifact_materialized_bytes=sat_add(c.artifact_materialized_bytes,artifact_bytes_used-before_bytes);c.artifact_materialized_files=sat_add(c.artifact_materialized_files,artifact_files_used-before_files);
                        }
                        c.artifact_materialization_state=r.materialization.partial?"MATERIALIZED_PARTIAL":"MATERIALIZED";c.artifact_materialization_reason=r.materialization.partial?"materialized within the remaining directory aggregate allowance; compact high-value child reports were bounded and one or more derivatives were deferred":"materialized within the remaining directory aggregate allowance; high-value child reports use compact no-sidecar summaries";
                    }else{c.artifact_materialization_state="NO_OUTPUT";c.artifact_materialization_reason="analysis produced no regular automatic artifact files";}
                }
            }
        }
        if(!root_input_analysis_failed(r))++successful_inputs;
        c.analysis_elapsed_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-st).count());prts::refine_directory_candidate(c,r);compact.push_back(prts::make_directory_report_index(r));auto&idx=compact.back();
        if(prts::directory_report_requires_post_relationship_retention(r))retained.push_back(std::move(r));else if(!spool_report(r,c,idx))return exit_code(ExitCode::Internal);
    }
    if(!successful_inputs){std::cerr<<"no readable regular input files found\n";return exit_code(ExitCode::Input);}
    prts::build_directory_relationships(plan,compact);
    integrate_directory_godot_semantics(plan,compact,retained,static_opt,bounded_artifacts?&artifact_bytes_used:nullptr,bounded_artifacts?&artifact_files_used:nullptr,bounded_artifacts?&artifact_rendering:nullptr);
    artifact_rendering.materialized_bytes=artifact_bytes_used;artifact_rendering.materialized_files=artifact_files_used;
    artifact_rendering.partial=artifact_rendering.partial||artifact_rendering.deferred_candidate_count!=0;
    artifact_rendering.reason=bounded_artifacts?(artifact_rendering.partial?"one or more automatic artifact outputs or derivatives were deferred/refused to preserve the directory aggregate hard bound":"all automatic artifact outputs fit the default directory aggregate hard bound"):"explicit --extract requested the established per-file materialization behavior; no default directory aggregate cap is claimed";
    std::map<std::string,std::size_t> compact_by_input;for(std::size_t i=0;i<compact.size();++i)compact_by_input[directory_report_key(compact[i].input)]=i;std::set<std::string> retained_inputs;for(const auto&r:retained)retained_inputs.insert(directory_report_key(r.input));
    for(const auto&r:compact)if(r.post_relationship_mutated&&!retained_inputs.count(directory_report_key(r.input))){std::cerr<<"internal directory retention invariant failed: relationship-mutated report was not retained: "<<prts::path_utf8(r.input)<<"\n";return exit_code(ExitCode::Internal);}
    for(auto&r:retained){
        auto ci=compact_by_input.find(directory_report_key(r.input));if(ci==compact_by_input.end()){std::cerr<<"internal directory retention invariant failed: retained report has no compact index\n";return exit_code(ExitCode::Internal);}auto&idx=compact[ci->second];prts::apply_directory_report_index_mutations(r,idx);r.analysis_guidance=prts::build_analysis_guidance(r);
        if(idx.post_relationship_mutated){auto refreshed=prts::make_directory_report_index(r);refreshed.post_relationship_mutated=true;idx=std::move(refreshed);}auto pc=std::find_if(plan.candidates.begin(),plan.candidates.end(),[&](const auto&c){return directory_report_key(c.path)==directory_report_key(r.input);});if(pc==plan.candidates.end()){std::cerr<<"internal directory retention invariant failed: retained report has no candidate\n";return exit_code(ExitCode::Internal);}if(!spool_report(r,*pc,idx))return exit_code(ExitCode::Internal);
    }
    std::vector<prts::AnalysisReport>().swap(retained);prts::sort_directory_candidates(plan);
    std::map<std::string,std::size_t> rank;for(std::size_t i=0;i<plan.candidates.size();++i)rank[directory_report_key(plan.candidates[i].path)]=i;
    std::stable_sort(spool.records().begin(),spool.records().end(),[&](const auto&a,const auto&b){auto ai=rank.find(directory_report_key(a.input)),bi=rank.find(directory_report_key(b.input));auto av=ai==rank.end()?std::numeric_limits<std::size_t>::max():ai->second,bv=bi==rank.end()?std::numeric_limits<std::size_t>::max():bi->second;return av<bv;});
    if(spool.records().size()!=compact.size()){std::cerr<<"internal directory retention invariant failed: report spool/index cardinality mismatch\n";return exit_code(ExitCode::Internal);}std::string spool_error;if(!spool.validate(spool_error)){std::cerr<<spool_error<<"\n";return exit_code(ExitCode::Internal);}spool.annotate_plan(plan);
    const auto raw_elapsed=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count());const auto elapsed=raw_elapsed>spool_elapsed_ms?raw_elapsed-spool_elapsed_ms:0;auto summary=prts::summarize_directory(plan,compact,elapsed);auto rendering=spool.rendering();
    if(rendering.partial){summary.partial=true;summary.partial_reasons.push_back("bounded default report rendering deferred "+std::to_string(rendering.full_reports_deferred)+" of "+std::to_string(rendering.full_report_count)+" complete per-file reports; compact state remains present for every admitted file");}
    if(artifact_rendering.partial){summary.partial=true;summary.partial_reasons.push_back("bounded default artifact materialization deferred or refused one or more automatic outputs under the shared directory aggregate byte/file budget");}
    if(opt.json){auto paths=spool.selected_paths();if(!prts::render_directory_json_spooled(std::cout,plan,summary,paths,rendering,artifact_rendering,spool_error)){std::cerr<<spool_error<<"\n";return exit_code(ExitCode::Internal);}}
    else if(!render_directory_text_spooled(plan,summary,spool.records(),rendering,artifact_rendering,spool_error)){std::cerr<<spool_error<<"\n";return exit_code(ExitCode::Internal);}
    return finish_standard_output(ExitCode::Success);
}

int analyze_directory_retained(const std::filesystem::path&input,const Options&opt){
    const auto begin=std::chrono::steady_clock::now();auto plan=prts::inventory_directory(input,opt.directory_max_depth);plan.max_runtime_targets=opt.max_runtime_targets;plan.total_runtime_budget_ms=opt.total_runtime_budget_ms;plan.per_target_timeout_ms=opt.timeout_ms;plan.run_all=opt.run_all;if(plan.candidates.empty()){for(const auto&s:plan.traversal_skips)std::cerr<<prts::path_utf8(s.path)<<": "<<s.reason<<"\n";std::cerr<<"no regular input files found\n";return exit_code(ExitCode::Input);}
    Options static_opt=opt;static_opt.run_requested=false;static_opt.run_mode.clear();static_opt.apply=false;static_opt.run_all=false;static_opt.recursive=false;std::vector<prts::AnalysisReport>reports;reports.reserve(plan.candidates.size());std::size_t successful_inputs=0;
    for(auto&c:plan.candidates){if(!c.readable)continue;auto st=std::chrono::steady_clock::now();auto r=analyze_file(c.path,static_opt);if(!root_input_analysis_failed(r))++successful_inputs;c.analysis_elapsed_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-st).count());prts::refine_directory_candidate(c,r);reports.push_back(std::move(r));}
    if(!successful_inputs){std::cerr<<"no readable regular input files found\n";return exit_code(ExitCode::Input);}
    prts::build_directory_relationships(plan,reports);{std::vector<prts::DirectoryReportIndex> compact;compact.reserve(reports.size());for(const auto&r:reports)compact.push_back(prts::make_directory_report_index(r));integrate_directory_godot_semantics(plan,compact,reports,static_opt);}for(auto&r:reports)r.analysis_guidance=prts::build_analysis_guidance(r);prts::sort_directory_candidates(plan);
    if(opt.run_requested){
        std::uint64_t used=0;std::uint32_t targets=0;
        for(auto&c:plan.candidates){
            auto ri=std::find_if(reports.begin(),reports.end(),[&](const auto&r){return r.input==c.path;});
            if(ri==reports.end()){c.runtime_state="SKIPPED_NO_STATIC_REPORT";c.runtime_skip_reason="static report unavailable";continue;}
            prts::RuntimePlanningRequest preq;preq.requested=true;preq.apply_requested=opt.apply;preq.legacy_trace=opt.run_mode=="trace";preq.legacy_unpack=opt.run_mode=="unpack";preq.forced_python_probe=opt.run_mode=="python-probe";preq.timeout_ms=opt.timeout_ms;
            auto preview=prts::build_runtime_plan(*ri,preq);const auto*g=prts::runtime_plan_step(preview,"generic_runtime_trace");const auto*pstep=prts::runtime_plan_step(preview,"cpython_compiler_probe");const bool generic_selected=g&&g->selected,probe_selected=pstep&&pstep->selected;
            if(!generic_selected&&!probe_selected){c.runtime_state="SKIPPED_STATIC_NOT_EXECUTABLE";c.runtime_skip_reason=preview.runtime_eligibility_reason;if(pstep&&!pstep->reason.empty()&&pstep->reason!=c.runtime_skip_reason)c.runtime_skip_reason += "; "+pstep->reason;continue;}
            if(probe_selected&&!c.runtime_eligible){c.runtime_eligible=true;c.runtime_eligibility_reason="auxiliary CPython compiler probe can answer an unresolved static semantic question";}
            if(!opt.run_all&&c.priority_tier=="Tier 3"){c.runtime_state="SKIPPED_PRIORITY";c.runtime_skip_reason="Tier 3 is static-only under the conservative directory runtime policy; use --run-all to override";continue;}
            if(!opt.run_all&&targets>=plan.max_runtime_targets){c.runtime_state="SKIPPED_TARGET_LIMIT";c.runtime_skip_reason="directory runtime target limit reached";continue;}
            if(used>=plan.total_runtime_budget_ms){c.runtime_state="SKIPPED_RUNTIME_BUDGET";c.runtime_skip_reason="directory total runtime budget exhausted";continue;}
            Options ropt=opt;auto remain=plan.total_runtime_budget_ms-used;ropt.timeout_ms=static_cast<std::uint32_t>(std::min<std::uint64_t>(opt.timeout_ms,std::min<std::uint64_t>(remain,std::numeric_limits<std::uint32_t>::max())));c.runtime_selected=true;auto rt=std::chrono::steady_clock::now();execute_runtime_plan(*ri,c.path,ropt);analyze_runtime_children(*ri,c.path,ropt);c.runtime_elapsed_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-rt).count());used=std::min(plan.total_runtime_budget_ms,sat_add(used,ropt.timeout_ms));++targets;
            if(ri->replacement.performed)c.runtime_state="UNPACKED_VALIDATED_APPLIED";
            else if(ri->runtime.requested)c.runtime_state=ri->runtime.timed_out?"TIMED_OUT":"COMPLETED";
            else if(const auto*ps=prts::runtime_plan_step(ri->runtime_plan,"cpython_compiler_probe");ps&&ps->selected)c.runtime_state="COMPLETED_AUXILIARY_PROBE";
            else{c.runtime_state="SKIPPED_BY_RUNTIME_PLAN";c.runtime_skip_reason=ri->runtime_plan.runtime_eligibility_reason;}
        }
    }
    std::map<std::string,std::size_t> rank;for(std::size_t i=0;i<plan.candidates.size();++i)rank[prts::path_utf8(plan.candidates[i].path.lexically_normal())]=i;
    std::stable_sort(reports.begin(),reports.end(),[&](const auto&a,const auto&b){auto ai=rank.find(prts::path_utf8(a.input.lexically_normal())),bi=rank.find(prts::path_utf8(b.input.lexically_normal()));auto av=ai==rank.end()?std::numeric_limits<std::size_t>::max():ai->second,bv=bi==rank.end()?std::numeric_limits<std::size_t>::max():bi->second;return av<bv;});
    auto elapsed=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count());auto summary=prts::summarize_directory(plan,reports,elapsed);if(opt.json){std::string output_error;if(!prts::render_directory_json(std::cout,plan,summary,reports,output_error)){std::cerr<<output_error<<"\n";return exit_code(ExitCode::Internal);}}else render_directory_text(plan,summary,reports,opt.report_language);return finish_standard_output(ExitCode::Success);
}

int analyze_directory_default(const std::filesystem::path&input,const Options&opt){return opt.run_requested?analyze_directory_retained(input,opt):analyze_directory_static_spooled(input,opt);}


} // namespace

int main(int argc,char**argv){
#ifdef _WIN32
    DWORD cm=0;const bool stdout_console=GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE),&cm)!=0;const bool stderr_console=GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE),&cm)!=0;const bool stdin_console=GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),&cm)!=0;
    if(stdout_console||stderr_console)SetConsoleOutputCP(CP_UTF8);if(stdin_console)SetConsoleCP(CP_UTF8);
    auto utf8_storage=windows_utf8_args();std::vector<char*> utf8_argv;if(!utf8_storage.empty()){utf8_argv.reserve(utf8_storage.size()+1);for(auto&x:utf8_storage)utf8_argv.push_back(x.data());utf8_argv.push_back(nullptr);argc=static_cast<int>(utf8_storage.size());argv=utf8_argv.data();}
#endif
    if(argc>=2&&std::string(argv[1])=="--internal-cpython-probe")return prts::cpython_probe_child_main();
    try {
    if(argc<2){std::cerr<<"usage: auto-refirst <file|directory> [--run] [--apply] [--json] [--extract] [options]\nTry 'auto-refirst --help' for details.\n";return exit_code(ExitCode::Usage);}
    const std::string first=argv[1];if(first=="-h"||first=="--help"){print_help(std::cout);return finish_standard_output(ExitCode::Success);}if(first=="--version"){print_version(std::cout);return finish_standard_output(ExitCode::Success);}if(!first.empty()&&first.front()=='-'){std::cerr<<"unknown option: "<<first<<"\n";return exit_code(ExitCode::Usage);}
    Options opt;if(!parse_options(argc,argv,opt))return exit_code(ExitCode::Usage);if(opt.help){print_help(std::cout);return finish_standard_output(ExitCode::Success);}if(opt.version){print_version(std::cout);return finish_standard_output(ExitCode::Success);}
    const std::filesystem::path input=cli_path(argv[1]);std::error_code ec;const auto input_status=std::filesystem::status(input,ec);if(ec||input_status.type()==std::filesystem::file_type::not_found){std::cerr<<"cannot access input"<<(ec?": "+ec.message():std::string())<<"\n";return exit_code(ExitCode::Input);}const bool is_dir=input_status.type()==std::filesystem::file_type::directory;if(!is_dir&&input_status.type()!=std::filesystem::file_type::regular){std::cerr<<"input is neither a regular file nor a directory\n";return exit_code(ExitCode::Input);}
    if(opt.run_mode=="trace")std::cerr<<"warning: --run=trace is DEPRECATED; prefer bare --run for automatic deep non-destructive analysis\n";
    else if(opt.run_mode=="unpack")std::cerr<<"warning: --run=unpack is DEPRECATED and is non-destructive; prefer bare --run, and add --apply only when you explicitly authorize validated installation\n";
    else if(opt.run_mode=="python-probe")std::cerr<<"warning: --run=python-probe is a DEPRECATED forced-debug compatibility mode; bare --run routes the probe automatically when it can answer an unresolved question\n";
    if(!opt.search.empty()){prts::SearchOptions so;so.needle=opt.search;so.ignore_case=opt.search_ignore_case;so.recursive=true;so.json_lines=opt.json;auto st=prts::search_tree_streaming(input,so);if(!opt.json)std::cout<<"Search complete: files="<<st.files<<" bytes="<<st.bytes<<" matches="<<st.matches<<"\n";if(!st.files){std::cerr<<"no readable regular input files found\n";return finish_standard_output(ExitCode::Input);}return finish_standard_output(st.matches?ExitCode::Success:ExitCode::SearchNoMatch);}
    if(opt.recursive&&opt.extract&&opt.run_requested){std::cerr<<"recursive extracted-artifact analysis remains static-only; run root inputs without --extract --recursive so extracted children are never executed automatically\n";return exit_code(ExitCode::Usage);}
    if(is_dir&&opt.run_mode=="unpack"){std::cerr<<"deprecated --run=unpack is single-file compatibility only; for a directory use --run or --run --apply explicitly\n";return exit_code(ExitCode::Usage);}
    if(is_dir&&!(opt.recursive&&opt.extract))return analyze_directory_default(input,opt);
    std::vector<std::filesystem::path> files;
    if(is_dir){auto inv=prts::inventory_directory(input,opt.directory_max_depth);for(const auto&c:inv.candidates)if(c.readable)files.push_back(c.path);}
    else files.push_back(input);
    if(files.empty()){std::cerr<<"no regular input files found\n";return exit_code(ExitCode::Input);}

    std::vector<prts::AnalysisReport> reports;
    const bool artifact_graph_mode=opt.recursive&&opt.extract;
    std::size_t successful_root_inputs=0;
    if(!artifact_graph_mode){
        reports.reserve(files.size());for(const auto&f:files){auto report=analyze_file(f,opt);if(!root_input_analysis_failed(report))++successful_root_inputs;reports.push_back(std::move(report));}
    }else{
        prts::ArtifactGraphInfo graph;graph.enabled=true;graph.max_depth=opt.artifact_max_depth;graph.max_nodes=opt.artifact_max_nodes;graph.max_total_bytes=opt.artifact_max_bytes;
        std::deque<PendingArtifact> queue;
        if(files.size()>opt.artifact_max_nodes){graph.truncated=true;graph.skipped_limits=cap_count(files.size()-opt.artifact_max_nodes);graph.warnings.push_back("input root count exceeds artifact node limit; remaining roots were not analyzed");}
        for(std::size_t i=0;i<files.size()&&i<opt.artifact_max_nodes;++i)queue.push_back({files[i],{},files[i],"input",0,true});
        std::map<std::string,std::filesystem::path> first_by_sha;
        while(!queue.empty()){
            auto cur=std::move(queue.front());queue.pop_front();
            Options node_opt=opt;node_opt.recursive=false;node_opt.run_requested=false;node_opt.run_mode.clear();node_opt.apply=false;node_opt.run_all=false;node_opt.extract=cur.depth<opt.artifact_max_depth;node_opt.artifact_graph_node=true;node_opt.suppress_auto_child_analysis=true;
            node_opt.extract_budget_bytes=graph.materialized_bytes<graph.max_total_bytes?graph.max_total_bytes-graph.materialized_bytes:0;
            auto occupied=reports.size()+queue.size()+1;
            node_opt.extract_budget_files=occupied<graph.max_nodes?static_cast<std::uint32_t>(graph.max_nodes-occupied):0;
            auto report=analyze_file(cur.path,node_opt);if(cur.root&&!root_input_analysis_failed(report))++successful_root_inputs;report.artifact.graph_member=true;report.artifact.root=cur.root;report.artifact.depth=cur.depth;report.artifact.parent=cur.parent;report.artifact.root_input=cur.root_input;report.artifact.offset_basis=cur.path;report.artifact.offset_space="current_input_file";report.artifact.relation=cur.relation;
            ++graph.nodes;
            if(!report.input_snapshot.sha256.empty())first_by_sha.try_emplace(report.input_snapshot.sha256,cur.path);
            if(report.pyinstaller_extract.budget_exhausted){graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("PyInstaller extraction hit the recursive byte/file budget while decoding outer/PYZ artifacts at "+prts::path_utf8(cur.path));}
            if(report.apk_extract.budget_exhausted){graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("APK analysis-only extraction omitted lower-priority static children at "+prts::path_utf8(cur.path)+" because the remaining byte/file budget was insufficient");}
            if(report.jar_extract.budget_exhausted){graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("JAR analysis-only extraction omitted lower-priority static children at "+prts::path_utf8(cur.path)+" because the remaining byte/file budget was insufficient");}
            if(report.godot_extract.budget_exhausted){graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("Godot extraction omitted lower-priority materialization at "+prts::path_utf8(cur.path)+" because the remaining byte/file budget was insufficient");}
            if(report.nuitka_extract.budget_exhausted){graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("Nuitka extraction omitted lower-priority materialization at "+prts::path_utf8(cur.path)+" because the remaining byte/file budget was insufficient");}
            if(report.asar_extract.budget_exhausted){graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("ASAR extraction omitted lower-priority materialization at "+prts::path_utf8(cur.path)+" because the remaining byte/file budget was insufficient");}
            if(report.wxapkg_extract.budget_exhausted){graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("wxapkg extraction omitted lower-priority materialization at "+prts::path_utf8(cur.path)+" because the remaining byte/file budget was insufficient");}
            if(report.renpy_rpa_extract.budget_exhausted){graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("Ren'Py RPA extraction omitted lower-priority materialization at "+prts::path_utf8(cur.path)+" because the remaining byte/file budget was insufficient");}
            for(const auto&finding:report.findings){
                if(finding.family!="Artifact extraction budget"||finding.state!="REFUSED")continue;
                graph.truncated=true;++graph.skipped_limits;auto it=finding.fields.find("ecosystem");
                graph.warnings.push_back("recursive extraction preflight refused "+(it==finding.fields.end()?std::string("container"):it->second)+" at depth "+std::to_string(cur.depth)+" because the remaining byte/file budget was insufficient");
            }
            if(cur.depth>=graph.max_depth&&has_extractable_child_container(report)){
                graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("recursive depth limit reached at "+prts::path_utf8(cur.path)+"; deeper extraction was not materialized");
            }
            auto children=extracted_artifacts(report);
            for(const auto&child:children){
                prts::ArtifactGraphEdge edge;edge.parent=cur.path;edge.child=child.path;edge.relation=child.relation;edge.depth=cur.depth+1;
                std::error_code sec;auto st=std::filesystem::symlink_status(child.path,sec);
                if(sec||st.type()==std::filesystem::file_type::symlink||st.type()!=std::filesystem::file_type::regular){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.edges.push_back(std::move(edge));continue;}
                edge.size=std::filesystem::file_size(child.path,sec);if(sec){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.edges.push_back(std::move(edge));continue;}
                edge.sha256=prts::sha256_file(child.path);if(edge.sha256.empty()){edge.state="SKIPPED_UNSAFE";++graph.skipped_unsafe;graph.edges.push_back(std::move(edge));continue;}
                graph.materialized_bytes=sat_add(graph.materialized_bytes,edge.size);++graph.materialized_files;
                if(graph.materialized_bytes>graph.max_total_bytes){edge.state="SKIPPED_BYTE_LIMIT";graph.truncated=true;++graph.skipped_limits;graph.warnings.push_back("extractor materialized bytes exceeded the declared recursive budget; offending child was not analyzed");graph.edges.push_back(std::move(edge));continue;}
                if(auto it=first_by_sha.find(edge.sha256);it!=first_by_sha.end()){edge.state="DUPLICATE_SKIPPED";edge.duplicate_of=it->second;++graph.deduplicated;graph.edges.push_back(std::move(edge));continue;}
                if(edge.depth>graph.max_depth){edge.state="SKIPPED_DEPTH";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));continue;}
                if(reports.size()+queue.size()+1>=graph.max_nodes){edge.state="SKIPPED_NODE_LIMIT";graph.truncated=true;++graph.skipped_limits;graph.edges.push_back(std::move(edge));continue;}
                first_by_sha.emplace(edge.sha256,child.path);edge.state="ADMITTED";graph.admitted_bytes=sat_add(graph.admitted_bytes,edge.size);graph.edges.push_back(edge);queue.push_back({child.path,cur.path,cur.root_input,child.relation,edge.depth,false});
            }
            reports.push_back(std::move(report));
        }
        if(!reports.empty()){
            graph.nodes=static_cast<std::uint32_t>(reports.size());reports.front().artifact_graph=graph;
            prts::Finding f;f.kind="artifact_graph";f.family="Recursive artifact graph";f.state=graph.truncated?"PARTIAL":"CONFIRMED";
            f.evidence={"only files materialized by validated static extractors were eligible as child artifacts","child artifacts were analyzed statically; symlinks were never followed","SHA-256 de-duplication prevents repeated/cyclic artifact analysis","file offsets in each child report are scoped to that child artifact file; the graph root is carried separately and no transformed parent offset is invented"};
            f.fields["nodes"]=std::to_string(graph.nodes);f.fields["materialized_files"]=std::to_string(graph.materialized_files);f.fields["materialized_bytes"]=std::to_string(graph.materialized_bytes);f.fields["deduplicated"]=std::to_string(graph.deduplicated);f.fields["max_depth"]=std::to_string(graph.max_depth);f.fields["max_nodes"]=std::to_string(graph.max_nodes);f.fields["max_total_bytes"]=std::to_string(graph.max_total_bytes);
            for(const auto&w:graph.warnings)f.negative_evidence.push_back(w);
            reports.front().findings.push_back(std::move(f));
        }
    }

    if(!successful_root_inputs){std::cerr<<"no readable regular input files found\n";return exit_code(ExitCode::Input);}
    if(opt.json){
        if(reports.size()==1)std::cout<<prts::render_json(reports.front());
        else{
            std::cout<<"[\n";for(std::size_t i=0;i<reports.size();++i){if(i)std::cout<<",\n";auto j=prts::render_json(reports[i]);while(!j.empty()&&(j.back()=='\n'||j.back()=='\r'))j.pop_back();std::cout<<j;}std::cout<<"\n]\n";
        }
    }else{
        for(std::size_t i=0;i<reports.size();++i){if(i)std::cout<<"\n============================================================\n\n";std::cout<<prts::render_text(reports[i],opt.report_language);}
    }
    return finish_standard_output(ExitCode::Success);
    } catch(const std::exception& e) {
        std::cerr << "internal fatal error: " << e.what() << "\n";
        return exit_code(ExitCode::Internal);
    } catch(...) {
        std::cerr << "internal fatal error: unknown exception\n";
        return exit_code(ExitCode::Internal);
    }
}
