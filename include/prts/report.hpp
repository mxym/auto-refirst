#pragma once
#include "prts/file_snapshot.hpp"
#include "prts/artifact_relationship.hpp"
#include "prts/analysis_path.hpp"
#include "prts/interpreter_boundary.hpp"
#include "prts/orchestration.hpp"
#include "prts/implicit_exec.hpp"
#include "prts/pe.hpp"
#include "prts/authenticode.hpp"
#include "prts/elf.hpp"
#include "prts/macho.hpp"
#include "prts/timeline.hpp"
#include "prts/finding.hpp"
#include "prts/pyinstaller.hpp"
#include "prts/python_bytecode.hpp"
#include "prts/godot.hpp"
#include "prts/gdextension.hpp"
#include "prts/gdscript.hpp"
#include "prts/cpython.hpp"
#include "prts/cpython_static.hpp"
#include "prts/golang.hpp"
#include "prts/hermes.hpp"
#include "prts/rust.hpp"
#include "prts/nuitka.hpp"
#include "prts/lua.hpp"
#include "prts/wasm.hpp"
#include "prts/jvm.hpp"
#include "prts/android.hpp"
#include "prts/apk.hpp"
#include "prts/unreal.hpp"
#include "prts/dart.hpp"
#include "prts/flutter.hpp"
#include "prts/unity.hpp"
#include "prts/dotnet.hpp"
#include "prts/dotnet_native.hpp"
#include "prts/wxapkg.hpp"
#include "prts/asar.hpp"
#include "prts/autoit.hpp"
#include "prts/crypto.hpp"
#include "prts/renpy.hpp"
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <map>
#include <optional>
#include <string>
#include <vector>
namespace prts {
struct RuntimeArtifact { std::string kind,state; std::filesystem::path path; std::uint64_t process_uid=0; std::uint32_t pid=0; std::uint64_t oep_va=0; std::string detail; std::map<std::string,std::string> fields; std::vector<RangeRef> priority_ranges; };
struct RuntimeReport { bool requested=false,launched=false,console_expected=true,timed_out=false; std::optional<int> exit_code; FileSnapshot before,after; std::string stdout_text,stderr_text; std::vector<TimelineEvent> timeline; std::vector<RuntimeArtifact> artifacts; };
struct ReplacementReport { bool performed=false; std::filesystem::path target,backup,unpacked_source; std::string original_sha256,new_sha256,validation; };
struct ArtifactNodeInfo { bool graph_member=false; bool root=false; std::uint32_t depth=0; std::filesystem::path parent,root_input,offset_basis; std::string relation,offset_space="current_input_file"; };
struct ArtifactGraphEdge { std::filesystem::path parent,child,duplicate_of; std::string relation,sha256,state; std::uint64_t size=0; std::uint32_t depth=0; };
struct ArtifactGraphInfo { bool enabled=false,truncated=false; std::uint32_t max_depth=0,max_nodes=0,nodes=0,deduplicated=0,skipped_limits=0,skipped_unsafe=0,materialized_files=0; std::uint64_t max_total_bytes=0,materialized_bytes=0,admitted_bytes=0; std::vector<ArtifactGraphEdge> edges; std::vector<std::string> warnings; };
struct AnalysisArtifact {
    std::string kind,role,source,state,relation,priority;
    std::filesystem::path path,parent;
    std::uint64_t size=0;
    std::string sha256;
    bool normalized=false,runtime_confirmed=false;
};
struct ArtifactMaterializationInfo {
    std::filesystem::path root;
    bool partial=false;
    std::uint64_t omitted_count=0,omitted_bytes=0;
    std::vector<std::string> reasons;
};
struct AnalysisReport { std::filesystem::path input; FileSnapshot input_snapshot; PeInfo pe; AuthenticodeInfo authenticode; ElfInfo elf; ElfExtractResult elf_extract; ElfUnwindExtractResult elf_unwind_extract; MachOInfo macho; ImplicitExecutionInfo implicit_exec; ImplicitExecutionExtractResult implicit_exec_extract; StaticScanReport static_scan; PyInstArchiveInfo pyinstaller; PyInstExtractResult pyinstaller_extract; PythonBytecodeInfo python_bytecode; PythonBytecodeExtractResult python_bytecode_extract; CPythonMarshalLoaderInfo cpython_marshal_loader; GodotPckInfo godot; GodotExtractResult godot_extract; GodotLegacyEngineConfigInfo godot_legacy_config; GDExtensionDescriptorInfo gdextension_descriptor; GDScriptMaterializeResult gdscript_extract; CPythonStaticInfo cpython_static; std::vector<CPythonInfo> cpython_runtimes; GoInfo golang; GoExtractResult golang_extract; RustInfo rust; LuaInfo lua; LuaExtractResult lua_extract; WasmInfo wasm; WasmExtractResult wasm_extract; HermesInfo hermes; HermesExtractResult hermes_extract; DexInfo dex; DexExtractResult dex_extract; ApkInfo apk; ApkExtractResult apk_extract; UnrealInfo unreal; DartInfo dart; FlutterAssetManifestInfo flutter_asset_manifest; JvmClassInfo jvm_class; JvmExtractResult jvm_extract; JarInfo jar; JarExtractResult jar_extract; UnityInfo unity; UnityExtractResult unity_extract; DotNetInfo dotnet; DotNetExtractResult dotnet_extract; DotNetBundleInfo dotnet_bundle; NativeAotInfo native_aot; WxapkgInfo wxapkg; WxapkgExtractResult wxapkg_extract; AsarInfo asar; AsarExtractResult asar_extract; AutoItInfo autoit; AutoItExtractResult autoit_extract; CryptoInfo crypto; RenpyRpycInfo renpy_rpyc; RenpyExtractResult renpy_extract; RenpyRpaInfo renpy_rpa; RenpyRpaExtractResult renpy_rpa_extract; NuitkaInfo nuitka; NuitkaExtractResult nuitka_extract; InterpreterBoundaryInfo interpreter_boundary; AnalysisGuidance analysis_guidance; RuntimePlan runtime_plan; std::vector<Finding> findings; RuntimeReport runtime; ReplacementReport replacement; ArtifactNodeInfo artifact; ArtifactGraphInfo artifact_graph; ArtifactMaterializationInfo materialization; std::vector<AnalysisArtifact> artifacts; std::vector<ArtifactRelationship> artifact_relationships; };
enum class ReportLanguage { English, Chinese };
std::string render_text(const AnalysisReport& r);
std::string render_text(const AnalysisReport& r,ReportLanguage language);
void render_json(std::ostream& out,const AnalysisReport& r);
bool automatic_child_json_uses_summary(const AnalysisReport& r);
void render_automatic_child_json(std::ostream& out,const AnalysisReport& r);
std::string render_json(const AnalysisReport& r);
}
