#pragma once
#include "prts/artifact_relationship.hpp"
#include "prts/relationship_evidence.hpp"
#include "prts/runtime_modality.hpp"
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <map>
#include <string>
#include <vector>

namespace prts {
struct AnalysisReport;

struct RuntimePlanStep {
    std::string analyzer;
    bool selected=false;
    std::string reason;
    std::vector<std::string> evidence;
    std::uint32_t timeout_ms=0;
    std::uint64_t budget_ms=0;
    bool destructive=false;
    std::string state="PLANNED";
    std::string result;
    std::string refusal;
    std::uint64_t elapsed_ms=0;
};

struct RuntimePlan {
    bool requested=false;
    bool apply_requested=false;
    bool runtime_eligible=false;
    std::string runtime_eligibility_reason;
    std::string policy="static_only";
    std::uint32_t timeout_ms=0;
    std::vector<RuntimePlanStep> steps;
};

struct RuntimePlanningRequest {
    bool requested=false;
    bool apply_requested=false;
    bool legacy_trace=false;
    bool legacy_unpack=false;
    bool forced_python_probe=false;
    std::uint32_t timeout_ms=0;
};

RuntimePlan build_runtime_plan(const AnalysisReport& report,const RuntimePlanningRequest& request);
RuntimePlanStep* runtime_plan_step(RuntimePlan& plan,const std::string& analyzer);
const RuntimePlanStep* runtime_plan_step(const RuntimePlan& plan,const std::string& analyzer);

struct DirectoryCandidate {
    std::filesystem::path path;
    std::uint64_t size=0;
    std::string type_hint="unknown";
    std::string structural_confidence="low";
    std::string role="unknown";
    int priority_score=0;
    int relationship_priority_boost=0;
    std::string priority_tier="Tier 3";
    std::vector<std::string> priority_reasons;
    std::vector<std::filesystem::path> related_files;
    bool runtime_eligible=false;
    std::string runtime_eligibility_reason;
    bool readable=true;
    std::string analysis_state="PENDING";
    std::string skipped_reason;
    bool runtime_selected=false;
    std::string runtime_state="NOT_REQUESTED";
    std::string runtime_skip_reason;
    std::uint64_t analysis_elapsed_ms=0;
    std::uint64_t runtime_elapsed_ms=0;
    // BB default-directory detail state.  The compact candidate/file-state plane
    // remains complete even when the full per-file report is deferred.
    std::string report_detail_state="NOT_RENDERED";
    std::string report_detail_reason;
    std::uint64_t report_full_bytes=0;
    std::string artifact_materialization_state="NOT_MEASURED";
    std::string artifact_materialization_reason;
    std::uint64_t artifact_materialized_bytes=0;
    std::uint64_t artifact_materialized_files=0;
};

using DirectoryRelationship = ArtifactRelationship;

struct DirectoryTraversalSkip {
    std::filesystem::path path;
    std::string reason;
};

struct DirectoryPlan {
    std::filesystem::path root;
    std::uint32_t max_depth=0xffffffffu;
    std::uint32_t max_runtime_targets=4;
    // BB: default directory admission is cardinality-bounded. Every admitted
    // file still receives a compact file_state; excess regular files are
    // explicitly deferred instead of expanding the default envelope forever.
    std::uint32_t max_candidates=1024;
    std::uint64_t regular_files_seen=0;
    std::uint64_t candidate_omitted_count=0;
    bool candidate_admission_budget_exhausted=false;
    std::uint64_t total_runtime_budget_ms=45000;
    std::uint32_t per_target_timeout_ms=15000;
    bool run_all=false;
    std::uint32_t max_relationships=16384;
    std::uint32_t max_related_files_per_artifact=32;
    std::uint32_t max_rendered_relationships=64;
    std::uint64_t relationship_candidate_lookups=0;
    std::uint64_t relationship_ambiguous_reference_count=0;
    std::uint64_t relationship_omitted_count=0;
    std::uint64_t related_file_omitted_count=0;
    bool relationship_budget_exhausted=false;
    std::vector<DirectoryCandidate> candidates;
    std::vector<DirectoryRelationship> relationships;
    std::vector<DirectoryTraversalSkip> traversal_skips;
    std::uint64_t traversal_skips_total=0;
    std::uint64_t traversal_error_count=0;
    std::uint64_t depth_limited_directories=0;
};

struct DirectoryPeImportFact {
    std::string name;
    std::uint32_t descriptor_rva=0;
};

struct DirectoryPeExportFact {
    std::string name;
    std::uint32_t rva=0;
    bool forwarded=false;
};

struct DirectoryArtifactFact {
    std::filesystem::path path;
    std::filesystem::path parent;
    std::string role;
    std::string relation;
    std::string priority;
    std::string source;
    std::string sha256;
    bool runtime_confirmed=false;
    bool graph_linked=false;
    std::uint32_t graph_depth=0;
    std::string graph_state;
};

struct DirectoryGodotLibraryFact {
    std::filesystem::path descriptor;
    std::filesystem::path target;
    std::string descriptor_entry;
    std::string target_entry;
};

struct DirectoryUnrealPartitionFact {
    std::filesystem::path path;
    std::uint32_t index=0;
    std::uint64_t required_bytes=0;
    std::string state;
};

// Compact cross-file evidence view.  It intentionally contains only facts
// consumed by directory relationship/ranking/summary logic; the owning full
// AnalysisReport may be serialized and released before cross-file analysis.
struct DirectoryReportIndex {
    std::filesystem::path input;
    bool pe_valid=false;
    bool pe_dll=false;
    bool pe64=false;
    std::uint16_t pe_machine=0;
    std::vector<DirectoryPeImportFact> pe_imports;
    std::vector<DirectoryPeExportFact> pe_exports;
    std::uint64_t pe_named_export_count=0;
    bool pe_exports_truncated=false;
    bool elf_valid=false;
    std::uint16_t elf_type=0;
    std::uint64_t elf_entry=0;
    std::string elf_interpreter;
    std::string elf_soname;
    std::uint64_t elf_soname_file_offset=0;
    std::vector<std::string> elf_needed;
    bool mono_runtime_export_surface=false;

    bool pyinstaller_valid=false;
    bool godot_valid=false;
    bool apk_valid=false;
    bool jar_valid=false;
    bool nuitka_valid=false;
    bool cpython_runtime_present=false;

    // AW compact interpreter/program-boundary facts.  These are role/guidance
    // facts only; they never upgrade AR relationship evidence.
    bool interpreter_boundary_confirmed=false;
    bool interpreter_external_program_argument=false;
    bool interpreter_program_buffer_chain=false;
    bool interpreter_exact_program_target_bound=false;
    std::string interpreter_boundary_kind;
    std::string interpreter_host_role;
    std::string interpreter_target_role;
    std::string interpreter_semantic_requirement;
    std::string interpreter_runtime_family;
    std::string interpreter_exact_program_target_state;
    std::uint64_t implicit_high_priority_count=0;
    std::uint64_t failure_count=0;
    std::uint64_t partial_count=0;

    bool unity_valid=false;
    bool unity_player_import=false;
    bool unity_metadata_valid=false;
    bool unity_il2cpp=false;
    bool unity_il2cpp_export_evidence=false;
    bool unity_registration_resolved=false;
    bool unity_game_assembly_validated=false;
    bool unity_mono=false;
    bool unity_mono_runtime_validated=false;
    std::filesystem::path unity_metadata_path;
    std::filesystem::path unity_game_assembly_path;
    std::filesystem::path unity_managed_path;
    std::filesystem::path unity_mono_runtime_path;
    std::string unity_backend_state;

    bool dotnet_valid=false;
    bool dotnet_unity_managed=false;
    bool dotnet_unity_mono=false;
    std::vector<std::string> dotnet_pinvoke_modules;

    // AR compact source-side exact/structural references. Endpoint closure is
    // deferred until the complete directory candidate set is known.
    std::vector<RelationshipReferenceEvidence> relationship_references;

    std::vector<DirectoryArtifactFact> artifacts;
    std::vector<DirectoryGodotLibraryFact> godot_library_refs;
    bool unreal_iostore_toc_valid=false;
    bool unreal_iostore_pair_valid=false;
    bool unreal_iostore_encrypted=false;
    std::vector<DirectoryUnrealPartitionFact> unreal_iostore_partitions;


    // Set only when relationship closure changes user-visible report state.
    // The optimized directory path treats this as a retention invariant.
    bool post_relationship_mutated=false;
};

struct DirectoryArtifactRendering {
    std::string profile="unbounded";
    bool partial=false;
    std::uint64_t max_bytes=0;
    std::uint64_t max_files=0;
    std::uint64_t pre_relationship_max_bytes=0;
    std::uint64_t pre_relationship_max_files=0;
    std::uint64_t post_relationship_reserve_bytes=0;
    std::uint64_t post_relationship_reserve_files=0;
    std::uint64_t materialized_bytes=0;
    std::uint64_t materialized_files=0;
    std::uint64_t retained_candidate_roots=0;
    std::uint64_t deferred_candidate_count=0;
    std::uint64_t known_omitted_bytes=0;
    std::uint64_t known_omitted_files=0;
    std::uint64_t unknown_omitted_candidate_count=0;
    std::string selection_policy;
    std::string reason;
    std::string detail_retrieval_mode;
    std::string detail_retrieval_command;
};

struct DirectoryReportRendering {
    std::string profile="full";
    bool partial=false;
    bool truncated=false;
    std::uint64_t full_report_count=0;
    std::uint64_t full_reports_rendered=0;
    std::uint64_t full_reports_deferred=0;
    std::uint64_t known_full_report_bytes=0;
    std::uint64_t inline_report_bytes=0;
    std::uint64_t known_deferred_report_bytes=0;
    std::uint64_t inline_report_budget_bytes=0;
    std::uint64_t per_report_max_bytes=0;
    std::uint64_t spool_hard_budget_bytes=0;
    std::uint64_t spool_peak_bytes=0;
    std::string selection_policy;
    std::string reason;
    std::string detail_retrieval_mode;
    std::string detail_retrieval_command;
};

struct DirectorySummary {
    std::uint64_t total_files=0;
    std::uint64_t analyzed_files=0;
    std::uint64_t skipped_files=0;
    std::uint64_t total_bytes=0;
    std::uint64_t discovered_regular_files=0;
    std::uint64_t candidate_omitted_count=0;
    bool partial=false;
    std::vector<std::string> partial_reasons;
    std::map<std::string,std::uint64_t> type_counts;
    std::vector<std::string> confirmed_ecosystems;
    std::string unity_engine_state="ABSENT";
    std::string unity_backend_state="ABSENT";
    std::string unity_next_priority;
    std::uint64_t unity_mono_relationship_count=0;
    std::uint64_t unity_il2cpp_relationship_count=0;
    std::uint64_t high_priority_evidence_count=0;
    std::uint64_t artifact_relationship_count=0;
    std::uint64_t relationship_omitted_count=0;
    std::uint64_t relationship_ambiguous_reference_count=0;
    bool relationship_budget_exhausted=false;
    std::uint64_t failures=0;
    std::uint64_t partials=0;
    std::uint64_t elapsed_ms=0;
    RuntimeModalityGuidance runtime_modality;
};

DirectoryPlan inventory_directory(const std::filesystem::path& root,std::uint32_t max_depth);
DirectoryCandidate preflight_directory_candidate(const std::filesystem::path& path);
void refine_directory_candidate(DirectoryCandidate& candidate,const AnalysisReport& report);
DirectoryReportIndex make_directory_report_index(const AnalysisReport& report);
bool directory_report_requires_post_relationship_retention(const AnalysisReport& report);
void apply_directory_report_index_mutations(AnalysisReport& report,const DirectoryReportIndex& index);
void build_directory_relationships(DirectoryPlan& plan,std::vector<DirectoryReportIndex>& reports);
void build_directory_relationships(DirectoryPlan& plan,std::vector<AnalysisReport>& reports);
void sort_directory_candidates(DirectoryPlan& plan);
DirectorySummary summarize_directory(const DirectoryPlan& plan,const std::vector<DirectoryReportIndex>& reports,std::uint64_t elapsed_ms);
DirectorySummary summarize_directory(const DirectoryPlan& plan,const std::vector<AnalysisReport>& reports,std::uint64_t elapsed_ms);
bool render_directory_json(std::ostream& out,const DirectoryPlan& plan,const DirectorySummary& summary,const std::vector<AnalysisReport>& reports,std::string& error);
bool render_directory_json_spooled(std::ostream& out,const DirectoryPlan& plan,const DirectorySummary& summary,const std::vector<std::filesystem::path>& report_paths,const DirectoryReportRendering& rendering,const DirectoryArtifactRendering& artifact_rendering,std::string& error);
std::string render_directory_json(const DirectoryPlan& plan,const DirectorySummary& summary,const std::vector<AnalysisReport>& reports);
}
