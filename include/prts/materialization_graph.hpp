#pragma once
#include "prts/finding.hpp"
#include "prts/report.hpp"
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace prts {

enum class MaterializationNodeKind : std::uint8_t {
    ORIGINAL_IMAGE=0,
    ORIGINAL_IMAGE_REGION,
    ANONYMOUS_REGION,
    MEMFD_BACKING,
    O_TMPFILE_BACKING,
    RELEASED_FILE,
    CROSS_PROCESS_REGION,
    REPLACEMENT_IMAGE,
    MEMORY_DUMP,
    RECONSTRUCTED_IMAGE,
    INSTALLED_VALIDATED_IMAGE,
};

enum class MaterializationEdgeKind : std::uint8_t {
    ALLOCATED_FROM=0,
    WRITTEN_FROM,
    MUTATED_FROM,
    COPIED_FROM,
    MATERIALIZED_BY_RUNTIME,
    PROTECTED_EXECUTABLE,
    FIRST_EXECUTED_AS,
    DUMPED_AS,
    RECONSTRUCTED_AS,
    EXEC_HANDOFF_TO,
    INSTALLED_AS,
    CHILD_INHERITED,
};

const char* materialization_node_kind_name(MaterializationNodeKind kind);
const char* materialization_edge_kind_name(MaterializationEdgeKind kind);

struct MaterializationNode {
    std::uint64_t id=0;
    MaterializationNodeKind kind=MaterializationNodeKind::ANONYMOUS_REGION;
    std::optional<std::uint32_t> generation;
    bool executed=false;
    bool cross_process=false;
    std::uint64_t process_uid=0;
    std::uint32_t pid=0;
    std::optional<std::uint32_t> thread_id;
    std::uint64_t creator_process_uid=0;
    std::optional<std::uint32_t> creator_thread_id;
    std::uint64_t writer_process_uid=0;
    std::optional<std::uint32_t> writer_thread_id;
    std::optional<std::uint32_t> writer_execution_generation;
    std::uint64_t write_first_seq=0;
    std::uint64_t write_last_seq=0;
    std::uint64_t first_execution_process_uid=0;
    std::optional<std::uint32_t> first_execution_thread_id;
    std::uint64_t first_execution_seq=0;
    std::uint64_t first_execution_address=0;
    std::uint64_t seq=0;
    std::uint64_t t_us=0;
    CoordinateSpace coordinate_space=CoordinateSpace::UNKNOWN;
    CoordinateBasis coordinate_basis=CoordinateBasis::UNKNOWN;
    std::uint64_t address=0;
    std::uint64_t size=0;
    std::string backing_identity;
    std::string backing_path;
    std::uint64_t device=0;
    std::uint64_t inode=0;
    std::string sha256;
    std::string evidence_state="OBSERVED";
    std::string image;
    std::string detail;
};

struct MaterializationEdge {
    std::uint64_t id=0;
    std::optional<std::uint64_t> source_node;
    std::uint64_t destination_node=0;
    MaterializationEdgeKind kind=MaterializationEdgeKind::MATERIALIZED_BY_RUNTIME;
    // source_generation is byte/source provenance. It deliberately stays UNKNOWN
    // for MATERIALIZED_BY_RUNTIME even when the executing writer generation is known.
    std::optional<std::uint32_t> source_generation;
    std::optional<std::uint32_t> writer_execution_generation;
    std::uint64_t process_uid=0;
    std::optional<std::uint32_t> thread_id;
    std::uint64_t seq=0;
    std::uint64_t t_us=0;
    CoordinateBasis coordinate_basis=CoordinateBasis::UNKNOWN;
    std::uint64_t address=0;
    std::uint64_t size=0;
    std::string evidence_state="OBSERVED";
    std::string detail;
};

struct RuntimeSemanticDivergence {
    std::uint64_t seq=0;
    std::uint64_t process_uid=0;
    std::string kind;
    std::string static_expectation;
    std::string runtime_observation;
    std::string evidence_state="CONFIRMED";
};

struct MaterializationGraphSummary {
    std::uint32_t generation_count=0;
    std::uint32_t deepest_confirmed_generation=0;
    std::uint32_t executed_generation_count=0;
    std::uint32_t image_generation_count=0;
    std::uint32_t memory_only_generation_count=0;
    std::uint32_t cross_process_generation_count=0;
    std::uint32_t provenance_unknown_edge_count=0;
    bool partial=false;
};

struct MaterializationGraph {
    std::vector<MaterializationNode> nodes;
    std::vector<MaterializationEdge> edges;
    std::vector<RuntimeSemanticDivergence> divergences;
    MaterializationGraphSummary summary;
};

MaterializationGraph build_materialization_graph(const RuntimeReport& runtime,
                                                  const ReplacementReport* replacement=nullptr);
bool write_materialization_graph_csv(const MaterializationGraph& graph,
                                     const std::filesystem::path& node_csv,
                                     const std::filesystem::path& edge_csv,
                                     std::string& error);
// Builds from the immutable runtime ledger/artifacts, writes CSVs, then appends one
// generic runtime artifact containing summary metrics. It does not alter Timeline.
void finalize_materialization_graph(AnalysisReport& report,
                                    const std::filesystem::path& artifact_dir);

} // namespace prts
