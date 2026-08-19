#pragma once
#include "prts/model_trust.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace prts {

enum class RepairClass : std::uint8_t {
    MetadataNormalization,
    LayoutReconstruction,
    DeterministicBytePatch,
    DecompressUnpackHandoff,
    RuntimeDerivedRepair,
};

enum class RepairState : std::uint8_t { Proposed, Bounded, Validated, Rejected, Ambiguous };
enum class RepairValidationStage : std::uint8_t {
    InternalStructure,
    FormatPackerInvariant,
    ExactReferenceChosenInputOracle,
    NativeBoundary,
    ResultSemanticClosure,
};
enum class RepairValidationState : std::uint8_t { NotRun, Pass, Fail };

struct RepairChangedRange {
    std::uint64_t file_offset=0;
    std::vector<std::uint8_t> before_bytes;
    std::vector<std::uint8_t> after_bytes;
    std::string before_sha256;
    std::string after_sha256;
    std::string reason;
    bool executable_bytes=false;
    bool embedded_signature_overlap=false;
};

struct RepairValidation {
    RepairValidationStage stage=RepairValidationStage::InternalStructure;
    RepairValidationState state=RepairValidationState::NotRun;
    ModelEvidenceLevel evidence_level=ModelEvidenceLevel::None;
    std::string detail;
};

struct RepairLimits {
    std::uint64_t max_input_bytes=64ull*1024ull*1024ull;
    std::uint64_t max_output_bytes=64ull*1024ull*1024ull;
    std::uint32_t max_candidate_count=4;
    std::uint32_t max_changed_ranges=8;
    std::uint64_t max_changed_bytes=64;
};

struct RepairProposal {
    std::filesystem::path input_path;
    std::string input_sha256;
    std::uint64_t input_size=0;
    RepairClass repair_class=RepairClass::MetadataNormalization;
    RepairState state=RepairState::Proposed;
    std::string semantic_scope;
    std::string mechanism;
    std::vector<RepairChangedRange> changed_ranges;
    std::vector<RepairValidation> validations;
    std::vector<std::string> evidence;
    std::vector<std::string> ambiguity;
    ModelEvidenceLevel evidence_ceiling=ModelEvidenceLevel::None;
    std::string proposed_result_sha256;
    std::filesystem::path result_path;
    std::filesystem::path provenance_path;
    std::string result_sha256;
    std::string integrity_semantics;
    std::string decision_reason;
    std::string materialization_error;
    bool materialized=false;
    bool original_unchanged=false;
    bool static_reanalysis_eligible=false;
    bool automatic_runtime_execution_eligible=false;
};

// Strict R1 producer for legacy UPX Win32/PE metadata normalization.  It never
// scans for mutation combinations: one PE-local geometry yields at most one
// bounded proposal.  Standard UPX returns REJECTED/NO_REPAIR_NEEDED.
RepairProposal assess_upx_metadata_repair(const std::filesystem::path& input,
                                          std::span<const std::uint8_t> data,
                                          const PeInfo& pe,
                                          const RepairLimits& limits={});

// R2 boundary classifier.  It reports physically missing section bytes as
// AMBIGUOUS rather than inventing payload or choosing one of several metadata
// descriptions merely because a permissive parser accepts them.
RepairProposal assess_pe_layout_reconstruction(const std::filesystem::path& input,
                                               std::span<const std::uint8_t> data,
                                               const PeInfo& pe,
                                               const RepairLimits& limits={});

// Only VALIDATED proposals can be materialized.  The original path is never
// written, renamed, chmod'ed, or used as an output.  The result is a derived,
// non-executable artifact with a provenance sidecar.
bool materialize_validated_repair(RepairProposal& proposal,
                                  std::span<const std::uint8_t> original,
                                  const std::filesystem::path& repair_root={});
std::filesystem::path default_repair_root(const std::filesystem::path& input);

std::string render_repair_json(const RepairProposal& proposal);
std::string_view to_string(RepairClass value);
std::string_view to_string(RepairState value);
std::string_view to_string(RepairValidationStage value);
std::string_view to_string(RepairValidationState value);
std::string_view repair_evidence_level_name(ModelEvidenceLevel value);

}
