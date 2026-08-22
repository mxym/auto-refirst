#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace prts {
struct AnalysisReport;

// Source-side reference evidence retained for directory relationship closure.
// Endpoint resolution is deliberately separate: an exact source reference may
// still be missing or ambiguous in the admitted directory candidate set.
struct RelationshipReferenceEvidence {
    std::string kind;
    std::string evidence_level;        // R2_STRUCTURAL_RELATION / R3_EXACT_DATA_DEPENDENCY
    std::string semantic_relevance;    // STRUCTURAL / DATA_DEPENDENCY
    std::string reference;
    std::string resolution_mode;       // EXACT_RELATIVE_PATH / DECLARED_BASENAME_VALIDATED_IMAGE / GODOT_RES_PATH
    std::string target_symbol;         // optional exact exported entry required by the source contract
    std::string feature_key;           // optional platform/architecture feature identity
    std::string source_coordinate;
    std::string evidence_basis;
    std::string evidence_source;
    std::string source_relation_role;
    std::string target_relation_role;
    int source_priority_delta=0;
    int target_priority_delta=0;
    int priority_cap=20;
    bool target_must_be_validated_image=false;
};

// Bounded, non-executing source evidence extraction used only by directory
// orchestration.  It never follows paths or opens referenced sidecars.
std::vector<RelationshipReferenceEvidence> extract_relationship_reference_evidence(const AnalysisReport& report);
}
