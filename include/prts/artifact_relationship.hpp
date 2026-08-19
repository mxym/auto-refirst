#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace prts {

namespace artifact_relationship_state {
inline constexpr std::string_view confirmed="CONFIRMED";
inline constexpr std::string_view bounded="BOUNDED";
inline constexpr std::string_view route_hint="ROUTE_HINT";
inline constexpr std::string_view unresolved="UNRESOLVED";
}

// Cross-file/materialized-artifact relationship contract.
//
// `first`/`second` are concrete artifact paths.  When `directed` is true the
// relationship reads first -> second.  Coordinates are deliberately strings:
// a producer may have an exact file offset (for example a PE import descriptor
// RVA or ELF DT_SONAME file offset), while other validated metadata provides a
// symbolic coordinate such as "ELF:DT_NEEDED(libfoo.so.1)".  The coordinate
// basis/scope must be stated instead of silently mixing parent/child offsets.
//
// `evidence_level` is independent of `state`: same-directory/name/stem evidence
// is capped at R1, while structured metadata may reach R2 and exact consumer
// dataflow may reach R3/R4. Ambiguous endpoint resolution is explicit and
// fail-closed.
//
// `priority_eligible` is independent of `state`: only CONFIRMED/BOUNDED facts
// are permitted to opt in, and ROUTE_HINT/UNRESOLVED relationships must leave
// both priority deltas at zero. `first_role`/`second_role` describe artifact
// classification; `*_relation_role` says which endpoint produces, consumes,
// references, or is the target/peer of the relation.
struct ArtifactRelationship {
    std::filesystem::path first;
    std::filesystem::path second;
    bool directed=false;
    std::string kind;
    std::string state="UNRESOLVED";
    std::string first_role;
    std::string second_role;
    std::string first_relation_role;
    std::string second_relation_role;
    std::string evidence_basis;
    std::string evidence_source;
    std::string source_coordinate;
    std::string target_coordinate;
    std::string provenance_scope;
    // AR evidence taxonomy: R0 colocated, R1 routing, R2 structural,
    // R3 exact data dependency, R4 semantic application relation.
    std::string evidence_level="R0_COLOCATED_ONLY";
    std::string ambiguity="NONE";
    std::string semantic_relevance="NONE";
    bool priority_eligible=false;
    int first_priority_delta=0;
    int second_priority_delta=0;
    std::string reason;
};

inline bool artifact_relationship_state_allows_priority(std::string_view state) {
    return state==artifact_relationship_state::confirmed||state==artifact_relationship_state::bounded;
}

} // namespace prts
