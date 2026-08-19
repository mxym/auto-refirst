#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct ReferenceSemanticItem {
    std::string key;
    std::uint16_t value=0;
};

// A release-pinned product reference.  The generated semantic_items are a
// compact derivative of authenticated source bytes; reference_sha256 and the
// origin identity remain part of the trust contract so the table cannot be
// treated as self-authenticating truth.
struct ReferenceRegistryEntry {
    std::string id;
    std::string ecosystem;
    std::string version;
    std::string reference_artifact_kind;
    std::string semantic_scope;
    std::string reference_sha256;
    std::string semantic_table_sha256;
    std::string origin_release_identity;
    std::string origin_commit;
    std::string origin_path;
    std::string authentication_method;
    std::string validity_constraints;
    int python_minor=0;
    std::array<std::uint8_t,4> pyc_magic{};
    bool requires_exact_runtime_version=false;
    bool requires_pyc_magic=false;
    std::vector<ReferenceSemanticItem> semantic_items;
};

enum class ReferenceSelectionState : std::uint8_t { NoReference, ReferenceMatch, Unresolved, Conflict };

struct ReferenceSelectionRequest {
    std::string ecosystem;
    std::string version;
    std::string reference_artifact_kind;
    std::string semantic_scope;
    int python_minor=0;
    std::optional<std::array<std::uint8_t,4>> pyc_magic;
    bool runtime_identity_exact=false;
    bool runtime_identity_conflict=false;
    std::string conflict_evidence;
};

struct ReferenceSelectionResult {
    ReferenceSelectionState state=ReferenceSelectionState::NoReference;
    const ReferenceRegistryEntry* selected=nullptr;
    std::vector<const ReferenceRegistryEntry*> admissible;
    std::string reason;
};

const std::vector<ReferenceRegistryEntry>& reference_registry();
ReferenceSelectionResult select_reference(std::span<const ReferenceRegistryEntry> registry,
                                          const ReferenceSelectionRequest& request);
ReferenceSelectionResult select_reference(const ReferenceSelectionRequest& request);
bool reference_registry_entry_authenticated(const ReferenceRegistryEntry& entry);
bool authenticate_reference_bytes(const ReferenceRegistryEntry& entry,std::span<const std::uint8_t> bytes);
const char* to_string(ReferenceSelectionState state);

}
