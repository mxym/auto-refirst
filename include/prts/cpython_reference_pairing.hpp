#pragma once
#include "prts/cpython.hpp"
#include "prts/cpython_opcode_module.hpp"
#include "prts/model_trust.hpp"
#include "prts/pe.hpp"
#include "prts/pyinstaller.hpp"
#include "prts/reference_registry.hpp"
#include "prts/semantic_delta.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {

// Policy surface used both by the real pairing coordinator and focused
// negatives.  It names every claim that must be independently closed before
// ExactDeclarativeDelta is allowed; same-bundle evidence satisfies none of the
// exact relation/application fields by itself.
struct CPythonReferencePairingGateEvidence {
    bool exact_runtime_reference_selection=false;
    bool exact_reference_authenticated=false;
    bool target_semantic_artifact_exact=false;
    bool matcher_complete=false;
    bool exact_payload_binding=false;
    bool exact_application_proof=false;
    bool ambiguity_closed=false;
    bool native_contradiction=false;
};

inline bool cpython_reference_pairing_gate(const CPythonReferencePairingGateEvidence& evidence,
                                             std::string* reason=nullptr){
    auto fail=[&](const char* text){if(reason)*reason=text;return false;};
    if(!evidence.exact_runtime_reference_selection)return fail("exact runtime/reference selection is not closed");
    if(!evidence.exact_reference_authenticated)return fail("selected reference is not authenticated");
    if(!evidence.target_semantic_artifact_exact)return fail("target semantic artifact identity is not exact");
    if(!evidence.matcher_complete)return fail("named-opcode matcher is incomplete");
    if(!evidence.exact_payload_binding)return fail("exact payload/runtime binding is not closed");
    if(!evidence.exact_application_proof)return fail("exact semantic application proof is not closed");
    if(!evidence.ambiguity_closed)return fail("reference/runtime/module/payload ambiguity remains");
    if(evidence.native_contradiction)return fail("stronger native evidence contradicts the recovered semantic delta");
    if(reason)reason->clear();
    return true;
}

struct CPythonPairingBootstrapWitness {
    std::string module,state,reference_source_sha256,reference_semantic_sha256,normalized_semantic_sha256,error;
    std::uint64_t normalized_code_units=0;
};

struct CPythonReferencePairingResult {
    bool attempted=false;
    std::string state="UNRESOLVED"; // REFERENCE_MATCH / EXACT_DECLARATIVE_DELTA / UNRESOLVED
    std::string reason;
    std::string semantic_scope="cpython.opcode_module_named_semantics";
    std::string model_id;
    std::string reference_scope;
    std::string reference_sha256;
    std::string reference_origin;
    std::string reference_authentication;
    std::string runtime_version,runtime_sha256,runtime_entry;
    std::string runtime_file_version,runtime_product_version,runtime_original_filename;
    std::string pyz_entry,pyz_sha256,opcode_marshal_sha256;
    std::string payload_entry,payload_marshal_sha256,normalized_payload_sha256;
    std::string application_reference,application_origin,application_bootloader_blob,application_bootloader_sha256,bootloader_text_sha256;
    std::uint32_t named_opcode_count=0,changed_opcode_count=0;
    std::uint32_t bootstrap_witness_matched=0,bootstrap_witness_required=0;
    std::uint64_t payload_code_units=0,payload_rewritten_code_units=0;
    bool runtime_identity_exact=false;
    bool payload_binding_exact=false;
    bool application_proof_exact=false;
    bool ambiguity_closed=false;
    bool native_contradiction=false;
    std::vector<std::string> evidence,negative_evidence;
    std::vector<CPythonPairingBootstrapWitness> bootstrap_witnesses;
    CPythonOpcodeModuleDelta opcode_delta;
    SemanticDeltaAssessment semantic_delta;
    ModelTrustReport model_trust;
};

CPythonReferencePairingResult pair_cpython_pyinstaller_reference(
    std::span<const std::uint8_t> outer_bytes,
    const PeInfo& outer_pe,
    const PyInstArchiveInfo& pyinstaller,
    const CPythonInfo& runtime);

Finding cpython_reference_pairing_finding(const CPythonReferencePairingResult& result);

}
