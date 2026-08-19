#include "prts/semantic_producers.hpp"

#include <string>

namespace prts {
namespace {

constexpr const char* kGodotProducerModel="godot-native-key-external-pck-aes256-cfb-md5-v1";

void apply_validation_ambiguity(SemanticCompositionClaim&claim,const GodotExternalPckValidation&v){
    if(!v.target_valid)claim.ambiguity|=SemanticAmbiguity::TargetCandidate;
    if(v.matching_candidate_count!=1||v.candidate_budget_exhausted||v.source_coordinate_ambiguous||!v.value_unique)
        claim.ambiguity|=SemanticAmbiguity::SourceCandidate;
    claim.ambiguity_reasons=v.ambiguity_reasons;
}

SemanticProvenanceStep source_step(const GodotExternalPckValidation&v){
    return {v.source.path,v.source_coordinate,
            "recover bounded 256-bit Godot pack-key candidate from PE64 native code/data relationship",
            ModelEvidenceLevel::OfflineModel,kGodotProducerModel};
}

SemanticProducerClaim assessed(SemanticCompositionClaim claim){
    SemanticProducerClaim out;out.claim=std::move(claim);out.assessment=assess_semantic_composition(out.claim);return out;
}

SemanticCompositionClaim directory_claim(const GodotExternalPckValidation&v){
    SemanticCompositionClaim c;
    c.source_artifact=v.source.path;c.target_artifact=v.target.path;
    c.semantic_scope="godot.pck.encrypted_directory_plaintext";
    c.relation_level=SemanticRelationLevel::SemanticValue;c.relation_kind=SemanticRelationKind::ValueInterpretation;
    c.evidence_level=ModelEvidenceLevel::ChosenInputOracle;c.reference_or_model_id=kGodotProducerModel;
    c.source_coordinate=v.source_coordinate;c.target_coordinate=v.target_coordinate;
    c.transformation_description="the independently recovered source key value decrypts this exact target PCK directory under AES-256-CFB, matches the directory plaintext MD5, and the plaintext parses exactly under the declared PCK geometry";
    c.scope_complete=v.resolved&&v.directory_md5_validated&&v.directory_structure_validated;
    apply_validation_ambiguity(c,v);
    c.provenance_chain={source_step(v),
        {v.target.path,v.target_coordinate,
         "apply source key to exact encrypted PCK directory; verify plaintext MD5 and directory structure",
         ModelEvidenceLevel::ChosenInputOracle,kGodotProducerModel}};
    return c;
}

SemanticCompositionClaim script_claim(const GodotExternalPckValidation&v){
    SemanticCompositionClaim c;
    c.source_artifact=v.source.path;c.target_artifact=v.target.path;
    c.semantic_scope="godot.pck.gdscript_plaintext_interpretation";
    c.relation_level=SemanticRelationLevel::SemanticValue;c.relation_kind=SemanticRelationKind::ValueInterpretation;
    c.evidence_level=ModelEvidenceLevel::ChosenInputOracle;c.reference_or_model_id=kGodotProducerModel;
    c.source_coordinate=v.source_coordinate;c.target_coordinate=v.validated_script_target_coordinate;
    c.transformation_description="the independently recovered source key decrypts this exact encrypted GDScript entry; the encrypted envelope and directory entry MD5 authenticate its plaintext, and bounded GDScript bytecode/source structure validates script scope";
    c.scope_complete=v.resolved&&v.encrypted_script_validated_count!=0&&!v.validated_script_target_coordinate.empty();
    apply_validation_ambiguity(c,v);
    c.provenance_chain={source_step(v),
        {v.target.path,v.validated_script_target_coordinate,
         "decrypt exact encrypted GDScript entry; verify encrypted envelope, entry plaintext MD5, and bounded GDScript structure",
         ModelEvidenceLevel::ChosenInputOracle,kGodotProducerModel}};
    return c;
}

SemanticCompositionClaim encrypted_child_claim(const GodotExternalPckValidation&v){
    SemanticCompositionClaim c;
    c.source_artifact=v.source.path;c.target_artifact=v.target.path;
    c.semantic_scope="godot.pck.encrypted_child_plaintext_integrity";
    c.relation_level=SemanticRelationLevel::SemanticValue;c.relation_kind=SemanticRelationKind::ValueInterpretation;
    c.evidence_level=ModelEvidenceLevel::ChosenInputOracle;c.reference_or_model_id=kGodotProducerModel;
    c.source_coordinate=v.source_coordinate;c.target_coordinate=v.target_coordinate;
    c.transformation_description="the independently recovered source key authenticates an exact encrypted target entry through the Godot encrypted-file envelope and PCK-directory plaintext MD5";
    c.scope_complete=v.resolved&&v.encrypted_file_validated_count!=0;
    apply_validation_ambiguity(c,v);
    c.provenance_chain={source_step(v),
        {v.target.path,v.target_coordinate,
         "decrypt exact encrypted PCK child and verify encrypted envelope plus directory entry MD5",
         ModelEvidenceLevel::ChosenInputOracle,kGodotProducerModel}};
    return c;
}

SemanticCompositionClaim child_claim(const GodotExternalPckValidation&v,const GodotExternalPckMaterializedChild&child){
    SemanticCompositionClaim c;
    c.source_artifact=v.source.path;c.target_artifact=v.target.path;c.result_artifact=child.output_path;
    if(child.validation_state=="KEY_VALIDATED_FOR_SCRIPT")c.semantic_scope="godot.pck.gdscript_plaintext_materialization";
    else if(child.encrypted)c.semantic_scope="godot.pck.encrypted_entry_plaintext_materialization";
    else c.semantic_scope="godot.pck.directory-mediated_entry_materialization";
    c.relation_level=SemanticRelationLevel::TransformationProvenance;c.relation_kind=SemanticRelationKind::DeterministicTransformation;
    c.evidence_level=ModelEvidenceLevel::ChosenInputOracle;c.reference_or_model_id=kGodotProducerModel;
    c.source_coordinate=v.source_coordinate;c.target_coordinate=child.target_coordinate;
    c.transformation_description=child.encrypted
        ?"validated source-key semantics plus the exact encrypted PCK entry deterministically produce this authenticated plaintext child without modifying source or target"
        :"validated source-key directory semantics identify the exact PCK entry and deterministic integrity-checked extraction produces this child without modifying source or target";
    c.scope_complete=v.resolved&&!child.sha256.empty()&&
        (child.validation_state=="KEY_VALIDATED_FOR_SCRIPT"||child.validation_state=="ENCRYPTED_FILE_KEY_VALIDATED"||child.validation_state=="PCK_ENTRY_MD5_VALIDATED");
    apply_validation_ambiguity(c,v);
    c.provenance_chain={source_step(v),
        {v.target.path,child.target_coordinate,
         child.encrypted?"decrypt exact PCK entry and verify entry plaintext MD5":"select exact entry from authenticated directory and verify entry plaintext MD5",
         ModelEvidenceLevel::ChosenInputOracle,kGodotProducerModel},
        {child.output_path,"sha256:"+child.sha256,
         "materialize immutable-result child and bind its SHA-256 to source-key/target-entry provenance",
         ModelEvidenceLevel::ChosenInputOracle,kGodotProducerModel}};
    return c;
}

} // namespace

GodotSemanticProducerResult produce_godot_semantic_composition(
    const GodotExternalPckValidation&v,std::span<const GodotExternalPckMaterializedChild>children){
    GodotSemanticProducerResult out;
    // Emit only scopes for which mechanism-specific application proof exists;
    // unresolved reductions are still assessed fail-closed by the AB envelope.
    if(v.directory_md5_validated)out.l3_claims.push_back(assessed(directory_claim(v)));
    if(v.encrypted_script_validated_count&&!v.validated_script_target_coordinate.empty())
        out.l3_claims.push_back(assessed(script_claim(v)));
    // For an encrypted directory, child coordinates are emitted by the L4
    // materializer below; do not widen the directory L3 claim merely because a
    // bounded child probe also authenticated.  A plaintext directory may use
    // the exact child oracle coordinate as its narrower L3 scope.
    if(!v.directory_md5_validated&&v.encrypted_file_validated_count)
        out.l3_claims.push_back(assessed(encrypted_child_claim(v)));
    for(const auto&child:children)out.l4_claims.push_back(assessed(child_claim(v,child)));
    return out;
}

} // namespace prts
