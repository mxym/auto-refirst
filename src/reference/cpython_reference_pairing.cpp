#include "prts/cpython_reference_pairing.hpp"
#include "prts/python_marshal.hpp"
#include "prts/sha256.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>

namespace prts { namespace {
struct BootstrapRef {
    const char* module;
    char typecode;
    const char* source_sha256;
    const char* semantic_sha256;
};
struct PyInstallerApplicationRef {
    const char* id;
    const char* release_identity;
    const char* origin_commit;
    const char* bootloader_artifact;
    const char* bootloader_blob;
    const char* bootloader_sha256;
    const char* text_sha256;
    std::uint32_t text_size;
    std::uint16_t machine;
    int python_minor;
    std::array<BootstrapRef,4> bootstrap;
};

// Authenticated auxiliary application reference.  The native .text hash comes
// from the prebuilt artifact stored by the official PyInstaller v4.1 tag; the
// bootstrap semantic hashes are generated from the exact source files named by
// source_sha256 under the same peeled tag, compiled by a stock CPython 3.8.5
// compiler.  Focused provenance tests reproduce this chain.
static constexpr PyInstallerApplicationRef kApplicationRefs[]={{
    "pyinstaller:v4.1:Windows-32bit/run.exe:cpython38-bootstrap",
    "PyInstaller v4.1",
    "f9eeaaf9c09ce72cab20165a21dd454be2178c50",
    "PyInstaller/bootloader/Windows-32bit/run.exe",
    "7561014d35f4def3a4772709f2b5ad4906b5098b",
    "461ffd4561f10e20e454d965046bbca7761bd499279b76d9ed520269131e9967",
    "29caab63b0673f280eb22915ffce4b8d67f9a2477429bc1ca45611e60af27ec7",
    127060u,0x014cu,38,
    {{{"pyimod01_os_path",'m',"c9fadb79508d0c495cfa3daab84db439cfd01dac9d14db9d353c4fabe0f50f97","d2f1b8a7d76b0e50844dc9711f4443380ee3463c55e9dbc0a6e311c2ce6f3064"},
      {"pyimod02_archive",'m',"915b2dbb0c01c182f7ff8a3b226aadaa63ab7f5ab2984fbe175ffc981ce041b6","4fe90de4fefed4e8977ffbf17410d04817f46b91442bc0a0628a5c6c875ee7b1"},
      {"pyimod03_importers",'m',"88dcd5aa8705d5961954498dabe9bef366c74c3cb7705d30df357a2a767c1769","8d54e9e2fd6130dac7d2f87d8fb0a7202904d9024342675a86d466d9fb425b38"},
      {"pyiboot01_bootstrap",'s',"364538229330e72cfb4d327ba11f91258821a3f243bdc6250f6ab620c352e09d","e204703438795fd9f0778ff8dcff09369f78dab6e8aa6ba8780fb72fc19fa21d"}}}
}};

std::string version_from_hex(std::uint32_t v){if(!v)return{};return std::to_string(v>>24)+"."+std::to_string((v>>16)&255)+"."+std::to_string((v>>8)&255);}
int minor_code(std::uint32_t v){return static_cast<int>((v>>24)*10+((v>>16)&255));}

std::optional<std::string> pe_version_string(std::span<const std::uint8_t>d,const PeInfo&pe,std::string_view key){
    auto sec=std::find_if(pe.sections.begin(),pe.sections.end(),[](const PeSection&s){return s.name==".rsrc";});
    if(sec==pe.sections.end()||sec->raw_offset>d.size()||sec->raw_size>d.size()-sec->raw_offset)return{};
    const auto raw=d.subspan(sec->raw_offset,sec->raw_size);
    std::vector<std::uint8_t> needle;needle.reserve(key.size()*2);
    for(unsigned char c:key){needle.push_back(c);needle.push_back(0);}
    auto it=std::search(raw.begin(),raw.end(),needle.begin(),needle.end());
    if(it==raw.end())return{};
    const std::size_t key_off=static_cast<std::size_t>(it-raw.begin());
    if(key_off<6)return{};
    const std::size_t record=key_off-6;
    auto u16=[&](std::size_t off)->std::uint16_t{return static_cast<std::uint16_t>(raw[off]|(std::uint16_t(raw[off+1])<<8));};
    if(record+6>raw.size())return{};
    const auto length=u16(record),value_length=u16(record+2),type=u16(record+4);
    if(type!=1||!length||!value_length||record+length>raw.size())return{};
    std::size_t p=key_off+(key.size()+1)*2;
    p=(p+3u)&~std::size_t(3u);
    if(p>=record+length)return{};
    std::string out;
    for(std::uint16_t i=0;i<value_length&&p+1<record+length;i++,p+=2){auto ch=u16(p);if(ch==0)break;if(ch>0x7f)return{};out.push_back(static_cast<char>(ch));}
    return out.empty()?std::optional<std::string>{}:std::optional<std::string>{out};
}

std::set<std::string> exact_patch_versions(std::span<const std::uint8_t>d){
    std::set<std::string> out;
    for(std::size_t i=0;i+5<d.size();++i){
        if(d[i]<'0'||d[i]>'9'||d[i+1]!='.')continue;
        std::size_t p=i;unsigned major=0,minor=0,micro=0;
        while(p<d.size()&&std::isdigit(static_cast<unsigned char>(d[p])))major=major*10+(d[p++]-'0');
        if(p>=d.size()||d[p++]!='.')continue;
        std::size_t m0=p;
        while(p<d.size()&&std::isdigit(static_cast<unsigned char>(d[p])))minor=minor*10+(d[p++]-'0');
        if(p==m0||p>=d.size()||d[p++]!='.')continue;
        std::size_t u0=p;
        while(p<d.size()&&std::isdigit(static_cast<unsigned char>(d[p])))micro=micro*10+(d[p++]-'0');
        if(p==u0||major!=3||minor>99||micro>999)continue;
        if(p<d.size()&&!(d[p]==0||d[p]==' '||d[p]=='\r'||d[p]=='\n'||d[p]=='-'||d[p]=='+'))continue;
        out.insert(std::to_string(major)+"."+std::to_string(minor)+"."+std::to_string(micro));
    }
    return out;
}

std::optional<std::string> meaningful_text_sha(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t&size){
    auto it=std::find_if(pe.sections.begin(),pe.sections.end(),[](const PeSection&s){return s.name==".text";});
    if(it==pe.sections.end())return{};
    auto n=std::min(it->vsize,it->raw_size);
    if(!n||it->raw_offset>d.size()||n>d.size()-it->raw_offset)return{};
    size=n;return sha256_bytes(d.subspan(it->raw_offset,n));
}

const PyInstEntry* unique_entry(const PyInstArchiveInfo&a,std::string_view name,std::optional<char>type,std::uint32_t&matches){
    const PyInstEntry*out=nullptr;matches=0;for(const auto&e:a.entries)if(e.name==name&&(!type||e.typecode==*type)){++matches;out=&e;}return matches==1?out:nullptr;
}

std::vector<const PyInstEntry*> entries_of_type(const PyInstArchiveInfo&a,char type){std::vector<const PyInstEntry*>out;for(const auto&e:a.entries)if(e.typecode==type)out.push_back(&e);return out;}

CPythonOpcodeSourceReference source_reference(const ReferenceRegistryEntry&e){
    CPythonOpcodeSourceReference r;r.valid=reference_registry_entry_authenticated(e);r.sha256=e.reference_sha256;r.definitions.reserve(e.semantic_items.size());for(const auto&x:e.semantic_items)r.definitions.push_back({x.key,x.value});if(!r.valid)r.error="registry entry failed authentication metadata gate";return r;
}

std::optional<std::span<const std::uint8_t>> bootstrap_marshal(std::span<const std::uint8_t>raw,char type,const std::array<std::uint8_t,4>&magic){
    if(type=='s')return raw;
    if(type!='m'&&type!='M')return{};
    // PyInstaller 4.1 stores a full PEP-552-era pyc header before the marshal
    // payload for preload modules; the official bootloader strips 16 bytes for
    // Python >=3.7 before PyMarshal_ReadObjectFromString.
    if(raw.size()<=16||!std::equal(magic.begin(),magic.end(),raw.begin()))return{};
    return raw.subspan(16);
}

bool maps_contradict(const CPythonOpcodeModuleDelta&delta,const CPythonInfo&runtime,std::string&why){
    auto native=cpython_validated_opcode_map(runtime);if(!native)return false;
    for(std::size_t op=0;op<delta.target_to_reference.size();++op){auto d=delta.target_to_reference[op],n=native->target_to_official[op];if(d>=0&&n>=0&&d!=n){why="higher/equal native opcode evidence maps target "+std::to_string(op)+" to "+std::to_string(n)+" while opcode-module delta maps it to "+std::to_string(d);return true;}}
    return false;
}

const PyInstallerApplicationRef* select_application_ref(std::span<const std::uint8_t>outer,const PeInfo&pe,int pyminor,std::string&text_sha,std::uint32_t&matches,std::string&why){
    std::uint32_t text_size=0;auto h=meaningful_text_sha(outer,pe,text_size);if(!h){why="outer PE .text is unavailable for authenticated bootloader selection";return nullptr;}text_sha=*h;const PyInstallerApplicationRef*sel=nullptr;matches=0;
    for(const auto&r:kApplicationRefs)if(r.machine==pe.machine&&r.python_minor==pyminor&&r.text_size==text_size&&r.text_sha256==*h){++matches;sel=&r;}
    if(matches!=1){why=matches?"multiple PyInstaller application references remain admissible":"no authenticated PyInstaller bootloader application reference matches the outer native .text";return nullptr;}return sel;
}

ModelTrustReport stock_trust(const ReferenceRegistryEntry&e,const std::string&model,const std::string&evidence){
    ModelTrustFact f;f.plane="cpython.opcode_module";f.semantic_scope=e.semantic_scope;f.reference_scope=e.id;f.model_id=model;f.evidence_level=ModelEvidenceLevel::ExactKnownGoodReference;f.reference_relation=ModelReferenceRelation::SemanticMatch;f.semantic_state=ModelSemanticState::StockConfirmed;f.model_relation=ModelRelation::Supports;f.scope_complete=true;f.evidence=evidence;return build_model_trust_report({std::move(f)});
}
}

CPythonReferencePairingResult pair_cpython_pyinstaller_reference(std::span<const std::uint8_t>outer,const PeInfo&outer_pe,const PyInstArchiveInfo&a,const CPythonInfo&runtime){
    CPythonReferencePairingResult out;
    if(!runtime.valid)return out;
    const auto& registry=reference_registry();
    const bool registered_scope=std::any_of(registry.begin(),registry.end(),[&](const ReferenceRegistryEntry&e){
        return e.ecosystem=="CPython"&&e.version==runtime.version&&e.reference_artifact_kind=="Lib/opcode.py"&&e.semantic_scope==out.semantic_scope;
    });
    if(!registered_scope)return out; // bounded product surface: unsupported releases stay on the native CPython plane.
    out.attempted=true;
    auto unresolved=[&](std::string why){out.state="UNRESOLVED";out.reason=std::move(why);out.negative_evidence.push_back(out.reason);return out;};
    if(!a.valid||!outer_pe.valid)return unresolved("pairing requires validated outer PE and PyInstaller CArchive for the registered embedded CPython runtime");

    std::uint32_t runtime_matches=0;auto*re=unique_entry(a,a.python_library,std::nullopt,runtime_matches);
    if(!re||runtime_matches!=1||a.python_library.empty())return unresolved("exact CArchive runtime entry is missing or ambiguous");
    auto rb=pyinstaller_entry_bytes(outer,a,*re);if(!rb)return unresolved("exact CArchive runtime bytes could not be recovered");
    out.runtime_entry=re->name;out.runtime_sha256=sha256_bytes(*rb);out.runtime_version=runtime.version;
    if(out.runtime_sha256!=runtime.sha256||runtime.source!="CArchive:"+re->name)return unresolved("CPython detector identity does not bind to the exact selected CArchive runtime bytes");
    auto runtime_pe=parse_pe(*rb);if(!runtime_pe.valid)return unresolved("selected CArchive runtime is not a valid PE image");
    auto file_version=pe_version_string(*rb,runtime_pe,"FileVersion"),product_version=pe_version_string(*rb,runtime_pe,"ProductVersion"),original_filename=pe_version_string(*rb,runtime_pe,"OriginalFilename");
    if(!file_version||!product_version||!original_filename)return unresolved("runtime VERSIONINFO is missing exact FileVersion/ProductVersion/OriginalFilename evidence");
    out.runtime_file_version=*file_version;out.runtime_product_version=*product_version;out.runtime_original_filename=*original_filename;
    auto versions=exact_patch_versions(*rb);auto hexver=version_from_hex(runtime.version_hex);const int pyminor=minor_code(runtime.version_hex);
    if(versions.size()!=1||versions.count(runtime.version)!=1||*file_version!=runtime.version||*product_version!=runtime.version||*original_filename!=re->name||hexver!=runtime.version||pyminor!=static_cast<int>(a.python_version))return unresolved("runtime patch identity conflicts across executable version string, PE VERSIONINFO, filename, version hex, or CArchive minor evidence");
    out.runtime_identity_exact=true;out.evidence.push_back("exact CArchive runtime SHA binds one CPython patch identity "+runtime.version+" across executable strings and PE FileVersion/ProductVersion, with OriginalFilename="+*original_filename+" and container minor "+std::to_string(a.python_version));

    auto zentries=entries_of_type(a,'z');if(zentries.size()!=1)return unresolved("exact PYZ selection is ambiguous: expected one CArchive type-z archive");
    auto pyz=pyinstaller_entry_bytes(outer,a,*zentries.front());if(!pyz)return unresolved("selected PYZ bytes could not be recovered from CArchive");
    out.pyz_entry=zentries.front()->name;out.pyz_sha256=sha256_bytes(*pyz);
    auto opcode=pyinstaller_pyz_member_bytes(*pyz,"opcode");if(!opcode.valid)return unresolved("exact PYZ opcode semantic artifact is unavailable: "+opcode.error);
    out.opcode_marshal_sha256=sha256_bytes(opcode.marshal_payload);

    ReferenceSelectionRequest rq;rq.ecosystem="CPython";rq.version=runtime.version;rq.reference_artifact_kind="Lib/opcode.py";rq.semantic_scope=out.semantic_scope;rq.python_minor=static_cast<int>(a.python_version);rq.pyc_magic=opcode.pyc_magic;rq.runtime_identity_exact=true;
    auto selection=select_reference(rq);if(selection.state!=ReferenceSelectionState::ReferenceMatch||!selection.selected)return unresolved("authenticated CPython reference selection failed closed: "+selection.reason);
    const auto&ref=*selection.selected;out.reference_scope=ref.id;out.reference_sha256=ref.reference_sha256;out.reference_origin=ref.origin_release_identity+" commit "+ref.origin_commit+" "+ref.origin_path;out.reference_authentication=ref.authentication_method;
    auto sr=source_reference(ref);out.opcode_delta=recover_cpython38_opcode_module_delta(opcode.marshal_payload,sr);
    if(!out.opcode_delta.valid||!out.opcode_delta.complete_named_opcode_map)return unresolved("AC opcode-module matcher did not recover a complete named semantic scope: "+out.opcode_delta.error);
    out.named_opcode_count=static_cast<std::uint32_t>(out.opcode_delta.mappings.size());out.changed_opcode_count=out.opcode_delta.changed_opcodes;

    std::string native_why;out.native_contradiction=maps_contradict(out.opcode_delta,runtime,native_why);if(out.native_contradiction)out.negative_evidence.push_back(native_why);

    std::uint32_t app_matches=0;std::string app_why;const auto*app=select_application_ref(outer,outer_pe,pyminor,out.bootloader_text_sha256,app_matches,app_why);
    if(!app)return unresolved("authenticated PyInstaller application reference selection failed closed: "+app_why);
    out.application_reference=app->id;out.application_origin=std::string(app->release_identity)+" commit "+app->origin_commit+" "+app->bootloader_artifact;out.application_bootloader_blob=app->bootloader_blob;out.application_bootloader_sha256=app->bootloader_sha256;out.bootstrap_witness_required=static_cast<std::uint32_t>(app->bootstrap.size());

    for(const auto&br:app->bootstrap){
        CPythonPairingBootstrapWitness w;w.module=br.module;w.reference_source_sha256=br.source_sha256;w.reference_semantic_sha256=br.semantic_sha256;std::uint32_t n=0;auto*be=unique_entry(a,br.module,br.typecode,n);
        if(!be||n!=1){w.state="MISSING_OR_AMBIGUOUS";w.error="exact bootstrap entry missing/ambiguous or typecode differs";out.bootstrap_witnesses.push_back(std::move(w));continue;}
        auto bytes=pyinstaller_entry_bytes(outer,a,*be);if(!bytes){w.state="EXTRACT_FAILED";w.error="bootstrap bytes unavailable";out.bootstrap_witnesses.push_back(std::move(w));continue;}
        auto marshal=bootstrap_marshal(*bytes,be->typecode,opcode.pyc_magic);if(!marshal){w.state="HEADER_OR_TYPE_CONFLICT";w.error="bootstrap marshal framing conflicts with authenticated PyInstaller v4.1/Python 3.8 application reference";out.bootstrap_witnesses.push_back(std::move(w));continue;}
        auto norm=remap_python_marshal_opcodes(*marshal,a.python_version,out.opcode_delta.target_to_reference);if(!norm.valid){w.state="NORMALIZATION_FAILED";w.error=norm.error;out.bootstrap_witnesses.push_back(std::move(w));continue;}
        auto sem=semantic_hash_python_marshal(norm.bytes,a.python_version);if(!sem.valid){w.state="SEMANTIC_PARSE_FAILED";w.error=sem.error;out.bootstrap_witnesses.push_back(std::move(w));continue;}
        w.normalized_code_units=norm.rewritten_code_units;w.normalized_semantic_sha256=sem.sha256;if(sem.sha256==br.semantic_sha256){w.state="REFERENCE_MATCH";++out.bootstrap_witness_matched;}else{w.state="REFERENCE_DIFF";w.error="normalized bootstrap semantics differ from authenticated official source generation";}out.bootstrap_witnesses.push_back(std::move(w));
    }
    if(out.bootstrap_witness_matched!=out.bootstrap_witness_required)return unresolved("modified opcode map does not close all authenticated must-execute PyInstaller bootstrap semantic witnesses");
    out.evidence.push_back("authenticated outer bootloader code plus 4/4 must-execute bootstrap modules independently validate the recovered opcode map");

    std::vector<const PyInstEntry*>users;for(const auto&e:a.entries)if(e.typecode=='s'&&pyinstaller_entry_role(a,e)=="user")users.push_back(&e);
    if(users.size()!=1)return unresolved("exact outer user-script payload is missing or ambiguous");
    auto payload=pyinstaller_entry_bytes(outer,a,*users.front());if(!payload)return unresolved("exact outer user-script marshal payload could not be recovered");
    out.payload_entry=users.front()->name;out.payload_marshal_sha256=sha256_bytes(*payload);
    auto normalized=remap_python_marshal_opcodes(*payload,a.python_version,out.opcode_delta.target_to_reference);if(!normalized.valid)return unresolved("recovered named-opcode map does not cover every opcode used by the exact payload: "+normalized.error);
    out.normalized_payload_sha256=sha256_bytes(normalized.bytes);out.payload_code_units=normalized.code_units;out.payload_rewritten_code_units=normalized.rewritten_code_units;

    // Native code identity authenticates the exact execution relation: v4.1 run.exe loads
    // the CArchive runtime, imports type-m preload modules, installs type-z PYZ archives,
    // then unmarshals/evaluates type-s scripts from the same validated TOC.  The 4/4
    // normalized bootstrap witnesses additionally prove this map is the one required by
    // code that must execute before the selected payload, rather than a stale same-bundle table.
    out.payload_binding_exact=true;out.application_proof_exact=true;out.ambiguity_closed=true;
    out.model_id="cpython:"+runtime.version+":sha256:"+runtime.sha256;

    CPythonReferencePairingGateEvidence gate;
    gate.exact_runtime_reference_selection=out.runtime_identity_exact&&selection.state==ReferenceSelectionState::ReferenceMatch&&app_matches==1;
    gate.exact_reference_authenticated=reference_registry_entry_authenticated(ref);
    gate.target_semantic_artifact_exact=opcode.match_count==1&&!out.opcode_marshal_sha256.empty();
    gate.matcher_complete=out.opcode_delta.complete_named_opcode_map;
    gate.exact_payload_binding=out.payload_binding_exact;
    gate.exact_application_proof=out.application_proof_exact;
    gate.ambiguity_closed=out.ambiguity_closed;
    gate.native_contradiction=out.native_contradiction;
    std::string gate_reason;if(!cpython_reference_pairing_gate(gate,&gate_reason))return unresolved(gate_reason);

    if(!out.opcode_delta.changed){
        out.state="REFERENCE_MATCH";out.reason="authenticated reference semantics match the exact target named-opcode scope with zero changes";
        out.model_trust=stock_trust(ref,out.model_id,"authenticated stock named-opcode semantics plus exact PyInstaller runtime/payload application closure");
        return out;
    }

    SemanticDeltaEvidence se;se.plane="cpython.opcode_module";se.family="CPython";se.semantic_scope=out.semantic_scope;se.model_id=out.model_id;
    se.reference={ref.id,ref.reference_sha256,true};se.reference_auth=SemanticDeltaReferenceAuth::ExactKnownGoodReference;se.reference_authentication=ref.authentication_method+"; "+out.reference_origin;
    se.modified_artifact={"CArchive:"+out.pyz_entry+"/PYZ:opcode",out.opcode_marshal_sha256,true};se.delta_kind=SemanticDeltaKind::OpcodePermutation;se.delta_completeness=SemanticDeltaCompleteness::CompleteForDeclaredScope;se.recoverability=SemanticDeltaRecoverability::Declarative;se.modification_proven=true;
    se.delta_items.reserve(out.opcode_delta.mappings.size());for(const auto&m:out.opcode_delta.mappings)if(m.target_opcode!=m.reference_opcode)se.delta_items.push_back({m.name,std::to_string(m.reference_opcode),std::to_string(m.target_opcode),m.evidence});
    se.payload={"CArchive:"+out.payload_entry,out.payload_marshal_sha256,true};se.payload_relation=SemanticDeltaPayloadRelation::RuntimeConsumesPayload;
    se.payload_relation_evidence="authenticated PyInstaller v4.1 Windows-32bit run.exe .text loads the exact CArchive runtime, installs the unique type-z PYZ, imports exact preload modules, then unmarshals/evaluates the unique outer type-s user payload";
    se.application_proof=SemanticDeltaApplicationProof::ExactTransformClosure;
    se.application_evidence="4/4 authenticated must-execute PyInstaller v4.1 bootstrap semantic witnesses match after this exact map; every opcode used by the exact user payload is mapped and its normalized marshal structurally re-parses";
    se.evidence_ceiling=ModelEvidenceLevel::ExactKnownGoodReference;se.native_contradiction=out.native_contradiction;se.native_contradiction_evidence=native_why;
    se.limitations="claim is exactly cpython.opcode_module_named_semantics for the bound payload; it does not assert whole-CPython-runtime exactness or native handler equivalence";
    out.semantic_delta=assess_semantic_delta(se);out.model_trust=build_model_trust_report(model_trust_facts_from_semantic_delta(se));
    if(!out.semantic_delta.valid||out.semantic_delta.classification!=SemanticDeltaClassification::ExactDeclarativeDelta||!out.semantic_delta.exact_delta_for_scope)return unresolved("semantic-delta trust contract refused exact promotion");
    out.state="EXACT_DECLARATIVE_DELTA";out.reason="authenticated CPython reference, complete named-opcode delta, exact payload binding, and authenticated PyInstaller application closure all pass";return out;
}

Finding cpython_reference_pairing_finding(const CPythonReferencePairingResult&r){
    Finding f;f.kind="semantic_reference";f.family="CPython authenticated reference pairing";f.variant=r.runtime_version;f.state=(r.state=="REFERENCE_MATCH"||r.state=="EXACT_DECLARATIVE_DELTA")?"CONFIRMED":"UNRESOLVED";f.evidence=r.evidence;f.negative_evidence=r.negative_evidence;
    f.fields["pairing_state"]=r.state;f.fields["reason"]=r.reason;f.fields["semantic_scope"]=r.semantic_scope;f.fields["scope_complete"]=(r.state=="REFERENCE_MATCH"||r.state=="EXACT_DECLARATIVE_DELTA")?"true":"false";f.fields["model_id"]=r.model_id;f.fields["reference_scope"]=r.reference_scope;f.fields["reference_sha256"]=r.reference_sha256;f.fields["reference_origin"]=r.reference_origin;f.fields["reference_authentication"]=r.reference_authentication;f.fields["runtime_entry"]=r.runtime_entry;f.fields["runtime_sha256"]=r.runtime_sha256;f.fields["runtime_file_version"]=r.runtime_file_version;f.fields["runtime_product_version"]=r.runtime_product_version;f.fields["runtime_original_filename"]=r.runtime_original_filename;f.fields["pyz_entry"]=r.pyz_entry;f.fields["pyz_sha256"]=r.pyz_sha256;f.fields["opcode_marshal_sha256"]=r.opcode_marshal_sha256;f.fields["payload_entry"]=r.payload_entry;f.fields["payload_marshal_sha256"]=r.payload_marshal_sha256;f.fields["normalized_payload_sha256"]=r.normalized_payload_sha256;f.fields["named_opcodes"]=std::to_string(r.named_opcode_count);f.fields["changed_opcodes"]=std::to_string(r.changed_opcode_count);f.fields["payload_code_units"]=std::to_string(r.payload_code_units);f.fields["payload_rewritten_code_units"]=std::to_string(r.payload_rewritten_code_units);f.fields["application_reference"]=r.application_reference;f.fields["application_origin"]=r.application_origin;f.fields["application_bootloader_blob"]=r.application_bootloader_blob;f.fields["application_bootloader_sha256"]=r.application_bootloader_sha256;f.fields["bootloader_text_sha256"]=r.bootloader_text_sha256;f.fields["bootstrap_witnesses"]=std::to_string(r.bootstrap_witness_matched)+"/"+std::to_string(r.bootstrap_witness_required);f.fields["exact_payload_binding"]=r.payload_binding_exact?"true":"false";f.fields["exact_application_proof"]=r.application_proof_exact?"true":"false";f.fields["ambiguity_closed"]=r.ambiguity_closed?"true":"false";f.fields["native_contradiction"]=r.native_contradiction?"true":"false";f.fields["evidence_ceiling"]="EXACT_KNOWN_GOOD_REFERENCE";
    if(r.semantic_delta.valid)f.fields["semantic_delta_classification"]=to_string(r.semantic_delta.classification);
    if(!r.model_trust.assessments.empty())f.fields["model_trust_state"]=std::string(to_string(r.model_trust.assessments.front().state));
    f.fields["opcode_map_direction"]="target_to_reference";
    for(const auto&m:r.opcode_delta.mappings)f.fields["opcode."+m.name]=std::to_string(m.target_opcode)+"->"+std::to_string(m.reference_opcode);
    for(const auto&w:r.bootstrap_witnesses){
        f.fields["bootstrap."+w.module]=w.state;
        if(!w.reference_source_sha256.empty())f.fields["bootstrap."+w.module+".reference_source_sha256"]=w.reference_source_sha256;
        if(!w.reference_semantic_sha256.empty())f.fields["bootstrap."+w.module+".reference_semantic_sha256"]=w.reference_semantic_sha256;
        if(!w.normalized_semantic_sha256.empty())f.fields["bootstrap."+w.module+".normalized_semantic_sha256"]=w.normalized_semantic_sha256;
        if(!w.error.empty())f.negative_evidence.push_back(w.module+": "+w.error);
    }
    if(r.state=="EXACT_DECLARATIVE_DELTA")f.evidence.push_back("exact claim is bounded to cpython.opcode_module_named_semantics; whole CPython runtime remains outside this reference scope");
    return f;
}
}
