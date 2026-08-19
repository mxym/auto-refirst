#include "prts/reference_registry.hpp"
#include "prts/sha256.hpp"
#include <algorithm>
#include <iterator>

namespace prts { namespace {
struct CPythonOpcodeReferenceItemData { const char* key; std::uint16_t value; };
#include "cpython_reference_registry.inc"

bool all_zero(const std::array<std::uint8_t,4>& a){return std::all_of(a.begin(),a.end(),[](auto x){return x==0;});}
}

const std::vector<ReferenceRegistryEntry>& reference_registry(){
    static const std::vector<ReferenceRegistryEntry> registry=[](){
        ReferenceRegistryEntry r;
        r.id="cpython:3.8.5:Lib/opcode.py:named-semantics";
        r.ecosystem="CPython";
        r.version="3.8.5";
        r.reference_artifact_kind="Lib/opcode.py";
        r.semantic_scope="cpython.opcode_module_named_semantics";
        r.reference_sha256="e26b2952088b43e96b9f2bc7776330541cae9fb1f1f1ac48c0cd974cee908b04";
        r.semantic_table_sha256="5df532d1ac72dda063ad2aa8f92662e6ec9b01c297080016111a69f468cb4bad";
        r.origin_release_identity="CPython v3.8.5";
        r.origin_commit="580fbb018fd0844806119614d752b41fc69660f9";
        r.origin_path="Lib/opcode.py";
        r.authentication_method="official_release_tag+peeled_commit+exact_source_sha256+generated_table_check";
        r.validity_constraints="exact runtime patch 3.8.5; Python minor 38 container/PYZ agreement; pyc magic 550d0d0a; no competing admissible reference";
        r.python_minor=38;r.pyc_magic={0x55,0x0d,0x0d,0x0a};
        r.requires_exact_runtime_version=true;r.requires_pyc_magic=true;
        r.semantic_items.reserve(std::size(kCPython385OpcodeItems));
        for(const auto& x:kCPython385OpcodeItems)r.semantic_items.push_back({x.key,x.value});
        return std::vector<ReferenceRegistryEntry>{std::move(r)};
    }();
    return registry;
}

bool reference_registry_entry_authenticated(const ReferenceRegistryEntry& e){
    // Runtime selection may consume only entries that are exactly the pinned,
    // generated release manifest.  Merely supplying plausible metadata plus a
    // 64-character hash must never manufacture an authenticated reference.
    if(e.id!="cpython:3.8.5:Lib/opcode.py:named-semantics"||e.ecosystem!="CPython"||
       e.version!="3.8.5"||e.reference_artifact_kind!="Lib/opcode.py"||
       e.semantic_scope!="cpython.opcode_module_named_semantics"||
       e.reference_sha256!="e26b2952088b43e96b9f2bc7776330541cae9fb1f1f1ac48c0cd974cee908b04"||
       e.semantic_table_sha256!="5df532d1ac72dda063ad2aa8f92662e6ec9b01c297080016111a69f468cb4bad"||
       e.origin_release_identity!="CPython v3.8.5"||e.origin_commit!="580fbb018fd0844806119614d752b41fc69660f9"||
       e.origin_path!="Lib/opcode.py"||e.python_minor!=38||e.pyc_magic!=std::array<std::uint8_t,4>{0x55,0x0d,0x0d,0x0a}||
       !e.requires_exact_runtime_version||!e.requires_pyc_magic||e.semantic_items.size()!=std::size(kCPython385OpcodeItems))return false;
    std::string canonical;
    for(std::size_t i=0;i<e.semantic_items.size();++i){
        const auto& got=e.semantic_items[i];const auto& expected=kCPython385OpcodeItems[i];
        if(got.key!=expected.key||got.value!=expected.value)return false;
        canonical+=got.key;canonical+='\t';canonical+=std::to_string(got.value);canonical+='\n';
    }
    return sha256_bytes(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(canonical.data()),canonical.size()))==e.semantic_table_sha256;
}

bool authenticate_reference_bytes(const ReferenceRegistryEntry& e,std::span<const std::uint8_t> bytes){
    return reference_registry_entry_authenticated(e)&&sha256_bytes(bytes)==e.reference_sha256;
}

ReferenceSelectionResult select_reference(std::span<const ReferenceRegistryEntry> registry,const ReferenceSelectionRequest& q){
    ReferenceSelectionResult out;
    if(q.runtime_identity_conflict){out.state=ReferenceSelectionState::Conflict;out.reason=q.conflict_evidence.empty()?"runtime/container identity evidence conflicts":q.conflict_evidence;return out;}
    if(q.ecosystem.empty()||q.version.empty()||q.reference_artifact_kind.empty()||q.semantic_scope.empty()){
        out.state=ReferenceSelectionState::Unresolved;out.reason="reference selection requires ecosystem, exact version, artifact kind, and semantic scope";return out;
    }
    for(const auto& e:registry){
        if(e.ecosystem!=q.ecosystem||e.version!=q.version||e.reference_artifact_kind!=q.reference_artifact_kind||e.semantic_scope!=q.semantic_scope)continue;
        if(e.requires_exact_runtime_version&&!q.runtime_identity_exact)continue;
        if(q.python_minor&&e.python_minor&&q.python_minor!=e.python_minor)continue;
        if(e.requires_pyc_magic){if(!q.pyc_magic||all_zero(e.pyc_magic)||*q.pyc_magic!=e.pyc_magic)continue;}
        if(!reference_registry_entry_authenticated(e))continue;
        out.admissible.push_back(&e);
    }
    if(out.admissible.empty()){
        out.state=q.runtime_identity_exact?ReferenceSelectionState::NoReference:ReferenceSelectionState::Unresolved;
        out.reason=q.runtime_identity_exact?"no authenticated registry entry satisfies the exact runtime/container constraints":"runtime identity is not exact; version-like evidence cannot select a reference";
        return out;
    }
    if(out.admissible.size()!=1){out.state=ReferenceSelectionState::Unresolved;out.reason="multiple authenticated references remain admissible; first-match selection is forbidden";return out;}
    out.selected=out.admissible.front();out.state=ReferenceSelectionState::ReferenceMatch;out.reason="one authenticated release-pinned reference satisfies all validity constraints";return out;
}

ReferenceSelectionResult select_reference(const ReferenceSelectionRequest& q){const auto&r=reference_registry();return select_reference(r,q);}

const char* to_string(ReferenceSelectionState s){switch(s){case ReferenceSelectionState::NoReference:return "NO_REFERENCE";case ReferenceSelectionState::ReferenceMatch:return "REFERENCE_MATCH";case ReferenceSelectionState::Unresolved:return "UNRESOLVED";case ReferenceSelectionState::Conflict:return "CONFLICT";}return "UNRESOLVED";}
}
