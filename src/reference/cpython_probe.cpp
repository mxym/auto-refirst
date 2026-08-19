#include "prts/cpython_probe.hpp"
#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <span>
#include <string_view>
#include <utility>
namespace prts { namespace {
struct CPythonCompilerProbeCodeReference { const char* path; const std::uint8_t* code; std::size_t size; };
struct CPythonCompilerProbeReference { std::uint32_t version_hex; const char* version; const CPythonCompilerProbeCodeReference* codes; std::size_t count; };
#include "cpython_probe_refs.inc"
const CPythonCompilerProbeReference* find_probe_ref(std::uint32_t v){for(const auto&r:kCPythonCompilerProbeReferences)if(r.version_hex==v)return &r;return nullptr;}
}
CPythonCompilerProbeInfo compare_cpython_compiler_probe(std::uint32_t version_hex,const std::vector<CPythonCompilerProbeCode>&target){
    CPythonCompilerProbeInfo out;out.attempted=true;
    const auto*ref=find_probe_ref(version_hex);if(!ref){out.state="NO_REFERENCE";out.error="no exact CPython compiler-probe reference for target version";return out;}
    out.reference_version=ref->version;
    std::map<std::string,std::span<const std::uint8_t>> tm;
    for(const auto&c:target){if(!tm.emplace(c.path,std::span<const std::uint8_t>(c.code)).second){out.state="COMPILER_DIFFERENT";out.error="duplicate target code-object path: "+c.path;return out;}}
    if(tm.size()!=ref->count){out.state="COMPILER_DIFFERENT";out.error="compiler probe code-object count differs from official reference";return out;}
    std::array<std::array<std::uint64_t,256>,256> pairs{};
    std::array<std::uint64_t,256> target_seen{},ref_seen{};
    for(std::size_t i=0;i<ref->count;++i){
        const auto&rc=ref->codes[i];auto it=tm.find(rc.path);if(it==tm.end()){out.state="COMPILER_DIFFERENT";out.error="missing target code-object path: "+std::string(rc.path);return out;}
        auto t=it->second;if(t.size()!=rc.size||t.size()%2){out.state="COMPILER_DIFFERENT";out.error="code-unit length differs at path "+std::string(rc.path);return out;}
        ++out.code_objects;
        for(std::size_t z=0;z<t.size();z+=2){
            ++out.code_units;const auto to=t[z],ro=rc.code[z];
            if(t[z+1]!=rc.code[z+1]){out.state="COMPILER_DIFFERENT";out.error="oparg differs from official compiler probe at path "+std::string(rc.path)+" code-unit "+std::to_string(z/2);return out;}
            ++out.oparg_matches;++pairs[to][ro];++target_seen[to];++ref_seen[ro];
        }
    }
    std::array<int,256> t2r,r2t;t2r.fill(-1);r2t.fill(-1);
    for(int t=0;t<256;++t){if(!target_seen[t])continue;int only=-1;std::uint64_t obs=0;for(int r=0;r<256;++r)if(pairs[t][r]){if(only!=-1){out.state="COMPILER_DIFFERENT";out.error="one target opcode maps to multiple official opcodes";return out;}only=r;obs=pairs[t][r];}if(only<0)continue;if(r2t[only]!=-1&&r2t[only]!=t){out.state="COMPILER_DIFFERENT";out.error="multiple target opcodes map to one official opcode";return out;}t2r[t]=only;r2t[only]=t;out.mappings.push_back({static_cast<std::uint16_t>(t),static_cast<std::uint16_t>(only),obs});++out.observed_opcodes;if(t!=only)++out.changed_opcodes;}
    out.success=true;out.state=out.changed_opcodes?"OPCODE_PERMUTATION_RECOVERED":"REFERENCE_MATCH";return out;
}
}
