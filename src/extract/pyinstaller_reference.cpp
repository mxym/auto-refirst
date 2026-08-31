#include "prts/pyinstaller.hpp"
#include <algorithm>
#include <array>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {
struct PyInstallerLoaderGenerationReference {
    const char* generation_sha256;
    const char* component;
    int python_min;
    int python_max;
    const char* releases;
};
#include "../reference/pyinstaller_loader_generations.inc"
}

namespace prts { namespace {
constexpr std::array<std::string_view,4> kLegacyRequired={
    "pyimod01_os_path","pyimod02_archive","pyimod03_importers","pyimod04_ctypes"
};
constexpr std::array<std::string_view,3> kModernRequired={
    "pyimod01_archive","pyimod02_importers","pyimod03_ctypes"
};
constexpr std::string_view kModernWindowsOptional="pyimod04_pywin32";

std::vector<std::string_view> split_pipe(std::string_view text){
    std::vector<std::string_view> out;std::size_t p=0;
    while(p<=text.size()){
        const auto q=text.find('|',p);const auto part=text.substr(p,q==std::string_view::npos?text.size()-p:q-p);
        if(!part.empty())out.push_back(part);
        if(q==std::string_view::npos)break;
        p=q+1;
    }
    return out;
}
std::set<std::string> pipe_set(std::string_view text){
    std::set<std::string> out;for(const auto part:split_pipe(text))out.emplace(part);return out;
}
std::string join_set(const std::set<std::string>&values){
    std::string out;for(const auto&x:values){if(!out.empty())out+='|';out+=x;}return out;
}
std::set<std::string> intersect_sets(const std::set<std::string>&a,const std::set<std::string>&b){
    std::set<std::string> out;std::set_intersection(a.begin(),a.end(),b.begin(),b.end(),std::inserter(out,out.begin()));return out;
}
void intersect_into(std::set<std::string>&common,const std::set<std::string>&values,bool&first){
    if(first){common=values;first=false;return;}
    common=intersect_sets(common,values);
}
std::set<std::string> releases_for_component_generation(std::string_view component,std::string_view generation,bool compatible_only,int python_minor){
    std::set<std::string> releases;
    for(const auto&g:kPyInstallerLoaderGenerations){
        if(component!=g.component||generation!=g.generation_sha256)continue;
        if(compatible_only&&(python_minor<g.python_min||python_minor>g.python_max))continue;
        for(const auto release:split_pipe(g.releases))releases.emplace(release);
    }
    return releases;
}

bool has_entry(const PyInstArchiveInfo&a,std::string_view name){
    return std::any_of(a.entries.begin(),a.entries.end(),[&](const PyInstEntry&e){return e.name==name;});
}
template<std::size_t N> bool has_all(const PyInstArchiveInfo&a,const std::array<std::string_view,N>&names){
    return std::all_of(names.begin(),names.end(),[&](auto n){return has_entry(a,n);});
}
const PyInstBootstrapModuleMatch* module_match(const PyInstArchiveInfo&a,std::string_view name){
    const auto it=std::find_if(a.bootstrap_modules.begin(),a.bootstrap_modules.end(),[&](const auto&m){return m.name==name;});
    return it==a.bootstrap_modules.end()?nullptr:&*it;
}
bool matched(const PyInstBootstrapModuleMatch*m){
    if(!m)return false;
    return m->state=="EXACT_MATCH"||m->state=="SEMANTIC_MATCH"||m->state=="OPCODE_NORMALIZED_SEMANTIC_MATCH";
}
std::string mode_for(const std::vector<const PyInstBootstrapModuleMatch*>&mods){
    if(mods.empty())return {};
    std::size_t exact=0,semantic=0,normalized=0;
    for(const auto*m:mods){
        if(!m)continue;
        if(m->state=="EXACT_MATCH")++exact;
        else if(m->state=="SEMANTIC_MATCH")++semantic;
        else if(m->state=="OPCODE_NORMALIZED_SEMANTIC_MATCH"){++semantic;++normalized;}
    }
    if(normalized)return normalized==mods.size()?"OPCODE_NORMALIZED":"MIXED_OPCODE_NORMALIZED";
    if(exact==mods.size())return "EXACT";
    if(semantic==mods.size())return "SEMANTIC";
    return "MIXED";
}

struct CoreClosure {
    std::set<std::string> generations;
    std::set<std::string> direct_labels;
    bool first_generation=true;
    bool first_direct=true;
    bool metadata_conflict=false;
    std::vector<const PyInstBootstrapModuleMatch*> matched_modules;
};
void add_core_match(CoreClosure&c,const PyInstBootstrapModuleMatch&m,std::string_view expected_component){
    if(m.reference_component!=expected_component||m.reference_generation.empty()){c.metadata_conflict=true;return;}
    intersect_into(c.generations,pipe_set(m.reference_generation),c.first_generation);
    intersect_into(c.direct_labels,pipe_set(m.reference_label),c.first_direct);
    c.matched_modules.push_back(&m);
}
void fill_core_result(PyInstArchiveInfo&a,const CoreClosure&core,std::string_view core_component){
    if(core.metadata_conflict||core.first_generation||core.generations.size()!=1){a.bootstrap_reference_status="REFERENCE_METADATA_CONFLICT";return;}
    a.bootstrap_reference_generation=*core.generations.begin();
    a.bootstrap_reference_label=core.first_direct?std::string{}:join_set(core.direct_labels);
    a.bootstrap_source_equal_releases=join_set(releases_for_component_generation(core_component,a.bootstrap_reference_generation,false,0));
    a.bootstrap_release_candidates=join_set(releases_for_component_generation(core_component,a.bootstrap_reference_generation,true,static_cast<int>(a.python_version)));
    a.bootstrap_match_mode=mode_for(core.matched_modules);
    if(a.bootstrap_release_candidates.empty())a.bootstrap_reference_status="REFERENCE_COMPATIBILITY_CONFLICT";
}
void apply_windows_extension(PyInstArchiveInfo&a,const PyInstBootstrapModuleMatch&m,CoreClosure&core){
    if(m.reference_component!="WINDOWS_EXTENSION"||m.reference_generation.empty()){a.bootstrap_reference_status="REFERENCE_METADATA_CONFLICT";return;}
    const auto generations=pipe_set(m.reference_generation);
    if(generations.size()!=1){a.bootstrap_reference_status="REFERENCE_METADATA_CONFLICT";return;}
    a.bootstrap_windows_extension_generation=*generations.begin();
    const auto win_source=releases_for_component_generation("WINDOWS_EXTENSION",a.bootstrap_windows_extension_generation,false,0);
    const auto win_compat=releases_for_component_generation("WINDOWS_EXTENSION",a.bootstrap_windows_extension_generation,true,static_cast<int>(a.python_version));
    auto source=intersect_sets(pipe_set(a.bootstrap_source_equal_releases),win_source);
    auto candidates=intersect_sets(pipe_set(a.bootstrap_release_candidates),win_compat);
    // Preserve the old direct-label intersection semantics across all required modules.
    if(!core.first_direct)core.direct_labels=intersect_sets(core.direct_labels,pipe_set(m.reference_label));
    a.bootstrap_reference_label=core.first_direct?std::string{}:join_set(core.direct_labels);
    core.matched_modules.push_back(&m);a.bootstrap_match_mode=mode_for(core.matched_modules);
    a.bootstrap_source_equal_releases=join_set(source);a.bootstrap_release_candidates=join_set(candidates);
    if(source.empty()){a.bootstrap_reference_status="REFERENCE_DIFF";return;}
    if(candidates.empty())a.bootstrap_reference_status="REFERENCE_COMPATIBILITY_CONFLICT";
}
void fallback_unresolved(PyInstArchiveInfo&a){
    // Without a complete legacy/modern profile, retain the historical direct-label partial behavior.
    int matched_count=0;bool any_reference=false;std::set<std::string>common;bool first=true;std::vector<const PyInstBootstrapModuleMatch*> mods;
    for(const auto&m:a.bootstrap_modules){
        if(m.name=="struct")continue;
        any_reference|=m.reference_available;if(!matched(&m))continue;
        ++matched_count;mods.push_back(&m);intersect_into(common,pipe_set(m.reference_label),first);
    }
    if(matched_count>=3&&!common.empty()){
        a.bootstrap_reference_status="PARTIAL_REFERENCE_MATCH";a.bootstrap_reference_label=join_set(common);a.bootstrap_match_mode=mode_for(mods);
    }else a.bootstrap_reference_status=any_reference?"REFERENCE_DIFF":"NO_REFERENCE";
}
}

std::string pyinstaller_reference_component_for_module(std::string_view module){
    if(std::find(kLegacyRequired.begin(),kLegacyRequired.end(),module)!=kLegacyRequired.end())return "LEGACY_CORE";
    if(std::find(kModernRequired.begin(),kModernRequired.end(),module)!=kModernRequired.end())return "MODERN_CORE";
    if(module==kModernWindowsOptional)return "WINDOWS_EXTENSION";
    return {}; // struct and unknown auxiliary witnesses do not carry PyInstaller source-generation identity.
}
std::string pyinstaller_reference_generation_for_label(std::string_view label,std::string_view component){
    for(const auto&g:kPyInstallerLoaderGenerations){
        if(component!=g.component)continue;
        for(const auto release:split_pipe(g.releases))if(release==label)return g.generation_sha256;
    }
    return {};
}
std::string pyinstaller_source_equal_releases_for_component_generation(std::string_view component,std::string_view generation){
    return join_set(releases_for_component_generation(component,generation,false,0));
}
std::string pyinstaller_compatible_releases_for_component_generation(std::string_view component,std::string_view generation,int python_minor){
    return join_set(releases_for_component_generation(component,generation,true,python_minor));
}

void finalize_pyinstaller_bootstrap_reference(PyInstArchiveInfo&a){
    a.bootstrap_reference_status.clear();a.bootstrap_reference_label.clear();a.bootstrap_reference_generation.clear();a.bootstrap_windows_extension_generation.clear();
    a.bootstrap_release_candidates.clear();a.bootstrap_source_equal_releases.clear();a.bootstrap_match_mode.clear();a.bootstrap_profile.clear();
    if(!a.valid)return;
    const bool legacy=has_all(a,kLegacyRequired),modern=has_all(a,kModernRequired);
    if(legacy&&modern){a.bootstrap_profile="AMBIGUOUS";a.bootstrap_reference_status="REFERENCE_PROFILE_AMBIGUOUS";return;}
    if(!legacy&&!modern){a.bootstrap_profile="UNRESOLVED";fallback_unresolved(a);return;}

    const std::string_view core_component=legacy?"LEGACY_CORE":"MODERN_CORE";
    std::vector<std::string_view> required;
    if(legacy){a.bootstrap_profile="LEGACY_4X";required.assign(kLegacyRequired.begin(),kLegacyRequired.end());}
    else{a.bootstrap_profile="MODERN_5X_6X";required.assign(kModernRequired.begin(),kModernRequired.end());}

    bool any_reference=false,all_required_matched=true;std::size_t required_matched=0;CoreClosure core;
    for(const auto name:required){
        const auto*m=module_match(a,name);if(m)any_reference|=m->reference_available;
        if(!matched(m)){all_required_matched=false;continue;}
        ++required_matched;add_core_match(core,*m,core_component);
    }
    if(core.metadata_conflict){a.bootstrap_reference_status="REFERENCE_METADATA_CONFLICT";return;}
    if(!all_required_matched){
        // A complete generation interpretation is only exposed when all core modules close.
        if(required_matched>=3&&!core.first_direct&&!core.direct_labels.empty()){
            a.bootstrap_reference_status="PARTIAL_REFERENCE_MATCH";a.bootstrap_reference_label=join_set(core.direct_labels);a.bootstrap_match_mode=mode_for(core.matched_modules);
        }else a.bootstrap_reference_status=any_reference?"REFERENCE_DIFF":"NO_REFERENCE";
        return;
    }
    if(core.first_generation||core.generations.size()!=1){a.bootstrap_reference_status="REFERENCE_DIFF";return;}
    a.bootstrap_reference_status="REFERENCE_MATCH";fill_core_result(a,core,core_component);
    if(a.bootstrap_reference_status!="REFERENCE_MATCH")return;

    if(modern&&has_entry(a,kModernWindowsOptional)){
        const auto*m=module_match(a,kModernWindowsOptional);if(m)any_reference|=m->reference_available;
        if(!matched(m)){
            if(m&&m->reference_available){a.bootstrap_reference_status="REFERENCE_DIFF";return;}
            a.bootstrap_reference_status="PARTIAL_REFERENCE_MATCH";return;
        }
        apply_windows_extension(a,*m,core);
    }
}

std::vector<std::string> pyinstaller_bootstrap_required_modules(const PyInstArchiveInfo&a){
    std::vector<std::string> out;
    if(a.bootstrap_profile=="LEGACY_4X")for(const auto name:kLegacyRequired)out.emplace_back(name);
    else if(a.bootstrap_profile=="MODERN_5X_6X"){
        for(const auto name:kModernRequired)out.emplace_back(name);
        if(has_entry(a,kModernWindowsOptional))out.emplace_back(kModernWindowsOptional);
    }
    return out;
}
}
