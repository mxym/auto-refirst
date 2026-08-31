#include "prts/pyinstaller.hpp"
#include <algorithm>
#include <array>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace prts { namespace {
constexpr std::array<std::string_view,4> kLegacyRequired={
    "pyimod01_os_path","pyimod02_archive","pyimod03_importers","pyimod04_ctypes"
};
constexpr std::array<std::string_view,3> kModernRequired={
    "pyimod01_archive","pyimod02_importers","pyimod03_ctypes"
};
constexpr std::string_view kModernWindowsOptional="pyimod04_pywin32";

bool has_entry(const PyInstArchiveInfo&a,std::string_view name){
    return std::any_of(a.entries.begin(),a.entries.end(),[&](const PyInstEntry&e){return e.name==name;});
}
template<std::size_t N> bool has_all(const PyInstArchiveInfo&a,const std::array<std::string_view,N>&names){
    return std::all_of(names.begin(),names.end(),[&](auto n){return has_entry(a,n);});
}
const PyInstBootstrapModuleMatch* module_match(const PyInstArchiveInfo&a,std::string_view name){
    auto it=std::find_if(a.bootstrap_modules.begin(),a.bootstrap_modules.end(),[&](const auto&m){return m.name==name;});
    return it==a.bootstrap_modules.end()?nullptr:&*it;
}
bool matched(const PyInstBootstrapModuleMatch*m){
    if(!m)return false;
    return m->state=="EXACT_MATCH"||m->state=="SEMANTIC_MATCH"||m->state=="OPCODE_NORMALIZED_SEMANTIC_MATCH";
}
std::set<std::string> labels_of(const PyInstBootstrapModuleMatch&m){
    std::set<std::string> out;std::size_t p=0;
    while(p<=m.reference_label.size()){
        auto q=m.reference_label.find('|',p);auto part=m.reference_label.substr(p,q==std::string::npos?m.reference_label.size()-p:q-p);
        if(!part.empty())out.insert(part);
        if(q==std::string::npos)break;
        p=q+1;
    }
    return out;
}
std::string join_labels(const std::set<std::string>&s){
    std::string out;for(const auto&x:s){if(!out.empty())out+='|';out+=x;}return out;
}
void intersect_into(std::set<std::string>&common,const std::set<std::string>&labels,bool&first){
    if(first){common=labels;first=false;return;}
    std::set<std::string> next;std::set_intersection(common.begin(),common.end(),labels.begin(),labels.end(),std::inserter(next,next.begin()));common=std::move(next);
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
void fallback_unresolved(PyInstArchiveInfo&a){
    int matched_count=0;bool any_reference=false;std::set<std::string>common;bool first=true;std::vector<const PyInstBootstrapModuleMatch*> matched_modules;
    for(const auto&m:a.bootstrap_modules){
        if(m.name=="struct")continue;
        any_reference|=m.reference_available;
        if(!matched(&m))continue;
        ++matched_count;matched_modules.push_back(&m);intersect_into(common,labels_of(m),first);
    }
    if(matched_count>=3&&!common.empty()){
        a.bootstrap_reference_status="PARTIAL_REFERENCE_MATCH";a.bootstrap_reference_label=join_labels(common);a.bootstrap_match_mode=mode_for(matched_modules);
    }else a.bootstrap_reference_status=any_reference?"REFERENCE_DIFF":"NO_REFERENCE";
}}

void finalize_pyinstaller_bootstrap_reference(PyInstArchiveInfo&a){
    a.bootstrap_reference_status.clear();a.bootstrap_reference_label.clear();a.bootstrap_match_mode.clear();a.bootstrap_profile.clear();
    if(!a.valid)return;
    const bool legacy=has_all(a,kLegacyRequired),modern=has_all(a,kModernRequired);
    if(legacy&&modern){a.bootstrap_profile="AMBIGUOUS";a.bootstrap_reference_status="REFERENCE_PROFILE_AMBIGUOUS";return;}
    if(!legacy&&!modern){a.bootstrap_profile="UNRESOLVED";fallback_unresolved(a);return;}

    std::vector<std::string_view> required;
    if(legacy){a.bootstrap_profile="LEGACY_4X";required.assign(kLegacyRequired.begin(),kLegacyRequired.end());}
    else{a.bootstrap_profile="MODERN_5X_6X";required.assign(kModernRequired.begin(),kModernRequired.end());}

    bool any_reference=false,all_required_matched=true,first=true;std::set<std::string>common;std::vector<const PyInstBootstrapModuleMatch*> matched_modules;
    std::size_t required_matched=0;
    for(auto name:required){
        auto*m=module_match(a,name);if(m)any_reference|=m->reference_available;
        if(!matched(m)){all_required_matched=false;continue;}
        ++required_matched;matched_modules.push_back(m);intersect_into(common,labels_of(*m),first);
    }
    if(!all_required_matched){
        if(required_matched>=3&&!common.empty()){
            a.bootstrap_reference_status="PARTIAL_REFERENCE_MATCH";a.bootstrap_reference_label=join_labels(common);a.bootstrap_match_mode=mode_for(matched_modules);
        }else a.bootstrap_reference_status=any_reference?"REFERENCE_DIFF":"NO_REFERENCE";
        return;
    }
    if(common.empty()){a.bootstrap_reference_status="REFERENCE_DIFF";return;}

    if(modern&&has_entry(a,kModernWindowsOptional)){
        auto*m=module_match(a,kModernWindowsOptional);if(m)any_reference|=m->reference_available;
        if(!matched(m)){
            a.bootstrap_reference_status=(m&&m->reference_available)?"REFERENCE_DIFF":"PARTIAL_REFERENCE_MATCH";
            a.bootstrap_reference_label=join_labels(common);a.bootstrap_match_mode=mode_for(matched_modules);return;
        }
        auto opt_labels=labels_of(*m);std::set<std::string>next;std::set_intersection(common.begin(),common.end(),opt_labels.begin(),opt_labels.end(),std::inserter(next,next.begin()));common=std::move(next);
        if(common.empty()){a.bootstrap_reference_status="REFERENCE_DIFF";return;}
        matched_modules.push_back(m);
    }

    a.bootstrap_reference_status="REFERENCE_MATCH";a.bootstrap_reference_label=join_labels(common);a.bootstrap_match_mode=mode_for(matched_modules);
}

std::vector<std::string> pyinstaller_bootstrap_required_modules(const PyInstArchiveInfo&a){
    std::vector<std::string> out;
    if(a.bootstrap_profile=="LEGACY_4X"){
        for(auto name:kLegacyRequired)out.emplace_back(name);
    }else if(a.bootstrap_profile=="MODERN_5X_6X"){
        for(auto name:kModernRequired)out.emplace_back(name);
        if(has_entry(a,kModernWindowsOptional))out.emplace_back(kModernWindowsOptional);
    }
    return out;
}
}
