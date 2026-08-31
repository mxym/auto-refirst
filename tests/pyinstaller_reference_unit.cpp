#include "prts/pyinstaller.hpp"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
using prts::PyInstArchiveInfo;using prts::PyInstBootstrapModuleMatch;using prts::PyInstEntry;
void need(bool v,const char*msg){if(!v){std::cerr<<"FAIL: "<<msg<<'\n';std::exit(1);}}
void append_unique(std::string&out,const std::string&value){
    if(value.empty())return;
    std::size_t p=0;
    while(p<=out.size()){
        const auto q=out.find('|',p);const auto part=out.substr(p,q==std::string::npos?out.size()-p:q-p);
        if(part==value)return;
        if(q==std::string::npos)break;
        p=q+1;
    }
    if(!out.empty())out+='|';
    out+=value;
}
PyInstBootstrapModuleMatch match(std::string name,std::string state="EXACT_MATCH",std::string labels="6.20.0",bool available=true){
    PyInstBootstrapModuleMatch m;m.name=std::move(name);m.state=std::move(state);m.reference_label=std::move(labels);m.reference_available=available;
    m.reference_component=prts::pyinstaller_reference_component_for_module(m.name);
    if(m.reference_component.empty())return m;
    std::size_t p=0;
    while(p<=m.reference_label.size()){
        const auto q=m.reference_label.find('|',p);const auto label=m.reference_label.substr(p,q==std::string::npos?m.reference_label.size()-p:q-p);
        append_unique(m.reference_generation,prts::pyinstaller_reference_generation_for_label(label,m.reference_component));
        if(q==std::string::npos)break;
        p=q+1;
    }
    return m;
}
void entry(PyInstArchiveInfo&a,const char*name){PyInstEntry e;e.name=name;a.entries.push_back(std::move(e));}
PyInstArchiveInfo modern(bool windows=false,int python=314){
    PyInstArchiveInfo a;a.valid=true;a.python_version=python;
    for(auto n:{"pyimod01_archive","pyimod02_importers","pyimod03_ctypes"}){entry(a,n);a.bootstrap_modules.push_back(match(n));}
    if(windows){entry(a,"pyimod04_pywin32");a.bootstrap_modules.push_back(match("pyimod04_pywin32"));}
    return a;
}
PyInstArchiveInfo legacy(){
    PyInstArchiveInfo a;a.valid=true;a.python_version=310;
    for(auto n:{"pyimod01_os_path","pyimod02_archive","pyimod03_importers","pyimod04_ctypes"}){entry(a,n);a.bootstrap_modules.push_back(match(n,"EXACT_MATCH","4.10"));}
    return a;
}
bool contains_release(const std::string&list,const std::string&release){
    std::size_t p=0;
    while(p<=list.size()){
        const auto q=list.find('|',p);
        if(list.substr(p,q==std::string::npos?list.size()-p:q-p)==release)return true;
        if(q==std::string::npos)break;
        p=q+1;
    }
    return false;
}
}

int main(){
    need(prts::pyinstaller_reference_component_for_module("struct").empty(),"struct remains auxiliary, not loader source");
    need(prts::pyinstaller_reference_component_for_module("pyimod01_archive")=="MODERN_CORE","modern core component");
    need(prts::pyinstaller_reference_component_for_module("pyimod04_pywin32")=="WINDOWS_EXTENSION","Windows extension component");

    const auto core=prts::pyinstaller_reference_generation_for_label("6.20.0","MODERN_CORE");
    const auto win=prts::pyinstaller_reference_generation_for_label("6.20.0","WINDOWS_EXTENSION");
    need(!core.empty()&&!win.empty()&&core!=win,"core and Windows extension generations are independent");
    need(prts::pyinstaller_reference_generation_for_label("6.16.0","MODERN_CORE")==core,"6.16 core generation equality");
    need(prts::pyinstaller_reference_generation_for_label("6.22.2","MODERN_CORE")==core,"6.22.2 core generation equality");
    need(prts::pyinstaller_reference_generation_for_label("6.0.0","MODERN_CORE")!=core,"different core generation separation");
    need(!prts::pyinstaller_reference_generation_for_label("5.3","MODERN_CORE").empty(),"5.3 transitional modern core cataloged");
    need(prts::pyinstaller_reference_generation_for_label("5.3","WINDOWS_EXTENSION").empty(),"5.3 has no Windows extension generation");
    need(!prts::pyinstaller_reference_generation_for_label("5.5","WINDOWS_EXTENSION").empty(),"5.5 introduces Windows extension generation");

    const auto core_equal=prts::pyinstaller_source_equal_releases_for_component_generation("MODERN_CORE",core);
    const auto win_equal=prts::pyinstaller_source_equal_releases_for_component_generation("WINDOWS_EXTENSION",win);
    need(contains_release(core_equal,"6.16.0")&&contains_release(core_equal,"6.22.2"),"core source-equal release expansion");
    need(contains_release(win_equal,"6.0.0")&&contains_release(win_equal,"6.22.2"),"Windows extension has wider source-equal range");
    const auto core315=prts::pyinstaller_compatible_releases_for_component_generation("MODERN_CORE",core,315);
    need(!contains_release(core315,"6.20.0")&&contains_release(core315,"6.21.0")&&contains_release(core315,"6.22.2"),"Python 3.15 core compatibility filter");

    {
        auto a=modern();prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_profile=="MODERN_5X_6X","modern profile");
        need(a.bootstrap_reference_status=="REFERENCE_MATCH","modern non-Windows match");
        need(a.bootstrap_reference_label=="6.20.0","direct reference labels retained");
        need(a.bootstrap_reference_generation==core,"modern core generation");
        need(a.bootstrap_windows_extension_generation.empty(),"non-Windows archive has no Windows extension generation");
        need(contains_release(a.bootstrap_release_candidates,"6.16.0")&&contains_release(a.bootstrap_release_candidates,"6.22.2"),"modern core candidate releases");
        need(a.bootstrap_match_mode=="EXACT","modern exact mode");
        auto required=prts::pyinstaller_bootstrap_required_modules(a);need(required.size()==3,"modern non-Windows required module count");
    }
    {
        auto a=modern(true);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_MATCH","modern Windows match");
        need(a.bootstrap_reference_generation==core&&a.bootstrap_windows_extension_generation==win,"Windows closes core plus extension generations");
        need(contains_release(a.bootstrap_release_candidates,"6.16.0")&&contains_release(a.bootstrap_release_candidates,"6.22.2"),"Windows candidates are component intersection");
        need(!contains_release(a.bootstrap_release_candidates,"6.0.0"),"Windows candidate intersection excludes extension-only source equality");
        auto required=prts::pyinstaller_bootstrap_required_modules(a);need(required.size()==4&&required.back()=="pyimod04_pywin32","modern Windows required module count");
    }
    {
        auto a=modern();
        a.bootstrap_modules[0]=match("pyimod01_archive","EXACT_MATCH","6.16.0");
        a.bootstrap_modules[1]=match("pyimod02_importers","SEMANTIC_MATCH","6.20.0");
        a.bootstrap_modules[2]=match("pyimod03_ctypes","EXACT_MATCH","6.22.2");
        prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_MATCH","source-equal direct labels close one core generation");
        need(a.bootstrap_reference_generation==core,"source-equal core generation identity");
        need(a.bootstrap_reference_label.empty(),"direct label intersection stays empty across representative labels");
        need(contains_release(a.bootstrap_release_candidates,"6.16.0")&&contains_release(a.bootstrap_release_candidates,"6.22.2"),"core generation expands candidate releases");
        need(a.bootstrap_match_mode=="MIXED","mixed exact/semantic mode preserved");
    }
    {
        auto a=modern();a.bootstrap_modules[1]=match("pyimod02_importers","EXACT_MATCH","6.0.0");prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_DIFF","different core generations reject");
    }
    {
        auto a=modern();a.bootstrap_modules[1].reference_generation.clear();prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_METADATA_CONFLICT","matched label without generation mapping fails closed");
    }
    {
        auto a=modern(true);a.bootstrap_modules.back()=match("pyimod04_pywin32","NO_REFERENCE","",false);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="PARTIAL_REFERENCE_MATCH","Windows optional no-reference must not confirm");
        need(!a.bootstrap_release_candidates.empty(),"partial Windows result retains bounded core candidates");
    }
    {
        auto a=modern(true);a.bootstrap_modules.back()=match("pyimod04_pywin32","DIFFERENT","",true);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_DIFF","Windows extension difference rejects");
    }
    {
        auto a=modern(true);a.bootstrap_modules.back()=match("pyimod04_pywin32","EXTRACT_FAILED","",true);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_DIFF","Windows extension extraction failure with known reference rejects");
    }
    {
        auto a=modern(true);a.bootstrap_modules.back()=match("pyimod04_pywin32","EXACT_MATCH","5.5");prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_DIFF","source generations from releases with no common package release reject");
    }
    {
        auto a=modern(true,315);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_MATCH","Python 3.15 modern Windows match");
        need(!contains_release(a.bootstrap_release_candidates,"6.20.0")&&contains_release(a.bootstrap_release_candidates,"6.21.0")&&contains_release(a.bootstrap_release_candidates,"6.22.2"),"Python 3.15 final candidates filter both components");
    }
    {
        auto a=legacy();prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_profile=="LEGACY_4X","legacy profile");need(a.bootstrap_reference_status=="REFERENCE_MATCH","legacy match");
        need(a.bootstrap_release_candidates=="4.10","legacy candidate release");
        auto required=prts::pyinstaller_bootstrap_required_modules(a);need(required.size()==4&&required.front()=="pyimod01_os_path"&&required.back()=="pyimod04_ctypes","legacy required module set");
    }
    {
        auto a=legacy();a.bootstrap_modules.back()=match("pyimod04_ctypes","DIFFERENT","",true);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="PARTIAL_REFERENCE_MATCH","legacy three-of-four remains partial, never full");
    }
    {
        auto a=modern();for(auto n:{"pyimod01_os_path","pyimod02_archive","pyimod03_importers","pyimod04_ctypes"}){entry(a,n);a.bootstrap_modules.push_back(match(n,"EXACT_MATCH","4.10"));}prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_profile=="AMBIGUOUS"&&a.bootstrap_reference_status=="REFERENCE_PROFILE_AMBIGUOUS","mixed profile fails closed");
    }
    std::cout<<"PASS\n";return 0;
}
