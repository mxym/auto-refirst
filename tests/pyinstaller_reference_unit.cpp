#include "prts/pyinstaller.hpp"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
using prts::PyInstArchiveInfo;using prts::PyInstBootstrapModuleMatch;using prts::PyInstEntry;
void need(bool v,const char*msg){if(!v){std::cerr<<"FAIL: "<<msg<<'\n';std::exit(1);}}
PyInstBootstrapModuleMatch match(std::string name,std::string state="EXACT_MATCH",std::string labels="R",bool available=true){
    PyInstBootstrapModuleMatch m;m.name=std::move(name);m.state=std::move(state);m.reference_label=std::move(labels);m.reference_available=available;return m;
}
void entry(PyInstArchiveInfo&a,const char*name){PyInstEntry e;e.name=name;a.entries.push_back(std::move(e));}
PyInstArchiveInfo modern(bool windows=false){PyInstArchiveInfo a;a.valid=true;for(auto n:{"pyimod01_archive","pyimod02_importers","pyimod03_ctypes"}){entry(a,n);a.bootstrap_modules.push_back(match(n));}if(windows){entry(a,"pyimod04_pywin32");a.bootstrap_modules.push_back(match("pyimod04_pywin32"));}return a;}
PyInstArchiveInfo legacy(){PyInstArchiveInfo a;a.valid=true;for(auto n:{"pyimod01_os_path","pyimod02_archive","pyimod03_importers","pyimod04_ctypes"}){entry(a,n);a.bootstrap_modules.push_back(match(n));}return a;}
}
int main(){
    {
        auto a=modern();prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_profile=="MODERN_5X_6X","modern profile");need(a.bootstrap_reference_status=="REFERENCE_MATCH","modern non-Windows match");need(a.bootstrap_reference_label=="R","modern label");need(a.bootstrap_match_mode=="EXACT","modern exact mode");
    }
    {
        auto a=modern(true);prts::finalize_pyinstaller_bootstrap_reference(a);need(a.bootstrap_reference_status=="REFERENCE_MATCH","modern Windows match");
    }
    {
        auto a=modern(true);a.bootstrap_modules.back()=match("pyimod04_pywin32","NO_REFERENCE","",false);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="PARTIAL_REFERENCE_MATCH","Windows optional no-reference must not confirm");
    }
    {
        auto a=modern(true);a.bootstrap_modules.back()=match("pyimod04_pywin32","DIFFERENT","",true);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_DIFF","Windows optional difference must reject");
    }
    {
        auto a=modern();a.bootstrap_modules[1]=match("pyimod02_importers","SEMANTIC_MATCH","R",true);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_MATCH"&&a.bootstrap_match_mode=="MIXED","mixed modern match");
    }
    {
        auto a=modern();a.bootstrap_modules[0].reference_label="A|B";a.bootstrap_modules[1].reference_label="A";a.bootstrap_modules[2].reference_label="B";prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="REFERENCE_DIFF","label intersection conflict must reject");
    }
    {
        auto a=legacy();prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_profile=="LEGACY_4X","legacy profile");need(a.bootstrap_reference_status=="REFERENCE_MATCH","legacy match");
    }
    {
        auto a=legacy();a.bootstrap_modules.back()=match("pyimod04_ctypes","DIFFERENT","",true);prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_reference_status=="PARTIAL_REFERENCE_MATCH","legacy three-of-four remains partial, never full");
    }
    {
        auto a=modern();for(auto n:{"pyimod01_os_path","pyimod02_archive","pyimod03_importers","pyimod04_ctypes"}){entry(a,n);a.bootstrap_modules.push_back(match(n));}prts::finalize_pyinstaller_bootstrap_reference(a);
        need(a.bootstrap_profile=="AMBIGUOUS"&&a.bootstrap_reference_status=="REFERENCE_PROFILE_AMBIGUOUS","mixed profile must fail closed");
    }
    std::cout<<"PASS\n";return 0;
}
