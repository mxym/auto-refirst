#include "prts/replacement.hpp"
#include "prts/path_utf8.hpp"
#include "prts/file_snapshot.hpp"
#include "prts/pe.hpp"
#include <system_error>
namespace prts {
std::filesystem::path choose_backup_path(const std::filesystem::path& target){
    auto p=path_with_ascii_suffix(target,".bak");
    std::error_code ec;
    if(!std::filesystem::exists(p,ec)) return p;
    for(unsigned i=1;i<10000;i++){
        auto q=path_with_ascii_suffix(target,".bak."+std::to_string(i));
        ec.clear(); if(!std::filesystem::exists(q,ec)) return q;
    }
    return path_with_ascii_suffix(target,".bak.overflow");
}
bool replace_with_unpacked(const std::filesystem::path& target,const std::filesystem::path& unpacked,ReplacementReport& r,std::string& error){
    r.target=target; r.unpacked_source=unpacked;
    auto before=snapshot_file(target), candidate=snapshot_file(unpacked);
    if(!before.exists){error="target missing";return false;}
    if(!candidate.exists){error="unpacked candidate missing";return false;}
    auto pe=parse_pe(unpacked);
    if(!pe.valid){r.validation="failed: "+pe.error;error="candidate is not a valid PE: "+pe.error;return false;}
    r.validation="valid PE"; r.original_sha256=before.sha256; r.new_sha256=candidate.sha256;
    r.backup=choose_backup_path(target);
    std::error_code ec;
    std::filesystem::rename(target,r.backup,ec);
    if(ec){error="backup rename failed: "+ec.message();return false;}
    std::filesystem::rename(unpacked,target,ec);
    if(ec){
        std::error_code rollback;
        std::filesystem::rename(r.backup,target,rollback);
        error="install unpacked failed: "+ec.message();
        if(rollback) error += "; rollback failed: "+rollback.message();
        return false;
    }
    r.performed=true;
    return true;
}
}
