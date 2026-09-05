#include "prts/replacement.hpp"
#include "prts/path_utf8.hpp"
#include "prts/file_snapshot.hpp"
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
}
