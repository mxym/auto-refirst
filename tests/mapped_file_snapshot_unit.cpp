#include "prts/mapped_file.hpp"
#include "prts/path_utf8.hpp"
#include "prts/sha256.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool ok,const char*message){if(!ok)throw std::runtime_error(message);}
void write(const std::filesystem::path&path,const std::string&bytes){
    std::ofstream out(path,std::ios::binary);out<<bytes;out.close();require(bool(out),"fixture write failed");
}
}

int main(int argc,char**argv){
    try{
        require(argc==2,"expected owned fixture directory");
        const std::filesystem::path root=argv[1];
        require(std::filesystem::create_directory(root),"fixture directory already exists");
        const auto path=root/prts::path_from_utf8("snapshot-样本.bin");
        write(path,"original bytes");
        const auto before=prts::snapshot_file(path);
        {
            prts::MappedFile mapped(path);
            require(mapped.valid(),"mapping failed");
            const auto first=mapped.snapshot();
            require(first.exists&&first.path==path&&first.size==14,"mapped metadata mismatch");
            require(first.sha256==before.sha256,"mapped/file hash mismatch");
            require(first.write_time.has_value()&&before.write_time.has_value(),"file timestamp missing");
#ifdef __MINGW32__
            // MinGW's stat-backed filesystem API can expose seconds only;
            // handle metadata retains native FILETIME subsecond precision.
            require(std::chrono::floor<std::chrono::seconds>(*first.write_time)==std::chrono::floor<std::chrono::seconds>(*before.write_time),"mapped/file timestamp mismatch");
#else
            require(first.write_time==before.write_time,"mapped/file timestamp mismatch");
#endif
            // Rebinding the pathname must not change the identity of the handle
            // already opened for parsing. Both files are ordinary test text.
            std::filesystem::rename(path,root/"renamed.bin");
            write(path,"replacement bytes");
            require(mapped.snapshot().sha256==before.sha256,"snapshot reopened a rebound path");
            require(mapped.snapshot().write_time==first.write_time,"handle timestamp changed after path rebinding");
            require(prts::snapshot_file(path).sha256!=before.sha256,"independent pathname check was reused");
            prts::MappedFile moved(std::move(mapped));
            require(!mapped.snapshot().exists,"moved-from handle reports a file");
            require(moved.snapshot().sha256==before.sha256,"move construction lost identity");
            prts::MappedFile assigned(path);assigned=std::move(moved);
            require(assigned.snapshot().sha256==before.sha256&&!moved.snapshot().exists,"move assignment lost identity");
        }
        const auto empty=root/"empty.bin";write(empty,"");
        prts::MappedFile empty_map(empty);
        require(empty_map.valid()&&empty_map.snapshot().exists&&empty_map.snapshot().size==0,"empty regular input rejected");
        require(empty_map.snapshot().sha256==prts::sha256_bytes({}),"empty hash mismatch");
        prts::MappedFile missing(root/"missing.bin");
        require(!missing.valid()&&!missing.snapshot().exists,"missing input accepted");
        prts::MappedFile directory(root);
        require(!directory.valid()&&!directory.snapshot().exists,"directory mapped as a regular file");
        std::cout<<"PASS\n";
    }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
}
