#include "prts/python_bytecode.hpp"
#include "prts/python_marshal.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {
std::vector<std::uint8_t> read_all(const std::filesystem::path&p){
    std::ifstream in(p,std::ios::binary);return {std::istreambuf_iterator<char>(in),std::istreambuf_iterator<char>()};
}
}

int main(int argc,char**argv){
    if(argc<3)return 2;
    const std::string mode=argv[1];auto data=read_all(argv[2]);
    if(mode=="inspect"){
        const bool hint=argc>=4&&std::string(argv[3])=="1";auto x=prts::detect_python_bytecode(data,hint);
        std::cout<<(x.candidate?1:0)<<'\t'<<(x.valid?1:0)<<'\t'<<x.magic.version_family<<'\t'<<x.header_kind<<'\t'<<x.marshal_offset<<'\t'<<x.marshal.code_object_count<<'\t'<<x.root.code.size()<<'\t'<<x.error<<'\n';return 0;
    }
    if(mode=="extract"){
        if(argc<4)return 2;
        auto x=prts::detect_python_bytecode(data,true);if(!x.valid){std::cerr<<x.error<<'\n';return 3;}
        auto r=prts::extract_python_bytecode_maps(x,argv[3]);if(!r.success){std::cerr<<r.error<<'\n';return 4;}
        std::cout<<r.rows<<'\t'<<r.code_objects_csv.string()<<'\t'<<r.root_symbols_csv.string()<<'\n';return 0;
    }
    if(mode=="marshal-hash"){
        if(argc!=4)return 2;
        const auto version=std::stoi(argv[3]);auto x=prts::semantic_hash_python_marshal(data,version);
        if(!x.valid){std::cerr<<x.error<<'\n';return 3;}
        std::cout<<x.sha256<<'\n';return 0;
    }
    return 2;
}
