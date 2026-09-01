#include "unity_engine_version.hpp"
#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {
void need(bool v,const char*m){if(!v){std::cerr<<"FAIL: "<<m<<'\n';std::exit(1);}}
void put32be(std::vector<std::uint8_t>&d,std::size_t o,std::uint32_t v){need(o+4<=d.size(),"put32 bounds");for(int i=3;i>=0;--i)d[o+static_cast<std::size_t>(3-i)]=static_cast<std::uint8_t>(v>>(i*8));}
void put64be(std::vector<std::uint8_t>&d,std::size_t o,std::uint64_t v){need(o+8<=d.size(),"put64 bounds");for(int i=7;i>=0;--i)d[o+static_cast<std::size_t>(7-i)]=static_cast<std::uint8_t>(v>>(i*8));}
void putz(std::vector<std::uint8_t>&d,std::size_t o,const std::string&s){need(o+s.size()+1<=d.size(),"putz bounds");std::copy(s.begin(),s.end(),d.begin()+static_cast<std::ptrdiff_t>(o));d[o+s.size()]=0;}
std::vector<std::uint8_t> ggm21(std::string version){std::vector<std::uint8_t>d(256);put32be(d,0,64);put32be(d,4,256);put32be(d,8,21);put32be(d,12,128);d[0x10]=0;putz(d,0x14,version);return d;}
std::vector<std::uint8_t> ggm22(std::string version){std::vector<std::uint8_t>d(320);put32be(d,8,22);put32be(d,0x14,80);put64be(d,0x18,320);put64be(d,0x20,160);put64be(d,0x28,0);putz(d,0x30,version);return d;}
std::vector<std::uint8_t> unityfs(std::string version){std::vector<std::uint8_t>d(256);const char magic[]="UnityFS";std::copy(magic,magic+7,d.begin());d[7]=0;put32be(d,8,6);std::size_t p=12;putz(d,p,"5.x.x");p+=6;putz(d,p,version);p+=version.size()+1;put64be(d,p,256);put32be(d,p+8,24);put32be(d,p+12,48);put32be(d,p+16,0);return d;}
void write_file(const std::filesystem::path&p,const std::vector<std::uint8_t>&d){std::ofstream out(p,std::ios::binary);need(bool(out),"open temp fixture");out.write(reinterpret_cast<const char*>(d.data()),static_cast<std::streamsize>(d.size()));need(bool(out),"write temp fixture");}
}
int main(int argc,char**argv){
    if(argc==3&&std::string(argv[1])=="inspect"){std::filesystem::path p=argv[2];auto ev=prts::inspect_unity_engine_version_near(p);std::cout<<ev.state<<'\t'<<ev.version<<'\t'<<ev.source<<'\t'<<ev.detail<<'\n';return ev.state=="RESOLVED"?0:3;}
    if(argc!=1)return 2;
    std::string canonical;
    prts::UnityEngineVersionValue parsed;
    need(prts::parse_unity_engine_version_value("6000.6.0a6",parsed)&&parsed.major==6000&&parsed.minor==6&&parsed.patch==0&&parsed.channel=='a'&&parsed.channel_number==6,"structured Unity version parse");
    need(prts::parse_unity_engine_version_string("2019.4.34f1",canonical)&&canonical=="2019.4.34f1","version grammar 2019");
    need(prts::parse_unity_engine_version_string("6000.1.0b12",canonical),"version grammar Unity 6");
    need(!prts::parse_unity_engine_version_string("6000.1",canonical),"reject incomplete version");
    need(!prts::parse_unity_engine_version_string("6000.1.0z1",canonical),"reject unknown channel");
    {std::vector<std::uint8_t> fake(256);putz(fake,0x14,"2019.4.34f1");need(prts::probe_unity_globalgamemanagers(fake,fake.size()).state=="UNSUPPORTED_FORMAT","version-looking bytes without serialized header do not resolve");}
    auto a=ggm21("2019.4.34f1");auto pa=prts::probe_unity_globalgamemanagers(a,a.size());need(pa.state=="RESOLVED"&&pa.version=="2019.4.34f1"&&pa.format_version==21,"ggm v21");
    auto b=ggm22("2022.3.35f1");auto pb=prts::probe_unity_globalgamemanagers(b,b.size());need(pb.state=="RESOLVED"&&pb.version=="2022.3.35f1"&&pb.format_version==22,"ggm v22");
    put64be(b,0x18,319);need(prts::probe_unity_globalgamemanagers(b,b.size()).state=="INVALID","ggm declared size mismatch");
    auto f=unityfs("6000.0.60f1");auto pf=prts::probe_unityfs(f,f.size());need(pf.state=="RESOLVED"&&pf.version=="6000.0.60f1"&&pf.format_version==6,"UnityFS header");
    f[0]='X';need(prts::probe_unityfs(f,f.size()).state=="UNSUPPORTED_FORMAT","UnityFS magic required");
    prts::UnityEngineVersionProbe p1;p1.state="RESOLVED";p1.source="globalgamemanagers";p1.version="6000.0.60f1";
    auto p2=p1;p2.source="data.unity3d";auto agree=prts::aggregate_unity_engine_versions({p1,p2});need(agree.state=="RESOLVED"&&agree.version==p1.version&&agree.source=="globalgamemanagers+data.unity3d","source consensus");
    p2.version="6000.1.0b1";auto conflict=prts::aggregate_unity_engine_versions({p1,p2});need(conflict.state=="CONFLICT"&&conflict.version.empty(),"source conflict fail closed");
    {
        const auto nonce=std::chrono::high_resolution_clock::now().time_since_epoch().count();
        const auto root=std::filesystem::temp_directory_path()/("auto-refirst-unity-version-"+std::to_string(nonce));
        const auto metadata_dir=root/"Game_Data"/"il2cpp_data"/"Metadata";std::filesystem::create_directories(metadata_dir);
        const auto metadata=metadata_dir/"global-metadata.dat";{std::ofstream out(metadata,std::ios::binary);out.put('x');}
        write_file(root/"Game_Data"/"globalgamemanagers",ggm22("6000.0.60f1"));
        auto near=prts::inspect_unity_engine_version_near(metadata);need(near.state=="RESOLVED"&&near.version=="6000.0.60f1"&&near.root==root/"Game_Data","bounded ancestor directory correlation");
        write_file(root/"Game_Data"/"data.unity3d",unityfs("6000.0.60f1"));near=prts::inspect_unity_engine_version_near(metadata);need(near.state=="RESOLVED"&&near.source=="globalgamemanagers+data.unity3d","directory source consensus");
        write_file(root/"Game_Data"/"data.unity3d",unityfs("6000.1.0b1"));near=prts::inspect_unity_engine_version_near(metadata);need(near.state=="CONFLICT"&&near.version.empty(),"directory source conflict fail closed");
        std::filesystem::remove(root/"Game_Data"/"globalgamemanagers");std::filesystem::remove(root/"Game_Data"/"data.unity3d");std::filesystem::create_directory(root/"Game_Data"/"globalgamemanagers");near=prts::inspect_unity_engine_version_near(metadata);need(near.state=="ABSENT","non-regular candidate ignored");
        std::filesystem::remove_all(root);
    }
    std::cout<<"PASS\n";return 0;
}
