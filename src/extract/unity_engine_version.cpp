#include "unity_engine_version.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>

namespace prts {
namespace {
constexpr std::size_t kPrefixLimit=512;
constexpr std::size_t kMaxVersionLength=48;
constexpr std::size_t kMaxBundleGenerationLength=32;

std::uint32_t be32(std::span<const std::uint8_t>d,std::size_t off){
    if(off>d.size()||4>d.size()-off)return 0;
    return (std::uint32_t(d[off])<<24)|(std::uint32_t(d[off+1])<<16)|(std::uint32_t(d[off+2])<<8)|std::uint32_t(d[off+3]);
}
std::uint64_t be64(std::span<const std::uint8_t>d,std::size_t off){
    if(off>d.size()||8>d.size()-off)return 0;
    std::uint64_t value=0;for(std::size_t i=0;i<8;++i)value=(value<<8)|d[off+i];return value;
}
bool known_serialized_generation(std::uint32_t v){
    return v>=9&&v<=22; // The evidence offsets below are validated for modern serialized-file generations only.
}
bool read_zero_string(std::span<const std::uint8_t>d,std::size_t&off,std::size_t max,std::string&out){
    out.clear();if(off>=d.size())return false;
    const auto limit=std::min(d.size(),off+max+1);
    for(std::size_t i=off;i<limit;++i){
        if(d[i]==0){if(i==off)return false;out.assign(reinterpret_cast<const char*>(d.data()+off),i-off);off=i+1;return true;}
        if(d[i]<0x20||d[i]>0x7e)return false;
    }
    return false;
}
bool bundle_generation_string_ok(std::string_view s){
    if(s.empty()||s.size()>kMaxBundleGenerationLength)return false;
    for(unsigned char c:s)if(!std::isalnum(c)&&c!='.'&&c!='_'&&c!='-')return false;
    return true;
}
bool parse_decimal(std::string_view text,std::size_t&pos,std::uint32_t&value){
    if(pos>=text.size()||!std::isdigit(static_cast<unsigned char>(text[pos])))return false;
    std::uint64_t acc=0;std::size_t start=pos;
    while(pos<text.size()&&std::isdigit(static_cast<unsigned char>(text[pos]))){acc=acc*10+std::uint64_t(text[pos]-'0');if(acc>65535)return false;++pos;}
    if(pos==start)return false;
    value=static_cast<std::uint32_t>(acc);
    return true;
}
UnityEngineVersionProbe read_probe_file(const std::filesystem::path&path,bool ggm){
    UnityEngineVersionProbe out;out.source=ggm?"globalgamemanagers":"data.unity3d";
    std::error_code ec;auto st=std::filesystem::symlink_status(path,ec);
    if(ec||std::filesystem::is_symlink(st)||!std::filesystem::is_regular_file(st)){
        out.state="INVALID";out.detail="candidate is missing, linked, or not a regular file";return out;
    }
    const auto size=std::filesystem::file_size(path,ec);if(ec){out.state="INVALID";out.detail="candidate file size is unavailable";return out;}
    std::ifstream in(path,std::ios::binary);if(!in){out.state="INVALID";out.detail="candidate cannot be opened";return out;}
    std::array<std::uint8_t,kPrefixLimit> buffer{};in.read(reinterpret_cast<char*>(buffer.data()),static_cast<std::streamsize>(buffer.size()));
    const auto got=static_cast<std::size_t>(in.gcount());std::span<const std::uint8_t>prefix(buffer.data(),got);
    return ggm?probe_unity_globalgamemanagers(prefix,size):probe_unityfs(prefix,size);
}
std::string summarize_invalid(const UnityEngineVersionProbe&p){return p.source+"="+p.state+(p.detail.empty()?std::string{}:"("+p.detail+")");}
}

bool parse_unity_engine_version_value(std::string_view text,UnityEngineVersionValue&value){
    value={};if(text.empty()||text.size()>kMaxVersionLength)return false;
    std::size_t pos=0;
    if(!parse_decimal(text,pos,value.major)||pos>=text.size()||text[pos++]!='.')return false;
    if(!parse_decimal(text,pos,value.minor)||pos>=text.size()||text[pos++]!='.')return false;
    if(!parse_decimal(text,pos,value.patch)||pos>=text.size())return false;
    value.channel=text[pos++];if(value.channel!='a'&&value.channel!='b'&&value.channel!='c'&&value.channel!='f'&&value.channel!='p'&&value.channel!='x')return false;
    if(!parse_decimal(text,pos,value.channel_number)||pos!=text.size())return false;
    return true;
}

bool parse_unity_engine_version_string(std::string_view text,std::string&canonical){
    canonical.clear();UnityEngineVersionValue value;if(!parse_unity_engine_version_value(text,value))return false;canonical.assign(text);return true;
}

UnityEngineVersionProbe probe_unity_globalgamemanagers(std::span<const std::uint8_t>prefix,std::uint64_t actual_file_size){
    UnityEngineVersionProbe out;out.source="globalgamemanagers";
    if(prefix.size()<20||actual_file_size<prefix.size()){out.state="INVALID";out.detail="serialized-file prefix/header is truncated";return out;}
    const auto generation=be32(prefix,8);out.format_version=generation;
    if(!known_serialized_generation(generation)){out.state="UNSUPPORTED_FORMAT";out.detail="serialized-file generation is outside validated 9..22 engine-version evidence profiles";return out;}
    std::uint64_t metadata_size=be32(prefix,0),declared_size=be32(prefix,4),data_offset=be32(prefix,12);std::size_t version_off=0x14;
    if(generation==22){
        if(prefix.size()<0x30){out.state="INVALID";out.detail="large-file serialized header is truncated";return out;}
        if(be32(prefix,0)!=0||be32(prefix,4)!=0||be32(prefix,12)!=0){out.state="INVALID";out.detail="generation-22 legacy header fields must be zero";return out;}
        metadata_size=be32(prefix,0x14);declared_size=be64(prefix,0x18);data_offset=be64(prefix,0x20);version_off=0x30;
    }else{
        if(prefix[0x10]>1){out.state="INVALID";out.detail="serialized-file endian flag is invalid";return out;}
    }
    out.declared_file_size=declared_size;
    if(metadata_size<13||metadata_size>actual_file_size){out.state="INVALID";out.detail="serialized metadata size is outside file bounds";return out;}
    if(declared_size!=actual_file_size){out.state="INVALID";out.detail="serialized header file size does not match actual file size";return out;}
    if(data_offset<version_off||data_offset>actual_file_size){out.state="INVALID";out.detail="serialized object-data offset is outside file bounds";return out;}
    std::size_t pos=version_off;std::string raw,canonical;
    if(!read_zero_string(prefix,pos,kMaxVersionLength,raw)||!parse_unity_engine_version_string(raw,canonical)){
        out.state="INVALID";out.detail="engine version string is missing, unbounded, non-ASCII, or outside strict Unity version grammar";return out;
    }
    out.state="RESOLVED";out.version=canonical;out.detail="validated serialized-file header geometry and bounded engine-version string";return out;
}

UnityEngineVersionProbe probe_unityfs(std::span<const std::uint8_t>prefix,std::uint64_t actual_file_size){
    UnityEngineVersionProbe out;out.source="data.unity3d";
    static constexpr std::array<std::uint8_t,8> magic={'U','n','i','t','y','F','S',0};
    if(prefix.size()<32||actual_file_size<prefix.size()){out.state="INVALID";out.detail="UnityFS prefix/header is truncated";return out;}
    if(!std::equal(magic.begin(),magic.end(),prefix.begin())){out.state="UNSUPPORTED_FORMAT";out.detail="candidate is not a UnityFS bundle";return out;}
    const auto format=be32(prefix,8);out.format_version=format;
    if(format<6||format>8){out.state="UNSUPPORTED_FORMAT";out.detail="UnityFS bundle version is outside validated 6..8 profiles";return out;}
    std::size_t pos=12;std::string generation,revision,canonical;
    if(!read_zero_string(prefix,pos,kMaxBundleGenerationLength,generation)||!bundle_generation_string_ok(generation)){
        out.state="INVALID";out.detail="UnityFS generation string is missing, unbounded, or malformed";return out;
    }
    if(!read_zero_string(prefix,pos,kMaxVersionLength,revision)||!parse_unity_engine_version_string(revision,canonical)){
        out.state="INVALID";out.detail="UnityFS minimum-revision string is missing, unbounded, or outside strict Unity version grammar";return out;
    }
    if(pos>prefix.size()||20>prefix.size()-pos){out.state="INVALID";out.detail="UnityFS fixed tail header is truncated";return out;}
    const auto declared_size=be64(prefix,pos);out.declared_file_size=declared_size;
    const auto compressed=be32(prefix,pos+8),uncompressed=be32(prefix,pos+12);
    if(declared_size<pos+20||declared_size>std::uint64_t(std::numeric_limits<std::int64_t>::max())||(compressed&0x80000000u)||(uncompressed&0x80000000u)){out.state="INVALID";out.detail="UnityFS size/block-info geometry is implausible";return out;}
    out.state="RESOLVED";out.version=canonical;out.detail="validated UnityFS signature/version/header strings and bounded block-info geometry";return out;
}

UnityEngineVersionEvidence aggregate_unity_engine_versions(const std::vector<UnityEngineVersionProbe>&probes){
    UnityEngineVersionEvidence out;if(probes.empty())return out;
    std::vector<const UnityEngineVersionProbe*>resolved;std::vector<std::string>other;
    for(const auto&p:probes){if(p.state=="RESOLVED")resolved.push_back(&p);else other.push_back(summarize_invalid(p));}
    if(resolved.empty()){
        out.state="UNRESOLVED";std::ostringstream detail;for(std::size_t i=0;i<other.size();++i){if(i)detail<<"; ";detail<<other[i];}out.detail=detail.str();return out;
    }
    const auto&version=resolved.front()->version;for(const auto*p:resolved)if(p->version!=version){
        out.state="CONFLICT";std::ostringstream detail;for(std::size_t i=0;i<resolved.size();++i){if(i)detail<<"; ";detail<<resolved[i]->source<<'='<<resolved[i]->version;}out.detail=detail.str();return out;
    }
    out.state="RESOLVED";out.version=version;std::ostringstream source;for(std::size_t i=0;i<resolved.size();++i){if(i)source<<'+';source<<resolved[i]->source;}out.source=source.str();
    if(!other.empty()){std::ostringstream detail;detail<<"resolved source(s) agree; ignored invalid/unsupported candidate(s): ";for(std::size_t i=0;i<other.size();++i){if(i)detail<<"; ";detail<<other[i];}out.detail=detail.str();}
    else out.detail="all structurally valid engine-version sources agree";
    return out;
}

UnityEngineVersionEvidence inspect_unity_engine_version_near(const std::filesystem::path&anchor){
    UnityEngineVersionEvidence out;std::error_code ec;auto base=std::filesystem::is_regular_file(anchor,ec)?anchor.parent_path():anchor;
    for(int depth=0;depth<5&&!base.empty();++depth){
        const auto ggm=base/"globalgamemanagers",data=base/"data.unity3d";std::vector<UnityEngineVersionProbe>probes;
        auto exists_regular=[&](const std::filesystem::path&p){std::error_code e;auto st=std::filesystem::symlink_status(p,e);return !e&&!std::filesystem::is_symlink(st)&&std::filesystem::is_regular_file(st);};
        if(exists_regular(ggm)){out.globalgamemanagers_path=ggm;out.globalgamemanagers=read_probe_file(ggm,true);probes.push_back(out.globalgamemanagers);}
        if(exists_regular(data)){out.data_unity3d_path=data;out.data_unity3d=read_probe_file(data,false);probes.push_back(out.data_unity3d);}
        if(!probes.empty()){auto aggregate=aggregate_unity_engine_versions(probes);out.state=aggregate.state;out.version=aggregate.version;out.source=aggregate.source;out.detail=aggregate.detail;out.root=base;return out;}
        auto parent=base.parent_path();if(parent==base)break;base=parent;
    }
    return out;
}
}
