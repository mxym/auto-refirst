#include "prts/python_marshal.hpp"
#include "prts/cpython_opcode.hpp"
#include "prts/sha256.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
namespace prts { namespace {
constexpr std::uint8_t FLAG_REF=0x80;
constexpr std::uint8_t TYPE_NULL='0',TYPE_NONE='N',TYPE_FALSE='F',TYPE_TRUE='T',TYPE_STOPITER='S',TYPE_ELLIPSIS='.';
constexpr std::uint8_t TYPE_INT='i',TYPE_INT64='I',TYPE_FLOAT='f',TYPE_BINARY_FLOAT='g',TYPE_COMPLEX='x',TYPE_BINARY_COMPLEX='y',TYPE_LONG='l';
constexpr std::uint8_t TYPE_STRING='s',TYPE_INTERNED='t',TYPE_REF='r',TYPE_TUPLE='(',TYPE_LIST='[',TYPE_DICT='{',TYPE_CODE='c',TYPE_UNICODE='u',TYPE_SET='<',TYPE_FROZENSET='>';
constexpr std::uint8_t TYPE_ASCII='a',TYPE_ASCII_INTERNED='A',TYPE_SMALL_TUPLE=')',TYPE_SHORT_ASCII='z',TYPE_SHORT_ASCII_INTERNED='Z',TYPE_SLICE=':';
enum class K{NullTag,None,False,True,StopIter,Ellipsis,Int,Long,Float,Complex,Bytes,String,Tuple,List,Dict,Set,FrozenSet,Slice,Code};
struct Node;
using NP=std::shared_ptr<Node>;
struct CodeData {
    std::int32_t argcount=0,posonly=0,kwonly=0,nlocals=0,stacksize=0,flags=0,firstlineno=0;
    NP code,consts,names,varnames,freevars,cellvars,localsplusnames,localspluskinds,filename,name,qualname,linetable,exceptiontable;
};
struct Node {
    K k=K::None;
    std::int64_t iv=0;
    std::vector<std::uint8_t> blob;
    std::uint64_t blob_offset=0;
    std::vector<NP> seq;
    std::vector<std::pair<NP,NP>> dict;
    std::shared_ptr<CodeData> code;
};
struct Reader {
    std::span<const std::uint8_t>d; std::size_t p=0; int minor=0,depth=0; std::vector<NP> refs; PythonMarshalSemantic*out=nullptr;
    bool fail(std::string s,std::size_t at=std::numeric_limits<std::size_t>::max()){if(out&&out->error.empty()){out->error=std::move(s);out->error_offset=(at==std::numeric_limits<std::size_t>::max()?p:at);}return false;}
    bool need(std::size_t n){return n<=d.size()-std::min(p,d.size())||fail("marshal truncated");}
    std::uint8_t u8(){if(!need(1))return 0;return d[p++];}
    std::uint16_t u16(){if(!need(2))return 0;auto v=std::uint16_t(d[p])|(std::uint16_t(d[p+1])<<8);p+=2;return v;}
    std::uint32_t u32(){if(!need(4))return 0;auto v=std::uint32_t(d[p])|(std::uint32_t(d[p+1])<<8)|(std::uint32_t(d[p+2])<<16)|(std::uint32_t(d[p+3])<<24);p+=4;return v;}
    std::int32_t i32(){return static_cast<std::int32_t>(u32());}
    std::uint64_t u64(){if(!need(8))return 0;std::uint64_t v=0;for(int i=0;i<8;i++)v|=std::uint64_t(d[p+i])<<(8*i);p+=8;return v;}
    std::vector<std::uint8_t> bytes(std::size_t n){if(!need(n))return{};std::vector<std::uint8_t>x(d.begin()+static_cast<std::ptrdiff_t>(p),d.begin()+static_cast<std::ptrdiff_t>(p+n));p+=n;return x;}
};
NP obj(Reader&r);
NP reserve_node(Reader&r,K k,bool ref){auto n=std::make_shared<Node>();n->k=k;if(ref)r.refs.push_back(n);if(r.out)++r.out->object_count;return n;}
bool count_ok(Reader&r,std::int32_t n,std::size_t minbytes=0){if(n<0||n>10000000)return r.fail("marshal container length unreasonable");if(minbytes&&std::uint64_t(n)*minbytes>r.d.size()-r.p)return r.fail("marshal container exceeds input");return true;}
NP parse_code(Reader&r,bool ref,std::size_t tagoff){auto n=reserve_node(r,K::Code,ref);n->code=std::make_shared<CodeData>();auto&c=*n->code;if(r.out)++r.out->code_object_count;
    auto ri=[&](std::int32_t&v){if(!r.need(4))return false;v=r.i32();return true;};
    if(!ri(c.argcount)||!ri(c.posonly)||!ri(c.kwonly))return{};
    if(r.minor<=10){if(!ri(c.nlocals)||!ri(c.stacksize)||!ri(c.flags))return{};}
    else{if(!ri(c.stacksize)||!ri(c.flags))return{};}
    auto ro=[&](NP&x){x=obj(r);return bool(x);};
    if(!ro(c.code)||!ro(c.consts)||!ro(c.names))return{};
    if(r.minor<=10){if(!ro(c.varnames)||!ro(c.freevars)||!ro(c.cellvars)||!ro(c.filename)||!ro(c.name))return{};if(!ri(c.firstlineno)||!ro(c.linetable))return{};}
    else{if(!ro(c.localsplusnames)||!ro(c.localspluskinds)||!ro(c.filename)||!ro(c.name)||!ro(c.qualname))return{};if(!ri(c.firstlineno)||!ro(c.linetable)||!ro(c.exceptiontable))return{};}
    if(r.out&&c.code&&c.code->k==K::Bytes){
        auto text=[](const NP&x){return x&&x->k==K::String?std::string(reinterpret_cast<const char*>(x->blob.data()),x->blob.size()):std::string();};
        auto exists=std::any_of(r.out->code_ranges.begin(),r.out->code_ranges.end(),[&](const auto&x){return x.offset==c.code->blob_offset&&x.size==c.code->blob.size();});
        if(!exists)r.out->code_ranges.push_back({c.code->blob_offset,c.code->blob.size(),text(c.name),text(c.filename),text(c.qualname),c.firstlineno});
    }
    (void)tagoff;return n;}
NP obj(Reader&r){if(r.depth++>500){--r.depth;r.fail("marshal recursion depth exceeded");return{};}auto done=[&](NP n){--r.depth;return n;};auto tagoff=r.p;if(!r.need(1)){--r.depth;return{};}auto tc=r.u8();bool ref=(tc&FLAG_REF)!=0;auto t=tc&~FLAG_REF;
    auto scalar=[&](K k){return reserve_node(r,k,ref);};
    switch(t){
      case TYPE_NULL:return done(scalar(K::NullTag));case TYPE_NONE:return done(scalar(K::None));case TYPE_FALSE:return done(scalar(K::False));case TYPE_TRUE:return done(scalar(K::True));case TYPE_STOPITER:return done(scalar(K::StopIter));case TYPE_ELLIPSIS:return done(scalar(K::Ellipsis));
      case TYPE_INT:{auto n=scalar(K::Int);if(!r.need(4))return done({});n->iv=r.i32();return done(n);}case TYPE_INT64:{auto n=scalar(K::Int);if(!r.need(8))return done({});n->blob=r.bytes(8);return done(n);}
      case TYPE_LONG:{auto n=scalar(K::Long);if(!r.need(4))return done({});auto sz=r.i32();auto cnt=sz<0?-std::int64_t(sz):std::int64_t(sz);if(cnt>10000000||std::uint64_t(cnt)*2>r.d.size()-r.p){r.fail("marshal long digit count invalid");return done({});}n->iv=sz;n->blob=r.bytes(std::size_t(cnt)*2);return done(n);}
      case TYPE_FLOAT:{auto n=scalar(K::Float);auto len=r.u8();if(!r.need(len))return done({});n->blob=r.bytes(len);return done(n);}case TYPE_BINARY_FLOAT:{auto n=scalar(K::Float);if(!r.need(8))return done({});n->blob=r.bytes(8);return done(n);}
      case TYPE_COMPLEX:{auto n=scalar(K::Complex);auto a=r.u8();if(!r.need(a))return done({});auto x=r.bytes(a);auto b=r.u8();if(!r.need(b))return done({});auto y=r.bytes(b);n->blob=x;n->blob.push_back(0);n->blob.insert(n->blob.end(),y.begin(),y.end());return done(n);}case TYPE_BINARY_COMPLEX:{auto n=scalar(K::Complex);if(!r.need(16))return done({});n->blob=r.bytes(16);return done(n);}
      case TYPE_STRING:{auto n=scalar(K::Bytes);auto len=r.i32();if(!count_ok(r,len,1))return done({});n->blob_offset=r.p;n->blob=r.bytes(len);return done(n);}
      case TYPE_INTERNED:case TYPE_UNICODE:case TYPE_ASCII:case TYPE_ASCII_INTERNED:{auto n=scalar(K::String);auto len=r.i32();if(!count_ok(r,len,1))return done({});n->blob_offset=r.p;n->blob=r.bytes(len);return done(n);}
      case TYPE_SHORT_ASCII:case TYPE_SHORT_ASCII_INTERNED:{auto n=scalar(K::String);auto len=r.u8();if(!r.need(len))return done({});n->blob_offset=r.p;n->blob=r.bytes(len);return done(n);}
      case TYPE_REF:{if(ref){r.fail("marshal TYPE_REF unexpectedly carries FLAG_REF",tagoff);return done({});}auto idx=r.i32();if(idx<0||std::size_t(idx)>=r.refs.size()||!r.refs[idx]){r.fail("marshal reference index invalid",tagoff);return done({});}return done(r.refs[idx]);}
      case TYPE_SMALL_TUPLE:case TYPE_TUPLE:case TYPE_LIST:case TYPE_SET:case TYPE_FROZENSET:{K k=t==TYPE_LIST?K::List:(t==TYPE_SET?K::Set:(t==TYPE_FROZENSET?K::FrozenSet:K::Tuple));auto n=reserve_node(r,k,ref);std::int32_t len=t==TYPE_SMALL_TUPLE?r.u8():r.i32();if(!count_ok(r,len))return done({});n->seq.reserve(len);for(int i=0;i<len;i++){auto x=obj(r);if(!x)return done({});n->seq.push_back(x);}return done(n);}
      case TYPE_DICT:{auto n=reserve_node(r,K::Dict,ref);for(std::size_t i=0;i<10000000;i++){auto k=obj(r);if(!k)return done({});if(k->k==K::NullTag)return done(n);auto v=obj(r);if(!v)return done({});n->dict.emplace_back(k,v);}r.fail("marshal dict too large");return done({});}
      case TYPE_SLICE:{if(r.minor<14){r.fail("marshal slice tag before Python 3.14",tagoff);return done({});}auto n=reserve_node(r,K::Slice,ref);for(int i=0;i<3;i++){auto x=obj(r);if(!x)return done({});n->seq.push_back(x);}return done(n);}
      case TYPE_CODE:{auto n=parse_code(r,ref,tagoff);--r.depth;return n;}
      default:{r.fail("unknown marshal tag 0x"+[] (unsigned v){static const char*h="0123456789abcdef";std::string s;s+=h[(v>>4)&15];s+=h[v&15];return s;}(t),tagoff);return done({});}
    }}
void put_u32(std::vector<std::uint8_t>&o,std::uint32_t v){for(int i=0;i<4;i++)o.push_back(std::uint8_t(v>>(8*i)));}
void put_u64(std::vector<std::uint8_t>&o,std::uint64_t v){for(int i=0;i<8;i++)o.push_back(std::uint8_t(v>>(8*i)));}
void put_blob(std::vector<std::uint8_t>&o,std::span<const std::uint8_t>b){put_u64(o,b.size());o.insert(o.end(),b.begin(),b.end());}
void canon(const NP&n,std::vector<std::uint8_t>&o,std::set<const Node*>&active);
std::vector<std::uint8_t> canon_one(const NP&n){std::vector<std::uint8_t>o;std::set<const Node*>a;canon(n,o,a);return o;}
void canon_seq(const std::vector<NP>&v,std::vector<std::uint8_t>&o,std::set<const Node*>&active,bool unordered=false){put_u64(o,v.size());if(unordered){std::vector<std::vector<std::uint8_t>>xs;xs.reserve(v.size());for(auto&x:v)xs.push_back(canon_one(x));const auto byte_less=[](const auto&a,const auto&b){const auto n=std::min(a.size(),b.size());for(std::size_t i=0;i<n;++i){if(a[i]!=b[i])return a[i]<b[i];}return a.size()<b.size();};std::sort(xs.begin(),xs.end(),byte_less);for(auto&x:xs)put_blob(o,x);}else for(auto&x:v)canon(x,o,active);}
void canon(const NP&n,std::vector<std::uint8_t>&o,std::set<const Node*>&active){if(!n){o.push_back(0xff);return;}if(!active.insert(n.get()).second){o.push_back(0xfe);return;}o.push_back(static_cast<std::uint8_t>(n->k));switch(n->k){
 case K::Int:case K::Long:put_u64(o,static_cast<std::uint64_t>(n->iv));put_blob(o,n->blob);break;case K::Float:case K::Complex:case K::Bytes:case K::String:put_blob(o,n->blob);break;
 case K::Tuple:case K::List:case K::Slice:canon_seq(n->seq,o,active,false);break;case K::Set:case K::FrozenSet:canon_seq(n->seq,o,active,true);break;
 case K::Dict:put_u64(o,n->dict.size());for(auto&kv:n->dict){canon(kv.first,o,active);canon(kv.second,o,active);}break;
 case K::Code:{auto&c=*n->code;put_u32(o,c.argcount);put_u32(o,c.posonly);put_u32(o,c.kwonly);put_u32(o,c.nlocals);put_u32(o,c.stacksize);put_u32(o,c.flags);canon(c.code,o,active);canon(c.consts,o,active);canon(c.names,o,active);if(c.varnames){canon(c.varnames,o,active);canon(c.freevars,o,active);canon(c.cellvars,o,active);}else{canon(c.localsplusnames,o,active);canon(c.localspluskinds,o,active);}canon(c.name,o,active);if(c.qualname)canon(c.qualname,o,active);if(c.exceptiontable)canon(c.exceptiontable,o,active);break;}
 default:break;}active.erase(n.get());}
int minor_from_version(int v){if(v>=300)return v%100;if(v>=30)return v%10;return v;}
}
PythonMarshalSemantic semantic_hash_python_marshal(std::span<const std::uint8_t>d,int version){
    PythonMarshalSemantic out;
    out.python_minor=minor_from_version(version);
    if(out.python_minor<8||out.python_minor>14){out.error="semantic marshal supports Python 3.8-3.14";return out;}
    Reader r{d,0,out.python_minor,0,{},&out};
    auto root=obj(r);if(!root)return out;
    if(root->k!=K::Code){out.error="marshal root is not a code object";out.error_offset=0;return out;}
    if(r.p!=d.size()){out.error="trailing bytes after root marshal object";out.error_offset=r.p;return out;}
    auto c=canon_one(root);out.sha256=sha256_bytes(c);out.valid=true;return out;
}

PythonMarshalRootCode inspect_python_marshal_root_code(std::span<const std::uint8_t>d,int version){
    PythonMarshalRootCode out;out.python_minor=minor_from_version(version);
    if(out.python_minor<8||out.python_minor>14){out.error="marshal root inspection supports Python 3.8-3.14";return out;}
    PythonMarshalSemantic parse;
    Reader r{d,0,out.python_minor,0,{},&parse};
    auto root=obj(r);
    if(!root){out.error=parse.error;out.error_offset=parse.error_offset;return out;}
    if(root->k!=K::Code||!root->code){out.error="marshal root is not a code object";return out;}
    if(r.p!=d.size()){out.error="trailing bytes after root marshal object";out.error_offset=r.p;return out;}
    const auto&c=*root->code;
    if(!c.code||c.code->k!=K::Bytes){out.error="root code object lacks bytecode bytes";return out;}
    if(!c.consts||c.consts->k!=K::Tuple){out.error="root code object co_consts is not a tuple";return out;}
    if(!c.names||c.names->k!=K::Tuple){out.error="root code object co_names is not a tuple";return out;}
    out.code_offset=c.code->blob_offset;out.code=c.code->blob;
    out.constants.reserve(c.consts->seq.size());
    for(const auto&x:c.consts->seq){
        PythonMarshalScalar v;
        if(x&&x->k==K::Int){v.kind=PythonMarshalScalarKind::Integer;v.integer=x->iv;}
        else if(x&&x->k==K::String){v.kind=PythonMarshalScalarKind::String;v.text.assign(reinterpret_cast<const char*>(x->blob.data()),x->blob.size());}
        out.constants.push_back(std::move(v));
    }
    out.names.reserve(c.names->seq.size());
    for(const auto&x:c.names->seq){
        if(!x||x->k!=K::String){out.error="root code object co_names contains a non-string entry";out.names.clear();out.constants.clear();out.code.clear();return out;}
        out.names.emplace_back(reinterpret_cast<const char*>(x->blob.data()),x->blob.size());
    }
    out.valid=true;return out;
}

namespace {
int marshal_minor(int version){return version>=300?version%100:(version>=30?version%10:version);}
std::string hexoff(std::uint64_t v){std::ostringstream x;x<<std::hex<<v;return x.str();}
}

PythonMarshalOpcodeRewrite remap_python_marshal_opcodes(std::span<const std::uint8_t>d,int version,const std::array<std::int16_t,256>&map){
    PythonMarshalOpcodeRewrite out;out.python_minor=marshal_minor(version);
    auto layout=semantic_hash_python_marshal(d,version);
    if(!layout.valid){out.error="marshal layout parse failed at +0x"+hexoff(layout.error_offset)+": "+layout.error;return out;}
    out.code_object_count=layout.code_object_count;
    out.bytes.assign(d.begin(),d.end());
    std::set<std::uint16_t>unmapped;
    for(const auto&r:layout.code_ranges){
        if(r.size&1u){out.error="co_code payload size is not 2-byte aligned for code object "+r.name;out.bytes.clear();return out;}
        if(r.offset>d.size()||r.size>d.size()-r.offset){out.error="co_code payload range exceeds marshal input";out.bytes.clear();return out;}
        for(std::uint64_t i=0;i<r.size;i+=2){
            ++out.code_units;
            auto off=static_cast<std::size_t>(r.offset+i);auto op=out.bytes[off];auto mapped=map[op];
            if(mapped<0||mapped>255){unmapped.insert(op);continue;}
            if(mapped!=op){out.bytes[off]=static_cast<std::uint8_t>(mapped);++out.rewritten_code_units;}
        }
    }
    if(!unmapped.empty()){
        out.unmapped_opcodes.assign(unmapped.begin(),unmapped.end());std::ostringstream x;x<<"unmapped opcode(s) used in serialized co_code:";for(auto op:out.unmapped_opcodes)x<<' '<<op;out.error=x.str();out.bytes.clear();return out;
    }
    auto verify=semantic_hash_python_marshal(out.bytes,version);
    if(!verify.valid||verify.code_object_count!=layout.code_object_count||verify.code_ranges.size()!=layout.code_ranges.size()){
        out.error="normalized marshal failed structural re-parse";out.bytes.clear();return out;
    }
    out.changed=out.rewritten_code_units!=0;out.valid=true;return out;
}

PythonMarshalOpcodeRewrite normalize_python_marshal_opcodes(std::span<const std::uint8_t>d,int version,const CPythonDispatchInfo&dispatch){
    std::array<std::int16_t,256>map;map.fill(-1);
    if(dispatch.reference_status=="REFERENCE_MATCH"){
        for(int i=0;i<256;i++)map[i]=static_cast<std::int16_t>(i);
        return remap_python_marshal_opcodes(d,version,map);
    }
    if(dispatch.reference_status!="OPCODE_PERMUTATION"){
        PythonMarshalOpcodeRewrite out;out.python_minor=marshal_minor(version);out.error="dispatch is not a pure, validated opcode permutation";return out;
    }
    for(const auto&m:dispatch.mappings){
        if(m.state=="SLOT_MATCH"||m.state=="SEMANTIC_SLOT_MATCH")map[m.target_opcode]=static_cast<std::int16_t>(m.target_opcode);
        else if((m.state=="PERMUTED"||m.state=="SEMANTIC_PERMUTED")&&m.reference_opcodes.size()==1)map[m.target_opcode]=static_cast<std::int16_t>(m.reference_opcodes.front());
    }
    return remap_python_marshal_opcodes(d,version,map);
}
}
