#include "prts/interpreter_boundary.hpp"
#include "prts/path_utf8.hpp"
#include "Zydis.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace prts { namespace {
constexpr std::size_t kTextCap=2u*1024u*1024u;
constexpr std::size_t kNativeCap=32u*1024u*1024u;
constexpr std::uint32_t kMaxFunctions=32;
constexpr std::uint32_t kMaxInstructionsPerFunction=8192;
constexpr std::uint32_t kMaxTotalInstructions=32768;
constexpr std::uint64_t kMaxFunctionBytes=1u<<20;

std::string lower_ascii(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}
std::string hx(std::uint64_t v){std::ostringstream o;o<<"0x"<<std::hex<<v;return o.str();}

struct Decoded{std::uint64_t va=0;ZydisDecodedInstruction ins{};std::array<ZydisDecodedOperand,ZYDIS_MAX_OPERAND_COUNT> ops{};};
ZydisRegister reg64(ZydisRegister r){return r==ZYDIS_REGISTER_NONE?r:ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,r);}
std::optional<std::pair<std::size_t,std::size_t>> va_extent(const ElfInfo&e,std::uint64_t va,std::size_t n){for(const auto&s:e.segments){if(s.type!=1||va<s.address)continue;auto d=va-s.address;if(d>=s.file_size||s.offset>n||d>n-s.offset)continue;auto off=s.offset+d;if(off>=n)return{};auto avail=std::min<std::uint64_t>(s.file_size-d,n-off);return std::pair<std::size_t,std::size_t>{static_cast<std::size_t>(off),static_cast<std::size_t>(avail)};}return{};}
std::optional<std::uint64_t> add_signed(std::uint64_t b,std::int64_t d){if(d>=0){auto u=static_cast<std::uint64_t>(d);if(b>std::numeric_limits<std::uint64_t>::max()-u)return{};return b+u;}auto m=static_cast<std::uint64_t>(-(d+1))+1;if(b<m)return{};return b-m;}
std::optional<std::uint64_t> rip_mem(const Decoded&x,const ZydisDecodedOperand&o){if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.index!=ZYDIS_REGISTER_NONE||reg64(o.mem.base)!=ZYDIS_REGISTER_RIP)return{};return add_signed(x.va+x.ins.length,o.mem.disp.has_displacement?o.mem.disp.value:0);}
std::optional<std::uint64_t> rel_target(const Decoded&x){for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){auto&o=x.ops[i];if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative)return add_signed(x.va+x.ins.length,o.imm.value.s);}return{};}
std::optional<Decoded> decode_one(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va){auto ex=va_extent(e,va,d.size());if(!ex)return{};ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return{};Decoded x;x.va=va;auto n=std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH,ex->second);if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+ex->first,n,&x.ins,x.ops.data()))||!x.ins.length)return{};return x;}
std::vector<Decoded> decode_range(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t begin,std::uint64_t end,std::uint32_t&total,bool&budget){std::vector<Decoded>out;if(end<=begin||end-begin>kMaxFunctionBytes)return out;for(auto va=begin;va<end;){if(out.size()>=kMaxInstructionsPerFunction||total>=kMaxTotalInstructions){budget=true;break;}auto x=decode_one(d,e,va);if(!x){out.clear();return out;}va+=x->ins.length;out.push_back(*x);++total;}return out;}
std::map<std::uint64_t,std::string> got_names(const ElfInfo&e){std::map<std::uint64_t,std::string>out;if(e.dynamic.state!="RESOLVED")return out;for(const auto&r:e.dynamic.relocations){if(r.symbol_index>=e.dynamic.symbols.size())continue;const auto&s=e.dynamic.symbols[r.symbol_index];if(s.imported&&!s.name.empty())out.emplace(r.target_va,s.name);}return out;}
std::optional<std::string> plt_name(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va,const std::map<std::uint64_t,std::string>&got){for(int i=0;i<2;++i){auto x=decode_one(d,e,va);if(!x)return{};if(x->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR&&x->ins.operand_count_visible){auto slot=rip_mem(*x,x->ops[0]);if(!slot)return{};auto it=got.find(*slot);return it==got.end()?std::optional<std::string>{}:std::optional<std::string>{it->second};}if(x->ins.mnemonic!=ZYDIS_MNEMONIC_ENDBR64&&x->ins.mnemonic!=ZYDIS_MNEMONIC_NOP)return{};va+=x->ins.length;}return{};}
std::optional<std::string> call_name(std::span<const std::uint8_t>d,const ElfInfo&e,const Decoded&x,const std::map<std::uint64_t,std::string>&got){if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL||!x.ins.operand_count_visible)return{};auto&o=x.ops[0];if(auto slot=rip_mem(x,o)){auto it=got.find(*slot);if(it!=got.end())return it->second;}if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative){if(auto t=rel_target(x))return plt_name(d,e,*t,got);}return{};}
std::optional<std::uint64_t> pointer_arg_before(const std::vector<Decoded>&ins,std::size_t at,ZydisRegister wanted){auto cur=reg64(wanted);std::size_t seen=0;for(std::size_t z=at;z-->0&&seen++<96;){const auto&x=ins[z];if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)return{};if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||reg64(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER){cur=reg64(x.ops[1].reg.value);continue;}if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){auto&m=x.ops[1].mem;if(m.index==ZYDIS_REGISTER_NONE&&reg64(m.base)==ZYDIS_REGISTER_RIP)return add_signed(x.va+x.ins.length,m.disp.has_displacement?m.disp.value:0);}if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!x.ops[1].imm.is_relative)return x.ops[1].imm.value.u;return{};}return{};}
const ElfUnwindFde* fde_for(const ElfInfo&e,std::uint64_t va){for(const auto&f:e.unwind.fdes)if(f.function_file_backed&&f.function_start_va<=va&&va<f.function_end_va&&f.function_size&&f.function_size<=kMaxFunctionBytes)return &f;return nullptr;}
std::optional<std::uint64_t> recover_main(std::span<const std::uint8_t>d,const ElfInfo&e,const std::map<std::uint64_t,std::string>&got){std::vector<Decoded>entry;auto cur=e.entry;for(int i=0;i<48;++i){auto x=decode_one(d,e,cur);if(!x)break;entry.push_back(*x);cur+=x->ins.length;if(x->ins.meta.category==ZYDIS_CATEGORY_RET)break;}for(std::size_t i=0;i<entry.size();++i){auto n=call_name(d,e,entry[i],got);if(!n||*n!="__libc_start_main")continue;return pointer_arg_before(entry,i,ZYDIS_REGISTER_RDI);}return{};}

bool known_janet_runtime(const ElfInfo&e,std::vector<std::string>&ev){
    static const std::array<const char*,10> names={"janet_init","janet_deinit","janet_vm_load","janet_interpreter_interrupt","janet_compile","janet_unmarshal_janet","janet_marshal_janet","janet_asm_decode_instruction","janet_call","janet_core_env"};
    std::array<bool,names.size()> have{};
    for(const auto&s:e.dynamic.symbols){
        if(s.name.empty())continue;
        for(std::size_t i=0;i<names.size();++i)if(!have[i]&&s.name==names[i])have[i]=true;
    }
    std::size_t hits=0;
    for(std::size_t i=0;i<names.size();++i)if(have[i]){++hits;if(ev.size()<8)ev.push_back(std::string("ELF symbol surface contains ")+names[i]);}
    const bool vm=have[2]||have[3];
    const bool code=have[4]||have[7];
    const bool image=have[5]||have[6];
    const bool lifecycle=have[0]&&have[1];
    return hits>=5&&vm&&code&&image&&lifecycle;
}

std::string mask_python(std::string_view s){
    std::string out(s);enum class St{Code,SQ,DQ,TQ1,TQ2,Comment};St st=St::Code;bool esc=false;
    for(std::size_t i=0;i<s.size();++i){char c=s[i];
        if(st==St::Comment){if(c=='\n'){st=St::Code;out[i]='\n';}else out[i]=' ';continue;}
        if(st==St::SQ||st==St::DQ){out[i]=(c=='\n')?'\n':' ';if(esc){esc=false;continue;}if(c=='\\'){esc=true;continue;}if((st==St::SQ&&c=='\'')||(st==St::DQ&&c=='\"'))st=St::Code;continue;}
        if(st==St::TQ1||st==St::TQ2){char q=st==St::TQ1?'\'':'\"';out[i]=(c=='\n')?'\n':' ';if(c==q&&i+2<s.size()&&s[i+1]==q&&s[i+2]==q){out[i+1]=out[i+2]=' ';i+=2;st=St::Code;}continue;}
        if(c=='#'){out[i]=' ';st=St::Comment;continue;}
        if(c=='\''||c=='\"'){out[i]=' ';if(i+2<s.size()&&s[i+1]==c&&s[i+2]==c){out[i+1]=out[i+2]=' ';i+=2;st=c=='\''?St::TQ1:St::TQ2;}else st=c=='\''?St::SQ:St::DQ;}
    }return out;
}
std::string compact_ws(std::string_view s){
    std::string out;out.reserve(s.size());
    for(char c:s){if(c=='\n')out.push_back('\n');else if(c!=' '&&c!='\t'&&c!='\r'&&c!='\f'&&c!='\v')out.push_back(c);}
    return out;
}
bool has_any(std::string_view s,std::initializer_list<std::string_view> needles){for(auto n:needles)if(s.find(n)!=std::string_view::npos)return true;return false;}
bool line_has_vm_loop(std::string_view s){
    std::size_t pos=0;while(pos<s.size()){auto e=s.find('\n',pos);if(e==std::string_view::npos)e=s.size();auto line=s.substr(pos,e-pos);if(line.find("while")!=std::string_view::npos&&line.find(':')!=std::string_view::npos&&has_any(line,{"self.pc","program_counter","self.program_counter"}))return true;pos=e+1;}return false;
}
bool line_has_state_mutation(std::string_view s){
    std::size_t pos=0;while(pos<s.size()){auto e=s.find('\n',pos);if(e==std::string_view::npos)e=s.size();auto line=s.substr(pos,e-pos);if(has_any(line,{"self.registers[","registers[","self.stack[","stack[","self.memory[","memory["})&&has_any(line,{"]=","]+=","]-=","]^=","]|=","]&="}))return true;pos=e+1;}return false;
}
std::size_t dispatch_entry_count(std::string_view s){
    const std::array<std::string_view,6> marks={"self.instructions={","instructions={","self.opcodes={","opcodes={","self.dispatch={","dispatch={"};
    std::size_t best=0;
    for(auto mark:marks){auto p=s.find(mark);if(p==std::string_view::npos)continue;p+=mark.size()-1;int depth=0;std::size_t count=0;for(;p<s.size();++p){char c=s[p];if(c=='{')++depth;else if(c=='}'){if(--depth==0)break;}else if(c==':'&&depth==1)++count;}best=std::max(best,count);}
    return best;
}
std::optional<InterpreterBoundaryInfo> analyze_python_source(std::span<const std::uint8_t>d,const std::filesystem::path&input){
    if(d.empty()||d.size()>kTextCap)return{};
    auto ext=lower_ascii(path_utf8(input.extension()));
    if(ext!=".py")return{};
    std::size_t printable=0;for(auto c:d)if(c==9||c==10||c==13||(c>=32&&c<127))++printable;if(printable*100<d.size()*90)return{};
    std::string raw(reinterpret_cast<const char*>(d.data()),d.size());auto code=mask_python(raw);auto compact=compact_ws(code);InterpreterBoundaryInfo x;x.analyzed=true;x.boundary_kind="SOURCE_CUSTOM_INTERPRETER";x.host_role="INTERPRETER_DEFINITION_SOURCE";x.target_role="BYTECODE_PROGRAM";x.semantic_requirement="SEMANTIC_MAP_REQUIRED";
    const bool pc_state=has_any(compact,{"self.pc=","pc=","self.program_counter=","program_counter="});
    const bool dispatch_table=dispatch_entry_count(compact)>=4;
    const bool loop=line_has_vm_loop(compact);
    const bool fetch=has_any(compact,{"program[self.pc]","program[pc]","program[self.program_counter]","program[program_counter]"});
    const bool opcode=has_any(compact,{"opcode=","self.opcode="});
    const bool indirect=has_any(compact,{"self.instructions[opcode](","instructions[opcode](","self.opcodes[opcode](","opcodes[opcode](","self.dispatch[opcode](","dispatch[opcode]("});
    const bool state=has_any(compact,{"self.registers[","registers[","self.stack[","stack[","self.memory[","memory[","self.registers=","registers=","self.stack=","stack=","self.memory=","memory="});
    const bool mutation=line_has_state_mutation(compact);
    const std::array<std::pair<bool,const char*>,8> facts={{{pc_state,"program-counter state"},{dispatch_table,"multi-opcode dispatch table"},{loop,"program-counter-controlled execution loop"},{fetch,"instruction fetch from program[pc]"},{opcode,"explicit opcode decode variable"},{indirect,"opcode-indexed handler invocation"},{state,"register/stack/memory VM state"},{mutation,"VM state mutation"}}};
    for(const auto&f:facts)if(f.first){++x.evidence_count;x.evidence.push_back(f.second);}
    if(pc_state&&dispatch_table&&loop&&fetch&&opcode&&indirect&&state&&mutation&&x.evidence_count>=7){x.state="CONFIRMED";x.program_buffer_chain_confirmed=true;x.exact_program_target_state="SOURCE_PROGRAM_VALUE_OR_EXTERNAL_INPUT_UNRESOLVED";return x;}
    return{};
}

enum class Kind{Unknown,Argv,ArgvPath,Arg0Path,Arg1Ptr,StackAddr,File,Heap};
struct Value{Kind kind=Kind::Unknown;std::int64_t off=0;int id=0;};
bool same(const Value&a,const Value&b){return a.kind==b.kind&&a.off==b.off&&a.id==b.id;}
bool is_path(const Value&v){return v.kind==Kind::ArgvPath||v.kind==Kind::Arg0Path;}
bool mem_stack(const ZydisDecodedOperand&o,std::int64_t&disp){if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.index!=ZYDIS_REGISTER_NONE||reg64(o.mem.base)!=ZYDIS_REGISTER_RBP)return false;disp=o.mem.disp.has_displacement?o.mem.disp.value:0;return true;}
Value regv(const std::map<ZydisRegister,Value>&r,ZydisRegister x){auto it=r.find(reg64(x));return it==r.end()?Value{}:it->second;}
void setreg(std::map<ZydisRegister,Value>&r,ZydisRegister x,Value v){r[reg64(x)]=v;}
Value mem_read(const ZydisDecodedOperand&o,const std::map<ZydisRegister,Value>&regs,const std::map<std::int64_t,Value>&slots){std::int64_t sd=0;if(mem_stack(o,sd)){auto it=slots.find(sd);return it==slots.end()?Value{}:it->second;}if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY)return{};auto base=regv(regs,o.mem.base);auto disp=o.mem.disp.has_displacement?o.mem.disp.value:0;if(base.kind==Kind::Argv&&o.mem.index==ZYDIS_REGISTER_NONE&&base.off+disp==8)return {Kind::ArgvPath,0,0};return{};}
void assign_basic(const Decoded&x,std::map<ZydisRegister,Value>&regs,std::map<std::int64_t,Value>&slots){
    if(x.ins.operand_count_visible<2)return;
    auto&dst=x.ops[0];auto&src=x.ops[1];
    if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV||x.ins.mnemonic==ZYDIS_MNEMONIC_MOVZX||x.ins.mnemonic==ZYDIS_MNEMONIC_MOVSX||x.ins.mnemonic==ZYDIS_MNEMONIC_MOVSXD){Value v;if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)v=regv(regs,src.reg.value);else if(src.type==ZYDIS_OPERAND_TYPE_MEMORY)v=mem_read(src,regs,slots);if(dst.type==ZYDIS_OPERAND_TYPE_REGISTER)setreg(regs,dst.reg.value,v);else{std::int64_t sd=0;if(mem_stack(dst,sd))slots[sd]=v;}return;}
    if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&dst.type==ZYDIS_OPERAND_TYPE_REGISTER&&src.type==ZYDIS_OPERAND_TYPE_MEMORY){auto disp=src.mem.disp.has_displacement?src.mem.disp.value:0;if(src.mem.index==ZYDIS_REGISTER_NONE&&reg64(src.mem.base)==ZYDIS_REGISTER_RBP){const int owner=disp>=std::numeric_limits<int>::min()&&disp<=std::numeric_limits<int>::max()?static_cast<int>(disp):0;setreg(regs,dst.reg.value,{Kind::StackAddr,disp,owner});return;}if(src.mem.index==ZYDIS_REGISTER_NONE){auto b=regv(regs,src.mem.base);if(b.kind!=Kind::Unknown){b.off+=disp;setreg(regs,dst.reg.value,b);return;}}setreg(regs,dst.reg.value,{});return;}
    if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&dst.type==ZYDIS_OPERAND_TYPE_REGISTER&&src.type==ZYDIS_OPERAND_TYPE_IMMEDIATE){auto v=regv(regs,dst.reg.value);if(v.kind!=Kind::Unknown){auto delta=static_cast<std::int64_t>(src.imm.value.s);if(x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)delta=-delta;v.off+=delta;setreg(regs,dst.reg.value,v);}return;}
}

struct LoaderShape{bool path_open=false,read=false,returns_read_buffer=false;std::uint64_t va=0;};
LoaderShape analyze_loader(std::span<const std::uint8_t>d,const ElfInfo&e,const std::map<std::uint64_t,std::string>&got,const ElfUnwindFde&fde,std::uint32_t&total,bool&budget){LoaderShape out;out.va=fde.function_start_va;auto ins=decode_range(d,e,fde.function_start_va,fde.function_end_va,total,budget);std::map<ZydisRegister,Value>regs;std::map<std::int64_t,Value>slots;setreg(regs,ZYDIS_REGISTER_RDI,{Kind::Arg0Path});setreg(regs,ZYDIS_REGISTER_RSI,{Kind::Arg1Ptr});int next_heap=1;std::set<int>read_heap;
    for(const auto&x:ins){assign_basic(x,regs,slots);if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL)continue;auto name=call_name(d,e,x,got);if(!name){setreg(regs,ZYDIS_REGISTER_RAX,{});continue;}if(*name=="fopen"||*name=="fopen64"){if(is_path(regv(regs,ZYDIS_REGISTER_RDI)))out.path_open=true;setreg(regs,ZYDIS_REGISTER_RAX,{Kind::File});}
        else if(*name=="malloc"||*name=="calloc"){setreg(regs,ZYDIS_REGISTER_RAX,{Kind::Heap,0,next_heap++});}
        else if(*name=="fread"){auto dst=regv(regs,ZYDIS_REGISTER_RDI),file=regv(regs,ZYDIS_REGISTER_RCX);if(out.path_open&&file.kind==Kind::File&&dst.kind==Kind::Heap){out.read=true;read_heap.insert(dst.id);}setreg(regs,ZYDIS_REGISTER_RAX,{});}
        else setreg(regs,ZYDIS_REGISTER_RAX,{});
    }
    // A successful bounded helper must place the same fread-backed heap pointer in RAX on at least one return path.
    // O0 code normally reloads it immediately before LEAVE/RET, so inspect the final 24 instructions without crossing a call.
    for(std::size_t i=ins.size();i-->0&&ins.size()-i<24;){const auto&x=ins[i];if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)break;if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&reg64(x.ops[0].reg.value)==ZYDIS_REGISTER_RAX){Value v;if(x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER)v=regv(regs,x.ops[1].reg.value);else if(x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){std::int64_t sd=0;if(mem_stack(x.ops[1],sd)){auto it=slots.find(sd);if(it!=slots.end())v=it->second;}}if(v.kind==Kind::Heap&&read_heap.count(v.id)){out.returns_read_buffer=true;break;}}}
    // The final-state scan above can lose path-sensitive RAX; the common conservative invariant is stronger:
    // a unique heap object is allocated, used as fread destination, and remains in a local stack slot returned near RET.
    if(out.path_open&&out.read&&!read_heap.empty())for(std::size_t i=0;i<ins.size();++i){const auto&x=ins[i];if(x.ins.mnemonic!=ZYDIS_MNEMONIC_MOV||x.ins.operand_count_visible<2||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||reg64(x.ops[0].reg.value)!=ZYDIS_REGISTER_RAX||x.ops[1].type!=ZYDIS_OPERAND_TYPE_MEMORY)continue;std::int64_t sd=0;if(!mem_stack(x.ops[1],sd))continue;auto it=slots.find(sd);if(it!=slots.end()&&it->second.kind==Kind::Heap&&read_heap.count(it->second.id)&&i+4>=ins.size())out.returns_read_buffer=true;}
    return out;}

struct VmShape{bool confirmed=false;std::uint64_t va=0;std::uint32_t back_edges=0,indirect_dispatch=0,bounded_cmps=0,mem_reads=0,mem_writes=0,direct_calls=0;};
VmShape analyze_vm(std::span<const std::uint8_t>d,const ElfInfo&e,const ElfUnwindFde&fde,std::uint32_t&total,bool&budget){VmShape v;v.va=fde.function_start_va;auto ins=decode_range(d,e,fde.function_start_va,fde.function_end_va,total,budget);if(ins.empty())return v;for(const auto&x:ins){
        if((x.ins.meta.category==ZYDIS_CATEGORY_COND_BR||x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR)&&x.ins.operand_count_visible){if(auto t=rel_target(x);t&&*t<x.va&&*t>=fde.function_start_va)++v.back_edges;}
        if((x.ins.meta.category==ZYDIS_CATEGORY_CALL||x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR)&&x.ins.operand_count_visible){auto&o=x.ops[0];if(o.type==ZYDIS_OPERAND_TYPE_REGISTER||(o.type==ZYDIS_OPERAND_TYPE_MEMORY&&reg64(o.mem.base)!=ZYDIS_REGISTER_RIP))++v.indirect_dispatch;else if(x.ins.meta.category==ZYDIS_CATEGORY_CALL&&o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative)++v.direct_calls;}
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_CMP)for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i)if(x.ops[i].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&x.ops[i].imm.value.u>=2&&x.ops[i].imm.value.u<=0x100)++v.bounded_cmps;
        for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i)if(x.ops[i].type==ZYDIS_OPERAND_TYPE_MEMORY){if(x.ops[i].actions&ZYDIS_OPERAND_ACTION_READ)++v.mem_reads;if(x.ops[i].actions&ZYDIS_OPERAND_ACTION_WRITE)++v.mem_writes;}
    }
    const bool dispatch=v.indirect_dispatch>0&&v.bounded_cmps>0&&v.back_edges>0;
    const bool stateful=(v.mem_reads>=4&&v.mem_writes>=2)||(v.direct_calls>=1&&v.mem_reads>=2);
    v.confirmed=dispatch&&stateful;return v;}

std::optional<InterpreterBoundaryInfo> analyze_native(std::span<const std::uint8_t>d,const ElfInfo&e){
    if(!e.valid||!e.elf64||!e.little_endian||e.machine!=62||e.dynamic.state!="RESOLVED"||d.empty()||d.size()>kNativeCap)return{};
    auto got=got_names(e);if(got.empty())return{};bool has_fopen=false,has_fread=false;for(const auto&kv:got){has_fopen|=kv.second=="fopen"||kv.second=="fopen64";has_fread|=kv.second=="fread";}if(!has_fopen||!has_fread)return{};
    auto mainva=recover_main(d,e,got);if(!mainva)return{};auto mf=fde_for(e,*mainva);if(!mf)return{};
    InterpreterBoundaryInfo info;info.analyzed=true;info.main_va=*mainva;info.boundary_kind="NATIVE_CUSTOM_INTERPRETER";info.host_role="INTERPRETER_HOST";info.target_role="BYTECODE_PROGRAM";info.semantic_requirement="SEMANTIC_MAP_REQUIRED";std::uint32_t total=0;bool budget=false;auto main=decode_range(d,e,mf->function_start_va,mf->function_end_va,total,budget);if(main.empty())return{};
    std::map<std::uint64_t,LoaderShape> loaders;std::uint32_t functions=1;
    for(const auto&x:main){if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL||x.ins.operand_count_visible==0||x.ops[0].type!=ZYDIS_OPERAND_TYPE_IMMEDIATE||!x.ops[0].imm.is_relative)continue;auto t=rel_target(x);if(!t||got.count(*t)||loaders.count(*t))continue;auto f=fde_for(e,*t);if(!f||functions>=kMaxFunctions)continue;++functions;auto ls=analyze_loader(d,e,got,*f,total,budget);if(ls.path_open&&ls.read&&ls.returns_read_buffer)loaders[*t]=ls;}
    std::map<ZydisRegister,Value>regs;std::map<std::int64_t,Value>slots;setreg(regs,ZYDIS_REGISTER_RSI,{Kind::Argv});int next_file=1,next_program=1000;bool argv_open=false,loaded=false;Value read_dest,program_value;std::uint64_t loader_va=0,load_point=0;
    for(std::size_t i=0;i<main.size();++i){const auto&x=main[i];assign_basic(x,regs,slots);if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL)continue;auto name=call_name(d,e,x,got);if(name){if(*name=="fopen"||*name=="fopen64"){if(regv(regs,ZYDIS_REGISTER_RDI).kind==Kind::ArgvPath)argv_open=true;setreg(regs,ZYDIS_REGISTER_RAX,{Kind::File,0,next_file++});}
            else if(*name=="fread"){auto file=regv(regs,ZYDIS_REGISTER_RCX),dst=regv(regs,ZYDIS_REGISTER_RDI);if(argv_open&&file.kind==Kind::File&&dst.kind!=Kind::Unknown){loaded=true;read_dest=dst;program_value=dst;load_point=x.va;}setreg(regs,ZYDIS_REGISTER_RAX,{});}
            else setreg(regs,ZYDIS_REGISTER_RAX,{});
            continue;}
        auto t=rel_target(x);if(!t){setreg(regs,ZYDIS_REGISTER_RAX,{});continue;}auto li=loaders.find(*t);if(li!=loaders.end()&&regv(regs,ZYDIS_REGISTER_RDI).kind==Kind::ArgvPath){loaded=true;argv_open=true;loader_va=*t;load_point=x.va;program_value={Kind::Heap,0,next_program++};setreg(regs,ZYDIS_REGISTER_RAX,program_value);continue;}
        if(loaded&&x.va>load_point){auto f=fde_for(e,*t);if(f&&functions<kMaxFunctions){++functions;auto vm=analyze_vm(d,e,*f,total,budget);auto arg0=regv(regs,ZYDIS_REGISTER_RDI);bool chain=false;if(vm.confirmed){if(program_value.kind==Kind::Heap&&same(arg0,program_value))chain=true;else if(read_dest.kind==Kind::StackAddr&&arg0.kind==Kind::StackAddr){auto delta=read_dest.off-arg0.off;chain=read_dest.id==arg0.id&&delta>=0&&delta<=65536;}}
                if(chain){info.state="CONFIRMED";info.external_program_argument_required=true;info.program_buffer_chain_confirmed=true;info.exact_program_target_state="UNRESOLVED_RUNTIME_ARGV_VALUE";info.loader_va=loader_va;info.dispatch_va=vm.va;info.functions_examined=functions;info.decoded_instructions=total;info.budget_exhausted=budget;info.evidence={"entry closes to __libc_start_main(main) and the main FDE","argv[1]-derived path reaches an imported file-open path","the opened file is read into a bounded program buffer/state region","the read-backed buffer/state reaches a main-reachable opcode dispatch loop","dispatch has a bounded opcode comparison, indirect control transfer, state/memory access, and a loop back-edge"};info.evidence_count=static_cast<std::uint32_t>(info.evidence.size());info.negative_evidence.push_back("runtime argv[1] value is unknown statically; no sibling filename is promoted to an exact program target");return info;}}
        }
        setreg(regs,ZYDIS_REGISTER_RAX,{});
    }
    return{};
}
}

InterpreterBoundaryInfo analyze_interpreter_boundary(std::span<const std::uint8_t>d,const ElfInfo&e,const std::filesystem::path&input){
    if(auto src=analyze_python_source(d,input))return *src;
    if(e.valid){std::vector<std::string>ev;if(d.size()<=kNativeCap&&known_janet_runtime(e,ev)){InterpreterBoundaryInfo x;x.analyzed=true;x.state="CONFIRMED";x.boundary_kind="KNOWN_RUNTIME_INTERPRETER";x.host_role="INTERPRETER_HOST";x.target_role="RUNTIME_IMAGE";x.semantic_requirement="REQUIRES_INTERPRETER_DEFINITION";x.runtime_family="Janet";x.exact_program_target_state="UNRESOLVED_RUNTIME_IMAGE_SELECTION";x.evidence=std::move(ev);x.evidence_count=static_cast<std::uint32_t>(x.evidence.size());x.negative_evidence.push_back("runtime-family identity does not prove which sibling, if any, is the program image");return x;}
        if(auto n=analyze_native(d,e))return *n;}
    return {};
}

Finding interpreter_boundary_finding(const InterpreterBoundaryInfo&i){Finding f;f.kind="interpreter_boundary";f.family="Interpreter / bytecode boundary";f.state=i.state;f.variant=i.boundary_kind;f.evidence=i.evidence;f.negative_evidence=i.negative_evidence;f.fields["host_role"]=i.host_role;f.fields["target_role"]=i.target_role;f.fields["semantic_requirement"]=i.semantic_requirement;f.fields["runtime_family"]=i.runtime_family;f.fields["program_argument_required"]=i.external_program_argument_required?"true":"false";f.fields["program_requirement"]=i.external_program_argument_required?"PROGRAM_ARGUMENT_REQUIRED":"UNRESOLVED_OR_NON_ARGUMENT_PROGRAM_SOURCE";f.fields["program_buffer_chain_confirmed"]=i.program_buffer_chain_confirmed?"true":"false";f.fields["exact_program_target_bound"]=i.exact_program_target_bound?"true":"false";f.fields["exact_program_target_state"]=i.exact_program_target_state;f.fields["evidence_count"]=std::to_string(i.evidence_count);f.fields["functions_examined"]=std::to_string(i.functions_examined);f.fields["decoded_instructions"]=std::to_string(i.decoded_instructions);f.fields["hard_function_budget"]=std::to_string(kMaxFunctions);f.fields["hard_instruction_budget"]=std::to_string(kMaxTotalInstructions);f.fields["budget_exhausted"]=i.budget_exhausted?"true":"false";if(i.main_va)f.fields["main_va"]=hx(i.main_va);if(i.loader_va)f.fields["loader_va"]=hx(i.loader_va);if(i.dispatch_va)f.fields["dispatch_va"]=hx(i.dispatch_va);if(i.state=="CONFIRMED"){f.suggested_actions.push_back("stop treating the host declared entry as the final preprocessing target; recover/define interpreter opcode/state semantics and analyze the program payload");f.suggested_actions.push_back("do not infer opcode meanings or bind a runtime argv value from filename/suffix proximity alone");}return f;}

}
