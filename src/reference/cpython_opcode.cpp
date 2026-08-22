#include "prts/cpython_opcode.hpp"
#include "prts/x86_semantic.hpp"
extern "C" {
#include "Zydis.h"
}
#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
namespace prts { namespace {
struct CPythonOpcodeReferenceEntry { std::uint16_t opcode; const char* name; std::uint32_t handler_rva; std::uint64_t signature; std::uint32_t block_count; };
struct CPythonOpcodeReference { std::uint32_t version_hex; std::uint16_t machine; const char* version; std::uint16_t first_opcode; std::uint16_t entry_count; const CPythonOpcodeReferenceEntry* entries; };
#include "cpython_opcode_refs.inc"
std::optional<std::size_t> rvaoff(const PeInfo&pe,std::uint32_t rva,std::size_t n){
    if(rva<pe.headers_size&&rva<n)return std::size_t(rva);
    for(const auto&s:pe.sections){auto span=std::max(s.vsize,s.raw_size);if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span){auto delta=std::uint64_t(rva)-s.rva;if(delta>=s.raw_size)return{};auto o=std::uint64_t(s.raw_offset)+delta;if(o<n)return std::size_t(o);}}
    return{};
}
const PeExport* export_named(const PeInfo&pe,const char*name){auto it=std::find_if(pe.exports.begin(),pe.exports.end(),[&](const PeExport&e){return e.name==name;});return it==pe.exports.end()?nullptr:&*it;}
bool exec_rva(const PeInfo&pe,std::uint32_t rva){for(const auto&s:pe.sections){auto span=std::max(s.vsize,s.raw_size);if((s.characteristics&0x20000000)&&rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span)return true;}return false;}
std::uint32_t u32(std::span<const std::uint8_t>d,std::size_t o){return std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);}
ZydisRegister large_reg(ZydisRegister r,ZydisMachineMode mode){return r==ZYDIS_REGISTER_NONE?r:ZydisRegisterGetLargestEnclosing(mode,r);}
std::uint64_t sigmix(std::uint64_t h,std::uint64_t v){h^=v+0x9e3779b97f4a7c15ull+(h<<6)+(h>>2);h*=0x100000001b3ull;return h;}
std::uint64_t strict_small_immediate_digest(std::span<const std::uint8_t>d,const PeInfo&pe,const SemanticCfg&cfg){
    ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return 0;std::uint64_t h=1469598103934665603ull;
    for(const auto&b:cfg.blocks){std::uint32_t cur=b.rva;for(std::uint32_t k=0;k<b.instruction_count;k++){auto off=rvaoff(pe,cur,d.size());if(!off)break;ZydisDecodedInstruction zi{};ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*off,d.size()-*off,&zi,ops))||!zi.length)break;h=sigmix(h,zi.mnemonic);for(std::uint8_t oi=0;oi<zi.operand_count_visible;oi++){auto&o=ops[oi];if(o.type!=ZYDIS_OPERAND_TYPE_IMMEDIATE||o.imm.is_relative)continue;if(o.imm.is_signed){auto v=o.imm.value.s;if(v>=-65536&&v<=65535){h=sigmix(h,0x100);h=sigmix(h,static_cast<std::uint64_t>(v));}else h=sigmix(h,0x101);}else{auto v=o.imm.value.u;if(v<=65535){h=sigmix(h,0x102);h=sigmix(h,v);}else h=sigmix(h,0x103);}}cur+=zi.length;}}
    return h;
}
struct Candidate {std::uint32_t load_rva=0,table_rva=0,exec_count=0,unique=0;std::uint16_t first_opcode=0,entry_count=0;std::vector<std::uint32_t>handlers;};
std::optional<Candidate> validate_table(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t load,std::uint64_t table_va,std::uint16_t first_opcode,std::uint16_t entry_count){
    if(entry_count<96||entry_count>256||std::uint32_t(first_opcode)+entry_count>256)return{};
    if(table_va<pe.image_base||table_va-pe.image_base>0xffffffffull)return{};
    auto tr=static_cast<std::uint32_t>(table_va-pe.image_base);auto off=rvaoff(pe,tr,d.size());if(!off||*off+std::size_t(entry_count)*4>d.size())return{};
    Candidate c;c.load_rva=load;c.table_rva=tr;c.first_opcode=first_opcode;c.entry_count=entry_count;c.handlers.resize(entry_count);std::set<std::uint32_t>uniq;
    for(unsigned i=0;i<entry_count;i++){auto v=u32(d,*off+i*4);c.handlers[i]=v;if(exec_rva(pe,v)){++c.exec_count;uniq.insert(v);}}
    c.unique=static_cast<std::uint32_t>(uniq.size());
    // CPython switch tables are overwhelmingly executable targets; reject incidental integer arrays.
    if(c.exec_count+4<entry_count||c.unique<60)return{};
    return c;
}
}
CPythonDispatchInfo recover_cpython_dispatch(std::span<const std::uint8_t>d,const PeInfo&pe,bool fingerprint_handlers){
    CPythonDispatchInfo out;out.attempted=true;
    if(!pe.valid||!pe.pe64||pe.machine!=0x8664){out.state="UNSUPPORTED";out.error="CPython dispatch recovery currently supports PE64/AMD64";return out;}
    auto ex=export_named(pe,"_PyEval_EvalFrameDefault");if(!ex){out.state="TABLE_NOT_FOUND";out.error="_PyEval_EvalFrameDefault export not found";return out;}out.evaluator_rva=ex->rva;
    auto mode=ZYDIS_MACHINE_MODE_LONG_64;ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,mode,ZYDIS_STACK_WIDTH_64))){out.state="TABLE_NOT_FOUND";out.error="Zydis init failed";return out;}
    std::map<ZydisRegister,std::uint64_t> constants;std::map<ZydisRegister,int> index_first;std::map<ZydisRegister,std::uint32_t> index_count;std::optional<Candidate>best;
    // The first dispatch appears near evaluator entry, but MSVC may materialize image-base on a later-addressed back-edge (3.10).
    std::uint32_t limit=ex->rva+0x2000;std::set<ZydisRegister> image_base_regs;
    for(std::uint32_t pc=ex->rva;pc<limit;){auto off=rvaoff(pe,pc,d.size());if(!off)break;ZydisDecodedInstruction zi{};ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*off,d.size()-*off,&zi,ops))||!zi.length){++pc;continue;}if(zi.mnemonic==ZYDIS_MNEMONIC_LEA&&zi.operand_count_visible>=2&&ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&ops[1].mem.base==ZYDIS_REGISTER_RIP&&ops[1].mem.index==ZYDIS_REGISTER_NONE){auto target=pe.image_base+pc+zi.length+ops[1].mem.disp.value;if(target==pe.image_base)image_base_regs.insert(large_reg(ops[0].reg.value,mode));}pc+=zi.length;}
    std::uint32_t cur=ex->rva;
    while(cur<limit){auto off=rvaoff(pe,cur,d.size());if(!off||*off>=d.size())break;ZydisDecodedInstruction zi{};ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*off,d.size()-*off,&zi,ops))||!zi.length){++cur;continue;}
        // Resolve RIP-relative LEA constants (MSVC commonly materializes image base this way), and legacy index bias such as opcode-1.
        bool handled_write=false;
        if(zi.mnemonic==ZYDIS_MNEMONIC_LEA&&zi.operand_count_visible>=2&&ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&ops[1].mem.index==ZYDIS_REGISTER_NONE){
            auto dst=large_reg(ops[0].reg.value,mode);handled_write=true;
            if(ops[1].mem.base==ZYDIS_REGISTER_RIP){auto target=pe.image_base+cur+zi.length+ops[1].mem.disp.value;constants[dst]=target;index_first.erase(dst);index_count.erase(dst);}
            else{constants.erase(dst);auto base=large_reg(ops[1].mem.base,mode);auto disp=ops[1].mem.disp.has_displacement?ops[1].mem.disp.value:0;if(disp<=0&&disp>=-255)index_first[dst]=static_cast<int>(-disp);else index_first.erase(dst);auto ci=index_count.find(base);if(ci!=index_count.end())index_count[dst]=ci->second;else index_count.erase(dst);}
        }else if(zi.mnemonic==ZYDIS_MNEMONIC_MOV&&zi.operand_count_visible>=2&&ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER){
            auto dst=large_reg(ops[0].reg.value,mode),src=large_reg(ops[1].reg.value,mode);handled_write=true;auto it=constants.find(src);if(it!=constants.end())constants[dst]=it->second;else constants.erase(dst);auto bi=index_first.find(src);if(bi!=index_first.end())index_first[dst]=bi->second;else index_first.erase(dst);auto ci=index_count.find(src);if(ci!=index_count.end())index_count[dst]=ci->second;else index_count.erase(dst);
        }
        // A compare of the normalized table index against max establishes compact legacy table length.
        if(zi.mnemonic==ZYDIS_MNEMONIC_CMP&&zi.operand_count_visible>=2){ZydisRegister reg=ZYDIS_REGISTER_NONE;std::uint64_t imm=0;bool have=false;if(ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!ops[1].imm.is_relative){reg=large_reg(ops[0].reg.value,mode);imm=ops[1].imm.value.u;have=true;}else if(ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&ops[0].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!ops[0].imm.is_relative){reg=large_reg(ops[1].reg.value,mode);imm=ops[0].imm.value.u;have=true;}if(have&&imm>=95&&imm<256)index_count[reg]=static_cast<std::uint32_t>(imm+1);}
        // Candidate switch load: 32-bit table indexed by opcode (3.11+) or opcode-bias (3.8-3.10).
        if((zi.mnemonic==ZYDIS_MNEMONIC_MOV||zi.mnemonic==ZYDIS_MNEMONIC_MOVSXD)&&zi.operand_count_visible>=2&&ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&ops[1].mem.index!=ZYDIS_REGISTER_NONE&&ops[1].mem.scale==4&&ops[1].mem.disp.has_displacement){
            auto base=large_reg(ops[1].mem.base,mode),idx=large_reg(ops[1].mem.index,mode);auto it=constants.find(base);if(it!=constants.end()||image_base_regs.count(base)){auto table_base=it!=constants.end()?it->second:pe.image_base;auto table_va=std::uint64_t(std::int64_t(table_base)+ops[1].mem.disp.value);std::uint16_t first=0,count=256;auto fi=index_first.find(idx);auto ci=index_count.find(idx);if(fi!=index_first.end()&&ci!=index_count.end()&&fi->second>=0&&fi->second<256&&ci->second<=256u-static_cast<unsigned>(fi->second)){first=static_cast<std::uint16_t>(fi->second);count=static_cast<std::uint16_t>(ci->second);}if(auto c=validate_table(d,pe,cur,table_va,first,count)){if(!best||c->entry_count>best->entry_count||(c->entry_count==best->entry_count&&c->unique>best->unique))best=std::move(*c);}}
        }
        // Conservative invalidation for explicitly-written first register operands not handled above.
        if(zi.operand_count_visible&&ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&(ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)&&!handled_write){auto dst=large_reg(ops[0].reg.value,mode);constants.erase(dst);/* Keep index metadata across CDQE/CLTQ which has no explicit destination; explicit writes invalidate it. */index_first.erase(dst);index_count.erase(dst);}
        cur+=zi.length;
    }
    if(!best){out.state="TABLE_NOT_FOUND";out.error="no validated CPython opcode jump table found near evaluator entry";return out;}
    out.table_found=true;out.state="TABLE_RECOVERED";out.table_load_rva=best->load_rva;out.table_rva=best->table_rva;out.table_first_opcode=best->first_opcode;out.table_entry_count=best->entry_count;out.executable_entries=best->exec_count;out.unique_handler_count=best->unique;out.entries.reserve(best->entry_count);
    std::map<std::uint32_t,std::pair<std::uint64_t,std::uint32_t>> sig_cache;
    for(unsigned i=0;i<best->entry_count;i++){
        CPythonDispatchEntry e;e.opcode=static_cast<std::uint16_t>(best->first_opcode+i);e.handler_rva=best->handlers[i];
        if(fingerprint_handlers&&exec_rva(pe,e.handler_rva)){
            auto ci=sig_cache.find(e.handler_rva);
            if(ci!=sig_cache.end()){e.entry_block_hash=ci->second.first;e.entry_instruction_count=ci->second.second;}
            else{auto cfg=build_x86_cfg(d,pe,e.handler_rva,0x1000,4);if(cfg.valid&&!cfg.blocks.empty()){auto h=semantic_cfg_digest(cfg);h=sigmix(h,strict_small_immediate_digest(d,pe,cfg));e.entry_block_hash=h;e.entry_instruction_count=static_cast<std::uint32_t>(cfg.blocks.size());sig_cache[e.handler_rva]={e.entry_block_hash,e.entry_instruction_count};}}
        }
        out.entries.push_back(e);
    }
    return out;
}
namespace {
const CPythonOpcodeReference* opcode_ref(std::uint32_t version,std::uint16_t machine){for(const auto&r:kCPythonOpcodeReferences)if(r.version_hex==version&&r.machine==machine)return &r;return nullptr;}
std::string ref_name(const CPythonOpcodeReferenceEntry&e){return (e.name&&*e.name)?std::string(e.name):("opcode_"+std::to_string(e.opcode));}
void assign_refs(CPythonOpcodeMapping&m,const std::vector<const CPythonOpcodeReferenceEntry*>&v){for(auto*e:v){m.reference_opcodes.push_back(e->opcode);m.reference_names.push_back(ref_name(*e));}}
}
CPythonDispatchInfo analyze_cpython_dispatch(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t version_hex,bool comparable,bool exact_reference_match){
    auto out=recover_cpython_dispatch(d,pe,comparable&&!exact_reference_match);if(!out.table_found)return out;
    auto ref=opcode_ref(version_hex,pe.machine);if(!ref){out.reference_status="TABLE_RECOVERED_NO_REFERENCE";return out;}out.reference_version=ref->version;
    const bool same_shape=out.table_first_opcode==ref->first_opcode&&out.table_entry_count==ref->entry_count;
    if(exact_reference_match&&same_shape){out.reference_status="REFERENCE_MATCH";out.slot_matches=ref->entry_count;return out;}
    if(!comparable){out.reference_status="TABLE_RECOVERED_BUILD_INCOMPARABLE";return out;}
    std::map<std::uint16_t,const CPythonOpcodeReferenceEntry*> by_opcode;
    std::map<std::uint32_t,std::vector<const CPythonOpcodeReferenceEntry*>> by_rva;
    std::map<std::pair<std::uint64_t,std::uint32_t>,std::vector<const CPythonOpcodeReferenceEntry*>> by_sig;
    for(unsigned i=0;i<ref->entry_count;i++){const auto&e=ref->entries[i];by_opcode[e.opcode]=&e;by_rva[e.handler_rva].push_back(&e);if(e.signature)by_sig[{e.signature,e.block_count}].push_back(&e);}
    out.mappings.reserve(out.entries.size());
    for(const auto&t:out.entries){
        auto ei=by_opcode.find(t.opcode);const CPythonOpcodeReferenceEntry*expected=ei==by_opcode.end()?nullptr:ei->second;CPythonOpcodeMapping m;m.target_opcode=t.opcode;m.target_handler_rva=t.handler_rva;m.expected_handler_rva=expected?expected->handler_rva:0;
        if(expected&&t.handler_rva==expected->handler_rva){
            if(!expected->signature||t.entry_block_hash==expected->signature){m.state="SLOT_MATCH";++out.slot_matches;assign_refs(m,by_rva[expected->handler_rva]);}
            else{m.state="HANDLER_MODIFIED_CANDIDATE";++out.handler_modified;assign_refs(m,by_rva[expected->handler_rva]);}
        }else if(auto it=by_rva.find(t.handler_rva);it!=by_rva.end()){
            bool sig_ok=false;for(auto*e:it->second)if(!e->signature||e->signature==t.entry_block_hash){sig_ok=true;break;}m.state=sig_ok?"PERMUTED":"PERMUTED_HANDLER_MODIFIED";++out.permuted_slots;if(!sig_ok)++out.handler_modified;assign_refs(m,it->second);
        }else if(t.entry_block_hash){
            auto signature_it=by_sig.find({t.entry_block_hash,t.entry_instruction_count});if(signature_it!=by_sig.end()){std::set<std::uint32_t>rvas;for(auto*e:signature_it->second)rvas.insert(e->handler_rva);assign_refs(m,signature_it->second);if(rvas.size()==1){bool same=std::any_of(signature_it->second.begin(),signature_it->second.end(),[&](auto*e){return e->opcode==t.opcode;});m.state=same?"SEMANTIC_SLOT_MATCH":"SEMANTIC_PERMUTED";++out.semantic_mapped;if(same)++out.slot_matches;else ++out.permuted_slots;}else{m.state="AMBIGUOUS_SEMANTIC";++out.ambiguous;}}else{m.state="UNMAPPED";++out.unmapped;}
        }else{m.state="UNMAPPED";++out.unmapped;}
        out.mappings.push_back(std::move(m));
    }
    if(same_shape&&out.slot_matches==ref->entry_count&&out.handler_modified==0){out.reference_status="REFERENCE_MATCH";}
    else if(out.handler_modified&&out.permuted_slots)out.reference_status="OPCODE_AND_HANDLER_MODIFIED";
    else if(out.handler_modified)out.reference_status="HANDLER_MODIFIED";
    else if(out.permuted_slots&&out.ambiguous==0&&out.unmapped==0&&same_shape)out.reference_status="OPCODE_PERMUTATION";
    else out.reference_status="PARTIAL_OPCODE_MAPPING";
    return out;
}

}
