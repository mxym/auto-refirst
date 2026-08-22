#include "prts/gdextension.hpp"
#include "Zydis.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <tuple>

namespace prts { namespace {

constexpr std::uint32_t kExec = 0x20000000u;
constexpr std::uint32_t kWrite = 0x80000000u;
constexpr std::uint32_t kKnownMethodFlags = 1u | 2u | 4u | 8u | 16u | 32u;
constexpr std::size_t kMaxDescriptorBytes = 4u * 1024u * 1024u;

std::string trim(std::string_view v) {
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front()))) v.remove_prefix(1);
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back()))) v.remove_suffix(1);
    return std::string(v);
}

bool valid_utf8(std::span<const std::uint8_t> s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = s[i++];
        if (c < 0x80) { if (c == 0) return false; continue; }
        std::uint32_t cp = 0; int need = 0;
        if ((c & 0xe0) == 0xc0) { cp = c & 0x1f; need = 1; if (cp < 2) return false; }
        else if ((c & 0xf0) == 0xe0) { cp = c & 0x0f; need = 2; }
        else if ((c & 0xf8) == 0xf0) { cp = c & 0x07; need = 3; }
        else return false;
        if (i + need > s.size()) return false;
        for (int n = 0; n < need; ++n) { auto d = s[i++]; if ((d & 0xc0) != 0x80) return false; cp = (cp << 6) | (d & 0x3f); }
        if ((need == 2 && cp < 0x800) || (need == 3 && cp < 0x10000) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    }
    return true;
}

std::string strip_comment(std::string_view v) {
    bool quote = false, escape = false;
    for (std::size_t i = 0; i < v.size(); ++i) {
        char c = v[i];
        if (escape) { escape = false; continue; }
        if (quote && c == '\\') { escape = true; continue; }
        if (c == '"') { quote = !quote; continue; }
        if (!quote && (c == ';' || c == '#')) return std::string(v.substr(0, i));
    }
    return std::string(v);
}

bool parse_quoted(std::string_view v, std::string& out) {
    auto t = trim(v);
    if (t.size() < 2 || t.front() != '"' || t.back() != '"') return false;
    out.clear();
    for (std::size_t i = 1; i + 1 < t.size(); ++i) {
        char c = t[i];
        if (c == '\\') {
            if (++i + 1 >= t.size()) return false;
            char n = t[i];
            if (n == '"' || n == '\\') out.push_back(n);
            else if (n == 'n') out.push_back('\n');
            else if (n == 't') out.push_back('\t');
            else return false;
        } else if (c == '"' || static_cast<unsigned char>(c) < 0x20) return false;
        else out.push_back(c);
    }
    return true;
}

bool valid_symbol(std::string_view s) {
    if (s.empty() || !(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_')) return false;
    return std::all_of(s.begin() + 1, s.end(), [](unsigned char c) { return std::isalnum(c) || c == '_'; });
}

bool parse_compatibility_value(std::string_view value,std::string&out){
    std::string t;if(!parse_quoted(value,t))t=trim(value);
    if(t.empty()||t.size()>32)return false;
    std::array<unsigned,3> version{};std::size_t part=0,digits=0;unsigned current=0;
    for(unsigned char c:t){
        if(c=='.'){
            if(!digits||part>=2)return false;
            version[part++]=current;current=0;digits=0;continue;
        }
        if(!std::isdigit(c)||++digits>4)return false;
        current=current*10u+unsigned(c-'0');
    }
    if(!digits)return false;
    version[part]=current;
    // Godot 4.x rejects GDExtension compatibility_minimum below 4.1.0.
    if(version[0]<4||(version[0]==4&&version[1]<1))return false;
    out=std::move(t);return true;
}

bool valid_feature_key(std::string_view s) {
    if (s.empty() || s.size() > 512) return false;
    bool token = false;
    for (unsigned char c : s) {
        if (c == '.') { if (!token) return false; token = false; continue; }
        if (!(std::isalnum(c) || c == '_')) return false;
        token = true;
    }
    return token;
}

bool safe_res_path(std::string_view s) {
    if (s.rfind("res://", 0) != 0 || s.size() <= 6 || s.size() > (1u << 20)) return false;
    std::string part;
    for (std::size_t i = 6; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '/' || s[i] == '\\') {
            if (part.empty() || part == "." || part == "..") return false;
            part.clear();
        } else {
            unsigned char c = s[i]; if (c < 0x20 || c == ':') return false; part.push_back(static_cast<char>(c));
        }
    }
    return true;
}

std::optional<std::string> normalize_res_path(std::string_view input) {
    if (input.empty() || input.size() > (1u << 20)) return std::nullopt;
    if (input.rfind("res://", 0) == 0) input.remove_prefix(6);
    if (input.empty() || input.front() == '/' || input.front() == '\\') return std::nullopt;
    std::string out = "res://";
    std::string part;
    bool first = true;
    auto flush = [&]() -> bool {
        if (part.empty() || part == "." || part == "..") return false;
        if (!first) out.push_back('/');
        out += part; part.clear(); first = false; return true;
    };
    for (std::size_t i = 0; i <= input.size(); ++i) {
        if (i == input.size() || input[i] == '/' || input[i] == '\\') { if (!flush()) return std::nullopt; }
        else { unsigned char c = input[i]; if (c < 0x20 || c == ':') return std::nullopt; part.push_back(static_cast<char>(c)); }
    }
    return out;
}

std::set<std::string> feature_tokens(std::string_view key) {
    std::set<std::string> out; std::size_t p = 0;
    while (p <= key.size()) { auto e = key.find('.', p); if (e == std::string_view::npos) e = key.size(); out.emplace(key.substr(p, e - p)); if (e == key.size()) break; p = e + 1; }
    return out;
}

bool pe64_x64_feature_compatible(std::string_view key) {
    const auto t = feature_tokens(key);
    static const std::set<std::string> os = {"windows","linux","macos","android","ios","web"};
    static const std::set<std::string> arch = {"x86_64","x86_32","arm64","arm32","rv64","wasm32"};
    bool has_os = false, has_arch = false;
    for (const auto& x : os) has_os = has_os || t.count(x);
    for (const auto& x : arch) has_arch = has_arch || t.count(x);
    if (has_os && !t.count("windows")) return false;
    if (has_arch && !t.count("x86_64")) return false;
    return true;
}

std::optional<std::size_t> rva_off(const PeInfo& pe, std::uint32_t rva, std::size_t file_size, std::size_t need = 1) {
    if (rva < pe.headers_size && std::uint64_t(rva) + need <= file_size) return std::size_t(rva);
    for (const auto& s : pe.sections) {
        const auto span = std::max(s.vsize, s.raw_size);
        if (rva < s.rva || std::uint64_t(rva) >= std::uint64_t(s.rva) + span) continue;
        const auto delta = std::uint64_t(rva) - s.rva;
        if (delta + need > s.raw_size) return std::nullopt;
        const auto o = std::uint64_t(s.raw_offset) + delta;
        if (o + need <= file_size) return static_cast<std::size_t>(o);
    }
    return std::nullopt;
}

std::optional<std::size_t> va_off(const PeInfo& pe, std::uint64_t va, std::size_t file_size, std::size_t need = 1) {
    if (va < pe.image_base || va - pe.image_base > 0xffffffffull) return std::nullopt;
    return rva_off(pe, static_cast<std::uint32_t>(va - pe.image_base), file_size, need);
}

const PeSection* va_section(const PeInfo& pe, std::uint64_t va) {
    if (va < pe.image_base) return nullptr;
    const auto rva = va - pe.image_base;
    for (const auto& s : pe.sections) {
        const auto span = std::max(s.vsize, s.raw_size);
        if (rva >= s.rva && rva < std::uint64_t(s.rva) + span) return &s;
    }
    return nullptr;
}

bool executable_va(const PeInfo& pe, std::uint64_t va) {
    auto* s = va_section(pe, va); return s && (s->characteristics & kExec);
}

std::optional<std::string> cstr_va(std::span<const std::uint8_t> d, const PeInfo& pe, std::uint64_t va, std::size_t cap = 512) {
    auto o = va_off(pe, va, d.size()); if (!o) return std::nullopt;
    std::string s;
    while (*o + s.size() < d.size() && s.size() < cap) {
        auto c = d[*o + s.size()];
        if (!c) return s;
        if (c < 0x20 || c > 0x7e) return std::nullopt;
        s.push_back(static_cast<char>(c));
    }
    return std::nullopt;
}

std::optional<std::uint64_t> qword_va(std::span<const std::uint8_t> d, const PeInfo& pe, std::uint64_t va) {
    auto o=va_off(pe,va,d.size(),8); if(!o)return std::nullopt; std::uint64_t v=0; std::memcpy(&v,d.data()+*o,8); return v;
}

std::optional<std::uint32_t> dword_va(std::span<const std::uint8_t> d, const PeInfo& pe, std::uint64_t va) {
    auto o=va_off(pe,va,d.size(),4); if(!o)return std::nullopt; std::uint32_t v=0; std::memcpy(&v,d.data()+*o,4); return v;
}

std::string variant_type_name(std::uint32_t t) {
    static constexpr const char* names[] = {
        "NIL","BOOL","INT","FLOAT","STRING","VECTOR2","VECTOR2I","RECT2","RECT2I","VECTOR3","VECTOR3I","TRANSFORM2D","VECTOR4","VECTOR4I","PLANE","QUATERNION","AABB","BASIS","TRANSFORM3D","PROJECTION","COLOR","STRING_NAME","NODE_PATH","RID","OBJECT","CALLABLE","SIGNAL","DICTIONARY","ARRAY","PACKED_BYTE_ARRAY","PACKED_INT32_ARRAY","PACKED_INT64_ARRAY","PACKED_FLOAT32_ARRAY","PACKED_FLOAT64_ARRAY","PACKED_STRING_ARRAY","PACKED_VECTOR2_ARRAY","PACKED_VECTOR3_ARRAY","PACKED_COLOR_ARRAY","PACKED_VECTOR4_ARRAY"
    };
    return t < std::size(names) ? names[t] : std::string{};
}

struct Decoded { ZydisDecodedInstruction ins{}; std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops{}; };

bool decode(std::span<const std::uint8_t> d, const PeInfo& pe, const ZydisDecoder& dec, std::uint32_t rva, Decoded& z) {
    auto o = rva_off(pe, rva, d.size()); if (!o) return false;
    auto avail = std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH, d.size() - *o);
    return avail && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, d.data() + *o, avail, &z.ins, z.ops.data())) && z.ins.length;
}

ZydisRegister reg64(ZydisRegister r) { return r == ZYDIS_REGISTER_NONE ? r : ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r); }

std::optional<std::uint64_t> rip_mem_va(const Decoded& z, std::uint64_t ip, const ZydisDecodedOperand& o) {
    if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.base != ZYDIS_REGISTER_RIP || o.mem.index != ZYDIS_REGISTER_NONE) return std::nullopt;
    return std::uint64_t(std::int64_t(ip + z.ins.length) + o.mem.disp.value);
}

std::optional<std::uint64_t> rel_target(const Decoded& z, std::uint64_t ip) {
    for (std::uint8_t i = 0; i < z.ins.operand_count_visible; ++i) if (z.ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && z.ops[i].imm.is_relative)
        return std::uint64_t(std::int64_t(ip + z.ins.length) + z.ops[i].imm.value.s);
    return std::nullopt;
}

const PeRuntimeFunction* function_for(const PeInfo& pe, std::uint32_t rva) {
    auto it = std::upper_bound(pe.exception.runtime_functions.begin(), pe.exception.runtime_functions.end(), rva,
        [](std::uint32_t v, const PeRuntimeFunction& f){ return v < f.begin_rva; });
    if (it == pe.exception.runtime_functions.begin()) return nullptr;
    --it; return rva >= it->begin_rva && rva < it->end_rva ? &*it : nullptr;
}

std::set<std::uint32_t> reachable_functions(std::span<const std::uint8_t> d, const PeInfo& pe, const ZydisDecoder& dec, std::uint32_t entry) {
    std::set<std::uint32_t> seen; std::deque<std::pair<std::uint32_t,unsigned>> q;
    auto root = function_for(pe, entry); if (!root) return seen; q.push_back({root->begin_rva,0});
    while (!q.empty() && seen.size() < 1024) {
        auto [begin,depth] = q.front(); q.pop_front(); if (!seen.insert(begin).second) continue;
        auto* f = function_for(pe, begin); if (!f) continue;
        std::uint32_t pc=f->begin_rva; std::size_t n=0;
        while (pc < f->end_rva && n++ < 8192) {
            Decoded z; if (!decode(d,pe,dec,pc,z)) break; auto ip=pe.image_base+pc;
            if (z.ins.meta.category == ZYDIS_CATEGORY_CALL || z.ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR) if (auto t=rel_target(z,ip); t && *t>=pe.image_base && *t-pe.image_base<=0xffffffffull) {
                auto* tf=function_for(pe,static_cast<std::uint32_t>(*t-pe.image_base)); if(tf && tf->begin_rva!=begin && depth<8) q.push_back({tf->begin_rva,depth+1});
            }
            pc += z.ins.length;
        }
    }
    return seen;
}

enum class VKind { Unknown, Const, Stack, Proc };
struct Value { VKind kind=VKind::Unknown; std::uint64_t u=0; std::int64_t stack=0; std::string text; };
Value unknown(){return{};} Value constant(std::uint64_t v){Value x;x.kind=VKind::Const;x.u=v;return x;} Value stackv(std::int64_t v){Value x;x.kind=VKind::Stack;x.stack=v;return x;} Value proc(std::string n){Value x;x.kind=VKind::Proc;x.text=std::move(n);return x;}

struct StackCell { Value value; std::uint16_t bits=0; };
struct ResolverObservation { std::string api; ZydisRegister target_reg=ZYDIS_REGISTER_NONE; std::uint32_t call_rva=0; std::uint64_t slot_va=0; };

bool official_api_name(std::string_view s) {
    static const std::set<std::string> names={
        "print_error","get_godot_version","get_godot_version2","string_name_new_with_latin1_chars",
        "classdb_register_extension_class3","classdb_register_extension_class4","classdb_register_extension_class5",
        "classdb_register_extension_class_method","classdb_register_extension_class_virtual_method",
        "classdb_register_extension_class_signal","classdb_register_extension_class_property"
    };
    return names.count(std::string(s));
}

std::optional<std::int64_t> stack_coord(const ZydisDecodedOperand& o, const std::map<ZydisRegister,Value>& regs, std::int64_t rsp_bias) {
    if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.index != ZYDIS_REGISTER_NONE) return std::nullopt;
    auto b=reg64(o.mem.base); if (b==ZYDIS_REGISTER_RSP) return rsp_bias + o.mem.disp.value;
    auto it=regs.find(b); if(it!=regs.end()&&it->second.kind==VKind::Stack) return it->second.stack+o.mem.disp.value;
    return std::nullopt;
}

Value operand_value(const Decoded& z, std::uint64_t ip, const ZydisDecodedOperand& o, const std::map<ZydisRegister,Value>& regs,
                    const std::map<std::uint64_t,std::string>& api_slots, std::int64_t rsp_bias) {
    if (o.type==ZYDIS_OPERAND_TYPE_REGISTER) { auto it=regs.find(reg64(o.reg.value)); return it==regs.end()?unknown():it->second; }
    if (o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE && !o.imm.is_relative) return constant(o.imm.value.u);
    if (o.type==ZYDIS_OPERAND_TYPE_MEMORY) {
        if (auto va=rip_mem_va(z,ip,o)) { auto it=api_slots.find(*va); if(it!=api_slots.end())return proc(it->second); return constant(*va); }
        if (auto sc=stack_coord(o,regs,rsp_bias)) return stackv(*sc);
    }
    return unknown();
}

bool callback_forwards_first_arg(std::span<const std::uint8_t>d,const PeInfo&pe,const ZydisDecoder&dec,std::uint64_t va){
    if(va<pe.image_base||va-pe.image_base>0xffffffffull)return false;
    auto*f=function_for(pe,static_cast<std::uint32_t>(va-pe.image_base));
    if(!f)return false;
    std::set<ZydisRegister> first{ZYDIS_REGISTER_RCX};std::uint32_t pc=f->begin_rva;std::size_t n=0;
    while(pc<f->end_rva&&n++<512){Decoded z;if(!decode(d,pe,dec,pc,z))break;const auto oc=z.ins.operand_count_visible;
        if(z.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&oc>=2&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER){auto dst=reg64(z.ops[0].reg.value);bool src=z.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&first.count(reg64(z.ops[1].reg.value));if(src)first.insert(dst);else first.erase(dst);}
        else if((z.ins.mnemonic==ZYDIS_MNEMONIC_LEA||z.ins.mnemonic==ZYDIS_MNEMONIC_XOR)&&oc&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER)first.erase(reg64(z.ops[0].reg.value));
        if(z.ins.meta.category==ZYDIS_CATEGORY_CALL){if(oc&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&first.count(reg64(z.ops[0].reg.value)))return true;first.erase(ZYDIS_REGISTER_RAX);first.erase(ZYDIS_REGISTER_RCX);first.erase(ZYDIS_REGISTER_RDX);first.erase(ZYDIS_REGISTER_R8);first.erase(ZYDIS_REGISTER_R9);}
        pc+=z.ins.length;
    }
    return false;
}

struct FunctionTrace {
    std::vector<ResolverObservation> resolver;
    std::map<std::uint64_t,std::string> proc_slot_stores;
    std::vector<GDExtensionClassRegistrationInfo> classes;
    std::vector<GDExtensionMethodRegistrationInfo> methods;
};

struct TraceOptions { bool collect_resolver=false, collect_registration=false; };

FunctionTrace trace_function(std::span<const std::uint8_t>d,const PeInfo&pe,const ZydisDecoder&dec,const PeRuntimeFunction&f,
                             const std::map<std::uint64_t,std::string>&api_slots,TraceOptions opt){
    FunctionTrace out; std::map<ZydisRegister,Value> regs; std::map<std::int64_t,StackCell> mem; std::map<std::int64_t,std::string> string_names; std::set<ZydisRegister> zero_vec; std::vector<std::pair<std::int64_t,std::size_t>> zero_ranges;
    std::int64_t rsp_bias=0; regs[ZYDIS_REGISTER_RSP]=stackv(0);
    std::optional<ResolverObservation> pending_resolve;
    auto getreg=[&](ZydisRegister r){auto it=regs.find(reg64(r));return it==regs.end()?unknown():it->second;};
    auto setreg=[&](ZydisRegister r,Value v){auto q=reg64(r);if(q!=ZYDIS_REGISTER_NONE)regs[q]=std::move(v);};
    auto store_stack=[&](std::int64_t c,Value v,std::uint16_t bits){mem[c]={std::move(v),bits};};
    auto load_cell=[&](std::int64_t c)->std::optional<StackCell>{auto it=mem.find(c);if(it==mem.end())return{};return it->second;};
    auto name_for=[&](const Value&v)->std::string{if(v.kind!=VKind::Stack)return{};auto it=string_names.find(v.stack);return it==string_names.end()?std::string{}:it->second;};
    auto zero_covers=[&](std::int64_t c,std::size_t bytes){for(const auto&r:zero_ranges)if(c>=r.first&&std::uint64_t(c-r.first)+bytes<=r.second)return true;return false;};
    auto scalar=[&](std::int64_t c,std::size_t bytes,std::uint64_t&v)->bool{
        if(!bytes||bytes>8)return false;
        if(auto x=load_cell(c);x&&x->value.kind==VKind::Const&&x->bits>=bytes*8){const auto width=std::min<std::size_t>(8,x->bits/8);const auto mask=bytes==8?~std::uint64_t(0):((std::uint64_t(1)<<(bytes*8))-1);v=x->value.u&mask;if(bytes<=width)return true;}
        for(const auto&[base,cell]:mem){if(cell.value.kind!=VKind::Const||!cell.bits)continue;const auto width=std::size_t(cell.bits/8);if(c<base||std::uint64_t(c-base)+bytes>width||width>8)continue;const auto shift=std::size_t(c-base)*8;const auto mask=bytes==8?~std::uint64_t(0):((std::uint64_t(1)<<(bytes*8))-1);v=(cell.value.u>>shift)&mask;return true;}
        if(zero_covers(c,bytes)){v=0;return true;}return false;
    };
    auto pointer=[&](std::int64_t c,Value&v)->bool{auto x=load_cell(c);if(!x)return false;v=x->value;return v.kind==VKind::Const||v.kind==VKind::Stack;};
    std::uint32_t pc=f.begin_rva;std::size_t insns=0;
    while(pc<f.end_rva&&insns++<12000){Decoded z;if(!decode(d,pe,dec,pc,z))break;auto ip=pe.image_base+pc;const auto oc=z.ins.operand_count_visible;
        if(z.ins.mnemonic==ZYDIS_MNEMONIC_SUB&&oc>=2&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&reg64(z.ops[0].reg.value)==ZYDIS_REGISTER_RSP&&z.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){rsp_bias-=static_cast<std::int64_t>(z.ops[1].imm.value.u);regs[ZYDIS_REGISTER_RSP]=stackv(rsp_bias);}
        else if(z.ins.mnemonic==ZYDIS_MNEMONIC_ADD&&oc>=2&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&reg64(z.ops[0].reg.value)==ZYDIS_REGISTER_RSP&&z.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){rsp_bias+=static_cast<std::int64_t>(z.ops[1].imm.value.u);regs[ZYDIS_REGISTER_RSP]=stackv(rsp_bias);}
        else if(z.ins.mnemonic==ZYDIS_MNEMONIC_PUSH){rsp_bias-=8;regs[ZYDIS_REGISTER_RSP]=stackv(rsp_bias);}
        else if(z.ins.mnemonic==ZYDIS_MNEMONIC_POP){if(oc&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER)setreg(z.ops[0].reg.value,unknown());rsp_bias+=8;regs[ZYDIS_REGISTER_RSP]=stackv(rsp_bias);}
        else if(z.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&oc>=2&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER){Value v;if(auto va=rip_mem_va(z,ip,z.ops[1]))v=constant(*va);else if(auto sc=stack_coord(z.ops[1],regs,rsp_bias))v=stackv(*sc);setreg(z.ops[0].reg.value,std::move(v));}
        else if(z.ins.mnemonic==ZYDIS_MNEMONIC_XOR&&oc>=2&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&z.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&reg64(z.ops[0].reg.value)==reg64(z.ops[1].reg.value))setreg(z.ops[0].reg.value,constant(0));
        else if((z.ins.mnemonic==ZYDIS_MNEMONIC_XORPS||z.ins.mnemonic==ZYDIS_MNEMONIC_XORPD||z.ins.mnemonic==ZYDIS_MNEMONIC_PXOR)&&oc>=2&&z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&z.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&z.ops[0].reg.value==z.ops[1].reg.value)zero_vec.insert(z.ops[0].reg.value);
        else if((z.ins.mnemonic==ZYDIS_MNEMONIC_MOVAPS||z.ins.mnemonic==ZYDIS_MNEMONIC_MOVUPS||z.ins.mnemonic==ZYDIS_MNEMONIC_MOVDQU)&&oc>=2&&z.ops[0].type==ZYDIS_OPERAND_TYPE_MEMORY&&z.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&zero_vec.count(z.ops[1].reg.value)){if(auto sc=stack_coord(z.ops[0],regs,rsp_bias))zero_ranges.push_back({*sc,z.ops[0].size/8});}
        else if(z.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&oc>=2){
            if(z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER){Value v;
                if(z.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){if(auto va=rip_mem_va(z,ip,z.ops[1])){auto ai=api_slots.find(*va);if(ai!=api_slots.end())v=proc(ai->second);else if(auto q=qword_va(d,pe,*va);q&&api_slots.count(*q))v=constant(*q);else v=unknown();}else if(auto sc=stack_coord(z.ops[1],regs,rsp_bias)){auto c=load_cell(*sc);v=c?c->value:unknown();}}
                else v=operand_value(z,ip,z.ops[1],regs,api_slots,rsp_bias);
                setreg(z.ops[0].reg.value,std::move(v));
            } else if(z.ops[0].type==ZYDIS_OPERAND_TYPE_MEMORY){
                Value v=operand_value(z,ip,z.ops[1],regs,api_slots,rsp_bias);if(auto sc=stack_coord(z.ops[0],regs,rsp_bias))store_stack(*sc,v,z.ops[0].size);
                if(auto va=rip_mem_va(z,ip,z.ops[0])){if(pending_resolve&&v.kind==VKind::Proc&&v.text==pending_resolve->api){pending_resolve->slot_va=*va;out.resolver.push_back(*pending_resolve);out.proc_slot_stores[*va]=v.text;pending_resolve.reset();}}
            }
        }
        if(z.ins.meta.category==ZYDIS_CATEGORY_CALL){
            Value target;ZydisRegister target_reg=ZYDIS_REGISTER_NONE;
            if(oc){if(z.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER){target_reg=reg64(z.ops[0].reg.value);target=getreg(target_reg);}else if(z.ops[0].type==ZYDIS_OPERAND_TYPE_MEMORY){if(auto va=rip_mem_va(z,ip,z.ops[0])){auto it=api_slots.find(*va);if(it!=api_slots.end())target=proc(it->second);}else if(z.ops[0].mem.index==ZYDIS_REGISTER_NONE){auto b=getreg(z.ops[0].mem.base);if(b.kind==VKind::Const){auto addr=std::uint64_t(std::int64_t(b.u)+z.ops[0].mem.disp.value);auto it=api_slots.find(addr);if(it!=api_slots.end())target=proc(it->second);}}}}
            auto rcx=getreg(ZYDIS_REGISTER_RCX),rdx=getreg(ZYDIS_REGISTER_RDX),r8=getreg(ZYDIS_REGISTER_R8);
            if(opt.collect_resolver&&target.kind==VKind::Unknown&&target_reg!=ZYDIS_REGISTER_NONE&&rcx.kind==VKind::Const){if(auto s=cstr_va(d,pe,rcx.u);s&&official_api_name(*s)){pending_resolve=ResolverObservation{*s,target_reg,pc,0};setreg(ZYDIS_REGISTER_RAX,proc(*s));}}
            else if(target.kind==VKind::Proc&&target.text=="string_name_new_with_latin1_chars"){if(rcx.kind==VKind::Stack&&rdx.kind==VKind::Const){if(auto s=cstr_va(d,pe,rdx.u))string_names[rcx.stack]=*s;}setreg(ZYDIS_REGISTER_RAX,unknown());}
            else if(opt.collect_registration&&target.kind==VKind::Proc&&(target.text=="classdb_register_extension_class3"||target.text=="classdb_register_extension_class4"||target.text=="classdb_register_extension_class5")){
                GDExtensionClassRegistrationInfo x;x.registration_function_rva=f.begin_rva;x.registration_call_rva=pc;x.class_name=name_for(rdx);x.parent_class_name=name_for(r8);x.evidence_state=(!x.class_name.empty()&&!x.parent_class_name.empty())?"EXACT_REGISTRATION":"UNRESOLVED_REGISTRATION";out.classes.push_back(std::move(x));setreg(ZYDIS_REGISTER_RAX,unknown());}
            else if(opt.collect_registration&&target.kind==VKind::Proc&&target.text=="classdb_register_extension_class_method"){
                GDExtensionMethodRegistrationInfo x;x.registration_function_rva=f.begin_rva;x.registration_call_rva=pc;x.class_name=name_for(rdx);
                if(r8.kind==VKind::Stack){const auto b=r8.stack;Value pv;std::uint64_t q=0;
                    if(pointer(b+0,pv))x.method_name=name_for(pv);
                    if(pointer(b+8,pv)&&pv.kind==VKind::Const){x.method_userdata_known=true;x.method_userdata_va=pv.u;}
                    if(pointer(b+16,pv)&&pv.kind==VKind::Const){x.call_func_known=true;x.call_func_va=pv.u;}
                    if(pointer(b+24,pv)&&pv.kind==VKind::Const){x.ptrcall_func_known=true;x.ptrcall_func_va=pv.u;}
                    if(scalar(b+32,4,q)&&q<=0xffffffffu){x.method_flags_known=true;x.method_flags=static_cast<std::uint32_t>(q);}
                    if(scalar(b+36,1,q)&&q<=1){x.has_return_value_known=true;x.has_return_value=q!=0;}
                    if(scalar(b+48,4,q)&&q<=12){x.return_value_metadata_known=true;x.return_value_metadata=static_cast<std::uint32_t>(q);}
                    if(scalar(b+52,4,q)&&q<=4096){x.argument_count_known=true;x.argument_count=static_cast<std::uint32_t>(q);}
                    if(scalar(b+72,4,q)&&q<=4096){x.default_argument_count_known=true;x.default_argument_count=static_cast<std::uint32_t>(q);}
                    Value return_info,args_info,args_metadata;
                    if(x.has_return_value_known&&x.has_return_value&&pointer(b+40,return_info)&&return_info.kind==VKind::Const){if(auto t=dword_va(d,pe,return_info.u)){auto n=variant_type_name(*t);if(!n.empty()){x.return_variant_type_known=true;x.return_variant_type=*t;x.return_variant_type_name=std::move(n);}}}
                    if(x.argument_count_known&&x.argument_count<=256&&pointer(b+56,args_info)&&args_info.kind==VKind::Const){auto bytes=std::uint64_t(x.argument_count)*48;if(bytes<=12288&&va_off(pe,args_info.u,d.size(),static_cast<std::size_t>(bytes))){bool ok=true;for(std::uint32_t ai=0;ai<x.argument_count;++ai){auto t=dword_va(d,pe,args_info.u+std::uint64_t(ai)*48);if(!t){ok=false;break;}auto n=variant_type_name(*t);if(n.empty()){ok=false;break;}x.argument_variant_types.push_back(*t);x.argument_variant_type_names.push_back(std::move(n));}x.argument_types_complete=ok&&x.argument_variant_types.size()==x.argument_count;if(!x.argument_types_complete){x.argument_variant_types.clear();x.argument_variant_type_names.clear();}}}
                    if(x.argument_count_known&&x.argument_count<=256&&pointer(b+64,args_metadata)&&args_metadata.kind==VKind::Const){auto bytes=std::uint64_t(x.argument_count)*4;if(bytes<=1024&&va_off(pe,args_metadata.u,d.size(),static_cast<std::size_t>(bytes))){bool ok=true;for(std::uint32_t ai=0;ai<x.argument_count;++ai){auto m=dword_va(d,pe,args_metadata.u+std::uint64_t(ai)*4);if(!m||*m>12){ok=false;break;}x.argument_metadata.push_back(*m);}x.argument_metadata_complete=ok&&x.argument_metadata.size()==x.argument_count;if(!x.argument_metadata_complete)x.argument_metadata.clear();}}
                }
                bool core=!x.class_name.empty()&&!x.method_name.empty()&&x.method_flags_known&&(x.method_flags&~kKnownMethodFlags)==0&&x.has_return_value_known&&x.argument_count_known&&x.default_argument_count_known&&x.default_argument_count<=x.argument_count&&x.call_func_known&&x.ptrcall_func_known;
                if(x.call_func_known&&!executable_va(pe,x.call_func_va))core=false;
                if(x.ptrcall_func_known&&!executable_va(pe,x.ptrcall_func_va))core=false;
                x.evidence_state=core?"EXACT_REGISTRATION":"UNRESOLVED_REGISTRATION";
                if(core&&x.method_userdata_known&&executable_va(pe,x.method_userdata_va)){bool forwarded=(x.call_func_known&&callback_forwards_first_arg(d,pe,dec,x.call_func_va))||(x.ptrcall_func_known&&callback_forwards_first_arg(d,pe,dec,x.ptrcall_func_va));if(forwarded){x.bridge_candidates.push_back({x.method_userdata_va,static_cast<std::uint32_t>(x.method_userdata_va-pe.image_base),"executable method_userdata reached by a registered wrapper through first-argument dataflow"});x.evidence_state="BOUNDED_BRIDGE_CANDIDATES";}}
                x.detail=core?"registration structure and class/method provenance close under official x64 GDExtensionClassMethodInfo layout":"registration API call proven but class/method/method-info core is incomplete";
                out.methods.push_back(std::move(x));setreg(ZYDIS_REGISTER_RAX,unknown());}
            else setreg(ZYDIS_REGISTER_RAX,unknown());
            setreg(ZYDIS_REGISTER_RCX,unknown());setreg(ZYDIS_REGISTER_RDX,unknown());setreg(ZYDIS_REGISTER_R8,unknown());setreg(ZYDIS_REGISTER_R9,unknown());
        }
        if(z.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR||z.ins.meta.category==ZYDIS_CATEGORY_COND_BR){/* linear trace is intentionally conservative; joins are not promoted */}
        pc+=z.ins.length;
    }
    return out;
}

} // namespace

std::optional<std::string> normalize_gdextension_resource_path(std::string_view input) { return normalize_res_path(input); }

bool gdextension_pe64_x64_feature_compatible(std::string_view feature_key) { return pe64_x64_feature_compatible(feature_key); }

GDExtensionDescriptorInfo parse_gdextension_descriptor(std::span<const std::uint8_t> data) {
    GDExtensionDescriptorInfo out;
    if (data.empty() || data.size() > kMaxDescriptorBytes || !valid_utf8(data)) { out.error="descriptor is empty/oversized or not valid UTF-8"; return out; }
    out.candidate=true; std::string text(reinterpret_cast<const char*>(data.data()),data.size()), section; std::set<std::string> libkeys; bool entry_seen=false;
    std::size_t line_no=0,pos=0;
    while(pos<=text.size()){
        auto end=text.find('\n',pos);if(end==std::string::npos)end=text.size();auto raw=std::string_view(text).substr(pos,end-pos);if(!raw.empty()&&raw.back()=='\r')raw.remove_suffix(1);++line_no;auto clean=trim(strip_comment(raw));pos=end==text.size()?text.size()+1:end+1;if(clean.empty())continue;
        if(clean.front()=='['){if(clean.size()<3||clean.back()!=']'){out.error="malformed section header";out.error_line=line_no;return out;}section=trim(std::string_view(clean).substr(1,clean.size()-2));if(section.empty()){out.error="empty section name";out.error_line=line_no;return out;}continue;}
        if(section!="configuration"&&section!="libraries")continue; // Other official sections (e.g. dependencies) can contain multiline Variant syntax and are not registration identity evidence.
        bool quote=false,esc=false;std::size_t eq=std::string::npos;for(std::size_t i=0;i<clean.size();++i){char c=clean[i];if(esc){esc=false;continue;}if(quote&&c=='\\'){esc=true;continue;}if(c=='"'){quote=!quote;continue;}if(!quote&&c=='='){eq=i;break;}}
        if(eq==std::string::npos){out.error="descriptor assignment lacks '='";out.error_line=line_no;return out;}auto key=trim(std::string_view(clean).substr(0,eq));auto val=std::string_view(clean).substr(eq+1);if(key.empty()){out.error="empty descriptor key";out.error_line=line_no;return out;}
        if(section=="configuration"){
            if(key=="entry_symbol"){std::string v;if(entry_seen||!parse_quoted(val,v)||!valid_symbol(v)){out.error="invalid or duplicate configuration.entry_symbol";out.error_line=line_no;return out;}entry_seen=true;out.entry_symbol=std::move(v);}
            else if(key=="compatibility_minimum"){std::string v;if(!parse_compatibility_value(val,v)){out.error="compatibility_minimum must be a bounded dotted version accepted by the GDExtension 4.1+ contract";out.error_line=line_no;return out;}out.compatibility_minimum=std::move(v);}
            else if(key=="reloadable"){auto t=trim(val);if(t!="true"&&t!="false"){out.error="reloadable must be true/false";out.error_line=line_no;return out;}out.reloadable_present=true;out.reloadable=t=="true";}
        } else if(section=="libraries"){
            std::string path;if(!valid_feature_key(key)||!parse_quoted(val,path)||!safe_res_path(path)||!libkeys.insert(key).second){out.error="invalid/duplicate libraries entry or unsafe res:// path";out.error_line=line_no;return out;}out.libraries.push_back({key,std::move(path),line_no});
        }
    }
    if(!entry_seen){out.error="configuration.entry_symbol is missing";return out;}if(out.libraries.empty()){out.error="libraries section has no valid library declarations";return out;}
    out.valid=true;out.state="CONFIRMED";return out;
}

GDExtensionNativeInfo analyze_gdextension_pe(std::span<const std::uint8_t>d,const PeInfo&pe,const GDExtensionDescriptorInfo&desc){
    GDExtensionNativeInfo out;out.entry_symbol=desc.entry_symbol;
    if(!desc.valid){out.error="GDExtension descriptor is not structurally validated";return out;}out.candidate=true;
    if(!pe.valid||!pe.pe64||pe.machine!=0x8664){out.error="native GDExtension analyzer currently requires PE32+ x86-64";return out;}out.architecture="x86_64-windows";
    const PeExport* ex=nullptr;for(const auto&e:pe.exports)if(e.name==desc.entry_symbol){if(ex){out.error="descriptor entry symbol resolves to multiple PE exports";return out;}ex=&e;}if(!ex||!ex->forwarder.empty()){out.error="descriptor entry symbol is absent or forwarded in the sibling PE";return out;}out.entry_rva=ex->rva;out.entry_export_validated=true;
    if(!function_for(pe,out.entry_rva)){out.error="entry export is not covered by a validated x64 RUNTIME_FUNCTION";return out;}
    ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64))){out.error="Zydis decoder initialization failed";return out;}
    auto reach=reachable_functions(d,pe,dec,out.entry_rva);out.reachable_function_count=reach.size();
    struct Candidate{std::uint32_t func=0;ZydisRegister reg=ZYDIS_REGISTER_NONE;std::vector<ResolverObservation>obs;};std::vector<Candidate> candidates;
    for(auto fr:reach){auto*f=function_for(pe,fr);if(!f)continue;auto tr=trace_function(d,pe,dec,*f,{},TraceOptions{true,false});std::map<ZydisRegister,std::vector<ResolverObservation>>g;for(auto&o:tr.resolver)if(o.slot_va)g[o.target_reg].push_back(o);for(auto&[r,v]:g){std::set<std::string>names;std::set<std::uint64_t>slots;for(auto&o:v){names.insert(o.api);slots.insert(o.slot_va);}if(names.size()>=3&&slots.size()>=3)candidates.push_back({fr,r,v});}}
    if(candidates.size()!=1){out.error=candidates.empty()?"entry-reachable get_proc_address resolver relationship was not structurally closed":"multiple entry-reachable get_proc_address resolver candidates remain";out.valid=true;return out;}
    auto&c=candidates.front();out.get_proc_relationship_validated=true;out.resolver_function_rva=c.func;
    std::map<std::uint64_t,std::string>slots;std::map<std::string,std::uint64_t>name_slot;
    for(const auto&o:c.obs){if(!o.slot_va)continue;auto*sec=va_section(pe,o.slot_va);if(!sec||(sec->characteristics&kWrite)==0)continue;if(auto prev=name_slot.find(o.api);prev!=name_slot.end()&&prev->second!=o.slot_va){out.error="one GDExtension API resolved into multiple writable slots";out.valid=true;return out;}name_slot[o.api]=o.slot_va;slots[o.slot_va]=o.api;GDExtensionApiSlotInfo x;x.api_name=o.api;x.resolver_function_rva=c.func;x.resolve_call_rva=o.call_rva;x.storage_va=o.slot_va;x.storage_rva=static_cast<std::uint32_t>(o.slot_va-pe.image_base);x.storage_writable=true;if(auto fo=va_off(pe,o.slot_va,d.size(),8)){x.storage_file_backed=true;x.storage_file_offset=*fo;}out.api_slots.push_back(std::move(x));}
    if(!name_slot.count("classdb_register_extension_class_method")){out.error="get_proc relationship closes but method-registration API slot was not recovered";out.valid=true;return out;}
    for(const auto&f:pe.exception.runtime_functions){auto tr=trace_function(d,pe,dec,f,slots,TraceOptions{false,true});out.classes.insert(out.classes.end(),tr.classes.begin(),tr.classes.end());out.methods.insert(out.methods.end(),tr.methods.begin(),tr.methods.end());}
    bool exact=false,bounded=false,proven=false;for(const auto&m:out.methods){proven=true;if(m.evidence_state=="EXACT_REGISTRATION")exact=true;else if(m.evidence_state=="BOUNDED_BRIDGE_CANDIDATES")bounded=true;}
    out.valid=true;if(bounded)out.state="BOUNDED_BRIDGE_CANDIDATES";else if(exact)out.state="EXACT_REGISTRATION";else out.state="UNRESOLVED_REGISTRATION";
    if(!proven)out.error="method-registration API slot is proven but no bounded registration callsite closed";
    return out;
}

GDExtensionBundleInfo analyze_gdextension_pck_bundle(const GDExtensionPckChildView& descriptor_child,
                                                        std::span<const GDExtensionPckChildView> children) {
    GDExtensionBundleInfo out; out.descriptor_path = descriptor_child.path; out.descriptor_entry_index = descriptor_child.entry_index; out.descriptor_child_validated = descriptor_child.validated;
    if (!descriptor_child.validated) { out.error = "descriptor PCK child is not independently validated"; return out; }
    auto descriptor_path = normalize_res_path(descriptor_child.path);
    if (!descriptor_path || descriptor_path->size() < 12 || descriptor_path->substr(descriptor_path->size() - 12) != ".gdextension") { out.error = "validated PCK child is not routed as a .gdextension resource"; return out; }
    out.descriptor_path = *descriptor_path; out.descriptor = parse_gdextension_descriptor(descriptor_child.data);
    if (!out.descriptor.valid) { out.error = "GDExtension descriptor structure failed: " + out.descriptor.error; return out; }

    std::map<std::string, std::vector<const GDExtensionPckChildView*>> by_path;
    for (const auto& child : children) if (auto p = normalize_res_path(child.path)) by_path[*p].push_back(&child);

    bool any_exact = false, any_exact_registration = false, any_bounded = false;
    for (const auto& decl : out.descriptor.libraries) {
        GDExtensionLibraryMatchInfo m; m.feature_key = decl.feature_key; m.declared_path = decl.path;
        auto normalized = normalize_res_path(decl.path);
        if (!normalized) { m.state = "INVALID_DECLARED_LIBRARY_PATH"; m.error = "descriptor library path cannot be normalized"; out.libraries.push_back(std::move(m)); continue; }
        m.normalized_declared_path = *normalized; auto it = by_path.find(*normalized);
        if (it == by_path.end()) { m.state = "MISSING_DECLARED_LIBRARY"; m.error = "no PCK child has the declared resource path"; out.libraries.push_back(std::move(m)); continue; }
        std::vector<const GDExtensionPckChildView*> validated; for (auto* c : it->second) if (c->validated) validated.push_back(c);
        if (validated.empty()) { m.state = "MATCHED_UNVALIDATED_CHILD"; m.error = "resource path exists but no matching child is independently validated"; out.libraries.push_back(std::move(m)); continue; }
        if (validated.size() != 1) { m.state = "AMBIGUOUS_VALIDATED_LIBRARY_PATH"; m.error = "multiple validated PCK children normalize to the same declared resource path"; out.libraries.push_back(std::move(m)); continue; }
        const auto& child = *validated.front(); m.exact_path_match = true; m.child_validated = true; m.matched_child_path = child.path; m.matched_entry_index = child.entry_index; ++out.exact_library_match_count; any_exact = true;
        auto pe = parse_pe(child.data);
        if (!pe.valid) { m.state = "UNSUPPORTED_NATIVE_FORMAT"; m.error = "exact validated sibling path matched, but current D20 core only analyzes PE32+ x86-64 native images"; out.libraries.push_back(std::move(m)); continue; }
        m.native_format = "PE";
        if (!pe.pe64 || pe.machine != 0x8664) { m.state = "UNSUPPORTED_NATIVE_ARCHITECTURE"; m.error = "PE sibling is not x86-64"; out.libraries.push_back(std::move(m)); continue; }
        if (!pe64_x64_feature_compatible(decl.feature_key)) { m.state = "FEATURE_NATIVE_MISMATCH"; m.error = "declared feature key conflicts with PE64/x86-64 sibling format"; out.libraries.push_back(std::move(m)); continue; }
        m.native = analyze_gdextension_pe(child.data, pe, out.descriptor); m.native_analyzed = true; ++out.analyzed_native_count; m.state = m.native.state; if (!m.native.error.empty()) m.error = m.native.error;
        any_exact_registration = any_exact_registration || m.native.state == "EXACT_REGISTRATION"; any_bounded = any_bounded || m.native.state == "BOUNDED_BRIDGE_CANDIDATES"; out.libraries.push_back(std::move(m));
    }
    if (!any_exact) { out.error = "no declared library path matched exactly one validated PCK child"; return out; }
    out.valid = true; out.state = any_bounded ? "BOUNDED_BRIDGE_CANDIDATES" : (any_exact_registration ? "EXACT_REGISTRATION" : "UNRESOLVED_REGISTRATION"); return out;
}

} // namespace prts
