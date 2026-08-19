#include "prts/cpython_opcode_module.hpp"
#include "prts/python_marshal.hpp"
#include "prts/sha256.hpp"
#include <algorithm>
#include <charconv>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <utility>

namespace prts { namespace {
std::string_view trim(std::string_view s){
    while(!s.empty()&&(s.front()==' '||s.front()=='\t'||s.front()=='\r'))s.remove_prefix(1);
    while(!s.empty()&&(s.back()==' '||s.back()=='\t'||s.back()=='\r'))s.remove_suffix(1);
    return s;
}

bool opcode_definition_line(std::string_view line,std::string&name,std::uint16_t&opcode){
    line=trim(line);
    static constexpr std::string_view helpers[]={"def_op(","name_op(","jrel_op(","jabs_op("};
    std::size_t prefix=std::string_view::npos;
    for(auto h:helpers)if(line.starts_with(h)){prefix=h.size();break;}
    if(prefix==std::string_view::npos||prefix>=line.size())return false;
    const char quote=line[prefix];if(quote!='\''&&quote!='\"')return false;
    const auto end=line.find(quote,prefix+1);if(end==std::string_view::npos||end==prefix+1)return false;
    auto comma=line.find(',',end+1);if(comma==std::string_view::npos)return false;
    auto close=line.find(')',comma+1);if(close==std::string_view::npos)return false;
    auto num=trim(line.substr(comma+1,close-comma-1));unsigned value=0;
    auto [ptr,ec]=std::from_chars(num.data(),num.data()+num.size(),value,10);
    if(ec!=std::errc{}||ptr!=num.data()+num.size()||value>255)return false;
    name.assign(line.substr(prefix+1,end-prefix-1));opcode=static_cast<std::uint16_t>(value);return true;
}


bool scalar_string(const PythonMarshalRootCode&r,std::uint32_t i,std::string_view&out){
    if(i>=r.constants.size())return false;
    const auto&x=r.constants[i];
    if(x.kind!=PythonMarshalScalarKind::String)return false;
    out=x.text;return true;
}
bool scalar_int(const PythonMarshalRootCode&r,std::uint32_t i,std::int64_t&out){
    if(i>=r.constants.size())return false;
    const auto&x=r.constants[i];
    if(x.kind!=PythonMarshalScalarKind::Integer)return false;
    out=x.integer;return true;
}
bool name_at(const PythonMarshalRootCode&r,std::uint32_t i,std::string_view&out){if(i>=r.names.size())return false;out=r.names[i];return true;}

struct DecodedInstruction {std::int16_t opcode=-1;std::uint32_t arg=0;};
}

CPythonOpcodeSourceReference parse_cpython_opcode_source_reference(std::span<const std::uint8_t>source){
    CPythonOpcodeSourceReference out;out.sha256=sha256_bytes(source);
    std::string text(reinterpret_cast<const char*>(source.data()),source.size());
    std::map<std::string,std::uint16_t>by_name;std::map<std::uint16_t,std::string>by_opcode;
    for(std::size_t p=0;p<=text.size();){
        auto e=text.find('\n',p);if(e==std::string::npos)e=text.size();auto line=std::string_view(text).substr(p,e-p);
        std::string name;std::uint16_t op=0;
        if(opcode_definition_line(line,name,op)){
            if(auto it=by_name.find(name);it!=by_name.end()&&it->second!=op){out.error="stock opcode source redefines "+name+" with a different value";return out;}
            if(auto it=by_opcode.find(op);it!=by_opcode.end()&&it->second!=name){out.error="stock opcode source assigns one opcode value to multiple names";return out;}
            by_name[name]=op;by_opcode[op]=name;
        }
        if(e==text.size())break;
        p=e+1;
    }
    static constexpr const char* required[]={"POP_TOP","STORE_NAME","LOAD_CONST","LOAD_NAME","CALL_FUNCTION","EXTENDED_ARG"};
    for(auto*n:required)if(!by_name.count(n)){out.error=std::string("stock opcode source lacks required CPython 3.8 definition ")+n;return out;}
    if(by_name.size()<80){out.error="stock opcode source contains too few named opcode definitions";return out;}
    out.definitions.reserve(by_name.size());for(const auto&[name,op]:by_name)out.definitions.push_back({name,op});
    std::sort(out.definitions.begin(),out.definitions.end(),[](const auto&a,const auto&b){return a.opcode<b.opcode;});out.valid=true;return out;
}

CPythonOpcodeModuleDelta recover_cpython38_opcode_module_delta(std::span<const std::uint8_t>marshal,
                                                               const CPythonOpcodeSourceReference&ref){
    CPythonOpcodeModuleDelta out;out.attempted=true;out.python_minor=8;out.target_to_reference.fill(-1);out.reference_sha256=ref.sha256;
    if(!ref.valid){out.state="NO_EXACT_REFERENCE";out.error="stock opcode source reference is not valid: "+ref.error;return out;}
    auto root=inspect_python_marshal_root_code(marshal,38);
    if(!root.valid){out.state="MARSHAL_UNAVAILABLE";out.error="opcode module marshal parse failed: "+root.error;return out;}
    if(root.code.empty()||(root.code.size()&1u)){out.state="UNRESOLVED";out.error="CPython 3.8 opcode module root code is not aligned wordcode";return out;}

    std::map<std::string,std::uint16_t>reference_by_name;for(const auto&d:ref.definitions)reference_by_name[d.name]=d.opcode;
    std::map<std::string,std::uint16_t>target_by_name;std::map<std::string,std::string>evidence_by_name;
    auto add=[&](std::string_view name,std::int64_t target,std::string evidence)->bool{
        auto ri=reference_by_name.find(std::string(name));if(ri==reference_by_name.end())return true;
        if(target<0||target>255){out.error="opcode module assigns out-of-range target value to "+std::string(name);return false;}
        auto t=static_cast<std::uint16_t>(target);auto existing=out.target_to_reference[t];
        if(existing>=0&&existing!=static_cast<std::int16_t>(ri->second)){out.error="opcode module target value is assigned to multiple stock semantics";return false;}
        auto ni=target_by_name.find(std::string(name));if(ni!=target_by_name.end()&&ni->second!=t){out.error="opcode module name has conflicting target values: "+std::string(name);return false;}
        out.target_to_reference[t]=static_cast<std::int16_t>(ri->second);target_by_name[std::string(name)]=t;evidence_by_name[std::string(name)]=std::move(evidence);return true;
    };

    // Preserve Q's diagnostic metric, but never use co_consts adjacency as
    // semantic evidence.  Real CPython 3.8.5 constant dedup proves that
    // serialization order is a compiler shape, not module semantics.
    std::set<std::string>adjacent_metric_names;
    for(std::size_t i=0;i+1<root.constants.size();++i){
        const auto&a=root.constants[i];const auto&b=root.constants[i+1];
        if(a.kind==PythonMarshalScalarKind::String&&b.kind==PythonMarshalScalarKind::Integer&&reference_by_name.count(a.text)&&b.integer>=0&&b.integer<=255)
            adjacent_metric_names.insert(a.text);
    }
    out.initial_constant_pairs=static_cast<std::uint32_t>(adjacent_metric_names.size());

    // Bounded bootstrap: direct helper registrations repeat a compiler-stable
    // semantic relation even when concrete opcode bytes are permuted:
    //   LOAD_NAME helper; LOAD_CONST name; LOAD_CONST value; CALL_FUNCTION 2; POP_TOP
    // We do not assume any of those opcode bytes.  Instead, candidate raw-byte
    // quartets must self-authenticate at least three of the four compiler roles
    // through their own registrations. At most one role may be provisional,
    // unclaimed by another semantic, and must close through an exact bounded
    // helper call before the final 120/120 proof. This removes the circular
    // co_consts seed without turning the bootstrap into an evaluator.
    struct RawHelperCall {std::size_t offset=0;std::string helper;std::string opname;std::int64_t target=0;};
    std::map<std::array<std::uint8_t,4>,std::vector<RawHelperCall>>groups;
    static const std::set<std::string_view>helpers={"def_op","name_op","jrel_op","jabs_op"};
    for(std::size_t i=0;i+9<root.code.size();i+=2){
        const auto o0=root.code[i],a0=root.code[i+1],o1=root.code[i+2],a1=root.code[i+3],o2=root.code[i+4],a2=root.code[i+5],o3=root.code[i+6],a3=root.code[i+7],o4=root.code[i+8];
        if(o1!=o2||a3!=2)continue;
        std::string_view helper,opname;std::int64_t target=0;
        if(!name_at(root,a0,helper)||!helpers.count(helper)||!scalar_string(root,a1,opname)||!scalar_int(root,a2,target))continue;
        if(!reference_by_name.count(std::string(opname))||target<0||target>255)continue;
        groups[{o0,o1,o3,o4}].push_back({i,std::string(helper),std::string(opname),target});
    }
    struct BootstrapCandidate {std::array<std::uint8_t,4> key{};std::string provisional_role;};
    std::vector<BootstrapCandidate>seed_candidates;
    static constexpr std::array<std::string_view,4>role_names={"LOAD_NAME","LOAD_CONST","CALL_FUNCTION","POP_TOP"};
    for(const auto&[key,calls]:groups){
        if(calls.size()<80)continue;
        std::set<std::uint8_t>role_bytes(key.begin(),key.end());if(role_bytes.size()!=4)continue;
        std::map<std::string,std::uint16_t>observed;std::map<std::uint16_t,std::string>observed_by_target;bool conflict=false;
        for(const auto&c:calls){
            auto t=static_cast<std::uint16_t>(c.target);auto [it,inserted]=observed.emplace(c.opname,t);if(!inserted&&it->second!=t){conflict=true;break;}
            auto [ti,tinserted]=observed_by_target.emplace(t,c.opname);if(!tinserted&&ti->second!=c.opname){conflict=true;break;}
        }
        if(conflict)continue;
        auto exact=[&](std::string_view name,std::uint16_t value){auto it=observed.find(std::string(name));return it!=observed.end()&&it->second==value;};
        std::string missing;unsigned exact_roles=0;
        for(std::size_t r=0;r<role_names.size();++r){if(exact(role_names[r],key[r]))++exact_roles;else{if(!missing.empty()){missing="*";break;}missing=std::string(role_names[r]);}}
        if(exact_roles<3||missing=="*")continue;
        // A single compiler-shape role may be provisional only when the raw
        // byte is not already claimed by a different named semantic.  The
        // final 120/120 helper closure must independently validate it.
        if(!missing.empty()){auto rit=std::find(role_names.begin(),role_names.end(),std::string_view(missing));if(rit==role_names.end())continue;auto r=static_cast<std::size_t>(rit-role_names.begin());auto ti=observed_by_target.find(key[r]);if(ti!=observed_by_target.end()&&ti->second!=missing)continue;}
        if(!observed.count("EXTENDED_ARG")||!observed.count("STORE_NAME")||!observed.count("DELETE_NAME"))continue;
        seed_candidates.push_back({key,missing});
    }
    if(seed_candidates.size()!=1){out.state="UNRESOLVED";out.error="could not uniquely recover self-consistent CPython 3.8 helper-registration bootstrap";return out;}
    const auto seed=seed_candidates.front();const auto&seed_calls=groups[seed.key];
    std::set<std::string>helper_validated_names;
    for(const auto&c:seed_calls){
        auto before=target_by_name.size();if(!add(c.opname,c.target,"raw CPython 3.8 helper registration with self-consistent co_names/co_consts/code roles")){out.state="UNRESOLVED";return out;}
        helper_validated_names.insert(c.opname);if(target_by_name.size()!=before)++out.recovered_call_pairs;
    }
    if(!seed.provisional_role.empty()){
        auto rit=std::find(role_names.begin(),role_names.end(),std::string_view(seed.provisional_role));
        if(rit==role_names.end()){out.state="UNRESOLVED";out.error="provisional helper-registration role is invalid";return out;}
        auto r=static_cast<std::size_t>(rit-role_names.begin());
        if(!add(seed.provisional_role,seed.key[r],"provisional compiler-shape role; must close through an exact bounded helper call")){out.state="UNRESOLVED";return out;}
    }
    out.bootstrap_helper_calls=static_cast<std::uint32_t>(helper_validated_names.size());

    auto target_for_stock=[&](std::string_view name)->std::optional<std::uint16_t>{auto i=target_by_name.find(std::string(name));if(i==target_by_name.end())return{};return i->second;};
    const auto extended_target=target_for_stock("EXTENDED_ARG");
    if(!extended_target){out.state="UNRESOLVED";out.error="helper-registration bootstrap did not recover EXTENDED_ARG";return out;}

    // Decode only CPython 3.8's fixed two-byte wordcode and EXTENDED_ARG
    // folding. Unknown opcodes remain unknown.  This is structural decoding,
    // not evaluation of Python expressions or arbitrary name/data flow.
    std::vector<DecodedInstruction>decoded;decoded.reserve(root.code.size()/2);std::uint32_t ext=0;
    for(std::size_t i=0;i<root.code.size();i+=2){
        auto target=root.code[i];auto stock=out.target_to_reference[target];auto bytearg=std::uint32_t(root.code[i+1]);
        if(target==*extended_target&&stock==static_cast<std::int16_t>(reference_by_name["EXTENDED_ARG"])){
            if(ext>0x00ffffffu){out.state="UNRESOLVED";out.error="EXTENDED_ARG chain exceeds bounded 32-bit oparg";return out;}ext=(ext|bytearg)<<8;continue;
        }
        if(stock<0){ext=0;decoded.push_back({-1,bytearg});continue;}
        decoded.push_back({stock,ext|bytearg});ext=0;
    }
    if(ext){out.state="UNRESOLVED";out.error="opcode module ends with dangling EXTENDED_ARG";return out;}

    const auto stock_load_name=reference_by_name["LOAD_NAME"],stock_load_const=reference_by_name["LOAD_CONST"],stock_call=reference_by_name["CALL_FUNCTION"],stock_pop=reference_by_name["POP_TOP"],stock_store_name=reference_by_name["STORE_NAME"];
    auto del_it=reference_by_name.find("DELETE_NAME");const auto stock_delete_name=del_it==reference_by_name.end()?std::uint16_t(0xffff):del_it->second;

    // Full direct-call closure, now including calls whose const/name indices
    // need EXTENDED_ARG.  The registration itself is the named-opcode semantic
    // fact; the redundant module-level EXTENDED_ARG assignment is deliberately
    // outside this claim and no longer a compiler-shape bootstrap dependency.
    for(std::size_t i=0;i+4<decoded.size();++i){
        const auto&a=decoded[i],&b=decoded[i+1],&c=decoded[i+2],&d=decoded[i+3],&e=decoded[i+4];
        if(a.opcode!=stock_load_name||b.opcode!=stock_load_const||c.opcode!=stock_load_const||d.opcode!=stock_call||e.opcode!=stock_pop||d.arg!=2)continue;
        std::string_view helper,opname;std::int64_t target=0;
        if(!name_at(root,a.arg,helper)||!helpers.count(helper)||!scalar_string(root,b.arg,opname)||!scalar_int(root,c.arg,target))continue;
        if(!reference_by_name.count(std::string(opname)))continue;
        auto before=target_by_name.size();if(!add(opname,target,"decoded CPython 3.8 direct opcode helper call with exact co_names/co_consts/code relation")){out.state="UNRESOLVED";return out;}
        helper_validated_names.insert(std::string(opname));if(target_by_name.size()!=before)++out.recovered_call_pairs;
    }

    // Count exact module-scope bindings before accepting the only two bounded
    // data-flow relaxations: a one-hop helper alias or immutable integer name.
    // Any redefinition, extra load, missing delete, or expression-built alias
    // is rejected rather than interpreted.
    std::set<std::uint16_t>control_flow_predecessors;
    for(const auto&[name,op]:reference_by_name)if(name.find("JUMP")!=std::string::npos||name=="FOR_ITER")control_flow_predecessors.insert(op);
    auto direct_producer=[&](std::size_t i){return i==0||(decoded[i-1].opcode>=0&&!control_flow_predecessors.count(static_cast<std::uint16_t>(decoded[i-1].opcode)));};
    std::map<std::string,std::uint32_t>stores,loads,deletes;
    for(const auto&ins:decoded){
        std::string_view n;
        if(ins.opcode==stock_store_name&&name_at(root,ins.arg,n))++stores[std::string(n)];
        else if(ins.opcode==stock_load_name&&name_at(root,ins.arg,n))++loads[std::string(n)];
        else if(ins.opcode==stock_delete_name&&name_at(root,ins.arg,n))++deletes[std::string(n)];
    }
    for(std::size_t i=0;i+7<decoded.size();++i){
        const auto&a=decoded[i],&b=decoded[i+1],&c=decoded[i+2],&d=decoded[i+3],&e=decoded[i+4],&f=decoded[i+5],&g=decoded[i+6],&h=decoded[i+7];
        if(!direct_producer(i)||a.opcode!=stock_load_name||b.opcode!=stock_store_name||c.opcode!=stock_load_name||d.opcode!=stock_load_const||e.opcode!=stock_load_const||f.opcode!=stock_call||g.opcode!=stock_pop||h.opcode!=stock_delete_name||f.arg!=2)continue;
        std::string_view helper,alias,alias_load,alias_delete,opname;std::int64_t target=0;
        if(!name_at(root,a.arg,helper)||!helpers.count(helper)||!name_at(root,b.arg,alias)||!name_at(root,c.arg,alias_load)||!name_at(root,h.arg,alias_delete)||alias!=alias_load||alias!=alias_delete)continue;
        if(stores[std::string(alias)]!=1||loads[std::string(alias)]!=1||deletes[std::string(alias)]!=1)continue;
        if(!scalar_string(root,d.arg,opname)||!scalar_int(root,e.arg,target)||!reference_by_name.count(std::string(opname)))continue;
        auto before=helper_validated_names.size();if(!add(opname,target,"bounded one-hop helper alias: single STORE_NAME, one LOAD_NAME use, immediate DELETE_NAME")){out.state="UNRESOLVED";return out;}
        helper_validated_names.insert(std::string(opname));if(helper_validated_names.size()!=before)++out.validated_one_hop_helper_aliases;
    }
    for(std::size_t i=0;i+7<decoded.size();++i){
        const auto&a=decoded[i],&b=decoded[i+1],&c=decoded[i+2],&d=decoded[i+3],&e=decoded[i+4],&f=decoded[i+5],&g=decoded[i+6],&h=decoded[i+7];
        if(!direct_producer(i)||a.opcode!=stock_load_const||b.opcode!=stock_store_name||c.opcode!=stock_load_name||d.opcode!=stock_load_const||e.opcode!=stock_load_name||f.opcode!=stock_call||g.opcode!=stock_pop||h.opcode!=stock_delete_name||f.arg!=2)continue;
        std::int64_t target=0;std::string_view alias,helper,opname,alias_load,alias_delete;
        if(!scalar_int(root,a.arg,target)||target<0||target>255||!name_at(root,b.arg,alias)||!name_at(root,c.arg,helper)||!helpers.count(helper)||!scalar_string(root,d.arg,opname)||!name_at(root,e.arg,alias_load)||!name_at(root,h.arg,alias_delete)||alias!=alias_load||alias!=alias_delete)continue;
        if(stores[std::string(alias)]!=1||loads[std::string(alias)]!=1||deletes[std::string(alias)]!=1||!reference_by_name.count(std::string(opname)))continue;
        auto before=helper_validated_names.size();if(!add(opname,target,"bounded immutable integer binding: single STORE_NAME, one LOAD_NAME use, immediate DELETE_NAME")){out.state="UNRESOLVED";return out;}
        helper_validated_names.insert(std::string(opname));if(helper_validated_names.size()!=before)++out.validated_one_hop_integer_bindings;
    }
    out.validated_helper_calls=static_cast<std::uint32_t>(helper_validated_names.size());

    if(helper_validated_names.size()!=reference_by_name.size()){
        out.state="INCOMPLETE_HELPER_CALL_VALIDATION";out.error="opcode module validates "+std::to_string(helper_validated_names.size())+" of "+std::to_string(reference_by_name.size())+" named stock opcodes through bounded helper semantics";return out;
    }
    if(target_by_name.size()!=reference_by_name.size()){
        out.state="INCOMPLETE_NAMED_OPCODE_MAP";out.error="opcode module recovered "+std::to_string(target_by_name.size())+" of "+std::to_string(reference_by_name.size())+" named stock opcodes";return out;
    }
    std::set<std::uint16_t>targets;
    for(const auto&d:ref.definitions){auto it=target_by_name.find(d.name);if(it==target_by_name.end()||!targets.insert(it->second).second){out.state="UNRESOLVED";out.error="named opcode map is not bijective";return out;}}

    // Exactness is limited to the stock opcode module's registration region.
    // Prove that region is straight-line module code: from the final helper
    // definition (STORE_NAME jabs_op) through the helper cleanup (DELETE_NAME
    // def_op), every opcode must already have a recovered named semantic and
    // no control-transfer instruction may occur.  This prevents a conditional
    // or loop from making syntactically present helper calls look executed.
    const auto store_name_target=target_for_stock("STORE_NAME");
    const auto delete_name_target=target_for_stock("DELETE_NAME");
    if(!store_name_target||!delete_name_target){out.state="UNRESOLVED";out.error="complete named map lacks STORE_NAME/DELETE_NAME registration-region anchors";return out;}
    std::vector<std::size_t>helper_definition_ends,helper_cleanup_starts;
    for(std::size_t i=0;i+1<root.code.size();i+=2){
        std::string_view n;
        if(root.code[i]==*store_name_target&&name_at(root,root.code[i+1],n)&&n=="jabs_op")helper_definition_ends.push_back(i);
        if(root.code[i]==*delete_name_target&&name_at(root,root.code[i+1],n)&&n=="def_op")helper_cleanup_starts.push_back(i);
    }
    if(helper_definition_ends.size()!=1||helper_cleanup_starts.size()!=1||helper_definition_ends[0]>=helper_cleanup_starts[0]){
        out.state="UNRESOLVED";out.error="could not uniquely bound the CPython opcode helper-registration module region";return out;
    }
    std::map<std::uint16_t,std::string>reference_name_by_opcode;for(const auto&d:ref.definitions)reference_name_by_opcode[d.opcode]=d.name;
    auto transfers_control=[](std::string_view name){
        return name.find("JUMP")!=std::string_view::npos||name=="FOR_ITER"||name.starts_with("SETUP_")||
               name=="RETURN_VALUE"||name=="RAISE_VARARGS"||name=="BREAK_LOOP"||name=="CONTINUE_LOOP"||
               name=="YIELD_VALUE"||name=="YIELD_FROM";
    };
    for(std::size_t i=helper_definition_ends[0]+2;i<helper_cleanup_starts[0];i+=2){
        auto stock=out.target_to_reference[root.code[i]];
        if(stock<0){out.state="UNRESOLVED";out.error="unknown opcode inside bounded helper-registration module region";return out;}
        auto ni=reference_name_by_opcode.find(static_cast<std::uint16_t>(stock));
        if(ni==reference_name_by_opcode.end()){out.state="UNRESOLVED";out.error="unnamed opcode inside bounded helper-registration module region";return out;}
        if(transfers_control(ni->second)){out.state="UNRESOLVED";out.error="control transfer inside bounded helper-registration module region: "+ni->second;return out;}
    }

    out.mappings.reserve(ref.definitions.size());
    for(const auto&d:ref.definitions){auto target=target_by_name[d.name];if(target!=d.opcode)++out.changed_opcodes;out.mappings.push_back({target,d.opcode,d.name,evidence_by_name[d.name]});}
    out.complete_named_opcode_map=true;out.changed=out.changed_opcodes!=0;out.valid=true;out.state=out.changed?"COMPLETE_NAMED_OPCODE_PERMUTATION":"REFERENCE_MATCH";return out;
}
}
