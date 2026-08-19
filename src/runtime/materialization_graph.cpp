#include "prts/materialization_graph.hpp"
#include "prts/path_utf8.hpp"
#include "prts/file_snapshot.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <tuple>
#include <unordered_map>

namespace prts {
namespace {

const std::string* field(const std::map<std::string,std::string>& f,const char* key){
    auto it=f.find(key);return it==f.end()?nullptr:&it->second;
}
bool field_is(const std::map<std::string,std::string>& f,const char* key,const char* value){auto p=field(f,key);return p&&*p==value;}
std::optional<std::uint64_t> parse_u64(const std::string&s){
    if(s.empty()||s=="UNKNOWN") return {};
    std::uint64_t v=0;
    const char* b=s.data();
    const char* e=b+s.size();
    int base=10;
    if(s.size()>2&&s[0]=='0'&&(s[1]=='x'||s[1]=='X')){b+=2;base=16;}
    auto r=std::from_chars(b,e,v,base);
    if(r.ec!=std::errc{}||r.ptr!=e) return {};
    return v;
}
std::optional<std::uint64_t> fu64(const std::map<std::string,std::string>&f,const char*key){auto p=field(f,key);return p?parse_u64(*p):std::optional<std::uint64_t>{};}
std::optional<std::uint32_t> fu32(const std::map<std::string,std::string>&f,const char*key){auto v=fu64(f,key);if(!v||*v>std::numeric_limits<std::uint32_t>::max())return{};return static_cast<std::uint32_t>(*v);}
std::string csvq(const std::string&s){std::string o="\"";for(char c:s){if(c=='\"')o+="\"\"";else if(c=='\n'||c=='\r')o+=' ';else o+=c;}o+='\"';return o;}
std::string optu(const std::optional<std::uint32_t>&v){return v?std::to_string(*v):"UNKNOWN";}
std::string optid(const std::optional<std::uint64_t>&v){return v?std::to_string(*v):"";}
std::string basis_name(CoordinateBasis b){return coordinate_basis_name(b);}
std::string space_name(CoordinateSpace s){return coordinate_space_name(s);}

bool artifact_nonzero(const RuntimeArtifact&a){
    if(a.path.empty()) return false;
    std::ifstream f(a.path,std::ios::binary);
    if(!f) return false;
    std::array<char,65536>b{};
    while(f){
        f.read(b.data(),static_cast<std::streamsize>(b.size()));
        auto n=f.gcount();
        for(std::streamsize i=0;i<n;++i)
            if(static_cast<unsigned char>(b[static_cast<std::size_t>(i)])!=0) return true;
    }
    return false;
}
std::string artifact_sha(const RuntimeArtifact&a){
    if(auto p=field(a.fields,"snapshot_sha256"))return *p;
    if(auto p=field(a.fields,"post_exec_snapshot_sha256"))return *p;
    if(a.path.empty()) return {};
    auto s=snapshot_file(a.path);
    return s.exists?s.sha256:std::string{};
}
MaterializationNodeKind backing_kind(const std::string&k){if(k.find("tmpfile")!=std::string::npos)return MaterializationNodeKind::O_TMPFILE_BACKING;if(k.find("released_file")!=std::string::npos)return MaterializationNodeKind::RELEASED_FILE;return MaterializationNodeKind::MEMFD_BACKING;}
bool image_kind(MaterializationNodeKind k){return k==MaterializationNodeKind::ORIGINAL_IMAGE||k==MaterializationNodeKind::ORIGINAL_IMAGE_REGION||k==MaterializationNodeKind::REPLACEMENT_IMAGE||k==MaterializationNodeKind::RECONSTRUCTED_IMAGE||k==MaterializationNodeKind::INSTALLED_VALIDATED_IMAGE;}
bool memory_kind(MaterializationNodeKind k){return k==MaterializationNodeKind::ANONYMOUS_REGION||k==MaterializationNodeKind::MEMFD_BACKING||k==MaterializationNodeKind::O_TMPFILE_BACKING||k==MaterializationNodeKind::RELEASED_FILE||k==MaterializationNodeKind::CROSS_PROCESS_REGION;}
bool executable_protection(const std::map<std::string,std::string>&f){
    if(field_is(f,"armed_execute_breakpoint","true")||field_is(f,"materialization_candidate","true"))return true;
    auto p=field(f,"requested_prot");if(!p)return false;auto v=parse_u64(*p);if(!v)return false;
    // Linux PROT_EXEC=0x4. Windows PAGE_EXECUTE*=0x10/0x20/0x40/0x80.
    return ((*v&4u)!=0)||*v==0x10u||*v==0x20u||*v==0x40u||*v==0x80u;
}

struct NodeState {
    bool write_confirmed=false;
    bool executable_transition=false;
    bool exact_exec_handoff=false;
    bool zero_initialized_basis=false;
    bool write_edge_emitted=false;
    std::optional<std::uint32_t> writer_execution_generation;
    std::optional<std::uint32_t> byte_source_generation;
    std::optional<std::uint32_t> executor_prior_generation;
    std::optional<std::uint32_t> mutation_parent_generation;
    std::optional<std::uint32_t> executor_tid;
};

struct Builder {
    MaterializationGraph g;
    const RuntimeReport&r;
    const ReplacementReport*replacement;
    std::vector<NodeState> ns;
    std::map<std::uint64_t,std::uint64_t> original;
    std::map<std::pair<std::uint64_t,std::uint32_t>,std::uint32_t> thread_generation;
    std::map<std::pair<std::uint64_t,std::uint32_t>,std::uint64_t> thread_node;
    std::map<std::tuple<std::uint64_t,std::string,std::uint64_t>,std::uint64_t> backings;
    std::map<std::tuple<std::uint64_t,std::uint64_t,std::uint64_t,int>,std::uint64_t> regions;
    std::map<std::string,std::uint64_t> artifacts;
    std::map<std::pair<std::uint64_t,std::uint64_t>,bool> backing_nonzero_capture;
    std::map<std::tuple<std::uint64_t,std::uint64_t,std::uint64_t>,bool> region_nonzero_capture;
    std::map<std::pair<std::uint64_t,std::uint64_t>,std::string> artifact_sha_by_backing;
    std::set<std::uint64_t> processes_with_generated_execution;
    std::map<std::uint64_t,std::uint64_t> latest_executed_node;

    Builder(const RuntimeReport&rr,const ReplacementReport*rp):r(rr),replacement(rp){preindex_artifacts();}

    void preindex_artifacts(){
        for(const auto&a:r.artifacts){
            if(a.kind!="materialized_region"&&a.kind!="runtime_backing_elf")continue;
            const bool nz=artifact_nonzero(a);auto bid=fu64(a.fields,"backing_id");
            if(bid){backing_nonzero_capture[{a.process_uid,*bid}]=backing_nonzero_capture[{a.process_uid,*bid}]||nz;if(nz)artifact_sha_by_backing[{a.process_uid,*bid}]=artifact_sha(a);}
            if(a.kind!="materialized_region")continue;
            auto start=fu64(a.fields,"memory_address");if(!start)start=fu64(a.fields,"region_start");std::uint64_t size=0;if(auto z=fu64(a.fields,"memory_size"))size=*z;else if(auto e=fu64(a.fields,"region_end");e&&start&&*e>*start)size=*e-*start;if(start&&size)region_nonzero_capture[{a.process_uid,*start,*start+size}]=nz;
        }
    }
    MaterializationNode& node(std::uint64_t id){return g.nodes.at(static_cast<std::size_t>(id-1));}
    NodeState& state(std::uint64_t id){return ns.at(static_cast<std::size_t>(id-1));}
    std::uint64_t add_node(MaterializationNode n){n.id=g.nodes.size()+1;g.nodes.push_back(std::move(n));ns.emplace_back();return g.nodes.back().id;}
    void add_edge(std::optional<std::uint64_t>src,std::uint64_t dst,MaterializationEdgeKind kind,const TimelineEvent*e,std::string evidence,std::string detail,std::optional<std::uint32_t>writer_gen={}){
        MaterializationEdge x;x.id=g.edges.size()+1;x.source_node=src;x.destination_node=dst;x.kind=kind;x.writer_execution_generation=writer_gen;x.process_uid=e?e->process_uid:node(dst).process_uid;x.thread_id=e?event_tid(*e):node(dst).thread_id;x.seq=e?e->seq:node(dst).seq;x.t_us=e?e->t_us:node(dst).t_us;x.coordinate_basis=node(dst).coordinate_basis;x.address=node(dst).address;x.size=node(dst).size;x.evidence_state=std::move(evidence);x.detail=std::move(detail);g.edges.push_back(std::move(x));
    }
    std::optional<std::uint32_t> event_tid(const TimelineEvent&e) const {
        for(const char*k:{"writer_tid","thread_id","executor_tid","backing_executor_tid","creator_tid"})if(auto v=fu32(e.fields,k))return v;
        auto sc=field(e.fields,"scope");if(sc&&(*sc=="root_thread"||*sc=="child_thread"||*sc=="root_process"||*sc=="child_process"||*sc=="descendant_process"))return e.pid;
        if(e.kind==TimelineKind::FileWrite)return e.pid;
        if(e.kind==TimelineKind::ProcessStart&&e.subject=="runtime_backing_exec_handoff")return e.pid;
#ifdef __linux__
        if(e.kind==TimelineKind::MemoryAllocate||e.kind==TimelineKind::MemoryProtect||e.kind==TimelineKind::MemoryWrite||e.kind==TimelineKind::FileCreate||e.kind==TimelineKind::MaterializedExecute)return e.pid;
#endif
        return{};
    }
    std::optional<std::uint32_t> active_generation(const TimelineEvent&e) const {auto t=event_tid(e);if(!t)return{};auto it=thread_generation.find({e.process_uid,*t});return it==thread_generation.end()?std::optional<std::uint32_t>{}:std::optional<std::uint32_t>{it->second};}
    std::optional<std::uint64_t> active_node(const TimelineEvent&e) const {auto t=event_tid(e);if(!t)return{};auto it=thread_node.find({e.process_uid,*t});return it==thread_node.end()?std::optional<std::uint64_t>{}:std::optional<std::uint64_t>{it->second};}
    std::uint64_t ensure_original(const TimelineEvent&e){
        if(auto it=original.find(e.process_uid);it!=original.end()) return it->second;
        MaterializationNode n;
        n.kind=MaterializationNodeKind::ORIGINAL_IMAGE;n.generation=0;n.executed=true;n.process_uid=e.process_uid;n.pid=e.pid;
        n.creator_process_uid=e.process_uid;n.creator_thread_id=event_tid(e);n.first_execution_process_uid=e.process_uid;
        n.first_execution_thread_id=event_tid(e);n.first_execution_seq=e.seq;n.seq=e.seq;n.t_us=e.t_us;
        n.coordinate_space=CoordinateSpace::VA;n.coordinate_basis=CoordinateBasis::PROCESS_IMAGE;n.image=e.process_image;
        n.backing_path=e.process_image;n.backing_identity="process:"+std::to_string(e.process_uid)+":original_image";
        n.evidence_state="CONFIRMED";n.detail="process image observed at runtime start";
        auto id=add_node(std::move(n));original[e.process_uid]=id;latest_executed_node[e.process_uid]=id;
        auto tid=fu32(e.fields,"initial_thread_id");if(!tid)tid=e.pid;
        thread_generation[{e.process_uid,*tid}]=0;thread_node[{e.process_uid,*tid}]=id;return id;
    }
    std::uint64_t ensure_backing(const TimelineEvent&e,std::uint64_t process_uid,const std::string&kind,std::uint64_t bid){
        auto key=std::make_tuple(process_uid,kind,bid);if(auto it=backings.find(key);it!=backings.end())return it->second;MaterializationNode n;n.kind=backing_kind(kind);n.process_uid=process_uid;n.pid=e.pid;n.thread_id=event_tid(e);n.creator_process_uid=fu64(e.fields,"backing_creator_process_uid").value_or(process_uid);n.creator_thread_id=fu32(e.fields,"backing_creator_tid");if(!n.creator_thread_id)n.creator_thread_id=fu32(e.fields,"creator_tid");if(!n.creator_thread_id)n.creator_thread_id=event_tid(e);n.seq=e.seq;n.t_us=e.t_us;n.coordinate_basis=CoordinateBasis::UNKNOWN;n.backing_identity="process:"+std::to_string(process_uid)+":"+kind+":"+std::to_string(bid);n.backing_path=field(e.fields,"backing_path")?*field(e.fields,"backing_path"):std::string{};n.device=fu64(e.fields,"backing_device").value_or(0);n.inode=fu64(e.fields,"backing_inode").value_or(0);n.image=e.process_image;n.evidence_state="CONFIRMED";n.detail="runtime-created backing identity";auto id=add_node(std::move(n));backings[key]=id;state(id).zero_initialized_basis=true;if(auto it=backing_nonzero_capture.find({process_uid,bid});it!=backing_nonzero_capture.end()&&it->second)state(id).write_confirmed=true;return id;
    }
    int region_code(MaterializationNodeKind k)const{return static_cast<int>(k);}
    std::uint64_t ensure_region(const TimelineEvent&e,std::uint64_t process_uid,std::uint64_t start,std::uint64_t end,MaterializationNodeKind kind,bool cross=false){
        if(end<=start) end=start+1;
        auto key=std::make_tuple(process_uid,start,end,region_code(kind));
        if(auto it=regions.find(key);it!=regions.end()) return it->second;
        // First try an overlapping region of the same semantic kind. Runtime APIs often page-align protection ranges.
        for(const auto&kv:regions){auto [pu,a,b,k]=kv.first;if(pu==process_uid&&k==region_code(kind)&&a<end&&b>start)return kv.second;}
        MaterializationNode n;n.kind=kind;n.process_uid=process_uid;n.pid=process_uid==e.process_uid?e.pid:fu32(e.fields,"target_pid").value_or(0);n.thread_id=process_uid==e.process_uid?event_tid(e):std::optional<std::uint32_t>{};n.seq=e.seq;n.t_us=e.t_us;n.coordinate_space=CoordinateSpace::VA;n.coordinate_basis=CoordinateBasis::MEMORY_REGION;n.address=start;n.size=end-start;n.image=e.process_image;n.cross_process=cross;n.evidence_state="OBSERVED";n.backing_identity="process:"+std::to_string(process_uid)+":va:0x"+hex(start)+"-0x"+hex(end);auto id=add_node(std::move(n));regions[key]=id;auto it=region_nonzero_capture.find({process_uid,start,end});if(it!=region_nonzero_capture.end()&&it->second)state(id).write_confirmed=true;return id;
    }
    static std::string hex(std::uint64_t v){std::ostringstream o;o<<std::hex<<v;return o.str();}
    MaterializationNodeKind region_kind(const TimelineEvent&e,bool cross=false)const{
        auto rel=field(e.fields,"image_relation");if(!rel)rel=field(e.fields,"target_image_relation");if(rel&&*rel=="replacement_at_original_base")return MaterializationNodeKind::REPLACEMENT_IMAGE;if(rel&&*rel=="original_image")return MaterializationNodeKind::ORIGINAL_IMAGE_REGION;if(cross)return MaterializationNodeKind::CROSS_PROCESS_REGION;return MaterializationNodeKind::ANONYMOUS_REGION;
    }
    std::optional<std::uint64_t> existing_region(std::uint64_t process_uid,std::uint64_t start,std::uint64_t end) const {
        if(end<=start) end=start+1;
        for(const auto&kv:regions){auto [pu,a,b,k]=kv.first;(void)k;if(pu==process_uid&&a<end&&b>start)return kv.second;}
        return {};
    }
    std::optional<std::uint64_t> existing_region_for_execution(const TimelineEvent&e){
        auto start=fu64(e.fields,"range_start");if(!start)start=fu64(e.fields,"address");if(!start)start=parse_u64(e.subject);if(!start)return{};
        auto end=fu64(e.fields,"range_end");if(!end)end=*start+std::max<std::uint64_t>(1,fu64(e.fields,"size").value_or(1));
        for(const auto&kv:regions){auto [pu,a,b,k]=kv.first;if(pu!=e.process_uid||a>=*end||b<=*start)continue;auto kind=static_cast<MaterializationNodeKind>(k);if(kind==MaterializationNodeKind::CROSS_PROCESS_REGION||kind==MaterializationNodeKind::REPLACEMENT_IMAGE||kind==MaterializationNodeKind::ORIGINAL_IMAGE_REGION)return kv.second;}
        return{};
    }
    std::uint64_t event_region(const TimelineEvent&e,std::uint64_t process_uid,bool cross=false){
        auto start=fu64(e.fields,"range_start");if(!start)start=fu64(e.fields,"address");std::uint64_t size=fu64(e.fields,"written_bytes").value_or(fu64(e.fields,"size").value_or(1));auto end=fu64(e.fields,"range_end");if(!end&&start)end=*start+std::max<std::uint64_t>(1,size);if(!start){auto s=parse_u64(e.subject);start=s;}return ensure_region(e,process_uid,start.value_or(0),end.value_or(start.value_or(0)+std::max<std::uint64_t>(1,size)),region_kind(e,cross),cross);
    }
    std::optional<std::uint64_t> roll_same_mapping_mutation(const TimelineEvent&e,std::uint64_t process_uid){
        if(!field_is(e.fields,"runtime_mutation_generation_candidate","true"))return{};
        auto start=fu64(e.fields,"mapping_range_start"),end=fu64(e.fields,"mapping_range_end");
        if(!start||!end||*end<=*start)return{};
        auto key=std::make_tuple(process_uid,*start,*end,region_code(MaterializationNodeKind::ANONYMOUS_REGION));
        auto it=regions.find(key);if(it==regions.end())return{};
        const auto prior=it->second;if(node(prior).kind!=MaterializationNodeKind::ANONYMOUS_REGION||!node(prior).executed||!node(prior).generation)return{};
        MaterializationNode n;n.kind=MaterializationNodeKind::ANONYMOUS_REGION;n.process_uid=process_uid;n.pid=e.pid;n.thread_id=event_tid(e);n.creator_process_uid=node(prior).creator_process_uid;n.creator_thread_id=node(prior).creator_thread_id;n.writer_process_uid=e.process_uid;n.writer_thread_id=event_tid(e);n.write_first_seq=e.seq;n.write_last_seq=e.seq;n.seq=e.seq;n.t_us=e.t_us;n.coordinate_space=CoordinateSpace::VA;n.coordinate_basis=CoordinateBasis::MEMORY_REGION;n.address=*start;n.size=*end-*start;n.image=e.process_image;n.evidence_state="CONFIRMED";n.backing_identity=node(prior).backing_identity+":mutation:"+std::to_string(e.seq);n.detail="same anonymous mapping bytes changed after a prior confirmed execution; awaiting post-mutation execution before assigning the next generation";
        auto id=add_node(std::move(n));regions[key]=id;state(id).write_confirmed=true;state(id).write_edge_emitted=true;state(id).mutation_parent_generation=node(prior).generation;
        add_edge(prior,id,MaterializationEdgeKind::MUTATED_FROM,&e,"CONFIRMED","bounded same-mapping byte mutation observed after prior confirmed execution; generation advances only if this mutated mapping is later actually executed");
        auto rs=fu64(e.fields,"range_start"),re=fu64(e.fields,"range_end");if(rs){g.edges.back().address=*rs;if(re&&*re>*rs)g.edges.back().size=*re-*rs;}
        return id;
    }
    void start_event(const TimelineEvent&e){
        auto scope=field(e.fields,"scope");const bool thread_start=scope&&(*scope=="root_thread"||*scope=="child_thread");if(thread_start){auto tid=event_tid(e);auto pt=fu32(e.fields,"parent_thread_tid");if(tid&&pt){auto gi=thread_generation.find({e.process_uid,*pt});if(gi!=thread_generation.end())thread_generation[{e.process_uid,*tid}]=gi->second;auto ni=thread_node.find({e.process_uid,*pt});if(ni!=thread_node.end())thread_node[{e.process_uid,*tid}]=ni->second;}return;}
        if(e.subject=="runtime_backing_exec_handoff"&&(field_is(e.fields,"exec_image_identity_match","true"))){
            auto bid=fu64(e.fields,"backing_id");auto bk=field(e.fields,"backing_kind");if(bid&&bk){std::string kk=*bk;if(kk.rfind("runtime_",0)==0)kk=kk.substr(8);auto b=ensure_backing(e,e.process_uid,kk,*bid);state(b).exact_exec_handoff=true;state(b).executable_transition=true;state(b).write_confirmed=state(b).write_confirmed||fu64(e.fields,"backing_write_bytes").value_or(0)>0||backing_nonzero_capture[{e.process_uid,*bid}];if(state(b).write_confirmed&&!state(b).write_edge_emitted){add_edge({},b,MaterializationEdgeKind::MATERIALIZED_BY_RUNTIME,&e,"CONFIRMED","runtime backing contains materialized bytes before exact exec handoff; writer identity, write time, and source byte generation remain UNKNOWN",{});state(b).write_edge_emitted=true;}assign_generation(b);node(b).executed=true;if(!node(b).first_execution_seq){node(b).first_execution_process_uid=e.process_uid;node(b).first_execution_thread_id=event_tid(e);node(b).first_execution_seq=e.seq;}node(b).evidence_state=node(b).generation?"CONFIRMED":"PROVENANCE_UNKNOWN";auto repl=ensure_region(e,e.process_uid,0,1,MaterializationNodeKind::REPLACEMENT_IMAGE,false);node(repl).backing_identity=node(b).backing_identity;node(repl).backing_path=field(e.fields,"exec_image_path")?*field(e.fields,"exec_image_path"):node(b).backing_path;node(repl).coordinate_space=CoordinateSpace::UNKNOWN;node(repl).coordinate_basis=CoordinateBasis::PROCESS_IMAGE;node(repl).address=0;node(repl).size=0;node(repl).executed=true;node(repl).generation=node(b).generation;node(repl).creator_process_uid=node(b).creator_process_uid;node(repl).creator_thread_id=node(b).creator_thread_id;node(repl).writer_process_uid=node(b).writer_process_uid;node(repl).writer_thread_id=node(b).writer_thread_id;node(repl).writer_execution_generation=node(b).writer_execution_generation;node(repl).write_first_seq=node(b).write_first_seq;node(repl).write_last_seq=node(b).write_last_seq;node(repl).first_execution_process_uid=e.process_uid;node(repl).first_execution_thread_id=event_tid(e);node(repl).first_execution_seq=e.seq;state(repl).write_confirmed=state(b).write_confirmed;state(repl).exact_exec_handoff=true;add_edge(b,repl,MaterializationEdgeKind::EXEC_HANDOFF_TO,&e,"CONFIRMED","exact runtime backing identity matched executed image");if(node(repl).generation){latest_executed_node[e.process_uid]=repl;auto tid=event_tid(e);if(tid){thread_generation[{e.process_uid,*tid}]=*node(repl).generation;thread_node[{e.process_uid,*tid}]=repl;}}return;}
        }
        auto oid=ensure_original(e);(void)oid;
        // Child process inherited backing identities are explicit when instrumentation can prove them.
        if(auto ids=field(e.fields,"inherited_backing_ids");ids&&e.parent_uid){std::istringstream is(*ids);std::string tok;while(std::getline(is,tok,',')){auto bid=parse_u64(tok);if(!bid)continue;for(auto &kv:backings){auto [pu,k,b]=kv.first;if(pu!=e.parent_uid||b!=*bid)continue;auto child=ensure_backing(e,e.process_uid,k,b);auto parent=kv.second;node(child).backing_path=node(parent).backing_path;node(child).device=node(parent).device;node(child).inode=node(parent).inode;node(child).creator_process_uid=node(parent).creator_process_uid;node(child).creator_thread_id=node(parent).creator_thread_id;node(child).writer_process_uid=node(parent).writer_process_uid;node(child).writer_thread_id=node(parent).writer_thread_id;node(child).writer_execution_generation=node(parent).writer_execution_generation;node(child).write_first_seq=node(parent).write_first_seq;node(child).write_last_seq=node(parent).write_last_seq;state(child)=state(parent);node(child).generation=node(parent).generation;add_edge(parent,child,MaterializationEdgeKind::CHILD_INHERITED,&e,"CONFIRMED","runtime backing identity inherited across child creation");break;}}}
    }
    void allocation_event(const TimelineEvent&e){
        auto bid=fu64(e.fields,"backing_id");auto bk=field(e.fields,"backing_kind");std::uint64_t id=0;
        if(bid&&bk){std::string kk=*bk;if(kk.rfind("runtime_",0)==0)kk=kk.substr(8);id=ensure_backing(e,e.process_uid,kk,*bid);}
        else {
            auto target_uid=fu64(e.fields,"target_process_uid").value_or(e.process_uid);const bool cross=target_uid!=e.process_uid;
            auto rel=field(e.fields,"image_relation");if(!rel)rel=field(e.fields,"target_image_relation");
            const bool image_materialization=rel&&(*rel=="original_image"||*rel=="replacement_at_original_base");
            if(field_is(e.fields,"anonymous","true")||field_is(e.fields,"materialization_candidate","true")||cross||image_materialization){
                id=event_region(e,target_uid,cross);state(id).zero_initialized_basis=field_is(e.fields,"anonymous","true")||field_is(e.fields,"materialization_candidate","true");node(id).creator_process_uid=e.process_uid;node(id).creator_thread_id=event_tid(e);node(id).cross_process=node(id).cross_process||cross;
            }
        }
        if(id){auto src=active_node(e);add_edge(src,id,MaterializationEdgeKind::ALLOCATED_FROM,&e,"OBSERVED","allocation/mapping fact only; does not assign a generation",active_generation(e));}
    }
    void write_event(const TimelineEvent&e){
        bool confirmed=true;if(auto st=field(e.fields,"success"))confirmed=*st=="true";if(auto st=field(e.fields,"state"))confirmed=confirmed&&(*st=="CONFIRMED"||*st=="CHANGED_SINCE_PROCESS_CREATE");if(fu64(e.fields,"written_bytes").value_or(1)==0)confirmed=false;
        std::uint64_t id=0;std::uint64_t target_uid=e.process_uid;bool cross=false;auto bid=fu64(e.fields,"backing_id");auto bk=field(e.fields,"backing_kind");const bool mutation_candidate=confirmed&&field_is(e.fields,"runtime_mutation_generation_candidate","true");
        if(bid&&bk){std::string kk=*bk;if(kk.rfind("runtime_",0)==0)kk=kk.substr(8);id=ensure_backing(e,e.process_uid,kk,*bid);}
        else{
            if(auto t=fu64(e.fields,"target_process_uid")){target_uid=*t;cross=target_uid!=e.process_uid;}
            if(mutation_candidate){auto rolled=roll_same_mapping_mutation(e,target_uid);if(rolled)id=*rolled;}
            if(!id)id=event_region(e,target_uid,cross);
        }
        if(confirmed){
            state(id).write_confirmed=true;node(id).writer_process_uid=e.process_uid;node(id).writer_thread_id=event_tid(e);if(!node(id).write_first_seq)node(id).write_first_seq=e.seq;node(id).write_last_seq=e.seq;node(id).evidence_state="CONFIRMED";
            if(!mutation_candidate){auto wg=active_generation(e);state(id).writer_execution_generation=wg;node(id).writer_execution_generation=wg;}
        }
        if(mutation_candidate&&state(id).mutation_parent_generation){return;}
        auto src=active_node(e);MaterializationEdgeKind ek=MaterializationEdgeKind::MATERIALIZED_BY_RUNTIME;std::optional<std::uint64_t>byte_src;
        // Exact source-buffer containment is the only existing Windows fact strong enough for WRITTEN_FROM.
        if(auto sb=fu64(e.fields,"source_buffer")){for(const auto&n:g.nodes)if(n.process_uid==e.process_uid&&n.address&&n.size&&*sb>=n.address&&*sb<n.address+n.size&&n.generation){byte_src=n.id;state(id).byte_source_generation=n.generation;ek=MaterializationEdgeKind::WRITTEN_FROM;break;}}
        if(node(id).kind==MaterializationNodeKind::ORIGINAL_IMAGE_REGION){auto oi=original.find(target_uid);add_edge(oi==original.end()?std::optional<std::uint64_t>{}:std::optional<std::uint64_t>{oi->second},id,MaterializationEdgeKind::MUTATED_FROM,&e,confirmed?"CONFIRMED":"FAILED","original image region differs from the process-create baseline; incoming byte source may remain UNKNOWN",active_generation(e));}
        if(ek==MaterializationEdgeKind::WRITTEN_FROM)add_edge(byte_src,id,ek,&e,confirmed?"CONFIRMED":"FAILED","source buffer lies inside a generation-known runtime node",active_generation(e));
        else if(node(id).kind!=MaterializationNodeKind::ORIGINAL_IMAGE_REGION)add_edge(src,id,ek,&e,confirmed?"CONFIRMED":"FAILED","runtime write observed; source byte generation intentionally UNKNOWN",active_generation(e));
        if(confirmed)state(id).write_edge_emitted=true;
    }
    void protect_event(const TimelineEvent&e){
        if(!executable_protection(e.fields))return;
        std::uint64_t id=0;auto bid=fu64(e.fields,"backing_id");auto bk=field(e.fields,"backing_kind");
        if(bid&&bk){std::string kk=*bk;if(kk.rfind("runtime_",0)==0)kk=kk.substr(8);id=ensure_backing(e,e.process_uid,kk,*bid);}
        else {
            auto target_uid=fu64(e.fields,"target_process_uid").value_or(e.process_uid);const bool cross=target_uid!=e.process_uid;
            auto start=fu64(e.fields,"range_start");if(!start)start=fu64(e.fields,"address");auto end=fu64(e.fields,"range_end");if(!end&&start)end=*start+std::max<std::uint64_t>(1,fu64(e.fields,"size").value_or(1));
            if(start){auto existing=existing_region(target_uid,*start,end.value_or(*start+1));if(existing)id=*existing;}
            auto rel=field(e.fields,"image_relation");if(!rel)rel=field(e.fields,"target_image_relation");
            const bool materialization_evidence=field_is(e.fields,"materialization_candidate","true")||field_is(e.fields,"armed_execute_breakpoint","true")||cross||(rel&&(*rel=="original_image"||*rel=="replacement_at_original_base"));
            if(!id&&materialization_evidence)id=event_region(e,target_uid,cross);
        }
        if(!id)return;
        state(id).executable_transition=true;add_edge(id,id,MaterializationEdgeKind::PROTECTED_EXECUTABLE,&e,field_is(e.fields,"success","false")?"FAILED":"CONFIRMED","observed executable protection/arm; generation is not assigned by protection alone");
    }
    void assign_generation(std::uint64_t id){
        auto&n=node(id);auto&s=state(id);if(n.generation||!s.write_confirmed)return;std::optional<std::uint32_t>base=s.mutation_parent_generation?s.mutation_parent_generation:s.writer_execution_generation;if(base)n.generation=*base+1;else if(!processes_with_generated_execution.count(n.process_uid))n.generation=1; // first confirmed runtime materialization after observed gen0; exact writer remains unknown
        if(n.generation)n.evidence_state="CONFIRMED";else n.evidence_state="PROVENANCE_UNKNOWN";
    }
    void execute_event(const TimelineEvent&e){
        std::uint64_t id=0;auto bid=fu64(e.fields,"backing_id");auto bk=field(e.fields,"backing_kind");if(bid&&bk){std::string kk=*bk;if(kk.rfind("runtime_",0)==0)kk=kk.substr(8);id=ensure_backing(e,e.process_uid,kk,*bid);if(backing_nonzero_capture[{e.process_uid,*bid}])state(id).write_confirmed=true;if(fu64(e.fields,"backing_write_bytes").value_or(0)>0)state(id).write_confirmed=true;}
        else{id=existing_region_for_execution(e).value_or(event_region(e,e.process_uid));auto k=std::make_tuple(e.process_uid,node(id).address,node(id).address+node(id).size);if(region_nonzero_capture[k]&&node(id).kind==MaterializationNodeKind::ANONYMOUS_REGION){state(id).write_confirmed=true;state(id).zero_initialized_basis=true;}if(fu64(e.fields,"changed_bytes").value_or(0)>0){state(id).write_confirmed=true;}}
        state(id).executable_transition=true;
        if(state(id).write_confirmed&&!state(id).write_edge_emitted){add_edge({},id,MaterializationEdgeKind::MATERIALIZED_BY_RUNTIME,&e,"CONFIRMED","nonzero execution-time bytes prove materialization of a runtime-created zero-based region/backing; writer identity, write time, and source byte generation remain UNKNOWN",{});state(id).write_edge_emitted=true;}
        state(id).executor_prior_generation=active_generation(e);state(id).executor_tid=event_tid(e);assign_generation(id);if(!node(id).generation)node(id).evidence_state="PROVENANCE_UNKNOWN";node(id).executed=true;node(id).thread_id=event_tid(e);const auto exec_addr=fu64(e.fields,"address");if(!node(id).first_execution_seq){node(id).first_execution_process_uid=e.process_uid;node(id).first_execution_thread_id=event_tid(e);node(id).first_execution_seq=e.seq;if(exec_addr)node(id).first_execution_address=*exec_addr;}node(id).seq=e.seq;node(id).t_us=e.t_us;add_edge(id,id,MaterializationEdgeKind::FIRST_EXECUTED_AS,&e,"CONFIRMED",node(id).generation?"first execution of confirmed runtime materialization":"execution observed without sufficient prior write/source evidence");if(exec_addr){g.edges.back().address=*exec_addr;g.edges.back().size=1;}
        if(node(id).generation){processes_with_generated_execution.insert(e.process_uid);latest_executed_node[e.process_uid]=id;if(auto tid=event_tid(e)){thread_generation[{e.process_uid,*tid}]=*node(id).generation;thread_node[{e.process_uid,*tid}]=id;}}
        if(node(id).kind==MaterializationNodeKind::ORIGINAL_IMAGE_REGION&&fu64(e.fields,"changed_bytes").value_or(0)>0){RuntimeSemanticDivergence d;d.seq=e.seq;d.process_uid=e.process_uid;d.kind="EXECUTION_TIME_IMAGE_BYTES_CHANGED";d.static_expectation="process-create original-image executable baseline";d.runtime_observation="first executed region differs from baseline";g.divergences.push_back(std::move(d));}
    }
    std::optional<std::uint64_t> find_source_for_artifact(const RuntimeArtifact&a){
        if(auto execute_seq=fu64(a.fields,"materialization_execute_seq")){for(const auto&n:g.nodes)if(n.process_uid==a.process_uid&&n.first_execution_seq==*execute_seq)return n.id;}
        if(auto bid=fu64(a.fields,"backing_id")){std::string k=field(a.fields,"backing_kind")?*field(a.fields,"backing_kind"):"memfd";if(k.rfind("runtime_",0)==0)k=k.substr(8);auto it=backings.find({a.process_uid,k,*bid});if(it!=backings.end())return it->second;for(const auto&kv:backings){auto [pu,kk,b]=kv.first;if(pu==a.process_uid&&b==*bid)return kv.second;}}
        auto start=fu64(a.fields,"memory_address");if(!start)start=fu64(a.fields,"region_start");if(start){for(const auto&n:g.nodes)if(n.process_uid==a.process_uid&&n.address&&n.size&&*start>=n.address&&*start<n.address+n.size&&!artifacts.count(n.backing_path))return n.id;}
        auto it=latest_executed_node.find(a.process_uid);if(it!=latest_executed_node.end())return it->second;auto oi=original.find(a.process_uid);if(oi!=original.end())return oi->second;return{};
    }
    void artifacts_phase(){
        for(const auto&a:r.artifacts){if(a.kind=="unpack_diagnostic"||a.kind=="materialization_graph")continue;MaterializationNodeKind kind;if(a.kind=="materialized_region")kind=MaterializationNodeKind::MEMORY_DUMP;else if(a.kind=="reconstructed_elf"||a.kind=="unpacked_pe"||a.kind=="runtime_backing_elf")kind=MaterializationNodeKind::RECONSTRUCTED_IMAGE;else continue;MaterializationNode n;n.kind=kind;n.process_uid=a.process_uid;n.pid=a.pid;n.coordinate_space=CoordinateSpace::FILE_OFFSET;n.coordinate_basis=CoordinateBasis::ARTIFACT_FILE;n.backing_path=path_utf8(a.path);n.backing_identity=a.path.empty()?a.kind:path_utf8(a.path);n.sha256=artifact_sha(a);n.evidence_state=a.state;n.detail=a.detail;n.executed=a.state.find("EXEC_HANDOFF")!=std::string::npos||a.state=="UNPACKED_VALIDATED";auto id=add_node(std::move(n));artifacts[path_utf8(a.path)]=id;auto src=find_source_for_artifact(a);if(src){node(id).generation=node(*src).generation;node(id).creator_process_uid=node(*src).creator_process_uid;node(id).creator_thread_id=node(*src).creator_thread_id;node(id).writer_process_uid=node(*src).writer_process_uid;node(id).writer_thread_id=node(*src).writer_thread_id;node(id).writer_execution_generation=node(*src).writer_execution_generation;node(id).write_first_seq=node(*src).write_first_seq;node(id).write_last_seq=node(*src).write_last_seq;node(id).first_execution_process_uid=node(*src).first_execution_process_uid;node(id).first_execution_thread_id=node(*src).first_execution_thread_id;node(id).first_execution_seq=node(*src).first_execution_seq;node(id).first_execution_address=node(*src).first_execution_address;}MaterializationEdgeKind ek=kind==MaterializationNodeKind::MEMORY_DUMP?MaterializationEdgeKind::DUMPED_AS:MaterializationEdgeKind::RECONSTRUCTED_AS;add_edge(src,id,ek,nullptr,"CONFIRMED",kind==MaterializationNodeKind::MEMORY_DUMP?"captured runtime memory artifact":"runtime-derived reconstructed/snapshotted image artifact");
            if(a.state=="UNPACKED_VALIDATED"&&replacement&&replacement->performed){MaterializationNode in;in.kind=MaterializationNodeKind::INSTALLED_VALIDATED_IMAGE;in.generation=node(id).generation;in.executed=true;in.process_uid=a.process_uid;in.creator_process_uid=node(id).creator_process_uid;in.creator_thread_id=node(id).creator_thread_id;in.writer_process_uid=node(id).writer_process_uid;in.writer_thread_id=node(id).writer_thread_id;in.writer_execution_generation=node(id).writer_execution_generation;in.write_first_seq=node(id).write_first_seq;in.write_last_seq=node(id).write_last_seq;in.first_execution_process_uid=node(id).first_execution_process_uid;in.first_execution_thread_id=node(id).first_execution_thread_id;in.first_execution_seq=node(id).first_execution_seq;in.first_execution_address=node(id).first_execution_address;in.pid=a.pid;in.coordinate_space=CoordinateSpace::FILE_OFFSET;in.coordinate_basis=CoordinateBasis::CURRENT_INPUT_FILE;in.backing_path=path_utf8(replacement->target);in.backing_identity=path_utf8(replacement->target);in.sha256=replacement->new_sha256;in.evidence_state="UNPACKED_VALIDATED";in.detail="validated runtime-derived image transactionally installed";auto iid=add_node(std::move(in));add_edge(id,iid,MaterializationEdgeKind::INSTALLED_AS,nullptr,"CONFIRMED","standalone-validated image installed at target path");if(replacement->original_sha256!=replacement->new_sha256){RuntimeSemanticDivergence d;d.process_uid=a.process_uid;d.kind="INSTALLED_IMAGE_HASH_CHANGED";d.static_expectation="original_sha256="+replacement->original_sha256;d.runtime_observation="installed_runtime_validated_sha256="+replacement->new_sha256;g.divergences.push_back(std::move(d));}}
        }
    }
    void semantic_exec_handoff_divergence(const TimelineEvent&e){if(e.subject!="runtime_backing_exec_handoff"||!field_is(e.fields,"exec_image_identity_match","true"))return;auto oi=original.find(e.process_uid);std::string initial=oi!=original.end()?node(oi->second).image:e.process_image;auto target=field(e.fields,"exec_image_path");if(!target)target=field(e.fields,"backing_path");if(target&&!initial.empty()&&*target!=initial){RuntimeSemanticDivergence d;d.seq=e.seq;d.process_uid=e.process_uid;d.kind="RUNTIME_EXEC_TARGET_DIVERGED";d.static_expectation="initial_image="+initial;d.runtime_observation="runtime_materialized_exec_target="+*target;g.divergences.push_back(std::move(d));}}
    void final_edges(){for(auto&e:g.edges){if(e.kind!=MaterializationEdgeKind::MATERIALIZED_BY_RUNTIME&&e.kind!=MaterializationEdgeKind::PROTECTED_EXECUTABLE&&e.kind!=MaterializationEdgeKind::FIRST_EXECUTED_AS&&e.source_node)e.source_generation=node(*e.source_node).generation;if(e.kind==MaterializationEdgeKind::MATERIALIZED_BY_RUNTIME)e.source_generation.reset();}}
    void summarize(){std::set<std::uint32_t>gens,exec,image,memory,cross;for(const auto&n:g.nodes)if(n.generation){gens.insert(*n.generation);if(n.executed)exec.insert(*n.generation);if(image_kind(n.kind))image.insert(*n.generation);if(memory_kind(n.kind)&&*n.generation>0)memory.insert(*n.generation);if(n.cross_process)cross.insert(*n.generation);}std::uint32_t memory_only=0;for(auto gen:memory)if(!image.count(gen))++memory_only;g.summary.generation_count=static_cast<std::uint32_t>(gens.size());g.summary.deepest_confirmed_generation=gens.empty()?0:*gens.rbegin();g.summary.executed_generation_count=static_cast<std::uint32_t>(exec.size());g.summary.image_generation_count=static_cast<std::uint32_t>(image.size());g.summary.memory_only_generation_count=memory_only;g.summary.cross_process_generation_count=static_cast<std::uint32_t>(cross.size());for(const auto&e:g.edges)if(e.kind==MaterializationEdgeKind::MATERIALIZED_BY_RUNTIME&&!e.source_generation)++g.summary.provenance_unknown_edge_count;g.summary.partial=r.timed_out;}
    MaterializationGraph run(){for(const auto&e:r.timeline){switch(e.kind){case TimelineKind::ProcessStart:start_event(e);semantic_exec_handoff_divergence(e);break;case TimelineKind::MemoryAllocate:case TimelineKind::FileCreate:allocation_event(e);break;case TimelineKind::MemoryWrite:case TimelineKind::FileWrite:write_event(e);break;case TimelineKind::MemoryProtect:protect_event(e);break;case TimelineKind::MaterializedExecute:execute_event(e);break;default:break;}}artifacts_phase();final_edges();summarize();return std::move(g);}
};

} // namespace

const char* materialization_node_kind_name(MaterializationNodeKind k){switch(k){case MaterializationNodeKind::ORIGINAL_IMAGE:return "ORIGINAL_IMAGE";case MaterializationNodeKind::ORIGINAL_IMAGE_REGION:return "ORIGINAL_IMAGE_REGION";case MaterializationNodeKind::ANONYMOUS_REGION:return "ANONYMOUS_REGION";case MaterializationNodeKind::MEMFD_BACKING:return "MEMFD_BACKING";case MaterializationNodeKind::O_TMPFILE_BACKING:return "O_TMPFILE_BACKING";case MaterializationNodeKind::RELEASED_FILE:return "RELEASED_FILE";case MaterializationNodeKind::CROSS_PROCESS_REGION:return "CROSS_PROCESS_REGION";case MaterializationNodeKind::REPLACEMENT_IMAGE:return "REPLACEMENT_IMAGE";case MaterializationNodeKind::MEMORY_DUMP:return "MEMORY_DUMP";case MaterializationNodeKind::RECONSTRUCTED_IMAGE:return "RECONSTRUCTED_IMAGE";case MaterializationNodeKind::INSTALLED_VALIDATED_IMAGE:return "INSTALLED_VALIDATED_IMAGE";}return "UNKNOWN";}
const char* materialization_edge_kind_name(MaterializationEdgeKind k){switch(k){case MaterializationEdgeKind::ALLOCATED_FROM:return "ALLOCATED_FROM";case MaterializationEdgeKind::WRITTEN_FROM:return "WRITTEN_FROM";case MaterializationEdgeKind::MUTATED_FROM:return "MUTATED_FROM";case MaterializationEdgeKind::COPIED_FROM:return "COPIED_FROM";case MaterializationEdgeKind::MATERIALIZED_BY_RUNTIME:return "MATERIALIZED_BY_RUNTIME";case MaterializationEdgeKind::PROTECTED_EXECUTABLE:return "PROTECTED_EXECUTABLE";case MaterializationEdgeKind::FIRST_EXECUTED_AS:return "FIRST_EXECUTED_AS";case MaterializationEdgeKind::DUMPED_AS:return "DUMPED_AS";case MaterializationEdgeKind::RECONSTRUCTED_AS:return "RECONSTRUCTED_AS";case MaterializationEdgeKind::EXEC_HANDOFF_TO:return "EXEC_HANDOFF_TO";case MaterializationEdgeKind::INSTALLED_AS:return "INSTALLED_AS";case MaterializationEdgeKind::CHILD_INHERITED:return "CHILD_INHERITED";}return "UNKNOWN";}

MaterializationGraph build_materialization_graph(const RuntimeReport&r,const ReplacementReport*replacement){return Builder(r,replacement).run();}

bool write_materialization_graph_csv(const MaterializationGraph&g,const std::filesystem::path&nodes,const std::filesystem::path&edges,std::string&error){
    std::error_code ec;auto dir=nodes.parent_path();if(!dir.empty())std::filesystem::create_directories(dir,ec);if(ec){error="cannot create materialization graph directory: "+ec.message();return false;}std::ofstream nf(nodes,std::ios::trunc);if(!nf){error="cannot create "+path_utf8(nodes);return false;}nf<<"node_id,kind,generation,executed,process_uid,pid,thread_id,creator_process_uid,creator_thread_id,writer_process_uid,writer_thread_id,writer_execution_generation,write_first_seq,write_last_seq,first_execution_process_uid,first_execution_thread_id,first_execution_seq,first_execution_address,seq,t_us,coordinate_space,coordinate_basis,address,size,backing_identity,backing_path,device,inode,sha256,evidence_state,image,cross_process,detail\n";for(const auto&n:g.nodes)nf<<n.id<<','<<materialization_node_kind_name(n.kind)<<','<<optu(n.generation)<<','<<(n.executed?"true":"false")<<','<<n.process_uid<<','<<n.pid<<','<<(n.thread_id?std::to_string(*n.thread_id):"UNKNOWN")<<','<<n.creator_process_uid<<','<<(n.creator_thread_id?std::to_string(*n.creator_thread_id):"UNKNOWN")<<','<<n.writer_process_uid<<','<<(n.writer_thread_id?std::to_string(*n.writer_thread_id):"UNKNOWN")<<','<<optu(n.writer_execution_generation)<<','<<n.write_first_seq<<','<<n.write_last_seq<<','<<n.first_execution_process_uid<<','<<(n.first_execution_thread_id?std::to_string(*n.first_execution_thread_id):"UNKNOWN")<<','<<n.first_execution_seq<<",0x"<<std::hex<<n.first_execution_address<<std::dec<<','<<n.seq<<','<<n.t_us<<','<<space_name(n.coordinate_space)<<','<<basis_name(n.coordinate_basis)<<",0x"<<std::hex<<n.address<<std::dec<<','<<n.size<<','<<csvq(n.backing_identity)<<','<<csvq(n.backing_path)<<','<<n.device<<','<<n.inode<<','<<csvq(n.sha256)<<','<<csvq(n.evidence_state)<<','<<csvq(n.image)<<','<<(n.cross_process?"true":"false")<<','<<csvq(n.detail)<<'\n';if(!nf){error="write failed for "+path_utf8(nodes);return false;}std::ofstream ef(edges,std::ios::trunc);if(!ef){error="cannot create "+path_utf8(edges);return false;}ef<<"edge_id,source_node,destination_node,kind,source_generation,destination_generation,writer_execution_generation,process_uid,thread_id,seq,t_us,evidence_state,coordinate_basis,address,size,detail\n";for(const auto&e:g.edges){std::optional<std::uint32_t>dg;if(e.destination_node&&e.destination_node<=g.nodes.size())dg=g.nodes[static_cast<std::size_t>(e.destination_node-1)].generation;ef<<e.id<<','<<optid(e.source_node)<<','<<e.destination_node<<','<<materialization_edge_kind_name(e.kind)<<','<<optu(e.source_generation)<<','<<optu(dg)<<','<<optu(e.writer_execution_generation)<<','<<e.process_uid<<','<<(e.thread_id?std::to_string(*e.thread_id):"UNKNOWN")<<','<<e.seq<<','<<e.t_us<<','<<csvq(e.evidence_state)<<','<<basis_name(e.coordinate_basis)<<",0x"<<std::hex<<e.address<<std::dec<<','<<e.size<<','<<csvq(e.detail)<<'\n';}if(!ef){error="write failed for "+path_utf8(edges);return false;}return true;
}

void finalize_materialization_graph(AnalysisReport&report,const std::filesystem::path&artifact_dir){
    auto g=build_materialization_graph(report.runtime,&report.replacement);const auto np=artifact_dir/"materialization-graph.csv",ep=artifact_dir/"materialization-edges.csv";std::string err;const bool ok=write_materialization_graph_csv(g,np,ep,err);RuntimeArtifact a;a.kind="materialization_graph";a.state=ok?"CONFIRMED":"FAILED";a.path=np;a.process_uid=1;a.detail=ok?"causal runtime materialization/stage provenance graph built from Timeline and RuntimeArtifact facts":"materialization graph build succeeded but CSV persistence failed: "+err;a.fields["nodes_path"]=path_utf8(np);a.fields["edges_path"]=path_utf8(ep);a.fields["generation_count"]=std::to_string(g.summary.generation_count);a.fields["deepest_confirmed_generation"]=std::to_string(g.summary.deepest_confirmed_generation);a.fields["executed_generation_count"]=std::to_string(g.summary.executed_generation_count);a.fields["image_generation_count"]=std::to_string(g.summary.image_generation_count);a.fields["memory_only_generation_count"]=std::to_string(g.summary.memory_only_generation_count);a.fields["cross_process_generation_count"]=std::to_string(g.summary.cross_process_generation_count);a.fields["provenance_unknown_edge_count"]=std::to_string(g.summary.provenance_unknown_edge_count);a.fields["node_count"]=std::to_string(g.nodes.size());a.fields["edge_count"]=std::to_string(g.edges.size());a.fields["semantic_divergence_count"]=std::to_string(g.divergences.size());a.fields["partial"]=g.summary.partial?"true":"false";a.fields["generation_contract"]="generation requires confirmed runtime materialization plus execution/exec-handoff; allocation/protection alone never assigns a generation";a.fields["source_generation_contract"]="MATERIALIZED_BY_RUNTIME retains source_generation=UNKNOWN unless exact source-byte generation is proven";if(!g.divergences.empty()){std::ostringstream d;for(std::size_t i=0;i<g.divergences.size();++i){if(i)d<<"; ";d<<g.divergences[i].kind<<'['<<g.divergences[i].static_expectation<<" -> "<<g.divergences[i].runtime_observation<<']';if(d.tellp()>8192){d<<"; ...";break;}}a.fields["semantic_divergences"]=d.str();}report.runtime.artifacts.push_back(std::move(a));
}

} // namespace prts
