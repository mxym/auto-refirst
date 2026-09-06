#include "prts/directory_report_spool.hpp"
#include <iostream>
#include <stdexcept>

namespace {
void require(bool value,const char*message){if(!value)throw std::runtime_error(message);}
std::size_t file_count(const std::filesystem::path&root){
    std::size_t count=0;
    for(const auto&entry:std::filesystem::directory_iterator(root)){(void)entry;++count;}
    return count;
}
}

int main(){
    try{
        std::filesystem::path root;
        {
            prts::DirectoryReportSpool spool;
            require(spool.ready(),"spool initialization failed");
            std::string error;
            auto add=[&](const char*name,std::int64_t priority,std::size_t bytes){
                return spool.add(name,priority,[&](std::ostream&out){
                    const std::string block(4096,'x');
                    while(bytes){auto n=std::min(bytes,block.size());out.write(block.data(),static_cast<std::streamsize>(n));bytes-=n;}
                },error);
            };
            constexpr std::size_t mib=1024*1024;
            require(add("first",20,6*mib),"first add failed");
            root=spool.records().front().payload.parent_path();
            require(add("second",30,6*mib),"second add failed");
            // Inline deferral keeps exact bytes available for final priorities.
            require(add("low",10,6*mib),"current payload eviction failed");
            require(!spool.records().back().selected,"lower priority payload retained");
            require(file_count(root)==3,"deferred payload was not cached");
            require(add("high",40,6*mib),"previous payload eviction failed");
            require(!spool.records().front().selected,"wrong previous payload evicted");
            require(spool.records().back().selected,"high priority payload lost");
            for(unsigned i=0;i<4;++i){
                require(add("oversize",100,8*mib+1),"oversize deferral failed");
                require(file_count(root)==2,"oversize payload accumulated on disk");
                require(spool.validate(error),"disk accounting mismatch");
            }
            std::map<std::string,std::int64_t> priorities;
            for(const auto&r:spool.records())priorities[prts::spool_path_key(r.input)]=r.detail_priority;
            priorities["first"]=1000;
            require(spool.finalize_selection(priorities,error),"cache-pressure finalization failed");
            require(!spool.records().front().selected&&spool.records().front().deferred_reason=="DIRECTORY_SPOOL_CACHE_BUDGET","evicted bytes incorrectly recovered");
            auto rendering=spool.rendering();
            require(rendering.priorities_finalized&&rendering.cache_evicted_reports==2,"cache accounting missing");
            require(rendering.full_reports_rendered==2,"selected count mismatch");
            require(rendering.inline_report_bytes==12*mib,"selected byte count mismatch");
            require(rendering.full_reports_deferred==6,"deferred count mismatch");
            auto stray=root/"unexpected.report";
            {std::ofstream out(stray);out<<"unexpected";}
            require(!spool.validate(error),"unaccounted payload was not detected");
            require(std::filesystem::remove(stray),"stray cleanup failed");
            require(spool.validate(error),"restored spool failed validation");
        }
        require(!std::filesystem::exists(root),"temporary root leaked after destruction");
        {
            prts::DirectoryReportSpool spool;
            std::string error;
            const std::string bytes(6*1024*1024,'x');
            for(const auto&name:{"first","second","later"}){
                const int priority=std::string(name)=="later"?1:20;
                require(spool.add(name,priority,[&](std::ostream&out){out<<bytes;},error),"cache fixture write failed");
            }
            require(!spool.records().back().selected,"late fixture was not initially deferred");
            const auto exact_payload=spool.records().back().payload;
            require(!spool.finalize_selection({{"first",20}},error),"incomplete priorities accepted");
            require(spool.finalize_selection({{"first",20},{"second",20},{"later",100}},error),"final priority selection failed");
            require(spool.records().back().selected&&spool.records().back().payload==exact_payload,"promoted report did not reuse original payload");
            require(spool.rendering().reports_reselected==1,"reselected count mismatch");
            require(spool.rendering().spool_resident_bytes==18*1024*1024,"cached disk bytes mismatch");
            std::ifstream in(exact_payload,std::ios::binary);
            require(std::string(std::istreambuf_iterator<char>(in),{})==bytes,"cached report bytes changed");
            require(!spool.add("unexpected",1,[](std::ostream&out){out<<"x";},error),"write after final selection accepted");
        }
        {
            prts::DirectoryReportSpool spool;
            std::string error;
            require(!spool.add("failed",1,[](std::ostream&out){out.setstate(std::ios::badbit);},error),"serializer failure accepted");
            require(!error.empty(),"serializer failure has no diagnostic");
        }
        std::cout<<"PASS\n";
    }catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
}
