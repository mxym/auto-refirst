#pragma once
#include "prts/orchestration.hpp"
#include "prts/path_utf8.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <functional>
#include <limits>
#include <optional>
#include <ostream>
#include <streambuf>

namespace prts {
// The renderer is injected so storage accounting is shared by JSON and text,
// and can be tested independently of format parsing and runtime analysis.
inline std::uint64_t spool_sat_add(std::uint64_t a,std::uint64_t b){
    return b>std::numeric_limits<std::uint64_t>::max()-a?std::numeric_limits<std::uint64_t>::max():a+b;
}
inline std::string spool_path_key(const std::filesystem::path&p){return path_utf8(p.lexically_normal());}

constexpr std::uint64_t kDirectoryInlineReportBytes=16ull*1024*1024;
constexpr std::uint64_t kDirectoryPerReportBytes=8ull*1024*1024;
constexpr std::uint64_t kDirectoryReportSpoolHardBytes=kDirectoryInlineReportBytes+kDirectoryPerReportBytes;

struct DirectorySpoolRecord {
    std::filesystem::path input;
    std::filesystem::path payload;
    std::uint64_t full_bytes=0;
    std::int64_t detail_priority=0;
    bool selected=false;
    std::string deferred_reason;
};

class CappedSpoolStreambuf final:public std::streambuf {
    std::ofstream&out_;
    std::uint64_t cap_=0,total_=0,written_=0;
    bool failed_=false;
protected:
    std::streamsize xsputn(const char*s,std::streamsize n)override{
        if(n<=0)return n;
        const auto add=static_cast<std::uint64_t>(n);total_=spool_sat_add(total_,add);
        if(written_<cap_){
            const auto room=cap_-written_;const auto take=static_cast<std::streamsize>(std::min<std::uint64_t>(room,add));
            if(take>0){out_.write(s,take);if(!out_){failed_=true;return 0;}written_=spool_sat_add(written_,static_cast<std::uint64_t>(take));}
        }
        return n;
    }
    int_type overflow(int_type ch)override{
        if(traits_type::eq_int_type(ch,traits_type::eof()))return traits_type::not_eof(ch);
        const char c=traits_type::to_char_type(ch);return xsputn(&c,1)==1?ch:traits_type::eof();
    }
    int sync()override{out_.flush();if(!out_){failed_=true;return -1;}return 0;}
public:
    CappedSpoolStreambuf(std::ofstream&out,std::uint64_t cap):out_(out),cap_(cap){}
    std::uint64_t total()const{return total_;}
    std::uint64_t written()const{return written_;}
    bool failed()const{return failed_;}
};

class DirectoryReportSpool {
    std::filesystem::path root_;
    std::vector<DirectorySpoolRecord> records_;
    std::string error_;
    std::uint64_t selected_bytes_=0;
    std::uint64_t peak_bytes_=0;
    std::uint64_t known_full_bytes_=0;

    bool record_better(const DirectorySpoolRecord&a,const DirectorySpoolRecord&b)const{
        if(a.detail_priority!=b.detail_priority)return a.detail_priority>b.detail_priority;
        if(a.full_bytes!=b.full_bytes)return a.full_bytes<b.full_bytes;
        return spool_path_key(a.input)<spool_path_key(b.input);
    }
    bool remove_payload(const std::filesystem::path&path,std::string&error){
        std::error_code ec;
        if(!std::filesystem::remove(path,ec)||ec){
            error="cannot remove deferred directory report spool: "+(ec?error_message_utf8(ec):"payload is missing");
            error_=error;
            return false;
        }
        return true;
    }
    bool drop_record(std::size_t i,const char*reason,std::string&error){
        auto&r=records_[i];
        if(!remove_payload(r.payload,error))return false;
        r.selected=false;r.deferred_reason=reason;selected_bytes_-=r.full_bytes;
        r.payload.clear();
        return true;
    }
    bool enforce_inline_budget(std::string&error){
        while(selected_bytes_>kDirectoryInlineReportBytes){
            std::optional<std::size_t>worst;
            for(std::size_t i=0;i<records_.size();++i)if(records_[i].selected&&(!worst||record_better(records_[*worst],records_[i])))worst=i;
            if(!worst){error="internal directory report selection invariant failed";return false;}
            if(!drop_record(*worst,"DIRECTORY_INLINE_REPORT_BUDGET",error))return false;
        }
        return true;
    }
public:
    DirectoryReportSpool(){
        std::error_code ec;auto base=std::filesystem::temp_directory_path(ec);if(ec){error_="cannot locate temporary directory for report spool: "+prts::error_message_utf8(ec);return;}
        const auto nonce=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        for(unsigned attempt=0;attempt<128;++attempt){
            auto name="auto-refirst-report-spool-"+std::to_string(nonce)+"-"+std::to_string(attempt);auto candidate=base/prts::path_from_utf8(name);ec.clear();
            if(std::filesystem::create_directory(candidate,ec)){root_=std::move(candidate);break;}
            if(ec){error_="cannot create temporary report spool: "+prts::error_message_utf8(ec);return;}
        }
        if(root_.empty()){error_="cannot create unique temporary report spool";return;}
#ifndef _WIN32
        ec.clear();std::filesystem::permissions(root_,std::filesystem::perms::owner_all,std::filesystem::perm_options::replace,ec);if(ec){error_="cannot restrict temporary report spool permissions: "+prts::error_message_utf8(ec);std::filesystem::remove_all(root_,ec);root_.clear();return;}
#endif
    }
    ~DirectoryReportSpool(){if(root_.empty())return;std::error_code ec;std::filesystem::remove_all(root_,ec);}
    DirectoryReportSpool(const DirectoryReportSpool&)=delete;
    DirectoryReportSpool& operator=(const DirectoryReportSpool&)=delete;
    bool ready()const{return !root_.empty()&&error_.empty();}
    const std::string& error()const{return error_;}
    std::vector<DirectorySpoolRecord>& records(){return records_;}
    const std::vector<DirectorySpoolRecord>& records()const{return records_;}
    bool add(const std::filesystem::path&input,std::int64_t detail_priority,const std::function<void(std::ostream&)>&write_report,std::string&error){
        if(!ready()){error=error_;return false;}
        auto payload=root_/prts::path_from_utf8(std::to_string(records_.size())+".report");
        std::ofstream out(payload,std::ios::binary|std::ios::trunc);if(!out){error="cannot create temporary directory report spool file";return false;}
        std::uint64_t full_bytes=0,staged_bytes=0;
        CappedSpoolStreambuf buf(out,kDirectoryPerReportBytes);
        std::ostream bounded(&buf);
        write_report(bounded);
        bounded.flush();
        full_bytes=buf.total();staged_bytes=buf.written();
        if(!bounded||buf.failed()){error="temporary directory report serialization failed";return false;}
        // Windows does not allow deleting a payload while its ofstream is open.
        // Close and check it before either per-report or aggregate eviction.
        out.close();if(!out){error="temporary directory report spool write/close failed";return false;}
        peak_bytes_=std::max(peak_bytes_,spool_sat_add(selected_bytes_,staged_bytes));
        if(peak_bytes_>kDirectoryReportSpoolHardBytes){error="internal directory report spool hard-budget invariant failed";return false;}
        known_full_bytes_=spool_sat_add(known_full_bytes_,full_bytes);
        DirectorySpoolRecord rec;rec.input=input;rec.payload=payload;rec.full_bytes=full_bytes;rec.detail_priority=detail_priority;
        if(full_bytes>kDirectoryPerReportBytes){
            rec.deferred_reason="PER_REPORT_BYTE_BUDGET";
            if(!remove_payload(payload,error))return false;
            rec.payload.clear();records_.push_back(std::move(rec));return true;
        }
        rec.selected=true;selected_bytes_=spool_sat_add(selected_bytes_,full_bytes);records_.push_back(std::move(rec));return enforce_inline_budget(error);
    }
    bool validate(std::string&error)const{
        if(!ready()){error=error_;return false;}
        std::uint64_t on_disk=0;
        std::size_t selected_count=0;
        for(const auto&r:records_)if(r.selected){
            ++selected_count;
            std::error_code ec;auto st=std::filesystem::symlink_status(r.payload,ec);if(ec||st.type()!=std::filesystem::file_type::regular){error="temporary directory report spool is unavailable or non-regular";return false;}
            auto n=std::filesystem::file_size(r.payload,ec);if(ec||n!=r.full_bytes){error="temporary directory report spool size changed after bounded selection";return false;}on_disk=spool_sat_add(on_disk,n);
            std::ifstream in(r.payload,std::ios::binary);if(!in){error="cannot reopen temporary directory report spool";return false;}
        }
        // Check the actual directory as well as selected records. Otherwise a
        // failed eviction can leave unaccounted bytes behind the advertised cap.
        std::error_code ec;
        std::size_t payload_count=0;
        std::filesystem::directory_iterator it(root_,ec),end;
        if(ec){error="cannot enumerate directory report spool: "+error_message_utf8(ec);return false;}
        while(it!=end){
            ++payload_count;
            it.increment(ec);
            if(ec){error="cannot enumerate directory report spool: "+error_message_utf8(ec);return false;}
        }
        if(payload_count!=selected_count){error="unaccounted directory report spool payload";return false;}
        if(on_disk!=selected_bytes_||on_disk>kDirectoryInlineReportBytes||peak_bytes_>kDirectoryReportSpoolHardBytes){error="internal directory report spool accounting invariant failed";return false;}
        return true;
    }
    void annotate_plan(prts::DirectoryPlan&plan)const{
        std::map<std::string,const DirectorySpoolRecord*>by_input;for(const auto&r:records_)by_input[spool_path_key(r.input)]=&r;
        for(auto&c:plan.candidates){auto it=by_input.find(spool_path_key(c.path));if(it==by_input.end()){c.report_detail_state=c.analysis_state=="ANALYZED"?"DEFERRED":"NOT_ANALYZED";c.report_detail_reason=c.analysis_state=="ANALYZED"?"REPORT_METADATA_UNAVAILABLE":"file was not analyzed";continue;}const auto&r=*it->second;c.report_full_bytes=r.full_bytes;c.report_detail_state=r.selected?"INLINE_FULL":"DEFERRED";c.report_detail_reason=r.selected?"selected by semantic priority within bounded default directory detail budget":r.deferred_reason;}
    }
    std::vector<std::filesystem::path> selected_paths()const{std::vector<std::filesystem::path>out;for(const auto&r:records_)if(r.selected)out.push_back(r.payload);return out;}
    prts::DirectoryReportRendering rendering()const{
        prts::DirectoryReportRendering x;x.profile="bounded_default";x.full_report_count=records_.size();for(const auto&r:records_)if(r.selected)++x.full_reports_rendered;x.full_reports_deferred=x.full_report_count-x.full_reports_rendered;x.partial=x.full_reports_deferred!=0;x.truncated=x.partial;x.known_full_report_bytes=known_full_bytes_;x.inline_report_bytes=selected_bytes_;x.known_deferred_report_bytes=known_full_bytes_>=selected_bytes_?known_full_bytes_-selected_bytes_:0;x.inline_report_budget_bytes=kDirectoryInlineReportBytes;x.per_report_max_bytes=kDirectoryPerReportBytes;x.spool_hard_budget_bytes=kDirectoryReportSpoolHardBytes;x.spool_peak_bytes=peak_bytes_;x.selection_policy="semantic priority: Tier 1/2 and decisive application roles, high-priority evidence, failures/partials, then candidate score; per-report and aggregate byte budgets are hard";x.reason=x.partial?"one or more complete per-file reports were deferred by the default bounded directory rendering budget":"all complete per-file reports fit the bounded default directory rendering budget";x.detail_retrieval_mode="reanalyze_file";x.detail_retrieval_command="auto-refirst <file-from-directory_plan.file_states> --json";return x;
    }
};

} // namespace prts
