#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace prts {

struct ImplicitExecutionFact {
    std::uint32_t index = 0;
    std::int64_t depends_on_fact_index = -1;
    std::string format;
    std::string ecosystem;
    std::string phase;
    std::string trigger;
    std::string relation;
    std::string source_kind;
    std::uint64_t source_index = 0;
    std::uint64_t source_file_offset = 0;
    std::uint64_t source_va = 0;
    std::uint64_t source_size = 0;
    bool source_file_backed = false;
    std::string target_kind;
    std::uint64_t target_va = 0;
    std::uint64_t target_file_offset = 0;
    bool target_file_backed = false;
    std::uint64_t target_token = 0;
    std::uint64_t target_function_index = 0;
    std::string target_name;
    std::string evidence_state;
    std::string mutability;
    std::string execution_condition;
    std::string anomaly_class = "NONE";
    std::string priority = "INFORMATIONAL";
    std::string priority_reason;
    std::string detail;
};

// Format planes own fact payloads. A merged plane is a compact immutable view
// over those payload stores plus independent global dependency metadata. The
// source fact's index/dependency fields therefore always retain local-plane
// semantics; use index_at()/dependency_at() when consuming a possibly merged
// list in report/global coordinates.
class ImplicitExecutionFactList {
public:
    using value_type = ImplicitExecutionFact;
    using size_type = std::size_t;

    class const_iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using iterator_concept = std::forward_iterator_tag;
        using value_type = ImplicitExecutionFact;
        using difference_type = std::ptrdiff_t;
        using pointer = const ImplicitExecutionFact*;
        using reference = const ImplicitExecutionFact&;

        const_iterator() = default;
        reference operator*() const { return (*owner_)[pos_]; }
        pointer operator->() const { return &(*owner_)[pos_]; }
        const_iterator& operator++() { ++pos_; return *this; }
        const_iterator operator++(int) { auto old=*this; ++*this; return old; }
        friend bool operator==(const const_iterator& a,const const_iterator& b) { return a.owner_==b.owner_&&a.pos_==b.pos_; }
        friend bool operator!=(const const_iterator& a,const const_iterator& b) { return !(a==b); }

    private:
        friend class ImplicitExecutionFactList;
        const_iterator(const ImplicitExecutionFactList* owner,size_type pos):owner_(owner),pos_(pos){}
        const ImplicitExecutionFactList* owner_ = nullptr;
        size_type pos_ = 0;
    };

    ImplicitExecutionFactList() = default;
    ImplicitExecutionFactList(const ImplicitExecutionFactList&) = default;
    ImplicitExecutionFactList(ImplicitExecutionFactList&&) noexcept = default;
    ImplicitExecutionFactList& operator=(const ImplicitExecutionFactList&) = default;
    ImplicitExecutionFactList& operator=(ImplicitExecutionFactList&&) noexcept = default;

    size_type size() const noexcept {
        if(shared_view_)return view_dependencies_.size();
        return owned_?owned_->size():0;
    }
    bool empty() const noexcept { return size()==0; }
    bool is_shared_view() const noexcept { return shared_view_; }

    const ImplicitExecutionFact& operator[](size_type i) const { return ref_at(i); }
    const_iterator begin() const { return const_iterator(this,0); }
    const_iterator end() const { return const_iterator(this,size()); }
    const_iterator begin() { return const_iterator(this,0); }
    const_iterator end() { return const_iterator(this,size()); }

    void push_back(const ImplicitExecutionFact& fact) {
        ensure_owned_for_write();
        owned_->push_back(fact);
    }
    void push_back(ImplicitExecutionFact&& fact) {
        ensure_owned_for_write();
        owned_->push_back(std::move(fact));
    }

    std::uint32_t index_at(size_type i) const {
        return shared_view_?static_cast<std::uint32_t>(i):ref_at(i).index;
    }
    std::int64_t dependency_at(size_type i) const {
        return shared_view_?view_dependencies_[i]:ref_at(i).depends_on_fact_index;
    }

    // Internal merge primitive: append payload references without copying a
    // fact or any of its strings. dependencies must already be in the new
    // merged plane's global coordinate space.
    void append_shared_view(const ImplicitExecutionFactList& source,const std::vector<std::int64_t>& dependencies) {
        if(dependencies.size()!=source.size())throw std::logic_error("implicit fact view dependency cardinality mismatch");
        if(!shared_view_&&!empty())throw std::logic_error("implicit fact view cannot append onto owning facts");
        if(!shared_view_){shared_view_=true;owned_.reset();}
        auto view_offset=view_dependencies_.size();
        if(source.shared_view_){
            for(const auto& s:source.segments_){
                segments_.push_back({s.storage,s.storage_offset,s.count,view_offset});
                view_offset+=s.count;
            }
        }else if(source.owned_&&!source.owned_->empty()){
            segments_.push_back({source.owned_,0,source.owned_->size(),view_offset});
            view_offset+=source.owned_->size();
        }
        view_dependencies_.insert(view_dependencies_.end(),dependencies.begin(),dependencies.end());
    }

    void reserve_shared_view(size_type facts,size_type segments) {
        if(!shared_view_&&!empty())throw std::logic_error("implicit fact view reserve on owning facts");
        view_dependencies_.reserve(facts);
        segments_.reserve(segments);
    }

private:
    using Storage = std::vector<ImplicitExecutionFact>;
    struct Segment {
        std::shared_ptr<const Storage> storage;
        size_type storage_offset = 0;
        size_type count = 0;
        size_type view_offset = 0;
    };

    const ImplicitExecutionFact& ref_at(size_type i) const {
        if(!shared_view_)return (*owned_)[i];
        for(const auto& s:segments_){
            if(i>=s.view_offset&&i-s.view_offset<s.count)return (*s.storage)[s.storage_offset+(i-s.view_offset)];
        }
        throw std::out_of_range("implicit fact view index");
    }

    void ensure_owned_for_write() {
        if(shared_view_){
            auto fresh=std::make_shared<Storage>();
            fresh->reserve(size());
            for(size_type i=0;i<size();++i){
                auto fact=ref_at(i);
                fact.index=index_at(i);
                fact.depends_on_fact_index=dependency_at(i);
                fresh->push_back(std::move(fact));
            }
            owned_=std::move(fresh);
            segments_.clear();
            view_dependencies_.clear();
            shared_view_=false;
        }else if(!owned_)owned_=std::make_shared<Storage>();
        else if(owned_.use_count()!=1)owned_=std::make_shared<Storage>(*owned_);
    }

    std::shared_ptr<Storage> owned_;
    std::vector<Segment> segments_;
    std::vector<std::int64_t> view_dependencies_;
    bool shared_view_ = false;
};

struct ImplicitExecutionInfo {
    std::string state = "NOT_PRESENT";
    std::string error;
    std::uint64_t informational_count = 0;
    std::uint64_t review_count = 0;
    std::uint64_t high_priority_count = 0;
    std::uint64_t anomaly_count = 0;
    std::uint64_t unresolved_runtime_semantics = 0;
    std::uint64_t deterministic_effect_count = 0;
    std::uint64_t raw_loader_symbol_count = 0;
    bool analysis_limited = false;
    ImplicitExecutionFactList facts;

    std::uint32_t fact_index(std::size_t position) const { return facts.index_at(position); }
    std::int64_t fact_dependency(std::size_t position) const { return facts.dependency_at(position); }
};

struct ImplicitExecutionExtractResult {
    bool success = false;
    std::filesystem::path csv;
    std::uint64_t fact_count = 0;
    std::string error;
};

struct ImplicitExecutionPlaneRef {
    std::string source;
    const ImplicitExecutionInfo* info = nullptr;
};

ImplicitExecutionInfo merge_implicit_execution(const std::vector<ImplicitExecutionPlaneRef>& planes);

ImplicitExecutionExtractResult extract_implicit_execution(
    const ImplicitExecutionInfo& info,
    const std::filesystem::path& csv);

} // namespace prts
