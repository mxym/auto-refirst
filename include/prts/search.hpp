#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
namespace prts {
struct SearchOptions {
    std::string needle;
    bool ignore_case=false;
    bool recursive=true;
    bool json_lines=false;
    std::size_t context=48;
};
struct SearchStats { std::uint64_t files=0,bytes=0,matches=0; };
SearchStats search_tree_streaming(const std::filesystem::path&root,const SearchOptions&opt);
}
