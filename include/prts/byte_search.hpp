#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace prts::detail {
inline std::size_t find_exact(std::span<const std::uint8_t> data,
                              std::span<const std::uint8_t> needle,
                              std::size_t from=0) {
    if (needle.empty()) return from<=data.size()?from:std::string::npos;
    if (from>data.size() || needle.size()>data.size()-from) return std::string::npos;
    const auto* base=data.data();
    const auto* cur=base+from;
    const auto* last=base+data.size()-needle.size();
    while (cur<=last) {
        const auto* hit=static_cast<const std::uint8_t*>(
            std::memchr(cur,needle.front(),static_cast<std::size_t>(last-cur)+1));
        if (!hit) return std::string::npos;
        if (needle.size()==1 || std::memcmp(hit,needle.data(),needle.size())==0)
            return static_cast<std::size_t>(hit-base);
        cur=hit+1;
    }
    return std::string::npos;
}
inline std::size_t find_exact(std::span<const std::uint8_t> data,
                              std::string_view needle,
                              std::size_t from=0) {
    return find_exact(data,
        {reinterpret_cast<const std::uint8_t*>(needle.data()),needle.size()},from);
}
inline bool contains_exact(std::span<const std::uint8_t> data,std::string_view needle) {
    return find_exact(data,needle)!=std::string::npos;
}
}
