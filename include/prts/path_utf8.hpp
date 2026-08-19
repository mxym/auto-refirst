#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#ifdef _WIN32
#include <windows.h>
#endif

namespace prts {
inline std::string path_utf8(const std::filesystem::path& path) {
#ifdef _WIN32
    const auto& wide = path.native();
    if (wide.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()), out.data(), n, nullptr, nullptr);
    return out;
#else
    return path.string();
#endif
}

inline std::filesystem::path path_from_utf8(std::string_view text) {
#ifdef _WIN32
    if (text.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring wide(static_cast<std::size_t>(n), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), wide.data(), n) != n) return {};
    return std::filesystem::path(wide);
#else
    return std::filesystem::path(std::string(text));
#endif
}

inline std::filesystem::path path_with_ascii_suffix(std::filesystem::path path, std::string_view suffix) {
#ifdef _WIN32
    std::wstring wide;
    wide.reserve(suffix.size());
    for (unsigned char c : suffix) wide.push_back(static_cast<wchar_t>(c));
    path += wide;
#else
    path += suffix;
#endif
    return path;
}
}
