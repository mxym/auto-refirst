#pragma once
#include <algorithm>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#ifdef _WIN32
#include <windows.h>
#endif

namespace prts {
inline std::string error_message_utf8(const std::error_code& error) {
    const auto local = error.message();
#ifdef _WIN32
    if (local.empty()) return "error_code=" + std::to_string(error.value());
    const int wide_size = MultiByteToWideChar(CP_ACP, 0, local.data(), static_cast<int>(local.size()), nullptr, 0);
    if (wide_size <= 0) return "error_code=" + std::to_string(error.value());
    std::wstring wide(static_cast<std::size_t>(wide_size), L'\0');
    if (MultiByteToWideChar(CP_ACP, 0, local.data(), static_cast<int>(local.size()), wide.data(), wide_size) != wide_size)
        return "error_code=" + std::to_string(error.value());
    const int utf8_size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), wide_size, nullptr, 0, nullptr, nullptr);
    if (utf8_size <= 0) return "error_code=" + std::to_string(error.value());
    std::string utf8(static_cast<std::size_t>(utf8_size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), wide_size, utf8.data(), utf8_size, nullptr, nullptr) != utf8_size)
        return "error_code=" + std::to_string(error.value());
    return utf8;
#else
    return local;
#endif
}

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

// Convert an already UTF-8 native path spelling to the separator convention
// used by archive/container member names. The separator is explicit so this
// can be regression-tested on any host without rewriting a literal backslash
// that is a valid POSIX filename character.
inline std::string normalize_native_path_separators(std::string text, char native_separator) {
    if (native_separator == '\\') {
        std::replace(text.begin(), text.end(), '\\', '/');
    }
    return text;
}

inline std::string generic_path_utf8(const std::filesystem::path& path) {
#ifdef _WIN32
    return normalize_native_path_separators(path_utf8(path), '\\');
#else
    return path_utf8(path);
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
