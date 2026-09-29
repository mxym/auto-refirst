#include "prts/asar.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

namespace prts { namespace {

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string extension_lower(std::string_view path) {
    const auto slash = path.find_last_of('/');
    const auto dot = path.find_last_of('.');
    if (dot == std::string_view::npos || (slash != std::string_view::npos && dot < slash)) return {};
    return lower_ascii(std::string(path.substr(dot)));
}

const AsarEntry* find_file(const AsarInfo& info, std::string_view path) {
    for (const auto& entry : info.entries) {
        if (entry.kind == AsarEntryKind::File && entry.path == path) return &entry;
    }
    return nullptr;
}

enum class JsState { Code, Single, Double, Template, LineComment, BlockComment, Regex, RegexClass };

bool regex_start(std::string_view text, std::size_t at) {
    std::size_t p = at;
    while (p > 0 && std::isspace(static_cast<unsigned char>(text[p - 1]))) --p;
    if (!p) return true;
    const char c = text[p - 1];
    return c == '=' || c == '(' || c == '[' || c == '{' || c == ',' || c == ':' ||
           c == ';' || c == '!' || c == '?' || c == '&' || c == '|' || c == '+' ||
           c == '-' || c == '*' || c == '%' || c == '^' || c == '~' || c == '<' || c == '>';
}

bool js_code_position(std::string_view text, std::size_t target) {
    JsState state = JsState::Code;
    bool escaped = false;
    for (std::size_t i = 0; i < target && i < text.size(); ++i) {
        const char c = text[i];
        if (state == JsState::LineComment) { if (c == '\n') state = JsState::Code; continue; }
        if (state == JsState::BlockComment) {
            if (c == '*' && i + 1 < text.size() && text[i + 1] == '/') { ++i; state = JsState::Code; }
            continue;
        }
        if (state == JsState::Regex || state == JsState::RegexClass) {
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if (state == JsState::Regex && c == '[') { state = JsState::RegexClass; continue; }
            if (state == JsState::RegexClass && c == ']') { state = JsState::Regex; continue; }
            if (state == JsState::Regex && c == '/') state = JsState::Code;
            continue;
        }
        if (state == JsState::Single || state == JsState::Double || state == JsState::Template) {
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if ((state == JsState::Single && c == '\'') ||
                (state == JsState::Double && c == '"') ||
                (state == JsState::Template && c == '`')) state = JsState::Code;
            continue;
        }
        if (c == '/' && i + 1 < text.size() && text[i + 1] == '/') { ++i; state = JsState::LineComment; continue; }
        if (c == '/' && i + 1 < text.size() && text[i + 1] == '*') { ++i; state = JsState::BlockComment; continue; }
        if (c == '/' && regex_start(text, i)) { state = JsState::Regex; continue; }
        if (c == '\'') { state = JsState::Single; continue; }
        if (c == '"') { state = JsState::Double; continue; }
        if (c == '`') state = JsState::Template;
    }
    return state == JsState::Code;
}

std::optional<std::pair<std::string, std::size_t>> direct_call_literal(
    std::string_view text, std::size_t at, std::string_view token) {
    if (at + token.size() > text.size() || text.substr(at, token.size()) != token || !js_code_position(text, at)) return {};
    const bool left = at == 0 || (!(std::isalnum(static_cast<unsigned char>(text[at - 1])) ||
                                    text[at - 1] == '_' || text[at - 1] == '$' || text[at - 1] == '.'));
    const auto end = at + token.size();
    const bool right = end == text.size() || (!(std::isalnum(static_cast<unsigned char>(text[end])) ||
                                                text[end] == '_' || text[end] == '$'));
    if (!left || !right) return {};
    std::size_t p = end;
    while (p < text.size() && std::isspace(static_cast<unsigned char>(text[p]))) ++p;
    if (p >= text.size() || text[p] != '(') return {};
    ++p;
    while (p < text.size() && std::isspace(static_cast<unsigned char>(text[p]))) ++p;
    if (p >= text.size() || (text[p] != '\'' && text[p] != '"')) return {};
    const char quote = text[p++];
    std::string value;
    for (; p < text.size(); ++p) {
        const char c = text[p];
        if (c == quote) {
            std::size_t after = p + 1;
            while (after < text.size() && std::isspace(static_cast<unsigned char>(text[after]))) ++after;
            if (after >= text.size() || text[after] != ')') return {};
            return std::pair<std::string, std::size_t>{std::move(value), after + 1};
        }
        if (c == '\\') {
            if (p + 1 >= text.size()) return {};
            const char next = text[++p];
            if (next == 'n' || next == 'r' || next == 't' || next == '\\' || next == '\'' || next == '"' || next == '/')
                value.push_back(next == 'n' ? '\n' : (next == 'r' ? '\r' : (next == 't' ? '\t' : next)));
            else return {};
        } else {
            if (static_cast<unsigned char>(c) < 0x20) return {};
            value.push_back(c);
        }
    }
    return {};
}

std::optional<std::string> resolve_member(std::string_view source, std::string ref) {
    if (ref.empty() || ref.front() == '/' || ref.find('\\') != std::string::npos || ref.find('\0') != std::string::npos) return {};
    std::replace(ref.begin(), ref.end(), '\\', '/');
    std::vector<std::string> parts;
    auto add = [&](std::string_view part) {
        if (part.empty() || part == ".") return true;
        if (part == "..") { if (parts.empty()) return false; parts.pop_back(); return true; }
        if (part.find(':') != std::string_view::npos) return false;
        parts.emplace_back(part); return true;
    };
    auto consume = [&](std::string_view path) {
        std::size_t pos = 0;
        while (pos < path.size()) {
            auto end = path.find('/', pos); if (end == std::string_view::npos) end = path.size();
            if (!add(path.substr(pos, end - pos))) return false;
            pos = end == path.size() ? end : end + 1;
        }
        return true;
    };
    const auto slash = source.find_last_of('/');
    if (!consume(slash == std::string_view::npos ? std::string_view{} : source.substr(0, slash)) || !consume(ref)) return {};
    if (parts.empty()) return {};
    std::string out;
    for (const auto& part : parts) { if (!out.empty()) out.push_back('/'); out += part; }
    return out;
}

std::uint64_t line_number(std::string_view text, std::size_t offset) {
    return 1 + static_cast<std::uint64_t>(std::count(text.begin(), text.begin() + std::min(offset, text.size()), '\n'));
}

} // namespace

void analyze_asar_script_references(std::span<const std::uint8_t> data, AsarInfo& info) {
    constexpr std::size_t kScriptCap = 64, kReferenceCap = 256, kScriptBytes = 2u * 1024u * 1024u, kTotalBytes = 8u * 1024u * 1024u;
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 6> calls = {{
        {"fetch", "fetch"}, {"fs.readFileSync", "fs.readFileSync"}, {"require", "require"},
        {"import", "import"}, {"WebAssembly.instantiateStreaming", "WebAssembly.instantiateStreaming"},
        {"WebAssembly.instantiate", "WebAssembly.instantiate"},
    }};
    std::size_t scripts = 0, bytes = 0;
    auto promote = [&](const std::string& path) {
        if (std::find(info.interesting_paths.begin(), info.interesting_paths.end(), path) == info.interesting_paths.end()) {
            if (info.interesting_paths.size() >= 48) { info.interesting_paths.back() = path; }
            else info.interesting_paths.push_back(path);
        }
    };
    for (const auto& source : info.entries) {
        if (source.kind != AsarEntryKind::File || source.unpacked) continue;
        const auto ext = extension_lower(source.path);
        if (ext != ".js" && ext != ".cjs" && ext != ".mjs") continue;
        if (scripts >= kScriptCap || bytes >= kTotalBytes || source.size > kScriptBytes ||
            source.offset > std::numeric_limits<std::uint64_t>::max() - info.data_offset ||
            info.data_offset + source.offset > data.size() || source.size > data.size() - info.data_offset - source.offset) {
            info.script_reference_scan_limited = true;
            continue;
        }
        const auto offset = static_cast<std::size_t>(info.data_offset + source.offset);
        const auto size = static_cast<std::size_t>(source.size);
        const std::string_view text(reinterpret_cast<const char*>(data.data() + offset), size);
        ++scripts; bytes += size;
        for (const auto& [token, call] : calls) {
            for (std::size_t pos = 0; pos < text.size() && info.script_references.size() < kReferenceCap;) {
                pos = text.find(token, pos);
                if (pos == std::string_view::npos) break;
                const auto token_pos = pos;
                pos += token.size();
                const auto parsed = direct_call_literal(text, token_pos, token);
                if (!parsed) continue;
                const auto target = resolve_member(source.path, parsed->first);
                if (!target) continue;
                const auto* entry = find_file(info, *target);
                if (!entry || entry->path == source.path) continue;
                const auto target_lower = lower_ascii(entry->path);
                const bool wasm = target_lower.ends_with(".wasm");
                const bool native = target_lower.ends_with(".node");
                if (!wasm && !native) continue;
                bool duplicate = false;
                for (const auto& prior : info.script_references)
                    if (prior.source_path == source.path && prior.target_path == entry->path && prior.call_kind == call) duplicate = true;
                if (duplicate) continue;
                AsarScriptReference reference;
                reference.kind = wasm ? "asar_script_wasm_dependency" : "asar_script_native_dependency";
                reference.source_path = source.path; reference.target_path = entry->path; reference.call_kind = call;
                reference.literal = parsed->first; reference.source_byte = token_pos; reference.source_line = line_number(text, token_pos);
                reference.target_offset = entry->unpacked ? 0 : entry->offset; reference.target_size = entry->size; reference.target_unpacked = entry->unpacked;
                reference.resolution_basis = entry->unpacked ? "ASAR_UNPACKED_SIBLING" : "ASAR_PACKED_OFFSET";
                info.script_references.push_back(std::move(reference));
                promote(source.path); promote(entry->path);
            }
        }
    }
    info.script_reference_scanned_bytes = bytes;
    info.script_reference_scanned_files = scripts;
    if (scripts >= kScriptCap || bytes >= kTotalBytes || info.script_references.size() >= kReferenceCap) info.script_reference_scan_limited = true;
}

} // namespace prts
