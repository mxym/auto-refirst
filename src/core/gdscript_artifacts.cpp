#include "prts/gdscript.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace prts {
namespace {
std::string csv(std::string_view s) {
    bool quote = false;
    for (char ch : s) if (ch == ',' || ch == '"' || ch == '\n' || ch == '\r') { quote = true; break; }
    if (!quote) return std::string(s);
    std::string out; out.push_back('"');
    for (char ch : s) { if (ch == '"') out.push_back('"'); out.push_back(ch); }
    out.push_back('"'); return out;
}

bool write_text(const std::filesystem::path& p, const std::string& text) {
    std::ofstream f(p, std::ios::binary);
    if (!f) return false;
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
    return bool(f);
}
} // namespace

GDScriptMaterializeResult materialize_gdscript_analysis(const GDScriptAnalysisInfo& info,
                                                         const std::filesystem::path& output_base) {
    GDScriptMaterializeResult out;
    if (!info.valid || info.state != "CONFIRMED") { out.error = "GDScript analysis is not uniquely confirmed"; return out; }
    const auto base = output_base.string();
    out.info_json = base + ".godot-script-info.json";
    out.identifiers_csv = base + ".godot-identifiers.csv";
    out.constants_csv = base + ".godot-constants.csv";
    out.lines_csv = base + ".godot-lines.csv";
    out.tokens_csv = base + ".godot-tokens.csv";
    const std::filesystem::path targets[]={out.info_json,out.identifiers_csv,out.constants_csv,out.lines_csv,out.tokens_csv};
    std::error_code ec;
    for(const auto& target:targets){
        const bool exists=std::filesystem::exists(target,ec);
        if(ec){out.error="cannot inspect GDScript artifact target: "+target.string()+": "+ec.message();return out;}
        if(exists){out.error="refusing to overwrite existing GDScript artifact target: "+target.string();return out;}
    }
    const auto parent = output_base.parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, ec);
    if (ec) { out.error = "cannot create GDScript artifact directory: " + ec.message(); return out; }
    std::vector<std::filesystem::path> created;
    auto put = [&](const std::filesystem::path& p, const std::string& text) {
        if (!write_text(p, text)) return false;
        created.push_back(p); return true;
    };
    auto fail = [&](std::string e) {
        out.error = std::move(e);
        for (const auto& p : created) { std::error_code rm; std::filesystem::remove(p, rm); }
        return out;
    };

    std::ostringstream info_json;
    info_json << "{\n"
              << "  \"schema\": \"auto-refirst.godot-script-analysis.v1\",\n"
              << "  \"state\": \"CONFIRMED\",\n"
              << "  \"variant\": \"" << info.variant << "\",\n"
              << "  \"offset_space\": \"" << info.offset_space << "\",\n"
              << "  \"input_bytes\": " << info.input_bytes << ",\n"
              << "  \"input_sha256\": \"" << info.input_sha256 << "\",\n"
              << "  \"payload_sha256\": \"" << info.payload_sha256 << "\",\n"
              << "  \"analysis_set_id\": \"" << info.analysis_set_id << "\",\n"
              << "  \"identifier_pair_basis\": \"exact-keyword-identifier-pairs; no grammar/AST validation\",\n"
              << "  \"compression\": \"" << info.compression << "\",\n"
              << "  \"official_version_scope\": \"" << info.official_version_scope << "\",\n"
              << "  \"official_version_basis\": \"" << info.official_version_basis << "\",\n"
              << "  \"declared_decompressed_size\": " << info.decompressed_size << ",\n"
              << "  \"payload_bytes\": " << info.payload_bytes << ",\n"
              << "  \"source_decompilation\": false,\n"
              << "  \"tokenizer_version\": " << info.tokenizer_version << ",\n"
              << "  \"payload_reserved_word_present\": " << (info.payload_reserved_word_present ? "true" : "false") << ",\n"
              << "  \"payload_reserved_word\": " << info.payload_reserved_word << ",\n"
              << "  \"token_record_size\": " << info.token_record_size << ",\n"
              << "  \"line_record_size\": " << info.line_record_size << ",\n"
              << "  \"typed_array_count\": " << info.typed_array_count << ",\n"
              << "  \"typed_dictionary_count\": " << info.typed_dictionary_count << ",\n"
              << "  \"class_name_container_count\": " << info.class_name_container_count << ",\n"
              << "  \"script_container_count\": " << info.script_container_count << ",\n"
              << "  \"position_mapped_token_count\": " << info.position_mapped_token_count << ",\n"
              << "  \"mapped_column_token_count\": " << info.mapped_column_token_count << ",\n"
              << "  \"semantic_text_token_count\": " << info.semantic_text_token_count << ",\n"
              << "  \"effective_line_token_count\": " << info.effective_line_token_count << ",\n"
              << "  \"unknown_line_token_count\": " << info.unknown_line_token_count << ",\n"
              << "  \"semantic_text_complete_token_count\": " << info.semantic_text_complete_token_count << ",\n"
              << "  \"semantic_text_incomplete_token_count\": " << info.semantic_text_incomplete_token_count << ",\n"
              << "  \"native_super_call_basis\": \"unique top-level extends identifier + named top-level function block + explicit super.method; official-compatible only; no general AST\",\n"
              << "  \"native_super_call_count\": " << info.native_super_calls.size() << ",\n"
              << "  \"identifier_count\": " << info.identifiers.size() << ",\n"
              << "  \"constant_count\": " << info.constants.size() << ",\n"
              << "  \"line_count\": " << info.lines.size() << ",\n"
              << "  \"token_count\": " << info.tokens.size() << "\n"
              << "}\n";
    if (!put(out.info_json, info_json.str())) return fail("write failed: " + out.info_json.string());

    std::ostringstream ids; ids << "analysis_set_id,index,payload_offset,referenced,token_reference_count,annotation_reference_count,func_identifier_pair_count,var_identifier_pair_count,const_identifier_pair_count,signal_identifier_pair_count,class_name_identifier_pair_count,class_identifier_pair_count,enum_identifier_pair_count,extends_identifier_pair_count,first_token_index,last_token_index,text\n";
    for (const auto& x : info.identifiers) ids << csv(info.analysis_set_id) << ',' << x.index << ',' << x.payload_offset << ',' << (x.referenced ? "true" : "false") << ',' << x.token_reference_count << ',' << x.annotation_reference_count << ',' << x.func_identifier_pair_count << ',' << x.var_identifier_pair_count << ',' << x.const_identifier_pair_count << ',' << x.signal_identifier_pair_count << ',' << x.class_name_identifier_pair_count << ',' << x.class_identifier_pair_count << ',' << x.enum_identifier_pair_count << ',' << x.extends_identifier_pair_count << ',' << x.first_token_index << ',' << x.last_token_index << ',' << csv(x.text) << '\n';
    if (!put(out.identifiers_csv, ids.str())) return fail("write failed: " + out.identifiers_csv.string());

    std::ostringstream constants; constants << "analysis_set_id,index,payload_offset,encoded_size,referenced,token_reference_count,literal_reference_count,error_reference_count,first_token_index,last_token_index,type_id,type,summary_available,summary_complete,summary\n";
    for (const auto& x : info.constants) constants << csv(info.analysis_set_id) << ',' << x.index << ',' << x.payload_offset << ',' << x.encoded_size << ',' << (x.referenced ? "true" : "false") << ',' << x.token_reference_count << ',' << x.literal_reference_count << ',' << x.error_reference_count << ',' << x.first_token_index << ',' << x.last_token_index << ',' << x.type_id << ',' << csv(x.type) << ',' << (x.summary_available ? "true" : "false") << ',' << (x.summary_complete ? "true" : "false") << ',' << csv(x.summary) << '\n';
    if (!put(out.constants_csv, constants.str())) return fail("write failed: " + out.constants_csv.string());

    std::ostringstream lines; lines << "analysis_set_id,index,token_index,line,column,unknown,has_column,has_unknown\n";
    for (const auto& x : info.lines) lines << csv(info.analysis_set_id) << ',' << x.index << ',' << x.token_index << ',' << x.line << ',' << x.column << ',' << x.unknown << ',' << (x.has_column ? "true" : "false") << ',' << (x.has_unknown ? "true" : "false") << '\n';
    if (!put(out.lines_csv, lines.str())) return fail("write failed: " + out.lines_csv.string());

    std::ostringstream tokens; tokens << "analysis_set_id,index,payload_offset,record_size,type_id,type,semantic_text_available,semantic_text_complete,semantic_text_source,semantic_text,data,line,effective_line_known,effective_line,effective_line_source,mapped_line,mapped_column,position_map_present,mapped_column_known,custom,reference_kind,reference,keyword_identifier_pair_present,keyword_identifier_pair_keyword,keyword_identifier_pair_token_index\n";
    for (const auto& x : info.tokens) tokens << csv(info.analysis_set_id) << ',' << x.index << ',' << x.payload_offset << ',' << x.record_size << ',' << x.type_id << ',' << csv(x.type) << ',' << (x.semantic_text_available ? "true" : "false") << ',' << (x.semantic_text_complete ? "true" : "false") << ',' << csv(x.semantic_text_source) << ',' << csv(x.semantic_text) << ',' << x.data << ',' << x.line << ',' << (x.effective_line_known ? "true" : "false") << ',' << x.effective_line << ',' << csv(x.effective_line_source) << ',' << x.mapped_line << ',' << x.mapped_column << ',' << (x.position_map_present ? "true" : "false") << ',' << (x.mapped_column_known ? "true" : "false") << ',' << (x.custom ? "true" : "false") << ',' << csv(x.reference_kind) << ',' << csv(x.reference) << ',' << (x.keyword_identifier_pair_present ? "true" : "false") << ',' << csv(x.keyword_identifier_pair_keyword) << ',' << x.keyword_identifier_pair_token_index << '\n';
    if (!put(out.tokens_csv, tokens.str())) return fail("write failed: " + out.tokens_csv.string());

    out.success = true; out.error.clear(); return out;
}

} // namespace prts
