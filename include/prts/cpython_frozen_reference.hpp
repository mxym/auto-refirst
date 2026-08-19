#pragma once
#include "prts/cpython_frozen.hpp"
#include <cstddef>
#include <optional>
#include <string_view>
namespace prts {
struct CPythonFrozenReferenceHash { std::string_view raw_sha256; std::string_view semantic_sha256; };
std::optional<CPythonFrozenReferenceHash> cpython_frozen_reference(std::string_view version,std::string_view table,std::string_view module);
std::size_t cpython_frozen_reference_count();
void apply_cpython_frozen_reference(CPythonFrozenInfo& info,std::string_view reference_version);
}
