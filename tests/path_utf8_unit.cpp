#include "prts/path_utf8.hpp"

#include <iostream>
#include <string>

namespace {
bool require(bool condition, const char* message) {
    if (condition) return true;
    std::cerr << message << '\n';
    return false;
}
}

int main() {
    using prts::normalize_native_path_separators;

    const std::string windows_spelling = R"(assets\releases\index.android.bundle)";
    if (!require(
            normalize_native_path_separators(windows_spelling, '\\') ==
                "assets/releases/index.android.bundle",
            "Windows native separators were not converted to generic separators")) return 1;
    if (!require(
            normalize_native_path_separators(windows_spelling, '/') == windows_spelling,
            "a POSIX filename backslash must not be rewritten")) return 1;
    if (!require(
            normalize_native_path_separators("assets/releases/app.payload", '\\') ==
                "assets/releases/app.payload",
            "existing generic separators must remain stable")) return 1;

    const auto nested = std::filesystem::path("assets") / "releases" / "app.payload";
    if (!require(
            prts::generic_path_utf8(nested) == "assets/releases/app.payload",
            "filesystem path did not produce a generic UTF-8 spelling")) return 1;

    std::cout << "PASS\n";
    return 0;
}
