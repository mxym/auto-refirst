cmake_minimum_required(VERSION 3.20)
project(AutoRefirst VERSION 0.1.0 LANGUAGES C CXX)

set(AUTO_REFIRST_PRODUCT_VERSION "0.1.0-rc.2" CACHE STRING "Product version reported by auto-refirst --version")
if(NOT AUTO_REFIRST_PRODUCT_VERSION MATCHES "^[0-9A-Za-z.+-]+$")
  message(FATAL_ERROR "AUTO_REFIRST_PRODUCT_VERSION contains unsupported characters")
endif()

set(AUTO_REFIRST_BUILD_ID "unknown")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
  execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE _auto_refirst_git_commit
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE _auto_refirst_git_result
  )
  string(LENGTH "${_auto_refirst_git_commit}" _auto_refirst_git_commit_len)
  if(_auto_refirst_git_result EQUAL 0 AND _auto_refirst_git_commit MATCHES "^[0-9A-Fa-f]+$" AND (_auto_refirst_git_commit_len EQUAL 40 OR _auto_refirst_git_commit_len EQUAL 64))
    set(AUTO_REFIRST_BUILD_ID "${_auto_refirst_git_commit}")
    execute_process(
      COMMAND git status --porcelain=v1 --untracked-files=all
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      OUTPUT_VARIABLE _auto_refirst_git_status
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
      RESULT_VARIABLE _auto_refirst_git_status_result
    )
    if(NOT _auto_refirst_git_status_result EQUAL 0)
      string(APPEND AUTO_REFIRST_BUILD_ID "-status-unknown")
    elseif(NOT _auto_refirst_git_status STREQUAL "")
      string(APPEND AUTO_REFIRST_BUILD_ID "-dirty")
    endif()
  endif()
else()
  # Source archives have no source-root .git marker. Do not let Git discover an
  # unrelated ancestor repository: archive identity must come only from the
  # release harness fallback, and never overrides a live checkout/worktree.
  set(_auto_refirst_source_commit "$ENV{AUTO_REFIRST_SOURCE_COMMIT}")
  string(LENGTH "${_auto_refirst_source_commit}" _auto_refirst_source_commit_len)
  if(_auto_refirst_source_commit MATCHES "^[0-9A-Fa-f]+$" AND (_auto_refirst_source_commit_len EQUAL 40 OR _auto_refirst_source_commit_len EQUAL 64))
    set(AUTO_REFIRST_BUILD_ID "${_auto_refirst_source_commit}")
  endif()
endif()
if(CMAKE_SYSTEM_PROCESSOR)
  set(AUTO_REFIRST_BUILD_PLATFORM "${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(AUTO_REFIRST_BUILD_PLATFORM "${CMAKE_SYSTEM_NAME}/unknown")
endif()
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_metadata.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/prts/build_metadata.hpp"
  @ONLY
)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(auto_refirst_enable_msvc_utf8 target)
  if(MSVC)
    # Keep source and execution character sets deterministic on Windows hosts
    # whose active code page is not UTF-8. Apply this only to project-owned
    # targets; do not change flags on vendored subdirectory targets.
    target_compile_options(${target} PRIVATE /utf-8)
  endif()
endfunction()

option(AUTO_REFIRST_WARNINGS_AS_ERRORS "Treat warnings as errors for release/CI product gates" OFF)
function(auto_refirst_enable_warnings_as_errors target)
  if(AUTO_REFIRST_WARNINGS_AS_ERRORS)
    if(MSVC)
      target_compile_options(${target} PRIVATE /WX)
    else()
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

# Keep product warning policy strict while treating vendored implementation
# noise as third-party debt. Do not edit imported sources solely to satisfy
# our warning baseline; scope compatibility options to only the translation
# units that require them.
if(MSVC)
  set_source_files_properties(
      third_party/rustc_demangle/demangle.c
      PROPERTIES COMPILE_OPTIONS "/wd4244;/wd4457;/wd4996")
  set_source_files_properties(
      third_party/zydis/Zydis.c
      PROPERTIES COMPILE_OPTIONS "/wd4201")
  set_source_files_properties(
      third_party/miniz/miniz_zip.c
      PROPERTIES COMPILE_OPTIONS "/wd4127")
else()
  set_source_files_properties(third_party/zydis/Zydis.c PROPERTIES COMPILE_OPTIONS "-Wno-unused-const-variable;-Wno-unused-function")
  set_source_files_properties(
      third_party/miniz/miniz_zip.c
      third_party/miniz/miniz_tinfl.c
      third_party/miniz/miniz_tdef.c
      third_party/miniz/miniz.c
      PROPERTIES COMPILE_OPTIONS "-Wno-unused-function")
endif()
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  set_source_files_properties(
      third_party/rustc_demangle/demangle.c
      PROPERTIES COMPILE_OPTIONS "-Wno-gnu-zero-variadic-macro-arguments;-Wno-missing-field-initializers")
  set_property(SOURCE third_party/zydis/Zydis.c APPEND PROPERTY COMPILE_OPTIONS "-Wno-newline-eof")
endif()

add_executable(auto_refirst
    src/main.cpp
    src/core/sha256.cpp
    src/core/sha1.cpp
    third_party/tiny_aes/aes.c
    third_party/rustc_demangle/demangle.c
    third_party/zydis/Zydis.c
    src/core/md5.cpp
    src/core/zstd_wrap.c
    src/core/gdscript_buffer.cpp
    src/core/gdscript_artifacts.cpp
    src/core/gdextension.cpp
    src/core/mapped_file.cpp
    src/core/static_scan.cpp
    src/core/search.cpp
    src/detect/upx.cpp
    src/detect/packed_pe.cpp
    src/detect/authenticode.cpp
    src/detect/antidebug.cpp
    src/detect/execution_prerequisite.cpp
    src/detect/manual_resolver.cpp
    src/detect/crypto.cpp
    src/detect/golang.cpp
    src/detect/rust.cpp
    src/core/file_snapshot.cpp
    src/core/report.cpp
    src/core/analysis_path.cpp
    src/core/runtime_modality.cpp
    src/core/orchestration.cpp
    src/core/relationship_evidence.cpp
    src/core/interpreter_boundary.cpp
    src/core/semantic_composition.cpp
    src/core/semantic_producers.cpp
    src/core/implicit_exec.cpp
    src/core/exception_flow.cpp
    src/core/dwarf_expression_surface.cpp
    src/detect/continuation.cpp
    src/core/continuation.cpp
    src/detect/control_record.cpp
    src/core/control_record.cpp
    src/formats/pe.cpp
    src/formats/elf.cpp
    src/formats/macho.cpp
    src/formats/macho_swift.cpp
    src/formats/python_marshal.cpp
    src/formats/python_bytecode.cpp
    src/unpack/replacement.cpp
    src/unpack/repair.cpp
    src/extract/pyinstaller.cpp
    src/extract/pyinstaller_reference.cpp
    src/extract/nested_executable.cpp
    src/extract/container_ingress.cpp
    src/extract/nuitka.cpp
    src/extract/nuitka_version.cpp
    src/extract/lua.cpp
    src/extract/wasm.cpp
    src/extract/hermes.cpp
    src/extract/jvm.cpp
    src/extract/android.cpp
    src/extract/apk.cpp
    src/extract/unreal.cpp
    src/extract/dart.cpp
    src/extract/flutter.cpp
    src/extract/unity.cpp
    src/extract/unity_registration_profile.cpp
    src/extract/dotnet.cpp
    src/extract/dotnet_native.cpp
    src/extract/wxapkg.cpp
    src/extract/asar.cpp
    src/extract/autoit.cpp
    src/extract/renpy.cpp
    src/extract/godot.cpp
    src/extract/cpython_extension.cpp
    src/extract/cpython_cython.cpp
    src/extract/cpython_frozen.cpp
    src/extract/cpython_static.cpp
    src/runtime/runtime.cpp
    src/runtime/materialization_graph.cpp
    src/runtime/cpython_probe_runtime.cpp
    src/runtime/cpython_introspection_protocol.cpp
    src/reference/cpython.cpp
    src/reference/cpython_frozen_reference.cpp
    src/reference/cpython_frozen_priority.cpp
    src/reference/cpython_frozen_gate.cpp
    src/reference/cpython_opcode.cpp
    src/reference/cpython_opcode_module.cpp
    src/reference/reference_registry.cpp
    src/reference/cpython_reference_pairing.cpp
    src/reference/cpython_probe.cpp
    src/reference/model_trust.cpp
    src/reference/semantic_delta.cpp
    src/reference/cpython_model_trust.cpp
    src/reference/x86_semantic.cpp
    third_party/miniz/miniz_zip.c
    third_party/miniz/miniz_tinfl.c
    third_party/miniz/miniz_tdef.c
    third_party/miniz/miniz.c
)
target_include_directories(auto_refirst PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated" include third_party/tiny_aes third_party/zydis)
target_include_directories(auto_refirst SYSTEM PRIVATE third_party/miniz)
set_target_properties(auto_refirst PROPERTIES OUTPUT_NAME "auto-refirst")
auto_refirst_enable_msvc_utf8(auto_refirst)
if(MSVC)
  # MSBuild /m parallelizes projects, but auto_refirst is one large project
  # with many translation units. Bound cl.exe intra-project parallelism to four
  # processes on the 4-vCPU public Windows runner; do not use unbounded /MP so
  # CI memory/CPU use remains predictable.
  target_compile_options(auto_refirst PRIVATE /W4 /permissive- /EHsc /MP4)
  target_compile_definitions(auto_refirst PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
  set_property(TARGET auto_refirst PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
  target_compile_options(auto_refirst PRIVATE -Wall -Wextra -Wpedantic)
endif()
auto_refirst_enable_warnings_as_errors(auto_refirst)

target_compile_definitions(auto_refirst PRIVATE AES256=1 ZYDIS_STATIC_BUILD=1 ZYAN_STATIC_BUILD=1)

if(WIN32)
  set(PECONV_LIB_INSTALL OFF CACHE BOOL "" FORCE)
  set(PECONV_LOG_VERBOSITY "NONE" CACHE STRING "" FORCE)
  add_subdirectory(third_party/libpeconv)
  if(MSVC)
    # Keep libPeConv on the same CRT and TCHAR ABI as the product target.
    # Otherwise MSVC sees /MD vs /MT and char vs wchar_t symbol mismatches.
    set_property(TARGET libpeconv PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions(libpeconv PRIVATE UNICODE _UNICODE)
    # libpeconv is a 29-source prerequisite project and is built before the
    # product target, so give it the same bounded intra-project parallelism.
    target_compile_options(libpeconv PRIVATE /utf-8 /wd4828 /MP4)
  endif()
  target_link_libraries(auto_refirst PRIVATE libpeconv)
  if(MSVC)
    target_link_libraries(auto_refirst PRIVATE shell32)
  else()
    target_link_options(auto_refirst PRIVATE -lshell32)
  endif()
  target_include_directories(auto_refirst PRIVATE third_party/libpeconv/include)
endif()


include(GNUInstallDirs)
install(TARGETS auto_refirst RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES README.md README_EN.md LICENSE NOTICE THIRD_PARTY_NOTICES.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/auto-refirst)
install(DIRECTORY LICENSES DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/auto-refirst)

# Explicit local supply-chain gates. They are opt-in targets so the normal
# product build does not acquire a Python configure-time dependency.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_custom_target(auto_refirst_public_provenance_check
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_third_party_provenance.py"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      USES_TERMINAL VERBATIM)

  set(_auto_refirst_install_check_config_args)
  if(CMAKE_CONFIGURATION_TYPES)
    set(_auto_refirst_install_check_config_args --config "$<CONFIG>")
  endif()
  add_custom_target(auto_refirst_public_install_stage_check
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_install_stage.py"
              --build-binary "$<TARGET_FILE:auto_refirst>"
              --build-dir "${CMAKE_CURRENT_BINARY_DIR}"
              ${_auto_refirst_install_check_config_args}
      DEPENDS auto_refirst auto_refirst_public_provenance_check
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      USES_TERMINAL VERBATIM)
endif()

# Self-contained public CI helpers. These are built on demand by the public regression runner.
add_executable(auto_refirst_public_model_trust_unit EXCLUDE_FROM_ALL
    tests/model_trust_unit.cpp
    src/reference/model_trust.cpp
)
target_include_directories(auto_refirst_public_model_trust_unit PRIVATE include)

add_executable(auto_refirst_public_python_bytecode_unit EXCLUDE_FROM_ALL
    tests/python_bytecode_ingress_unit.cpp
    src/formats/python_bytecode.cpp
    src/formats/python_marshal.cpp
    src/core/sha256.cpp
)
target_include_directories(auto_refirst_public_python_bytecode_unit PRIVATE include)

add_executable(auto_refirst_public_flutter_codec_unit EXCLUDE_FROM_ALL
    tests/flutter_codec_unit.cpp
    src/extract/flutter.cpp
)
target_include_directories(auto_refirst_public_flutter_codec_unit PRIVATE include)

add_executable(auto_refirst_public_path_utf8_unit EXCLUDE_FROM_ALL
    tests/path_utf8_unit.cpp
)
target_include_directories(auto_refirst_public_path_utf8_unit PRIVATE include)

add_executable(auto_refirst_public_nuitka_unit EXCLUDE_FROM_ALL
    tests/nuitka_unit.cpp
    src/extract/nuitka.cpp
    src/extract/nuitka_version.cpp
    src/core/zstd_wrap.c
    third_party/zydis/Zydis.c
)
target_include_directories(auto_refirst_public_nuitka_unit PRIVATE include third_party/zydis)
target_compile_definitions(auto_refirst_public_nuitka_unit PRIVATE ZYDIS_STATIC_BUILD=1 ZYAN_STATIC_BUILD=1)

add_executable(auto_refirst_public_static_scan_unit EXCLUDE_FROM_ALL
    tests/static_scan_unit.cpp
    src/core/static_scan.cpp
)
target_include_directories(auto_refirst_public_static_scan_unit PRIVATE include)

add_executable(auto_refirst_public_pyinstaller_reference_unit EXCLUDE_FROM_ALL
    tests/pyinstaller_reference_unit.cpp
    src/extract/pyinstaller_reference.cpp
)
target_include_directories(auto_refirst_public_pyinstaller_reference_unit PRIVATE include)

add_executable(auto_refirst_public_unity_registration_profile_unit EXCLUDE_FROM_ALL
    tests/unity_registration_profile_unit.cpp
    src/extract/unity_registration_profile.cpp
)
target_include_directories(auto_refirst_public_unity_registration_profile_unit PRIVATE include src/extract)

add_executable(auto_refirst_public_fixture_ordinary EXCLUDE_FROM_ALL tests/public/ordinary.c)
add_executable(auto_refirst_public_fixture_crypto EXCLUDE_FROM_ALL tests/public/crypto_tea.c)
add_executable(auto_refirst_public_fixture_runtime_child EXCLUDE_FROM_ALL tests/public/runtime_child.c)
add_executable(auto_refirst_public_fixture_runtime_parent EXCLUDE_FROM_ALL tests/public/runtime_parent.c)

foreach(_public_target
        auto_refirst_public_model_trust_unit
        auto_refirst_public_python_bytecode_unit
        auto_refirst_public_flutter_codec_unit
        auto_refirst_public_path_utf8_unit
        auto_refirst_public_nuitka_unit
        auto_refirst_public_static_scan_unit
        auto_refirst_public_pyinstaller_reference_unit
        auto_refirst_public_unity_registration_profile_unit
        auto_refirst_public_fixture_ordinary
        auto_refirst_public_fixture_crypto
        auto_refirst_public_fixture_runtime_child
        auto_refirst_public_fixture_runtime_parent)
    auto_refirst_enable_msvc_utf8(${_public_target})
endforeach()

foreach(_public_target
        auto_refirst_public_model_trust_unit
        auto_refirst_public_python_bytecode_unit
        auto_refirst_public_flutter_codec_unit
        auto_refirst_public_path_utf8_unit
        auto_refirst_public_nuitka_unit
        auto_refirst_public_static_scan_unit
        auto_refirst_public_pyinstaller_reference_unit
        auto_refirst_public_unity_registration_profile_unit)
    if(MSVC)
        target_compile_options(${_public_target} PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(${_public_target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    auto_refirst_enable_warnings_as_errors(${_public_target})
endforeach()

# Parser-only sanitizer surface. It deliberately excludes runtime execution paths and
# links the same PE/ELF/JVM/DEX/Wasm/Hermes/Lua parser implementations used by the product.
add_executable(auto_refirst_public_malformed_sanitizer EXCLUDE_FROM_ALL
    tests/public/malformed_sanitizer.cpp
    src/formats/pe.cpp
    src/formats/elf.cpp
    src/extract/wasm.cpp
    src/extract/hermes.cpp
    src/extract/jvm.cpp
    src/extract/android.cpp
    src/extract/lua.cpp
    src/extract/unity_registration_profile.cpp
    src/core/sha1.cpp
    third_party/miniz/miniz_zip.c
    third_party/miniz/miniz_tinfl.c
    third_party/miniz/miniz_tdef.c
    third_party/miniz/miniz.c
)
target_include_directories(auto_refirst_public_malformed_sanitizer PRIVATE include src/extract)
target_include_directories(auto_refirst_public_malformed_sanitizer SYSTEM PRIVATE third_party/miniz)
auto_refirst_enable_msvc_utf8(auto_refirst_public_malformed_sanitizer)
if(MSVC)
    target_compile_options(auto_refirst_public_malformed_sanitizer PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(auto_refirst_public_malformed_sanitizer PRIVATE -Wall -Wextra -Wpedantic)
endif()
auto_refirst_enable_warnings_as_errors(auto_refirst_public_malformed_sanitizer)
