cmake_minimum_required(VERSION 3.20)
project(AutoRefirst VERSION 0.1.0 LANGUAGES C CXX)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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
    src/formats/python_marshal.cpp
    src/formats/python_bytecode.cpp
    src/unpack/replacement.cpp
    src/unpack/repair.cpp
    src/extract/pyinstaller.cpp
    src/extract/nested_executable.cpp
    src/extract/container_ingress.cpp
    src/extract/nuitka.cpp
    src/extract/lua.cpp
    src/extract/wasm.cpp
    src/extract/jvm.cpp
    src/extract/android.cpp
    src/extract/apk.cpp
    src/extract/dart.cpp
    src/extract/flutter.cpp
    src/extract/unity.cpp
    src/extract/dotnet.cpp
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
target_include_directories(auto_refirst PRIVATE include third_party/miniz third_party/tiny_aes third_party/zydis)
set_target_properties(auto_refirst PROPERTIES OUTPUT_NAME "auto-refirst")
if(MSVC)
  target_compile_options(auto_refirst PRIVATE /W4 /permissive- /EHsc)
  target_compile_definitions(auto_refirst PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
  set_property(TARGET auto_refirst PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
  target_compile_options(auto_refirst PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_compile_definitions(auto_refirst PRIVATE AES256=1 ZYDIS_STATIC_BUILD=1 ZYAN_STATIC_BUILD=1)

if(WIN32)
  set(PECONV_LIB_INSTALL OFF CACHE BOOL "" FORCE)
  set(PECONV_LOG_VERBOSITY "NONE" CACHE STRING "" FORCE)
  add_subdirectory(third_party/libpeconv)
  target_link_libraries(auto_refirst PRIVATE libpeconv shell32)
  target_include_directories(auto_refirst PRIVATE third_party/libpeconv/include)
endif()


include(GNUInstallDirs)
install(TARGETS auto_refirst RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES README.md README_EN.md LICENSE NOTICE THIRD_PARTY_NOTICES.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/auto-refirst)
install(DIRECTORY LICENSES DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/auto-refirst)

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

add_executable(auto_refirst_public_fixture_ordinary EXCLUDE_FROM_ALL tests/public/ordinary.c)
add_executable(auto_refirst_public_fixture_crypto EXCLUDE_FROM_ALL tests/public/crypto_tea.c)
add_executable(auto_refirst_public_fixture_runtime_child EXCLUDE_FROM_ALL tests/public/runtime_child.c)
add_executable(auto_refirst_public_fixture_runtime_parent EXCLUDE_FROM_ALL tests/public/runtime_parent.c)

foreach(_public_target
        auto_refirst_public_model_trust_unit
        auto_refirst_public_python_bytecode_unit)
    if(MSVC)
        target_compile_options(${_public_target} PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(${_public_target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endforeach()

# Parser-only sanitizer surface. It deliberately excludes runtime execution paths and
# links the same PE/ELF/JVM/DEX/Wasm/Lua parser implementations used by the product.
add_executable(auto_refirst_public_malformed_sanitizer EXCLUDE_FROM_ALL
    tests/public/malformed_sanitizer.cpp
    src/formats/pe.cpp
    src/formats/elf.cpp
    src/extract/wasm.cpp
    src/extract/jvm.cpp
    src/extract/android.cpp
    src/extract/lua.cpp
    src/core/sha1.cpp
    third_party/miniz/miniz_zip.c
    third_party/miniz/miniz_tinfl.c
    third_party/miniz/miniz_tdef.c
    third_party/miniz/miniz.c
)
target_include_directories(auto_refirst_public_malformed_sanitizer PRIVATE include third_party/miniz)
if(MSVC)
    target_compile_options(auto_refirst_public_malformed_sanitizer PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(auto_refirst_public_malformed_sanitizer PRIVATE -Wall -Wextra -Wpedantic)
endif()
