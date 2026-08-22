# 构建与安装

## Linux x86-64

要求：CMake 3.20+、支持 C++20 的 GCC/Clang、常规 libc/libstdc++ 开发环境。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./build/auto-refirst --version
```

安装：

```sh
cmake --install build --prefix ./stage
```

## Windows x64

推荐使用 Visual Studio 2022 / MSVC 的 x64 Developer Command Prompt：

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\auto-refirst.exe --version
```

也可以使用 MinGW/UCRT64 或 Zig `x86_64-windows-gnu` 交叉构建。仓库内 `cmake/windows-zig-x64.cmake` 使用 `tools/zig-cc-win64` / `zig-cxx-win64`；设置 `ZIG=/path/to/zig` 或确保 `zig` 在 PATH 中。

```sh
ZIG=/path/to/zig cmake -S . -B build-win \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake/windows-zig-x64.cmake
ZIG=/path/to/zig cmake --build build-win --parallel
```

## Public regression

```sh
python3 tests/run_public_regression.py --binary build/auto-refirst --tier all
```

Windows 多配置生成器需要将 `--binary` 指向实际配置目录中的 executable。

候选发布构建应显式启用 warnings-as-errors，并要求 binary 内嵌的完整 commit
与 clean source 精确一致：

```sh
cmake -S . -B build-strict -DCMAKE_BUILD_TYPE=Release \
  -DAUTO_REFIRST_WARNINGS_AS_ERRORS=ON
cmake --build build-strict --parallel
python3 tests/run_public_regression.py \
  --binary build-strict/auto-refirst --tier all --require-clean-source
python3 tests/test_build_metadata_source_root.py
```

Windows 多配置生成器省略 `CMAKE_BUILD_TYPE`，并在 build 命令增加
`--config Release`。`--version` 会分别报告 product version、完整 source
commit、目标平台及 report schema version；source archive 只有在 source root
没有 `.git` 时才接受 release harness 注入的完整 40/64 位 commit。

本地 provenance 与安装 allowlist gate：

```sh
cmake --build build --target auto_refirst_public_provenance_check
cmake --build build --target auto_refirst_public_install_stage_check
```

Windows 多配置生成器在上述命令后增加 `--config Release`。安装 gate 会把当前
build 暂存到临时 prefix，逐字节核对 binary、README、NOTICE、项目许可证及
`LICENSES/`，并拒绝额外文件、目录和链接。

## Sanitizer smoke

GCC/Clang：

```sh
cmake -S . -B build-san -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-san --target auto_refirst_public_malformed_sanitizer --parallel
python3 tests/run_public_regression.py \
  --binary build-san/auto_refirst_public_malformed_sanitizer --sanitizer-smoke
```
