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
