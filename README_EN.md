# auto-refirst

Evidence-driven binary preprocessing for reverse engineering and CTF workflows.

`auto-refirst` runs before the main decompiler/debugger stage: it identifies formats and ecosystems, expands bounded nested artifacts, extracts high-value evidence, ranks directory inputs, and can optionally perform runtime materialization and reconstruction. Static analysis is the default. Target execution requires explicit `--run`; validated installation requires the additional `--apply` authorization.

Current public version: **0.1.0-rc.2**.

中文: [README.md](README.md)

## Quick start

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./build/auto-refirst ./target --json
```

Directories recurse by default:

```sh
./build/auto-refirst ./challenge-directory --json
```

Full/heavy static materialization:

```sh
./build/auto-refirst ./target --extract --recursive --json
```

Opt-in runtime analysis:

```sh
./build/auto-refirst ./target --run --json
```

Validated transactional installation additionally requires `--apply`:

```sh
./build/auto-refirst ./target --run --apply --json
```

See [docs/CLI.md](docs/CLI.md), the exact [CLI process and authorization contract](docs/CLI_CONTRACT.md), [docs/BUILD.md](docs/BUILD.md), and the maintainer [release checklist](docs/RELEASE_CHECKLIST.md).

## Capability groups

- Native executable parsing: PE, ELF, Mach-O/Universal Mach-O, including bounded Swift metadata records without source or full-semantic recovery claims.
- Managed and bytecode formats: JVM/JAR, DEX/APK/JNI relations, WebAssembly, Lua, Hermes HBC, ECMA-335/.NET single-file/NativeAOT, and CPython bytecode/runtime evidence.
- Packers and ecosystems: UPX and bounded PE packer/protector evidence, PyInstaller, Nuitka, Electron/ASAR, AutoIt, Ren'Py/RPA, wxapkg, Unreal Pak/IoStore, Go, Rust, and Dart/Flutter.
- Unity and Godot routing/materialization, including Mono/IL2CPP and PCK/GDScript/GDExtension evidence.
- Anti-debug, crypto-use, implicit execution, interpreter boundaries, exceptional control flow, cross-file relationships and analysis guidance.
- Bounded recursive artifact graph with provenance, SHA-256 deduplication and static child re-analysis.
- Directory-scale prioritization and bounded report/artifact output.
- Opt-in runtime materialization, reconstruction and independently validated transactional installation on supported host backends.

See [docs/CAPABILITIES.md](docs/CAPABILITIES.md) for detailed boundaries.

## Validation

A frozen 36-case external holdout completed 36/36 after the directory resource fixes. The accepted evaluation reported no false HIGH promotion, no wrong semantic promotion and no clearly wrong top-priority route. Detailed scoring, resource observations and known gaps are documented in [docs/VALIDATION.md](docs/VALIDATION.md).

## Safety

Static analysis does not execute the target. `--run` executes untrusted target code and should be used in an isolated environment. `--apply` is a separate installation authorization protected by the implemented validation and rollback gates. See [SECURITY.md](SECURITY.md).

## License

Project-owned original source is Apache-2.0. Vendored components retain their own terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), [LICENSES/](LICENSES/) and [SBOM.spdx.json](SBOM.spdx.json).
