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
- Bounded algorithm recognition on supported PE64/x64 layouts and function boundaries: compositional evidence for TEA/XTEA, RC4 KSA, AES-NI, and CryptoAPI/BCrypt/OpenSSL EVP calls, parameters and key/IV use. This is not a claim of universal algorithm classification, arbitrary key recovery or plaintext validation.
- Bounded recursive artifact graph with provenance, SHA-256 deduplication and static child re-analysis.
- Directory-scale prioritization and bounded report/artifact output.
- Opt-in runtime materialization, reconstruction and independently validated transactional installation on supported host backends.

See [docs/CAPABILITIES.md](docs/CAPABILITIES.md) for detailed boundaries.

## RC.2 progress

Included in the public capability contract:

- Hermes HBC v89/v96/v98 and exact APK content-child routing;
- Unreal Pak/IoStore framing and UTOC/UCAS pair relationships;
- .NET single-file bundles, Linux NativeAOT and bounded Mach-O/Swift structural metadata;
- APK JNI exports, `RegisterNatives` and strict Modified UTF-8 relationship evidence;
- the bounded PE64/x64 TEA/XTEA, RC4 KSA, AES-NI and common crypto-API context described above.

Experimental auxiliary path: `tools/de4dotex/` contains a disabled-by-default Linux/x86_64 de4dotEx adapter source and exact manifest. Neither the repository nor release assets bundle de4dotEx, .NET or bubblewrap. Invocation requires explicit `--run` and the full isolation contract; results remain `PARTIAL`, output DLLs must be reparsed by the core product, and the current Windows/Wine route is `NO-GO`. This is not universal restoration support for arbitrary .NET obfuscators.

Still under research and not included in RC.2: broader algorithm generalization beyond validated patterns, ABIs and layouts, and a separate kernel/virtualization dynamic-observer by-product. These are outside the default path, P0/P1 and release assets, and make no compatibility, stealth or support promise.

## Validation

The historical `0.1.0-alpha.1` 36-case external holdout completed 36/36 after the directory resource fixes. It reported no false HIGH promotion, no wrong semantic promotion and no clearly wrong top-priority route. These are not new RC.2 results; detailed scoring, resource observations and the then-known gaps are documented in [docs/VALIDATION.md](docs/VALIDATION.md).

The frozen `v0.1.0-rc.2` commit is `8cb0416d6b273c1807948ae89bd4ff8043fb1d4e`. That exact commit completed local Linux Release/ASan and native Windows gates, three hosted exact-commit CI runs, and post-publication fresh download-back and cross-platform verification of all nine assets. Run IDs, hashes and exact scope are recorded on the [RC.2 release page](https://github.com/mxym/auto-refirst/releases/tag/v0.1.0-rc.2) and in [the public testing notes](docs/PUBLIC_TESTING.md).

The earlier maintainer candidate's full-suite totals (125 PASS, 25 Windows-labelled PASS and 0 SKIP) were not rerun at `8cb0416`. They are not RC.2 exact-commit evidence and do not extend RC.2 capability claims.

## Safety

Static analysis does not execute the target. `--run` executes untrusted target code and should be used in an isolated environment. `--apply` is a separate installation authorization protected by the implemented validation and rollback gates. See [SECURITY.md](SECURITY.md).

## Known limitations

The current RC does not claim Swift source/full-semantic recovery, decrypted Unreal asset semantics, universal restoration of arbitrary .NET obfuscators, deep Dart semantics, a general VM solver, whole-program symbolic execution or general decompilation.

Algorithm recognition is bounded by architecture, function boundaries, call-chain closure and data flow. An S-box, delta, name, string or single constant is only a candidate signal and cannot establish a high-confidence semantic conclusion by itself. A recovered key/IV also does not prove successful decryption or plaintext correctness.

Only evidence that reproduces across independent positive, mutation and negative samples is promoted into the supported product path. Single examples, name/string-baited rules and challenge-specific identities remain unsupported or research-only.

## License

Project-owned original source is Apache-2.0. Vendored components retain their own terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), [LICENSES/](LICENSES/) and [SBOM.spdx.json](SBOM.spdx.json).
