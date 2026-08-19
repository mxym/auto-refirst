# Third-party notices

auto-refirst is licensed under Apache-2.0 for project-owned original source. Vendored components retain their original terms. The corresponding license texts are included in `LICENSES/` and, where provided upstream, beside the vendored source.

## Components compiled into the product

| Component | Vendored identity | License | Use | Local changes |
|---|---|---|---|---|
| libPeConv | `0fc25f680e03699d33ef3b2034a6724365f3d1a4` | BSD-2-Clause | Windows static link | none in vendored code |
| miniz | `3.1.2`, `77d0dce8627735138c51770d1799a1ef48f2117d` | MIT | Linux/Windows static compile | local compatibility header |
| tiny-AES-c | `1.0.0`, `23856752fbd139da0b8ca6e471a13d5bcc99a08d` | Unlicense | Linux/Windows static compile | none |
| Zstandard single-file decoder | `1.6.0-dev`, `82d322c4973d9e2968d94047a40892bc6d9a9bdf` | BSD-3-Clause | Linux/Windows static compile | none |
| rustc-demangle native-c | `f36e2988643d7db47a6aa6e328cc7ffd61343651` | MIT OR Apache-2.0 | Linux/Windows static compile | `MIN`/`MAX` compatibility macros |
| Zydis | `v4.1.1`, `a2278f1d254e492f6a6b39f6cb5d1f5d515659dc` | MIT | Linux/Windows static compile | generator source-path comments normalized |
| Zycore-C | `v1.5.2`, `0b2432ced0884fd152b471d97ecf0258ff4d859f` | MIT | embedded in the Zydis amalgamation | none identified |

Binary distributions should include `LICENSE`, `NOTICE`, this file, and `LICENSES/`.

## Reference inputs

Several product tables were generated from documented facts or normalized fingerprints derived from upstream implementations and formats. These projects are reference inputs and are not linked product dependencies:

- CPython — interpreter/version/export/opcode/reference facts. See `LICENSES/CPython-PSF-2.0.txt`.
- UPX — normalized packer/reference fingerprints. See `LICENSES/UPX-LICENSE.txt` and `LICENSES/UPX-COPYING-GPL-2.0.txt`.
- Go and Dart toolchains were used during compatibility research; retained public test fixtures are project-owned and source-backed.

The public repository does not contain private challenge attachments or opaque historical regression corpora. Public fixture provenance is recorded in `tests/corpus/PROVENANCE.csv`.
