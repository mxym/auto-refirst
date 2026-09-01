# 公开测试

公开仓库只包含可再分发、可解释来源的测试数据以及 source-generated/synthetic fixtures。

## P0 — self-contained core

P0 校验：

- 13 个公开 fixture 的 provenance 与 SHA-256；
- PE/ELF/JVM/DEX/Wasm/Lua/Hermes 静态格式边界；
- 跨文件关系与目录 guidance；
- interpreter/runtime-modality 静态授权边界；
- nested executable 与 recursive artifact graph；
- model trust 与 CPython bytecode ingress；
- Nuitka 弱字符串不提升、constant/onefile 结构 gate；现代 variable-length 与 legacy fixed-width（32/64-bit C-long）constant stream 正例、旧 `G` GenericAlias/固定宽度 bigint 语义、尾随字节和未知 tag fail-closed；以及 ELF64/x86-64 `__compiled__` version tuple 的直接符号/导入 PLT 合成正例、candidate/releaselevel 语义与 descriptor/字段/构造器/导入符号扰动负例；
- Unity 裸词不路由，以及 Godot identifier/`encrypted pack` 的 ASCII 词边界路由：真实 `Godot Engine`、`encrypted pack directory` / `encrypted pack-referenced` 保留，普通 `bigodot` / `encrypted packet` 不再触发 Godot；string-only Godot 证据保持 `SUSPECTED`，结构化 PCK 由独立解析器提升；
- Unity engine-version / v106-v108 source-generated P0：严格 Unity 版本 grammar、serialized-file v21/v22 `globalgamemanagers` header、`UnityFS` v6-v8 header、有界向上目录关联、双来源 consensus/conflict，以及“仅在固定偏移出现版本字符串但 header 非法”不得确认。v106/v107 profile unit 覆盖 Unity `6000.6.0a6`/`6000.6` 归一化边界、engine/structure corroboration、zero-tail 消歧、strong-tail 冲突，以及“engine 指向 106.1 但第 9 pair malformed/non-file-backed”必须 `INVALID`；106.1 always-init strong evidence 进一步要求 writable/file-backed `TypeInfo` runtime tokens，非 TypeInfo、source 越界或 low-bit=0 均拒绝。独立 metadata-usage codec unit 覆盖 declared 106/107 的 normalized `106`/`106.1` profile 选择、traditional/compact kind 映射、runtime-token low bit/source 解码、compact raw-kind overflow 和 runtime kind compare limit `6/5`。required malformed sanitizer 会实际执行 registration closure 与共享 codec 依赖。
- Unity 6.x 外部真实回放（研究输入不入库）：Cpp2IL `TestFiles/Simple_6000_5_0_a6` 的官方 `GameAssembly.dll` + `global-metadata.dat`（metadata v106）在没有 engine evidence 时保持 `AMBIGUOUS/common-8pair`；加入 256-byte source-generated `UnityFS` `6000.5.0a6` header 后闭合为 `RESOLVED/traditional-8pair/106` 且 v106 metadata-usage 恢复。把同一个 engine header 故意改成 `6000.6.0a6` 时必须 `INVALID_PROFILE`，证明版本证据不会修复 unresolved 第 9 pair。Cpp2IL `Simple_6000_6_0_b1`（metadata v108）则保持 `v108 compact-7pair` 且 `metadata_registration_engine_hint` 为空，验证 106/107 closure 不越界影响 v108。外部 fixture 只用于本地交叉验证，不分发其字节。 该回放固定于 Cpp2IL `development` commit `1f59b73e27e8c614845107c24474f30fb881ba2b`；6000.5 GameAssembly/metadata Git blob 分别为 `4c2c3abb7e066ad5a588a73ad1ffd00cd32d6a1d` / `f057d19be15abd0d16843a2265c42e421860db93`，6000.6 为 `dfdcb3e54471ba8360de675c214ba50c75c6f5ec` / `395cb2992d707114396eeaf36e1354c437161d93`。
- Unity metadata-usage 外部/受控回放：同一真实 Cpp2IL 6000.5/v106 样本在新 codec 下仍 `RESOLVED`，31601 个 usage 不变；真实 6000.6.0b1/v108 仍为 26332 个 usage，其中 116 个 always-init + 26216 个 runtime-discovered，独立直接读取其完整 116-entry eager 表确认 116/116 都是 raw kind 1 `TypeInfo`、low-bit=1、high32=0。受控派生回放把真实 v108 registration 的 always-init pair 改为合法 0/0 后仍恢复 26216 个 runtime usage 且 eager=0；另把真实 6000.5 metadata 的 declared integer 106 改为 107、source-generated engine evidence 改为 `6000.5.1f1`，验证 v107 backport 归一化到 traditional 106 后仍恢复同样 31601 usages。没有找到来源清晰且体积合理的公开 6000.6.0a6 IL2CPP fixture，因此不把受控派生样本宣称为真实 106.1；106.1 enum/registration ABI 由 `nneonneo/Il2CppVersions` commit `8a51ff05ea28a33fda2804197f3c2f1afff6f0c8` 的 6000.5.0a6/6000.6.0a6/a7/b1 headers 交叉确认，runtime token / `alwaysInitMetadataUsages` 行为由 `js6pak/libil2cpp-archive` commit `8893ff0e0b179b76c7a5dd4d296517da7f570c69` 的 `GlobalMetadata` / `MetadataCache` 实现交叉确认；这些上游内容只作为研究参照，不分发其字节。

- Nuitka onefile filename geometry与 PyInstaller/Godot route-only 边界：onefile filename 遵循 upstream bootstrap 的 1024-char buffer（最大 1023 字符）；PyInstaller/`pyimod` 纯字符串以及裸 `PYZ\0` / `GDPC` 在 static/embedded finding 层都只保留 `SUSPECTED`；裸 `_MEI` 不再路由，历史/当前 `_MEIXXXXXX`、`_MEI%...`、`_MEIPASS*`、`_PYI_APPLICATION_HOME_DIR` 特异标识仍保留；CArchive/PYZ/PCK 深层结构闭合后才提升；
- PyInstaller bootstrap reference profile：公开 synthetic unit 覆盖 `LEGACY_CORE`、`MODERN_CORE`、`WINDOWS_EXTENSION` 三类 source component，验证 v5.3 只有 modern core、v5.5 才引入 Windows extension、不同 core generation 必须 fail-closed、core 与 Windows extension generation 独立且最终 release candidates 必须取两者交集，以及 Python 3.15 compatibility 只允许 6.21+。`struct` 被明确视为 auxiliary CPython stdlib witness，不参与 PyInstaller source-generation closure。`tests/generate_pyinstaller_loader_generation.py --source-repo <official-checkout> --through v6.22.2` 可从官方 stable tags 重放 `src/reference/pyinstaller_loader_generations.inc`；当前 catalog 覆盖 v4.10–v6.22.2 共 50 个 stable releases、30 个 component/compatibility rows。`tests/check_pyinstaller_reference_catalog.py` 已接入 P0 provenance gate，验证每个 release 恰有一个 core、Windows extension 只可附着 modern core、raw/semantic payload row 的 label 与模块必须映射到正确 component 且 Python minor 落在官方 compatibility 范围内。真实研究还用 Python 3.10.11 在 Linux/Windows 分别构建并运行 PyInstaller 5.2、5.3、5.4.1、5.5 onefile，版本匹配的官方 `CArchiveReader` 独立确认 5.2 仍为旧四模块、5.3/5.4.1 为现代三 core、5.5 仅 Windows 新增 `pyimod04_pywin32`，且官方 reader 提取的 preload raw size/SHA-256 与项目 generator 逐项一致；对应 required-module semantic hash 在两平台稳定并进入 compact refs。真实研究矩阵覆盖 Windows Python 3.10.0–3.10.11、3.11.0–3.11.9、3.12.0–3.12.10、3.13.0–3.13.15、3.14.0–3.14.7 的 PyInstaller 6.22.2 onefile；Linux 又复核 3.11/3.12 endpoints 及 3.13.0/3.13.4/3.13.15、3.14 首尾，证明跨平台 core semantic hash 一致。3.13 的 `pyimod02_importers` 与 `pyimod04_pywin32` 在 3.13.0、3.13.4 形成两个额外 bounded compiler variants。多个真实压缩 payload 单字节破坏样本仍保持 CArchive 独立 `CONFIRMED`，同时 bootstrap reference 降为 `REFERENCE_DIFF/SUSPECTED`，证明 component-generation metadata 不能绕过 payload fail-closed。
- JSON/text/version 与 `0/1/2/3/4` process contract；
- APK/Hermes child 与 APK/JNI J0-J4 结构关系的有界静态 gate；
- Windows junction/reparse 输出安全（Windows runner）。

## P1 — source-generated integration

P1 从仓库源码构建普通 native、crypto、runtime-child/runtime-parent fixtures，并验证分析仍保持 static-only。Python bytecode fixture 由测试脚本按固定字节格式生成。

P1 还运行 .NET bundle/NativeAOT、Mach-O/Swift、Unreal Pak/IoStore 与完整 Hermes HBC 的 source/project-generated focused gates；这些 gate 不属于 P0。

运行：

```sh
python3 tests/run_public_regression.py --binary build/auto-refirst --tier all
```

P0/P1 不下载 challenge corpus，不执行分析目标，不需要任何私有 fixture root。

## RC.2 exact-commit 证据边界

`v0.1.0-rc.2` 的公开冻结提交为 `8cb0416d6b273c1807948ae89bd4ff8043fb1d4e`。该提交自身的发布证据包括本地 Linux Release/ASan、原生 Windows、三项 hosted exact-commit CI（runs `32693325705`、`32693325671`、`32693325702`），以及发布后九件资产的 fresh download-back 双平台复核。

上一阶段维护候选的 maintainer-only 完整回归统计（125 PASS、25 个 Windows-labelled PASS、0 SKIP）没有在 `8cb0416` 上重跑。它不是 RC.2 exact-commit 证据，不能用于扩大 RC.2 的能力或兼容性声明。

完整 hosted run、资产哈希和验证边界见 [v0.1.0-rc.2 发布页](https://github.com/mxym/auto-refirst/releases/tag/v0.1.0-rc.2)。

## Sanitizer surface

`auto_refirst_public_malformed_sanitizer` 只链接 PE/ELF/JVM/DEX/Wasm/Hermes/Lua parser 相关路径，用 malformed synthetic inputs 执行 ASan+UBSan smoke。

## Fixture provenance

公开 fixture inventory 位于 `tests/corpus/PROVENANCE.csv`。新增持久二进制 fixture 必须记录 generator/source、toolchain、license/redistribution basis、rebuild command 和 SHA-256。
