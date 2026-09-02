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
- Unity v106.1 vtable/RGCTX 外部/受控回放：版本匹配的 `js6pak/libil2cpp-archive` tags `6000.5.0a6` (`ddfa46701c5c4ac6b5418f36702d7dfbe045052f`) 与 `6000.6.0a6` (`43698b1f03d2e13a0a7f6a68f2264a3d48e62b80`) 确认两代 runtime 的 vtable 都把 metadata `vtableMethods` 交给 `GetMethodInfoFromEncodedIndex()`；6000.6.0a6 constrained RGCTX 已从单个 pointer payload 改为相邻 `CONSTRAINED_CALL_TYPE`/`METHOD` inline records，并同样把 METHOD 的 `__encodedMethodIndex` 交给该 decoder。对应 `Il2CppVersions` 6000.6.0a6 header 仍保留 CodeGenModule RGCTX arrays，但 `Il2CppMetadataUsage` 已删除旧 `Il2CppType` kind；6000.6.0b1 才进一步迁移到 metadata-global RGCTX。产品级受控派生样本从真实 Cpp2IL 6000.5.0a6 bytes 出发：新增独立 PE section 承载 9-pair registration（zero always-init），只重定向 registration thunk 的 MetadataRegistration LEA，将 engine evidence 改为 `6000.6.0a6`，把 98478 个 vtable entries 的 raw MethodDef/MethodRef 从 3/6 转为 2/5，并把 31 个 CodeGenModule 的 17099 条 16-byte pointer RGCTX records 原位转换成 17692 条 8-byte inline records（593 个 constrained records 拆为 TYPE/METHOD 对）。独立结构审计与产品回放均通过：`normalized=106.1`，type-dispatch `RESOLVED`，vtable 90862 MethodDef + 6824 MethodRef + 792 `ENTRY_POINT_NOT_FOUND` sentinel，rgctx `compact-inline-8` 17692/17692、593 constrained。派生样本刻意保留真实 v106 runtime metadata initializer/usage slots（其中有 365 个已被 106.1 删除的 `Il2CppType` usages），所以 metadata-usage plane 必须因 compact wrapper/core contract 不成立而 `FAILED`；没有把不等价语义伪造成 106.1。真实 v106 与 v108 的 sentinel 重分类也交叉验证：此前被称为 null 的 encoded `7` 分别有 792/737 条，按 runtime 实际是 InvalidMetadataUsage token 3 `EntryPointNotFound`；修正后两者 `vtable_null=0`、`vtable_invalid=792/737`，MethodDef/MethodRef、exact-slot/interface-mapped 计数保持不变。额外产品 mutation 验证 compact vtable 非 method kind、未知 invalid token source 5、以及跨断的 constrained TYPE/METHOD pair 均 fail-closed；P0 codec unit 另覆盖 invalid token 0..4 名称、unknown token rejection、traditional/compact MethodDef/MethodRef mapping 与 106/106.1/107 RGCTX profile 选择。受控派生与 mutation bytes 只在本地研究目录生成，不入库、不分发。
- Unity pre-v108 MethodDef dispatch 外部/受控回放：版本匹配的 libil2cpp `6000.5.0a6` / `6000.6.0a6` `MetadataCache::GetMethodPointer/GetMethodInvoker/GetAdjustorThunk` 实现逐行一致：token RID 索引 module-local `methodPointers`/`invokerIndices`，adjustor 通过有序 MethodDef token 表查找。对真实 Cpp2IL `Simple_6000_5_0_a6` 做独立全量 PE/CSV 交叉，71/71 个 CodeGenModule 与 71 个 metadata image 一一对应，62281 个 `methodPointerCount`/MethodDef 完全覆盖，62281/62281 `methodPointers[rid-1]` 与既有独立 native-bound RVA 逐条一致；全局 16638 个 invoker pointer 全部 executable，53626 个 MethodDef 有有效 invoker、8655 个为 `-1` missing，7477 个 adjustor token 全部严格递增、同 module 有 MethodDef owner且 thunk executable；另将首个 pair 的 4-byte ABI padding 改为非零后仍必须 `RESOLVED`，证明 padding 不被误当协议字段。产品启用 `pre-v108-module-method+invoker+token-adjustor` 后复现相同计数，完整 `unity-symbols.csv` 62281 行中恰有 53626 行 invoker 与 7477 行 adjustor。受控 declared-v107 backport 与 controlled normalized 106.1 均恢复相同 62281/53626/8655/7477；真实 v108 的既有 `56028/47924/8104/2199` 与 static-init `32/13` profile逐字段不变。产品级 mutation 将一个 invoker index 改为全局 count 或把 adjustor token 改为非 MethodDef owner时，仅 method-dispatch plane `FAILED`，registration/RGCTX 保持已确认；后段 module 的 adjustor failure 还验证 62281 行 `unity-symbols.csv` 的 invoker/adjustor 字段全部保持空，证明 plane 采用全局事务式提交而不会泄漏前序 module partial evidence。受控派生/negative native bytes 测后即删除，仅保留小型 JSON/manifest；P0 helper unit 与 required sanitizer 另覆盖 RID/count/invoker/adjustor semantic contract。

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
