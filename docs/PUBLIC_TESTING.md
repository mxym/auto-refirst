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
- Nuitka onefile filename geometry与 PyInstaller/Godot route-only 边界：onefile filename 遵循 upstream bootstrap 的 1024-char buffer（最大 1023 字符）；PyInstaller/`pyimod` 纯字符串以及裸 `PYZ\0` / `GDPC` 在 static/embedded finding 层都只保留 `SUSPECTED`；裸 `_MEI` 不再路由，历史/当前 `_MEIXXXXXX`、`_MEI%...`、`_MEIPASS*`、`_PYI_APPLICATION_HOME_DIR` 特异标识仍保留；CArchive/PYZ/PCK 深层结构闭合后才提升；
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
