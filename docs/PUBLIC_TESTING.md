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
- PyInstaller bootstrap reference profile：公开 synthetic unit 覆盖 legacy 4.x 与 modern 5.x/6.x profile、Linux/macOS 不要求 Windows-only `pyimod04_pywin32`、该模块一旦存在则必须与三个跨平台核心共同匹配同一 label、混合 profile/label 冲突均 fail-closed。`tests/generate_pyinstaller_loader_refs.py` 可从外部构建的标准 CArchive 样本生成 compact raw/semantic rows；脚本要求 TOC 精确闭合，并调用项目自己的 `marshal-hash` helper，仓库只保留模块名、大小和 hash，不保存 upstream loader bytecode。研究矩阵使用 Python 3.10 官方 manylinux wheel 构建的 PyInstaller 4.10/5.13.2/6.0.0/6.16.0/6.22.2 样本，并使用 GitHub-hosted Windows x64 + Python 3.10.11 + 官方 win_amd64 wheels 生成/运行同版本 onefile 样本；Windows 5.13.2/6.0.0/6.16.0/6.22.2 的 `pyimod04_pywin32` raw payload 由版本匹配的官方 `CArchiveReader` 独立交叉验证；Python 3.10.0–3.10.11 的完整 Windows installer 矩阵进一步验证同一 PyInstaller 6.22.2 `pyimod02_importers` 只有三种稳定 semantic compiler outputs（3.10.0、3.10.1–3.10.2、3.10.3–3.10.11），并在 5.13.2/6.0.0/6.16.0 上分别用 3.10.0、3.10.1、3.10.11 复核三组边界；重复 release label 的 semantic rows 表达这些实证 compiler variants，而不是放宽 semantic hash。PyInstaller 6.22.2 另以完整 Windows Python 3.11.0–3.11.9（10 个）和 3.12.0–3.12.10（11 个）binary-installer 矩阵验证：五个 preload 模块在各 minor 内 semantic hash 全程各只有一组；其中 `struct` 与三个跨平台 core 又由 Linux 3.11/3.12 首尾 onefile 独立复核为与 Windows 相同，Windows-only `pyimod04_pywin32` 则在完整 Windows patch 族内稳定。3.11/3.12 因 raw payload 随 bugfix compiler 漂移而不新增 raw reference，只保留平台/patch 稳定的 semantic rows；对真实 Windows Python 3.12.10 onefile 的 `pyimod02_importers` 压缩 payload 单字节破坏仍保持 CArchive `CONFIRMED`，但 bootstrap 降为 `REFERENCE_DIFF/SUSPECTED` 3/4，证明 semantic-only reference 仍 fail-closed。对真实 6.22.2 onefile 仅翻转 `pyimod04_pywin32` 压缩 payload 一个字节时，CArchive 仍保持 `CONFIRMED`，但 bootstrap reference 降为 `REFERENCE_DIFF/SUSPECTED` 且 required match 为 3/4。Linux 5.13.2 在该宿主运行时自身 bootstrap 兼容失败仅作为静态 reference 样本，不作为运行成功断言；
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
