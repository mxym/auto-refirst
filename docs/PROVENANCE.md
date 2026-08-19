# 第三方与生成引用来源

## Vendored code

产品直接编译的 vendored 依赖及精确 revision/许可证记录在 `THIRD_PARTY_NOTICES.md`、`docs/THIRD_PARTY_PROVENANCE.csv` 和 `SBOM.spdx.json`。完整许可证文本位于 `LICENSES/`。

主要依赖包括 libPeConv、miniz、tiny-AES-c、Zstandard single-file decoder、rustc-demangle native-c、Zydis 与其 amalgamation 中的 Zycore-C。

## Generated reference tables

`src/reference/` 包含若干生成引用表。它们用于匹配版本/结构事实、导出/API 名称、magic、地址/布局事实或规范化 fingerprint。公开源码没有嵌入对应上游 runtime binary。

主要参考输入：

- CPython 官方源码/Windows 发行物：版本、PE/export/opcode/runtime/reference facts；
- UPX：packer 结构与规范化 fingerprint；
- PyInstaller：loader/module 结构、名称/大小/hash reference；
- Unity/Godot：公开格式/运行时结构事实与项目自身独立解析实现。

相关上游许可证文本在需要时随 `LICENSES/` 提供。

## Public fixtures

`tests/corpus/PROVENANCE.csv` 是公开持久 fixture 的机器可读 inventory。当前只有 9 个 source-backed/project-generated payload rows。公开 CI 使用其中 4 个，其余用于格式回归。

公开仓库不包含历史私有 challenge corpus、内部执行日志或来源不充分的 opaque fixtures。
