# 相关论文与成熟工具

本页列出设计和能力边界的重要参考点。除 `THIRD_PARTY_NOTICES.md` 明确列出的 vendored 组件外，下列项目均不是 auto-refirst 的链接依赖，也不表示代码来源关系。

## 综合逆向与二进制分析

### Ghidra

NSA 维护的 Software Reverse Engineering framework，提供反汇编、反编译、程序模型、脚本和 headless 分析。auto-refirst 的定位偏向前置 evidence/routing/materialization；复杂交互式反编译与人工语义恢复适合继续交给 Ghidra。

- https://github.com/NationalSecurityAgency/ghidra

### angr

多架构二进制分析框架，支持静态分析和 dynamic symbolic execution。auto-refirst 当前没有集成通用符号执行器；在需要路径约束求解、程序状态探索时可把其报告出的关键入口/工件交给 angr。

- https://docs.angr.io/en/latest/
- Yan Shoshitaishvili et al., *SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis*, IEEE S&P 2016（angr 官方文档给出的项目论文引用）。

### LIEF

面向 PE/ELF/Mach-O 等 executable formats 的跨平台解析/修改库。auto-refirst 的 format parsers 是项目自身实现；LIEF 作为格式 API 和工具设计的成熟参考点。

- https://github.com/lief-project/LIEF

## 运行时恢复

### PE-sieve / libPeConv

PE-sieve 针对运行进程中的 replaced/injected PE、shellcode、hooks 和 memory patches 做检测/转储。auto-refirst Windows runtime path vendored `libPeConv`，并在更上层增加 static evidence、materialization graph、reconstruction validation 和 transaction gate。

- https://github.com/hasherezade/pe-sieve
- https://github.com/hasherezade/libpeconv

## 语言与生态

### GoReSym

Mandiant FLARE 的 Go symbol recovery tool，可提取编译器/程序、函数、源码位置和 runtime type metadata。auto-refirst 的 Go 路线以结构识别和前置分析为主，新 Go 版本 metadata 兼容仍是持续工作项。

- https://github.com/mandiant/GoReSym

### Cpp2IL

Unity IL2CPP reverse-engineering toolchain，覆盖 metadata/native image 等深层恢复。auto-refirst 侧重自动发现、结构确认、跨文件关系和分析优先级；完整 IL2CPP 反编译可交给 Cpp2IL 等专门工具。

- https://github.com/SamboyCoding/Cpp2IL

### GDRETools / gdsdecomp

Godot reverse-engineering suite，支持 PCK、GDScript 和项目恢复。auto-refirst 提供自动 PCK/GDScript/GDExtension routing/materialization，并对未闭环布局保持保守状态。

- https://github.com/GDRETools/gdsdecomp

### pyinstxtractor-ng

PyInstaller extractor，可提取 PyInstaller executable 内容，并利用 xdis 处理不同 Python bytecode 版本。auto-refirst 的 PyInstaller 路线优先提取用户 bytecode、建立工件 provenance，并与统一 CPython bytecode/static analysis 衔接。

- https://github.com/pyinstxtractor/pyinstxtractor-ng

## 设计取舍

这些成熟工具展示了两种重要边界：专门生态工具可以投入更深的格式/版本恢复；通用分析框架可以承担符号执行、交互式反编译等高成本任务。auto-refirst 重点优化自动前置阶段：在未知目录/附件中以有界成本找出值得深入分析的工件、证明证据强度、保留失败与 partial 状态，并把后续路线交给人工或专门工具。
