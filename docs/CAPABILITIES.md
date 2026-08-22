# 能力与支持边界

本文描述 `0.1.0-rc.1` 主产品中实际链接并可达的能力。支持等级以结构/语义证据为核心，名称、后缀、字符串和工具标记主要用于路由或弱证据。

## 1. 原生可执行文件与系统元数据

### PE / Windows

- DOS/NT/COFF/Optional Header、节表、入口、导入/导出、TLS、Load Config 等结构验证。
- Authenticode `WIN_CERTIFICATE`、PKCS#7、PE image digest、签名者/证书元数据、RFC3161 时间戳、EKU、page hash 与嵌套签名证据。
- x64 常见执行前置条件、手工解析器、反调试与运行时物化相关证据。
- Windows 运行时路径集成 libPeConv，用于受控的进程映像/重建工作流。

### ELF / Linux

- ELF32/64 基础结构、Program/Section Header、动态段、符号、REL/RELA/RELR、解释器与 ABI 关系。
- unwind / exception metadata 和函数范围相关结构。
- Linux x86-64 运行时后端可对适合的 executable/PIE 目标进行显式 `--run` 分析。

### Mach-O

- 32/64 位、大小端、Universal/FAT/FAT64 容器。
- segments/sections、dylib、`LC_MAIN`、UUID/build/encryption/code-signature 元数据、symbols 与 function starts。
- 当前公开运行时后端不执行 Mach-O 目标。

## 2. 字节码与托管生态

- JVM ClassFile 与 JAR 路由、方法/调用与隐式执行相关结构。
- Android DEX 035/037/038/039/040 及 container-v041 的关键几何、ids/classes/code/debug/invoke-custom 和完整性字段；APK 负责容器/AXML/签名块/本地库与高价值子工件路由。
- WebAssembly 模块结构和静态入口/导入导出相关证据。
- Lua 5.x bytecode 结构、proto/指令/常量和受限 introspection 证据。
- ECMA-335/.NET 元数据、方法、P/Invoke 与运行时/应用程序集路由。
- CPython `.pyc`、marshal、opcode、扩展模块、Cython/frozen/static/runtime 参考比较；PyInstaller/Nuitka 负责打包层与高价值 Python 子工件。

## 3. 游戏与应用运行时

### Unity

- Unity Mono：托管应用程序集、Mono runtime 与宿主关系，优先定位 `Assembly-CSharp` 等应用层载荷。
- Unity IL2CPP：`global-metadata.dat`、`GameAssembly`/native image、metadata 版本/注册结构、managed/native 关联与优先级。
- 关系确认依赖结构和跨文件一致性。文件名可参与弱排序，但不能单独形成高置信结论。

### Godot

- PCK 目录结构、脚本/项目工件物化、GDScript bytecode/layout/analysis、标准加密键相关证据。
- GDExtension descriptor/native library 路由和本地扩展语义提示。
- Android Godot 当前可稳定识别 runtime/native 交付面；游戏脚本资产的跨容器闭环仍有限。

### Dart / Flutter

- Android Flutter 交付面：`libapp.so`、`libflutter.so` 与 Flutter assets/manifests 的容器关系和静态子分析。
- Dart 深层对象/函数语义恢复仍属于有限支持。

## 4. 打包、容器与应用封装

- UPX 和多类 PE packer/protector 的有界结构/入口/语义路由。
- PyInstaller CArchive/PYZ，优先物化用户入口/高价值 Python bytecode 并进行子分析。
- Nuitka、AutoIt、Electron ASAR、Ren'Py/RPA、wxapkg 等格式/封装路线。
- ZIP 派生容器、ASAR、APK 和嵌套 executable 进入统一工件图。

## 5. 语义证据面

### 反调试

组合 IAT/调用参数/PEB/Native API/异常/时序等证据，区分明确调用语义、弱线索和 bait。详细规则见 [ANTI_DEBUG.md](ANTI_DEBUG.md)。

### 加密

覆盖常见 AES/RC4/TEA/XTEA、Windows CryptoAPI/BCrypt、OpenSSL EVP 等调用或常量使用模式。只有调用链、参数/数据流或多信号结构闭合时才提升置信度。

### 隐式执行与解释器边界

- PE/ELF/JVM/DEX/Wasm/.NET/Mach-O 等格式的隐式执行入口和初始化机制。
- 原生/源码形式的自定义解释器可在满足 program-buffer/read、opcode/dispatch/state 等结构条件时形成解释器边界证据。
- 运行时 argv 未知时保留 `UNRESOLVED`，不根据“目录里只有一个候选文件”推断精确绑定。

### 异常与控制记录

解析 Windows exception/unwind、Linux signal/Itanium LSDA 等静态控制证据，并保留 coroutine/control-record 等有明确消费者证明的结构。静态事实不会自动提升为“运行时已发生”。

## 6. 工件物化与递归分析

默认分析可以自动物化高价值代码、脚本、bytecode、metadata 和部分修复/语义闭包结果；`--extract` 增加完整容器展开和较重分析面。

统一工件图提供：

- root/current-input offset basis；
- relation / source provenance；
- SHA-256 去重；
- depth/node/byte budgets；
- HIGH-priority child static re-analysis；
- symlink/reparse/path traversal 防护。

`--extract --recursive` 保持静态；不会因此执行子工件。

## 7. 目录编排与资源约束

目录默认递归。候选通过有界 preflight 评分后进入完整静态分析，并结合跨文件关系重新排序。

默认目录资源合同：

- 最多 1024 个 regular-file 候选进入完整分析；其余以显式 omitted 计数保留。
- 完整报告 inline detail 预算 16 MiB。
- 单报告 staging 预算 8 MiB。
- report spool hard peak 24 MiB。
- 自动目录工件总预算 64 MiB / 512 files；其中为后关系决定性工件保留 8 MiB / 128 files。

超预算会形成明确 `PARTIAL`/deferred 状态。每个已接纳文件仍保留紧凑状态；完整细节可通过直接分析该文件恢复。

## 8. 运行时恢复

运行时分析需要显式 `--run`。支持平台上的计划可包括：

- generic trace；
- executable memory/materialization tracking；
- runtime-generated/reconstructed PE/ELF candidate；
- reconstructed artifact 独立静态验证；
- CPython compiler probe（仅在静态证据存在未决问题时选择）；
- validated transactional install。

最后一步只有 `--apply` 才能被选择。默认 `--run` 保留重建物，不修改原输入。

## 9. 报告与置信度

JSON 与人类可读报告共享同一事实模型。常见状态包括 `CONFIRMED`、`LIKELY`、`SUSPECTED`、`PARTIAL`、`FAILED`、`REFUSED`、`UNPACKED_VALIDATED` 等；具体字段按分析面提供坐标、证据、负证据、优先级和恢复建议。

深解析失败在强路由后会显式呈现，不会静默退化成“未检测到”。

## 10. 当前不提供的能力

- 通用反编译器/伪代码恢复。
- 通用 VM/自定义 ISA 求解器。
- 全程序符号执行或对任意状态空间的路径求解。
- 对任意版本 Unity/Godot/Go/Dart/CPython 产物的无条件兼容承诺。
- 由名称、字符串、单一 magic 或单个外部样本直接推广出的高置信检测。

这些边界用于控制状态爆炸、误报和样本过拟合。后续能力只有在独立正例、扰动和负例能够共同关闭证据链时进入默认产品路径。
