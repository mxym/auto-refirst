# 能力与支持边界

本文描述 `0.1.0-rc.2` 主产品中实际链接并可达的能力。支持等级以结构/语义证据为核心，名称、后缀、字符串和工具标记主要用于路由或弱证据。

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
- 解析 Swift metadata section 清单；只有 nominal type、parent/module、field descriptor 与有界字符串关系全部闭合时才报告 `SWIFT_STRUCTURED`，否则保留 `SWIFT_PRESENCE`/`PARTIAL`。
- Swift 输出是直接元数据记录与字节事实，不声明源码、完整类型系统或程序语义恢复；当前公开运行时后端不执行 Mach-O 目标。

## 2. 字节码与托管生态

- JVM ClassFile 与 JAR 路由、方法/调用与隐式执行相关结构。
- Android DEX 035/037/038/039/040 及 container-v041 的关键几何、ids/classes/code/debug/invoke-custom 和完整性字段；APK 负责容器/AXML/签名块/本地库与高价值子工件路由。
- APK JNI 可组合 Java native declaration、`Java_...` export 与 `RegisterNatives` 表的结构关系，并严格处理 JNI modified UTF-8。J2/J3/J4 关系等级不被夸大为已执行注册或完整 native 语义证明。
- WebAssembly 模块结构和静态入口/导入导出相关证据。
- Lua 5.x bytecode 结构、proto/指令/常量和受限 introspection 证据。
- ECMA-335/.NET 元数据、方法、P/Invoke 与运行时/应用程序集路由。
- .NET single-file bundle v2/v6 manifest/member geometry与 Linux NativeAOT section/table evidence；识别结果不等同于 IL 反混淆或源码恢复。
- Hermes HBC v89/v96/v98 的 header/table/function/string/opcode/debug/footer 完整性与有界提取，并可由 APK content entry 进入静态子分析；不声明 JavaScript 源码恢复或 runtime loading。
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
- Nuitka 的 onefile KA[X/Y] 与 standalone `constant_bin` 保持各自的结构确认门；此外，**ELF64/x86-64 extension module** 可由当前镜像自身的 `__compiled__` 结构独立闭合身份。版本平面验证 `__nuitka_version__` `PyStructSequence` 描述符、连续 major/minor/micro 初始化和 releaselevel 写入：standalone 可闭合文件内 CPython 构造器，动态扩展模块则沿 ELF relocation/GOT/PLT 精确解析到导入的 CPython API，只有整条调用与 tuple-slot 关系闭合时才输出 `compiled_version_tuple`。该字段表达目标二进制实际构造的 `__compiled__` major/minor/micro 元组，**不是完整发行 tag**：Nuitka `0.6.19.7` 只编码 `0.6.19`；0.9.6 至 4.2 的生成器还显式丢弃 `rc_number`，只将预发布状态编码为 `candidate`，因此不能恢复 rc 序号。onefile 顶层 bootstrap 不继承/推断 child 的 tuple；物化后的 child 可独立进入同一检测。当前不把这项证据外推到 PE、其他 ABI 或未闭合的 CPython 链接布局。
- Unreal Pak v1-v12 footer/index/hash profile 与 IoStore UTOC/UCAS pair/chunk geometry；加密内容、未知版本或未验证签名保持 `PARTIAL`，不声明 asset semantics 枚举。
- ZIP 派生容器、ASAR、APK 和嵌套 executable 进入统一工件图。

## 5. 语义证据面

### 反调试

组合 IAT/调用参数/PEB/Native API/异常/时序等证据，区分明确调用语义、弱线索和 bait。详细规则见 [ANTI_DEBUG.md](ANTI_DEBUG.md)。

### 有界算法与加密使用识别

在带可验证 `RUNTIME_FUNCTION` 边界的 PE64/x64 布局中，当前产品提供以下有界路径：

- TEA/XTEA-family 的 delta、shift、XOR/add/sub loop 与 key-argument 组合；
- RC4 KSA 的 256-byte identity S-box 初始化、indexed state/key access、swap 与 key-length modulo data flow；
- AES-NI key schedule、round-key layout 和 encrypt/decrypt consumer 关系；
- Windows CryptoAPI/BCrypt 与 OpenSSL EVP 的 import-call、selector/mode、参数和有界 key/IV object 关系。

只有函数边界、调用链、参数/数据流或多信号结构闭合时才提升状态。单独出现 S 盒、delta、API 名、字符串或常量只产生候选信号。上述能力不构成任意架构/编译布局上的通用算法分类、任意密钥恢复、明文验证或加密正确性证明。

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

## 11. 实验性 sidecar 工具

`tools/de4dotex/` 提供 Linux/x86_64、默认关闭的实验性 de4dotEx 适配器源码与精确 manifest，但不捆绑 de4dotEx/.NET/bubblewrap 二进制，也不进入主产品或 P0/P1。它是辅助检测/受控去混淆路径，不构成任意 .NET 混淆器的通用还原支持。任何调用都视为可能执行目标代码，必须绑定显式 `--run` 授权、精确输入哈希、可信不可变工具树、namespace/cgroup/rlimit 与无网络沙箱。当前发布状态保持 `PARTIAL`；Windows/Wine 路线为 `NO-GO`，输出 DLL 必须由主产品重新解析后才能使用。

## 12. 研究副产品边界

超出上述已验证模式、ABI 与布局的更多算法泛化，以及内核/虚拟化动态观察器，仍处于独立研究与评估中。它们不属于 `0.1.0-rc.2` 的公开能力合同、默认执行路径、P0/P1 或发布资产，也不构成支持、兼容性或隐蔽性承诺。
