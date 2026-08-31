# auto-refirst

面向逆向工程与 CTF 的证据驱动二进制预处理器。

`auto-refirst` 在反编译器/调试器之前完成格式识别、生态路由、容器与嵌套工件展开、关键证据提取、目录级优先级排序，以及可选的运行时物化与重建。默认模式只做静态分析；运行目标需要显式 `--run`，写回/安装需要额外的 `--apply` 授权。

当前公开版本：**0.1.0-rc.2**。

English: [README_EN.md](README_EN.md)

## 快速开始

Linux：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./build/auto-refirst ./target --json
```

目录输入默认递归：

```sh
./build/auto-refirst ./challenge-directory --json
```

显式展开完整/重型静态工件：

```sh
./build/auto-refirst ./target --extract --recursive --json
```

运行时分析：

```sh
./build/auto-refirst ./target --run --json
```

仅在确认需要、且运行环境可承受目标代码风险时使用 `--run`。验证后的事务式安装还需要显式 `--apply`：

```sh
./build/auto-refirst ./target --run --apply --json
```

如果样本位于只读目录，可把单文件产物树安全迁移到可写位置：

```sh
./build/auto-refirst /read-only/evidence.bin --artifact-root=/writable/case/evidence-artifacts --json
```

该 root 由 ownership marker 绑定到输入路径，不会接管任意已有目录。完整参数见 [docs/CLI.md](docs/CLI.md)，精确退出码与授权契约见 [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md)，构建说明见 [docs/BUILD.md](docs/BUILD.md)。

## 能力概览

- **原生可执行格式**：PE、ELF、Mach-O/Universal Mach-O 的结构、入口、导入/导出、动态链接、异常/展开、签名、Mach-O Swift 元数据与部分平台安全元数据。
- **字节码与托管格式**：JVM Class/JAR、DEX/APK/JNI 关系、WebAssembly、Lua、Hermes HBC、ECMA-335/.NET single-file/NativeAOT、CPython bytecode 与嵌入式运行时相关证据。
- **封装与生态识别**：UPX/多类 PE packer/protector 证据、PyInstaller、Nuitka、ASAR/Electron、AutoIt、Ren'Py/RPA、wxapkg、Unreal Pak/IoStore，以及 Go/Rust/Dart/Flutter 等运行时/编译产物特征。
- **Unity / Godot**：Unity Mono、IL2CPP 元数据/本地映像关系、Godot PCK/GDScript/GDExtension 等结构与工件路线。
- **语义证据**：反调试、加密调用/常量使用、隐式执行入口、解释器/字节码边界、异常驱动控制流、跨文件关系与分析优先级。
- **有界算法识别**：在受支持的 PE64/x64 布局和函数边界内，组合确认 TEA/XTEA、RC4 KSA、AES-NI，以及 CryptoAPI、BCrypt、OpenSSL EVP 的调用、参数和 key/IV 使用；不据此声明通用算法分类、任意密钥恢复或明文验证。
- **递归工件图**：容器、嵌套可执行文件和高价值脚本/字节码的有界物化、SHA-256 去重、来源关系和静态子分析。
- **目录编排**：基于结构与关系的有界候选选择、排序、紧凑状态、详细报告延迟与可恢复输出。
- **运行时恢复**：在支持的平台上跟踪执行、内存物化、重建候选和独立验证；事务式安装受 `--apply`、备份和回滚条件约束。

详细能力和边界见 [docs/CAPABILITIES.md](docs/CAPABILITIES.md)。

## RC.2 工作进展

已经纳入公开能力合同：

- Hermes HBC v89/v96/v98 与 APK 内容子项路由；
- Unreal Pak/IoStore 容器框架及 UTOC/UCAS 配对关系；
- .NET single-file bundle、Linux NativeAOT 和 Mach-O/Swift 有界结构元数据；
- APK JNI 导出名、`RegisterNatives` 与严格 Modified UTF-8 关系证据；
- 上述受限 PE64/x64 范围内的 TEA/XTEA、RC4 KSA、AES-NI 与常见加密 API 上下文证据。

实验性辅助路径：`tools/de4dotex/` 提供默认关闭的 Linux/x86_64 de4dotEx 适配器源码与精确 manifest。仓库和发布资产不捆绑 de4dotEx、.NET 或 bubblewrap；调用需要显式 `--run` 和完整隔离条件，结果保持 `PARTIAL`，输出 DLL 必须交回主程序重新解析。当前 Windows/Wine 路线为 `NO-GO`，它不构成任意 .NET 混淆器的通用还原能力。

仍在研究、未纳入 RC.2：超出已验证模式、ABI 和布局的更多算法泛化，以及内核/虚拟化动态观察器副产品。它们不属于默认执行路径、P0/P1 或发布资产，也不构成兼容性、隐蔽性或支持承诺。

## 证据与验证

项目使用结构/语义证据、扰动负例和独立外部样本评估，避免以题目名、已知哈希、固定路径或 flag 文本作为产品规则。

`0.1.0-alpha.1` 阶段冻结的 36 个外部样本评估在资源修复后全部完成（36/36，rc=0）。其中：

- 产品边界最高等级：28/36；
- 分析指导达到较高等级：29/36；
- 路线质量达到较高等级：29/36；
- 证据质量最高等级：32/36；
- 错误 `HIGH` 提升：0；
- 错误语义提升：0；
- 明确错误的最高优先级路线：0。

同一 Alpha 历史评估的目录压力上限观测：最大 JSON 约 16.5 MiB、最大目录自动工件约 56 MiB、最大 RSS 约 268 MiB、最大 wall time 约 10.9 s。它不是 RC.2 的新验证结果；详细方法、当时口径和当时缺口见 [docs/VALIDATION.md](docs/VALIDATION.md)。

`v0.1.0-rc.2` 的冻结提交为 `8cb0416d6b273c1807948ae89bd4ff8043fb1d4e`。该提交自身完成了本地 Linux Release/ASan、原生 Windows、三组 hosted exact-commit CI，以及发布后九件资产的全量回下载和双平台复核。Run ID、资产哈希和精确边界见 [RC.2 发布页](https://github.com/mxym/auto-refirst/releases/tag/v0.1.0-rc.2) 与 [公开测试说明](docs/PUBLIC_TESTING.md)。

上一阶段维护候选的 maintainer-only 完整回归统计（125 PASS、25 个 Windows-labelled PASS、0 SKIP）没有在 `8cb0416` 上重跑，因此不属于 RC.2 的 exact-commit 证据，也不用于扩大 RC.2 的能力声明。

## 安全边界

- 默认静态分析不执行目标代码。
- `--run` 会执行用户指定或目录计划选中的目标；项目不提供沙箱。
- `--apply` 是独立写回授权。只有满足实现中的验证条件时才会执行事务式安装。
- 递归提取和目录分析具有深度、节点、字节、候选、报告和自动工件预算，并拒绝符号链接/Windows reparse 跳转到产品拥有路径之外。

安全报告流程见 [SECURITY.md](SECURITY.md)。

## 已知限制

当前 RC 仍保留明确边界：Swift 源码/完整语义恢复、加密 Unreal 资产内容、任意 .NET 混淆器的通用还原、Dart 深层语义、通用 VM 求解、全程序符号执行和通用反编译都不在已声明能力内。

算法识别也受架构、函数边界、调用链和数据流闭合条件约束；S 盒、delta、名字、字符串或单个常量只能作为候选信号，不能单独提升为高置信语义结论。已识别 key/IV 也不等同于完成解密或证明明文正确。

仅在结构/语义证据能够跨独立样本稳定复现时提升为正式能力。单一正例、容易被名称/字符串诱导的规则、依赖特定题目身份的规则会保留为未支持或研究项。

## 文档

- [能力与支持边界](docs/CAPABILITIES.md)
- [架构与证据模型](docs/ARCHITECTURE.md)
- [外部验证与已知缺口](docs/VALIDATION.md)
- [CLI 与安全授权](docs/CLI.md)
- [CLI 退出码与授权契约](docs/CLI_CONTRACT.md)
- [构建与安装](docs/BUILD.md)
- [公开测试](docs/PUBLIC_TESTING.md)
- [第三方与生成引用来源](docs/PROVENANCE.md)
- [相关论文与成熟工具](docs/REFERENCES.md)
- [反调试证据说明](docs/ANTI_DEBUG.md)
- [发布检查清单](docs/RELEASE_CHECKLIST.md)

## 许可证

项目原创代码采用 [Apache License 2.0](LICENSE)。Vendored/第三方组件保留各自许可证，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)、[LICENSES/](LICENSES/) 与 [SBOM.spdx.json](SBOM.spdx.json)。
