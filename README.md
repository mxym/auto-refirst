# auto-refirst

面向逆向工程与 CTF 的证据驱动二进制预处理器。

`auto-refirst` 在反编译器/调试器之前完成格式识别、生态路由、容器与嵌套工件展开、关键证据提取、目录级优先级排序，以及可选的运行时物化与重建。默认模式只做静态分析；运行目标需要显式 `--run`，写回/安装需要额外的 `--apply` 授权。

当前公开版本：**0.1.0-alpha.1**。

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

完整参数见 [docs/CLI.md](docs/CLI.md)，构建说明见 [docs/BUILD.md](docs/BUILD.md)。

## 能力概览

- **原生可执行格式**：PE、ELF、Mach-O/Universal Mach-O 的结构、入口、导入/导出、动态链接、异常/展开、签名与部分平台安全元数据。
- **字节码与托管格式**：JVM Class/JAR、DEX/APK、WebAssembly、Lua bytecode、ECMA-335/.NET、CPython bytecode 与嵌入式运行时相关证据。
- **封装与生态识别**：UPX/多类 PE packer/protector 证据、PyInstaller、Nuitka、ASAR/Electron、AutoIt、Ren'Py/RPA、wxapkg，以及 Go/Rust/Dart/Flutter 等运行时/编译产物特征。
- **Unity / Godot**：Unity Mono、IL2CPP 元数据/本地映像关系、Godot PCK/GDScript/GDExtension 等结构与工件路线。
- **语义证据**：反调试、加密调用/常量使用、隐式执行入口、解释器/字节码边界、异常驱动控制流、跨文件关系与分析优先级。
- **递归工件图**：容器、嵌套可执行文件和高价值脚本/字节码的有界物化、SHA-256 去重、来源关系和静态子分析。
- **目录编排**：基于结构与关系的有界候选选择、排序、紧凑状态、详细报告延迟与可恢复输出。
- **运行时恢复**：在支持的平台上跟踪执行、内存物化、重建候选和独立验证；事务式安装受 `--apply`、备份和回滚条件约束。

详细能力和边界见 [docs/CAPABILITIES.md](docs/CAPABILITIES.md)。

## 证据与验证

项目使用结构/语义证据、扰动负例和独立外部样本评估，避免以题目名、已知哈希、固定路径或 flag 文本作为产品规则。

最近一组冻结后的 36 个新鲜外部样本评估在资源修复后全部完成（36/36，rc=0）。其中：

- 产品边界最高等级：28/36；
- 分析指导达到较高等级：29/36；
- 路线质量达到较高等级：29/36；
- 证据质量最高等级：32/36；
- 错误 `HIGH` 提升：0；
- 错误语义提升：0；
- 明确错误的最高优先级路线：0。

同一评估的目录压力上限观测：最大 JSON 约 16.5 MiB、最大目录自动工件约 56 MiB、最大 RSS 约 268 MiB、最大 wall time 约 10.9 s。详细方法、口径和已知缺口见 [docs/VALIDATION.md](docs/VALIDATION.md)。

## 安全边界

- 默认静态分析不执行目标代码。
- `--run` 会执行用户指定或目录计划选中的目标；项目不提供沙箱。
- `--apply` 是独立写回授权。只有满足实现中的验证条件时才会执行事务式安装。
- 递归提取和目录分析具有深度、节点、字节、候选、报告和自动工件预算，并拒绝符号链接/Windows reparse 跳转到产品拥有路径之外。

安全报告流程见 [SECURITY.md](SECURITY.md)。

## 已知限制

当前 Alpha 仍存在明确的外部兼容性边界，例如：旧版 Godot 导出中的嵌入 PCK 识别、部分 GDExtension 精确关系、Godot APK 游戏脚本面、Go 新版本元数据、重命名后的 Unity IL2CPP 配对，以及 Dart 深层语义恢复。通用 VM 求解、全程序符号执行和通用反编译不在当前产品范围内。

仅在结构/语义证据能够跨独立样本稳定复现时提升为正式能力。单一正例、容易被名称/字符串诱导的规则、依赖特定题目身份的规则会保留为未支持或研究项。

## 文档

- [能力与支持边界](docs/CAPABILITIES.md)
- [架构与证据模型](docs/ARCHITECTURE.md)
- [外部验证与已知缺口](docs/VALIDATION.md)
- [CLI 与安全授权](docs/CLI.md)
- [构建与安装](docs/BUILD.md)
- [公开测试](docs/PUBLIC_TESTING.md)
- [第三方与生成引用来源](docs/PROVENANCE.md)
- [相关论文与成熟工具](docs/REFERENCES.md)
- [反调试证据说明](docs/ANTI_DEBUG.md)
- [发布检查清单](docs/RELEASE_CHECKLIST.md)

## 许可证

项目原创代码采用 [Apache License 2.0](LICENSE)。Vendored/第三方组件保留各自许可证，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)、[LICENSES/](LICENSES/) 与 [SBOM.spdx.json](SBOM.spdx.json)。
