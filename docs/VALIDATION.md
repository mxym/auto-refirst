# 外部验证与已知缺口

本页固定保留 `0.1.0-alpha.1` 的历史外部验证记录。以下数字、资源观测和缺口均按当时冻结的 Alpha 产品与评估口径描述，不构成 `0.1.0-rc.1` 的新验证结果，也不应被解释为 RC 当前缺口清单。RC 的实现边界见 [CAPABILITIES.md](CAPABILITIES.md)；发布门状态以冻结提交上的 hosted CI 和 `RELEASE_CHECKLIST.md` 要求为准。

## 方法

公开 Alpha 的能力结论来自三类验证：

1. source-generated / synthetic 单元与集成 fixture，用于精确测试结构边界；
2. 独立真实样本/开源发行物，用于验证产品边界和生态泛化；
3. 冻结后再评估的 holdout，选择、产品版本和评估口径在查看最终 ground truth 前固定，并包含扰动与负例检查。

产品逻辑在评估过程中不使用样本名、路径、哈希或题目身份。真实样本只作为验收 oracle，不进入公开仓库。

## Alpha 36-case 外部 holdout

该轮 Alpha holdout 包含 36 个新鲜外部案例，覆盖 Unity、Godot、.NET/NativeAOT、JVM/JAR、Android/Flutter、PyInstaller/direct-pyc、普通 PE/ELF 等类别。资源修复后的默认产品运行：

```text
36 / 36   exit code 0
0         observed timeout
0         false HIGH promotion
0         wrong semantic promotion
0         clearly wrong top-priority route
```

评估维度中的主要结果：

```text
M4 (product boundary)        28 / 36
I >= 3 (guidance)            29 / 36
J >= 3 (route quality)       29 / 36
D4 (evidence quality)        32 / 36
```

这些数字描述该轮样本集上的验收结果，不等同于对所有版本/产品的覆盖率承诺。

## Alpha 目录资源压力

同一批次的默认资源观测：

```text
max JSON output              17,270,144 bytes
max directory artifacts      58,720,070 bytes
max RSS                      274,516 KiB
max wall time                10.9 s
```

目录合同还具有 24 MiB report-spool hard peak、64 MiB / 512-file 自动工件预算和 1024 候选接纳上限。预算不足时报告显式记录 partial/deferred/omitted 状态。

## 关键外部正例类型

该轮 Alpha 验证中形成较强闭包的代表性能力包括：

- Unity Mono application payload 与 runtime 关系；
- 多个 Unity IL2CPP metadata/native pair；
- sidecar Godot PCK + GDScript/project materialization；
- 大型 .NET 应用目录的应用 payload 排序；
- Android DEX/JNI 与 Flutter native/assets 交付面；
- PyInstaller CArchive -> user bytecode 物化/再分析；
- 普通 PE/ELF/JVM/Wasm 等格式边界。

## Alpha 验证时记录的缺口

### Godot

- 一组 Godot 3.3.2 Windows export 的 embedded PCK 仍只得到保守 Godot 路由，未完成 embedded PCK 结构闭包。
- GDExtension native library 与 descriptor 能正确排序，但 descriptor -> exact entry symbol 的显式关系仍有限。
- Godot Android APK 可定位 native runtime/DEX；游戏脚本资产未在所有布局上闭环。

### Unity

IL2CPP metadata/native pair 对常见命名和结构组合表现稳定；同时把 `GameAssembly` 与 `global-metadata.dat` 改成不透明名称时，backend 仍可能被确认，但精确 pair relation 会丢失。该轮 Alpha 产品没有用特定文件名硬编码补齐这一关系。

### Go

该轮 Alpha 产品已支持普通 Go executable/runtime 结构；一组 Go 1.26.6 新鲜样本的 buildinfo/runtime metadata 确认不稳定，因此当时不把最新 Go 版本元数据恢复描述为无条件支持。

### Dart / Flutter

该轮 Alpha 产品中，Flutter APK 的 native delivery surface 和 assets 可以提供可靠路线；Dart snapshot/AOT 的深层函数/对象语义恢复仍有限。

### VM / symbolic execution

该轮 Alpha 产品的解释器边界分析用于识别 program/state/dispatch 结构和下一步路线。通用 VM solver、全程序符号执行、自动 flag 求解当时未进入产品。原因包括路径/状态空间增长、环境建模成本和外部样本泛化不足。需要这类能力时可与 angr、Ghidra 等下游工具组合。

## 过拟合防护

以下规则不接受为正式高置信检测：

- 单一 challenge 名称、文件路径或哈希；
- flag/题面文本；
- 单个容易伪造的字符串或 marker；
- 只在一个外部样本成立、没有负例/扰动的语义模式；
- 为通过某一 fixture 而降低全局证据门槛。

新能力需要保持现有 false-HIGH / semantic-promotion 防线，并在独立样本上重新验证。
