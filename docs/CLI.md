# CLI 与运行时授权

## 基本形式

```text
auto-refirst <file|directory> [options]
```

常用选项：

```text
-h, --help
--version
--json
--report-lang=en|zh
--extract
--run
--apply
--timeout=MS
```

目录默认递归；可通过 `--max-depth`、`--max-runtime-targets`、`--total-runtime-budget` 和 `--run-all` 控制运行计划。

## 静态与工件

```sh
auto-refirst file --json
auto-refirst directory --json
auto-refirst file --extract --recursive --json
```

默认静态模式可自动物化有界高价值工件。`--extract` 增加完整容器/resource 展开和重型静态分析。递归工件模式不会执行子工件。

相关限制：

```text
--artifact-depth=N
--artifact-nodes=N
--artifact-bytes=N
```

## 快速字符串搜索

```sh
auto-refirst directory --search=TEXT
auto-refirst directory --search=TEXT --search-ignore-case --json
```

搜索支持 ASCII / UTF-16LE 路径，遵守目录 symlink/reparse 边界。

## 运行时

```sh
auto-refirst target --run --json
```

`--run` 允许执行目标，并在支持的平台上选择 runtime trace、materialization、reconstruction 等步骤。它不会授权安装/替换原输入。

```sh
auto-refirst target --run --apply --json
```

`--apply` 允许经过严格验证的候选进入事务式安装。是否实际安装由最终验证结果决定。

兼容参数：

```text
--run=trace          deprecated shallow trace mode
--run=unpack         deprecated non-destructive deep-runtime alias
--run=python-probe   deprecated forced CPython probe mode
```

`--run=unpack --apply` 仍要求显式 `--apply` 才能进入安装步骤。

## 安全建议

`--run` 会执行潜在不可信代码。建议使用一次性 VM、隔离 CTF 环境或等价的受控系统。`auto-refirst` 不提供沙箱。
