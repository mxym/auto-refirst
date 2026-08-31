# CLI 与运行时授权

发布自动化所依赖的精确退出码和授权语义见 [CLI process and authorization contract](CLI_CONTRACT.md)。

## 基本形式

```text
auto-refirst <file|directory> [options]
```

常用选项：

```text
-h, --help
--version
--json
--json-envelope
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

`--json` 的现有输出形状保持兼容：单文件通常是一个 report object，`--extract --recursive` 在产生多个 report 时是顶层 array，而目录分析使用带 `reports` 的 directory envelope。需要稳定集合传输层的调用方可显式使用 `--json --json-envelope`：单文件与递归工件图都统一为 `{ "report_schema_version": "1.0", "reports": [...] }`；目录 JSON 本来就是 envelope，因此保持其现有 directory 字段和 `reports` 数组。该选项是 opt-in，不改变既有 `--json` 输出，也不提升 `report_schema_version`。`--json-envelope` 必须与 `--json` 一起使用，且不适用于 `--search` 的 JSON Lines 模式。

单文件输入默认写入 `<input>.auto-refirst/`。如果输入位于只读介质、系统目录或不希望产生旁路文件的位置，可显式迁移整个产物树：

```sh
auto-refirst /read-only/evidence.bin --artifact-root=/writable/case/evidence-artifacts --json
```

`--artifact-root` 是**精确的单输入 product-owned 根目录**。首次使用要求该路径不存在；工具创建目录并写入 `.auto-refirst-owner`。后续仅允许同一输入路径复用匹配的 ownership marker。已有但无 marker 的目录、其他输入拥有的 root、symlink/reparse root 都会拒绝，避免把任意用户目录误当成可管理产物树。当前该选项不与目录输入、纯 `--search` 或 `--extract --recursive` 多节点图模式组合；这些情况返回用法错误。

相关限制：

```text
--artifact-depth=N
--artifact-nodes=N
--artifact-bytes=N
--artifact-root=PATH
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

## 进程退出码

CLI 使用固定的 `0/1/2/3/4` 契约。可疑发现、部分分析、预算拒绝或不支持的深层路线会写入报告，本身不等于进程失败。精确定义见 [docs/CLI_CONTRACT.md](CLI_CONTRACT.md)。

## 安全建议

`--run` 会执行潜在不可信代码。建议使用一次性 VM、隔离 CTF 环境或等价的受控系统。`auto-refirst` 不提供沙箱。
