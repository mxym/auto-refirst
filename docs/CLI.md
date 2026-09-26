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
--json-errors
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

默认静态模式可自动物化有界高价值工件，包括已验证 .NET `ManifestResource` 的原始嵌入字节。`--extract` 增加完整容器/resource 展开和重型静态分析；.NET 资源仍保持原样，不做解压、解密或执行。递归工件模式不会执行子工件。

`--json` 的现有输出形状保持兼容：单文件通常是一个 report object，`--extract --recursive` 在产生多个 report 时是顶层 array，而目录分析使用带 `reports` 的 directory envelope。需要稳定集合传输层的调用方可显式使用 `--json --json-envelope`：单文件与递归工件图都统一为 `{ "report_schema_version": "1.0", "reports": [...] }`；目录 JSON 本来就是 envelope，因此保持其现有 directory 字段和 `reports` 数组。该选项是 opt-in，不改变既有 `--json` 输出，也不提升 `report_schema_version`。`--json-envelope` 必须与 `--json` 一起使用，且不适用于 `--search` 的 JSON Lines 模式。


`--json-errors` 是一个 opt-in 的失败诊断传输选项。它不会改变成功分析的 stdout；当命令行参数、输入预检、目录编排不变量或顶层异常导致退出码为 `2/3/4` 时，CLI 会在 stderr 写入一个单独的 JSON object：`error_schema_version` 固定为 `1.0`，`error` 固定包含 `kind`、`code`、`stage`、`message`，输入相关错误还包含 `path`。`error.code` 与进程退出码一致，stdout 在失败预检时保持为空。该选项不等价于 `--json`，可单独使用；`--search` 的无匹配仍然是退出码 `1`，不产生错误 envelope。

`--json-errors` is an opt-in failure-diagnostics transport. It leaves successful report stdout unchanged. When command-line validation, input preflight, directory orchestration invariants, or an uncaught top-level exception produces exit code `2`, `3`, or `4`, the CLI writes one JSON object to stderr: `error_schema_version` is `1.0`, and `error` always contains `kind`, `code`, `stage`, and `message`; input failures also include `path`. `error.code` equals the process exit code, and stdout stays empty for preflight failures. The option does not imply `--json` and can be used alone; a `--search` no-match result remains exit code `1` without an error envelope.

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

搜索查找 ASCII 文本及其 UTF-16LE 表示，输出路径统一使用 UTF-8；`--search-ignore-case` 仅折叠 ASCII 字母。`--max-depth=N` 同样约束搜索的目录递归深度，`0` 只读取根目录文件。搜索遵守目录 symlink/reparse 边界。

目录分析的预筛选信息仅用于候选接纳。它只读取每个文件开头最多 64 KiB，不看文件名来决定格式；目前对 PE、ELF、Mach-O（含 universal）、JVM Class、Hermes HBC、Lua 5.1–5.5、CPython bytecode、WebAssembly、DEX、ZIP、IoStore、Godot PCK 和 shebang 提供有界路由。`CAFEBABE` 这类共享前缀在结构不足时保持低置信度，损坏或不受支持的头部不会获得格式优先级。完整解析会刷新格式、置信度和运行资格；被否定的结构路由不再保留可执行根角色和临时优先级。`directory_plan.depth_limited_directories` 记录因深度限制未展开的目录数量，`traversal_error_count` 记录可观察的遍历错误。深度截断、遍历错误或不可读候选都会让目录摘要的 `partial` 为 `true`，进程仍遵循既有退出码契约。跳过路径仅保留最多 128 条明细、JSON 展示最多 64 条；`traversal_skips_total` 保留真实总数，不代表被跳过的后代文件数。

静态扫描还会对非零偏移的多格式标记做低置信度分层线索：当 PDF、Mach-O/JVM、UDF、VHD 或已识别容器标记中至少两种格式同时出现时，报告会加入 `Layered/polyglot format markers` finding。该 finding 只提供 `current_input_file` 坐标的有界范围、候选数量和后续结构检查建议；它不会把魔数当作已验证子工件，也不会触发提取或运行。

目录的静态分析和 `--run` 共用报告预算：内联完整详情最多 16 MiB、单份最多 8 MiB、暂存总量最多 24 MiB（含延迟缓存与当前写入）。关系确认后会按最终优先级重新选择仍在缓存中的报告；`reports_reselected` 记录重新入选数量，`cache_evicted_reports` 记录为维持上限而删除的缓存。每个已接纳文件的紧凑状态仍保留。

默认 64 MiB / 512 文件工件预算只统计自动静态准备；静态准备保留之前的 `runtime/` 观测工件及 ownership marker。运行时产物由后端另行约束，显式 `--extract` 继续使用原有逐文件提取合同。`runtime_detail_deferred=true` 表示某个已运行目标的详情被延迟，应检查保留的运行时工件；再次显式 `--run` 会产生新的观测，不能还原上一次运行。

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
