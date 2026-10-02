# 架构与证据模型

## 处理管线

`auto-refirst` 的默认流程按成本和证据强度逐级推进：

1. 输入快照与路径安全检查；
2. 便宜的格式/结构路由；
3. 目标格式深解析；
4. 生态与语义证据组合；
5. 高价值工件的有界物化；
6. 子工件静态再分析与跨文件关系；
7. 分析指导与目录优先级；
8. 可选运行时计划；
9. JSON/文本报告。

解析器会把 attacker-controlled size/count/depth 纳入显式预算。名称、后缀和字符串主要用于路由或弱排序；结构几何、引用关系、调用参数、数据流、跨文件一致性和独立验证提供更高权重。

## 证据平面

不同平面的事实保持区分：

- **静态结构**：文件头、表、section/segment、metadata、容器目录、签名结构。
- **静态语义**：调用目标、参数、控制/数据关系、解释器结构、跨文件绑定。
- **物化**：从当前输入实际提取/重建出的字节和 provenance。
- **运行时观测**：实际进程事件、内存物化、执行转移和 dump。
- **独立验证**：对重建候选重新解析、校验入口/导入/重定位/安全结构等。

一个平面的强证据不会自动替代另一个平面。例如静态 `VirtualProtect` 导入只能证明能力可用，不能证明运行时权限变更已发生。

## 置信度

- `CONFIRMED`：要求实现定义的结构/语义闭包成立。
- `LIKELY`：存在多项一致证据，但关键闭包仍未完成。
- `SUSPECTED`：弱路由或局部模式，适合提示下一步检查。
- `PARTIAL`：分析有效但受预算、缺失关系或不完整工件限制。
- `FAILED`：强路由后深解析/验证失败，失败本身需要保留。
- `REFUSED`：安全/预算/授权策略明确阻止操作。
- `UNPACKED_VALIDATED`：重建物通过独立验证；dump 本身不足以达到该状态。

## 工件 provenance

每个递归子工件区分：

- 根输入；
- 当前输入/offset basis；
- 来源关系；
- materialization path；
- SHA-256；
- depth 与预算状态。

嵌套文件的 offset 默认属于当前物化子文件；只有明确证明坐标映射时才报告外层容器坐标。

## 目录模型

目录流程包含 bounded preflight、候选接纳、完整静态报告、跨文件关系、重新排序、报告保留/延迟和可选运行时预算。决定性关系可以提升相关文件，但不能覆盖原始证据状态。目录触发的静态子工件也经过同一个 `artifact-depth` gate；深度为 0 时保留根文件的结构报告并拒绝子工件报告。对已计算摘要的子工件，图先检查 SHA-256 去重，再应用深度、节点和字节接纳预算，避免重复内容在预算耗尽时被误报为新的拒绝节点。

## 运行时授权

运行时采用分层授权：

- Level 0：静态；
- Level 1：`--run`，允许执行和观测；
- Level 2：`--run` 下可重建并独立验证单独工件；
- Level 3：`--run --apply`，允许严格验证后的事务式安装。

`--apply` 不代表一定发生安装；最终报告会记录计划选择、验证状态、备份和替换结果。

Linux 运行时物化会保留创建者、句柄、映射权限和首次执行之间的 provenance。`memfd`、`O_TMPFILE`、严格创建的释放文件以及本次新建的 POSIX shared memory 都按 backing 分开记录；普通文件和运行前已存在的 shared memory 不会仅因被映射就升级为运行时载荷。`write`、`pwrite`、向量写入、`copy_file_range`、`sendfile` 和 `splice` 的内核返回字节数只作为写入证据，并按真正的目标 fd 归因；`splice` 的 pipe 上游若由 `vmsplice` 填充，会按 pipe inode 连接到目标 backing，普通 pipe→file 传输不会继承旧的上游标记。首次执行仍需独立的执行断点或 NX guard 证据。`process_vm_writev` 属于跨进程内存写入，不是 backing fd 写入；匿名映射的执行证据仍由 mmap/mprotect 与首取 guard 提供。

`process_vm_writev` 只有在被跟踪进程返回正的写入字节数时才生成 `MemoryWrite` 事件。事件的 `pid`/`scope` 表示发起调用的进程，`target_pid` 单独记录内核目标，不能把目标进程误当作已经执行；子进程事件保持 `root_replacement_eligible=false`。local/remote iovec 指针和计数会在跟踪停止点做有界解析（最多 16 项、总字节最多 1 MiB），并记录 `*_iov_parse_state`、解析项数、字节数与 `iov_parse_complete`。空数组明确标为 `EMPTY`，合法零长度项保留计数；空基址、数组不可读、字节/项上限和 `base+len` 溢出分别产生非完整状态，溢出项不写入 `remote_ranges`。失败或未观测到的调用不生成该事件；即使事件存在，它也只证明跨进程写入闭包，不证明目标地址已执行。
`ptrace(PTRACE_POKEDATA/PTRACE_POKETEXT)` 成功返回时也生成 `MemoryWrite` 事件，用于覆盖调试器/注入器按机器字写入目标进程内存的路径。事件保留请求名和值、`target_pid`、目标地址、数据字和写入宽度；只记录成功的写入，事件本身不替代目标地址的执行证据。
`prctl(PR_SET_DUMPABLE/PR_SET_PTRACER)` 与 `ptrace(PTRACE_TRACEME/PTRACE_ATTACH/PTRACE_SEIZE)` 会生成独立的 `debugger_control` 事件，记录操作参数和成功/错误状态。这样可以区分“程序主动尝试改变调试关系”与普通内存写入；事件不推断调试器存在或恶意意图。

## 泛化纪律

产品规则禁止使用题目名、fixture 路径、已知输入哈希、flag 字符串作为识别条件。新增机制应至少具备：

- 独立正例；
- 结构扰动/损坏；
- 相似 bait/负例；
- 明确资源上界；
- 对已有外部样本的回归比较。

只有单一正例或稳定性不足的研究结果不会进入默认高置信路径。
