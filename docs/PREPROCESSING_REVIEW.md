# 预处理流程审计与优化计划

审计基线：`a78dc78496773dddf4b5caf1bfbfd977fd9a6759`。本轮目标是完善已有预处理能力：输入盘点、格式与生态路由、证据交接、工件预算、报告及构建验证。完整求解题目、通用解密、通用反编译和自动执行附件不作为验收目标。

近期能力深化：PE/CLR bootstrap import contract 将 `mscoree.dll` 导入、CLR data directory 与 EXE/DLL 标志做有界闭合，帮助识别自定义 CLR host、被改写的入口契约和不完整托管壳；完整且已验证的普通 bootstrap 只作为基线不重复输出。该 finding 只有 import directory/CLR directory 结构证据，不能推出运行时 host、DLL 搜索路径或保护器身份；没有 CLR 或 mscoree 结构的普通 PE 不会产生该 finding。

## 结论与覆盖范围

项目已具备广泛的格式覆盖和证据分层。更迫切的问题集中在公共流程与验证维护：预筛选状态和完整解析不同步、Windows 路径与存储差异、目录覆盖范围提示不完整，以及旧测试与当前 CI/来源目录脱节。继续扩展格式前，应先稳定这些共同依赖。

本轮逐段检查入口、目录编排、搜索、报告暂存、快照/映射、授权交接、替换入口及构建/测试配置；对格式解析、容器提取、语义指导、运行时与辅助适配器进行了架构和调用边界检查，并通过公开回归覆盖已有行为。这不等同于对每个格式的全部代码路径完成形式化验证，也不把历史私有样本、历史 RC.2 数据视为当前提交的验证结果。

| 审计面 | 结论与处理 |
| --- | --- |
| 输入与 CLI | 退出码区分保留；修正搜索路径编码和深度选项交接。读取失败后目录状态不再显示已分析。 |
| 目录预筛选与排序 | 完整解析重新决定运行资格，撤销已否定的结构优先级；统一 64 KiB、与文件名无关的格式路由，覆盖 PE、ELF、Mach-O、JVM Class、Hermes、Lua、CPython bytecode 及已有容器/字节码提示；共享魔数和损坏头部保持低置信度。候选接纳由线性最差项扫描改为有界堆。 |
| 覆盖范围 | 深度截断、可观察的遍历错误、不可读候选均进入部分覆盖摘要；跳过记录限制内存保留数量，同时保留真实总数。 |
| 递归工件 | 保留静态子分析、SHA-256 去重、来源坐标、深度/节点/字节预算；现有公开图测试负责回归。未扩大执行授权。 |
| 报告暂存 | 存储逻辑从 main 分离；JSON/文本共用限额写入；先关闭文件再删除、删除成功后更新计账、验证磁盘实际条目，写入失败明确返回错误。 |
| 报告一致性 | 共用目录计划文本渲染，完整/暂存文本与 JSON 均表达部分覆盖；JSON 1.0 传输形状保持兼容，目录增加覆盖计数字段。 |
| 执行/安装边界 | 复用既有平台运行资格判定，静态默认和子工件授权清除保持；移除仓库无调用方的旧 `replace_with_unpacked` 接口，保留产品实际使用的验证安装流程。 |
| 平台与第三方 | 修正 MinGW 严格构建暴露的项目告警；miniz 的 Windows ABI 常量比较告警仅在对应 vendor translation unit 局部处理，第三方源码不改动。 |
| 测试与发布身份 | 修正过时的 CI 任务拓扑检查、来源目录测试锚点；公共 runner 与 CMake 一致，仅在源码根缺少 `.git` 时使用完整归档 commit fallback。 |

## 本轮已实现的顺序

1. 修复构建阻塞，建立可运行的本地验证环境。
2. 独立报告暂存组件，以磁盘文件核对代替仅验证 JSON 中的预算计数。
3. 修正搜索编码/深度、目录状态交接和候选接纳成本。
4. 补齐目录部分覆盖信息，限制跳过明细保留，合并重复文本计划输出。
5. 清理无调用方旧接口，修正已经失效的验证脚本。
6. 运行公开 P0/P1、目录压力、安装/来源和 hosted CI；以对应提交的实际结果决定合并。

## 后续优化顺序与验收条件

这些项目需独立设计和验证，本轮不通过批量重构或增加猜测规则掩盖它们。

| 优先级 | 工作项 | 验收条件 |
| --- | --- | --- |
| P1 · 已实现 | 关系构建后的报告保留优先级 | 延迟报告在既有 24 MiB 暂存总量内缓存，关系完成后按最终优先级重选；16 MiB 内联和 8 MiB 单份上限保持。缓存确实被回收时显式记录，不能恢复的详情不会被伪造或自动重新提取。 |
| P1 · 已实现 | 输入快照与一次读取 | 顶层快照从同一映射计算散列，并使用打开句柄的大小和时间；普通路径被重新绑定不会让快照读到另一个文件。安装前后独立 `snapshot_file` 校验保留；映射不声称抵抗并发内容修改。 |
| P1 · 已实现 | 静态/运行时目录资源合同协调 | 共用有界静态准备、报告缓存与最终输出；仅运行时规划可用和关系处理必需的完整报告继续驻留。保留旧运行时工件，明确静态 64 MiB / 512 文件预算的统计范围；运行期输出和聚合模型内存不冒充受同一个字节上限控制。 |
| P2 · 已实现 | 精确范围内的格式接纳一致性 | 统一的 64 KiB、与文件名无关的低成本路由覆盖 Mach-O（含 universal）、Hermes、Lua 5.1–5.5、JVM Class、CPython 及既有 PE/ELF/容器；`CAFEBABE` 等共享魔数在结构不足时降为低置信度，高置信结论仍由深解析产生。 |
| P2 · 已实现 | PE 证书区载荷线索 | 对已验证的 Certificate Table 仅做 file-offset 坐标下的有界 DER 遍历；私有企业 OID 后接至少 256 字节 OCTET STRING 时输出 `SUSPECTED` 载荷线索，并在 AUTO_CORE/`--extract` 的预算内按原始字节物化为 `BULK` 不透明工件，带精确范围、负证据和后续检查建议；不递归解释、解密或执行嵌套内容。 |
| P2 · 已实现 | PE 导出 forwarder/API-set 关系 | 对导出地址落入导出目录的字符串做既有有界解析，验证模块与符号/ordinal 几何并输出 `RVA`/`CURRENT_INPUT_IMAGE` 范围；API-set 仅标记命名空间，畸形目标降为 `PARTIAL`，不猜主机 DLL 或运行时加载结果。 |
| P2 · 已实现 | PE delay-load 关系 | 对 `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` 有界验证 RVA/VA 属性、descriptor、INT/IAT thunk 及 DLL/name/ordinal 几何；首次调用与 helper 搜索路径保持静态未决，截断目录或 thunk 降为 `PARTIAL`。 |
| P2 · 已实现 | 非标准分层/Polyglot 线索 | 在静态扫描上限内汇总非零偏移的 PDF、Mach-O/JVM、UDF、VHD 以及已知容器标记；至少两种不同格式同时出现时输出 `Layered/polyglot format markers`，附当前输入文件坐标、候选上限、负证据和后续结构检查建议，不将标记当作已验证子工件。 |
| P2 · 已实现 | Wasm relocatable metadata | 对 `linking` 与 `reloc.*` custom section 做有界版本、subsection、目标 section 和 relocation entry geometry 检查；合法 linking 版本可标记 relocatable module，unsupported/truncated metadata 保留核心模块确认并显式报告 `FAILED`/`PARTIAL`，不推断完整链接语义。 |
| P2 · 已实现 | PE export forwarder/API-set triage | 对已验证导出目录内的 forwarder 字符串做有界 module/symbol/ordinal/API-set 几何整理；畸形目标降为 `PARTIAL`，不猜 API-set host、不模拟 loader 搜索路径、不执行 DLL。 |
| P2 · 已实现 | CLR/native boundary triage | 对 PE COR20、native entry flag/RVA、OEP、MethodDef body、P/Invoke 及非 CLR 原生导入/导出面做静态边界整理；MethodDef body 进一步区分 RVA 缺失、RVA 不可映射和 tiny/fat IL 几何无效，标出疑似改写/裁剪的托管方法；VMProtect/自定义 loader 常见的托管-原生分界保留 `CONFIRMED`/`LIKELY`/`PARTIAL`，所有运行时解析保持明确拒绝。 |
| P2 · 已实现 | .NET dynamic loader/reflection surface | 组合已验证 `MemberRef` 与 `P/Invoke` 中的程序集加载、metadata 解析、反射调用、动态生成、资源访问和原生加载桥接信号；至少两类独立信号才升级为 `SUSPECTED`/`LIKELY`，报告命中 token 和计数，明确不推出运行时可达、解密或执行。 |
| P2 · 已实现 | .NET MethodDef body map | JSON 与 `.NET symbols.csv` 输出 MethodDef 元数据行、IL body/header/code 的 file-offset、长度和 file-backed 状态；下游可以直接按 token 与当前输入偏移复核异常方法，不需要重新猜测 RVA 到文件范围的映射。 |
| P2 · 已实现 | PE custom-loader surface | 组合 resolver imports、重定位目录、TLS 预入口和入口段权限的独立信号，输出低置信度手动映射/反射式 loader 路由；单一 API、单独重定位目录和普通插件宿主形状不升级，保持静态-only。 |
| P2 · 已实现 | 原生 IAT/代码 hook 面 | 在有界 PE 函数或入口窗口内定位对精确 IAT 槽/可执行范围的文件内写入，并与同函数 loader/patch bridge 调用组合；保留写入指令、IAT 目标和未解析 hook 目标，不把导入或保护 API 单独当作 hook。 |
| P2 · 已实现 | 嵌套 PE 加载路线 | 父 PE 资源目录、资源提取导入与独立写出/启动/模块加载桥和已验证嵌套 PE 同时成立时，生成 `ROUTE_HINT` 父子关系；资源身份、参数流、调用顺序和运行时执行保持未解析，不提升优先级。 |
| P2 · 已实现 | ASAR 脚本到 Wasm/原生成员路线 | 对有界脚本的直接字符串成员引用进行路径规范化和目标格式校验，唯一 exact 成员进入 AUTO_CORE 并生成 `BOUNDED`/R2 关系；动态表达式、缺失目标和未验证格式不伪造端点，运行时加载保持未解析。 |
| P2 · 已实现 | ASAR/JavaScript 目录预检 | 对 ASAR Pickle/JSON 几何及多个 JavaScript-like token 提供有界排序提示；完整分析复核后才保留 Electron ASAR/脚本类型，文本诱饵不会获得原生运行时资格。 |
| P2 · 已实现 | 无 `.pdata` 与魔改名称哈希手工解析器 | 对没有可用 `RUNTIME_FUNCTION` 的 x64 PE，仅在入口可执行节的 8 KiB 有界窗口内复核完整 PEB → export 解析形状；FNV-1a32 走精确分支，算术/位运算替换的名称哈希输出 `MODIFIED_OR_UNKNOWN_NAME_HASH`，不凭静态目录强行分配 API 名称。结果标为 `SUSPECTED`/`ENTRY_SECTION_WINDOW`，不把窗口当作真实函数边界。 |
| P2 · 已实现 | .NET managed resources surface | 将已验证 `ManifestResource` 的嵌入 payload 与外部 `AssemblyRef`/`File`/`ExportedType` 实现关系交接给报告，并在预算内原样物化嵌入字节接入递归子工件图，保留文件偏移和静态-only 边界，优先提示内嵌 DLL/配置/二进制资源。 |
| P2 · 已实现 | .NET single-file bundle materialization | 在 v2/v6 manifest/member geometry 已闭合后，按 AUTO_CORE/`--extract` 预算物化未压缩 managed assembly、native runtime、deps/runtimeconfig 与 symbols 成员，注册到现有静态子工件图；v6 压缩成员明确保留为待解压边界，不执行应用、不伪造 Brotli 结果。 |
| P2 | 路径与输出公共层 | 逐步统一各提取器的路径编码、输出创建与失败状态；按格式迁移，每次保留现有公开静态用例，避免一次性替换所有文件操作。 |
| P2 | Wasm 跨文件路由深化 | 对 validated Wasm 的 import(module/name) 与唯一 supplied sibling export 做有界 `BOUNDED` 关系；多目标、截断或运行时模块搜索不明时保持未解析，不把静态目录关系当作实例化成功。 |
| P2 | 入口/报告/运行时大文件拆分 | 按 CLI、单文件静态管线、工件协调、目录协调和呈现分离；每次拆分验证行为等价与构建成本。禁止以目录名、样本名或已知哈希作为产品规则。 |
| P3 | 新能力准入 | 仅在以上公共流程稳定后拓展；每个新增格式/生态须有独立正例、损坏输入、相似负例、资源上界和明确的预处理产出。 |

## 验证方法与边界

P1 后续基线为 `e93f3cdb8de29f6f87571e74d77bf895e6bfb4fd`。新增映射快照 unit 覆盖空文件、普通文件、句柄移动、路径重新绑定、独立校验仍可发现路径内容变化；沿用报告暂存 unit 增加二阶段重选和缓存回收断言。原 1031 文件压力场景增加跨文件关系提升，复用现有测试流程；原有授权运行时目录用例增加 128 个静态输入，验证它们不需要继续驻留完整模型。

开发过程中的一次 Windows MinGW GCC 14.2 / 静态链接受控对比：64 MiB 全零普通输入的散列不变，进程 `ReadTransferCount` 从 67,108,864 B 变为 6,219 B，耗时 0.454 s / 0.451 s。该计数不包含映射缺页带来的物理磁盘读取，因此只证明消除了额外缓冲读取，不表示磁盘 I/O 归零。768 个普通文本输入在显式请求运行时但没有可运行目标的场景中，采样峰值工作集从 50,728,960 B 变为 15,818,752 B，JSON 从 25,455,774 B 变为 17,627,691 B，耗时 7.276 s / 7.166 s；紧凑状态仍覆盖全部输入，超出预算的详情被明确延迟。以上是开发阶段单次观察，不是冻结版本的性能基准或普遍加速承诺。

句柄时间转换遵循目标标准库的文件时钟；Microsoft 实现采用 1601 epoch / 100 ns tick，见 [Microsoft file_clock 文档](https://learn.microsoft.com/en-us/cpp/standard-library/file-clock-class?view=msvc-170)。MinGW 的路径 stat 接口可能只有秒精度，映射快照保留句柄提供的亚秒精度。

后续 P2 仍需继续处理大量可运行原生映像的聚合模型内存、各后端运行时产物总量，以及格式路由和路径公共层的渐进统一；当前不声称这些问题已经全部解决。

- 新增 `directory_report_spool_unit.cpp` 与 `test_preprocessing_contract.py` 已纳入公开 P0；它们不运行被分析文件。
- `test_bounded_directory_output.py` 使用 1031 个普通生成输入检查优先接纳、1024 个状态、报告/工件预算及 UTF-8 输出。
- `check_workflow_contract.py --self-test` 验证当前三个 workflow，包括在 Linux GCC job 内严格限定非 PR 事件的运行时测试步骤。
- 源码归档身份测试的三个场景复用一个构建目录，减少重复编译器探测和 try-compile，同时检查重新配置能否清除旧身份；不增加重复的独立 CI 构建任务。
- 本地 Windows MinGW 使用严格告警和静态链接验证；MSVC、Linux GCC/Clang 与 ASan/UBSan 由对应 hosted CI 验证，不能相互替代。
- 不将 sanitizer smoke 当作全解析器安全证明；当前 sanitizer 链接的格式范围以 CMake target 为准。
- 搜索大小写折叠限于 ASCII；POSIX 非 UTF-8 原始文件名字节的通用 JSON 表示、遍历过程中并发修改的完整快照语义，以及权限拒绝被文件系统静默跳过的计数仍需独立合同。

精确提交、测试完成状态与 CI 链接以本次合并请求为准。本文件不复制旧发布成绩，也不预先声明尚未完成的验证通过。
