# 公开测试

公开仓库只包含可再分发、可解释来源的测试数据以及 source-generated/synthetic fixtures。

## P0 — self-contained core

P0 校验：

- 9 个公开 fixture 的 provenance 与 SHA-256；
- PE/ELF/JVM/DEX/Wasm/Lua 静态格式边界；
- 跨文件关系与目录 guidance；
- interpreter/runtime-modality 静态授权边界；
- nested executable 与 recursive artifact graph；
- model trust 与 CPython bytecode ingress；
- JSON/text/version 基础合同；
- Windows junction/reparse 输出安全（Windows runner）。

## P1 — source-generated integration

P1 从仓库源码构建普通 native、crypto、runtime-child/runtime-parent fixtures，并验证分析仍保持 static-only。Python bytecode fixture 由测试脚本按固定字节格式生成。

运行：

```sh
python3 tests/run_public_regression.py --binary build/auto-refirst --tier all
```

P0/P1 不下载 challenge corpus，不执行分析目标，不需要任何私有 fixture root。

## Sanitizer surface

`auto_refirst_public_malformed_sanitizer` 只链接 PE/ELF/JVM/DEX/Wasm/Lua parser 相关路径，用 malformed synthetic inputs 执行 ASan+UBSan smoke。

## Fixture provenance

公开 fixture inventory 位于 `tests/corpus/PROVENANCE.csv`。新增持久二进制 fixture 必须记录 generator/source、toolchain、license/redistribution basis、rebuild command 和 SHA-256。
