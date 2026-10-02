# Anti-debug detection contract

This document defines how auto-refirst reports anti-debug / debugger-evasion behavior. The goal is not to label software as malicious. The goal is to turn common anti-debug mechanisms into factual, bounded reverse-engineering entry points.

## Reporting model

Each technique is emitted as an independent `Finding`:

- `kind=anti-analysis`
- `family=Anti-debug`
- `variant=<specific technique>`
- `state=SUSPECTED|LIKELY|CONFIRMED`
- `confidence=<bounded confidence>`
- `fields.category`
- `fields.method`
- `fields.api/module/transfer` where applicable
- `fields.callsite_rva` and `fields.function_rva` when a native call/instruction is localized
- `fields.malicious_intent=NOT_INFERRED`
- `ranges[]` contains exact callsite / instruction / debugger-name coordinates when available

`CONFIRMED` means the debugger-probe/control behavior itself is structurally confirmed. It never means malicious intent is confirmed.

Linux runtime tracing also emits a `debugger_control` timeline event for `prctl(PR_SET_DUMPABLE/PR_SET_PTRACER)` and `ptrace(PTRACE_TRACEME/PTRACE_ATTACH/PTRACE_SEIZE)` calls. The event keeps the operation, relevant PID/value, and syscall success or error status. A failed `PTRACE_TRACEME` under the product tracer remains useful evidence of a self-tracing attempt; the event does not infer intent or claim that a debugger was present.

## Confidence policy

### Strong semantic behavior — normally `CONFIRMED`

These have debugger-specific semantics once the call/instruction and required parameter are recovered:

- `IsDebuggerPresent` real callsite.
- `CheckRemoteDebuggerPresent` real callsite.
- `NtQueryInformationProcess` / `ZwQueryInformationProcess` with:
  - `ProcessDebugPort = 7`
  - `ProcessDebugObjectHandle = 30`
  - `ProcessDebugFlags = 31`
- `NtSetInformationThread` / `ZwSetInformationThread` with `ThreadHideFromDebugger = 17`.
- `NtCreateThreadEx` with the actual seventh Win64 argument `CreateFlags` containing `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x4`. The stack argument is recovered from the callsite; the constant merely appearing elsewhere is insufficient.
- x64 direct PEB access `GS:[0x60] -> PEB + 2` (`BeingDebugged`), including the optimized direct-segment form `GS:[0x60+2]`.

A nearby branch or output-value use is additional evidence, not required to acknowledge that the debugger-state query happened.

### Strong combination — normally `LIKELY`

These are meaningful only when multiple facts line up:

- `GetThreadContext` / `NtGetContextThread` with `CONTEXT_DEBUG_REGISTERS`-compatible flags is at least a context probe; when the same stack-resident x64 `CONTEXT` is subsequently read at Dr0/Dr1/Dr2/Dr3/Dr6/Dr7 offsets, the hardware-breakpoint-register inspection itself is `CONFIRMED`.
- `SetThreadContext` / `NtSetContextThread` / `ZwSetContextThread` is `CONFIRMED` when its second argument resolves to a file-backed or stack-local `CONTEXT` whose `ContextFlags` includes `CONTEXT_DEBUG_REGISTERS (0x10)`. The report localizes the file bytes or stack initializer while leaving the runtime Dr0-Dr7 values unresolved.
- `CloseHandle` on an invalid/pseudo handle. This can intentionally exploit debugger exception behavior, but can also be a bug or diagnostic path.
- `RaiseException` with debugger-specific `DBG_*` status codes.
- `INT3` only when a local exception-handler registration (`AddVectoredExceptionHandler`, `RtlAddVectoredExceptionHandler`, `AddVectoredContinueHandler`, `RtlAddVectoredContinueHandler`, or `SetUnhandledExceptionFilter`) is nearby in the same function. A distant CRT failure-path `INT3` is deliberately ignored.
- `INT1` / ICEBP and `INT 0x2D` are intrinsically more debugger-specific, but still remain separate from malicious-intent inference.
- Software-breakpoint byte scanning is `CONFIRMED` only when a bounded loop starts from a statically recovered current-PE executable/file-backed address, reads one byte at a time, compares the loaded byte against `0xCC`, advances a zero-based index by one, and has a recovered upper bound plus conditional backedge. Merely containing `INT3` bytes, scanning a data section for `0xCC`, or scanning executable bytes for another value is insufficient. The report includes the exact checked code range.
- `FindWindowA` becomes a strong combination when its actual class/title argument is statically resolved to a debugger-identifying string (`x64dbg`, `WinDbg`, `OllyDbg`, IDA, Ghidra, etc.). Process/window enumeration plus uncorrelated debugger-name strings remains only `SUSPECTED`.
- `GetProcAddress` becomes `LIKELY` when its actual name argument resolves to a file-backed anti-debug API string. Merely having `GetProcAddress` plus such a string elsewhere in the file stays `SUSPECTED`; acquiring a function address still does not prove the function is invoked.
- `NtQuerySystemInformation(SystemKernelDebuggerInformation=35/0x23)` is recognized as a kernel-debugger-state query but remains `LIKELY`, because the information class is an NT-internal/version-sensitive contract rather than a stable Win32 API surface. A 2-byte output length is retained as strengthening evidence.
- `NtQueryObject(ObjectTypeInformation=2)` is promoted only when the output `OBJECT_TYPE_INFORMATION` buffer is recovered, a later comparison loads `UNICODE_STRING.Buffer` at output-buffer `+8`, the comparison's actual UTF-16 literal is `DebugObject`, and the compare callsite is in the same bounded x64 function. Merely importing `NtQueryObject` or containing a `DebugObject` string is insufficient.
- x64 `PEB.NtGlobalFlag` is recognized only when the PEB is derived from `GS:[0x60]`, offset `+0xBC` is accessed, and the canonical debug-heap mask `0x70` is explicitly tested/masked. The internal offset is reported as version-sensitive and is not treated like a public ABI.
- x64 `PEB.ProcessHeap` is recognized only when `GS:[0x60] -> PEB + 0x30` is recovered and the resulting heap pointer reaches a bounded `Flags` (`+0x70`) or `ForceFlags` (`+0x74`) `TEST`/`CMP`/`AND` operation. A bare `+0x30`, `+0x70`, or `+0x74` load is ignored.
- `CPUID/hypervisor-present` is recognized only when the same bounded function loads `EAX=1`, executes `CPUID`, tests `ECX[31]` (`0x80000000`, or `BT ECX,31`), and feeds a nearby conditional branch. Ordinary CPUID feature dispatch is ignored; the result identifies a virtualized environment and does not by itself establish debugger intent.
- `VirtualProtect/PAGE_GUARD` is recognized only when a same-function executable VEH/SEH callback registration precedes `VirtualProtect`, the protection argument contains `PAGE_GUARD (0x100)`, and the protected address/size resolve to current-PE executable/file-backed bytes. A guard-page import or flag without this protocol remains silent.
- `RFLAGS.TrapFlag` is recognized only when `PUSHFQ` is immediately followed by `POP` into a tracked register, RFLAGS bit 8 is tested (`TEST/AND/CMP` with `0x100` or `BT` with `8`), and a nearby conditional branch consumes the result. Bit 0 is Carry Flag and is deliberately ignored. A plain flags save/restore sequence is ignored. The bit assignment follows Intel SDM Vol. 1 §3.4.3.1 and the public `PUSHFQ` reference: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>, <https://www.felixcloutier.com/x86/pushf:pushfd:pushfq>.

### Weak/ambiguous — normally `SUSPECTED`

These are common in benign software and must not be upgraded without extra semantics:

- multiple `QueryPerformanceCounter`, `GetTickCount*`, `timeGetTime` samples;
- multiple `RDTSC` / `RDTSCP` reads plus comparison/branch;
- `NtYieldExecution` by itself. It is only promoted when the returned status is immediately compared against `STATUS_NO_YIELD_PERFORMED (0x40000024)` and controls a branch, and even then remains lower-confidence because the behavior is inherently unreliable and overlaps scheduler APIs such as `SwitchToThread`.
- `DebugBreak` by itself;
- `OutputDebugString*` by itself;
- exception-handler registration by itself;
- `GetThreadContext` with ordinary `CONTEXT_CONTROL` / crash-dump flags;
- process/window enumeration without debugger-specific comparison evidence.

## Import-call normalization

For x64 PE files with `.pdata`, anti-debug API calls are recovered from decoded instructions and normalized across compiler/linker shapes:

- direct `call [IAT]`;
- relative `call` to an import thunk;
- `mov reg,[IAT] -> call reg`;
- `jmp [IAT]` tail calls;
- relative tail `jmp` to an import thunk.

The detector prefers real `RUNTIME_FUNCTION` boundaries instead of scanning arbitrary executable bytes for `FF 15/25` patterns. This avoids treating accidental bytes or adjacent CRT code as API callsites.
For Native APIs with more than four parameters, bounded backward slicing also recovers immediate/register-backed Win64 stack arguments at the callsite. This is currently used to prove the seventh `NtCreateThreadEx` `CreateFlags` argument instead of searching the function for a standalone constant `4`.

## Current first-class methods

Implemented now:

1. Win32 debugger-presence APIs.
2. Native process debug information classes 7/30/31.
3. `ThreadHideFromDebugger`.
4. x64 PEB `BeingDebugged`.
5. hardware-debug-register context requests and correlated Dr0/Dr1/Dr2/Dr3/Dr6/Dr7 consumption.
6. invalid/pseudo-handle `CloseHandle` exception probe.
7. `RaiseException(DBG_*)`.
8. local exception handler + software trap correlation.
9. QPC/GetTickCount/timeGetTime timing pairs (weak).
10. RDTSC/RDTSCP timing pairs (weak), with exact read/compare/branch ranges; explicit low32 delta threshold gates are reported separately by the Execution prerequisite detector.
11. exact `FindWindowA` debugger-name arguments plus weaker uncorrelated process/window discovery.
12. exact `GetProcAddress` anti-debug API-name arguments plus weak unresolved dynamic-resolution surfaces.
13. `NtQuerySystemInformation(SystemKernelDebuggerInformation=35)` with internal-API caveat.
14. x64 `PEB.NtGlobalFlag + 0xBC` only when debug-heap mask `0x70` semantics are also present.
15. `NtCreateThreadEx` hidden-thread creation with exact Win64 stack-argument recovery.
16. `NtYieldExecution` status-comparison pattern (`0x40000024`) as an explicitly unreliable scheduler/timing probe.
17. `NtQueryObject(ObjectTypeInformation)` with stack-output + `TypeName.Buffer` + exact `DebugObject` comparison correlation.
18. bounded current-PE executable-range software-breakpoint scans that compare each byte against `0xCC`, with exact target file/RVA range recovery.
19. separate `Self-integrity` findings for bounded current-PE executable-range ADD32/XOR32/FNV-1a32 byte checksums, with scanner/direct-caller reference comparison, immediate/RIP-global references, exact target range recovery, and current-reference match/mismatch recomputation.
20. x64 PEB `ProcessHeap` `Flags`/`ForceFlags` probes, requiring PEB-to-heap data flow and a concrete field test rather than magic-offset co-occurrence.
21. CPUID leaf-1 hypervisor-present bit checks with a localized compare and conditional branch.
22. x64 RFLAGS trap-flag reads through `PUSHFQ`/`POP` with a localized bit-8 test and branch.
23. PE64 guard-page exception probes when a prior same-function executable VEH/SEH callback, a PAGE_GUARD protection request, and a current-PE executable/file-backed target all resolve.

## Research backlog / planned detectors

The following techniques are useful, but require additional validation before they become first-class findings.

### PEB / heap internals

- direct heap metadata checks across Windows generations. The current detector deliberately reports only the x64 PEB-to-heap offsets and exact field test; version-specific heap layouts and non-x64 variants remain separate research work.

These are version/heap-implementation sensitive. They should not be reported solely from a magic offset without architecture/version context.

### Trap-flag / instruction quirks

- trap-flag single-step tests;
- `push ss / pop ss`, `mov ss` interrupt-shadow tricks;
- prefix/ICEBP variants;
- deliberate breakpoint-byte (`0xCC`) scanning.

Instruction presence alone is insufficient. The detector should recover the surrounding exception/control-flow protocol.
The classic `push ss; pop ss; pushf` sequence documented by the Check Point Anti-Debug guide is a 32-bit segment-register trick; the current PE64 decoder deliberately leaves it out because those segment-register opcodes are not valid x64 instructions. See <https://anti-debug.checkpoint.com/techniques/assembly.html>.

### Code / breakpoint integrity

- richer checksum/hash families beyond the implemented byte-wise ADD32/XOR32/FNV-1a32 forms (for example CRC/cryptographic hashes, wider rolling checksums, multi-range schemes, or non-x64 implementations);
- richer self-scans for patched bytes beyond the implemented bounded `0xCC` software-breakpoint loop;
- comparing in-memory code against a separately materialized embedded/disk reference;
- guard-page / memory-protection checks used to detect breakpoints.

These should be reported as self-integrity / breakpoint-detection behavior only when the checked range and reaction can be localized.

### Debug objects / system information

- `NtQueryObject` debug-object enumeration;
- kernel-debugger state through `NtQuerySystemInformation` when the information class and returned fields can be validated safely;
- parent-process / shell checks using `ProcessBasicInformation` plus process enumeration.

Undocumented/version-sensitive information classes remain lower confidence unless the exact layout is independently corroborated.

### Scheduler / timing / environment

- `NtYieldExecution` / scheduling anomalies;
- `Sleep`/wait timing skew;
- CPUID/hypervisor timing combinations;
- debugger process/service/driver discovery.

These are broad anti-analysis families and require multi-signal routing to avoid false positives.

### Runtime confirmation

Once the runtime resolver/TLS work is stable, dynamic observation may upgrade selected static clues:

- actual return values from debugger-presence queries;
- actual `ProcessDebug*` / `ThreadHideFromDebugger` calls reached before OEP;
- timing threshold and branch outcome;
- first-chance exception routing differences;
- self-integrity/breakpoint scan result and subsequent control-flow decision.

Runtime confirmation must remain separate from static detection and must not alter `MEMORY_DUMP` / `UNPACKED_VALIDATED` semantics.

## False-positive rules

- Import presence is never enough.
- Debugger-name strings are never enough.
- Weak `SUSPECTED` findings are globally capped per artifact so large runtimes do not drown the report in QPC/trap/profiling noise; stronger findings are never dropped by that cap.
- Timing sources are never enough for `LIKELY`/`CONFIRMED` without stronger semantics.
- `OutputDebugString`, `DebugBreak`, exception handlers and thread-context APIs have legitimate diagnostic uses.
- Native internal APIs are version-sensitive; parameter constants and callsite recovery are required.
- General executable-range checksum/reference self-integrity is reported under the separate `Self-integrity` family rather than being presumed anti-debug. Software-breakpoint `0xCC` scanning remains here because it is debugger-specific. See the technical reference for checksum confidence and attribution rules.
- A protector/DRM/anti-cheat can legitimately implement anti-debugging. Report the behavior, not an intent label.

## Suggested analyst workflow

For every `Anti-debug` finding:

1. jump to `callsite_rva` / `function_rva`;
2. verify the reported constant/output operand;
3. follow the conditional reaction and failure/exit path;
4. patch or emulate only the specific check if needed;
5. if several findings cluster in one early/TLS/entry function, prioritize that region as the anti-analysis gate;
6. compare with Authenticode/page-hash/self-integrity evidence before patching a signed target, because a patch may intentionally trigger a second integrity layer.
