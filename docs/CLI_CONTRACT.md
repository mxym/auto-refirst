# CLI process and authorization contract

This document defines the stable command-line process contract for release automation. Report findings and process status are separate: suspicious content, a partial analysis, or a bounded refusal is not by itself a command failure.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The requested command completed and its output was written successfully. Findings may still report suspicious, failed, partial, unsupported, or budget-limited analysis states. |
| `1` | A valid `--search` completed over readable input and found no match. |
| `2` | Command-line usage was invalid, including unknown or incompatible options. |
| `3` | The input could not be accessed, was not an accepted file/directory type, or contained no readable regular input. |
| `4` | A fatal process-level failure prevented completion, such as an output, temporary-storage, report-spool, or orchestration invariant failure. |

`--help` and `--version` return `0` when their output is written successfully. A failed output write returns `4`.

Runtime observations are represented in the text or JSON report. A target exit, timeout, refused runtime route, unsupported deep-analysis path, materialization limit, or validation failure does not become a different process exit code merely because it was observed; the command returns `0` if the requested analysis and report emission still completed.

## Execution and write authorization

- Static analysis is the default and does not execute the target.
- `--run` explicitly authorizes target execution. It does not authorize replacement of the input.
- `--run=unpack` is a deprecated compatibility alias for non-destructive deep runtime analysis. Without `--apply`, it may retain recovered artifacts but may not install or replace the input.
- `--apply` is rejected unless runtime execution is also authorized. Even with `--run --apply` (or the compatible `--run=unpack --apply` form), installation occurs only after the implemented validation, backup, and rollback gates succeed.
- Automatically extracted or recursively analyzed child artifacts remain static-only; authorization for a root target is not inherited by children.
- `--artifact-root=PATH` relocates a **single file's** product-owned artifact tree. It never authorizes replacement of the input. A pre-existing root is accepted only when its regular `.auto-refirst-owner` marker binds it to the same input path; unrelated existing directories and symlink/reparse roots are refused with usage exit code `2`.
- `--artifact-root` is currently incompatible with directory input, pure `--search`, and `--extract --recursive`, because those modes require either no artifact tree or multiple independently owned roots.

`--run` executes potentially untrusted code. Use an isolated environment appropriate to the target; auto-refirst is not a sandbox.
