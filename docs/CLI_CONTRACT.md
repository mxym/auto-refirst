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

## JSON transport shape

`--json` preserves the existing 1.0 transport behavior: a direct single-file analysis emits one report object; recursive extracted-artifact mode emits a bare report array when it produces multiple reports; directory analysis emits a directory envelope with a `reports` array. This transport distinction is compatibility behavior and is not silently changed inside schema 1.0.

`--json-envelope` is an opt-in transport normalization and requires `--json`. For single-file and recursive artifact analysis it emits an object containing top-level `report_schema_version` and `reports`; directory analysis already has an envelope and retains its existing directory fields. The option does not change the child report schema or imply a schema-version bump. It is rejected with `--search`, whose JSON mode remains JSON Lines.

## Directory resource scope

Static and explicitly authorized runtime directory analysis share the same report transport budget: 16 MiB of complete inline reports, 8 MiB per report, and 24 MiB of temporary report payloads including deferred cache and the active writer. Final cross-file priorities reselect available cached reports without repeating extraction or target execution. `cache_evicted_reports` counts payloads discarded to maintain the disk bound; their compact file states remain present, but final priority changes cannot recover discarded bytes. `priorities_finalized`, `reports_reselected` and `spool_resident_bytes` describe this final selection.

For default materialization, `artifact_materialization.scope` is `automatic_static_preparation`: the 64 MiB / 512-file aggregate covers new static derivatives, including relationship-driven materialization. Prior `runtime/` contents and `.auto-refirst-owner` survive static preparation and are excluded from that count. Runtime outputs remain subject to their backend's separate controls, and explicit `--extract` retains its per-file extraction contract. The static aggregate is not a total disk bound for runtime output or pre-existing observations.

Reports needed for relationship mutation or a selected runtime **planning route** remain resident until that work finishes; other reports are serialized and released. `retained_full_reports_peak` counts these retained models, not transient parser objects or bytes. The input candidate count remains bounded; an aggregate in-memory model-byte limit is not claimed for directories full of runtime-eligible images.

If only static details are deferred, direct static reanalysis remains the retrieval route. If an executed target's report is deferred, `runtime_detail_deferred` is true and retrieval points to retained runtime artifacts or an explicit `--run` invocation. A new invocation cannot reproduce the previous run's observations and does not inherit `--apply` authorization.

## Execution and write authorization

- Static analysis is the default and does not execute the target.
- `--run` explicitly authorizes target execution. It does not authorize replacement of the input.
- `--run=unpack` is a deprecated compatibility alias for non-destructive deep runtime analysis. Without `--apply`, it may retain recovered artifacts but may not install or replace the input.
- `--apply` is rejected unless runtime execution is also authorized. Even with `--run --apply` (or the compatible `--run=unpack --apply` form), installation occurs only after the implemented validation, backup, and rollback gates succeed.
- Automatically extracted or recursively analyzed child artifacts remain static-only; authorization for a root target is not inherited by children.
- `--artifact-root=PATH` relocates a **single file's** product-owned artifact tree. It never authorizes replacement of the input. A pre-existing root is accepted only when its regular `.auto-refirst-owner` marker binds it to the same input path; unrelated existing directories and symlink/reparse roots are refused with usage exit code `2`.
- `--artifact-root` is currently incompatible with directory input, pure `--search`, and `--extract --recursive`, because those modes require either no artifact tree or multiple independently owned roots.

`--run` executes potentially untrusted code. Use an isolated environment appropriate to the target; auto-refirst is not a sandbox.
