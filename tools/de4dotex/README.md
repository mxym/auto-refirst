# de4dotEx sidecar adapter (experimental)

This directory contains a narrow experimental adapter for a separately distributed
GPL tools pack. Its current integration/publishability decision is `PARTIAL`,
not release-ready `GO`. It is not a general plugin system and does not place
de4dotEx source or binaries in the core tree.

Every de4dotEx invocation is treated as capable of loading or executing target
code. The provider is disabled by default. Neither detector mode nor
`--default-strtyp none` is a static-only boundary. P0/P1 and other static-only
flows must never invoke this adapter.

The caller must supply an existing explicit `--run` authorization document
bound to the exact input:

```json
{
  "schema": "auto-refirst.target-execution-authorization.v1",
  "authorization_source": "explicit --run",
  "runtime_execution_authorized": true,
  "static_evidence_only": false,
  "target_sha256": "<lowercase sha256>",
  "target_size": 1234
}
```

Linux invocation (all paths must be absolute and the output path must not
exist):

```sh
python3 tools/de4dotex/adapter.py \
  --manifest /path/to/manifest.linux-x64.json \
  --tool-root /path/to/pinned/de4dotex-3.8.0 \
  --bwrap /usr/bin/bwrap \
  --authorization /analysis/auth.json \
  --input /analysis/target.dll \
  --output-dir /analysis/new-result \
  --mode detect
```

The adapter emits one bounded JSON object and exits zero for both `COMPLETE`
and fail-closed `PARTIAL` outcomes. Argument usage errors exit 2. Missing or
mismatched tools, authorization failures, timeout, crash, excessive output,
malformed output, and unsafe output objects are `PARTIAL`; they do not affect
core analysis. A deobfuscated DLL is always `PENDING_CORE_REPARSE` until the
core PE/CLR/ECMA-335 parser independently accepts it.

The v1 result always identifies `schema_version`, `provider`, `mode`, `state`,
and `attempted`. `attempted=false` guarantees that neither bubblewrap nor
de4dotEx was started; `attempted=true` means launch was attempted, not that the
tool necessarily reached its entry point. Preflight
failures such as `MANIFEST_UNTRUSTED`, `TOOL_TREE_NOT_IMMUTABLE`,
`SANDBOX_UNAVAILABLE`, and `HARD_RESOURCE_SANDBOX_UNAVAILABLE` are therefore
observable without being confused with a tool attempt. `COMPLETE` is possible
only for the bounded detector profile; it is not a deobfuscation claim.

The Linux sandbox uses new mount/user/PID/IPC/UTS/network namespaces, a
read-only copied input, a private output, empty HOME, private `/tmp`, a minimal
read-only host ABI, no network, timeout, process/address-space/file-size/file
count/log limits, and `--die-with-parent`. The manifest's bubblewrap 0.6.1
minimum records only the research host proof. Publication must either pin and
audit a supported upstream bubblewrap or state an audited system dependency
and minimum version.

The adapter source pins this manifest at SHA-256
`7e636d58afb2e61b3e479bbf40bd9926b71a7e6744b0b5de4f5255b7c90a4039`.
A self-authored manifest cannot redefine the provider, tool tree, release,
bind mounts, or limits. The installed tool tree and bubblewrap path chain must
be root-owned,
ACL-free, and non-writable by the adapter identity, group, or world; a mutable
user-owned BYO directory is rejected. The adapter itself must not run as root.
The bubblewrap launcher receives a small fixed environment so host
`LD_PRELOAD`, `LD_LIBRARY_PATH`, and similar variables cannot run code before
`--clearenv` takes effect. The output parent must be canonical, private
(no group/world permissions), and owned by the adapter identity.

The adapter also requires its current cgroup v2 to have numeric `memory.max`,
`memory.swap.max`, and `pids.max` values no larger than the manifest maxima
(the current manifest disables swap). A host with unbounded or unavailable
controls receives `PARTIAL/HARD_RESOURCE_SANDBOX_UNAVAILABLE`
before de4dotEx starts. `RLIMIT_AS` is a separate, high virtual-address guard:
it is not represented as a physical-memory limit. The .NET GC heap hard limit
is defense in depth and does not replace the cgroup.

Output and log totals are polled, while `RLIMIT_FSIZE` is a hard per-file
ceiling. This checkpoint does not yet provide a hard aggregate filesystem
quota; a publishable deployment must add one (or equivalently strict brokered
I/O) for hostile concurrent writers.

Linux tools-pack publication remains `PARTIAL` until the selected supported
bubblewrap dependency, exact de4dotEx and BeaEngine corresponding sources,
build provenance or an independent pinned rebuild, a hard aggregate output
quota, GPL/LGPL source delivery,
.NET license/notices, dependency notices, and SBOM are packaged and reviewed.
A BYO deployment has the same runtime gates and must use a trusted installer to
verify the pinned archive and create the immutable tree; pointing the adapter at
an ordinary user-writable extraction is not supported. Once those conditions
are met and the product's explicit `--run` authorization is bound to this
adapter, Linux may be promoted to `GO` without blending GPL code into the core.

There is no validated equivalent Windows sandbox in this checkpoint. Direct
Windows bundling remains NO-GO until AppContainer/low-integrity isolation, Job
Object limits, and network denial are implemented and tested. Wine is not a
sandbox; invoking a Windows BYO tool through this adapter is also NO-GO.
