# Security policy

## Execution and writeback boundary

Static analysis is the default. `--run` authorizes execution of potentially untrusted target code and should be used only in an isolated environment whose compromise is acceptable. auto-refirst does not provide a sandbox.

`--run --apply` separately authorizes validated installation/replacement. A candidate must pass the implemented reconstruction, validation, backup/hash, post-install validation, and rollback gates before installation can occur. The deprecated `--run=unpack` alias is non-destructive unless `--apply` is also supplied.

Use auto-refirst only on binaries and files you are authorized to analyze.

## Security reports

Please report issues involving:

- target execution without explicit `--run`;
- installation/writeback without explicit `--apply`;
- path traversal, symlink/reparse escape, or extraction outside the owned artifact root;
- memory-safety defects reachable from malformed static input;
- validation bypass that can cross the `--apply` boundary;
- release or dependency substitution affecting distributed artifacts.

Do not disclose suspected vulnerabilities, exploit details, credentials, private samples, or sensitive crash artifacts in a public issue. Use GitHub Private Vulnerability Reporting from the repository Security tab.

A useful report includes the affected version/commit, OS/architecture, exact command, whether `--run` or `--apply` was supplied, a minimal redistributable reproducer when available, and sanitized JSON/log excerpts.

## Supported versions

The latest public 0.x release is the primary supported line during the alpha period.
