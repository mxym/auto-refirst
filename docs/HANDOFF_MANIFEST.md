# Static handoff manifest

`tools/create_handoff_manifest.py` converts an auto-refirst JSON report (the
normal `--json` output or a `--json-envelope` containing `reports[]`) into a
small deterministic transport contract for a downstream analyst or tool:

```sh
python3 tools/create_handoff_manifest.py report.json -o handoff.json
```

The converter consumes only the report bytes. It does not open, resolve,
execute, install, extract, or write back any path named by the report. Every
entry is marked `STATIC_ARTIFACT_UNTRUSTED`; runtime observations use
`RUNTIME_OBSERVED_UNTRUSTED`. The policy always sets `execution_authorized`,
`installation_authorized`, and `writeback_authorized` to `false`.

The manifest contains:

- `sources`: declared input paths plus the report-provided top-level SHA-256
  and size, scoped to `current_input_file`;
- `entries`: bounded static and runtime artifact observations with state,
  role, relation, size and SHA-256 when supplied by the report;
- `findings`: bounded evidence, negative evidence, fields and suggested
  actions, without copying arbitrary report fields;
- `relationships`: bounded structural relations and their provenance fields;
- `next_actions`: deterministic union of suggested actions and guidance;
- `truncation`: total and omitted counts for each bounded collection.

Output uses sorted JSON keys and stable collection ordering. A caller that
wants a larger handoff must raise an explicit bound; the output records the
resulting counts. The manifest is a handoff description, not proof that an
artifact is safe, executable, decoded, or trusted.
