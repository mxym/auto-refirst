# Optional Qt evidence workspace

`auto-refirst-gui` is a small Qt Widgets client for the existing
`auto-refirst` command line contract. It is intended for triaging unusual or
modified samples before opening a disassembler: drop files or directories into
the queue, run bounded static analysis, and inspect the resulting evidence and
limitations without copying parser logic into a second implementation.

The GUI is disabled by default and does not add Qt to the normal CLI build.
When enabled, CMake prefers Qt 6 Widgets and falls back to Qt 5 Widgets:

```sh
cmake -S . -B build-gui -DAUTO_REFIRST_BUILD_QT_UI=ON
cmake --build build-gui --target auto_refirst_gui --parallel
./build-gui/auto-refirst-gui
```

On Windows with a multi-configuration generator, use
`cmake --build build-gui --config Release --target auto_refirst_gui`. The
machine must provide the corresponding Qt development package and CMake
package configuration. If Qt is not installed, leave the option at its default
`OFF`; the CLI remains buildable. Enabling it without Qt fails at configure
time with an explicit dependency message.

The client locates `auto-refirst` beside the GUI executable (or uses the
`AUTO_REFIRST_CLI` environment override for development). There is no CLI
path picker in the product UI. Normal analysis invokes the CLI once per queue item with:

```text
auto-refirst <file-or-directory> --json --json-envelope --json-errors
```

Search mode replaces `--json-envelope` with `--search=TEXT` because the CLI
returns JSON Lines; the GUI wraps those hits into the same report view.

The **Basic** tab maps static preparation, recursive artifact reports,
runtime mode, replacement authorization, report language, and the per-item
timeout. Runtime analysis and replacement are disabled by default and require
confirmation. The **Advanced** tab exposes directory depth/runtime budgets,
`--run-all`, artifact depth/node/byte limits, a product-owned artifact folder,
directory text search (including case-insensitive mode), and optional `wxid`.
The GUI passes these values to the CLI rather than reimplementing analysis;
search mode uses a normalized JSON report so its JSON-lines results can be
reviewed in the same workspace. Reports are written
as timestamped JSON files under the selected report directory. The *Open
report* and *Open output directory* buttons use the desktop's registered file
handler.

Each item runs serially with a user-visible timeout (default 120 seconds), a
cancel action, and a 64 MiB stdout cap. A timeout, process failure, malformed
JSON, or report write failure stays attached to that queue row and does not
discard completed reports. The summary counts findings and separates
`CONFIRMED` from review-level states such as `LIKELY` and `SUSPECTED`. It shows
concise next steps and whether output was partial; detailed coordinates and
limits remain in the JSON report.

The interface includes a Chinese/English switch, a finding filter, a readable
summary, next-step text, and compact limit messages. Internal evidence fields
are kept in JSON but are not copied into the normal report view. On Windows
both the GUI target and its CLI child use the no-console process path.

The dependency-free contract check can run on a headless machine:

```sh
python3 tests/check_qt_ui_contract.py
cmake --build build --target auto_refirst_public_qt_ui_contract_check
```

It checks that the optional target stays off by default and that drag/drop,
bounded process transport, cancellation, error diagnostics, and limitation
display remain wired without launching Qt.
