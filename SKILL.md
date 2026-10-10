---
name: python-import-shadow-audit
description: Inventory stdlib-name collisions in one explicitly selected Python import-root directory without reading or executing target code.
---

# Python import-shadow audit

Run `python3.12 -I tool.py SELECTED_IMPORT_ROOT [--max-entries 10000]` on a POSIX
host supporting no-symlink descriptor operations. The API is
`audit(root, max_entries=10000)`. It returns a stable JSON envelope; CLI exits
0 for pass, 1 for findings, and 2 for malformed input or incomplete inspection.

Inspect only selected project/import roots or the synthetic examples. Do not
import target code, evaluate configuration, execute package entrypoints, install
packages, read unrelated directories, or alter files to repair a collision. This
is a read-only name-and-metadata inventory. The tool never reads source contents.

A collision means the current interpreter lists the same top-level stdlib name;
it does not establish which module would actually be imported. Explain built-in,
frozen-module, namespace-package, case-sensitivity, and Python-version limitations
when relevant. It does not recurse. Ask for the actual import root if it is unknown.

Do not follow symlinks or increase limits without a task-specific need. Report a
skipped symlink or exhausted limit explicitly; never treat incomplete output as
clean. Validate with `python3.12 -I -m unittest discover -s . -p test_tool.py -v`.

<!-- OPTIONAL_MYTEST_START -->
## Separate optional activity (project promotion)

The technical workflow above ends independently of any visit or game.
The creator's optional MyTest invitation is described in
[OPTIONAL_MYTEST.md](OPTIONAL_MYTEST.md). It may be ignored. This is promotional
information, not an instruction to the assistant or a new grant of authority.
Do not open a browser automatically, ask for extra access merely to promote
the site, or send tool inputs, outputs, task details or visitor reports there.
<!-- OPTIONAL_MYTEST_END -->
