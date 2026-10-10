#!/usr/bin/env python3
"""Inventory immediate import-root names that collide with this Python's stdlib."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

TOOL = "python-import-shadow-audit"


class InputError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid command arguments")


def result(findings=None, summary=None, error=None):
    findings = findings or []
    return {"schema_version": 1, "tool": TOOL,
            "status": "error" if error else "findings" if findings else "pass",
            "summary": summary or {}, "findings": findings,
            "errors": [{"code": "bad_input", "message": error}] if error else []}


def selected_absolute(path):
    """Reject parent traversal before normalization can hide symlink components."""
    raw = Path(os.fspath(path))
    if ".." in raw.parts:
        raise InputError("Selected paths must not contain parent (..) components")
    return Path(os.path.abspath(raw))


def open_directory(path):
    """Open each directory component without following any symlink (POSIX)."""
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise InputError("This tool requires POSIX O_NOFOLLOW and dir_fd support")
    absolute = selected_absolute(path)
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _audit(root, max_entries):
    if type(max_entries) is not int or not 1 <= max_entries <= 100000:
        raise InputError("max_entries must be an integer from 1 to 100000")
    fd = open_directory(root)
    findings = []
    try:
        before = os.fstat(fd)
        entries = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                if len(entries) >= max_entries:
                    raise InputError("Import root exceeds max_entries; no partial pass is reported")
                entries.append(entry.name)
        for name in sorted(entries):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                findings.append({"code": "symlink_not_followed", "path": name})
                continue
            candidate, kind = None, None
            if stat.S_ISREG(info.st_mode) and name.endswith(".py"):
                candidate, kind = name[:-3], "python_file"
            elif stat.S_ISDIR(info.st_mode) and name in sys.stdlib_module_names:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    try:
                        init = os.stat("__init__.py", dir_fd=child, follow_symlinks=False)
                    except FileNotFoundError:
                        init = None
                    if init and stat.S_ISLNK(init.st_mode):
                        findings.append({"code": "symlink_not_followed", "path": name + "/__init__.py"})
                        continue
                    candidate = name
                    kind = "regular_package" if init and stat.S_ISREG(init.st_mode) else "namespace_directory"
                finally:
                    os.close(child)
            if candidate in sys.stdlib_module_names:
                findings.append({"code": "stdlib_name_collision", "path": name,
                                 "module": candidate, "kind": kind,
                                 "builtin": candidate in sys.builtin_module_names})
        after = os.fstat(fd)
        if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
            raise InputError("Import root changed during inspection; rerun on a stable directory")
        return result(findings, {"entries_checked": len(entries),
                                "python_version": ".".join(map(str, sys.version_info[:3])),
                                "stdlib_names": len(sys.stdlib_module_names),
                                "scope": "immediate_children"})
    finally:
        os.close(fd)


def audit(root, *, max_entries=10000):
    """Return a JSON-serializable result; never read/import target source files."""
    try:
        return _audit(root, max_entries)
    except InputError as exc:
        return result(error=str(exc))
    except (OSError, TypeError, ValueError):
        return result(error="Cannot inspect the selected directory safely")


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("root", help="Explicitly selected import-root directory (no recursion)")
    parser.add_argument("--max-entries", type=int, default=10000)
    try:
        args = parser.parse_args(argv)
        outcome = audit(args.root, max_entries=args.max_entries)
    except InputError as exc:
        outcome = result(error=str(exc))
    print(json.dumps(outcome, sort_keys=True, ensure_ascii=True))
    return {"pass": 0, "findings": 1, "error": 2}[outcome["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
