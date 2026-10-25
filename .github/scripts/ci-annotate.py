#!/usr/bin/env python3
"""Report test and lint failures as GitHub Actions annotations.

    go test -json ./... 2>&1 | python3 .github/scripts/ci-annotate.py go-test
    cargo clippy --message-format=json ... 2>&1 | python3 .github/scripts/ci-annotate.py cargo sidecar-rs

Each mode prints the usual human-readable output, then turns every failure (a
failing Go test, a rustc or clippy diagnostic) into an error annotation, and
exits 1 if there was one. Annotations appear on the pull request's Checks page
and in the REST API, so a failure on a hosted runner -- above all the Windows
one, which a contributor may have no other way to reproduce -- can be read
without opening the raw job log.
"""

import json
import os
import re
import sys

MAX_ANNOTATIONS = 10  # GitHub keeps at most 10 error annotations per step
MAX_CHARS = 4000  # per annotation; the full text is in the job log

# "x_test.go:12: msg", "dir/x.go:3:7: msg", or a stack frame "D:/a/r/r/x_test.go:12 +0x1f"
GO_FILE_LINE = re.compile(r"((?:[A-Za-z]:)?[^\s:]+\.go):(\d+)(?::(\d+))?(?=[:\s]|$)")
GO_MARKERS = ("=== RUN", "=== PAUSE", "=== CONT", "=== NAME")


def escape_data(s):
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_prop(s):
    return escape_data(s).replace(":", "%3A").replace(",", "%2C")


def clip(text):
    if len(text) <= MAX_CHARS:
        return text
    head = MAX_CHARS // 3
    return text[:head] + "\n[...]\n" + text[-(MAX_CHARS - head) :]


def emit(failures):
    """Print one ::error command per failure: (title, message, file, line, col)."""
    if len(failures) > MAX_ANNOTATIONS:
        rest = failures[MAX_ANNOTATIONS - 1 :]
        names = "\n".join(f[0] for f in rest)
        failures = failures[: MAX_ANNOTATIONS - 1] + [
            ("%d more failures" % len(rest), names + "\n\nSee the job log.", None, None, None)
        ]
    for title, message, file, line, col in failures:
        props = []
        if file:
            props.append("file=" + escape_prop(file))
            if line:
                props.append("line=%d" % line)
                if col:
                    props.append("col=%d" % col)
        props.append("title=" + escape_prop(title))
        print("::error %s::%s" % (",".join(props), escape_data(clip(message))))


def repo_path(path, base=""):
    """A diagnostic's file as a repository-relative POSIX path, or None."""
    path = path.replace("\\", "/")
    workspace = os.environ.get("GITHUB_WORKSPACE", "").replace("\\", "/").rstrip("/")
    if workspace and path.lower().startswith(workspace.lower() + "/"):
        return path[len(workspace) + 1 :]
    if path.startswith("/") or re.match(r"^[A-Za-z]:/", path):
        return None
    return base.rstrip("/") + "/" + path if base else path


def go_module():
    try:
        with open("go.mod", encoding="utf-8") as f:
            for line in f:
                if line.startswith("module "):
                    return line.split()[1]
    except OSError:
        pass
    return ""


def go_test(_args):
    module = go_module()

    def pkg_dir(pkg):
        pkg = pkg.split(" ")[0]  # build events: "example.com/p [example.com/p.test]"
        return pkg[len(module) + 1 :] if pkg.startswith(module + "/") else ""

    output = {}  # (package, test) -> output lines
    failed = []  # (package, test) in the order they failed
    for raw in sys.stdin:
        try:
            ev = json.loads(raw)
        except ValueError:
            sys.stdout.write(raw)  # plain text, e.g. go vet or toolchain messages
            continue
        if not isinstance(ev, dict):
            sys.stdout.write(raw)
            continue
        key = (ev.get("Package") or ev.get("ImportPath") or "", ev.get("Test") or "")
        text = ev.get("Output")
        if text:
            sys.stdout.write(text)
            output.setdefault(key, []).append(text)
        action = ev.get("Action")
        # A package whose build failed is reported by its build-fail event.
        if action == "build-fail" or (action == "fail" and not ev.get("FailedBuild")):
            failed.append(key)
    sys.stdout.flush()

    tests = [k for k in failed if k[1]]
    failures = []
    for pkg, test in failed:
        if test and any(p == pkg and t.startswith(test + "/") for p, t in tests):
            continue  # the failing subtest carries the detail
        if not test and any(p == pkg for p, _ in tests):
            continue  # the failing tests carry the detail
        lines = [l for l in output.get((pkg, test), []) if not l.startswith(GO_MARKERS)]
        title = "FAIL %s%s" % (pkg_dir(pkg) or pkg, " " + test if test else "")
        file = line = col = None
        for m in GO_FILE_LINE.finditer("".join(lines)):
            name = m.group(1)
            # A bare file name is relative to the package; a stack frame's path
            # is absolute and maps only if it's under the workspace.
            file = repo_path(name, "" if "/" in name.replace("\\", "/") else pkg_dir(pkg))
            if file:
                line = int(m.group(2))
                col = int(m.group(3)) if m.group(3) else None
                break
        failures.append((title, "".join(lines).rstrip() or title, file, line, col))
    emit(failures)
    return 1 if failed else 0


def cargo(args):
    root = args[0] if args else ""  # the crate's directory within the repository
    failures, seen, stray = [], set(), []
    for raw in sys.stdin:
        try:
            msg = json.loads(raw)
        except ValueError:
            sys.stdout.write(raw)  # cargo's own progress and errors (stderr)
            if raw.startswith("error"):
                stray.append(raw.rstrip())
            continue
        if not isinstance(msg, dict) or msg.get("reason") != "compiler-message":
            continue
        d = msg.get("message") or {}
        rendered = d.get("rendered") or d.get("message") or ""
        span = next((s for s in d.get("spans") or [] if s.get("is_primary")), None)
        if span:
            spot = (span.get("file_name"), span.get("line_start"), span.get("column_start"), d.get("message"))
            if spot in seen:
                continue  # the same diagnostic from another target (bin, test)
            seen.add(spot)
        sys.stdout.write(rendered)
        if not span or not str(d.get("level", "")).startswith(("error", "warning")):
            continue  # notes, and summaries such as "aborting due to 2 previous errors"
        code = (d.get("code") or {}).get("code")
        title = "%s%s: %s" % (d.get("level"), " [%s]" % code if code else "", d.get("message"))
        file = repo_path(span.get("file_name") or "", root)
        failures.append((title, rendered.rstrip(), file, span.get("line_start"), span.get("column_start")))
    sys.stdout.flush()
    if not failures and stray:
        failures = [(s, s, None, None, None) for s in stray]
    emit(failures)
    return 1 if failures else 0


def main():
    for stream in (sys.stdin, sys.stdout):
        stream.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(line_buffering=True)  # stream the log as it arrives
    modes = {"go-test": go_test, "cargo": cargo}
    if len(sys.argv) < 2 or sys.argv[1] not in modes:
        sys.exit("usage: ci-annotate.py go-test | cargo [crate-dir]")
    sys.exit(modes[sys.argv[1]](sys.argv[2:]))


if __name__ == "__main__":
    main()
