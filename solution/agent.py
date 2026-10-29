"""Hardened runtime with path confinement and tool policy."""

from __future__ import annotations

import json
import os
import sys
import urllib.parse


SANDBOX = "/app/sandbox"
ALLOWLIST_PATH = "/app/runtime/allowlist.txt"


def load_allowlist() -> set[str]:
    if not os.path.exists(ALLOWLIST_PATH):
        return set()
    with open(ALLOWLIST_PATH, encoding="utf-8") as fh:
        return {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}


def confined_path(path: str) -> str:
    if os.path.isabs(path):
        candidate = path
    else:
        candidate = os.path.join(SANDBOX, path)
    # Normalize and reject escapes.
    real_sandbox = os.path.realpath(SANDBOX)
    real_candidate = os.path.realpath(candidate)
    try:
        common = os.path.commonpath([real_sandbox, real_candidate])
    except ValueError as exc:
        raise PermissionError("path escapes sandbox") from exc
    if common != real_sandbox:
        raise PermissionError("path escapes sandbox")
    return real_candidate


def tool_read_file(args: dict) -> str:
    p = confined_path(args["path"])
    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def tool_write_file(args: dict) -> str:
    p = confined_path(args["path"])
    parent = os.path.dirname(p)
    os.makedirs(parent, exist_ok=True)
    # Re-check parent still inside sandbox after makedirs.
    confined_path(parent)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(args.get("content", ""))
    return "wrote"


def tool_run_shell(args: dict) -> str:
    raise PermissionError("run_shell is disabled")


def tool_http_fetch(args: dict) -> str:
    url = args.get("url", "")
    host = urllib.parse.urlparse(url).hostname or ""
    allow = load_allowlist()
    if host not in allow:
        raise PermissionError(f"host not allowlisted: {host}")
    return json.dumps({"fetched": url, "host": host})


TOOLS = {
    "read_file": tool_read_file,
    "write_file": tool_write_file,
    "run_shell": tool_run_shell,
    "http_fetch": tool_http_fetch,
}


def run_transcript(path: str) -> None:
    with open(path, encoding="utf-8") as fh:
        calls = json.load(fh)
    for call in calls:
        name = call.get("tool")
        args = call.get("args") or {}
        fn = TOOLS.get(name)
        if fn is None:
            print(json.dumps({"ok": False, "error": f"unknown tool {name}"}))
            continue
        try:
            result = fn(args)
            print(json.dumps({"ok": True, "result": result}))
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"ok": False, "error": str(exc)}))


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("usage: python -m runtime.agent <transcript.json>", file=sys.stderr)
        return 2
    run_transcript(args[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
