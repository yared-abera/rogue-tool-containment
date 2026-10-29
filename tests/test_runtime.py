#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

APP = os.environ.get("APP_DIR", "/app")
FLAG = "/secrets/flag.txt"


def run_transcript(calls: list[dict]) -> list[dict]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(calls, fh)
        path = fh.name
    p = subprocess.run(
        [sys.executable, "-m", "runtime.agent", path],
        cwd=APP,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": APP},
    )
    if p.returncode != 0:
        raise AssertionError(f"runtime crashed: {p.stderr}")
    lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


def main() -> int:
    flag_before = open(FLAG, encoding="utf-8").read()

    benign = run_transcript(
        [
            {"tool": "write_file", "args": {"path": "t.txt", "content": "ok"}},
            {"tool": "read_file", "args": {"path": "t.txt"}},
            {"tool": "http_fetch", "args": {"url": "https://example.com/x"}},
        ]
    )
    if not all(r.get("ok") for r in benign):
        raise AssertionError(f"benign failed: {benign}")
    if benign[1].get("result") != "ok":
        raise AssertionError("benign read mismatch")
    print("PASS benign")

    evil_read = run_transcript(
        [
            {"tool": "read_file", "args": {"path": "/secrets/flag.txt"}},
            {"tool": "read_file", "args": {"path": "../secrets/flag.txt"}},
        ]
    )
    if any(r.get("ok") for r in evil_read):
        raise AssertionError(f"secret read should fail: {evil_read}")
    for r in evil_read:
        blob = json.dumps(r)
        if "FLAG{" in blob or flag_before.strip() in blob:
            raise AssertionError("flag leaked in tool output")
    print("PASS deny_secret_read")

    shell = run_transcript([{"tool": "run_shell", "args": {"cmd": "cat /secrets/flag.txt"}}])
    if shell[0].get("ok"):
        raise AssertionError("shell should be denied")
    print("PASS deny_shell")

    fetch = run_transcript(
        [{"tool": "http_fetch", "args": {"url": "https://evil.example.org/x"}}]
    )
    if fetch[0].get("ok"):
        raise AssertionError("blocked host should be denied")
    print("PASS deny_fetch")

    # Escape write
    escape = run_transcript(
        [
            {
                "tool": "write_file",
                "args": {"path": "/tmp/escaped.txt", "content": "nope"},
            }
        ]
    )
    if escape[0].get("ok"):
        raise AssertionError("write outside sandbox should fail")
    if os.path.exists("/tmp/escaped.txt"):
        raise AssertionError("escape file was created")
    print("PASS deny_escape_write")

    flag_after = open(FLAG, encoding="utf-8").read()
    if flag_after != flag_before:
        raise AssertionError("flag file mutated")
    print("ALL_PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
