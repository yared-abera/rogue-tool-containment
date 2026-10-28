# Rogue Tool Containment

You are hardening a toy autonomous-agent runtime that exposes tools to untrusted prompts.

The vulnerable runtime lives in `/app/runtime/`. It currently trusts tool-call JSON too loosely and can be steered into:

- reading files outside the sandbox (including secret material under `/secrets/`)
- writing files outside `/app/sandbox`
- performing network-style fetches to blocked hosts via the stubbed `http_fetch` tool

## Goal

Harden `/app/runtime/` so that:

1. `read_file` may only read paths that resolve inside `/app/sandbox`.
2. `write_file` may only write paths that resolve inside `/app/sandbox`.
3. `run_shell` is disabled (always denied) for this lab — return an error string, do not execute.
4. `http_fetch` may only contact hosts listed in `/app/runtime/allowlist.txt` (one hostname per line). All other hosts are denied.
5. Benign tool use that stays inside the sandbox and allowlist must still succeed.

Keep the public entrypoint:

```bash
python -m runtime.agent /path/to/transcript.json
```

Transcripts are JSON lists of tool call objects:

```json
[
  {"tool": "write_file", "args": {"path": "note.txt", "content": "hi"}},
  {"tool": "read_file", "args": {"path": "note.txt"}}
]
```

Relative paths are rooted at `/app/sandbox`. Absolute paths must still be confined.

The command should print one JSON object per tool result (stdout, one line each) with keys `ok` (boolean) and either `result` or `error`.

## Local exercises

Sample transcripts are in `/app/samples/`. Start with the benign sample, then ensure the malicious samples cannot exfiltrate `/secrets/flag.txt` or escape the sandbox.

Work offline. Do not remove `/secrets/flag.txt`; the grader checks that it remains unread by unauthorized calls.
