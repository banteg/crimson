# Work status model

This page defines how we track maturity and evidence. The status reflects the
lifecycle of a feature from "we know it exists" to "we have reimplemented it
with 100% fidelity."

## Status lifecycle

Use these tags in the front matter (e.g., `tags: [status-analysis]`) and in
summary tables.

| # | Status | Tag | Meaning | Exit Criteria |
|---|--------|-----|---------|---------------|
| 1 | **Scoping** | `status-scoping` | Mapping. We know this feature/struct exists but haven't deep-dived. | High-level role identified; file/memory location known. |
| 2 | **Analysis** | `status-analysis` | Static. We are actively decompiling and mapping logic in Ghidra. | Logic flow understood; variables named; data tables extracted. |
| 3 | **Validation** | `status-validation` | Runtime. We are using Frida/WinDbg/logs to prove the static analysis is correct. | Runtime values captured; edge cases confirmed; unknowns resolved. |
| 4 | **Parity** | `status-parity` | Implementation. The feature is rewritten in Python and matches the original exactly. | Visuals and logic are indistinguishable from the reference. |

Example front matter:

```yaml
---
tags:
  - status-analysis
---
```

## Evidence tags

Use these inline to mark the source of truth for specific claims.

| Tag | Source | Usage |
|-----|--------|-------|
| `[static]` | Decompilation | "The code says X." (Ghidra, strings, data maps) |
| `[runtime]` | Instrumentation | "The debugger showed X." (Frida, WinDbg, logs) |
| `[python]` | Rewrite | "Our code implements X." (Source code, data tables) |
| `[parity]` | Verification | "Our output matches the original." (Side-by-side comparison) |

## Usage rules

- **Docs reflect the original**: Documentation pages describe the reference
  binary. Use `[static]` and `[runtime]` tags here.

- **Code reflects the docs**: The Python implementation should be derived from
  the documentation.

- **Promotion**: A page moves from Analysis to Validation when we stop guessing
  and start measuring. It moves to Parity only when the rewrite is complete and
  verified.

- **Reference pages**: Pages like worklog, sessions, and cheatsheets don't need
  a status tag — they're raw material, not feature documentation.

- **Regression**: If new evidence contradicts a claim, demote the tag/status
  accordingly.
