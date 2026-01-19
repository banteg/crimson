---
tags:
  - status-draft
---

# Work status model

This page defines how we track document maturity and how we mark evidence for
individual claims. The goal is to make "where we are" explicit and to clarify
what is backed by static analysis, runtime validation, or the Python reference
implementation.

## Page status ladder

Use these statuses in `docs/index.md` (and any doc header that includes a
status line).

| Status | Meaning | Exit criteria |
| --- | --- | --- |
| Planned | Topic is scoped but not yet documented. | We have a starter doc or tracking notes. |
| Tracking | Raw notes + pointers to evidence; structure is loose. | Core sections exist and at least some claims are tagged. |
| Draft | Structured doc with sections; gaps and TODOs called out. | Major sections filled and evidence tags used for key claims. |
| In progress | Actively validating; most claims tagged and gaps shrinking. | Remaining gaps are small or isolated; runtime/static coverage is solid. |
| Completed | Stable and validated; changes are incremental. | Key claims are tagged; open questions are resolved or explicitly deferred. |

## Zensical page tags

We mirror the status ladder into Zensical page tags (front matter `tags:`) so
status can be filtered in the site UI.

Tag names:

- `status-planned`
- `status-tracking`
- `status-draft`
- `status-in-progress`
- `status-completed`

Example front matter:

```
---
tags:
  - status-draft
---
```

## Evidence tags for claims

Use inline tags in bullets/paragraphs to mark the source of truth for each
claim. Combine tags when multiple kinds of evidence exist (e.g., `[static+runtime]`).

| Tag | Meaning | Typical sources |
| --- | --- | --- |
| `[hypothesis]` | Hypothesis / inferred (no direct evidence yet). | Educated guess, pattern matching. |
| `[static]` | Static confirmed. | Decompiled code, data maps, string refs. |
| `[runtime]` | Runtime verified. | Frida/Windbg traces, live logs, capture artifacts. |
| `[python]` | Python reference implementation. | `src/crimson/` builders, parsers, tables. |

### Suggested lock-in rules

These are guidelines for when a claim feels "locked in":

- Behavior claims: `[static+runtime]` (static + runtime).
- Data tables/ids: `[static+python]` (static + reference implementation).
- End-to-end reimplementation: `[python+runtime]` (Python output matches runtime capture).

## Usage pattern

Example claim list using tags:

- `[static]` `creature_spawn_template` assigns `template_id` to `creature_type_id`.
- `[runtime]` Quest builder 5.2 emits 132 entries in runtime capture.
- `[static+python]` Spawn ids mapped to creature names in `src/crimson/spawn_templates.py`.

## Notes

- Keep tags short and visible. Prefer `[static]`, `[runtime]`, `[python]` in-line over long prose.
- If a claim changes status, update the tag rather than rewriting the claim.
