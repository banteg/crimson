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

## Evidence tags for claims

Use inline tags in bullets/paragraphs to mark the source of truth for each
claim. Combine tags when multiple kinds of evidence exist (e.g., `[SR]`).

| Tag | Meaning | Typical sources |
| --- | --- | --- |
| `[H]` | Hypothesis / inferred (no direct evidence yet). | Educated guess, pattern matching. |
| `[S]` | Static confirmed. | Decompiled code, data maps, string refs. |
| `[R]` | Runtime verified. | Frida/Windbg traces, live logs, capture artifacts. |
| `[P]` | Python reference implementation. | `src/crimson/` builders, parsers, tables. |

### Suggested lock-in rules

These are guidelines for when a claim feels "locked in":

- Behavior claims: `[S]` + `[R]` (static + runtime).
- Data tables/ids: `[S]` + `[P]` (static + reference implementation).
- End-to-end reimplementation: `[P]` + `[R]` (Python output matches runtime capture).

## Usage pattern

Example claim list using tags:

- `[S]` `creature_spawn_template` assigns `template_id` to `creature_type_id`.
- `[R]` Quest builder 5.2 emits 132 entries in runtime capture.
- `[SP]` Spawn ids mapped to creature names in `src/crimson/spawn_templates.py`.

## Notes

- Keep tags short and visible. Prefer `[S]`, `[R]`, `[P]` in-line over long prose.
- If a claim changes status, update the tag rather than rewriting the claim.
