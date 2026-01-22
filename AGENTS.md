# Agents: decompilation project playbook

This repo supports **two agent personas** that collaborate to recover intent from
compiled binaries and turn it into reviewable, versioned artifacts.

The goal is repeatable progress: **static analysis is the source of truth**, and
**runtime evidence** is used to confirm or disambiguate what we see in Ghidra.

---

## Personas

### 1) `linux-ghidra` (static analyst)

**Environment:** Linux sandbox with Ghidra + headless automation.

**Best at:**

- Decompilation, callgraph reading, data-flow reasoning.
- Type recovery (struct layouts, vtables, calling conventions).
- Building and maintaining maps:
  - `analysis/ghidra/maps/name_map.json`
  - `analysis/ghidra/maps/data_map.json`
- Producing stable, reproducible exports under `analysis/ghidra/raw/` and
  `analysis/ghidra/derived/`.

**Constraints:**

- Cannot run the target game/process.
- Treat anything under `analysis/ghidra/raw/` as **read-only** (regenerate via
  scripts).

**Default workflow:**

1. Identify unknowns in decompilation (mystery functions, ambiguous globals,
   structs with unknown fields).
2. Turn unknowns into a **runtime wishlist** (exact addresses / symbol names,
   what to log, what triggers the code path).
3. When runtime evidence arrives, promote confirmed facts into the maps, rerun
   headless Ghidra, and update docs.

---

### 2) `windows-vm` (runtime investigator)

**Environment:** Windows VM (user-operated) that can run the target + tooling.

**Tools:** Frida + WinDbg/CDB (typically via the repo `justfile`).

**Best at:**

- Verifying hypotheses: “does this function run?”, “what arguments does it
  receive?”, “what is the real caller/callsite?”
- Capturing evidence logs (Frida JSONL, WinDbg log excerpts).
- Finding dynamic values that are painful statically (indirect calls, tables,
  runtime-only pointers, decoded state).

**Constraints:**

- The VM is not owned by the agent; **the user must start/attach privileged
  tooling** when needed.
- Runtime changes are not “truth” until promoted into the Ghidra maps.

**Default workflow:**

1. Receive a concrete wishlist from `linux-ghidra`.
2. Ask the user for the *minimum* set of actions (copy/paste blocks), capture
   logs, and store them under `analysis/frida/raw/` or as WinDbg session notes.
3. Reduce logs into machine-readable evidence and hand findings back to
   `linux-ghidra` for promotion.

---

## Collaboration contract (how we work)

### What “done” means

Any of the following is a valid “deliverable”, in descending order of value:

1. **Map updates** (preferred): new names/labels/types in
   `analysis/ghidra/maps/*` backed by evidence.
2. **Evidence artifacts**: Frida/WinDbg logs stored in the repo, plus a short
   summary explaining how they support a rename or struct claim.
3. **Docs updates** under `docs/` explaining behavior, formats, or recovered
   state machines.
4. **Hypotheses** (allowed): clearly marked, with a follow-up plan.

### Evidence rule

Prefer at least one of:

- A stable static xref chain (callers + data xrefs).
- A runtime capture (Frida hit, WinDbg stack + args + callsite).
- A file-format decode validated against real assets.

If evidence is weak, record it as a hypothesis and keep the rename conservative
(e.g. `maybe_*`, `sub_*` with a comment in docs).

### Small, reviewable steps

- Touch maps incrementally.
- Keep edits localized: one subsystem / struct / feature per change.
- Regenerate derived artifacts via scripts instead of hand-editing exports.

---

## Repo layout (where things go)

- `analysis/ghidra/`
  - `raw/` — exported artifacts (**regenerate; do not edit**)
  - `derived/` — script-generated derivatives
  - `maps/` — **source of truth** for names/data + WinAPI GDT
  - `scripts/` — custom Ghidra automation
- `analysis/frida/`
  - `raw/` — raw JSONL logs captured in the VM
  - `facts.jsonl` and `*_summary.*` — reduced evidence (generated)
- `scripts/` — reducers and tooling helpers
- `docs/` — human-facing notes (link to evidence + maps)
- `justfile` — repeatable command surface (Linux + Windows recipes)

---

## Standard operating procedures

### Static analysis loop (`linux-ghidra`)

1) Make the question precise

- “What is `FUN_0040f400`?” is too broad.
- “What are args/return semantics of `FUN_0040f400`, and who calls it?” is good.

2) Locate the “stability anchor”

- A constant table, a file format magic, a UI string, an import, a vtable.

3) Update maps conservatively

- Prefer semantic prefixes (`ui_`, `sfx_`, `paq_`, `jaz_`, `quest_`, etc.).
- For structs, name fields by *role* first (`count`, `flags`, `timer_ms`), then
  refine.

4) Re-run headless Ghidra when maps change

Typical:

```bash
just ghidra-exe
```

If Windows is the primary workspace and Ghidra runs in WSL, prefer:

```bash
just ghidra-sync
```

This runs `ghidra-exe` + `ghidra-grim` in WSL, syncs `analysis/ghidra/raw/` and
`analysis/ghidra/derived/` back to the Windows repo, and cleans WSL outputs so
future `git pull` stays clean.

5) Update docs when behavior is understood

- Put the *story* in `docs/` and keep maps as the structured index.

---

### Runtime evidence loop (`windows-vm`)

#### Frida

Use Frida as an evidence engine and save raw logs for reproducibility.

- Attach (by name) and write logs into the VM share.
- Copy logs into `analysis/frida/raw/`.
- Reduce to facts + summaries via `scripts/frida_reduce.py`.

See: `docs/frida-workflow.md` and `docs/cheatsheets/frida.md`.

#### WinDbg / CDB

The user starts the server; the agent connects as a client.

- User (server owner): `just windbg-server`
- Agent (client):

```text
just windbg-tail
just windbg-client
```

See: `docs/windbg.md`.

---

## “Wishlist” template (what the static analyst hands the runtime investigator)

Copy/paste this format so the VM session is efficient:

```text
Target:
  - Module: <exe/dll>
  - Address: <module+offset or absolute>

Goal:
  - Confirm: <what must be proven>

Break/Hook:
  - WinDbg bp: <command>
  - or Frida Interceptor target: <ptr>

When it triggers:
  - Capture: stack, regs, args, return value
  - Dump: <memory ranges / structs>
  - Record: callsite (return address) + backtrace

How to trigger:
  - Steps: <in-game actions>

Output:
  - Files: <expected logs + paths>
  - Notes: <what to paste back>
```

---

## “Promotion” checklist (turn evidence into maps)

When evidence arrives:

1. Summarize the finding in 3–6 bullets (what happened, why we believe it).
2. Update `analysis/ghidra/maps/name_map.json` and/or `data_map.json`.
3. Regenerate exports (`just ghidra-exe` / `just ghidra-grim`).
4. If docs are affected, add/adjust a page and link to:
   - function name(s)
   - global address(es)
   - evidence log(s)
5. If unsure, leave a TODO and keep naming conservative.

---

## Guardrails

- Prefer reproducible commands (`just …`, `uv run …`) over ad-hoc steps.
- Don’t “invent” semantics. If it’s a guess, label it as such and attach a plan
  to validate.
