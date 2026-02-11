---
tags:
  - docs-hub
---

# Crimsonland documentation

A from-scratch rewrite of Crimsonland (2003), aiming for full parity with the
original Windows executable. These docs cover the game's mechanics, the rewrite
implementation, and the reverse engineering work that ties them together.

[Blog post](https://banteg.xyz/posts/crimsonland/) • [Source code](https://github.com/banteg/crimson)

## Play now

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
uvx crimsonland@latest
```

## Highlights

- [Perks](mechanics/perks.md): all 58 perks with exact numbers, interaction
  rules, and original bug notes verified against two builds of the binary.

## Sections

- [Mechanics](mechanics/index.md): how the game actually plays. Behavior
  specs, reference tables, and game rules written without decompiler details.
- [Rewrite](rewrite/index.md): the Python port. Architecture, module map,
  debug views, and parity status.
- [Reverse engineering](re/index.md): static analysis, runtime probes, struct
  layouts, and file formats extracted from the original binary.
- [Verification](verification/index.md): differential testing, evidence
  ledger, and parity matrices that connect claims to proof.
- [Contributor](contributor/index.md): setup, workflows, and project tracking.
