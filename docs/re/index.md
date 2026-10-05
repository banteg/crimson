---
tags:
  - reverse-engineering
  - audience-analysis
---

# Reverse Engineering

Primary evidence and decompile-facing documentation for original binary behavior.

The matching decompilation of 1.9.93 is complete for game and engine code: all
858 functions come from [recovered source](https://github.com/banteg/crimson/tree/master/decomp)
that compiles to the original machine code. Progress for 1.9.93 and 1.9.8 is
tracked on [decomp.dev](https://decomp.dev/banteg/crimson).

## Subsections

- [Static](static/index.md) — decompiler findings and symbol/data analysis.
- [Formats](formats/index.md) — asset and file format reverse engineering.
- [Structs](structs/index.md) — pool/struct mapping and layouts.

## Related sections

- [Mechanics](../mechanics/index.md) for behavior specs.
- [Rewrite](../rewrite/index.md) for implementation details.
- [Verification](../verification/index.md) for parity claims and differential checks, including the
  native execution oracle that runs original code under Unicorn.
