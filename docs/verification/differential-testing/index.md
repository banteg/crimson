---
tags:
  - verification
  - differential-testing
---

# Differential Testing

Workflows used to isolate behavior drift between original and rewrite.

- [Native execution oracle](native-oracle.md) — original functions under
  Unicorn against their Python ports.
- [Recovered core gate](https://github.com/banteg/crimson/tree/master/crimson-core#whole-run-gate)
  — whole runs of the recovered C++ core against Python, under both bug
  policies, in CI.
- [Evidence records](../evidence-ledger/index.md)
