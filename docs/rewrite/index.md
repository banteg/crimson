---
tags:
  - rewrite
---

# Rewrite

The Python + raylib implementation and the native Zig port reproduce Crimsonland
Classic v1.9.93. Both have live gameplay and deterministic replay tooling. Native
behavior is established from the executable and recovered source; passing port
regression tests alone does not establish parity with the original.

Start with [setup](../contributor/setup.md), [coverage and scope](status.md), or
[Zig build and tooling](zig-verifier.md).

## Architecture and contracts

- [Module map](module-map.md): package boundaries, screen ownership, and runtime components.
- [Deterministic session](deterministic-step-pipeline.md): live/replay tick order, input, and presentation.
- [Run startup](replay-run-start.md): shared initialization, native capture boundary, and terrain RNG.
- [Perks architecture](perks-architecture.md): explicit effect phases and ordering.
- [Rendering pipeline](rendering-pipeline.md) and [terrain](terrain.md): drawing and decal application.
- [Local multiplayer](local-multiplayer.md): the 3/4-player extension to native 1/2-player behavior.
- [Netplay](netplay.md): deferred scope and requirements for a replacement.

## Parity work

- [Original bugs](original-bugs.md): intentional fixes and `--preserve-bugs` behavior.
- [Float policy](float-parity-policy.md) and [precision map](float-expression-precision-map.md).
- [Trace contracts](trace-format-alignment.md) and [CDT format](cdt-trace-format.md).
- [Differential playbook](../frida/differential-playbook.md) and [evidence records](../verification/evidence-ledger/index.md).
- [RNG caller mapping](rng-caller-mapping-workflow.md).
