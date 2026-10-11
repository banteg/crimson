---
tags:
  - rewrite
---

# Rewrite

The Python + raylib implementation reproduces Crimsonland Classic v1.9.93, with
live gameplay and deterministic replay tooling. The recovered core
(`crimson-core/`) compiles the recovered C/C++ into a native executable and a
WASM module; it verifies replays and agrees with Python under both bug policies.
Native behavior is established from the executable and recovered source;
passing port regression tests alone does not establish parity with the original.

Start with [setup](../contributor/setup.md), [coverage and scope](status.md), or the
[feature matrix](feature-matrix.md) of the Python port and the web and native clients.

Python remains the reference port and the fast iteration platform. The core
also builds the whole recovered game, which plays the original natively and
[in the browser](https://crimson.land/play/), held to the verifier on every gate
stream; the Python port and both clients play ranked runs. The core and its
staged gates are documented in `crimson-core/README.md` and
`crimson-core/ROADMAP.md`, the clients in `crimson-core/PORT.md`.

Pages under Architecture and Modules describe how the port is built, Contracts
the rules a change must keep (tick order, timing, replays, ranked play, traces,
float precision), and Parity what differs from the original and why.
