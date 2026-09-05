---
tags:
  - rewrite
---

# Netplay: deferred

The custom LAN, lockstep, rollback, and relay implementations were removed from
both ports on 2026-09-05. Their lobby screens, CLI commands, wire schemas, and
network-specific rendering/input adapters are also gone. Local 2–4 player co-op
and deterministic replay support remain.

The previous implementation did not establish complete state recovery. Python
rollback replayed old inputs without restoring the world; resync payloads in both
ports contained mode metadata rather than a recoverable deterministic session.
Controller and transport tests did not prove live multiplayer correctness.

A future design should start from the shared deterministic session and its
canonical inputs. Before adding transport or lobby UI, prove full state restore
and corrected-input resimulation, including RNG, pool allocation state, and
parity-affecting presentation effects. Retain input history independently of
emission and verify convergence after loss, delay, reordering, and reconnect.
Playback, recording, and presentation need explicit recovery boundaries so
resimulation cannot duplicate audio or persistence effects.

There is currently no supported network play command or server to run. The
removed implementation and its tests remain available in Git history.
