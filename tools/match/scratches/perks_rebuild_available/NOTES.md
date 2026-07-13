# perks_rebuild_available WIP

Current best local score:

```txt
match=73.08% prefix=9/52 target_insns=52 candidate_insns=52 refs=16/0/0
```

The recovered source preserves the native full-table clear, base perk range,
four always-available perks, bounded quest-unlock scan, byte-sized availability
writes, and final Antiperk exclusion. All 16 masked references resolve to the
intended ids, metadata fields, and quest table boundaries.

The unconditional clear is behaviorally important. The Zig port previously
returned early when the quest unlock index was unchanged, allowing stale or
injected availability bits to survive. Native rebuilds on every call; the port
now does the same, with a regression test that dirties the table at the cached
index before rebuilding.

The remaining mismatch is register allocation and loop layout. The candidate
loads the unlock count early and combines its initial test with the later quest
loop, while native initializes the quest index and tests the count after the
four always-available stores. Writing the decompiler's unrelated global loads
inside the base-range loop would only steer scheduling and is not plausible
source, so the clean WIP remains preferable.
