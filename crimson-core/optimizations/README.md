# Behavior-preserving optimizations

These diffs change generated copies, leaving `decomp/` as the matching source
of truth. They apply to the verifier and game under both bug policies. Unlike
`patches/`, they must preserve all gameplay state and random-number draws.

`survival-spawn-batch.patch` resumes allocation from the previous slot within
Survival's wave loop. Only this batch has the guarantee that no occupied slot
becomes free. The cursor is local to `survival_update`; other allocator callers
search from zero. Full-pool attempts retain logging and overflow-slot writes.
See [original bug 37](../../docs/rewrite/original-bugs.md#37-survival-spawning-grows-without-bound-after-fifteen-minutes)
and the [profile](../../docs/verification/survival-spawn-profile.md).

Run `uv run python crimson-core/checks/spawn_batch.py` to compare 640 batches
against the same recovered bodies without optimization. To also confirm the
original game's late-time spawn counts through Unicorn:

```sh
uv run python crimson-core/checks/spawn_batch.py \
  --exe game_bins/crimsonland/1.9.93-gog/crimsonland.exe
```

CI runs both checks.
