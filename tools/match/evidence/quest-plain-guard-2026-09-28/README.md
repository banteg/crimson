# Timeline dead store from a plain pointer comparison

The canonical `quest_spawn_timeline_update` remains **91.228070%**, 113/115
instructions, prefix 51, 13/0/0 references. No scratch source or compiler
setting changes here. This is diagnostic evidence, not a recovered match.

[witness.cpp](witness.cpp) compiles with the stock `msvc6.5` compiler to
**99.130435%**, 115/115 instructions, prefix 88, 13/0/0 references, and the
native 28-byte frame. It produces the exact native pointer/store sequence:

```asm
lea edi, dword [esi+0xc]
mov dword [esp+0x10], edi
mov dword [esp+0x10], ebx
```

The [complete native diff](native-diff.txt) has one differing instruction:

```diff
-fadd dword [esi+0x4]
+fadd dword [edi+-0x8]
```

These address the same field because `edi = esi + 12`, but the encoded body
is **not exact**. Moving the spawn counter outside the group loop and resetting
it at the group tail restores native's shared EBX zero and allocation. Keeping
the counter scoped inside the group gives the earlier 86.086957% witness body.

## A second plain-source route, with the correct pointer value

Inside the existing positive-count branch, the witness has this deliberately
redundant guard:

```cpp
int *template_id = &entry->template_id;
if (template_id != 0 && entry->count <= 0) return;
```

The actual spawn reads `entry->template_id` directly. No intervening call or
write can change the count, so the guard cannot return. It is an artificial
probe: there is no evidence that the original source contained this guard.
It uses no byte-copy loop, `memcpy`, volatile access, compiler intervention,
or assembly patch.

This corrects two earlier restrictions in
[qst-dead-store.md](../../c2/compiler/qst-dead-store.md): an opaque copy is not
necessary, and the dead store need not belong to a named class-4 local. The
new store belongs to an **unnamed class-3 comparison temporary**. A scan limited
to named dead definitions cannot exclude this mechanism elsewhere in the game.

The preserving trace follows this chain in the pinned witness:

| Boundary | Observed state |
|---|---|
| Merge #2 | Creates unsigned temporary `#326 = #295 - 8` for the pointer comparison |
| Address strength reduction | Rebuilds it as `#326 = #216`, where `#216 = entry + 12`; both have flag byte zero |
| Last DCE, callsite `0x10713683` | Keeps the copy and the comparison reading `#326` |
| Flow-graph rebuild, callsite `0x107136f2` | Removes the comparison; keeps the now-unused copy |
| `build_live_ranges` | `demote_unused_candidate_def` demotes `#326c3z4` into a memory store of `#216` |
| Allocation | That store shares the four-byte spread slot; its value use keeps the pointer in EDI |

Unlike Claude's [indexed-source route](../quest-history-sources-2026-09-28/README.md),
this does not require a flagged winning induction pointer. The read disappears
in flow-graph cleanup after DCE, rather than through late CSE of duplicate loads.

Static inspection also found that C2's `+0x32 & 3` test covers invariant-expression
bit 2 as well as IV bit 1 (`get_derived_iv`, `0x10753def`). However, loop cleanup
`0x10745b7e` clears invariant bits with `& 0xfff9`. The new witness does not use
that possible forwarding path: the stored copy and its source are unflagged.

## Controls and proof

[verify.py](verify.py) rebuilds eleven controls and optionally collects both
the loop-tail trace and the demotion trace. [results.json](results.json) records
the results, source hashes, transition tuples and preserving-trace receipts.

- Deleting the guard, reversing its operands, or using the named pointer for
  the actual template load removes the store pair.
- Using the field address directly in the guard, or testing `count == 0`,
  reproduces the 99.130435% body.
- The equivalent predicate `count < 1` changes the optimization and loses
  the pair. Equivalence of the predicate does not imply identical compiler IL.
- An ordinary live null check keeps a conditional branch instead of the dead
  store; it is not a match.
- Giving both coordinate additions a group-scoped y pointer makes the y load
  exact, but moves the heading load to `[esi+8]` instead of `[edi-4]`. That
  control is also 99.130435%, with prefix 82. Combining the two desired bases
  in plain source remains unresolved.

Both traces preserve the complete COFF apart from timestamps, reject missing
capture streams, and report `compiler_decisions_modified=false`. They produce
the same normalized COFF hash. These are stock builds, not patched compiler
results. The checker explicitly requires `body_byte_exact=false` for every
control, so these results cannot silently be reported as a solved function.

Additional temporary controls covered pointer lifetimes, scan-cursor reuse,
relative field accesses, loop forms, signed/unsigned address locals, vector
accessors and temporaries, heading copies, subobject views, and applying the
guard to the historical indexed sources. No canonical improvement was found.
The retained controls capture the mechanism and the two one-instruction
residuals, rather than claiming these families are exhausted.

## Reproduce and resume

```sh
UV_CACHE_DIR=/private/tmp/crimson-qst-uv uv run --no-sync python \
  tools/match/evidence/quest-plain-guard-2026-09-28/verify.py \
  --out /private/tmp/quest-plain-guard-proof --trace
```

Investigation is parked at the user's request while the executable is reorganized
into a plausible source tree based on the newly identified 23 translation units.
After those changes land, fetch and inspect them, rebuild the canonical function
in its new context, then rerun these controls before drawing conclusions from
the previous isolated-scratch compiler state.
