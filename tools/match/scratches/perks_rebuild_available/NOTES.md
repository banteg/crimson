# perks_rebuild_available

Native target: `crimsonland.exe` at `0x0042fc30` (181 bytes, 52
instructions).

The recovered stock MSVC 6.5 `/O2 /GB` source matches exactly:

```txt
match=100.00% prefix=52/52 target_insns=52 candidate_insns=52 refs=19/0/0
```

The function clears availability across the complete perk table, enables the
base perk range and four always-available full-version perks, publishes the
bounded quest unlocks, and clears Antiperk again at the end. Availability is a
byte-sized `perk_meta_t` field throughout.

## Quest-unlock loop ownership

The exact loop is owned by the logical quest index:

- cache `quest_unlock_index` and guard the zero-count case;
- iterate `index < unlock_count` with a `for` loop;
- guard `&quest_selected_meta[index].unlock_perk_id` against the fixed table
  end inside the body;
- read the unlock id directly from `quest_selected_meta[index]` and publish the
  corresponding perk-table availability byte.

VC6 strength-reduces the two direct quest-table expressions into the native
`EDX` cursor. The body increments the logical index in `ECX`, advances the
cursor by `sizeof(quest_meta_t)`, compares the index with the cached count, and
then performs the availability write. The taken count edge returns to the
pointer guard. This reproduces the complete native loop without an explicit
source-level cursor or register steering.

The earlier cursor-owned `do` loop was semantically equivalent but allowed VC6
to prove the first cursor value in range and rotate the pointer check to the
latch. It stopped at 96.15% with the same instruction count and resolved
references. The recorded loop-shape, boundary-identity, combined-condition,
and entry-boundary sweeps remain useful negative evidence for that explicit
cursor ownership; the direct indexed `for` form resolves their shared blind
spot.

## Port parity

The unconditional clear is behaviorally important. The Zig port previously
returned early when the quest unlock index was unchanged, allowing stale or
injected availability bits to survive. Native rebuilds on every call; the port
does the same and has a regression test that dirties the table at the cached
index before rebuilding.

## Exactness audit

Live Binary Ninja evidence accounts for the complete clear, base range,
always-available ids, bounded quest scan, byte writes, and final Antiperk
exclusion. Candidate and native each have 52 instructions and 181 bytes with
references `19/0/0`; their normalized instruction streams are identical.
