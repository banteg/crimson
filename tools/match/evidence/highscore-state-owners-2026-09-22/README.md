# Highscore state ownership and scheduling

The stock `stage-reference` witness reproduces **7,980 of 8,026 native bytes**
in three explicitly bounded regions. The remaining 46 bytes are two float-store
sequences. The proof resolves each positional reference, compares every other
encoded byte, and checks literal branch destinations against the full function.
It permits no stack bindings, register substitutions, or added reference aliases.
Both full-function exactness flags remain false; canonical source/configuration
and **804/810** coverage are unchanged.

The source SHA is
`2ebc0af90c8ff218d7db9bc0a5a85e5b2ebb73af243f56dd93060632aa5958f3`;
the body SHA is
`7f3ffe1db59c43703b5334dfca8bd192e0335f8b68ea58f09597d42b771d6134`.
The witness has 2,004 instructions, prefix 108, and references 639/0/0.
Its 99.750499% alignment is not the acceptance criterion.

## Recovered state and status code

The [preceding witness](../highscore-quest-ordering-2026-09-22/README.md)
already recovered the row and quest gate. These controls recover the saved-state
block, surrounding right-panel setup, the complete filter setup, a shared status
tail, and two batch-stage stores while preserving the earlier regions.

- Reversing the source order of the saved quest-index copies changes which
  symbols occupy the first and second loads. Their encoded body stays identical,
  so a body hash alone cannot distinguish the controls.
- Reading the saved game mode first into a local reproduces the required
  register lifetimes but changes other code. Publishing the value through the
  existing configuration field before the quest copies avoids that extra local.
  Putting the overlay assignment before it also recovers native write order.
- Moving the seven identical `Sleep(10)` source calls to one common status tail
  changes exactly the remaining native branch destination. C2 still emits the
  duplicated calls visible in the original binary.
- Making `stage` a reference to the saved stage index removes the separate
  local/global constant stores. The two native stores then use the stage
  register ECX. Merely replacing the global's zero literal with the separate
  local value is whole-COFF neutral and leaves EBP in those stores. Directly
  spelling the global everywhere recovers the local pattern but changes the row.

Preserving C2 traces distinguish register allocation from final ordering.
Before `0x336f4`, the saved-mode value already owns EAX; the copy temporaries
are unallocated. After that pass, the old source assigns minor/major/hardcore
to EDX/EAX/ECX. The new source assigns them to ECX/EDX/EDX. The instruction list
still follows source order at entry to `0x374aa`. That later scheduler produces
the native load/store order, including the minor store before the major store
and the overlay store before the configuration-mode store.

`verify_execution.py` compares native, stock, and an independent oracle on
9,216 saved-state fixtures, including every hardcore byte and signed mode/index
extremes. It checks all seven ordered writes, final output bytes, ESP, and saved
registers. Four corruptions are rejected, including a store-order change whose
final output values are otherwise identical. This is a straight-line state
proof, not complete UI execution or a claim that every bit pattern is reachable.

## Two distinct float residuals

Offsets below are relative to native `highscore_screen_update` at `0x4423d0`.
The candidate has the same offsets outside these ranges.

| Excluded range | Native sequence | Current stock sequence |
| --- | --- | --- |
| `0x1d8..0x1e7` (15 bytes) | interface load, height push, separator-Y store | Y store, interface load, height push |
| `0xf2f..0xf4e` (31 bytes) | save filter X, save widget X, then load/store Y, interleaved with setup | save widget X, load/store Y, then save filter X |

The scheduler graph explains why these need different controls:

**Separator.** C2 `0x37a43` stops a scheduling window after 81 IR nodes
(`i <= 0x50`). The observed first window has 81 nodes plus two graph sentinels
and ends at the separator-Y `0x162` marker. Its store starts the next window.
After `0x3a684` computes priorities, that FSTP has depth 19 / priority 221,184;
the interface load has depth 18 / priority 212,992. There is no dependency
requiring the store before that interface load. The graph does require the
store before the following FILD and vtable load.

A separate diagnostic moves only this window endpoint back two nodes, so the
Y addition enters the next window. It moves the interface load and first push
to their native positions, but now delays the store past the width-slot push
and address calculation. Prefix 110 is therefore another negative control,
not a recovered separator. No installed compiler is modified, and no diagnostic
receives match credit.

**Online checkbox.** The graph has an ordered dependency chain from the widget-X
FST through the Y load/round/store to the filter-X FSTP. Reprioritizing ready
instructions cannot reverse that chain. The source must change the ownership
or copy graph. Moving the snapshot earlier, including through a widening cast
or a constructor output reference, turns the copies into integer moves and
changes stack placement. Separately assigning the constructed vector also
changes earlier code. These are retained negative controls.

The separator member-assignment control changes scheduling earlier than the
residual. Applying its Y offset after construction is whole-COFF neutral.
Do not repeat these forms as unexplored fixes. A useful next control must
preserve the established register and stack ownership while changing the
relevant scheduling window or floating-copy dependencies.

## Validation and replay

`verify.py` rebuilds all 16 stock controls, propagates ESP through every path,
and checks 1,993 instructions / 7,980 bytes outside the two excluded ranges.
Five corruptions are rejected, including an attempted full-function claim.
The rest of the function may branch across a region boundary: its encoded
branch and actual destination must still equal native. Excluding a range does
not establish the semantics of the complete function.

`verify_compiler.py` uses pinned C2
`d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`
with three preserving captures/replays. Each checks whole COFF identity except
timestamp and rejects missing frontend streams. Graph nodes are identified
within each trace, then recorded by ordinal; arena addresses are not compared
across compilations. Two graph corruptions and the separate boundary diagnostic
are checked. Raw streams, objects, and snapshots remain in the output directory;
the checked-in receipts bind their inputs and hashes.

From the repository root, use fresh output directories:

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-state-owners-2026-09-22/verify.py \
  --out /tmp/highscore-state-owners-regions
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-state-owners-2026-09-22/verify_compiler.py \
  --out /tmp/highscore-state-owners-compiler
uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/highscore-state-owners-2026-09-22/verify_execution.py \
  --out /tmp/highscore-state-owners-execution
```
