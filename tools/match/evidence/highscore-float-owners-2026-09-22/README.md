# Highscore complete stock match

The canonical scratch has since replaced both `double` intermediates with
single-use `float` locals ([plain-float-sources.md](../../c2/compiler/plain-float-sources.md)).
A float centering local is exact when written as `128 - title_width / 2`; the
failed float control below used `128 - title_half_width`. This directory
records the 2026-09-22 witness.

`separator-double-center` reproduces the complete native
`highscore_screen_update` at `0x4423d0`: **2,004 instructions / 8,026 bytes**,
with both normalized exactness and relocation-aware encoded-body identity.
The independent proof covers the entire function without excluded ranges,
stack bindings, register substitutions, branch substitutions, or new aliases.
It resolves **648 positional references** and checks **241 literal branch
destinations**. The source is promoted to the canonical scratch.

- Source SHA: `2a80e0b92021ecdfa8fbf692791c7d42a5e3c4a48590fbf75e50093df574ba2f`
- Body SHA: `26caa07047c4ebfc2dffe0c669b87066bd241076f958ca1d92d89a2231f78014`
- Whole COFF SHA, clearing only its timestamp:
  `0c694ed3b350c1bc8d3dd050ebff87335e4374fbcf3c81c47cec96185e6e3751`
- Stock compiler: pinned `msvc6.5`, `/O2 /GB /W3 /GR-`.
- Matcher references: **639 / 0 / 0** (clean / unresolved / mismatched).

## The two final source controls

The [preceding state-owner witness](../highscore-state-owners-2026-09-22/README.md)
proved every byte except two float-store sequences. Two live `double`
intermediates recover those sequences while preserving the earlier regions.
These are source-level dataflow controls; the accepted build uses the
unmodified compiler and contains no inline assembly or dummy operations.

**Checkbox X snapshot.** The same loaded coordinate feeds the saved filter X
and widget X before loading widget Y:

```cpp
double x_value = right_panel.x;
filter_x = (float)x_value;
highscore_vec2_t widget_position((float)x_value, right_panel.y);
```

The frontend emits a float-to-double conversion and two narrowing uses.
By the `0xfcda` entry snapshot, C2 shares the narrowed value. At `0x374aa`
entry, it retains the native `FLD; FST filter_x; FSTP widget_x; FLD y`
dataflow. The scheduler interleaves the integer setup to match native bytes.

Changing only that intermediate to `float` removes the conversion. Both X
copies begin as floating loads/stores, but between the `0x30a40` and `0x336f4`
entry snapshots they become four integer MOVs. This bounds the lowering phase;
it does not identify one particular routine inside that interval.
Multiplication by one produces the same whole COFF as this float control.
Independent scalar reads, a projected vector temporary, and a vector offset
also fail to reproduce the required copy graph.

This first recovery independently proves **8,011 bytes**, leaving only the
15-byte separator reorder.

**Separator centering offset.** Its integer result is held as `double` before
the vector's float addition:

```cpp
double center_offset = 128 - title_half_width;
highscore_vec2_t separator(
    position.x + (float)center_offset,
    position.y + 14.0f);
```

The pre-scheduler list gains one `0x162` round marker after the offset's FILD.
It emits no extra machine instruction. C2's 81-node scheduling window now ends
at the Y FADD; the Y round marker moves into the following window before its
FSTP. That window initially exposes the interface load at priority 212,992
and the round marker at 163,840, instead of exposing the Y FSTP at 221,184.
Stock scheduling consequently emits the native interface load, height push,
and Y store in that order.

A separate diagnostic moves only the preceding witness's window endpoint
back one node. Its entire COFF equals the independently compiled stock
recovery after clearing timestamps. This explains the scheduling effect;
the instrumented diagnostic receives **no match credit**. The earlier
two-node endpoint change remains a negative control. A float centering local
also recovers the separator but loses 14 instructions elsewhere, so it is
retained as a failed whole-function control.

## Reproduction and limits

`controls.json` retains all ten new stock controls as hash-bound edits against
the preceding witness. `verify.py` rebuilds them, propagates ESP through every
path, and proves every encoded byte, positional reference, and literal branch
destination of the complete successful function. Five corruptions are
rejected, including altered destinations, an incorrect interface reference,
and promotion of the partial witness.

`verify_compiler.py` checks three preserving frontend capture/backend replay
pairs, rejects missing frontend streams, validates the float-width and window
evidence, and rejects deletion of the recovered round marker. It also replays
the separately marked endpoint diagnostic. Arena addresses are not compared
between compilations. The stock source and pinned compiler establish the
match; the source spelling is a reconstruction, not proof of the original
author's exact text.

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-float-owners-2026-09-22/verify.py \
  --out /tmp/highscore-float-owners-regions
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-float-owners-2026-09-22/verify_compiler.py \
  --out /tmp/highscore-float-owners-compiler
```

Use fresh output directories. The checked-in receipts bind the verification
inputs; raw frontend streams, objects, and snapshots are retained under the
chosen output directories.
