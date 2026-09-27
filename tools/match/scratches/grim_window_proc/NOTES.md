# `grim_window_proc` recovery notes

## Byte-exact (2026-09-27)

The callback is now raw-byte exact. The last two differences were SIB
base/index swaps in the `WM_CHAR` terminator stores
`grim_key_char_buffer[*grim_key_char_buffer_count] = 0`: native encodes the
buffer as the base, and the earlier source encoded the count.

The cause is C2's commutative operand sort
([sib-operand-order.md](../../c2/compiler/sib-operand-order.md) §4). The
address is `grim_key_char_buffer + *grim_key_char_buffer_count`. The buffer is
a global leaf with hash `id << 5`. The count is a load through a global
pointer, whose hash keeps only the low byte of that pointer's own hash:
`((id << 5) & 0xff) << 8 | 7`. C2 numbers global symbols in first-reference
order, in 32-id chunks. With `WM_CHAR` directly after `WM_ACTIVATE`, the count
pointer is the 30th global (id 61), so its load outranks the buffer
(0xa007 against 0x07c0). Native needs three more globals referenced first, so
that the count pointer opens the next chunk (id 256, hash 0x0007).

`case WM_MOUSEMOVE:` placed before `case WM_CHAR:` supplies exactly those
three: the `grim_config_values[13]` test (one element record),
`grim_mouse_x_cached` and `grim_mouse_y_cached`. The sparse-switch layout does not depend on that case's
source position, so every other byte is unchanged. The append store keeps the
count as the base in both builds, because there the count is a CSE temporary
carried over from the capacity test.

## Plausibility pass (2026-09-27)

The quit path assigns both DC flags and then calls `PostQuitMessage(0)` instead of passing the chained assignment as the argument. Normalized exactness and all 148 references are unchanged; the two SIB byte differences were removed later by the case order above. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Target: `grim.dll` `grim_window_proc @ 0x100033b0`, 1,671 bytes and 472
normalized instructions.

## Exact checkpoint

The recovered callback matches all 472 normalized instructions with a
472-instruction prefix and 148 resolved references, with no unresolved or
mismatched references, under VC6 `/O2 /GB /W3 /GR-`.

With this promotion, the all-scope Grim dashboard is 1,154/1,154 functions and
288,391/288,391 manifest bytes exact, with zero fuzzy-gap debt.

The callback covers both DC and D3D dispatch paths, window creation, painting,
activation and device-loss handling, character buffering, system-command
filtering, native mouse input, and shutdown.

## Native source shape

- `PAINTSTRUCT` stays local to the `WM_PAINT` case; VC6 still assigns it the
  native stack home while emitting only the two Win32 calls and state writes.
- The D3D switch source order is `WM_CLOSE`, `WM_ENTERSIZEMOVE`,
  `WM_EXITSIZEMOVE`, `WM_CREATE`, `WM_SIZE`, `WM_ACTIVATEAPP`, then
  `WM_ACTIVATE`. That order recovers the native sparse-switch partitions and
  shared tails.
  `WM_MOUSEMOVE` then precedes `WM_CHAR`, which gives the `WM_CHAR` buffer
  stores native's SIB order (see above).
- D3D activation uses paired active/inactive branches. The inactive paths
  preserve the native device-loss, input-unacquire, timing, and readiness
  write order; the active paths preserve the native restore callback split.
- Both character-buffer paths use the published buffer and count directly.
  Backspace decrements the count before terminating; append writes the
  character, increments the count, then writes the new terminator.

## Final instruction diagnosis (superseded)

This section predates the byte-exact case order above. Before bounded SIB
canonicalization, the retained source was already at
99.79% with all 148 references proven. Its only raw-encoding difference was:

```text
target:    mov byte [edx+ecx*1], 0
candidate: mov byte [ecx+edx*1], 0
```

Both instructions compute the same DS address: with scale one, exchanging the
SIB base and index fields does not change `edx + ecx`. The matcher now
canonicalizes that architectural equivalence generally, only when both
registers are non-frame registers. EBP/ESP forms remain distinct because a
swap can change the default segment or be unencodable, and non-unit scales
remain distinct. This is not a function-specific exception.

Trying to force the native SIB field assignment in C++ was actively
misleading. A local-reference spelling changed the store to pointer-plus-index
form but rotated the live registers, lost one proven reference, and perturbed
the later mouse-coordinate coloring (`98.52%`, refs `147/0/0`). Helpers,
pointer-owner wrappers, volatile aliases, commuted expressions, scaled
identities, and translation-unit padding all fell into the same two allocation
states. The useful stopping rule was the instruction-level proof that the last
difference was architecturally interchangeable, not the collapsed score. The
sort trace later showed that the choice depends only on global symbol ids, and
that a plain case order fixes it.

## Toolchain and provenance

The Grim Rich records identify VC6 build 9782. The available `msvc6.3`,
`msvc6.4`, `msvc6.5`, and `msvc6.6` profiles emit the same retained callback
shape. Native diagnostic literals are separate pooled COMDAT data objects in
address order, matching `/O2`; `/Ox` flattens or aliases that data and creates
reference debt even when its instruction stream looks competitive, so it is
not retained.

The historical Grim2D SDK callback in
`grim2d_sdk_1_2_1/grim_api/grim.dll` (`sha256`
`c195149c6381b3ce14f7738fd87adda7a95f1d294eea84f429759de16c0d11fe`)
confirms the same activation/device-loss lineage. Its SDK header also defines
native-mouse state as configuration slot 13.
