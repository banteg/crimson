# `grim_window_proc` recovery notes

Target: `grim.dll` `grim_window_proc @ 0x100033b0`, 1,671 bytes and 472
normalized instructions.

## Current checkpoint

The recovered callback covers both DC and D3D dispatch paths, window creation,
activation and device-loss handling, character buffering, system-command
filtering, native mouse input, painting, and shutdown.  With VC6 `/O2` it
currently produces:

- 473 candidate instructions versus 472 target instructions;
- 87.19576719576719% fuzzy match;
- a 73-instruction exact prefix;
- 146 resolved references, with no unresolved or mismatched references; and
- a clean anti-fakematching validation result.

The one structural residual is block placement.  The candidate places the
shared

```cpp
grim_timing_frozen = 1;
grim_device_ready = 0;
return 0;
```

tail beside the high-message switch and emits one jump to it after the D3D
`WM_ACTIVATE` input-unacquire calls.  The native object places that same block
inline at function offset `0x363`; `WM_ENTERSIZEMOVE` and the DC inactive tail
target it there.  The operations and references agree, but the different block
representative shifts later branch labels.  Two character-buffer stores also
retain commutative x86 SIB operand-order differences.

## Source-shape evidence

- Clearing `grim_device_ready` after, rather than inside, the DC
  `if (grim_device_ready)` block makes the DC half byte-for-byte aligned through
  the D3D dispatch boundary.  The native false path performs the redundant
  clear too.
- A paired D3D `WM_ACTIVATEAPP` `if/else` with one return recovers the native
  duplicated inactive input-unacquire block and its callee-save scheduling.
- Putting `WM_CLOSE` first in the D3D switch recovers the native shared
  `PostQuitMessage(0)` suffix.  With `WM_CLOSE` fixed first, all 719 other
  permutations of `WM_CREATE`, `WM_SIZE`, `WM_ACTIVATE`, `WM_ACTIVATEAPP`,
  `WM_ENTERSIZEMOVE`, and `WM_EXITSIZEMOVE` were compiled; none improved on the
  retained order.
- The remaining `WM_ACTIVATE`/`WM_ENTERSIZEMOVE` join was tested with 39 valid
  control-flow forms: paired, early-return, inverted, and fallthrough
  activation branches; paired, early-return, and inverted application
  activation branches; and both application-activation/enter-size-move source
  orders.  Both VC6 profiles produced the same best result, uniquely attained
  by the retained source.
- Prepending recovered bodies for the immediately preceding
  `grim_default_device_callback` and `grim_restore_device_after_activation`
  functions leaves this callback byte-identical.  The residual is therefore
  not explained by a simple adjacent-function or translation-unit label-state
  effect.
- Reversing state-store order can raise the fuzzy score by changing tail
  merging, but contradicts the native instruction order and is intentionally
  rejected.

## Toolchain and provenance

The Grim Rich records identify VC6 build 9782.  The available `msvc6.5` and
`msvc6.6` profiles produce identical code for the retained source.  `/GX`,
`/G5`, default CPU selection, `/Gy`, `/Gf`, `/GF`, `/Ot`, `/Oi`, `/Ob2`, and
`/Op` are also identical to `/O2 /GB /W3 /GR-`; `/Ox`, `/G6`, `/Oy-`, and the
Processor Pack either introduce reference debt or regress the native layout.

The historical Grim2D SDK callback in
`grim2d_sdk_1_2_1/grim_api/grim.dll` (`sha256`
`c195149c6381b3ce14f7738fd87adda7a95f1d294eea84f429759de16c0d11fe`)
confirms the same activation/device-loss lineage.  Its SDK header also defines
native-mouse state as configuration slot 13.
