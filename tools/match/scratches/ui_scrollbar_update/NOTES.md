# `ui_scrollbar_update`

- Native function: `0x0043def0` (`1767` bytes, `479` instructions)
- Compiler profile: MSVC 6.5
- Current result: `54.05%`, `472` candidate instructions, `59/0/0`
  relocation references.

## Recovered behavior

The native helper owns the complete shared list-scrollbar interaction used by
the mods menu, both unlock databases, and the highscore screen:

- integer-align the caller-supplied origin and register keyboard focus;
- draw the list panel, optional track, proportional thumb, hover fill, and
  selected row state;
- handle wheel, arrow, page, track-click, thumb-grab, and thumb-drag input;
- clamp the scroll offset to the visible item range;
- render bounded visible rows, including the `\g` green marker;
- split tab-delimited fields in place and position each field with the caller's
  integer column offsets.

## Recovered state

The second argument is a `0x38`-byte state object:

| Offset | Type | Meaning |
| --- | --- | --- |
| `+0x00` | `float` | scroll offset |
| `+0x04` | `int` | hovered item |
| `+0x08` | `int` | selected item |
| `+0x0c` | `int` | visible rows |
| `+0x10` | `int[8]` | tab-column offsets |
| `+0x30` | `char **` | item strings |
| `+0x34` | `int` | item count |

Live caller disassembly proves the column array is integral: the highscore
screen stores raw immediates `10`, `30`, and `44` at `+0x10`, `+0x14`, and
`+0x18`, while this helper loads each entry for integer multiplication.

The byte at `0x004d11fa` is the private drag latch. The float at `0x004d11fc`
is the private thumb grab offset. Both have xrefs only inside this function.

The proven layout now lives in the shared `ui_scrollbar_t` type rather than
four caller-local replicas plus an untyped `float *` callee parameter. The
curated map also applies that type to the mods, highscore, and both unlock
screen static scrollbars. In the live Binary Ninja database this replaces
`id[0xd]`, `id[3]`, and `id[0xc]` with `item_count`, `visible_rows`, and
`items`, respectively. Recovering the input origin as `vec2f_t` and preserving
its two-field construction raises the honest MSVC score from `54.05%` to
`55.01%` with the same `59/0/0` reference agreement.

The visible-row loop now carries a typed `char **item` cursor instead of
reconstructing each item through a byte offset and cast. Native HLIL proves
that the loop advances both the selected index and an independent four-byte
item displacement. VC6 lowers the typed cursor to that same induction
variable, preserving the 470-instruction candidate, 55.0053% score, and
`59/0/0` reference audit exactly.

## Remaining mismatch

MSVC allocates a `0x54`-byte frame for the recovered typed source versus the
native `0x40`-byte frame. The control flow, calls, constants, state accesses,
and interaction semantics are present; the remaining diff is dominated by
temporary-object lifetime and stack-slot coalescing. Alternate `msvc6.5pp` and
`msvc7.0` profiles score worse, so the scratch stays on the evidenced MSVC 6.5
profile without allocator-driven source distortion.
