# Grim plausibility audit (2026-09-27)

This audit repeats the [exe plausibility audit](PLAUSIBILITY-AUDIT-2026-09-25.md)
for `grim.dll`. It read all 171 recovered sources under
`tools/native/recovered/grim`: 180 function bindings, which are the 139
port-scope functions plus the platform-replaced dialogs, window, device and
input code. It looked for constructs that only exist to steer the compiler and
tried plainer source for each one. A rewrite was kept only when normalized
instructions, relocation references and encoded body bytes all stayed
identical under the pinned `msvc6.5` `/O2 /GB` profile. 28 scratches were
rewritten.

As in the exe audit, vendored code was out of scope: the IJG libjpeg, libpng
and zlib reconstructions follow upstream spellings such as `register` locals,
`goto have_c0min` and `while (--n)`. The D3DX pixel-format, surface-guard and
vertex-converter leaves were also left alone; their explicit vtable installs
are a documented data-ownership choice, not a body shape.

The 2002 Grim2D SDK 1.2.1 header
(`artifacts/grim_20080214/site/grim2d_sdk_1_2_1.zip`) predates the game's Grim
build and has a different `grValue` layout. It served only as house-style
evidence: 10tons code uses pointer puns such as `*(int *)&f` and small vector
types with operators.

## Shapes C2 already produces from plain source

| Hand-written form | Plain source | C2 mechanism |
| --- | --- | --- |
| `while ((int)slot < (int)(&slots + 256))` with a `goto` | `for (i = 0; i < 256; i++) if (slots[i] == 0) return i;` | Strength reduction and linear test replacement, as in the exe audit. |
| Row and entry cursors anchored at a field, with `entry_v[-1]` | Row and column loops over a running `index` (`table[index].u`, `++index`) | `index` is a basic IV of both loops. The row pointer stays a separate IV stepped once per row, the entry pointer anchors at `.v` (the second field in IL order) and the outer test stays on `y`. A flat `y * n + column` index lets final-value analysis fold the row pointer into the entry pointer and moves the outer test onto it. |
| `a[0] = s; memcpy(&a[1], &a[0], 127 * sizeof(a[0]));` | `for (i = 0; i < 128; i++) a[i] = s;` | The idiom pass turns the struct fill into a peeled first store and an overlapping forward `rep movsd`. |
| Guarded `do`/`while` | `for` or `while`, with any outer condition as a plain `if` | Loop inversion adds the guard. |
| A `goto` into the default tail after a partial store | The whole assignment in both places | Cross-jumping in the second jump optimizer rebuilds the shared tail. |
| `do { ... break; ... } while (0)`, `goto succeeded` | Early returns, or nested `if`s that fall through to one `return` | Cross-jumping merges identical returns. A single fall-through return keeps one epilogue block instead of duplicated epilogues. |
| One `return false` shared by fall-through `case 0: case 1: case 2:` | One `return false` per case | Separate case bodies keep the `sub`/`dec` chain before cross-jumping merges them. Fall-through cases become a range check. |
| Split `double` accumulators for a 2D rotation | An inline `rotate(point, matrix)` that computes x into a local, then stores y and x, and an inline `translate(point, offset)` | Each helper evaluates the global write pointer once, which gives native's reload per helper. The y store blocks forward propagation of x, so x stays on the x87 stack. |
| `memcpy(dst, &vertex, sizeof(vertex))` | Struct assignment | Both lower to the same `rep movsd`. |
| A global cached in a local before a compare and update | Direct global access | The same loads, in the same order. |
| `(D3DSWAPEFFECT)((flag != 0) + 1)` | `flag ? D3DSWAPEFFECT_FLIP : D3DSWAPEFFECT_DISCARD` | If-conversion. |

Two lessons carry over from the exe audit. A named local anywhere in the body
shifts every inline-copy id by one, so x87 operand order can depend on an
unrelated local ([x87-scheduling.md](c2/compiler/x87-scheduling.md)). In
`grim_submit_vertices_transform_color` a natural `unsigned long *vertex` for
the color store gives native's `y*m1 + x*m0` order, and no spelling inside
the helpers can. Single-use float locals remain acceptable FROUND owners.

## Rewritten scratches

- **Loops:** `grim_find_free_texture_slot` (int-cast walk),
  `grim_get_key_char` (countdown cursor), `grim_state_init` (five cursor nests
  and the overlapping config fill), `grim_submit_vertices_offset` and
  `grim_submit_vertices_offset_color` (countdowns),
  `grim_draw_circle_outline` and `grim_decode_jaz_texture` (guarded
  `do`/`while`), `grim_run_loop` (guarded main loop, field-pointer decay).
- **Control flow:** `grim_decode_jaz_texture` (`do { } while (0)`),
  `grim_restore_device_after_activation` (`goto succeeded`/`failed`),
  `grim_set_config_var` (`goto copy_config_tail`, cached case-21 locals),
  `grim_zlib_status_is_error` (shared case body), `grim_d3d_init` (arithmetic
  select).
- **x87 temporaries:** `grim_submit_vertices_transform` and
  `grim_submit_vertices_transform_color` (inline rotate and translate
  helpers).
- **Copies and puns:** `grim_draw_circle_filled` and
  `grim_draw_circle_outline` (`memcpy` to struct assignment),
  `grim_draw_quad_points` (`float point[2]` pun to a `GrimPoint` local),
  `grim_draw_text_small` (`glyph * 2` float views to the `GrimUV[256]`
  table), `grim_try_reset_device`, `grim_restore_device_after_activation` and
  `grim_save_screenshot` (`&grim_present_parameters` instead of its first
  field), `grim_window_proc` (quit argument chain).
- **Cached globals:** `grim_create_texture`, `grim_destroy_texture`.
- **Declarations:** `grim_draw_fullscreen_quad` and four other users now
  declare `grim_backbuffer_width` and `grim_backbuffer_height` as
  `unsigned int`, which drops the `(float)(unsigned int)` casts. The four
  vertex submitters declare `grim_vertex_write_ptr` as `float *`.
- **Vtable methods:** `grim_get_time_ms`, `grim_get_frame_dt`,
  `grim_get_error_text`, `grim_get_mouse_wheel_delta` and `grim_get_mouse_x`
  were `extern "C"` functions. They are now `IGrim2D_cpp` methods like their
  siblings, and the vtable initializer names the method symbols.

Every rewrite is byte-exact. `grim_window_proc` became byte-exact in a
follow-up: `case WM_MOUSEMOVE:` placed before `case WM_CHAR:` gives its
`WM_CHAR` buffer stores native's SIB order, because C2 numbers globals by
first reference ([sib-operand-order.md](c2/compiler/sib-operand-order.md)
§4).

## Retained, with native evidence

- **Batch counter low word.** Native adds with `add word [grim_vertex_count], reg`
  and reads with `mov reg, dword [grim_vertex_count]; and reg, 0xffff`. An
  `unsigned short` variable, a 16-bit bitfield and a 32-bit variable all give
  other code, so the source had lvalues of two widths:
  `*(unsigned short *)&grim_vertex_count`.
- **Key and button bit 7.** Native shifts the byte (`shr al, 7`). Every
  expression form promotes to a 32-bit shift, so the byte local with
  `result >>= 7` stays.
- **`grim_path_has_extension`.** Native increments both indices after the
  first compare and returns the last compare without zero-extending, so the
  post-increments and the named `bool result` are original.
- **`grim_joystick_*_active`.** Native copies the deadzone and center globals
  into stack slots before the virtual call.
- **`grim_is_key_active` axis gotos.** Native keeps the shared
  `fmul`/`fabs`/`fcomp` return tail in the first (0x13f) arm. That arm's
  return must be the newest reference to the exit label
  ([aim-chain-mover.md](c2/compiler/aim-chain-mover.md)). Plain `if` chains,
  `else if` chains, a select-then-test join, an inline helper and descending
  order all keep the tail in the last arm (87.43%). A `switch` becomes a jump
  table.
- **`grim_mouse_poll` `goto reacquire`.** A classic error exit. Every loop
  restructuring either merges the success return into the preceding block
  (95.56% at best) or changes the loop.
- **`grim_draw_quad` and `grim_draw_quad_rotated_matrix` corner staging.**
  A `GrimPoint` array, or separate center and corner points, makes C2 align
  the frame (`and esp, -8`). Per-field copies make the float array
  register-promotable and change the x87 allocation. The per-lane `p = c;
  p += d;` statements and the single-use `neg_dx` pin operand order and keep
  native's `fchs`, because C2 folds `a + -b` into `fsub`. They read as the
  per-lane expansion of vector `operator+=`.
- **Config value views.** `*(float *)&value.words[0]` and byte views of bool
  slots spell the 16-byte config value. This is a data-model choice in 10tons'
  pun style, not an allocation trick.
- **Config dialog `*(unsigned int *)&bpp16 & 0xff`.** Native reloads the bool
  as a dword and masks it.
- **`grim_app_init` client rectangle.** Native stores a byte over `RECT.left`
  before copying the whole record.
- **`grim_noop` prototypes.** `grim_backup_textures` needs the fixed
  `(char *, int)` prototype for native's call cleanup. The fixed and variadic
  prototypes likely named different empty debug functions that the linker
  folded.
- **`grim_draw_text_small` `uv1_raw`.** It rounds the sum to float before the
  final subtract.

## Tooling

`scripts/c2/sort_trace.py` and `scripts/c2/xjump_trace.py` still called
`il_stage_trace.load_modules(False, None)` after its parameters were removed.
Both now call `load_modules()`.
