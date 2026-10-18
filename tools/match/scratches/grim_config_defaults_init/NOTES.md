# `grim_config_defaults_init`

Native target: `grim.dll` at `0x10001710` (734 bytes); 1.9.8 at `0x10001700`
(704 bytes).

The native instruction stream is identical to the executable's
`config_init_defaults` after relocations are normalized, in both builds. Both
images compile one recovered body, `crimson_cfg_cpp_t::set_defaults()` in
`tools/match/include/crimson_config_defaults_impl.h`, against their own
`crimson_cfg_t` blob. Earlier cursor-shaped reconstructions are in git history.

## Why a member function

The body is the game's C++ reset of a config blob, inlined through `this`, like
`highscore_record_cpp_t::reset_light`. `this` stays opaque through loop
optimization, and that is what lets the plain indexed loop
`saved_name_order[i] = i; strcpy(saved_names[i], "default");` match:

- 1.9.93 (C2 8966): exact, 140/140, references 83/0/0, stock `/O2 /GB /W3 /GR-`.
  The same loop against the blob directly is 87%; the old exact form needed a
  byte order-offset cursor and a separately scheduled name cursor.
- 1.9.8 (C2 9044): native builds the strcpy delta as `mov esi, blob;
  sub esi, "default"` and adds `0xa8` later, keeps an order-slot pointer in
  `ebp` and a stack countdown. Only `this` reproduces that: a direct reference,
  a local pointer, a free `__inline`/`__forceinline` helper (pointer, reference,
  `void *` or `char *` parameter, cast argument), a byte or typed cursor, an
  `int` offset induction variable and a raw byte index all fold `blob + 0xa8`
  into one relocation first. A member called on a derived-type object (no cast)
  behaves like the cast call.

`config_sync_from_grim` confirms the routine in 1.9.8: its legacy blob shows the
same `this - "default" + 0xa8` delta, so 1.9.8 calls `set_defaults()` there.

## 1.9.8 status

msvc6.5pp: 86.61%, 127/127 instructions, references 78/0/0 (msvc6.5 63.70%).
The loop shape, countdown, delta chain and every store match; the residual is
register allocation. Native gives the delta `esi` and the inner source cursor
`eax` (the countdown reloads through `eax`); 9044 gives the delta `eax`, the
cursor `esi`, and therefore schedules the memset's last `al` store earlier.
`config_sync_from_grim` shows the mirror-image swap (delta/`i` in `edx`/`esi`).

Tried without effect on that allocation: for/while/do-while forms, `i != 8`,
`i <= 7`, unsigned `i`, block-scoped or for-scoped `i`, a member-local
`const char *` source, `&saved_names[i][0]`, `saved_names[0] + i * 27`,
`saved_names[saved_name_order[i] = i]`, an inline member taking the slot,
a separate loop member, a `count` or name parameter, reference/static/
reinterpret casts, the 9-byte name clear at every prologue position, and an
explicit `n` countdown with an order pointer (any init or increment order). A
user order pointer (`*order++ = i`) restores the native allocation but replaces
the countdown with `cmp edi, 8` (93.98%), so it is not retained. The previous
non-member best (94.07%, an `n` countdown with the delta folded) is superseded
because it cannot produce the native delta.

## Guard

`ui_info_texts`: 1.9.8 stores it from the shared integer-one register (`bl`),
1.9.93 as an immediate. 8966 needs `memset(&ui_info_texts, 1, 1)`; 9044 needs
the plain store. `= true`, `= (unsigned char)1`, `*(unsigned char *)&... = 1`
and `*(&...) = 1` all behave like the plain store under 8966 (78.45%). The
header keeps a commented code-generation-only `CL_BUILD == 10908` guard.

## Not landed (2026-10-16)

The `ui_info_texts = 1` 1.9.8 spelling above is not in the source: guards land only when every build they claim compiles exactly, and this body still differs in register allocation under 9044.

## 1.9.8 match (2026-10-19)

Both builds match: 1.9.93 stays exact; 1.9.8 is 127/127 with references
84/0/0 and one encoded byte left, the SIB of the default-name copy store
(native `[eax+esi]`, 9044 `[esi+eax]`; see
`../highscore_sync_worker/NOTES.md`). The register swap came from colouring
priority (`scripts/c2/priority_trace.py --build 1.9.8`): the 16-bit arrow-flag
store `*(unsigned short *)direction_arrow_flags = 0x101` shared its immediate
with `key_pick_perk = 0x101`, adding a candidate range to block 1 and raising
the delta's priority above the source cursor's. `memset(direction_arrow_flags,
1, 2)` emits the same `mov word` with a different immediate, so the cursor
colours `eax` first. The defaults also move `detail_preset`, the POV angles,
the reserved word and the screen size to config_sync_from_grim's store order,
and a guard stores `ui_info_texts` directly under 1.9.8.
