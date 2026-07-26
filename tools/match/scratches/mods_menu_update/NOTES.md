# `mods_menu_update`

Native target: `crimsonland.exe` at `0x0040e9a0` (2,607 bytes, 648
normalized instructions).

Live Binary Ninja disassembly and decompilation recover the complete native
Mods browser callback:

- a refresh-gated `mods\*.dll` enumeration with 31 usable rows and the native
  `+ more` sentinel in slot 31;
- parallel filename, display-name, and scrollbar-label tables;
- the selected plugin's title, version, author, filename, and API
  compatibility panel;
- launch gating on API version 3, plugin loading, and transition to the plugin
  runtime state;
- transposition of both players' eleven input bindings into the mod API key
  configuration, plus the pick-perk and reload bindings; and
- Main Menu behavior, which rearms the DLL scan.

The reconstructed source preserves the native two-stage vector expression.
Writing `position = position + offset` exposes the VC6 return temporary seen
in the opening x87 sequence. Keeping the three table accesses directly indexed
also reproduces the native enumeration loop. The renderer used for the
scrollbar-label color is captured before the scrollbar fields are populated,
matching the native load at `0x0040ec74` and its use at `0x0040ecbc`.

Current MSVC 6.5 `/O2 /GB` result:

```txt
match=83.53% prefix=0/648 target_insns=648 candidate_insns=645 refs=168/0/0
first_target=sub esp, 0x144
first_candidate=sub esp, 0x15c
```

Recovery is semantic-complete. The remaining differences are compiler lifetime
and scheduling residue. The
native function reuses the ended `_finddata_t` metadata area for the later
16-byte version string and places a vector return temporary eight bytes later;
the natural candidate retains a frame 24 bytes larger. Capturing the renderer
at its recovered source lifetime removes the prior static-scrollbar scheduling
mismatch and reduces the fuzzy gap by 12.10 bytes. The source deliberately does
not use unions, volatile state, dead expressions, forced addresses, inline
assembly, or fake aliases to manufacture native local layout.

The function-local scrollbar, Main Menu button, Launch button, shared
constructor guard, and all three `atexit` cleanup thunks are mapped. Each
cleanup thunk is separately verified as the native one-byte `ret` function.

## Scrollbar column-initialization sweep (2026-07-26)

Live Binary Ninja localized one compact constructor mismatch at native
`0x0040ec34..0x0040ec61`. The native static-scrollbar guard zeroes
`column_offsets[0]` before `column_offsets[1]`, using a freshly cleared `ecx`;
the current object at function-relative `0x294..0x2bf` emits the two stores in
the opposite order and reuses the already-zero `edi`. This is downstream of
the documented frame-size divergence and independent of the previously
improved renderer capture.

The recorded one-site sweep in
`scrollbar-column-init-mutations.json` tested five ordinary C++ spellings:
separate integer and floating-point stores, both reverse-chain constant types,
and a zero-then-copy form. MSVC 6.5 canonicalized every single to the same
matcher result as the baseline: **83.53%**, 645 candidate instructions, prefix
0, `168/0/0` references, and exactly zero weighted-score delta. There were no
positive singles, so no interaction was eligible. The complete sweep is
recorded in `experiments.jsonl`; no source variant was applied.
