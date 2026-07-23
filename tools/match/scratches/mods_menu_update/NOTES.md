# `mods_menu_update`

Native target: `crimsonland.exe` at `0x0040e9a0` (2,607 bytes, 648
normalized instructions).

Live Binary Ninja disassembly and decompilation recover the complete native
Mods browser callback:

- a refresh-gated `mods\*.dll` enumeration with 31 usable rows and the native
  `+ more` sentinel in slot 31;
- parallel filename, display-name, and scrollbar-label tables;
- the selected plugin's title, version, author, filename, description, and API
  compatibility panel;
- launch gating on API version 3, plugin loading, and transition to the plugin
  runtime state;
- transposition of both players' eleven input bindings into the mod API key
  configuration, plus the pick-perk and reload bindings; and
- Main Menu and Escape behavior, both of which rearm the DLL scan.

The reconstructed source preserves the native two-stage vector expression.
Writing `position = position + offset` exposes the VC6 return temporary seen
in the opening x87 sequence. Keeping the three table accesses directly indexed
also reproduces the native enumeration loop; no register hints or alias tricks
are involved.

Current MSVC 6.5 `/O2 /GB` result:

```txt
match=83.06% prefix=0/648 target_insns=648 candidate_insns=645 refs=166/0/1
first_target=sub esp, 0x144
first_candidate=sub esp, 0x15c
```

The remaining differences are compiler lifetime and scheduling residue. The
native function reuses the ended `_finddata_t` metadata area for the later
16-byte version string and places a vector return temporary eight bytes later;
the natural candidate retains a frame 24 bytes larger. Its one audited
reference mismatch follows the static-scrollbar constructor's different
register scheduling: both sides still reference the independently mapped item
count and renderer globals. The source deliberately does not use unions,
volatile state, dead expressions, forced addresses, inline assembly, or fake
aliases to manufacture native local layout.

The function-local scrollbar, Main Menu button, Launch button, shared
constructor guard, and all three `atexit` cleanup thunks are mapped. Each
cleanup thunk is separately verified as the native one-byte `ret` function.
