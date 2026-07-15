# `perk_prompt_update_and_render`

Native target: `crimsonland.exe` at `0x00403550` (378 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 93/93
normalized instructions, full prefix, and masked references `35/0/0`.

Live Binary Ninja shows that the prompt is suppressed in demo and Rush modes.
Its timer eases toward 200 ms while gameplay has a pending perk and back toward
zero otherwise. When informational text is enabled, the timer controls the
prompt alpha and right-aligned label. The same timer rotates the prompt element
through a quarter turn before the element is rendered.

The phase local is assigned as the ordinary `cos` argument. VC6 therefore
stores that value for the later `sin` while evaluating cosine from the live x87
value, reproducing the native schedule without an artificial spill. No inline
assembly, volatile state, dummy references, or dead expressions are used.
