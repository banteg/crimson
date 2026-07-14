# console_register_cvar

Native target: `crimsonland.exe` at `0x00402350` (295 bytes).

The member first searches for an existing cvar. Existing entries release and
replace their owned string value, then refresh the cached float with the CRT
locale-aware conversion. New entries are appended to the singly linked list;
the empty-list and non-empty-list paths preserve the native allocation and
initialization order.

The recovered entry constructor also establishes the native split between the
ordinary name/value fields and the later mod-facing pointers. The resulting
source matches all 118 instructions, full prefix, with all twelve references
aligned.
