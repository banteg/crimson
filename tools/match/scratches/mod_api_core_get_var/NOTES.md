# mod_api_core_get_var

Native target: `crimsonland.exe` at `0x40e040` (59 bytes).

The method finds a console cvar or creates it with default string `"1"`, then
publishes the cvar's embedded three-pointer SDK view at offset `0x18`.
`floatValue` is assigned first, followed by `id` and `stringValue`; the method
returns the address of that embedded view. The recovered field layout and
assignment order match all 21 instructions and all 5 references exactly.
