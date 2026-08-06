# grim_parental_lock_dialog_proc

`grim_parental_lock_dialog_proc` at `0x10001ad0` owns all three legacy
parental-lock dialogs: the status toggle, password setup, and password entry.
It updates the persisted violence flag, stores at most eight password bytes in
`grim_config_blob.player_name_buf`, and writes the complete config blob after
every successful state change.

The unlock comparison intentionally checks only the stored password length,
and the nine-byte password copy intentionally overwrites byte eight with NUL.
Those native behaviors are preserved directly. The natural MSVC 6.5
`/O2 /GB` reconstruction matches all 318 native instructions and all 66
references. This function remains `platform-replaced` for port ownership, but
its exact object is included in the recovered Grim platform provider.
