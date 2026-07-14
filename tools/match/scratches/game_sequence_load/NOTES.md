# `game_sequence_load`

Exact 101-byte, 32-instruction match with MSVC 6.5 `/O2 /GB`; all seven masked
references align, including both Win32 imports, the registry path and value
name, `reg_read_dword_default`, and `game_sequence_id`.

The function opens/creates the machine-wide status key with `KEY_ALL_ACCESS`,
reads the `sequence` dword with fallback zero, and only raises the in-memory
sequence id when the persisted value is greater. It always closes a
successfully opened key and leaves state untouched if `RegCreateKeyExA` fails.
