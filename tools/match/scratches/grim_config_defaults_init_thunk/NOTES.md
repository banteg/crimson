# `grim_config_defaults_init_thunk`

Native target: `grim.dll` at `0x10001700` (5 bytes).

The exported wrapper performs only a tail transfer to
`grim_config_defaults_init`. VC6 `/O2 /GB` naturally emits the observed
five-byte jump for the void wrapper; no ABI shim or forced control flow is
required. The single normalized instruction and reference both match exactly
(`1/0/0`).
