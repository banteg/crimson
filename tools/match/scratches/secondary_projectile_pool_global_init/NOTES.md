# `secondary_projectile_pool_global_init`

Native target: `crimsonland.exe` at `0x0041e460` (41 bytes).

The CRT initializer constructs all 64 entries in the 0x2c-byte secondary
projectile pool. Each entry starts inactive with rocket type, zero life and
trail timers, and an unused tail word at offset `0x28` set to `-100`.

Binary Ninja instruction evidence rules out a gameplay meaning for the tail
word in this executable. `fx_spawn_secondary_projectile` never rewrites it;
the secondary-projectile loop in `projectile_update` advances from `vel_y` by
the full 0x2c-byte stride without accessing `[esi+0x10]`; all three render
loops likewise stay within the fields through `type_id`; and session reset
only clears `active`. No instruction references the first field address at
`0x00495b00`. The Python and Zig ports therefore correctly omit this
constructor-only storage.
