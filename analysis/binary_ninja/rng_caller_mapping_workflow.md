# RNG Caller Mapping Workflow

Goal: recover exact native `caller_static` values for Python RNG draw sites.

## Key Rule

`caller_static` is the return address after `call crt_rand`, not the function start and not the call instruction address.

For x86 PE code in Crimsonland:

- `call_addr` is the instruction that calls `crt_rand`
- `caller_static` is `call_addr + instruction_length`

## Trial Functions

Start with small ports where the Python draw structure still matches native closely.

Good first targets:

- `bonus_pick_random_type`
- `fx_queue_add_random`

Avoid large ownership-mixed functions first:

- `player_update`
- `projectile_update`
- `creature_spawn_template`

## BN Workflow

Use the stable target name from `bn target list`:

```bash
TARGET="crimsonland.exe.bndb"
```

Do not copy the numeric selector from a live session into docs; it changes between sessions.

1. Find the native function.

```bash
bn function search --target "$TARGET" bonus_pick_random_type
bn function info --target "$TARGET" bonus_pick_random_type
```

2. Confirm semantics in decompile/disassembly.

```bash
bn decompile --target "$TARGET" bonus_pick_random_type
bn disasm --target "$TARGET" bonus_pick_random_type
```

3. Enumerate `crt_rand` callsites with LLIL and compute exact `caller_static`.

```bash
bn py exec --target "$TARGET" --stdin <<'PY'
from binaryninja import LowLevelILOperation

CRT_RAND = 0x461746
name = "bonus_pick_random_type"
f = next(fn for fn in bv.functions if fn.symbol and fn.symbol.short_name == name)
rows = []
for block in f.low_level_il:
    for insn in block:
        if insn.operation != LowLevelILOperation.LLIL_CALL:
            continue
        dest = insn.dest
        if dest.operation != LowLevelILOperation.LLIL_CONST_PTR or dest.constant != CRT_RAND:
            continue
        info = bv.arch.get_instruction_info(bv.read(insn.address, 16), insn.address)
        rows.append((insn.address, insn.address + info.length))
print("\n".join(f"call={call:#x} caller_static={ret:#x}" for call, ret in rows))
PY
```

4. Open the Python port and map each draw site by semantics and order.

```bash
nl -ba src/crimson/bonuses/selection.py | sed -n '56,75p'
```

5. Record the mapping as a table before changing code.

Use:

- Python file and line
- native function
- native `call_addr`
- exact `caller_static`
- semantic meaning of the draw

## Trial Mapping: `bonus_pick_random_type`

Native function:

- `0x412470 bonus_pick_random_type`

Recovered callsites:

| Python | Meaning | Native call | `caller_static` |
| --- | --- | --- | --- |
| `src/crimson/bonuses/selection.py:60` | main roll `rand() % 162 + 1` | `0x4124a0` | `0x4124a5` |
| `src/crimson/bonuses/selection.py:70` | energizer branch `rand() & 0x3F` | `0x4124d1` | `0x4124d6` |

Why this is a good trial:

- only two draws
- branch structure is obvious
- Python port still mirrors native control flow closely

## Trial Mapping: `fx_queue_add_random`

Native function:

- `0x427740 fx_queue_add_random`

Recovered callsites:

| Python | Meaning | Native call | `caller_static` |
| --- | --- | --- | --- |
| `src/crimson/effects.py:532` | grayscale `rand() & 0xF` | `0x42775b` | `0x427760` |
| `src/crimson/effects.py:533` | width `rand() % 24 - 12` | `0x427789` | `0x42778e` |
| `src/crimson/effects.py:534` | rotation `rand() % 628` | `0x4277ab` | `0x4277b0` |
| `src/crimson/effects.py:535` | `effect_id` `rand() % 5 + 3` | `0x427806` | `0x42780b` |

Why this is a good second trial:

- multiple sequential draws
- draw meanings are explicit in both native and Python
- no helper ownership ambiguity inside the function

## Practical Rules

Only map exact callers when all of these are true:

- the Python code is the semantic owner of the draw
- the native function is identified confidently
- the Python draw order is still aligned with native
- the draw is not being delegated to a helper that should really be parent-owned

If ownership is split, fix ownership first, then map callers.

## Next Good Targets

- `weapon_pick_random_available`
- `perk_select_random`
- `bonus_try_spawn_on_kill`

These should be easier than:

- `player_fire_weapon`
- `player_update`
- `projectile_update`
