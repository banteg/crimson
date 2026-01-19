# WinDbg / CDB workflow

## Remote server setup (works reliably)

Server (run once, long-lived):

```
cdb -server tcp:port=5005,password=secret -pn crimsonland.exe
```

Client (reconnect as needed):

```
cdb -remote tcp:server=127.0.0.1,port=5005,password=secret -bonc
```

Notes:
- `-bonc` breaks on connect, so you must `g` after attaching.

## Sessions

### Session 1 (2026-01-18) - credits secret

#### Wishlist

Yes, WinDbg is a great way to recover the "missing pointer" when Ghidra's call graph
does not show a direct xref. You can catch the function at runtime, inspect who called
it, and see where the board pointer lives.

Here is a practical workflow (32-bit game):

1) Attach and break on the function

```
lm m crimsonland
bp <base>+0x40f400
g
```

- Use the module base from lm in case the image is not fixed at 0x00400000.

2) Trigger the suspected minigame
When the breakpoint hits:

```
k
r
dd @esp L10
```

- k shows the call stack.
- The return address is at [@esp]. You can disassemble the callsite:

```
ln poi(@esp)
u poi(@esp) L20
```

3) Inspect the arguments (board pointer + outputs)
The signature looks like: FUN_0040f400(int *board, int *out_idx, char *out_dir)

```
dd @esp+4 L3      ; args
dd poi(@esp+4) L36 ; dump 6x6 board (36 ints)
```

4) If the breakpoint never hits, hunt the pointer table
Search memory for the function address and break on reads:

```
s -d <base> L? 0040f400
ba r4 <addr>
g
```

When a read break triggers, check k and disassemble around @eip to see who is using the pointer.

Why this helps

- It gives you the actual callsite (even if indirect).
- It shows the board memory layout and who populates it.
- You can map the caller in name_map.json with real evidence.

If you want, I can translate the WinDbg outputs into specific name-map updates once you capture a hit.

#### Captured

**Target:** `crimsonland.exe+0x40f400` (absolute `0x0040f400`)

**Breakpoint hit:**
- EIP: `0x0040f400`
- Return address (caller): `0x0040fe59`

**Stack / Args (cdecl):**
At `esp=0x0019f8fc`:
- `[@esp]` return address: `0x0040fe59`
- `[@esp+4]` board pointer: `0x004819ec`
- `[@esp+8]` out_idx pointer: `0x0019f938`
- `[@esp+0xC]` out_dir pointer: `0x0019f91f`

**Caller snippet (around 0x0040fe59):**
```
0040fe59 83c40c          add     esp,0Ch
0040fe5c 84c0            test    al,al
0040fe5e 75bd            jne     0040fe1d
0040fe60 c705f02e4700ffffffff mov dword ptr [00472ef0],0FFFFFFFFh
0040fe6a 891dec244800    mov     dword ptr [004824ec],ebx
0040fe70 c705e424480080250000 mov dword ptr [004824e4],25880h
0040fe7a a0101c4800      mov     al,byte ptr [00481c10]
0040fe7f a802            test    al,2
0040fe81 7553            jne     0040fed6
0040fe85 6830ff4000      push    0040ff30
0040fe8d c605c61b480001  mov     byte ptr [00481bc6],1
0040fe94 8815101c4800    mov     byte ptr [00481c10],dl
0040fe9a 881dd51b4800    mov     byte ptr [00481bd5],bl
0040fea0 881dd41b4800    mov     byte ptr [00481bd4],bl
0040fea6 c705d01b48000000803f mov dword ptr [00481bd0],3F800000h
0040feb0 891dcc1b4800    mov     dword ptr [00481bcc],ebx
0040feb6 891dc01b4800    mov     dword ptr [00481bc0],ebx
0040febc 881dc41b4800    mov     byte ptr [00481bc4],bl
0040fec2 881dc51b4800    mov     byte ptr [00481bc5],bl
0040fec8 891dc81b4800    mov     dword ptr [00481bc8],ebx
```

**Board dump (6x6 ints at 0x004819ec):**
```
2 2 0 4 4 4
4 4 0 2 2 2
0 3 0 2 4 4
3 1 4 2 4 0
3 2 0 1 2 2
1 2 4 1 4 4
```

#### Interpretation

- `0x0040f400` is confirmed live and receives a 6x6 int board at `0x004819ec`.
- The return address `0x0040fe59` is inside the credits secret update loop and gates UI init for globals near `0x00481bc0..0x00481bd5`.
- The globals touched in the snippet align with credits secret state (selection index, timer, score, flags), now mapped in `data_map.json`.
- Remaining gap: record `*out_idx` and `*out_dir` to confirm orientation encoding.

### Session 2 (2026-01-19) - credits secret

#### Wishlist

- Log `*out_idx` and `*out_dir` after calls to `0x0040f400` (match-3 finder), for both hit and miss cases.
- Dump globals each visit to `0x0040f4f0`: `0x00472ef0`, `0x004824e4`, `0x004824e8`, `0x004824ec`, `0x00481c10`.
- Snapshot boards and masks: `0x004819ec` (6x6 ints), `0x004819f0`, `0x004819f4`, `0x00481a04`, `0x00481a1c`.
- Break on writes to `0x00472ef0` to capture selection/swap flow (EIP + regs + stack).
- Grab a call stack the first time `0x0040f4f0` runs to confirm the caller chain.

#### Captured

**Match-3 finder `0x0040f400`**

- **Hit (miss case):**
  - Return address: `0x0040fbdd`
  - Args:
    - board = `0x004819ec`
    - out_idx_ptr = `0x0019f928`
    - out_dir_ptr = `0x0019f91f`
  - `*out_idx = 0x00000000`, `*out_dir = 0x00`
  - Board sample (6x6 ints; `-3` = `0xFFFFFFFD`):
    ```
    4 4 2 4 0 4
    1 1 2 2 4 4
    1 -3 4 4 1 3
    2 -3 2 1 0 0
    2 0 3 4 2 3
    ```

- **Hit (success case):**
  - Return address: `0x0040fe59`
  - Args:
    - board = `0x004819ec`
    - out_idx_ptr = `0x0019f938`
    - out_dir_ptr = `0x0019f91f`
  - `*out_idx = 0x00000012`, `*out_dir = 0x01`
  - Board sample:
    ```
    2 4 3 0 4 1
    2 4 1 0 4 1
    3 0 2 3 2 3
    2 3 4 4 0 0
    1 2 4 1 3 3
    4 3 2 0 1 1
    ```

**Direction encoding (out_dir)**

- We attempted to map `out_dir` to absolute move direction, but the logging was noisy and multiple hits fired per user move.
- Observed `out_dir` values were often `0x01` across different moves, suggesting it may not encode absolute direction.
- Hypothesis: `out_dir` may encode axis or relative polarity (or another flag), not absolute direction.
- Next reliable step: capture a one-shot return with `out_idx/out_dir` *and* a full board dump, then infer direction by comparing tiles.

**Selection/swap flow**

- `ba w4 0x00472ef0` hit at `0x0040fe6a` inside the credits secret update block.
- Callsite is in the same `0x0040fe6a..0x0040fe9a` region that initializes UI globals.

**Timer globals**

- `0x004824e4` is the main countdown value.
  - Timer update block: `0x0040f69d..0x0040f6a3` (`mov [0x004824e4], eax`).
  - One-shot log:
    - pre: `0x004824e4 = 0x00000000`, `0x004824e8 = 0x0000fd3b`
    - post: `0x004824e4 = 0x00002580`, `0x004824e8 = 0x0001039a`
- Low-timer trigger: `0x0040f6a3` when `0x004824e4 < 0x100` (observed `cur = 0x47`).
- Timer-expire sfx:
  - Breakpoint at `0x0040f6b5` (call to `0x0043d120`, `sfx_play(sfx_trooper_die_01)` in decompile).
  - Hit with `0x004824e4 = 0xFFFFFFF9` (timer already negative at callsite).

**Caller chain**

- Per-frame update chain repeats:
  - `... -> crimsonland+0x4732a -> crimsonland+0x46bd7 -> crimsonland+0x1a64d -> crimsonland+0x6b2e -> grim...`

#### Interpretation

- `0x0040f400` confirmed: `out_idx/out_dir` are non-zero on success and zero on miss.
- `0x004824e4` is the countdown timer; `0x004824e8` tracks a paired value in the same update block.
- The flashing Reset/Back hover effect correlates with `0x004824e4 < 0x100`.
- Still missing: exact “timer zero / dying sound” callsite; likely triggered by a different state flag or audio hook.
