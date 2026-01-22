---
tags:
  - status-tracking
---

# WinDbg sessions

## Session 1 (2026-01-18) - credits secret

### Wishlist

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
The signature looks like: credits_secret_match3_find (`FUN_0040f400`) (int *board, int *out_idx, char *out_dir)

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

### Captured

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

### Interpretation

- `0x0040f400` is confirmed live and receives a 6x6 int board at `0x004819ec`.
- The return address `0x0040fe59` is inside the credits secret update loop and gates UI init for globals near `0x00481bc0..0x00481bd5`.
- The globals touched in the snippet align with credits secret state (selection index, timer, score, flags), now mapped in `data_map.json`.
- Remaining gap: record `*out_idx` and `*out_dir` to confirm orientation encoding.

## Session 2 (2026-01-19) - credits secret

### Wishlist

- Log `*out_idx` and `*out_dir` after calls to `0x0040f400` (match-3 finder), for both hit and miss cases.
- Dump globals each visit to `0x0040f4f0`: `0x00472ef0`, `0x004824e4`, `0x004824e8`, `0x004824ec`, `0x00481c10`.
- Snapshot boards and masks: `0x004819ec` (6x6 ints), `0x004819f0`, `0x004819f4`, `0x00481a04`, `0x00481a1c`.
- Break on writes to `0x00472ef0` to capture selection/swap flow (EIP + regs + stack).
- Grab a call stack the first time `0x0040f4f0` runs to confirm the caller chain.

### Captured

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

- Static analysis of `credits_secret_match3_find` confirms:
  - `out_dir = 0x01` for **horizontal** matches (left-to-right).
  - `out_dir = 0x00` for **vertical** matches (top-to-bottom).
  - `out_idx` is the **start index** of the 3-tile run in row-major order (leftmost/topmost).

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

### Interpretation

- `0x0040f400` confirmed: `out_idx/out_dir` are non-zero on success and zero on miss.
- `0x004824e4` is the countdown timer; `0x004824e8` tracks a paired value in the same update block.
- The flashing Reset/Back hover effect correlates with `0x004824e4 < 0x100`.
- `out_dir` encodes orientation only (0 = vertical, 1 = horizontal); no absolute direction.
- Still missing: exact "timer zero / dying sound" callsite; likely triggered by a different state flag or audio hook.

## Session 3 (2026-01-19) - credits screen / Secret button unlock

### Goal

Capture the exact unlock point for the **Secret** button on the credits screen and dump the injected
secret lines.

### Breakpoint

One-shot write watch on the unlock flag:

```
ba w1 crimsonland+0x811c4 ".printf \"[credits] Secret unlock write (DAT_004811c4)\\n\"; k; r; dd crimsonland+0x811c4 L1; dd crimsonland+0x811bc L1; dd crimsonland+0x80980 L40; gc"
```

### Captured

- **Hit location:** `EIP=0x0040dda7` (`credits_screen_update` + `0x5a7`)
- **Instruction:** `mov edx, dword ptr [crimsonland+0x80984 + eax*8]`
- **Registers:** `EAX=0x54` (line index)
- **Unlock flag:** `DAT_004811c4 = 1`
- **Secret base index:** `DAT_004811bc = 0x54`

### Secret line table dump

The credits line table lives at `0x00480980` and is a pair array: `ptr, flags`.
The secret lines begin at index `0x54`, so the injected block starts at:

- `0x00480980 + 0x54*8 = 0x00480c20`

Dumped strings (all flags `0x00000004`):

- `0x54` — "Inside Dead Let Mighty Blood"
- `0x55` — "Do Firepower See Mark Of"
- `0x56` — "The Sacrifice Old Center"
- `0x57` — "Yourself Ground First For"
- `0x58` — "Triangle Cube Last Not Flee"
- `0x59` — "0001001110000010101110011"
- `0x5A` — "0101001011100010010101100"
- `0x5B` — "011111001000111"
- `0x5C` — "(4 bits for index) <- OOOPS I meant FIVE!"
- `0x5D` — "(4 bits for index)"

Additional dump at `0x00480c70` (index `0x5E` onward) was zeroed, indicating no further injected
lines beyond `0x5D`.

### Interpretation

- The Secret button unlock is driven by the **credits line scan** in `credits_screen_update`, not by
  a separate hidden state. Once all required lines are flagged, `DAT_004811c4` is set and the secret
  lines are injected at index `0x54`.

## Session 4 (2026-01-19) - console tilde hotkey

### Goal

Identify the runtime path that toggles the in-game console when pressing `~`.

### Breakpoints

```
ba w1 crimsonland+0x7eec8 ".printf \"[console] open_flag write\\n\"; k; r; u @eip L12; dd crimsonland+0x7eec8 L1; gc"
ba w4 crimsonland+0x7f4d4 ".printf \"[console] 0x7f4d4 write\\n\"; k; r; u @eip L12; dd crimsonland+0x7f4d4 L1; gc"
bp crimsonland+0x18b0 ".printf \"[console] console_set_open\\n\"; k; r; dd @esp L4; gc"
```

### Captured

- **Callsite:** `0x0040c39a` calls `console_set_open` (`0x004018b0`) when `~` is pressed.
- **Call stack:** `0x0040c39a -> 0x004018b0 -> DINPUT8!CDIDev_GetDeviceState -> grim...`
- **Writes inside `console_set_open`:**
  - `console_open_flag` (`0x0047eec8`) written at `0x004018b7`
  - `console_input_enabled` (`0x0047f4d4`) written at `0x004018bd`

**Disasm snippet (from `console_set_open`):**

```
004018b0 8a442404        mov     al,byte ptr [esp+4]
004018b7 8b0d3c084800    mov     ecx,dword ptr [0048083c]
004018bd a2d4f44700      mov     byte ptr [0047f4d4],al
004018c2 8b01            mov     eax,dword ptr [ecx]
004018c4 ff504c          call    dword ptr [eax+4Ch]
004018c7 c20400          ret     4
```

### Interpretation

- The tilde hotkey **calls `console_set_open`**, not a direct flag write.
- The remaining task is to identify the function containing `0x0040c39a` and the
  specific key check (likely `DIK_GRAVE = 0x29`).

## Session 5 (2026-01-19) - console hotkey check (DIK_GRAVE)

### Goal

Capture the actual key check that gates the console toggle.

### Breakpoint

```
bp /1 crimsonland+0xc39a ".printf \"[console] hotkey callsite 0x0040c39a\\n\"; r; k; u @eip-40 L80; dd @esp L8; gc"
```

### Captured

Disassembly confirms the check and toggle sequence:

```
0040c36d 6a29            push    29h              ; DIK_GRAVE
0040c37d ff5248          call    dword ptr [edx+48h]
0040c380 84c0            test    al,al
0040c382 7416            je      0040c39a
0040c384 8a15c8ee4700    mov     dl,[0047eec8]    ; console_open_flag
0040c38f 3ad3            cmp     dl,bl
0040c391 0f94c0          sete    al               ; al = (open_flag == 0)
0040c394 50              push    eax
0040c395 e81655ffff      call    004018b0         ; console_set_open
0040c39a b9a0ee4700      mov     ecx,0047eea0      ; console state
0040c39f e89c56ffff      call    00401a40         ; console_update
```

Additional context from the block entry (`0x0040c360`):

```
0040c320 6a57            push    57h
0040c322 8818            mov     byte ptr [eax],bl
0040c324 8b0d3c084800    mov     ecx,dword ptr [0048083c]
0040c32a 8b11            mov     edx,dword ptr [ecx]
0040c32c ff5220          call    dword ptr [edx+20h]
0040c32f e80c1c0100      call    0041df40
0040c334 84c0            test    al,al
0040c336 7513            jne     0040c34b
0040c338 833d347048000a  cmp     dword ptr [00487034],0Ah
0040c33f 7e0a            jle     0040c34b
0040c341 c705347048000a000000 mov dword ptr [00487034],0Ah
0040c34b 381d84af4a00    cmp     byte ptr [004aaf84],bl
0040c351 740d            je      0040c360
0040c353 e898e20100      call    0042a5f0
0040c358 b001            mov     al,1
0040c35a 5e              pop     esi
0040c35b 5b              pop     ebx
0040c35c 83c428          add     esp,28h
0040c35f c3              ret
0040c360 a144084800      mov     eax,dword ptr [00480844]
```

Additional hotkey in the same block:

```
0040c3aa 6a58            push    58h              ; DIK_F12
0040c3ae ff5248          call    dword ptr [edx+48h]
```

### Interpretation

- The tilde hotkey uses **Grim2D key polling** (`vtable +0x48`) with `DIK_GRAVE (0x29)`.
- The toggle is explicit: if `console_open_flag` is 0, it passes 1 to `console_set_open`; otherwise 0.
- The same function calls `console_update` immediately after the toggle.
- The hotkey block appears inside a larger per-frame input/update function that also checks `DIK_F12 (0x58)`.
- The block is gated by `audio_suspend_flag` (`0x004aaf84`); when non-zero, it calls `audio_resume_all`
  (`0x0042a5f0`) and returns early.

## Session 6 (2026-01-19) - console hotkey function entry

### Goal

Find the true function entry that contains the hotkey block at `0x0040c360`.

### Breakpoint

```
bp 0x0040c1c0 ".printf \"[console] entry 0x0040c1c0\\n\"; kb; u @eip L40; gc"
```

### Captured

- **Entry hit:** `0x0040c1c0`
- **Stack (unwind warning):** call chain passes through Grim (`grim+0x3def`, `grim+0x6025`) and a
  `crimsonland` caller around `0x0042cf41` before returning to `grim!GRIM__GetInterface`.

**Prolog:**

```
0040c1c0 8b0d3c084800    mov     ecx,dword ptr [0048083c]
0040c1c6 83ec28          sub     esp,28h
0040c1c9 8b01            mov     eax,dword ptr [ecx]
0040c1cb 53              push    ebx
0040c1cc 56              push    esi
0040c1cd ff503c          call    dword ptr [eax+3Ch]
```

### Interpretation

- The hotkey block (`0x0040c360`) and its callsite (`0x0040c39a`) live inside a larger per‑frame
  input/update function that starts at `0x0040c1c0`.
