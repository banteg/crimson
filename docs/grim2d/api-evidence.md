---
tags:
  - status-validation
---

# Grim2D vtable evidence appendix

This appendix collects one concrete callsite snippet per vtable offset,

plus the current grim.dll entry signature and address from

`analysis/ghidra/derived/grim2d_vtable_map.json`.

Ghidra signatures include the implicit `this` pointer on vtable calls; the
Suggested signature lines omit it and add const qualifiers where evidence
supports them.

## 0x0 — grim_release @ 0x10005c80

- Ghidra signature: `void grim_release(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: crimsonland_main:L21607 (base vtable call)
- First callsite: crimsonland_main (line 21607)


```c
    (**(code **)*DAT_0048083c)();
    return 0;
```

grim.dll body:

```c
  operator_delete(in_ECX);
```


## 0x4 — grim_set_paused @ 0x10005c90

- Ghidra signature: `void grim_set_paused(int paused)`
- Notes: stores the paused flag in a byte-sized global (likely boolean)
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  grim_paused_flag = (undefined1)paused;
```


## 0x8 — grim_get_version @ 0x10005ca0

- Ghidra signature: `float grim_get_version(void)`
- Notes: returns the hard-coded engine version constant
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return 1.21;
```


## 0xc — grim_check_device @ 0x10005cb0

- Ghidra signature: `int grim_check_device(void)`
- Notes: wraps a D3D device status call; negative results are masked with `0xffffff00`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  uVar1 = (**(code **)(*DAT_10059dbc + 0x6c))(DAT_10059dbc,DAT_10059df8,DAT_10059dfc,0x15,&uStack_4);
  if ((int)uVar1 < 0) {
    return uVar1 & 0xffffff00;
  }
```


## 0x10 — grim_apply_config @ 0x10005d40

- Ghidra signature: `int grim_apply_config(void)`
- Notes: creates the D3D8 interface and shows the config dialog
- Suggested signature: `bool grim_apply_config(void)` (low byte indicates success)
- Call sites: 1 (unique funcs: 1)
- Sample calls: crimsonland_main (`FUN_0042c450`):L19443
- First callsite: crimsonland_main (`FUN_0042c450`) (line 21580)


```c
  FUN_00401870(&DAT_0047eea0,(byte *)s____invoking_grim_config_00474aa0);
  FUN_00402860(0x47eea0);
  cVar1 = (**(code **)(*DAT_0048083c + 0x10))();
  DAT_004aaf45 = 1;
  if (cVar1 == '\0') {
```

grim.dll body:

```c
  DAT_1005b2c4 = (int *)Direct3DCreate8(0xdc);
  DialogBoxParamA(DAT_1005bacc,(LPCSTR)0x74,(HWND)0x0,(DLGPROC)&LAB_10002120,0);
  (**(code **)(*DAT_1005b2c4 + 8))(DAT_1005b2c4);
  if (grim_config_dialog_canceled == '\0') {
    (**(code **)(*in_ECX + 0x20))(0x54,DAT_1005d400);
```


## 0x14 — grim_init_system @ 0x10005eb0

- Ghidra signature: `int grim_init_system(void)`
- Notes: initializes D3D + input devices and loads `smallFnt.dat`
- Suggested signature: `bool grim_init_system(void)` (low byte indicates success)
- Call sites: 1 (unique funcs: 1)
- Sample calls: crimsonland_main (`FUN_0042c450`):L19504
- First callsite: crimsonland_main (`FUN_0042c450`) (line 21641)


```c
  FUN_00401870(&DAT_0047eea0,(byte *)s____using_joystick_00474998);
  FUN_00401870(&DAT_0047eea0,(byte *)s____initiating_Grim_system_0047497c);
  cVar1 = (**(code **)(*DAT_0048083c + 0x14))();
  if (cVar1 == '\0') {
    FUN_00401870(&DAT_0047eea0,(byte *)s_Critical_failure__00474968);
```


## 0x18 — grim_shutdown @ 0x10005ff0

- Ghidra signature: `void grim_shutdown(void)`
- Call sites: 1 (unique funcs: 1)
- Sample calls: crimsonland_main (`FUN_0042c450`):L19599
- First callsite: crimsonland_main (`FUN_0042c450`) (line 21736)


```c
  FUN_0043d110();
  FUN_00401870(&DAT_0047eea0,(byte *)s_Shutdown_Grim___00474848);
  (**(code **)(*DAT_0048083c + 0x18))();
  FUN_00402860(0x47eea0);
  (**(code **)*DAT_0048083c)();
```


## 0x1c — grim_apply_settings @ 0x10006020

- Ghidra signature: `void grim_apply_settings(void)`
- Notes: forwards to Grim2D’s internal settings routine (`FUN_10003c00`)
- Call sites: 1 (unique funcs: 1)
- Sample calls: crimsonland_main (`FUN_0042c450`):L19581
- First callsite: crimsonland_main (`FUN_0042c450`) (line 21718)


```c
    puVar9 = puVar10;
  } while ((int)puVar10 < 0x4805c0);
  (**(code **)(*DAT_0048083c + 0x1c))();
  LVar11 = RegCreateKeyExA((HKEY)0x80000001,s_Software_10tons_entertainment_Cr_00474604,0,(LPSTR)0x0
                           ,0,0xf003f,(LPSECURITY_ATTRIBUTES)0x0,&pHStack_5c4,(LPDWORD)0x0);
```

grim.dll body:

```c
  FUN_10003c00();
```


## 0x20 — grim_set_config_var @ 0x10006580

- Confirmed name: `set_config_var`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_config_var(unsigned int id, grim_config_value_t value)`
- Previous Ghidra signature: `void grim_set_config_var(unsigned int id, unsigned int value)`
- Notes: config/state dispatcher; some IDs map to D3D render/texture stage
  state, while others update the table or consume pointer/callback fields.
- Call sites: 206 (unique funcs: 35)
- Sample calls: FUN_00401dd0:L754; FUN_00401dd0:L755; FUN_00401dd0:L847; FUN_00402d50:L1438; FUN_00402d50:L1460; demo_trial_overlay_render (`FUN_004047c0`):L3147; ui_render_keybind_help:L3373; ui_render_keybind_help:L3377
- First callsite: FUN_00401dd0 (line 754)


```c
    (**(code **)(*DAT_0048083c + 0xd0))(&fStack_4c,DAT_00471140,0x40800000,&puStack_44);
    (**(code **)(*DAT_0048083c + 0xf0))();
    (**(code **)(*DAT_0048083c + 0x20))(0x15,2);
    (**(code **)(*DAT_0048083c + 0x20))(0x18,0x3f000000);
    (**(code **)(*DAT_0048083c + 0x114))
```

The vtable entry is exactly `0x10006580`. Live Binary Ninja shows five stack
dwords (`id` plus the four record words) at every path and `retn 0x14` on all
returns. A representative caller reserves 16 bytes, initializes only word 0,
pushes ID `0x15`, and calls slot `+0x20`; the callee removes the entire 20-byte
argument block. Other recovered callers initialize all four words. This is
MSVC's ordinary by-value aggregate ABI, not a variadic two-word API.


## 0x24 — grim_get_config_var @ 0x10006c30

- Confirmed name: `get_config_var`
- Confirmed C++ signature: `grim_config_value_t __thiscall IGrim2D::get_config_var(int id)`
- ABI-level analyzer signature: `grim_config_value_t *grim_get_config_var(grim_config_value_t *out, int id)`
- Previous Ghidra signature: `void grim_get_config_var(unsigned int *out, int id)`
- Notes: grim.dll returns one 16-byte record from `grim_config_values` for IDs
  in `0..127`; all other IDs return the zero-filled `grim_config_default`.
- Call sites: 17 (unique funcs: 4)
- Sample calls: config_sync_from_grim (`FUN_0041ec60`):L13402; config_sync_from_grim (`FUN_0041ec60`):L13410; config_sync_from_grim (`FUN_0041ec60`):L13413; config_sync_from_grim (`FUN_0041ec60`):L13415; config_sync_from_grim (`FUN_0041ec60`):L13417; config_sync_from_grim (`FUN_0041ec60`):L13419; crimsonland_main (`FUN_0042c450`):L19456; crimsonland_main (`FUN_0042c450`):L19458
- First callsite: config_sync_from_grim (`FUN_0041ec60`) (line 15539)


```c
  acStack_4b0[0] = '|';
  acStack_4b0[1] = -0x14;
  acStack_4b0[2] = 'A';
  acStack_4b0[3] = '\0';
  puVar2 = (undefined1 *)(**(code **)(*DAT_0048083c + 0x24))();
  DAT_0048050c = *puVar2;
  puVar3 = (undefined4 *)(**(code **)(*DAT_0048083c + 0x24))(&stack0xfffffb60);
  DAT_00480504 = *puVar3;
  puVar3 = (undefined4 *)(**(code **)(*DAT_0048083c + 0x24))(&uStack_4a8,0x2a);
  DAT_00480508 = *puVar3;
```

Live Binary Ninja resolves the apparent `out` argument as MSVC's hidden
structure-return buffer: callers push the ID and a 16-byte destination, the
method returns with `retn 8`, and callers immediately read through the pointer
left in `EAX`. A natural by-value return compiles with VC6.5 to all 32 native
instructions and all five masked data references, including the four
base-plus-offset reads from the fallback record.


## 0x28 — grim_get_error_text @ 0x10006ca0

- Ghidra signature: `char * grim_get_error_text(void)`
- Suggested signature: `const char * grim_get_error_text(void)`
- Call sites: 1 (unique funcs: 1)
- Sample calls: crimsonland_main (`FUN_0042c450`):L19509
- First callsite: crimsonland_main (`FUN_0042c450`) (line 21646)


```c
    uType = 0;
    pcVar6 = s_Crimsonland__00474958;
    lpText = (LPCSTR)(**(code **)(*DAT_0048083c + 0x28))();
    MessageBoxA((HWND)0x0,lpText,pcVar6,uType);
    (**(code **)*DAT_0048083c)();
```

grim.dll body:

```c
  return grim_error_text;
```


## 0x2c — grim_clear_color @ 0x10006cb0

- Ghidra signature: `void grim_clear_color(float r, float g, float b, float a)`
- Call sites: 5 (unique funcs: 3)
- Sample calls: FUN_00417b80:L9215; terrain_generate_random:L9452; crimsonland_main (`FUN_0042c450`):L19534; crimsonland_main (`FUN_0042c450`):L19538; crimsonland_main (`FUN_0042c450`):L19547
- First callsite: terrain_generate (`FUN_00417b80`) (line 11352)


```c
  fStack_98 = 0.24705882;
  uStack_9c = 0x417c89;
  (**(code **)(*DAT_0048083c + 0x2c))();
  iVar3 = iStack_70;
  uStack_9c = 0;
```

grim.dll body:

```c
  uVar3 = ftol(0,0);
  iVar4 = ftol();
  uVar5 = ftol();
  uVar6 = ftol();
  (**(code **)(iVar1 + 0x90))(piVar2,0,0,1,
      ((uVar3 & 0xff | iVar4 << 8) << 8 | uVar5 & 0xff) << 8 | uVar6 & 0xff);
```


## 0x30 — grim_set_render_target @ 0x10006d50

- Ghidra signature: `int grim_set_render_target(int target_index)`
- Notes: called with `-1` to restore the backbuffer
- Call sites: 6 (unique funcs: 3)
- Sample calls: FUN_00417b80:L9209; FUN_00417b80:L9333; terrain_generate_random:L9446; terrain_generate_random:L9563; fx_queue_render (`FUN_00427920`):L17949; fx_queue_render (`FUN_00427920`):L18035
- First callsite: terrain_generate (`FUN_00417b80`) (line 11346)


```c
  fStack_88 = DAT_0048f530;
  iStack_8c = 0x417c6a;
  (**(code **)(*DAT_0048083c + 0x30))();
  iStack_8c = 0x3f800000;
  uStack_90 = 0x3dc8c8c9;
```


## 0x34 — grim_get_time_ms @ 0x10006e40

- Ghidra signature: `int grim_get_time_ms(void)`
- Notes: returns the global millisecond counter
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return DAT_1005a054;
```


## 0x38 — grim_set_time_ms @ 0x10006e50

- Ghidra signature: `void grim_set_time_ms(int ms)`
- Notes: overwrites the global millisecond counter
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  DAT_1005a054 = ms;
```


## 0x3c — grim_get_frame_dt @ 0x10006e60

- Ghidra signature: `float grim_get_frame_dt(void)`
- Notes: clamps the frame delta to `0.1`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  if (0.1 < _DAT_10059768) {
    return 0.1;
  }
  return _DAT_10059768;
```


## 0x40 — grim_get_fps @ 0x10006e90

- Ghidra signature: `float grim_get_fps(void)`
- Notes: returns the cached FPS estimate
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return _DAT_1005b2bc;
```


## 0x44 — grim_is_key_down @ 0x10007320

- Confirmed name: `is_key_down`
- Confirmed C++ signature: `unsigned char __thiscall IGrim2D::is_key_down(unsigned int key)`
- Previous Ghidra signature: `int grim_is_key_down(unsigned int key)`
- Notes: byte-sized 0/1 predicate; the underlying helper aliases keys by their
  low byte before reading the 256-byte keyboard state.
- Call sites: 6 (unique funcs: 2)
- Sample calls: console_update (`FUN_00401a40`):L509; console_update (`FUN_00401a40`):L511; console_update (`FUN_00401a40`):L526; console_update (`FUN_00401a40`):L528; ui_focus_update (`FUN_0043d830`):L26638; ui_focus_update (`FUN_0043d830`):L26639
- First callsite: console_update (`FUN_00401a40`) (line 509)


```c
              (float10)*(int *)((int)param_1 + 0x18));
  FUN_00401060();
  cVar2 = (**(code **)(*DAT_0048083c + 0x44))(0x1d);
  if (cVar2 == '\0') {
    cVar2 = (**(code **)(*DAT_0048083c + 0x44))(0x9d);
```

Live callers load `ECX=this`, push one key, call vtable slot `+0x44`, and test
only `AL`. The callee forwards to `grim_keyboard_key_down`, ignores `this`, and
uses `retn 4`. Modeling both functions with byte returns compiles to all five
native instructions, full prefix, and masked references `1/0/0`; declaring the
wrapper as `int` or native C++ `bool` adds a widening/normalization sequence.


## 0x48 — grim_was_key_pressed @ 0x10007390

- Confirmed name: `was_key_pressed`
- Confirmed C++ signature: `bool __thiscall IGrim2D::was_key_pressed(unsigned int key)`
- Previous Ghidra signature: `int grim_was_key_pressed(unsigned int key)`
- Notes: press/repeat query with a 0.5-second initial delay and 0.1-second
  held-repeat interval.
- Call sites: 39 (unique funcs: 16)
- Sample calls: console_update (`FUN_00401a40`):L514; console_update (`FUN_00401a40`):L522; console_update (`FUN_00401a40`):L531; console_update (`FUN_00401a40`):L543; console_update (`FUN_00401a40`):L547; console_update (`FUN_00401a40`):L551; console_update (`FUN_00401a40`):L574; console_update (`FUN_00401a40`):L578
- First callsite: console_update (`FUN_00401a40`) (line 514)


```c
    if (cVar2 != '\0') goto LAB_00401ac4;
LAB_00401add:
    cVar2 = (**(code **)(*DAT_0048083c + 0x48))(200);
    if (cVar2 != '\0') {
      *(int *)((int)param_1 + 0x14) = *(int *)((int)param_1 + 0x14) + 1;
```

Live Binary Ninja shows that the full key value is passed to
`grim_keyboard_key_down`, while all repeat arrays index `(unsigned char)key`.
On a down key whose timer is zero, the function reloads the timer from the
global `0.5f` delay. Subsequent repeats multiply that delay by `0.2f`, giving
`0.1f`; releasing the key resets its timer to zero and first-press latch to 1.
The timers are decremented and clamped elsewhere in the keyboard poll.

The recovered virtual-bool member compiles with MSVC 6.5 to all 31 native
instructions, full prefix, and masked references `10/0/0`. Callers supply
`ECX=this`, push one key, and test only `AL`, confirming the member ABI and
byte-sized result.


## 0x4c — grim_flush_input @ 0x10007330

- Confirmed name: `flush_input`
- Confirmed C++ signature: `void __thiscall IGrim2D::flush_input(void)`
- Ghidra signature: `void grim_flush_input(void)`
- Notes: clears the 256-byte keyboard state, drains queued DirectInput events,
  clears the state again, and empties the key-char FIFO.
- Call sites: 12 (unique funcs: 10)
- Sample calls: console_set_open (`FUN_004018b0`):L346; quest_mode_update:L4357; tutorial_prompt_dialog (`FUN_00408530`):L5083; tutorial_prompt_dialog (`FUN_00408530`):L5104; gameplay_update_and_render:L5879; game_over_screen_update:L7055; quest_failed_screen_update:L7326; quest_results_screen_update (`FUN_00410d20`):L7702
- First callsite: console_set_open (`FUN_004018b0`) (line 346)


```c
  *(undefined1 *)((int)this + 0x28) = param_1;
  DAT_0047f4d4 = param_1;
  (**(code **)(*DAT_0048083c + 0x4c))();
  return;
}
```

Live Binary Ninja identifies a 91-byte function at the vtable's `+0x4c` slot.
It zeroes `grim_keyboard_state[256]`, initializes an event count to 10, and
calls the keyboard device's `GetDeviceData` slot with 20-byte events. The call
is repeated while the returned unsigned count is nonzero, with a 101-call
safety cap. The function then zeroes the keyboard state again and clears
`grim_key_char_queue_count`.

The recovered C++ source compiles with MSVC 6.5 to all 34 native instructions,
with full prefix and masked references `5/0/0`. The five references resolve to
the keyboard device, event buffer, keyboard state (twice), and key-char count.


## 0x50 — grim_get_key_char @ 0x10005c40

- Confirmed name: `get_key_char`
- Confirmed C++ signature: `int __thiscall IGrim2D::get_key_char(void)`
- Ghidra signature: `int grim_get_key_char(void)`
- Notes: pops the oldest entry from the internal eight-int key-character FIFO,
  shifts the remaining entries down, and returns zero when empty.
- Call sites: 1 (unique funcs: 1)
- Sample calls: console_input_poll (`FUN_00401060`):L33
- First callsite: console_input_poll (`FUN_00401060`) (line 33)


```c
  int iVar1;
  
  iVar1 = (**(code **)(*DAT_0048083c + 0x50))();
  if (DAT_0047f4d4 != '\0') {
    if ((iVar1 != 0) && (DAT_0047ea58 == '\0')) {
```

Live Binary Ninja shows `grim_key_char_queue[8]` at `0x1005d3c4` and its count
at `0x1005d3e4`. The enqueue path caps the count below 7, leaving the eighth
slot available to the getter's shift. The recovered snapshot-and-do/while
source compiles to all 22 native instructions, full prefix, and references
`4/0/0`.


## 0x54 — grim_set_key_char_buffer @ 0x10005c20

- Confirmed name: `set_key_char_buffer`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_key_char_buffer(unsigned char *buffer, int *count, int size)`
- Ghidra signature: `void grim_set_key_char_buffer(unsigned char *buffer, int *count, int size)`
- Notes: installs a caller-owned text buffer, its count pointer, and capacity;
  native code performs no null or size validation here.
- Call sites: 2 (unique funcs: 2)
- Sample calls: crimsonland_main (`FUN_0042c450`):L19559; ui_text_input_update (`FUN_0043ecf0`):L27394
- First callsite: crimsonland_main (`FUN_0042c450`) (line 21696)


```c
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  }
  (**(code **)(*DAT_0048083c + 0x54))(&DAT_004aacd8,&DAT_004aaedc,uVar14);
  FUN_0041ec60();
  puVar13 = &DAT_00490be0;
```

The three arguments are stored verbatim at `0x10053048`, `0x1005304c`, and
`0x10053050`, immediately after the unrelated key-repeat delay. Three ordinary
global assignments compile to all seven native instructions, full prefix, and
references `3/0/0`; the member ignores `this` and removes 12 argument bytes.


## 0x58 — grim_is_mouse_button_down @ 0x10007410

- Confirmed name: `is_mouse_button_down`
- Confirmed C++ signature: `unsigned char __thiscall IGrim2D::is_mouse_button_down(int button)`
- Previous Ghidra signature: `int grim_is_mouse_button_down(int button)`
- Notes: button 0 is observed; cached mode returns the saved byte directly,
  otherwise the helper extracts bit 7 from `DIMOUSESTATE2.rgbButtons[button]`.
- Call sites: 4 (unique funcs: 3)
- Sample calls: gameplay_update_and_render:L6349; input_primary_just_pressed (`FUN_00446030`):L31421; input_primary_just_pressed (`FUN_00446030`):L31439; input_primary_is_down (`FUN_004460f0`):L31467
- First callsite: gameplay_update_and_render (line 6349)


```c
    }
  }
  cVar3 = (**(code **)(*DAT_0048083c + 0x58))(0);
  DAT_004808b9 = cVar3 != '\0';
  FUN_0040a320();
```

grim.dll body:

```c
  if (grim_input_cached != '\0') {
    return CONCAT31((int3)((uint)button >> 8),(&DAT_1005a044)[button]);
  }
  bVar1 = FUN_1000a590(button);
  return CONCAT31(extraout_var,bVar1);
```

The recovered byte-predicate member and its raw DirectInput helper both compile
exactly with MSVC 6.5. The member matches 11/11 instructions with references
`3/0/0`; the helper at `0x1000a590` matches 4/4 with references `1/0/0`.


## 0x5c — grim_was_mouse_button_pressed @ 0x10007440

- Confirmed name: `was_mouse_button_pressed`
- Confirmed C++ signature: `bool __thiscall IGrim2D::was_mouse_button_pressed(int button)`
- Previous Ghidra signature: `int grim_was_mouse_button_pressed(void *this, int button)`
- Notes: edge-triggered mouse button query; the per-button latch is true only
  while the button is released.
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  cVar1 = (**(code **)(*(int *)this + 0x58))(button);
  if ((cVar1 == '\0') || ((&grim_mouse_button_latch)[button] == '\0')) {
    uVar4 = 0;
  }
  else {
    uVar4 = 1;
  }
  uVar2 = (**(code **)(*(int *)this + 0x58))(button);
  (&grim_mouse_button_latch)[button] = (char)uVar2 == '\0';
  return CONCAT31((int3)((uint)uVar2 >> 8),uVar4);
```

The source performs the down query twice by design: the first value is ANDed
with the previous release latch to produce the result, and the second is
negated into the next latch state. Cached mode applies the same short-circuit
logic directly to `grim_mouse_button_cache`. This natural source compiles to
all 51 native instructions, full prefix, and masked references `7/0/0`.


## 0x60 — grim_get_mouse_wheel_delta @ 0x10007560

- Provisional name: `get_mouse_wheel_delta` (high)
- Guess: `float get_mouse_wheel_delta(void)`
- Notes: positive/negative scroll used to change selection
- Ghidra signature: `float grim_get_mouse_wheel_delta(void)`
- Call sites: 2 (unique funcs: 1)
- Sample calls: ui_scrollbar_update (`FUN_0043def0`):L26948; ui_scrollbar_update (`FUN_0043def0`):L26952
- First callsite: ui_scrollbar_update (`FUN_0043def0`) (line 29084)


```c
    (**(code **)(*DAT_0048083c + 0xd0))(&stack0xffffffb0,0x3f800000,fVar1,&local_30);
  }
  fVar8 = (float10)(**(code **)(*DAT_0048083c + 0x60))();
  if ((float10)0.0 < fVar8) {
    *param_2 = *param_2 - 1.0;
```


## 0x64 — grim_set_mouse_pos @ 0x10007530

- Provisional name: `set_mouse_pos` (high)
- Guess: `void set_mouse_pos(float x, float y)`
- Ghidra signature: `void grim_set_mouse_pos(float x, float y)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  grim_mouse_x = x;
  grim_mouse_y = y;
  _DAT_1005b278 = x;
  _DAT_1005b27c = y;
```


## 0x68 — grim_get_mouse_x @ 0x10007510

- Provisional name: `get_mouse_x` (high)
- Guess: `float get_mouse_x(void)`
- Ghidra signature: `float grim_get_mouse_x(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return _DAT_1005b278;
```


## 0x6c — grim_get_mouse_y @ 0x10007520

- Provisional name: `get_mouse_y` (high)
- Guess: `float get_mouse_y(void)`
- Ghidra signature: `float grim_get_mouse_y(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return _DAT_1005b27c;
```


## 0x70 — grim_get_mouse_dx @ 0x100074d0

- Provisional name: `get_mouse_dx` (high)
- Guess: `float get_mouse_dx(void)`
- Ghidra signature: `float grim_get_mouse_dx(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return grim_mouse_dx;
```


## 0x74 — grim_get_mouse_dy @ 0x100074e0

- Provisional name: `get_mouse_dy` (high)
- Guess: `float get_mouse_dy(void)`
- Ghidra signature: `float grim_get_mouse_dy(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return grim_mouse_dy;
```


## 0x78 — grim_get_mouse_dx_indexed @ 0x100074f0

- Provisional name: `get_mouse_dx_indexed` (high)
- Guess: `float get_mouse_dx_indexed(int index)`
- Ghidra signature: `float grim_get_mouse_dx_indexed(int index)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  fVar1 = (float10)(**(code **)(*in_ECX + 0x70))();
  return (float)fVar1;
```


## 0x7c — grim_get_mouse_dy_indexed @ 0x10007500

- Provisional name: `get_mouse_dy_indexed` (high)
- Guess: `float get_mouse_dy_indexed(int index)`
- Ghidra signature: `float grim_get_mouse_dy_indexed(int index)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  fVar1 = (float10)(**(code **)(*in_ECX + 0x74))();
  return (float)fVar1;
```

Live Binary Ninja and the VC6.5 matcher confirm the full mouse motion/position
cluster. `grim_get_mouse_dx`, `grim_get_mouse_dy`, and `grim_get_mouse_y` are
two-instruction x87 global getters with references `1/0/0`; `grim_set_mouse_pos`
writes the supplied X/Y bit patterns to both accumulated and cached globals in
9/9 instructions with references `4/0/0`. The indexed methods intentionally
ignore their stack argument and dispatch through `this` slots `0x70` and
`0x74`; each natural forwarding method matches all 3 instructions and ends in
`retn 4`.


## grim.dll — joystick direction helpers @ 0x10006ea0..0x10006fd9

- Confirmed names: `grim_joystick_up_active`, `grim_joystick_down_active`,
  `grim_joystick_left_active`, and `grim_joystick_right_active`
- Confirmed signatures: `int helper(void)`

Each helper snapshots the configured deadzone and the corresponding axis
center before reading X (`0x98`) or Y (`0x9c`) through the Grim2D interface.
The negative helpers test `axis - center < -deadzone`; the positive helpers
test `axis - center > deadzone`, so equality remains inactive. Natural VC6.5
source reproduces all 88 instructions across the four functions, with full
prefixes and aggregate references `12/0/0`.


## 0x80 — grim_is_key_active @ 0x10006fe0

- Confirmed name: `grim_is_key_active`
- Recovered signature: `unsigned char grim_is_key_active(int key)`
- Ghidra signature: `int grim_is_key_active(int key)` (stale width)
- Call sites: 6 (unique funcs: 4)
- Sample calls: gameplay_update_and_render:L5929; input_any_key_pressed (`FUN_00446000`):L29232; input_primary_just_pressed (`FUN_00446030`):L29266; input_primary_just_pressed (`FUN_00446030`):L29282; input_primary_is_down (`FUN_004460f0`):L29308; input_primary_is_down (`FUN_004460f0`):L29310
- First callsite: tutorial_timeline_update (`FUN_00408990`) (line 5277)


```c
    if (DAT_00486fd8 == 1) {
      puVar6 = &DAT_00490be0;
      while ((((cVar2 = (**(code **)(*DAT_0048083c + 0x80))(puVar6[-1]), cVar2 == '\0' &&
               (cVar2 = (**(code **)(*DAT_0048083c + 0x80))(*puVar6), cVar2 == '\0')) &&
              ((cVar2 = (**(code **)(*DAT_0048083c + 0x80))(puVar6[1]), cVar2 == '\0' &&
```

The live grim.dll body and its natural VC6.5 WIP recover the complete routing:

```c
key <= 0xff       -> raw keyboard query
0x100..0x104      -> mouse buttons 0..4
0x11f..0x12a      -> joystick buttons 0..11
0x131..0x134      -> up/down/left/right deadzone helpers
0x13f,0x140,0x141,
0x153,0x154,0x155 -> fabs(axis * 0.001f) > 0.5
0x16d..0x17b      -> provider(player 0..2, action 0..4)
all other IDs     -> 0
```

The byte return is visible at direct forwarding exits, which preserve `al`
without widening. The current source is deliberately recorded as WIP:
174/175 candidate/target instructions, 73.93% normalized match, 2/175 prefix,
and references `7/0/1`. Its remaining debt is register allocation and the
placement of the shared axis-threshold tail. The lone conflicting masked
reference is the resulting alignment of the candidate Rz load with the target
X load; all six axis globals are present, and no semantic branch is unresolved.


## 0x84 — grim_get_config_float @ 0x100071b0

- Provisional name: `get_config_float` (high)
- Guess: `float get_config_float(int id)`
- Notes: IDs 0x13f..0x155
- Ghidra signature: `float grim_get_config_float(int id)`
- Suggested signature: `float grim_get_config_float(int id)` (special-cases `0x15f` to return `grim_get_mouse_dx`)
- Call sites: 6 (unique funcs: 1)
- Sample calls: FUN_00448b50:L30229; FUN_00448b50:L30233; FUN_00448b50:L30237; FUN_00448b50:L30241; FUN_00448b50:L30245; FUN_00448b50:L30249
- First callsite: player_update (`FUN_004136b0`) (line 9703)


```c
    }
    if (iVar10 == 3) {
      fVar19 = (float10)(**(code **)(*DAT_0048083c + 0x84))((&DAT_00490c0c)[iVar6 * 0xd8]);
      pfVar12 = (float *)(&DAT_00490c08)[iVar6 * 0xd8];
      fVar20 = (float10)(**(code **)(*DAT_0048083c + 0x84))();
```

grim.dll mapping:

```c
  if (id == 0x13f) {
    return (float)DAT_1005d830 * 0.001;
  }
  if (id == 0x140) {
    return (float)grim_joystick_axis_y * 0.001;
  }
  if (id == 0x15f) {
    fVar3 = (float10)(**(code **)(*in_ECX + 0x70))();
    return (float)fVar3;
  }
```

Live Binary Ninja and the VC6.5 matcher confirm the complete router. Six
`DIJOYSTATE2` axes (`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, `0x155`)
are scaled by `0.001f`; `0x15f`/`0x160` return direct mouse X/Y delta; and a
three-iteration loop maps `0x163..0x165` and `0x168..0x16a` to the indexed
delta compatibility methods. All other IDs return `0.0f`. Natural C++ matches
all 88 instructions, full prefix, and references `13/0/0`.


## 0x88 — grim_get_slot_float @ 0x100072c0

- Notes: returns a float slot from the engine scratch array
- Ghidra signature: `float grim_get_slot_float(int index)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return *(float *)(&DAT_1005c100 + index * 4);
```


## 0x8c — grim_get_slot_int @ 0x100072d0

- Notes: returns an int slot from the engine scratch array
- Ghidra signature: `int grim_get_slot_int(int index)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return *(int *)(&DAT_1005bf00 + index * 4);
```


## 0x90 — grim_set_slot_float @ 0x100072e0

- Notes: writes a float slot in the engine scratch array
- Ghidra signature: `void grim_set_slot_float(int index, float value)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  *(float *)(&DAT_1005c100 + index * 4) = value;
```


## 0x94 — grim_set_slot_int @ 0x10007300

- Notes: writes an int slot in the engine scratch array
- Ghidra signature: `void grim_set_slot_int(int index, int value)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  *(int *)(&DAT_1005bf00 + index * 4) = value;
```

Live Binary Ninja names the two backing arrays `grim_slot_ints` and
`grim_slot_floats`. Natural unchecked array access reproduces all 14 VC6.5
instructions across the four getters/setters, with full prefixes and aggregate
references `4/0/0`; there is no bounds check or conversion beyond the x87
float load/store required by the ABI.


## 0x98 — grim_get_joystick_x @ 0x10007580

- Notes: returns cached joystick axis X
- Ghidra signature: `int grim_get_joystick_x(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return DAT_1005d830;
```


## 0x9c — grim_get_joystick_y @ 0x10007590

- Notes: returns cached joystick axis Y
- Ghidra signature: `int grim_get_joystick_y(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return grim_joystick_axis_y;
```


## 0xa0 — grim_get_joystick_z @ 0x100075a0

- Notes: returns cached joystick axis Z
- Ghidra signature: `int grim_get_joystick_z(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  return grim_joystick_axis_z;
```


## 0xa4 — grim_get_joystick_pov @ 0x100075b0

- Ghidra signature: `int grim_get_joystick_pov(int index)`
- Call sites: 2 (unique funcs: 2)
- Sample calls: input_aim_pov_left_active; input_aim_pov_right_active
- First callsite: input_aim_pov_left_active


```c
  int iVar1;
  
  iVar1 = (**(code **)(*DAT_0048083c + 0xa4))(0);
  return iVar1 == DAT_004804fc;
}
```


## 0xa8 — grim_is_joystick_button_down @ 0x100075c0

- Previous Ghidra signature: `int grim_is_joystick_button_down(int button)`
- Confirmed signature: `unsigned char grim_is_joystick_button_down(int button)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  bVar1 = FUN_1000a310(button);
  return CONCAT31(extraout_var,bVar1);
```

Live Binary Ninja identifies the callee as the 19-byte
`grim_joystick_button_down`: it masks the argument to its low byte, reads
`DIJOYSTATE2.rgbButtons[index]`, and shifts bit 7 into `AL`. The natural helper
and public wrapper each match all 5 native instructions with references
`1/0/0`. The absence of widening in the wrapper confirms a byte return rather
than the earlier provisional `bool`/`int` declaration. The X/Y/Z accessors each
match 2/2 instructions, and the unchecked POV array accessor matches 3/3.


## 0xac — grim_create_texture @ 0x100075d0

- Confirmed name: `create_texture`
- Confirmed C++ signature: `bool create_texture(char *name, int width, int height)`
- Notes: used for terrain texture
- Previous Ghidra signature: `int grim_create_texture(char *name, int width, int height)`
- Call sites: 2 (unique funcs: 1)
- Sample calls: init_audio_and_terrain:L21242; init_audio_and_terrain:L21250
- First callsite: init_audio_and_terrain (`FUN_0042a9f0`) (line 21221)


```c
  if (DAT_004871c8 == '\0') {
    lVar5 = __ftol();
    cVar3 = (**(code **)(*DAT_0048083c + 0xac))(s_ground_004740c4,(int)lVar5,(int)lVar5);
    fVar2 = DAT_004803b8;
    if (cVar3 == '\0') {
```

grim.dll body:

```c
  uVar1 = grim_find_free_texture_slot();
  uVar2 = (**(code **)(*DAT_10059dbc + 0x50))(DAT_10059dbc,width,height,1,1,DAT_1005a488,0,local_10);
  pvVar3 = operator_new(0x18);
  pvVar3 = grim_texture_init(pvVar3,unaff_EDI,(char *)name_00);
  (&DAT_1005d404)[uVar1] = pvVar3;
```

The recovered VC6.5 source matches all 81 native instructions (257 bytes;
references `13/0/0`). It scans for a free slot, creates a one-level managed
texture, allocates and initializes the 24-byte texture entry, stores it in the
slot table, and returns a byte-sized success value. Allocation failures unwind
the partially constructed entry through the compiler-generated cleanup path.


## 0xb0 — grim_recreate_texture @ 0x10007790

- Confirmed name: `recreate_texture`
- Confirmed C++ signature: `bool recreate_texture(int handle)`
- Previous Ghidra signature: `int grim_recreate_texture(int handle)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


Recovered source shape:

```cpp
bool IGrim2D_cpp::grim_recreate_texture(int handle)
{
    if (grim_texture_slots[handle] == 0) {
        return false;
    }

    IDirect3DTexture8 *replacement;
    if (D3DXCreateTexture(
            grim_d3d_device,
            grim_texture_slots[handle]->width,
            grim_texture_slots[handle]->height,
            1,
            0,
            grim_preferred_texture_format,
            D3DPOOL_MANAGED,
            &replacement) < 0) {
        return false;
    }

    if (d3dx_copy_texture_filtered(
            replacement,
            grim_texture_slots[handle]->texture,
            0,
            0,
            0x10,
            1.0f) < 0) {
        replacement->Release();
        return false;
    }

    grim_texture_slots[handle]->texture->Release();
    grim_texture_slots[handle]->texture = replacement;
    return true;
}
```

This natural VC6.5 source matches all 57 native instructions (157 bytes;
references `8/0/0`). The six-argument copy target is a linked internal D3DX8
resampler rather than a public load API: its body validates copy/filter flags
and consumes the final argument as an x87 scale. The old texture is released
and replaced only after a successful copy; the temporary replacement is
released on failure.


## 0xb4 — grim_load_texture @ 0x100076e0

- Confirmed name: `load_texture`
- Confirmed C++ signature: `bool load_texture(char *name, char *path)`
- Notes: name + filename
- Previous Ghidra signature: `int grim_load_texture(char *name, char *path)`
- Call sites: 3 (unique funcs: 3)
- Sample calls: ui_element_load:L10132; texture_get_or_load (`FUN_0042a670`):L18970; texture_get_or_load_alt (`FUN_0042a700`):L18996
- First callsite: ui_element_load (line 12269)

```c
    FUN_00401870(&DAT_0047eea0,(byte *)s_Loading_uiElement__s_004737b4);
  }
  (**(code **)(*DAT_0048083c + 0xb4))(local_100,param_2);
  iVar2 = (**(code **)(*DAT_0048083c + 0xc0))(&stack0xfffffef8);
  *(int *)(iStack_8 + 0xe0) = iVar2;
```

The public method is an exact 7-instruction, 21-byte wrapper around
`grim_load_texture_internal` (references `1/0/0`). Its return remains in `AL`,
confirming the byte-sized C++ `bool` ABI.


## 0xb8 — grim_save_texture @ 0x10007750

- Confirmed name: `save_texture`
- Confirmed C++ signature: `bool __thiscall IGrim2D::save_texture(int handle, char *path)`
- Previous Ghidra signature: `int grim_validate_texture(int handle)`
- Notes: live disassembly reads both stack arguments and returns with `retn 0x8`.
  For a populated handle it calls the statically linked
  `D3DXSaveTextureToFileA(path, 2, texture, NULL)`; D3DX image format `2` is
  TGA. The old one-argument validation interpretation lost the path argument
  and misidentified the operation.
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  texture = grim_texture_slots[handle];
  if (texture == NULL)
    return false;
  return D3DXSaveTextureToFileA(path, 2, texture->texture, NULL) >= 0;
```


## 0xbc — grim_destroy_texture @ 0x10007700

- Notes: releases the texture, clears the slot, and adjusts the max handle
- Ghidra signature: `void grim_destroy_texture(int handle)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  texture = (void *)(&DAT_1005d404)[handle];
  if (texture != (void *)0x0) {
    grim_texture_release(texture);
    operator_delete(texture);
    (&DAT_1005d404)[handle] = 0;
  }
```


## 0xc0 — grim_get_texture_handle @ 0x10007740

- Provisional name: `get_texture_handle` (high)
- Guess: `int get_texture_handle(const char *name)`
- Notes: returns -1 on missing
- Ghidra signature: `int grim_get_texture_handle(char *name)`
- Suggested signature: `int grim_get_texture_handle(const char *name)`
- Call sites: 22 (unique funcs: 8)
- Sample calls: demo_purchase_screen_update (`FUN_0040b740`):L6362; demo_purchase_screen_update (`FUN_0040b740`):L6374; gameplay_reset_state (`FUN_00412dc0`):L8687; gameplay_reset_state (`FUN_00412dc0`):L8698; gameplay_reset_state (`FUN_00412dc0`):L8710; gameplay_reset_state (`FUN_00412dc0`):L8722; gameplay_reset_state (`FUN_00412dc0`):L8734; gameplay_reset_state (`FUN_00412dc0`):L8750
- First callsite: demo_purchase_screen_update (`FUN_0040b740`) (line 6749)


```c
    pcStack_f4 = s_mockup_00472964;
    pcStack_f8 = (char *)0x40bb08;
    pcStack_f8 = (char *)(**(code **)(*DAT_0048083c + 0xc0))();
    fStack_fc = 3.58732e-43;
    iStack_104 = DAT_00480508 / 2 + -0x8c;
```


## 0xc4 — grim_bind_texture @ 0x10007830

- Confirmed name: `bind_texture`
- Confirmed C++ signature: `void __thiscall IGrim2D::bind_texture(int handle, int stage)`
- Notes: negative handles, empty slots, and slots with a null texture pointer
  return without touching D3D state. A valid slot supplies its `+4` texture
  field to `IDirect3DDevice8::SetTexture(stage, texture)`, then becomes the
  current bound handle. Live disassembly calls D3D vtable slot `0xf4` and
  returns with `retn 0x8`.
- Ghidra signature: `void grim_bind_texture(int handle, int stage)`
- Call sites: 66 (unique funcs: 22)
- Sample calls: ui_draw_clock_gauge:L3882; ui_draw_clock_gauge:L3891; ui_render_aim_indicators:L5641; ui_render_aim_indicators:L5663; ui_draw_textured_quad:L9120; terrain_generate (`FUN_00417b80`):L9220; terrain_generate (`FUN_00417b80`):L9265; terrain_generate (`FUN_00417b80`):L9296
- First callsite: ui_draw_clock_gauge (line 3882)
- Runtime evidence: the checked-in `ui_render_trace.jsonl` contains 44,536
  `grim_bind_texture` events.


```c
  iVar2 = 1;
  (**(code **)(*DAT_0048083c + 0x20))(0x15,1);
  (**(code **)(*DAT_0048083c + 0xc4))(DAT_0048f7c8,0);
  iVar1 = 0;
  (**(code **)(*DAT_0048083c + 0x100))(0,0,0x3f800000,0x3f800000);
```

grim.dll body:

```c
  if (((-1 < handle) && ((&DAT_1005d404)[handle] != 0)) &&
     (iVar1 = *(int *)((&DAT_1005d404)[handle] + 4), iVar1 != 0)) {
    (**(code **)(*DAT_10059dbc + 0xf4))(DAT_10059dbc,stage,iVar1);
    _DAT_10053060 = handle;
  }
```

The recovered VC6.5 source matches all 20 instructions and all 3 masked
references. A minimal two-field texture-slot view recovers the validated
`+4` texture pointer without inventing the rest of the resource layout.


## 0xc8 — grim_draw_fullscreen_quad @ 0x10007870

- Confirmed name: `draw_fullscreen_quad`
- Confirmed C++ signature: `void __thiscall IGrim2D::draw_fullscreen_quad(int unused)`
- Ghidra signature (missing unused argument): `void grim_draw_fullscreen_quad(void)`
- Notes: the sole EXE call pushes zero, and live Binary Ninja shows `retn 0x4`,
  proving one unused stack argument. The method clears rotation, batches one
  current-texture quad from the origin to the unsigned-at-use backbuffer
  dimensions, and ends the batch.
- Call sites: 1 (unique funcs: 1)
- Sample calls: terrain_render (`FUN_004188a0`):L11783
- First callsite: terrain_render (`FUN_004188a0`) (line 11783)
- Runtime evidence: `evidence_summary.json` records 6,902 entry/exit events and
  3,451 `begin_batch`/`end_batch` pairs.


```c
  (**(code **)(*DAT_0048083c + 200))(0);
```

grim.dll body:

```c
  (**(code **)(*in_ECX + 0xfc))(0);
  (**(code **)(*in_ECX + 0xe8))();
  (**(code **)(*in_ECX + 0x11c))(0,0,(float)DAT_1005c400,(float)DAT_10059dc0);
  (**(code **)(*in_ECX + 0xf0))();
```

The recovered VC6.5 source matches all 32 instructions and both masked
references. Explicit unsigned casts of the signed dimension globals naturally
produce the native qword `fild` stack schedule; the corrected parameter
accounts for the native stack cleanup without an ABI shim.


## 0xcc — grim_draw_fullscreen_color @ 0x100079b0

- Confirmed name: `draw_fullscreen_color`
- Confirmed C++ signature: `void __thiscall IGrim2D::draw_fullscreen_color(float r, float g, float b, float a)`
- Ghidra signature: `void grim_draw_fullscreen_color(float r, float g, float b, float a)`
- Notes: positive alpha selects untextured D3D8 color/alpha state, forwards the
  RGBA scalars to `set_color`, clears rotation, and draws one quad from the
  origin to the unsigned backbuffer dimensions. Non-positive alpha returns
  before changing state; the normal modulate state is restored after drawing.
- Call sites: 2 (unique funcs: 2)
- Sample calls: gameplay_render_world (`FUN_00405960`):L3696; FUN_00406af0:L4120
- First callsite: gameplay_render_world (`FUN_00405960`) (line 3696)
- Runtime evidence: `evidence_summary.json` records 60 calls, of which 30
  positive-alpha paths begin and end a batch.


```c
  FUN_004295f0();
  if (0.0 < DAT_00487264) {
    (**(code **)(*DAT_0048083c + 0xcc))(0,0,0,DAT_00487264);
  }
  return;
```

grim.dll body:

```c
  if (0.0 < a) {
    (**(code **)(*DAT_10059dbc + 0xf4))(DAT_10059dbc,0,0);
    (**(code **)(*in_ECX + 0x114))(piVar1,uVar2,uVar3,uVar4);
    (**(code **)(*in_ECX + 0xfc))(0);
    (**(code **)(*in_ECX + 0xe8))();
    (**(code **)(*in_ECX + 0x11c))(0,0,(float)DAT_1005c400,(float)DAT_10059dc0);
    (**(code **)(*in_ECX + 0xf0))();
  }
```

The recovered VC6.5 source matches all 83 instructions and all 8 masked
references. Declaring the backbuffer dimensions as unsigned naturally produces
the native qword `fild` conversions; live Binary Ninja confirms the four-float
member ABI and `retn 0x10`.


## 0xd0 — grim_draw_rect_filled @ 0x100078e0

- Confirmed name: `draw_rect_filled`
- Confirmed C++ signature: `void __thiscall IGrim2D::draw_rect_filled(float *xy, float w, float h, float *rgba)`
- Notes: draws UI panel backgrounds with an explicit RGBA pointer. Live Binary
  Ninja disassembly loads the fourth stack argument, tests `rgba[3]`, receives
  `this` in `ECX`, and returns with `retn 0x10`. This corrects the prior
  three-argument Ghidra prototype.
- Ghidra signature (missing fourth argument): `void grim_draw_rect_filled(float *xy, float w, float h)`
- Call sites: 24 (unique funcs: 14)
- Sample calls: FUN_00401dd0:L740; FUN_00401dd0:L752; FUN_00402d50:L1448; demo_trial_overlay_render (`FUN_004047c0`):L3096; ui_render_keybind_help:L3369; tutorial_prompt_dialog (`FUN_00408530`):L5029; demo_purchase_screen_update (`FUN_0040b740`):L6476; demo_purchase_screen_update (`FUN_0040b740`):L6480
- First callsite: FUN_00401dd0 (line 740)


```c
    fStack_48 = (float)*(int *)(param_1 + 0x18);
    fStack_4c = DAT_00471140;
    (**(code **)(*DAT_0048083c + 0xd0))(&stack0xffffffd4);
    (**(code **)(*DAT_0048083c + 0x114))
              (0x3dcccccd,0x3f19999a,0x3f800000,
```

grim.dll body:

```c
  if (0.0 < *(float *)(in_stack_00000010 + 0xc)) {
    (**(code **)(*DAT_10059dbc + 0xf4))(DAT_10059dbc,0,0);
    (**(code **)(*in_ECX + 0xfc))(0);
    (**(code **)(*in_ECX + 0xe8))();
    (**(code **)(*in_ECX + 0x11c))(*puVar1,puVar1[1],uVar2,uVar3);
    (**(code **)(*in_ECX + 0xf0))();
  }
```

The recovered VC6.5 source matches all 72 instructions and all 6 masked
references. For positive alpha it selects untextured D3D8 color/alpha state,
forwards `rgba` to `set_color_ptr`, clears rotation, brackets one quad with
`begin_batch`/`end_batch`, and restores the normal modulate state.


## 0xd4 — grim_draw_rect_outline @ 0x10008f10

- Confirmed name: `draw_rect_outline`
- Confirmed C++ signature: `void __thiscall IGrim2D::draw_rect_outline(float *xy, float w, float h)`
- Notes: selects untextured D3D8 color/alpha state, clears rotation, and
  brackets the edge draw with `begin_batch`/`end_batch`. Unit height or width
  takes a one-quad fast path. Other rectangles draw top, left, bottom, and
  right quads; the bottom edge is widened by one pixel before normal modulate
  state is restored.
- Ghidra signature: `void grim_draw_rect_outline(float *xy, float w, float h)`
- Call sites: 12 (unique funcs: 11)
- Sample calls: FUN_00402d50:L1454; demo_trial_overlay_render (`FUN_004047c0`):L3107; ui_render_keybind_help:L3372; tutorial_prompt_dialog (`FUN_00408530`):L5031; quest_results_screen_update (`FUN_00410d20`):L7694; ui_menu_item_update:L27177; ui_text_input_update (`FUN_0043ecf0`):L27413; ui_text_input_update (`FUN_0043ecf0`):L27448
- First callsite: FUN_00402d50 (line 1454)
- Runtime evidence: the checked-in `ui_render_trace_summary.json` contains
  3,132 `grim_draw_rect_outline` events.


```c
  fStack_4c = (float)(DAT_00480504 / 2 + -0x6e);
  fStack_48 = (float)(DAT_00480508 / 2 + -0x1e);
  (**(code **)(*DAT_0048083c + 0xd4))(&fStack_4c,0x435c0000,0x42700000);
  iVar1 = *DAT_0048083c;
  iVar2 = (**(code **)(iVar1 + 0x14c))
```

grim.dll body:

```c
  (**(code **)(*in_ECX + 0xfc))(0);
  (**(code **)(*in_ECX + 0xe8))();
  (**(code **)(*in_ECX + 0x11c))(fRam00000000,fRam00000004,4,0x3f800000);
  (**(code **)(*in_ECX + 0x11c))(fRam00000000,fRam00000004,0x3f800000,0);
  (**(code **)(*in_ECX + 0x11c))(fRam00000000,fVar3 + fRam00000004,fVar2 + 1.0,0x3f800000);
  (**(code **)(*in_ECX + 0x11c))(fVar1 + fRam00000000,fRam00000004,0x3f800000,0);
  (**(code **)(*in_ECX + 0xf0))();
```

The recovered VC6.5 source matches all 125 instructions and all 8 masked
references. Live Binary Ninja confirms the three-argument member ABI,
documented D3D8 calls, comparison branches, four vtable `draw_quad` calls, and
`retn 0xc` without source-shaping artifacts.


## 0xd8 — grim_draw_circle_filled @ 0x10007b90

- Ghidra signature: `void grim_draw_circle_filled(float x, float y, float radius)`
- Call sites: 1 (unique funcs: 1)
- Sample calls: ui_render_aim_indicators:L5640
- First callsite: ui_render_aim_indicators (line 6027)


```c
          DAT_004802a8 = _DAT_00484fc8 + (float)(&DAT_00490900)[DAT_004aaf0c * 0xd8];
          DAT_004802ac = _DAT_00484fcc + (float)(&DAT_00490904)[DAT_004aaf0c * 0xd8];
          (**(code **)(*DAT_0048083c + 0xd8))(DAT_004802a8,DAT_004802ac,uVar7);
          (**(code **)(*DAT_0048083c + 0xc4))(DAT_0048f7e8,0);
          (**(code **)(*DAT_0048083c + 0x100))(0x3f000000,0,0x3f000000,0x3f800000);
```


## 0xdc — grim_draw_circle_outline @ 0x10007d40

- Ghidra signature: `void grim_draw_circle_outline(float x, float y, float radius)`
- Call sites: 1 (unique funcs: 1)
- Sample calls: ui_render_aim_indicators:L5644
- First callsite: ui_render_aim_indicators (line 6031)


```c
          (**(code **)(*DAT_0048083c + 0x100))(0x3f000000,0,0x3f000000,0x3f800000);
          (**(code **)(*DAT_0048083c + 0x114))(0x3f800000,0x3f800000,0x3f800000,0x3f0ccccd);
          (**(code **)(*DAT_0048083c + 0xdc))(DAT_004802a8,DAT_004802ac,uVar7);
          (**(code **)(*DAT_0048083c + 0x114))(0x3f800000,0x3f333333,0x3dcccccd,0x3f4ccccd);
          DAT_004802a8 = _DAT_00484fc8 + (float)(&DAT_00490900)[DAT_004aaf0c * 0xd8];
```


## 0xe0 — grim_draw_line @ 0x100080b0

- Confirmed name: `draw_line`
- Confirmed C++ signature: `void grim_draw_line(float *p0, float *p1, float thickness)`
- Previous Ghidra signature: `void grim_draw_line(void *this, float *p0, float *p1, float thickness)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


Recovered source shape:

```cpp
static GrimLineVector half_vector;
half_vector.x = p1[0] - p0[0];
half_vector.y = p1[1] - p0[1];
D3DXVec2Normalize(&half_vector, &half_vector);
half_vector.x = half_vector.y * thickness;
half_vector.y = half_vector.x * thickness;
grim_draw_line_quad(p0, p1, &half_vector.x);
```

The source matches all 40 native instructions (134 bytes; references
`13/0/0`), including VC6's guard and `atexit` registration for the
function-static vector. The linked thunk is `D3DXVec2Normalize`. The second
component genuinely multiplies the already-scaled first component by
`thickness`; the scratch preserves that observed behavior instead of silently
turning it into a conventional perpendicular-vector formula.


## 0xe4 — grim_draw_line_quad @ 0x10008150

- Confirmed name: `draw_line_quad`
- Confirmed C++ signature: `void grim_draw_line_quad(float *p0, float *p1, float *half_vec)`
- Previous Ghidra signature: `void grim_draw_line_quad(void *this, float *p0, float *p1, float *half_vec)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  (**(code **)(*(int *)this + 0x138))
            (*p0 - *half_vec,p0[1] - half_vec[1],*p0 + *half_vec,p0[1] + half_vec[1],
             *p1 + *half_vec,p1[1] + half_vec[1],*p1 - *half_vec,p1[1] - half_vec[1]);
```

The direct eight-float forwarding source matches all 42 native instructions
(99 bytes; no masked references). It expands the two endpoints into four
corners and calls vtable slot `0x138` (`grim_draw_quad_points`).


## 0xe8 — grim_begin_batch @ 0x10007ac0

- Confirmed name: `begin_batch`
- Confirmed C++ signature: `void __thiscall IGrim2D::begin_batch(void)`
- Notes: marks the batch active, begins a D3D8 scene, locks the dynamic vertex
  buffer with flags `0x2800`, and resets the low-word vertex count. Lock
  failure clears the device-ready byte.
- Ghidra signature: `void grim_begin_batch(void)`
- Call sites: 79 (unique funcs: 23)
- Sample calls: ui_draw_clock_gauge:L3887; ui_draw_clock_gauge:L3892; ui_render_aim_indicators:L5683; FUN_00417b80:L9228; FUN_00417b80:L9271; FUN_00417b80:L9299; terrain_generate_random:L9464; terrain_generate_random:L9506
- First callsite: ui_draw_clock_gauge (line 3887)


```c
  (**(code **)(*DAT_0048083c + 0x114))(0x3f800000,0x3f800000,0x3f800000,iVar2);
  (**(code **)(*DAT_0048083c + 0xfc))(0);
  (**(code **)(*DAT_0048083c + 0xe8))();
  (**(code **)(*DAT_0048083c + 0x11c))((float)iVar2,(float)iVar1,0x42000000,0x42000000);
  (**(code **)(*DAT_0048083c + 0xf0))();
```

The recovered VC6.5 source matches all 27 instructions and all 9 masked
references. `0x2800` is the documented D3D8 combination
`D3DLOCK_DISCARD | D3DLOCK_NOSYSLOCK`.


## 0xec — grim_flush_batch @ 0x100083c0

- Confirmed name: `flush_batch`
- Confirmed C++ signature: `void __thiscall IGrim2D::flush_batch(void)`
- Notes: unlocks and submits the current vertex buffer, then relocks it for
  continued batching. Only a successful relock clears the low-word count.
- Ghidra signature: `void grim_flush_batch(void)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  if ((grim_render_disabled == '\0') && (grim_batch_active != '\0')) {
    (**(code **)(*DAT_10059e2c + 0x30))(DAT_10059e2c);
    (**(code **)(*DAT_10059dbc + 0x11c))
              (DAT_10059dbc,4,0,grim_vertex_count & 0xffff,0,(grim_vertex_count & 0xffff) >> 1);
    iVar1 = (**(code **)(*DAT_10059e2c + 0x2c))(DAT_10059e2c,0,0,&DAT_10059e34,0x2800);
    if (-1 < iVar1) {
      grim_vertex_count = grim_vertex_count & 0xffff0000;
    }
  }
```

The recovered VC6.5 source matches all 37 instructions and all 8 masked
references. It uses ordinary D3D8 `Unlock`, `DrawIndexedPrimitive`, and `Lock`
calls; native code submits even when the current count is zero.


## 0xf0 — grim_end_batch @ 0x10007b20

- Confirmed name: `end_batch`
- Confirmed C++ signature: `void __thiscall IGrim2D::end_batch(void)`
- Notes: unlocks the vertex buffer, conditionally submits a nonempty triangle
  list, ends the D3D8 scene, and clears the active flag. If device readiness is
  lost after unlock, native code returns without clearing the active flag.
- Ghidra signature: `void grim_end_batch(void)`
- Call sites: 86 (unique funcs: 28)
- Sample calls: FUN_00401dd0:L753; demo_trial_overlay_render (`FUN_004047c0`):L3134; ui_draw_clock_gauge:L3889; ui_draw_clock_gauge:L3895; ui_render_aim_indicators:L5702; demo_purchase_screen_update (`FUN_0040b740`):L6346; ui_draw_textured_quad:L9125; terrain_generate (`FUN_00417b80`):L9261
- First callsite: FUN_00401dd0 (line 753)


```c
    fStack_48 = fStack_48 - 4.0;
    (**(code **)(*DAT_0048083c + 0xd0))(&fStack_4c,DAT_00471140,0x40800000,&puStack_44);
    (**(code **)(*DAT_0048083c + 0xf0))();
    (**(code **)(*DAT_0048083c + 0x20))(0x15,2);
    (**(code **)(*DAT_0048083c + 0x20))(0x18,0x3f000000);
```

The recovered VC6.5 source matches all 36 instructions and all 8 masked
references. It derives the D3D primitive count as half of the low-word vertex
count and skips only the draw call for an empty batch.


## 0xf4 — grim_submit_vertex_raw @ 0x10008e30

- Confirmed name: `submit_vertex_raw`
- Confirmed C++ signature: `void submit_vertex_raw(float *vertex)`
- Notes: copies 7 floats and auto-flushes when the batch is full
- Previous Ghidra signature: `void grim_submit_vertex_raw(float *vertex)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  if (grim_batch_active == '\0') {
    (**(code **)(*in_ECX + 0xe8))();
  }
  for (iVar1 = 7; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pfVar2 = *vertex;
    vertex = vertex + 1;
    pfVar2 = pfVar2 + 1;
  }
  grim_vertex_count._0_2_ = (ushort)grim_vertex_count + 1;
  if (DAT_1005976c <= (ushort)grim_vertex_count) {
    (**(code **)(*in_ECX + 0xec))();
  }
```

The recovered source matches all 35 native instructions (116 bytes;
references `9/0/0`). It rejects disabled/unready rendering, lazily begins a
batch, copies one 28-byte transformed/lit vertex, advances the cursor and
low-word count, and flushes at capacity.


## 0xf8 — grim_submit_quad_raw @ 0x10008eb0

- Confirmed name: `submit_quad_raw`
- Confirmed C++ signature: `void submit_quad_raw(float *verts)`
- Notes: copies 28 floats (4 vertices) and auto-flushes when the batch is full
- Previous Ghidra signature: `void grim_submit_quad_raw(float *verts)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  for (iVar1 = 0x1c; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pfVar2 = *verts;
    verts = verts + 1;
    pfVar2 = pfVar2 + 1;
  }
  grim_vertex_count._0_2_ = (ushort)grim_vertex_count + 4;
  if (DAT_1005976c <= (ushort)grim_vertex_count) {
    (**(code **)(*in_ECX + 0xec))();
  }
```

The recovered source matches all 25 native instructions (91 bytes;
references `7/0/0`). This lower-level path checks only the render-disable byte,
copies 112 bytes into an already active batch, advances by four vertices, and
flushes at capacity.


## 0xfc — grim_set_rotation @ 0x10007f30

- Confirmed name: `set_rotation`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_rotation(float radians)`
- Notes: stores the supplied angle and evaluates sine/cosine at
  `radians + 0.7853982f`. The resulting row-major matrix is
  `{cos, sin, -sin, cos}`. Live Binary Ninja shows the one-argument member ABI,
  x87 `fcos`/`fsin`, seven scalar global writes, and `retn 0x4`.
- Ghidra signature: `void grim_set_rotation(float radians)`
- Call sites: 65 (unique funcs: 17)
- Sample calls: FUN_00401dd0:L736; ui_draw_clock_gauge:L3886; ui_draw_clock_gauge:L3893; ui_render_aim_indicators:L5662; demo_purchase_screen_update (`FUN_0040b740`):L6325; terrain_render (`FUN_004188a0`):L9599; terrain_render (`FUN_004188a0`):L9630; creature_render_type (`FUN_00418b60`):L9718
- First callsite: FUN_00401dd0 (line 736)
- Runtime evidence: the checked-in `ui_render_trace_summary.json` contains
  53,352 `grim_set_rotation` events.


```c
    uStack_40 = 0;
    puStack_44 = (undefined1 *)0x401e8d;
    (**(code **)(*DAT_0048083c + 0xfc))();
    puStack_44 = &stack0xffffffdc;
    fStack_48 = (float)*(int *)(param_1 + 0x18);
```

grim.dll precompute:

```c
  _DAT_10059e30 = radians;
  fVar1 = (float10)fcos((float10)radians + (float10)0.7853982);
  grim_rotation_cos = (float)fVar1;
```

The recovered VC6.5 source matches all 19 instructions and all 11 masked
references. Ordinary repeated trig expressions plus row-major assignments
produce the native x87 schedule and register allocation without volatile
state, copies, or layout-only expressions.


## 0x100 — grim_set_uv @ 0x10008350

- Confirmed name: `set_uv`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_uv(float u0, float v0, float u1, float v1)`
- Notes: expands opposite UV corners into the four clockwise pairs consumed by
  draw calls. The vtable slot and `retn 0x10` establish the member ABI even
  though the body does not otherwise read `this`.
- Ghidra signature: `void grim_set_uv(float u0, float v0, float u1, float v1)`
- Call sites: 59 (unique funcs: 23)
- Sample calls: demo_trial_overlay_render (`FUN_004047c0`):L3126; ui_draw_clock_gauge:L3884; ui_render_aim_indicators:L5635; ui_render_aim_indicators:L5642; ui_render_aim_indicators:L5664; demo_purchase_screen_update (`FUN_0040b740`):L6331; ui_draw_textured_quad:L9121; terrain_generate (`FUN_00417b80`):L9206
- First callsite: demo_trial_overlay_render (`FUN_004047c0`) (line 3126)


```c
  uStack_18c = 0;
  uStack_190 = 0x4048bd;
  (**(code **)(*DAT_0048083c + 0x100))();
  uStack_190 = 0x4239999a;
  fStack_198 = param_1[1] + 22.0;
```

grim.dll UV assignment:

```c
  DAT_1005b290 = u0;
  DAT_1005b294 = v0;
  DAT_1005b298 = u1;
  DAT_1005b29c = v0;
```

The recovered VC6.5 source matches all 17 instructions and all 8 masked
references. It consists solely of ordinary field assignments to the same
four-element UV array recovered independently in the exact quad renderers.


## 0x104 — grim_set_atlas_frame @ 0x10008230

- Confirmed name: `set_atlas_frame`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_atlas_frame(int atlas_size, int frame)`
- Notes: atlas size (cells per side) + frame index
- Ghidra signature: `void grim_set_atlas_frame(int atlas_size, int frame)`
- Call sites: 25 (unique funcs: 6)
- Sample calls: creature_render_type (`FUN_00418b60`):L9704; creature_render_type (`FUN_00418b60`):L9715; creature_render_type (`FUN_00418b60`):L9759; creature_render_type (`FUN_00418b60`):L9770; creature_render_type (`FUN_00418b60`):L9819; creature_render_type (`FUN_00418b60`):L9830; bonus_hud_slot_update_and_render:L10630; projectile_render (`FUN_00422c70`):L16482
- First callsite: creature_render_type (`FUN_00418b60`) (line 11841)


```c
              iVar2 = iVar2 + 0x20;
            }
            (**(code **)(*DAT_0048083c + 0x104))(8,iVar2);
          }
          else {
```

Live Binary Ninja shows `ECX=this`, two stack parameters, and `retn 0x8`.
The recovered source initializes four UV corners from the indexed atlas origin,
then advances the right and bottom edges by one cell (`1 / atlas_size`). VC6.5
reproduces all 31 instructions and all 15 masked references without codegen
scaffolding.


## 0x108 — grim_set_sub_rect @ 0x100082c0

- Confirmed name: `set_sub_rect`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_sub_rect(int atlas_size, int width, int height, int frame)`
- Notes: atlas grid sub-rect; `atlas_size` indexes a pointer table with entries at 2/4/8/16; explicit call uses `(8, 2, 1, frame<<1)`
- Ghidra signature: `void grim_set_sub_rect(int atlas_size, int width, int height, int frame)`
- Call sites: 6 (unique funcs: 3)
- Sample calls: ui_render_hud (`FUN_0041aed0`):L10950; ui_render_hud (`FUN_0041aed0`):L10961; ui_render_hud (`FUN_0041aed0`):L10964; ui_render_hud (`FUN_0041aed0`):L11488; bonus_render (`FUN_004295f0`):L18733; ui_text_input_render (`FUN_004413a0`):L27845
- First callsite: ui_render_hud (`FUN_0041aed0`) (line 13087)


```c
      fStack_f8 = 1.12104e-44;
      fStack_fc = 6.033625e-39;
      (**(code **)(*DAT_0048083c + 0x108))();
      fStack_fc = 32.0;
      fStack_100 = 64.0;
```

Explicit parameterized call (bonus_render (`FUN_004295f0`)):

```c
        (**(code **)(*DAT_0048083c + 0x108))
                  (8,2,1,(&DAT_004d7a90)[(int)pfVar7[4] * 0x1f] << 1);
        (**(code **)(*DAT_0048083c + 0x11c))();
```

Live Binary Ninja shows `ECX=this`, four stack parameters, and `retn 0x10`.
The recovered source loads one `(u, v)` origin, initializes all four current
UV corners, then advances the right edge by `width / atlas_size` and the
bottom edge by `height / atlas_size`. VC6.5 reproduces all 31 instructions and
all 15 masked references without codegen scaffolding.

Atlas pointer table setup (grim.dll init):

```c
  puVar9 = &DAT_1005bc78;
  for (iVar7 = 0x10; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  _DAT_1005bc80 = &grim_subrect_table_0;
  _DAT_1005bc88 = &grim_subrect_table_1;
  _DAT_1005bc98 = &grim_subrect_table_2;
  _DAT_1005bcb8 = &DAT_1005a678;
```


## 0x10c — grim_set_uv_point @ 0x100083a0

- Confirmed name: `set_uv_point`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_uv_point(int index, float u, float v)`
- Ghidra signature: `void grim_set_uv_point(int index, float u, float v)`
- Notes: called as four consecutive `set_uv_point` calls (indices 0..3) to
  override per-corner UVs; u=0.625, v in {0, 0.25}. The native method performs
  no bounds check. Its vtable slot and `retn 0xc` establish the member ABI.
- Call sites: 4 (unique funcs: 1)
- Sample calls: projectile_render (`FUN_00422c70`):L16721; projectile_render (`FUN_00422c70`):L16725; projectile_render (`FUN_00422c70`):L16728; projectile_render (`FUN_00422c70`):L16729
- First callsite: projectile_render (`FUN_00422c70`) (line 18858)


```c
            fVar14 = fVar32;
            do {
              (**(code **)(*DAT_0048083c + 0x10c))(0,0x3f200000,0);
              fVar26 = 0.25;
              fVar24 = 0.625;
              fVar21 = 1.4013e-45;
              (**(code **)(*DAT_0048083c + 0x10c))(1,0x3f200000,0x3e800000);
              fVar19 = 0.25;
              in_stack_fffffd48 = 0.625;
              (**(code **)(*DAT_0048083c + 0x10c))(2,0x3f200000,0x3e800000);
              (**(code **)(*DAT_0048083c + 0x10c))(3,0x3f200000,0);
              pfVar7 = &fStack_274;
```

The recovered VC6.5 source matches all 6 instructions and both masked
references. It consists solely of indexed U/V field assignments through the
same eight-byte UV array recovered by `grim_set_uv`.


## 0x110 — grim_set_color_ptr @ 0x10008040

- Confirmed name: `set_color_ptr`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_color_ptr(float *rgba)`
- Notes: converts a four-float RGBA vector directly to packed ARGB and copies
  it to all four corner slots. This method does not clamp; relevant callers
  clamp inputs when needed. The vtable slot and `retn 0x4` establish the member
  ABI even though the body does not otherwise read `this`.
- Ghidra signature: `void grim_set_color_ptr(float *rgba)`
- Call sites: 20 (unique funcs: 10)
- Sample calls: game_over_screen_update:L7098; game_over_screen_update:L7171; quest_results_screen_update (`FUN_00410d20`):L7782; quest_results_screen_update (`FUN_00410d20`):L7851; creature_render_type (`FUN_00418b60`):L9717; creature_render_type (`FUN_00418b60`):L9772; creature_render_type (`FUN_00418b60`):L9832; creature_render_type (`FUN_00418b60`):L9894
- First callsite: game_over_screen_update (line 7485)


```c
            (**(code **)(*DAT_0048083c + 0x104))(8,iVar2);
          }
          (**(code **)(*DAT_0048083c + 0x110))(&fStack_58);
          (**(code **)(*DAT_0048083c + 0xfc))(pfVar5[7] - 1.5707964);
          (**(code **)(*DAT_0048083c + 0x11c))
                    ((_DAT_00484fc8 + pfVar5[1]) - fVar10,(_DAT_00484fcc + pfVar5[2]) - fVar10,
                     pfVar5[9] * 1.07,pfVar5[9] * 1.07);
```

Clamped RGBA example (input_primary_just_pressed (`FUN_00446030`)):

```c
        if (0.0 <= afStack_8c[2]) {
          if (1.0 < afStack_8c[2]) {
            afStack_8c[2] = 1.0;
          }
        }
        else {
          afStack_8c[2] = 0.0;
        }
        if (0.0 <= afStack_8c[3]) {
          if (1.0 < afStack_8c[3]) {
            afStack_8c[3] = 1.0;
          }
        }
        else {
          afStack_8c[3] = 0.0;
        }
        (**(code **)(*DAT_0048083c + 0x110))(afStack_8c + 2);
```

The recovered VC6.5 source matches all 25 instructions and all 12 masked
references. A four-byte color union accounts for the native per-channel byte
writes; VC6 reuses the dead parameter home for that local after preserving the
input pointer in `ESI`.


## 0x114 — grim_set_color @ 0x10007f90

- Confirmed name: `set_color`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_color(float r, float g, float b, float a)`
- Notes: clamps alpha to `[0, 1]`, converts four channels with the native x87
  `_ftol` path, packs ARGB, and propagates the value to all four corner slots.
  RGB is not clamped inside this method. The vtable slot and `retn 0x10`
  establish the member ABI even though the body does not otherwise read
  `this`.
- Ghidra signature: `void grim_set_color(float r, float g, float b, float a)`
- Call sites: 203 (unique funcs: 37)
- Sample calls: FUN_00401dd0:L733; FUN_00401dd0:L741; FUN_00401dd0:L756; FUN_00401dd0:L764; FUN_00401dd0:L769; FUN_00401dd0:L787; FUN_00401dd0:L833; FUN_00402d50:L1451
- First callsite: FUN_00401dd0 (line 733)


```c
    uStack_3c = 0x3f19999a;
    uStack_40 = 0x401e7d;
    (**(code **)(*DAT_0048083c + 0x114))();
    uStack_40 = 0;
    puStack_44 = (undefined1 *)0x401e8d;
```

grim.dll packing:

```c
  DAT_1005bc04 = ((uVar1 & 0xff | iVar2 << 8) << 8 | uVar3 & 0xff) << 8 | uVar4 & 0xff;
  DAT_1005bc10 = DAT_1005bc04;
```

The recovered VC6.5 source matches all 42 instructions and all 16 masked
references. Its ordinary alpha clamp, unsigned byte packing, and chained color
slot assignment reproduce the native compare, conversion, shift, and store
order without matching-only constructs.


## 0x118 — grim_set_color_slot @ 0x100081c0

- Confirmed name: `set_color_slot`
- Confirmed C++ signature: `void __thiscall IGrim2D::set_color_slot(int index, float r, float g, float b, float a)`
- Notes: packs RGBA directly into color slot `index`; draw calls consume slots
  0..3. The method performs no channel clamp and no index bounds check. Its
  vtable slot and `retn 0x14` establish the member ABI even though the body
  does not otherwise read `this`.
- Ghidra signature: `void grim_set_color_slot(int index, float r, float g, float b, float a)`
- Call sites: 12 (unique funcs: 2)
- Sample calls: demo_purchase_screen_update (`FUN_0040b740`):L6302; demo_purchase_screen_update (`FUN_0040b740`):L6308; demo_purchase_screen_update (`FUN_0040b740`):L6315; demo_purchase_screen_update (`FUN_0040b740`):L6322; projectile_render (`FUN_00422c70`):L15993; projectile_render (`FUN_00422c70`):L16000; projectile_render (`FUN_00422c70`):L16068; projectile_render (`FUN_00422c70`):L16075
- First callsite: demo_purchase_screen_update (`FUN_0040b740`) (line 6689)


```c
    fVar10 = 0.0;
    fsin((float10)(DAT_004808c0 % 1000) * (float10)6.2831855);
    (**(code **)(*DAT_0048083c + 0x118))();
    uStack_7c = 0x3e99999a;
    puStack_80 = (undefined1 *)0x0;
```

grim.dll slot write:

```c
  (&DAT_1005bc04)[index] = ((uVar1 & 0xff | iVar2 << 8) << 8 | uVar3 & 0xff) << 8 | uVar4 & 0xff;
```

The recovered VC6.5 source matches all 27 instructions and all 9 masked
references. It uses the same ordinary ARGB expression as the exact all-slot
setter, then writes the result through the caller-provided array index.


## 0x11c — grim_draw_quad @ 0x10008b10

- Confirmed name: `draw_quad`
- Confirmed C++ signature: `void __thiscall IGrim2D::draw_quad(float x, float y, float w, float h)`
- Notes: core draw call; uses per-corner color slots + UV array. Live callers
  pass the interface in `ECX`, and the implementation returns with `retn 0x10`.
- Ghidra signature: `void grim_draw_quad(float x, float y, float w, float h)`
- Call sites: 100 (unique funcs: 21)
- Sample calls: demo_trial_overlay_render (`FUN_004047c0`):L3132; ui_draw_clock_gauge:L3888; ui_draw_clock_gauge:L3894; ui_render_aim_indicators:L5701; demo_purchase_screen_update (`FUN_0040b740`):L6344; ui_draw_textured_quad:L9124; terrain_render (`FUN_004188a0`):L9613; creature_render_type (`FUN_00418b60`):L9720
- First callsite: demo_trial_overlay_render (`FUN_004047c0`) (line 3132)


```c
  fStack_19c = *param_1 + 72.0;
  pcStack_1a0 = (char *)0x4048ee;
  (**(code **)(*DAT_0048083c + 0x11c))();
  pcStack_1a0 = (char *)0x4048fc;
  (**(code **)(*DAT_0048083c + 0xf0))();
```

grim.dll vertex fill (color + UV):

```c
    DAT_10059e34[4] = DAT_1005bc04;
    DAT_10059e34[5] = DAT_1005b290;
    DAT_10059e34[6] = DAT_1005b294;
```

The recovered VC6.5 source matches all 195 instructions and all 68 masked
references. Its rotated path uses one Quake inverse-square-root refinement:
`half_diag = 0.5 * length_sq * inverse_sqrt(length_sq)`. This is a close
approximation of `0.5 * sqrt(length_sq)`, not a CRT `sqrt` call.


## 0x120 — grim_draw_quad_xy @ 0x10008720

- Confirmed name: `draw_quad_xy`
- Confirmed C++ signature: `void __thiscall IGrim2D::draw_quad_xy(float *xy, float w, float h)`
- Notes: direct wrapper around `draw_quad` using an XY pointer. Live
  disassembly receives `this` in `ECX`, forwards through slot `0x11c`, and
  returns with `retn 0xc`.
- Ghidra signature: `void grim_draw_quad_xy(float *xy, float w, float h)`
- Call sites: 6 (unique funcs: 2)
- Sample calls: FUN_00417b80:L9255; FUN_00417b80:L9289; FUN_00417b80:L9317; terrain_generate_random:L9491; terrain_generate_random:L9524; terrain_generate_random:L9547
- First callsite: terrain_generate (`FUN_00417b80`) (line 11392)


```c
      fStack_bc = fVar6;
      fStack_b8 = fVar6;
      (**(code **)(*DAT_0048083c + 0x120))();
      iVar4 = iVar4 + 1;
      iVar1 = DAT_0048f538 * DAT_0048f534 * 800;
```

grim.dll body:

```c
  (**(code **)(*in_ECX + 0x11c))(*xy,xy[1],w,h);
```

The recovered VC6.5 source matches all 14 instructions with no masked-reference
debt. Its body is exactly `draw_quad(xy[0], xy[1], w, h)`.


## 0x124 — grim_draw_quad_rotated_matrix @ 0x10008750

- Notes: emits a quad using the current rotation matrix and UV/color slots
- Ghidra signature: `void grim_draw_quad_rotated_matrix(void *this, float x, float y, float w, float h)`
- Suggested signature: `void grim_draw_quad_rotated_matrix(float x, float y, float w, float h)`
- Call sites: 0 (unique funcs: 0)
- Sample calls: none found
- First callsite: not found in decompiled output


grim.dll body:

```c
  if (_DAT_10059e30 == 0.0) {
    local_18 = x + w;
    local_20 = x;
    local_1c = y;
    local_14 = y;
  } else {
    fVar3 = w * 0.5;
    fStack_8 = fVar3 + x;
```


## 0x128 — grim_submit_vertices_transform @ 0x100085c0

- Confirmed name: `submit_vertices_transform`
- Confirmed C++ signature: `void __thiscall IGrim2D::submit_vertices_transform(float *verts, int count, float *offset, float *matrix)`
- Ghidra signature: `void grim_submit_vertices_transform(float * verts, int count, float * offset, float * matrix)`
- Notes: the render-disabled guard precedes a `count * 0x1c` bulk copy. For
  positive counts, live Binary Ninja disassembly shows the exact transforms
  `x' = y*m[1] + x*m[0]` and `y' = y*m[3] + x*m[2]`, followed by the XY
  offset and a seven-dword global write-pointer advance. The method then adds
  `count` to the counter's low word and calls virtual slot `0xec` at capacity;
  `retn 0x10` confirms the four-argument member ABI.
- Call sites: 5 (unique funcs: 1)
- Sample calls: ui_element_render (`FUN_00446c40`):L29980; ui_element_render (`FUN_00446c40`):L29985; ui_element_render (`FUN_00446c40`):L29986; ui_element_render (`FUN_00446c40`):L30065; ui_element_render (`FUN_00446c40`):L30107
- First callsite: ui_element_render (`FUN_00446c40`) (line 32116)
- Runtime evidence: the checked-in `ui_render_trace.jsonl` contains 13,940
  `grim_submit_vertices` events with `kind: transform`.


```c
      pppcStack_84 = (char ***)pppfVar1;
      ppfStack_80 = (float **)pppcVar2;
      (**(code **)(*DAT_0048083c + 0x128))();
      if (*(int *)(param_1 + 0x120) == 8) {
        pppcStack_98 = (char ***)0x4;
```

grim.dll inner loop (stride + matrix):

```c
    for (uVar5 = (uint)(count * 0x1c) >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
      *pfVar7 = *verts;
```

The recovered VC6.5 source matches all 64 instructions and all 9 masked
references. Ordinary scalar rotation accumulators preserve the native x87
evaluation order; no inline assembly, dummy references, or layout-only
branches are used.


## 0x12c — grim_submit_vertices_offset @ 0x10008680

- Confirmed name: `submit_vertices_offset`
- Confirmed C++ signature: `void __thiscall IGrim2D::submit_vertices_offset(float *verts, int count, float *offset)`
- Ghidra signature: `void grim_submit_vertices_offset(float * verts, int count, float * offset)`
- Notes: copies a generic seven-float vertex stream, adds XY offsets in place,
  advances the global batch pointer, and flushes at capacity. The decompiler
  emits decimal vtable offset `+ 300` (0x12c). Live disassembly receives `this`
  in `ECX` and returns with `retn 0xc`.
- Call sites: 4 (unique funcs: 1)
- Sample calls: ui_element_render (`FUN_00446c40`):L30035; ui_element_render (`FUN_00446c40`):L30042; ui_element_render (`FUN_00446c40`):L30045; ui_element_render (`FUN_00446c40`):L30074
- First callsite: ui_element_render (`FUN_00446c40`) (line 32196)


```c
      (**(code **)(*DAT_0048083c + 300))();
      if (*(int *)(param_1 + 0x120) == 8) {
        (**(code **)(*DAT_0048083c + 300))();
```

grim.dll body:

```c
  *DAT_10059e34 = *DAT_10059e34 + *offset;
  DAT_10059e34[1] = offset[1] + DAT_10059e34[1];
  grim_vertex_count._0_2_ = (ushort)grim_vertex_count + (short)count;
  if (DAT_1005976c <= (ushort)grim_vertex_count) {
    (**(code **)(*in_ECX + 0xec))();
  }
```

The recovered VC6.5 source matches all 50 instructions and all 8 masked
references. An ordinary `memcpy(count * 0x1c)` produces the native bulk-copy
sequence; a local float pointer then updates X/Y without imposing an invented
vertex struct.


## 0x130 — grim_submit_vertices_offset_color @ 0x10008430

- Confirmed name: `submit_vertices_offset_color`
- Confirmed C++ signature: `void __thiscall IGrim2D::submit_vertices_offset_color(float *verts, int count, float *offset, unsigned long *color)`
- Ghidra signature (color incorrectly typed as float): `void grim_submit_vertices_offset_color(float * verts, int count, float * offset, float * color)`
- Notes: bulk-copies seven-dword vertices, adds an XY offset, and overwrites
  field 4 with `*color` as packed ARGB. Live integer loads/stores establish the
  corrected color-pointer type; `retn 0x10` establishes the member ABI.
- Call sites: 3 (unique funcs: 1)
- Sample calls: ui_element_render (`FUN_00446c40`):L30006; ui_element_render (`FUN_00446c40`):L30014; ui_element_render (`FUN_00446c40`):L30018
- First callsite: ui_element_render (`FUN_00446c40`) (line 32142)


```c
        fStack_6c = fStack_64 + *(float *)(param_1 + 0xc);
        pppcStack_90 = (char ***)0x446fe3;
        (**(code **)(*DAT_0048083c + 0x130))();
        if (*(int *)(param_1 + 0x120) == 8) {
          pfStack_74 = (float *)(*(float *)(param_1 + 0x1c) + 7.0);
```

grim.dll body:

```c
  *DAT_10059e34 = *offset + *DAT_10059e34;
  DAT_10059e34[1] = offset[1] + DAT_10059e34[1];
  DAT_10059e34[4] = *color;
```

The recovered VC6.5 source matches all 54 instructions and all 9 masked
references. Its ordinary bulk copy, local XY temporaries, packed-color dword
assignment, pointer advance, and low-word capacity check recover the complete
native loop.


## 0x134 — grim_submit_vertices_transform_color @ 0x100084e0

- Confirmed name: `submit_vertices_transform_color`
- Confirmed C++ signature: `void __thiscall IGrim2D::submit_vertices_transform_color(float *verts, int count, float *offset, float *matrix, unsigned long *color)`
- Ghidra signature (color incorrectly typed as float): `void grim_submit_vertices_transform_color(float * verts, int count, float * offset, float * matrix, float * color)`
- Notes: the copy and matrix/offset loop match the non-color transform sibling,
  then an integer load/store overwrites dword field 4 with `*color` as packed
  ARGB. The integer operation corrects the stale color-pointer prototype;
  `retn 0x14` confirms the five-argument member ABI.
- Call sites: 5 (unique funcs: 2)
- Sample calls: effects_render (`FUN_0042e820`):L20025; effects_render (`FUN_0042e820`):L20053; ui_element_render (`FUN_00446c40`):L29953; ui_element_render (`FUN_00446c40`):L29959; ui_element_render (`FUN_00446c40`):L29962
- First callsite: effects_render (`FUN_0042e820`) (line 22162)
- Runtime evidence: the checked-in `ui_render_trace.jsonl` contains 7,202
  `grim_submit_vertices` events with `kind: transform_color`.


```c
      pfStack_60 = &fStack_40;
      pfStack_64 = &fStack_48;
      (**(code **)(*DAT_0048083c + 0x134))(puVar2 + 5,4);
    }
    puVar2 = puVar2 + 0x2f;
```

grim.dll body:

```c
  DAT_10059e34[1] = *DAT_10059e34 * matrix[2] + DAT_10059e34[1] * matrix[3];
  *DAT_10059e34 = *DAT_10059e34 * *matrix + DAT_10059e34[1] * matrix[1];
  *DAT_10059e34 = *offset + *DAT_10059e34;
  DAT_10059e34[1] = offset[1] + DAT_10059e34[1];
  DAT_10059e34[4] = *color;
```

The recovered VC6.5 source matches all 72 instructions and all 10 masked
references. Its scalar rotation accumulators, packed-color dword assignment,
and ordinary batch accounting reproduce the full native function without
inline assembly, dummy references, or layout-only branches.


## 0x138 — grim_draw_quad_points @ 0x10009080

- Confirmed name: `draw_quad_points`
- Confirmed C++ signature: `void __thiscall IGrim2D::draw_quad_points(float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3)`
- Notes: pushes a quad using four explicit points and the current per-corner
  color/UV slots. Live disassembly receives `this` in `ECX`, returns with
  `retn 0x20`, and dispatches batch begin/flush through slots `0xe8`/`0xec`.
- Ghidra signature: `void grim_draw_quad_points(float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3)`
- Call sites: 4 (unique funcs: 1)
- Sample calls: projectile_render (`FUN_00422c70`):L16048; projectile_render (`FUN_00422c70`):L16204; projectile_render (`FUN_00422c70`):L16755; projectile_render (`FUN_00422c70`):L16768
- First callsite: projectile_render (`FUN_00422c70`) (line 18185)


```c
          fStack_224 = (float)((float10)(float)(fVar9 * (float10)512.0 + (float10)fVar31) + fVar8 +
                              fVar11 * (float10)1.1);
          (**(code **)(*DAT_0048083c + 0x138))();
          fStack_244 = 6.07815e-39;
          (**(code **)(*DAT_0048083c + 0xf0))();
```

grim.dll vertex fill (color + UV slots):

```c
    DAT_10059e34[4] = DAT_1005bc04;
    DAT_10059e34[5] = DAT_1005b290;
    DAT_10059e34[6] = DAT_1005b294;
    DAT_10059e34 = DAT_10059e34 + 7;
    *DAT_10059e34 = x1;
```

The recovered VC6.5 source matches all 130 instructions and all 59 masked
references. It reuses one two-float stack temporary for the four incoming
points, copies Z/RHW and UV as paired aggregates, writes one packed color per
corner, and advances the native 28-byte vertex stream before its low-word batch
count/capacity check.


## 0x13c — grim_draw_text_mono @ 0x100092b0

- Provisional name: `draw_text_mono` (high)
- Guess: `void draw_text_mono(float x, float y, const char *text)`
- Notes: fixed 16px grid; advances X **before** drawing each glyph (except after 0xA7); draws most glyphs at `y + 1.0`; special-cases a few extended codes (0xA7, 0xE4, 0xE5, 0xF6).
- Font texture is loaded into `grim_font_texture` from Grim2D resources (resource id `0x6f`). [static]
- Ghidra signature: `void grim_draw_text_mono(float x, float y, char *text)`
- Suggested signature: `void grim_draw_text_mono(float x, float y, const char *text)`
- Call sites: 5 (unique funcs: 3)
- Sample calls: FUN_00401dd0:L781; FUN_00401dd0:L804; FUN_00401dd0:L843; demo_purchase_screen_update (`FUN_0040b740`):L6491; ui_render_hud (`FUN_0041aed0`):L11263
- First callsite: FUN_00401dd0 (line 781)


```c
    }
    else {
      (**(code **)(*DAT_0048083c + 0x13c))
                (0x41200000,(float)((iVar1 + 1) * 0x10) + *(float *)(param_1 + 0x1c),&DAT_004712c0);
      iVar3 = *DAT_0048083c;
```

grim.dll body:

```c
  if (grim_font_texture_bound == '\0') {
    (**(code **)(*DAT_10059dbc + 0xf4))(DAT_10059dbc,0,grim_font_texture);
  }
  (**(code **)(*in_ECX + 0xfc))(0);
  (**(code **)(*in_ECX + 0xe8))();
```


## 0x140 — grim_draw_text_mono_fmt @ 0x10009940

- Confirmed name: `draw_text_mono_fmt`
- Confirmed C++ signature: `void __cdecl IGrim2D::draw_text_mono_fmt(float x, float y, char *fmt, ...)`
- Notes: this cdecl varargs member passes the argument tail after `fmt` to the
  imported `vsprintf`, writes into `grim_printf_buffer`, and dispatches
  `(x, y, buffer)` through the mono-font draw slot at `0x13c`. Live Binary
  Ninja disassembly confirms the explicit stack `self` and plain `ret`.
- Ghidra signature: `void grim_draw_text_mono_fmt(IGrim2D *self, float x, float y, char *fmt, ...)`
- Call sites: 3 (unique funcs: 3)
- Sample calls: ui_render_keybind_help:L3374; FUN_00406350:L3950; ui_render_hud (`FUN_0041aed0`):L11281
- First callsite: ui_render_keybind_help (line 3374)


```c
  (**(code **)(*DAT_0048083c + 0xd4))(param_1,0x44000000,0x43800000);
  (**(code **)(*DAT_0048083c + 0x20))(0x18,0x3f4ccccd);
  (**(code **)(*DAT_0048083c + 0x140))
            (DAT_0048083c,*param_1 + 16.0,param_1[1] + 16.0,s_key_info_00471ffc);
  (**(code **)(*DAT_0048083c + 0x114))(0x3f800000,0x3f800000,0x3f800000,uVar4);
```

grim.dll body:

```c
  vsprintf(&DAT_1005ae78,fmt,&stack0x00000014);
  (**(code **)(*self + 0x13c))(x,y,&DAT_1005ae78);
```

The recovered VC6.5 source matches all 16 instructions and all 3 masked
references, including both `grim_printf_buffer` operands and the imported
`vsprintf` IAT slot.


## 0x144 — grim_draw_text_small @ 0x10009730

- Provisional name: `draw_text_small` (high)
- Guess: `void draw_text_small(float x, float y, const char *text)`
- Notes: uses `smallFnt.dat` widths + `GRIM_Font2`
- Ghidra signature: `void grim_draw_text_small(float x, float y, char *text)`
- Suggested signature: `void grim_draw_text_small(float x, float y, const char *text)`
- Call sites: 20 (unique funcs: 9)
- Sample calls: FUN_00401dd0:L760; FUN_00401dd0:L800; perk_selection_screen_update:L3808; demo_purchase_screen_update (`FUN_0040b740`):L6398; demo_purchase_screen_update (`FUN_0040b740`):L6401; demo_purchase_screen_update (`FUN_0040b740`):L6409; demo_purchase_screen_update (`FUN_0040b740`):L6426; demo_purchase_screen_update (`FUN_0040b740`):L6428
- First callsite: FUN_00401dd0 (line 760)


```c
               (((float)*(int *)(param_1 + 0x18) + *(float *)(param_1 + 0x1c)) /
               (float)*(int *)(param_1 + 0x18)) * 0.3);
    (**(code **)(*DAT_0048083c + 0x144))
              (DAT_00471140 - 210.0,
               ((float)*(int *)(param_1 + 0x18) + *(float *)(param_1 + 0x1c)) - 18.0,
```

grim.dll body:

```c
  if ((DAT_10053070 != -1) ||
     (DAT_10053070 = (**(code **)(*in_ECX + 0xc0))(s_GRIM_Font2_10053c3c), DAT_10053070 != -1)) {
    (**(code **)(*in_ECX + 0xc4))(DAT_10053070,0);
    uVar3 = (uint)(byte)(&DAT_1005a570)[(byte)text[iVar5]];
    (**(code **)(*in_ECX + 0x100))
              ((float)(&DAT_1005b2c8)[uVar3 * 2] + 0.001953125,
               (float)(&DAT_1005b2cc)[uVar3 * 2] + 0.001953125,
               ((float)*(byte *)((int)&DAT_1005bad8 + uVar3) * 0.00390625 +
               (float)(&DAT_1005b2c8)[uVar3 * 2] + 0.001953125) - 0.001953125,
               ((float)(&DAT_1005b2cc)[uVar3 * 2] + 0.001953125 + 0.0625) - 0.001953125);
```


## 0x148 — grim_draw_text_small_fmt @ 0x10009980

- Confirmed name: `draw_text_small_fmt`
- Confirmed C++ signature: `void __cdecl IGrim2D::draw_text_small_fmt(float x, float y, char *fmt, ...)`
- Notes: the varargs member uses the cdecl member ABI, so `self` is an explicit
  first stack argument and the function returns with plain `ret`. It passes the
  argument tail beginning after `fmt` to the imported `vsprintf`, writes into
  `grim_printf_buffer_alt`, then dispatches `(x, y, buffer)` through vtable
  slot `0x144`.
- Ghidra signature: `void grim_draw_text_small_fmt(IGrim2D *self, float x, float y, char *fmt, ...)`
- Call sites: 86 (unique funcs: 15)
- Sample calls: demo_trial_overlay_render (`FUN_004047c0`):L3140; demo_trial_overlay_render (`FUN_004047c0`):L3193; demo_trial_overlay_render (`FUN_004047c0`):L3197; demo_trial_overlay_render (`FUN_004047c0`):L3201; demo_trial_overlay_render (`FUN_004047c0`):L3206; demo_trial_overlay_render (`FUN_004047c0`):L3211; demo_trial_overlay_render (`FUN_004047c0`):L3214; demo_trial_overlay_render (`FUN_004047c0`):L3217
- First callsite: demo_trial_overlay_render (`FUN_004047c0`) (line 3140)


```c
  piStack_1ac = DAT_0048083c;
  fStack_1b0 = 5.903715e-39;
  (**(code **)(*DAT_0048083c + 0x148))();
  pcStack_1a0 = (char *)uStack_8;
  fStack_1a4 = 1.0;
```

grim.dll body:

```c
  vsprintf(&DAT_1005b078,in_stack_00000010,&stack0x00000014);
  (**(code **)(*(int *)x + 0x144))(y,fmt,&DAT_1005b078);
```

The recovered VC6.5 source matches all 16 instructions and all 3 masked
references. The reference audit independently identifies both uses of
`grim_printf_buffer_alt` and the `vsprintf` IAT slot at `0x1004c0b4`; no
address-only placeholder is accepted.


## 0x14c — grim_measure_text_width @ 0x100096c0

- Provisional name: `measure_text_width` (high)
- Guess: `int measure_text_width(const char *text)`
- Notes: returns width for small font
- Ghidra signature: `int grim_measure_text_width(char *text)`
- Suggested signature: `int grim_measure_text_width(const char *text)`
- Call sites: 14 (unique funcs: 10)
- Sample calls: tutorial_prompt_dialog (`FUN_00408530`):L5007; bonus_render (`FUN_004295f0`):L18761; FUN_0042fd00:L20753; ui_checkbox_update (`FUN_0043dc80`):L26810; ui_menu_item_update:L27164; ui_button_update (`FUN_0043e830`):L27225; ui_text_input_update (`FUN_0043ecf0`):L27429; ui_list_widget_update (`FUN_0043efc0`):L27482
- First callsite: tutorial_prompt_dialog (`FUN_00408530`) (line 5007)


```c
  float fStack_8;
  
  iVar3 = (**(code **)(*DAT_0048083c + 0x14c))();
  iVar6 = 1;
  fStack_4c = 5.925313e-39;
```

grim.dll body:

```c
  if (text[iVar6] == 10) {
    if (iVar2 < iVar4) {
      iVar2 = iVar4;
    }
    iVar4 = 0;
  }
  else {
    iVar4 = iVar4 + (uint)*(byte *)((int)&DAT_1005bad8 +
                                   (uint)(byte)(&DAT_1005a570)[(byte)text[iVar6]]);
  }
```


## grim.dll — joystick lifecycle @ 0x1000a110..0x1000a36d

- Confirmed callbacks: `grim_joystick_enum_device` (`0x1000a110`) and
  `grim_joystick_configure_axis` (`0x1000a150`)
- Confirmed lifecycle: `grim_joystick_init` (`0x1000a1c0`),
  `grim_joystick_poll` (`0x1000a2b0`), and `grim_joystick_shutdown`
  (`0x1000a330`)
- Confirmed lifecycle signatures: `bool grim_joystick_init(HWND hwnd)`,
  `bool grim_joystick_poll(void)`, and `void grim_joystick_shutdown(void)`

Live Binary Ninja exposes the standard DirectInput source shape. Initialization
creates DirectInput8 when needed, enumerates attached game controllers, and
stops after the first device is created. It installs `c_dfDIJoystick2`, sets
cooperative flags `5`, enumerates device objects, acquires the device, and
performs an initial poll. The axis callback applies `DIPROP_RANGE` by object ID
to every object whose type has an axis bit, using `[-1000, 1000]`; property
failure stops object enumeration. The null-window fallback calls
`GetDesktopWindow` without retaining its result, matching the keyboard and
mouse initializers.

Polling calls `Poll` first. A failure enters an `Acquire` loop only while the
result is `DIERR_INPUTLOST`, then returns false for that frame; a successful
poll reads the full 272-byte `DIJOYSTATE2` and reports the `GetDeviceState`
HRESULT. Shutdown unacquires/releases the device and then releases the parent
DirectInput interface, nulling both globals.

Natural C++ reproduces all 183 instructions across the five functions, with
full prefixes and aggregate references `33/0/0` under the stock VC6.5 profile.
No inline assembly, volatile shaping, fake references, or forced addresses are
used.


## grim.dll — keyboard init helper @ 0x1000a390

- Confirmed name: `grim_keyboard_init`
- Confirmed C++ signature: `bool grim_keyboard_init(HWND hwnd)`
- Notes: lazily creates the DirectInput8 interface and system-keyboard device,
  installs a ten-event buffer, acquires it, and performs an initial poll.

Live Binary Ninja identifies a 272-byte function. The recovered ordinary C++
uses `IID_IDirectInput8A`, `GUID_SysKeyboard`, `c_dfDIKeyboard`, cooperative
flags `0x16`, and a 20-byte device-scoped dword property with value 10. It
reproduces all 89 native instructions, full prefix, and references `18/0/0`.
The unusual null-window fallback is also preserved: `GetDesktopWindow` is
called but its return value is not assigned to the original argument.


## grim.dll — keyboard poll helper @ 0x1000a4a0

- Confirmed name: `grim_keyboard_poll`
- Confirmed C++ signature: `bool grim_keyboard_poll(void)`
- Notes: acquires the DirectInput keyboard, snapshots its 256-byte state, and
  applies the returned 20-byte buffered events.

Live Binary Ninja identifies a 165-byte function. It retries `Acquire` only
for `DIERR_INPUTLOST` and `DIERR_NOTACQUIRED`, ignores the `GetDeviceState`
HRESULT, and gates event application on the `GetDeviceData` HRESULT and a
positive signed count. The native loop trusts both the returned count and each
event offset. Ordinary C++ reproduces all 60 native instructions, full prefix,
and references `9/0/0` with the stock MSVC 6.5 profile.


## grim.dll — keyboard shutdown helper @ 0x1000a550

- Confirmed name: `grim_keyboard_shutdown`
- Confirmed C++ signature: `void grim_keyboard_shutdown(void)`
- Notes: unacquires and releases the keyboard device, nulls it, then releases
  and nulls the parent DirectInput interface.

Live Binary Ninja identifies a 62-byte function with COM vtable calls at
offsets `0x20` (`Unacquire`) and `0x08` (`Release`). Ordinary C++ reproduces
all 19 native instructions, full prefix, and references `5/0/0` with MSVC 6.5.


## grim.dll — mouse init helper @ 0x1000a5a0

- Confirmed name: `grim_mouse_init`
- Confirmed C++ signature: `bool grim_mouse_init(void)`
- Notes: lazily creates the DirectInput8 interface and system-mouse device,
  installs the Mouse2 data format, acquires it, and performs an initial poll.

Live Binary Ninja identifies a 194-byte function using `IID_IDirectInput8A`,
`GUID_SysMouse`, `c_dfDIMouse2`, and cooperative flags 5. Ordinary C++
reproduces all 71 instructions, full prefix, and references `18/0/0`. As in
keyboard initialization, the null-window `GetDesktopWindow` result is ignored.


## grim.dll — mouse shutdown helper @ 0x1000a7d0

- Confirmed name: `grim_mouse_shutdown`
- Confirmed C++ signature: `void grim_mouse_shutdown(void)`
- Notes: unacquires and releases the mouse device, nulls it, then releases and
  nulls the parent DirectInput interface.

Live Binary Ninja identifies the same 62-byte lifecycle shape as keyboard
shutdown, using vtable offsets `0x20` and `0x08`. The natural mouse-specific
source reproduces all 19 instructions, full prefix, and references `5/0/0`.


## grim.dll — coordinate space conversion helper @ 0x10016944

- Provisional name: `grim_convert_vertex_space` (medium)
- Guess: `float *grim_convert_vertex_space(void *this, float *src)`
- Uses `this+0x1058` as a vertex count and writes vec4s to `this+0x104c`.
- Remaps coordinates between three space modes (`this+8` and `this+0x1048`) with explicit
  `[-1, 1]` ↔ `[0, 1]` conversions (`(v + 1) * 0.5` and `v * 2 - 1`).

- Inferred mapping:
  - Mode 1: xyz in `[-1, 1]`, w in `[-1, 1]`.
  - Mode 2: xyz in `[0, 1]`, w in `[-1, 1]`.
  - Mode 3: xyz in `[0, 1]`, w in `[0, 1]`.
  - Mode 1↔2 converts xyz only; any conversion involving mode 3 also remaps w.
- Constructors feeding the mode parameter:
  - Mode 2: vtables `PTR_FUN_1004ccd0`, `PTR_FUN_1004cce0`, `PTR_FUN_1004ccf0`,
    `PTR_FUN_1004cd10`, `PTR_FUN_1004cd20`, `PTR_FUN_1004cd30` (param2 is `0x10` or `0x20`).

  - Mode 3: only `PTR_FUN_1004cd00` (param2 `0x20`).
  - Mode 1: remaining constructors (`PTR_FUN_1004cb6c`..`PTR_FUN_1004cd80`) using
    param2 values `0`, `8`, `0x10`, `0x18`, `0x20`, `0x30`, `0x40`.


## grim.dll — pixel format init helper @ 0x100170f9

- Provisional name: `grim_pixel_format_init` (low)
- Notes:
  - Called by many format-specific constructors; `param_2 >> 3` is stored as bytes-per-pixel
    (`this+0x1068`) and used to derive buffer pitches and sizes.

  - `param_3` is stored at `this+8` and later compared to `this+0x1048` to decide whether
    `grim_convert_vertex_space` should run.

  - `param_1` appears to be a descriptor block: width/height/stride fields copy into
    `this+0x1030..0x1044`, and palette data (if present at `param_1[0x12]`) is expanded into
    a 0x400-byte RGBA table at `this+0x34`.

Constructor mapping (observed):

| Ctor addr | Vtable | bpp param | Mode |
| --- | --- | --- | --- |
| `0x1001a428` | `PTR_FUN_1004cb6c` | `0x18` | 1 |
| `0x1001a53c` | `PTR_FUN_1004cb8c` | `0x20` | 1 |
| `0x1001a558` | `PTR_FUN_1004cb9c` | `0x20` | 1 |
| `0x1001a579` | `PTR_FUN_1004cbac` | `0x10` | 1 |
| `0x1001a781` | `PTR_FUN_1004cbdc` | `0x10` | 1 |
| `0x1001a79d` | `PTR_FUN_1004cbec` | `0x10` | 1 |
| `0x1001aa8a` | `PTR_FUN_1004cc10` | `0x10` | 1 |
| `0x1001aaa6` | `PTR_FUN_1004cc20` | `0x8` | 1 |
| `0x1001aac2` | `PTR_FUN_1004cc30` | `0x8` | 1 |
| `0x1001aade` | `PTR_FUN_1004cc40` | `0x10` | 1 |
| `0x1001aafa` | `PTR_FUN_1004cc50` | `0x10` | 1 |
| `0x1001aba3` | `PTR_FUN_1004cc60` | `0x20` | 1 |
| `0x1001ac2e` | `PTR_FUN_1004cc70` | `0x20` | 1 |
| `0x1001ac4a` | `PTR_FUN_1004caf8` | `0x0` | 1 |
| `0x1001ae3c` | `PTR_FUN_1004cc80` | `0x10` | 1 |
| `0x1001ae74` | `PTR_FUN_1004cc90` | `0x8` | 1 |
| `0x1001ae90` | `PTR_FUN_1004cca0` | `0x8` | 1 |
| `0x1001aeac` | `PTR_FUN_1004ccb0` | `0x10` | 1 |
| `0x1001aee4` | `PTR_FUN_1004ccc0` | `0x8` | 1 |
| `0x1001b001` | `PTR_FUN_1004ccd0` | `0x10` | 2 |
| `0x1001b01d` | `PTR_FUN_1004cce0` | `0x10` | 2 |
| `0x1001b039` | `PTR_FUN_1004ccf0` | `0x20` | 2 |
| `0x1001b055` | `PTR_FUN_1004cd00` | `0x20` | 3 |
| `0x1001b071` | `PTR_FUN_1004cd10` | `0x20` | 2 |
| `0x1001b08d` | `PTR_FUN_1004cd20` | `0x20` | 2 |
| `0x1001b0a9` | `PTR_FUN_1004cd30` | `0x20` | 2 |
| `0x1001b0c5` | `PTR_FUN_1004cd40` | `0x10` | 1 |
| `0x1001b0e1` | `PTR_FUN_1004cd50` | `0x10` | 1 |
| `0x1001b3a6` | `PTR_FUN_1004cd60` | `0x20` | 1 |
| `0x1001b3c2` | `PTR_FUN_1004cd70` | `0x30` | 1 |
| `0x1001b3de` | `PTR_FUN_1004cd80` | `0x40` | 1 |
