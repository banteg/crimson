# Grim2D vtable evidence appendix

This appendix collects one concrete callsite snippet per vtable offset,

plus the current grim.dll entry signature and address from

`source/decompiled/grim2d_vtable_map.json`.



## 0x10 — FUN_10005d40 @ 0x10005d40
- Ghidra signature: `undefined FUN_10005d40()`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_0042c450:L19443
- First callsite: FUN_0042c450 (line 21580)

```c
  FUN_00401870(&DAT_0047eea0,(byte *)s____invoking_grim_config_00474aa0);
  FUN_00402860(0x47eea0);
  cVar1 = (**(code **)(*DAT_0048083c + 0x10))();
  DAT_004aaf45 = 1;
  if (cVar1 == '\0') {
```


## 0x14 — FUN_10005eb0 @ 0x10005eb0
- Ghidra signature: `undefined4 FUN_10005eb0(int * param_1)`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_0042c450:L19504
- First callsite: FUN_0042c450 (line 21641)

```c
  FUN_00401870(&DAT_0047eea0,(byte *)s____using_joystick_00474998);
  FUN_00401870(&DAT_0047eea0,(byte *)s____initiating_Grim_system_0047497c);
  cVar1 = (**(code **)(*DAT_0048083c + 0x14))();
  if (cVar1 == '\0') {
    FUN_00401870(&DAT_0047eea0,(byte *)s_Critical_failure__00474968);
```


## 0x18 — FUN_10005ff0 @ 0x10005ff0
- Ghidra signature: `undefined FUN_10005ff0()`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_0042c450:L19599
- First callsite: FUN_0042c450 (line 21736)

```c
  FUN_0043d110();
  FUN_00401870(&DAT_0047eea0,(byte *)s_Shutdown_Grim___00474848);
  (**(code **)(*DAT_0048083c + 0x18))();
  FUN_00402860(0x47eea0);
  (**(code **)*DAT_0048083c)();
```


## 0x1c — FUN_10006020 @ 0x10006020
- Ghidra signature: `undefined FUN_10006020()`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_0042c450:L19581
- First callsite: FUN_0042c450 (line 21718)

```c
    puVar9 = puVar10;
  } while ((int)puVar10 < 0x4805c0);
  (**(code **)(*DAT_0048083c + 0x1c))();
  LVar11 = RegCreateKeyExA((HKEY)0x80000001,s_Software_10tons_entertainment_Cr_00474604,0,(LPSTR)0x0
                           ,0,0xf003f,(LPSECURITY_ATTRIBUTES)0x0,&pHStack_5c4,(LPDWORD)0x0);
```


## 0x20 — FUN_10006580 @ 0x10006580
- Provisional name: `set_render_state` (high)
- Guess: `void set_render_state(uint32_t state, uint32_t value)`
- Notes: D3D-style SetRenderState usage
- Ghidra signature: `undefined FUN_10006580()`
- Call sites: 206 (unique funcs: 35)
- Sample calls: FUN_00401dd0:L754; FUN_00401dd0:L755; FUN_00401dd0:L847; FUN_00402d50:L1438; FUN_00402d50:L1460; FUN_004047c0:L3147; FUN_00405160:L3373; FUN_00405160:L3377
- First callsite: FUN_00401dd0 (line 754)

```c
    (**(code **)(*DAT_0048083c + 0xd0))(&fStack_4c,DAT_00471140,0x40800000,&puStack_44);
    (**(code **)(*DAT_0048083c + 0xf0))();
    (**(code **)(*DAT_0048083c + 0x20))(0x15,2);
    (**(code **)(*DAT_0048083c + 0x20))(0x18,0x3f000000);
    (**(code **)(*DAT_0048083c + 0x114))
```


## 0x24 — grim_get_config_var @ 0x10006c30
- Provisional name: `get_config_var` (high)
- Guess: `void get_config_var(uint32_t *out, int id)`
- Notes: grim.dll writes 4 dwords from a config table for `id` in `0..0x7f`
- Ghidra signature: `void grim_get_config_var(unsigned int *out, int id)`
- Call sites: 17 (unique funcs: 4)
- Sample calls: FUN_0041ec60:L13402; FUN_0041ec60:L13410; FUN_0041ec60:L13413; FUN_0041ec60:L13415; FUN_0041ec60:L13417; FUN_0041ec60:L13419; FUN_0042c450:L19456; FUN_0042c450:L19458
- First callsite: FUN_0041ec60 (line 15539)

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


## 0x28 — FUN_10006ca0 @ 0x10006ca0
- Ghidra signature: `undefined FUN_10006ca0()`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_0042c450:L19509
- First callsite: FUN_0042c450 (line 21646)

```c
    uType = 0;
    pcVar6 = s_Crimsonland__00474958;
    lpText = (LPCSTR)(**(code **)(*DAT_0048083c + 0x28))();
    MessageBoxA((HWND)0x0,lpText,pcVar6,uType);
    (**(code **)*DAT_0048083c)();
```


## 0x2c — FUN_10006cb0 @ 0x10006cb0
- Ghidra signature: `undefined FUN_10006cb0()`
- Call sites: 5 (unique funcs: 3)
- Sample calls: FUN_00417b80:L9215; FUN_004181b0:L9452; FUN_0042c450:L19534; FUN_0042c450:L19538; FUN_0042c450:L19547
- First callsite: FUN_00417b80 (line 11352)

```c
  fStack_98 = 0.24705882;
  uStack_9c = 0x417c89;
  (**(code **)(*DAT_0048083c + 0x2c))();
  iVar3 = iStack_70;
  uStack_9c = 0;
```


## 0x30 — FUN_10006d50 @ 0x10006d50
- Ghidra signature: `undefined FUN_10006d50()`
- Call sites: 6 (unique funcs: 3)
- Sample calls: FUN_00417b80:L9209; FUN_00417b80:L9333; FUN_004181b0:L9446; FUN_004181b0:L9563; FUN_00427920:L17949; FUN_00427920:L18035
- First callsite: FUN_00417b80 (line 11346)

```c
  fStack_88 = DAT_0048f530;
  iStack_8c = 0x417c6a;
  (**(code **)(*DAT_0048083c + 0x30))();
  iStack_8c = 0x3f800000;
  uStack_90 = 0x3dc8c8c9;
```


## 0x44 — FUN_10007320 @ 0x10007320
- Provisional name: `is_key_down` (high)
- Guess: `bool is_key_down(uint32_t key)`
- Notes: Ctrl/arrow keycodes
- Ghidra signature: `undefined FUN_10007320()`
- Call sites: 6 (unique funcs: 2)
- Sample calls: FUN_00401a40:L509; FUN_00401a40:L511; FUN_00401a40:L526; FUN_00401a40:L528; FUN_0043d830:L26638; FUN_0043d830:L26639
- First callsite: FUN_00401a40 (line 509)

```c
              (float10)*(int *)((int)param_1 + 0x18));
  FUN_00401060();
  cVar2 = (**(code **)(*DAT_0048083c + 0x44))(0x1d);
  if (cVar2 == '\0') {
    cVar2 = (**(code **)(*DAT_0048083c + 0x44))(0x9d);
```


## 0x48 — FUN_10007390 @ 0x10007390
- Provisional name: `was_key_pressed` (high)
- Guess: `bool was_key_pressed(uint32_t key)`
- Notes: edge-triggered key checks
- Ghidra signature: `uint FUN_10007390(uint param_1)`
- Call sites: 39 (unique funcs: 16)
- Sample calls: FUN_00401a40:L514; FUN_00401a40:L522; FUN_00401a40:L531; FUN_00401a40:L543; FUN_00401a40:L547; FUN_00401a40:L551; FUN_00401a40:L574; FUN_00401a40:L578
- First callsite: FUN_00401a40 (line 514)

```c
    if (cVar2 != '\0') goto LAB_00401ac4;
LAB_00401add:
    cVar2 = (**(code **)(*DAT_0048083c + 0x48))(200);
    if (cVar2 != '\0') {
      *(int *)((int)param_1 + 0x14) = *(int *)((int)param_1 + 0x14) + 1;
```


## 0x4c — grim_flush_input @ 0x10007330
- Ghidra signature: `undefined grim_flush_input()`
- Call sites: 12 (unique funcs: 10)
- Sample calls: FUN_004018b0:L346; FUN_004070e0:L4357; FUN_00408530:L5083; FUN_00408530:L5104; FUN_0040aab0:L5879; FUN_0040ffc0:L7055; FUN_004107e0:L7326; FUN_00410d20:L7702
- First callsite: FUN_004018b0 (line 346)

```c
  *(undefined1 *)((int)this + 0x28) = param_1;
  DAT_0047f4d4 = param_1;
  (**(code **)(*DAT_0048083c + 0x4c))();
  return;
}
```


## 0x50 — FUN_10005c40 @ 0x10005c40
- Provisional name: `get_key_char` (high)
- Guess: `int get_key_char(void)`
- Notes: console text input
- Ghidra signature: `undefined FUN_10005c40()`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_00401060:L33
- First callsite: FUN_00401060 (line 33)

```c
  int iVar1;
  
  iVar1 = (**(code **)(*DAT_0048083c + 0x50))();
  if (DAT_0047f4d4 != '\0') {
    if ((iVar1 != 0) && (DAT_0047ea58 == '\0')) {
```


## 0x54 — grim_set_key_char_buffer @ 0x10005c20
- Ghidra signature: `undefined grim_set_key_char_buffer()`
- Call sites: 2 (unique funcs: 2)
- Sample calls: FUN_0042c450:L19559; FUN_0043ecf0:L27394
- First callsite: FUN_0042c450 (line 21696)

```c
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  }
  (**(code **)(*DAT_0048083c + 0x54))(&DAT_004aacd8,&DAT_004aaedc,uVar14);
  FUN_0041ec60();
  puVar13 = &DAT_00490be0;
```


## 0x58 — FUN_10007410 @ 0x10007410
- Provisional name: `is_mouse_button_down` (medium)
- Guess: `bool is_mouse_button_down(int button)`
- Notes: button 0 used
- Ghidra signature: `undefined FUN_10007410()`
- Call sites: 4 (unique funcs: 3)
- Sample calls: FUN_0040aab0:L5953; FUN_00446030:L29260; FUN_00446030:L29278; FUN_004460f0:L29306
- First callsite: FUN_0040aab0 (line 6340)

```c
    }
  }
  cVar3 = (**(code **)(*DAT_0048083c + 0x58))(0);
  DAT_004808b9 = cVar3 != '\0';
  FUN_0040a320();
```


## 0x60 — FUN_10007560 @ 0x10007560
- Provisional name: `get_mouse_wheel_delta` (high)
- Guess: `float get_mouse_wheel_delta(void)`
- Notes: positive/negative scroll used to change selection
- Ghidra signature: `undefined FUN_10007560()`
- Call sites: 2 (unique funcs: 1)
- Sample calls: FUN_0043def0:L26948; FUN_0043def0:L26952
- First callsite: FUN_0043def0 (line 29084)

```c
    (**(code **)(*DAT_0048083c + 0xd0))(&stack0xffffffb0,0x3f800000,fVar1,&local_30);
  }
  fVar8 = (float10)(**(code **)(*DAT_0048083c + 0x60))();
  if ((float10)0.0 < fVar8) {
    *param_2 = *param_2 - 1.0;
```


## 0x80 — FUN_10006fe0 @ 0x10006fe0
- Provisional name: `is_key_active` (medium)
- Guess: `bool is_key_active(int key)`
- Notes: called with key mapping entries
- Ghidra signature: `uint FUN_10006fe0(void * this, int param_1)`
- Call sites: 6 (unique funcs: 4)
- Sample calls: FUN_0040aab0:L5929; FUN_00446000:L29232; FUN_00446030:L29266; FUN_00446030:L29282; FUN_004460f0:L29308; FUN_004460f0:L29310
- First callsite: FUN_00408990 (line 5277)

```c
    if (DAT_00486fd8 == 1) {
      puVar6 = &DAT_00490be0;
      while ((((cVar2 = (**(code **)(*DAT_0048083c + 0x80))(puVar6[-1]), cVar2 == '\0' &&
               (cVar2 = (**(code **)(*DAT_0048083c + 0x80))(*puVar6), cVar2 == '\0')) &&
              ((cVar2 = (**(code **)(*DAT_0048083c + 0x80))(puVar6[1]), cVar2 == '\0' &&
```


## 0x84 — FUN_100071b0 @ 0x100071b0
- Provisional name: `get_config_float` (medium)
- Guess: `float get_config_float(int id)`
- Notes: IDs 0x13f..0x155
- Ghidra signature: `undefined FUN_100071b0()`
- Call sites: 6 (unique funcs: 1)
- Sample calls: FUN_00448b50:L30229; FUN_00448b50:L30233; FUN_00448b50:L30237; FUN_00448b50:L30241; FUN_00448b50:L30245; FUN_00448b50:L30249
- First callsite: FUN_004136b0 (line 9703)

```c
    }
    if (iVar10 == 3) {
      fVar19 = (float10)(**(code **)(*DAT_0048083c + 0x84))((&DAT_00490c0c)[iVar6 * 0xd8]);
      pfVar12 = (float *)(&DAT_00490c08)[iVar6 * 0xd8];
      fVar20 = (float10)(**(code **)(*DAT_0048083c + 0x84))();
```


## 0xa4 — grim_get_joystick_pov @ 0x100075b0
- Ghidra signature: `undefined grim_get_joystick_pov()`
- Call sites: 2 (unique funcs: 2)
- Sample calls: FUN_0041e8d0:L13164; FUN_0041e8f0:L13177
- First callsite: FUN_0041e8d0 (line 15301)

```c
  int iVar1;
  
  iVar1 = (**(code **)(*DAT_0048083c + 0xa4))(0);
  return iVar1 == DAT_004804fc;
}
```


## 0xac — FUN_100075d0 @ 0x100075d0
- Provisional name: `create_texture` (medium)
- Guess: `bool create_texture(const char *name, int width, int height)`
- Notes: used for terrain texture
- Ghidra signature: `uint FUN_100075d0(undefined4 param_1, undefined4 param_2, undefined4 param_3)`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_0042a9f0:L19084
- First callsite: FUN_0042a9f0 (line 21221)

```c
  if (DAT_004871c8 == '\0') {
    lVar5 = __ftol();
    cVar3 = (**(code **)(*DAT_0048083c + 0xac))(s_ground_004740c4,(int)lVar5,(int)lVar5);
    fVar2 = DAT_004803b8;
    if (cVar3 == '\0') {
```


## 0xb4 — FUN_100076e0 @ 0x100076e0
- Provisional name: `load_texture` (high)
- Guess: `bool load_texture(const char *name, const char *path)`
- Notes: name + filename
- Ghidra signature: `undefined FUN_100076e0()`
- Call sites: 3 (unique funcs: 3)
- Sample calls: FUN_00419d00:L10132; FUN_0042a670:L18970; FUN_0042a700:L18996
- First callsite: FUN_00419d00 (line 12269)

```c
    FUN_00401870(&DAT_0047eea0,(byte *)s_Loading_uiElement__s_004737b4);
  }
  (**(code **)(*DAT_0048083c + 0xb4))(local_100,param_2);
  iVar2 = (**(code **)(*DAT_0048083c + 0xc0))(&stack0xfffffef8);
  *(int *)(iStack_8 + 0xe0) = iVar2;
```


## 0xc0 — FUN_10007740 @ 0x10007740
- Provisional name: `get_texture_handle` (high)
- Guess: `int get_texture_handle(const char *name)`
- Notes: returns -1 on missing
- Ghidra signature: `undefined FUN_10007740()`
- Call sites: 22 (unique funcs: 8)
- Sample calls: FUN_0040b740:L6362; FUN_0040b740:L6374; FUN_00412dc0:L8687; FUN_00412dc0:L8698; FUN_00412dc0:L8710; FUN_00412dc0:L8722; FUN_00412dc0:L8734; FUN_00412dc0:L8750
- First callsite: FUN_0040b740 (line 6749)

```c
    pcStack_f4 = s_mockup_00472964;
    pcStack_f8 = (char *)0x40bb08;
    pcStack_f8 = (char *)(**(code **)(*DAT_0048083c + 0xc0))();
    fStack_fc = 3.58732e-43;
    iStack_104 = DAT_00480508 / 2 + -0x8c;
```


## 0xc4 — FUN_10007830 @ 0x10007830
- Provisional name: `bind_texture` (medium)
- Guess: `void bind_texture(int handle, int stage)`
- Notes: often called with handle,0
- Ghidra signature: `undefined FUN_10007830(int param_1, undefined4 param_2)`
- Call sites: 66 (unique funcs: 22)
- Sample calls: FUN_004061e0:L3882; FUN_004061e0:L3891; FUN_0040a510:L5641; FUN_0040a510:L5663; FUN_00417ae0:L9120; FUN_00417b80:L9220; FUN_00417b80:L9265; FUN_00417b80:L9296
- First callsite: FUN_004061e0 (line 3882)

```c
  iVar2 = 1;
  (**(code **)(*DAT_0048083c + 0x20))(0x15,1);
  (**(code **)(*DAT_0048083c + 0xc4))(DAT_0048f7c8,0);
  iVar1 = 0;
  (**(code **)(*DAT_0048083c + 0x100))(0,0,0x3f800000,0x3f800000);
```


## 0xc8 — grim_draw_fullscreen_quad @ 0x10007870
- Ghidra signature: `undefined grim_draw_fullscreen_quad()`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_004188a0:L9637
- First callsite: not found in decompiled output


## 0xcc — FUN_100079b0 @ 0x100079b0
- Ghidra signature: `undefined FUN_100079b0()`
- Call sites: 2 (unique funcs: 2)
- Sample calls: FUN_00405960:L3696; FUN_00406af0:L4120
- First callsite: FUN_00405960 (line 3696)

```c
  FUN_004295f0();
  if (0.0 < DAT_00487264) {
    (**(code **)(*DAT_0048083c + 0xcc))(0,0,0,DAT_00487264);
  }
  return;
```


## 0xd0 — grim_draw_rect_filled @ 0x100078e0
- Provisional name: `draw_rect_filled` (medium)
- Guess: `void draw_rect_filled(const float *xy, float w, float h)`
- Notes: used for UI panel backgrounds before setting color
- Ghidra signature: `undefined grim_draw_rect_filled()`
- Call sites: 24 (unique funcs: 14)
- Sample calls: FUN_00401dd0:L740; FUN_00401dd0:L752; FUN_00402d50:L1448; FUN_004047c0:L3096; FUN_00405160:L3369; FUN_00408530:L5029; FUN_0040b740:L6476; FUN_0040b740:L6480
- First callsite: FUN_00401dd0 (line 740)

```c
    fStack_48 = (float)*(int *)(param_1 + 0x18);
    fStack_4c = DAT_00471140;
    (**(code **)(*DAT_0048083c + 0xd0))(&stack0xffffffd4);
    (**(code **)(*DAT_0048083c + 0x114))
              (0x3dcccccd,0x3f19999a,0x3f800000,
```


## 0xd4 — grim_draw_rect_outline @ 0x10008f10
- Provisional name: `draw_rect_outline` (medium)
- Guess: `void draw_rect_outline(const float *xy, float w, float h)`
- Notes: used for UI framing with explicit width/height
- Ghidra signature: `undefined grim_draw_rect_outline()`
- Call sites: 12 (unique funcs: 11)
- Sample calls: FUN_00402d50:L1454; FUN_004047c0:L3107; FUN_00405160:L3372; FUN_00408530:L5031; FUN_00410d20:L7694; FUN_0043e5e0:L27177; FUN_0043ecf0:L27413; FUN_0043ecf0:L27448
- First callsite: FUN_00402d50 (line 1454)

```c
  fStack_4c = (float)(DAT_00480504 / 2 + -0x6e);
  fStack_48 = (float)(DAT_00480508 / 2 + -0x1e);
  (**(code **)(*DAT_0048083c + 0xd4))(&fStack_4c,0x435c0000,0x42700000);
  iVar1 = *DAT_0048083c;
  iVar2 = (**(code **)(iVar1 + 0x14c))
```


## 0xd8 — grim_draw_circle_filled @ 0x10007b90
- Ghidra signature: `undefined grim_draw_circle_filled()`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_0040a510:L5640
- First callsite: FUN_0040a510 (line 6027)

```c
          DAT_004802a8 = _DAT_00484fc8 + (float)(&DAT_00490900)[DAT_004aaf0c * 0xd8];
          DAT_004802ac = _DAT_00484fcc + (float)(&DAT_00490904)[DAT_004aaf0c * 0xd8];
          (**(code **)(*DAT_0048083c + 0xd8))(DAT_004802a8,DAT_004802ac,uVar7);
          (**(code **)(*DAT_0048083c + 0xc4))(DAT_0048f7e8,0);
          (**(code **)(*DAT_0048083c + 0x100))(0x3f000000,0,0x3f000000,0x3f800000);
```


## 0xdc — grim_draw_circle_outline @ 0x10007d40
- Ghidra signature: `undefined grim_draw_circle_outline()`
- Call sites: 1 (unique funcs: 1)
- Sample calls: FUN_0040a510:L5644
- First callsite: FUN_0040a510 (line 6031)

```c
          (**(code **)(*DAT_0048083c + 0x100))(0x3f000000,0,0x3f000000,0x3f800000);
          (**(code **)(*DAT_0048083c + 0x114))(0x3f800000,0x3f800000,0x3f800000,0x3f0ccccd);
          (**(code **)(*DAT_0048083c + 0xdc))(DAT_004802a8,DAT_004802ac,uVar7);
          (**(code **)(*DAT_0048083c + 0x114))(0x3f800000,0x3f333333,0x3dcccccd,0x3f4ccccd);
          DAT_004802a8 = _DAT_00484fc8 + (float)(&DAT_00490900)[DAT_004aaf0c * 0xd8];
```


## 0xe8 — FUN_10007ac0 @ 0x10007ac0
- Ghidra signature: `undefined FUN_10007ac0()`
- Call sites: 79 (unique funcs: 23)
- Sample calls: FUN_004061e0:L3887; FUN_004061e0:L3892; FUN_0040a510:L5683; FUN_00417b80:L9228; FUN_00417b80:L9271; FUN_00417b80:L9299; FUN_004181b0:L9464; FUN_004181b0:L9506
- First callsite: FUN_004061e0 (line 3887)

```c
  (**(code **)(*DAT_0048083c + 0x114))(0x3f800000,0x3f800000,0x3f800000,iVar2);
  (**(code **)(*DAT_0048083c + 0xfc))(0);
  (**(code **)(*DAT_0048083c + 0xe8))();
  (**(code **)(*DAT_0048083c + 0x11c))((float)iVar2,(float)iVar1,0x42000000,0x42000000);
  (**(code **)(*DAT_0048083c + 0xf0))();
```


## 0xf0 — FUN_10007b20 @ 0x10007b20
- Ghidra signature: `undefined FUN_10007b20()`
- Call sites: 86 (unique funcs: 28)
- Sample calls: FUN_00401dd0:L753; FUN_004047c0:L3134; FUN_004061e0:L3889; FUN_004061e0:L3895; FUN_0040a510:L5702; FUN_0040b740:L6346; FUN_00417ae0:L9125; FUN_00417b80:L9261
- First callsite: FUN_00401dd0 (line 753)

```c
    fStack_48 = fStack_48 - 4.0;
    (**(code **)(*DAT_0048083c + 0xd0))(&fStack_4c,DAT_00471140,0x40800000,&puStack_44);
    (**(code **)(*DAT_0048083c + 0xf0))();
    (**(code **)(*DAT_0048083c + 0x20))(0x15,2);
    (**(code **)(*DAT_0048083c + 0x20))(0x18,0x3f000000);
```


## 0xfc — FUN_10007f30 @ 0x10007f30
- Provisional name: `set_rotation` (medium)
- Guess: `void set_rotation(float radians)`
- Notes: rotation angle before draw
- Ghidra signature: `undefined FUN_10007f30()`
- Call sites: 65 (unique funcs: 17)
- Sample calls: FUN_00401dd0:L736; FUN_004061e0:L3886; FUN_004061e0:L3893; FUN_0040a510:L5662; FUN_0040b740:L6325; FUN_004188a0:L9599; FUN_004188a0:L9630; FUN_00418b60:L9718
- First callsite: FUN_00401dd0 (line 736)

```c
    uStack_40 = 0;
    puStack_44 = (undefined1 *)0x401e8d;
    (**(code **)(*DAT_0048083c + 0xfc))();
    puStack_44 = &stack0xffffffdc;
    fStack_48 = (float)*(int *)(param_1 + 0x18);
```


## 0x100 — FUN_10008350 @ 0x10008350
- Provisional name: `set_uv` (high)
- Guess: `void set_uv(float u0, float v0, float u1, float v1)`
- Notes: sets all 4 UV pairs (u0/v0/u1/v1) used by draw calls
- Ghidra signature: `void grim_set_uv(float u0, float v0, float u1, float v1)`
- Call sites: 59 (unique funcs: 23)
- Sample calls: FUN_004047c0:L3126; FUN_004061e0:L3884; FUN_0040a510:L5635; FUN_0040a510:L5642; FUN_0040a510:L5664; FUN_0040b740:L6331; FUN_00417ae0:L9121; FUN_00417b80:L9206
- First callsite: FUN_004047c0 (line 3126)

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


## 0x104 — FUN_10008230 @ 0x10008230
- Provisional name: `set_atlas_frame` (high)
- Guess: `void set_atlas_frame(int atlas_size, int frame)`
- Notes: atlas size (cells per side) + frame index
- Ghidra signature: `void grim_set_atlas_frame(int atlas_size, int frame)`
- Call sites: 25 (unique funcs: 6)
- Sample calls: FUN_00418b60:L9704; FUN_00418b60:L9715; FUN_00418b60:L9759; FUN_00418b60:L9770; FUN_00418b60:L9819; FUN_00418b60:L9830; FUN_0041a8b0:L10630; FUN_00422c70:L16482
- First callsite: FUN_00418b60 (line 11841)

```c
              iVar2 = iVar2 + 0x20;
            }
            (**(code **)(*DAT_0048083c + 0x104))(8,iVar2);
          }
          else {
```


## 0x108 — FUN_100082c0 @ 0x100082c0
- Provisional name: `set_sub_rect` (medium)
- Guess: `void set_sub_rect(int atlas_size, int width, int height, int frame)`
- Notes: atlas grid sub-rect; `atlas_size` indexes a pointer table with entries at 2/4/8/16; explicit call uses `(8, 2, 1, frame<<1)`
- Ghidra signature: `void grim_set_sub_rect(int atlas_size, int width, int height, int frame)`
- Call sites: 6 (unique funcs: 3)
- Sample calls: FUN_0041aed0:L10950; FUN_0041aed0:L10961; FUN_0041aed0:L10964; FUN_0041aed0:L11488; FUN_004295f0:L18733; FUN_004413a0:L27845
- First callsite: FUN_0041aed0 (line 13087)

```c
      fStack_f8 = 1.12104e-44;
      fStack_fc = 6.033625e-39;
      (**(code **)(*DAT_0048083c + 0x108))();
      fStack_fc = 32.0;
      fStack_100 = 64.0;
```

Explicit parameterized call (FUN_004295f0):

```c
        (**(code **)(*DAT_0048083c + 0x108))
                  (8,2,1,(&DAT_004d7a90)[(int)pfVar7[4] * 0x1f] << 1);
        (**(code **)(*DAT_0048083c + 0x11c))();
```

Atlas pointer table setup (grim.dll init):

```c
  puVar9 = &DAT_1005bc78;
  for (iVar7 = 0x10; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  _DAT_1005bc80 = &DAT_1005d388;
  _DAT_1005bc88 = &DAT_1005cb08;
  _DAT_1005bc98 = &DAT_1005c908;
  _DAT_1005bcb8 = &DAT_1005a678;
```


## 0x10c — FUN_100083a0 @ 0x100083a0
- Ghidra signature: `undefined FUN_100083a0()`
- Notes: called as four consecutive `set_uv_point` calls (indices 0..3) to override per-corner UVs; u=0.625, v in {0, 0.25}
- Call sites: 4 (unique funcs: 1)
- Sample calls: FUN_00422c70:L16721; FUN_00422c70:L16725; FUN_00422c70:L16728; FUN_00422c70:L16729
- First callsite: FUN_00422c70 (line 18858)

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


## 0x110 — FUN_10008040 @ 0x10008040
- Provisional name: `set_color_ptr` (medium)
- Guess: `void set_color_ptr(float *rgba)`
- Notes: pointer to RGBA floats (0..1); values are clamped before call
- Ghidra signature: `void grim_set_color_ptr(float *rgba)`
- Call sites: 20 (unique funcs: 10)
- Sample calls: FUN_0040ffc0:L7098; FUN_0040ffc0:L7171; FUN_00410d20:L7782; FUN_00410d20:L7851; FUN_00418b60:L9717; FUN_00418b60:L9772; FUN_00418b60:L9832; FUN_00418b60:L9894
- First callsite: FUN_0040ffc0 (line 7485)

```c
            (**(code **)(*DAT_0048083c + 0x104))(8,iVar2);
          }
          (**(code **)(*DAT_0048083c + 0x110))(&fStack_58);
          (**(code **)(*DAT_0048083c + 0xfc))(pfVar5[7] - 1.5707964);
          (**(code **)(*DAT_0048083c + 0x11c))
                    ((_DAT_00484fc8 + pfVar5[1]) - fVar10,(_DAT_00484fcc + pfVar5[2]) - fVar10,
                     pfVar5[9] * 1.07,pfVar5[9] * 1.07);
```

Clamped RGBA example (FUN_00446030):

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


## 0x114 — FUN_10007f90 @ 0x10007f90
- Provisional name: `set_color` (high)
- Guess: `void set_color(float r, float g, float b, float a)`
- Notes: RGBA floats
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


## 0x118 — FUN_100081c0 @ 0x100081c0
- Notes: packs RGBA into color slot `index` (0..3); draw_quad reads slots 0..3
- Ghidra signature: `void grim_set_color_slot(int index, float r, float g, float b, float a)`
- Call sites: 12 (unique funcs: 2)
- Sample calls: FUN_0040b740:L6302; FUN_0040b740:L6308; FUN_0040b740:L6315; FUN_0040b740:L6322; FUN_00422c70:L15993; FUN_00422c70:L16000; FUN_00422c70:L16068; FUN_00422c70:L16075
- First callsite: FUN_0040b740 (line 6689)

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


## 0x11c — FUN_10008b10 @ 0x10008b10
- Provisional name: `draw_quad` (high)
- Guess: `void draw_quad(float x, float y, float w, float h)`
- Notes: core draw call; uses per-corner color slots + UV array
- Ghidra signature: `void grim_draw_quad(float x, float y, float w, float h)`
- Call sites: 100 (unique funcs: 21)
- Sample calls: FUN_004047c0:L3132; FUN_004061e0:L3888; FUN_004061e0:L3894; FUN_0040a510:L5701; FUN_0040b740:L6344; FUN_00417ae0:L9124; FUN_004188a0:L9613; FUN_00418b60:L9720
- First callsite: FUN_004047c0 (line 3132)

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


## 0x120 — FUN_10008720 @ 0x10008720
- Notes: wrapper around `draw_quad` using `xy` pointer
- Ghidra signature: `void grim_draw_quad_xy(float *xy, float w, float h)`
- Call sites: 6 (unique funcs: 2)
- Sample calls: FUN_00417b80:L9255; FUN_00417b80:L9289; FUN_00417b80:L9317; FUN_004181b0:L9491; FUN_004181b0:L9524; FUN_004181b0:L9547
- First callsite: FUN_00417b80 (line 11392)

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


## 0x128 — grim_submit_vertices_transform @ 0x100085c0
- Ghidra signature: `void grim_submit_vertices_transform(float * verts, int count, float * offset, float * matrix)`
- Notes: copies `count * 0x1c` bytes (7-float stride) into the batch, applies 2x2 matrix + offset per vertex
- Call sites: 5 (unique funcs: 1)
- Sample calls: FUN_00446c40:L29980; FUN_00446c40:L29985; FUN_00446c40:L29986; FUN_00446c40:L30065; FUN_00446c40:L30107
- First callsite: FUN_00446c40 (line 32116)

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


## 0x12c — grim_submit_vertices_offset @ 0x10008680
- Ghidra signature: `void grim_submit_vertices_offset(float * verts, int count, float * offset)`
- Notes: decompiler emits decimal offset `+ 300` (0x12c)
- Call sites: 4 (unique funcs: 1)
- Sample calls: FUN_00446c40:L30035; FUN_00446c40:L30042; FUN_00446c40:L30045; FUN_00446c40:L30074
- First callsite: FUN_00446c40 (line 32196)

```c
      (**(code **)(*DAT_0048083c + 300))();
      if (*(int *)(param_1 + 0x120) == 8) {
        (**(code **)(*DAT_0048083c + 300))();
```


## 0x130 — grim_submit_vertices_offset_color @ 0x10008430
- Ghidra signature: `void grim_submit_vertices_offset_color(float * verts, int count, float * offset, float * color)`
- Notes: writes `DAT_10059e34[4] = *color;` (packed ARGB)
- Call sites: 3 (unique funcs: 1)
- Sample calls: FUN_00446c40:L30006; FUN_00446c40:L30014; FUN_00446c40:L30018
- First callsite: FUN_00446c40 (line 32142)

```c
        fStack_6c = fStack_64 + *(float *)(param_1 + 0xc);
        pppcStack_90 = (char ***)0x446fe3;
        (**(code **)(*DAT_0048083c + 0x130))();
        if (*(int *)(param_1 + 0x120) == 8) {
          pfStack_74 = (float *)(*(float *)(param_1 + 0x1c) + 7.0);
```


## 0x134 — grim_submit_vertices_transform_color @ 0x100084e0
- Ghidra signature: `void grim_submit_vertices_transform_color(float * verts, int count, float * offset, float * matrix, float * color)`
- Notes: applies 2x2 matrix + offset, then overwrites vertex color from `*color`
- Call sites: 5 (unique funcs: 2)
- Sample calls: FUN_0042e820:L20025; FUN_0042e820:L20053; FUN_00446c40:L29953; FUN_00446c40:L29959; FUN_00446c40:L29962
- First callsite: FUN_0042e820 (line 22162)

```c
      pfStack_60 = &fStack_40;
      pfStack_64 = &fStack_48;
      (**(code **)(*DAT_0048083c + 0x134))(puVar2 + 5,4);
    }
    puVar2 = puVar2 + 0x2f;
```


## 0x138 — grim_draw_quad_points @ 0x10009080
- Ghidra signature: `undefined grim_draw_quad_points()`
- Call sites: 4 (unique funcs: 1)
- Sample calls: FUN_00422c70:L16048; FUN_00422c70:L16204; FUN_00422c70:L16755; FUN_00422c70:L16768
- First callsite: FUN_00422c70 (line 18185)

```c
          fStack_224 = (float)((float10)(float)(fVar9 * (float10)512.0 + (float10)fVar31) + fVar8 +
                              fVar11 * (float10)1.1);
          (**(code **)(*DAT_0048083c + 0x138))();
          fStack_244 = 6.07815e-39;
          (**(code **)(*DAT_0048083c + 0xf0))();
```


## 0x13c — FUN_100092b0 @ 0x100092b0
- Provisional name: `draw_text_mono` (medium)
- Guess: `void draw_text_mono(float x, float y, const char *text)`
- Notes: fixed 16px grid; special-cases a few extended codes (0xA7, 0xE4, 0xE5, 0xF6)
- Ghidra signature: `undefined FUN_100092b0()`
- Call sites: 5 (unique funcs: 3)
- Sample calls: FUN_00401dd0:L781; FUN_00401dd0:L804; FUN_00401dd0:L843; FUN_0040b740:L6491; FUN_0041aed0:L11263
- First callsite: FUN_00401dd0 (line 781)

```c
    }
    else {
      (**(code **)(*DAT_0048083c + 0x13c))
                (0x41200000,(float)((iVar1 + 1) * 0x10) + *(float *)(param_1 + 0x1c),&DAT_004712c0);
      iVar3 = *DAT_0048083c;
```


## 0x140 — FUN_10009940 @ 0x10009940
- Ghidra signature: `undefined FUN_10009940()`
- Call sites: 3 (unique funcs: 3)
- Sample calls: FUN_00405160:L3374; FUN_00406350:L3950; FUN_0041aed0:L11281
- First callsite: FUN_00405160 (line 3374)

```c
  (**(code **)(*DAT_0048083c + 0xd4))(param_1,0x44000000,0x43800000);
  (**(code **)(*DAT_0048083c + 0x20))(0x18,0x3f4ccccd);
  (**(code **)(*DAT_0048083c + 0x140))
            (DAT_0048083c,*param_1 + 16.0,param_1[1] + 16.0,s_key_info_00471ffc);
  (**(code **)(*DAT_0048083c + 0x114))(0x3f800000,0x3f800000,0x3f800000,uVar4);
```


## 0x144 — FUN_10009730 @ 0x10009730
- Provisional name: `draw_text_small` (medium)
- Guess: `void draw_text_small(float x, float y, const char *text)`
- Notes: uses `smallFnt.dat` widths + `GRIM_Font2`
- Ghidra signature: `undefined FUN_10009730()`
- Call sites: 20 (unique funcs: 9)
- Sample calls: FUN_00401dd0:L760; FUN_00401dd0:L800; FUN_00405be0:L3808; FUN_0040b740:L6398; FUN_0040b740:L6401; FUN_0040b740:L6409; FUN_0040b740:L6426; FUN_0040b740:L6428
- First callsite: FUN_00401dd0 (line 760)

```c
               (((float)*(int *)(param_1 + 0x18) + *(float *)(param_1 + 0x1c)) /
               (float)*(int *)(param_1 + 0x18)) * 0.3);
    (**(code **)(*DAT_0048083c + 0x144))
              (DAT_00471140 - 210.0,
               ((float)*(int *)(param_1 + 0x18) + *(float *)(param_1 + 0x1c)) - 18.0,
```


## 0x148 — grim_draw_text_small_fmt @ 0x10009980
- Provisional name: `draw_text_small_fmt` (medium)
- Guess: `void draw_text_small_fmt(float x, float y, const char *fmt, ...)`
- Notes: `vsprintf` wrapper that forwards to `0x144` (small font draw)
- Ghidra signature: `void grim_draw_text_small_fmt(float x, float y, char *fmt)`
- Call sites: 86 (unique funcs: 15)
- Sample calls: FUN_004047c0:L3140; FUN_004047c0:L3193; FUN_004047c0:L3197; FUN_004047c0:L3201; FUN_004047c0:L3206; FUN_004047c0:L3211; FUN_004047c0:L3214; FUN_004047c0:L3217
- First callsite: FUN_004047c0 (line 3140)

```c
  piStack_1ac = DAT_0048083c;
  fStack_1b0 = 5.903715e-39;
  (**(code **)(*DAT_0048083c + 0x148))();
  pcStack_1a0 = (char *)uStack_8;
  fStack_1a4 = 1.0;
```


## 0x14c — FUN_100096c0 @ 0x100096c0
- Provisional name: `measure_text_width` (medium)
- Guess: `int measure_text_width(const char *text)`
- Notes: returns width for small font
- Ghidra signature: `int FUN_100096c0(char * param_1)`
- Call sites: 14 (unique funcs: 10)
- Sample calls: FUN_00408530:L5007; FUN_004295f0:L18761; FUN_0042fd00:L20753; FUN_0043dc80:L26810; FUN_0043e5e0:L27164; FUN_0043e830:L27225; FUN_0043ecf0:L27429; FUN_0043efc0:L27482
- First callsite: FUN_00408530 (line 5007)

```c
  float fStack_8;
  
  iVar3 = (**(code **)(*DAT_0048083c + 0x14c))();
  iVar6 = 1;
  fStack_4c = 5.925313e-39;
```
