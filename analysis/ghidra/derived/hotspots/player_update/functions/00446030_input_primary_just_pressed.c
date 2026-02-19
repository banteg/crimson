/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: input_primary_just_pressed */
/* function_mapped: input_primary_just_pressed */
/* address: 0x00446030 */
/* byte_range: [1454086, 1455638) */
/* input_primary_just_pressed @ 00446030 */

/* edge-detect primary action (mouse button 0 or per-player fire key DAT_00490bec) */

int input_primary_just_pressed(void)

{
  undefined4 in_EAX;
  uint3 uVar2;
  int iVar1;
  uint3 extraout_var;
  int *piVar3;
  bool bVar4;
  
  uVar2 = (uint3)((uint)in_EAX >> 8);
  if (console_open_flag == '\0') {
    if (input_primary_latch == '\0') {
      iVar1 = (*grim_interface_ptr->vtable->grim_is_mouse_button_down)(0);
      if ((char)iVar1 != '\0') {
        input_primary_latch = '\x01';
      }
      piVar3 = &player_state_table.input.fire_key;
      do {
        iVar1 = (*grim_interface_ptr->vtable->grim_is_key_active)(*piVar3);
        if ((char)iVar1 != '\0') {
          input_primary_latch = '\x01';
        }
        piVar3 = piVar3 + 0xd8;
      } while ((int)piVar3 < 0x4912ac);
      uVar2 = (uint3)((uint)iVar1 >> 8);
      if (input_primary_latch != '\0') {
        return CONCAT31(uVar2,1);
      }
    }
    else {
      iVar1 = (*grim_interface_ptr->vtable->grim_is_mouse_button_down)(0);
      bVar4 = (char)iVar1 == '\0';
      piVar3 = &player_state_table.input.fire_key;
      do {
        iVar1 = (*grim_interface_ptr->vtable->grim_is_key_active)(*piVar3);
        extraout_var = (uint3)((uint)iVar1 >> 8);
        if ((char)iVar1 != '\0') {
          bVar4 = false;
        }
        piVar3 = piVar3 + 0xd8;
      } while ((int)piVar3 < 0x4912ac);
      uVar2 = extraout_var;
      if (bVar4) {
        input_primary_latch = '\0';
      }
    }
  }
  return (uint)uVar2 << 8;
}



/*
