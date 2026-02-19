/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: input_aim_pov_right_active */
/* function_mapped: input_aim_pov_right_active */
/* address: 0x0041e8f0 */
/* byte_range: [609193, 609562) */
/* input_aim_pov_right_active @ 0041e8f0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* returns true when joystick POV matches the configured aim-right direction */

bool input_aim_pov_right_active(void)

{
  int iVar1;
  
  iVar1 = (*grim_interface_ptr->vtable->grim_get_joystick_pov)(0);
  return iVar1 == _DAT_004804f8;
}
