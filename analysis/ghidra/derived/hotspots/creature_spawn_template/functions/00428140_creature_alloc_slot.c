/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: creature_alloc_slot */
/* function_mapped: creature_alloc_slot */
/* address: 0x00428140 */
/* byte_range: [802354, 803292) */
/* creature_alloc_slot @ 00428140 */

/* finds a free creature entry in DAT_0049bf38 and seeds defaults */

int creature_alloc_slot(void)

{
  creature_t *pcVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = 0;
  pcVar1 = &creature_pool;
  do {
    if (pcVar1->active == '\0') {
      (&creature_pool)[iVar3].flags = 0;
      uVar2 = crt_rand();
      (&creature_pool)[iVar3].phase_seed = (float)(uVar2 & 0x17f);
      pcVar1 = &creature_pool + iVar3;
      pcVar1->_pad3[0] = '\0';
      pcVar1->_pad3[1] = '\0';
      pcVar1->_pad3[2] = '\0';
      pcVar1->_pad3[3] = '\0';
      (&creature_pool)[iVar3].anim_phase = 0.0;
      creature_spawned_count = creature_spawned_count + 1;
      return iVar3;
    }
    pcVar1 = pcVar1 + 1;
    iVar3 = iVar3 + 1;
  } while ((int)pcVar1 < 0x4aa338);
  if (*(float *)((int)cv_verbose + 0xc) != 0.0) {
    console_printf(&console_log_queue,s_No_free_creatures_to_spawn__00473e6c);
  }
  return 0x180;
}
