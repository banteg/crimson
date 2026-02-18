/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: weapon_pick_random_available */
/* function_mapped: weapon_pick_random_available */
/* address: 0x00452cd0 */
/* byte_range: [1793048, 1793685) */
/* weapon_pick_random_available @ 00452cd0 */

/* selects a random weapon id that is marked available */

int weapon_pick_random_available(void)

{
  int iVar1;
  uint uVar2;
  
  do {
    iVar1 = crt_rand();
    iVar1 = iVar1 % 0x21 + 1;
    if (weapon_usage_counts[iVar1] != 0) {
      uVar2 = crt_rand();
      if ((uVar2 & 1) == 0) {
        iVar1 = crt_rand();
        iVar1 = iVar1 % 0x21 + 1;
      }
    }
  } while (((&weapon_table)[iVar1].unlocked == '\0') ||
          ((((config_game_mode == GAME_MODE_QUEST && (quest_stage_major == 5)) &&
            (quest_stage_minor == 10)) && (iVar1 == 0x17))));
  return iVar1;
}



/*
