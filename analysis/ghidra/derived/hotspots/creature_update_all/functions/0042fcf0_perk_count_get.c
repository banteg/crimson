/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: perk_count_get */
/* function_mapped: perk_count_get */
/* address: 0x0042fcf0 */
/* byte_range: [949026, 949203) */
/* perk_count_get @ 0042fcf0 */

/* returns perk count from DAT_00490968 */

int perk_count_get(int perk_id)

{
  return player_state_table.perk_counts[perk_id];
}



/*
