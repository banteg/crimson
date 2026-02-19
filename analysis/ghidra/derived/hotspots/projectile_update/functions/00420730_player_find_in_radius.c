/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: player_find_in_radius */
/* function_mapped: player_find_in_radius */
/* address: 0x00420730 */
/* byte_range: [656243, 657082) */
/* player_find_in_radius @ 00420730 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* returns a player index in range, skipping owner_id (-1/-2/-3 -> player 0/1/2) */

int player_find_in_radius(int owner_id, float *pos, float radius)

{
  int iVar1;
  float *pfVar2;
  
  iVar1 = 0;
  if (0 < _config_player_count) {
    pfVar2 = &player_state_table.health;
    do {
      if (iVar1 != -1 - owner_id) {
        if (0.0 < *pfVar2) {
          if (SQRT((pfVar2[-3] - pos[1]) * (pfVar2[-3] - pos[1]) +
                   (pfVar2[-4] - *pos) * (pfVar2[-4] - *pos)) - radius <
              pfVar2[4] * 0.14285715 + 3.0) {
            return iVar1;
          }
        }
      }
      iVar1 = iVar1 + 1;
      pfVar2 = pfVar2 + 0xd8;
    } while (iVar1 < _config_player_count);
  }
  return -1;
}
