/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: creature_find_nearest */
/* function_mapped: creature_find_nearest */
/* address: 0x00420040 */
/* byte_range: [645445, 646664) */
/* creature_find_nearest @ 00420040 */

/* returns nearest creature index; uses lifecycle-stage sentinel when exclude_id == -1 */

int creature_find_nearest(float *pos, int exclude_id, float min_dist)

{
  float fVar1;
  float fVar2;
  float fVar3;
  creature_t *pcVar4;
  int iVar5;
  int iVar6;
  
  fVar1 = 1e+06;
  iVar6 = 0;
  if (exclude_id == -1) {
    iVar5 = 0;
    pcVar4 = &creature_pool;
    do {
      if (((pcVar4->active != '\0') && (pcVar4->lifecycle_stage == 16.0)) &&
         (fVar2 = *pos - pcVar4->pos_x, fVar3 = pos[1] - pcVar4->pos_y,
         fVar2 = SQRT(fVar3 * fVar3 + fVar2 * fVar2), fVar2 < fVar1)) {
        iVar6 = iVar5;
        fVar1 = fVar2;
      }
      pcVar4 = pcVar4 + 1;
      iVar5 = iVar5 + 1;
    } while ((int)pcVar4 < 0x4aa338);
    return iVar6;
  }
  iVar5 = 0;
  pcVar4 = &creature_pool;
  do {
    if ((((pcVar4->active != '\0') && (iVar5 != exclude_id)) &&
        (fVar2 = *pos - pcVar4->pos_x, fVar3 = pos[1] - pcVar4->pos_y,
        fVar2 = SQRT(fVar2 * fVar2 + fVar3 * fVar3), min_dist < fVar2)) && (fVar2 < fVar1)) {
      iVar6 = iVar5;
      fVar1 = fVar2;
    }
    pcVar4 = pcVar4 + 1;
    iVar5 = iVar5 + 1;
  } while ((int)pcVar4 < 0x4aa338);
  return iVar6;
}
