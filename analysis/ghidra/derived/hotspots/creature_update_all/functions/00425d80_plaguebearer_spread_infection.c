/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: plaguebearer_spread_infection */
/* function_mapped: plaguebearer_spread_infection */
/* address: 0x00425d80 */
/* byte_range: [755682, 756748) */
/* plaguebearer_spread_infection @ 00425d80 */

/* propagates collision_flag infection between nearby creatures (radius 45, hp < 150) */

int plaguebearer_spread_infection(int creature_id)

{
  float fVar1;
  float fVar2;
  creature_t *pcVar3;
  int iVar4;
  
  iVar4 = 0;
  pcVar3 = &creature_pool;
  do {
    if (pcVar3->active != '\0') {
      fVar1 = pcVar3->pos_x - (&creature_pool)[creature_id].pos_x;
      fVar2 = pcVar3->pos_y - (&creature_pool)[creature_id].pos_y;
      if (SQRT(fVar2 * fVar2 + fVar1 * fVar1) < 45.0) {
        if (((&creature_pool)[iVar4].collision_flag != '\0') &&
           ((&creature_pool)[creature_id].health < 150.0)) {
          (&creature_pool)[creature_id].collision_flag = '\x01';
        }
        if (((&creature_pool)[creature_id].collision_flag != '\0') &&
           ((&creature_pool)[iVar4].health < 150.0)) {
          (&creature_pool)[iVar4].collision_flag = '\x01';
        }
        return iVar4;
      }
    }
    pcVar3 = pcVar3 + 1;
    iVar4 = iVar4 + 1;
  } while ((int)pcVar3 < 0x4aa338);
  return 0;
}
