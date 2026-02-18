/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: player_apply_move_with_spawn_avoidance */
/* function_mapped: player_apply_move_with_spawn_avoidance */
/* address: 0x0041e290 */
/* byte_range: [605752, 607569) */
/* player_apply_move_with_spawn_avoidance @ 0041e290 */

/* applies movement delta (scaled by alternate-weapon perk) and resolves collisions with creature
   spawn slots */

void __cdecl player_apply_move_with_spawn_avoidance(int player_index,float *pos,float *delta)

{
  float fVar1;
  float fVar2;
  creature_t *pcVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  creature_spawn_slot_t *pcVar7;
  
  iVar6 = perk_count_get(perk_id_alternate_weapon);
  if (iVar6 != 0) {
    *delta = *delta * 0.8;
    delta[1] = delta[1] * 0.8;
  }
  pcVar7 = &creature_spawn_slot_table;
  *pos = *pos + *delta;
  pos[1] = delta[1] + pos[1];
  do {
    pcVar3 = pcVar7->owner;
    if ((pcVar3 != (creature_t *)0x0) &&
       (fVar4 = (pcVar3->size + (&player_state_table)[player_index].size) * 0.33333334,
       fVar1 = pcVar3->pos_x - *pos, fVar2 = pcVar3->pos_y - pos[1],
       SQRT(fVar1 * fVar1 + fVar2 * fVar2) <= fVar4)) {
      *pos = *pos - *delta;
      fVar1 = pos[1];
      fVar2 = delta[1];
      pos[1] = fVar1 - fVar2;
      fVar5 = pcVar3->pos_x - *pos;
      fVar1 = pcVar3->pos_y - (fVar1 - fVar2);
      fVar2 = *pos + *delta;
      if (fVar4 < SQRT(fVar5 * fVar5 + fVar1 * fVar1)) {
        *pos = fVar2;
        fVar1 = pcVar3->pos_x - fVar2;
        fVar5 = pcVar3->pos_y - pos[1];
        if (SQRT(fVar1 * fVar1 + fVar5 * fVar5) <= fVar4) {
          *pos = fVar2 - *delta;
          fVar1 = delta[1] + pos[1];
          pos[1] = fVar1;
          fVar5 = pcVar3->pos_x - *pos;
          fVar2 = pcVar3->pos_y - fVar1;
          if (SQRT(fVar5 * fVar5 + fVar2 * fVar2) <= fVar4) {
            pos[1] = fVar1 - delta[1];
          }
        }
      }
      else {
        *pos = fVar2;
        pos[1] = delta[1] + pos[1];
      }
    }
    pcVar7 = pcVar7 + 1;
  } while ((int)pcVar7 < 0x4852d0);
  return;
}
