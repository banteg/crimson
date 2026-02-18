/* WORK COPY: player_apply_move_with_spawn_avoidance */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* player_apply_move_with_spawn_avoidance @ 0041e290 */

/* applies movement delta (scaled by alternate-weapon perk) and resolves collisions with creature
   spawn slots */

void __cdecl player_apply_move_with_spawn_avoidance(int player_index,float *pos,float *delta)

{
  float fVar1;
  float fVar2;
  creature_t *spawn_owner_ptr;
  float collision_radius;
  float fVar5;
  int alternate_weapon_perk_count;
  creature_spawn_slot_t *spawn_slot_ptr;
  
  alternate_weapon_perk_count = perk_count_get(perk_id_alternate_weapon);
  if (alternate_weapon_perk_count != 0) {
    *delta = *delta * 0.8;
    delta[1] = delta[1] * 0.8;
  }
  spawn_slot_ptr = &creature_spawn_slot_table;
  *pos = *pos + *delta;
  pos[1] = delta[1] + pos[1];
  do {
    spawn_owner_ptr = spawn_slot_ptr->owner;
    if ((spawn_owner_ptr != (creature_t *)0x0) &&
       (collision_radius = (spawn_owner_ptr->size + (&player_state_table)[player_index].size) * 0.33333334,
       fVar1 = spawn_owner_ptr->pos_x - *pos, fVar2 = spawn_owner_ptr->pos_y - pos[1],
       SQRT(fVar1 * fVar1 + fVar2 * fVar2) <= collision_radius)) {
      *pos = *pos - *delta;
      fVar1 = pos[1];
      fVar2 = delta[1];
      pos[1] = fVar1 - fVar2;
      fVar5 = spawn_owner_ptr->pos_x - *pos;
      fVar1 = spawn_owner_ptr->pos_y - (fVar1 - fVar2);
      fVar2 = *pos + *delta;
      if (collision_radius < SQRT(fVar5 * fVar5 + fVar1 * fVar1)) {
        *pos = fVar2;
        fVar1 = spawn_owner_ptr->pos_x - fVar2;
        fVar5 = spawn_owner_ptr->pos_y - pos[1];
        if (SQRT(fVar1 * fVar1 + fVar5 * fVar5) <= collision_radius) {
          *pos = fVar2 - *delta;
          fVar1 = delta[1] + pos[1];
          pos[1] = fVar1;
          fVar5 = spawn_owner_ptr->pos_x - *pos;
          fVar2 = spawn_owner_ptr->pos_y - fVar1;
          if (SQRT(fVar5 * fVar5 + fVar2 * fVar2) <= collision_radius) {
            pos[1] = fVar1 - delta[1];
          }
        }
      }
      else {
        *pos = fVar2;
        pos[1] = delta[1] + pos[1];
      }
    }
    spawn_slot_ptr = spawn_slot_ptr + 1;
  } while ((int)spawn_slot_ptr < 0x4852d0);
  return;
}
