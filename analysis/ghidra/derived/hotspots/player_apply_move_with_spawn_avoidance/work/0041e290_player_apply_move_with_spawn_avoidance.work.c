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
  float dx_to_owner;
  float dy_to_owner;
  float candidate_x;
  float candidate_y;
  float delta_y;
  creature_t *spawn_owner_ptr;
  float collision_radius;
  int alternate_weapon_perk_count;
  creature_spawn_slot_t *spawn_slot_ptr;
  
  /* Alternate-weapon perk dampens move delta before any collision checks. */
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
    /* Overlap test against spawn owner using reduced combined radius. */
    if ((spawn_owner_ptr != (creature_t *)0x0) &&
       (collision_radius = (spawn_owner_ptr->size + (&player_state_table)[player_index].size) * 0.33333334,
       dx_to_owner = spawn_owner_ptr->pos_x - *pos, dy_to_owner = spawn_owner_ptr->pos_y - pos[1],
       SQRT(dx_to_owner * dx_to_owner + dy_to_owner * dy_to_owner) <= collision_radius)) {
      /* Collision resolution tries rollback then axis-reapply fallbacks. */
      *pos = *pos - *delta;
      delta_y = delta[1];
      candidate_y = pos[1] - delta_y;
      pos[1] = candidate_y;
      dx_to_owner = spawn_owner_ptr->pos_x - *pos;
      dy_to_owner = spawn_owner_ptr->pos_y - candidate_y;
      candidate_x = *pos + *delta;
      if (collision_radius < SQRT(dx_to_owner * dx_to_owner + dy_to_owner * dy_to_owner)) {
        *pos = candidate_x;
        dx_to_owner = spawn_owner_ptr->pos_x - candidate_x;
        dy_to_owner = spawn_owner_ptr->pos_y - pos[1];
        if (SQRT(dx_to_owner * dx_to_owner + dy_to_owner * dy_to_owner) <= collision_radius) {
          *pos = candidate_x - *delta;
          candidate_y = delta_y + pos[1];
          pos[1] = candidate_y;
          dx_to_owner = spawn_owner_ptr->pos_x - *pos;
          dy_to_owner = spawn_owner_ptr->pos_y - candidate_y;
          if (SQRT(dx_to_owner * dx_to_owner + dy_to_owner * dy_to_owner) <= collision_radius) {
            pos[1] = candidate_y - delta_y;
          }
        }
      }
      else {
        /* Legacy fallback: restore the original full move when probes fail. */
        *pos = candidate_x;
        pos[1] = delta_y + pos[1];
      }
    }
    spawn_slot_ptr = spawn_slot_ptr + 1;
  } while ((int)spawn_slot_ptr < 0x4852d0);
  return;
}
