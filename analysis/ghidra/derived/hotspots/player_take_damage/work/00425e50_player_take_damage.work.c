/* WORK COPY: player_take_damage */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* player_take_damage @ 00425e50 */

/* applies player damage with perk modifiers, SFX, and retaliation effects. Runtime capture
   (2026-02-06 gameplay_state_capture): dominant sfx_play_panned ids are 0/2/1. */

void __cdecl player_take_damage(int player_index,float damage)

{
  float *player_pos_ptr;
  float fVar1;
  float fVar2;
  bool dodge_triggered;
  int iVar4;
  uint rng_value;
  creature_t *creature_ptr;
  bool was_dead_before_hit;
  float damage_scale;
  float zero_impulse [2];
  
  iVar4 = perk_count_get(perk_id_death_clock);
  if (iVar4 != 0) {
    return;
  }
  iVar4 = perk_count_get(perk_id_tough_reloader);
  if ((iVar4 != 0) && ((char)(&player_state_table)[player_index].reload_active != '\0')) {
    damage = damage * 0.5;
  }
  survival_reward_damage_seen = 1;
  damage_scale = 1.0;
  if (0.0 < (&player_state_table)[player_index].shield_timer) {
    survival_reward_damage_seen = 1;
    return;
  }
  was_dead_before_hit = player_state_table.health <= 0.0;
  iVar4 = perk_count_get(perk_id_thick_skinned);
  if (iVar4 != 0) {
    damage_scale = 0.666;
  }
  dodge_triggered = false;
  iVar4 = perk_count_get(perk_id_ninja);
  if (iVar4 == 0) {
    iVar4 = perk_count_get(perk_id_dodger);
    if ((iVar4 != 0) && (iVar4 = crt_rand(), iVar4 % 5 == 0)) {
      dodge_triggered = true;
      goto LAB_00425fa1;
    }
  }
  else {
    iVar4 = crt_rand();
    if (iVar4 % 3 == 0) {
      dodge_triggered = true;
      goto LAB_00425fa1;
    }
  }
  iVar4 = perk_count_get(perk_id_highlander);
  if (iVar4 == 0) {
    (&player_state_table)[player_index].health =
         (&player_state_table)[player_index].health - damage_scale * damage;
  }
  else {
    iVar4 = crt_rand();
    if (iVar4 % 10 == 0) {
      (&player_state_table)[player_index].health = 0.0;
    }
  }
LAB_00425fa1:
  if (0.0 <= (&player_state_table)[player_index].health) {
    iVar4 = crt_rand();
    sfx_play_panned((float)(iVar4 % 3 + sfx_trooper_inpain_01));
    if (was_dead_before_hit) {
      return;
    }
  }
  else {
    (&player_state_table)[player_index].death_timer =
         (&player_state_table)[player_index].death_timer - frame_dt * 28.0;
    if (was_dead_before_hit) {
      return;
    }
    iVar4 = perk_count_get(perk_id_final_revenge);
    if (iVar4 == 0) {
      rng_value = crt_rand();
      rng_value = rng_value & 0x80000001;
      if ((int)rng_value < 0) {
        rng_value = (rng_value - 1 | 0xfffffffe) + 1;
      }
      sfx_play_panned((float)(rng_value + sfx_trooper_die_01));
    }
    else {
      player_pos_ptr = &(&player_state_table)[player_index].pos_x;
      effect_spawn_explosion_burst(player_pos_ptr,1.8);
      bonus_spawn_guard._0_1_ = 1;
      iVar4 = 0;
      creature_ptr = &creature_pool;
      do {
        if ((((creature_ptr->active != '\0') && (ABS(creature_ptr->pos_x - *player_pos_ptr) <= 512.0)) &&
            (ABS(creature_ptr->pos_y - (&player_state_table)[player_index].pos_y) <= 512.0)) &&
           (fVar1 = creature_ptr->pos_x - *player_pos_ptr,
           fVar2 = creature_ptr->pos_y - (&player_state_table)[player_index].pos_y,
           fVar1 = 512.0 - SQRT(fVar1 * fVar1 + fVar2 * fVar2), 0.0 < fVar1)) {
          zero_impulse[0] = 0.0;
          zero_impulse[1] = 0.0;
          creature_apply_damage(iVar4,fVar1 * 5.0,3,zero_impulse);
        }
        creature_ptr = creature_ptr + 1;
        iVar4 = iVar4 + 1;
      } while ((int)creature_ptr < 0x4aa338);
      bonus_spawn_guard._0_1_ = 0;
      sfx_play_panned(sfx_explosion_large);
      sfx_play_panned(sfx_shockwave);
    }
  }
  if (!dodge_triggered) {
    iVar4 = perk_count_get(perk_id_unstoppable);
    if (iVar4 == 0) {
      iVar4 = crt_rand();
      (&player_state_table)[player_index].heading =
           (float)(iVar4 % 100 + -0x32) * 0.04 + (&player_state_table)[player_index].heading;
      fVar1 = damage * 0.01 + (&player_state_table)[player_index].spread_heat;
      (&player_state_table)[player_index].spread_heat = fVar1;
      if (0.48 < fVar1) {
        (&player_state_table)[player_index].spread_heat = 0.48;
      }
    }
    if (((&player_state_table)[player_index].health <= 20.0) &&
       (iVar4 = crt_rand(), ((byte)iVar4 & 7) == 3)) {
      (&player_state_table)[player_index].low_health_timer = 0.0;
    }
  }
  return;
}
