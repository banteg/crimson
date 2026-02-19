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
  float blast_delta_x;
  float blast_delta_y;
  float blast_falloff;
  float next_spread_heat;
  bool dodge_triggered;
  int perk_count;
  int rand_roll;
  int creature_idx;
  uint rng_value;
  creature_t *creature_ptr;
  bool was_dead_before_hit;
  float damage_scale;
  float zero_impulse [2];
  
  /* Hard pre-gates: death-clock immunity and tough-reloader mitigation. */
  perk_count = perk_count_get(perk_id_death_clock);
  if (perk_count != 0) {
    return;
  }
  perk_count = perk_count_get(perk_id_tough_reloader);
  if ((perk_count != 0) && ((char)(&player_state_table)[player_index].reload_active != '\0')) {
    damage = damage * 0.5;
  }
  survival_reward_damage_seen = 1;
  damage_scale = 1.0;
  /* Shielded hits are consumed here and skip health/dodge/death branches. */
  if (0.0 < (&player_state_table)[player_index].shield_timer) {
    survival_reward_damage_seen = 1;
    return;
  }
  was_dead_before_hit = player_state_table.health <= 0.0;
  perk_count = perk_count_get(perk_id_thick_skinned);
  if (perk_count != 0) {
    damage_scale = 0.666;
  }
  /* Dodge evaluation: ninja and dodger can short-circuit direct health subtraction. */
  dodge_triggered = false;
  perk_count = perk_count_get(perk_id_ninja);
  if (perk_count == 0) {
    perk_count = perk_count_get(perk_id_dodger);
    if ((perk_count != 0) && (rand_roll = crt_rand(), rand_roll % 5 == 0)) {
      dodge_triggered = true;
      goto LAB_00425fa1;
    }
  }
  else {
    rand_roll = crt_rand();
    if (rand_roll % 3 == 0) {
      dodge_triggered = true;
      goto LAB_00425fa1;
    }
  }
  /* Apply incoming damage or highlander one-shot roulette. */
  perk_count = perk_count_get(perk_id_highlander);
  if (perk_count == 0) {
    (&player_state_table)[player_index].health =
         (&player_state_table)[player_index].health - damage_scale * damage;
  }
  else {
    rand_roll = crt_rand();
    if (rand_roll % 10 == 0) {
      (&player_state_table)[player_index].health = 0.0;
    }
  }
LAB_00425fa1:
  /* Post-hit branch: alive pain reaction vs lethal branch and final-revenge resolution. */
  if (0.0 <= (&player_state_table)[player_index].health) {
    rand_roll = crt_rand();
    sfx_play_panned((float)(rand_roll % 3 + sfx_trooper_inpain_01));
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
    perk_count = perk_count_get(perk_id_final_revenge);
    if (perk_count == 0) {
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
      creature_idx = 0;
      creature_ptr = &creature_pool;
      do {
        if ((((creature_ptr->active != '\0') && (ABS(creature_ptr->pos_x - *player_pos_ptr) <= 512.0)) &&
            (ABS(creature_ptr->pos_y - (&player_state_table)[player_index].pos_y) <= 512.0)) &&
           (blast_delta_x = creature_ptr->pos_x - *player_pos_ptr,
           blast_delta_y = creature_ptr->pos_y - (&player_state_table)[player_index].pos_y,
           blast_falloff = 512.0 - SQRT(blast_delta_x * blast_delta_x + blast_delta_y * blast_delta_y),
           0.0 < blast_falloff)) {
          zero_impulse[0] = 0.0;
          zero_impulse[1] = 0.0;
          creature_apply_damage(creature_idx,blast_falloff * 5.0,3,zero_impulse);
        }
        creature_ptr = creature_ptr + 1;
        creature_idx = creature_idx + 1;
      } while ((int)creature_ptr < 0x4aa338);
      bonus_spawn_guard._0_1_ = 0;
      sfx_play_panned(sfx_explosion_large);
      sfx_play_panned(sfx_shockwave);
    }
  }
  /* Non-dodged hits can add heading/spread penalties and low-health bleed trigger. */
  if (!dodge_triggered) {
    perk_count = perk_count_get(perk_id_unstoppable);
    if (perk_count == 0) {
      rand_roll = crt_rand();
      (&player_state_table)[player_index].heading =
           (float)(rand_roll % 100 + -0x32) * 0.04 + (&player_state_table)[player_index].heading;
      next_spread_heat = damage * 0.01 + (&player_state_table)[player_index].spread_heat;
      (&player_state_table)[player_index].spread_heat = next_spread_heat;
      if (0.48 < next_spread_heat) {
        (&player_state_table)[player_index].spread_heat = 0.48;
      }
    }
    if (((&player_state_table)[player_index].health <= 20.0) &&
       (rand_roll = crt_rand(), ((byte)rand_roll & 7) == 3)) {
      (&player_state_table)[player_index].low_health_timer = 0.0;
    }
  }
  return;
}
