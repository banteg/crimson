/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: player_take_damage */
/* function_mapped: player_take_damage */
/* address: 0x00425e50 */
/* byte_range: [757036, 761012) */
/* player_take_damage @ 00425e50 */

/* applies player damage with perk modifiers, SFX, and retaliation effects. Runtime capture
   (2026-02-06 gameplay_state_capture): dominant sfx_play_panned ids are 0/2/1. */

void __cdecl player_take_damage(int player_index,float damage)

{
  float *pos;
  float fVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  uint uVar5;
  creature_t *pcVar6;
  bool bVar7;
  float local_c;
  float local_8 [2];
  
  iVar4 = perk_count_get(perk_id_death_clock);
  if (iVar4 != 0) {
    return;
  }
  iVar4 = perk_count_get(perk_id_tough_reloader);
  if ((iVar4 != 0) && ((char)(&player_state_table)[player_index].reload_active != '\0')) {
    damage = damage * 0.5;
  }
  survival_reward_damage_seen = 1;
  local_c = 1.0;
  if (0.0 < (&player_state_table)[player_index].shield_timer) {
    survival_reward_damage_seen = 1;
    return;
  }
  bVar7 = player_state_table.health <= 0.0;
  iVar4 = perk_count_get(perk_id_thick_skinned);
  if (iVar4 != 0) {
    local_c = 0.666;
  }
  bVar3 = false;
  iVar4 = perk_count_get(perk_id_ninja);
  if (iVar4 == 0) {
    iVar4 = perk_count_get(perk_id_dodger);
    if ((iVar4 != 0) && (iVar4 = crt_rand(), iVar4 % 5 == 0)) {
      bVar3 = true;
      goto LAB_00425fa1;
    }
  }
  else {
    iVar4 = crt_rand();
    if (iVar4 % 3 == 0) {
      bVar3 = true;
      goto LAB_00425fa1;
    }
  }
  iVar4 = perk_count_get(perk_id_highlander);
  if (iVar4 == 0) {
    (&player_state_table)[player_index].health =
         (&player_state_table)[player_index].health - local_c * damage;
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
    if (bVar7) {
      return;
    }
  }
  else {
    (&player_state_table)[player_index].death_timer =
         (&player_state_table)[player_index].death_timer - frame_dt * 28.0;
    if (bVar7) {
      return;
    }
    iVar4 = perk_count_get(perk_id_final_revenge);
    if (iVar4 == 0) {
      uVar5 = crt_rand();
      uVar5 = uVar5 & 0x80000001;
      if ((int)uVar5 < 0) {
        uVar5 = (uVar5 - 1 | 0xfffffffe) + 1;
      }
      sfx_play_panned((float)(uVar5 + sfx_trooper_die_01));
    }
    else {
      pos = &(&player_state_table)[player_index].pos_x;
      effect_spawn_explosion_burst(pos,1.8);
      bonus_spawn_guard._0_1_ = 1;
      iVar4 = 0;
      pcVar6 = &creature_pool;
      do {
        if ((((pcVar6->active != '\0') && (ABS(pcVar6->pos_x - *pos) <= 512.0)) &&
            (ABS(pcVar6->pos_y - (&player_state_table)[player_index].pos_y) <= 512.0)) &&
           (fVar1 = pcVar6->pos_x - *pos,
           fVar2 = pcVar6->pos_y - (&player_state_table)[player_index].pos_y,
           fVar1 = 512.0 - SQRT(fVar1 * fVar1 + fVar2 * fVar2), 0.0 < fVar1)) {
          local_8[0] = 0.0;
          local_8[1] = 0.0;
          creature_apply_damage(iVar4,fVar1 * 5.0,3,local_8);
        }
        pcVar6 = pcVar6 + 1;
        iVar4 = iVar4 + 1;
      } while ((int)pcVar6 < 0x4aa338);
      bonus_spawn_guard._0_1_ = 0;
      sfx_play_panned(sfx_explosion_large);
      sfx_play_panned(sfx_shockwave);
    }
  }
  if (!bVar3) {
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
