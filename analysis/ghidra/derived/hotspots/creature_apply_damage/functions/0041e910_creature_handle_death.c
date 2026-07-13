/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: creature_handle_death */
/* function_mapped: creature_handle_death */
/* address: 0x0041e910 */
/* byte_range: [609566, 615008) */
/* creature_handle_death @ 0041e910 */

/* death handler: bonus spawns, split-on-death, score, and cleanup */

void creature_handle_death(int creature_id, bool keep_corpse)

{
  float *pos;
  creature_t *pcVar1;
  uchar uVar2;
  uchar uVar3;
  uchar uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  creature_t *pcVar8;
  creature_t *pcVar9;
  longlong lVar10;
  
  pcVar1 = &creature_pool + creature_id;
  if (((&creature_pool)[creature_id].flags & 0x400U) != 0) {
    bonus_spawn_at(&(&creature_pool)[creature_id].pos_x,
                   (int)(short)(&creature_pool)[creature_id].link_index,
                   (int)*(short *)((int)&(&creature_pool)[creature_id].link_index + 2));
  }
  if (survival_recent_death_count < 6) {
    if (survival_recent_death_count < 3) {
      (&survival_recent_death_pos)[survival_recent_death_count].x =
           (&creature_pool)[creature_id].pos_x;
      (&survival_recent_death_pos)[survival_recent_death_count].y =
           (&creature_pool)[creature_id].pos_y;
    }
    survival_recent_death_count = survival_recent_death_count + 1;
    if (survival_recent_death_count == 3) {
      survival_reward_fire_seen = 0;
      survival_reward_handout_enabled = 0;
    }
  }
  if (pcVar1->active != '\0') {
    if (((&creature_pool)[creature_id].flags & 4) != 0) {
      (&creature_spawn_slot_table)[(&creature_pool)[creature_id].link_index].owner =
           (creature_t *)0x0;
    }
    if ((((&creature_pool)[creature_id].flags & 8) != 0) &&
       (35.0 < (&creature_pool)[creature_id].size)) {
      iVar5 = creature_alloc_slot();
      pcVar8 = pcVar1;
      pcVar9 = &creature_pool + iVar5;
      for (iVar7 = 0x26; iVar7 != 0; iVar7 = iVar7 + -1) {
        uVar2 = pcVar8->_pad0[0];
        uVar3 = pcVar8->_pad0[1];
        uVar4 = pcVar8->_pad0[2];
        pcVar9->active = pcVar8->active;
        pcVar9->_pad0[0] = uVar2;
        pcVar9->_pad0[1] = uVar3;
        pcVar9->_pad0[2] = uVar4;
        pcVar8 = (creature_t *)&pcVar8->phase_seed;
        pcVar9 = (creature_t *)&pcVar9->phase_seed;
      }
      uVar6 = crt_rand();
      (&creature_pool)[iVar5].phase_seed = (float)(uVar6 & 0xff);
      (&creature_pool)[iVar5].heading = (&creature_pool)[creature_id].heading - 1.5707964;
      (&creature_pool)[iVar5].health = (&creature_pool)[creature_id].max_health * 0.25;
      (&creature_pool)[iVar5].reward_value = (&creature_pool)[iVar5].reward_value * 0.6666667;
      (&creature_pool)[iVar5].size = (&creature_pool)[iVar5].size - 8.0;
      (&creature_pool)[iVar5].move_speed = (&creature_pool)[iVar5].move_speed + 0.1;
      (&creature_pool)[iVar5].contact_damage = (&creature_pool)[iVar5].contact_damage * 0.7;
      (&creature_pool)[iVar5].lifecycle_stage = 16.0;
      iVar5 = creature_alloc_slot();
      pcVar8 = pcVar1;
      pcVar9 = &creature_pool + iVar5;
      for (iVar7 = 0x26; iVar7 != 0; iVar7 = iVar7 + -1) {
        uVar2 = pcVar8->_pad0[0];
        uVar3 = pcVar8->_pad0[1];
        uVar4 = pcVar8->_pad0[2];
        pcVar9->active = pcVar8->active;
        pcVar9->_pad0[0] = uVar2;
        pcVar9->_pad0[1] = uVar3;
        pcVar9->_pad0[2] = uVar4;
        pcVar8 = (creature_t *)&pcVar8->phase_seed;
        pcVar9 = (creature_t *)&pcVar9->phase_seed;
      }
      uVar6 = crt_rand();
      (&creature_pool)[iVar5].phase_seed = (float)(uVar6 & 0xff);
      (&creature_pool)[iVar5].heading = (&creature_pool)[creature_id].heading + 1.5707964;
      (&creature_pool)[iVar5].health = (&creature_pool)[creature_id].max_health * 0.25;
      (&creature_pool)[iVar5].size = (&creature_pool)[iVar5].size - 8.0;
      (&creature_pool)[iVar5].move_speed = (&creature_pool)[iVar5].move_speed + 0.1;
      (&creature_pool)[iVar5].reward_value = (&creature_pool)[iVar5].reward_value * 0.6666667;
      (&creature_pool)[iVar5].lifecycle_stage = 16.0;
      (&creature_pool)[iVar5].contact_damage = (&creature_pool)[iVar5].contact_damage * 0.7;
      effect_spawn_burst(&(&creature_pool)[creature_id].pos_x,8);
    }
    if (keep_corpse) {
      (&creature_pool)[creature_id].lifecycle_stage =
           (&creature_pool)[creature_id].lifecycle_stage - frame_dt;
    }
    else {
      pcVar1->active = '\0';
    }
    iVar5 = perk_id_bloody_mess_quick_learner;
    if (player_state_table.perk_counts[perk_id_bloody_mess_quick_learner] < 1) {
      lVar10 = __ftol();
      player_state_table.experience = (int)lVar10;
    }
    else {
      lVar10 = __ftol();
      player_state_table.experience = player_state_table.experience + (int)lVar10;
    }
    if (0.0 < bonus_double_xp_timer) {
      if (player_state_table.perk_counts[iVar5] < 1) {
        lVar10 = __ftol();
        player_state_table.experience = (int)lVar10;
      }
      else {
        lVar10 = __ftol();
        player_state_table.experience = player_state_table.experience + (int)lVar10;
      }
    }
    if ((char)bonus_spawn_guard == '\0') {
      bonus_try_spawn_on_kill(&(&creature_pool)[creature_id].pos_x);
    }
    if (0.0 < bonus_freeze_timer) {
      pos = &(&creature_pool)[creature_id].pos_x;
      iVar5 = 8;
      do {
        iVar7 = crt_rand();
        effect_spawn_freeze_shard(pos,(float)(iVar7 % 0x264) * 0.01);
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
      iVar5 = crt_rand();
      effect_spawn_freeze_shatter(pos,(float)(iVar5 % 0x264) * 0.01);
      creature_kill_count = creature_kill_count + 1;
      pcVar1->active = '\0';
      fx_queue_add_random(pos);
    }
  }
  return;
}
