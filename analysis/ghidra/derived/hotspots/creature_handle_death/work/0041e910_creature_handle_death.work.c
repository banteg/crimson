/* WORK COPY: creature_handle_death */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* creature_handle_death @ 0041e910 */

/* death handler: bonus spawns, split-on-death, score, and cleanup */

void creature_handle_death(int creature_id, bool keep_corpse)

{
  float *death_pos_ptr;
  creature_t *creature_ptr;
  uchar copy_pad_byte0;
  uchar copy_pad_byte1;
  uchar copy_pad_byte2;
  int split_clone_id;
  uint rng_value;
  int copy_word_count;
  int bloody_mess_perk_id;
  int freeze_spawn_count;
  int freeze_angle_roll;
  creature_t *copy_src_ptr;
  creature_t *copy_dst_ptr;
  longlong xp_gain_i64;
  
  creature_ptr = &creature_pool + creature_id;
  /* Flag 0x400 creatures force a bonus spawn on death. */
  if (((&creature_pool)[creature_id].flags & 0x400U) != 0) {
    bonus_spawn_at(&(&creature_pool)[creature_id].pos_x,
                   (int)(short)(&creature_pool)[creature_id].link_index,
                   (int)*(short *)((int)&(&creature_pool)[creature_id].link_index + 2));
  }
  /* Survival kill streak bookkeeping also toggles reward-handout gates at 3 kills. */
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
  if (creature_ptr->active != '\0') {
    /* Spawn-slot-owned creatures release their slot immediately on death. */
    if (((&creature_pool)[creature_id].flags & 4) != 0) {
      (&creature_spawn_slot_table)[(&creature_pool)[creature_id].link_index].owner =
           (creature_t *)0x0;
    }
    /* Split-on-death branch: duplicate the dying creature into two weaker side spawns. */
    if ((((&creature_pool)[creature_id].flags & 8) != 0) &&
       (35.0 < (&creature_pool)[creature_id].size)) {
      split_clone_id = creature_alloc_slot();
      copy_src_ptr = creature_ptr;
      copy_dst_ptr = &creature_pool + split_clone_id;
      for (copy_word_count = 0x26; copy_word_count != 0; copy_word_count = copy_word_count + -1) {
        copy_pad_byte0 = copy_src_ptr->_pad0[0];
        copy_pad_byte1 = copy_src_ptr->_pad0[1];
        copy_pad_byte2 = copy_src_ptr->_pad0[2];
        copy_dst_ptr->active = copy_src_ptr->active;
        copy_dst_ptr->_pad0[0] = copy_pad_byte0;
        copy_dst_ptr->_pad0[1] = copy_pad_byte1;
        copy_dst_ptr->_pad0[2] = copy_pad_byte2;
        copy_src_ptr = (creature_t *)&copy_src_ptr->phase_seed;
        copy_dst_ptr = (creature_t *)&copy_dst_ptr->phase_seed;
      }
      rng_value = crt_rand();
      (&creature_pool)[split_clone_id].phase_seed = (float)(rng_value & 0xff);
      (&creature_pool)[split_clone_id].heading = (&creature_pool)[creature_id].heading - 1.5707964;
      (&creature_pool)[split_clone_id].health = (&creature_pool)[creature_id].max_health * 0.25;
      (&creature_pool)[split_clone_id].reward_value =
           (&creature_pool)[split_clone_id].reward_value * 0.6666667;
      (&creature_pool)[split_clone_id].size = (&creature_pool)[split_clone_id].size - 8.0;
      (&creature_pool)[split_clone_id].move_speed = (&creature_pool)[split_clone_id].move_speed + 0.1;
      (&creature_pool)[split_clone_id].contact_damage =
           (&creature_pool)[split_clone_id].contact_damage * 0.7;
      (&creature_pool)[split_clone_id].lifecycle_stage = 16.0;
      split_clone_id = creature_alloc_slot();
      copy_src_ptr = creature_ptr;
      copy_dst_ptr = &creature_pool + split_clone_id;
      for (copy_word_count = 0x26; copy_word_count != 0; copy_word_count = copy_word_count + -1) {
        copy_pad_byte0 = copy_src_ptr->_pad0[0];
        copy_pad_byte1 = copy_src_ptr->_pad0[1];
        copy_pad_byte2 = copy_src_ptr->_pad0[2];
        copy_dst_ptr->active = copy_src_ptr->active;
        copy_dst_ptr->_pad0[0] = copy_pad_byte0;
        copy_dst_ptr->_pad0[1] = copy_pad_byte1;
        copy_dst_ptr->_pad0[2] = copy_pad_byte2;
        copy_src_ptr = (creature_t *)&copy_src_ptr->phase_seed;
        copy_dst_ptr = (creature_t *)&copy_dst_ptr->phase_seed;
      }
      rng_value = crt_rand();
      (&creature_pool)[split_clone_id].phase_seed = (float)(rng_value & 0xff);
      (&creature_pool)[split_clone_id].heading = (&creature_pool)[creature_id].heading + 1.5707964;
      (&creature_pool)[split_clone_id].health = (&creature_pool)[creature_id].max_health * 0.25;
      (&creature_pool)[split_clone_id].size = (&creature_pool)[split_clone_id].size - 8.0;
      (&creature_pool)[split_clone_id].move_speed = (&creature_pool)[split_clone_id].move_speed + 0.1;
      (&creature_pool)[split_clone_id].reward_value =
           (&creature_pool)[split_clone_id].reward_value * 0.6666667;
      (&creature_pool)[split_clone_id].lifecycle_stage = 16.0;
      (&creature_pool)[split_clone_id].contact_damage =
           (&creature_pool)[split_clone_id].contact_damage * 0.7;
      effect_spawn_burst(&(&creature_pool)[creature_id].pos_x,8);
    }
    /* Corpse policy: shrink lingering corpse or mark slot inactive immediately. */
    if (keep_corpse) {
      (&creature_pool)[creature_id].lifecycle_stage =
           (&creature_pool)[creature_id].lifecycle_stage - frame_dt;
    }
    else {
      creature_ptr->active = '\0';
    }
    /* XP grant uses the same conversion path for base and double-XP bonus. */
    bloody_mess_perk_id = perk_id_bloody_mess_quick_learner;
    if (player_state_table.perk_counts[bloody_mess_perk_id] < 1) {
      xp_gain_i64 = __ftol();
      player_state_table.experience = (int)xp_gain_i64;
    }
    else {
      xp_gain_i64 = __ftol();
      player_state_table.experience = player_state_table.experience + (int)xp_gain_i64;
    }
    if (0.0 < bonus_double_xp_timer) {
      if (player_state_table.perk_counts[bloody_mess_perk_id] < 1) {
        xp_gain_i64 = __ftol();
        player_state_table.experience = (int)xp_gain_i64;
      }
      else {
        xp_gain_i64 = __ftol();
        player_state_table.experience = player_state_table.experience + (int)xp_gain_i64;
      }
    }
    if ((char)bonus_spawn_guard == '\0') {
      bonus_try_spawn_on_kill(&(&creature_pool)[creature_id].pos_x);
    }
    /* Freeze bonus adds shard/shatter FX and hard-clears the corpse state. */
    if (0.0 < bonus_freeze_timer) {
      death_pos_ptr = &(&creature_pool)[creature_id].pos_x;
      freeze_spawn_count = 8;
      do {
        freeze_angle_roll = crt_rand();
        effect_spawn_freeze_shard(death_pos_ptr,(float)(freeze_angle_roll % 0x264) * 0.01);
        freeze_spawn_count = freeze_spawn_count + -1;
      } while (freeze_spawn_count != 0);
      freeze_angle_roll = crt_rand();
      effect_spawn_freeze_shatter(death_pos_ptr,(float)(freeze_angle_roll % 0x264) * 0.01);
      creature_kill_count = creature_kill_count + 1;
      creature_ptr->active = '\0';
      fx_queue_add_random(death_pos_ptr);
    }
  }
  return;
}
