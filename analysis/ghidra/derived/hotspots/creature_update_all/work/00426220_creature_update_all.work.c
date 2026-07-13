/* WORK COPY: creature_update_all */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* creature_update_all @ 00426220 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* primary creature update loop: AI, movement, attacks, and animation phase */

void creature_update_all(void)

{
  float *lifecycle_stage_ptr;
  uchar *collision_flag_ptr;
  float *attack_cooldown_ptr;
  int *target_player_ptr;
  int spawn_limit;
  float target_delta_y;
  int iVar7;
  uint uVar8;
  int iVar9;
  char cVar10;
  float10 fVar11;
  float10 fVar12;
  longlong lVar13;
  float *health_ptr;
  float fVar15;
  float *pfVar16;
  float fVar17;
  int creature_idx;
  float dist_to_target_player;
  float move_scale;
  float alt_player_dist;
  float local_60;
  float tmp_vec_scratch [12];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_8;
  
  creature_update_tick = creature_update_tick + 1;
  creature_active_count = 0;
  /* Master creature pool sweep (one update per active slot). */
  creature_idx = 0;
  do {
    if ((&creature_pool)[creature_idx].active != '\0') {
      creature_active_count = creature_active_count + 1;
      if (0.0 < (&creature_pool)[creature_idx].hit_flash_timer) {
        (&creature_pool)[creature_idx].hit_flash_timer =
             (&creature_pool)[creature_idx].hit_flash_timer - frame_dt;
      }
      /* Freeze bonus pauses most live-AI behavior when active. */
      if (bonus_freeze_timer <= 0.0) {
        health_ptr = &(&creature_pool)[creature_idx].health;
        /* Flag-driven periodic damage (poison/self-harm lanes). */
        if (((&creature_pool)[creature_idx].health <= 0.0) &&
           ((&creature_pool)[creature_idx].lifecycle_stage == 16.0)) {
          (&creature_pool)[creature_idx].lifecycle_stage = (&creature_pool)[creature_idx].lifecycle_stage - frame_dt
          ;
        }
        if (((&creature_pool)[creature_idx].flags & 2U) == 0) {
          if (((&creature_pool)[creature_idx].flags & 1U) != 0) {
            fVar17 = frame_dt * 60.0;
            pfVar16 = tmp_vec_scratch + 2;
            tmp_vec_scratch[2] = 0.0;
            tmp_vec_scratch[3] = 0.0;
            goto LAB_0042634c;
          }
        }
        else {
          fVar17 = frame_dt * 180.0;
          pfVar16 = tmp_vec_scratch;
          tmp_vec_scratch[0] = 0.0;
          tmp_vec_scratch[1] = 0.0;
LAB_0042634c:
          creature_apply_damage(creature_idx,fVar17,0,pfVar16);
        }
        /* AI7 pulse timer toggles between roaming and orbit-style phases. */
        if (((&creature_pool)[creature_idx].flags & 0x80) != 0) {
          iVar7 = (&creature_pool)[creature_idx].link_index;
          if (iVar7 < 0) {
            iVar7 = iVar7 + frame_dt_ms;
            (&creature_pool)[creature_idx].link_index = iVar7;
            if (-1 < iVar7) {
              uVar8 = crt_rand();
              (&creature_pool)[creature_idx].ai_mode = 7;
              (&creature_pool)[creature_idx].link_index = (uVar8 & 0x1ff) + 500;
            }
          }
          else {
            iVar7 = iVar7 - frame_dt_ms;
            (&creature_pool)[creature_idx].link_index = iVar7;
            if (iVar7 < 1) {
              uVar8 = crt_rand();
              (&creature_pool)[creature_idx].link_index = -700 - (uVar8 & 0x3ff);
            }
          }
        }
        if ((*health_ptr <= 0.0) && ((&creature_pool)[creature_idx].lifecycle_stage == 16.0)) {
          (&creature_pool)[creature_idx].lifecycle_stage = (&creature_pool)[creature_idx].lifecycle_stage - frame_dt
          ;
        }
        /* Retarget logic: choose nearest live player and update player auto-target feedback. */
        cVar10 = (char)(&creature_pool)[creature_idx].target_player;
        iVar7 = (int)cVar10;
        pfVar16 = &(&creature_pool)[creature_idx].pos_x;
        iVar9 = iVar7 * 0x360;
        fVar17 = (&player_state_table)[iVar7].pos_x - *pfVar16;
        fVar15 = (&player_state_table)[iVar7].pos_y - (&creature_pool)[creature_idx].pos_y;
        dist_to_target_player = SQRT(fVar15 * fVar15 + fVar17 * fVar17);
        if (creature_update_tick % 0x46 != 0) {
          if (_config_player_count == 2) {
            if ((0.0 < (float)(&player2_health)[iVar7 * -0xd8]) &&
               (fVar17 = (float)(&player2_pos_y)[iVar7 * -0xd8] - (&creature_pool)[creature_idx].pos_y,
               alt_player_dist = SQRT(fVar17 * fVar17 +
                               ((float)(&player2_pos_x)[iVar7 * -0xd8] - *pfVar16) *
                               ((float)(&player2_pos_x)[iVar7 * -0xd8] - *pfVar16)),
               alt_player_dist < dist_to_target_player)) {
              *(char *)&(&creature_pool)[creature_idx].target_player = '\x01' - cVar10;
              dist_to_target_player = alt_player_dist;
            }
          }
          else {
            fVar17 = player_state_table.pos_y - (&creature_pool)[creature_idx].pos_y;
            alt_player_dist = SQRT(fVar17 * fVar17 +
                            (player_state_table.pos_x - *pfVar16) *
                            (player_state_table.pos_x - *pfVar16));
          }
          cVar10 = (char)(&creature_pool)[creature_idx].target_player;
          iVar7 = (int)cVar10;
          iVar9 = iVar7 * 0x360;
          fVar17 = player_state_table.pos_x -
                   (&creature_pool)[(&player_state_table)[iVar7].auto_target].pos_x;
          fVar15 = player_state_table.pos_y -
                   (&creature_pool)[(&player_state_table)[iVar7].auto_target].pos_y;
          if (alt_player_dist < SQRT(fVar15 * fVar15 + fVar17 * fVar17)) {
            (&player_state_table)[iVar7].auto_target = creature_idx;
          }
        }
        if (*(float *)(player_state_table._pad0 + iVar9 + -0x14) <= 0.0) {
          *(char *)&(&creature_pool)[creature_idx].target_player = '\x01' - cVar10;
        }
        lifecycle_stage_ptr = &(&creature_pool)[creature_idx].lifecycle_stage;
        /* Active-body branch: collision pulses, AI target synthesis, movement, and attacks. */
        if ((&creature_pool)[creature_idx].lifecycle_stage == 16.0) {
          collision_flag_ptr = &(&creature_pool)[creature_idx].collision_flag;
          if ((&creature_pool)[creature_idx].collision_flag != '\0') {
            fVar17 = (&creature_pool)[creature_idx].collision_timer - frame_dt;
            (&creature_pool)[creature_idx].collision_timer = fVar17;
            if (fVar17 < 0.0) {
              (&creature_pool)[creature_idx].state_flag = '\x01';
              (&creature_pool)[creature_idx].collision_timer = fVar17 + 0.5;
              fVar17 = *health_ptr;
              *health_ptr = fVar17 - 15.0;
              if (fVar17 - 15.0 < 0.0) {
                plaguebearer_infection_count = plaguebearer_infection_count + 1;
                creature_handle_death(creature_idx,true);
                uVar8 = crt_rand();
                uVar8 = uVar8 & 0x80000001;
                if ((int)uVar8 < 0) {
                  uVar8 = (uVar8 - 1 | 0xfffffffe) + 1;
                }
                sfx_play_panned((float)creature_type_table[(&creature_pool)[creature_idx].type_id].
                                       sfx_bank_b[uVar8]);
              }
              fx_queue_add_random(pfVar16);
            }
          }
          iVar7 = player_state_table.evil_eyes_target_creature;
          fVar17 = (&creature_pool)[creature_idx].phase_seed;
          *(undefined1 *)&(&creature_pool)[creature_idx].force_target = 0;
          move_scale = 1.0;
          fVar17 = (float)(int)fVar17 * 3.7 * 3.1415927;
          if (creature_idx != iVar7) {
            /* AI mode dispatch for target point generation (follow/orbit/link/idle variants). */
            iVar7 = (&creature_pool)[creature_idx].ai_mode;
            if (iVar7 == 0) {
              iVar7 = (int)(char)(&creature_pool)[creature_idx].target_player;
              if (800.0 < dist_to_target_player) {
LAB_0042676e:
                fVar15 = (&player_state_table)[iVar7].pos_y;
                (&creature_pool)[creature_idx].target_x = (&player_state_table)[iVar7].pos_x;
                (&creature_pool)[creature_idx].target_y = fVar15;
              }
              else {
                fVar11 = (float10)fcos((float10)fVar17);
                (&creature_pool)[creature_idx].target_x =
                     (float)(fVar11 * (float10)dist_to_target_player * (float10)0.85 +
                            (float10)(&player_state_table)[iVar7].pos_x);
                fVar11 = (float10)fsin((float10)fVar17);
                (&creature_pool)[creature_idx].target_y =
                     (float)(fVar11 * (float10)dist_to_target_player * (float10)0.85 +
                            (float10)(&player_state_table)[iVar7].pos_y);
              }
            }
            else if (iVar7 == 8) {
              fVar11 = (float10)fcos((float10)fVar17);
              cVar10 = (char)(&creature_pool)[creature_idx].target_player;
              (&creature_pool)[creature_idx].target_x =
                   (float)(fVar11 * (float10)dist_to_target_player * (float10)0.9 +
                          (float10)(&player_state_table)[cVar10].pos_x);
              fVar11 = (float10)fsin((float10)fVar17);
              (&creature_pool)[creature_idx].target_y =
                   (float)(fVar11 * (float10)dist_to_target_player * (float10)0.9 +
                          (float10)(&player_state_table)[cVar10].pos_y);
            }
            else if (iVar7 == 1) {
              iVar7 = (int)(char)(&creature_pool)[creature_idx].target_player;
              if (800.0 < dist_to_target_player) goto LAB_0042676e;
              fVar11 = (float10)fcos((float10)fVar17);
              (&creature_pool)[creature_idx].target_x =
                   (float)(fVar11 * (float10)dist_to_target_player * (float10)0.55 +
                          (float10)(&player_state_table)[iVar7].pos_x);
              fVar11 = (float10)fsin((float10)fVar17);
              (&creature_pool)[creature_idx].target_y =
                   (float)(fVar11 * (float10)dist_to_target_player * (float10)0.55 +
                          (float10)(&player_state_table)[iVar7].pos_y);
            }
            else if (iVar7 == 3) {
              iVar7 = (&creature_pool)[creature_idx].link_index;
              if ((&creature_pool)[iVar7].health <= 0.0) {
                (&creature_pool)[creature_idx].ai_mode = 0;
              }
              else {
                (&creature_pool)[creature_idx].target_x =
                     (&creature_pool)[iVar7].pos_x + (&creature_pool)[creature_idx].target_offset_x;
                (&creature_pool)[creature_idx].target_y =
                     (&creature_pool)[iVar7].pos_y + (&creature_pool)[creature_idx].target_offset_y;
              }
            }
            else if (iVar7 == 5) {
              iVar7 = (&creature_pool)[creature_idx].link_index;
              if ((&creature_pool)[iVar7].health <= 0.0) {
                (&creature_pool)[creature_idx].ai_mode = 0;
                tmp_vec_scratch[4] = 0.0;
                tmp_vec_scratch[5] = 0.0;
                creature_apply_damage(creature_idx,1000.0,1,tmp_vec_scratch + 4);
              }
              else {
                (&creature_pool)[creature_idx].target_x =
                     (&creature_pool)[iVar7].pos_x + (&creature_pool)[creature_idx].target_offset_x;
                (&creature_pool)[creature_idx].target_y =
                     (&creature_pool)[iVar7].pos_y + (&creature_pool)[creature_idx].target_offset_y;
                fVar15 = (&creature_pool)[creature_idx].target_x - *pfVar16;
                target_delta_y = (&creature_pool)[creature_idx].target_y - (&creature_pool)[creature_idx].pos_y;
                fVar15 = SQRT(fVar15 * fVar15 + target_delta_y * target_delta_y);
                if (fVar15 <= 64.0) {
                  move_scale = fVar15 * 0.015625;
                }
              }
            }
            iVar7 = (&creature_pool)[creature_idx].ai_mode;
            if (iVar7 == 4) {
              if ((&creature_pool)[(&creature_pool)[creature_idx].link_index].health <= 0.0) {
                (&creature_pool)[creature_idx].ai_mode = 0;
                tmp_vec_scratch[6] = 0.0;
                tmp_vec_scratch[7] = 0.0;
                creature_apply_damage(creature_idx,1000.0,1,tmp_vec_scratch + 6);
              }
              else {
                cVar10 = (char)(&creature_pool)[creature_idx].target_player;
                if (dist_to_target_player <= 800.0) {
                  fVar11 = (float10)fcos((float10)fVar17);
                  (&creature_pool)[creature_idx].target_x =
                       (float)(fVar11 * (float10)dist_to_target_player * (float10)0.85 +
                              (float10)(&player_state_table)[cVar10].pos_x);
                  fVar11 = (float10)fsin((float10)fVar17);
                  (&creature_pool)[creature_idx].target_y =
                       (float)(fVar11 * (float10)dist_to_target_player * (float10)0.85 +
                              (float10)(&player_state_table)[cVar10].pos_y);
                }
                else {
                  fVar17 = (&player_state_table)[cVar10].pos_y;
                  (&creature_pool)[creature_idx].target_x = (&player_state_table)[cVar10].pos_x;
                  (&creature_pool)[creature_idx].target_y = fVar17;
                }
              }
            }
            else if (iVar7 == 7) {
              uVar8 = (&creature_pool)[creature_idx].flags & 0x80;
              if ((uVar8 == 0) || ((&creature_pool)[creature_idx].link_index < 1)) {
                if (((&creature_pool)[creature_idx].orbit_radius.radius <= 0.0) || (uVar8 != 0)) {
LAB_00426ac8:
                  (&creature_pool)[creature_idx].ai_mode = 0;
                }
                else {
                  fVar15 = (&creature_pool)[creature_idx].orbit_radius.radius - frame_dt;
                  fVar17 = (&creature_pool)[creature_idx].pos_y;
                  (&creature_pool)[creature_idx].target_x = *pfVar16;
                  (&creature_pool)[creature_idx].target_y = fVar17;
                  (&creature_pool)[creature_idx].orbit_radius.radius = fVar15;
                }
              }
              else {
                fVar17 = (&creature_pool)[creature_idx].pos_y;
                (&creature_pool)[creature_idx].target_x = *pfVar16;
                (&creature_pool)[creature_idx].target_y = fVar17;
              }
            }
            else if (iVar7 == 6) {
              iVar7 = (&creature_pool)[creature_idx].link_index;
              if ((&creature_pool)[iVar7].health <= 0.0) goto LAB_00426ac8;
              fVar11 = (float10)(&creature_pool)[creature_idx].orbit_angle +
                       (float10)(&creature_pool)[creature_idx].heading;
              fVar12 = (float10)fcos(fVar11);
              (&creature_pool)[creature_idx].target_x =
                   (float)(fVar12 * (float10)(&creature_pool)[creature_idx].orbit_radius.radius +
                          (float10)(&creature_pool)[iVar7].pos_x);
              fVar11 = (float10)fsin(fVar11);
              (&creature_pool)[creature_idx].target_y =
                   (float)(fVar11 * (float10)(&creature_pool)[creature_idx].orbit_radius.radius +
                          (float10)(&creature_pool)[iVar7].pos_y);
            }
            fVar17 = (&creature_pool)[creature_idx].target_x - *pfVar16;
            fVar15 = (&creature_pool)[creature_idx].target_y - (&creature_pool)[creature_idx].pos_y;
            if (SQRT(fVar17 * fVar17 + fVar15 * fVar15) < 40.0) {
              *(undefined1 *)&(&creature_pool)[creature_idx].force_target = 1;
            }
            fVar17 = (&creature_pool)[creature_idx].target_x - *pfVar16;
            fVar15 = (&creature_pool)[creature_idx].target_y - (&creature_pool)[creature_idx].pos_y;
            if (400.0 < SQRT(fVar17 * fVar17 + fVar15 * fVar15)) {
              *(undefined1 *)&(&creature_pool)[creature_idx].force_target = 1;
            }
            if (((char)(&creature_pool)[creature_idx].force_target != '\0') ||
               ((&creature_pool)[creature_idx].ai_mode == 2)) {
              cVar10 = (char)(&creature_pool)[creature_idx].target_player;
              (&creature_pool)[creature_idx].target_x = (&player_state_table)[cVar10].pos_x;
              (&creature_pool)[creature_idx].target_y = (&player_state_table)[cVar10].pos_y;
            }
            /* Heading approach + velocity integration; spawner roots run spawn-slot timers too. */
            fVar11 = (float10)fpatan((float10)(&creature_pool)[creature_idx].target_y -
                                     (float10)(&creature_pool)[creature_idx].pos_y,
                                     (float10)(&creature_pool)[creature_idx].target_x -
                                     (float10)*pfVar16);
            (&creature_pool)[creature_idx].target_heading = (float)(fVar11 + (float10)1.5707964);
            if (((0.0 < bonus_energizer_timer) && ((&creature_pool)[creature_idx].max_health < 500.0))
               || (*collision_flag_ptr != '\0')) {
              (&creature_pool)[creature_idx].target_heading =
                   (float)(fVar11 + (float10)1.5707964 + (float10)3.1415927);
            }
            uVar8 = (&creature_pool)[creature_idx].flags;
            if ((uVar8 & 4) == 0) {
              if ((&creature_pool)[creature_idx].ai_mode != 7) {
                angle_approach(&(&creature_pool)[creature_idx].heading,
                               (&creature_pool)[creature_idx].target_heading,
                               (&creature_pool)[creature_idx].move_speed * 0.33333334 * 4.0);
                fVar11 = (float10)(&creature_pool)[creature_idx].heading - (float10)1.5707964;
                fVar12 = (float10)fcos(fVar11);
                (&creature_pool)[creature_idx].vel_x =
                     (float)(fVar12 * (float10)frame_dt * (float10)move_scale *
                             (float10)(&creature_pool)[creature_idx].move_speed * (float10)30.0);
                fVar11 = (float10)fsin(fVar11);
                (&creature_pool)[creature_idx].vel_y =
                     (float)(fVar11 * (float10)frame_dt * (float10)move_scale *
                             (float10)(&creature_pool)[creature_idx].move_speed * (float10)30.0);
                vec2_add_inplace(creature_idx,pfVar16,&(&creature_pool)[creature_idx].vel_x);
              }
            }
            else {
              if (*pfVar16 < (&creature_pool)[creature_idx].size) {
                *pfVar16 = (&creature_pool)[creature_idx].size;
              }
              if ((&creature_pool)[creature_idx].pos_y < (&creature_pool)[creature_idx].size) {
                (&creature_pool)[creature_idx].pos_y = (&creature_pool)[creature_idx].size;
              }
              fVar17 = 1024.0 - (&creature_pool)[creature_idx].size;
              if (fVar17 < *pfVar16) {
                *pfVar16 = fVar17;
              }
              if (fVar17 < (&creature_pool)[creature_idx].pos_y) {
                (&creature_pool)[creature_idx].pos_y = fVar17;
              }
              if ((uVar8 & 0x40) == 0) {
                (&creature_pool)[creature_idx].vel_y = 0.0;
                (&creature_pool)[creature_idx].vel_x = 0.0;
              }
              else {
                angle_approach(&(&creature_pool)[creature_idx].heading,
                               (&creature_pool)[creature_idx].target_heading,
                               (&creature_pool)[creature_idx].move_speed * 0.33333334 * 4.0);
                fVar11 = (float10)(&creature_pool)[creature_idx].heading - (float10)1.5707964;
                fVar12 = (float10)fcos(fVar11);
                (&creature_pool)[creature_idx].vel_x =
                     (float)(fVar12 * (float10)frame_dt * (float10)move_scale *
                             (float10)(&creature_pool)[creature_idx].move_speed * (float10)30.0);
                fVar11 = (float10)fsin(fVar11);
                (&creature_pool)[creature_idx].vel_y =
                     (float)(fVar11 * (float10)frame_dt * (float10)move_scale *
                             (float10)(&creature_pool)[creature_idx].move_speed * (float10)30.0);
                vec2_add_inplace(creature_idx,pfVar16,&(&creature_pool)[creature_idx].vel_x);
              }
              iVar7 = (&creature_pool)[creature_idx].link_index;
              fVar17 = (&creature_spawn_slot_table)[iVar7].timer_s - frame_dt;
              (&creature_spawn_slot_table)[iVar7].timer_s = fVar17;
              if (fVar17 < 0.0) {
                iVar9 = (&creature_spawn_slot_table)[iVar7].count;
                spawn_limit = (&creature_spawn_slot_table)[iVar7].limit;
                (&creature_spawn_slot_table)[iVar7].timer_s =
                     fVar17 + (&creature_spawn_slot_table)[iVar7].interval_s;
                if (iVar9 < spawn_limit) {
                  (&creature_spawn_slot_table)[iVar7].count = iVar9 + 1;
                  creature_spawn_template
                            ((&creature_spawn_slot_table)[iVar7].template_id,pfVar16,-100.0);
                }
              }
            }
            /* Animation, cooldown decay, and ranged attack gates (flags 0x10 / 0x100). */
            iVar7 = perk_count_get(perk_id_plaguebearer);
            if ((iVar7 != 0) && (plaguebearer_infection_count < 0x3c)) {
              plaguebearer_spread_infection(creature_idx);
            }
            fVar17 = 30.0 / (&creature_pool)[creature_idx].size;
            if ((((&creature_pool)[creature_idx].flags & 4U) == 0) ||
               (((&creature_pool)[creature_idx].flags & 0x40U) != 0)) {
              if ((&creature_pool)[creature_idx].ai_mode != 7) {
                fVar17 = creature_type_table[(&creature_pool)[creature_idx].type_id].anim_rate *
                         (&creature_pool)[creature_idx].move_speed * frame_dt * fVar17 * move_scale * 25.0
                         + (&creature_pool)[creature_idx].anim_phase;
                (&creature_pool)[creature_idx].anim_phase = fVar17;
                while (31.0 < fVar17) {
                  fVar17 = (&creature_pool)[creature_idx].anim_phase - 31.0;
                  (&creature_pool)[creature_idx].anim_phase = fVar17;
                }
              }
            }
            else {
              fVar17 = creature_type_table[(&creature_pool)[creature_idx].type_id].anim_rate *
                       (&creature_pool)[creature_idx].move_speed * frame_dt * fVar17 * move_scale * 22.0 +
                       (&creature_pool)[creature_idx].anim_phase;
              (&creature_pool)[creature_idx].anim_phase = fVar17;
              if (15.0 < fVar17) {
                fVar17 = (&creature_pool)[creature_idx].anim_phase;
                do {
                  fVar17 = fVar17 - 15.0;
                } while (15.0 < fVar17);
                (&creature_pool)[creature_idx].anim_phase = fVar17;
              }
            }
            attack_cooldown_ptr = &(&creature_pool)[creature_idx].attack_cooldown;
            if ((&creature_pool)[creature_idx].attack_cooldown <= 0.0) {
              *attack_cooldown_ptr = 0.0;
            }
            else {
              *attack_cooldown_ptr = *attack_cooldown_ptr - frame_dt;
            }
            cVar10 = (char)(&creature_pool)[creature_idx].target_player;
            target_player_ptr = &(&creature_pool)[creature_idx].target_player;
            fVar17 = *pfVar16 - (&player_state_table)[cVar10].pos_x;
            fVar15 = (&creature_pool)[creature_idx].pos_y - (&player_state_table)[cVar10].pos_y;
            fVar17 = SQRT(fVar17 * fVar17 + fVar15 * fVar15);
            if ((((fVar17 < 100.0) && (iVar7 = perk_count_get(perk_id_radioactive), iVar7 != 0)) &&
                (fVar15 = (&creature_pool)[creature_idx].collision_timer - frame_dt * 1.5,
                (&creature_pool)[creature_idx].collision_timer = fVar15, fVar15 < 0.0)) &&
               (0.0 < *health_ptr)) {
              (&creature_pool)[creature_idx].collision_timer = 0.5;
              (&creature_pool)[creature_idx].state_flag = '\x01';
              fVar15 = *health_ptr - (100.0 - fVar17) * 0.3;
              *health_ptr = fVar15;
              if (fVar15 < 0.0) {
                if ((&creature_pool)[creature_idx].type_id == 1) {
                  *health_ptr = 1.0;
                }
                else {
                  lVar13 = __ftol();
                  player_state_table.experience = (int)lVar13;
                  *lifecycle_stage_ptr = *lifecycle_stage_ptr - frame_dt;
                }
              }
              fx_queue_add_random(pfVar16);
            }
            if (64.0 < fVar17) {
              if ((((&creature_pool)[creature_idx].flags & 0x10) != 0) && (*attack_cooldown_ptr <= 0.0)) {
                projectile_spawn(pfVar16,(&creature_pool)[creature_idx].heading,
                                 PROJECTILE_TYPE_PLASMA_RIFLE,creature_idx);
                fVar15 = sfx_shock_fire;
                *attack_cooldown_ptr = *attack_cooldown_ptr + 1.0;
                sfx_play_panned(fVar15);
              }
              if ((((&creature_pool)[creature_idx].flags & 0x100U) != 0) && (*attack_cooldown_ptr <= 0.0)) {
                projectile_spawn(pfVar16,(&creature_pool)[creature_idx].heading,
                                 (&creature_pool)[creature_idx].orbit_radius.projectile_type,creature_idx);
                uVar8 = crt_rand();
                fVar15 = sfx_plasmaminigun_fire;
                local_60 = (float)(uVar8 & 3);
                *attack_cooldown_ptr = (float)(int)local_60 * 0.1 + (&creature_pool)[creature_idx].orbit_angle +
                          *attack_cooldown_ptr;
                sfx_play_panned(fVar15);
              }
            }
            /* Near-contact resolution: melee hits, perk hooks, infection propagation. */
            if (fVar17 < 20.0) {
              *pfVar16 = *pfVar16 - (&creature_pool)[creature_idx].vel_x;
              (&creature_pool)[creature_idx].pos_y =
                   (&creature_pool)[creature_idx].pos_y - (&creature_pool)[creature_idx].vel_y;
              if (((&creature_pool)[creature_idx].max_health < 380.0) && (0.0 < bonus_energizer_timer))
              {
                lVar13 = __ftol();
                player_state_table.experience = (int)lVar13;
                effect_spawn_burst(pfVar16,6);
                sfx_play_panned(sfx_ui_bonus);
                bonus_spawn_guard._0_1_ = 1;
                creature_handle_death(creature_idx,false);
                bonus_spawn_guard._0_1_ = 0;
              }
            }
            if (16.0 < (&creature_pool)[creature_idx].size) {
              if (30.0 <= fVar17) goto LAB_004276d6;
              if ((0.0 < (&player_state_table)[(char)*target_player_ptr].health) &&
                 (bonus_energizer_timer <= 0.0)) {
                if (*attack_cooldown_ptr <= 0.0) {
                  uVar8 = crt_rand();
                  uVar8 = uVar8 & 0x80000001;
                  if ((int)uVar8 < 0) {
                    uVar8 = (uVar8 - 1 | 0xfffffffe) + 1;
                  }
                  sfx_play_panned((float)creature_type_table[(&creature_pool)[creature_idx].type_id].
                                         sfx_bank_b[uVar8]);
                  iVar7 = perk_count_get(perk_id_mr_melee);
                  if (iVar7 != 0) {
                    tmp_vec_scratch[8] = 0.0;
                    tmp_vec_scratch[9] = 0.0;
                    creature_apply_damage(creature_idx,25.0,2,tmp_vec_scratch + 8);
                  }
                  if ((&player_state_table)[(char)*target_player_ptr].shield_timer <= 0.0) {
                    iVar7 = perk_count_get(perk_id_toxic_avenger);
                    if (iVar7 == 0) {
                      iVar7 = perk_count_get(perk_id_veins_of_poison);
                      if (iVar7 == 0) goto LAB_0042733a;
                      uVar8 = (&creature_pool)[creature_idx].flags | 1;
                    }
                    else {
                      uVar8 = (&creature_pool)[creature_idx].flags | 3;
                    }
                    (&creature_pool)[creature_idx].flags = uVar8;
                  }
LAB_0042733a:
                  player_take_damage((int)(char)*target_player_ptr,(&creature_pool)[creature_idx].contact_damage);
                  vec2_normalize_dispatch();
                  tmp_vec_scratch[9] = (float)collision_flag_ptr * 3.0 + (&player_state_table)[(char)*target_player_ptr].pos_y;
                  tmp_vec_scratch[8] = local_60 * 3.0 + (&player_state_table)[(char)*target_player_ptr].pos_x;
                  fx_queue_add_random(tmp_vec_scratch + 8);
                  *attack_cooldown_ptr = *attack_cooldown_ptr + 1.0;
                }
                if ((((&player_plaguebearer_active)[(char)*target_player_ptr * 0x360] != '\0') &&
                    (*health_ptr < 150.0)) && (plaguebearer_infection_count < 0x32)) {
                  *collision_flag_ptr = '\x01';
                }
              }
            }
            if ((fVar17 < 30.0) && ((&creature_pool)[creature_idx].size <= 30.0)) {
              *health_ptr = 0.0;
              *lifecycle_stage_ptr = *lifecycle_stage_ptr - frame_dt;
            }
          }
        }
        /* Death/corpse branch: shrink, slide, spawn corpse FX, and eventually deactivate. */
        else if (*lifecycle_stage_ptr <= 0.0) {
          *lifecycle_stage_ptr = *lifecycle_stage_ptr - frame_dt * 20.0;
        }
        else {
          fVar17 = *lifecycle_stage_ptr - frame_dt * 28.0;
          *lifecycle_stage_ptr = fVar17;
          if (0.0 < fVar17) {
            if ((((&creature_pool)[creature_idx].flags & 4U) == 0) ||
               (((&creature_pool)[creature_idx].flags & 0x40U) != 0)) {
              fVar11 = (float10)(&creature_pool)[creature_idx].heading - (float10)1.5707964;
              fVar12 = (float10)fcos(fVar11);
              (&creature_pool)[creature_idx].vel_x =
                   (float)(fVar12 * (float10)fVar17 * (float10)frame_dt * (float10)9.0);
              fVar11 = (float10)fsin(fVar11);
              (&creature_pool)[creature_idx].vel_y =
                   (float)(fVar11 * (float10)fVar17 * (float10)frame_dt * (float10)9.0);
              *pfVar16 = *pfVar16 - (&creature_pool)[creature_idx].vel_x;
              (&creature_pool)[creature_idx].pos_y =
                   (&creature_pool)[creature_idx].pos_y - (&creature_pool)[creature_idx].vel_y;
            }
            else {
              (&creature_pool)[creature_idx].vel_x = 0.0;
              (&creature_pool)[creature_idx].vel_y = 0.0;
            }
          }
          else {
            if (config_violence_disabled == '\0') {
              if ((((&creature_pool)[creature_idx].flags & 4U) == 0) ||
                 (((&creature_pool)[creature_idx].flags & 0x40U) != 0)) {
                local_8 = (&creature_pool)[creature_idx].size * 0.5;
                iVar7 = (&creature_pool)[creature_idx].type_id;
                fVar17 = (&creature_pool)[creature_idx].size;
                fVar15 = (&creature_pool)[creature_idx].heading;
                local_18 = *pfVar16 - local_8;
                health_ptr = &local_18;
                local_14 = (&creature_pool)[creature_idx].pos_y - local_8;
              }
              else {
                local_10 = (&creature_pool)[creature_idx].size * 0.5;
                fVar17 = (&creature_pool)[creature_idx].size;
                fVar15 = (&creature_pool)[creature_idx].heading;
                iVar7 = 7;
                local_20 = *pfVar16 - local_10;
                health_ptr = &local_20;
                local_1c = (&creature_pool)[creature_idx].pos_y - local_10;
              }
              iVar7 = fx_queue_add_rotated
                                (health_ptr,&(&creature_pool)[creature_idx].tint_r,fVar15,fVar17,iVar7);
              if ((char)iVar7 == '\0') {
                *lifecycle_stage_ptr = 0.001;
                goto LAB_004276d6;
              }
            }
            creature_kill_count = creature_kill_count + 1;
            /* Spawner-class deaths burst extra blood and can be culled immediately. */
            if ((config_violence_disabled == '\0') && (((&creature_pool)[creature_idx].flags & 4) != 0)) {
              iVar7 = 8;
              do {
                fVar17 = 0.0;
                iVar9 = crt_rand();
                effect_spawn_blood_splatter(pfVar16,(float)(iVar9 % 0x264) * 0.01,fVar17);
                iVar7 = iVar7 + -1;
              } while (iVar7 != 0);
              iVar7 = 6;
              do {
                fVar17 = -0.07;
                iVar9 = crt_rand();
                effect_spawn_blood_splatter(pfVar16,(float)(iVar9 % 0x264) * 0.01,fVar17);
                iVar7 = iVar7 + -1;
              } while (iVar7 != 0);
              iVar7 = 5;
              do {
                fVar17 = -0.12;
                iVar9 = crt_rand();
                effect_spawn_blood_splatter(pfVar16,(float)(iVar9 % 0x264) * 0.01,fVar17);
                iVar7 = iVar7 + -1;
              } while (iVar7 != 0);
            }
            if (*(float *)((int)cv_bodiesFade + 0xc) == 0.0) {
              (&creature_pool)[creature_idx].active = '\0';
            }
          }
        }
      }
    }
LAB_004276d6:
    creature_idx = creature_idx + 1;
    if (0x17f < creature_idx) {
      return;
    }
  } while( true );
}
