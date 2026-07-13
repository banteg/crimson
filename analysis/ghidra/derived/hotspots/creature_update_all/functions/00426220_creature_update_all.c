/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: creature_update_all */
/* function_mapped: creature_update_all */
/* address: 0x00426220 */
/* byte_range: [760732, 791227) */
/* creature_update_all @ 00426220 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* primary creature update loop: AI, movement, attacks, and animation phase */

void creature_update_all(void)

{
  float *pfVar1;
  float *pfVar2;
  int *piVar3;
  int iVar4;
  float fVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  char cVar9;
  float10 fVar10;
  float10 fVar11;
  longlong lVar12;
  float *pfVar13;
  float fVar14;
  float *pfVar15;
  float fVar16;
  int local_7c;
  float local_78;
  float local_70;
  float local_6c;
  float local_58;
  float local_54;
  float local_50 [11];
  float fStack_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_8;
  
  creature_update_tick = creature_update_tick + 1;
  creature_active_count = 0;
  local_7c = 0;
  do {
    if ((&creature_pool)[local_7c].active != '\0') {
      creature_active_count = creature_active_count + 1;
      if (0.0 < (&creature_pool)[local_7c].hit_flash_timer) {
        (&creature_pool)[local_7c].hit_flash_timer =
             (&creature_pool)[local_7c].hit_flash_timer - frame_dt;
      }
      if (bonus_freeze_timer <= 0.0) {
        pfVar13 = &(&creature_pool)[local_7c].health;
        if (((&creature_pool)[local_7c].health <= 0.0) &&
           ((&creature_pool)[local_7c].lifecycle_stage == 16.0)) {
          (&creature_pool)[local_7c].lifecycle_stage = (&creature_pool)[local_7c].lifecycle_stage - frame_dt
          ;
        }
        if (((&creature_pool)[local_7c].flags & 2U) == 0) {
          if (((&creature_pool)[local_7c].flags & 1U) != 0) {
            fVar16 = frame_dt * 60.0;
            pfVar15 = local_50 + 2;
            local_50[2] = 0.0;
            local_50[3] = 0.0;
            goto LAB_0042634c;
          }
        }
        else {
          fVar16 = frame_dt * 180.0;
          pfVar15 = local_50;
          local_50[0] = 0.0;
          local_50[1] = 0.0;
LAB_0042634c:
          creature_apply_damage(local_7c,fVar16,0,pfVar15);
        }
        if (((&creature_pool)[local_7c].flags & 0x80) != 0) {
          iVar6 = (&creature_pool)[local_7c].link_index;
          if (iVar6 < 0) {
            iVar6 = iVar6 + frame_dt_ms;
            (&creature_pool)[local_7c].link_index = iVar6;
            if (-1 < iVar6) {
              uVar7 = crt_rand();
              (&creature_pool)[local_7c].ai_mode = 7;
              (&creature_pool)[local_7c].link_index = (uVar7 & 0x1ff) + 500;
            }
          }
          else {
            iVar6 = iVar6 - frame_dt_ms;
            (&creature_pool)[local_7c].link_index = iVar6;
            if (iVar6 < 1) {
              uVar7 = crt_rand();
              (&creature_pool)[local_7c].link_index = -700 - (uVar7 & 0x3ff);
            }
          }
        }
        if ((*pfVar13 <= 0.0) && ((&creature_pool)[local_7c].lifecycle_stage == 16.0)) {
          (&creature_pool)[local_7c].lifecycle_stage = (&creature_pool)[local_7c].lifecycle_stage - frame_dt
          ;
        }
        cVar9 = (char)(&creature_pool)[local_7c].target_player;
        iVar6 = (int)cVar9;
        pfVar15 = &(&creature_pool)[local_7c].pos_x;
        iVar8 = iVar6 * 0x360;
        fVar16 = (&player_state_table)[iVar6].pos_x - *pfVar15;
        fVar14 = (&player_state_table)[iVar6].pos_y - (&creature_pool)[local_7c].pos_y;
        local_78 = SQRT(fVar14 * fVar14 + fVar16 * fVar16);
        if (creature_update_tick % 0x46 != 0) {
          if (_config_player_count == 2) {
            if ((0.0 < (float)(&player2_health)[iVar6 * -0xd8]) &&
               (fVar16 = (float)(&player2_pos_y)[iVar6 * -0xd8] - (&creature_pool)[local_7c].pos_y,
               local_6c = SQRT(fVar16 * fVar16 +
                               ((float)(&player2_pos_x)[iVar6 * -0xd8] - *pfVar15) *
                               ((float)(&player2_pos_x)[iVar6 * -0xd8] - *pfVar15)),
               local_6c < local_78)) {
              *(char *)&(&creature_pool)[local_7c].target_player = '\x01' - cVar9;
              local_78 = local_6c;
            }
          }
          else {
            fVar16 = player_state_table.pos_y - (&creature_pool)[local_7c].pos_y;
            local_6c = SQRT(fVar16 * fVar16 +
                            (player_state_table.pos_x - *pfVar15) *
                            (player_state_table.pos_x - *pfVar15));
          }
          cVar9 = (char)(&creature_pool)[local_7c].target_player;
          iVar6 = (int)cVar9;
          iVar8 = iVar6 * 0x360;
          fVar16 = player_state_table.pos_x -
                   (&creature_pool)[(&player_state_table)[iVar6].auto_target].pos_x;
          fVar14 = player_state_table.pos_y -
                   (&creature_pool)[(&player_state_table)[iVar6].auto_target].pos_y;
          if (local_6c < SQRT(fVar14 * fVar14 + fVar16 * fVar16)) {
            (&player_state_table)[iVar6].auto_target = local_7c;
          }
        }
        if (*(float *)(player_state_table._pad0 + iVar8 + -0x14) <= 0.0) {
          *(char *)&(&creature_pool)[local_7c].target_player = '\x01' - cVar9;
        }
        pfVar1 = &(&creature_pool)[local_7c].lifecycle_stage;
        if ((&creature_pool)[local_7c].lifecycle_stage == 16.0) {
          if ((&creature_pool)[local_7c].collision_flag != '\0') {
            fVar16 = (&creature_pool)[local_7c].collision_timer - frame_dt;
            (&creature_pool)[local_7c].collision_timer = fVar16;
            if (fVar16 < 0.0) {
              (&creature_pool)[local_7c].state_flag = '\x01';
              (&creature_pool)[local_7c].collision_timer = fVar16 + 0.5;
              fVar16 = *pfVar13;
              *pfVar13 = fVar16 - 15.0;
              if (fVar16 - 15.0 < 0.0) {
                plaguebearer_infection_count = plaguebearer_infection_count + 1;
                creature_handle_death(local_7c,true);
                uVar7 = crt_rand();
                uVar7 = uVar7 & 0x80000001;
                if ((int)uVar7 < 0) {
                  uVar7 = (uVar7 - 1 | 0xfffffffe) + 1;
                }
                sfx_play_panned((float)creature_type_table[(&creature_pool)[local_7c].type_id].
                                       sfx_bank_b[uVar7]);
              }
              fx_queue_add_random(pfVar15);
            }
          }
          iVar6 = player_state_table.evil_eyes_target_creature;
          fVar16 = (&creature_pool)[local_7c].phase_seed;
          *(undefined1 *)&(&creature_pool)[local_7c].force_target = 0;
          local_70 = 1.0;
          fVar16 = (float)(int)fVar16 * 3.7 * 3.1415927;
          if (local_7c != iVar6) {
            iVar6 = (&creature_pool)[local_7c].ai_mode;
            if (iVar6 == 0) {
              iVar6 = (int)(char)(&creature_pool)[local_7c].target_player;
              if (800.0 < local_78) {
LAB_0042676e:
                fVar14 = (&player_state_table)[iVar6].pos_y;
                (&creature_pool)[local_7c].target_x = (&player_state_table)[iVar6].pos_x;
                (&creature_pool)[local_7c].target_y = fVar14;
              }
              else {
                fVar10 = (float10)fcos((float10)fVar16);
                (&creature_pool)[local_7c].target_x =
                     (float)(fVar10 * (float10)local_78 * (float10)0.85 +
                            (float10)(&player_state_table)[iVar6].pos_x);
                fVar10 = (float10)fsin((float10)fVar16);
                (&creature_pool)[local_7c].target_y =
                     (float)(fVar10 * (float10)local_78 * (float10)0.85 +
                            (float10)(&player_state_table)[iVar6].pos_y);
              }
            }
            else if (iVar6 == 8) {
              fVar10 = (float10)fcos((float10)fVar16);
              cVar9 = (char)(&creature_pool)[local_7c].target_player;
              (&creature_pool)[local_7c].target_x =
                   (float)(fVar10 * (float10)local_78 * (float10)0.9 +
                          (float10)(&player_state_table)[cVar9].pos_x);
              fVar10 = (float10)fsin((float10)fVar16);
              (&creature_pool)[local_7c].target_y =
                   (float)(fVar10 * (float10)local_78 * (float10)0.9 +
                          (float10)(&player_state_table)[cVar9].pos_y);
            }
            else if (iVar6 == 1) {
              iVar6 = (int)(char)(&creature_pool)[local_7c].target_player;
              if (800.0 < local_78) goto LAB_0042676e;
              fVar10 = (float10)fcos((float10)fVar16);
              (&creature_pool)[local_7c].target_x =
                   (float)(fVar10 * (float10)local_78 * (float10)0.55 +
                          (float10)(&player_state_table)[iVar6].pos_x);
              fVar10 = (float10)fsin((float10)fVar16);
              (&creature_pool)[local_7c].target_y =
                   (float)(fVar10 * (float10)local_78 * (float10)0.55 +
                          (float10)(&player_state_table)[iVar6].pos_y);
            }
            else if (iVar6 == 3) {
              iVar6 = (&creature_pool)[local_7c].link_index;
              if ((&creature_pool)[iVar6].health <= 0.0) {
                (&creature_pool)[local_7c].ai_mode = 0;
              }
              else {
                (&creature_pool)[local_7c].target_x =
                     (&creature_pool)[iVar6].pos_x + (&creature_pool)[local_7c].target_offset_x;
                (&creature_pool)[local_7c].target_y =
                     (&creature_pool)[iVar6].pos_y + (&creature_pool)[local_7c].target_offset_y;
              }
            }
            else if (iVar6 == 5) {
              iVar6 = (&creature_pool)[local_7c].link_index;
              if ((&creature_pool)[iVar6].health <= 0.0) {
                (&creature_pool)[local_7c].ai_mode = 0;
                local_50[4] = 0.0;
                local_50[5] = 0.0;
                creature_apply_damage(local_7c,1000.0,1,local_50 + 4);
              }
              else {
                (&creature_pool)[local_7c].target_x =
                     (&creature_pool)[iVar6].pos_x + (&creature_pool)[local_7c].target_offset_x;
                (&creature_pool)[local_7c].target_y =
                     (&creature_pool)[iVar6].pos_y + (&creature_pool)[local_7c].target_offset_y;
                fVar14 = (&creature_pool)[local_7c].target_x - *pfVar15;
                fVar5 = (&creature_pool)[local_7c].target_y - (&creature_pool)[local_7c].pos_y;
                fVar14 = SQRT(fVar14 * fVar14 + fVar5 * fVar5);
                if (fVar14 <= 64.0) {
                  local_70 = fVar14 * 0.015625;
                }
              }
            }
            iVar6 = (&creature_pool)[local_7c].ai_mode;
            if (iVar6 == 4) {
              if ((&creature_pool)[(&creature_pool)[local_7c].link_index].health <= 0.0) {
                (&creature_pool)[local_7c].ai_mode = 0;
                local_50[6] = 0.0;
                local_50[7] = 0.0;
                creature_apply_damage(local_7c,1000.0,1,local_50 + 6);
              }
              else {
                cVar9 = (char)(&creature_pool)[local_7c].target_player;
                if (local_78 <= 800.0) {
                  fVar10 = (float10)fcos((float10)fVar16);
                  (&creature_pool)[local_7c].target_x =
                       (float)(fVar10 * (float10)local_78 * (float10)0.85 +
                              (float10)(&player_state_table)[cVar9].pos_x);
                  fVar10 = (float10)fsin((float10)fVar16);
                  (&creature_pool)[local_7c].target_y =
                       (float)(fVar10 * (float10)local_78 * (float10)0.85 +
                              (float10)(&player_state_table)[cVar9].pos_y);
                }
                else {
                  fVar16 = (&player_state_table)[cVar9].pos_y;
                  (&creature_pool)[local_7c].target_x = (&player_state_table)[cVar9].pos_x;
                  (&creature_pool)[local_7c].target_y = fVar16;
                }
              }
            }
            else if (iVar6 == 7) {
              uVar7 = (&creature_pool)[local_7c].flags & 0x80;
              if ((uVar7 == 0) || ((&creature_pool)[local_7c].link_index < 1)) {
                if (((&creature_pool)[local_7c].orbit_radius.radius <= 0.0) || (uVar7 != 0)) {
LAB_00426ac8:
                  (&creature_pool)[local_7c].ai_mode = 0;
                }
                else {
                  fVar14 = (&creature_pool)[local_7c].orbit_radius.radius - frame_dt;
                  fVar16 = (&creature_pool)[local_7c].pos_y;
                  (&creature_pool)[local_7c].target_x = *pfVar15;
                  (&creature_pool)[local_7c].target_y = fVar16;
                  (&creature_pool)[local_7c].orbit_radius.radius = fVar14;
                }
              }
              else {
                fVar16 = (&creature_pool)[local_7c].pos_y;
                (&creature_pool)[local_7c].target_x = *pfVar15;
                (&creature_pool)[local_7c].target_y = fVar16;
              }
            }
            else if (iVar6 == 6) {
              iVar6 = (&creature_pool)[local_7c].link_index;
              if ((&creature_pool)[iVar6].health <= 0.0) goto LAB_00426ac8;
              fVar10 = (float10)(&creature_pool)[local_7c].orbit_angle +
                       (float10)(&creature_pool)[local_7c].heading;
              fVar11 = (float10)fcos(fVar10);
              (&creature_pool)[local_7c].target_x =
                   (float)(fVar11 * (float10)(&creature_pool)[local_7c].orbit_radius.radius +
                          (float10)(&creature_pool)[iVar6].pos_x);
              fVar10 = (float10)fsin(fVar10);
              (&creature_pool)[local_7c].target_y =
                   (float)(fVar10 * (float10)(&creature_pool)[local_7c].orbit_radius.radius +
                          (float10)(&creature_pool)[iVar6].pos_y);
            }
            fVar16 = (&creature_pool)[local_7c].target_x - *pfVar15;
            fVar14 = (&creature_pool)[local_7c].target_y - (&creature_pool)[local_7c].pos_y;
            if (SQRT(fVar16 * fVar16 + fVar14 * fVar14) < 40.0) {
              *(undefined1 *)&(&creature_pool)[local_7c].force_target = 1;
            }
            fVar16 = (&creature_pool)[local_7c].target_x - *pfVar15;
            fVar14 = (&creature_pool)[local_7c].target_y - (&creature_pool)[local_7c].pos_y;
            if (400.0 < SQRT(fVar16 * fVar16 + fVar14 * fVar14)) {
              *(undefined1 *)&(&creature_pool)[local_7c].force_target = 1;
            }
            if (((char)(&creature_pool)[local_7c].force_target != '\0') ||
               ((&creature_pool)[local_7c].ai_mode == 2)) {
              cVar9 = (char)(&creature_pool)[local_7c].target_player;
              (&creature_pool)[local_7c].target_x = (&player_state_table)[cVar9].pos_x;
              (&creature_pool)[local_7c].target_y = (&player_state_table)[cVar9].pos_y;
            }
            fVar10 = (float10)fpatan((float10)(&creature_pool)[local_7c].target_y -
                                     (float10)(&creature_pool)[local_7c].pos_y,
                                     (float10)(&creature_pool)[local_7c].target_x -
                                     (float10)*pfVar15);
            (&creature_pool)[local_7c].target_heading = (float)(fVar10 + (float10)1.5707964);
            if (((0.0 < bonus_energizer_timer) && ((&creature_pool)[local_7c].max_health < 500.0))
               || ((&creature_pool)[local_7c].collision_flag != '\0')) {
              (&creature_pool)[local_7c].target_heading =
                   (float)(fVar10 + (float10)1.5707964 + (float10)3.1415927);
            }
            uVar7 = (&creature_pool)[local_7c].flags;
            if ((uVar7 & 4) == 0) {
              if ((&creature_pool)[local_7c].ai_mode != 7) {
                angle_approach(&(&creature_pool)[local_7c].heading,
                               (&creature_pool)[local_7c].target_heading,
                               (&creature_pool)[local_7c].move_speed * 0.33333334 * 4.0);
                fVar10 = (float10)(&creature_pool)[local_7c].heading - (float10)1.5707964;
                fVar11 = (float10)fcos(fVar10);
                (&creature_pool)[local_7c].vel_x =
                     (float)(fVar11 * (float10)frame_dt * (float10)local_70 *
                             (float10)(&creature_pool)[local_7c].move_speed * (float10)30.0);
                fVar10 = (float10)fsin(fVar10);
                (&creature_pool)[local_7c].vel_y =
                     (float)(fVar10 * (float10)frame_dt * (float10)local_70 *
                             (float10)(&creature_pool)[local_7c].move_speed * (float10)30.0);
                vec2_add_inplace(local_7c,pfVar15,&(&creature_pool)[local_7c].vel_x);
              }
            }
            else {
              if (*pfVar15 < (&creature_pool)[local_7c].size) {
                *pfVar15 = (&creature_pool)[local_7c].size;
              }
              if ((&creature_pool)[local_7c].pos_y < (&creature_pool)[local_7c].size) {
                (&creature_pool)[local_7c].pos_y = (&creature_pool)[local_7c].size;
              }
              fVar16 = 1024.0 - (&creature_pool)[local_7c].size;
              if (fVar16 < *pfVar15) {
                *pfVar15 = fVar16;
              }
              if (fVar16 < (&creature_pool)[local_7c].pos_y) {
                (&creature_pool)[local_7c].pos_y = fVar16;
              }
              if ((uVar7 & 0x40) == 0) {
                (&creature_pool)[local_7c].vel_y = 0.0;
                (&creature_pool)[local_7c].vel_x = 0.0;
              }
              else {
                angle_approach(&(&creature_pool)[local_7c].heading,
                               (&creature_pool)[local_7c].target_heading,
                               (&creature_pool)[local_7c].move_speed * 0.33333334 * 4.0);
                fVar10 = (float10)(&creature_pool)[local_7c].heading - (float10)1.5707964;
                fVar11 = (float10)fcos(fVar10);
                (&creature_pool)[local_7c].vel_x =
                     (float)(fVar11 * (float10)frame_dt * (float10)local_70 *
                             (float10)(&creature_pool)[local_7c].move_speed * (float10)30.0);
                fVar10 = (float10)fsin(fVar10);
                (&creature_pool)[local_7c].vel_y =
                     (float)(fVar10 * (float10)frame_dt * (float10)local_70 *
                             (float10)(&creature_pool)[local_7c].move_speed * (float10)30.0);
                vec2_add_inplace(local_7c,pfVar15,&(&creature_pool)[local_7c].vel_x);
              }
              iVar6 = (&creature_pool)[local_7c].link_index;
              fVar16 = (&creature_spawn_slot_table)[iVar6].timer_s - frame_dt;
              (&creature_spawn_slot_table)[iVar6].timer_s = fVar16;
              if (fVar16 < 0.0) {
                iVar8 = (&creature_spawn_slot_table)[iVar6].count;
                iVar4 = (&creature_spawn_slot_table)[iVar6].limit;
                (&creature_spawn_slot_table)[iVar6].timer_s =
                     fVar16 + (&creature_spawn_slot_table)[iVar6].interval_s;
                if (iVar8 < iVar4) {
                  (&creature_spawn_slot_table)[iVar6].count = iVar8 + 1;
                  creature_spawn_template
                            ((&creature_spawn_slot_table)[iVar6].template_id,pfVar15,-100.0);
                }
              }
            }
            iVar6 = perk_count_get(perk_id_plaguebearer);
            if ((iVar6 != 0) && (plaguebearer_infection_count < 0x3c)) {
              plaguebearer_spread_infection(local_7c);
            }
            fVar16 = 30.0 / (&creature_pool)[local_7c].size;
            if ((((&creature_pool)[local_7c].flags & 4U) == 0) ||
               (((&creature_pool)[local_7c].flags & 0x40U) != 0)) {
              if ((&creature_pool)[local_7c].ai_mode != 7) {
                fVar16 = creature_type_table[(&creature_pool)[local_7c].type_id].anim_rate *
                         (&creature_pool)[local_7c].move_speed * frame_dt * fVar16 * local_70 * 25.0
                         + (&creature_pool)[local_7c].anim_phase;
                (&creature_pool)[local_7c].anim_phase = fVar16;
                while (31.0 < fVar16) {
                  fVar16 = (&creature_pool)[local_7c].anim_phase - 31.0;
                  (&creature_pool)[local_7c].anim_phase = fVar16;
                }
              }
            }
            else {
              fVar16 = creature_type_table[(&creature_pool)[local_7c].type_id].anim_rate *
                       (&creature_pool)[local_7c].move_speed * frame_dt * fVar16 * local_70 * 22.0 +
                       (&creature_pool)[local_7c].anim_phase;
              (&creature_pool)[local_7c].anim_phase = fVar16;
              if (15.0 < fVar16) {
                fVar16 = (&creature_pool)[local_7c].anim_phase;
                do {
                  fVar16 = fVar16 - 15.0;
                } while (15.0 < fVar16);
                (&creature_pool)[local_7c].anim_phase = fVar16;
              }
            }
            pfVar2 = &(&creature_pool)[local_7c].attack_cooldown;
            if ((&creature_pool)[local_7c].attack_cooldown <= 0.0) {
              *pfVar2 = 0.0;
            }
            else {
              *pfVar2 = *pfVar2 - frame_dt;
            }
            cVar9 = (char)(&creature_pool)[local_7c].target_player;
            piVar3 = &(&creature_pool)[local_7c].target_player;
            fVar16 = *pfVar15 - (&player_state_table)[cVar9].pos_x;
            fVar14 = (&creature_pool)[local_7c].pos_y - (&player_state_table)[cVar9].pos_y;
            fVar16 = SQRT(fVar16 * fVar16 + fVar14 * fVar14);
            if ((((fVar16 < 100.0) && (iVar6 = perk_count_get(perk_id_radioactive), iVar6 != 0)) &&
                (fVar14 = (&creature_pool)[local_7c].collision_timer - frame_dt * 1.5,
                (&creature_pool)[local_7c].collision_timer = fVar14, fVar14 < 0.0)) &&
               (0.0 < *pfVar13)) {
              (&creature_pool)[local_7c].collision_timer = 0.5;
              (&creature_pool)[local_7c].state_flag = '\x01';
              fVar14 = *pfVar13 - (100.0 - fVar16) * 0.3;
              *pfVar13 = fVar14;
              if (fVar14 < 0.0) {
                if ((&creature_pool)[local_7c].type_id == 1) {
                  *pfVar13 = 1.0;
                }
                else {
                  lVar12 = __ftol();
                  player_state_table.experience = (int)lVar12;
                  *pfVar1 = *pfVar1 - frame_dt;
                }
              }
              fx_queue_add_random(pfVar15);
            }
            if (64.0 < fVar16) {
              if ((((&creature_pool)[local_7c].flags & 0x10) != 0) && (*pfVar2 <= 0.0)) {
                projectile_spawn(pfVar15,(&creature_pool)[local_7c].heading,
                                 PROJECTILE_TYPE_PLASMA_RIFLE,local_7c);
                fVar14 = sfx_shock_fire;
                *pfVar2 = *pfVar2 + 1.0;
                sfx_play_panned(fVar14);
              }
              if ((((&creature_pool)[local_7c].flags & 0x100U) != 0) && (*pfVar2 <= 0.0)) {
                projectile_spawn(pfVar15,(&creature_pool)[local_7c].heading,
                                 (&creature_pool)[local_7c].orbit_radius.projectile_type,local_7c);
                uVar7 = crt_rand();
                fVar14 = sfx_plasmaminigun_fire;
                *pfVar2 = (float)(uVar7 & 3) * 0.1 + (&creature_pool)[local_7c].orbit_angle +
                          *pfVar2;
                sfx_play_panned(fVar14);
              }
            }
            if (fVar16 < 20.0) {
              *pfVar15 = *pfVar15 - (&creature_pool)[local_7c].vel_x;
              (&creature_pool)[local_7c].pos_y =
                   (&creature_pool)[local_7c].pos_y - (&creature_pool)[local_7c].vel_y;
              if (((&creature_pool)[local_7c].max_health < 380.0) && (0.0 < bonus_energizer_timer))
              {
                lVar12 = __ftol();
                player_state_table.experience = (int)lVar12;
                effect_spawn_burst(pfVar15,6);
                sfx_play_panned(sfx_ui_bonus);
                bonus_spawn_guard._0_1_ = 1;
                creature_handle_death(local_7c,false);
                bonus_spawn_guard._0_1_ = 0;
              }
            }
            if (16.0 < (&creature_pool)[local_7c].size) {
              if (30.0 <= fVar16) goto LAB_004276d6;
              if ((0.0 < (&player_state_table)[(char)*piVar3].health) &&
                 (bonus_energizer_timer <= 0.0)) {
                if (*pfVar2 <= 0.0) {
                  uVar7 = crt_rand();
                  uVar7 = uVar7 & 0x80000001;
                  if ((int)uVar7 < 0) {
                    uVar7 = (uVar7 - 1 | 0xfffffffe) + 1;
                  }
                  sfx_play_panned((float)creature_type_table[(&creature_pool)[local_7c].type_id].
                                         sfx_bank_b[uVar7]);
                  iVar6 = perk_count_get(perk_id_mr_melee);
                  if (iVar6 != 0) {
                    local_50[8] = 0.0;
                    local_50[9] = 0.0;
                    creature_apply_damage(local_7c,25.0,2,local_50 + 8);
                  }
                  if ((&player_state_table)[(char)*piVar3].shield_timer <= 0.0) {
                    iVar6 = perk_count_get(perk_id_toxic_avenger);
                    if (iVar6 == 0) {
                      iVar6 = perk_count_get(perk_id_veins_of_poison);
                      if (iVar6 == 0) goto LAB_0042733a;
                      uVar7 = (&creature_pool)[local_7c].flags | 1;
                    }
                    else {
                      uVar7 = (&creature_pool)[local_7c].flags | 3;
                    }
                    (&creature_pool)[local_7c].flags = uVar7;
                  }
LAB_0042733a:
                  player_take_damage((int)(char)*piVar3,(&creature_pool)[local_7c].contact_damage);
                  local_54 = (&player_state_table)[(char)*piVar3].pos_y -
                             (&creature_pool)[local_7c].pos_y;
                  local_58 = (&player_state_table)[(char)*piVar3].pos_x - *pfVar15;
                  vec2_normalize_dispatch(&local_58,&local_58);
                  fStack_24 = local_54 * 3.0 + (&player_state_table)[(char)*piVar3].pos_y;
                  local_50[10] = local_58 * 3.0 + (&player_state_table)[(char)*piVar3].pos_x;
                  fx_queue_add_random(local_50 + 10);
                  *pfVar2 = *pfVar2 + 1.0;
                }
                if ((((&player_plaguebearer_active)[(char)*piVar3 * 0x360] != '\0') &&
                    (*pfVar13 < 150.0)) && (plaguebearer_infection_count < 0x32)) {
                  (&creature_pool)[local_7c].collision_flag = '\x01';
                }
              }
            }
            if ((fVar16 < 30.0) && ((&creature_pool)[local_7c].size <= 30.0)) {
              *pfVar13 = 0.0;
              *pfVar1 = *pfVar1 - frame_dt;
            }
          }
        }
        else if (*pfVar1 <= 0.0) {
          *pfVar1 = *pfVar1 - frame_dt * 20.0;
        }
        else {
          fVar16 = *pfVar1 - frame_dt * 28.0;
          *pfVar1 = fVar16;
          if (0.0 < fVar16) {
            if ((((&creature_pool)[local_7c].flags & 4U) == 0) ||
               (((&creature_pool)[local_7c].flags & 0x40U) != 0)) {
              fVar10 = (float10)(&creature_pool)[local_7c].heading - (float10)1.5707964;
              fVar11 = (float10)fcos(fVar10);
              (&creature_pool)[local_7c].vel_x =
                   (float)(fVar11 * (float10)fVar16 * (float10)frame_dt * (float10)9.0);
              fVar10 = (float10)fsin(fVar10);
              (&creature_pool)[local_7c].vel_y =
                   (float)(fVar10 * (float10)fVar16 * (float10)frame_dt * (float10)9.0);
              *pfVar15 = *pfVar15 - (&creature_pool)[local_7c].vel_x;
              (&creature_pool)[local_7c].pos_y =
                   (&creature_pool)[local_7c].pos_y - (&creature_pool)[local_7c].vel_y;
            }
            else {
              (&creature_pool)[local_7c].vel_x = 0.0;
              (&creature_pool)[local_7c].vel_y = 0.0;
            }
          }
          else {
            if (config_violence_disabled == '\0') {
              if ((((&creature_pool)[local_7c].flags & 4U) == 0) ||
                 (((&creature_pool)[local_7c].flags & 0x40U) != 0)) {
                local_8 = (&creature_pool)[local_7c].size * 0.5;
                iVar6 = (&creature_pool)[local_7c].type_id;
                fVar16 = (&creature_pool)[local_7c].size;
                fVar14 = (&creature_pool)[local_7c].heading;
                local_18 = *pfVar15 - local_8;
                pfVar13 = &local_18;
                local_14 = (&creature_pool)[local_7c].pos_y - local_8;
              }
              else {
                local_10 = (&creature_pool)[local_7c].size * 0.5;
                fVar16 = (&creature_pool)[local_7c].size;
                fVar14 = (&creature_pool)[local_7c].heading;
                iVar6 = 7;
                local_20 = *pfVar15 - local_10;
                pfVar13 = &local_20;
                local_1c = (&creature_pool)[local_7c].pos_y - local_10;
              }
              iVar6 = fx_queue_add_rotated
                                (pfVar13,&(&creature_pool)[local_7c].tint_r,fVar14,fVar16,iVar6);
              if ((char)iVar6 == '\0') {
                *pfVar1 = 0.001;
                goto LAB_004276d6;
              }
            }
            creature_kill_count = creature_kill_count + 1;
            if ((config_violence_disabled == '\0') && (((&creature_pool)[local_7c].flags & 4) != 0)) {
              iVar6 = 8;
              do {
                fVar16 = 0.0;
                iVar8 = crt_rand();
                effect_spawn_blood_splatter(pfVar15,(float)(iVar8 % 0x264) * 0.01,fVar16);
                iVar6 = iVar6 + -1;
              } while (iVar6 != 0);
              iVar6 = 6;
              do {
                fVar16 = -0.07;
                iVar8 = crt_rand();
                effect_spawn_blood_splatter(pfVar15,(float)(iVar8 % 0x264) * 0.01,fVar16);
                iVar6 = iVar6 + -1;
              } while (iVar6 != 0);
              iVar6 = 5;
              do {
                fVar16 = -0.12;
                iVar8 = crt_rand();
                effect_spawn_blood_splatter(pfVar15,(float)(iVar8 % 0x264) * 0.01,fVar16);
                iVar6 = iVar6 + -1;
              } while (iVar6 != 0);
            }
            if (*(float *)((int)cv_bodiesFade + 0xc) == 0.0) {
              (&creature_pool)[local_7c].active = '\0';
            }
          }
        }
      }
    }
LAB_004276d6:
    local_7c = local_7c + 1;
    if (0x17f < local_7c) {
      return;
    }
  } while( true );
}
