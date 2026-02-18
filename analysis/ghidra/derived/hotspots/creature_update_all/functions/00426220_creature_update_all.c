/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: creature_update_all */
/* function_mapped: creature_update_all */
/* address: 0x00426220 */
/* byte_range: [761016, 791316) */
/* creature_update_all @ 00426220 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* primary creature update loop: AI, movement, attacks, and animation phase */

void creature_update_all(void)

{
  float *pfVar1;
  uchar *puVar2;
  float *pfVar3;
  int *piVar4;
  int iVar5;
  float fVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  char cVar10;
  float10 fVar11;
  float10 fVar12;
  longlong lVar13;
  float *pfVar14;
  float fVar15;
  float *pfVar16;
  float fVar17;
  int local_7c;
  float local_78;
  float local_70;
  float local_6c;
  float local_60;
  float local_50 [12];
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
        pfVar14 = &(&creature_pool)[local_7c].health;
        if (((&creature_pool)[local_7c].health <= 0.0) &&
           ((&creature_pool)[local_7c].hitbox_size == 16.0)) {
          (&creature_pool)[local_7c].hitbox_size = (&creature_pool)[local_7c].hitbox_size - frame_dt
          ;
        }
        if (((&creature_pool)[local_7c].flags & 2U) == 0) {
          if (((&creature_pool)[local_7c].flags & 1U) != 0) {
            fVar17 = frame_dt * 60.0;
            pfVar16 = local_50 + 2;
            local_50[2] = 0.0;
            local_50[3] = 0.0;
            goto LAB_0042634c;
          }
        }
        else {
          fVar17 = frame_dt * 180.0;
          pfVar16 = local_50;
          local_50[0] = 0.0;
          local_50[1] = 0.0;
LAB_0042634c:
          creature_apply_damage(local_7c,fVar17,0,pfVar16);
        }
        if (((&creature_pool)[local_7c].flags & 0x80) != 0) {
          iVar7 = (&creature_pool)[local_7c].link_index;
          if (iVar7 < 0) {
            iVar7 = iVar7 + frame_dt_ms;
            (&creature_pool)[local_7c].link_index = iVar7;
            if (-1 < iVar7) {
              uVar8 = crt_rand();
              (&creature_pool)[local_7c].ai_mode = 7;
              (&creature_pool)[local_7c].link_index = (uVar8 & 0x1ff) + 500;
            }
          }
          else {
            iVar7 = iVar7 - frame_dt_ms;
            (&creature_pool)[local_7c].link_index = iVar7;
            if (iVar7 < 1) {
              uVar8 = crt_rand();
              (&creature_pool)[local_7c].link_index = -700 - (uVar8 & 0x3ff);
            }
          }
        }
        if ((*pfVar14 <= 0.0) && ((&creature_pool)[local_7c].hitbox_size == 16.0)) {
          (&creature_pool)[local_7c].hitbox_size = (&creature_pool)[local_7c].hitbox_size - frame_dt
          ;
        }
        cVar10 = (char)(&creature_pool)[local_7c].target_player;
        iVar7 = (int)cVar10;
        pfVar16 = &(&creature_pool)[local_7c].pos_x;
        iVar9 = iVar7 * 0x360;
        fVar17 = (&player_state_table)[iVar7].pos_x - *pfVar16;
        fVar15 = (&player_state_table)[iVar7].pos_y - (&creature_pool)[local_7c].pos_y;
        local_78 = SQRT(fVar15 * fVar15 + fVar17 * fVar17);
        if (creature_update_tick % 0x46 != 0) {
          if (_config_player_count == 2) {
            if ((0.0 < (float)(&player2_health)[iVar7 * -0xd8]) &&
               (fVar17 = (float)(&player2_pos_y)[iVar7 * -0xd8] - (&creature_pool)[local_7c].pos_y,
               local_6c = SQRT(fVar17 * fVar17 +
                               ((float)(&player2_pos_x)[iVar7 * -0xd8] - *pfVar16) *
                               ((float)(&player2_pos_x)[iVar7 * -0xd8] - *pfVar16)),
               local_6c < local_78)) {
              *(char *)&(&creature_pool)[local_7c].target_player = '\x01' - cVar10;
              local_78 = local_6c;
            }
          }
          else {
            fVar17 = player_state_table.pos_y - (&creature_pool)[local_7c].pos_y;
            local_6c = SQRT(fVar17 * fVar17 +
                            (player_state_table.pos_x - *pfVar16) *
                            (player_state_table.pos_x - *pfVar16));
          }
          cVar10 = (char)(&creature_pool)[local_7c].target_player;
          iVar7 = (int)cVar10;
          iVar9 = iVar7 * 0x360;
          fVar17 = player_state_table.pos_x -
                   (&creature_pool)[(&player_state_table)[iVar7].auto_target].pos_x;
          fVar15 = player_state_table.pos_y -
                   (&creature_pool)[(&player_state_table)[iVar7].auto_target].pos_y;
          if (local_6c < SQRT(fVar15 * fVar15 + fVar17 * fVar17)) {
            (&player_state_table)[iVar7].auto_target = local_7c;
          }
        }
        if (*(float *)(player_state_table._pad0 + iVar9 + -0x14) <= 0.0) {
          *(char *)&(&creature_pool)[local_7c].target_player = '\x01' - cVar10;
        }
        pfVar1 = &(&creature_pool)[local_7c].hitbox_size;
        if ((&creature_pool)[local_7c].hitbox_size == 16.0) {
          puVar2 = &(&creature_pool)[local_7c].collision_flag;
          if ((&creature_pool)[local_7c].collision_flag != '\0') {
            fVar17 = (&creature_pool)[local_7c].collision_timer - frame_dt;
            (&creature_pool)[local_7c].collision_timer = fVar17;
            if (fVar17 < 0.0) {
              (&creature_pool)[local_7c].state_flag = '\x01';
              (&creature_pool)[local_7c].collision_timer = fVar17 + 0.5;
              fVar17 = *pfVar14;
              *pfVar14 = fVar17 - 15.0;
              if (fVar17 - 15.0 < 0.0) {
                plaguebearer_infection_count = plaguebearer_infection_count + 1;
                creature_handle_death(local_7c,true);
                uVar8 = crt_rand();
                uVar8 = uVar8 & 0x80000001;
                if ((int)uVar8 < 0) {
                  uVar8 = (uVar8 - 1 | 0xfffffffe) + 1;
                }
                sfx_play_panned((float)creature_type_table[(&creature_pool)[local_7c].type_id].
                                       sfx_bank_b[uVar8]);
              }
              fx_queue_add_random(pfVar16);
            }
          }
          iVar7 = player_state_table.evil_eyes_target_creature;
          fVar17 = (&creature_pool)[local_7c].phase_seed;
          *(undefined1 *)&(&creature_pool)[local_7c].force_target = 0;
          local_70 = 1.0;
          fVar17 = (float)(int)fVar17 * 3.7 * 3.1415927;
          if (local_7c != iVar7) {
            iVar7 = (&creature_pool)[local_7c].ai_mode;
            if (iVar7 == 0) {
              iVar7 = (int)(char)(&creature_pool)[local_7c].target_player;
              if (800.0 < local_78) {
LAB_0042676e:
                fVar15 = (&player_state_table)[iVar7].pos_y;
                (&creature_pool)[local_7c].target_x = (&player_state_table)[iVar7].pos_x;
                (&creature_pool)[local_7c].target_y = fVar15;
              }
              else {
                fVar11 = (float10)fcos((float10)fVar17);
                (&creature_pool)[local_7c].target_x =
                     (float)(fVar11 * (float10)local_78 * (float10)0.85 +
                            (float10)(&player_state_table)[iVar7].pos_x);
                fVar11 = (float10)fsin((float10)fVar17);
                (&creature_pool)[local_7c].target_y =
                     (float)(fVar11 * (float10)local_78 * (float10)0.85 +
                            (float10)(&player_state_table)[iVar7].pos_y);
              }
            }
            else if (iVar7 == 8) {
              fVar11 = (float10)fcos((float10)fVar17);
              cVar10 = (char)(&creature_pool)[local_7c].target_player;
              (&creature_pool)[local_7c].target_x =
                   (float)(fVar11 * (float10)local_78 * (float10)0.9 +
                          (float10)(&player_state_table)[cVar10].pos_x);
              fVar11 = (float10)fsin((float10)fVar17);
              (&creature_pool)[local_7c].target_y =
                   (float)(fVar11 * (float10)local_78 * (float10)0.9 +
                          (float10)(&player_state_table)[cVar10].pos_y);
            }
            else if (iVar7 == 1) {
              iVar7 = (int)(char)(&creature_pool)[local_7c].target_player;
              if (800.0 < local_78) goto LAB_0042676e;
              fVar11 = (float10)fcos((float10)fVar17);
              (&creature_pool)[local_7c].target_x =
                   (float)(fVar11 * (float10)local_78 * (float10)0.55 +
                          (float10)(&player_state_table)[iVar7].pos_x);
              fVar11 = (float10)fsin((float10)fVar17);
              (&creature_pool)[local_7c].target_y =
                   (float)(fVar11 * (float10)local_78 * (float10)0.55 +
                          (float10)(&player_state_table)[iVar7].pos_y);
            }
            else if (iVar7 == 3) {
              iVar7 = (&creature_pool)[local_7c].link_index;
              if ((&creature_pool)[iVar7].health <= 0.0) {
                (&creature_pool)[local_7c].ai_mode = 0;
              }
              else {
                (&creature_pool)[local_7c].target_x =
                     (&creature_pool)[iVar7].pos_x + (&creature_pool)[local_7c].target_offset_x;
                (&creature_pool)[local_7c].target_y =
                     (&creature_pool)[iVar7].pos_y + (&creature_pool)[local_7c].target_offset_y;
              }
            }
            else if (iVar7 == 5) {
              iVar7 = (&creature_pool)[local_7c].link_index;
              if ((&creature_pool)[iVar7].health <= 0.0) {
                (&creature_pool)[local_7c].ai_mode = 0;
                local_50[4] = 0.0;
                local_50[5] = 0.0;
                creature_apply_damage(local_7c,1000.0,1,local_50 + 4);
              }
              else {
                (&creature_pool)[local_7c].target_x =
                     (&creature_pool)[iVar7].pos_x + (&creature_pool)[local_7c].target_offset_x;
                (&creature_pool)[local_7c].target_y =
                     (&creature_pool)[iVar7].pos_y + (&creature_pool)[local_7c].target_offset_y;
                fVar15 = (&creature_pool)[local_7c].target_x - *pfVar16;
                fVar6 = (&creature_pool)[local_7c].target_y - (&creature_pool)[local_7c].pos_y;
                fVar15 = SQRT(fVar15 * fVar15 + fVar6 * fVar6);
                if (fVar15 <= 64.0) {
                  local_70 = fVar15 * 0.015625;
                }
              }
            }
            iVar7 = (&creature_pool)[local_7c].ai_mode;
            if (iVar7 == 4) {
              if ((&creature_pool)[(&creature_pool)[local_7c].link_index].health <= 0.0) {
                (&creature_pool)[local_7c].ai_mode = 0;
                local_50[6] = 0.0;
                local_50[7] = 0.0;
                creature_apply_damage(local_7c,1000.0,1,local_50 + 6);
              }
              else {
                cVar10 = (char)(&creature_pool)[local_7c].target_player;
                if (local_78 <= 800.0) {
                  fVar11 = (float10)fcos((float10)fVar17);
                  (&creature_pool)[local_7c].target_x =
                       (float)(fVar11 * (float10)local_78 * (float10)0.85 +
                              (float10)(&player_state_table)[cVar10].pos_x);
                  fVar11 = (float10)fsin((float10)fVar17);
                  (&creature_pool)[local_7c].target_y =
                       (float)(fVar11 * (float10)local_78 * (float10)0.85 +
                              (float10)(&player_state_table)[cVar10].pos_y);
                }
                else {
                  fVar17 = (&player_state_table)[cVar10].pos_y;
                  (&creature_pool)[local_7c].target_x = (&player_state_table)[cVar10].pos_x;
                  (&creature_pool)[local_7c].target_y = fVar17;
                }
              }
            }
            else if (iVar7 == 7) {
              uVar8 = (&creature_pool)[local_7c].flags & 0x80;
              if ((uVar8 == 0) || ((&creature_pool)[local_7c].link_index < 1)) {
                if (((&creature_pool)[local_7c].orbit_radius.radius <= 0.0) || (uVar8 != 0)) {
LAB_00426ac8:
                  (&creature_pool)[local_7c].ai_mode = 0;
                }
                else {
                  fVar15 = (&creature_pool)[local_7c].orbit_radius.radius - frame_dt;
                  fVar17 = (&creature_pool)[local_7c].pos_y;
                  (&creature_pool)[local_7c].target_x = *pfVar16;
                  (&creature_pool)[local_7c].target_y = fVar17;
                  (&creature_pool)[local_7c].orbit_radius.radius = fVar15;
                }
              }
              else {
                fVar17 = (&creature_pool)[local_7c].pos_y;
                (&creature_pool)[local_7c].target_x = *pfVar16;
                (&creature_pool)[local_7c].target_y = fVar17;
              }
            }
            else if (iVar7 == 6) {
              iVar7 = (&creature_pool)[local_7c].link_index;
              if ((&creature_pool)[iVar7].health <= 0.0) goto LAB_00426ac8;
              fVar11 = (float10)(&creature_pool)[local_7c].orbit_angle +
                       (float10)(&creature_pool)[local_7c].heading;
              fVar12 = (float10)fcos(fVar11);
              (&creature_pool)[local_7c].target_x =
                   (float)(fVar12 * (float10)(&creature_pool)[local_7c].orbit_radius.radius +
                          (float10)(&creature_pool)[iVar7].pos_x);
              fVar11 = (float10)fsin(fVar11);
              (&creature_pool)[local_7c].target_y =
                   (float)(fVar11 * (float10)(&creature_pool)[local_7c].orbit_radius.radius +
                          (float10)(&creature_pool)[iVar7].pos_y);
            }
            fVar17 = (&creature_pool)[local_7c].target_x - *pfVar16;
            fVar15 = (&creature_pool)[local_7c].target_y - (&creature_pool)[local_7c].pos_y;
            if (SQRT(fVar17 * fVar17 + fVar15 * fVar15) < 40.0) {
              *(undefined1 *)&(&creature_pool)[local_7c].force_target = 1;
            }
            fVar17 = (&creature_pool)[local_7c].target_x - *pfVar16;
            fVar15 = (&creature_pool)[local_7c].target_y - (&creature_pool)[local_7c].pos_y;
            if (400.0 < SQRT(fVar17 * fVar17 + fVar15 * fVar15)) {
              *(undefined1 *)&(&creature_pool)[local_7c].force_target = 1;
            }
            if (((char)(&creature_pool)[local_7c].force_target != '\0') ||
               ((&creature_pool)[local_7c].ai_mode == 2)) {
              cVar10 = (char)(&creature_pool)[local_7c].target_player;
              (&creature_pool)[local_7c].target_x = (&player_state_table)[cVar10].pos_x;
              (&creature_pool)[local_7c].target_y = (&player_state_table)[cVar10].pos_y;
            }
            fVar11 = (float10)fpatan((float10)(&creature_pool)[local_7c].target_y -
                                     (float10)(&creature_pool)[local_7c].pos_y,
                                     (float10)(&creature_pool)[local_7c].target_x -
                                     (float10)*pfVar16);
            (&creature_pool)[local_7c].target_heading = (float)(fVar11 + (float10)1.5707964);
            if (((0.0 < bonus_energizer_timer) && ((&creature_pool)[local_7c].max_health < 500.0))
               || (*puVar2 != '\0')) {
              (&creature_pool)[local_7c].target_heading =
                   (float)(fVar11 + (float10)1.5707964 + (float10)3.1415927);
            }
            uVar8 = (&creature_pool)[local_7c].flags;
            if ((uVar8 & 4) == 0) {
              if ((&creature_pool)[local_7c].ai_mode != 7) {
                angle_approach(&(&creature_pool)[local_7c].heading,
                               (&creature_pool)[local_7c].target_heading,
                               (&creature_pool)[local_7c].move_speed * 0.33333334 * 4.0);
                fVar11 = (float10)(&creature_pool)[local_7c].heading - (float10)1.5707964;
                fVar12 = (float10)fcos(fVar11);
                (&creature_pool)[local_7c].vel_x =
                     (float)(fVar12 * (float10)frame_dt * (float10)local_70 *
                             (float10)(&creature_pool)[local_7c].move_speed * (float10)30.0);
                fVar11 = (float10)fsin(fVar11);
                (&creature_pool)[local_7c].vel_y =
                     (float)(fVar11 * (float10)frame_dt * (float10)local_70 *
                             (float10)(&creature_pool)[local_7c].move_speed * (float10)30.0);
                vec2_add_inplace(local_7c,pfVar16,&(&creature_pool)[local_7c].vel_x);
              }
            }
            else {
              if (*pfVar16 < (&creature_pool)[local_7c].size) {
                *pfVar16 = (&creature_pool)[local_7c].size;
              }
              if ((&creature_pool)[local_7c].pos_y < (&creature_pool)[local_7c].size) {
                (&creature_pool)[local_7c].pos_y = (&creature_pool)[local_7c].size;
              }
              fVar17 = 1024.0 - (&creature_pool)[local_7c].size;
              if (fVar17 < *pfVar16) {
                *pfVar16 = fVar17;
              }
              if (fVar17 < (&creature_pool)[local_7c].pos_y) {
                (&creature_pool)[local_7c].pos_y = fVar17;
              }
              if ((uVar8 & 0x40) == 0) {
                (&creature_pool)[local_7c].vel_y = 0.0;
                (&creature_pool)[local_7c].vel_x = 0.0;
              }
              else {
                angle_approach(&(&creature_pool)[local_7c].heading,
                               (&creature_pool)[local_7c].target_heading,
                               (&creature_pool)[local_7c].move_speed * 0.33333334 * 4.0);
                fVar11 = (float10)(&creature_pool)[local_7c].heading - (float10)1.5707964;
                fVar12 = (float10)fcos(fVar11);
                (&creature_pool)[local_7c].vel_x =
                     (float)(fVar12 * (float10)frame_dt * (float10)local_70 *
                             (float10)(&creature_pool)[local_7c].move_speed * (float10)30.0);
                fVar11 = (float10)fsin(fVar11);
                (&creature_pool)[local_7c].vel_y =
                     (float)(fVar11 * (float10)frame_dt * (float10)local_70 *
                             (float10)(&creature_pool)[local_7c].move_speed * (float10)30.0);
                vec2_add_inplace(local_7c,pfVar16,&(&creature_pool)[local_7c].vel_x);
              }
              iVar7 = (&creature_pool)[local_7c].link_index;
              fVar17 = (&creature_spawn_slot_table)[iVar7].timer_s - frame_dt;
              (&creature_spawn_slot_table)[iVar7].timer_s = fVar17;
              if (fVar17 < 0.0) {
                iVar9 = (&creature_spawn_slot_table)[iVar7].count;
                iVar5 = (&creature_spawn_slot_table)[iVar7].limit;
                (&creature_spawn_slot_table)[iVar7].timer_s =
                     fVar17 + (&creature_spawn_slot_table)[iVar7].interval_s;
                if (iVar9 < iVar5) {
                  (&creature_spawn_slot_table)[iVar7].count = iVar9 + 1;
                  creature_spawn_template
                            ((&creature_spawn_slot_table)[iVar7].template_id,pfVar16,-100.0);
                }
              }
            }
            iVar7 = perk_count_get(perk_id_plaguebearer);
            if ((iVar7 != 0) && (plaguebearer_infection_count < 0x3c)) {
              plaguebearer_spread_infection(local_7c);
            }
            fVar17 = 30.0 / (&creature_pool)[local_7c].size;
            if ((((&creature_pool)[local_7c].flags & 4U) == 0) ||
               (((&creature_pool)[local_7c].flags & 0x40U) != 0)) {
              if ((&creature_pool)[local_7c].ai_mode != 7) {
                fVar17 = creature_type_table[(&creature_pool)[local_7c].type_id].anim_rate *
                         (&creature_pool)[local_7c].move_speed * frame_dt * fVar17 * local_70 * 25.0
                         + (&creature_pool)[local_7c].anim_phase;
                (&creature_pool)[local_7c].anim_phase = fVar17;
                while (31.0 < fVar17) {
                  fVar17 = (&creature_pool)[local_7c].anim_phase - 31.0;
                  (&creature_pool)[local_7c].anim_phase = fVar17;
                }
              }
            }
            else {
              fVar17 = creature_type_table[(&creature_pool)[local_7c].type_id].anim_rate *
                       (&creature_pool)[local_7c].move_speed * frame_dt * fVar17 * local_70 * 22.0 +
                       (&creature_pool)[local_7c].anim_phase;
              (&creature_pool)[local_7c].anim_phase = fVar17;
              if (15.0 < fVar17) {
                fVar17 = (&creature_pool)[local_7c].anim_phase;
                do {
                  fVar17 = fVar17 - 15.0;
                } while (15.0 < fVar17);
                (&creature_pool)[local_7c].anim_phase = fVar17;
              }
            }
            pfVar3 = &(&creature_pool)[local_7c].attack_cooldown;
            if ((&creature_pool)[local_7c].attack_cooldown <= 0.0) {
              *pfVar3 = 0.0;
            }
            else {
              *pfVar3 = *pfVar3 - frame_dt;
            }
            cVar10 = (char)(&creature_pool)[local_7c].target_player;
            piVar4 = &(&creature_pool)[local_7c].target_player;
            fVar17 = *pfVar16 - (&player_state_table)[cVar10].pos_x;
            fVar15 = (&creature_pool)[local_7c].pos_y - (&player_state_table)[cVar10].pos_y;
            fVar17 = SQRT(fVar17 * fVar17 + fVar15 * fVar15);
            if ((((fVar17 < 100.0) && (iVar7 = perk_count_get(perk_id_radioactive), iVar7 != 0)) &&
                (fVar15 = (&creature_pool)[local_7c].collision_timer - frame_dt * 1.5,
                (&creature_pool)[local_7c].collision_timer = fVar15, fVar15 < 0.0)) &&
               (0.0 < *pfVar14)) {
              (&creature_pool)[local_7c].collision_timer = 0.5;
              (&creature_pool)[local_7c].state_flag = '\x01';
              fVar15 = *pfVar14 - (100.0 - fVar17) * 0.3;
              *pfVar14 = fVar15;
              if (fVar15 < 0.0) {
                if ((&creature_pool)[local_7c].type_id == 1) {
                  *pfVar14 = 1.0;
                }
                else {
                  lVar13 = __ftol();
                  player_state_table.experience = (int)lVar13;
                  *pfVar1 = *pfVar1 - frame_dt;
                }
              }
              fx_queue_add_random(pfVar16);
            }
            if (64.0 < fVar17) {
              if ((((&creature_pool)[local_7c].flags & 0x10) != 0) && (*pfVar3 <= 0.0)) {
                projectile_spawn(pfVar16,(&creature_pool)[local_7c].heading,
                                 PROJECTILE_TYPE_PLASMA_RIFLE,local_7c);
                fVar15 = sfx_shock_fire;
                *pfVar3 = *pfVar3 + 1.0;
                sfx_play_panned(fVar15);
              }
              if ((((&creature_pool)[local_7c].flags & 0x100U) != 0) && (*pfVar3 <= 0.0)) {
                projectile_spawn(pfVar16,(&creature_pool)[local_7c].heading,
                                 (&creature_pool)[local_7c].orbit_radius.projectile_type,local_7c);
                uVar8 = crt_rand();
                fVar15 = sfx_plasmaminigun_fire;
                local_60 = (float)(uVar8 & 3);
                *pfVar3 = (float)(int)local_60 * 0.1 + (&creature_pool)[local_7c].orbit_angle +
                          *pfVar3;
                sfx_play_panned(fVar15);
              }
            }
            if (fVar17 < 20.0) {
              *pfVar16 = *pfVar16 - (&creature_pool)[local_7c].vel_x;
              (&creature_pool)[local_7c].pos_y =
                   (&creature_pool)[local_7c].pos_y - (&creature_pool)[local_7c].vel_y;
              if (((&creature_pool)[local_7c].max_health < 380.0) && (0.0 < bonus_energizer_timer))
              {
                lVar13 = __ftol();
                player_state_table.experience = (int)lVar13;
                effect_spawn_burst(pfVar16,6);
                sfx_play_panned(sfx_ui_bonus);
                bonus_spawn_guard._0_1_ = 1;
                creature_handle_death(local_7c,false);
                bonus_spawn_guard._0_1_ = 0;
              }
            }
            if (16.0 < (&creature_pool)[local_7c].size) {
              if (30.0 <= fVar17) goto LAB_004276d6;
              if ((0.0 < (&player_state_table)[(char)*piVar4].health) &&
                 (bonus_energizer_timer <= 0.0)) {
                if (*pfVar3 <= 0.0) {
                  uVar8 = crt_rand();
                  uVar8 = uVar8 & 0x80000001;
                  if ((int)uVar8 < 0) {
                    uVar8 = (uVar8 - 1 | 0xfffffffe) + 1;
                  }
                  sfx_play_panned((float)creature_type_table[(&creature_pool)[local_7c].type_id].
                                         sfx_bank_b[uVar8]);
                  iVar7 = perk_count_get(perk_id_mr_melee);
                  if (iVar7 != 0) {
                    local_50[8] = 0.0;
                    local_50[9] = 0.0;
                    creature_apply_damage(local_7c,25.0,2,local_50 + 8);
                  }
                  if ((&player_state_table)[(char)*piVar4].shield_timer <= 0.0) {
                    iVar7 = perk_count_get(perk_id_toxic_avenger);
                    if (iVar7 == 0) {
                      iVar7 = perk_count_get(perk_id_veins_of_poison);
                      if (iVar7 == 0) goto LAB_0042733a;
                      uVar8 = (&creature_pool)[local_7c].flags | 1;
                    }
                    else {
                      uVar8 = (&creature_pool)[local_7c].flags | 3;
                    }
                    (&creature_pool)[local_7c].flags = uVar8;
                  }
LAB_0042733a:
                  player_take_damage((int)(char)*piVar4,(&creature_pool)[local_7c].contact_damage);
                  thunk_FUN_00452f1d();
                  local_50[9] = (float)puVar2 * 3.0 + (&player_state_table)[(char)*piVar4].pos_y;
                  local_50[8] = local_60 * 3.0 + (&player_state_table)[(char)*piVar4].pos_x;
                  fx_queue_add_random(local_50 + 8);
                  *pfVar3 = *pfVar3 + 1.0;
                }
                if ((((&player_plaguebearer_active)[(char)*piVar4 * 0x360] != '\0') &&
                    (*pfVar14 < 150.0)) && (plaguebearer_infection_count < 0x32)) {
                  *puVar2 = '\x01';
                }
              }
            }
            if ((fVar17 < 30.0) && ((&creature_pool)[local_7c].size <= 30.0)) {
              *pfVar14 = 0.0;
              *pfVar1 = *pfVar1 - frame_dt;
            }
          }
        }
        else if (*pfVar1 <= 0.0) {
          *pfVar1 = *pfVar1 - frame_dt * 20.0;
        }
        else {
          fVar17 = *pfVar1 - frame_dt * 28.0;
          *pfVar1 = fVar17;
          if (0.0 < fVar17) {
            if ((((&creature_pool)[local_7c].flags & 4U) == 0) ||
               (((&creature_pool)[local_7c].flags & 0x40U) != 0)) {
              fVar11 = (float10)(&creature_pool)[local_7c].heading - (float10)1.5707964;
              fVar12 = (float10)fcos(fVar11);
              (&creature_pool)[local_7c].vel_x =
                   (float)(fVar12 * (float10)fVar17 * (float10)frame_dt * (float10)9.0);
              fVar11 = (float10)fsin(fVar11);
              (&creature_pool)[local_7c].vel_y =
                   (float)(fVar11 * (float10)fVar17 * (float10)frame_dt * (float10)9.0);
              *pfVar16 = *pfVar16 - (&creature_pool)[local_7c].vel_x;
              (&creature_pool)[local_7c].pos_y =
                   (&creature_pool)[local_7c].pos_y - (&creature_pool)[local_7c].vel_y;
            }
            else {
              (&creature_pool)[local_7c].vel_x = 0.0;
              (&creature_pool)[local_7c].vel_y = 0.0;
            }
          }
          else {
            if (config_fx_toggle == '\0') {
              if ((((&creature_pool)[local_7c].flags & 4U) == 0) ||
                 (((&creature_pool)[local_7c].flags & 0x40U) != 0)) {
                local_8 = (&creature_pool)[local_7c].size * 0.5;
                iVar7 = (&creature_pool)[local_7c].type_id;
                fVar17 = (&creature_pool)[local_7c].size;
                fVar15 = (&creature_pool)[local_7c].heading;
                local_18 = *pfVar16 - local_8;
                pfVar14 = &local_18;
                local_14 = (&creature_pool)[local_7c].pos_y - local_8;
              }
              else {
                local_10 = (&creature_pool)[local_7c].size * 0.5;
                fVar17 = (&creature_pool)[local_7c].size;
                fVar15 = (&creature_pool)[local_7c].heading;
                iVar7 = 7;
                local_20 = *pfVar16 - local_10;
                pfVar14 = &local_20;
                local_1c = (&creature_pool)[local_7c].pos_y - local_10;
              }
              iVar7 = fx_queue_add_rotated
                                (pfVar14,&(&creature_pool)[local_7c].tint_r,fVar15,fVar17,iVar7);
              if ((char)iVar7 == '\0') {
                *pfVar1 = 0.001;
                goto LAB_004276d6;
              }
            }
            creature_kill_count = creature_kill_count + 1;
            if ((config_fx_toggle == '\0') && (((&creature_pool)[local_7c].flags & 4) != 0)) {
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
