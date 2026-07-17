#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct tutorial_vec2_t {
    float x;
    float y;

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern unsigned char console_open_flag;
extern int frame_dt_ms;
extern int quest_spawn_timeline;
extern int tutorial_stage_index;
extern int tutorial_stage_timer;
extern int tutorial_stage_transition_timer;
extern int tutorial_hint_index;
extern int tutorial_repeat_spawn_count;
extern creature_t *tutorial_hint_bonus_ptr;
extern bool tutorial_hint_bonus_consumed_latch;
extern int tutorial_hint_alpha;
extern int tutorial_hint_bonus_id;
extern int tutorial_hint_bonus_amount;
extern int perk_pending_count;
extern int sfx_ui_levelup;
extern char tutorial_empty_string[];

void tutorial_prompt_dialog(char *text, float alpha, char tutorial_complete);
creature_t *creature_spawn_template(int template_id, float *pos, float heading);
unsigned char creatures_none_active(void);
}

static __inline void tutorial_spawn_creature(
    int template_id,
    tutorial_vec2_t *pos,
    float x,
    float y)
{
    pos->set(x, y);
    creature_spawn_template(template_id, &pos->x, 3.14159274f);
}

static __inline creature_t *tutorial_spawn_bonus_carrier(
    tutorial_vec2_t *pos,
    float x,
    float y)
{
    pos->set(x, y);
    return creature_spawn_template(
        SPAWN_ID_ALIEN_CONST_WEAPON_BONUS_27,
        &pos->x,
        3.14159274f);
}

extern "C" void tutorial_timeline_update(void)
{
    if (console_open_flag) {
        return;
    }

    char *hint_text[7] = {
        "This is the speed powerup, it makes you move faster for\na limited amount of time.",
        "This is a weapon powerup. Picking it you gets\nyou another weapon. This one is a submachine gun.",
        "This powerup doubles all experience points gained when\nx2 powerup is active.",
        "This is the nuke powerup, picking it up causes a huge\nexposion harming all monsters nearby!",
        "Reflex Boost powerup slows down time giving you a chance to react better",
        tutorial_empty_string,
        tutorial_empty_string,
    };
    char *stage_text[10] = {
        "In this tutorial you'll learn how to play Crimsonland",
        "First learn to move by pushing the arrow keys.",
        "Now pick up the bonuses by walking over them",
        "Now learn to shoot and move at the same time.\nClick the left Mouse button to shoot.",
        "Now, move the mouse to aim at the monsters",
        "It will help you to move and shoot and aim at the same time, so practice!",
        "Now let's learn about Perks. You can pick a Perk by clicking\nthe 'level up' sign at the upper right corner of the screen.",
        "Perks can give you extra abilities that help\nyou survive in Crimsonland.",
        "Great! Now you are ready to start playing Crimsonland!",
        tutorial_empty_string,
    };
    int dt_ms = frame_dt_ms;
    quest_spawn_timeline += dt_ms;
    tutorial_stage_timer += dt_ms;
    player_state_table[0].health = 100.0f;
    if (tutorial_stage_index != 6) {
        player_state_table[0].experience = 0;
    }

    int transition = tutorial_stage_transition_timer;
    if (transition < -1) {
        transition += dt_ms;
        tutorial_stage_transition_timer = transition;
        if (transition >= -1) {
            ++tutorial_stage_index;
            if (tutorial_stage_index == 9) {
                tutorial_stage_index = 0;
            }
            tutorial_stage_transition_timer = 0;
        }
    } else {
        if (transition >= 0) {
            transition += dt_ms;
            tutorial_stage_transition_timer = transition;
        }
        if (transition > 1000) {
            tutorial_stage_transition_timer = -1;
        }
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

    int stage;
    {
        int prompt_transition = tutorial_stage_transition_timer;
        int stage_timer = tutorial_stage_timer;
        float prompt_alpha;
        if (prompt_transition >= 0) {
            prompt_alpha = (float)tutorial_stage_transition_timer;
        } else if (prompt_transition < -1) {
            prompt_alpha = (float)-prompt_transition;
        } else {
            prompt_alpha = 1000.0f;
        }
        prompt_alpha *= 0.001f;

        stage = tutorial_stage_index;
        if (prompt_alpha >= 1.0f) {
            if (stage == 5
                && stage_timer > 5000
                && prompt_transition >= -1) {
                prompt_alpha = 1.0f
                    - (float)(stage_timer - 5000) * 0.001f;
            }
        }
        if (stage == 5 && stage_timer > 6000) {
            prompt_alpha = 0.0f;
        }
        if (prompt_alpha > 1.0f) {
            prompt_alpha = 1.0f;
        } else if (prompt_alpha < 0.0f) {
            prompt_alpha = 0.0f;
        }

        if (stage >= 0 && (stage != 6 || perk_pending_count > 0)) {
            tutorial_prompt_dialog(stage_text[stage], prompt_alpha, stage == 8);
        }
    }

    tutorial_vec2_t stage3_pos2;
    transition = tutorial_stage_transition_timer;
    stage = tutorial_stage_index;
    if (!tutorial_hint_bonus_consumed_latch) {
        creature_t *carrier = tutorial_hint_bonus_ptr;
        if (carrier != 0
            && !carrier->active
            && carrier->health <= 0.0f
            && (carrier->flags & CREATURE_FLAG_BONUS_ON_DEATH)) {
            short *drop = (short *)&carrier->link_index;
            tutorial_hint_bonus_id = drop[0];
            tutorial_hint_bonus_amount = drop[1];
            tutorial_hint_bonus_consumed_latch = true;

            tutorial_vec2_t hint_spawn_pos;
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_GREEN_24,
                &hint_spawn_pos,
                128.0f,
                128.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                &hint_spawn_pos,
                152.0f,
                160.0f);
            transition = tutorial_stage_transition_timer;
            stage = tutorial_stage_index;
            ++tutorial_hint_index;
        }
        tutorial_hint_alpha -= frame_dt_ms * 3;
    } else {
        tutorial_hint_alpha += frame_dt_ms * 3;
    }
    if (tutorial_hint_alpha > 1000) {
        tutorial_hint_alpha = 1000;
    }
    if (tutorial_hint_alpha < 0) {
        tutorial_hint_alpha = 0;
    }
    if (tutorial_hint_index >= 0) {
        char *text = hint_text[tutorial_hint_index];
        if ((unsigned char)text[0] != 0xa7) {
            tutorial_prompt_dialog(
                text,
                (float)tutorial_hint_alpha * 0.001f,
                0);
            transition = tutorial_stage_transition_timer;
            stage = tutorial_stage_index;
        }
    }

    if (stage == 0) {
        if (tutorial_stage_timer > 6000 && transition == -1) {
            tutorial_repeat_spawn_count = 0;
            tutorial_hint_index = transition;
            tutorial_hint_bonus_consumed_latch = false;
            tutorial_stage_transition_timer = -1000;
        }
        return;
    }

    if (stage == 1) {
        player_state_t *player = &player_state_table[0];
        while ((!grim_interface_ptr->grim_is_key_active(
                    player->input.move_key_forward)
                && !grim_interface_ptr->grim_is_key_active(
                    player->input.move_key_backward)
                && !grim_interface_ptr->grim_is_key_active(
                    player->input.turn_key_left)
                && !grim_interface_ptr->grim_is_key_active(
                    player->input.turn_key_right))
            || tutorial_stage_transition_timer != -1) {
            ++player;
            if ((int)player >= (int)&player_state_table[2]) {
                return;
            }
        }

        tutorial_stage_transition_timer = -1000;
        sfx_play(sfx_ui_levelup, 1.0f);
        tutorial_vec2_t bonus_pos0;
        tutorial_vec2_t bonus_pos1;
        tutorial_vec2_t bonus_pos2;
        bonus_pos0.set(260.0f, 260.0f);
        bonus_pool[0].bonus_id = BONUS_ID_POINTS;
        bonus_pool[0].time.time_left = 100.0f;
        bonus_pool[0].time.time_max = 100.0f;
        bonus_pool[0].state = 0;
        bonus_pool[0].time.amount = 500;
        *(tutorial_vec2_t *)&bonus_pool[0].time.pos_x = bonus_pos0;
        effect_spawn_burst(&bonus_pool[0].time.pos_x, 12);

        bonus_pos1.set(600.0f, 400.0f);
        bonus_pool[1].bonus_id = BONUS_ID_POINTS;
        bonus_pool[1].time.time_left = 100.0f;
        bonus_pool[1].time.time_max = bonus_pool[0].time.time_left;
        bonus_pool[1].state = 0;
        bonus_pool[1].time.amount = 1000;
        *(tutorial_vec2_t *)&bonus_pool[1].time.pos_x = bonus_pos1;
        effect_spawn_burst(&bonus_pool[1].time.pos_x, 12);

        bonus_pos2.set(300.0f, 400.0f);
        bonus_pool[2].bonus_id = BONUS_ID_POINTS;
        bonus_pool[2].time.time_left = 100.0f;
        bonus_pool[2].time.time_max = bonus_pool[0].time.time_left;
        bonus_pool[2].state = 0;
        bonus_pool[2].time.amount = 500;
        *(tutorial_vec2_t *)&bonus_pool[2].time.pos_x = bonus_pos2;
        effect_spawn_burst(&bonus_pool[2].time.pos_x, 12);
        return;
    }

    if (stage == 2) {
        int bonus_count = 0;
        bonus_entry_t *bonus = bonus_pool;
        do {
            if (bonus->bonus_id != BONUS_ID_NONE) {
                break;
            }
            ++bonus;
            ++bonus_count;
        } while ((int)bonus < (int)&bonus_pool[0x10]);
        if (bonus_count == 0x10 && tutorial_stage_transition_timer == -1) {
            tutorial_stage_transition_timer = -1000;
            sfx_play(sfx_ui_levelup, 1.0f);
        }
        return;
    }

    if (stage == 3) {
        tutorial_vec2_t stage3_pos0;
        tutorial_vec2_t stage3_pos1;
        int *fire_key = &player_state_table[0].input.fire_key;
        do {
            if (grim_interface_ptr->grim_is_key_active(*fire_key)
                && tutorial_stage_transition_timer == -1) {
                tutorial_stage_transition_timer = -1000;
                sfx_play(sfx_ui_levelup, 1.0f);
                tutorial_spawn_creature(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    &stage3_pos0,
                    -164.0f,
                    412.0f);
                tutorial_spawn_creature(
                    SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                    &stage3_pos1,
                    -184.0f,
                    512.0f);
                tutorial_spawn_creature(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    &stage3_pos2,
                    -154.0f,
                    612.0f);
            }
            fire_key += sizeof(player_state_t) / sizeof(int);
        } while ((int)fire_key
            < (int)&player_state_table[2].input.fire_key);
        return;
    }

    if (stage == 4) {
        if (creatures_none_active()
            && tutorial_stage_transition_timer == -1) {
            tutorial_stage_timer = 1000;
            tutorial_stage_transition_timer = -1000;
            sfx_play(sfx_ui_levelup, 1.0f);
            tutorial_repeat_spawn_count = 0;
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_GREEN_24,
                &stage3_pos2,
                1188.0f,
                412.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                &stage3_pos2,
                1208.0f,
                512.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_GREEN_24,
                &stage3_pos2,
                1178.0f,
                612.0f);
        }
        return;
    }

    if (stage == 5) {
        int bonus_count = 0;
        bonus_entry_t *bonus = bonus_pool;
        do {
            if (bonus->bonus_id != BONUS_ID_NONE) {
                break;
            }
            ++bonus;
            ++bonus_count;
        } while ((int)bonus < (int)&bonus_pool[0x10]);
        if (bonus_count == 0x10 && creatures_none_active()) {
            ++tutorial_repeat_spawn_count;
            if (tutorial_repeat_spawn_count > 7) {
                if (tutorial_stage_transition_timer == -1) {
                    tutorial_stage_transition_timer = -1000;
                    sfx_play(sfx_ui_levelup, 1.0f);
                    player_state_table[0].experience = 3000;
                }
                return;
            }

            tutorial_hint_bonus_consumed_latch = false;
            if (tutorial_repeat_spawn_count & 1) {
                if (tutorial_repeat_spawn_count < 6) {
                    tutorial_hint_bonus_ptr = tutorial_spawn_bonus_carrier(
                        &stage3_pos2,
                        -32.0f,
                        1056.0f);
                }
                tutorial_spawn_creature(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    &stage3_pos2,
                    -164.0f,
                    412.0f);
                tutorial_spawn_creature(
                    SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                    &stage3_pos2,
                    -184.0f,
                    512.0f);
                stage3_pos2.set(-154.0f, 612.0f);
            } else {
                if (tutorial_repeat_spawn_count < 6) {
                    tutorial_hint_bonus_ptr = tutorial_spawn_bonus_carrier(
                        &stage3_pos2,
                        1056.0f,
                        1056.0f);
                }
                tutorial_spawn_creature(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    &stage3_pos2,
                    1188.0f,
                    1136.0f);
                tutorial_spawn_creature(
                    SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                    &stage3_pos2,
                    1208.0f,
                    512.0f);
                stage3_pos2.set(1178.0f, 612.0f);
            }
            creature_spawn_template(
                SPAWN_ID_ALIEN_CONST_GREEN_24,
                &stage3_pos2.x,
                3.14159274f);
            if (tutorial_repeat_spawn_count == 4) {
                tutorial_spawn_creature(
                    SPAWN_ID_SPIDER_SP1_CONST_BLUE_40,
                    &stage3_pos2,
                    512.0f,
                    1056.0f);
            }

            if (tutorial_repeat_spawn_count < 6) {
                switch (tutorial_repeat_spawn_count) {
                case 1:
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[0]
                        = BONUS_ID_SPEED;
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[1] = -1;
                    break;
                case 2:
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[0]
                        = BONUS_ID_WEAPON;
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[1] = 5;
                    break;
                case 3:
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[0]
                        = BONUS_ID_DOUBLE_EXPERIENCE;
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[1] = -1;
                    break;
                case 4:
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[0]
                        = BONUS_ID_NUKE;
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[1] = -1;
                    break;
                case 5:
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[0]
                        = BONUS_ID_REFLEX_BOOST;
                    ((short *)&tutorial_hint_bonus_ptr->link_index)[1] = -1;
                    break;
                }
            }
        }
        return;
    }

    if (stage == 6) {
        if (perk_pending_count <= 0 && transition == -1) {
            tutorial_stage_transition_timer = -1000;
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_GREEN_24,
                &stage3_pos2,
                -164.0f,
                412.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                &stage3_pos2,
                -184.0f,
                512.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_GREEN_24,
                &stage3_pos2,
                -154.0f,
                612.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_PURPLE_28,
                &stage3_pos2,
                -32.0f,
                -32.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_GREEN_24,
                &stage3_pos2,
                1188.0f,
                412.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                &stage3_pos2,
                1208.0f,
                512.0f);
            tutorial_spawn_creature(
                SPAWN_ID_ALIEN_CONST_GREEN_24,
                &stage3_pos2,
                1178.0f,
                612.0f);
        }
        return;
    }

    if (stage == 7) {
        int bonus_count = 0;
        bonus_entry_t *bonus = bonus_pool;
        do {
            if (bonus->bonus_id != BONUS_ID_NONE) {
                break;
            }
            ++bonus;
            ++bonus_count;
        } while ((int)bonus < (int)&bonus_pool[0x10]);
        if (bonus_count == 0x10
            && creatures_none_active()
            && tutorial_stage_transition_timer == -1) {
            tutorial_stage_transition_timer = -1000;
        }
        return;
    }
}
