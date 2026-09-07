#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct tutorial_vec2_t {
    float x;
    float y;
    tutorial_vec2_t() {}
    tutorial_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

extern IGrim2D_cpp *grim_interface_ptr;

extern "C"
{
    extern unsigned char console_open_flag;
    extern int frame_dt_ms;
    extern int quest_spawn_timeline;
    extern int tutorial_stage_index;
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
    unsigned char creatures_none_active(void);
}

// Three adjacent stage fields at 0x00486fd8..0x00486fe3.
struct tutorial_stage_state_t {
    int index;
    int timer;
    int transition_timer;
};

extern "C" void tutorial_timeline_update(void)
{
    tutorial_stage_state_t &tutorial_stage_state =
        *(tutorial_stage_state_t *)&tutorial_stage_index;
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
    tutorial_stage_state.timer += dt_ms;
    player_state_table[0].health = 100.0f;
    if (tutorial_stage_state.index != 6) {
        player_state_table[0].experience = 0;
    }

    int transition = tutorial_stage_state.transition_timer;
    if (transition < -1) {
        transition += dt_ms;
        tutorial_stage_state.transition_timer = transition;
        if (transition >= -1) {
            ++tutorial_stage_state.index;
            if (tutorial_stage_state.index == 9) {
                tutorial_stage_state.index = 0;
            }
            tutorial_stage_state.transition_timer = 0;
        }
    }
    else if (transition >= 0) {
        transition += dt_ms;
        tutorial_stage_state.transition_timer = transition;
    }
    if (tutorial_stage_state.transition_timer > 1000) {
        tutorial_stage_state.transition_timer = -1;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

    {
        int prompt_transition = tutorial_stage_state.transition_timer;
        int stage_timer = tutorial_stage_state.timer;
        float prompt_alpha;
        if (prompt_transition >= 0) {
            prompt_alpha = (float)tutorial_stage_state.transition_timer * 0.001f;
        }
        else {
            if (prompt_transition < -1) {
                prompt_alpha = (float)-prompt_transition * 0.001f;
            }
            else {
                prompt_alpha = 1.0f;
            }
        }

        if (prompt_alpha >= 1.0f) {
            if (tutorial_stage_state.index == 5 && stage_timer > 5000 &&
                prompt_transition >= -1) {
                prompt_alpha = 1.0f - (float)(stage_timer - 5000) * 0.001f;
            }
        }
        if (tutorial_stage_state.index == 5 && stage_timer > 6000) {
            prompt_alpha = 0.0f;
        }
        if (prompt_alpha > 1.0f) {
            prompt_alpha = 1.0f;
        }
        else if (prompt_alpha < 0.0f) {
            prompt_alpha = 0.0f;
        }

        if (tutorial_stage_state.index >= 0 &&
            (tutorial_stage_state.index != 6 || perk_pending_count > 0)) {
            tutorial_prompt_dialog(stage_text[tutorial_stage_state.index], prompt_alpha,
                                   tutorial_stage_state.index == 8);
        }
    }

    transition = tutorial_stage_state.transition_timer;
    if (!tutorial_hint_bonus_consumed_latch) {
        creature_t *carrier = tutorial_hint_bonus_ptr;
        if (carrier != 0 && !carrier->active && carrier->health <= 0.0f &&
            (carrier->flags & CREATURE_FLAG_BONUS_ON_DEATH)) {
            tutorial_hint_bonus_id = carrier->bonus_args.bonus_id;
            tutorial_hint_bonus_amount = carrier->bonus_args.duration_override;
            tutorial_hint_bonus_consumed_latch = true;

            creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_24,
                                    (const vec2f_t *)&tutorial_vec2_t(128.0f, 128.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_SMALL_GRAY_26,
                                    (const vec2f_t *)&tutorial_vec2_t(152.0f, 160.0f),
                                    3.14159274f);
            transition = tutorial_stage_state.transition_timer;
            ++tutorial_hint_index;
        }
        tutorial_hint_alpha -= frame_dt_ms * 3;
    }
    else {
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
            tutorial_prompt_dialog(text, (float)tutorial_hint_alpha * 0.001f, 0);
            transition = tutorial_stage_state.transition_timer;
        }
    }

    if (tutorial_stage_state.index == 0) {
        if (tutorial_stage_state.timer > 6000 && transition == -1) {
            tutorial_repeat_spawn_count = 0;
            tutorial_hint_index = transition;
            tutorial_hint_bonus_consumed_latch = false;
            tutorial_stage_state.transition_timer = -1000;
        }
        return;
    }

    if (tutorial_stage_state.index == 1) {
        player_input_t *input = &player_state_table[0].input;
        while ((!grim_interface_ptr->grim_is_key_active(input->move_key_forward) &&
                !grim_interface_ptr->grim_is_key_active(input->move_key_backward) &&
                !grim_interface_ptr->grim_is_key_active(input->turn_key_left) &&
                !grim_interface_ptr->grim_is_key_active(input->turn_key_right)) ||
               tutorial_stage_state.transition_timer != -1) {
            input = (player_input_t *)((char *)input + sizeof(player_state_t));
            if ((int)&input->move_key_backward >=
                (int)&player_state_table[2].input.move_key_backward) {
                return;
            }
        }

        tutorial_stage_state.transition_timer = -1000;
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
        *(tutorial_vec2_t *)&bonus_pool[0].time.position = bonus_pos0;
        effect_spawn_burst(&bonus_pool[0].time.position, 12);

        bonus_pos1.set(600.0f, 400.0f);
        bonus_pool[1].bonus_id = BONUS_ID_POINTS;
        bonus_pool[1].time.time_left = 100.0f;
        bonus_pool[1].time.time_max = bonus_pool[0].time.time_left;
        bonus_pool[1].state = 0;
        bonus_pool[1].time.amount = 1000;
        *(tutorial_vec2_t *)&bonus_pool[1].time.position = bonus_pos1;
        effect_spawn_burst(&bonus_pool[1].time.position, 12);

        bonus_pos2.set(300.0f, 400.0f);
        bonus_pool[2].bonus_id = BONUS_ID_POINTS;
        bonus_pool[2].time.time_left = 100.0f;
        bonus_pool[2].time.time_max = bonus_pool[0].time.time_left;
        bonus_pool[2].state = 0;
        bonus_pool[2].time.amount = 500;
        *(tutorial_vec2_t *)&bonus_pool[2].time.position = bonus_pos2;
        effect_spawn_burst(&bonus_pool[2].time.position, 12);
        return;
    }

    if (tutorial_stage_state.index == 2) {
        int bonus_count = 0;
        while (bonus_count < 0x10 &&
               bonus_pool[bonus_count].bonus_id == BONUS_ID_NONE) {
            ++bonus_count;
        }
        if (bonus_count == 0x10 && tutorial_stage_state.transition_timer == -1) {
            tutorial_stage_state.transition_timer = -1000;
            sfx_play(sfx_ui_levelup, 1.0f);
        }
        return;
    }

    if (tutorial_stage_state.index == 3) {
        int *fire_key = &player_state_table[0].input.fire_key;
        do {
            if (grim_interface_ptr->grim_is_key_active(*fire_key) &&
                tutorial_stage_state.transition_timer == -1) {
                tutorial_stage_state.transition_timer = -1000;
                sfx_play(sfx_ui_levelup, 1.0f);
                creature_spawn_template(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    (const vec2f_t *)&tutorial_vec2_t(-164.0f, 412.0f), 3.14159274f);
                creature_spawn_template(
                    SPAWN_ID_ALIEN_SMALL_GRAY_26,
                    (const vec2f_t *)&tutorial_vec2_t(-184.0f, 512.0f), 3.14159274f);
                creature_spawn_template(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    (const vec2f_t *)&tutorial_vec2_t(-154.0f, 612.0f), 3.14159274f);
            }
            fire_key += sizeof(player_state_t) / sizeof(int);
        } while ((int)fire_key < (int)&player_state_table[2].input.fire_key);
        return;
    }

    if (tutorial_stage_state.index == 4) {
        if (creatures_none_active() && tutorial_stage_state.transition_timer == -1) {
            tutorial_stage_state.timer = 1000;
            tutorial_stage_state.transition_timer = -1000;
            sfx_play(sfx_ui_levelup, 1.0f);
            tutorial_repeat_spawn_count = 0;
            creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_24,
                                    (const vec2f_t *)&tutorial_vec2_t(1188.0f, 412.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_SMALL_GRAY_26,
                                    (const vec2f_t *)&tutorial_vec2_t(1208.0f, 512.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_24,
                                    (const vec2f_t *)&tutorial_vec2_t(1178.0f, 612.0f),
                                    3.14159274f);
        }
        return;
    }

    if (tutorial_stage_state.index == 5) {
        int bonus_count = 0;
        while (bonus_count < 0x10 &&
               bonus_pool[bonus_count].bonus_id == BONUS_ID_NONE) {
            ++bonus_count;
        }
        if (bonus_count == 0x10 && creatures_none_active()) {
            int repeat_count = ++tutorial_repeat_spawn_count;
            if (repeat_count > 7) {
                if (tutorial_stage_state.transition_timer == -1) {
                    tutorial_stage_state.transition_timer = -1000;
                    sfx_play(sfx_ui_levelup, 1.0f);
                    player_state_table[0].experience = 3000;
                }
                return;
            }

            tutorial_hint_bonus_consumed_latch = false;
            if (tutorial_repeat_spawn_count & 1) {
                if (tutorial_repeat_spawn_count < 6) {
                    tutorial_hint_bonus_ptr = creature_spawn_template(
                        SPAWN_ID_ALIEN_BONUS_CARRIER_27,
                        (const vec2f_t *)&tutorial_vec2_t(-32.0f, 1056.0f),
                        3.14159274f);
                }
                creature_spawn_template(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    (const vec2f_t *)&tutorial_vec2_t(-164.0f, 412.0f), 3.14159274f);
                creature_spawn_template(
                    SPAWN_ID_ALIEN_SMALL_GRAY_26,
                    (const vec2f_t *)&tutorial_vec2_t(-184.0f, 512.0f), 3.14159274f);
                creature_spawn_template(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    (const vec2f_t *)&tutorial_vec2_t(-154.0f, 612.0f), 3.14159274f);
            }
            else {
                if (tutorial_repeat_spawn_count < 6) {
                    tutorial_hint_bonus_ptr = creature_spawn_template(
                        SPAWN_ID_ALIEN_BONUS_CARRIER_27,
                        (const vec2f_t *)&tutorial_vec2_t(1056.0f, 1056.0f),
                        3.14159274f);
                }
                creature_spawn_template(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    (const vec2f_t *)&tutorial_vec2_t(1188.0f, 1136.0f), 3.14159274f);
                creature_spawn_template(
                    SPAWN_ID_ALIEN_SMALL_GRAY_26,
                    (const vec2f_t *)&tutorial_vec2_t(1208.0f, 512.0f), 3.14159274f);
                creature_spawn_template(
                    SPAWN_ID_ALIEN_CONST_GREEN_24,
                    (const vec2f_t *)&tutorial_vec2_t(1178.0f, 612.0f), 3.14159274f);
            }
            if (tutorial_repeat_spawn_count == 4) {
                creature_spawn_template(
                    SPAWN_ID_SPIDER_SMALL_BLUE_40,
                    (const vec2f_t *)&tutorial_vec2_t(512.0f, 1056.0f), 3.14159274f);
            }

            if (tutorial_repeat_spawn_count < 6) {
                switch (tutorial_repeat_spawn_count) {
                case 1:
                    tutorial_hint_bonus_ptr->bonus_args.bonus_id = BONUS_ID_SPEED;
                    tutorial_hint_bonus_ptr->bonus_args.duration_override = -1;
                    break;
                case 2:
                    tutorial_hint_bonus_ptr->bonus_args.bonus_id = BONUS_ID_WEAPON;
                    tutorial_hint_bonus_ptr->bonus_args.duration_override = 5;
                    break;
                case 3:
                    tutorial_hint_bonus_ptr->bonus_args.bonus_id =
                        BONUS_ID_DOUBLE_EXPERIENCE;
                    tutorial_hint_bonus_ptr->bonus_args.duration_override = -1;
                    break;
                case 4:
                    tutorial_hint_bonus_ptr->bonus_args.bonus_id = BONUS_ID_NUKE;
                    tutorial_hint_bonus_ptr->bonus_args.duration_override = -1;
                    break;
                case 5:
                    tutorial_hint_bonus_ptr->bonus_args.bonus_id =
                        BONUS_ID_REFLEX_BOOST;
                    tutorial_hint_bonus_ptr->bonus_args.duration_override = -1;
                    break;
                }
            }
        }
        return;
    }

    if (tutorial_stage_state.index == 6) {
        if (perk_pending_count <= 0 && transition == -1) {
            tutorial_stage_state.transition_timer = -1000;
            creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_24,
                                    (const vec2f_t *)&tutorial_vec2_t(-164.0f, 412.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_SMALL_GRAY_26,
                                    (const vec2f_t *)&tutorial_vec2_t(-184.0f, 512.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_24,
                                    (const vec2f_t *)&tutorial_vec2_t(-154.0f, 612.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_CONST_PURPLE_28,
                                    (const vec2f_t *)&tutorial_vec2_t(-32.0f, -32.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_24,
                                    (const vec2f_t *)&tutorial_vec2_t(1188.0f, 412.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_SMALL_GRAY_26,
                                    (const vec2f_t *)&tutorial_vec2_t(1208.0f, 512.0f),
                                    3.14159274f);
            creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_24,
                                    (const vec2f_t *)&tutorial_vec2_t(1178.0f, 612.0f),
                                    3.14159274f);
        }
        return;
    }

    if (tutorial_stage_state.index == 7) {
        int bonus_count = 0;
        while (bonus_count < 0x10 &&
               bonus_pool[bonus_count].bonus_id == BONUS_ID_NONE) {
            ++bonus_count;
        }
        if (bonus_count == 0x10 && creatures_none_active() &&
            tutorial_stage_state.transition_timer == -1) {
            tutorial_stage_state.transition_timer = -1000;
        }
        return;
    }
}
