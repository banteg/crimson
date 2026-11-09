#include "overlay.h"
#include "../game/encounter_choices.h"

extern "C" {
extern unsigned char freeware_encounter_active, freeware_spawn_enabled;
extern int freeware_encounter_id, freeware_encounter_page, freeware_encounter_day;
extern char *freeware_town_choices[];
void freeware_encounter_experience();
void freeware_encounter_nine_lizards();
void freeware_encounter_endless_army();
void freeware_encounter_pineapple();
void freeware_encounter_duct_tape();
void creature_reset_all();
void projectile_reset_pools();
void terrain_generate(int ground);
void gameplay_reset_state();
int crt_sprintf(char *dst, const char *fmt, ...);
int crt_rand();
}

using namespace ui140;

extern "C" void freeware_encounter_update() {
    switch (freeware_encounter_id) {
    case 1:
        freeware_encounter_experience();
        break;
    case 2:
        freeware_encounter_nine_lizards();
        break;
    case 3:
        freeware_encounter_endless_army();
        break;
    case 4:
        freeware_encounter_pineapple();
        break;
    case 5:
        freeware_encounter_duct_tape();
        break;
    }
    ui140::aim_cursor();
}

extern "C" void freeware_career_menu_update() {
    freeware_name_alpha = freeware_simulation_clock - freeware_state_since < 1.0f
        ? freeware_simulation_clock - freeware_state_since : 1.0f;
    if (freeware_name_alpha < 0)
        freeware_name_alpha = 0;
    freeware_overlay_begin();
    scale(.65f);
    tint(.68f, .68f, .89f, 1);
    freeware_player_t *players = reinterpret_cast<freeware_player_t *>(player_state_table);
    crt_sprintf(freeware_ui_buffer, "Day %d\nExperience %d", freeware_encounter_day,
                players[current_player_index].experience);
    text(50, 40, freeware_ui_buffer);
    if (freeware_encounter_active) {
        freeware_encounter_update();
        return;
    }

    scale(.6f);
    text(100, 100, "What shall you do today?");
    vec2f_t lo;
    lo.x = 100;
    scale(.65f);
    tint(.6f, 1, .6f, 1);
    draw_choice_labels(lo, freeware_town_choices, 3);
    tint(.85f, .85f, .85f, 1);
    scale(.65f);
    if (freeware_encounter_hover == 0)
        text(100, 250, "Go out to slay animals and seek fortune.");
    scale(.5f);
    tint(1, 1, 1, 1);
    aim_cursor();

    if (freeware_encounter_hover < 0 || !left_click())
        return;
    freeware_encounter_page = 0;
    freeware_encounter_id = crt_rand() % 5 + 1;
    if (freeware_encounter_hover == 0) {
        freeware_encounter_active = 1;
        return;
    }
    if (freeware_encounter_hover == 1) {
        creature_reset_all();
        projectile_reset_pools();
        terrain_generate(1);
        vec2f_t pos = {240.0f, 320.0f};
        reinterpret_cast<freeware_player_t *>(player_state_table)[current_player_index].position = pos;
        freeware_encounter_page = 1;
        freeware_spawn_enabled = 1;
        game_state_id = 3;
    }
    if (freeware_encounter_hover == 2) {
        gameplay_reset_state();
        game_state_id = 1;
    }
}
