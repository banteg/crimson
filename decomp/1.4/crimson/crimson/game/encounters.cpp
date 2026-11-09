#include "crimsonland_types.h"
#include "encounter_choices.h"

extern "C" {
extern freeware_player_t player_state_table[2];
extern int current_player_index, game_state_id, freeware_encounter_page, freeware_encounter_day;
extern unsigned char freeware_spawn_enabled, freeware_encounter_active;
extern char *freeware_encounter_choices[];
char *wrap_text_to_width_alloc(char *, int);
char *strdup_malloc(const char *);
void crt_free(void *);
void projectile_reset_pools();
void creature_reset_all();
void terrain_generate(int ground);
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
}

namespace {
__forceinline void tint(float r, float g, float b, float a) {
    grim_interface_ptr->grim_set_color(r, g, b, a);
}

__forceinline void set_text_scale() {
    grim_interface_ptr->grim_set_config_var(0x11, .65f);
}

__forceinline void narration(char *description) {
    char *wrapped = wrap_text_to_width_alloc(description, 30);
    grim_interface_ptr->grim_draw_text_mono(30, 100, wrapped);
    crt_free(wrapped);
}

__forceinline void choices(int count, char *first, char *second = 0, char *third = 0,
                           int release_count = 1, int weapon = 0) {
    vec2f_t lo;
    lo.x = 100.0f;
    set_text_scale();
    tint(.6f, 1, .6f, 1);
    freeware_encounter_choices[0] = strdup_malloc(first);
    if (count > 1)
        freeware_encounter_choices[1] = strdup_malloc(second);
    if (count > 2)
        freeware_encounter_choices[2] = strdup_malloc(third);
    if (weapon)
        player_state_table[current_player_index].weapon = weapon;
    draw_choice_labels(lo, freeware_encounter_choices, count);
    // The experience and nine-lizard result pages also free the second label.
    crt_free(freeware_encounter_choices[0]);
    if (release_count > 1)
        crt_free(freeware_encounter_choices[1]);
    if (release_count > 2)
        crt_free(freeware_encounter_choices[2]);
}

__forceinline bool clicked() {
    return freeware_encounter_hover >= 0 && grim_interface_ptr->grim_was_mouse_button_pressed(0);
}

__forceinline void battle(int ground, float px, float py, int size, float x, float alpha, bool endless) {
    creature_reset_all();
    projectile_reset_pools();
    terrain_generate(ground);
    vec2f_t start = {px, py};
    player_state_table[current_player_index].position = start;
    freeware_encounter_page = 1;
    if (endless)
        freeware_spawn_enabled = 1;
    for (int i = 0; i < size; ++i) {
        for (int j = 0; j < size; ++j) {
            effect_color_t color = {1, 1, 1, alpha};
            vec2f_t pos = {i * 50.0f + x, j * 50.0f + 240.0f};
            creature_spawn(&pos, &color, 1);
        }
    }
    game_state_id = 3;
}
} // namespace

extern "C" void freeware_encounter_experience() {
    tint(.85f, .85f, .85f, 1);
    set_text_scale();
    if (freeware_encounter_page == 0) {
        narration(
            "You go wandering on in the desert and find 100 perfectly good experience points just "
            "lying around on the ground.");
        grim_interface_ptr->grim_draw_text_mono(100, 270, "What will you do?");
        choices(2, "Start gathering the exp. pts.", "Leave it there and go back where you came from.", 0, 2);
    } else if (freeware_encounter_page == 1) {
        narration("You grab the experience and walk away.");
        choices(1, "'I walk away'.. Got it.", 0, 0, 2);
    }
    if (clicked()) {
        if (freeware_encounter_page == 0) {
            if (freeware_encounter_hover == 0) {
                freeware_encounter_page = 1;
                game_state_id = 3;
                player_state_table[current_player_index].experience += 100;
                ++freeware_encounter_day;
            } else if (freeware_encounter_hover == 1) {
                freeware_encounter_page = 2;
                freeware_encounter_active = 0;
                ++freeware_encounter_day;
            }
        } else {
            freeware_encounter_active = 0;
        }
    }
}

extern "C" void freeware_encounter_nine_lizards() {
    tint(.85f, .85f, .85f, 1);
    set_text_scale();
    if (freeware_encounter_page == 0) {
        narration("You stumble on nine almost invisible lizards eating some delicious looking small rocks.");
        grim_interface_ptr->grim_draw_text_mono(100, 270, "What will you do?");
        choices(2, "Kick some lizard ass.", "Leave them alone.", 0, 2);
    } else if (freeware_encounter_page == 1) {
        narration("You finish slaying the lizards and head back home.");
        choices(1, "OKOK!!", 0, 0, 2);
    }
    if (clicked()) {
        if (freeware_encounter_page == 0) {
            if (freeware_encounter_hover == 0) {
                battle(3, 10, 410, 3, 550, .221f, false);
                ++freeware_encounter_day;
            } else if (freeware_encounter_hover == 1) {
                freeware_encounter_page = 2;
                ++freeware_encounter_day;
                freeware_encounter_active = 0;
            }
        } else {
            freeware_encounter_active = 0;
        }
    }
}

extern "C" void freeware_encounter_pineapple() {
    tint(.85f, .85f, .85f, 1);
    set_text_scale();
    if (freeware_encounter_page == 0) {
        narration(
            "After walking half a day you suddenly stop and dig a hole on the ground. You find a "
            "flamethrower and a pineapple. You have the strength to carry only one of them.");
        grim_interface_ptr->grim_draw_text_mono(100, 270, "What will you do?");
        choices(2, "Flamethrower it is.", "I'll have the pineapple!", 0, 2);
    } else if (freeware_encounter_page == 1) {
        narration(
            "Feeling sad about leaving the pineapple behind you grab the flamethrower and head back "
            "to your camp. (Yes, you have a camp.)");
        choices(1, "Nice, now I can burn stuff.", 0, 0, 1, 4);
    } else if (freeware_encounter_page == 2) {
        narration("Good choice! You eat the pineapple right away and forget the flamer ever even existed.");
        choices(1, "Mmmm.. delicious!");
    }
    if (clicked()) {
        if (freeware_encounter_page == 0) {
            if (freeware_encounter_hover == 0) {
                freeware_encounter_page = 1;
                ++freeware_encounter_day;
            } else if (freeware_encounter_hover == 1) {
                ++freeware_encounter_day;
                freeware_encounter_page = 2;
                player_state_table[current_player_index].health += 10.0f;
            }
        } else {
            freeware_encounter_active = 0;
        }
    }
}

extern "C" void freeware_encounter_duct_tape() {
    tint(.85f, .85f, .85f, 1);
    set_text_scale();
    if (freeware_encounter_page == 0) {
        narration("You find some duct tape and a swiss army knife. What shall you do with them?");
        grim_interface_ptr->grim_draw_text_mono(100, 270, "What will you do?");
        choices(3, "I'll make an automatic rifle kind of thingie", "I'll make an uzi", "Nothing, just give them back to Angus.", 3);
    } else if (freeware_encounter_page == 1) {
        narration(
            "With clever use of the equipments you create your self an automatic rifle kind of "
            "thingie.");
        choices(1, "I'm good at this ain't I?", 0, 0, 1, 2);
    } else if (freeware_encounter_page == 2) {
        narration("With clever use of available equipments you create your self an uzi.");
        choices(1, "Wow it's shiny.", 0, 0, 1, 5);
    } else if (freeware_encounter_page == 3) {
        narration("Angus thanks and hands you 300 experience points.");
        choices(1, "Gee wiz, thanks mister.", 0, 0, 1, 5);
    }
    if (clicked()) {
        if (freeware_encounter_page == 0) {
            if (freeware_encounter_hover == 0) {
                freeware_encounter_page = 1;
                ++freeware_encounter_day;
            } else if (freeware_encounter_hover == 1) {
                ++freeware_encounter_day;
                freeware_encounter_page = 2;
            } else {
                ++freeware_encounter_day;
                freeware_encounter_page = 3;
            }
        } else {
            freeware_encounter_active = 0;
        }
    }
}

extern "C" void freeware_encounter_endless_army() {
    tint(.85f, .85f, .85f, 1);
    set_text_scale();
    if (freeware_encounter_page == 0) {
        narration(
            "While walking on beautiful grassland you bump into enless army of lizards and some "
            "humanoid-like creatures (like there's so many creatures to choose from).");
        grim_interface_ptr->grim_draw_text_mono(100, 270, "What will you do?");
        choices(2, "Hey! Let's kill 'em all!", "No one can slay an endless army! I'm out of here!", 0, 2);
    } else if (freeware_encounter_page == 1) {
        narration("Amazingly enough you have slain the endless army of creatures.");
        choices(1, "Yeah well what'cha gonna do about it.");
    }
    if (clicked()) {
        if (freeware_encounter_page == 0) {
            if (freeware_encounter_hover == 0) {
                battle(1, 240, 320, 5, 950, .4f, true);
                ++freeware_encounter_day;
            } else if (freeware_encounter_hover == 1) {
                freeware_encounter_page = 2;
                ++freeware_encounter_day;
                freeware_encounter_active = 0;
            }
        } else {
            freeware_encounter_active = 0;
        }
    }
}
