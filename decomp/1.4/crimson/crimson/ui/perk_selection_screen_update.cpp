#include "freeware_edition.h"
// crimson.exe 1.4.0, 0x415690.
#include "overlay.h"
#include <string.h>
#ifdef CRIMSON_FREEWARE_CLIENT
#include <cstdlib>
#endif
using namespace ui140;
extern "C" {
extern freeware_perk_entry_t perk_meta_table[48];
extern int perk_id_count, perk_id_perk_expert, freeware_perk_hover;
extern unsigned char perk_choice_flags[48], freeware_pause_perks;
extern float freeware_perk_choice_timer;
extern char *freeware_message;
int crt_rand();
void weapon_assign_player(int, int);
char *wrap_text_to_width_alloc(char *, int);
#ifndef CRIMSON_FREEWARE_CLIENT
void crt_free(void *);
char *strdup_malloc(const char *);
extern int perk_id_instant_winner, perk_id_grim_deal, perk_id_plaguebearer, perk_id_fatal_lottery,
    perk_id_weapon_assault_rifle, perk_id_weapon_shotgun, perk_id_infernal_contract, freeware_hint_ids[7];
unsigned char freeware_point_in_rect(const vec2f_t *, const vec2f_t *, const vec2f_t *);
#endif
}
namespace {
#define HOVER UI_FIELD(freeware_perk_hover, perk_hover)
#define PERKS(i) UI_FIELD(player_state_table[current_player_index].freeware.perks[i], run.perks[i])
#define XP UI_FIELD(player_state_table[current_player_index].freeware.experience, run.experience)
#define HP UI_FIELD(player_state_table[current_player_index].freeware.health, actor(current_player_index).health)
#define PENDING UI_FIELD(freeware_pending_perks, run.pending)
#ifdef CRIMSON_FREEWARE_CLIENT
#define PERK_ID(symbol, id) id
#else
#define PERK_ID(symbol, id) symbol
#endif
__forceinline bool inside(float x, float y, float right, float bottom) {
#ifdef CRIMSON_FREEWARE_CLIENT
    return UI_MOUSE_X > x && UI_MOUSE_X < right && UI_MOUSE_Y > y && UI_MOUSE_Y < bottom;
#else
    vec2f_t lo = {x, y}, hi = {right, bottom};
    return freeware_point_in_rect(&freeware_aim_screen, &lo, &hi) != 0;
#endif
}
__forceinline const char *name(int id) {
#ifdef CRIMSON_FREEWARE_CLIENT
    return freeware::perk_name(id);
#else
    return (const char *)perk_meta_table[id].name_va;
#endif
}
__forceinline const char *description(int id) {
#ifdef CRIMSON_FREEWARE_CLIENT
    return freeware::perk_description(id);
#else
    return (const char *)perk_meta_table[id].description_va;
#endif
}
__forceinline void secret_hint(const char *odd, const char *even, int chance) {
#ifdef CRIMSON_FREEWARE_CLIENT
    char *message = strdup(odd);
#else
    if (freeware_message)
        crt_free(freeware_message);
    char *message = strdup_malloc(odd);
#endif
    for (unsigned i = 0; i < strlen(even); i += 2)
        message[i] = even[i];
    if (chance) {
        for (unsigned j = 0; j < strlen(message); ++j)
            if (message[j] != ' ' && (chance == 2 ? crt_rand() % 2 == 0 : crt_rand() % 5 < 2))
                message[j] = (char)('a' + crt_rand() % 26);
    }
    char *wrapped = wrap_text_to_width_alloc(message, 25);
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.message = wrapped;
    delete[] wrapped;
    free(message);
#else
    freeware_message = wrapped;
    crt_free(message);
#endif
    set_state(7);
}
__forceinline void grant(int id) {
    UI_FIELD(freeware_pause_perks, paused_perks) = 0;
#ifndef CRIMSON_FREEWARE_CLIENT
    freeware_perk_choice_timer = 0;
#endif
    ++PERKS(id);
    if (id == PERK_ID(perk_id_instant_winner, freeware_rules::instant_winner))
        XP += 2500;
#if !defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION == 10400
    if (id == PERK_ID(perk_id_fatal_lottery, 19)) {
        if (crt_rand() % 2 == 0)
            XP += 10000;
        else
            HP = -1;
    }
    if (id == PERK_ID(perk_id_weapon_shotgun, 21)) {
        weapon_assign_player(current_player_index, 3);
        player_state_table[current_player_index].freeware.clip_size += 5;
    }
    if (id == PERK_ID(perk_id_weapon_assault_rifle, 20)) {
        weapon_assign_player(current_player_index, 2);
        player_state_table[current_player_index].freeware.clip_size += 10;
    }
#endif
    if (id == PERK_ID(perk_id_infernal_contract, freeware_rules::infernal_contract)) {
        UI_FIELD(player_state_table[current_player_index].freeware.level, run.level) += 3;
        PENDING += 3;
        HP = .1f;
    }
    if (id == PERK_ID(perk_id_grim_deal, freeware_rules::grim_deal)) {
        XP += 6666;
        HP = -1;
    }
    if (id == PERK_ID(perk_id_plaguebearer, freeware_rules::plaguebearer))
        player_state_table[current_player_index].freeware.plaguebearer = 1;
    --PENDING;
    set_state(3);
    // Secret hints are assembled from interleaved strings before the CRT chooses letters to replace.
#if !defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION == 10400
    if (id == PERK_ID(freeware_hint_ids[0], 26))
        secret_hint(" s n w y b r   t y s i l w i i g f r a m n t r t   o e   l y i   i h a s n l   h t a d g   t "
                    "n i g o   h   e d b d   f t e m n t r w i i g f r i s f i n s t   o e t a   o   p r . W e   "
                    "t n a   e t   o d t o   n   i l b   i e     i t o e c n k e   f s i l r m i i g a i e ",
                    "A   e l   o n s a   t l   a t n   o     o s e   o c m . S a   t w t     i g e s o   n   o s "
                    "a d n   n t e d a   o y o   h   o s e   a t n   o   t   r e d   o c m   e r y u a a t   h n "
                    "a   e r d a h c n i i n o e w l   e g v n a g f   n   a   e p i   t l   e a n n   l v .",
                    5);
    if (id == PERK_ID(freeware_hint_ids[1], 27))
        secret_hint(" o g t o e o   h m   n   a   o a   a d   n   a   o  c r     e s l   c r   n   a r f c   t e "
                    "f t   a n a m m n   f i m r a i y a d a d r  w a o .",
                    "T   e   n   f t e , o e h s t   s s i . O e h s t  s o e a b a t y s o e a d s c i i e i s l "
                    "  o g i     o e t o   m o t l t   n     a k  e p n ",
                    5);
    if (id == PERK_ID(freeware_hint_ids[2], 28))
        secret_hint(
            " e a e o   h   a s   n o m t o . S m   a   r   o l a   o   s r y   v r t i g d e n t m k   e s .",
            "B w r   f t e f l e i f r a i n   o e m y t y t   e d y u a t a . E e y h n   o s '   a e s n e ", 5);
    if (id == PERK_ID(freeware_hint_ids[3], 29))
        secret_hint("Always the same about the Secret Weapon: jymrmpibftxkmnmstqvxz",
                    "Always the same about the Secret Weapon: jymrmpibftxkmnmstqvxz", 0);
    if (id == PERK_ID(freeware_hint_ids[4], 30))
        secret_hint(" i a a   h e l i t   i l a t a i   n   i a t s a t i a m t a   y t a o l   u t n a n . v i ",
                    "M t h n i m e l s a k e t   a k n o ? E p   a t   a d   i a n h o y   l a k i e k a .   a ?",
                    2);
    if (id == PERK_ID(freeware_hint_ids[5], 31))
        secret_hint(" n   e t   w   i h , f u   o t   n   i   a k  And again. What does it form if left is back "
                    "and Ceasar is not only an emperor?",
                    "O e l f , t o r g t   o r f r h a d s x b c . And again. What does it form if left is back "
                    "and Ceasar is not only an emperor?",
                    5);
    if (id == PERK_ID(freeware_hint_ids[6], 32))
        secret_hint(" n y a t u   u b e b y s r i e   e c f l y o e   a s   i u t i   i h u     c a c .",
                    "O l     r e b b l   o   u v v s p a e u l   v r k k i m n u t a w t o t a s r t h ", 5);
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
    for (int i = 0; i < 48; ++i)
        player_state_table[0].freeware.perks[i] = UI_GAME.run.perks[i];
    UI_GAME.run.choices.clear();
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) || FREEWARE_EDITION != 10002
    for (int slot = 0; slot < 48; ++slot)
        player_state_table[1].freeware.perks[slot] = player_state_table[0].freeware.perks[slot];
#endif
}
} // namespace
extern "C" void perk_selection_screen_update() {
    float age = freeware_simulation_clock - UI_SINCE;
    UI_FIELD(freeware_name_alpha, death_clock) = age >= 1 ? 1 : age;
    UI_FIELD(freeware_pause_perks, paused_perks) = 1;
#ifdef CRIMSON_FREEWARE_CLIENT
    bool held = freeware_frame_input->mouse_fire || freeware_frame_input->click;
#else
    bool held = grim_interface_ptr->grim_is_mouse_button_down(0) != 0;
#endif
    if (FREEWARE_EDITION != 10002 && inside(390, 5, 590, 37) && held)
        UI_SEE_THROUGH = 1;
    freeware_overlay_begin();
    UI_SEE_THROUGH = 0;
    scale(.65f);
    tint(1, 1, 1, 1);
    text(150, 40, "Pick a perk:");
    tint(.68f, .68f, .89f, 1);
    scale(.55f);
    if (PERKS(perk_id_perk_expert) <= 0)
        text(285, 43, "(of random 5)");
    else {
        text(285, 43, "(of random 5+2)");
        scale(.5f);
        tint(1, 1, 1, 1);
        text(130, 57, "Extra perks sponsored by the Perk Expert");
    }
    tint(.78f, .78f, .49f, inside(390, 5, 590, 37) ? 1.f : .5f);
    scale(.65f);
    if (FREEWARE_EDITION != 10002)
        text(390, 5, "(click to see through)");
    if (HOVER >= 0) {
        int count = 0;
        for (int i = 0; i <= HOVER; ++i)
            if (perk_choice_flags[i])
                ++count;
        tint(.8f, .8f, .8f, .3f);
#ifdef CRIMSON_FREEWARE_CLIENT
        bind("bullet");
#else
        bind(freeware_bullet_texture);
#endif
        uv(0, 0, 1, 1);
        begin();
        quad(45, 82.f + (count - 1) * 20, 350, 15);
        end();
    }
    scale(.65f);
    tint(.6f, 1, .6f, 1);
    int row = 0;
    HOVER = -1;
    for (int id = 0; id <= perk_id_count; ++id)
        if (perk_choice_flags[id]) {
            float y = 85.f + row * 20;
            tint(.9f, 1, .7f, .7f);
            if (inside(45, y, 295, y + 15)) {
                tint(.9f, 1, .7f, 1);
                HOVER = id;
#ifdef CRIMSON_FREEWARE_CLIENT
                UI_GAME.selected = row;
#endif
            }
            if (PERKS(id) > 0)
                tint(.9f, 1, .9f, 1);
            if (config_player_count == 2 && !perk_meta_table[id].available)
                tint(.9f, 1, .9f, .3f);
            text(50, y - 5, name(id));
            ++row;
        }
    tint(.85f, .85f, .85f, 1);
    scale(.65f);
    if (HOVER >= 0) {
        text(100, 250, description(HOVER));
        filter(1);
#ifndef CRIMSON_FREEWARE_CLIENT
        bind(perk_meta_table[HOVER].texture);
#endif
        uv(0, 0, 1, 1);
        tint(1, 1, 1, 1);
        angle(0);
        begin();
        end();
        filter(2);
    }
    scale(.5f);
    tint(1, 1, 1, 1);
    aim_cursor();
    if (HOVER >= 0 && left_click())
        grant(HOVER);
}

#ifdef CRIMSON_FREEWARE_CLIENT
extern "C" void freeware_grant_perk(int id) { grant(id); }
#endif
