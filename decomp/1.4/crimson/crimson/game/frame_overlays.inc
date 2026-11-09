// The frame itself draws these overlays. SDL receives the same sized and
// tinted quads and strings that the Grim virtual calls submit on x86.
#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" {
extern char freeware_name_buffer[32];
extern int freeware_name_length, freeware_low_fps_frames, highscore_record_hits, highscore_record_shots_fired;
extern int freeware_kills, freeware_rank;
extern float freeware_name_alpha;
extern unsigned char freeware_cheated, freeware_music_started;
char freeware_read_name_key();
int freeware_score_rank(int);
unsigned char freeware_save_score();
void freeware_music_start(int);
}
#endif
#if FREEWARE_EDITION >= 10300
struct AimPoint : vec2f_t {
    __forceinline AimPoint() {}
    __forceinline AimPoint(const float &px, const float &py) {
        x = px;
        y = py;
    }
};
__forceinline AimPoint operator+(const vec2f_t &a, const vec2f_t &b) {
    AimPoint result;
    result.x = a.x + b.x;
    result.y = a.y + b.y;
    return result;
}
__forceinline AimPoint operator-(const vec2f_t &a, const vec2f_t &b) {
    return AimPoint(a.x - b.x, a.y - b.y);
}

__forceinline void aim_color(float alpha) {
    if (config_player_count == 2) {
        if (current_player_index == 0)
            world_tint(.8f, .9f, 1.f, alpha);
        else
            world_tint(1.f, .9f, .8f, alpha);
    } else
        world_tint(1.f, 1.f, 1.f, alpha);
}

#endif
__forceinline void update_fps(float value) {
    if (FIELD(freeware_fps_min, run.min_fps) > value)
        FIELD(freeware_fps_min, run.min_fps) = value;
    if (FIELD(freeware_fps_max, run.max_fps) < value)
        FIELD(freeware_fps_max, run.max_fps) = value;
    int &count = FIELD(freeware_fps_count, fps_count);
    if (count < 2)
        count = 2;
    if (value != FIELD(freeware_fps, fps_history)[(count - 1) % 50])
        FIELD(freeware_fps, fps_history)[count++ % 50] = value;
}
__forceinline float average_fps() {
    float sum = 0;
    for (int i = 0; i < 50; ++i)
        sum += FIELD(freeware_fps, fps_history)[i];
    return sum * .02f;
}
#if defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION < 10400
__forceinline void edit_early_score_name() {
    if (INPUT.backspace) {
        sfx_play_panned(17, .45f, .5f);
        if (G.name_cursor > 0)
            --G.name_cursor;
        G.name.resize(G.name_cursor);
    }
    for (unsigned char key : INPUT.text) {
        if (key >= 32 && key < 127) {
            sfx_play_panned(17, .45f, .5f);
            G.name.resize(G.name_cursor);
            if (G.name_cursor < 31) {
                G.name.push_back((char)key);
                ++G.name_cursor;
            }
        }
    }
}
#endif
#if FREEWARE_EDITION == 10002
#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" freeware_score_entry freeware_last_score;
#define EARLY_NAME freeware_last_score.name
#else
#define EARLY_NAME G.name.c_str()
#endif
#if defined(CRIMSON_FREEWARE_CLIENT)
#define name_tint ui140::tint
#define name_scale(value) ui140::scale(value)
#define name_text ui140::text
#else
#define name_tint grim_interface_ptr->grim_set_color
#define name_scale(value) grim_interface_ptr->grim_set_config_var(0x11, value)
#define name_text grim_interface_ptr->grim_draw_text_mono
#endif
__forceinline void name_screen(float &pulse, float &orbit, float &cursor_alpha) {
    using namespace ui140;
    if (ACTIVE)
        FIELD(freeware_name_length, name_cursor) = 0;
    ACTIVE = 0;
    menu_tracks(false);
    begin_overlay();
    float &alpha = FIELD(freeware_name_alpha, death_clock);
    if (CLOCK - STATE_SINCE < 1)
        alpha = CLOCK - STATE_SINCE;
    else
        alpha = 1;

#ifdef CRIMSON_FREEWARE_CLIENT
    char local_output[64];
#else
    char *local_output = freeware_ui_buffer;
#endif
    begin();
    bind("reaper");
    name_tint(1, 1, 1, alpha);
    quad(10, 10, 128, 128);
    end();

    if (config_game_mode == 2) {
        name_scale(.975435f);
        name_tint(.75f, .35f, .22f, alpha * .9f);
        name_text(100, 50, "The Reaper got you.");
        name_text(100, 50, "The Reaper got you.");
        name_scale(.75435f);
        name_tint(.85f, .55f, .35f, alpha * .8f);
        sprintf(local_output, "Seconds survived: %d", (int)SECONDS);
        name_text(120, 90, local_output);
    } else {
        name_scale(.975435f);
        name_tint(.45f, .55f, .85f, alpha * .9f);
        name_text(100, 50, "The Reaper got you.");
        name_text(100, 50, "The Reaper got you.");
        name_tint(.25f, .55f, .85f, alpha * .9f);
        name_scale(.75435f);
        name_tint(.85f, .75f, .85f, alpha * .8f);
        sprintf(local_output, "Gained experience: %d", FIELD(P(current_player_index).experience, run.experience));
        name_text(150, 90, local_output);
    }
    name_scale(.75435f);
    name_tint(1, 1, 1, alpha);
    name_text(10, 165, "Who were you:");
    name_scale(1.f);
    name_text(50, 190, EARLY_NAME);
    pulse = CLOCK;
    orbit = CLOCK + CLOCK;
    if ((float)sin(pulse * 6.f) > 0.f)
        name_tint(1, 1, 1, alpha);
    else
        name_tint(1, 1, 1, alpha * .4f);
    name_text(50.f + strlen(EARLY_NAME) * 16, 190, "_");
    name_tint(.511f, .5f, .5f, alpha * .8f);
#ifdef CRIMSON_FREEWARE_CLIENT
    edit_early_score_name();
    if (INPUT.accept) {
        sfx_play_panned(17, .45f, .5f);
        G.record_score(0);
        enter(1);
        menu_tracks(false);
        STATE_SINCE = CLOCK;
    }
#else
    int key = (signed char)freeware_read_name_key();
    if (key != (signed char)0xa7) {
        sfx_play_panned(17, .45f, .5f);
        if (key == 9) {
            freeware_save_score();
            enter(1);
            menu_tracks(false);
            STATE_SINCE = CLOCK;
        } else {
            if (key == 8) {
                if (freeware_name_length > 0)
                    --freeware_name_length;
            } else {
                freeware_last_score.name[freeware_name_length++] = (char)key;
                if (freeware_name_length > 31)
                    freeware_name_length = 31;
            }
            freeware_last_score.name[freeware_name_length] = 0;
        }
    }
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
    cursor_particles(pulse, orbit);
#else
    cursor_particles_102(pulse, orbit, cursor_alpha);
#endif
    name_scale(1.f);
}
#undef EARLY_NAME
#undef name_text
#undef name_scale
#undef name_tint
#elif !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
#if FREEWARE_EDITION == 10300
extern "C" freeware_score_entry freeware_last_score;
#endif
__forceinline void format_name_rank(char *buf) {
#if FREEWARE_EDITION >= 10400
    if (freeware_rank == -1)
        sprintf(buf, "(You didn't made to 100 top scores list)");
    else
        sprintf(buf, "(You scored %d. in top 100 scores list)", freeware_rank);
#endif
}
__forceinline void leave_name_entry() {
    SCALE = 1;
    enter(1);
    ACTIVE = 0;
}

#else
__forceinline void name_screen() {
    if ((FREEWARE_EDITION != 10300 && FIELD(freeware_cheated, run.cheated)) || config_game_mode == 3) {
        SCALE = 1;
        ACTIVE = 0;
        enter(1);
        STATE_SINCE = CLOCK;
        PERK(perk_id_reflex_boosted) = 0;
        if (FREEWARE_EDITION != 10300)
            FIELD(freeware_cheated, run.cheated) = 0;
        return;
    }
    if (ACTIVE) {
#ifdef CRIMSON_FREEWARE_CLIENT
        if (FREEWARE_EDITION == 10300)
            G.name_cursor = 0;
        else
            G.name.clear();
#else
        highscore_load_table();
        freeware_name_length = 0;
        freeware_rank = freeware_score_rank(config_game_mode == 2 ? (int)SECONDS : XP) + 1;
#endif
    }
    ACTIVE = 0;
    begin_overlay();
    float alpha = CLOCK - STATE_SINCE;
    if (alpha >= 1)
        alpha = 1;
    else if (FREEWARE_EDITION >= 10400 && alpha < .8f) {
        creatures();
        shots();
    }
    FIELD(freeware_name_alpha, death_clock) = alpha;
    sprite("reaper", 10, 10, 128, 128, 0, 1, 1, 1, alpha);
    float red = config_game_mode == 2 ? .75f : .45f, green = config_game_mode == 2 ? .35f : .55f,
          blue = config_game_mode == 2 ? .22f : .85f;
    label("The Reaper got you.", 100, 50, .975435f, red, green, blue, alpha * .9f);
    label("The Reaper got you.", 100, 50, .975435f, red, green, blue, alpha * .9f);
    char buf[160];
    if (config_game_mode == 2) {
        sprintf(buf, "Seconds survived: %d", (int)SECONDS);
        label(buf, 120, 90, .75435f, .85f, .55f, .35f, alpha * .8f);
    } else {
        sprintf(buf, "Gained experience: %d", XP);
        label(buf, 150, 90, .75435f, .85f, .75f, .85f, alpha * .8f);
    }
    label("Who were you:", 10, 165, .75435f, 1, 1, 1, alpha);
#ifdef CRIMSON_FREEWARE_CLIENT
    const char *name = G.name.c_str();
#else
    const char *name = freeware_name_buffer;
#endif
    label(name, 50, 190, 1, 1, 1, 1, alpha);
#if FREEWARE_EDITION != 10002
    float fps = average_fps();
    int &low = FIELD(freeware_low_fps_frames, low_fps_frames);
    if (fps < 50)
        ++low;
    if (low > 1500)
        FIELD(freeware_shadows, shadows) = 0;
    else if (low > 1000)
        FIELD(freeware_glow, effects) = 0;
    else if (low > 500)
        FIELD(freeware_smoke, smoke) = 0;
#endif
    label("_", 50 + (float)strlen(name) * 16, 190, 1, 1, 1, 1, sin(CLOCK * 6) > 0 ? alpha : alpha * .4f);
#if !defined(FREEWARE_EDITION) || FREEWARE_EDITION != 10002
    if (fps < 15)
        label("(your fps is too low for highscore table)", 50, 222, .75435f, 1, 1, 1, alpha);
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
#if FREEWARE_EDITION == 10300
    edit_early_score_name();
#else
    if (INPUT.backspace) {
        sfx_play_panned(17, .45f, .5f);
        if (!G.name.empty())
            G.name.pop_back();
    }
    for (size_t i = 0; i < INPUT.text.size(); ++i) {
        unsigned char c = INPUT.text[i];
        if (c >= 32 && c < 127) {
            sfx_play_panned(17, .45f, .5f);
            if (G.name.size() < 31)
                G.name += (char)c;
        }
    }
#endif
    bool accepted = INPUT.accept;
    if (accepted)
        sfx_play_panned(17, .45f, .5f);
#else
    char c = freeware_read_name_key();
    if (c != (char)0xa7) {
        sfx_play_panned(17, .45f, .5f);
        if (c == '\b') {
            if (freeware_name_length > 0)
                --freeware_name_length;
        } else if (c != '\t') {
            freeware_name_buffer[freeware_name_length++] = c;
            if (freeware_name_length > 31)
                freeware_name_length = 31;
        }
        freeware_name_buffer[freeware_name_length] = 0;
    }
    bool accepted = c == '\t';
#endif
    if (accepted) {
#ifdef CRIMSON_FREEWARE_CLIENT
#if FREEWARE_EDITION == 10002
        G.record_score(0);
#else
        if (fps >= 15)
            G.record_score(fps);
#endif
#else
        freeware_save_score();
#endif
#if FREEWARE_EDITION != 10002
        SCALE = 1;
#endif
        enter(1);
#if FREEWARE_EDITION == 10002
        STATE_SINCE = CLOCK;
#else
        show_page(scores_page);
        STATE_SINCE = CLOCK - 1;
        FIELD(freeware_transition_pending, transition_pending) = 0;
        PERK(perk_id_reflex_boosted) = 0;
#endif
    }
#if FREEWARE_EDITION != 10002
    int hits = highscore_record_hits, fired = highscore_record_shots_fired;
    sprintf(buf, "Gained level: %d\nHit accuracy: %d%%\nFrags: %d\n", FIELD(P(0).level, run.level),
            fired ? (int)((double)hits / fired * 100) : 0, FIELD(freeware_kills, run.kills));
    label(buf, 60, 320, .66f, 1, 1, 1, 1);
#endif
    cursor_particles(CLOCK, CLOCK + CLOCK);
}
#endif
