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
__forceinline void aim_overlays() {
    if (bonus_fire_bullets_timer > 0 && config_player_count == 1)
        sprite("part", MOUSE_X - 32, MOUSE_Y - 32, 64, 64, 0, 1, 1, 1, saturate(bonus_fire_bullets_timer));
    for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
        if (HP(current_player_index) <= 0)
            continue;
        const freeware_player_t &p = P(current_player_index);
        double dx = (double)p.aim.x - p.position.x, dy = (double)p.aim.y - p.position.y;
        float size = (float)(sqrt(dx * dx + dy * dy) * p.spread * .25);
        if (size < 16)
            size = 16;
        const char *name = size < 32 ? "aim32" : size < 64 ? "aim64" : "aim128";
        float x = CAM.x + p.aim.x, y = CAM.y + p.aim.y;
        float red = config_player_count == 2 && !current_player_index ? .8f : 1.f;
        float green = config_player_count == 2 ? .9f : 1.f;
        float blue = config_player_count == 2 && current_player_index ? .8f : 1.f;
        sprite(name, x - size * .5f, y - size * .5f, size, size, 0, red, green, blue, 1);
        sprite("aimen", x - 10, y - 10, 20, 20, CLOCK * 2, 1, 1, .1f, .7f);
    }
    for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
        if (HP(current_player_index) <= 0)
            continue;
        const freeware_player_t &p = P(current_player_index);
        double angle = (double)p.heading - 1.57079637f;
        float x = CAM.x + p.position.x + (float)cos(angle) * 60.f - 16;
        float y = (float)(CAM.y + p.position.y + sin(angle) * 60. - 16);
        if (FIELD(freeware_direction_arrow, direction_arrow))
            sprite("arrow", x, y, 32, 32, p.heading, config_player_count == 2 && !current_player_index ? .8f : 1.f,
                   config_player_count == 2 ? .9f : 1.f,
                   config_player_count == 2 && current_player_index ? .8f : 1.f, .6f);
    }
    current_player_index = 0;
}
__forceinline void update_fps(float value) {
    if (value < FIELD(freeware_fps_min, run.min_fps))
        FIELD(freeware_fps_min, run.min_fps) = value;
    if (value > FIELD(freeware_fps_max, run.max_fps))
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
__forceinline void name_screen() {
    if (FIELD(freeware_cheated, run.cheated) || config_game_mode == 3) {
        SCALE = 1;
        ACTIVE = 0;
        enter(1);
        STATE_SINCE = CLOCK;
        PERK(perk_id_reflex_boosted) = 0;
        FIELD(freeware_cheated, run.cheated) = 0;
        return;
    }
    if (ACTIVE) {
#ifdef CRIMSON_FREEWARE_CLIENT
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
