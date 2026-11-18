#include "crimsonland_console.h"
#include "crimsonland_types.h"

extern "C" {
int console_cmd_argc_get(void);
int freeware_atoi(char *text);
double crt_atof_l(char *text);
int sfx_play_panned(int sample, float volume, float pan);
int creature_spawn(const vec2f_t *position, const effect_color_t *color, int type);
unsigned char freeware_score_merge(const char *source_path);

extern void *freeware_sfx_samples[64];
extern int freeware_console_creature_health;
extern int freeware_console_creature_size;
extern unsigned char freeware_cheated;
extern creature_t creature_pool[];
extern effect_color_t freeware_creature_spawn_tint;
}

struct console_spawn_color_t : effect_color_t {
    console_spawn_color_t(float red, float green, float blue, float alpha)
    {
        r = red;
        g = green;
        b = blue;
        a = alpha;
    }
};

struct console_spawn_position_t : vec2f_t {
    console_spawn_position_t(float px, float py)
    {
        x = px;
        y = py;
    }
};

extern "C" void freeware_console_cmd_givegun(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(&console_log_queue, "givegun <weaponnum>\n");
        return;
    }
    console_printf(&console_log_queue, "Command is disabled.\n");
}

extern "C" void freeware_console_cmd_giveperk(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(&console_log_queue, "giveperk <perknum>\n");
        return;
    }
    console_printf(&console_log_queue, "Command is disabled.\n");
}

extern "C" void freeware_console_cmd_playsample(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(&console_log_queue, "playsample <samplenum>\n");
        return;
    }
    const int sample = freeware_atoi(console_cmd_arg_get(1));
    if (sample < 0 || sample >= 64) {
        // The native handler omits the formatting argument on this path.
        console_printf(&console_log_queue, "Invalid sample number %i (range is 0..63)\n");
        return;
    }
    if (!freeware_sfx_samples[sample]) {
        console_printf(&console_log_queue, "Sample slot %i is empty.\n", sample);
        return;
    }
    if (sample == 29 || sample == 30 || sample == 31) {
        console_printf(&console_log_queue, "No don't play that one :)\n", sample);
        return;
    }
    sfx_play_panned(sample, 0.45f, 0.5f);
    console_printf(&console_log_queue, "Playing sample %i..\n", sample);
}

extern "C" void freeware_console_cmd_setcreaturecolor(void)
{
    if (console_cmd_argc_get() != 5) {
        console_printf(&console_log_queue, "setcreaturecolor <r> <g> <b> <a>\n");
        return;
    }
    float r = (float)crt_atof_l(console_cmd_arg_get(1));
    float g = (float)crt_atof_l(console_cmd_arg_get(2));
    float b = (float)crt_atof_l(console_cmd_arg_get(3));
    float a = (float)crt_atof_l(console_cmd_arg_get(4));
    if (r > 1.0f || g > 1.0f || b > 1.0f || a > 1.0f ||
        r < 0.0f || g < 0.0f || b < 0.0f || a < 0.0f) {
        console_printf(&console_log_queue, "rgba color values must be in range 0.0 to 1.0.\n");
        return;
    }
    freeware_creature_spawn_tint = console_spawn_color_t(r,
        (float)crt_atof_l(console_cmd_arg_get(2)),
        (float)crt_atof_l(console_cmd_arg_get(3)),
        (float)crt_atof_l(console_cmd_arg_get(4)));
    console_printf(&console_log_queue,
        "Next spawned creature will be colored (%.2f,%.2f,%.2f,%.2f) (RGBA).\n",
        freeware_creature_spawn_tint.r, freeware_creature_spawn_tint.g,
        freeware_creature_spawn_tint.b, freeware_creature_spawn_tint.a);
}

extern "C" void freeware_console_cmd_setcreaturehealth(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(&console_log_queue, "setcreaturehealth <health>\n");
        return;
    }
    freeware_console_creature_health = freeware_atoi(console_cmd_arg_get(1));
    console_printf(&console_log_queue, "Next spawned creature will have %i health.\n",
                   freeware_console_creature_health);
}

static inline int spawn_creature_at(const vec2f_t &position)
{
    return creature_spawn(&position, &freeware_creature_spawn_tint, 1);
}

extern "C" void freeware_console_cmd_spawncreature(void)
{
    if (console_cmd_argc_get() != 3) {
        console_printf(&console_log_queue, "spawncreature <x> <y>\n");
        return;
    }
    int x = freeware_atoi(console_cmd_arg_get(1));
    int y = freeware_atoi(console_cmd_arg_get(2));

    int index = spawn_creature_at(console_spawn_position_t((float)x, (float)y));
    creature_pool[index].health = (float)freeware_console_creature_health;
    creature_pool[index].freeware.size = (float)freeware_console_creature_size;
    if (!freeware_cheated) {
        freeware_cheated = 1;
        console_printf(&console_log_queue, "You have been marked as a cheater. (No highscore entry allowed for this game)\n");
    }
    console_printf(&console_log_queue, "Creature spawned to (%i,%i)", x, y);
}

extern "C" void freeware_console_cmd_mergehighs(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(&console_log_queue, "mergehighs <otherscorefile>\n");
        return;
    }
    freeware_score_merge(console_cmd_arg_get(1));
}
