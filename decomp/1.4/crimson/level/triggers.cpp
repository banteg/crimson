#include "freeware_level.h"
#include <math.h>

void freeware_level_map::set_texture(int handle)
{
    texture = handle;
}

void freeware_level_map::arm_triggers()
{
    for (unsigned i = 0; i < (unsigned)triggers.size(); ++i)
        triggers[i]->enabled = 1;
}

extern "C" {
extern int current_player_index;
extern creature_t creature_pool[512];
#if CL_BUILD == 10400
extern player_state_t player_state_table[2];
#define PLAYER(i) player_state_table[i].freeware
#else
extern freeware_player_t player_state_table[2];
#define PLAYER(i) player_state_table[i]
#endif
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
void weapon_assign_player(int, int);
}

static __forceinline float distance(const vec2f_t &a, const vec2f_t &b)
{
    float dx = a.x - b.x, dy = a.y - b.y;
    return (float)sqrt(dx * dx + dy * dy);
}

void freeware_level_map::update_triggers()
{
    for (unsigned i = 0; i < (unsigned)triggers.size(); ++i) {
        freeware_level_trigger *trigger = triggers[i];
        if (!trigger->enabled)
            continue;

        if (trigger->type == 0) {
            effect_color_t color = {0.8f, 0.8f, 0.8f, 1.0f};
            int index = creature_spawn(&trigger->position, &color, 1);
            creature_pool[index].ai_mode = 0;
            creature_pool[index].activation_radius = trigger->radius;
            trigger->enabled = 0;
        } else {
            const vec2f_t &pos = PLAYER(current_player_index).position;
            if (distance(trigger->position, pos) < trigger->radius && trigger->type == 2) {
                weapon_assign_player(current_player_index, trigger->weapon);
                trigger->enabled = 0;
            }
        }
    }
}
