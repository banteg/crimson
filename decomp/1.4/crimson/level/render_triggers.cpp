#include "freeware_level.h"
#include "../crimson/render/world_render.h"
#include <math.h>

using namespace world140;

static __forceinline float aim_distance(const vec2f_t &a, const vec2f_t &b)
{
    float dx = a.x - b.x;
    float dy = a.y - b.y;
    float squared = dx * dx;
    squared += dy * dy;
    return (float)sqrt(squared);
}

void freeware_level_map::render_triggers(unsigned char game)
{
    unsigned i;
    if (!game) {
        bind("spot");
        uv(0, 0, 1, 1);
        angle((float)sin(freeware_simulation_clock) * .2f);
        begin();
        tint(1, 1, 1, 1);
        for (i = 0; i < triggers.size(); ++i) {
            const freeware_level_trigger &trigger = *triggers[i];
            quad(CAMERA.x + trigger.position.x - 16, CAMERA.y + trigger.position.y - 16, 32, 32);
        }
        quad(CAMERA.x + start.x - 16, CAMERA.y + start.y - 16, 32, 32);
        end();
        tint(1, 1, 1, .6f);
        bind("radius");
        uv(0, 0, 1, 1);
        angle(0);
        begin();
        for (i = 0; i < triggers.size(); ++i) {
            const freeware_level_trigger &trigger = *triggers[i];
            quad(CAMERA.x + trigger.position.x - trigger.radius, CAMERA.y + trigger.position.y - trigger.radius,
                 trigger.radius * 2, trigger.radius * 2);
        }
        end();
        tint(1, 1, 1, 1);
        scale(.55f);
        grim_interface_ptr->grim_draw_text_mono(CAMERA.x + start.x, CAMERA.y + start.y - 8, "Player start");
        for (i = 0; i < triggers.size(); ++i) {
            const freeware_level_trigger &trigger = *triggers[i];
            if (trigger.type == 0)
                grim_interface_ptr->grim_draw_text_mono(
                    CAMERA.x + trigger.position.x, CAMERA.y + trigger.position.y - 8, "Creature");
            else if (trigger.type == 2)
                grim_interface_ptr->grim_draw_text_mono(
                    CAMERA.x + trigger.position.x, CAMERA.y + trigger.position.y - 8, weapon_name_get(trigger.weapon));
            else if (trigger.type == 1)
                grim_interface_ptr->grim_draw_text_mono(
                    CAMERA.x + trigger.position.x, CAMERA.y + trigger.position.y - 8, "Message");
            else
                grim_interface_ptr->grim_draw_text_mono(
                    CAMERA.x + trigger.position.x, CAMERA.y + trigger.position.y - 8, "Unknown");
        }
    } else {
        angle(0);
        source(5);
        destination(2);
        bind("part");
        uv(0, 0, 1, 1);
        tint(1, 1, 1, 1);
        begin();
        for (i = 0; i < triggers.size(); ++i) {
            const freeware_level_trigger &trigger = *triggers[i];
            if (trigger.enabled && trigger.type == 2) {
                float radius = (float)pow((float)sin(freeware_simulation_clock), 2) * 16 + 24;
                quad(CAMERA.x + trigger.position.x - radius, CAMERA.y + trigger.position.y - radius, radius * 2, radius * 2);
            }
        }
        end();
        destination(6);
        angle((float)sin(freeware_simulation_clock * 2) * .2f);
        bind("b_weapon");
        begin();
        for (i = 0; i < triggers.size(); ++i) {
            const freeware_level_trigger &trigger = *triggers[i];
            if (trigger.enabled && trigger.type == 2)
                quad(CAMERA.x + trigger.position.x - 20, CAMERA.y + trigger.position.y - 20, 40, 40);
        }
        end();
        scale(.45f);
        tint(1, 1, 1, .6f);
        for (i = 0; i < triggers.size(); ++i) {
            const freeware_level_trigger &trigger = *triggers[i];
            const vec2f_t &aim = reinterpret_cast<const freeware_player_t *>(player_state_table)->aim;
            if (trigger.enabled && trigger.type == 2 && aim_distance(aim, trigger.position) < trigger.radius) {
                grim_interface_ptr->grim_draw_text_mono(
                    aim.x + CAMERA.x + 8, aim.y + CAMERA.y - 7, weapon_name_get(trigger.weapon));
            }
        }
    }
}
