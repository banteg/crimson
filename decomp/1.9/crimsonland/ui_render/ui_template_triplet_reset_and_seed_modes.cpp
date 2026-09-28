#include "crimsonland_gameplay.h"

extern "C" ui_menu_template_triplet_t *__fastcall ui_template_triplet_reset_and_seed_modes(
    ui_menu_template_triplet_t *block)
{
    block->blocks[0].quad_mode = 4;
    block->blocks[1].quad_mode = 4;
    block->blocks[2].quad_mode = 4;
    block->tail_state_2f8 = 0;
    block->tail_active_314 = 0;
    block->head_state_38 = 0;
    block->head_state_34 = 0;
    block->active = 0;
    return block;
}
