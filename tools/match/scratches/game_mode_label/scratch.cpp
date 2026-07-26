#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" char game_mode_label_buffer[];

extern "C" char *game_mode_label(void)
{
    game_mode_id_t mode = config_game_mode;
    if (mode == GAME_MODE_RUSH) {
        strcpy(game_mode_label_buffer, "Rush");
        return game_mode_label_buffer;
    }
    if (mode == GAME_MODE_SURVIVAL) {
        strcpy(game_mode_label_buffer, "Survival");
        return game_mode_label_buffer;
    }
    if (mode == GAME_MODE_QUEST) {
        strcpy(game_mode_label_buffer, "Quests");
        return game_mode_label_buffer;
    }
    if (mode == GAME_MODE_TYPO_SHOOTER) {
        strcpy(game_mode_label_buffer, "Typ'o'Shooter");
        return game_mode_label_buffer;
    }

    strcpy(game_mode_label_buffer, "Unknown");
    return game_mode_label_buffer;
}
