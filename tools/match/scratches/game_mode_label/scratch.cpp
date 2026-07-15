#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" char game_mode_label_buffer[];

extern "C" char *game_mode_label(void)
{
    char *label;
    game_mode_id_t mode = config_game_mode;
    if (mode == GAME_MODE_RUSH) {
        label = "Rush";
    } else if (mode == GAME_MODE_SURVIVAL) {
        return strcpy(game_mode_label_buffer, "Survival");
    } else if (mode == GAME_MODE_QUEST) {
        label = "Quests";
    } else if (mode == GAME_MODE_TYPO_SHOOTER) {
        return strcpy(game_mode_label_buffer, "Typ'o'Shooter");
    } else {
        label = "Unknown";
    }

    strcpy(game_mode_label_buffer, label);
    return game_mode_label_buffer;
}
