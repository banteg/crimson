#ifndef CRIMSONLAND_GAME_STATUS_OWNER_H
#define CRIMSONLAND_GAME_STATUS_OWNER_H

/*
 * The authenticated gameStatus_t declaration owns this complete 0x268-byte
 * persisted block.  The target names below retain 1.9.93 semantics while
 * restoring member access through the already recovered game_status_t.
 */
#ifdef __cplusplus
extern "C" {
#endif
extern game_status_t game_status_blob;
#ifdef __cplusplus
}
#endif

#ifdef CRIMSONLAND_USE_ORIGINAL_GAME_STATUS_OWNER
#define weapon_usage_counts game_status_blob.weapon_usage_counts
#define quest_play_counts game_status_blob.quest_play_counts
#define mode_play_survival game_status_blob.mode_play_survival
#define mode_play_rush game_status_blob.mode_play_rush
#define mode_play_typo game_status_blob.mode_play_typo
#define mode_play_other game_status_blob.mode_play_other
#define play_time_ms game_status_blob.play_time_ms
#endif

#endif
