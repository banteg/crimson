#ifndef CRIMSONLAND_CONFIG_OWNER_H
#define CRIMSONLAND_CONFIG_OWNER_H

/*
 * Authenticated 1.9.93 config_t ownership.  The standalone semantic symbols
 * below are interior names within the 0x480-byte config_blob rooted at
 * 0x00480348: game_mode at +0x18, hardcore at +0x448, and the violence flag
 * at +0x46c.
 */
#ifdef __cplusplus
extern "C" {
#endif
extern crimson_cfg_t config_blob;
#ifdef __cplusplus
}
#endif

#ifdef CRIMSONLAND_USE_ORIGINAL_CONFIG_OWNER
#define config_game_mode config_blob.game_mode
#define config_hardcore config_blob.hardcore
#define config_violence_disabled config_blob.violence_disabled
#endif

#endif
