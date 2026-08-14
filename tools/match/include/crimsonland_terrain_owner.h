#ifndef CRIMSONLAND_TERRAIN_OWNER_H
#define CRIMSONLAND_TERRAIN_OWNER_H

/*
 * Authenticated 2003 terrain_t layout rooted at terrain_render_target
 * (0x0048f530).  The 1.9.93 renderer stores its target/texture handle in the
 * old bitmap-pointer slot, followed by width, height, three selectors, and
 * sixteen terrain texture handles.
 */
typedef struct terrain_original_t {
    int render_target;
    int width;
    int height;
    int selectors[3];
    int texture_handles[16];
} terrain_original_t;

#ifdef __cplusplus
extern "C" {
#endif
extern int terrain_render_target;
#ifdef __cplusplus
}
#endif

#define terrain_state (*(terrain_original_t *)&terrain_render_target)

#ifdef CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#define terrain_texture_width terrain_state.width
#define terrain_texture_height terrain_state.height
#define terrain_texture_selectors terrain_state.selectors
#define terrain_texture_handles terrain_state.texture_handles
#endif

#endif
