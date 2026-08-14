#ifndef CRIMSONLAND_GFXS_OWNER_H
#define CRIMSONLAND_GFXS_OWNER_H

#include "crimsonland_types.h"

/*
 * Authenticated 2003 gfxs_t layout rooted at ui_template_pool_block_00
 * (0x0048f808).  Every member is one 0xe8-byte gfx_t: eight vertices,
 * followed by its texture handle and vertex count.
 */
#ifndef CRIMSONLAND_GFX_BLOCK_TYPE
#define CRIMSONLAND_GFX_BLOCK_TYPE ui_menu_item_subtemplate_block_t
#define CRIMSONLAND_GFX_BLOCK_TYPE_WAS_DEFAULTED
#endif

typedef struct gfxs_original_t {
    CRIMSONLAND_GFX_BLOCK_TYPE ui_gearSmall;
    CRIMSONLAND_GFX_BLOCK_TYPE ui_gearMedium;
    CRIMSONLAND_GFX_BLOCK_TYPE ui_gearLarge;
    CRIMSONLAND_GFX_BLOCK_TYPE ui_signCrimson;
    CRIMSONLAND_GFX_BLOCK_TYPE ui_menuItem;
    CRIMSONLAND_GFX_BLOCK_TYPE ui_menuPanel;
    CRIMSONLAND_GFX_BLOCK_TYPE ui_menuPanelTall;
    CRIMSONLAND_GFX_BLOCK_TYPE ui_menuPanelTallSmall;
    CRIMSONLAND_GFX_BLOCK_TYPE ui_blueGlow;
    CRIMSONLAND_GFX_BLOCK_TYPE ent_zombie;
    CRIMSONLAND_GFX_BLOCK_TYPE ent_spider;
    CRIMSONLAND_GFX_BLOCK_TYPE ent_lizard;
} gfxs_original_t;

#ifdef __cplusplus
extern "C" {
#endif
extern CRIMSONLAND_GFX_BLOCK_TYPE ui_template_pool_block_00;
#ifdef __cplusplus
}
#endif

#define gfxs (*(gfxs_original_t *)&ui_template_pool_block_00)

#ifdef CRIMSONLAND_USE_ORIGINAL_GFXS_OWNER
#define ui_template_pool_block_01 gfxs.ui_gearMedium
#define ui_template_pool_block_02 gfxs.ui_gearLarge
#define ui_sign_crimson_template gfxs.ui_signCrimson
#define ui_menu_item_element gfxs.ui_menuItem
#define ui_menu_panel_template gfxs.ui_menuPanel
#define ui_menu_item_subtemplate_block_01 gfxs.ui_menuPanelTall
#define ui_menu_item_subtemplate_block_02 gfxs.ui_menuPanelTallSmall
#define ui_menu_item_subtemplate_block_03 gfxs.ui_blueGlow
#define ui_menu_item_subtemplate_block_04 gfxs.ent_zombie
#define ui_menu_item_subtemplate_block_05 gfxs.ent_spider
#define ui_menu_item_subtemplate_block_06 gfxs.ent_lizard
#endif

#ifdef CRIMSONLAND_GFX_BLOCK_TYPE_WAS_DEFAULTED
#undef CRIMSONLAND_GFX_BLOCK_TYPE_WAS_DEFAULTED
#undef CRIMSONLAND_GFX_BLOCK_TYPE
#endif

#endif
