#include "crimsonland_console.h"

extern "C" console_cvar_entry_t *cv_silentloads;
extern "C" console_cvar_entry_t *cv_terrainFilter;
extern "C" console_cvar_entry_t *cv_bodiesFade;
extern "C" console_cvar_entry_t *cv_uiTransparency;
extern "C" console_cvar_entry_t *cv_uiPointFilterPanels;
extern "C" console_cvar_entry_t *cv_enableMousePointAndClickMovement;
extern "C" console_cvar_entry_t *cv_verbose;
extern "C" console_cvar_entry_t *cv_terrainBodiesTransparency;
extern "C" console_cvar_entry_t *cv_uiSmallIndicators;
extern "C" console_cvar_entry_t *cv_aimEnhancementFade;
extern "C" console_cvar_entry_t *cv_friendlyFire;
extern "C" console_cvar_entry_t *cv_showFPS;
extern "C" console_cvar_entry_t *cv_padAimDistMul;

extern "C" void register_core_cvars(void)
{
    cv_silentloads = console_log_queue.console_register_cvar("cv_silentloads", "1");
    cv_terrainFilter = console_log_queue.console_register_cvar("cv_terrainFilter", "1");
    cv_bodiesFade = console_log_queue.console_register_cvar("cv_bodiesFade", "1");
    cv_uiTransparency = console_log_queue.console_register_cvar("cv_uiTransparency", "1");
    cv_uiPointFilterPanels =
        console_log_queue.console_register_cvar("cv_uiPointFilterPanels", "0");
    cv_enableMousePointAndClickMovement =
        console_log_queue.console_register_cvar(
            "cv_enableMousePointAndClickMovement", "0");
    cv_verbose = console_log_queue.console_register_cvar("cv_verbose", "0");
    cv_terrainBodiesTransparency =
        console_log_queue.console_register_cvar("cv_terrainBodiesTransparency", "0");
    cv_uiSmallIndicators =
        console_log_queue.console_register_cvar("cv_uiSmallIndicators", "0");
    cv_aimEnhancementFade =
        console_log_queue.console_register_cvar("cv_aimEnhancementFade", "0.7");
    cv_friendlyFire =
        console_log_queue.console_register_cvar("cv_friendlyFire", "0");
    cv_showFPS = console_log_queue.console_register_cvar("cv_showFPS", "0");
    cv_padAimDistMul =
        console_log_queue.console_register_cvar("cv_padAimDistMul", "96");
}
