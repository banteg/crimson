// crimson.exe: 1.0.2 0x40eda0, 1.3.0 0x4183f0, 1.4.0 0x41e330.
#include "overlay.h"
#include "freeware_edition.h"
using namespace ui140;
#if FREEWARE_EDITION < 10400
namespace {
__forceinline bool draw_early_credits(float time) {
#if FREEWARE_EDITION == 10002
    float top = (480.f - time * 17);
#define CREDIT_TOP top
#else
    float travel = time * 17;
#define CREDIT_TOP viewport_height() - travel
#endif
    int row = 0;
#if FREEWARE_EDITION == 10002
#define LINE(str) do { float y = CREDIT_TOP + row++ * 18; text(50, y, str); } while (0)
    LINE("Project Crimsonland");
#else
#define CREDIT_ROW(y, str) do { text(50, y, str); } while (0)
#define LINE(str) CREDIT_ROW(CREDIT_TOP + row++ * 18, str)
    CREDIT_ROW((CREDIT_TOP) + row++ * 18, "Project Crimsonland");
#endif
    LINE("----credits--------");
    row += 2;
    LINE("Coded & designed by");
    LINE("Tero Alatalo");
    row += 2;
    LINE("3D Art modelled by");
    LINE("Timo Palonen");
    row += 2;
    LINE("Music performed by");
    LINE("Valtteri Pihlajamaki");
    row += 2;
    LINE("2D Art drawn by");
    LINE("Tero Alatalo");
    row += 2;
    LINE("Additional Perk coordinators");
    LINE("Jarkko Forsbacka");
    LINE("Wille Mantyla");
    row += 2;
#if FREEWARE_EDITION == 10002
    LINE("Crimsonland uses FMOD sound system");
    LINE("http://www.fmod.org");
#else
    LINE("Special thanks to");
    LINE("all you ppl at Pelit.fi and MuroPaketti.com");
    LINE("(MuroBBS) forums for lots of cool ideas,");
    LINE("bug reports and support! Too many names to");
    LINE("list here ! =)");
#endif
    row += 2;
    LINE("Beta testers / thanks / greets");
    LINE("                (alphabetical)");
    LINE("Armas");
#if FREEWARE_EDITION == 10300
    LINE("crud");
#endif
    LINE("epaz");
    LINE("exi");
    LINE("Jayzon");
    LINE("KySSe");
    LINE("lore");
    LINE("milzer");
    LINE("monotonic");
#if FREEWARE_EDITION == 10300
    LINE("muzzy");
    LINE("PornReindeer");
#endif
    LINE("Outolintu");
#if FREEWARE_EDITION == 10300
    LINE("Quarot");
#endif
    LINE("Skele");
#if FREEWARE_EDITION == 10300
    LINE("Sniperwolf / Wolf_");
    LINE("Strombo");
#endif
    LINE("TeLa");
    LINE("Ukuli");
    LINE("Vulderi");
    LINE("Wiltsu");
    LINE("+ the ones I forgot :)");
    row += 2;
#if FREEWARE_EDITION == 10300
    LINE("Crimsonland uses FMOD sound system");
    LINE("http://www.fmod.org");
    row += 2;
#endif
    LINE("     Visit the website");
    LINE("http://crimsonland.10tons.org");
    row += 2;
    LINE("2002 (c) 10tons entertainment");
    LINE("    http://www.10tons.org");
    row += 2;
    LINE(" 10tons entertainment is..");
    ++row;
    scale(.7f);
    LINE("milzer - miikka kulmala - code, html, 2d gfx");
    LINE("vulder - valtteri pihlajam\xe4ki - ideas, music");
    LINE("jmp - janne papula - code");
    LINE("temper - tero alatalo - code, 2d/3d gfx");
    LINE("sampsas - samppa nevala - code");
    LINE("armas - timo palonen - 3d gfx");
    LINE("dimoon - pertti viitala - 3d gfx");
    LINE("crud - ville eriksson - music, 3d gfx");
    LINE("pHx - pasi heinonen - 2d gfx");
    return CREDIT_TOP + row * 18 < 0;
#undef LINE
#undef CREDIT_ROW
#undef CREDIT_TOP
}
}
#endif

extern "C" unsigned char game_credits_update() {
    filter(3);
#if FREEWARE_EDITION == 10002
    frame_dt = raw_delta(.8f);
#else
    frame_dt = raw_delta();
#endif
    if (UI_PENDING)
        reset_overlay_time();
#if FREEWARE_EDITION == 10002
#ifdef CRIMSON_FREEWARE_CLIENT
    if (freeware_frame_input->space_down)
#else
    if (grim_interface_ptr->grim_is_key_down(0x39))
#endif
        UI_PENDING = 1;
    float time = freeware_simulation_clock - UI_SINCE;
#else
    float time = (freeware_simulation_clock - UI_SINCE) * 1.3f;
#endif
    backdrop(time, false);
    draw_backdrop();
#if FREEWARE_EDITION < 10400
    bool past_end = draw_early_credits(time);
#else
    float travel = time * 17;
    int lines;
    bool draw_testers = true;
#ifdef CRIMSON_FREEWARE_CLIENT
#define CREDIT_HEIGHT viewport_height()
#define LINE(s) text(50, CREDIT_HEIGHT - travel + lines++ * 18, s)
#else
#define CREDIT_HEIGHT screen_height
#define LINE(s) grim_interface_ptr->grim_draw_text_mono(50, CREDIT_HEIGHT - travel + lines++ * 18, (char *)s)
#endif
    if (CREDIT_HEIGHT - travel + 540 > -30) {
        lines = 0;
        LINE("Project Crimsonland");
        LINE("----credits--------");
        lines += 2;
        LINE("Game coded & designed by");
        LINE("Tero Alatalo");
        lines += 2;
        LINE("3D Art modelled by");
        LINE("Timo Palonen");
        lines += 2;
        LINE("Music performed by");
        LINE("Valtteri Pihlajamaki");
        lines += 2;
        LINE("2D Art drawn by");
        LINE("Tero Alatalo");
        lines += 2;
        LINE("Using Grim API & SFX API by");
        LINE("Tero Alatalo");
        lines += 2;
        LINE("Additional Perk coordinators");
        LINE("Jarkko Forsbacka");
        LINE("Wille Mantyla");
        lines += 3;
        draw_testers = CREDIT_HEIGHT - travel + lines * 18 - 32 < CREDIT_HEIGHT;
    }
    if (draw_testers) {
        lines = 30;
        LINE("Beta testers / thanks / greets");
        LINE("                (alphabetical)");
        LINE("Armas");
        LINE("crud");
        LINE("epaz");
        LINE("exi");
        LINE("Jayzon");
        LINE("KySSe");
        LINE("lore");
        LINE("matricks");
        LINE("milzer");
        LINE("monotonic");
        LINE("muzzy");
        LINE("PornReindeer");
        LINE("Outolintu");
        LINE("Quarot");
        LINE("Skele");
        LINE("Sniperwolf / Wolf_");
        LINE("Strombo");
        LINE("TeLa");
        LINE("Tieom");
        LINE("Ukuli");
        LINE("Vulderi");
        LINE("Wiltsu");
        LINE("Womba!");
        LINE("+ you guys at Pelit.fi and MuroPaketti.com");
        LINE("+ the ones I forgot :)");
        lines += 2;
        LINE("     Visit the website");
        LINE("http://crimsonland.10tons.org");
        lines += 2;
        LINE("2002 (c) 10tons entertainment");
        LINE("    http://www.10tons.org");
        LINE("     (10tons logo by pHx)");
    }
    bool past_end = CREDIT_HEIGHT - travel + lines * 18 < 0;
#undef CREDIT_HEIGHT
#undef LINE
#endif
    if (dismiss_scroll(past_end)) {
#ifndef CRIMSON_FREEWARE_CLIENT
        freeware_credits_open = 0;
#endif
    }
    return 1;
}
