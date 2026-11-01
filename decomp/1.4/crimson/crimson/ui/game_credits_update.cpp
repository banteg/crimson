// crimson.exe: 1.0.2 0x40eda0, 1.3.0 0x4183f0, 1.4.0 0x41e330.
#include "overlay.h"
#include "freeware_edition.h"
using namespace ui140;
#if FREEWARE_EDITION < 10400
namespace {
__forceinline bool draw_early_credits(float time) {
#if FREEWARE_EDITION == 10002
    float top = 480.f - time * 17;
#define CREDIT_TOP top
#else
    float travel = time * 17;
#define CREDIT_TOP (viewport_height() - travel)
#endif
    int row = 0;
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
    // The original reads the Grim receiver before evaluating the current viewport height.
#define LINE(s) do {                                                    \
        IGrim2D_cpp *grim = grim_interface_ptr;                         \
        grim->grim_draw_text_mono(50, CREDIT_TOP + row++ * 18, (char *)s); \
    } while (0)
#else
#define LINE(s) text(50, CREDIT_TOP + (row++ * 18), s)
#endif
    LINE("Project Crimsonland");
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
#undef CREDIT_TOP
}
}
#endif

extern "C" unsigned char game_credits_update() {
    filter(3);
    frame_dt = raw_delta();
#if FREEWARE_EDITION == 10002
    frame_dt *= .8f;
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
    float top = viewport_height() - time * 17;
    int lines = 30;
    if (top + 540 > -30) {
        text(50, top + 0, "Project Crimsonland");
        text(50, top + 18, "----credits--------");
        text(50, top + 72, "Game coded & designed by");
        text(50, top + 90, "Tero Alatalo");
        text(50, top + 144, "3D Art modelled by");
        text(50, top + 162, "Timo Palonen");
        text(50, top + 216, "Music performed by");
        text(50, top + 234, "Valtteri Pihlajamaki");
        text(50, top + 288, "2D Art drawn by");
        text(50, top + 306, "Tero Alatalo");
        text(50, top + 360, "Using Grim API & SFX API by");
        text(50, top + 378, "Tero Alatalo");
        text(50, top + 432, "Additional Perk coordinators");
        text(50, top + 450, "Jarkko Forsbacka");
        text(50, top + 468, "Wille Mantyla");
    }
    if (top + 540 <= -30 || top + 540 - 32 < viewport_height()) {
        lines = 66;
        text(50, top + 540, "Beta testers / thanks / greets");
        text(50, top + 558, "                (alphabetical)");
        text(50, top + 576, "Armas");
        text(50, top + 594, "crud");
        text(50, top + 612, "epaz");
        text(50, top + 630, "exi");
        text(50, top + 648, "Jayzon");
        text(50, top + 666, "KySSe");
        text(50, top + 684, "lore");
        text(50, top + 702, "matricks");
        text(50, top + 720, "milzer");
        text(50, top + 738, "monotonic");
        text(50, top + 756, "muzzy");
        text(50, top + 774, "PornReindeer");
        text(50, top + 792, "Outolintu");
        text(50, top + 810, "Quarot");
        text(50, top + 828, "Skele");
        text(50, top + 846, "Sniperwolf / Wolf_");
        text(50, top + 864, "Strombo");
        text(50, top + 882, "TeLa");
        text(50, top + 900, "Tieom");
        text(50, top + 918, "Ukuli");
        text(50, top + 936, "Vulderi");
        text(50, top + 954, "Wiltsu");
        text(50, top + 972, "Womba!");
        text(50, top + 990, "+ you guys at Pelit.fi and MuroPaketti.com");
        text(50, top + 1008, "+ the ones I forgot :)");
        text(50, top + 1062, "     Visit the website");
        text(50, top + 1080, "http://crimsonland.10tons.org");
        text(50, top + 1134, "2002 (c) 10tons entertainment");
        text(50, top + 1152, "    http://www.10tons.org");
        text(50, top + 1170, "     (10tons logo by pHx)");
    }
    bool past_end = top + lines * 18 < 0;
#endif
    if (dismiss_scroll(past_end)) {
#ifndef CRIMSON_FREEWARE_CLIENT
        freeware_credits_open = 0;
#endif
    }
    return 1;
}
