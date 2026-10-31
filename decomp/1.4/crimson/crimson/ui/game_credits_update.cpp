// crimson.exe 1.4.0, 0x41e330. The credits are culled in two groups.
#include "overlay.h"
using namespace ui140;
extern "C" unsigned char game_credits_update() {
    filter(3);
    frame_dt = raw_delta();
    if (UI_PENDING)
        reset_overlay_time();
    float time = (freeware_simulation_clock - UI_SINCE) * 1.3f;
    backdrop(time, false);
    draw_backdrop();
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
    if (dismiss_scroll(top + lines * 18 < 0)) {
#ifndef CRIMSON_FREEWARE_CLIENT
        freeware_credits_open = 0;
#endif
    }
    return 1;
}
