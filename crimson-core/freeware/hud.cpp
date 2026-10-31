// Grim draw calls in the 1.4.0 HUD (0x416a00), including its separate player-count layouts.
#include "display.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
namespace freeware {
// The credits renderer at 0x41e330 uses fixed 18-pixel line spacing with intentional gaps.
void Display::credits(float clock) {
  struct Line {
    float y;
    const char *name;
  };
  static const Line lines[] = {
      {0, "Project Crimsonland"},
      {18, "----credits--------"},
      {72, "Game coded & designed by"},
      {90, "Tero Alatalo"},
      {144, "3D Art modelled by"},
      {162, "Timo Palonen"},
      {216, "Music performed by"},
      {234, "Valtteri Pihlajamaki"},
      {288, "2D Art drawn by"},
      {306, "Tero Alatalo"},
      {360, "Using Grim API & SFX API by"},
      {378, "Tero Alatalo"},
      {432, "Additional Perk coordinators"},
      {450, "Wille Mantyla"},
      {0, "Beta testers / thanks / greets"},
      {558, "                (alphabetical)"},
      {576, "Armas"},
      {594, "crud"},
      {612, "epaz"},
      {630, "exi"},
      {648, "Jayzon"},
      {666, "KySSe"},
      {684, "lore"},
      {702, "matricks"},
      {720, "milzer"},
      {738, "monotonic"},
      {756, "muzzy"},
      {774, "PornReindeer"},
      {792, "Outolintu"},
      {810, "Quarot"},
      {828, "Skele"},
      {846, "Strombo"},
      {882, "TeLa"},
      {900, "Tieom"},
      {918, "Ukuli"},
      {936, "Vulderi"},
      {954, "Wiltsu"},
      {972, "Womba!"},
      {990, "+ you guys at Pelit.fi and MuroPaketti.com"},
      {1008, "+ the ones I forgot :)"},
      {1062, "http://crimsonland.10tons.org"},
      {1134, "2002 (c) 10tons entertainment"},
      {1152, "    http://www.10tons.org"},
      {1170, "     (10tons logo by pHx)"},
  };
  SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
  SDL_RenderClear(renderer);
  float top = height - clock * 48;
  for (auto &line : lines)
    if (top + line.y >= -30 && top + line.y < height)
      text(line.name, 50, top + line.y, .76f, {1, 1, 1, .68f});
}
} // namespace freeware
