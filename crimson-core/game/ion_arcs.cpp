// An ion shot in its impact phase arcs to every creature in its reach. A crowd
// piled on one spot under a Shock Chain (a new link each tick, ~22 impacting at
// once) makes thousands of arcs over the same pixels, white either way. Each
// shot draws at most two arcs to the creatures in one small cell. The search is
// presentation only: the run never sees it.
#include "crimsonland_gameplay.h"
#include <math.h>

extern "C" int creature_find_in_radius(float *pos, float radius, int start_index);

namespace {
// Arcs into one cell overlap almost entirely, and two already whiten their core.
constexpr int ARCS_PER_CELL = 2;
struct Cell {
  int x, y, arcs;
  unsigned shot;
};
Cell cells[1024];
unsigned shot;
} // namespace

// creature_find_in_radius for the arc loop (game/changes/ion-arc-merge.patch):
// a shot's search starts at slot 1. Cells are three quarters of the inner
// strip's half-width (a quarter of the reach) across, in world units.
extern "C" int ion_arc_find(float *pos, float radius, int start_index) {
  if (start_index == 1)
    ++shot;
  float size = radius * 0.1875f;
  for (int i = creature_find_in_radius(pos, radius, start_index); i != -1;
       i = creature_find_in_radius(pos, radius, i + 1)) {
    int x = (int)floorf(creature_pool[i].pos_x / size), y = (int)floorf(creature_pool[i].pos_y / size);
    unsigned slot = ((unsigned)x * 73856093u ^ (unsigned)y * 19349663u) & 1023;
    while (cells[slot].shot == shot && (cells[slot].x != x || cells[slot].y != y))
      slot = (slot + 1) & 1023;
    if (cells[slot].shot != shot)
      cells[slot] = {x, y, 0, shot};
    if (++cells[slot].arcs <= ARCS_PER_CELL)
      return i;
  }
  return -1;
}
