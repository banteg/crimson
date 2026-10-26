// Compile the production grid builder. Dead stripping discards the unrelated
// light collectors; these are the actual game pools and ABI light records.
#include "../game/rtx_lights.cpp"
#include <cassert>
#include <cstdio>

decltype(creature_pool) creature_pool = {};
decltype(player_state_table) player_state_table = {};
decltype(bonus_pool) bonus_pool = {};
decltype(config_blob) config_blob = {};
decltype(terrain_texture_width) terrain_texture_width = 1024;
decltype(terrain_texture_height) terrain_texture_height = 1024;

int main() {
  float grid[5] = {1, 2, 3, 4, 5};
  int size = 123;
  // No source record may be touched when shadows are disabled, even after a
  // previous populated frame. Empty descriptors prevent stale host uploads.
  assert(!rtx_build_occlusion(nullptr, 1, false, grid, &size));
  assert(size == 0 && grid[0] == 0 && grid[1] == 0 && grid[2] == 0 && grid[3] == 0 && grid[4] == 64);
  assert(!rtx_build_occlusion(nullptr, 0, true, grid, &size) && size == 0);

  auto &c = creature_pool[0];
  c.active = 1; c.type_id = 0; c.size = 50; c.death_timer = 16; c.tint_a = 1;
  c.pos_x = 100; c.pos_y = 100;
  float light[RTX_LIGHT_FLOATS] = {};
  light[0] = 100; light[1] = 90; light[2] = light[14] = 150; light[3] = 24;
  light[8] = 1; light[11] = 200; light[12] = light[13] = 1; light[15] = 3;
  light[18] = 64; light[23] = 164;
  const float *values = rtx_build_occlusion(light, 1, true, grid, &size);
  assert(values && grid[2] > 0 && size > 0);
  int headers = (int)(grid[2] * grid[3]), references = 0;
  for (int i = 0; i < headers; ++i) {
    assert(values[i * 4 + 2] == 0 && values[i * 4 + 3] == 0);
    int offset = (int)values[i * 4], count = (int)values[i * 4 + 1];
    assert(offset >= headers + 3 && count >= 0 && (offset + count) * 4 <= size);
    for (int j = 0; j < count; ++j)
      assert(values[(offset + j) * 4] == headers); // the only body transform
    references += count;
  }
  assert(references > 0 && size == headers * 4 + 12 + references * 4);
  assert(!rtx_build_occlusion(nullptr, 1, false, grid, &size) && size == 0 && grid[2] == 0);

  // Keep the beam head's source support, even without padded fan-ray lists.
  c.pos_x = 448;
  light[0] = 260; light[1] = 100; light[2] = light[14] = 5;
  assert(rtx_build_occlusion(light, 1, true, grid, &size));
  light[23] = 0;
  assert(!rtx_build_occlusion(light, 1, true, grid, &size));

  // A crowd retains its density/height, with no body or secondary-list payload.
  c.pos_x = 100;
  for (int i = 1; i <= CROWD_BODIES; ++i) creature_pool[i] = c;
  light[0] = 100; light[2] = light[14] = 150;
  values = rtx_build_occlusion(light, 1, true, grid, &size);
  headers = (int)(grid[2] * grid[3]);
  assert(values && size == headers * 4);
  int x = (int)((100 - grid[0]) / grid[4]), y = (int)((100 - grid[1]) / grid[4]);
  assert(values[(y * (int)grid[2] + x) * 4] > 0);
  assert(values[(y * (int)grid[2] + x) * 4 + 1] < 0);
  for (int i = 0; i < headers; ++i)
    assert(values[i * 4 + 2] == 0 && values[i * 4 + 3] == 0);
  puts("rtx occlusion: ordinary payload, beam head support, crowds and shadows-off early exit passed");
}
