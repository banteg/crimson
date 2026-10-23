#pragma once
// The passes the game module marks for its host (host_render_pass): the RTX
// world's bounds in the frame, and within it the batches the host lights
// (creature bodies, players) until sprites return to the device's own shading.
enum {
  HOST_PASS_WORLD_BEGIN = 1,
  HOST_PASS_WORLD_END = 2,
  HOST_PASS_CREATURES = 3,
  HOST_PASS_PLAYERS = 4,
  HOST_PASS_SPRITES = 5,
};
