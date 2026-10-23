#pragma once
// The passes the game module marks for its host (host_render_pass): the RTX
// world's bounds in the frame, and within it the batches the host lights
// (creature bodies, players, the ground) until sprites return to the device's
// own shading.
enum {
  HOST_PASS_WORLD_BEGIN = 1,
  HOST_PASS_WORLD_END = 2,
  HOST_PASS_CREATURES = 3,
  HOST_PASS_PLAYERS = 4,
  HOST_PASS_SPRITES = 5,
  HOST_PASS_GROUND = 6,
};
// Floats per light in host_scene (game/rtx_lights.cpp lays them out).
enum { RTX_LIGHT_FLOATS = 32 };
// The terrain's decals by material (host_ground), as render/rtx/materials.py
// sorts them: what the draws into the terrain until HOST_GROUND_END are.
// A decal without a material reaches the ground's substrate alone.
enum {
  HOST_GROUND_END = -1,
  HOST_GROUND_DECAL = 0,
  HOST_GROUND_BLOOD = 1,
  HOST_GROUND_CORPSE = 2,
  HOST_GROUND_BRASS = 3,
  HOST_GROUND_SCORCH = 4,
  HOST_GROUND_ICE = 5,
};
