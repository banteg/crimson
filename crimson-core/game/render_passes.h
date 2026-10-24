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
  HOST_PASS_AURA = 7, // Monster Vision's aura quads, drawn as an analytic glow over [0, 1] UVs
};
// Floats per light in host_scene (game/rtx_lights.cpp lays them out).
enum { RTX_LIGHT_FLOATS = 32 };
// The fluid smoke solver's commands (host_smoke, game/rtx_smoke.cpp), each an
// opcode and its floats: RESET clears the field targets (resolution, world
// size, step seconds, pressure iterations); FADE scales density and heat;
// SPLAT deposits an emission (its rect in the solver's uv, then source, motion,
// rotation and flow) and IMPULSE an airflow (rect, segment, impulse, phase);
// PROJECT advects velocity and removes its divergence; TRANSPORT carries density
// and heat along it and decays them (decay).
enum { SMOKE_RESET = 1, SMOKE_FADE, SMOKE_SPLAT, SMOKE_IMPULSE, SMOKE_PROJECT, SMOKE_TRANSPORT };
// Floats per smoke light in host_smoke_draw: position, height, radius; RGB, gain;
// direction, half length, ring radius; tail radiance (source_geometry.glsl).
enum { SMOKE_LIGHT_FLOATS = 13, SMOKE_MAX_LIGHTS = 16, SMOKE_MAX_SIGHTS = 4 };
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
