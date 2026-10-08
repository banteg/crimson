// The game's terrain rules (src/crimson/sim/terrain_generate.py): crt_rand places 1600 base, 70 overlay and 30
// detail stamps of 128x128 textures, rotated, on a 1024x1024 ground. test/unit/terrain.test.ts checks them against
// the Python generator.

export const SIZE = 1024;
// How terrain_render paints the stamps (src/grim/terrain_render.py): 128px patches over the clear color, each layer
// tinted RGB 178/255 with alpha 230, 230 and 153, and texels at or below 4/255 after the tint discarded (the DX8
// alpha test).
export const PATCH = 128;
export const CLEAR = [63, 56, 25] as const;
export const TINT_RGB = 178 / 255;
export const LAYER_ALPHA = [230, 230, 153];
export const ALPHA_REF = 4;
// Unlock-gated quest terrains of terrain_generate_random: quests 4.2, 3.2 and 2.2.
const UNLOCK_SLOTS: [number, Slots][] = [[40, [6, 7, 6]], [30, [4, 5, 4]], [20, [2, 3, 2]]];

export type Slots = [number, number, number];
export type Stamp = [rotation: number, x: number, y: number];
export interface Ground {
  slots: Slots;
  layers: [Stamp[], Stamp[], Stamp[]];
}

// MSVC crt_rand.
export function crtRand(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 214013) + 2531011) >>> 0;
    return (state >>> 16) & 0x7fff;
  };
}

// The game's ground is SIZE square; a taller one keeps the same stamp density over its area, and at SIZE x SIZE is
// exactly the game's.
function layer(rand: () => number, density: number, width: number, height: number): Stamp[] {
  const stamps: Stamp[] = [];
  for (let i = 0; i < Math.floor((width * height * density) / 0x80000); i++) {
    const rotation = Math.fround((rand() % 314) * Math.fround(0.01));
    // terrain_vec2_t(x, y) takes two crt_rand() arguments; MSVC evaluates the y one first.
    const y = (rand() % (height + 128)) - 64;
    const x = (rand() % (width + 128)) - 64;
    stamps.push([rotation, x, y]);
  }
  return stamps;
}

// terrain_generate: base, overlay and detail stamps with the given texture slots.
export function generate(rand: () => number, slots: Slots, width = SIZE, height = SIZE): Ground {
  return { slots, layers: [layer(rand, 800, width, height), layer(rand, 35, width, height), layer(rand, 15, width, height)] };
}

// terrain_generate_random for a save that has unlocked `unlockIndex` quests.
export function generateRandom(rand: () => number, unlockIndex: number, width = SIZE, height = SIZE): Ground {
  // Three % 7 texture selectors, overwritten with (0, 1, 0) right after.
  rand(), rand(), rand();
  for (const [threshold, slots] of UNLOCK_SLOTS)
    if (unlockIndex >= threshold && (rand() & 7) === 3) return generate(rand, slots, width, height);
  return generate(rand, [0, 1, 0], width, height);
}

// src/crimson/terrain_slots.py terrain_slots_for_quest.
export function questSlots(major: number, minor: number): Slots {
  const base = (major - 1) * 2;
  if (major > 4) return [minor & 3, 1, 3];
  return minor < 6 ? [base, base + 1, base] : [base, base, base + 1];
}

// gameplay_reset_state draws a score tag, one animation phase per creature slot (0x180) and the tag again before
// terrain_generate_random (src/crimson/sim/bootstrap.py).
const RESET_DRAWS = 1 + 0x180 + 1;
// Ranked runs play with every quest unlocked (docs/rewrite/ranked-rules.md).
const RANKED_UNLOCK_INDEX = 50;

// The terrain a ranked run starts on, from its seed: the reset's random terrain, or for a quest its score tag draw
// and then the quest's own terrain over it (src/crimson/sim/run_init.py).
export function runGround(seed: number, quest: [major: number, minor: number] | null): Ground {
  const rand = crtRand(seed);
  for (let i = 0; i < RESET_DRAWS; i++) rand();
  const ground = generateRandom(rand, RANKED_UNLOCK_INDEX);
  if (quest === null) return ground;
  rand();
  return generate(rand, questSlots(...quest));
}
