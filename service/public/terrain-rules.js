// The game's terrain rules (src/crimson/sim/terrain_generate.py): crt_rand places 1600 base, 70 overlay and 30
// detail stamps of 128x128 textures, rotated, on a 1024x1024 ground. Shared by terrain.js and the service's tests,
// which check it against the Python generator.

export const SIZE = 1024;
// Unlock-gated quest terrains of terrain_generate_random: quests 4.2, 3.2 and 2.2.
const UNLOCK_SLOTS = [[40, [6, 7, 6]], [30, [4, 5, 4]], [20, [2, 3, 2]]];

// MSVC crt_rand.
export function crtRand(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 214013) + 2531011) >>> 0;
    return (state >>> 16) & 0x7fff;
  };
}

function layer(rand, density) {
  const stamps = [];
  for (let i = 0; i < (SIZE * SIZE * density) / 0x80000; i++) {
    const rotation = Math.fround((rand() % 314) * Math.fround(0.01));
    // terrain_vec2_t(x, y) takes two crt_rand() arguments; MSVC evaluates the y one first.
    const y = (rand() % (SIZE + 128)) - 64;
    const x = (rand() % (SIZE + 128)) - 64;
    stamps.push([rotation, x, y]);
  }
  return stamps;
}

// terrain_generate: base, overlay and detail stamps with the given texture slots.
export function generate(rand, slots) {
  return { slots, layers: [layer(rand, 800), layer(rand, 35), layer(rand, 15)] };
}

// terrain_generate_random for a save that has unlocked `unlockIndex` quests.
export function generateRandom(rand, unlockIndex) {
  // Three % 7 texture selectors, overwritten with (0, 1, 0) right after.
  rand(), rand(), rand();
  for (const [threshold, slots] of UNLOCK_SLOTS)
    if (unlockIndex >= threshold && (rand() & 7) === 3) return generate(rand, slots);
  return generate(rand, [0, 1, 0]);
}

// src/crimson/terrain_slots.py terrain_slots_for_quest.
export function questSlots(major, minor) {
  const base = (major - 1) * 2;
  if (major > 4) return [minor & 3, 1, 3];
  return minor < 6 ? [base, base + 1, base] : [base, base, base + 1];
}
