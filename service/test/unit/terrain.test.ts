import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { crtRand, generate, generateRandom, questSlots, type Stamp } from "../../web/src/terrain/rules";
import vectors from "../vectors.json";

function digest(layer: Stamp[]): string {
  const bits = new DataView(new ArrayBuffer(4));
  const lines = layer.map(([rotation, x, y]) => {
    bits.setFloat32(0, rotation, true);
    const hex = Array.from(new Uint8Array(bits.buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex},${x},${y}\n`;
  });
  return createHash("sha256").update(lines.join("")).digest("hex");
}

describe("the site's terrain follows the game's generator", () => {
  for (const vector of vectors.terrain) {
    it(vector.quest ? `quest ${vector.quest.join(".")}, seed ${vector.seed}` : `random terrain, seed ${vector.seed}`, () => {
      const rand = crtRand(vector.seed);
      const ground = vector.quest ? generate(rand, questSlots(vector.quest[0]!, vector.quest[1]!)) : generateRandom(rand, 50);

      expect(ground.slots).toEqual(vector.slots);
      expect(ground.layers.map(digest)).toEqual(vector.layers);
    });
  }
});
