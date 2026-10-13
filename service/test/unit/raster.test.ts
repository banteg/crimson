import { describe, expect, it } from "vitest";
import { Canvas, Layer, straightTexture } from "../../src/raster";

const PIXEL = { x: 0, y: 0, width: 1, height: 1, rotation: 0 };
const ALPHA_REF = 4;

// What a one-pixel layer leaves on a pixel of `under` after `draw`.
function drawn(under: number[], draw: (layer: Layer) => void): number[] {
  const canvas = new Canvas(1, 1, under);
  const layer = new Layer(1, 1);
  draw(layer);
  layer.composite(canvas);
  return [...canvas.pixels().data.subarray(0, 3)];
}

describe("Layer.drawQuad", () => {
  it("drops samples the alpha test drops, shadows included", () => {
    const faint = straightTexture({ width: 1, height: 1, data: new Uint8Array([255, 255, 255, 3]) });
    for (const shadow of [false, true])
      expect(drawn([255, 255, 255], (layer) => {
        for (let i = 0; i < 100; i++) layer.drawQuad(faint, { x: 0, y: 0, width: 1, height: 1 }, PIXEL, [0, 0, 0, 1], shadow, ALPHA_REF);
      })).toEqual([255, 255, 255]);
  });

  it("filters colour and alpha apart, as the device filters a straight texture", () => {
    // Opaque red beside transparent green, sampled halfway: the green bleeds in at half alpha.
    const edge = straightTexture({ width: 2, height: 1, data: new Uint8Array([255, 0, 0, 255, 0, 255, 0, 0]) });
    expect(drawn([0, 0, 0], (layer) => layer.drawQuad(edge, { x: 0.5, y: 0, width: 1, height: 1 }, PIXEL, [1, 1, 1, 1], false, ALPHA_REF))).toEqual([64, 64, 0]);
  });
});
