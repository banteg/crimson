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
  it.each([1, 31, 32, 33, 65])("keeps covered spans covered and resets them after compositing at width %i", (width) => {
    const canvas = new Canvas(width, 3, [255, 255, 255]);
    const layer = new Layer(width, 3);
    const white = straightTexture({ width: 1, height: 1, data: new Uint8Array([255, 255, 255, 255]) });
    // A constant opaque texel, so the checks include bit 31 and the final partial block without filtered edges.
    const cell = { x: 0.5, y: 0.5, width: 0, height: 0 };
    const quad = { x: 0, y: 0, width, height: 3, rotation: 0 };
    layer.drawQuad(white, cell, quad, [1, 0, 0, 1], false, ALPHA_REF);
    layer.drawQuad(white, cell, quad, [0, 0, 1, 1], false, ALPHA_REF);
    layer.composite(canvas);
    expect([...canvas.pixels().data]).toEqual(Array.from({ length: width * 3 }, () => [255, 0, 0, 255]).flat());

    layer.drawQuad(white, cell, quad, [0, 0, 1, 1], false, ALPHA_REF);
    layer.composite(canvas);
    expect([...canvas.pixels().data]).toEqual(Array.from({ length: width * 3 }, () => [0, 0, 255, 255]).flat());
  });

  it("keeps live pixels in a partly covered block, including when a shadow covers them", () => {
    const canvas = new Canvas(35, 1, [255, 255, 255]);
    const layer = new Layer(35, 1);
    const white = straightTexture({ width: 1, height: 1, data: new Uint8Array([255, 255, 255, 255]) });
    const cell = { x: 0.5, y: 0.5, width: 0, height: 0 };
    layer.drawQuad(white, cell, { x: 1, y: 0, width: 30, height: 1, rotation: 0 }, [1, 0, 0, 1], false, ALPHA_REF);
    layer.drawQuad(white, cell, { x: 32, y: 0, width: 1, height: 1, rotation: 0 }, [0, 0, 0, 1], true, ALPHA_REF);
    layer.drawQuad(white, cell, { x: -2, y: 0, width: 40, height: 1, rotation: 0 }, [0, 0, 1, 1], false, ALPHA_REF);
    layer.composite(canvas);
    const expected = Array.from({ length: 35 }, (_, x) => x >= 1 && x < 31 ? [255, 0, 0, 255] : x === 32 ? [0, 0, 0, 255] : [0, 0, 255, 255]).flat();
    expect([...canvas.pixels().data]).toEqual(expected);
  });

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
