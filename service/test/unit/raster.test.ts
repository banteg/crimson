import { describe, expect, it } from "vitest";
import { Canvas, Layer, prepareCell, straightTexture } from "../../src/raster";

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
  it.each([0, 0.37, Math.PI / 2, Math.PI])("keeps bilinear atlas-neighbour contributions at rotation %f", (rotation) => {
    const data = new Uint8Array(8 * 8 * 4);
    // The requested cell is empty, but filtering at its right edge can reach the next cell's red texel.
    data.set([255, 0, 0, 255], (3 * 8 + 4) * 4);
    const art = straightTexture({ width: 8, height: 8, data });
    const cell = { x: 0, y: 0, width: 4, height: 4 };
    const quad = { x: 0.25, y: -0.125, width: 16, height: 16, rotation };
    const layers = [new Layer(20, 20), new Layer(20, 20)];
    layers[0]!.drawQuad(art, cell, quad, [1, 1, 1, 1], false, ALPHA_REF);
    layers[1]!.drawQuad(art, prepareCell(art, cell), quad, [1, 1, 1, 1], false, ALPHA_REF);
    expect(layers[0]!.rgb.some((value) => value > 0)).toBe(true);
    expect(layers[1]!.rgb).toEqual(layers[0]!.rgb);
    expect(layers[1]!.clear).toEqual(layers[0]!.clear);
  });

  it("retains faint isolated texels at the sampler's alpha-test boundary", () => {
    const data = new Uint8Array(32 * 32 * 4);
    data.set([0, 0, 255, 4], (17 * 32 + 15) * 4);
    const art = straightTexture({ width: 32, height: 32, data });
    const cell = { x: 0, y: 0, width: 32, height: 32 };
    const quad = { ...cell, rotation: 0 };
    const layers = [new Layer(32, 32), new Layer(32, 32)];
    layers[0]!.drawQuad(art, cell, quad, [1, 1, 1, 1], false, ALPHA_REF);
    layers[1]!.drawQuad(art, prepareCell(art, cell), quad, [1, 1, 1, 1], false, ALPHA_REF);
    // The stored float32 alpha, multiplied back by 255, is just above 4.
    expect(layers[0]!.rgb[(17 * 32 + 15) * 3 + 2]).toBeGreaterThan(0);
    expect(layers[1]!.rgb).toEqual(layers[0]!.rgb);
    expect(layers[1]!.clear).toEqual(layers[0]!.clear);
  });

  it("leaves an entirely transparent prepared cell untouched", () => {
    const art = straightTexture({ width: 8, height: 8, data: new Uint8Array(8 * 8 * 4) });
    const layer = new Layer(8, 8);
    layer.drawQuad(art, prepareCell(art, { x: 0, y: 0, width: 8, height: 8 }), { x: 0, y: 0, width: 8, height: 8, rotation: 0.3 }, [1, 1, 1, 1], true, ALPHA_REF);
    expect(layer.rgb.every((value) => value === 0)).toBe(true);
    expect(layer.clear.every((value) => value === 1)).toBe(true);
  });

  it("keeps alpha support for black decals that only darken the ground", () => {
    const data = new Uint8Array(8 * 8 * 4);
    data.set([0, 0, 0, 255], (3 * 8 + 4) * 4);
    const art = straightTexture({ width: 8, height: 8, data });
    const cell = { x: 0, y: 0, width: 8, height: 8 };
    const quad = { ...cell, rotation: 0 };
    const layers = [new Layer(8, 8), new Layer(8, 8)];
    layers[0]!.drawQuad(art, cell, quad, [0, 0, 0, 0.25], false, ALPHA_REF);
    layers[1]!.drawQuad(art, prepareCell(art, cell), quad, [0, 0, 0, 0.25], false, ALPHA_REF);
    expect(layers[1]!.clear.some((value) => value < 1)).toBe(true);
    expect(layers[1]!.rgb).toEqual(layers[0]!.rgb);
    expect(layers[1]!.clear).toEqual(layers[0]!.clear);
  });

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
