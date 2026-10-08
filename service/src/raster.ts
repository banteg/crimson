// The preview card's raster layers, painted in plain TypeScript and handed to resvg as one image: the run's ground,
// stamped as web/src/terrain/draw.ts stamps it on a canvas, the player's heat as web/src/run.tsx Arena blurs it, and
// the game's menu panel with its shadow. resvg would decode a texture again for each of the ground's 1700 stamps, and
// render the whole stretched panel art for each of its nine slices.

import { ALPHA_REF, CLEAR, type Ground, LAYER_ALPHA, PATCH, SIZE, TINT_RGB } from "../web/src/terrain/rules";
import type { Pixels } from "./png";

// A texture ready to sample: premultiplied floats, colour in 0..255 and alpha in 0..1, inside a transparent border
// one texel wide, so bilinear samples at the edges fade out without bounds checks.
interface Texture {
  width: number;
  height: number;
  data: Float32Array;
}

function texture(pixels: Pixels, tint: readonly number[] = [1, 1, 1], alphaScale = 1, alphaRef = -1): Texture {
  const width = pixels.width + 2;
  const data = new Float32Array(width * (pixels.height + 2) * 4);
  for (let y = 0; y < pixels.height; y++)
    for (let x = 0; x < pixels.width; x++) {
      const from = (y * pixels.width + x) * 4;
      const a = pixels.data[from + 3]! * alphaScale;
      if (a <= alphaRef) continue;
      const to = ((y + 1) * width + x + 1) * 4;
      for (let c = 0; c < 3; c++) data[to + c] = (pixels.data[from + c]! * tint[c]! * a) / 255;
      data[to + 3] = a / 255;
    }
  return { width, height: pixels.height + 2, data };
}

// An opaque image being painted: RGB floats in 0..255.
export class Canvas {
  readonly rgb: Float32Array;

  constructor(readonly width: number, readonly height: number, fill: readonly number[]) {
    this.rgb = new Float32Array(width * height * 3);
    for (let i = 0; i < this.rgb.length; i += 3) this.rgb.set(fill, i);
  }

  // The bilinear sample of `texture` at (u, v), in texels of the unpadded art from its top left, laid over pixel
  // (x, y). Samples outside the art leave the pixel alone.
  sample(texture: Texture, u: number, v: number, x: number, y: number): void {
    u += 0.5;
    v += 0.5;
    if (u < 0 || v < 0 || u >= texture.width - 1 || v >= texture.height - 1) return;
    const u0 = u | 0;
    const v0 = v | 0;
    const fu = u - u0;
    const fv = v - v0;
    const w00 = (1 - fu) * (1 - fv);
    const w10 = fu * (1 - fv);
    const w01 = (1 - fu) * fv;
    const w11 = fu * fv;
    const t = texture.data;
    const t00 = (v0 * texture.width + u0) * 4;
    const t01 = t00 + texture.width * 4;
    const a = t[t00 + 3]! * w00 + t[t00 + 7]! * w10 + t[t01 + 3]! * w01 + t[t01 + 7]! * w11;
    if (a === 0) return;
    const at = (y * this.width + x) * 3;
    for (let c = 0; c < 3; c++)
      this.rgb[at + c] = t[t00 + c]! * w00 + t[t00 + 4 + c]! * w10 + t[t01 + c]! * w01 + t[t01 + 4 + c]! * w11 + this.rgb[at + c]! * (1 - a);
  }

  // Pixel (x, y) darkened by `shade` of the coverage of `texture` at (u, v), as sample() places it.
  shadow(texture: Texture, u: number, v: number, x: number, y: number, shade: number): void {
    u += 0.5;
    v += 0.5;
    if (u < 0 || v < 0 || u >= texture.width - 1 || v >= texture.height - 1) return;
    const u0 = u | 0;
    const v0 = v | 0;
    const fu = u - u0;
    const fv = v - v0;
    const t = texture.data;
    const t00 = (v0 * texture.width + u0) * 4 + 3;
    const t01 = t00 + texture.width * 4;
    const a = (t[t00]! * (1 - fu) + t[t00 + 4]! * fu) * (1 - fv) + (t[t01]! * (1 - fu) + t[t01 + 4]! * fu) * fv;
    const at = (y * this.width + x) * 3;
    for (let c = 0; c < 3; c++) this.rgb[at + c]! *= 1 - a * shade;
  }

  pixels(): Pixels {
    const data = new Uint8ClampedArray(this.width * this.height * 4);
    for (let i = 0, j = 0; i < this.rgb.length; i += 3, j += 4) {
      data[j] = this.rgb[i]!;
      data[j + 1] = this.rgb[i + 1]!;
      data[j + 2] = this.rgb[i + 2]!;
      data[j + 3] = 255;
    }
    return { width: this.width, height: this.height, data: new Uint8Array(data.buffer) };
  }
}

// The ground over the canvas's top left `size` pixels square, from the terrain textures by slot.
export function paintGround(canvas: Canvas, ground: Ground, textures: Pixels[], size: number): void {
  const scale = size / SIZE;
  const half = PATCH / 2;
  // A rotated patch's corners stay within this of its centre.
  const reach = Math.ceil(half * Math.SQRT2 * scale) + 1;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) canvas.rgb.set(CLEAR, (y * canvas.width + x) * 3);
  ground.layers.forEach((stamps, layer) => {
    const tinted = texture(textures[ground.slots[layer]!]!, [TINT_RGB, TINT_RGB, TINT_RGB], LAYER_ALPHA[layer]! / 255, ALPHA_REF);
    for (const [rotation, sx, sy] of stamps) {
      const cos = Math.cos(rotation) / scale;
      const sin = Math.sin(rotation) / scale;
      const cx = (sx + half) * scale;
      const cy = (sy + half) * scale;
      const [x0, x1] = [Math.max(0, Math.floor(cx - reach)), Math.min(size, Math.ceil(cx + reach))];
      for (let y = Math.max(0, Math.floor(cy - reach)); y < Math.min(size, Math.ceil(cy + reach)); y++) {
        const dy = y + 0.5 - cy;
        for (let x = x0; x < x1; x++) {
          // The pixel's centre back in the unrotated patch.
          const dx = x + 0.5 - cx;
          canvas.sample(tinted, cos * dx + sin * dy + half - 0.5, cos * dy - sin * dx + half - 0.5, x, y);
        }
      }
    }
  });
}

// Where the player spent the run, over the ground: the 10 Hz positions binned into 32px cells of the game's ground,
// each cell filled `color` at 0.85 of the square root of its share of the busiest, then blurred.
export function paintHeat(canvas: Canvas, path: [t: number, x: number, y: number][], size: number, color: readonly number[], blur: number): void {
  const CELL = 32;
  const cells = SIZE / CELL;
  const bins = new Float32Array(cells * cells);
  for (const [, x, y] of path) {
    const [col, row] = [Math.floor(x / CELL), Math.floor(y / CELL)];
    if (col >= 0 && row >= 0 && col < cells && row < cells) bins[row * cells + col]!++;
  }
  const most = Math.max(...bins);
  const alpha = new Float32Array(size * size);
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) {
      const count = bins[Math.floor((y * cells) / size) * cells + Math.floor((x * cells) / size)]!;
      alpha[y * size + x] = 0.85 * Math.sqrt(count / most);
    }
  // feGaussianBlur's three box blurs each way (SVG 1.1, filters.html#feGaussianBlurElement).
  const box = Math.floor(blur * ((3 * Math.sqrt(2 * Math.PI)) / 4) + 0.5);
  const scratch = new Float32Array(size);
  for (const vertical of [false, true])
    for (let pass = 0; pass < 3; pass++)
      for (let line = 0; line < size; line++) {
        const at = (i: number) => (vertical ? i * size + line : line * size + i);
        // Even boxes shift by half a pixel each way across their passes.
        const lead = box % 2 ? (box - 1) / 2 : pass === 1 ? box / 2 - 1 : box / 2;
        for (let i = 0; i < size; i++) scratch[i] = alpha[at(i)]!;
        let sum = 0;
        for (let i = -lead; i < box - lead; i++) sum += i >= 0 && i < size ? scratch[i]! : 0;
        for (let i = 0; i < size; i++) {
          alpha[at(i)] = sum / box;
          const [enter, leave] = [i + box - lead, i - lead];
          sum += (enter < size ? scratch[enter]! : 0) - (leave >= 0 ? scratch[leave]! : 0);
        }
      }
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) {
      const a = alpha[y * size + x]!;
      const at = (y * canvas.width + x) * 3;
      for (let c = 0; c < 3; c++) canvas.rgb[at + c] = color[c]! * a + canvas.rgb[at + c]! * (1 - a);
    }
}

// The canvas's left `side` columns mirrored across their right edge into the rest of its width.
export function mirror(canvas: Canvas, side: number): void {
  for (let y = 0; y < canvas.height; y++)
    for (let x = side; x < canvas.width; x++) {
      const row = y * canvas.width;
      canvas.rgb.copyWithin((row + x) * 3, (row + 2 * side - 1 - x) * 3, (row + 2 * side - x) * 3);
    }
}

export interface Box {
  x: number;
  y: number;
  width: number;
  height: number;
}

// `art` stretched over `box` with its borders kept at their size, as CSS border-image draws web/src/style.css .panel,
// after its silhouette `offset` pixels right and down, darkening what lies under it by `shade` of its alpha.
export function paintPanel(canvas: Canvas, art: Pixels, borders: { top: number; right: number; bottom: number; left: number }, box: Box, offset: number, shade: number): void {
  const panel = texture(art);
  // A box pixel's centre along one axis, back in the art.
  const along = (d: number, size: number, artSize: number, start: number, end: number) =>
    (d < start ? d : d >= size - end ? artSize - (size - d) : start + ((d - start) * (artSize - start - end)) / (size - start - end)) - 0.5;
  for (const shadow of [true, false])
    for (let y = 0; y < box.height; y++) {
      const v = along(y + 0.5, box.height, art.height, borders.top, borders.bottom);
      for (let x = 0; x < box.width; x++) {
        const u = along(x + 0.5, box.width, art.width, borders.left, borders.right);
        if (!shadow) canvas.sample(panel, u, v, box.x + x, box.y + y);
        else if (box.x + x + offset < canvas.width && box.y + y + offset < canvas.height) canvas.shadow(panel, u, v, box.x + x + offset, box.y + y + offset, shade);
      }
    }
}

