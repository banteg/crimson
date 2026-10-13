// The raster layers of a run's ground (src/ground.ts) and preview card, painted in plain TypeScript: the terrain,
// stamped as web/src/terrain/draw.ts stamps it on a canvas, the decals and corpses the run baked into it, and the game's
// menu panel with its shadow. resvg would decode a texture again for each of the ground's 1700 stamps, and render the
// whole stretched panel art for each of its nine slices.

import { ALPHA_REF, CLEAR, type Ground, LAYER_ALPHA, PATCH, SIZE, TINT_RGB } from "../web/src/terrain/rules";
import type { Pixels } from "./png";

// A texture ready to sample: floats, colour in 0..255 and alpha in 0..1, inside a transparent border one texel wide,
// so bilinear samples at the edges fade out without bounds checks. texture() premultiplies the colour by its alpha;
// straightTexture() keeps it straight.
export interface Texture {
  width: number;
  height: number;
  data: Float32Array;
}

export function texture(pixels: Pixels, tint: readonly number[] = [1, 1, 1], alphaScale = 1, alphaRef = -1): Texture {
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

// A texture whose colour and alpha interpolate apart, as Grim's device filters the atlases fx_queue_render draws
// from: Layer.drawQuad then weighs the filtered colour by the filtered alpha.
export function straightTexture(pixels: Pixels): Texture {
  const width = pixels.width + 2;
  const data = new Float32Array(width * (pixels.height + 2) * 4);
  for (let y = 0; y < pixels.height; y++)
    for (let x = 0; x < pixels.width; x++) {
      const from = (y * pixels.width + x) * 4;
      const to = ((y + 1) * width + x + 1) * 4;
      for (let c = 0; c < 3; c++) data[to + c] = pixels.data[from + c]!;
      data[to + 3] = pixels.data[from + 3]! / 255;
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

  // The canvas darkened to `factor` of itself.
  dim(factor: number): void {
    for (let i = 0; i < this.rgb.length; i++) this.rgb[i] = this.rgb[i]! * factor;
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

// A square of the canvas: where it draws the arena, the game's ground.
export interface Square {
  x: number;
  y: number;
  size: number;
}

// The ground over `arena`, from the terrain textures by slot.
export function paintGround(canvas: Canvas, ground: Ground, textures: Pixels[], arena: Square): void {
  const size = arena.size;
  const scale = size / SIZE;
  const half = PATCH / 2;
  // A rotated patch's corners stay within this of its centre.
  const reach = Math.ceil(half * Math.SQRT2 * scale) + 1;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) canvas.rgb.set(CLEAR, ((arena.y + y) * canvas.width + arena.x + x) * 3);
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
          canvas.sample(tinted, cos * dx + sin * dy + half - 0.5, cos * dy - sin * dx + half - 0.5, arena.x + x, arena.y + y);
        }
      }
    }
  });
}

// Quads drawn front to back, the last drawn first: what they add over the pixels under them (`rgb`, premultiplied)
// and how much of those still shows through (`clear`). A pixel that shows through less than SHOWS takes no more
// samples: what lies under it no longer moves it by half a level.
const SHOWS = 1 / 512;
export class Layer {
  readonly rgb: Float32Array;
  readonly clear: Float32Array;
  // One bit per pixel in horizontal blocks of 32: cleared once the pixel stops showing through. Empty blocks
  // let an older quad skip covered spans without visiting their pixels. The final block's padding is clipped.
  private readonly blocks: number;
  private readonly visible: Uint32Array;

  constructor(readonly width: number, readonly height: number) {
    this.rgb = new Float32Array(width * height * 3);
    this.clear = new Float32Array(width * height).fill(1);
    this.blocks = Math.ceil(width / 32);
    this.visible = new Uint32Array(this.blocks * height).fill(0xffffffff);
  }

  // `cell` of `texture` (a box of its texels, sampled straight) drawn as Grim draws a quad, under what this layer
  // holds: modulated by `color` (0..1, alpha included) as its vertex colour does and blended by the sample's alpha;
  // or, a `shadow`, darkening what lies under by that alpha. A sample whose alpha is at most `alphaRef` (of 255) does
  // neither, as Grim's alpha test drops it.
  drawQuad(texture: Texture, cell: Box, quad: Quad, color: readonly number[], shadow: boolean, alphaRef: number): void {
    const cx = quad.x + quad.width / 2;
    const cy = quad.y + quad.height / 2;
    const cos = Math.cos(quad.rotation);
    const sin = Math.sin(quad.rotation);
    // A pixel centre's place across the unturned quad, 0..1 each way: s and t step by a constant along a row.
    const sx = cos / quad.width;
    const sy = sin / quad.width;
    const tx = -sin / quad.height;
    const ty = cos / quad.height;
    const reach = (Math.abs(quad.width * sin) + Math.abs(quad.height * cos)) / 2 + 1;
    const top = Math.max(0, Math.floor(cy - reach));
    const bottom = Math.min(this.height, Math.ceil(cy + reach));
    const [r, g, b, alpha] = color as [number, number, number, number];
    const t = texture.data;
    for (let y = top; y < bottom; y++) {
      const dy = y + 0.5 - cy;
      const s0 = sx * (0.5 - cx) + sy * dy + 0.5;
      const t0 = tx * (0.5 - cx) + ty * dy + 0.5;
      // The row's columns where both lie in [0, 1).
      const lo = Math.max(0, spanStart(s0, sx), spanStart(t0, tx));
      const hi = Math.min(this.width, spanEnd(s0, sx), spanEnd(t0, tx));
      for (let start = lo; start < hi; ) {
        const base = start & ~31;
        const end = Math.min(hi, base + 32);
        const block = y * this.blocks + (base >>> 5);
        let mask = this.visible[block]! & (-1 << (start - base)) & (-1 >>> (base + 32 - end));
        start = end;
        while (mask) {
          // Consume the lowest set bit, keeping the surviving pixels in their original left-to-right order.
          const bit = 31 - Math.clz32(mask & -mask);
          mask &= mask - 1;
          const x = base + bit;
          const at = y * this.width + x;
          const clear = this.clear[at]!;
          if (clear < SHOWS) continue;
          // The bilinear sample at the pixel's centre, as Canvas.sample() takes it.
          const u = cell.x + (s0 + sx * x) * cell.width + 0.5;
          const v = cell.y + (t0 + tx * x) * cell.height + 0.5;
          if (u < 0 || v < 0 || u >= texture.width - 1 || v >= texture.height - 1) continue;
          const u0 = u | 0;
          const v0 = v | 0;
          const fu = u - u0;
          const fv = v - v0;
          const w00 = (1 - fu) * (1 - fv);
          const w10 = fu * (1 - fv);
          const w01 = (1 - fu) * fv;
          const w11 = fu * fv;
          const t00 = (v0 * texture.width + u0) * 4;
          const t01 = t00 + texture.width * 4;
          const a = (t[t00 + 3]! * w00 + t[t00 + 7]! * w10 + t[t01 + 3]! * w01 + t[t01 + 7]! * w11) * alpha;
          if (a * 255 <= alphaRef) continue;
          this.clear[at] = clear * (1 - a);
          // Read back the float32 result, exactly as the next quad's per-pixel cutoff does.
          if (this.clear[at]! < SHOWS) this.visible[block] = this.visible[block]! & ~(1 << bit);
          if (shadow) continue;
          const rgb = at * 3;
          const k = clear * a;
          this.rgb[rgb] = this.rgb[rgb]! + k * r * (t[t00]! * w00 + t[t00 + 4]! * w10 + t[t01]! * w01 + t[t01 + 4]! * w11);
          this.rgb[rgb + 1] = this.rgb[rgb + 1]! + k * g * (t[t00 + 1]! * w00 + t[t00 + 5]! * w10 + t[t01 + 1]! * w01 + t[t01 + 5]! * w11);
          this.rgb[rgb + 2] = this.rgb[rgb + 2]! + k * b * (t[t00 + 2]! * w00 + t[t00 + 6]! * w10 + t[t01 + 2]! * w01 + t[t01 + 6]! * w11);
        }
      }
    }
  }

  // The layer over `canvas`, and the layer empty again.
  composite(canvas: Canvas): void {
    for (let i = 0; i < this.clear.length; i++) {
      const clear = this.clear[i]!;
      for (let c = 0; c < 3; c++) canvas.rgb[i * 3 + c] = this.rgb[i * 3 + c]! + clear * canvas.rgb[i * 3 + c]!;
    }
    this.rgb.fill(0);
    this.clear.fill(1);
    this.visible.fill(0xffffffff);
  }
}

// The columns where f0 + k x lies in [0, 1): from spanStart, up to spanEnd.
function spanStart(f0: number, k: number): number {
  return k > 0 ? Math.ceil(-f0 / k) : k < 0 ? Math.ceil((1 - f0) / k) : f0 >= 0 && f0 < 1 ? 0 : Infinity;
}
function spanEnd(f0: number, k: number): number {
  return k > 0 ? Math.ceil((1 - f0) / k) : k < 0 ? Math.ceil(-f0 / k) : Infinity;
}

// A quad as Grim draws one, in canvas pixels: from its top left, turned `rotation` radians about its centre.
export interface Quad {
  x: number;
  y: number;
  width: number;
  height: number;
  rotation: number;
}

// `source` of `pixels` (all of it by default) over `box`, resampled bilinearly; what falls outside the canvas is left.
export function paintImage(canvas: Canvas, pixels: Pixels, box: Box, source: Box = { x: 0, y: 0, width: pixels.width, height: pixels.height }): void {
  const image = texture(pixels);
  const [kx, ky] = [source.width / box.width, source.height / box.height];
  for (let y = Math.max(0, -box.y); y < Math.min(box.height, canvas.height - box.y); y++)
    for (let x = Math.max(0, -box.x); x < Math.min(box.width, canvas.width - box.x); x++)
      canvas.sample(image, source.x + (x + 0.5) * kx, source.y + (y + 0.5) * ky, box.x + x, box.y + y);
}

// `pixels` shrunk by `factor` each way, each pixel the mean of the block it covers: drawn back up, a soft blur.
export function shrink({ width, height, data }: Pixels, factor: number): Pixels {
  const [w, h] = [Math.floor(width / factor), Math.floor(height / factor)];
  const out = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++)
      for (let c = 0; c < 4; c++) {
        let sum = 0;
        for (let dy = 0; dy < factor; dy++)
          for (let dx = 0; dx < factor; dx++) sum += data[((y * factor + dy) * width + x * factor + dx) * 4 + c]!;
        out[(y * w + x) * 4 + c] = sum / (factor * factor);
      }
  return { width: w, height: h, data: out };
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

