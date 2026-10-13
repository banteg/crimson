// A run's ground as it ends: the terrain its seed stamps (web/src/terrain/rules.ts), with every decal and corpse its
// ticks baked into it, drawn as the original's fx_queue_render draws them into its terrain render target
// (decomp/1.9/crimsonland/crimsonland/fx_queue_render.cpp). The verifier hands the bakes out tick by tick
// (PortableBakes in crimson-core/host/api.h); the ground is kept beside the run's replay.

import artFiles from "./ground-art.json";
import { ALPHA_REF, type Ground, SIZE } from "../web/src/terrain/rules";
import type { Env } from "./http";
import { decodePng, type Pixels } from "./png";
import { Canvas, Layer, paintGround, prepareCell, type PreparedCell, type Quad, straightTexture, type Texture } from "./raster";

const BAKE_BYTES = 44;
const DECALS = 0x80;
const CORPSES = 0x40;
export const BAKES_BYTES = 8 + (DECALS + CORPSES) * BAKE_BYTES;
// fx_queue_render's half texel, 1 over half the terrain's width, which it takes off corpse positions in pixels.
const HALF_TEXEL = 1 / (SIZE * 0.5);
// The bodyset's corpses lie a quarter turn from their creature's heading.
const QUARTER_TURN = 1.5707964;
// A corpse's shadow: larger, nudged up and left, at half its alpha.
const SHADOW_SCALE = 1.064;
const SHADOW_NUDGE = 0.5;

// The atlases the bakes draw from (game/particles.jaz, game/bodyset.jaz) and the terrain textures by slot.
export interface GroundArt {
  terrain: Pixels[];
  particles: Pixels;
  bodyset: Pixels;
}

// Where a run's ground is kept, beside its replay.
export const groundKey = (runId: string) => `runs/${runId}.ground.jpg`;

// The site's art (scripts/assets.py), read from its own files once per isolate.
let siteArt: Promise<GroundArt> | null = null;

export function groundArt(env: Env, origin: string): Promise<GroundArt> {
  const file = async (name: string) => decodePng(new Uint8Array(await (await env.ASSETS.fetch(new URL(`/ui/${name}`, origin))).arrayBuffer()));
  return (siteArt ??= (async () => ({
    terrain: await Promise.all(artFiles.terrain.map(file)),
    particles: await file(artFiles.particles),
    bodyset: await file(artFiles.bodyset),
  }))());
}

interface Bake {
  x: number;
  y: number;
  width: number;
  height: number;
  rotation: number;
  color: number[];
  grid: number;
  frame: number;
}

// Bake `index` of a chunk's records, laid out as PortableBake.
function readBake(bakes: DataView, index: number): Bake {
  const at = index * BAKE_BYTES;
  const f = (field: number) => bakes.getFloat32(at + field * 4, true);
  return {
    x: f(0),
    y: f(1),
    width: f(2),
    height: f(3),
    rotation: f(4),
    color: [f(5), f(6), f(7), f(8)],
    grid: bakes.getInt32(at + 36, true),
    frame: bakes.getInt32(at + 40, true),
  };
}

// Cell `frame` of an atlas cut `grid` cells a side, in texels of its art: the texture less its border.
const cells = new WeakMap<Texture, Map<number, PreparedCell>>();
function cell(art: Texture, grid: number, frame: number): PreparedCell {
  let cache = cells.get(art);
  if (!cache) {
    cache = new Map();
    cells.set(art, cache);
  }
  // The largest original atlas grid is 16x16, so its frame fits in eight bits.
  const key = grid * 256 + frame;
  const known = cache.get(key);
  if (known) return known;
  const [width, height] = [(art.width - 2) / grid, (art.height - 2) / grid];
  const result = prepareCell(art, { x: (frame % grid) * width, y: Math.floor(frame / grid) * height, width, height });
  cache.set(key, result);
  return result;
}

// Bakes a chunk holds before it is drawn: the more, the more of them later ones cover.
const CHUNK = 1 << 18;

// The ground at `size` pixels a side, the game's SIZE scaled. Each chunk of ticks draws newest first, under what
// later bakes laid, so the blood a later splat covers takes no samples; then the chunk lies over the ground.
export class GroundBake {
  private readonly canvas: Canvas;
  private readonly layer: Layer;
  private readonly scale: number;
  private readonly particles: Texture;
  private readonly bodyset: Texture;
  // The chunk's ticks, each its bakes as the verifier hands them out, without the queues' unused room.
  private chunk = new Uint8Array(CHUNK * BAKE_BYTES);
  private ticks: { at: number; decals: number; corpses: number }[] = [];
  private used = 0;

  constructor(ground: Ground, art: GroundArt, size: number) {
    this.canvas = new Canvas(size, size, [0, 0, 0]);
    this.layer = new Layer(size, size);
    this.scale = size / SIZE;
    paintGround(this.canvas, ground, art.terrain, { x: 0, y: 0, size });
    this.particles = straightTexture(art.particles);
    this.bodyset = straightTexture(art.bodyset);
  }

  bake(bakes: DataView): void {
    const decals = bakes.getInt32(0, true);
    const corpses = bakes.getInt32(4, true);
    if (!decals && !corpses) return;
    if (this.used + decals + corpses > CHUNK) this.flush();
    const bytes = new Uint8Array(bakes.buffer, bakes.byteOffset, bakes.byteLength);
    const at = this.used * BAKE_BYTES;
    this.chunk.set(bytes.subarray(8, 8 + decals * BAKE_BYTES), at);
    this.chunk.set(bytes.subarray(8 + DECALS * BAKE_BYTES, 8 + (DECALS + corpses) * BAKE_BYTES), at + decals * BAKE_BYTES);
    this.ticks.push({ at: this.used, decals, corpses });
    this.used += decals + corpses;
  }

  pixels(): Pixels {
    this.flush();
    return this.canvas.pixels();
  }

  // The chunk's ticks newest first, each as fx_queue_render bakes it backwards: its corpses, their shadows, its decals.
  private flush(): void {
    const view = new DataView(this.chunk.buffer);
    for (let i = this.ticks.length - 1; i >= 0; i--) {
      const { at, decals, corpses } = this.ticks[i]!;
      for (let c = corpses - 1; c >= 0; c--) {
        const b = readBake(view, at + decals + c);
        const quad = { x: b.x - HALF_TEXEL, y: b.y - HALF_TEXEL, width: b.width, height: b.height, rotation: b.rotation - QUARTER_TURN };
        this.draw(this.bodyset, b, quad, b.color, false);
      }
      for (let c = corpses - 1; c >= 0; c--) {
        const b = readBake(view, at + decals + c);
        const quad = {
          x: b.x - SHADOW_NUDGE - HALF_TEXEL,
          y: b.y - SHADOW_NUDGE - HALF_TEXEL,
          width: b.width * SHADOW_SCALE,
          height: b.height * SHADOW_SCALE,
          rotation: b.rotation - QUARTER_TURN,
        };
        this.draw(this.bodyset, b, quad, [0, 0, 0, b.color[3]! * 0.5], true);
      }
      for (let d = decals - 1; d >= 0; d--) {
        const b = readBake(view, at + d);
        const quad = { x: b.x - b.width / 2, y: b.y - b.height / 2, width: b.width, height: b.height, rotation: b.rotation };
        this.draw(this.particles, b, quad, b.color, false);
      }
    }
    this.layer.composite(this.canvas);
    this.ticks = [];
    this.used = 0;
  }

  private draw(art: Texture, bake: Bake, quad: Quad, color: readonly number[], shadow: boolean): void {
    const k = this.scale;
    const scaled = { x: quad.x * k, y: quad.y * k, width: quad.width * k, height: quad.height * k, rotation: quad.rotation };
    this.layer.drawQuad(art, cell(art, bake.grid, bake.frame), scaled, color, shadow, ALPHA_REF);
  }
}
