// A run's preview card, the image a shared link unfurls into: the run's own ground with where the player spent it, as
// the run page's arena shows it, and the game's menu panel with the board, the player, the score and the run's
// numbers in the game's small font. The raster layers are painted in src/raster.ts; resvg draws the rest over them.

import { initWasm, Resvg } from "@resvg/resvg-wasm";
import resvgModule from "@resvg/resvg-wasm/index_bg.wasm";
import courierPrime from "../fonts/CourierPrime-Bold.ttf";
import { formatScore } from "../web/src/format";
import { playerParts } from "../web/src/names";
import { runGround, SIZE } from "../web/src/terrain/rules";
import weaponData from "../web/src/weapons.json";
import type { RunDetailView, Timeline } from "./api-types";
import type { Env } from "./http";
import { decodePng, encodePng, type Pixels } from "./png";
import { Canvas, mirror, paintGround, paintHeat, paintPanel } from "./raster";
import { runDetailView } from "./views";

const WEAPONS: Record<string, { name: string; icon_index: number }> = weaponData;

export const CARD_WIDTH = 1200;
export const CARD_HEIGHT = 630;

// The game art the card draws, from the site's own files (scripts/assets.py).
export interface CardArt {
  // The game's small font; the numbers are set in Courier, as the site and grim's mono font set them.
  font: Uint8Array;
  panel: Pixels;
  // The terrain textures by slot.
  textures: Pixels[];
  // ui_wicons, as a data URL.
  weapons: string;
  // The player's avatar as a data URL, when a linked account has one.
  avatar: string | null;
}

// web/src/run.tsx's colours, and web/src/style.css's label and dim greys.
const BLUE = "rgb(70,180,240)";
const RED = "rgb(250,70,60)";
const GREEN = "rgb(128,255,153)";
const GOLD = [240, 200, 90];
const LABEL = "#b3b3b3";
const DIM = "#7d7d7d";
// The arena's heat blur and the end marks are web/src/run.tsx Arena's, in the game's ground pixels.
const HEAT_BLUR = 14;
const TRAIL_S = 20;
// ui_menuPanel's frame around its black screen (web/src/style.css .panel), and ui_element_render's shadow.
const PANEL_BORDERS = { top: 18, right: 19, bottom: 19, left: 14 };
const SHADOW = { offset: 7, shade: 0x44 / 255 };
const PANEL = { x: CARD_HEIGHT + 10, y: 22, width: CARD_WIDTH - CARD_HEIGHT - 32, height: CARD_HEIGHT - 44 };
const PADDING = 26;
// The panel's contents.
const LEFT = PANEL.x + PANEL_BORDERS.left + PADDING;
const RIGHT = PANEL.x + PANEL.width - PANEL_BORDERS.right - PADDING;
const TOP = PANEL.y + PANEL_BORDERS.top;
const BOTTOM = PANEL.y + PANEL.height - PANEL_BORDERS.bottom;
const NAME_Y = TOP + 74;
const SCORE_SIZE = 84;
const STAT_SIZE = 46;
const STAT_COLUMN = 260;
const AVATAR = 64;
// ui_wicons: an 8x8 grid of 32px cells; each icon is two cells wide, at frame icon_index * 2.
const ICON_CELL = 32;
// One small-font pixel is 1/16 of the font size; whole multiples keep its pixels square.
const FONT_PX = 16;
// Courier's glyphs are all 0.6 em wide, so a number's width is known before it is drawn. grim draws its mono font
// through bilinear filtering, which leaves it slightly soft; a slight blur stands in for that.
const COURIER_ADVANCE = 0.6;
const SOFTEN = 0.7;

const escape = (text: string) => text.replace(/[&<>"]/g, (ch) => `&#${ch.charCodeAt(0)};`);
const grouped = (n: number) => Math.round(n).toLocaleString("en-US");
const clock = (s: number) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

export function dataUrl(bytes: Uint8Array, type: string): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return `data:${type};base64,${btoa(binary)}`;
}

function text(x: number, y: number, scale: number, content: string, fill = "#fff", anchor = "start"): string {
  return `<text x="${x}" y="${y}" font-size="${FONT_PX * scale}" fill="${fill}" text-anchor="${anchor}">${escape(content)}</text>`;
}

// A number in Courier at `size`, or smaller if that would run past `width`.
function number(x: number, y: number, size: number, width: number, content: string, fill = "#fff", anchor = "start"): string {
  const fitted = Math.min(size, width / (content.length * COURIER_ADVANCE));
  return `<text x="${x}" y="${y}" font-family="Courier Prime" font-size="${fitted}" fill="${fill}" text-anchor="${anchor}" filter="url(#soft)">${escape(content)}</text>`;
}

// The ground and heat at the card's left, mirrored on under the panel, and the panel.
function background(detail: RunDetailView, timeline: Timeline, art: CardArt): Pixels {
  const canvas = new Canvas(CARD_WIDTH, CARD_HEIGHT, [0, 0, 0]);
  const quest = detail.quest ? (detail.quest.split(".").map(Number) as [number, number]) : null;
  paintGround(canvas, runGround(timeline.seed, quest), art.textures, CARD_HEIGHT);
  mirror(canvas, CARD_HEIGHT);
  paintHeat(canvas, timeline.path, CARD_HEIGHT, GOLD, (HEAT_BLUR * CARD_HEIGHT) / SIZE);
  paintPanel(canvas, art.panel, PANEL_BORDERS, PANEL, SHADOW.offset, SHADOW.shade);
  return canvas.pixels();
}

// The last seconds of the player's path and how the run ended, in the game's ground pixels.
function trail(detail: RunDetailView, timeline: Timeline): string {
  const points = timeline.path.filter(([t]) => t > timeline.duration_s - TRAIL_S).map(([, x, y]) => `${x},${y}`);
  const [, x, y] = timeline.path.at(-1)!;
  const end =
    detail.result.outcome === "quest_completed"
      ? `<path d="M${x - 20},${y} l14,16 l28,-32" fill="none" stroke="${GREEN}" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>`
      : detail.result.outcome === "death"
        ? `<path d="M${x - 18},${y - 18} l36,36 M${x + 18},${y - 18} l-36,36" stroke="${RED}" stroke-width="8"/>`
        : `<circle cx="${x}" cy="${y}" r="18" fill="none" stroke="rgb(${GOLD})" stroke-width="6"/>`;
  return `<polyline points="${points.join(" ")}" fill="none" stroke="#fff" stroke-width="5" stroke-linejoin="round" stroke-opacity="0.9"/>${end}`;
}

function cardSvg(detail: RunDetailView, timeline: Timeline, art: CardArt, background: string): string {
  const result = detail.result;
  const quest = detail.board !== "survival";
  const weapon = WEAPONS[result.most_used_weapon_id];
  const stats: [string, string][] = [
    quest ? ["quest time", formatScore(detail.board, result.elapsed_ms)] : ["survived", clock(result.elapsed_ms / 1000)],
    ["kills", grouped(result.kills)],
    ["level", String(timeline.samples.at(-1)![2])],
    ["accuracy", result.shots_fired ? `${Math.round((result.shots_hit / result.shots_fired) * 100)}%` : "-"],
  ];
  const score = quest ? formatScore(detail.board, detail.score) : grouped(detail.score);
  const icon = (frame: number) => `viewBox="${(frame % 8) * ICON_CELL} ${Math.floor(frame / 8) * ICON_CELL} ${ICON_CELL * 2} ${ICON_CELL}"`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${CARD_WIDTH}" height="${CARD_HEIGHT}" font-family="Crimson Small">
  <defs>
    <clipPath id="round"><circle cx="${LEFT + AVATAR / 2}" cy="${NAME_Y + AVATAR / 2}" r="${AVATAR / 2}"/></clipPath>
    <filter id="soft"><feGaussianBlur stdDeviation="${SOFTEN}"/></filter>
  </defs>
  <image href="${background}" width="${CARD_WIDTH}" height="${CARD_HEIGHT}"/>
  <g transform="scale(${CARD_HEIGHT / SIZE})">${trail(detail, timeline)}</g>
  ${text(LEFT, TOP + 40, 2, detail.title, LABEL)}
  ${text(RIGHT, TOP + 40, 2, "crimson.land", DIM, "end")}
  ${art.avatar ? `<image href="${art.avatar}" x="${LEFT}" y="${NAME_Y}" width="${AVATAR}" height="${AVATAR}" clip-path="url(#round)" preserveAspectRatio="xMidYMid slice"/>` : ""}
  ${detail.rank ? number(RIGHT, NAME_Y + 46, 44, RIGHT - LEFT, `#${detail.rank}`, `rgb(${GOLD})`, "end") : ""}
  ${text(art.avatar ? LEFT + AVATAR + 18 : LEFT, NAME_Y + 48, 3, detail.name)}
  ${text(LEFT, TOP + 194, 2, quest ? "final time" : "experience", DIM)}
  ${number(LEFT - 4, TOP + 272, SCORE_SIZE, RIGHT - LEFT, score, BLUE)}
  ${stats.map(([label, value], i) => {
    const [x, y] = [LEFT + (i % 2) * STAT_COLUMN, TOP + 330 + Math.floor(i / 2) * 84];
    return text(x, y, 2, label, DIM) + number(x - 2, y + 46, STAT_SIZE, STAT_COLUMN - 20, value);
  }).join("")}
  ${weapon ? `<svg x="${LEFT}" y="${BOTTOM - 86}" width="${ICON_CELL * 4}" height="${ICON_CELL * 2}" ${icon(weapon.icon_index * 2)}><image href="${art.weapons}" width="${ICON_CELL * 8}" height="${ICON_CELL * 8}"/></svg>${text(LEFT + 144, BOTTOM - 42, 2, weapon.name, LABEL)}` : ""}
</svg>`;
}

let ready: Promise<unknown> | null = null;

export async function renderCard(detail: RunDetailView, timeline: Timeline, art: CardArt, wasm: WebAssembly.Module | BufferSource = resvgModule): Promise<Uint8Array> {
  await (ready ??= initWasm(wasm));
  const svg = cardSvg(detail, timeline, art, dataUrl(encodePng(background(detail, timeline, art)), "image/png"));
  return new Resvg(svg, { font: { fontBuffers: [art.font, new Uint8Array(courierPrime)], loadSystemFonts: false, defaultFontFamily: "Crimson Small" } }).render().asPng();
}

// The site's art, read from its own files once per isolate.
let siteArt: Promise<Omit<CardArt, "avatar">> | null = null;

function loadArt(env: Env, origin: string): Promise<Omit<CardArt, "avatar">> {
  const file = async (name: string) => new Uint8Array(await (await env.ASSETS.fetch(new URL(`/ui/${name}`, origin))).arrayBuffer());
  return (siteArt ??= (async () => ({
    font: await file("small.ttf"),
    panel: await decodePng(await file("panel.png")),
    textures: await Promise.all(Array.from({ length: 8 }, async (_, slot) => decodePng(await file(`ter${slot}.png`)))),
    weapons: dataUrl(await file("weapons.png"), "image/png"),
  }))());
}

// An avatar at the card's size, as each provider serves it: drawn without resampling, a large image downscaled in
// one step would alias. X serves fixed sizes; its 73px "bigger" is the nearest above the 48px "normal" it links.
function sizedAvatar(link: string): string {
  const url = new URL(link);
  if (url.hostname === "avatars.githubusercontent.com") url.searchParams.set("s", String(AVATAR));
  else if (url.hostname === "cdn.discordapp.com") url.searchParams.set("size", String(AVATAR));
  else if (url.hostname === "pbs.twimg.com") url.pathname = url.pathname.replace(/_normal(\.\w+)$/, "_bigger$1");
  return url.toString();
}

// The avatar a linked account shows, if its provider answers with an image.
async function fetchAvatar(link: string | null): Promise<string | null> {
  if (!link) return null;
  const response = await fetch(sizedAvatar(link)).catch(() => null);
  if (!response) return null;
  const type = response.headers.get("content-type") ?? "";
  return response.ok && type.startsWith("image/") ? dataUrl(new Uint8Array(await response.arrayBuffer()), type) : null;
}

// A run's card as a PNG, or null when there is no such run or its timeline is gone.
export async function runCard(env: Env, origin: string, id: string): Promise<Uint8Array | null> {
  const detail = await runDetailView(env, id);
  if (!detail?.timeline) return null;
  const [art, avatar] = await Promise.all([loadArt(env, origin), fetchAvatar(playerParts(detail.player).avatar)]);
  return renderCard(detail, detail.timeline, { ...art, avatar });
}
