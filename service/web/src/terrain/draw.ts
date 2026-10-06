// A ground drawn as src/grim/terrain_render.py draws it: the clear color, then each layer's stamps with the layer's
// tint and the DX8 alpha test, as an image URL the page shows behind its panels.

import { crtRand, generate, generateRandom, type Ground, questSlots, SIZE } from "./rules";

const PATCH = 128;
const CLEAR = "rgb(63, 56, 25)";
// Layer tints: RGB 178/255 on every layer, alpha 230, 230 and 153.
const TINT_RGB = 178 / 255;
const LAYER_ALPHA = [230, 230, 153];
// Texels at or below 4/255 after the tint are discarded.
const ALPHA_REF = 4;
// The random terrain of a save with every quest unlocked.
const UNLOCK_INDEX = 50;

function load(slot: number): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = reject;
    image.src = `/ui/ter${slot}.png`;
  });
}

function tinted(image: HTMLImageElement, alpha: number): HTMLCanvasElement {
  const canvas = document.createElement("canvas");
  canvas.width = image.width;
  canvas.height = image.height;
  const context = canvas.getContext("2d")!;
  context.drawImage(image, 0, 0);
  const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
  const data = pixels.data;
  for (let i = 0; i < data.length; i += 4) {
    const a = (data[i + 3]! * alpha) / 255;
    data[i] = data[i]! * TINT_RGB;
    data[i + 1] = data[i + 1]! * TINT_RGB;
    data[i + 2] = data[i + 2]! * TINT_RGB;
    data[i + 3] = a <= ALPHA_REF ? 0 : a;
  }
  context.putImageData(pixels, 0, 0);
  return canvas;
}

// A fresh ground for `quest` ("2.7"), or the game's random terrain; as tall as the display, so it fills the screen.
export async function drawGround(quest: string | null): Promise<{ url: string; height: number }> {
  const height = Math.max(SIZE, Math.ceil(Math.max(window.screen.height, window.innerHeight) / 64) * 64);
  const rand = crtRand(crypto.getRandomValues(new Uint32Array(1))[0]!);
  const ground: Ground = quest
    ? generate(rand, questSlots(...(quest.split(".").map(Number) as [number, number])), SIZE, height)
    : generateRandom(rand, UNLOCK_INDEX, SIZE, height);
  const images = await Promise.all(ground.slots.map(load));
  const canvas = document.createElement("canvas");
  canvas.width = SIZE;
  canvas.height = height;
  const context = canvas.getContext("2d")!;
  context.fillStyle = CLEAR;
  context.fillRect(0, 0, SIZE, height);
  ground.layers.forEach((stamps, i) => {
    const texture = tinted(images[i]!, LAYER_ALPHA[i]!);
    for (const [rotation, x, y] of stamps) {
      context.setTransform(1, 0, 0, 1, x + PATCH / 2, y + PATCH / 2);
      context.rotate(rotation);
      context.drawImage(texture, -PATCH / 2, -PATCH / 2, PATCH, PATCH);
    }
  });
  const blob = await new Promise<Blob>((resolve) => canvas.toBlob((b) => resolve(b!)));
  return { url: URL.createObjectURL(blob), height };
}
