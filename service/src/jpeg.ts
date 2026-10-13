// JPEGs through mozjpeg's WASM build (@jsquash/jpeg), for a run's ground: kept and served at a tenth of a PNG's size,
// and read back for its card.

import decode, { init as initDecode } from "@jsquash/jpeg/decode";
import encode, { init as initEncode } from "@jsquash/jpeg/encode";
import decoderModule from "@jsquash/jpeg/codec/dec/mozjpeg_dec.wasm";
import encoderModule from "@jsquash/jpeg/codec/enc/mozjpeg_enc.wasm";
import type { Pixels } from "./png";

// Quality 88 at full chroma resolution: the ground's red detail blurs when its colour is halved (4:2:0) at any quality.
const OPTIONS = { quality: 88, auto_subsample: false, chroma_subsample: 1 };

let encoder: Promise<void> | null = null;
let decoder: Promise<void> | null = null;

export async function encodeJpeg({ width, height, data }: Pixels): Promise<Uint8Array> {
  await (encoder ??= initEncode(encoderModule));
  const image = { width, height, data: new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength) };
  return new Uint8Array(await encode(image as unknown as Parameters<typeof encode>[0], OPTIONS));
}

export async function decodeJpeg(bytes: Uint8Array): Promise<Pixels> {
  await (decoder ??= initDecode(decoderModule));
  const image = await decode(bytes.slice().buffer);
  return { width: image.width, height: image.height, data: new Uint8Array(image.data.buffer, image.data.byteOffset, image.data.byteLength) };
}
