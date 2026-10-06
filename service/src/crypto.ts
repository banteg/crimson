// Ed25519 through WebCrypto, and the byte helpers the protocol uses (docs/rewrite/leaderboard-identity.md).

export const RUN_DOMAIN = new TextEncoder().encode("crimson-run-v1\n");
export const LOGIN_DOMAIN = new TextEncoder().encode("crimson-login-v1\n");

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function fromHex(text: string, length: number): Uint8Array | null {
  if (text.length !== length * 2 || !/^[0-9a-f]*$/.test(text)) return null;
  return Uint8Array.from({ length }, (_, i) => parseInt(text.slice(i * 2, i * 2 + 2), 16));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) out.set(part, at), (at += part.length);
  return out;
}

// Names are Latin-1 in the game's high-score entry; the signature covers those bytes.
export function latin1(text: string): Uint8Array | null {
  const codes = Array.from(text, (ch) => ch.codePointAt(0)!);
  return codes.every((code) => code <= 0xff) ? Uint8Array.from(codes) : null;
}

export async function verifyEd25519(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
}

export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  return hex(await sha256(publicKey)).slice(0, 4);
}

export function randomToken(): string {
  return hex(crypto.getRandomValues(new Uint8Array(32)));
}
