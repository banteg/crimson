// ICE servers for a co-op peer connection: Cloudflare Realtime TURN credentials, minted per request
// (https://developers.cloudflare.com/realtime/turn/generate-credentials/).

import type { Env } from "./http";

export interface IceServer {
  urls: string[];
  username?: string;
  credential?: string;
}

const STUN: IceServer = { urls: ["stun:stun.cloudflare.com:3478"] };
// Longer than a room lives (coop.ts), so a session never outlasts its credentials.
const TTL_S = 86400;

// UDP relays first: TCP and TLS relays reach through stricter networks but stall the tick stream behind lost packets
// (docs/rewrite/network-coop.md §6.1).
const transportRank = (url: string) => (url.startsWith("turns:") ? 2 : url.includes("transport=tcp") ? 1 : 0);

// STUN only without both TURN values, or when the TURN service fails: two players on open networks still connect.
export async function iceServers(env: Env): Promise<IceServer[]> {
  if (!env.TURN_KEY_ID || !env.TURN_KEY_API_TOKEN) return [STUN];
  let servers: unknown;
  try {
    const response = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`, {
      method: "POST",
      headers: { authorization: `Bearer ${env.TURN_KEY_API_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ ttl: TTL_S }),
    });
    if (!response.ok) throw new Error(`status ${response.status}`);
    servers = ((await response.json()) as { iceServers?: unknown }).iceServers;
    if (!Array.isArray(servers)) throw new Error("no iceServers list");
  } catch (error) {
    console.error(`TURN credentials: ${error}`);
    return [STUN];
  }
  return (servers as Partial<IceServer>[]).flatMap((server) => {
    // WebRTC also allows a single URL string.
    const urls = (typeof server?.urls === "string" ? [server.urls] : Array.isArray(server?.urls) ? server.urls : [])
      // Browsers block port 53, and a URL on it only times out.
      .filter((url) => typeof url === "string" && !/:53(\?|$)/.test(url))
      .sort((a, b) => transportRank(a) - transportRank(b));
    // A server left without URLs is one RTCPeerConnection refuses.
    return urls.length ? [{ ...server, urls }] : [];
  });
}
