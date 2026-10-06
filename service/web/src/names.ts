import type { LinkView, PlayerView } from "../../src/api-types";

// Linked accounts in this order: the avatar comes from the first that has one.
const LINK_ORDER = ["x", "discord", "github"] as const;
export const PROVIDER_LABELS: Record<string, string> = { github: "GitHub", discord: "Discord", x: "X" };

export interface PlayerParts {
  label: string;
  // The fingerprint stands in for a missing name.
  unnamed: boolean;
  avatar: string | null;
  // A handle shared by every link, shown only where it differs from the name.
  handle: string | null;
  // Each link with its own handle, or none when they collapse into `handle` or the name.
  links: { link: LinkView; handle: string | null }[];
  // The fingerprint suffix that tells apart unlinked accounts showing the same name.
  fingerprint: string | null;
}

// How boards and profiles show a player (docs/rewrite/leaderboard-identity.md, "Names").
export function playerParts(player: PlayerView): PlayerParts {
  const links = [...player.links].sort((a, b) => LINK_ORDER.indexOf(a.provider) - LINK_ORDER.indexOf(b.provider));
  const parts: PlayerParts = {
    label: player.name ?? player.fingerprint,
    unnamed: player.name === null,
    avatar: links.find((link) => link.avatar_url)?.avatar_url ?? null,
    handle: null,
    links: [],
    fingerprint: !links.length && player.clash && player.name !== null ? player.fingerprint : null,
  };
  const handles = new Set(links.map((link) => link.handle.toLowerCase()));
  if (handles.size === 1) {
    const handle = links[0]!.handle;
    parts.handle = player.name !== null && handle.toLowerCase() === player.name.toLowerCase() ? null : handle;
    parts.links = links.map((link) => ({ link, handle: null }));
  } else parts.links = links.map((link) => ({ link, handle: link.handle }));
  return parts;
}
