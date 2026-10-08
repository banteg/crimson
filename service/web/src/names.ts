import type { LinkView, PlayerView } from "../../src/api-types";

// Linked accounts in this order: the avatar comes from the first that has one, and so does the name when the
// handles disagree.
const LINK_ORDER = ["x", "discord", "github"] as const;
export const PROVIDER_LABELS: Record<string, string> = { github: "GitHub", discord: "Discord", x: "X" };
// A fresh config's name, which nobody chose.
export const DEFAULT_NAME = "10tons";

function byLinkOrder<T extends { provider: LinkView["provider"] }>(links: T[]): T[] {
  return [...links].sort((a, b) => LINK_ORDER.indexOf(a.provider) - LINK_ORDER.indexOf(b.provider));
}

// The name an account shows (docs/rewrite/leaderboard-identity.md, "Names"): a linked account shows the handle its
// typed name matches, else the handle most links share, else the first link's; an unlinked one shows its typed name
// unless that is the default.
export function shownName(typed: string, links: { provider: LinkView["provider"]; handle: string }[]): string | null {
  if (!links.length) return typed && typed !== DEFAULT_NAME ? typed : null;
  const handles = byLinkOrder(links).map((link) => link.handle);
  const count = (handle: string) => handles.filter((other) => other.toLowerCase() === handle.toLowerCase()).length;
  return (
    handles.find((handle) => handle.toLowerCase() === typed.toLowerCase()) ??
    handles.reduce((best, handle) => (count(handle) > count(best) ? handle : best))
  );
}

export interface PlayerParts {
  label: string;
  // The fingerprint stands in for a missing name.
  unnamed: boolean;
  avatar: string | null;
  // Each link with its handle where that differs from the name.
  links: { link: LinkView; handle: string | null }[];
  // The fingerprint suffix that tells apart unlinked accounts showing the same name.
  fingerprint: string | null;
}

// A player's name, or their key fingerprint without one.
export function playerLabel(player: PlayerView): string {
  return player.name ?? player.fingerprint;
}

// How boards and profiles show a player.
export function playerParts(player: PlayerView): PlayerParts {
  const links = byLinkOrder(player.links);
  return {
    label: playerLabel(player),
    unnamed: player.name === null,
    avatar: links.find((link) => link.avatar_url)?.avatar_url ?? null,
    links: links.map((link) => ({ link, handle: link.handle.toLowerCase() === player.name?.toLowerCase() ? null : link.handle })),
    fingerprint: !links.length && player.clash && player.name !== null ? player.fingerprint : null,
  };
}
