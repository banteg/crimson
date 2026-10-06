import { describe, expect, it } from "vitest";
import type { PlayerView } from "../../src/api-types";
import { playerParts } from "../../web/src/names";

const link = (provider: "github" | "discord" | "x", handle: string, avatar_url: string | null = null) => ({ provider, handle, avatar_url, url: "" });
const player = (name: string | null, links: PlayerView["links"], clash = false): PlayerView => ({ id: 1, name, fingerprint: "a2fe", clash, links });

describe("players show as the leaderboard identity rules describe", () => {
  it("handles shared by every link collapse into the name, in X, Discord, GitHub order", () => {
    const parts = playerParts(player("banteg", [link("github", "banteg", "gh.png"), link("x", "Banteg", "x.png")]));

    expect(parts).toMatchObject({ label: "banteg", avatar: "x.png", handle: null, fingerprint: null });
    expect(parts.links.map(({ link, handle }) => [link.provider, handle])).toEqual([["x", null], ["github", null]]);
  });

  it("a shared handle unlike the name shows once; differing handles show by each link", () => {
    expect(playerParts(player("Bob", [link("github", "banteg")])).handle).toBe("banteg");
    const mixed = playerParts(player("Bob", [link("github", "a"), link("discord", "b")]));
    expect(mixed.links.map(({ handle }) => handle)).toEqual(["b", "a"]);
  });

  it("an unlinked name another account shares gets the key fingerprint; a missing name shows it instead", () => {
    expect(playerParts(player("ghost", [], true)).fingerprint).toBe("a2fe");
    expect(playerParts(player("ghost", [link("github", "ghost")], true)).fingerprint).toBeNull();
    expect(playerParts(player(null, []))).toMatchObject({ label: "a2fe", unnamed: true, fingerprint: null });
  });
});
