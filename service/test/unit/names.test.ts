import { describe, expect, it } from "vitest";
import type { PlayerView } from "../../src/api-types";
import { playerParts, shownName } from "../../web/src/names";

const link = (provider: "github" | "discord" | "x", handle: string, avatar_url: string | null = null) => ({ provider, handle, avatar_url, url: "" });
const player = (name: string | null, links: PlayerView["links"], clash = false): PlayerView => ({ id: 1, name, fingerprint: "a2fe", clash, links });

describe("players show as the leaderboard identity rules describe", () => {
  it("a linked account shows the handle its typed name matches, else the one most links share, else X, Discord, GitHub", () => {
    expect(shownName("BANTEG", [link("x", "razenpok"), link("github", "banteg")])).toBe("banteg");
    expect(shownName("10tons]]", [link("x", "Razenpok"), link("discord", "razenpok"), link("github", "Razenpok")])).toBe("Razenpok");
    expect(shownName("bob", [link("x", "a"), link("discord", "b"), link("github", "b")])).toBe("b");
    expect(shownName("bob", [link("github", "a"), link("discord", "b")])).toBe("b");
  });

  it("an unlinked account shows its typed name, unless it is empty or the default", () => {
    expect(shownName("banteg", [])).toBe("banteg");
    expect(shownName("10tons", [])).toBeNull();
    expect(shownName("", [])).toBeNull();
  });

  it("links show their handles where they differ from the name, in X, Discord, GitHub order", () => {
    const parts = playerParts(player("banteg", [link("github", "banteg", "gh.png"), link("discord", "bant"), link("x", "Banteg", "x.png")]));

    expect(parts).toMatchObject({ label: "banteg", avatar: "x.png", fingerprint: null });
    expect(parts.links.map(({ link, handle }) => [link.provider, handle])).toEqual([["x", null], ["discord", "bant"], ["github", null]]);
  });

  it("an unlinked name another account shares gets the key fingerprint; a missing name shows it instead", () => {
    expect(playerParts(player("ghost", [], true)).fingerprint).toBe("a2fe");
    expect(playerParts(player("ghost", [link("github", "ghost")], true)).fingerprint).toBeNull();
    expect(playerParts(player(null, []))).toMatchObject({ label: "a2fe", unnamed: true, fingerprint: null });
  });
});
