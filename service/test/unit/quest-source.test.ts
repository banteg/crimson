import { readFileSync, readdirSync } from "node:fs";
import { URL } from "node:url";
import { describe, expect, it } from "vitest";
import { questTokens } from "../../web/src/quest-source";

describe("quest source highlighting", () => {
  it("distinguishes statements, calls, qualified names and numeric units", () => {
    const source = "at .5s:\n    place spider.stop_and_go on edge_line(side, count=0x10, spacing=1e2)\n    heading -90deg\n";
    const styled = questTokens(source).filter((token) => token.kind);
    expect(styled).toEqual([
      { text: "at", kind: "keyword" }, { text: ".5s", kind: "number" },
      { text: "place", kind: "keyword" }, { text: "spider.stop_and_go", kind: "entity" },
      { text: "on", kind: "keyword" }, { text: "edge_line", kind: "function" },
      { text: "0x10", kind: "number" }, { text: "1e2", kind: "number" },
      { text: "heading", kind: "keyword" }, { text: "90deg", kind: "number" },
    ]);
  });

  it("keeps quoted hashes, escaped quotes and markup as source text", () => {
    const source = String.raw`quest "Quick # \"Clear\" <script>" version 1 # actual comment` + "\r\n";
    const tokens = questTokens(source);
    expect(tokens.filter((token) => token.kind === "string").map((token) => token.text))
      .toEqual([String.raw`"Quick # \"Clear\" <script>"`]);
    expect(tokens.filter((token) => token.kind === "comment").map((token) => token.text)).toEqual(["# actual comment"]);
    expect(tokens.map((token) => token.text).join("")).toBe(source);
  });

  it("recognizes order values and booleans without coloring parts of longer names", () => {
    const tokens = questTokens("order as-written\nfixed_weapon false\nlet true_count = 1\nspawn spider.at at center\n");
    expect(tokens.filter((token) => token.kind === "literal").map((token) => token.text)).toEqual(["as-written", "false"]);
    expect(tokens.find((token) => token.text === "true_count")?.kind).toBeNull();
    expect(tokens.find((token) => token.text === "spider.at")?.kind).toBe("entity");
  });

  it("preserves every byte of every stock and example recipe, including indentation and newlines", () => {
    const base = new URL("../../../src/crimson/quests/dsl/", import.meta.url);
    for (const directory of ["stock/", "examples/"]) {
      const path = new URL(directory, base);
      for (const name of readdirSync(path).filter((name) => name.endsWith(".quest"))) {
        const source = readFileSync(new URL(name, path), "utf8");
        expect(questTokens(source).map((token) => token.text).join(""), name).toBe(source);
      }
    }
    expect(questTokens("")).toEqual([]);
  });
});
