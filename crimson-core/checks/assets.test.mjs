import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, webcrypto } from "node:crypto";
import { test } from "node:test";
import vm from "node:vm";

const shell = readFileSync(new URL("../client/web/shell.html", import.meta.url), "utf8");
const functions = shell.slice(shell.indexOf("  // Downloads, with"), shell.indexOf("  async function hydrate()"));
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const old = new TextEncoder().encode("old art"), current = new TextEncoder().encode("current art");

function browser(installed, downloaded = current, unavailable = false) {
  const files = new Map(installed ? [["/game/crimson.paq", installed]] : []);
  const requests = [];
  const context = vm.createContext({
    ART_VERSION: { current: digest(current), previous: [digest(old)] },
    artHash: async (bytes) => digest(bytes), crypto: webcrypto, URL, Uint8Array,
    location: { href: "https://example.invalid/play/" }, base: "game/",
    progress: { hidden: true, firstElementChild: { style: {} } }, say() {},
    console: { warn() {} }, exists: (name) => files.has("/game/" + name),
    FS: { readFile: (name) => files.get(name) },
    missing: () => files.has("/game/crimson.paq") ? [] : ["crimson.paq"],
    store: (name, bytes) => files.set("/game/" + name, bytes),
    storeMusic() { throw Error("Unexpected music migration"); },
    fetch: async (url) => {
      requests.push(String(url));
      if (unavailable) throw Error("offline");
      let read = false;
      return { ok: true, headers: new Map([["content-length", String(downloaded.length)]]),
        body: { getReader: () => ({ read: async () => {
          if (read) return { done: true };
          read = true;
          return { done: false, value: downloaded };
        } }) } };
    },
  });
  vm.runInContext(functions + "\nglobalThis.update = fetchMissing;", context);
  return { update: context.update, files, requests };
}

for (const [label, installed] of [["old", old], ["current", current], ["custom", new TextEncoder().encode("custom")], ["missing", null]]) {
  test(`browser upgrades ${label} artwork only when needed`, async () => {
    const b = browser(installed);
    await b.update();
    const upgrade = label === "old" || label === "missing";
    assert.equal(b.requests.length, upgrade ? 1 : 0);
    assert.equal(digest(b.files.get("/game/crimson.paq")), digest(upgrade ? current : installed));
    if (upgrade) assert.equal(new URL(b.requests[0]).searchParams.get("sha256"), digest(current));
    await b.update();
    assert.equal(b.requests.length, upgrade ? 1 : 0, "does not download again once current");
  });
}

for (const [label, downloaded, unavailable] of [["stale cache", old, false], ["HTML response", new TextEncoder().encode("<html>error</html>"), false], ["offline", current, true]]) {
  test(`browser keeps installed artwork on ${label}`, async () => {
    const b = browser(old, downloaded, unavailable);
    await b.update();
    assert.equal(digest(b.files.get("/game/crimson.paq")), digest(old));
  });
  test(`browser does not install missing artwork on ${label}`, async () => {
    const b = browser(null, downloaded, unavailable);
    await assert.rejects(b.update());
    assert.equal(b.files.has("/game/crimson.paq"), false);
  });
}
