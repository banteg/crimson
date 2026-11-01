import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { checkRecipe, reconcileRecipes } from "./check-recipes.mjs";

const { custom_quest_run: fixture } = JSON.parse(readFileSync(new URL("../test/vectors.json", import.meta.url)));
const cleared = { source: fixture.source, digest: fixture.digest, title: "Quick Clear", author: "banteg", seed: 0 };

test("the actual publishing compiler checks table bytes and both presentation fields", () => {
  const random = cleared.source.replace("500ms", "500 + rand() - 38");
  assert.equal(checkRecipe(cleared), "verified");
  for (const changes of [
    { source: cleared.source.replace("500ms", "9000ms") },
    { source: cleared.source.replace("(512, 420)", "(512, 421)") },
    { source: cleared.source.replace("Quick Clear", "Wrong title") },
    { author: "other" },
    { source: "unparseable" },
  ]) assert.equal(checkRecipe({ ...cleared, ...changes }), "rejected");
  // A full expression also compiles, even though its source is unlike a literal spawn table.
  assert.equal(checkRecipe({ ...cleared, source: random }), "verified");
  assert.equal(checkRecipe({ ...cleared, source: random, seed: 1 }), "rejected");
});

test("a candidate is compiled before its private receipt is handed to the owning Worker", async () => {
  const id = fixture.digest.slice(0, 12), revision = "0".repeat(32);
  const calls = [], compiler = "1".repeat(40);
  await reconcileRecipes([{ id, source_revision: revision, ...cleared }], (...args) => calls.push(args), (id) => calls.push(id), compiler);
  assert.deepEqual(calls, [[`recipe-checks/${revision}`, JSON.stringify({ state: "verified", compiler }), "application/json"], id]);
});

test("one operational failure leaves its candidate pending while later checks still finish", async () => {
  const compiler = "1".repeat(40);
  const rows = ["a", "b"].map((letter) => ({ ...cleared, id: letter.repeat(12), source_revision: letter.repeat(32) }));
  const settled = [];
  await assert.rejects(reconcileRecipes(rows, async (key) => {
    if (key.endsWith("a")) throw Error("temporary R2 outage");
  }, (id) => settled.push(id), compiler, () => "verified"), AggregateError);
  assert.deepEqual(settled, ["b".repeat(12)]);
});
