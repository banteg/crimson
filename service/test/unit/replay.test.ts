import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { outcomeReasons, rankedBoard, unrankedReasons } from "../../src/ranked";
import { decodeReplay, inflateReplay, ReplayError } from "../../src/replay";
import { encodeTransport, TransportError } from "../../src/transport";
import vectors from "../vectors.json";

const FIXTURES = join(import.meta.dirname, "../../../tests/fixtures/replays");
const sha256 = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");
const base64 = (text: string) => new Uint8Array(Buffer.from(text, "base64"));

describe("the recorded fixtures decode as the Python codec decodes them", () => {
  for (const fixture of vectors.fixtures) {
    it(fixture.file, () => {
      const payload = inflateReplay(new Uint8Array(readFileSync(join(FIXTURES, fixture.file))));
      const replay = decodeReplay(payload);

      expect(sha256(payload)).toBe(fixture.payload_sha256);
      expect([replay.run.game_mode_id, replay.run.seed, replay.ticks.length]).toEqual([fixture.game_mode_id, fixture.seed, fixture.ticks]);
      expect(rankedBoard(replay.run)).toBe(fixture.board);
      expect(unrankedReasons(replay.run)).toEqual(fixture.unranked_reasons);
      expect(outcomeReasons(replay.run, replay.result)).toEqual(fixture.outcome_reasons);
      if (fixture.transport_sha256 === null) expect(() => encodeTransport(replay)).toThrow(TransportError);
      else expect(sha256(encodeTransport(replay))).toBe(fixture.transport_sha256);
    });
  }
});

describe("payloads the Python codec refuses are refused", () => {
  it("the uncorrupted payload decodes", () => {
    expect(unrankedReasons(decodeReplay(base64(vectors.valid_payload)).run)).toEqual([]);
  });
  for (const vector of vectors.corrupted) {
    it(vector.name, () => {
      expect(() => decodeReplay(base64(vector.payload))).toThrow(ReplayError);
    });
  }
});
