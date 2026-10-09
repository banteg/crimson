import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type Head, Reader } from "../../src/msgpack";
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

// After egornomic's #615: the ticks decode as they stream, so their framing is refused as strictly as a whole tree's.
describe("the replay's tick array keeps canonical framing", () => {
  const payload = base64(vectors.valid_payload);
  const reader = new Reader(payload);
  const entries: { start: number; valueStart: number; end: number }[] = [];
  const fields = (reader.token() as Head).length;
  for (let field = 0; field < fields; field++) {
    const start = reader.offset;
    reader.key();
    const valueStart = reader.offset;
    reader.value();
    entries.push({ start, valueStart, end: reader.offset });
  }
  const ticks = entries.at(-1)!;
  const tickCount = new Reader(payload.subarray(ticks.valueStart)).token() as Head;
  const tickDataStart = ticks.valueStart + (tickCount.length < 16 ? 1 : tickCount.length < 0x10000 ? 3 : 5);
  const withTickHeader = (header: number[]) =>
    Buffer.concat([payload.subarray(0, ticks.valueStart), Buffer.from(header), payload.subarray(tickDataStart)]);
  const rootWith = (selected: typeof entries) =>
    Buffer.concat([Buffer.from([0x80 | selected.length]), ...selected.map(({ start, end }) => payload.subarray(start, end))]);
  const invalid: [string, Uint8Array][] = [
    ["duplicate ticks field", rootWith([...entries, ticks])],
    ["missing ticks field", rootWith(entries.slice(0, -1))],
    ["ticks before result", rootWith([...entries.slice(0, -2), ticks, entries.at(-2)!])],
    ["extra field after ticks", rootWith([...entries, entries[0]!])],
    ["ticks is null", withTickHeader([0xc0])],
    ["ticks is a map", withTickHeader([0x80])],
    ["non-minimal array16", withTickHeader([0xdc, tickCount.length >> 8, tickCount.length & 255])],
    ["non-minimal array32", withTickHeader([0xdd, 0, 0, tickCount.length >> 8, tickCount.length & 255])],
    ["truncated array32 header", Buffer.concat([payload.subarray(0, ticks.valueStart), Buffer.from([0xdd, 255])])],
    ["huge tick count without a tick", Buffer.concat([payload.subarray(0, ticks.valueStart), Buffer.from([0xdd, 255, 255, 255, 255])])],
    ["trailing bytes after ticks", Buffer.concat([payload, Buffer.from([0, 0])])],
  ];
  for (const [name, bytes] of invalid) {
    it(`refuses ${name}`, () => {
      expect(() => decodeReplay(bytes)).toThrow(ReplayError);
    });
  }
  it("refuses every truncated prefix of a real payload", () => {
    for (let end = 0; end < payload.length; end++) expect(() => decodeReplay(payload.subarray(0, end))).toThrow(ReplayError);
  });
});
