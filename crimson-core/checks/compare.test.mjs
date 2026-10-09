import assert from "node:assert/strict";
import test from "node:test";
import { nativeSnapshots } from "./compare.mjs";

const frame = (values) => {
  const result = Buffer.alloc(4 + values.length * 4);
  result.writeUInt32LE(values.length);
  values.forEach((value, i) => result.writeUInt32LE(value, 4 + i * 4));
  return result;
};
const first = frame([1, 2, 3]), second = frame([4, 5, 6]);
const stream = Buffer.concat([first, second]);
const collect = async (chunks) => {
  const snapshots = [];
  for await (const snapshot of nativeSnapshots(chunks, 3))
    snapshots.push(Buffer.from(snapshot));
  return snapshots;
};

test("coalesced and fragmented frames preserve every byte", async () => {
  const expected = [first.subarray(4), second.subarray(4)];
  assert.deepEqual(await collect([stream]), expected);
  for (let split = 1; split < stream.length; split++)
    assert.deepEqual(await collect([stream.subarray(0, split), stream.subarray(split)]), expected);
  assert.deepEqual(await collect(Array.from(stream, (byte) => Buffer.from([byte]))), expected);
});

test("every incomplete header or payload fails", async () => {
  for (let length = 1; length < first.length; length++)
    await assert.rejects(collect([first.subarray(0, length)]), /Truncated native snapshot/);
  await assert.rejects(collect([first, second.subarray(0, 9)]), /Truncated native snapshot/);
});

test("invalid counts fail before comparison", async () => {
  for (const fields of [0, 2, 4, 0xffffffff]) {
    const invalid = Buffer.alloc(4);
    invalid.writeUInt32LE(fields);
    await assert.rejects(collect([invalid.subarray(0, 2), invalid.subarray(2)]), /Invalid native snapshot length/);
  }
});
