import fs from "node:fs";

export const CORE = new URL("..", import.meta.url);
export const schema = JSON.parse(fs.readFileSync(new URL("schema.json", CORE)));
const named = (g, fields) =>
  Array.from({ length: g.count }, (_, i) => fields.map((f) => `${g.name}${g.count > 1 ? `[${i}]` : ""}.${f}`)).flat();
export const names = schema.flatMap((g) => named(g, g.fields));
// The fields only presentation reads (schema.json's `presentation`): a run inside the original may hold its own
// there, which the host's state hash leaves out as well (build.py).
export const presentation = new Set(schema.flatMap((g) => named(g, g.presentation ?? [])));
export const index = new Map(names.map((n, i) => [n, i]));

// The snapshot's byte ranges holding the fields `compared` accepts, adjacent fields merged.
export function fieldRanges(compared) {
  const ranges = [];
  names.forEach((name, i) => {
    if (!compared(name)) return;
    const last = ranges.at(-1);
    if (last?.[1] === i * 4) last[1] += 4;
    else ranges.push([i * 4, i * 4 + 4]);
  });
  return ranges;
}

// The index of the first field in `ranges` where two snapshots differ, or -1.
// Whole ranges compare as memory; only a differing one is walked field by field.
export function firstDifference(expected, actual, ranges) {
  for (const [start, end] of ranges) {
    if (!expected.compare(actual, start, end, start, end)) continue;
    for (let at = start; at < end; at += 4)
      if (expected.readUInt32LE(at) !== actual.readUInt32LE(at)) return at / 4;
  }
  return -1;
}

export function loadCore(wasm) {
  const module = new WebAssembly.Module(fs.readFileSync(wasm));
  if (WebAssembly.Module.imports(module).length)
    throw Error("Core must have zero host imports");
  const e = new WebAssembly.Instance(module, {}).exports;
  e._initialize();
  return e;
}

// A run's head: its config, then a custom quest's table when it plays one.
export function init(e, head) {
  if (head.length !== headBytes(head)) throw Error(`Expected a ${headBytes(head)}-byte head`);
  new Uint8Array(e.memory.buffer, e.portable_config(), CONFIG_BYTES).set(head.subarray(0, CONFIG_BYTES));
  if (head.length > CONFIG_BYTES) new Uint8Array(e.memory.buffer, e.portable_quest(), QUEST_BYTES).set(head.subarray(CONFIG_BYTES));
  if (!e.portable_init(...[0, 4, 8, 12].map((i) => head.readUInt32LE(i))))
    throw Error("Rejected config");
}

export function state(e) {
  const n = e.portable_snapshot();
  if (n !== names.length)
    throw Error(`Snapshot schema: ${n} != ${names.length}`);
  return Buffer.from(e.memory.buffer, e.portable_output(), n * 4);
}

export function field(e, name, floating = false) {
  const offset = index.get(name);
  if (offset === undefined) throw Error(`Unknown field ${name}`);
  const view = new DataView(e.memory.buffer);
  return floating
    ? view.getFloat32(e.portable_output() + offset * 4, true)
    : view.getUint32(e.portable_output() + offset * 4, true);
}

// A tick: each player's input (`input`, or a list of them, player one first), its command count and its commands.
export function record(input, commands = []) {
  const inputs = Array.isArray(input[0]) ? input : [input];
  const at = inputs.length * INPUT_BYTES;
  const b = Buffer.alloc(at + 4 + commands.length * 8);
  inputs.forEach((values, p) => {
    values.slice(0, 4).forEach((v, i) => b.writeFloatLE(v, p * INPUT_BYTES + i * 4));
    b.writeUInt32LE(values[4], p * INPUT_BYTES + 16);
  });
  b.writeUInt32LE(commands.length, at);
  commands.forEach(([type, arg], i) => {
    b.writeInt32LE(type, at + 4 + i * 8);
    b.writeInt32LE(arg, at + 8 + i * 8);
  });
  return b;
}

export function decode(input) {
  if (input.length < CONFIG_BYTES || input.length < headBytes(input)) throw Error("Truncated config");
  const inputs = players(input) * INPUT_BYTES;
  const records = [];
  for (let offset = headBytes(input); offset < input.length; ) {
    if (input.length - offset < inputs + 4) throw Error("Truncated tick");
    const count = input.readUInt32LE(offset + inputs);
    if (count > 16) throw Error("Too many commands");
    const length = inputs + 4 + count * 8;
    if (input.length - offset < length) throw Error("Truncated commands");
    records.push(input.subarray(offset, offset + length));
    offset += length;
  }
  return { config: input.subarray(0, headBytes(input)), records };
}

// A tick for the run `e` holds, with as many inputs as its config has players.
export function step(e, record) {
  const inputs = new DataView(e.memory.buffer).getUint32(e.portable_config() + PLAYERS_OFFSET, true) * INPUT_BYTES;
  const count = record.readUInt32LE(inputs);
  new Uint8Array(e.memory.buffer, e.portable_input(), inputs).set(record.subarray(0, inputs));
  if (count <= 16)
    new Uint8Array(e.memory.buffer, e.portable_commands(), count * 8).set(record.subarray(inputs + 4));
  return e.portable_step_many(count);
}

// Why the core refused its last tick (`portable_refusal` in host/api.h).
export function refusal(e) {
  const bytes = new Uint8Array(e.memory.buffer, e.portable_refusal());
  return Buffer.from(bytes.subarray(0, bytes.indexOf(0))).toString();
}

// `PortableConfig` in host/api.h: 13 uint32 settings, the player count last, then 53 weapon usage counts and two profile words.
export const CONFIG_BYTES = 272;
const PLAYERS_OFFSET = 48;
// `PortableInput`: four axes and the flag word.
export const INPUT_BYTES = 20;
// A stream's player count.
export const players = (head) => head.readUInt32LE(PLAYERS_OFFSET);
// `PortableQuest`: the weapon, three terrain slots, entry count, restriction bitmasks, then 256 24-byte entries.
export const QUEST_BYTES = 6184;

// A stream's config and, for a quest at stage 0.0, the custom quest's table after it.
export function headBytes(input) {
  const custom = input.readUInt32LE(4) === 3 && input.readUInt32LE(8) === 0 && input.readUInt32LE(12) === 0;
  return CONFIG_BYTES + (custom ? QUEST_BYTES : 0);
}

export function config(mode, major = 1, minor = 1, options = {}) {
  const b = Buffer.alloc(CONFIG_BYTES);
  [
    options.seed ?? 42,
    mode,
    major,
    minor,
    options.unlock ?? 50,
    options.unlockFull ?? 50,
    options.detail ?? 5,
    options.violence ?? 0,
    options.friendly ?? 0,
    options.hardcore ?? 0,
    options.retry ?? 0,
    options.preserveBugs ?? 1,
    options.players ?? 1,
    ...Array.from({ length: 53 }, (_, i) => (options.usage ? i * 3 : 0)),
    options.rules ?? 2,
    options.legacyCoopReload ?? 0,
  ].forEach((v, i) => b.writeUInt32LE(v, i * 4));
  return b;
}
