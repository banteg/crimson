import fs from "node:fs";

export const HERE = new URL(".", import.meta.url);
export const schema = JSON.parse(fs.readFileSync(new URL("schema.json", HERE)));
export const names = schema.flatMap((g) =>
  Array.from({ length: g.count }, (_, i) =>
    g.fields.map((f) => `${g.name}${g.count > 1 ? `[${i}]` : ""}.${f}`),
  ).flat(),
);
export const index = new Map(names.map((n, i) => [n, i]));

export function loadCore(wasm) {
  const module = new WebAssembly.Module(fs.readFileSync(wasm));
  if (WebAssembly.Module.imports(module).length)
    throw Error("Core must have zero host imports");
  const e = new WebAssembly.Instance(module, {}).exports;
  e._initialize();
  return e;
}

export function init(e, config) {
  if (config.length !== 256) throw Error("Expected 256-byte config");
  new Uint8Array(e.memory.buffer, e.portable_config(), 256).set(config);
  if (!e.portable_init(...[0, 4, 8, 12].map((i) => config.readUInt32LE(i))))
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

export function record(input, commands = []) {
  const b = Buffer.alloc(24 + commands.length * 8);
  input.slice(0, 4).forEach((v, i) => b.writeFloatLE(v, i * 4));
  b.writeUInt32LE(input[4], 16);
  b.writeUInt32LE(commands.length, 20);
  commands.forEach(([type, arg], i) => {
    b.writeInt32LE(type, 24 + i * 8);
    b.writeInt32LE(arg, 28 + i * 8);
  });
  return b;
}

export function decode(input) {
  if (input.length < 256) throw Error("Truncated config");
  const records = [];
  for (let offset = 256; offset < input.length; ) {
    if (input.length - offset < 24) throw Error("Truncated tick");
    const count = input.readUInt32LE(offset + 20);
    if (count > 16) throw Error("Too many commands");
    const length = 24 + count * 8;
    if (input.length - offset < length) throw Error("Truncated commands");
    records.push(input.subarray(offset, offset + length));
    offset += length;
  }
  return { config: input.subarray(0, 256), records };
}

export function step(e, record) {
  const count = record.readUInt32LE(20);
  new Uint8Array(e.memory.buffer, e.portable_input(), 20).set(
    record.subarray(0, 20),
  );
  if (count <= 16)
    new Uint8Array(e.memory.buffer, e.portable_commands(), count * 8).set(
      record.subarray(24),
    );
  return e.portable_step_many(count);
}

export function config(mode, major = 1, minor = 1, options = {}) {
  const b = Buffer.alloc(256);
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
    ...Array.from({ length: 53 }, (_, i) => (options.usage ? i * 3 : 0)),
  ].forEach((v, i) => b.writeUInt32LE(v, i * 4));
  return b;
}
