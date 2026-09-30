// Diagnostic simulator endpoint. No leaderboard writes or claimed scores.
import module from "./build/wasm/core.wasm";
import schema from "./schema.json";

const core = new WebAssembly.Instance(module, {}).exports;
core._initialize();
const offsets = new Map();
let length = 0;
for (const g of schema)
  for (let i = 0; i < g.count; i++)
    for (const f of g.fields) {
      offsets.set(`${g.name}${g.count > 1 ? `[${i}]` : ""}.${f}`, length++);
    }

async function boundedBody(request) {
  if (!request.body) throw Error("Missing body");
  const reader = request.body.getReader(),
    pieces = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 4 * 1024 * 1024) {
      await reader.cancel();
      throw Error("Body exceeds 4 MiB");
    }
    pieces.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const piece of pieces) {
    bytes.set(piece, offset);
    offset += piece.length;
  }
  return bytes;
}

export default {
  async fetch(request) {
    if (request.method !== "POST")
      return new Response("POST an .rsi test transport", { status: 405 });
    try {
      const input = await boundedBody(request),
        view = new DataView(input.buffer);
      if (input.length < 256) throw Error("Truncated config");
      // No awaits from init through the copied snapshot: requests cannot
      // interleave simulation state in this single shared instance.
      new Uint8Array(core.memory.buffer, core.portable_config(), 256).set(
        input.subarray(0, 256),
      );
      if (
        !core.portable_init(
          ...[0, 4, 8, 12].map((i) => view.getUint32(i, true)),
        )
      )
        throw Error("Invalid config");
      let ticks = 0;
      for (let offset = 256; offset < input.length; ) {
        if (ticks >= 60000 || input.length - offset < 24)
          throw Error("Tick limit or truncated tick");
        const count = view.getUint32(offset + 20, true),
          size = 24 + count * 8;
        if (count > 16 || input.length - offset < size)
          throw Error("Invalid commands");
        new Uint8Array(core.memory.buffer, core.portable_input(), 20).set(
          input.subarray(offset, offset + 20),
        );
        new Uint8Array(
          core.memory.buffer,
          core.portable_commands(),
          count * 8,
        ).set(input.subarray(offset + 24, offset + size));
        if (!core.portable_step_many(count))
          throw Error(`Rejected tick ${ticks}`);
        ticks++;
        offset += size;
      }
      if (core.portable_snapshot() !== length)
        throw Error("Snapshot schema mismatch");
      const snapshot = new Uint8Array(
        core.memory.buffer,
        core.portable_output(),
        length * 4,
      ).slice();
      const values = new DataView(snapshot.buffer);
      const u = (name) => values.getUint32(offsets.get(name) * 4, true);
      const pending = u("globals.game_state_pending");
      const result = {
        rules: "recovered-spike-v1",
        ticks,
        pending,
        terminal: [7, 8, 12].includes(pending),
        experience: u("players[0].experience"),
        elapsed_ms: u("globals.survival_elapsed_ms"),
        quest_timeline_ms: u("globals.quest_spawn_timeline"),
        rng: u("globals.rng"),
        wasm_memory_bytes: core.memory.buffer.byteLength,
      };
      const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", snapshot),
      );
      result.final_sha256 = Array.from(digest, (b) =>
        b.toString(16).padStart(2, "0"),
      ).join("");
      return Response.json(result);
    } catch (error) {
      return Response.json({ error: String(error.message) }, { status: 400 });
    }
  },
};
