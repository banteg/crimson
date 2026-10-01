import fs from "node:fs";
import { loadCore } from "./engine.mjs";

const input = fs.readFileSync(process.argv[2]),
  e = loadCore(process.argv[3]);
if (input.length % 16) throw Error("Truncated probe");
const output = [];
for (let offset = 0; offset < input.length; offset += 16) {
  const n = e.portable_builder_probe(
    ...[0, 4, 8, 12].map((i) => input.readUInt32LE(offset + i)),
  );
  if (!n) throw Error("Invalid builder probe");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(n);
  output.push(
    header,
    Buffer.from(new Uint8Array(e.memory.buffer, e.portable_output(), n * 4)),
  );
}
process.stdout.write(Buffer.concat(output));
