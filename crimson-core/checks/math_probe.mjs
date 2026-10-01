import fs from "node:fs";
import { loadCore } from "./engine.mjs";

const input = fs.readFileSync(process.argv[2]), e = loadCore(process.argv[3]);
if (input.length % 12) throw Error("Truncated math probe");
const output = [];
for (let offset = 0; offset < input.length; offset += 12) {
  const n = e.portable_math_probe(
    ...[0, 4, 8].map((i) => input.readUInt32LE(offset + i)),
  );
  if (n !== 2) throw Error("Invalid math probe");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(n);
  output.push(header, Buffer.from(new Uint8Array(e.memory.buffer, e.portable_output(), n * 4)));
}
process.stdout.write(Buffer.concat(output));
