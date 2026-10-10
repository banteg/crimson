---
tags:
  - verification
  - performance
---

# Optimization survey

The [catalog](https://github.com/banteg/crimson/blob/master/crimson-core/optimizations/README.md)
records which earlier Python optimizations transfer to the verifier/game.
Plaguebearer culling and orbit caching transfer as separate behavior-preserving
patches. Direct collision culling regressed 4–7%; a native spatial index needs
its own measurement and ordering/mutation audit. Python overhead optimizations
stay in their domain modules.

## Measurements

Apple M1 Pro, macOS 26.6.2, Node 26.10.0, Zig 0.17.0, hyperfine 2.0.0;
baseline `9759a26c545972b4ba1b667e974b273c45536394` already includes the spawn-batch fix.
Three fresh processes per build, baseline first; startup, JIT, decoding,
simulation and terminal hashing are included. These are not browser timings.

| Recording / build | Wall time (mean ± SD) | Peak RSS (mean; range) | Instructions |
| --- | ---: | ---: | ---: |
| 65,776 ticks: baseline | 1.972 ± 0.037 s | 121.9 MiB; 121.5–122.4 | 31.9 B |
| 65,776 ticks: optimized | 1.695 ± 0.008 s | 121.3 MiB; 120.7–121.6 | 28.2 B |
| 210,268 ticks: baseline | 26.493 ± 0.137 s | 153.4 MiB; 148.9–159.1 | 328.6 B |
| 210,268 ticks: optimized | 24.888 ± 0.303 s | 171.5 MiB; 163.9–176.6 | 298.8 B |

Time improves 14.0% and 6.1%. RSS includes Node/V8 and replay buffers: a reversed-order
repeat with GC traces reversed the long-run RSS means (167.2 → 157.7 MiB), so no
reliable memory gain/regression is established. Both cores ended with 2.5 MiB
of linear memory; the derived orbit cache adds 9 KiB inside that reservation.

## Reproduction

Build the baseline commit in a separate checkout as `before.wasm`, and this branch
as `after.wasm`. Convert the same recording with `crimson-core/checks/replay.py`:
the earlier recording is `survival_20261007_091930_score1926843.crd` (13:28.140),
and the [reported recording](https://crimson.land/play/?watch=209b0cdb6d9345e8c2dc4eaeac654e929338eecf07aaad28aaf9137dd9bc38d6)
is 35:54.555. Keep builds and other benchmarks outside the timed experiment.

```sh
uv run python crimson-core/build.py --target wasm
uv run python crimson-core/checks/creature_optimizations.py
node crimson-core/checks/profile_replay.mjs run.rsi before.wasm after.wasm comparison.json --compare
node crimson-core/checks/profile_replay.mjs run.rsi before.wasm after.wasm warm-timing.json
```

For fresh-process timing/RSS, use a temporary runner after the every-tick comparison:

```sh
cat > /tmp/crimson-bench.mjs <<'JS'
import fs from "node:fs";
import { createHash } from "node:crypto";
const { decode, init, loadCore, state, step } = await import(`${process.cwd()}/crimson-core/checks/engine.mjs`);
const { config, records } = decode(fs.readFileSync(process.argv[3]));
const core = loadCore(process.argv[2]);
init(core, config);
for (const tick of records) if (!step(core, tick)) throw Error("Rejected tick");
console.log(createHash("sha256").update(state(core)).digest("hex"));
JS
hyperfine --runs 3 \
  --metrics time_wall_clock:ms,memory_peak_resident:MiB,time_cpu:s,instructions:B,cpu_cycles:B \
  "node /tmp/crimson-bench.mjs before.wasm run.rsi" \
  "node /tmp/crimson-bench.mjs after.wasm run.rsi"
```

Hardware-counter availability depends on platform and permissions. Differential
checks cover Plaguebearer state/return boundaries and all orbit seeds; CI also
runs the existing Python/native/WASM and game/verifier agreement gates.
