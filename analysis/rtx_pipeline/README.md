# RTX pipeline optimization measurements

Baseline: `5b5f882b4a8b816ba2dfb3e11f6daf2a05d810c6`. Candidate: the renderer changes in this directory’s accompanying commit. Measured on Apple M1 Pro, macOS OpenGL 4.1/Metal, 2026-10-22. These are measurements of the Python/raylib RTX world renderer; they do not measure the native client.

The change batches consecutive analytic beam bodies/heads without changing their order, shares one selected light tuple across ground and entities, caches ground uniform locations, uploads source arrays in bulk, and skips ground reflection work with zero contribution. Direct visibility is reused only for point sources whose reflection height/width clamps leave the ray unchanged.

## Complete moving world frames

Three trials per variant and workload, with 180 moving frames per trial; discard the first 90. Baseline/candidate process order alternates between trials (AB, BA, AB); no concurrent GPU tests. Each timing starts after a batch flush and `glFinish`, includes the whole `runtime.draw()` and output-target exit, then flushes and waits for GPU completion. Smoke updates/display, terrain bakes, creatures, projectiles, effects, perks, pressure fronts and tone mapping remain enabled. HUD and window swap are excluded. Capture/readback runs are separate from timing runs.

Values below pool all 270 measured frames per variant. Lower is better.

| Workload | Output | Render median before → after | Reduction | Render p95 before → after | Update + render median before → after |
|---|---|---:|---:|---:|---:|
| replay19 | 1024×768 | 14.79 → 10.83 ms | 26.8% | 20.39 → 16.78 ms | 15.98 → 12.01 ms |
| replay19 | 2048×1536 | 21.19 → 19.76 ms | 6.8% | 26.24 → 24.33 ms | 22.47 → 21.09 ms |
| dense | 2048×1536 | 14.43 → 13.06 ms | 9.5% | 23.86 → 23.08 ms | 16.39 → 14.83 ms |
| minigun | 2048×1536 | 14.03 → 13.09 ms | 6.7% | 24.97 → 18.61 ms | 14.94 → 13.90 ms |

Run-to-run variation is material: these are observed improvements, not confidence bounds or a delivered-FPS promise. In particular, one 2048 replay trial regressed. Each run’s median render time is shown below so pooling cannot hide that result.

| Workload | Trial 1 before → after | Trial 2 before → after | Trial 3 before → after |
|---|---:|---:|---:|
| replay19-1024 | 15.24 → 12.50 ms | 16.28 → 11.42 ms | 12.57 → 10.12 ms |
| replay19-2048 | 23.26 → 19.78 ms | 19.92 → 20.86 ms | 21.15 → 17.82 ms |
| dense-2048 | 16.56 → 16.51 ms | 14.42 → 12.50 ms | 12.13 → 11.42 ms |
| minigun-2048 | 17.13 → 14.20 ms | 12.46 → 12.24 ms | 14.19 → 12.39 ms |

`replay19` plays ticks 182–185 s of the installed `19-survival.crd`, warming smoke from 167 s. The measured interval is 183.5–185 s. `dense` and `minigun` are scripted gameplay fixtures, not recordings: two players and native weapon inputs, with 99 stationary creatures plus Radioactive/Monster Vision for `dense`, and three creatures for `minigun`. Both include Fire Bullets/ion input transitions. Logical view size stays 1024×768. The fixture hashes, seed and individual run summaries are in [results.json](results.json).

## Visual parity

Twenty matched moving frames (indices 0, 30, 90, 120, 179 in each workload) have **zero differing channels** both in the RGBA16F world target read back as float32 and in the final SDR RGB image. This includes bright overlapping Fire Bullets, smoke, wet ground, bonus shells, dense Monster Vision and radioactive lighting. It establishes parity for the sampled scenes on this GPU, not every possible state or driver.

Regression tests additionally compare mixed beam/atlas/ion-arc draws against the standalone beam path in RGBA32F, with both bug-preservation modes and a following non-beam draw; compare 32/1/0/17-source bulk uploads against scalar uploads; and require reflection pixels to remain unchanged when enabling diffuse lighting at heights below/at/above 12, widths below/at the 0.1 clamp, point/beam/ring geometry, and both shadow settings.

Gemini Argon High reviewed the implementation and reported no blockers; the pixel comparisons and tests are the validation evidence.

## Reproduce

Install the locked dependencies and game assets for each checkout. Run from the checkout being measured; use an absolute path to this PR’s benchmark script so the baseline uses the identical fixture. `scene.py` prepends the current checkout’s `src` and tests to the import path. A display and OpenGL context are required. For `replay19`, install the replay with the SHA-256 recorded in `results.json` under the runtime directory’s `replays/19-survival.crd`.

```sh
uv sync --frozen
uv run --no-sync python /path/to/candidate/analysis/rtx_pipeline/bench.py \
  --scene replay19 --width 2048 --frames 180 --output /tmp/rtx-baseline-1
```

Repeat for both checkouts in AB/BA/AB order, with `replay19` at widths 1024 and 2048 and `dense`/`minigun` at 2048. For separate parity runs, add `--capture`: compare the `pixels` arrays in corresponding `*-hdr.npz` files and decoded pixels of the PNG files. Timing JSON contains every frame, measured summaries and fixture state; keep capture runs out of timing aggregates.

```sh
uv run --no-sync pytest --run-terrain tests/render/test_beam_batch.py \
  tests/render/test_ground_materials.py tests/render/test_player_lighting.py \
  tests/render/test_projectile_render.py tests/render/test_bonus_lighting.py
```
