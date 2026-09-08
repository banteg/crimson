# Conventional trail endpoint ownership, 2026-09-08

The native conventional-bullet pass constructs vertices 0/1 from the projectile
origin and vertices 2/3 from its current position. The pre-change scratch
reversed those owners in all four type arms. This is a semantic reconstruction
error, not an aliasing exemption or an instruction-alignment interpretation.

The checked executable is `game_bins/crimsonland/1.9.93-gog/crimsonland.exe`,
SHA-256 `771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4`.
At `0x00423011`, its raw bytes decode as `mov esi, 0x004926d4`:
`projectile_pool + 0x1c`, the `vel_y` field. The verified record layout places
current position at offsets `0x08/0x0c`, origin at `0x10/0x14`, and velocity at
`0x18/0x1c`. Consequently `[esi-0x0c]/[esi-0x08]` are origin coordinates,
whereas `[esi-0x14]/[esi-0x10]` are current-position coordinates.

| Type arm | Origin x/y additions for vertices 0/1 | Position x/y additions for vertices 2/3 |
| --- | --- | --- |
| Assault Rifle | `0x004230eb`, `0x004230f6` | `0x0042315e`, `0x00423170` |
| Pistol | `0x0042321c`, `0x00423227` | `0x004232af`, `0x004232bc` |
| Gauss Gun | `0x004233be`, `0x004233c9` | `0x0042345d`, `0x0042346a` |
| Remaining conventional types | `0x0042350a`, `0x00423515` | `0x004235a9`, `0x004235b6` |

The common draw at `0x0042363a..0x0042365d` passes the resulting eight scalar
coordinates in the expected right-to-left argument order. The earlier color
setup gives vertices 0/1 zero alpha and vertices 2/3 the per-projectile alpha,
so swapping endpoints also reverses the trail's fading direction.

The source/assembly listing was checked against the canonical object before
using its source associations: 11,799 function bytes, 2,885 machine rows,
527 relocations, and `object_function_equivalent=true`. It shows the scratch
loading position for the first points and origin for the last points. The
correction only exchanges those two field owners; the final candidate calls
the locals `trail_origin` and `trail_head` to describe their actual roles.

## Bounded results

All 38 mutation controls and the final naming verification probe completed
without compiler or evaluation errors. No source-acceptance exception is
needed for the endpoint correction.

| Candidate | Weighted matched bytes / 12,551 | Ratio | Instructions | References ok/unresolved/mismatch |
| --- | ---: | ---: | ---: | ---: |
| Starting source | 7,348.689129698611 | 58.55062648154419% | 2,885/3,021 | 448/0/10 |
| All four native endpoint owners | 7,429.4439552996955 | 59.19403995936336% | 2,885/3,021 | 456/0/10 |
| Endpoint owners plus Assault width reference | 7,381.689830508475 | 58.8135593220339% | 2,879/3,021 | 448/0/10 |

The accepted semantic correction adds **80.75482560108412 weighted bytes** and
eight proven aligned references, preserving the instruction count, prefix 0,
and zero unresolved references. It remains non-exact, with
`body_byte_exact=false`. The frame debt remains a separate problem; endpoint
ownership does not justify a claim about the missing source temporaries.

- `conventional-endpoint-ownership-2026-09-08.json` evaluates all 15 nonempty
  subsets of the four arm corrections. The all-four correction is best.
- `assault-width-reference-boundary-2026-09-08.json` evaluates const and mutable
  reference aliases because native uses the memory-backed width directly,
  whereas the candidate first copies it. Both lose 43.581672071491994 weighted
  bytes, six instructions, and four proven references on the starting source.
- `conventional-endpoint-width-interaction-2026-09-08.json` completes the five
  controls covering both width aliases before and after endpoint correction,
  plus the corrected-endpoint/value-width control. The references still regress
  on corrected endpoints, so neither alias is retained.
- `conventional-output-result-boundaries-2026-09-08.json` evaluates the native
  endpoint control and all 15 nonempty subsets of named `pointN_result`
  lifetimes across the four arms. Native stores each operator result before
  copying it into shared draw arguments. Every tested named-result combination
  has the same match, instruction, and reference metrics as the corrected
  endpoint control; no redundant locals are retained.

The last two plans include their corrected-endpoint control inside the menu so
that every interaction can be compared against both the original source and
the semantic correction. Their reported gain against the original baseline is
not an additional gain from width aliases or point-result names.

## Reproduction and artifacts

The specs describe the starting source at commit `5d47470f0` and no longer
apply to the integrated scratch. From the repository root, extract that source
and its configuration to an isolated temporary directory, then use the current
matcher and plans against that baseline. The checked baseline source SHA-256
is `57d0adb7c5305072e2405207031de48041ef8a29a42786b6320a1c5f9acfa063`.
These commands preserve the integrated source and omit `--record`.

```sh
replay_dir=$(mktemp -d /private/tmp/projectile-endpoint-replay.XXXXXX)
git show 5d47470f0:tools/match/scratches/projectile_render/scratch.cpp > "$replay_dir/scratch.cpp"
git show 5d47470f0:tools/match/scratches/projectile_render/scratch.conf > "$replay_dir/scratch.conf"
.venv/bin/crimson match mutate "$replay_dir" --match-root tools/match --spec tools/match/scratches/projectile_render/conventional-endpoint-ownership-2026-09-08.json --max-changes 4 --max-variants 15 --jobs 4 --json
.venv/bin/crimson match mutate "$replay_dir" --match-root tools/match --spec tools/match/scratches/projectile_render/assault-width-reference-boundary-2026-09-08.json --max-changes 1 --max-variants 2 --jobs 2 --json
.venv/bin/crimson match mutate "$replay_dir" --match-root tools/match --spec tools/match/scratches/projectile_render/conventional-endpoint-width-interaction-2026-09-08.json --max-changes 1 --max-variants 5 --jobs 4 --json
.venv/bin/crimson match mutate "$replay_dir" --match-root tools/match --spec tools/match/scratches/projectile_render/conventional-output-result-boundaries-2026-09-08.json --max-changes 1 --max-variants 16 --jobs 4 --top 16 --json
```

The isolated-directory procedure was checked with the two width-reference
controls after integration and reproduced their baseline and result metrics.
The final integrated source, including the semantic local names, has SHA-256
`5043ceab80ce808557be531c16785e585fcd0681974a6d73fdae8f0088bcbc3e`.

Worker artifacts are under `/private/tmp/projectile-render-2026-09-08/`:
`inspect.json`, `baseline.cod`, `listing.json`, `dump.txt`,
`native-conventional-raw.txt`, the four `*-results.json` files,
`endpoints-named.cpp`, and `endpoints-named-probe.json`.
`baseline.json` is the compiler listing's automatically written metadata;
the baseline match metrics are retained in `inspect.json` and every sweep.

The four plan SHA-256 values, in the order listed above, are:

```text
131afa09064f0d4ae0f293bf95e4cbf2c182455fd87811b680d8cdae0d102160
bff6399f864ef0847de6ed00cba292056446e4fcb30b29fa6e17f4f5c5bdc763
db225f9850147088572134f38b7b3b17d43c6220f58ade184f5fd8eca67a4ec7
850bf922cc618b146b03e0841703fa9213b4b8bd9ec388f38b54c168186fd19d
```
