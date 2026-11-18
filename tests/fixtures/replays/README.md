# Replay fixture provenance

The recordings without `rules2` in their names are historical rules-1 fixtures.
They play under the historical profile without changes to rules, results or
checkpoints. `rules1-ranked-survival.crd` and `rules1-ranked-coop.crd` preserve
the exact service vectors from c0565b0 and test legacy run-ID stability.

Current-rule fixtures are generated inputs, not human gameplay. Reproduce them
with `service/scripts/vectors.py`, `crimson-core/checks/matrix.mjs`, then
`crimson-core/checks/record_rules_fixtures.py`. The recorder runs every tick
through Python and writes fresh results and per-tick RNG/state checkpoints.
After replacing fixtures, regenerate service vectors to refresh their copies.

| File | Generated input source | Ticks | Outcome | XP | Kills |
| --- | --- | --- | --- | --- | --- |
| `rules2-survival.crd` | service `ranked_run` | 1968 | death | 749 | 10 |
| `rules2-survival-coop.crd` | service `coop_run.file` | 2050 | death | 1067 + 0 | 19 |
| `coop-perk-timers-rules2.crd` | matrix `coop-survival-independent-timers-ranked` | 7423 | death | 13190 + 0 | 245 |
| `quest-1.1-rules2.crd` | matrix `quest-1.1-ranked` | 1616 | completed | 1250 | 10 |
| `rush-rules2.crd` | matrix `rush-bot-ranked` | 932 | death | 5092 | 33 |
| `survival-rules2.crd` | matrix `survival-bot-ranked` | 30000 | incomplete | 82664 | 1332 |

These cover the complete rules-2 bundle at base
`c0565b0b4e74c9aed422f23ddd9328027967cbc0` plus the fixes documented in
`docs/rewrite/original-bugs.md` (#5, #42–49). The long Survival fixture stops at
the generator's eight-minute limit; it is intentionally an unfinished run for
watch/seek/practice and multiple-perk coverage. The co-op fixture removes only
synthetic signing keys from upload metadata.

`coop-quest-variants-v33-rules2.crd` re-encodes the 304 ticks and result of
the service's `coop_run.unkeyed_quest_file` in the early format-33 quest
layout. Table 0 spawns three aliens and table 1 spawns one. The eight variant
indices are `[0, 0, 1, 1, 1, 1, 1, 1]`, so the two-player run clears table 1.

The following rules-2 fixtures replay input streams from the sibling crimson-tas bot,
which reaches states the matrix bot does not. Each keeps the bot's pilot and
recorder. Python stepped each tick to write the result and checkpoints.

| File | Source in crimson-tas | Ticks | Outcome | What it covers |
| --- | --- | --- | --- | --- |
| `quest-5.7-hardcore-rules2.crd` | `results/quest-finish-25m/replays/hardcore-5.7.crd` | 4213 | completed, 57710 ms | late hardcore clear with fractional health and four unspent perks |
| `quest-5.10-hardcore-energizer-rules2.crd` | first 2200 ticks of `results/strategy/refined/replays/tas-quest-hardcore.crd` | 2200 | incomplete | Energizer from pickup to expiry |

Three complete hardcore clears exercise the last quest of tiers 3, 4 and 5. Each file is byte-identical to the
format-34 recording from crimson-tas commit `6b2d0e076e7b2c8c2ec99b6724231e7daae1a983`. Python reproduced
the original claimed result and generated the accompanying per-tick checkpoints.

| File | Source in crimson-tas | Ticks | Final time |
| --- | --- | ---: | ---: |
| `quest-3.10-hardcore-clear-rules2.crd` | `results/maneuvers/replays/3-10-hardcore-tas.crd` | 2,485 | 32,912 ms |
| `quest-4.10-hardcore-clear-rules2.crd` | `results/maneuvers/replays/4-10-hardcore-tas.crd` | 5,022 | 74,622 ms |
| `quest-5.10-hardcore-clear-rules2.crd` | `results/objectives/replays/quest-clear.crd` | 7,764 | 105,776 ms |

## Fixture contracts

[manifest.json](manifest.json) registers each recording. `every_tick` requires a sidecar with one checkpoint for
each input tick. `result_only` covers the two historical service vectors and the format-33 custom quest, which
carry their expected results. `python_only` marks the Typ-o recording. Its sidecar covers every tick, and
`crimson replay verify-checkpoints tests/fixtures/replays/typo-144.crd` checks them in the Python port.

The full matrix includes both bug policies and co-op Fire Cough/Hot Tempered
runs. Focused tests cover exact-zero and eligibility boundaries that ordinary
recordings do not guarantee. Future changes within this unreleased rules batch
must regenerate affected fixtures through simulation. Never copy old results
or checkpoints onto a new rules number.
