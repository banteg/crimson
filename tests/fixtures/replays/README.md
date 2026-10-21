# Replay fixture provenance

The recordings without `rules2` in their names are historical rules-1 fixtures.
They remain useful for decoding and transport compatibility. Current gameplay
gates report them as unsupported instead of changing their rules, results, or
checkpoints.

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

The full matrix includes both bug policies and co-op Fire Cough/Hot Tempered
runs. Focused tests cover exact-zero and eligibility boundaries that ordinary
recordings do not guarantee. Future changes within this unreleased rules batch
must regenerate affected fixtures through simulation. Never copy old results
or checkpoints onto a new rules number.
