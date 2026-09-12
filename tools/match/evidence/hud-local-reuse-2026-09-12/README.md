# HUD local-reuse controls

A temporary candidate improves normalized similarity from **92.214912% to
96.271930%**, retaining **1,824 instructions and 393/0/0 references**. It is
not normalized or encoded exact. The canonical HUD source remains unchanged.

The saved 16-way matrix crosses three float-local reuse groups with one integer
row group. Each float group has nonoverlapping lexical use spans:

- Banner fade, completion fade, then the bonus-slot Y cursor.
- Quest-clock opacity, completion scale, then timer-clock opacity.
- Multiplayer rounded pulse value, then health-bar fill opacity.
- HUD Y and the subsequent popup text row share one integer local.

The two block-local pulse values and clock opacities are named separately in
the controls so their uses can be transformed unambiguously. All assignments
remain at their original source positions. The groups affect VC6 interference
and stack coloring; observed native stack slots do not prove these original
source-variable identities. No execution-equivalence proof or compiler ceiling
is claimed, and this candidate is not counted as the requested exact match.

The complete matrix preserves reconstructible line edits, source hashes, and
fresh matcher metrics. It records the strongest local-reuse candidate found
during a larger temporary investigation; it is not a claim to enumerate every
possible source lifetime or every temporary experiment.

```sh
uv run --no-sync python tools/match/evidence/hud-local-reuse-2026-09-12/verify.py \
  --out /private/tmp/hud-local-reuse-proof
```

If the canonical source changes, recover it from the recorded `baseline_commit`
and provide its path with `--baseline`.
