# HUD stack-use evidence and VC6 lifetime controls

The current HUD has 1,824/1,824 paired instructions and 393 clean references.
Its 142 paired differences are stack displacements; normalized and encoded-body
exactness remain false. This package turns the checked compiler listing into
263 observed native stack accesses with candidate source names attached.

`native-stack.json` records Binary Ninja's concrete entry-relative ESP at each
simple stack operand. The verifier pins the native body hash, recompiles an
object-equivalent listing, rejects ambiguous/incomplete pairings, and computes
`entry ESP + instruction displacement`. It does not treat a compiler declaration
as an entry-relative address: the parameter declaration is 8 while its observed
native address is entry ESP + 4. All 263 saved observations were independently
re-exported from the live native database and compared exactly.

Selected observations (negative offsets are below entry ESP):

| Candidate source value | Observed native slots | Consequence |
| --- | --- | --- |
| `position` | -8, -4 | Heart, ammo, and quest use the same physical pair. |
| `bar_position.y` | -4 | Health bars also touch that pair; this does not prove one source object. |
| `progress_position` | -20, -16 | XP uses a different pair after the earlier position scope ends. |
| `health_ratio`, `pulse_speed`, `hud_y`, `slide_x`, `bar_x`, `text_y` | -44 | Branches and overwrites permit slot reuse; address-order use spans are not live ranges. |
| Both block-local `clock_alpha` values | -48 | Native sharing alone does not imply a shared C++ declaration. |
| `panel_alpha` | -40 | Its first access is at `0x0041af5f`, well before the late draws that reuse it. |

The full map preserves every access and its candidate source lines. Names label
the candidate compilation, not recovered original native variable names.

## Small compiler controls

`lifetimes.cpp` sends three coordinate values through an external observer using
three source lifetime patterns. Under the canonical VC6.5 flags:

| Pattern | Stack allocation | Instructions | Explanation |
| --- | ---: | ---: | --- |
| Outer position plus separate bar, then position assignment | 24 | 25 | Separate position, bar, and assignment temporary. |
| Three separate lexical scopes | 8 | 21 | Three names share one physical pair. |
| One position repeatedly assigned constructed values | 16 | 29 | Assignment temporaries remain despite one named position. |

These are compiler examples, not a proof of original HUD source or general
equivalence with arbitrary observers that retain pointers. In particular,
sharing a variable can add instructions; fewer source names need not mean fewer
native temporaries. This is why native stack reuse cannot be translated directly
into a source-variable merge.

The canonical HUD's seven-control `observed-stack-controls-2026-09-09.json` plan
is complete. SDK anonymous-union and constructor-body spellings, default-then-
assignment for the bar, and const panel alpha are neutral. Moving XP's position
initialization before its color loses alignment. Sharing the health-bar position
with the outer position loses alignment and adds three instructions. None is
retained; this bounds these controls only.

## Reproduce

From the repository root:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/hud-lifetimes-2026-09-09/verify.py \
  --out /private/tmp/crimson-hud-evidence
```

With the correct Crimsonland Binary Ninja view selected and full function
analysis available, `bn --target <selector> py --format json --script
tools/match/evidence/hud-lifetimes-2026-09-09/export_native.py` returns the saved
ESP facts in its `result`. The exporter is read-only and refuses non-concrete
stack states. The verifier and micro controls require no Binary Ninja instance.
