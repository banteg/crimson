# Exact HUD recovery

`ui_render_hud` matches **1,824/1,824 instructions and all 7,081 encoded body
bytes**, with **393 clean positional references**, zero reference problems,
and no padding difference. The predecessor had the same instruction count
and references but only 92.214912% alignment and a 42-instruction exact prefix.

The heart and ammunition positions now have separate lifetimes. The quest
progress position has a short block ending before the banner text. The bonus
cursor remains an independent float. These boundaries let VC6 reuse the
native position and integer-conversion storage without keeping the quest
position live through the title rendering.

Four scalar ownership changes complete that layout:

| Local | Disjoint uses |
| --- | --- |
| `hud_y` | Main HUD row, then the popup text row after bonus rendering. |
| `fade` | Quest banner fade, then completion fade. |
| `draw_factor` | Quest clock opacity, completion scale, then timer clock opacity. |
| `render_value` | Multiplayer heart pulse input, then health-fill opacity. |

Every value is assigned before use. Rendering operations, arithmetic, constants,
branches, global writes and call order are preserved. The ordinary VC6.5
`/O2 /GB /W3 /GR-` configuration, reference aliases and native extent are
unchanged. There are no compiler-state modifications, forced stack layouts,
register hints, injected bytes or matcher-rule changes.

`before.cpp` pins the preceding source from
`8f3e3d672b3ff21a52652dc7d25aebc8d450399f`, SHA-256
`6838b5e0e2c4989e5af8ba404fcb888b996ed84c611807f90d6814d54bf248a5`.
The current source SHA-256 is
`32bbe80fa55747d431ab5be9b004b157af9f94a5b7b8feea5c6cf80763eab5ca`.

## Reproduce

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/hud-exact-2026-09-12/verify.py \
  --out /private/tmp/hud-exact-proof
```

The verifier forces fresh compilation of the current source, predecessor and
18 reconstructible source controls. Sixteen controls cover every combination
of the four scalar changes with the position boundaries fixed; only all four
together are exact. Two additional controls restore the long quest-position
lifetime or a common heart/ammunition position; both lose exactness.
Changing the panel width must fail encoded identity, and withholding the
existing reference aliases must fail the reference audit.

`results.json` records the matcher evidence, compiler configuration, source,
object and image identities, and every control result. This proves native code
and reference identity independently of any finite execution fixtures. It does
not claim GPU pixel validation or unique recovery of the original source names.

Earlier 96.271930% and 96.929825% candidates were diagnostic steps. The
successful candidate was compiled and checked by the unchanged native matcher.
The controls bound these source forms; they do not enumerate every possible
original spelling.
