---
tags:
  - docs-hub
---

# Crimsonland, rebuilt

Crimsonland (2003) rebuilt twice: a reimplementation that plays exactly like the
original, and a matching decompilation whose source also plays the original game
in your browser. These docs cover how the game plays, how the rebuilds work, and
the reverse engineering that ties them to the original executable.

<div class="grid cards" markdown>

-   :lucide-gamepad-2: **Play in your browser**

    ---

    The original game, compiled from the recovered source, with ranked play.
    Nothing to install; saves stay in the browser. Keyboard and mouse, or a
    gamepad.

    :lucide-arrow-right: [crimson.land/play](https://crimson.land/play/)

-   :lucide-download: **Play the reimplementation**

    ---

    Windows, macOS and Linux, with controllers, replays and ranked play.
    Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

    ```bash
    uvx crimsonland@latest
    ```

-   :lucide-trophy: **Leaderboard**

    ---

    Survival and every quest, where each score is a whole run the server
    replays before it counts.

    :lucide-arrow-right: [crimson.land](https://crimson.land)

-   :lucide-code: **Source and story**

    ---

    The code, the progress of the matching decompilation, and how it all came
    together.

    :lucide-arrow-right: [GitHub](https://github.com/banteg/crimson) ·
    [decomp.dev](https://decomp.dev/banteg/crimson) ·
    [blog post](https://banteg.xyz/posts/crimsonland/)

</div>

## Highlights

- [Matching decompilation](https://decomp.dev/banteg/crimson): all 858 game
  and engine functions of 1.9.93 come from recovered C/C++ source that compiles
  to the original machine code. 1.9.8 is measured from the same source.

- [Perks](mechanics/perks.md): all 58 perks with exact numbers, interaction
  rules, and original bug notes verified against two builds of the binary.

- [Fire Bullets (1.9.8 vs 1.9.93)](re/static/fire-bullets-1.9.8-vs-1.9.93.md):
  how fire bullets changed from an additive bonus (1.9.8) to a full weapon
  replacement (1.9.93), with per-weapon DPS showing most weapons lost 80-95%
  of their output.

## Sections

<div class="grid cards" markdown>

-   [**Mechanics**](mechanics/index.md)

    How the game actually plays: behavior specs, reference tables, and game
    rules written without decompiler details.

-   [**Rewrite**](rewrite/index.md)

    The Python port and the recovered core: architecture, module map, debug
    views, and parity status.

-   [**Reverse engineering**](re/index.md)

    Static analysis, runtime probes, struct layouts, and file formats extracted
    from the original binary.

-   [**Verification**](verification/index.md)

    Differential testing, the evidence ledger, and parity matrices that connect
    claims to proof.

-   [**Contributor**](contributor/index.md)

    Setup, workflows, and project tracking.

</div>
