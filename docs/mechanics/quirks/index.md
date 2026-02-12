---
tags:
  - mechanics
  - quirks
---

# Gameplay quirks

These are player-visible oddities from active gameplay flow.

## Spawn timing quirks

- frame-rate-driven timers and integer timing math can make spawn batches appear grouped when cooldown edges cross zero.
- player count directly scales spawn cooldown decrease in wave modes.
- Survival uses an interval formula that can go negative and spawn multiple enemies in one timing step.

## Bonus behavior quirks

- Force weapon drops while on pistol are not guaranteed one-to-one with kills.
- Some modes disable bonuses entirely (Rush and Typ-o, plus Tutorial).
- Weapon drop amount and point conversion rules include position and suppression checks.

## Perk side effects worth calling out

- [Jinxed](../perks.md#42-jinxed) can cause occasional direct player damage in addition to normal threats.
- [Grim Deal](../perks.md#8-grim-deal) kills you on pick.
- [Infernal Contract](../perks.md#24-infernal-contract) and [Breathing Room](../perks.md#46-breathing-room) can immediately lower health.
- [Death Clock](../perks.md#47-death-clock) is a pure downside mode:
  - it starts at `100` health,
  - then drains at `3.333... hp/s` over about `30 s`.

## Score and ranking edge behavior

- Quest timing is ascending (fastest first), with unfinished entries ranked behind finished ones.
- Survival/Rush scoreboards share file-backed sorting rules that are mode-specific.
