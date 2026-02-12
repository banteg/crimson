---
tags:
  - mechanics
  - systems
  - bonuses
---

# Bonuses

Bonuses spawn from creature deaths in most combat modes and apply instantly when you walk into pickup radius.

## When bonuses appear

- The game evaluates bonus drops after creature kill processing.
- A kill can force a bonus, or it can use random selection.
- If [Bonus Magnet](../perks.md#27-bonus-magnet) is active, the chance of a second chance roll is improved.
- If a player is holding pistol, weapon drops are heavily favored first and often forced.

Some bonuses do not appear in these modes:

- no bonus spawns in Rush,
- no bonus spawns in Typ-o-Shooter,
- no bonus spawns while tutorial is running.

## How long bonuses last

All bonuses use internal timers. Visual entries fade at `3.0` points per second (or faster while you hold them), and unpicked entries vanish when their timer expires.

- Tutorial uses a fixed `5 second` template while active.
- Normal runs use `10 second` base persistence.

## Active duration bonuses

- [Energizer](../bonuses.md#energizer): fixed duration (`8` seconds).
- [Weapon Power Up](../bonuses.md#weapon-power-up): `10 seconds`.
- [Double Experience](../bonuses.md#double-experience): fixed `6 second` multiplier.
- [Reflex Boost](../bonuses.md#reflex-boost): fixed duration and applies global time scale.
- [Speed](../bonuses.md#speed): fixed duration and movement bonus.
- [Fire Bullets](../bonuses.md#fire-bullets): fixed `5 second` window with altered projectile behavior.
- [Shield](../bonuses.md#shield), [Freeze](../bonuses.md#freeze), [Nuke](../bonuses.md#nuke), and others use their own effect rules.

## Selection quirks that affect pickup value

- When you are near a newly spawned weapon bonus, it can be converted into points (`100`).
- Some modes clear the bonus stack when the spawn guard is active.
- Preserve-bugs mode can alter weapon-spawn suppression checks, which can slightly change whether certain drops are discarded.

## Why bonus behavior can feel uneven

Most variance comes from three places:

- enemy death RNG branch that decides whether to force a bonus,
- which bonus type is picked,
- whether active bonuses (especially [Bonus Magnet](../perks.md#27-bonus-magnet)) give you extra chances.
