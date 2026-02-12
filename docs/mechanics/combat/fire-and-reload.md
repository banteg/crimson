---
tags:
  - mechanics
  - combat
  - input-loop
---

# Fire and reload loop

This page describes what happens every frame while you fire or reload.

## Firing timing

You can shoot only when the shot cooldown is zero.

After a shot, the game sets your cooldown from the weapon’s base fire interval and then
immediately applies perk modifiers:

- [Fastshot](../perks.md#14-fastshot): cooldown × `0.88`.
- [Sharpshooter](../perks.md#2-sharpshooter): cooldown × `1.05`.

While you move through the frame loop, cooldown decreases by `1.5 × dt` per second.
With [Weapon Power Up](../systems/bonuses.md) active, that recovery becomes `2.25 × dt`.

To prevent flicker at very tiny values, tiny positive cooldown values (`< 1e-6`) are treated
as `0`.

## What happens when you hold fire

- If the cooldown is still active, the trigger input is ignored until it reaches zero.
- If the trigger is pressed with no ammo and no active reload timer, reload starts automatically.
- If you are empty and pressing fire while reload is already active, the shot will not fire unless
  one of the reload-bypass perks is active.
- If [Reflex](../systems/bonuses.md) speed effects are active, movement is slowed, but fire cooldown
  recovery uses the same per-frame cooldown update path.

## Reload start conditions

- Manual reload: press reload while not holding move-to-cursor and `player.reload_timer == 0`.
- Auto reload: happens right after a shot if ammo is `<= 0` and reload timer is already done.
- Firing while reloading:
  - [Regression Bullets](../perks.md#23-regression-bullets): allowed; shot spending uses XP.
  - [Ammunition Within](../perks.md#35-ammunition-within): allowed; shot spending uses health.

`player_start_reload` sets reload duration from weapon base and applies:

- [Fastloader](../perks.md#3-fastloader): ×`0.7`
- [Weapon Power Up](../systems/bonuses.md): ×`0.6`

If you are already reloading and one of the two bypass perks above is active, `player_start_reload`
does not restart the timer.

## Reload timer behavior

- The timer counts down every frame.
- If you stand still and have [Stationary Reloader](../perks.md#52-stationary-reloader), the timer decays
  `3 ×` faster.
- If [Anxious Loader](../perks.md#18-anxious-loader) is active and you are pressing fire during reload,
  reload time drops by `0.05` per press.
- In the frame just before an underflow, ammo is preloaded to full clip once.
- If timer reaches zero and you are still holding fire while still empty, ammo jumps to full clip immediately.
- The engine only clears reload state when both are true:
  - clip is full
  - shot cooldown is `0`.

## Angry Reloader burst behavior

[Angry Reloader](../perks.md#50-angry-reloader) adds a special event in longer reloads:

- only when `reload_timer_max > 0.5`,
- when the timer drops below half of its starting value,
- it spawns a burst of `[plasma minigun]` projectiles (`7 + int(reload_timer_max * 4)`) around you
  and plays a small explosion sound.

For common reload values, that means:

- `1.2s` reload → `11` projectiles.
- `1.8s` reload → `14` projectiles.

## Alternate Weapon interaction

When [Alternate Weapon](../perks.md#9-alternate-weapon) is equipped:

- pressing reload swaps weapon slots instead of forcing a manual reload;
- that swap adds `+0.1` to shot cooldown so you cannot shoot instantly after the swap.
