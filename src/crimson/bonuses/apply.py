from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from grim.geom import Vec2

from ..perks import PerkId
from ..projectiles import CreatureDamageApplier, Damageable, ProjectileTypeId
from ..sim.state_types import GameplayState, PlayerState
from .hud import _TimerRef
from .ids import BONUS_BY_ID, BonusId


class _HasPos(Protocol):
    pos: Vec2


@dataclass(frozen=True, slots=True)
class DeferredFreezeCorpseFx:
    pos: Vec2
    detail_preset: int


@dataclass(slots=True)
class _BonusApplyCtx:
    state: GameplayState
    player: PlayerState
    bonus_id: BonusId
    amount: int
    origin: _HasPos | None
    creatures: Sequence[Damageable] | None
    players: list[PlayerState] | None
    apply_creature_damage: CreatureDamageApplier | None
    detail_preset: int
    economist_multiplier: float
    label: str
    icon_id: int
    defer_freeze_corpse_fx: bool = False

    def register_global(self, timer_key: str) -> None:
        self.state.bonus_hud.register(
            self.bonus_id,
            label=self.label,
            icon_id=self.icon_id,
            timer_ref=_TimerRef("global", str(timer_key)),
        )

    def register_player(self, timer_key: str) -> None:
        if self.players is not None and len(self.players) > 1:
            self.state.bonus_hud.register(
                self.bonus_id,
                label=self.label,
                icon_id=self.icon_id,
                timer_ref=_TimerRef("player", str(timer_key), player_index=0),
                timer_ref_alt=_TimerRef("player", str(timer_key), player_index=1),
            )
        else:
            self.state.bonus_hud.register(
                self.bonus_id,
                label=self.label,
                icon_id=self.icon_id,
                timer_ref=_TimerRef("player", str(timer_key), player_index=int(self.player.index)),
            )

    def origin_pos(self) -> _HasPos:
        return self.origin or self.player


_BonusApplyHandler = Callable[[_BonusApplyCtx], None]


def _bonus_apply_seconds(ctx: _BonusApplyCtx) -> float:
    meta = BONUS_BY_ID.get(int(ctx.bonus_id))
    if meta is not None and meta.apply_seconds is not None:
        return float(meta.apply_seconds)
    return float(ctx.amount)


def _bonus_apply_points(ctx: _BonusApplyCtx) -> None:
    # Native adds Points directly to player0 XP (no Double XP multiplier).
    amount = int(ctx.amount)
    if amount <= 0:
        return
    target = ctx.player
    if ctx.players is not None and len(ctx.players) > 0:
        target = ctx.players[0]
    target.experience += int(amount)


def _bonus_apply_energizer(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.energizer)
    if old <= 0.0:
        ctx.register_global("energizer")

    ctx.state.bonuses.energizer = float(old + _bonus_apply_seconds(ctx) * ctx.economist_multiplier)


def _bonus_apply_weapon_power_up(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.weapon_power_up)
    if old <= 0.0:
        ctx.register_global("weapon_power_up")
    ctx.state.bonuses.weapon_power_up = float(old + float(ctx.amount) * ctx.economist_multiplier)
    ctx.player.weapon_reset_latch = 0
    ctx.player.shot_cooldown = 0.0
    ctx.player.reload_active = False
    ctx.player.reload_timer = 0.0
    ctx.player.reload_timer_max = 0.0
    ctx.player.ammo = float(ctx.player.clip_size)


def _bonus_apply_double_experience(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.double_experience)
    if old <= 0.0:
        ctx.register_global("double_experience")
    ctx.state.bonuses.double_experience = float(old + _bonus_apply_seconds(ctx) * ctx.economist_multiplier)


def _bonus_apply_reflex_boost(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.reflex_boost)
    if old <= 0.0:
        ctx.register_global("reflex_boost")
    ctx.state.bonuses.reflex_boost = float(old + float(ctx.amount) * ctx.economist_multiplier)

    targets = ctx.players if ctx.players is not None else [ctx.player]
    for target in targets:
        target.ammo = float(target.clip_size)
        target.reload_active = False
        target.reload_timer = 0.0
        target.reload_timer_max = 0.0


def _bonus_apply_freeze(ctx: _BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.freeze)
    if old <= 0.0:
        ctx.register_global("freeze")
    ctx.state.bonuses.freeze = float(old + float(ctx.amount) * ctx.economist_multiplier)

    creatures = ctx.creatures
    if creatures:
        defer_corpse_fx = bool(ctx.defer_freeze_corpse_fx)
        rand = ctx.state.rng.rand
        for creature in creatures:
            if not creature.active:
                continue
            if creature.hp > 0.0:
                continue
            pos = creature.pos
            if defer_corpse_fx:
                ctx.state.deferred_freeze_corpse_fx.append(
                    DeferredFreezeCorpseFx(
                        pos=Vec2(float(pos.x), float(pos.y)),
                        detail_preset=int(ctx.detail_preset),
                    )
                )
            else:
                for _ in range(8):
                    angle = float(int(rand()) % 0x264) * 0.01
                    ctx.state.effects.spawn_freeze_shard(
                        pos=pos,
                        angle=angle,
                        rand=rand,
                        detail_preset=int(ctx.detail_preset),
                    )
                angle = float(int(rand()) % 0x264) * 0.01
                ctx.state.effects.spawn_freeze_shatter(
                    pos=pos,
                    angle=angle,
                    rand=rand,
                    detail_preset=int(ctx.detail_preset),
                )
            creature.active = False

    ctx.state.sfx_queue.append("sfx_shockwave")


def flush_deferred_freeze_corpse_fx(state: GameplayState) -> None:
    pending = state.deferred_freeze_corpse_fx
    if not pending:
        return

    rand = state.rng.rand
    for queued in pending:
        pos = queued.pos
        detail = int(queued.detail_preset)
        for _ in range(8):
            angle = float(int(rand()) % 0x264) * 0.01
            state.effects.spawn_freeze_shard(
                pos=pos,
                angle=angle,
                rand=rand,
                detail_preset=detail,
            )
        angle = float(int(rand()) % 0x264) * 0.01
        state.effects.spawn_freeze_shatter(
            pos=pos,
            angle=angle,
            rand=rand,
            detail_preset=detail,
        )
    pending.clear()


def _bonus_apply_shield(ctx: _BonusApplyCtx) -> None:
    should_register = float(ctx.player.shield_timer) <= 0.0
    if ctx.players is not None and len(ctx.players) > 1:
        should_register = float(ctx.players[0].shield_timer) <= 0.0 and float(ctx.players[1].shield_timer) <= 0.0
    if should_register:
        ctx.register_player("shield_timer")
    ctx.player.shield_timer = float(ctx.player.shield_timer + float(ctx.amount) * ctx.economist_multiplier)


def _bonus_apply_speed(ctx: _BonusApplyCtx) -> None:
    should_register = float(ctx.player.speed_bonus_timer) <= 0.0
    if ctx.players is not None and len(ctx.players) > 1:
        should_register = (
            float(ctx.players[0].speed_bonus_timer) <= 0.0 and float(ctx.players[1].speed_bonus_timer) <= 0.0
        )
    if should_register:
        ctx.register_player("speed_bonus_timer")
    ctx.player.speed_bonus_timer = float(ctx.player.speed_bonus_timer + float(ctx.amount) * ctx.economist_multiplier)


def _bonus_apply_fire_bullets(ctx: _BonusApplyCtx) -> None:
    should_register = float(ctx.player.fire_bullets_timer) <= 0.0
    if ctx.players is not None and len(ctx.players) > 1:
        should_register = (
            float(ctx.players[0].fire_bullets_timer) <= 0.0 and float(ctx.players[1].fire_bullets_timer) <= 0.0
        )
    if should_register:
        ctx.register_player("fire_bullets_timer")
    ctx.player.fire_bullets_timer = float(
        ctx.player.fire_bullets_timer + _bonus_apply_seconds(ctx) * ctx.economist_multiplier
    )
    ctx.player.weapon_reset_latch = 0
    ctx.player.shot_cooldown = 0.0
    ctx.player.reload_active = False
    ctx.player.reload_timer = 0.0
    ctx.player.reload_timer_max = 0.0
    ctx.player.ammo = float(ctx.player.clip_size)


def _bonus_apply_shock_chain(ctx: _BonusApplyCtx) -> None:
    from ..gameplay import _owner_id_for_player, _projectile_spawn

    creatures = ctx.creatures
    if not creatures:
        return

    origin_pos = ctx.origin_pos()
    # Mirrors the `exclude_id == -1` behavior of `creature_find_nearest(origin, -1, 0.0)`:
    # - requires `active != 0`
    # - requires `hitbox_size == 16.0` (alive sentinel)
    # - no HP gate
    # - falls back to index 0 if nothing qualifies
    origin = origin_pos.pos
    best_idx = 0
    best_dist_sq = 1e12
    for idx, creature in enumerate(creatures):
        if not creature.active:
            continue
        if creature.hitbox_size != 16.0:
            continue
        d_sq = Vec2.distance_sq(origin, creature.pos)
        if d_sq < best_dist_sq:
            best_dist_sq = d_sq
            best_idx = idx

    target = creatures[best_idx]
    angle = (target.pos - origin).to_heading()
    owner_id = _owner_id_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else -100

    ctx.state.bonus_spawn_guard = True
    ctx.state.shock_chain_links_left = 0x20
    ctx.state.shock_chain_projectile_id = _projectile_spawn(
        ctx.state,
        players=ctx.players,
        pos=origin,
        angle=angle,
        type_id=int(ProjectileTypeId.ION_RIFLE),
        owner_id=int(owner_id),
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append("sfx_shock_hit_01")


def _bonus_apply_weapon(ctx: _BonusApplyCtx) -> None:
    from ..gameplay import perk_active, weapon_assign_player

    weapon_id = int(ctx.amount)
    if perk_active(ctx.player, PerkId.ALTERNATE_WEAPON) and ctx.player.alt_weapon_id is None:
        ctx.player.alt_weapon_id = int(ctx.player.weapon_id)
        ctx.player.alt_clip_size = int(ctx.player.clip_size)
        ctx.player.alt_ammo = float(ctx.player.ammo)
        ctx.player.alt_reload_active = bool(ctx.player.reload_active)
        ctx.player.alt_reload_timer = float(ctx.player.reload_timer)
        ctx.player.alt_shot_cooldown = float(ctx.player.shot_cooldown)
        ctx.player.alt_reload_timer_max = float(ctx.player.reload_timer_max)
    weapon_assign_player(ctx.player, weapon_id, state=ctx.state)


def _bonus_apply_medikit(ctx: _BonusApplyCtx) -> None:
    if float(ctx.player.health) >= 100.0:
        return
    ctx.player.health = min(100.0, float(ctx.player.health) + 10.0)


def _bonus_apply_fireblast(ctx: _BonusApplyCtx) -> None:
    from ..gameplay import _owner_id_for_player, _spawn_projectile_ring

    origin_pos = ctx.origin_pos()
    owner_id = _owner_id_for_player(ctx.player.index) if ctx.state.friendly_fire_enabled else -100
    ctx.state.bonus_spawn_guard = True
    _spawn_projectile_ring(
        ctx.state,
        origin_pos,
        count=16,
        angle_offset=0.0,
        type_id=ProjectileTypeId.PLASMA_RIFLE,
        owner_id=int(owner_id),
        players=ctx.players,
    )
    ctx.state.bonus_spawn_guard = False
    ctx.state.sfx_queue.append("sfx_explosion_medium")


def _bonus_apply_nuke(ctx: _BonusApplyCtx) -> None:
    from ..gameplay import _owner_id_for_player, _projectile_spawn

    # `bonus_apply` (crimsonland.exe @ 0x00409890) starts screen shake via:
    #   camera_shake_pulses = 0x14;
    #   camera_shake_timer = 0.2f;
    ctx.state.camera_shake_pulses = 0x14
    ctx.state.camera_shake_timer = 0.2

    origin_pos = ctx.origin_pos()
    origin = origin_pos.pos
    rand = ctx.state.rng.rand

    bullet_count = int(rand()) & 3
    bullet_count += 4
    for _ in range(bullet_count):
        angle = float(int(rand()) % 0x274) * 0.01
        proj_id = _projectile_spawn(
            ctx.state,
            players=ctx.players,
            pos=origin,
            angle=float(angle),
            type_id=int(ProjectileTypeId.PISTOL),
            owner_id=-100,
        )
        if proj_id != -1:
            speed_scale = float(int(rand()) % 0x32) * 0.01 + 0.5
            ctx.state.projectiles.entries[proj_id].speed_scale *= float(speed_scale)

    for _ in range(2):
        angle = float(int(rand()) % 0x274) * 0.01
        _projectile_spawn(
            ctx.state,
            players=ctx.players,
            pos=origin,
            angle=float(angle),
            type_id=int(ProjectileTypeId.GAUSS_GUN),
            owner_id=-100,
        )

    ctx.state.effects.spawn_explosion_burst(
        pos=origin,
        scale=1.0,
        rand=rand,
        detail_preset=int(ctx.detail_preset),
    )

    creatures = ctx.creatures
    if creatures:
        prev_guard = bool(ctx.state.bonus_spawn_guard)
        ctx.state.bonus_spawn_guard = True
        for idx, creature in enumerate(creatures):
            # Native applies explosion damage to any active creature, including
            # those already in the death/corpse state (this shrinks corpses
            # faster via the hp<=0 path in creature_apply_damage).
            if not creature.active:
                continue
            delta = creature.pos - origin
            if abs(delta.x) > 256.0 or abs(delta.y) > 256.0:
                continue
            dist = delta.length()
            if dist < 256.0:
                damage = (256.0 - dist) * 5.0
                if ctx.apply_creature_damage is not None:
                    ctx.apply_creature_damage(
                        int(idx),
                        float(damage),
                        3,
                        Vec2(),
                        _owner_id_for_player(ctx.player.index),
                    )
                else:
                    creature.hp -= float(damage)
        ctx.state.bonus_spawn_guard = prev_guard

    ctx.state.sfx_queue.append("sfx_explosion_large")
    ctx.state.sfx_queue.append("sfx_shockwave")


_BONUS_APPLY_HANDLERS: dict[BonusId, _BonusApplyHandler] = {
    BonusId.POINTS: _bonus_apply_points,
    BonusId.ENERGIZER: _bonus_apply_energizer,
    BonusId.WEAPON_POWER_UP: _bonus_apply_weapon_power_up,
    BonusId.DOUBLE_EXPERIENCE: _bonus_apply_double_experience,
    BonusId.REFLEX_BOOST: _bonus_apply_reflex_boost,
    BonusId.FREEZE: _bonus_apply_freeze,
    BonusId.SHIELD: _bonus_apply_shield,
    BonusId.MEDIKIT: _bonus_apply_medikit,
    BonusId.SPEED: _bonus_apply_speed,
    BonusId.FIRE_BULLETS: _bonus_apply_fire_bullets,
    BonusId.SHOCK_CHAIN: _bonus_apply_shock_chain,
    BonusId.WEAPON: _bonus_apply_weapon,
    BonusId.FIREBLAST: _bonus_apply_fireblast,
    BonusId.NUKE: _bonus_apply_nuke,
}


def bonus_apply(
    state: GameplayState,
    player: PlayerState,
    bonus_id: BonusId,
    *,
    amount: int | None = None,
    origin: _HasPos | None = None,
    creatures: Sequence[Damageable] | None = None,
    players: list[PlayerState] | None = None,
    apply_creature_damage: CreatureDamageApplier | None = None,
    detail_preset: int = 5,
    defer_freeze_corpse_fx: bool = False,
) -> None:
    """Apply a bonus to player + global timers (subset of `bonus_apply`)."""

    from ..gameplay import perk_count_get

    meta = BONUS_BY_ID.get(int(bonus_id))
    if meta is None:
        return
    if amount is None:
        amount = int(meta.default_amount or 0)

    economist_multiplier = 1.5 if perk_count_get(player, PerkId.BONUS_ECONOMIST) != 0 else 1.0
    icon_id = int(meta.icon_id) if meta.icon_id is not None else -1
    label = meta.name
    ctx = _BonusApplyCtx(
        state=state,
        player=player,
        bonus_id=bonus_id,
        amount=int(amount),
        origin=origin,
        creatures=creatures,
        players=players,
        apply_creature_damage=apply_creature_damage,
        detail_preset=int(detail_preset),
        economist_multiplier=float(economist_multiplier),
        label=str(label),
        icon_id=int(icon_id),
        defer_freeze_corpse_fx=bool(defer_freeze_corpse_fx),
    )
    handler = _BONUS_APPLY_HANDLERS.get(bonus_id)
    if handler is not None:
        handler(ctx)

    # Bonus types not modeled yet.
    return
