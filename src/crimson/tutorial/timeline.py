from __future__ import annotations

from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..bonuses import BonusId
from ..creatures.spawn_ids import CreatureFlags, SpawnId
from .state import TutorialOverlayState

if TYPE_CHECKING:
    from ..sim.world_state import WorldState

_HINT_TEXT = (
    "This is the speed powerup, it makes you move faster for\na limited amount of time.",
    "This is a weapon powerup. Picking it you gets\nyou another weapon. This one is a submachine gun.",
    "This powerup doubles all experience points gained when\nx2 powerup is active.",
    "This is the nuke powerup, picking it up causes a huge\nexposion harming all monsters nearby!",
    "Reflex Boost powerup slows down time giving you a chance to react better",
    "",
    "",
)
_STAGE_TEXT = (
    "In this tutorial you'll learn how to play Crimsonland",
    "First learn to move by pushing the arrow keys.",
    "Now pick up the bonuses by walking over them",
    "Now learn to shoot and move at the same time.\nClick the left Mouse button to shoot.",
    "Now, move the mouse to aim at the monsters",
    "It will help you to move and shoot and aim at the same time, so practice!",
    "Now let's learn about Perks. You can pick a Perk by clicking\nthe 'level up' sign at the upper right corner of the screen.",
    "Perks can give you extra abilities that help\nyou survive in Crimsonland.",
    "Great! Now you are ready to start playing Crimsonland!",
    "",
)
_HEADING = 3.1415927  # native 3.14159274f


def tutorial_timeline_update(world: WorldState, *, dt_ms: int) -> None:
    """`tutorial_timeline_update`: stage prompts, the bonus hints, and the scripted spawns of each stage.

    It runs after the world render and before the death and level-up checks, like native.
    """
    state = world.state
    tutorial = state.tutorial
    players = world.players

    def spawn(template_id: SpawnId, x: float, y: float) -> int:
        return world.creatures.spawn_template(
            template_id, Vec2(x, y), _HEADING, state=state, detail_preset=state.detail_preset,
        )

    def level_up_sfx() -> None:
        state.sfx_queue.append(SfxRequest(SfxId.UI_LEVELUP, None))

    tutorial.stage_timer_ms += dt_ms
    players[0].health = 100.0
    if tutorial.stage_index != 6:
        players[0].experience = 0

    transition = tutorial.stage_transition_timer_ms
    if transition < -1:
        transition += dt_ms
        tutorial.stage_transition_timer_ms = transition
        if transition >= -1:
            tutorial.stage_index += 1
            if tutorial.stage_index == 9:
                tutorial.stage_index = 0
            tutorial.stage_transition_timer_ms = 0
    elif transition >= 0:
        tutorial.stage_transition_timer_ms = transition + dt_ms
    if tutorial.stage_transition_timer_ms > 1000:
        tutorial.stage_transition_timer_ms = -1

    transition = tutorial.stage_transition_timer_ms
    if transition >= 0:
        prompt_alpha = transition * 0.001
    elif transition < -1:
        prompt_alpha = -transition * 0.001
    else:
        prompt_alpha = 1.0
    if prompt_alpha >= 1.0 and tutorial.stage_index == 5 and tutorial.stage_timer_ms > 5000 and transition >= -1:
        prompt_alpha = 1.0 - (tutorial.stage_timer_ms - 5000) * 0.001
    if tutorial.stage_index == 5 and tutorial.stage_timer_ms > 6000:
        prompt_alpha = 0.0
    overlay = TutorialOverlayState()
    if tutorial.stage_index >= 0 and (tutorial.stage_index != 6 or state.perk_selection.pending_count > 0):
        overlay.prompt_text = _STAGE_TEXT[tutorial.stage_index]
        overlay.prompt_alpha = min(1.0, max(0.0, prompt_alpha))

    # The carrier's slot is inactive once its corpse is culled. Native keeps the last carrier referenced, so
    # repeats 6 and 7, which spawn no carrier, latch on it again.
    if not tutorial.hint_fade_in:
        ref = tutorial.hint_bonus_creature_ref
        carrier = world.creatures.creature(ref) if ref is not None else None
        if (
            carrier is not None
            and not carrier.active
            and carrier.hp <= 0.0
            and carrier.flags & CreatureFlags.BONUS_ON_DEATH
        ):
            tutorial.hint_fade_in = True
            spawn(SpawnId.ALIEN_CONST_GREEN_24, 128.0, 128.0)
            spawn(SpawnId.ALIEN_SMALL_GRAY_26, 152.0, 160.0)
            tutorial.hint_index += 1
        tutorial.hint_alpha -= dt_ms * 3
    else:
        tutorial.hint_alpha += dt_ms * 3
    tutorial.hint_alpha = min(1000, max(0, tutorial.hint_alpha))
    if tutorial.hint_index >= 0 and _HINT_TEXT[tutorial.hint_index]:
        overlay.hint_text = _HINT_TEXT[tutorial.hint_index]
        overlay.hint_alpha = tutorial.hint_alpha * 0.001
    state.tutorial_overlay = overlay

    bonuses_gone = not state.bonus_pool.iter_active()
    creatures_gone = not world.creatures.iter_active()
    ready = tutorial.stage_transition_timer_ms == -1
    match tutorial.stage_index:
        case 0:
            if tutorial.stage_timer_ms > 6000 and ready:
                tutorial.repeat_spawn_count = 0
                tutorial.hint_index = -1
                tutorial.hint_fade_in = False
                tutorial.stage_transition_timer_ms = -1000
        case 1:
            if tutorial.move_active_this_tick and ready:
                tutorial.stage_transition_timer_ms = -1000
                level_up_sfx()
                # Native writes bonus slots 0..2 directly with 100-second timers, then bursts each.
                for index, (x, y, amount) in enumerate(((260.0, 260.0, 500), (600.0, 400.0, 1000), (300.0, 400.0, 500))):
                    entry = state.bonus_pool.seed_tutorial_entry(
                        index, pos=Vec2(x, y), bonus_id=BonusId.POINTS, amount=amount,
                    )
                    state.effects.spawn_burst(pos=entry.pos, count=12, rng=state.rng, detail_preset=state.detail_preset)
        case 2:
            if bonuses_gone and ready:
                tutorial.stage_transition_timer_ms = -1000
                level_up_sfx()
        case 3:
            if tutorial.fire_active_this_tick and ready:
                tutorial.stage_transition_timer_ms = -1000
                level_up_sfx()
                spawn(SpawnId.ALIEN_CONST_GREEN_24, -164.0, 412.0)
                spawn(SpawnId.ALIEN_SMALL_GRAY_26, -184.0, 512.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, -154.0, 612.0)
        case 4:
            if creatures_gone and ready:
                tutorial.stage_timer_ms = 1000
                tutorial.stage_transition_timer_ms = -1000
                level_up_sfx()
                tutorial.repeat_spawn_count = 0
                spawn(SpawnId.ALIEN_CONST_GREEN_24, 1188.0, 412.0)
                spawn(SpawnId.ALIEN_SMALL_GRAY_26, 1208.0, 512.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, 1178.0, 612.0)
        case 5:
            if not (bonuses_gone and creatures_gone):
                return
            tutorial.repeat_spawn_count += 1
            repeat = tutorial.repeat_spawn_count
            if repeat > 7:
                if ready:
                    tutorial.stage_transition_timer_ms = -1000
                    level_up_sfx()
                    # The level-up check after this update turns it into a perk.
                    players[0].experience = 3000
                return
            tutorial.hint_fade_in = False
            if repeat & 1:
                if repeat < 6:
                    tutorial.hint_bonus_creature_ref = spawn(SpawnId.ALIEN_BONUS_CARRIER_27, -32.0, 1056.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, -164.0, 412.0)
                spawn(SpawnId.ALIEN_SMALL_GRAY_26, -184.0, 512.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, -154.0, 612.0)
            else:
                if repeat < 6:
                    tutorial.hint_bonus_creature_ref = spawn(SpawnId.ALIEN_BONUS_CARRIER_27, 1056.0, 1056.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, 1188.0, 1136.0)
                spawn(SpawnId.ALIEN_SMALL_GRAY_26, 1208.0, 512.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, 1178.0, 612.0)
            if repeat == 4:
                spawn(SpawnId.SPIDER_SMALL_BLUE_40, 512.0, 1056.0)
            if repeat < 6 and tutorial.hint_bonus_creature_ref is not None:
                carrier = world.creatures.creature(tutorial.hint_bonus_creature_ref)
                match repeat:
                    case 1:
                        carrier.bonus_id, carrier.bonus_duration_override = BonusId.SPEED, -1
                    case 2:
                        carrier.bonus_id, carrier.bonus_duration_override = BonusId.WEAPON, 5
                    case 3:
                        carrier.bonus_id, carrier.bonus_duration_override = BonusId.DOUBLE_EXPERIENCE, -1
                    case 4:
                        carrier.bonus_id, carrier.bonus_duration_override = BonusId.NUKE, -1
                    case 5:
                        carrier.bonus_id, carrier.bonus_duration_override = BonusId.REFLEX_BOOST, -1
        case 6:
            if state.perk_selection.pending_count <= 0 and ready:
                tutorial.stage_transition_timer_ms = -1000
                spawn(SpawnId.ALIEN_CONST_GREEN_24, -164.0, 412.0)
                spawn(SpawnId.ALIEN_SMALL_GRAY_26, -184.0, 512.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, -154.0, 612.0)
                spawn(SpawnId.ALIEN_CONST_PURPLE_28, -32.0, -32.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, 1188.0, 412.0)
                spawn(SpawnId.ALIEN_SMALL_GRAY_26, 1208.0, 512.0)
                spawn(SpawnId.ALIEN_CONST_GREEN_24, 1178.0, 612.0)
        case 7:
            if bonuses_gone and creatures_gone and ready:
                tutorial.stage_transition_timer_ms = -1000
