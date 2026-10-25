"""Authored streak dimensions shared by visible sprites and lighting."""

from ..projectiles.types import Projectile, ProjectileTemplateId
from ..sim.state_types import TERRAIN_SIZE

STREAK_SCALES = {
    ProjectileTemplateId.ION_MINIGUN: 1.05,
    ProjectileTemplateId.ION_RIFLE: 2.2,
    ProjectileTemplateId.ION_CANNON: 3.5,
    ProjectileTemplateId.FIRE_BULLETS: 0.8,
}


def fire_bullets_flown(proj: Projectile, *, preserve_bugs: bool, barrel_greaser: bool) -> float:
    """How far a Fire Bullets shot has flown since the arena's edge stopped it (original bug 52).

    The update stops any shot 64 units past the terrain and fades it in place, so its whole trail hung at the screen's
    edge. Fire Bullets pass through what they hit, so out there only the edge stops them: drawn and lit, the shot flies
    on while it fades. It flew ceil(speed / 3) strides of 3 * 20 * speed_scale units a second, and the fade has run
    0.4 - life seconds. 0 for any other shot, in flight, or under the original's bugs.
    """
    pos = proj.pos
    inside = -64.0 <= pos.x <= TERRAIN_SIZE + 64.0 and -64.0 <= pos.y <= TERRAIN_SIZE + 64.0
    if preserve_bugs or proj.type_id != ProjectileTemplateId.FIRE_BULLETS or inside or proj.life_timer >= 0.4:
        return 0.0
    steps = int(proj.projectile_speed) * (2 if barrel_greaser and proj.owner_id < 0 else 1)
    return (0.4 - float(proj.life_timer)) * -(-steps // 3) * 3 * 20.0 * float(proj.speed_scale)
