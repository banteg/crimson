"""Shared timing and queue limits for GPU smoke and its CPU reference."""

MAX_PENDING_EMISSIONS = 1024
STEP_SECONDS = 1.0 / 60.0
FADE_SECONDS = 2.0
# Heat each source deposits per unit of smoke, relative to a muzzle's: explosions and rockets run hot, and the share
# above a muzzle's is what glows while it lasts (smoke.frag). Flame soot only just glows.
SOURCE_HEAT = {"ordinary": 2.5, "nuke": 2.5, "muzzle": 1.0, "rocket": 2.0, "soot": 1.6}
