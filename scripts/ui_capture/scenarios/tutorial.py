from common import *


def show_stage(stage):
    """Jump the tutorial to `stage` with its prompt fading in."""

    def run(gs):
        state = world(gs).state
        state.tutorial.stage_index = stage
        state.tutorial.stage_timer_ms = 0
        state.tutorial.stage_transition_timer_ms = 0

    return ("hook", run)


def pend_perk(gs):
    world(gs).state.perk_selection.pending_count = 1


STEPS = [*start("tutorial"), *burst("tutorial", 600, 60)]
for stage in (5, 7, 8):
    STEPS += [show_stage(stage), ("wait", 70), ("shot", f"tutorial_stage_{stage}")]
# Stage 6 prompts while a perk is pending; the level-up sign opens the perk menu.
STEPS += [show_stage(6), ("hook", pend_perk), ("wait", 70), ("shot", "tutorial_stage_6")]
STEPS += [("move", 512, 200), ("rclick",), *burst("tutorial_perk_in", 60, 12)]
