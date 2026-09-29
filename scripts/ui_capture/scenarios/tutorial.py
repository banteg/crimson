from common import *


def show_stage(stage):
    """Jump the tutorial to `stage` with its prompt fading in."""

    def run(gs):
        state = world(gs).state
        state.tutorial.stage_index = stage
        state.tutorial.stage_timer_ms = 0
        state.tutorial.stage_transition_timer_ms = 0

    return ("hook", run)


STEPS = [*start("tutorial"), *burst("tutorial", 600, 60)]
# Stage 6 only prompts while a perk is pending, and a pending perk opens the perk menu over it.
for stage in (5, 7, 8):
    STEPS += [show_stage(stage), ("wait", 70), ("shot", f"tutorial_stage_{stage}")]
