import math

MAIN = {"play": (235, 330), "options": (205, 395), "stats": (200, 455), "quit": (150, 510)}
PLAY = {"tutorial": (231, 317), "quests": (231, 349), "rush": (231, 381), "survival": (231, 413), "back": (240, 528)}
STATS = {"hiscores": (274, 315), "weapons": (274, 349), "perks": (274, 382), "credits": (274, 416), "back": (366, 500)}
OPTIONS = {"controls": (258, 430), "back": (235, 485)}
BACKS = {"controls": (141, 488), "hiscores": (344, 512), "weapons": (312, 525), "perks": (299, 525), "credits": (242, 522), "quests": (362, 517)}
QUEST_1_1 = (250, 296)
IDLE = (600, 600)


def burst(name, frames=90, every=6):
    steps = []
    for i in range(0, frames + 1, every):
        steps += [("shot", f"{name}_{i:03d}"), ("wait", every - 1)]
    return steps


def boot():
    return [("move", *IDLE), ("wait", 150)]


def nav(name, pos, frames=90, every=6):
    """Click, film the transition, then park the mouse and settle."""
    return [("click", *pos), *burst(name, frames, every), ("move", *IDLE), ("wait", 60), ("shot", f"{name}_settled")]


def hover(name, pos):
    return [("move", *pos), ("wait", 20), ("shot", f"{name}_hover"), ("move", *IDLE), ("wait", 20)]


def fight(frames, shots_every=None, prefix="fight", kite=True):
    steps = [("fire", frames)]
    for i in range(frames // 2):
        a = i * 0.05
        if kite and i % 45 == 0:
            steps.append(("hold", ("KEY_W", "KEY_D", "KEY_S", "KEY_A")[(i // 45) % 4], 88))
        steps += [("move", 512 + 200 * math.cos(a), 384 + 200 * math.sin(a)), ("wait", 2)]
        if shots_every and i and (2 * i) % shots_every == 0:
            steps.append(("shot", f"{prefix}_{2 * i:05d}"))
    return steps


def start(mode):
    return [*boot(), ("click", *MAIN["play"]), ("wait", 120), ("click", *PLAY[mode]), ("wait", 120)]


def world(gs):
    return gs.screens.active_gameplay.world


def grant_xp(xp):
    return ("hook", lambda gs: setattr(world(gs).players[0], "experience", xp))


def kill_player():
    return ("hook", lambda gs: setattr(world(gs).players[0], "health", 0.0))


def finish_quest():
    import msgspec

    def run(gs):
        mode = gs.screens.active_gameplay
        spawn = mode._quest_spawn_state
        spawn.spawn_entries = tuple(msgspec.structs.replace(e, count=0) for e in spawn.spawn_entries)
        for creature in world(gs).creatures.entries:
            creature.active = False

    return ("hook", run)


PAUSE = {"options": (250, 277), "quit": (213, 337), "back": (195, 396)}
PERK_ROWS = [(160, 216), (160, 235)]


def unlock_all(status):
    status.quest_unlock_index = 40
    status.quest_unlock_index_full = 40


# Main-menu buttons move with the window width (`ui_menu_layout_init`).
MAIN_640 = {"play": (210, 240), "options": (178, 288), "stats": (170, 337), "quit": (123, 386)}
MAIN_800 = {"play": (237, 285), "options": (206, 345), "stats": (200, 405), "quit": (152, 465)}


def small_menu(main, panel):
    """Film the main menu coming in at a smaller size, then open one panel."""
    steps = [("move", *IDLE), *burst("main_in", 90, 6), ("wait", 30), ("shot", "main_settled")]
    if panel == "play":
        for name, pos in main.items():
            steps += hover(f"main_{name}", pos)
    return steps + nav(f"{panel}_in", main[panel])
