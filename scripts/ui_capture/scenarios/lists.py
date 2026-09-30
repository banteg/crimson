import datetime as dt

from common import *

from crimson.game_modes import GameMode
from crimson.weapons import WeaponId

# Unlocked, so the weapon and perk databases overflow their ten rows.
STATUS = unlock_all
# The score list (thirty Survival scores, every third one sent) and the databases' lists at 1024x768: a row's
# middle, and the scrollbar track 10px right of the list.
HS_ROW, HS_TRACK = (200, 303), 357
DB_ROW, DB_TRACK = (200, 330), 359


def scores(gs):
    from crimson.persistence.highscores import HighScoreRecord, scores_path_for_config, write_highscore_records

    gs.config.gameplay.mode = GameMode.SURVIVAL
    records = []
    for i in range(30):
        record = HighScoreRecord.blank(rand_value=i)
        record.game_mode_id = GameMode.SURVIVAL
        record.set_name(f"player {i}")
        record.score_xp = 10000 - i * 250
        record.most_used_weapon_id = WeaponId.PISTOL
        record.flags = 1 if i % 3 == 0 else 0
        record.ensure_date_fields(dt.date(2026, 1, 1))
        records.append(record)
    write_highscore_records(scores_path_for_config(gs.base_dir, gs.config), records)


def drag(name, x, grab_y, ys, off_x=None):
    """Press on the track at `grab_y` and drag through `ys`, then off the track, and let go."""
    steps = [("move", x, grab_y), ("fire", 60), ("wait", 3), ("shot", f"{name}_grab")]
    for y in ys:
        steps += [("move", x, y), ("wait", 5), ("shot", f"{name}_{y}")]
    if off_x is not None:
        steps += [("move", off_x, ys[-1] - 30), ("wait", 5), ("shot", f"{name}_off_track")]
    return [*steps, ("wait", 60), ("move", *IDLE), ("wait", 5), ("shot", f"{name}_released")]


s = [*boot(), ("hook", scores), *nav("stats_in", MAIN["stats"]), *nav("hiscores_in", STATS["hiscores"])]
s += hover("hs_row_3", (HS_ROW[0], HS_ROW[1] + 3 * 16))
s += [("click", HS_ROW[0], HS_ROW[1] + 5 * 16), ("wait", 5), ("move", *IDLE), ("wait", 5), ("shot", "hs_row_5_selected")]
s += hover("hs_track", (HS_TRACK, 320))
s += [("click", HS_TRACK, 420), ("wait", 5), ("shot", "hs_track_click"), ("move", *IDLE), ("wait", 5), ("shot", "hs_track_click_left")]
s += drag("hs_drag", HS_TRACK, 430, (400, 360, 330), off_x=500)
s += nav("hiscores_out", BACKS["hiscores"])
s += nav("weapons_in", STATS["weapons"]) + hover("weapons_row_2", (DB_ROW[0], DB_ROW[1] + 2 * 16))
s += drag("weapons_drag", DB_TRACK, 340, (400, 440, 480))
s += nav("weapons_out", BACKS["weapons"])
s += nav("perks_in", STATS["perks"]) + hover("perks_row_4", (DB_ROW[0], DB_ROW[1] + 4 * 16))
s += [("click", DB_TRACK, 470), ("wait", 5), ("shot", "perks_track_click"), ("move", *IDLE), ("wait", 5), ("shot", "perks_track_click_left")]
s += [("key", "KEY_PAGE_UP"), ("wait", 5), ("shot", "perks_page_up")]
s += nav("perks_out", BACKS["perks"])
STEPS = s
