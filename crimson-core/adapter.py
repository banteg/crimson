"""Adapt generated copies of the recovered sources; `decomp/` stays untouched.

Each source is read as `decomp/` has it and changed in two steps:

1. Diffs make the edits that belong to one place. Each folder a target applies (DIFFS, and game.GAME_DIFFS) holds
   unified diffs against the recovered files, named by their paths from the repository root. A hunk matches by its
   exact old text, which must occur once; line numbers only say where it was written.
2. Passes make the edits a rule decides: the x87 boundaries below, each expecting its number of sites, then the
   dialect a modern compiler needs everywhere.

Diffs come first, so they read against the source of truth and the code they add takes the same rules.
"""

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
# abi/: compiler repairs at one place; seams/: where the recording replaces a live read;
# optimizations/: behavior-preserving performance changes; patches/: the ranked rules,
# where `patches/NN-*.patch` fixes original bug NN of docs/rewrite/original-bugs.md behind `portable_preserve_bugs`.
DIFFS = (HERE / "abi", HERE / "seams", HERE / "optimizations", HERE / "patches")
_HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
# C files give their functions C linkage, except where the header their callers use declares C++ (the resource reader):
# a lookahead for the definitions' names.
NOT_CPP_LINKAGE = r"(?!resource_pack_read_cstring\()"
# Signatures the recovered files disagree on, as their definitions have them; every declaration takes its definition's.
PROTOTYPES = {
    "void console_input_poll(void);": "int console_input_poll(void);",
    "void player_reset_all(void);": 'extern "C" void player_reset_all(void);',
}


def load_diffs(folders):
    """(patch name, old text, new text) hunks by source path, in folder then name order."""

    hunks = {}
    for patch in (path for folder in folders for path in sorted(folder.glob("*.patch"))):
        lines = patch.read_text().splitlines(keepends=True)
        rel = None
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            if line.startswith("+++ "):
                rel = line[4:].split()[0].removeprefix("b/")
                continue
            match = _HUNK.match(line)
            if not match:
                continue
            old_count, new_count = (int(n) if n is not None else 1 for n in match.groups())
            old, new = [], []
            while len(old) < old_count or len(new) < new_count:
                tag, body = lines[i][:1], lines[i][1:]
                i += 1
                if tag in " -":
                    old.append(body)
                if tag in " +":
                    new.append(body)
            if rel is None:
                raise SystemExit(f"{patch.name}: hunk before a +++ header")
            hunks.setdefault(rel, []).append((patch.name, "".join(old), "".join(new)))
    return hunks


def apply_diffs(rel, txt, hunks):
    for name, old, new in hunks.get(rel, ()):
        if txt.count(old) != 1:
            raise SystemExit(f"{name}: hunk for {rel} matches {txt.count(old)} times; audit the patch")
        txt = txt.replace(old, new)
    return txt


def replace(src, txt, old, new, count=1):
    """Replace `old`, which must occur `count` times; None leaves the count to a rule that applies wherever it can."""

    if count is not None and txt.count(old) != count:
        raise SystemExit(f"Audit {src.name}: {old!r} occurs {txt.count(old)} times, not {count}")
    return txt.replace(old, new)


def sub(src, pattern, repl, txt, count=1, flags=0):
    """re.subn that expects `count` sites; None leaves the count to a rule that applies wherever it can."""

    txt, found = re.subn(pattern, repl, txt, flags=flags)
    if count is not None and found != count:
        raise SystemExit(f"Audit {src.name}: {pattern!r} matches {found} times, not {count}")
    return txt


def prototypes(src, txt, table):
    for old, new in table.items():
        txt = sub(src, rf"(?m)^{re.escape(old)}", new.replace("\\", r"\\"), txt, count=None)
    return txt


def x87(src, txt):
    """The original's x87 evaluation at PC24: where a wide intermediate rounds, as the executable does."""

    txt = sub(src, r"\bfloat (VEC2_Angle|creature_vec2_angle|projectile_vec2_angle)\s*\(", r"double \1(", txt, None)
    if 'extern "C" float cos(float angle);' in txt:
        for fn in ("cos", "sin"):
            txt = replace(src, txt, f"float {fn}(float angle)", f"float {fn}f(float angle)", None)
            txt = replace(src, txt, f"{fn}(angle)", f"{fn}f(angle)", None)
    if src.stem.startswith("quest_build_"):
        # VC6 leaves transcendental results wide until their first arithmetic operation. Each following add still
        # rounds at PC24. These hold across the builders that use them; checks/builder_oracle.py runs every builder.
        txt = replace(src, txt, "float angle() const", "double angle() const", None)
        txt = replace(src, txt, "return (float)atan2(y, x);", "return atan2(y, x);", None)
        # Sweep Stakes and Deja vu spill cosine to F32, keeping sine wide.
        txt = replace(src, txt, "float angle_sin = (float)sin(angle);", "double angle_sin = sin(angle);", None)
        for fn in ("cos", "sin"):
            txt = replace(
                src,
                txt,
                f"(float)radius * (float){fn}(angle)",
                f"portable_mul32((float)radius,{fn}(angle))",
                None,
            )
        txt = sub(
            src,
            r"\(float\)(cos|sin)\((.*?)\)\s*\*\s*(radius|[0-9.]+f)",
            lambda m: f"portable_mul32({m[1]}({m[2]}),{m[3]})",
            txt,
            None,
            re.DOTALL,
        )
    if src.stem == "creature_update_all":
        # 0x00426b93: `fpatan` feeds the `fadd` of 1.5707964f directly; the heading rounds once.
        txt = replace(src, txt, "return (float)atan2(value.y, value.x);", "return atan2(value.y, value.x);")
        txt = replace(
            src,
            txt,
            "float desired_heading = creature_vec2_angle(",
            "double desired_heading = creature_vec2_angle(",
        )
        # Every `fcos`/`fsin` here feeds its first `fmul` wide. Movement multiplies left to right from the
        # cosine: dt, move_scale, move_speed, then 30 (0x00426cb9), unlike the source's grouping.
        txt = sub(
            src,
            r"30\.0f \* creatures\[creature_index\]\.move_speed\s*"
            r"\* \(move_scale \* \(frame_dt \* \(float\)(cos|sin)\(movement_heading\)\)\)",
            r"portable_mul32(\1(movement_heading), frame_dt) * move_scale * creatures[creature_index].move_speed * 30.0f",
            txt,
            4,
        )
        txt = sub(src, r"\(float\)(cos|sin)\((\w+)\)\s*\*\s*([\w.\[\]]+)", r"portable_mul32(\1(\2), \3)", txt, 12)
    if src.stem == "projectile_update":
        for fn in ("cos", "sin"):
            txt = replace(
                src,
                txt,
                f"(float){fn}(heading) * frame_dt * 20.0f",
                f"(float)({fn}(heading) * frame_dt) * 20.0f",
            )
        # Seeker steering keeps the trig result wide into its first multiply as well.
        txt = sub(
            src,
            r"\(float\)(cos|sin)\(secondary->angle - 1\.5707964f\) \* frame_dt \* 800\.0f",
            r"(float)(\1(secondary->angle - 1.5707964f) * frame_dt) * 800.0f",
            txt,
            4,
        )
        # A cast trig result multiplied directly stays wide into that multiply (e.g. the hit jitter at
        # 0x004211da, the particle velocities at 0x0042219f); stored ones are spilled (0x00421dfe).
        txt = sub(src, r"\(float\)(cos|sin)\(([^()]+)\) \* ([\w.]+)", r"portable_mul32(\1(\2), \3)", txt, 14)
        # 0x004212e5: the chain link's `fpatan` stays wide; each subtraction rounds.
        txt = replace(src, txt, "float chain_angle\n", "double chain_angle\n")
        txt = replace(src, txt, "= (float)atan2f(next_position->y", "= atan2f(next_position->y")
        txt = replace(
            src,
            txt,
            "chain_angle - 1.5707964f - 3.1415927f,",
            "(float)(chain_angle - 1.5707964f) - 3.1415927f,",
        )
    if src.stem in ("creature_handle_death", "creature_update_all", "perks_update_effects", "survival_spawn_creature"):
        # `fild` loads the int XP exactly and only the first PC24 operation rounds (kills 0x0041eb5b, Radioactive
        # 0x0042704b, Jinxed 0x004070a6); converting to float first rounds it too, which past 2^24 drifts.
        adds, muls = {
            "creature_handle_death": (2, 0),
            "creature_update_all": (2, 0),
            "perks_update_effects": (1, 0),
        }.get(
            src.stem,
            (0, 1),
        )
        txt = sub(
            src,
            r"\(int\)\(\s*\(float\)player_state_table\[0\]\.experience\b",
            "(int)(float)((double)player_state_table[0].experience",
            txt,
            adds,
        )
        txt = sub(
            src,
            r"\(float\)player_state_table\[0\]\.experience \* 0\.00125f",
            "portable_mul32((double)player_state_table[0].experience, 0.00125f)",
            txt,
            muls,
        )
    if src.stem == "perk_apply":
        # Grim Deal: `fild` the XP into the PC24 multiply.
        txt = replace(
            src,
            txt,
            "(int)(player_experience * 0.18f)",
            "(int)portable_mul32((double)player_experience, 0.18f)",
        )
    if src.stem == "bonus_apply":
        # 0x00409e0b: the first link's `fpatan` stays wide; each subtraction rounds.
        txt = replace(
            src,
            txt,
            "(float)atan2(dy, dx) - 1.5707964f - 3.1415927f,",
            "(float)(atan2(dy, dx) - 1.5707964f) - 3.1415927f,",
        )
    if src.stem == "player_update_heading":
        # Regression Bullets: `fild` the XP, `fsubp` the PC24 cost, then `_ftol`.
        txt = sub(
            src,
            r"player->experience = player->experience\s*- (weapon_table\[player->weapon_id\]\.reload_time \* [0-9.]+f);",
            r"player->experience = (int)(float)((double)player->experience - \1);",
            txt,
            2,
        )
        # FCOS/FSIN remain wide until the first FMUL (e.g. 0x00414335).
        # Subsequent multipliers must still round after every PC24 operation.
        txt = sub(
            src,
            r"(cosf|sinf)\(player->heading - 1\.5707964f\)\s*\*\s*player->move_speed",
            lambda m: f"portable_mul32({m[1][:-1]}(player->heading - 1.5707964f), player->move_speed)",
            txt,
            22,
        )
        # The shot and Fire Cough spreads feed their wide trig into the first multiply too (0x00415cb2, 0x00413b61).
        txt = sub(
            src,
            r"(cosf|sinf)\(spread_angle\) \* (spread_distance|spread_radius)",
            lambda m: f"portable_mul32({m[1][:-1]}(spread_angle), {m[2]})",
            txt,
            4,
        )
        # The 60-unit aim point keeps FCOS wide into its multiply but stores FSIN first (0x00415427, 0x00415576,
        # 0x00415606).
        txt = sub(
            src,
            r"vec2_t direction\(cosf\((player->aim_heading - 1\.5707964f)\), sinf\(\1\)\);"
            r"(\s*\*\(vec2_t \*\)&player->aim = )direction \* 60\.0f( \+ \*\(vec2_t \*\)&player->position;)",
            r"vec2_t reach(portable_mul32(cos(\1), 60.0f), sinf(\1) * 60.0f);\2reach\3",
            txt,
            3,
        )
    if src.stem == "gameplay_update_and_render":
        txt = replace(src, txt, "pow(", "portable_crt_pow_pc24(")
    return txt


def dialect(src, txt):
    """What a modern compiler needs from VC6 sources, wherever it applies."""

    txt = prototypes(src, txt, PROTOTYPES)
    if src.suffix == ".c":
        txt = sub(
            src,
            rf"(?m)^(extern )?(void|int|float|unsigned char|bool|bonus_id_t) {NOT_CPP_LINKAGE}(\w+)\(",
            r'extern "C" \2 \3(',
            txt,
            None,
        )
    # VC6 binds mutable references to value temporaries; the operators and helpers taking them never mutate through
    # them. List widgets are the exception: helpers take one to update it.
    txt = sub(src, r"(?<!const )\b(?!ui_list_widget_t\b)([A-Za-z_]\w*_t) &(\w+)\)", r"const \1 &\2)", txt, None)
    for fn in ("sin", "cos", "atan2", "pow", "sinf", "cosf", "atan2f"):
        txt = sub(src, rf"\b{fn}\(", f"portable_{fn}(", txt, None)
    return txt


def adapt(src, txt):
    return dialect(src, x87(src, txt))
