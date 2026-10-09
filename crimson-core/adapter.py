"""Modern-compiler adapters, applied to generated copies only."""

import re


def session_only(session, *_original, **_statement):
    return session


def adapt(src, txt, seam=session_only):
    # `seam` decides where a recorded-input seam replaces the original read: the
    # verifier always takes the recording; the game module only inside a session.
    txt = re.sub(r"\bfloat (VEC2_Angle|creature_vec2_angle|projectile_vec2_angle)\s*\(", r"double \1(", txt)
    if 'extern "C" float cos(float angle);' in txt:
        txt = txt.replace("float cos(float angle)", "float cosf(float angle)").replace(
            "float sin(float angle)",
            "float sinf(float angle)",
        )
        txt = txt.replace("cos(angle)", "cosf(angle)").replace("sin(angle)", "sinf(angle)")
    if src.stem.startswith("quest_build_"):
        # VC6 leaves transcendental results wide until their first arithmetic
        # operation. Each following add still rounds at PC24.
        txt = txt.replace("float angle() const", "double angle() const").replace(
            "return (float)atan2(y, x);",
            "return atan2(y, x);",
        )
        # Sweep Stakes and Deja vu spill cosine to F32, keeping sine wide.
        for fn in ("cos", "sin"):
            if fn == "sin":
                txt = txt.replace(f"float angle_{fn} = (float){fn}(angle);", f"double angle_{fn} = {fn}(angle);")
            txt = txt.replace(f"(float)radius * (float){fn}(angle)", f"portable_mul32((float)radius,{fn}(angle))")
        txt = re.sub(
            r"\(float\)(cos|sin)\((.*?)\)\s*\*\s*(radius|[0-9.]+f)",
            lambda m: f"portable_mul32({m[1]}({m[2]}),{m[3]})",
            txt,
            flags=re.DOTALL,
        )
    if src.stem == "creature_update_all":
        # 0x00426b93: `fpatan` feeds the `fadd` of 1.5707964f directly; the heading rounds once.
        for expression, wide in (
            ("return (float)atan2(value.y, value.x);", "return atan2(value.y, value.x);"),
            ("float desired_heading = creature_vec2_angle(", "double desired_heading = creature_vec2_angle("),
        ):
            if txt.count(expression) != 1:
                raise ValueError("Audit the creature target-heading boundary before changing this adapter")
            txt = txt.replace(expression, wide)
        # Every `fcos`/`fsin` here feeds its first `fmul` wide. Movement multiplies left to right from the
        # cosine: dt, move_scale, move_speed, then 30 (0x00426cb9), unlike the source's grouping.
        txt, count = re.subn(
            r"30\.0f \* creatures\[creature_index\]\.move_speed\s*"
            r"\* \(move_scale \* \(frame_dt \* \(float\)(cos|sin)\(movement_heading\)\)\)",
            r"portable_mul32(\1(movement_heading), frame_dt) * move_scale"
            r" * creatures[creature_index].move_speed * 30.0f",
            txt,
        )
        if count != 4:
            raise ValueError("Audit creature movement trig order before changing this adapter")
        txt, count = re.subn(
            r"\(float\)(cos|sin)\((\w+)\)\s*\*\s*([\w.\[\]]+)",
            r"portable_mul32(\1(\2), \3)",
            txt,
        )
        if count != 12:
            raise ValueError("Audit creature trig boundaries before changing this adapter")
    if src.stem == "projectile_update":
        for fn in ["cos", "sin"]:
            txt = txt.replace(
                "(float)" + fn + "(heading) * frame_dt * 20.0f",
                "(float)(" + fn + "(heading) * frame_dt) * 20.0f",
            )
        # Seeker steering keeps the trig result wide into its first multiply as well.
        txt, count = re.subn(
            r"\(float\)(cos|sin)\(secondary->angle - 1\.5707964f\) \* frame_dt \* 800\.0f",
            r"(float)(\1(secondary->angle - 1.5707964f) * frame_dt) * 800.0f",
            txt,
        )
        if count != 4:
            raise ValueError("Audit seeker steering trig boundaries before changing this adapter")
        # A cast trig result multiplied directly stays wide into that multiply (e.g. the hit jitter at
        # 0x004211da, the particle velocities at 0x0042219f); stored ones are spilled (0x00421dfe).
        txt, count = re.subn(r"\(float\)(cos|sin)\(([^()]+)\) \* ([\w.]+)", r"portable_mul32(\1(\2), \3)", txt)
        if count != 14:
            raise ValueError("Audit projectile trig boundaries before changing this adapter")
        # 0x004212e5: the chain link's `fpatan` stays wide; each subtraction rounds.
        for expression, wide in (
            ("float chain_angle\n", "double chain_angle\n"),
            ("= (float)atan2f(next_position->y", "= atan2f(next_position->y"),
            ("chain_angle - 1.5707964f - 3.1415927f,", "(float)(chain_angle - 1.5707964f) - 3.1415927f,"),
        ):
            if txt.count(expression) != 1:
                raise ValueError("Audit the shock chain link angle before changing this adapter")
            txt = txt.replace(expression, wide)
    if src.stem in ("creature_handle_death", "creature_update_all", "perks_update_effects", "survival_spawn_creature"):
        # `fild` loads the int XP exactly and only the first PC24 operation rounds (kills 0x0041eb5b, Radioactive
        # 0x0042704b, Jinxed 0x004070a6); converting to float first rounds it too, which past 2^24 drifts.
        txt, adds = re.subn(
            r"\(int\)\(\s*\(float\)player_state_table\[0\]\.experience\b",
            "(int)(float)((double)player_state_table[0].experience",
            txt,
        )
        txt, muls = re.subn(
            r"\(float\)player_state_table\[0\]\.experience \* 0\.00125f",
            "portable_mul32((double)player_state_table[0].experience, 0.00125f)",
            txt,
        )
        expected = {"creature_handle_death": (2, 0), "creature_update_all": (2, 0), "perks_update_effects": (1, 0)}
        if (adds, muls) != expected.get(src.stem, (0, 1)):
            raise ValueError("Audit the exact XP load boundaries before changing this adapter")
    if src.stem == "player_update_heading":
        # Regression Bullets: `fild` the XP, `fsubp` the PC24 cost, then `_ftol`.
        txt, count = re.subn(
            r"player->experience = player->experience\s*- (weapon_table\[player->weapon_id\]\.reload_time \* [0-9.]+f);",
            r"player->experience = (int)(float)((double)player->experience - \1);",
            txt,
        )
        if count != 2:
            raise ValueError("Audit the Regression Bullets XP boundary before changing this adapter")
    if src.stem == "perk_apply":
        # Grim Deal: `fild` the XP into the PC24 multiply.
        expression = "(int)(player_experience * 0.18f)"
        if txt.count(expression) != 1:
            raise ValueError("Audit the Grim Deal XP boundary before changing this adapter")
        txt = txt.replace(expression, "(int)portable_mul32((double)player_experience, 0.18f)")
    if src.stem in ("input_aim_pov_left_active", "input_aim_pov_right_active"):
        # A replay records the POV hat as its two turn flags, which can both be held.
        side = src.stem.split("_")[3]
        expression = f"grim_interface_ptr->grim_get_joystick_pov(0)\n        == config_blob.aim_pov_{side}"
        if txt.count(expression) != 1:
            raise ValueError("Audit the POV aim seam before changing this adapter")
        txt = '#include "api.h"\n' + txt.replace(expression, seam(f"portable_aim_turn_{side}()", expression))
    if src.stem == "bonus_apply":
        # 0x00409e0b: the first link's `fpatan` stays wide; each subtraction rounds.
        expression = "(float)atan2(dy, dx) - 1.5707964f - 3.1415927f,"
        if txt.count(expression) != 1:
            raise ValueError("Audit the shock chain angle before changing this adapter")
        txt = txt.replace(expression, "(float)(atan2(dy, dx) - 1.5707964f) - 3.1415927f,")
    if src.stem == "player_update_heading":
        # Mouse aim is recorded as a canonical world point. Reconstructing a
        # screen point and subtracting the camera again can lose one F32 ULP.
        for axis in ("x", "y"):
            expression = f"mouse_screen->{axis} - camera_offset_{axis}"
            if txt.count(expression) != 1:
                raise ValueError("Audit the normalized world-aim seam before changing this adapter")
            txt = txt.replace(expression, seam(f"portable_aim_{axis}()", expression))
        # Pad aim is recorded as the stick's reach (0x0041539e..0x004153ba); it
        # still lands on the position movement just produced.
        txt, count = re.subn(
            r"scalar = grim_interface_ptr->grim_get_config_float\(\s*player->input\.axis_aim_y\);.*?"
            r"(\*\(vec2_t \*\)&player->aim = )pad \* distance( \+ \*\(vec2_t \*\)&player->position;)",
            lambda m: seam(f"{m[1]}vec2_t(portable_aim_x(), portable_aim_y()){m[2]}", m[0], statement=True),
            txt,
            flags=re.DOTALL,
        )
        if count != 1:
            raise ValueError("Audit the pad-aim reach seam before changing this adapter")
        # Point-click movement records the move target the reload key and cursor set
        # (0x00413f5e); it reaches the scheme the way Python's replay carries it.
        expression = """            if (grim_interface_ptr->grim_is_key_active(config_key_reload)) {
                vec2_t target =
                    *(vec2_t *)&player_aim_screen_x[current_player_index * 2]
                    - *(vec2_t *)&camera_offset_x;
                *(vec2_t *)&player->move_target = target;
            }"""
        if txt.count(expression) != 1:
            raise ValueError("Audit the point-click move target seam before changing this adapter")
        txt = txt.replace(
            expression,
            seam(
                "            *(vec2_t *)&player->move_target = vec2_t(portable_move_x(), portable_move_y());",
                expression,
                statement=True,
            ),
        )
        txt = '#include "api.h"\n' + txt
        # FCOS/FSIN remain wide until the first FMUL (e.g. 0x00414335).
        # Subsequent multipliers must still round after every PC24 operation.
        txt, count = re.subn(
            r"(cosf|sinf)\(player->heading - 1\.5707964f\)\s*\*\s*player->move_speed",
            lambda m: f"portable_mul32({m[1][:-1]}(player->heading - 1.5707964f), player->move_speed)",
            txt,
        )
        if count != 22:
            raise ValueError("Audit player movement trig boundaries before changing this adapter")
        # The shot and Fire Cough spreads feed their wide trig into the first multiply too (0x00415cb2, 0x00413b61).
        txt, count = re.subn(
            r"(cosf|sinf)\(spread_angle\) \* (spread_distance|spread_radius)",
            lambda m: f"portable_mul32({m[1][:-1]}(spread_angle), {m[2]})",
            txt,
        )
        if count != 4:
            raise ValueError("Audit shot spread trig boundaries before changing this adapter")
        # The 60-unit aim point keeps FCOS wide into its multiply but stores FSIN first (0x00415427, 0x00415576,
        # 0x00415606).
        txt, count = re.subn(
            r"vec2_t direction\(cosf\((player->aim_heading - 1\.5707964f)\), sinf\(\1\)\);"
            r"(\s*\*\(vec2_t \*\)&player->aim = )direction \* 60\.0f( \+ \*\(vec2_t \*\)&player->position;)",
            r"vec2_t reach(portable_mul32(cos(\1), 60.0f), sinf(\1) * 60.0f);\2reach\3",
            txt,
        )
        if count != 3:
            raise ValueError("Audit the aim point trig boundaries before changing this adapter")
    if src.stem == "gameplay_update_and_render":
        txt = txt.replace("void console_input_poll(void);", "int console_input_poll(void);")
        txt = txt.replace("pow(", "portable_crt_pow_pc24(")
    if src.stem == "gameplay_reset_state":
        txt = txt.replace("void player_reset_all(void);", 'extern "C" void player_reset_all(void);')
    # VC6 permits mutable references to value temporaries; these operators never mutate their arguments.
    txt = (
        re.sub(r"(?m)^(extern )?(void|int|float|unsigned char|bool|bonus_id_t) (\w+)\(", r'extern "C" \2 \3(', txt)
        if src.suffix == ".c"
        else txt
    )
    txt = re.sub(r"(?<!const )\b([A-Za-z_][A-Za-z_0-9]*_t) &([A-Za-z_][A-Za-z_0-9]*)\)", r"const \1 &\2)", txt)
    for math in ["sin", "cos", "atan2", "pow", "sinf", "cosf", "atan2f"]:
        txt = re.sub(r"\b" + math + r"\(", "portable_" + math + "(", txt)
    return '#include "portable_math.h"\n' + txt
