"""Modern-compiler adapters, applied to generated copies only."""

import re


def adapt(src, txt):
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
    if src.stem == "projectile_update":
        for fn in ["cos", "sin"]:
            txt = txt.replace(
                "(float)" + fn + "(heading) * frame_dt * 20.0f",
                "(float)(" + fn + "(heading) * frame_dt) * 20.0f",
            )
    if src.stem == "player_update_heading":
        # Replay aim is already canonical world space. Reconstructing a screen
        # point and subtracting the camera again can lose one F32 ULP.
        for axis in ("x", "y"):
            expression = f"mouse_screen->{axis} - camera_offset_{axis}"
            if txt.count(expression) != 1:
                raise ValueError("Audit the normalized world-aim seam before changing this adapter")
            txt = txt.replace(expression, f"portable_world_aim_{axis}()")
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
