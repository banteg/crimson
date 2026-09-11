"""Recover effect-template initialization order and scaled decal vector values."""


def recover(source, *, flags=True, scales=(1,)):
    if flags:
        before = """                                    effect_template.color = effect_color;
                                    effect_template.flags = 0x59;"""
        after = """                                    effect_template.flags = 0x59;
                                    effect_template.color = effect_color;"""
        assert source.count(before) == 1
        source = source.replace(before, after)
    for index in scales:
        scale = {1: "1.5f", 2: "2.0f", 3: "2.5f"}[index]
        before = f"""                                            vec2f_t decal_pos_{index} = {{
                                                creature_pos->x
                                                    + offset_x * {scale},
                                                creature_pos->y
                                                    + offset_y * {scale},
                                            }};
                                            fx_queue_add_random(&decal_pos_{index});"""
        after = f"""                                            vec2f_t decal_offset_{index} = {{
                                                offset_x * {scale},
                                                offset_y * {scale},
                                            }};
                                            vec2f_t decal_pos_{index} = {{
                                                creature_pos->x + decal_offset_{index}.x,
                                                creature_pos->y + decal_offset_{index}.y,
                                            }};
                                            fx_queue_add_random(&decal_pos_{index});"""
        assert source.count(before) == 1
        source = source.replace(before, after)
    return source
