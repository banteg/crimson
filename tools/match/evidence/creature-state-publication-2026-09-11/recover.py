"""Reconstruct the four source edits from the pinned preceding candidate."""


def stages(before):
    zero = """                                creature_pool[creature_index].vel_x = 0.0f;
                                creature_pool[creature_index].vel_y = 0.0f;"""
    assert before.count(zero) == 2
    publication = before.replace(zero, """                                creature_pool[creature_index].vel_x =
                                    creature_pool[creature_index].vel_y = 0.0f;""", 1)
    hold = """                                    creature_pool[creature_index].orbit_radius.radius -= frame_dt;
                                    creature_pool[creature_index].target_x = position->x;
                                    creature_pool[creature_index].target_y = position->y;"""
    assert publication.count(hold) == 1
    publication = publication.replace(hold, """                                    creature_pool[creature_index].target_x = position->x;
                                    creature_pool[creature_index].target_y = position->y;
                                    creature_pool[creature_index].orbit_radius.radius -= frame_dt;""")
    movement = publication
    for indent in (" " * 36, " " * 32):
        for trig in ("cos", "sin"):
            old = (f"(float){trig}(movement_heading) * frame_dt * move_scale\n"
                   f"{indent}* creature_pool[creature_index].move_speed * 30.0f")
            new = ("30.0f * creature_pool[creature_index].move_speed\n"
                   f"{indent}* (move_scale * (frame_dt * (float){trig}(movement_heading)))")
            assert movement.count(old) == 1
            movement = movement.replace(old, new)
    reciprocal = """    float reciprocal = 1.0f / (float)sqrt(
        value.x * value.x + value.y * value.y);
    return 1.0f / reciprocal;"""
    assert movement.count(reciprocal) == 1
    recovered = movement.replace(reciprocal, """    float length = (float)sqrt(value.x * value.x + value.y * value.y);
    return length;""")
    return {"before": before, "publication": publication, "movement": movement, "recovered": recovered}
