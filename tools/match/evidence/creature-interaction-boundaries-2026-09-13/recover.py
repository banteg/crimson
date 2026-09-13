"""Reconstruct the three independently measured creature-interaction changes."""

import re

BEFORE_SHA256 = "c5bce487a3bb6a0b890b33cd9af9ff273a1ef45db1e42c19ac330b1b2e3159b2"


def stages(before):
    old = """                        dx = position->x - player_state_table[current_player_index].position.x;
                        dy = position->y - player_state_table[current_player_index].position.y;
                        distance = (float)sqrt(dx * dx + dy * dy);"""
    new = """                        distance = creature_vec2_length(
                            *(creature_vec2_t *)position
                            - *(creature_vec2_t *)&player_state_table[
                                current_player_index
                            ].position);"""
    assert before.count(old) == 1
    helper = before.replace(old, new)
    begin = helper.index("                        signed char *target_player =")
    end = helper.index("                    } else if (*lifecycle_stage > 0.0f)", begin)
    part = re.sub(r"\bdistance\b", "interaction_distance", helper[begin:end])
    part = part.replace(
        "                        interaction_distance =",
        "                        float interaction_distance =",
        1,
    )
    local = helper[:begin] + part + helper[end:]
    begin = local.index("                                    creature_vec2_t contact_delta =")
    end = local.index("                                    D3DXVec2Normalize(", begin)
    part = local[begin:end]
    assert part.count("current_player_index") == 1
    recovered = local[:begin] + part.replace("current_player_index", "(int)*target_player") + local[end:]
    return {"before": before, "length-helper": helper, "distance-local": local, "contact-reload": recovered}
