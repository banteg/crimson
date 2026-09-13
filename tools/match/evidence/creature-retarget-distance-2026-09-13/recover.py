"""Recover the four target-selection distance calls from the canonical source."""

BEFORE_SHA = "d7136f28e4aae58932dd6368b837d5769f2d13f1388faada97e571bc06b14d4f"
HELPER = """static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    float distance_sq = dx * dx;
    distance_sq += dy * dy;
    float distance = (float)sqrt(distance_sq);
    return distance;
}

"""
EDITS = [
    (
        """                    distance = creature_vec2_length(
                        *(creature_vec2_t *)&player_state_table[
                            current_player_index
                        ].position
                        - *(creature_vec2_t *)position);""",
        """                    distance = vec2_distance(
                        &player_state_table[current_player_index].position,
                        position);""",
    ),
    (
        """                                dx = alternate_pos->x - position->x;
                                dy = alternate_pos->y - position->y;
                                alternate_distance = (float)sqrt(dx * dx + dy * dy);""",
        """                                alternate_distance = vec2_distance(alternate_pos, position);""",
    ),
    (
        """                            dx = player_state_table[0].position.x - position->x;
                            dy = player_state_table[0].position.y - position->y;
                            alternate_distance = (float)sqrt(dx * dx + dy * dy);""",
        """                            alternate_distance = vec2_distance(
                                &player_state_table[0].position,
                                position);""",
    ),
    (
        """                        dx = player_state_table[0].position.x
                            - creature_pool[player_state_table[current_player_index].auto_target].pos_x;
                        dy = player_state_table[0].position.y
                            - creature_pool[player_state_table[current_player_index].auto_target].pos_y;
                        if (alternate_distance < (float)sqrt(dx * dx + dy * dy)) {""",
        """                        if (alternate_distance < vec2_distance(
                                &player_state_table[0].position,
                                &creature_pool[
                                    player_state_table[current_player_index].auto_target
                                ].position)) {""",
    ),
]


def stages(before):
    s = before.replace("inline float creature_vec2_length", HELPER + "inline float creature_vec2_length")
    rows = {"before": before}
    for (a, b), name in zip(EDITS, ["initial-distance", "alternate-distance", "solo-distance", "recovered"]):
        assert s.count(a) == 1
        s = s.replace(a, b)
        rows[name] = s
    return rows
