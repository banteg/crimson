"""Reconstruct the two corpse half-size vector boundaries independently."""

BEFORE_SHA256 = "ed2a2eda566b9ca39651ccbf3d1dcf75b3ee65c5b5b74dd160ff909642d3ea68"


def stages(before):
    old = """creature_vec2_t(
                                            position->x - corpse_size * 0.5f,
                                            position->y - corpse_size * 0.5f)"""
    new = """*(creature_vec2_t *)position
                                            - creature_vec2_t(
                                                corpse_size * 0.5f,
                                                corpse_size * 0.5f)"""
    assert before.count(old) == 1
    ordinary = before.replace(old, new)
    old = """                                    float corpse_half_size =
                                        creature_pool[creature_index].size * 0.5f;"""
    new = """                                    float corpse_width =
                                        creature_pool[creature_index].size;"""
    assert ordinary.count(old) == 1
    both = ordinary.replace(old, new)
    old = """creature_vec2_t(
                                            position->x - corpse_half_size,
                                            position->y - corpse_half_size)"""
    new = """*(creature_vec2_t *)position
                                            - creature_vec2_t(
                                                corpse_width * 0.5f,
                                                corpse_width * 0.5f)"""
    assert both.count(old) == 1
    both = both.replace(old, new)
    first = both.index("                                    float corpse_width =")
    last = both.index("                                if (!corpse_queued)", first)
    block = both[first:last]
    block = block.replace(
        "                                    corpse_queued = fx_queue_add_rotated(",
        "                                    float corpse_heading =\n"
        "                                        creature_pool[creature_index].heading;\n"
        "                                    corpse_queued = fx_queue_add_rotated(",
    ).replace(
        "                                        creature_pool[creature_index].heading,",
        "                                        corpse_heading,",
    )
    recovered = both[:first] + block + both[last:]
    return {"before": before, "ordinary-vector": ordinary, "both-vectors": both, "recovered": recovered}
