"""Reconstruct the bronze-grid branch attachment without changing its body."""


def recover(before):
    old = "                } else if (template_id == SPAWN_ID_FORMATION_GRID_ALIEN_BRONZE_18) {"
    new = "                }\n\n    if (template_id == SPAWN_ID_FORMATION_GRID_ALIEN_BRONZE_18) {"
    assert before.count(old) == 1
    source = before.replace(old, new)
    old = "    }\n\n    if (template_id == SPAWN_ID_SPIDER_SP2_SPLITTER_01) {"
    new = "    } else if (template_id == SPAWN_ID_SPIDER_SP2_SPLITTER_01) {"
    assert source.count(old) == 1
    return source.replace(old, new)
