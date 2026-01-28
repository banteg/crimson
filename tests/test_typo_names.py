from __future__ import annotations

from grim.rand import Crand

from crimson.typo.names import CreatureNameTable, NAME_MAX_CHARS


def test_creature_name_table_assign_random_unique_and_bounded() -> None:
    table = CreatureNameTable.sized(32)
    active = [True] * 32
    rng = Crand(0x1234)

    for idx in range(20):
        name = table.assign_random(idx, rng, score_xp=130, active_mask=active)
        assert name
        assert len(name) < NAME_MAX_CHARS

    assert len(set(table.names[:20])) == 20


def test_creature_name_table_find_by_name_active_only() -> None:
    table = CreatureNameTable.sized(4)
    table.names[0] = "alpha"
    table.names[1] = "beta"
    table.names[2] = "gamma"

    assert table.find_by_name("beta", active_mask=[True, True, True, True]) == 1
    assert table.find_by_name("beta", active_mask=[True, False, True, True]) is None
    assert table.find_by_name("missing", active_mask=[True, True, True, True]) is None


def test_creature_name_table_clear_removes_name() -> None:
    table = CreatureNameTable.sized(3)
    table.names[1] = "beta"
    table.clear(1)
    assert table.names[1] == ""

