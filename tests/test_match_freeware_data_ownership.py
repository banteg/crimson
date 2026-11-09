from __future__ import annotations

import json
import re

from crimson_re import match, match_builds, match_freeware_data_ownership


def test_freeware_owner_requires_mapped_name_and_consistent_providers() -> None:
    image = match_builds.load_registry().image("1.4.0", "crimson.exe")
    catalog = match_freeware_data_ownership.LabelOwnership(image)
    state, = catalog.placed["freeware_aim_screen"]
    sdk, = catalog.placed["IID_IGraphBuilder"]
    assert catalog.lookup(state, ["freeware_aim_screen"])[0] == "game"
    assert catalog.lookup(sdk, ["IID_IGraphBuilder"])[0] == "libraries"
    assert catalog.lookup(state, ["IID_IGraphBuilder"]) == ("unknown", [])
    assert catalog.lookup(state + 1, ["freeware_aim_screen"]) == ("unknown", [])
    assert catalog.lookup(state, ["freeware_unknown"]) == ("unknown", [])

    catalog.placed["second_provider"] = {state}
    catalog.by_name["second_provider"] = {("libraries", "test.cpp")}
    owner, paths = catalog.lookup(state, ["freeware_aim_screen", "second_provider"])
    assert owner == "unknown" and "test.cpp" in paths
    catalog.placed["freeware_aim_screen"].add(state + 8)
    assert catalog.lookup(state, ["freeware_aim_screen"]) == ("unknown", [])


def test_reviewed_freeware_names_have_source_evidence() -> None:
    plan = json.loads((match.REPO_ROOT / match_freeware_data_ownership.FREEWARE).read_text())
    seen = set()
    for group in plan["groups"]:
        source = match.REPO_ROOT / group["source"]
        assert source.is_file()
        assert group["names"]
        if "basis" not in group:
            assert set(group["names"]) <= set(re.findall(r"[a-zA-Z_]\w*", source.read_text()))
        for name in group["names"]:
            key = group["image"], name
            assert key not in seen
            seen.add(key)
