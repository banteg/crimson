from __future__ import annotations

import ast
from pathlib import Path


def _direct_creature_apply_damage_calls(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "creature_apply_damage":
            lines.append(int(node.lineno))
    return lines


def test_runtime_damage_paths_use_lethal_followup_helper() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src" / "crimson"
    allowed = {
        src_root / "creatures" / "damage.py",
    }

    offenders: list[str] = []
    for path in src_root.rglob("*.py"):
        if path in allowed:
            continue
        lines = _direct_creature_apply_damage_calls(path)
        if not lines:
            continue
        offenders.append(f"{path}:{','.join(str(line) for line in lines)}")

    assert not offenders, "Direct creature_apply_damage callsites found in runtime code: " + "; ".join(offenders)
