"""Re-run the five live diagnostic cases with explicit optional tool paths."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from crimson import match as m
from crimson import match_explain as explain


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new directory for full diagnostic bundles")
    parser.add_argument("--objdiff", default="objdiff-cli")
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--asm-differ", type=Path)
    parser.add_argument("--asm-python", default=sys.executable)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    results = []
    for name in (
        "quest_build_spiders_inc", "statistics_update_check_worker", "quest_spawn_timeline_update",
        "projectile_render", "highscore_screen_update",
    ):
        output = args.out / name
        explain.export_scratch(m.DEFAULT_MATCH_ROOT / "scratches" / name, output, m.DEFAULT_MATCH_ROOT, "port")
        summary = explain.compare_bundle(
            output, engine="both", objdiff=args.objdiff, asm_differ=args.asm_differ,
            asm_python=args.asm_python, objdump=args.objdump,
        )
        canonical = json.loads((output / "crimson.json").read_text())
        objdiff = json.loads((output / "objdiff-raw.json").read_text())
        levenshtein = json.loads((output / "levenshtein-raw.json").read_text())
        evidence = {s: json.loads((output / f"{s}-evidence.json").read_text()) for s in ("target", "candidate")}
        percent = next(s["match_percent"] for s in objdiff["left"]["symbols"] if s.get("kind") == "SYMBOL_FUNCTION")
        if name in ("quest_build_spiders_inc", "statistics_update_check_worker"):
            assert percent == 100 and levenshtein["current_score"] == 0, name
        result = {
            "function": name, "canonical_ratio": canonical["match_ratio"],
            "reference_counts": summary["reference_counts"],
            "disagreement_count": len(summary["alignment_disagreements"]),
            "address_group_sizes": {n: [len(g["uses"]) for g in groups] for n, groups in summary["address_hypotheses"].items()},
            "body_sha256": {s: data["body_sha256"] for s, data in evidence.items()},
            "instructions": {s: len(data["instructions"]) for s, data in evidence.items()},
            "self_controls": "passed", "objdiff_percent": percent,
            "levenshtein_penalty": levenshtein["current_score"],
        }
        results.append(result)
        print(name, result["reference_counts"], flush=True)
    explain.write_json(args.out / "results.json", results)


if __name__ == "__main__":
    main()
