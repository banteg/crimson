"""Execute native post-jitter audio and freeze shards against the Python world path."""

import argparse
import collections
import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[4]
PARENT = Path(__file__).resolve().parent.parent / "primary-impact-presentation-2026-09-11"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PARENT))

from execute import Program, match, run, unicorn

spec = importlib.util.spec_from_file_location("primary_parent_verify", PARENT / "verify.py")
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    image_sha = parent.sha(match.default_image_path().read_bytes())
    assert image_sha == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    source = ROOT / "crimson-zig/src/runtime/testdata/primary-impact-presentation.json"
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    assert source_sha == "7a7b5f27b414cf279e88e47d72f43ab9ff71f15471ed5748950ab8a0289ca98a"
    parent_sources = {
        "execute.py": "3f4cb71371d70d787b922eea8eb2622efcbe72a89dd4fcaf1926de86d711b291",
        "fixtures.py": "26dee3d1eceed0085519b007462cd7bcc92dc70d5f77d32d2a820f9c3b461546",
        "verify.py": "98f25915e2096d7cefec6bd08cbe79dfbb98083410a105854959d898162713ab",
    }
    for name, expected in parent_sources.items():
        assert parent.sha((PARENT / name).read_bytes()) == expected
    program = Program(match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update"), integrated=True)
    manifest = match.load_function_manifest(scope="all")
    _, start, end = match.resolve_function(manifest, "effect_spawn_freeze_shard")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    program.helpers["effect_spawn_freeze_shard"] = (
        start,
        {i.address for i in md.disasm(program.image.function_bytes(start, end), start)},
    )
    witnesses = []
    digests = []
    coverage = set()
    candidate_counts = collections.Counter()
    originals = json.loads(source.read_text())
    for projectile_type in (1, 19):
        for original in originals:
            for freeze in (0.0, 1.0):
                case = copy.deepcopy(original["input"])
                case["freeze"] = freeze
                case["primary"][0]["type"] = projectile_type
                if projectile_type == 19:
                    case["damage_scale"] = 1.0
                trace = run(program, True, case)
                candidate = run(program, False, case)
                for key in ("state", "scalars", "calls", "rng_state", "writes"):
                    candidate_counts[key + "_differences"] += trace[key] != candidate[key]
                    assert trace[key] == candidate[key], (len(witnesses), key)
                witness = parent.witness(len(witnesses), case, trace)
                witness["parent_index"] = original["index"]
                calls = [call for call in trace["calls"] if call[0] == "sfx_play_panned"]
                assert len(calls) == 1 and 0 <= calls[0][1] < 6
                witness["expected"]["audio"] = [
                    {"sfx_id": f"sfx_bullet_hit_{call[1] + 1:02}", "position": call[2], "gain": call[3]}
                    for call in calls
                ]
                witnesses.append(witness)
                digests.append(parent.observation_digest(trace))
                coverage.update(trace["coverage"])
    data = (json.dumps(witnesses, indent=2) + "\n").encode()
    (out / "witnesses.json").write_bytes(data)
    result = {
        "cases": len(witnesses),
        "native_image_sha256": image_sha,
        "parent_fixtures_sha256": source_sha,
        "parent_engine_sha256": parent.sha((PARENT / "execute.py").read_bytes()),
        "parent_sources_sha256": parent_sources,
        "witnesses_sha256": parent.sha(data),
        "native_observation_digests": digests,
        "native_coverage": sorted(coverage),
        "freeze_helper": {"entry": start, "instructions": len(program.helpers["effect_spawn_freeze_shard"][1])},
        "template_scale_reset": parent.template_scale_reset_proof(program),
        "candidate": {
            "source_sha256": parent.sha((program.config.directory / program.config.source).read_bytes()),
            "ratio": program.result.ratio,
            "instructions": len(program.result.candidate_disassembly),
            "reference_ok": program.result.masked_operand_audit.ok_count,
            "reference_problems": program.result.masked_operand_audit.problem_count,
            "exact": program.result.exact,
            "body_byte_exact": program.result.body_byte_exact,
            "comparison_counts": dict(candidate_counts),
        },
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("cases", "witnesses_sha256")}), flush=True)


if __name__ == "__main__":
    main()
