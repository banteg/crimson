"""Recompile the exact HUD, its predecessor, and bounded source reversions."""

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
CURRENT_SHA = "32bbe80fa55747d431ab5be9b004b157af9f94a5b7b8feea5c6cf80763eab5ca"
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def metrics(result):
    return {
        "ratio": result.ratio,
        "ins": len(result.candidate_lines),
        "prefix": result.prefix_instructions,
        "refs": result.masked_operand_audit.ok_count,
        "problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body": result.body_byte_exact,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/ui_render_hud")
    source = (config.directory / config.source).read_text()
    before = (HERE / "before.cpp").read_text()
    controls = json.loads((HERE / "source-controls.json").read_text())
    assert sha(source.encode()) == CURRENT_SHA
    assert sha(before.encode()) == controls["baseline_sha256"]
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    assert (config.compiler, config.cflags) == (controls["compiler"], controls["cflags"])

    def compile_source(name, text):
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(text)
        obj = match.compile_scratch(replace(config, directory=directory), force=True)
        result = match.run_match(
            obj_path=obj,
            function=config.function,
            symbol_name=config.symbol,
            reference_aliases=config.reference_aliases,
        )
        return obj, result

    obj, current = compile_source("current", source)
    assert metrics(current) == {
        "ratio": 1.0,
        "ins": 1824,
        "prefix": 1824,
        "refs": 393,
        "problems": 0,
        "exact": True,
        "body": True,
    }
    current_payload = match.match_result_payload(current)
    assert sum(line.size for line in current.target_disassembly) == 7081
    assert sum(line.size for line in current.candidate_disassembly) == 7081
    assert current.target_padding_bytes == current.candidate_padding_bytes == 0
    assert current.body_byte_mismatches == ()
    current_payload["encoded_body_bytes"] = 7081
    current_payload["native_start"] = current.target_disassembly[0].address
    current_payload["native_end"] = current.target_disassembly[-1].address + current.target_disassembly[-1].size
    _, baseline = compile_source("before", before)
    assert metrics(baseline) == {
        "ratio": 0.9221491228070176,
        "ins": 1824,
        "prefix": 42,
        "refs": 393,
        "problems": 0,
        "exact": False,
        "body": False,
    }

    rows = []
    for control in controls["controls"]:
        lines = before.splitlines(keepends=True)
        previous = len(lines)
        for edit in reversed(control["edits"]):
            start, stop = edit["start"], edit["stop"]
            assert 0 <= start <= stop <= previous
            assert "".join(lines[start:stop]) == edit["old"]
            lines[start:stop] = edit["new"].splitlines(keepends=True)
            previous = start
        text = "".join(lines)
        assert sha(text.encode()) == control["source_sha256"]
        _, result = compile_source(control["name"], text)
        observed = metrics(result)
        assert observed == control["observed"], (control["name"], observed)
        rows.append({"name": control["name"], "source_sha256": sha(text.encode()), "observed": observed})
    assert len(rows) == 18 and sum(row["observed"]["exact"] for row in rows) == 1

    changed = source.replace("0.0f, 0.0f, 512.0f, 64.0f", "0.0f, 0.0f, 511.0f, 64.0f", 1)
    assert changed != source
    _, wrong_width = compile_source("negative-panel-width", changed)
    assert not wrong_width.exact and not wrong_width.body_byte_exact
    withheld = match.run_match(obj_path=obj, function=config.function, symbol_name=config.symbol, reference_aliases=())
    assert withheld.masked_operand_audit.problem_count > 0 and not withheld.exact

    receipt = {
        "kind": "hud-exact-source-and-reference-proof",
        "source_sha256": CURRENT_SHA,
        "before_source_sha256": sha(before.encode()),
        "image_sha256": IMAGE_SHA,
        "compiler": config.compiler,
        "cflags": config.cflags,
        "reference_aliases": config.reference_aliases,
        "current_object_sha256": sha(obj.read_bytes()),
        "current": current_payload,
        "before": metrics(baseline),
        "controls": rows,
        "negative_panel_width": metrics(wrong_width),
        "negative_withheld_references": metrics(withheld),
        "controls_sha256": sha((HERE / "source-controls.json").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "scope": "Native code and reference identity; no new GPU or finite execution claim.",
    }
    (out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Verified exact HUD, 18 source controls, changed-width rejection, and withheld-reference rejection")


if __name__ == "__main__":
    main()
