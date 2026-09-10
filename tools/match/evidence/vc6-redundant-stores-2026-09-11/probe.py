"""Reproduce the stock-VC6 redundant initialization-store controls."""

import argparse
import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from crimson import match


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    config = match.load_scratch_config(
        root / "tools/match/scratches/dx_get_version_from_dxdiag",
    )
    source = (config.directory / config.source).read_text()
    declaration = "dxdiag_init_params_t params;\n        ZeroMemory(&params, sizeof(params));"
    assert source.count(declaration) == 1
    variants = [
        ("baseline", source, config),
        ("aggregate-init", source.replace(declaration, "dxdiag_init_params_t params = {0};"), config),
        ("field-init", source.replace("        ZeroMemory(&params, sizeof(params));\n", ""), config),
        (
            "explicit-memset",
            source.replace("ZeroMemory(&params, sizeof(params));", "memset(&params, 0, sizeof(params));"),
            config,
        ),
        ("intrinsics-off", source, replace(config, cflags=config.cflags + " /Oi-")),
    ]
    rows = []
    for name, variant, variant_config in variants:
        result = match.scratch_status_payload(
            match.evaluate_source_overlay(variant_config, variant),
        )
        # Temporary overlay paths are not evidence identities.
        result.pop("scratch", None)
        rows.append({"name": name, "source_sha256": sha256(variant.encode()).hexdigest(), "result": result})
        print(name, result["match_ratio"], result["body_byte_exact"], result["error"], flush=True)
    args.out.write_text(
        json.dumps({"baseline_source_sha256": sha256(source.encode()).hexdigest(), "controls": rows}, indent=2) + "\n",
    )


if __name__ == "__main__":
    main()
