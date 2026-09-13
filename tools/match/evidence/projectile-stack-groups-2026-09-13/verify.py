"""Observe projectile stack groups while preserving the whole compiled object."""

import argparse
import copy
import importlib.util
import json
import os
import re
import shutil
import struct
from dataclasses import replace
from pathlib import Path

from primary_homes import stack_map

from crimson import match
from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "projectile-ownership-and-stack-2026-09-13"
OBSERVER = HERE.parent / "hud-stack-coloring-2026-09-10"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def groups_from_conflicts(symbols, order, signed):
    """Predict memberships; check observed placement separately, without predicting it."""
    assert all(symbol["before"][1] & 255 != 5 for symbol in symbols), "This verifier expects no parameters"
    groups = []
    for index in order:
        symbol = symbols[index]
        size = symbol["before"][8]
        conflicts = set(symbol["conflicts"])
        for group in reversed(groups):
            if (
                size <= 2 * group["size"]
                and index not in group["conflicts"]
                and not conflicts.intersection(group["members"])
            ):
                group["members"].append(index)
                group["conflicts"].update(conflicts)
                group["size"] = max(size, group["size"])
                break
        else:
            groups.append({"size": size, "members": [index], "conflicts": conflicts})

    checked = 0
    for group in groups:
        group.pop("conflicts")
        offsets = []
        for index in group["members"]:
            symbol = symbols[index]
            if symbol["before"][1] & 255 == 4:
                offsets.append(signed(symbol["final_descriptor"][3]))
                checked += 1
        assert offsets and len(set(offsets)) == 1, "Predicted members have inconsistent observed offsets"
        group["observed_offset"] = offsets[0]

    # The HUD's ascending allocation order does not hold for this function.
    # Observe the actual permutation, and verify disjoint, complete storage.
    offset = -sum((group["size"] + 3) & ~3 for group in groups)
    allocation = -offset
    for group in sorted(groups, key=lambda row: row["observed_offset"]):
        assert group["observed_offset"] == offset, "Observed groups overlap or leave unexplained storage"
        offset += (group["size"] + 3) & ~3
    assert offset == 0 and checked
    return groups, checked, allocation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--experiment", default="primary-q1-chained-zero")
    args = parser.parse_args()
    out = args.out.resolve()
    assert not out.exists(), "Use a new output directory"
    profile = c2.load_profile()
    recovery = load("projectile_recovery", SOURCE / "recover.py")
    source = recovery.recover(args.experiment)
    decoder = load("stack_decoder", OBSERVER / "verify.py")
    assert (
        replay.sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    out.mkdir(parents=True)
    folders = {name: out / name for name in ("source", "wrapped", "helper", "capture", "replay", "observed", "missing")}
    for folder in folders.values():
        folder.mkdir()
    for name in ("source", "wrapped"):
        (folders[name] / config.source).write_text(source)
    frozen = replace(config, directory=folders["source"])
    with c2.compiler_environment():
        helper = folders["helper"]
        shutil.copyfile(c2.ASSETS / "capture.c", helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
        normal = match.compile_scratch(frozen, force=True)
        old = os.environ.get("CRIMSON_IL_CAPTURE_DIR")
        os.environ["CRIMSON_IL_CAPTURE_DIR"] = replay.windows_path(folders["capture"])
        try:
            wrapped = match.compile_scratch(
                replace(
                    config,
                    directory=folders["wrapped"],
                    cflags=config.cflags + f' /B2"Z:{helper / "capture.dll"}" /Bd',
                ),
                force=True,
            )
        finally:
            if old is None:
                os.environ.pop("CRIMSON_IL_CAPTURE_DIR", None)
            else:
                os.environ["CRIMSON_IL_CAPTURE_DIR"] = old
        arguments, streams = replay.read_arguments(folders["capture"])
        hashes = {name: replay.sha(path.read_bytes()) for name, path in streams.items()}
        replay.build_replay(folders["replay"], arguments)
        replay.run([replay.WIBO, "replay.exe"], folders["replay"])
        observed = folders["observed"]
        shutil.copyfile(folders["replay"] / "replay_settings.h", observed / "replay_settings.h")
        shutil.copyfile(OBSERVER / "observer.c", observed / "observer.c")
        replay.compile_driver(observed, "observer.c", "observer.obj")
        replay.link(observed, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], observed)
        objects = [normal, wrapped, folders["replay"] / "replay.obj", observed / "replay.obj"]
        normalized = replay.normalized_coff(normal)
        assert all(replay.normalized_coff(path) == normalized for path in objects)
        metrics = replay.function_metrics(frozen, normal)
        assert all(replay.function_metrics(frozen, path) == metrics for path in objects)
        missing = streams["ex"]
        backup = missing.with_suffix(".withheld")
        missing.rename(backup)
        try:
            rejected = replay.run(
                [replay.WIBO, folders["replay"] / "replay.exe"],
                folders["missing"],
                check=False,
            )
            assert rejected.returncode and not (folders["missing"] / "replay.obj").exists()
        finally:
            backup.rename(missing)
        assert hashes == {name: replay.sha(path.read_bytes()) for name, path in streams.items()}

    raw = (observed / "phases.bin").read_bytes()
    symbols, order = decoder.decode(raw)
    groups, checked, allocation = groups_from_conflicts(symbols, order, decoder.signed)
    corrupted = copy.deepcopy(symbols)
    local = next(symbol for symbol in corrupted if symbol["before"][1] & 255 == 4)
    local["final_descriptor"] = list(local["final_descriptor"])
    local["final_descriptor"][3] ^= 4
    try:
        groups_from_conflicts(corrupted, order, decoder.signed)
    except AssertionError:
        pass
    else:
        raise AssertionError("Changed offset accepted")
    try:
        decoder.decode(raw[:-4])
    except (AssertionError, struct.error):
        pass
    else:
        raise AssertionError("Truncated trace accepted")
    listing = match.generate_compiler_listing(frozen, output=out / "listing.cod")
    metadata = json.loads(listing.metadata_path.read_text())
    assert metadata["stack_layout"]["prologue_allocation_bytes"] == allocation
    result = match.run_match(
        obj_path=normal,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    primary = stack_map(result, listing.listing_path.read_text(encoding="latin1"), metadata)
    names = {
        int(found[1]): row["name"]
        for row in metadata["stack_layout"]["symbols"]
        if (found := re.search(r"\$(?:T)?([0-9]+)$", row["name"]))
    }
    stable = [
        {
            "index": symbol["index"],
            "kind": symbol["before"][1] & 255,
            "size": symbol["before"][8],
            "use_count": symbol["before"][13],
            "frontend_id": symbol["descriptor"][10] if symbol["before"][0] else None,
            "candidate_name": names.get(symbol["descriptor"][10]) if symbol["before"][0] else None,
            "initial_offset": decoder.signed(symbol["descriptor"][3]) if symbol["before"][0] else None,
            "final_offset": decoder.signed(symbol["final_descriptor"][3]) if symbol["before"][0] else None,
            "conflicts": symbol["conflicts"],
        }
        for symbol in symbols
    ]
    record = {
        "schema_version": 1,
        "experiment": args.experiment,
        "source_sha256": replay.sha(source.encode()),
        "compiler_sha256": profile["c2_sha256"],
        "normalized_object_sha256": replay.sha(normalized),
        "trace_sha256": replay.sha(raw),
        "stream_sha256": hashes,
        "metrics": metrics,
        "primary_stack_accesses": primary,
        "groups": groups,
        "symbols": stable,
        "symbol_order": order,
        "descriptor_offsets_checked": checked,
        "allocation_bytes": allocation,
        "whole_coff_preserved_except_timestamp": True,
        "missing_stream_rejected": True,
        "truncated_trace_rejected": True,
        "changed_offset_rejected": True,
        "new_exact_matches": 0,
        "scope": "Predicts group membership from this captured conflict graph. Final offsets and their permutation are observations, not predictions. Candidate names are not original-source identities. This does not prove native lifetimes or equivalence.",
        "harness_sha256": {
            str(path.relative_to(match.REPO_ROOT)): replay.sha(path.read_bytes())
            for path in (
                HERE / "verify.py",
                HERE / "primary_homes.py",
                OBSERVER / "verify.py",
                OBSERVER / "observer.c",
                SOURCE / "recover.py",
                SOURCE / "experiments.json",
                SOURCE / "before.cpp",
                Path(c2.__file__),
                Path(replay.__file__),
            )
        },
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        f"PASS: {len(symbols)} symbols, {len(groups)} groups, {checked} observed descriptor offsets; {allocation} bytes",
    )


if __name__ == "__main__":
    main()
