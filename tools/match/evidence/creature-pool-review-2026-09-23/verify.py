"""Recheck pointer retention on the pool-base source; compiler diagnostics only."""

import argparse
import importlib.util
import json
import shutil
from pathlib import Path

from crimson import match
from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

HERE = Path(__file__).resolve().parent
SOURCE_SHA = "7bb97911b09a9e96d60b4b7b93530f07702d92de55d343d75fb5b642b49f44bd"
PRIOR = HERE.parent / "creature-pointer-rematerialization-2026-09-22"
spec = importlib.util.spec_from_file_location("pointer_review_prior", PRIOR / "verify.py")
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
MODES = {
    "observer": (4, "control"),
    "early-health": (1, "early"),
    "health-home": (1, "health-home"),
    "four-homes": (4, "health-home"),
    "five-values": (5, "health-home"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--preserving", type=Path, help="Reuse a verified trace from this exact source")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_update_all")
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    hooks = prior.profile()
    preserving = args.preserving.resolve() if args.preserving else out / "preserving"
    if args.preserving is None:
        old_loader, old_observer = c2.load_profile, c2.observer_source
        try:
            c2.load_profile = lambda: hooks
            c2.observer_source = lambda p: prior.observer(old_observer, p, "control")
            c2.trace(config.directory, preserving)
        finally:
            c2.load_profile, c2.observer_source = old_loader, old_observer
    c2.read_verified(preserving)
    manifest = json.loads((preserving / "manifest.json").read_text())
    assert manifest["source_sha256"] == SOURCE_SHA
    assert json.loads((preserving / "profile.json").read_text()) == hooks
    stock = replay.normalized_coff(preserving / "observed/replay.obj")
    assert replay.sha(stock) == manifest["normalized_coff_sha256"]
    rows = {}
    for name, (count, control) in MODES.items():
        directory = out / name
        directory.mkdir()
        shutil.copyfile(preserving / "observed/replay_settings.h", directory / "replay_settings.h")
        source = prior.observer(c2.observer_source, hooks, control)
        original_watch = (PRIOR / "watch.c.in").read_text()
        assert source.count(original_watch) == 1
        source = source.replace(original_watch, f"#define WATCH_COUNT {count}\n" + (HERE / "watch.c.in").read_text())
        (directory / "observer.c").write_text(source)
        with c2.compiler_environment():
            replay.compile_driver(directory, "observer.c", "observer.obj")
            replay.link(directory, "observer.exe", "observer.obj")
            replay.run([replay.WIBO, "observer.exe"], directory)
        detail = prior.inspect(directory, config, hooks)
        (directory / "inspection.json").write_text(json.dumps(detail, indent=2) + "\n")
        rows[name] = {
            "watched_values": count,
            "frame_instruction": detail["frame_instruction"],
            "metrics": detail["metrics"],
            "stock_coff_equal_except_timestamp": replay.normalized_coff(directory / "replay.obj") == stock,
            "health_operations": detail["health_operations"],
            "counts": detail["counts"],
            "normalized_coff_sha256": detail["normalized_coff_sha256"],
        }
        print(name, rows[name]["frame_instruction"], rows[name]["metrics"], flush=True)
    assert all(rows[name]["stock_coff_equal_except_timestamp"] for name in ("observer", "early-health"))
    assert rows["observer"]["health_operations"]["10"] == []
    assert rows["early-health"]["health_operations"]["10"] == ["0x12"]
    assert rows["early-health"]["health_operations"]["112"] == []
    assert rows["health-home"]["health_operations"]["11"] == ["0x12", "0x1"]
    assert [rows[name]["frame_instruction"] for name in MODES] == [
        "sub esp, 0x6c",
        "sub esp, 0x6c",
        "sub esp, 0x70",
        "sub esp, 0x80",
        "sub esp, 0x80",
    ]
    result = {
        "source_sha256": SOURCE_SHA,
        "compiler_sha256": hooks["c2_sha256"],
        "match_credit": False,
        "runtime_equivalence_of_mutated_objects_claimed": False,
        "controls": rows,
        "harness_sha256": {name: replay.sha((HERE / name).read_bytes()) for name in ("verify.py", "watch.c.in")},
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA


if __name__ == "__main__":
    main()
