from __future__ import annotations

import argparse
import json
from pathlib import Path

from PIL import Image


def _load_events(jsonl_path: Path) -> list[dict]:
    events: list[dict] = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


def _bgra_raw_to_png(
    raw_path: Path, *, width: int, height: int, out_path: Path, format_name: str | None
) -> None:
    # Raw dumps are locked render target surfaces (X8R8G8B8), i.e. 4 bytes per
    # pixel in BGRA/BGRX order. Treat it as BGRA and write RGBA PNG.
    data = raw_path.read_bytes()
    expected = width * height * 4
    if len(data) != expected:
        raise RuntimeError(f"unexpected raw size for {raw_path} (got {len(data)} bytes, expected {expected})")
    # X8R8G8B8 is BGRX (alpha undefined). Force opaque alpha to make comparisons stable.
    if format_name == "X8R8G8B8":
        img = Image.frombuffer("RGB", (width, height), data, "raw", "BGRX", 0, 1).convert("RGBA")
    else:
        img = Image.frombuffer("RGBA", (width, height), data, "raw", "BGRA", 0, 1)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path)


def main() -> int:
    p = argparse.ArgumentParser(description="Import Frida ground dumps into test fixtures")
    p.add_argument("--jsonl", type=Path, default=Path(r"C:\share\frida\ground_dump.jsonl"))
    p.add_argument("--fixtures-dir", type=Path, default=Path("tests/fixtures/ground"))
    p.add_argument("--cases-out", type=Path, default=Path("tests/fixtures/ground/ground_dump_cases.json"))
    p.add_argument(
        "--keep-last",
        type=int,
        default=3,
        help="Keep only the last N dump events (0 = keep all).",
    )
    args = p.parse_args()

    events = _load_events(args.jsonl)

    dump_events = [ev for ev in events if ev.get("tag") == "dump"]
    if args.keep_last and args.keep_last > 0:
        dump_events = dump_events[-args.keep_last :]

    cases: list[dict] = []
    for ev in dump_events:
        tg = ev.get("terrain_generate") or {}
        indices = tg.get("indices") or {}

        raw_path = Path(str(ev["raw_path"]))
        width = int(ev["width"])
        height = int(ev["height"])

        fixture_name = raw_path.with_suffix(".png").name
        fixture_path = args.fixtures_dir / fixture_name
        _bgra_raw_to_png(
            raw_path,
            width=width,
            height=height,
            out_path=fixture_path,
            format_name=str(ev.get("format_name") or ""),
        )

        cases.append(
            {
                "fixture": fixture_name,
                "raw": raw_path.name,
                # IMPORTANT: this is the per-thread RNG state at terrain_generate entry (ptd[5]),
                # not the last srand seed.
                "seed": int(tg.get("seed")) if tg.get("seed") is not None else int(ev.get("seed")),
                "seed_srand": int(ev["seed_srand"]) if ev.get("seed_srand") is not None else None,
                "width": width,
                "height": height,
                "tex0_index": int(indices.get("tex0_index")),
                "tex1_index": int(indices.get("tex1_index")),
                "tex2_index": int(indices.get("tex2_index")),
                "desc_ptr": str(tg.get("desc")) if tg.get("desc") is not None else None,
            }
        )

    args.cases_out.parent.mkdir(parents=True, exist_ok=True)
    args.cases_out.write_text(json.dumps(cases, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases to {args.cases_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
