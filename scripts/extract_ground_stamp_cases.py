from __future__ import annotations

import argparse
import json
from pathlib import Path

CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011
CRT_RAND_MOD = 2**32


def _derive_rng_state0_from_outputs(r0: int, r1: int, r2: int) -> list[int]:
    """Given the first three crt_rand() outputs, derive the pre-update RNG state.

    crt_rand():
      state = state * 214013 + 2531011 (mod 2^32)
      return (state >> 16) & 0x7fff

    The return value discards bit31, so two states differing by 0x80000000 are
    indistinguishable via outputs alone; we return both candidates when found.
    """

    inv_mult = pow(CRT_RAND_MULT, -1, CRT_RAND_MOD)
    sols: list[int] = []
    for bit31 in (0, 1):
        upper = ((bit31 << 15) | (r0 & 0x7FFF)) & 0xFFFF  # bits16-31 of state1
        base = upper << 16
        for low16 in range(1 << 16):
            state1 = base | low16
            state0 = ((state1 - CRT_RAND_INC) * inv_mult) % CRT_RAND_MOD

            s = state0
            s = (s * CRT_RAND_MULT + CRT_RAND_INC) % CRT_RAND_MOD
            if ((s >> 16) & 0x7FFF) != (r0 & 0x7FFF):
                raise RuntimeError("internal error: bad inversion")
            s = (s * CRT_RAND_MULT + CRT_RAND_INC) % CRT_RAND_MOD
            if ((s >> 16) & 0x7FFF) != (r1 & 0x7FFF):
                continue
            s = (s * CRT_RAND_MULT + CRT_RAND_INC) % CRT_RAND_MOD
            if ((s >> 16) & 0x7FFF) != (r2 & 0x7FFF):
                continue
            sols.append(int(state0))
    # De-dupe while preserving order.
    out: list[int] = []
    seen: set[int] = set()
    for s in sols:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _pick_rand_field_mapping(stamp0: dict, *, inv_scale: float, texture_size: int = 1024) -> tuple[str, int]:
    """Return ("new"|"old", seed_state0).

    Older ground_dump.js logs mislabeled the 2nd/3rd rand outputs as rand_x/rand_y.
    We detect which mapping is used by checking which one reproduces the recorded x/y.
    """

    r0 = int(stamp0["rand_rot"])
    mappings = [
        ("new", int(stamp0["rand_y"]), int(stamp0["rand_x"])),  # correct: y then x
        ("old", int(stamp0["rand_x"]), int(stamp0["rand_y"])),  # swapped
    ]

    want_x = float(stamp0["x"])
    want_y = float(stamp0["y"])
    range_ = texture_size + 128
    for name, r1, r2 in mappings:
        sols = _derive_rng_state0_from_outputs(r0, r1, r2)
        if not sols:
            continue
        # Any candidate produces identical rand outputs; pick the low-bit31 one.
        state0 = sols[0]
        exp_x = ((r2 % range_) - 64) * inv_scale
        exp_y = ((r1 % range_) - 64) * inv_scale
        if exp_x == want_x and exp_y == want_y:
            return name, state0
    raise RuntimeError("could not determine rand_x/rand_y mapping from first stamp")


def extract_cases(jsonl_path: Path) -> list[dict]:
    events = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    enters: dict[int, dict] = {}
    dumps: dict[int, dict] = {}
    stamps: dict[int, list[dict]] = {}

    for ev in events:
        tag = ev.get("tag")
        if tag == "terrain_generate_enter":
            enters[int(ev["gen_index"])] = ev
        elif tag == "dump":
            tg = ev.get("terrain_generate") or {}
            gen_index = int(tg.get("gen_index") or 0)
            if gen_index:
                dumps[gen_index] = ev
        elif tag == "terrain_stamp":
            gi = int(ev["gen_index"])
            stamps.setdefault(gi, []).append(ev)

    out: list[dict] = []
    for gen_index in sorted(stamps.keys()):
        enter = enters.get(gen_index)
        dump = dumps.get(gen_index)
        stamp_list = stamps[gen_index]
        if not enter:
            raise RuntimeError(f"missing terrain_generate_enter for gen_index={gen_index}")

        scale = float(enter.get("terrain_scale") or 1.0)
        inv_scale = 1.0 / scale

        stamp0 = stamp_list[0]
        mapping, seed_state0 = _pick_rand_field_mapping(stamp0, inv_scale=inv_scale)

        y_field, x_field = ("rand_y", "rand_x") if mapping == "new" else ("rand_x", "rand_y")
        triplets: list[list[int]] = []
        for st in stamp_list:
            triplets.append([int(st["rand_rot"]), int(st[y_field]), int(st[x_field])])

        indices = enter.get("indices") or {}
        case = {
            "gen_index": gen_index,
            "seed_state": int(seed_state0) & 0xFFFFFFFF,
            "seed_state_hex": f"0x{int(seed_state0) & 0xFFFFFFFF:08x}",
            "seed_srand": int(dump.get("seed_srand")) if dump and dump.get("seed_srand") is not None else None,
            "terrain_scale": scale,
            "width": int(dump.get("width")) if dump and dump.get("width") is not None else 1024,
            "height": int(dump.get("height")) if dump and dump.get("height") is not None else 1024,
            "tex0_index": int(indices.get("tex0_index")),
            "tex1_index": int(indices.get("tex1_index")),
            "tex2_index": int(indices.get("tex2_index")),
            "stamps": len(triplets),
            "triplets_rot_y_x": triplets,
        }

        if dump and dump.get("raw_path"):
            raw_path = Path(str(dump["raw_path"]))
            case["raw"] = raw_path.name
            case["fixture"] = raw_path.with_suffix(".png").name

        out.append(case)

    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Extract terrain stamp sequences from ground_dump.jsonl")
    p.add_argument("--jsonl", type=Path, default=Path(r"C:\share\frida\ground_dump.jsonl"))
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()

    cases = extract_cases(args.jsonl)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(cases, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
