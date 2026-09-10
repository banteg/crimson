"""Test ordinary implicit pointer-wrapper copies after the late-store trace."""

import argparse
import json
from hashlib import sha256
from pathlib import Path

from crimson import match

SOURCE_SHA = "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9"


def variants(source):
    for constructor in (False, True):
        wrapper = "struct template_view { int *p; "
        if constructor:
            wrapper += "template_view(int *value) : p(value) {} "
        wrapper += "};\n"
        initial = "template_view view(&entry->template_id);" if constructor else "template_view view = { &entry->template_id };"
        for form in ("copy", "assign", "return"):
            helper = ""
            if form == "copy":
                declaration = initial + " template_view template_id = view;"
            elif form == "assign":
                declaration = initial + (" template_view template_id(0);" if constructor else " template_view template_id;")
                declaration += " template_id = view;"
            else:
                helper = "static inline template_view view_for(int *p) { "
                helper += "template_view view(p);" if constructor else "template_view view = { p };"
                helper += " return view; }\n"
                declaration = "template_view template_id = view_for(&entry->template_id);"
            for relative_heading in (False, True):
                variant = source.replace('extern "C" int frame_dt_ms;', wrapper + helper + 'extern "C" int frame_dt_ms;')
                variant = variant.replace("int *template_id = &entry->template_id;", declaration)
                variant = variant.replace("*template_id,", "*template_id.p,")
                if relative_heading:
                    variant = variant.replace("entry->heading", "((float *)template_id.p)[-1]")
                label = f"{'constructor' if constructor else 'pod'}-{form}-{'relative' if relative_heading else 'entry'}"
                yield label, variant


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    source = (config.directory / config.source).read_text()
    assert sha256(source.encode()).hexdigest() == SOURCE_SHA
    rows = []
    for label, variant in [("baseline", source), *variants(source)]:
        status = match.scratch_status_payload(match.evaluate_source_overlay(config, variant))
        status.pop("scratch", None)
        rows.append({"label": label, "source_sha256": sha256(variant.encode()).hexdigest(), "status": status})
        print(label, status["match_ratio"], status["candidate_instructions"], status["body_byte_exact"], status["error"], flush=True)
    args.out.write_text(json.dumps({"canonical_source_sha256": SOURCE_SHA, "results": rows}, indent=2) + "\n")


if __name__ == "__main__":
    main()
