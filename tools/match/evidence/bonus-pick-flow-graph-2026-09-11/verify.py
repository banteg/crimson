"""Compare bonus selection control flow without granting byte-match credit."""

import argparse
import hashlib
import json
import re
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match, match_flow_graph

SOURCE_SHA256 = "286648fb568fe81709b52093a204a820f7f7e9bf06968ed8e50042c063c26f42"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(target, candidate):
    """Map reachable instructions, preserving conditional edge polarity."""
    lines = (target, candidate)
    offsets = [{line.offset: index for index, line in enumerate(side)} for side in lines]
    jumps = (set(), set())

    def destination(side, index):
        found = re.fullmatch(r"j\w+ L([0-9a-f]+)", lines[side][index].text)
        assert found, "Expected an internal direct branch"
        return offsets[side][int(found[1], 16)]

    def resolve(side, index):
        seen = set()
        while lines[side][index].text.startswith("jmp "):
            assert index not in seen, "Unconditional jump cycle"
            seen.add(index)
            jumps[side].add(index)
            index = destination(side, index)
        return index

    def children(side, index):
        text = lines[side][index].text
        if text.startswith("ret"):
            return []
        if text.startswith("j"):
            return [resolve(side, destination(side, index)), resolve(side, index + 1)]
        assert index + 1 < len(lines[side]), "Unexpected fall-through out of function"
        return [resolve(side, index + 1)]

    def operation(text):
        return text.split(" ")[0] if re.fullmatch(r"j\w+ L[0-9a-f]+", text) else text

    pairs, reverse, references = {}, {}, []
    pending = [(resolve(0, 0), resolve(1, 0))]
    while pending:
        left, right = pending.pop()
        if left in pairs:
            assert pairs[left] == right, "Inconsistent target mapping"
            continue
        assert right not in reverse, "Candidate mapping is not one-to-one"
        a, b = target[left], candidate[right]
        assert operation(a.text) == operation(b.text), (left, right, a.text, b.text)
        if a.masked_references or b.masked_references:
            status = match._masked_reference_status(a.masked_references, b.masked_references)
            assert status == "ok", (left, right, status)
            references.append(
                {
                    "target_index": left,
                    "candidate_index": right,
                    "status": status,
                    "target": [asdict(ref) for ref in a.masked_references],
                    "candidate": [asdict(ref) for ref in b.masked_references],
                },
            )
        pairs[left], reverse[right] = right, left
        a_children, b_children = children(0, left), children(1, right)
        assert len(a_children) == len(b_children), "Different outgoing edge counts"
        pending.extend(zip(a_children, b_children))

    for side, mapped in enumerate((set(pairs), set(reverse))):
        assert mapped | jumps[side] == set(range(len(lines[side]))), "Uncovered instructions"
        assert not mapped & jumps[side]
    return {
        "mapped_non_jump_instructions": len(pairs),
        "transparent_jumps": [sorted(side) for side in jumps],
        "reference_instructions": len(references),
        "all_instructions_covered": True,
        "edge_order": "taken_then_fallthrough",
        "mapping": [
            {
                "target_index": left,
                "candidate_index": right,
                "target_offset": target[left].offset,
                "candidate_offset": candidate[right].offset,
                "target_instruction": target[left].text,
                "candidate_instruction": candidate[right].text,
            }
            for left, right in sorted(pairs.items())
        ],
        "references": references,
    }


def negative_controls(target, candidate):
    """Ensure the comparison notices changed conditions, edges, and owners."""
    branch = next(i for i, line in enumerate(candidate) if line.text.startswith("je "))
    reference = next(i for i, line in enumerate(candidate) if line.masked_references)
    mutations = {
        "condition": (branch, replace(candidate[branch], text=candidate[branch].text.replace("je ", "jne ", 1))),
        "edge": (branch, replace(candidate[branch], text="je L0")),
        "reference": (
            reference,
            replace(
                candidate[reference],
                masked_references=tuple(
                    replace(ref, keys=("deliberately_wrong_reference",))
                    for ref in candidate[reference].masked_references
                ),
            ),
        ),
    }
    rejected = []
    for name, (index, changed) in mutations.items():
        altered = list(candidate)
        altered[index] = changed
        try:
            compare(target, tuple(altered))
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError(f"Failed to reject changed {name}")
    return rejected


def sound_loop_control():
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/dsound_restore_buffer")
    obj = match.compile_scratch(config, force=True)
    result = match.run_match(
        obj_path=obj,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    assert result.exact and result.body_byte_exact, "Sound-buffer positive control no longer matches"
    outlined = []
    for index, line in enumerate(result.candidate_disassembly[:-1]):
        jump = re.fullmatch(r"jmp L([0-9a-f]+)", line.text)
        following = result.candidate_disassembly[index + 1]
        if jump and int(jump[1], 16) < line.offset and following.text == "test eax, eax":
            outlined.append({"jump_offset": line.offset, "condition_offset": following.offset})
    assert len(outlined) == 1, "Expected the known outlined loop condition"
    return {
        "function": config.function,
        "source_sha256": digest(config.directory / config.source),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "normalized_exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "outlined_loop_condition": outlined,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/bonus_pick_random_type")
    assert digest(config.directory / config.source) == SOURCE_SHA256, "Canonical source changed"
    obj = match.compile_scratch(config, force=True)
    result = match.run_match(
        obj_path=obj,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    graph = compare(result.target_disassembly, result.candidate_disassembly)
    diagnostic = match_flow_graph.flow_graph_payload(result)
    assert diagnostic["status"] == "matched"
    for field in ("mapping", "transparent_jumps", "mapped_non_jump_instructions", "reference_instructions"):
        assert diagnostic[field] == graph[field], f"CLI diagnostic disagrees on {field}"
    rejected = negative_controls(result.target_disassembly, result.candidate_disassembly)
    receipt = {
        "schema_version": 1,
        "source_sha256": SOURCE_SHA256,
        "verifier_sha256": digest(Path(__file__)),
        "image_sha256": digest(match.DEFAULT_IMAGE_PATH),
        "object_sha256": digest(obj),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "compiler": config.compiler,
        "cflags": config.cflags,
        "ratio": result.ratio,
        "normalized_exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "instructions": [len(result.target_lines), len(result.candidate_lines)],
        "negative_controls_rejected": rejected,
        "cli_diagnostic_agrees": True,
        "diagnostic_sha256": digest(Path(match_flow_graph.__file__)),
        "sound_loop_positive_control": sound_loop_control(),
        "graph": graph,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        f"Mapped {graph['mapped_non_jump_instructions']} operations and "
        f"{graph['reference_instructions']} references; "
        f"encoded exact={result.body_byte_exact}; rejected controls={rejected}",
    )


if __name__ == "__main__":
    main()
