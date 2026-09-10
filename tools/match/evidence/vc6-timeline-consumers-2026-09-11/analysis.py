"""Assert consumer identities and distinguish source controls by compiler history."""

import struct

PHASES = (
    "before_130cb",
    "after_130cb",
    "before_281cd",
    "before_2930f",
    "before_29511",
    "after_29511",
    "before_26d75",
    "after_26d75",
    "before_30308",
    "before_306c1",
    "after_306c1",
    "before_336f4",
)
PARTIAL = "advance-after-pointer-template-relative"


def kind(operand):
    return operand[2] & 255


def analyze(snapshots, label, source):
    lines = source.splitlines()
    signature = next(i for i, line in enumerate(lines) if "void quest_spawn_timeline_update" in line)
    entry_line = next(i for i, line in enumerate(lines) if "quest_spawn_entry_t *entry =" in line) - signature
    pointer_line = next(i for i, line in enumerate(lines) if "int *template_id" in line) - signature
    call_line = (
        next(i for i, line in enumerate(lines) if "entry->heading);" in line or "((float *)template_id)[-1]);" in line)
        - signature
    )
    entry = next(node["dst"][0][5] for node in snapshots[0] if node["line"] == entry_line and node["op"] == 0x15B)
    template = next(
        node["dst"][0][5]
        for node in reversed(snapshots[0])
        if node["line"] == pointer_line and node["op"] in (0x15B, 0x16B)
    )
    loads = [
        [
            node
            for node in nodes
            if node["line"] == call_line and node["op"] in (0x15A, 1) and node["src"] and kind(node["src"][0]) == 6
        ]
        for nodes in snapshots
    ]
    assert all(len(pair) == 2 and all(len(node["src"]) == 2 for node in pair) for pair in loads)
    # The two memory loads are emitted in cdecl argument order: heading, then ID.
    # Their identities persist after argument lowering; match by identity too.
    identities = [node["id"] for node in loads[5]]
    assert all([node["id"] for node in pair] == identities for pair in loads[5:])
    bases = [[node["src"][1][5] for node in pair] for pair in loads]
    assert bases[0][1] == template
    definitions = [[node for node in nodes if node["line"] == pointer_line] for nodes in snapshots]
    if label == PARTIAL:
        assert bases[9][1] == template and bases[9][0] not in (entry, template)
        assert bases[10] == bases[11] == [template, template]
        assert [node["op"] for node in definitions[9]] == [1]
        pointer_copy = definitions[9][0]
        assert all(
            any(node["id"] == pointer_copy["id"] and node["op"] == 1 and kind(node["dst"][0]) == 1 for node in nodes)
            for nodes in snapshots[9:]
        )
        finding = "template COPY survives; heading load rebased to template inside 306c1"
    else:
        assert all(base != entry for base in bases[9])
        assert bases[10] == bases[11] == [entry, entry]
        assert not definitions[10] and not definitions[11]
        if label in ("relative-heading", "memcpy-relative"):
            assert bases[8][1] == template and bases[9][1] not in (entry, template)
            assert definitions[8] and not definitions[9]
            finding = "30308 forwards pointer COPY to auxiliary base; 306c1 rebases both loads to entry"
        else:
            assert bases[9][1] == template
            assert [node["op"] for node in definitions[9]] == [0x12, 1]
            assert all(kind(node["dst"][0]) == 1 for node in definitions[9])
            finding = "both loads rebased to entry during 306c1, alongside pointer definition removal"

    copy_finding = None
    if label.startswith("memcpy-"):
        block = [node for node in definitions[0] if node["op"] == 0x16B]
        assert len(block) == 1
        assert kind(block[0]["src"][0]) == kind(block[0]["dst"][0]) == 2
        assert all(node["op"] != 0x16B for node in definitions[1])
        assert not any(node["id"] == block[0]["id"] and node["op"] == 0x16B for node in snapshots[1])
        assert [node["op"] for node in definitions[1]] in ([0x16D, 0x15B], [0x15B])
        assert all(kind(node["dst"][0]) == 1 for node in definitions[5])
        copy_finding = {
            "initial_opcode": "0x16b",
            "initial_source_kind": 2,
            "initial_destination_kind": 2,
            "block_copy_absent_after_130cb": True,
            "pointer_definitions_have_only_kind_1_destinations_after_29511": True,
            "late_nonzero_memory_store_mechanism_exercised": False,
        }

    def role(value):
        return "entry" if value == entry else "template" if value == template else "derived auxiliary"

    return {
        "finding": finding,
        "heading_and_id_load_node_identities_preserved_after_29511": True,
        "copy_probe": copy_finding,
        "phases": [
            {
                "phase": phase,
                "node_count": len(nodes),
                "heading_load_base": role(pair[0]),
                "id_load_base": role(pair[1]),
                "pointer_definition_opcodes": [hex(node["op"]) for node in defs],
                "pointer_definition_destination_kinds": [kind(node["dst"][0]) for node in defs if node["dst"]],
            }
            for phase, nodes, pair, defs in zip(PHASES, snapshots, bases, definitions)
        ],
    }


def analyze_decisions(path, snapshots, label):
    data = path.read_bytes()
    assert len(data) % 48 == 0
    rows = [struct.unpack_from("<12I", data, i) for i in range(0, len(data), 48)]
    watched = [row for row in rows if row[1] == row[2]]
    before = [row for row in watched if row[0] == 0x109]
    assert len(before) == 1
    pointer_defs = [node for node in snapshots[9] if node["line"] == 40 and node["op"] == 1]
    assert len(pointer_defs) == 1 and before[0][1] == pointer_defs[0]["dst"][0][6]
    predicate = [row for row in watched if row[0] in (2, 3)]
    conflicts = [row for row in watched if row[0] in (0, 1)]
    assert len(predicate) == 1
    if label == "baseline":
        assert predicate[0][6] == 0x12 and predicate[0][8] == 5 and predicate[0][9] == 1
        assert len(conflicts) == 1 and conflicts[0][9] == 0
    else:
        assert label == PARTIAL
        assert predicate[0][6] == 1 and predicate[0][8] == 1 and predicate[0][9] == 0
        assert not conflicts
    return {
        "preserving_call_and_return_observation": True,
        "eligibility_predicate_rva": "0x309bb",
        "input_definition_opcode": hex(predicate[0][6]),
        "input_source_operand_kind": predicate[0][8],
        "eligibility_return": predicate[0][9],
        "intervening_definition_check_rva": "0x31a50",
        "intervening_definition_check_reached_for_pointer": bool(conflicts),
        "intervening_definition_check_returns": [row[9] for row in conflicts],
        "total_observed_predicate_calls": sum(row[0] in (2, 3) for row in rows),
        "total_observed_intervening_definition_calls": sum(row[0] in (0, 1) for row in rows),
    }
