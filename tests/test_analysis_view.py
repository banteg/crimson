from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_view():
    path = Path(__file__).parents[1] / "scripts" / "analysis_view.py"
    spec = importlib.util.spec_from_file_location("analysis_view_test", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parse_prototype_preserves_nested_function_pointer_parameter() -> None:
    view = _load_view()

    prototype = view.parse_prototype(
        "void mod_api_core_add_command(const char *id, void (*cmd)(void))",
    )

    assert prototype is not None
    assert prototype.name == "mod_api_core_add_command"
    assert prototype.params == ("const char *id", "void (*cmd)(void)")


def test_compare_rows_reports_boundary_name_and_signature_drift() -> None:
    view = _load_view()
    canonical = [
        {
            "address": "0x00401030",
            "name": "console_input_clear",
            "signature": "void console_input_clear(void)",
        },
        {
            "address": "0x00401050",
            "name": "console_input_buffer",
            "signature": "char * console_input_buffer(void)",
        },
        {
            "address": "0x00401060",
            "name": "console_input_poll",
            "signature": "int console_input_poll(void)",
        },
    ]
    observed = [
        {
            "address": "00401030",
            "name": "console_input_clear",
            "signature": "void console_input_clear(void)",
        },
        {
            "address": "0x00401050",
            "name": "FUN_00401050",
            "signature": "int FUN_00401050(void)",
        },
    ]

    report = view.compare_rows("ghidra", canonical, observed)

    assert report.mapped == 2
    assert [row["name"] for row in report.missing] == ["console_input_poll"]
    assert len(report.name_mismatches) == 1
    assert len(report.signature_mismatches) == 1
    assert report.boundary_ok is False


def test_prototype_shape_normalizes_tool_integer_aliases() -> None:
    view = _load_view()

    assert view.prototype_shape("unsigned char predicate(void)") == view.prototype_shape(
        "unsigned __int8()",
    )
    assert view.prototype_shape("short callback(int a, int b)") == view.prototype_shape(
        "__int16(int a, int b)",
    )
    assert view.prototype_shape("unsigned __int64 packed(void)") == view.prototype_shape(
        "ulonglong packed(void)",
    )


def test_load_function_metadata_filters_program(tmp_path: Path) -> None:
    view = _load_view()
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(
        '{"program":"crimsonland.exe","functions":{"player_update":{"notes":["movement"]}}}',
        encoding="utf-8",
    )

    assert view.load_function_metadata(
        metadata_path,
        "crimsonland.exe",
        "player_update",
    ) == {"notes": ["movement"]}
    assert view.load_function_metadata(metadata_path, "grim.dll", "player_update") == {}


def test_resolve_entry_accepts_alias_and_address() -> None:
    view = _load_view()
    rows = [
        {
            "address": "0x00401560",
            "name": "console_init",
            "aliases": ["??0console_queue_t@@QAE@XZ"],
        },
    ]

    assert view.resolve_entry(rows, "??0console_queue_t@@QAE@XZ") == rows[0]
    assert view.resolve_entry(rows, "0x401560") == rows[0]
