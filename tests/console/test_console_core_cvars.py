from __future__ import annotations

from grim.console import create_console, register_core_cvars


def test_echo_off_silences_the_console_until_echo_on(tmp_path) -> None:
    console = create_console(tmp_path)
    register_core_cvars(console, width=1024, height=768)
    console.exec_line("echo off")
    before = len(console.log.lines)
    console.exec_line("cv_showFPS 1")
    console.exec_line("echo hello")
    assert len(console.log.lines) == before
    assert console.cvars["cv_showFPS"].value == "1"
    console.exec_line("echo on")
    console.exec_line("echo hello world")
    assert console.log.lines[-1] == "hello world "


def test_set_and_assignment_take_exactly_one_value(tmp_path) -> None:
    # Native `console_cmd_set` needs 3 tokens and `<cvar> <value>` assigns only with 2.
    console = create_console(tmp_path)
    register_core_cvars(console, width=1024, height=768)
    console.exec_line("set cv_showFPS 1 2")
    console.exec_line("cv_uiTransparency 0.5 extra")
    assert console.cvars["cv_showFPS"].value == "0"
    assert console.cvars["cv_uiTransparency"].value == "1"
