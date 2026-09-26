from __future__ import annotations

import struct

import pytest

from grim.rand import CrtRand

from ._support import f32_bits


def test_crt_rand_runs_natively_and_matches_port(oracle) -> None:
    oracle.rand_state = 0x1234_5678
    port = CrtRand(0x1234_5678)
    for _ in range(64):
        result = oracle.call("crt_rand")
        assert result.eax == port.rand()
        assert oracle.rand_state == port.state
        assert result.stack_popped == 0


def test_float_argument_float_return_and_callee_cleanup(oracle) -> None:
    # fld dword [esp+4]; fadd dword [esp+8]; ret 8   (stdcall float(float, float))
    probe = oracle.load_code(bytes.fromhex("d9442404" "d8442408" "c20800"))
    result = oracle.call(probe, 0.1, 0.2)
    assert result.stack_popped == 8
    assert f32_bits(result.st0) == f32_bits(struct.unpack("<f", struct.pack("<f", 0.1))[0] + 0.2)


def test_pc24_control_word_rounds_every_op(oracle) -> None:
    # fld1; fdiv st(0), st(1); ret  with ST1 = 3.0 preloaded -> 1/3 at 24 bits
    probe = oracle.load_code(bytes.fromhex("d9e8" "d8f1" "c3"))
    third = oracle.call(probe, st=(3.0,)).fpu_stack[0]
    assert third.mantissa == 0xAAAAAB00_00000000
    extended = oracle.call(probe, st=(3.0,), control_word=0x037F).fpu_stack[0]
    assert extended.mantissa == 0xAAAAAAAA_AAAAAAAB


def test_null_pointer_read_names_instruction_and_symbol(oracle) -> None:
    from crimson.dbg.native_oracle import NativeTrap

    oracle.write_u8("creature_pool", 1)
    # Pool full scan -> `creature_alloc_slot` dereferences the unset cv_verbose cvar.
    for slot in range(0x180):
        oracle.write_u8(oracle.resolve("creature_pool") + 0x98 * slot, 1)
    with pytest.raises(NativeTrap) as trap:
        oracle.call("creature_alloc_slot")
    assert trap.value.kind == "unmapped-read"
    assert "creature_alloc_slot+0x20" in str(trap.value)


def test_unstubbed_import_is_reported_and_stubs_answer(oracle) -> None:
    from crimson.dbg.native_oracle import NativeTrap

    # `crt_findclose` (0x004618fd) calls KERNEL32!FindClose.
    with pytest.raises(NativeTrap) as trap:
        oracle.call("crt_findclose", 7)
    assert trap.value.kind == "import"
    assert "FindClose" in str(trap.value)

    seen: list[int] = []
    oracle.stub_import("FindClose", lambda call: seen.append(call.arg_u32(0)) or 1, pop=4)
    result = oracle.call("crt_findclose", 7)
    assert seen == [7]
    assert result.eax == 0


def test_function_stub_and_memory_trace(oracle) -> None:
    oracle.stub("crt_rand", 1234)
    with oracle.trace_memory() as trace:
        slot = oracle.call("creature_alloc_slot").eax
    assert slot == 0
    assert oracle.read_i32(oracle.resolve("creature_pool") + 4) == 1234 & 0x17F
    assert any(name.startswith("creature_spawned_count") for name in trace.touched("write"))
    oracle.unstub("crt_rand")
    oracle.rand_state = 1
    assert oracle.call("crt_rand").eax == CrtRand(1).rand()


def test_restubbing_calls_the_callback_once_per_call(oracle) -> None:
    calls: list[int] = []
    for _ in range(3):
        oracle.stub("crt_rand", lambda call: calls.append(call.return_address) or 7)
        assert oracle.call("crt_rand").eax == 7
        oracle.unstub("crt_rand")
    assert len(calls) == 3


def test_static_initializers_seed_weapon_defaults(oracle) -> None:
    # The fixture ran them: every weapon row starts with the 45.0 travel budget
    # from `weapon_table_defaults_global_init` before `weapon_table_init`.
    travel_budget = oracle.resolve("weapon_projectile_travel_budget")
    assert oracle.read_f32(travel_budget + 5 * 0x7C) == 45.0
