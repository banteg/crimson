"""Execution oracle: run functions of the original `crimsonland.exe` under x86 emulation.

The oracle maps the PE image at its preferred base, gives it a stack, a scratch
heap and a fresh x87 state per call (control word ``0x007F`` by default: the
PC24 mode Direct3D 8 leaves the FPU in during gameplay), and executes native
functions or code fragments with Unicorn.  Differential tests use it to compare
the Python port's float math bit-for-bit against the original code.

Every access outside mapped memory, every call through an import thunk that
has no registered stub and every write to read-only sections stops execution
with a `NativeTrap` naming the faulting address, the instruction, and the
nearest symbols from `analysis/ghidra/maps`, so callers learn which state to
seed or which callee to stub.

Dev tooling only: nothing in the game runtime may import this module (Unicorn
is a dev dependency).  Unicorn needs to run outside the command sandbox.
"""

from __future__ import annotations

import json
import struct
from bisect import bisect_right
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Literal

import capstone
import pefile
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN_INVALID,
    UC_HOOK_INTR,
    UC_HOOK_MEM_PROT,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MEM_FETCH_PROT,
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_READ_PROT,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_WRITE,
    UC_MEM_WRITE_PROT,
    UC_MEM_WRITE_UNMAPPED,
    UC_MODE_32,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
    UcError,
)
from unicorn import x86_const as x86

__all__ = [
    "DEFAULT_EXE_PATH",
    "F32",
    "F64",
    "GAMEPLAY_CONTROL_WORD",
    "CallResult",
    "MemoryAccess",
    "MemoryTrace",
    "NativeOracle",
    "NativeOracleError",
    "NativeTrap",
    "StubCall",
    "SymbolTable",
    "X87Value",
    "f32_bits",
]

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EXE_PATH = REPO_ROOT / "game_bins" / "crimsonland" / "1.9.93-gog" / "crimsonland.exe"
NAME_MAP_PATH = REPO_ROOT / "analysis" / "ghidra" / "maps" / "name_map.json"
DATA_MAP_PATH = REPO_ROOT / "analysis" / "ghidra" / "maps" / "data_map.json"

# PC24 (single precision), round-to-nearest, all exceptions masked.
GAMEPLAY_CONTROL_WORD = 0x007F

_PAGE = 0x1000
_STACK_BASE = 0x1000_0000
_STACK_SIZE = 0x0010_0000
_HEAP_BASE = 0x2000_0000
_HEAP_SIZE = 0x0100_0000
_IMPORT_THUNK_BASE = 0x7F00_0000
_IMPORT_THUNK_STRIDE = 0x10
_STUB_DATA_BASE = 0x7F80_0000
_STUB_DATA_SIZE = 0x1000
_CODE_BASE = 0x7FE0_0000
# One page holding the GDT (first half) and the thread information block that FS
# addresses (`fs:[0]` is the SEH chain head used by C++ EH frames and the CRT).
_SEGMENT_BASE = 0x7FD0_0000
_GDT_CODE_INDEX = 1
_GDT_DATA_INDEX = 2
_GDT_FS_INDEX = 3
_TIB = _SEGMENT_BASE + 0x800
_TIB_SIZE = 0x800
_CODE_SIZE = 0x0001_0000
# Trampoline page: code at +0, control word / target / x87 inputs in the data half.
_TRAMPOLINE_BASE = 0x7FF0_0000
_TRAMPOLINE_CONTROL_WORD = _TRAMPOLINE_BASE + 0x800
_TRAMPOLINE_TARGET = _TRAMPOLINE_BASE + 0x804
_TRAMPOLINE_X87_INPUTS = _TRAMPOLINE_BASE + 0x810
_STACK_HEADROOM = 0x100
# Longest stub patch: `fld dword [slot]` + `ret imm16`.
_STUB_PATCH_SIZE = 9
_DEFAULT_INSTRUCTION_BUDGET = 20_000_000
# `crt_get_thread_data` returns the per-thread `_tiddata`; `_holdrand` sits at +0x14.
_TIDDATA_SIZE = 0x74
_TIDDATA_HOLDRAND = 0x14

_REGISTERS = {
    "eax": x86.UC_X86_REG_EAX,
    "ebx": x86.UC_X86_REG_EBX,
    "ecx": x86.UC_X86_REG_ECX,
    "edx": x86.UC_X86_REG_EDX,
    "esi": x86.UC_X86_REG_ESI,
    "edi": x86.UC_X86_REG_EDI,
    "ebp": x86.UC_X86_REG_EBP,
    "esp": x86.UC_X86_REG_ESP,
}
_FP_REGISTERS = tuple(getattr(x86, f"UC_X86_REG_FP{index}") for index in range(8))
_MEM_ACCESS_NAMES = {
    UC_MEM_READ_UNMAPPED: "unmapped-read",
    UC_MEM_WRITE_UNMAPPED: "unmapped-write",
    UC_MEM_FETCH_UNMAPPED: "unmapped-fetch",
    UC_MEM_READ_PROT: "protected-read",
    UC_MEM_WRITE_PROT: "protected-write",
    UC_MEM_FETCH_PROT: "protected-fetch",
}


class NativeOracleError(RuntimeError):
    """The oracle could not load the image or finish a native call."""


class NativeTrap(NativeOracleError):
    """Native execution touched something the oracle does not provide."""

    def __init__(self, kind: str, message: str, *, pc: int, address: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.pc = pc
        self.address = address


@dataclass(frozen=True, slots=True)
class F32:
    """A stack argument pushed as a 4-byte float."""

    value: float


@dataclass(frozen=True, slots=True)
class F64:
    """A stack argument pushed as an 8-byte double."""

    value: float


type StackArg = int | float | F32 | F64


@dataclass(frozen=True, slots=True)
class X87Value:
    """One 80-bit x87 register, kept exact."""

    mantissa: int
    sign_exponent: int

    @property
    def fraction(self) -> Fraction:
        exponent = self.sign_exponent & 0x7FFF
        if exponent == 0x7FFF:
            raise ValueError("x87 value is an infinity or NaN")
        sign = -1 if self.sign_exponent & 0x8000 else 1
        # Denormals use exponent 1 with an explicit leading zero bit.
        shift = max(exponent, 1) - 16383 - 63
        scale = Fraction(2) ** shift
        return sign * self.mantissa * scale

    def to_float(self) -> float:
        """Round to the nearest double (exact for PC24/PC53 arithmetic results)."""

        exponent = self.sign_exponent & 0x7FFF
        if exponent == 0x7FFF:
            if self.mantissa & ((1 << 63) - 1):
                return float("nan")
            return float("-inf") if self.sign_exponent & 0x8000 else float("inf")
        if self.mantissa == 0:
            return -0.0 if self.sign_exponent & 0x8000 else 0.0
        return float(self.fraction)


@dataclass(frozen=True, slots=True)
class CallResult:
    eax: int
    edx: int
    ecx: int
    # Logical x87 stack after the call, ST(0) first.
    fpu_stack: tuple[X87Value, ...]
    # Bytes of stack arguments the callee removed (`ret N`).
    stack_popped: int
    fpu_status_word: int

    @property
    def eax_i32(self) -> int:
        return self.eax - (1 << 32) if self.eax & 0x8000_0000 else self.eax

    @property
    def st0(self) -> float:
        if not self.fpu_stack:
            raise NativeOracleError("native call left the x87 stack empty (no float return)")
        return self.fpu_stack[0].to_float()


@dataclass(frozen=True, slots=True)
class StubCall:
    """Arguments of an intercepted call, as seen at the callee's first instruction."""

    oracle: NativeOracle
    address: int
    esp: int

    @property
    def return_address(self) -> int:
        return self.oracle.read_u32(self.esp)

    @property
    def ecx(self) -> int:
        return self.oracle.reg("ecx")

    def arg_u32(self, index: int) -> int:
        return self.oracle.read_u32(self.esp + 4 + 4 * index)

    def arg_i32(self, index: int) -> int:
        return self.oracle.read_i32(self.esp + 4 + 4 * index)

    def arg_f32(self, index: int) -> float:
        return self.oracle.read_f32(self.esp + 4 + 4 * index)


type StubFn = Callable[[StubCall], int | float | None]


@dataclass(frozen=True, slots=True)
class _Stub:
    fn: StubFn | None
    returns: Literal["eax", "st0"]
    slot: int
    original: bytes


@dataclass(frozen=True, slots=True)
class _Import:
    dll: str
    name: str
    thunk: int


@dataclass(frozen=True, slots=True)
class MemoryAccess:
    kind: Literal["read", "write"]
    pc: int
    address: int
    size: int


@dataclass(slots=True)
class MemoryTrace:
    symbols: SymbolTable
    accesses: list[MemoryAccess] = field(default_factory=list)

    def touched(self, kind: Literal["read", "write"] | None = None) -> list[str]:
        """Unique `symbol+offset` names of accessed addresses, in address order."""

        addresses = sorted({access.address for access in self.accesses if kind in (None, access.kind)})
        return [self.symbols.describe(address) for address in addresses]


class SymbolTable:
    """Address-keyed names from the curated Ghidra maps."""

    def __init__(self, symbols: Mapping[int, str]) -> None:
        self._addresses = sorted(symbols)
        self._names = [symbols[address] for address in self._addresses]
        self._by_name: dict[str, int] = {}
        for address, name in zip(self._addresses, self._names, strict=True):
            self._by_name.setdefault(name, address)

    @classmethod
    def load(
        cls,
        program: str = "crimsonland.exe",
        *,
        name_map: Path = NAME_MAP_PATH,
        data_map: Path = DATA_MAP_PATH,
    ) -> SymbolTable:
        entries = list(json.loads(name_map.read_text()))
        entries.extend(json.loads(data_map.read_text())["entries"])
        symbols: dict[int, str] = {}
        for entry in entries:
            if entry.get("program") == program:
                symbols.setdefault(int(entry["address"], 16), str(entry["name"]))
        return cls(symbols)

    def address(self, name: str) -> int:
        try:
            return self._by_name[name]
        except KeyError:
            raise KeyError(f"unknown native symbol {name!r}") from None

    def nearest(self, address: int) -> tuple[str, int] | None:
        index = bisect_right(self._addresses, address) - 1
        if index < 0:
            return None
        return self._names[index], address - self._addresses[index]

    def describe(self, address: int) -> str:
        found = self.nearest(address)
        if found is None:
            return f"0x{address:08x}"
        name, offset = found
        return f"{name}+0x{offset:x} (0x{address:08x})" if offset else f"{name} (0x{address:08x})"


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _f32_bytes(value: float) -> bytes:
    return struct.pack("<f", value)


class NativeOracle:
    """Unicorn-backed harness that calls functions of the original executable."""

    def __init__(
        self,
        exe_path: Path = DEFAULT_EXE_PATH,
        *,
        symbols: SymbolTable | None = None,
        control_word: int = GAMEPLAY_CONTROL_WORD,
        instruction_budget: int = _DEFAULT_INSTRUCTION_BUDGET,
    ) -> None:
        if not exe_path.is_file():
            raise NativeOracleError(f"original executable not found: {exe_path}")
        self.symbols = symbols if symbols is not None else SymbolTable.load()
        self.control_word = control_word
        self.instruction_budget = instruction_budget
        self._trap: NativeTrap | None = None
        self._disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self._stubs: dict[int, _Stub] = {}
        self._stub_hooks: set[int] = set()
        self._stub_slot_next = _STUB_DATA_BASE
        self._import_stubs: dict[str, tuple[StubFn | None, int]] = {}

        # pefile's structures are dynamic; keep the parsed image untyped.
        pe: Any = pefile.PE(str(exe_path))
        self.image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        self.image_size = _align_up(int(pe.OPTIONAL_HEADER.SizeOfImage), _PAGE)
        self._image = bytes(pe.get_memory_mapped_image())

        self._uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self._map_image(pe)
        self._imports = self._map_imports(pe)
        self._imports_by_name = {entry.name: entry for entry in self._imports.values()}
        self._uc.mem_map(_STACK_BASE, _STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self._uc.mem_map(_HEAP_BASE, _HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self._heap_top = _HEAP_BASE
        self._uc.mem_map(_STUB_DATA_BASE, _STUB_DATA_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self._uc.mem_map(_TRAMPOLINE_BASE, _PAGE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self._uc.mem_map(_CODE_BASE, _CODE_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self._code_top = _CODE_BASE
        self._install_hooks()
        self._install_thread_segment()
        self._install_crt_thread_data()

    # -- loading -----------------------------------------------------------------

    def _map_image(self, pe: Any) -> None:
        self._uc.mem_map(self.image_base, self.image_size, UC_PROT_READ)
        self._uc.mem_write(self.image_base, self._image[: self.image_size])
        self._writable_sections: list[tuple[int, int]] = []
        for section in pe.sections:
            start = self.image_base + int(section.VirtualAddress)
            size = _align_up(max(int(section.Misc_VirtualSize), int(section.SizeOfRawData)), _PAGE)
            characteristics = int(section.Characteristics)
            perms = UC_PROT_READ
            if characteristics & 0x2000_0000:
                perms |= UC_PROT_EXEC
            if characteristics & 0x8000_0000:
                perms |= UC_PROT_WRITE
                self._writable_sections.append((start, size))
            self._uc.mem_protect(start, size, perms)

    def _map_imports(self, pe: Any) -> dict[int, _Import]:
        imports: dict[int, _Import] = {}
        thunk = _IMPORT_THUNK_BASE
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            dll = descriptor.dll.decode()
            for entry in descriptor.imports:
                name = entry.name.decode() if entry.name else f"{dll}#{entry.ordinal}"
                imports[thunk] = _Import(dll=dll, name=name, thunk=thunk)
                self._uc.mem_write(int(entry.address), struct.pack("<I", thunk))
                thunk += _IMPORT_THUNK_STRIDE
        size = _align_up(thunk - _IMPORT_THUNK_BASE, _PAGE)
        self._uc.mem_map(_IMPORT_THUNK_BASE, size, UC_PROT_READ | UC_PROT_EXEC)
        self._uc.mem_write(_IMPORT_THUNK_BASE, b"\xcc" * size)
        return imports

    def _install_hooks(self) -> None:
        self._uc.hook_add(UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_PROT, self._on_bad_memory)
        self._uc.hook_add(UC_HOOK_INTR, self._on_interrupt)
        self._uc.hook_add(UC_HOOK_INSN_INVALID, self._on_invalid_instruction)
        self._uc.hook_add(
            UC_HOOK_CODE,
            self._on_import_thunk,
            begin=_IMPORT_THUNK_BASE,
            end=_IMPORT_THUNK_BASE + len(self._imports) * _IMPORT_THUNK_STRIDE - 1,
        )

    def _install_thread_segment(self) -> None:
        self._uc.mem_map(_SEGMENT_BASE, _PAGE, UC_PROT_READ | UC_PROT_WRITE)
        # Flat ring-0 code/data segments plus an FS data segment based at the TIB.
        segments = {
            _GDT_CODE_INDEX: (0, 0xFFFFF, 0x9A, 0xC),
            _GDT_DATA_INDEX: (0, 0xFFFFF, 0x92, 0xC),
            _GDT_FS_INDEX: (_TIB, _TIB_SIZE - 1, 0x92, 0x4),
        }
        for index, (base, limit, access, flags) in segments.items():
            descriptor = (
                (limit & 0xFFFF)
                | (base & 0xFF_FFFF) << 16
                | access << 40
                | ((limit >> 16) & 0xF) << 48
                | flags << 52
                | ((base >> 24) & 0xFF) << 56
            )
            self.write(_SEGMENT_BASE + 8 * index, struct.pack("<Q", descriptor))
        self._uc.reg_write(x86.UC_X86_REG_GDTR, (0, _SEGMENT_BASE, 8 * len(segments) + 7, 0))
        self._uc.reg_write(x86.UC_X86_REG_CS, _GDT_CODE_INDEX << 3)
        for register in (x86.UC_X86_REG_DS, x86.UC_X86_REG_ES, x86.UC_X86_REG_SS):
            self._uc.reg_write(register, _GDT_DATA_INDEX << 3)
        self._uc.reg_write(x86.UC_X86_REG_FS, _GDT_FS_INDEX << 3)
        self.write_u32(_TIB, 0xFFFF_FFFF)  # empty SEH chain
        self.write_u32(_TIB + 0x18, _TIB)  # NT_TIB.Self

    def _install_crt_thread_data(self) -> None:
        # `crt_get_thread_data` asks TlsGetValue for the CRT per-thread block;
        # answering with a heap block lets crt_rand/crt_srand run natively.
        self.tiddata = self.alloc(_TIDDATA_SIZE)
        self.write_u32(self.tiddata + _TIDDATA_HOLDRAND, 1)
        self.stub_import("GetLastError", 0)
        self.stub_import("SetLastError", None, pop=4)
        self.stub_import("TlsGetValue", self.tiddata, pop=4)
        # The CRT heap falls through to the Win32 heap; serve it from the scratch heap.
        self._win32_blocks: dict[int, int] = {}
        self.stub_import("HeapAlloc", lambda call: self._heap_alloc(call.arg_u32(2)), pop=12)
        self.stub_import("HeapReAlloc", lambda call: self._heap_realloc(call.arg_u32(2), call.arg_u32(3)), pop=16)
        self.stub_import("HeapSize", lambda call: self._win32_blocks.get(call.arg_u32(2), 0xFFFF_FFFF), pop=12)
        self.stub_import("HeapFree", 1, pop=12)
        # Single-threaded emulation: CRT locks are no-ops.
        for name in ("InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection"):
            self.stub_import(name, None, pop=4)

    def _heap_alloc(self, size: int) -> int:
        address = self.alloc(max(size, 1))
        self._win32_blocks[address] = size
        return address

    def _heap_realloc(self, address: int, size: int) -> int:
        moved = self._heap_alloc(size)
        self.write(moved, self.read(address, min(size, self._win32_blocks[address])))
        return moved

    # -- symbols -------------------------------------------------------------------

    def resolve(self, target: int | str) -> int:
        return self.symbols.address(target) if isinstance(target, str) else int(target)

    def describe(self, address: int) -> str:
        if _IMPORT_THUNK_BASE <= address < _IMPORT_THUNK_BASE + len(self._imports) * _IMPORT_THUNK_STRIDE:
            entry = self._imports[address - (address - _IMPORT_THUNK_BASE) % _IMPORT_THUNK_STRIDE]
            return f"import thunk {entry.dll}!{entry.name} (0x{address:08x})"
        if _STACK_BASE <= address < _STACK_BASE + _STACK_SIZE:
            return f"oracle stack (0x{address:08x})"
        if _HEAP_BASE <= address < _HEAP_BASE + _HEAP_SIZE:
            return f"oracle heap (0x{address:08x})"
        if address < 0x10000:
            return f"null page (0x{address:08x})"
        if self.image_base <= address < self.image_base + self.image_size:
            return self.symbols.describe(address)
        return f"unmapped 0x{address:08x}"

    # -- memory --------------------------------------------------------------------

    def read(self, address: int | str, size: int) -> bytes:
        return bytes(self._uc.mem_read(self.resolve(address), size))

    def write(self, address: int | str, data: bytes) -> None:
        self._uc.mem_write(self.resolve(address), bytes(data))

    def read_u8(self, address: int | str) -> int:
        return self.read(address, 1)[0]

    def write_u8(self, address: int | str, value: int) -> None:
        self.write(address, bytes((int(value) & 0xFF,)))

    def read_u32(self, address: int | str) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def read_i32(self, address: int | str) -> int:
        return struct.unpack("<i", self.read(address, 4))[0]

    def write_u32(self, address: int | str, value: int) -> None:
        self.write(address, struct.pack("<I", int(value) & 0xFFFF_FFFF))

    write_i32 = write_u32

    def read_f32(self, address: int | str) -> float:
        return struct.unpack("<f", self.read(address, 4))[0]

    def read_f32_bits(self, address: int | str) -> int:
        return self.read_u32(address)

    def write_f32(self, address: int | str, value: float) -> None:
        self.write(address, _f32_bytes(value))

    def read_f64(self, address: int | str) -> float:
        return struct.unpack("<d", self.read(address, 8))[0]

    def write_f64(self, address: int | str, value: float) -> None:
        self.write(address, struct.pack("<d", value))

    def read_fields(self, address: int | str, layout: Mapping[str, tuple[int, str]]) -> dict[str, int | float]:
        """Read `{name: (offset, struct_format)}` fields relative to `address`."""

        base = self.resolve(address)
        out: dict[str, int | float] = {}
        for name, (offset, fmt) in layout.items():
            size = struct.calcsize("<" + fmt)
            out[name] = struct.unpack("<" + fmt, self.read(base + offset, size))[0]
        return out

    def alloc(self, size: int, *, align: int = 16, data: bytes | None = None) -> int:
        """Bump-allocate zeroed scratch memory (for structs passed by pointer)."""

        address = _align_up(self._heap_top, align)
        if address + size > _HEAP_BASE + _HEAP_SIZE:
            raise NativeOracleError("oracle scratch heap exhausted")
        self._heap_top = address + size
        if data is not None:
            self.write(address, data)
        return address

    def alloc_f32s(self, *values: float) -> int:
        return self.alloc(4 * len(values), data=b"".join(_f32_bytes(value) for value in values))

    def load_code(self, code: bytes) -> int:
        """Place raw x86 code (a probe snippet) in an executable scratch page."""

        address = _align_up(self._code_top, 16)
        if address + len(code) > _CODE_BASE + _CODE_SIZE:
            raise NativeOracleError("oracle code page exhausted")
        self._code_top = address + len(code)
        self.write(address, code)
        return address

    @property
    def rand_state(self) -> int:
        """CRT `rand()` seed (`_tiddata._holdrand`)."""

        return self.read_u32(self.tiddata + _TIDDATA_HOLDRAND)

    @rand_state.setter
    def rand_state(self, value: int) -> None:
        self.write_u32(self.tiddata + _TIDDATA_HOLDRAND, value)

    def snapshot(self) -> tuple[bytes, ...]:
        """Capture the writable image sections and the scratch heap."""

        sections = tuple(self.read(start, size) for start, size in self._writable_sections)
        return (*sections, self.read(_HEAP_BASE, self._heap_top - _HEAP_BASE))

    def restore(self, snapshot: tuple[bytes, ...]) -> None:
        *sections, heap = snapshot
        for (start, _size), data in zip(self._writable_sections, sections, strict=True):
            self.write(start, data)
        stale = self._heap_top - _HEAP_BASE - len(heap)
        if stale > 0:
            self.write(_HEAP_BASE + len(heap), bytes(stale))
        self.write(_HEAP_BASE, heap)
        self._heap_top = _HEAP_BASE + len(heap)

    def reg(self, name: str) -> int:
        return int(self._uc.reg_read(_REGISTERS[name]))

    # -- stubs ---------------------------------------------------------------------

    def stub_import(self, name: str, fn: StubFn | int | None = None, *, pop: int = 0) -> None:
        """Answer calls to an imported API; `pop` is the stdcall argument byte count."""

        entry = self._imports_by_name.get(name)
        if entry is None:
            raise KeyError(f"crimsonland.exe does not import {name!r}")
        self._import_stubs[name] = (_constant_stub(fn), pop)
        self._uc.mem_write(entry.thunk, _ret(pop))
        self._uc.ctl_remove_cache(entry.thunk, entry.thunk + _IMPORT_THUNK_STRIDE)

    def stub(
        self,
        target: int | str,
        fn: StubFn | float | None = None,
        *,
        pop: int = 0,
        returns: Literal["eax", "st0"] = "eax",
    ) -> None:
        """Replace a native function with a Python callback (or a constant).

        `pop` is the callee-cleaned argument byte count (stdcall/thiscall);
        `returns="st0"` pushes the callback's float result as a float32 on the x87 stack.
        """

        address = self.resolve(target)
        existing = self._stubs.get(address)
        if returns == "st0":
            slot = existing.slot if existing is not None and existing.slot else self._alloc_stub_slot()
            code = b"\xd9\x05" + struct.pack("<I", slot) + _ret(pop)
        else:
            slot = 0
            code = _ret(pop)
        original = self.read(address, _STUB_PATCH_SIZE) if existing is None else existing.original
        if address not in self._stub_hooks:
            # One code hook per address for the oracle's lifetime; it dispatches via `_stubs`.
            self._stub_hooks.add(address)
            self._uc.hook_add(UC_HOOK_CODE, self._on_stub, begin=address, end=address)
        self._stubs[address] = _Stub(fn=_constant_stub(fn), returns=returns, slot=slot, original=original)
        self.write(address, code)
        self._uc.ctl_remove_cache(address, address + len(code))

    def unstub(self, target: int | str) -> None:
        address = self.resolve(target)
        stub = self._stubs.pop(address)
        self.write(address, stub.original)
        self._uc.ctl_remove_cache(address, address + len(stub.original))

    def _alloc_stub_slot(self) -> int:
        slot = self._stub_slot_next
        if slot + 4 > _STUB_DATA_BASE + _STUB_DATA_SIZE:
            raise NativeOracleError("too many float-returning stubs")
        self._stub_slot_next += 4
        return slot

    def run_static_initializers(self) -> dict[int, NativeTrap]:
        """Run the CRT C initializers and C++ static constructors, as CRT startup does.

        They seed global tables such as the weapon defaults. Returns the traps of
        initializers that need unprovided state, keyed by initializer address;
        all others have run.
        """

        failures: dict[int, NativeTrap] = {}
        for begin, end in (("crt_xi_begin", "crt_xi_end"), ("crt_xc_begin", "crt_xc_end")):
            for entry in range(self.resolve(begin), self.resolve(end), 4):
                initializer = self.read_u32(entry)
                if not initializer:
                    continue
                try:
                    self.call(initializer)
                except NativeTrap as trap:
                    failures[initializer] = trap
        return failures

    # -- execution -----------------------------------------------------------------

    def call(
        self,
        target: int | str,
        *args: StackArg,
        ecx: int | None = None,
        regs: Mapping[str, int] | None = None,
        st: Sequence[float | X87Value] = (),
        control_word: int | None = None,
    ) -> CallResult:
        """Call a native function with cdecl/stdcall/thiscall stack arguments.

        Python `float` and `F32` arguments are pushed as float32, `F64` as double.
        `st` preloads the x87 stack (`st[0]` ends up in ST(0)) for register-argument
        helpers such as `__ftol` or `__CIpow`.
        """

        entry = self.resolve(target)
        payload = b"".join(_pack_arg(arg) for arg in args)
        esp = _STACK_BASE + _STACK_SIZE - _STACK_HEADROOM - _align_up(len(payload), 4)
        self.write(esp, payload)
        registers = dict(regs or {})
        if ecx is not None:
            registers["ecx"] = ecx
        registers["esp"] = esp
        self._emulate(entry, until=None, registers=registers, st=st, control_word=control_word)
        return self._result(stack_popped=self.reg("esp") - esp)

    def run(
        self,
        start: int | str,
        stop: int | str,
        *,
        regs: Mapping[str, int] | None = None,
        frame: bytes = b"",
        frame_size: int = 0x400,
        st: Sequence[float | X87Value] = (),
        control_word: int | None = None,
    ) -> CallResult:
        """Execute a code fragment from `start` until it reaches `stop`.

        Unless `regs` sets ESP, ESP points at a zeroed `frame_size`-byte stack
        frame (see `frame_pointer`) that starts with `frame`.
        """

        registers = dict(regs or {})
        if "esp" not in registers:
            esp = self.frame_pointer(frame_size)
            self.write(esp, frame.ljust(frame_size, b"\0"))
            registers["esp"] = esp
        self._emulate(self.resolve(start), until=self.resolve(stop), registers=registers, st=st, control_word=control_word)
        return self._result(stack_popped=0)

    def frame_pointer(self, frame_size: int = 0x400) -> int:
        """ESP that `run()` uses for a stack frame of `frame_size` bytes."""

        return _STACK_BASE + _STACK_SIZE - _STACK_HEADROOM - _align_up(frame_size, 4)

    @contextmanager
    def trace_memory(self) -> Iterator[MemoryTrace]:
        """Record native reads/writes of the image's writable sections (game state)."""

        trace = MemoryTrace(symbols=self.symbols)
        handles = [
            self._uc.hook_add(
                UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                self._on_traced_access,
                user_data=trace,
                begin=start,
                end=start + size - 1,
            )
            for start, size in self._writable_sections
        ]
        try:
            yield trace
        finally:
            for handle in handles:
                self._uc.hook_del(handle)

    def _emulate(
        self,
        entry: int,
        *,
        until: int | None,
        registers: Mapping[str, int],
        st: Sequence[float | X87Value],
        control_word: int | None,
    ) -> None:
        # fninit; fldcw [cw]; fld <inputs, deepest first>; call/jmp [target]
        code = b"\xdb\xe3" + b"\xd9\x2d" + struct.pack("<I", _TRAMPOLINE_CONTROL_WORD)
        slot = _TRAMPOLINE_X87_INPUTS
        for value in reversed(st):
            if isinstance(value, X87Value):
                self.write(slot, struct.pack("<QH", value.mantissa, value.sign_exponent))
                code += b"\xdb\x2d" + struct.pack("<I", slot)  # fld tbyte
            else:
                self.write_f64(slot, value)
                code += b"\xdd\x05" + struct.pack("<I", slot)  # fld qword
            slot += 16
        code += (b"\xff\x15" if until is None else b"\xff\x25") + struct.pack("<I", _TRAMPOLINE_TARGET)
        stop = _TRAMPOLINE_BASE + len(code) if until is None else until
        self.write(_TRAMPOLINE_BASE, code + b"\xf4")
        self._uc.ctl_remove_cache(_TRAMPOLINE_BASE, _TRAMPOLINE_BASE + len(code) + 1)
        self.write_u32(_TRAMPOLINE_TARGET, entry)
        self.write(_TRAMPOLINE_CONTROL_WORD, struct.pack("<H", self.control_word if control_word is None else control_word))
        for name, uc_reg in _REGISTERS.items():
            self._uc.reg_write(uc_reg, int(registers.get(name, 0)) & 0xFFFF_FFFF)
        self._uc.reg_write(x86.UC_X86_REG_EFLAGS, 0x202)
        self._trap = None
        try:
            self._uc.emu_start(_TRAMPOLINE_BASE, stop, count=self.instruction_budget)
        except UcError as exc:
            if self._trap is not None:
                raise self._trap from None
            pc = int(self._uc.reg_read(x86.UC_X86_REG_EIP))
            raise NativeOracleError(f"emulation failed at {self.describe(pc)}: {exc}") from exc
        if self._trap is not None:
            raise self._trap
        pc = int(self._uc.reg_read(x86.UC_X86_REG_EIP))
        if pc != stop:
            raise NativeTrap(
                "budget",
                f"instruction budget ({self.instruction_budget}) exhausted at {self.describe(pc)}",
                pc=pc,
            )

    def _result(self, *, stack_popped: int) -> CallResult:
        status = int(self._uc.reg_read(x86.UC_X86_REG_FPSW))
        tags = int(self._uc.reg_read(x86.UC_X86_REG_FPTAG))
        top = (status >> 11) & 7
        stack: list[X87Value] = []
        for depth in range(8):
            physical = (top + depth) & 7
            if (tags >> (2 * physical)) & 3 == 3:
                break
            mantissa, exponent = self._uc.reg_read(_FP_REGISTERS[physical])
            stack.append(X87Value(int(mantissa), int(exponent)))
        return CallResult(
            eax=self.reg("eax"),
            edx=self.reg("edx"),
            ecx=self.reg("ecx"),
            fpu_stack=tuple(stack),
            stack_popped=stack_popped,
            fpu_status_word=status,
        )

    # -- hooks ---------------------------------------------------------------------

    def _stop(self, trap: NativeTrap) -> None:
        if self._trap is None:
            self._trap = trap
        self._uc.emu_stop()

    def _on_bad_memory(self, uc: Uc, access: int, address: int, size: int, value: int, _user: object) -> bool:
        pc = int(uc.reg_read(x86.UC_X86_REG_EIP))
        kind = _MEM_ACCESS_NAMES.get(access, f"memory-access-{access}")
        if access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT):
            caller = self.read_u32(int(uc.reg_read(x86.UC_X86_REG_ESP)))
            message = (
                f"{kind}: jumped to {self.describe(address)}; "
                f"[esp] = {self.describe(caller)} (likely call site of a null/unset function pointer)"
            )
        else:
            message = (
                f"{kind} of {size} bytes at {self.describe(address)} by `{self._instruction_text(pc)}` "
                f"at {self.describe(pc)} [{self._register_text()}]"
            )
            if access == UC_MEM_WRITE_PROT:
                message += f" (value 0x{value & 0xFFFF_FFFF:x})"
        self._stop(NativeTrap(kind, message, pc=pc, address=address))
        return False

    def _instruction_text(self, pc: int) -> str:
        try:
            code = self.read(pc, 16)
        except UcError:
            return "?"
        for instruction in self._disassembler.disasm(code, pc, count=1):
            return f"{instruction.mnemonic} {instruction.op_str}".strip()
        return "?"

    def _register_text(self) -> str:
        return " ".join(f"{name}=0x{self.reg(name):x}" for name in _REGISTERS)

    def _on_interrupt(self, uc: Uc, number: int, _user: object) -> None:
        pc = int(uc.reg_read(x86.UC_X86_REG_EIP))
        self._stop(NativeTrap("interrupt", f"interrupt {number} near {self.describe(pc)}", pc=pc))

    def _on_invalid_instruction(self, uc: Uc, _user: object) -> bool:
        pc = int(uc.reg_read(x86.UC_X86_REG_EIP))
        text = self._instruction_text(pc)
        self._stop(NativeTrap("invalid-instruction", f"unsupported instruction `{text}` at {self.describe(pc)}", pc=pc))
        return False

    def _on_import_thunk(self, uc: Uc, address: int, _size: int, _user: object) -> None:
        entry = self._imports[address]
        esp = int(uc.reg_read(x86.UC_X86_REG_ESP))
        stub = self._import_stubs.get(entry.name)
        if stub is None:
            caller = self.read_u32(esp)
            self._stop(
                NativeTrap(
                    "import",
                    f"call to unstubbed import {entry.dll}!{entry.name} from {self.describe(caller)}; "
                    f"register it with NativeOracle.stub_import({entry.name!r}, ...)",
                    pc=address,
                    address=address,
                ),
            )
            return
        fn, _pop = stub
        if fn is not None:
            value = fn(StubCall(oracle=self, address=address, esp=esp))
            if value is not None:
                uc.reg_write(x86.UC_X86_REG_EAX, int(value) & 0xFFFF_FFFF)

    def _on_stub(self, uc: Uc, address: int, _size: int, _user: object) -> None:
        stub = self._stubs.get(address)
        if stub is None or stub.fn is None:
            return
        value = stub.fn(StubCall(oracle=self, address=address, esp=int(uc.reg_read(x86.UC_X86_REG_ESP))))
        if stub.returns == "st0":
            self.write_f32(stub.slot, float(value or 0.0))
        elif value is not None:
            uc.reg_write(x86.UC_X86_REG_EAX, int(value) & 0xFFFF_FFFF)

    def _on_traced_access(self, uc: Uc, access: int, address: int, size: int, _value: int, trace: MemoryTrace) -> None:
        kind: Literal["read", "write"] = "write" if access == UC_MEM_WRITE else "read"
        trace.accesses.append(
            MemoryAccess(kind=kind, pc=int(uc.reg_read(x86.UC_X86_REG_EIP)), address=address, size=size),
        )


def _ret(pop: int) -> bytes:
    return b"\xc2" + struct.pack("<H", pop) if pop else b"\xc3"


def _constant_stub(fn: StubFn | float | None) -> StubFn | None:
    if fn is None or not isinstance(fn, int | float):
        return fn
    constant = fn
    return lambda _call: constant


def _pack_arg(arg: StackArg) -> bytes:
    match arg:
        case F64(value=value):
            return struct.pack("<d", value)
        case F32(value=value):
            return _f32_bytes(value)
        case bool() | int():
            return struct.pack("<I", int(arg) & 0xFFFF_FFFF)
        case float():
            return _f32_bytes(arg)
    raise TypeError(f"unsupported native stack argument: {arg!r}")


def f32_bits(value: float) -> int:
    """IEEE bits of `value` rounded to float32."""

    return struct.unpack("<I", _f32_bytes(value))[0]
