from __future__ import annotations

import textwrap
from pathlib import Path

from crimson.schema_inventory import list_struct_classes, summarize_inventory


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding='utf-8')


def test_inventory_detects_direct_and_inherited_msgspec_structs(tmp_path: Path) -> None:
    src = tmp_path / 'src'
    _write(
        src / 'pkg' / 'base.py',
        '''
        import msgspec


        class Base(msgspec.Struct):
            value: int = 0
        ''',
    )
    _write(
        src / 'pkg' / 'child.py',
        '''
        from .base import Base


        class Child(Base):
            other: int = 1
        ''',
    )

    structs = list_struct_classes(source_root=src)
    full_names = {entry.full_name for entry in structs}

    assert 'pkg.base.Base' in full_names
    assert 'pkg.child.Child' in full_names


def test_inventory_resolves_msgspec_alias_and_reports_duplicates(tmp_path: Path) -> None:
    src = tmp_path / 'src'
    _write(
        src / 'a.py',
        '''
        import msgspec as ms


        class Packet(ms.Struct):
            seq: int = 0
        ''',
    )
    _write(
        src / 'b.py',
        '''
        from msgspec import Struct


        class Packet(Struct):
            ack: int = 0
        ''',
    )

    structs = list_struct_classes(source_root=src)
    summary = summarize_inventory(structs=structs)

    assert summary.total_structs == 2
    assert 'Packet' in summary.duplicate_names
    assert len(summary.duplicate_names['Packet']) == 2
