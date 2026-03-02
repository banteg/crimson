from __future__ import annotations

import ast
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StructClass:
    class_name: str
    full_name: str
    module: str
    path: str
    lineno: int


@dataclass(frozen=True)
class InventorySummary:
    total_structs: int
    counts_by_bucket: dict[str, int]
    duplicate_names: dict[str, list[StructClass]]


def _module_name_for_path(*, source_root: Path, py_path: Path) -> str:
    rel = py_path.relative_to(source_root)
    parts = list(rel.parts)
    if parts and parts[-1].endswith('.py'):
        parts[-1] = parts[-1][:-3]
    if parts and parts[-1] == '__init__':
        parts = parts[:-1]
    return '.'.join(part for part in parts if part)


def _resolve_import_module(*, current_module: str, imported_module: str | None, level: int) -> str:
    if level <= 0:
        return str(imported_module or '')

    parts = [part for part in current_module.split('.') if part]
    base_parts = parts[:-level] if level <= len(parts) else []
    if imported_module:
        base_parts.extend([part for part in imported_module.split('.') if part])
    return '.'.join(base_parts)


def _base_name(base: ast.expr) -> str | None:
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute):
        chain: list[str] = []
        cur: ast.expr | None = base
        while isinstance(cur, ast.Attribute):
            chain.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            chain.append(cur.id)
            return '.'.join(reversed(chain))
    return None


def _resolve_symbol(symbol: str, *, imports: dict[str, str]) -> str:
    if symbol in imports:
        return imports[symbol]
    if '.' not in symbol:
        return symbol
    root, rest = symbol.split('.', 1)
    if root in imports:
        return f"{imports[root]}.{rest}"
    return symbol


@dataclass(frozen=True)
class _ClassInfo:
    class_name: str
    full_name: str
    module: str
    path: str
    lineno: int
    resolved_bases: tuple[str, ...]


def _iter_class_infos(source_root: Path) -> list[_ClassInfo]:
    infos: list[_ClassInfo] = []
    for py_path in sorted(source_root.rglob('*.py')):
        module = _module_name_for_path(source_root=source_root, py_path=py_path)
        try:
            tree = ast.parse(py_path.read_text(encoding='utf-8'))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue

        imports: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = alias.asname or alias.name
                    imports[target] = alias.name
            elif isinstance(node, ast.ImportFrom):
                import_module = _resolve_import_module(
                    current_module=module,
                    imported_module=node.module,
                    level=int(node.level),
                )
                for alias in node.names:
                    if alias.name == '*':
                        continue
                    target = alias.asname or alias.name
                    if import_module:
                        imports[target] = f"{import_module}.{alias.name}"
                    else:
                        imports[target] = alias.name

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            full_name = f"{module}.{node.name}" if module else node.name
            bases: list[str] = []
            for base in node.bases:
                raw = _base_name(base)
                if not raw:
                    continue
                bases.append(_resolve_symbol(raw, imports=imports))
            infos.append(
                _ClassInfo(
                    class_name=node.name,
                    full_name=full_name,
                    module=module,
                    path=py_path.as_posix(),
                    lineno=int(node.lineno),
                    resolved_bases=tuple(bases),
                ),
            )
    return infos


def list_struct_classes(*, source_root: Path) -> list[StructClass]:
    infos = _iter_class_infos(source_root)

    by_full_name = {info.full_name: info for info in infos}
    struct_full_names: set[str] = set()

    for info in infos:
        if 'msgspec.Struct' in info.resolved_bases:
            struct_full_names.add(info.full_name)

    changed = True
    while changed:
        changed = False
        for info in infos:
            if info.full_name in struct_full_names:
                continue
            for base in info.resolved_bases:
                if base in struct_full_names:
                    struct_full_names.add(info.full_name)
                    changed = True
                    break
                if '.' not in base:
                    same_module_base = f"{info.module}.{base}" if info.module else base
                    if same_module_base in struct_full_names:
                        struct_full_names.add(info.full_name)
                        changed = True
                        break

    structs: list[StructClass] = []
    for full_name in sorted(struct_full_names):
        info = by_full_name.get(full_name)
        if info is None:
            continue
        structs.append(
            StructClass(
                class_name=info.class_name,
                full_name=info.full_name,
                module=info.module,
                path=info.path,
                lineno=info.lineno,
            ),
        )
    return structs


def _bucket_for_path(path: str) -> str:
    parts = path.split('/')
    if len(parts) >= 3 and parts[0] == 'src' and parts[1] == 'crimson':
        return parts[2]
    if len(parts) >= 2 and parts[0] == 'src':
        return parts[1]
    return 'other'


def summarize_inventory(*, structs: list[StructClass]) -> InventorySummary:
    counts = Counter(_bucket_for_path(item.path) for item in structs)
    by_name: dict[str, list[StructClass]] = defaultdict(list)
    for item in structs:
        by_name[item.class_name].append(item)
    duplicates = {
        name: sorted(items, key=lambda entry: (entry.path, entry.lineno))
        for name, items in by_name.items()
        if len(items) > 1
    }
    return InventorySummary(
        total_structs=len(structs),
        counts_by_bucket=dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        duplicate_names=dict(sorted(duplicates.items())),
    )


def inventory_as_json(*, summary: InventorySummary, structs: list[StructClass]) -> str:
    payload = {
        'total_structs': int(summary.total_structs),
        'counts_by_bucket': {str(k): int(v) for k, v in summary.counts_by_bucket.items()},
        'duplicate_names': {
            str(name): [
                {
                    'path': item.path,
                    'lineno': int(item.lineno),
                    'module': item.module,
                    'full_name': item.full_name,
                }
                for item in items
            ]
            for name, items in summary.duplicate_names.items()
        },
        'structs': [
            {
                'class_name': item.class_name,
                'full_name': item.full_name,
                'module': item.module,
                'path': item.path,
                'lineno': int(item.lineno),
            }
            for item in structs
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
