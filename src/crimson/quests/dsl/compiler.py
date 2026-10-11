from __future__ import annotations

import ast
import math
import operator
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from grim.geom import Vec2
from grim.rand import CrtRand

from ...creatures.spawn_ids import SpawnId
from ...math_parity import NATIVE_TAU, f32, x87_pc24_add, x87_pc24_div, x87_pc24_mul, x87_pc24_sub
from ...weapons import WeaponId
from ..helpers import (
    NATIVE_CENTER,
    EdgePoints,
    angle_step,
    corner_points,
    edge_midpoints,
    heading_from_center,
    line_points,
    radial_points,
    random_angle,
    ring_point,
    ring_points,
    spawn,
)
from ..runtime import apply_hardcore_spawn_table_adjustment
from ..types import QuestContext, SpawnEntry
from .model import CompileLimits, QuestPlan, SourceLocation


class QuestCompileError(ValueError):
    def __init__(self, message: str, line: int = 1):
        self.line = line
        super().__init__(f"line {line}: {message}")


# Tokenize expressions before rewriting units/booleans: strings and comments stay literal.
_TOKEN = re.compile(
    r"""("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\#.*|\b(?:\d+(?:\.\d*)?|\.\d+)(?:ms|s|deg)\b|\b[a-zA-Z_]\w*\b)""",
)


def _expression(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match[0]
        if token.startswith(("'", '"', "#")):
            return token
        if token.startswith("_"):
            raise QuestCompileError("names beginning with '_' are reserved")
        if token in ("true", "false"):
            return token.title()
        unit = re.fullmatch(r"(\d+(?:\.\d*)?|\.\d+)(ms|s|deg)", token)
        if unit:
            value = float(unit[1])
            if unit[2] == "deg":
                return repr(math.radians(value))
            value *= 1000 if unit[2] == "s" else 1
            if not value.is_integer():
                raise QuestCompileError("time literals must resolve to whole milliseconds")
            return str(int(value))
        return token

    return _TOKEN.sub(replace, text)


def _lower(source: str) -> tuple[ast.Module, dict[str, Any]]:
    """Lower the indentation-based surface grammar into AST nodes, preserving line numbers.

    The AST is interpreted by the allowlist below; compile/eval/exec are never used.
    """
    metadata: dict[str, Any] = {
        "order": "chronological",
        "counts": "explicit",
        "weapon": "pistol",
        "terrain": (0, 1, 0),
    }
    seen: set[str] = set()
    lowered = []
    started = False
    for line_number, line in enumerate(source.splitlines(), 1):
        indent = line[: len(line) - len(line.lstrip())]
        text = line.strip()
        for token in _TOKEN.finditer(text):
            if token[0].startswith("#"):
                text = text[: token.start()].rstrip()
                break
        if not text or text.startswith("#"):
            lowered.append(line)
            continue
        header = re.fullmatch(r'quest\s+("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')\s+version\s+(\d+)', text)
        directive = re.fullmatch(r"(order|counts|weapon|terrain)\s+(.+)", text)
        try:
            if header or directive:
                if indent or started:
                    raise QuestCompileError("quest settings must precede construction statements", line_number)
                key = "quest" if header else directive[1] if directive else ""
                if key in seen:
                    raise QuestCompileError(f"duplicate {key} setting", line_number)
                seen.add(key)
                if header:
                    metadata.update(title=ast.literal_eval(header[1]), version=int(header[2]))
                else:
                    assert directive is not None
                    metadata[key] = ast.literal_eval(directive[2]) if key == "terrain" else directive[2]
                lowered.append("")
                continue
            started = True
            text = _expression(text)
            if match := re.fullmatch(r"(let|var)\s+(\w+)\s*=\s*(.+)", text):
                text = f"{match[2]}: __{match[1]}__ = {match[3]}"
            elif match := re.fullmatch(r"repeat\s+(.+)\s+as\s+(\w+)\s*:", text):
                text = f"for {match[2]} in range({match[1]}):"
            elif match := re.fullmatch(r"pattern\s+(.+)\s*:", text):
                text = f"def {match[1]}:"
            elif match := re.fullmatch(r"at\s+(.+)\s*:", text):
                text = f"with __at__({match[1]}):"
            elif match := re.fullmatch(r"(spawn|burst|place)\s+(.+?)\s+(?:at|on)\s+(.+)", text):
                kind, template, rest = match.groups()
                heading = "0"
                if " heading " in rest:
                    rest, heading = rest.rsplit(" heading ", 1)
                count = "1"
                if kind == "burst":
                    if " copies " not in rest:
                        raise QuestCompileError("burst requires 'copies N'", line_number)
                    rest, count = rest.rsplit(" copies ", 1)
                target = "__place__" if kind == "place" else "__spawn__"
                text = f"{target}({template}, {rest}, {heading}, {count})"
            lowered.append(indent + text)
        except (SyntaxError, ValueError) as exc:
            raise QuestCompileError(str(exc), line_number) from exc
    if "quest" not in seen or metadata["version"] != 1:
        raise QuestCompileError('expected quest "Title" version 1')
    if metadata["order"] not in ("native", "chronological") or metadata["counts"] not in ("native", "explicit"):
        raise QuestCompileError("order must be native/chronological; counts must be native/explicit")
    try:
        metadata["weapon"] = WeaponId[metadata["weapon"].upper()]
        if metadata["weapon"] == WeaponId.NONE:
            raise ValueError("starting weapon must not be NONE")
        slots = metadata["terrain"]
        if (
            not isinstance(slots, tuple)
            or len(slots) != 3
            or any(type(slot) is not int or not 0 <= slot <= 7 for slot in slots)
        ):
            raise ValueError("terrain must be three slot IDs in 0..7")
        tree = ast.parse("\n".join(lowered))
    except (SyntaxError, ValueError, KeyError, RecursionError) as exc:
        raise QuestCompileError(str(exc), getattr(exc, "lineno", 1) or 1) from exc
    return tree, metadata


@dataclass
class _Scope:
    parent: _Scope | None = None
    values: dict[str, Any] = field(default_factory=dict)
    mutable: set[str] = field(default_factory=set)

    def owner(self, name: str) -> _Scope:
        if name in self.values:
            return self
        if self.parent is not None:
            return self.parent.owner(name)
        raise ValueError(f"unknown name {name!r}")

    def assign(self, name: str, value: Any) -> None:
        owner = self.owner(name)
        if name not in owner.mutable:
            raise ValueError(f"{name!r} is immutable; declare a var to update it")
        owner.values[name] = value


class _Break(Exception):
    pass


_BINARY: dict[type[ast.operator], Callable[[Any, Any], Any]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
}
_UNARY: dict[type[ast.unaryop], Callable[[Any], Any]] = {
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Not: operator.not_,
}
_COMPARE: dict[type[ast.cmpop], Callable[[Any, Any], Any]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: operator.contains,
    ast.NotIn: operator.contains,
}
_ALIASES = {
    "alien": {"small_gray": SpawnId.ALIEN_SMALL_GRAY_26, "fast": SpawnId.ALIEN_DEADLY_FAST_2B},
    "spider": {
        "small_blue": SpawnId.SPIDER_SMALL_BLUE_40,
        "plasma": SpawnId.SPIDER_PLASMA_SHOOTER_3C,
        "splitter": SpawnId.SPIDER_SP2_SPLITTER_01,
        "boss": SpawnId.SPIDER_BOSS_3A,
    },
    "zombie": {"random": SpawnId.ZOMBIE_RANDOM_41, "spawner_boss": SpawnId.ZOMBIE_BOSS_SPAWNER_00},
    "nest": {
        "alien": SpawnId.DEN_ALIEN_BASIC_07,
        "alien_slow": SpawnId.DEN_ALIEN_BASIC_SLOWER_08,
        "spider": SpawnId.DEN_SPIDER_BASIC_0A,
        "plasma": SpawnId.DEN_SPIDER_PLASMA_SHOOTERS_0B,
    },
    "formation": {
        "alien_ring": SpawnId.FORMATION_RING_ALIEN_8_12,
        "lizard_chain": SpawnId.FORMATION_CHAIN_LIZARD_4_11,
        "alien_grid": SpawnId.FORMATION_GRID_ALIEN_WHITE_15,
        "lizard_grid": SpawnId.FORMATION_GRID_LIZARD_WHITE_16,
        "spider_grid": SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17,
    },
    "template": {member.name.lower(): member for member in SpawnId if member != SpawnId.UNUSED_02},
}


class _Compiler:
    def __init__(self, ctx: QuestContext, limits: CompileLimits):
        self.ctx, self.limits = ctx, limits
        self.work = 0
        self.entries: list[SpawnEntry] = []
        self.locations: list[SourceLocation] = []
        self.iterations: list[int] = []
        self.time: int | None = None
        self.patterns: dict[str, ast.FunctionDef] = {}
        self.active_patterns: set[str] = set()
        self.root = _Scope(
            values={
                **_ALIASES,
                "center": NATIVE_CENTER,
                "players": ctx.player_count,
                "hardcore": ctx.hardcore,
                "arena_size": 1024,
                "pi": math.pi,
                "tau": math.tau,
                "native_tau": NATIVE_TAU,
            },
        )
        self.functions: dict[str, Callable[..., Any]] = {
            "min": lambda *values: self.extreme(min, values),
            "max": lambda *values: self.extreme(max, values),
            "abs": abs,
            "int": int,
            "float": float,
            "len": len,
            "point": Vec2,
            "edge_points": edge_midpoints,
            "corners": corner_points,
            "polar": ring_point,
            "angle_step": angle_step,
            "random_angle": random_angle,
            "heading_from_center": heading_from_center,
            "f32": f32,
            "pc24_add": x87_pc24_add,
            "pc24_sub": x87_pc24_sub,
            "pc24_mul": x87_pc24_mul,
            "pc24_div": x87_pc24_div,
            "range": self.bounded_range,
            "line": self.line,
            "ring": self.ring,
            "ring_angles": self.ring_angles,
            "radial": self.radial,
            "edge": self.edge,
            "edge_line": self.edge_line,
            "opposite": self.opposite,
            "arc": self.arc,
            "rotate": self.rotate,
            "rand": self.rand,
            "choose": self.choose,
            "rand_int": self.rand_int,
            "shuffle": self.shuffle,
        }

    def tick(self, node: ast.AST, amount: int = 1) -> None:
        self.work += amount
        if self.work > self.limits.work:
            raise QuestCompileError("construction work budget exceeded", getattr(node, "lineno", 1))

    def bounded(self, value: Any) -> Any:
        if isinstance(value, (list, tuple, range, str)) and len(value) > self.limits.collection:
            raise ValueError("collection limit exceeded")
        if isinstance(value, int) and value.bit_length() > 64:
            raise ValueError("integer magnitude exceeds 64 bits")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("numbers must be finite")
        return value

    @staticmethod
    def integer(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("expected an integer")
        return value

    def bounded_range(self, *args: int) -> range:
        return self.bounded(range(*(self.integer(arg) for arg in args)))

    @staticmethod
    def scalar(value: Any) -> None:
        if not isinstance(value, (int, float, str, Vec2)):
            raise TypeError("comparisons require scalar values or points")

    def extreme(self, function: Callable[..., Any], values: tuple) -> Any:
        if len(values) == 1 and isinstance(values[0], (tuple, list, range)):
            values = values[0]
        if not all(isinstance(value, (int, float)) for value in values):
            raise TypeError("min/max require numbers")
        return function(values)

    def line(self, start: Vec2, step: Vec2, count: int) -> tuple[Vec2, ...]:
        return tuple(line_points(start, step, len(self.bounded_range(count))))

    def ring_angles(self, center: Vec2, radius: float, count: int, *, step: float, start: float = 0) -> tuple:
        return tuple(ring_points(center, radius, len(self.bounded_range(count)), step=step, start=start))

    def ring(self, center: Vec2, radius: float, count: int, *, start: float = 0) -> tuple[Vec2, ...]:
        # Operation order deliberately matches Gauntlet: (index * native_tau) / count.
        return tuple(
            ring_point(
                center,
                radius,
                x87_pc24_add(x87_pc24_div(x87_pc24_mul(float(i), NATIVE_TAU), float(count)), f32(start)),
            )
            for i in self.bounded_range(count)
        )

    def radial(self, center: Vec2, angle: float, start: int, stop: int, step: int) -> tuple[Vec2, ...]:
        self.bounded_range(start, stop, step)
        return tuple(radial_points(center, angle, start, stop, step))

    def edge(self, side: str, *, outside: float = 64, fraction: float = 0.5) -> Vec2:
        along = 1024 * fraction
        return {
            "west": Vec2(-outside, along),
            "east": Vec2(1024 + outside, along),
            "north": Vec2(along, -outside),
            "south": Vec2(along, 1024 + outside),
        }[side]

    def edge_line(self, side: str, count: int, spacing: float, *, outside: float = 64) -> tuple[Vec2, ...]:
        count = self.integer(count)
        if count < 0:
            raise ValueError("edge_line count must be nonnegative")
        self.bounded_range(count)
        anchor = self.edge(side, outside=outside)
        step = Vec2(0, spacing) if side in ("west", "east") else Vec2(spacing, 0)
        start = Vec2(anchor.x - step.x * (count - 1) * 0.5, anchor.y - step.y * (count - 1) * 0.5)
        return self.line(start, step, count)

    @staticmethod
    def opposite(side: str) -> str:
        return {"west": "east", "east": "west", "north": "south", "south": "north"}[side]

    def arc(self, center: Vec2, radius: float, start: float, sweep: float, count: int) -> tuple[Vec2, ...]:
        count = self.integer(count)
        if count < 0:
            raise ValueError("arc count must be nonnegative")
        # Both endpoints are included; a singleton is at start. Positive sweep is clockwise.
        return tuple(
            ring_point(
                center,
                radius,
                x87_pc24_add(f32(start), x87_pc24_div(x87_pc24_mul(float(i), f32(sweep)), float(max(count - 1, 1)))),
            )
            for i in self.bounded_range(count)
        )

    def rotate(self, points: tuple | list, angle: float, *, around: Vec2 = NATIVE_CENTER) -> tuple[Vec2, ...]:
        if not isinstance(points, (tuple, list)) or not all(isinstance(point, Vec2) for point in points):
            raise TypeError("rotate requires a list of points")
        self.bounded(points)
        cosine, sine = math.cos(angle), math.sin(angle)
        return tuple(
            Vec2(
                around.x + (point.x - around.x) * cosine - (point.y - around.y) * sine,
                around.y + (point.x - around.x) * sine + (point.y - around.y) * cosine,
            )
            for point in points
        )

    def rand(self, caller: int | None = None) -> int:
        return self.ctx.rng.rand() if caller is None else self.ctx.rng.rand_tagged(self.integer(caller))

    def choose(self, values: tuple | list) -> Any:
        return values[self.rand() % len(values)]

    def rand_int(self, low: int, high: int) -> int:
        low, high = self.integer(low), self.integer(high)
        if high < low:
            raise ValueError("rand_int bounds are reversed")
        return low + self.rand() % (high - low + 1)

    def shuffle(self, values: tuple | list | range) -> tuple:
        if not isinstance(values, (tuple, list, range)):
            raise TypeError("shuffle requires a list or range")
        self.bounded(values)
        shuffled = list(values)
        for i in range(len(shuffled) - 1, 0, -1):
            j = self.rand() % (i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        return tuple(shuffled)

    def expression(self, node: ast.AST, scope: _Scope) -> Any:
        self.tick(node)
        match node:
            case ast.Constant(value=value):
                result = value
            case ast.Name(id=name):
                result = scope.owner(name).values[name]
            case ast.List(elts=elts) | ast.Tuple(elts=elts):
                result = tuple(self.expression(elt, scope) for elt in elts)
            case ast.Attribute(value=value, attr=attr):
                base = self.expression(value, scope)
                if isinstance(base, dict):
                    result = base[attr]
                elif (isinstance(base, Vec2) and attr in ("x", "y")) or (
                    isinstance(base, EdgePoints) and attr in ("left", "right", "top", "bottom")
                ):
                    result = getattr(base, attr)
                else:
                    raise ValueError("only template aliases and point coordinates have attributes")
            case ast.Subscript(value=value, slice=index):
                base = self.expression(value, scope)
                if not isinstance(base, (tuple, list, range)):
                    raise TypeError("indexing requires a list")
                result = base[self.integer(self.expression(index, scope))]
            case ast.UnaryOp(op=op, operand=operand):
                value = self.expression(operand, scope)
                result = _UNARY[type(op)](value)
            case ast.BinOp(left=left, op=op, right=right):
                a, b = self.expression(left, scope), self.expression(right, scope)
                if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
                    raise TypeError("arithmetic requires numbers")
                result = _BINARY[type(op)](a, b)
            case ast.BoolOp(op=op, values=values):
                result = self.expression(values[0], scope)
                for value in values[1:]:
                    if (isinstance(op, ast.And) and not result) or (isinstance(op, ast.Or) and result):
                        break
                    result = self.expression(value, scope)
            case ast.Compare(left=left, ops=ops, comparators=comparators):
                a = self.expression(left, scope)
                result = True
                for op, comparator in zip(ops, comparators, strict=True):
                    b = self.expression(comparator, scope)
                    self.scalar(a)
                    if isinstance(op, (ast.In, ast.NotIn)):
                        if not isinstance(b, (tuple, list, range)):
                            raise TypeError("membership requires a list")
                        for item in b:
                            self.scalar(item)
                        self.tick(node, len(b))
                        ok = _COMPARE[type(op)](b, a)
                        if isinstance(op, ast.NotIn):
                            ok = not ok
                    else:
                        self.scalar(b)
                        ok = _COMPARE[type(op)](a, b)
                    if not ok:
                        result = False
                        break
                    a = b
            case ast.IfExp(test=test, body=body, orelse=orelse):
                result = self.expression(body if self.expression(test, scope) else orelse, scope)
            case ast.Call(func=ast.Name(id=name), args=args, keywords=keywords) if name in self.functions:
                positional = [self.expression(arg, scope) for arg in args]
                named = {kw.arg: self.expression(kw.value, scope) for kw in keywords if kw.arg is not None}
                for argument in (*positional, *named.values()):
                    if isinstance(argument, (tuple, list, range, str)):
                        self.tick(node, len(argument))
                result = self.functions[name](*positional, **named)
                if isinstance(result, (tuple, list, range)):
                    self.tick(node, len(result))
            case _:
                raise ValueError(f"unsupported expression: {type(node).__name__}")
        return self.bounded(result)

    def emit(self, node: ast.Call, scope: _Scope) -> None:
        assert isinstance(node.func, ast.Name)
        if self.time is None:
            raise ValueError("spawn operations must be inside an at block")
        template, positions, heading, count = [self.expression(arg, scope) for arg in node.args]
        template = SpawnId(self.integer(template))
        if template == SpawnId.UNUSED_02:
            raise ValueError("unused spawn template")
        count = self.integer(count)
        if not 1 <= count <= self.limits.copies:
            raise ValueError("copies must be positive and within the copy limit")
        points = positions if node.func.id == "__place__" else (positions,)
        if not isinstance(points, (tuple, list)):
            raise TypeError("place requires a list of points")
        for point in points:
            self.tick(node)
            if len(self.entries) >= self.limits.entries:
                raise ValueError("expanded spawn entry limit exceeded")
            if isinstance(point, tuple) and len(point) == 2:
                point = Vec2(*point)
            if not isinstance(point, Vec2):
                raise TypeError("expected a point (x, y)")
            entry = spawn(point, template, self.time, count, heading=heading)
            if not all(math.isfinite(value) for value in (entry.pos.x, entry.pos.y, entry.heading)):
                raise ValueError("spawn positions and headings must be finite float32 values")
            self.entries.append(entry)
            self.locations.append(SourceLocation(node.lineno, tuple(self.iterations)))

    def bind(self, target: ast.AST, value: Any, scope: _Scope) -> None:
        match target:
            case ast.Name(id=name):
                scope.values[name] = value
                scope.mutable.add(name)
            case ast.Tuple(elts=elts):
                if len(elts) != len(value):
                    raise ValueError("loop destructuring has the wrong number of values")
                for elt, item in zip(elts, value, strict=True):
                    self.bind(elt, item, scope)
            case _:
                raise ValueError("loop variables must be names")

    def assign(self, target: ast.AST, value: Any, scope: _Scope) -> None:
        match target:
            case ast.Name(id=name):
                scope.assign(name, value)
            case ast.Tuple(elts=elts):
                if len(elts) != len(value):
                    raise ValueError("destructuring has the wrong number of values")
                for elt, item in zip(elts, value, strict=True):
                    self.assign(elt, item, scope)
            case _:
                raise ValueError("assignment targets must be declared names")

    def block(self, nodes: list[ast.stmt], scope: _Scope, *, in_loop: bool = False) -> None:
        for node in nodes:
            self.tick(node)
            try:
                match node:
                    case ast.AnnAssign(target=ast.Name(id=name), annotation=ast.Name(id=kind), value=value):
                        assert value is not None
                        if name in scope.values or name in self.functions or name in self.patterns:
                            raise ValueError(f"duplicate or reserved name {name!r}")
                        scope.values[name] = self.expression(value, scope)
                        if kind == "__var__":
                            scope.mutable.add(name)
                    case ast.Assign(targets=[target], value=value):
                        self.assign(target, self.expression(value, scope), scope)
                    case ast.AugAssign(target=ast.Name(id=name), op=op, value=value):
                        old = scope.owner(name).values[name]
                        operand = self.expression(value, scope)
                        if not isinstance(old, (int, float)) or not isinstance(operand, (int, float)):
                            raise TypeError("arithmetic requires numbers")
                        new = _BINARY[type(op)](old, operand)
                        scope.assign(name, self.bounded(new))
                    case ast.If(test=test, body=body, orelse=orelse):
                        self.block(body if self.expression(test, scope) else orelse, _Scope(scope), in_loop=in_loop)
                    case ast.For(target=target, iter=iterable, body=body, orelse=[]):
                        values = self.expression(iterable, scope)
                        if not isinstance(values, (tuple, list, range)):
                            raise TypeError("for requires a bounded list or range")
                        for index, value in enumerate(values):
                            child = _Scope(scope)
                            self.bind(target, value, child)
                            if not self.iteration(body, child, index):
                                break
                    case ast.While(test=test, body=body, orelse=[]):
                        index = 0
                        while self.expression(test, scope):
                            if not self.iteration(body, _Scope(scope), index):
                                break
                            index += 1
                    case ast.Break():
                        if not in_loop:
                            raise ValueError("break requires a construction loop")
                        raise _Break
                    case ast.With(
                        items=[
                            ast.withitem(
                                context_expr=ast.Call(func=ast.Name(id="__at__"), args=[time], keywords=[]),
                                optional_vars=None,
                            ),
                        ],
                        body=body,
                    ):
                        trigger = self.integer(self.expression(time, scope))
                        if not 0 <= trigger <= self.limits.horizon_ms:
                            raise ValueError("trigger time outside authored horizon")
                        previous, self.time = self.time, trigger
                        try:
                            self.block(body, _Scope(scope), in_loop=in_loop)
                        finally:
                            self.time = previous
                    case ast.FunctionDef(name=name):
                        if (
                            scope is not self.root
                            or name in self.patterns
                            or name in self.functions
                            or name in self.root.values
                        ):
                            raise ValueError("patterns must have unique names and be declared at quest scope")
                        self.patterns[name] = node
                    case ast.Expr(value=ast.Call(func=ast.Name(id=name)) as call):
                        if name in ("__spawn__", "__place__"):
                            self.emit(call, scope)
                        elif name in self.patterns:
                            self.pattern(call, scope)
                        elif name in self.functions:
                            self.expression(call, scope)  # Explicit discarded RNG draws for native recipes.
                        else:
                            raise ValueError(f"unknown construction operation {name!r}")
                    case _:
                        raise ValueError(f"unsupported statement: {type(node).__name__}")
            except (ValueError, TypeError, KeyError, IndexError, ArithmeticError, AttributeError) as exc:
                if isinstance(exc, QuestCompileError):
                    raise
                raise QuestCompileError(str(exc), node.lineno) from exc

    def iteration(self, body: list[ast.stmt], scope: _Scope, index: int) -> bool:
        self.iterations.append(index)
        try:
            self.block(body, scope, in_loop=True)
        except _Break:
            return False
        finally:
            self.iterations.pop()
        return True

    def pattern(self, call: ast.Call, scope: _Scope) -> None:
        assert isinstance(call.func, ast.Name)
        name = call.func.id
        if name in self.active_patterns:
            raise ValueError("patterns cannot recurse")
        if len(self.active_patterns) >= self.limits.syntax_depth:
            raise ValueError("pattern expansion depth limit exceeded")
        definition = self.patterns[name]
        names = [arg.arg for arg in definition.args.args]
        values = [self.expression(arg, scope) for arg in call.args]
        if len(values) > len(names):
            raise ValueError("too many pattern arguments")
        bindings = dict(zip(names, values, strict=False))
        for kw in call.keywords:
            if kw.arg not in names or kw.arg in bindings:
                raise ValueError("unknown or duplicate pattern argument")
            bindings[kw.arg] = self.expression(kw.value, scope)
        if len(bindings) != len(names):
            raise ValueError("missing pattern arguments")
        self.active_patterns.add(name)
        try:
            self.block(definition.body, _Scope(self.root, bindings))
        finally:
            self.active_patterns.remove(name)


def _validate(tree: ast.Module, limits: CompileLimits) -> None:
    allowed = (
        ast.Module,
        ast.AnnAssign,
        ast.Assign,
        ast.AugAssign,
        ast.If,
        ast.For,
        ast.While,
        ast.Break,
        ast.With,
        ast.withitem,
        ast.FunctionDef,
        ast.arguments,
        ast.arg,
        ast.Expr,
        ast.Constant,
        ast.Name,
        ast.List,
        ast.Tuple,
        ast.Attribute,
        ast.Subscript,
        ast.UnaryOp,
        ast.USub,
        ast.UAdd,
        ast.Not,
        ast.BinOp,
        *_BINARY,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.Compare,
        *_COMPARE,
        ast.IfExp,
        ast.Call,
        ast.keyword,
        ast.Load,
        ast.Store,
    )
    pending: list[tuple[ast.AST, int]] = [(tree, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > limits.syntax_nodes or depth > limits.syntax_depth:
            raise QuestCompileError("syntax size/depth limit exceeded", getattr(node, "lineno", 1))
        if not isinstance(node, allowed):
            raise QuestCompileError(f"unsupported syntax: {type(node).__name__}", getattr(node, "lineno", 1))
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise QuestCompileError("private attributes are unavailable", node.lineno)
        if isinstance(node, ast.Call) and (
            not isinstance(node.func, ast.Name) or any(kw.arg is None for kw in node.keywords)
        ):
            raise QuestCompileError("calls require named construction functions; no argument unpacking", node.lineno)
        if isinstance(node, ast.AnnAssign) and (
            not isinstance(node.target, ast.Name)
            or node.value is None
            or not isinstance(node.annotation, ast.Name)
            or node.annotation.id not in ("__let__", "__var__")
        ):
            raise QuestCompileError("declare values with let or var", node.lineno)
        if isinstance(node, ast.FunctionDef):
            args = node.args
            if (
                node.decorator_list
                or node.returns
                or args.defaults
                or args.kw_defaults
                or args.vararg
                or args.kwarg
                or args.kwonlyargs
                or args.posonlyargs
                or any(arg.annotation for arg in args.args)
            ):
                raise QuestCompileError("patterns accept only named positional parameters", node.lineno)
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))


_DEFAULT_LIMITS = CompileLimits()


def compile_quest(
    source: str,
    *,
    seed: int = 0,
    player_count: int = 1,
    hardcore: bool = False,
    context: QuestContext | None = None,
    limits: CompileLimits = _DEFAULT_LIMITS,
) -> QuestPlan:
    """Construct a finite plan. An explicit context is the stock-parity/testing path.

    Ordinary compilation owns a separate construction RNG; it never initializes a game.
    """
    if len(source.encode("utf-8")) > limits.source_bytes:
        raise QuestCompileError("source byte limit exceeded")
    if context is None and (type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF):
        raise QuestCompileError("seed must be a uint32")
    ctx = context or QuestContext(player_count=player_count, hardcore=hardcore, rng=CrtRand(seed))
    if type(ctx.player_count) is not int or not 1 <= ctx.player_count <= 4:
        raise QuestCompileError("players must be in 1..4")
    if type(ctx.hardcore) is not bool:
        raise QuestCompileError("hardcore must be true or false")
    tree, metadata = _lower(source)
    _validate(tree, limits)
    compiler = _Compiler(ctx, limits)
    compiler.block(tree.body, compiler.root)
    entries = compiler.entries
    if ctx.hardcore and metadata["counts"] == "native":
        entries = apply_hardcore_spawn_table_adjustment(entries)
        if any(entry.count > limits.copies for entry in entries):
            raise QuestCompileError("native hardcore adjustment exceeds the copy limit")
    paired = list(zip(entries, compiler.locations, strict=True))
    if metadata["order"] == "chronological":
        paired.sort(key=lambda pair: pair[0].trigger_ms)
    return QuestPlan(
        title=metadata["title"],
        version=1,
        order=metadata["order"],
        counts=metadata["counts"],
        start_weapon_id=metadata["weapon"],
        terrain_slots=metadata["terrain"],
        entries=tuple(entry for entry, _ in paired),
        locations=tuple(location for _, location in paired),
        construction_rng_state=ctx.rng.state,
    )
