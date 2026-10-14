from __future__ import annotations

import inspect
import json
import math
import operator
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from decimal import Decimal
from functools import cache
from importlib.resources import files
from typing import Any

from lark import Lark, Token, Tree
from lark.exceptions import UnexpectedCharacters, UnexpectedInput, UnexpectedToken
from lark.indenter import DedentError, Indenter

from grim.geom import Vec2
from grim.rand import CrtRand

from ...bonuses.ids import BonusId
from ...creatures.spawn_ids import SpawnId
from ...perks.ids import PerkId
from ...weapons import WeaponId
from ..custom import (
    DROPPABLE_WEAPONS,
    MAX_COPIES,
    MAX_ENTRIES,
    MAX_TRIGGER_MS,
    CustomQuest,
    check_author,
    check_table,
    validate_custom_quest,
)
from ..helpers import NATIVE_CENTER, spawn
from ..runtime import apply_hardcore_spawn_table_adjustment
from ..types import QuestContext, SpawnEntry
from .model import CompileLimits, QuestPlan, SourceLocation


class QuestCompileError(ValueError):
    def __init__(self, message: str, line: int = 1):
        self.line = line
        super().__init__(f"line {line}: {message}")


class _Indenter(Indenter):
    NL_type = "_NL"
    OPEN_PAREN_types = ["LPAR", "LSQB"]  # noqa: RUF012 - Lark's class-level configuration
    CLOSE_PAREN_types = ["RPAR", "RSQB"]  # noqa: RUF012
    INDENT_type = "_INDENT"
    DEDENT_type = "_DEDENT"
    tab_len = 4

    def handle_NL(self, token: Token) -> Iterator[Token]:
        try:
            yield from super().handle_NL(token)
        except DedentError as exc:
            raise QuestCompileError("indentation does not match any enclosing block", token.end_line or 1) from exc


@cache
def _parser() -> Lark:
    grammar = files(__package__).joinpath("quest.lark").read_text(encoding="utf-8")
    return Lark(grammar, parser="lalr", postlex=_Indenter(), propagate_positions=True, maybe_placeholders=True)


_TERMINALS = {
    "NAME": "a name",
    "NUMBER": "a number",
    "INT": "an integer",
    "STRING": "a string",
    "DURATION": "a duration",
    "ANGLE": "an angle",
    "ORDER": "chronological or as-written",
    "_NL": "end of line",
    "_INDENT": "an indented block",
    "_DEDENT": "end of block",
    "$END": "end of input",
}


def _terminal(name: str) -> str:
    if name in _TERMINALS:
        return _TERMINALS[name]
    return repr(_parser().get_terminal(name).pattern.value)


def _syntax_error(exc: UnexpectedInput) -> QuestCompileError:
    if isinstance(exc, UnexpectedCharacters):
        return QuestCompileError(f"unexpected character {exc.char!r}", exc.line)
    if isinstance(exc, UnexpectedToken):
        token = exc.token
        found = _terminal(token.type) if token.type in _TERMINALS and token.type != "NAME" else repr(str(token))
        # The contextual lexer reports only lexer terminals; the parser also knows about indentation.
        accepted = exc.interactive_parser.accepts() if exc.interactive_parser else exc.expected
        expected = sorted(_terminal(name) for name in accepted)
        more = ", ..." if len(expected) > 8 else ""
        return QuestCompileError(f"unexpected {found}; expected {', '.join(expected[:8])}{more}", token.line or 1)
    return QuestCompileError("unexpected end of input", exc.line if exc.line > 0 else 1)


def _parse(source: str, limits: CompileLimits) -> Tree:
    try:
        tree = _parser().parse(source + "\n")
    except UnexpectedInput as exc:
        raise _syntax_error(exc) from exc
    pending: list[tuple[Tree | Token, int]] = [(tree, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > limits.syntax_nodes or depth > limits.syntax_depth:
            raise QuestCompileError("syntax size/depth limit exceeded", _line(node))
        if isinstance(node, Token) and node.type == "NAME" and node.startswith("_"):
            raise QuestCompileError("names beginning with '_' are reserved", _line(node))
        if isinstance(node, Tree):
            pending.extend((child, depth + 1) for child in node.children if child is not None)
    return tree


def _line(node: Tree | Token) -> int:
    if isinstance(node, Token):
        return node.line or 1
    return getattr(node.meta, "line", 1)


_PERK_ALIASES: dict[str, PerkId] = {
    **{
        name.lower(): member
        for name, member in PerkId.__members__.items()
        if member not in (PerkId.ANTIPERK, PerkId.INSTANT_WINNER)
    },
    "bloody_mess": PerkId.BLOODY_MESS_QUICK_LEARNER,
    "quick_learner": PerkId.BLOODY_MESS_QUICK_LEARNER,
}
_BONUS_ALIASES: dict[str, BonusId] = {
    name.lower(): member for name, member in BonusId.__members__.items() if member not in (BonusId.UNUSED, BonusId.POINTS)
}
_WEAPON_DROP_ALIASES: dict[str, WeaponId] = {weapon.name.lower(): weapon for weapon in DROPPABLE_WEAPONS}
_SETTING_NODES = ("author", "order", "weapon", "terrain", "no_bonuses", "no_perks", "no_weapons", "fixed_weapon")


def _parse_id_list[T](node: Tree, table: dict[str, T], kind: str, *, line: int) -> list[T]:
    names = [str(token) for token in node.children[0].children]
    seen: set[str] = set()
    out: list[T] = []
    for raw in names:
        key = raw.lower()
        if key in seen:
            raise QuestCompileError(f"duplicate {kind} {raw!r}", line)
        if key not in table:
            raise QuestCompileError(f"unknown or disallowed {kind} {raw!r}", line)
        seen.add(key)
        out.append(table[key])
    return out


def _settings(tree: Tree) -> tuple[dict[str, Any], list[Tree]]:
    header, *rest = tree.children
    title, version = (str(child) for child in header.children)
    if int(version) != 1:
        raise QuestCompileError("expected quest version 1", _line(header))
    try:
        title = _string(title)
    except ValueError as exc:
        raise QuestCompileError(str(exc), _line(header)) from exc
    metadata: dict[str, Any] = {
        "title": title,
        "author": None,
        "order": "chronological",
        "weapon": WeaponId.PISTOL,
        "terrain": (0, 1, 0),
        "no_bonuses": [],
        "no_perks": [],
        "no_weapons": [],
        "fixed_weapon": False,
    }
    seen: set[str] = set()
    statements = []
    for node in rest:
        if node.data not in _SETTING_NODES:
            statements.append(node)
            continue
        if node.data in seen:
            raise QuestCompileError(f"duplicate {node.data} setting", _line(node))
        seen.add(node.data)
        match node.data:
            case "author":
                try:
                    metadata["author"] = _string(str(node.children[0]))
                    check_author(metadata["author"])
                except ValueError as exc:
                    raise QuestCompileError(str(exc), _line(node)) from exc
            case "order":
                metadata["order"] = str(node.children[0])
            case "weapon":
                weapon = WeaponId.__members__.get(str(node.children[0]).upper(), WeaponId.NONE)
                if weapon == WeaponId.NONE or weapon.name.startswith("UNUSED_"):
                    raise QuestCompileError(f"unknown starting weapon {str(node.children[0])!r}", _line(node))
                metadata["weapon"] = weapon
            case "terrain":
                slots = tuple(int(str(slot)) for slot in node.children)
                if not all(0 <= slot <= 7 for slot in slots):
                    raise QuestCompileError("terrain must be three slot IDs in 0..7", _line(node))
                metadata["terrain"] = slots
            case "no_bonuses":
                metadata["no_bonuses"] = _parse_id_list(node, _BONUS_ALIASES, "bonus", line=_line(node))
            case "no_perks":
                metadata["no_perks"] = _parse_id_list(node, _PERK_ALIASES, "perk", line=_line(node))
            case "no_weapons":
                metadata["no_weapons"] = _parse_id_list(node, _WEAPON_DROP_ALIASES, "weapon drop", line=_line(node))
            case "fixed_weapon":
                metadata["fixed_weapon"] = node.children[0].data == "true"
    no_bonuses = set(metadata["no_bonuses"])
    no_perks = set(metadata["no_perks"])
    no_weapons = set(metadata["no_weapons"])
    if metadata["fixed_weapon"]:
        no_bonuses.add(BonusId.WEAPON)
        no_perks.update((PerkId.ALTERNATE_WEAPON, PerkId.RANDOM_WEAPON))
        no_weapons.update(DROPPABLE_WEAPONS)
    metadata["no_bonuses"] = tuple(sorted(no_bonuses))
    metadata["no_perks"] = tuple(sorted(no_perks))
    metadata["no_weapons"] = tuple(sorted(no_weapons))
    return metadata, statements

def _string(text: str) -> str:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ValueError("invalid string escape") from exc


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


Items = tuple | range

_BINARY: dict[str, Callable[[Any, Any], Any]] = {
    "+": operator.add,
    "-": operator.sub,
    "*": operator.mul,
    "/": operator.truediv,
    "//": operator.floordiv,
    "%": operator.mod,
}
_COMPARE: dict[str, Callable[[Any, Any], Any]] = {
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
}


def _arithmetic(op: str, a: Any, b: Any) -> Any:
    """Numbers combine freely; points add, subtract and scale by numbers."""
    numbers = isinstance(a, (int, float)) and isinstance(b, (int, float))
    points = isinstance(a, Vec2) and isinstance(b, Vec2) and op in ("+", "-")
    scaled = (isinstance(a, Vec2) and isinstance(b, (int, float)) and op in ("*", "/")) or (
        isinstance(a, (int, float)) and isinstance(b, Vec2) and op == "*"
    )
    if not (numbers or points or scaled):
        raise TypeError("arithmetic requires numbers, or points added, subtracted or scaled")
    return _BINARY[op](a, b)


def _choice(table: dict[str, Any], key: Any, kind: str) -> Any:
    if key not in table:
        raise ValueError(f"unknown {kind} {key!r}; expected {', '.join(table)}")
    return table[key]


_ALIASES = {
    "alien": {
        "small_gray": SpawnId.ALIEN_SMALL_GRAY_26,
        "fast": SpawnId.ALIEN_DEADLY_FAST_2B,
        "small_green": SpawnId.ALIEN_SMALL_GREEN_MAN_25,
        "green": SpawnId.ALIEN_CONST_GREEN_24,
        "purple": SpawnId.ALIEN_CONST_PURPLE_28,
        "big_gray": SpawnId.ALIEN_BIG_GRAY_29,
        "gray_fast": SpawnId.ALIEN_CONST_GREY_FAST_2A,
        "boss": SpawnId.ALIEN_CONST_RED_BOSS_2C,
        "cyan": SpawnId.ALIEN_CONST_CYAN_AI2_2D,
        "ghost": SpawnId.ALIEN_GHOST_0F,
        "bonus_carrier": SpawnId.ALIEN_BONUS_CARRIER_27,
        "delayed": SpawnId.ALIEN_DELAYED_START_36,
        "flanker": SpawnId.AI1_ALIEN_BLUE_TINT_1A,
        "spawner_ring": SpawnId.ALIEN_SPAWNER_RING_24_0E,
        "random": SpawnId.ALIEN_RANDOM_06,
    },
    "spider": {
        "small_blue": SpawnId.SPIDER_SMALL_BLUE_40,
        "plasma": SpawnId.SPIDER_PLASMA_SHOOTER_3C,
        "splitter": SpawnId.SPIDER_SP2_SPLITTER_01,
        "boss": SpawnId.SPIDER_BOSS_3A,
        "red_boss": SpawnId.SPIDER_SP1_CONST_RED_BOSS_3B,
        "white_fast": SpawnId.SPIDER_SP1_CONST_WHITE_FAST_3E,
        "small_brown": SpawnId.SPIDER_SP1_CONST_BROWN_SMALL_3F,
        "ranged": SpawnId.SPIDER_SP2_RANGED_VARIANT_37,
        "stop_and_go": SpawnId.SPIDER_SP1_STOP_AND_GO_38,
        "stop_and_go_weak": SpawnId.SPIDER_SP1_STOP_AND_GO_WEAK_39,
        "flanker": SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B,
        "random": SpawnId.SPIDER_SP1_RANDOM_03,
        "random_red": SpawnId.SPIDER_SP1_RANDOM_RED_33,
        "random_green": SpawnId.SPIDER_SP1_RANDOM_GREEN_34,
    },
    "lizard": {
        "gray": SpawnId.LIZARD_CONST_GREY_2F,
        "boss": SpawnId.LIZARD_CONST_YELLOW_BOSS_30,
        "flanker": SpawnId.AI1_LIZARD_BLUE_TINT_1C,
        "random": SpawnId.LIZARD_RANDOM_04,
    },
    "zombie": {
        "random": SpawnId.ZOMBIE_RANDOM_41,
        "spawner_boss": SpawnId.ZOMBIE_BOSS_SPAWNER_00,
        "small_white": SpawnId.ZOMBIE_SMALL_WHITE_42,
        "brute": SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43,
    },
    "nest": {
        "alien": SpawnId.DEN_ALIEN_BASIC_07,
        "alien_slow": SpawnId.DEN_ALIEN_BASIC_SLOWER_08,
        "alien_weak": SpawnId.DEN_ALIEN_WEAK_SMALL_09,
        "spider": SpawnId.DEN_SPIDER_BASIC_0A,
        "plasma": SpawnId.DEN_SPIDER_PLASMA_SHOOTERS_0B,
        "spider_weak": SpawnId.DEN_SPIDER_WEAK_10,
        "lizard": SpawnId.DEN_LIZARD_WEAK_0C,
        "lizard_slow": SpawnId.DEN_LIZARD_WEAK_SLOWER_0D,
    },
    "formation": {
        "alien_ring": SpawnId.FORMATION_RING_ALIEN_8_12,
        "alien_ring_small": SpawnId.FORMATION_RING_ALIEN_5_19,
        "alien_chain": SpawnId.FORMATION_CHAIN_ALIEN_10_13,
        "lizard_chain": SpawnId.FORMATION_CHAIN_LIZARD_4_11,
        "alien_grid": SpawnId.FORMATION_GRID_ALIEN_WHITE_15,
        "alien_grid_green": SpawnId.FORMATION_GRID_ALIEN_GREEN_14,
        "alien_grid_bronze": SpawnId.FORMATION_GRID_ALIEN_BRONZE_18,
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
        self.calls: list[int] = []
        self.time: int | None = None
        self.patterns: dict[str, Tree] = {}
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
            },
        )

    _FUNCTIONS: dict[str, Callable[..., Any]]
    _SIGNATURES: dict[str, inspect.Signature]
    _CHECKS: dict[Any, tuple[Callable[[Any], Any], str]]

    def tick(self, node: Tree | Token, amount: int = 1) -> None:
        self.work += amount
        if self.work > self.limits.work:
            raise QuestCompileError("construction work budget exceeded", _line(node))

    def bounded(self, value: Any) -> Any:
        if isinstance(value, (tuple, range, str)) and len(value) > self.limits.collection:
            raise ValueError("collection limit exceeded")
        if isinstance(value, int) and value.bit_length() > 64:
            raise ValueError("integer magnitude exceeds 64 bits")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("numbers must be finite")
        if isinstance(value, Vec2):
            self.point(value.x, value.y)
        return value

    # Value checks; helper parameters are checked against their annotations before a call.

    @staticmethod
    def number(value: Any) -> int | float:
        if not isinstance(value, (int, float)) or not math.isfinite(value):
            raise TypeError("expected a finite number")
        return value

    @staticmethod
    def integer(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("expected an integer")
        return value

    @staticmethod
    def expect_point(value: Any) -> Vec2:
        if isinstance(value, Vec2):
            return value
        if (
            isinstance(value, tuple)
            and len(value) == 2
            and all(not isinstance(item, bool) and isinstance(item, (int, float)) and math.isfinite(item) for item in value)
        ):
            return Vec2(value[0], value[1])
        raise TypeError("expected a point")
    @staticmethod
    def expect_string(value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("expected a string")
        return value

    @staticmethod
    def expect_items(value: Any) -> Items:
        if not isinstance(value, (tuple, range)):
            raise TypeError("expected a list")
        return value

    @staticmethod
    def scalar(value: Any) -> None:
        if not isinstance(value, (int, float, str, Vec2)):
            raise TypeError("comparisons require scalar values or points")

    def call(self, name: str, positional: list[Any], named: dict[str, Any]) -> Any:
        signature = self._SIGNATURES[name]
        try:
            bound = signature.bind(*positional, **named)
        except TypeError as exc:
            raise TypeError(f"{name}(): {exc}") from exc
        for parameter_name, value in bound.arguments.items():
            parameter = signature.parameters[parameter_name]
            if parameter.annotation not in self._CHECKS:
                continue
            check, description = self._CHECKS[parameter.annotation]
            try:
                if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
                    bound.arguments[parameter_name] = tuple(check(item) for item in value)
                else:
                    bound.arguments[parameter_name] = check(value)
            except TypeError as exc:
                raise TypeError(f"{name}() argument {parameter_name!r} must be {description}") from exc
        return self._FUNCTIONS[name](self, *bound.args, **bound.kwargs)

    # Construction helpers.

    def minimum(self, *values: Any) -> int | float:
        return self.extreme(min, values)

    def maximum(self, *values: Any) -> int | float:
        return self.extreme(max, values)

    @staticmethod
    def extreme(function: Callable[..., Any], values: tuple) -> Any:
        if len(values) == 1 and isinstance(values[0], (tuple, range)):
            values = tuple(values[0])
        if not values or not all(isinstance(value, (int, float)) for value in values):
            raise TypeError("min/max require numbers")
        return function(values)

    def absolute(self, value: float) -> int | float:
        return abs(value)

    def to_int(self, value: float) -> int:
        return int(value)

    def to_float(self, value: float) -> float:
        return float(value)

    def length(self, values: Items) -> int:
        return len(values)

    def point(self, x: float, y: float) -> Vec2:
        return Vec2(self.number(x), self.number(y))

    def bounded_range(self, *args: int) -> range:
        return self.bounded(range(*args))

    def line(self, start: Vec2, step: Vec2, count: int) -> tuple[Vec2, ...]:
        return tuple(start + step * i for i in self.bounded_range(count))

    def polar(self, center: Vec2, radius: float, angle: float) -> Vec2:
        return center + Vec2(math.cos(angle), math.sin(angle)) * radius

    def facing(self, point: Vec2, target: Vec2) -> float:
        # A creature at heading h moves along (cos(h - pi/2), sin(h - pi/2)).
        return math.atan2(point.y - target.y, point.x - target.x) - math.pi / 2

    def ring(self, center: Vec2, radius: float, count: int, *, start: float = 0) -> tuple[Vec2, ...]:
        return tuple(self.polar(center, radius, start + i * math.tau / count) for i in self.bounded_range(count))

    def corner(self, name: str, *, outside: float = 64) -> Vec2:
        near, far = -outside, 1024 + outside
        corners = {
            "northwest": Vec2(near, near),
            "northeast": Vec2(far, near),
            "southwest": Vec2(near, far),
            "southeast": Vec2(far, far),
        }
        return _choice(corners, name, "corner")

    def corners(self, *, outside: float = 64) -> tuple[Vec2, ...]:
        return tuple(
            self.corner(name, outside=outside) for name in ("northwest", "northeast", "southwest", "southeast")
        )

    def edge(self, side: str, *, outside: float = 64, fraction: float = 0.5) -> Vec2:
        along = 1024 * fraction
        edges = {
            "west": Vec2(-outside, along),
            "east": Vec2(1024 + outside, along),
            "north": Vec2(along, -outside),
            "south": Vec2(along, 1024 + outside),
        }
        return _choice(edges, side, "side")

    def edge_line(self, side: str, count: int, spacing: float, *, outside: float = 64) -> tuple[Vec2, ...]:
        if count < 0:
            raise ValueError("edge_line count must be nonnegative")
        self.bounded_range(count)
        anchor = self.edge(side, outside=outside)
        step = Vec2(0, spacing) if side in ("west", "east") else Vec2(spacing, 0)
        return self.line(anchor - step * ((count - 1) * 0.5), step, count)

    def opposite(self, side: str) -> str:
        return _choice({"west": "east", "east": "west", "north": "south", "south": "north"}, side, "side")

    def arc(self, center: Vec2, radius: float, start: float, sweep: float, count: int) -> tuple[Vec2, ...]:
        if count < 0:
            raise ValueError("arc count must be nonnegative")
        # Both endpoints are included; a singleton is at start. Positive sweep is clockwise.
        return tuple(
            self.polar(center, radius, start + i * sweep / max(count - 1, 1)) for i in self.bounded_range(count)
        )

    def rotate(self, points: Items, angle: float, *, around: Vec2 = NATIVE_CENTER) -> tuple[Vec2, ...]:
        try:
            vectors = [self.expect_point(point) for point in points]
        except TypeError as exc:
            raise TypeError("rotate requires a list of points") from exc
        cosine, sine = math.cos(angle), math.sin(angle)
        return tuple(
            Vec2(
                around.x + (point.x - around.x) * cosine - (point.y - around.y) * sine,
                around.y + (point.x - around.x) * sine + (point.y - around.y) * cosine,
            )
            for point in vectors
        )

    def rand(self) -> int:
        return self.ctx.rng.rand()

    def choose(self, values: Items) -> Any:
        return values[self.rand() % len(values)]

    def rand_int(self, low: int, high: int) -> int:
        if high < low:
            raise ValueError("rand_int bounds are reversed")
        return low + self.rand() % (high - low + 1)

    def shuffle(self, values: Items) -> tuple:
        shuffled = list(values)
        for i in range(len(shuffled) - 1, 0, -1):
            j = self.rand() % (i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        return tuple(shuffled)

    # Expressions.

    def literal(self, node: Tree) -> Any:
        token = str(node.children[0])
        match node.data:
            case "number":
                return float(token) if any(mark in token for mark in ".eE") else int(token)
            case "duration":
                unit = "ms" if token.endswith("ms") else "s"
                value = Decimal(token.removesuffix(unit)) * (1000 if unit == "s" else 1)
                if value != value.to_integral_value():
                    raise ValueError("time literals must resolve to whole milliseconds")
                return int(value)
            case "angle":
                return math.radians(float(token.removesuffix("deg")))
            case "string":
                return _string(token)
        raise AssertionError(node.data)

    def expression(self, node: Tree, scope: _Scope) -> Any:
        self.tick(node)
        children = node.children
        match node.data:
            case "number" | "duration" | "angle" | "string":
                result = self.literal(node)
            case "true" | "false":
                result = node.data == "true"
            case "name":
                name = str(children[0])
                result = scope.owner(name).values[name]
            case "tuple" | "list":
                result = tuple(self.expression(child, scope) for child in children)
            case "attribute":
                base, attribute = self.expression(children[0], scope), str(children[1])
                if isinstance(base, dict):
                    result = _choice(base, attribute, "template")
                elif isinstance(base, Vec2) and attribute in ("x", "y"):
                    result = getattr(base, attribute)
                else:
                    raise ValueError("only template aliases and point coordinates have attributes")
            case "index":
                base = self.expect_items(self.expression(children[0], scope))
                result = base[self.integer(self.expression(children[1], scope))]
            case "negative" | "positive":
                value = self.number(self.expression(children[0], scope))
                result = -value if node.data == "negative" else value
            case "not_":
                result = not self.expression(children[0], scope)
            case "sum" | "product":
                result = self.expression(children[0], scope)
                for op, operand in zip(children[1::2], children[2::2], strict=True):
                    # Bound every intermediate: a later operation must not hide an earlier overflow.
                    result = self.bounded(_arithmetic(str(op.children[0]), result, self.expression(operand, scope)))
            case "or_test" | "and_test":
                result = self.expression(children[0], scope)
                for operand in children[1:]:
                    if (node.data == "and_test") != bool(result):
                        break
                    result = self.expression(operand, scope)
            case "comparison":
                result = self.compare(node, scope)
            case "conditional":
                body, test, orelse = children
                result = self.expression(body if self.expression(test, scope) else orelse, scope)
            case "call":
                result = self.invoke(node, scope)
            case _:
                raise ValueError(f"unsupported expression {node.data}")
        return self.bounded(result)

    def compare(self, node: Tree, scope: _Scope) -> bool:
        children = node.children
        a = self.expression(children[0], scope)
        for op, operand in zip(children[1::2], children[2::2], strict=True):
            b = self.expression(operand, scope)
            self.scalar(a)
            symbol = " ".join(str(token) for token in op.children)
            if symbol in ("in", "not in"):
                for item in self.expect_items(b):
                    self.scalar(item)
                self.tick(node, len(b))
                ok = (a in b) == (symbol == "in")
            else:
                self.scalar(b)
                ok = _COMPARE[symbol](a, b)
            if not ok:
                return False
            a = b
        return True

    def invoke(self, node: Tree, scope: _Scope) -> Any:
        name, arguments = str(node.children[0]), node.children[1]
        if name not in self._FUNCTIONS:
            raise ValueError(f"unknown function {name!r}")
        positional, named = self.arguments(arguments, scope)
        for argument in (*positional, *named.values()):
            if isinstance(argument, (tuple, range, str)):
                self.tick(node, len(argument))
        result = self.call(name, positional, named)
        if isinstance(result, (tuple, range)):
            self.tick(node, len(result))
            for item in result:
                if isinstance(item, Vec2):
                    self.bounded(item)
        return result

    def arguments(self, node: Tree, scope: _Scope) -> tuple[list[Any], dict[str, Any]]:
        positional: list[Any] = []
        named: dict[str, Any] = {}
        for argument in node.children:
            if argument.data == "keyword":
                key = str(argument.children[0])
                if key in named:
                    raise ValueError(f"duplicate argument {key!r}")
                named[key] = self.expression(argument.children[1], scope)
            elif named:
                raise ValueError("positional arguments must precede named arguments")
            else:
                positional.append(self.expression(argument, scope))
        return positional, named

    # Statements.

    def emit(self, node: Tree, scope: _Scope) -> None:
        if self.time is None:
            raise ValueError("spawn operations must be inside an at block")
        template, positions, count, heading = node.children
        spawn_id = SpawnId(self.integer(self.expression(template, scope)))
        if spawn_id == SpawnId.UNUSED_02:
            raise ValueError("unused spawn template")
        copies = 1 if count is None else self.integer(self.expression(count, scope))
        if not 1 <= copies <= MAX_COPIES:
            raise ValueError("copies must be positive and within the copy limit")
        angle = 0 if heading is None else self.number(self.expression(heading, scope))
        located = self.expression(positions, scope)
        if node.data == "place":
            points = self.expect_items(located)
        elif node.data == "burst" or isinstance(located, Vec2) or (
            isinstance(located, tuple)
            and len(located) == 2
            and all(not isinstance(item, bool) and isinstance(item, (int, float)) for item in located)
        ):
            points = (located,)
        else:
            points = self.expect_items(located)
        for item, point in enumerate(points):
            self.tick(node)
            if len(self.entries) >= MAX_ENTRIES:
                raise ValueError("expanded spawn entry limit exceeded")
            coerced = self.expect_point(point)
            self.point(coerced.x, coerced.y)
            entry = spawn(coerced, spawn_id, self.time, copies, heading=angle)
            if not all(math.isfinite(value) for value in (entry.pos.x, entry.pos.y, entry.heading)):
                raise ValueError("spawn positions and headings must be finite float32 values")
            self.entries.append(entry)
            self.locations.append(SourceLocation(_line(node), tuple(self.iterations), tuple(self.calls), item))

    def bind(self, target: Tree, value: Any, scope: _Scope) -> None:
        names = [str(name) for name in target.children]
        values = (value,) if len(names) == 1 else self.expect_items(value)
        if len(values) != len(names):
            raise ValueError("loop destructuring has the wrong number of values")
        for name, item in zip(names, values, strict=True):
            scope.values[name] = item
            scope.mutable.add(name)

    def declare(self, name: str, value: Any, scope: _Scope, *, mutable: bool) -> None:
        if name in scope.values or name in self._FUNCTIONS or name in self.patterns:
            raise ValueError(f"duplicate or reserved name {name!r}")
        scope.values[name] = value
        if mutable:
            scope.mutable.add(name)

    def block(self, nodes: list[Tree], scope: _Scope, *, in_loop: bool = False) -> None:
        for node in nodes:
            self.tick(node)
            try:
                self.statement(node, scope, in_loop=in_loop)
            except (ValueError, TypeError, KeyError, IndexError, ArithmeticError, AttributeError) as exc:
                if isinstance(exc, QuestCompileError):
                    raise
                raise QuestCompileError(str(exc), _line(node)) from exc

    def statement(self, node: Tree, scope: _Scope, *, in_loop: bool) -> None:
        children = node.children
        match node.data:
            case "let" | "var":
                self.declare(str(children[0]), self.expression(children[1], scope), scope, mutable=node.data == "var")
            case "assign":
                scope.assign(str(children[0]), self.expression(children[1], scope))
            case "update":
                name, op, value = str(children[0]), str(children[1].children[0]), children[2]
                updated = _arithmetic(op[:-1], scope.owner(name).values[name], self.expression(value, scope))
                scope.assign(name, self.bounded(updated))
            case "spawn" | "burst" | "place":
                self.emit(node, scope)
            case "invoke":
                name = str(children[0])
                if name not in self.patterns:
                    raise ValueError(f"unknown construction operation {name!r}")
                self.pattern(node, scope)
            case "break_":
                if not in_loop:
                    raise ValueError("break requires a construction loop")
                raise _Break
            case "repeat":
                count, name, body = children
                for index in self.bounded_range(self.integer(self.expression(count, scope))):
                    child = _Scope(scope, {str(name): index}, {str(name)})
                    if not self.iteration(body, child, index):
                        break
            case "for_":
                target, iterable, body = children
                for index, value in enumerate(self.expect_items(self.expression(iterable, scope))):
                    child = _Scope(scope)
                    self.bind(target, value, child)
                    if not self.iteration(body, child, index):
                        break
            case "if_":
                *branches, otherwise = children
                tests = [(branches[0], branches[1])] + [
                    (branch.children[0], branch.children[1]) for branch in branches[2:]
                ]
                chosen = next((body for test, body in tests if self.expression(test, scope)), otherwise)
                if chosen is not None:
                    self.block(chosen.children, _Scope(scope), in_loop=in_loop)
            case "while_":
                test, body = children
                index = 0
                while self.expression(test, scope):
                    if not self.iteration(body, _Scope(scope), index):
                        break
                    index += 1
            case "at":
                time, body = children
                trigger = self.integer(self.expression(time, scope))
                if not 0 <= trigger <= MAX_TRIGGER_MS:
                    raise ValueError("trigger time outside authored horizon")
                previous, self.time = self.time, trigger
                try:
                    self.block(body.children, _Scope(scope), in_loop=in_loop)
                finally:
                    self.time = previous
            case "pattern":
                name = str(children[0])
                parameters = [str(parameter) for parameter in children[1].children]
                if scope is not self.root or name in self.patterns or name in self._FUNCTIONS or name in scope.values:
                    raise ValueError("patterns must have unique names and be declared at quest scope")
                if len(set(parameters)) != len(parameters):
                    raise ValueError("pattern parameters must be unique")
                self.patterns[name] = node
            case _:
                raise ValueError(f"unsupported statement {node.data}")

    def iteration(self, body: Tree, scope: _Scope, index: int) -> bool:
        self.iterations.append(index)
        try:
            self.block(body.children, scope, in_loop=True)
        except _Break:
            return False
        finally:
            self.iterations.pop()
        return True

    def pattern(self, call: Tree, scope: _Scope) -> None:
        name = str(call.children[0])
        if name in self.active_patterns:
            raise ValueError("patterns cannot recurse")
        if len(self.active_patterns) >= self.limits.syntax_depth:
            raise ValueError("pattern expansion depth limit exceeded")
        definition = self.patterns[name]
        names = [str(parameter) for parameter in definition.children[1].children]
        positional, named = self.arguments(call.children[1], scope)
        if len(positional) > len(names):
            raise ValueError("too many pattern arguments")
        bindings = dict(zip(names, positional, strict=False))
        for key, value in named.items():
            if key not in names or key in bindings:
                raise ValueError("unknown or duplicate pattern argument")
            bindings[key] = value
        if len(bindings) != len(names):
            raise ValueError("missing pattern arguments")
        self.active_patterns.add(name)
        self.calls.append(_line(call))
        try:
            self.block(definition.children[2].children, _Scope(self.root, bindings))
        finally:
            self.calls.pop()
            self.active_patterns.remove(name)


_Compiler._FUNCTIONS = {
    "min": _Compiler.minimum,
    "max": _Compiler.maximum,
    "abs": _Compiler.absolute,
    "int": _Compiler.to_int,
    "float": _Compiler.to_float,
    "len": _Compiler.length,
    "point": _Compiler.point,
    "corner": _Compiler.corner,
    "corners": _Compiler.corners,
    "polar": _Compiler.polar,
    "facing": _Compiler.facing,
    "range": _Compiler.bounded_range,
    "line": _Compiler.line,
    "ring": _Compiler.ring,
    "edge": _Compiler.edge,
    "edge_line": _Compiler.edge_line,
    "opposite": _Compiler.opposite,
    "arc": _Compiler.arc,
    "rotate": _Compiler.rotate,
    "rand": _Compiler.rand,
    "choose": _Compiler.choose,
    "rand_int": _Compiler.rand_int,
    "shuffle": _Compiler.shuffle,
}
_Compiler._SIGNATURES = {
    name: inspect.Signature(
        [
            param
            for param_name, param in inspect.signature(function, eval_str=True).parameters.items()
            if param_name != "self"
        ],
    )
    for name, function in _Compiler._FUNCTIONS.items()
}
_Compiler._CHECKS = {
    Vec2: (_Compiler.expect_point, "a point"),
    float: (_Compiler.number, "a finite number"),
    int: (_Compiler.integer, "an integer"),
    str: (_Compiler.expect_string, "a string"),
    Items: (_Compiler.expect_items, "a list"),
}

_DEFAULT_LIMITS = CompileLimits()


def _check_inputs(source: str, seed: int, limits: CompileLimits) -> None:
    if len(source.encode("utf-8")) > limits.source_bytes:
        raise QuestCompileError("source byte limit exceeded")
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
        raise QuestCompileError("seed must be a uint32")


def _construct(
    statements: list[Tree],
    order: str,
    *,
    seed: int,
    player_count: int,
    hardcore: bool,
    limits: CompileLimits,
) -> tuple[tuple[SpawnEntry, ...], tuple[SourceLocation, ...]]:
    """Run the recipe once and order its base table; the hardcore count rule is applied by the caller."""
    if type(player_count) is not int or not 1 <= player_count <= 4:
        raise QuestCompileError("players must be in 1..4")
    if type(hardcore) is not bool:
        raise QuestCompileError("hardcore must be true or false")
    compiler = _Compiler(QuestContext(player_count=player_count, hardcore=hardcore, rng=CrtRand(seed)), limits)
    compiler.block(statements, compiler.root)
    paired = list(zip(compiler.entries, compiler.locations, strict=True))
    if order == "chronological":
        paired.sort(key=lambda pair: pair[0].trigger_ms)
    return tuple(entry for entry, _ in paired), tuple(location for _, location in paired)


def compile_quest(
    source: str,
    *,
    seed: int = 0,
    player_count: int = 1,
    hardcore: bool = False,
    limits: CompileLimits = _DEFAULT_LIMITS,
) -> QuestPlan:
    """Construct the table one variant plays, from a construction seed; it never initializes a game.

    Hardcore is both a recipe input and the game's count rule, applied here as a run start would.
    """
    _check_inputs(source, seed, limits)
    metadata, statements = _settings(_parse(source, limits))
    entries, locations = _construct(
        statements,
        metadata["order"],
        seed=seed,
        player_count=player_count,
        hardcore=hardcore,
        limits=limits,
    )
    if hardcore:
        entries = tuple(apply_hardcore_spawn_table_adjustment(list(entries)))
    try:
        check_table(entries)
    except ValueError as exc:
        raise QuestCompileError(str(exc)) from exc
    return QuestPlan(
        title=metadata["title"],
        author=metadata["author"],
        version=1,
        start_weapon_id=metadata["weapon"],
        terrain_slots=metadata["terrain"],
        entries=entries,
        locations=locations,
        no_bonuses=metadata["no_bonuses"],
        no_perks=metadata["no_perks"],
        no_weapons=metadata["no_weapons"],
    )


def build_custom_quest(source: str, *, seed: int = 0, limits: CompileLimits = _DEFAULT_LIMITS) -> CustomQuest:
    """Resolve a recipe into a playable custom quest definition."""
    _check_inputs(source, seed, limits)
    metadata, statements = _settings(_parse(source, limits))
    entries, _ = _construct(
        statements,
        metadata["order"],
        seed=seed,
        player_count=1,
        hardcore=False,
        limits=limits,
    )
    quest = CustomQuest(
        title=metadata["title"],
        author=metadata["author"],
        start_weapon_id=metadata["weapon"],
        terrain_slots=metadata["terrain"],
        entries=entries,
        no_bonuses=metadata["no_bonuses"],
        no_perks=metadata["no_perks"],
        no_weapons=metadata["no_weapons"],
    )
    try:
        validate_custom_quest(quest)
    except ValueError as exc:
        raise QuestCompileError(str(exc)) from exc
    return quest
