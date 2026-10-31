"""Adapt generated copies of the recovered sources; `decomp/` stays untouched.

Each source is read as `decomp/` has it and changed in two steps:

1. Diffs make the edits that belong to one place. Each folder a target applies (DIFFS, and game.GAME_DIFFS) holds
   unified diffs against the recovered files, named by their paths from the repository root. A hunk matches by its
   exact old text, which must occur once; line numbers only say where it was written.
2. Passes make the edits a rule decides: the x87 boundaries below, each expecting its number of sites, then the
   dialect a modern compiler needs everywhere.

Diffs come first, so they read against the source of truth and the code they add takes the same rules. The sources
compile as 1.9.93 (CL_BUILD); a run plays 1.9.93's or 1.9.8's rules, which editions/ turns from guards into branches
on the run's build, or which a source names (tools/match/include/cl_rules.h) and host/rules.h defines as the run's.
Every other guard that tells the two apart stays the preprocessor's, as editions/guards.json classifies them
(check_guards).
"""

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import textwrap
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
# abi/: compiler repairs at one place; seams/: where the recording replaces a live read, and a custom quest the quest table;
# optimizations/: behavior-preserving performance changes; patches/: the ranked rules,
# where `patches/NN-*.patch` fixes original bug NN of docs/rewrite/original-bugs.md behind `portable_preserve_bugs`;
# editions/: the 1.9.8 rules, each guard of one a branch on `portable_cl_build`, read after the rules' fixes (1.9.8's
# own bugs are patches too) and before the game module's changes.
DIFFS = (HERE / "abi", HERE / "seams", HERE / "optimizations", HERE / "patches", HERE / "editions")
_HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
# Signatures the recovered files disagree on, as their definitions have them; every declaration takes its definition's.
PROTOTYPES = {
    "void console_input_poll(void);": "int console_input_poll(void);",
}


def load_diffs(folders):
    """(patch:line of the hunk header, old text, new text) hunks by source path, in folder then name order."""

    hunks = {}
    for patch in (path for folder in folders for path in sorted(folder.glob("*.patch"))):
        lines = patch.read_text().splitlines(keepends=True)
        rel = None
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            if line.startswith("+++ "):
                rel = line[4:].split()[0].removeprefix("b/")
                continue
            match = _HUNK.match(line)
            if not match:
                continue
            header = i
            old_count, new_count = (int(n) if n is not None else 1 for n in match.groups())
            old, new = [], []
            while len(old) < old_count or len(new) < new_count:
                tag, body = lines[i][:1], lines[i][1:]
                i += 1
                if tag in " -":
                    old.append(body)
                if tag in " +":
                    new.append(body)
            if rel is None:
                raise SystemExit(f"{patch.name}: hunk before a +++ header")
            label = f"{patch.relative_to(HERE)}:{header}"
            hunks.setdefault(rel, []).append((label, "".join(old), "".join(new)))
    return hunks


def _apply(rel, txt, hunks):
    """The text with every hunk that matches once applied in order, and a line for each one that doesn't."""

    stale = []
    for name, old, new in hunks.get(rel, ()):
        if (found := txt.count(old)) == 1:
            txt = txt.replace(old, new)
        else:
            stale.append(f"{name}: hunk for {rel} matches {found} times")
    return txt, stale


def _audit(stale):
    return SystemExit("Audit the patches; these hunks no longer match exactly once:\n  " + "\n  ".join(stale))


def apply_diffs(rel, txt, hunks):
    txt, stale = _apply(rel, txt, hunks)
    if stale:
        raise _audit(stale)
    return txt


def stale_hunks(root, hunks):
    """Every hunk whose old text doesn't occur once in its source under `root`, after the hunks before it."""

    return [line for rel in hunks for line in _apply(rel, (root / rel).read_text(), hunks)[1]]


def check_diffs(root, hunks):
    if stale := stale_hunks(root, hunks):
        raise _audit(stale)


# The builds a run plays (host/rules.h), and the guards that tell them apart: a `#if` chain whose branch differs for
# them. Those editions/ leaves to the preprocessor, which compiles 1.9.93's branch for both. editions/guards.json lists
# each one by file and the hash of its text, with the class that says why 1.9.93's branch plays a 1.9.8 run, so a new
# or changed guard stops the build until a rule's becomes a branch or the ledger classifies it.
RUN_BUILDS = (10908, 10993)
GUARDS = HERE / "editions" / "guards.json"
_DIRECTIVE = re.compile(r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b(.*)$", re.MULTILINE)
_ON_BUILD = re.compile(r"\bCL_BUILD\b")
RECORD_GUARDS = "uv run python crimson-core/adapter.py --record-guards"


def _holds(condition, build):
    """Whether a `#if`/`#elif` condition on CL_BUILD holds for `build`, in C++ (where __cplusplus is defined)."""

    expression = re.sub(r"\bdefined\s*\(?\s*__cplusplus\s*\)?", "1", condition.split("//")[0])
    expression = _ON_BUILD.sub(str(build), expression).replace("&&", " and ").replace("||", " or ")
    return bool(eval(re.sub(r"!(?!=)", " not ", expression), {}))


def build_guards(txt):
    """The `#if` chains in `txt` that take a different branch for each of RUN_BUILDS: each one's offset and text,
    from its `#if` through its `#endif`, in source order."""

    found, chains = [], []  # each open chain's start, its branch so far and the branch each build takes, None before
    for directive in _DIRECTIVE.finditer(txt):
        kind, condition = directive.groups()
        if kind == "endif":
            start, _, taken = chains.pop()
            if len(set(taken.values())) > 1:
                found.append((start, txt[start : directive.end()]))
            continue
        if kind in ("if", "ifdef", "ifndef"):
            chains.append([directive.start(), 0, dict.fromkeys(RUN_BUILDS)])
        else:
            chains[-1][1] += 1
        _, branch, taken = chains[-1]
        # A condition without CL_BUILD is the same for both builds, so either both take its branch or neither does.
        on_build = kind in ("if", "elif") and _ON_BUILD.search(condition)
        for build in RUN_BUILDS:
            if taken[build] is None and (kind == "else" or on_build and _holds(condition, build)):
                taken[build] = branch
    return sorted(found)


# A rule a recovered source names rather than guards: a macro tools/match/include/cl_rules.h defines so it expands by
# the build a source compiles as (CL_BUILD). host/rules.h defines each first, as the run's, for every target; one it
# leaves out, defines for some targets only, or defines by build, would compile 1.9.93's value for a 1.9.8 run, as a
# guard the ledger doesn't list would. The preprocessor decides both, so a rule counts as a compiler expands it.
CL_RULES = "tools/match/include/cl_rules.h"
HOOKS = HERE / "host" / "hooks.h"
_DEFINE_ON_BUILD = re.compile(r"^[ \t]*#[ \t]*define[ \t]+(\w+)\b(.*\bCL_BUILD\b.*)$", re.MULTILINE)
_DEFINE_NAME = re.compile(r"^#define (\w+)(\(?)", re.MULTILINE)
# What names nothing to the preprocessor: string and character literals, and comments. A quote after a digit
# separates digits (10'908) rather than opening a character.
_INERT = re.compile(r'"(?:\\.|[^"\\\n])*"|(?<![0-9A-Fa-f])\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|//[^\n]*', re.DOTALL)


def rule_definitions(txt):
    """The macros `txt` defines in terms of CL_BUILD, as the preprocessor reads the text: continued lines join, and
    literals and comments name nothing."""

    code = _INERT.sub(lambda m: " " if m[0][0] == "/" else '""', txt.replace("\\\n", ""))
    return [name for name, _ in _DEFINE_ON_BUILD.findall(code)]


def _preprocess(cc, args, text, cwd):
    return subprocess.run(
        [*cc, *args, "-x", "c++", "-E", "-P", "-"], input=text, capture_output=True, text=True, check=True, cwd=cwd,
    ).stdout


def _expansions(cc, args, text, names, cwd):
    """What each of `names` expands to after `text`, as `cc` preprocesses it with `args`, for each of RUN_BUILDS as
    CL_BUILD."""

    # Parenthesized, so a macro that expands to nothing still leaves its line.
    probe = text + "".join(f"__rule__ ({name}) __rule__\n" for name in names)
    return [
        re.findall(r"^__rule__ \((.*)\) __rule__$", _preprocess(cc, [*args, f"-DCL_BUILD={build}"], probe, cwd), re.MULTILINE)
        for build in RUN_BUILDS
    ]


def check_rules(root, cc, flags, first=HOOKS):
    """Every rule cl_rules.h names, with a target's `flags`, expands alike for every build, and to a condition, where a
    recovered source reads it: after `first` (host/hooks.h, which build.py includes ahead of every recovered source,
    and which brings host/rules.h) and cl_rules.h, as `cc` preprocesses them, with absolute include paths. It runs in an
    empty directory, as a recovered source's own holds no header for its quoted includes to find first."""

    with tempfile.TemporaryDirectory() as cwd:
        args = [*flags, "-I", str((root / CL_RULES).parent)]
        header = f'#include "{Path(CL_RULES).name}"\n'
        own, builtin = (set(_DEFINE_NAME.findall(_preprocess(cc, [*args, "-dM"], text, cwd))) for text in (header, ""))
        own = [(name, call) for name, call in sorted(own - builtin) if name != "CL_BUILD"]
        # A rule is a condition a source names bare; a function-like macro's bare name expands to nothing to compare.
        if functions := [name for name, call in own if call]:
            raise SystemExit(f"{CL_RULES} defines {', '.join(functions)} as a function; a rule is a condition, named bare")
        names = sorted(name for name, _ in own)
        rules = [name for name, *ways in zip(names, *_expansions(cc, args, header, names, cwd), strict=True) if len(set(ways)) > 1]
        seen = _expansions(cc, [*args, "-include", str(first)], header, rules, cwd)
        # Nothing, or the rule's own name (a function-like macro a bare use leaves alone), is no condition.
        if undecided := [name for name, *ways in zip(rules, *seen, strict=True) if len(set(ways)) > 1 or ways[0] in ("", name)]:
            raise SystemExit(
                f"Rules {CL_RULES} names that host/rules.h doesn't define as the run's for this target "
                f"({' '.join(cc + flags)}): {', '.join(undecided)}",
            )


def guarded_files(root, sources):
    """The `sources` and the headers every target compiles them with."""

    headers = (root / "tools/match/include", root / "third_party/headers")
    return [*sources, *(str(h.relative_to(root)) for d in headers for h in sorted(d.glob("*.h")))]


def guards(root, hunks, sources):
    """{file: {key: (line, text)}} for every guard telling RUN_BUILDS apart in `sources` and their headers after the
    diffs. A key is the hash of the guard's text with whitespace runs collapsed, `hash#N` for the Nth copy of one text
    in a file; the line is the recovered file's, or the diffed text's where a diff changed the guard."""

    found = {}
    for rel in guarded_files(root, sources):
        raw = (root / rel).read_text()
        txt = apply_diffs(rel, raw, hunks)
        copies, after = Counter(), {}  # each text's copies so far, and where the recovered file's last one ends
        for start, text in build_guards(txt):
            digest = hashlib.sha256(" ".join(text.split()).encode()).hexdigest()[:12]
            copies[digest] += 1
            if (at := raw.find(text, after.get(digest, 0))) >= 0:
                after[digest] = at + len(text)
                line = str(raw.count("\n", 0, at) + 1)
            else:
                line = f"{txt.count('\n', 0, start) + 1} after the diffs"
            found.setdefault(rel, {})[digest if copies[digest] == 1 else f"{digest}#{copies[digest]}"] = (line, text)
    return found


def _unclassified(guards):
    return "".join(
        f"{rel}:{line} (hash {key.split('#')[0]}):\n{textwrap.indent(text, '    ')}\n"
        for rel, key, line, text in guards
    )


def check_guards(root, hunks, sources):
    """Every guard telling RUN_BUILDS apart in `sources` and their headers after the diffs is one editions/guards.json
    lists, with one of its classes, and every macro they define in terms of CL_BUILD is a rule cl_rules.h names, which
    check_rules holds host/rules.h to."""

    if strays := [
        f"{rel}: {name}"
        for rel in guarded_files(root, sources)
        if rel not in (CL_RULES, "tools/match/include/cl_build.h")
        for name in rule_definitions(apply_diffs(rel, (root / rel).read_text(), hunks))
    ]:
        raise SystemExit(f"Macros defined by build outside {CL_RULES}; name each rule there:\n" + "\n".join(strays))
    ledger = json.loads(GUARDS.read_text())
    unlisted = [
        (rel, key, line, text)
        for rel, found in guards(root, hunks, sources).items()
        for key, (line, text) in found.items()
        if ledger["guards"].get(rel, {}).get(key) not in ledger["classes"]
    ]
    if unlisted:
        raise SystemExit(
            "Guards telling 1.9.8 from 1.9.93 changed. Turn a 1.9.8 rule's into a branch in editions/; for each other "
            f"one, pick the class in {GUARDS.parent.name}/{GUARDS.name} ({', '.join(ledger['classes'])}) that says "
            f"why 1.9.93's branch plays a 1.9.8 run, and record it with\n  {RECORD_GUARDS} HASH=CLASS ...\n"
            + _unclassified(unlisted),
        )


def stale_guards(root, targets):
    """The ledger's entries that no target, a (hunks, sources) pair, finds: (file, key, class) each."""

    found = {
        (rel, key) for hunks, sources in targets for rel, keys in guards(root, hunks, sources).items() for key in keys
    }
    listed = json.loads(GUARDS.read_text())["guards"]
    return [(rel, key, cls) for rel, keys in listed.items() for key, cls in keys.items() if (rel, key) not in found]


def record_guards(root, targets, assigned):
    """Rewrite the ledger with the guards of `targets`, (hunks, sources) pairs: a guard it lists by file and key keeps
    that class, and another, a new copy of a listed text among them, takes the one `assigned` gives its hash. Nothing
    is written while a guard has no class, or one the ledger doesn't define; returns the entries it dropped."""

    ledger = json.loads(GUARDS.read_text())
    if unknown := sorted(set(assigned.values()) - set(ledger["classes"])):
        raise SystemExit(f"Unknown guard classes {', '.join(unknown)}; the ledger's are {', '.join(ledger['classes'])}")
    known = {
        (rel, key): cls
        for rel, keys in ledger["guards"].items()
        for key, cls in keys.items()
        if cls in ledger["classes"]
    }
    found, missing = {}, {}
    for hunks, sources in targets:
        for rel, keys in guards(root, hunks, sources).items():
            for key, (line, text) in keys.items():
                if cls := known.get((rel, key)) or assigned.get(key.split("#")[0]):
                    found.setdefault(rel, {})[key] = cls
                else:
                    missing[rel, key] = (rel, key, line, text)
    if missing:
        raise SystemExit(
            f"Guards without a class; record each one's with {RECORD_GUARDS} HASH=CLASS ...\n"
            + _unclassified(missing.values()),
        )
    dropped = [
        (rel, key, cls)
        for rel, keys in ledger["guards"].items()
        for key, cls in keys.items()
        if key not in found.get(rel, {})
    ]
    ledger["guards"] = {rel: dict(sorted(found[rel].items())) for rel in sorted(found)}
    GUARDS.write_text(json.dumps(ledger, indent=2) + "\n")
    return dropped


def guard_targets(root):
    """Each target's (hunks, sources): the verifier's, and the game module's, which compiles every verifier source."""

    from game import GAME_DIFFS, game_sources

    core = json.loads((root / "crimson-core/sources.json").read_text())
    return [(load_diffs(DIFFS), core), (load_diffs(GAME_DIFFS), core + game_sources(root))]


# Every file write_if_changed wrote or found current in this run, so a build can drop what it no longer generates.
GENERATED = set()


def write_if_changed(path, text):
    """Write a generated file only when its bytes change: one that stays the same keeps its time, so Ninja leaves
    what reads it alone."""

    GENERATED.add(path)
    if not path.exists() or path.read_text() != text:
        path.write_text(text)


def replace(src, txt, old, new, count=1):
    """Replace `old`, which must occur `count` times; None leaves the count to a rule that applies wherever it can."""

    if count is not None and txt.count(old) != count:
        raise SystemExit(f"Audit {src.name}: {old!r} occurs {txt.count(old)} times, not {count}")
    return txt.replace(old, new)


def sub(src, pattern, repl, txt, count=1, flags=0):
    """re.subn that expects `count` sites; None leaves the count to a rule that applies wherever it can."""

    txt, found = re.subn(pattern, repl, txt, flags=flags)
    if count is not None and found != count:
        raise SystemExit(f"Audit {src.name}: {pattern!r} matches {found} times, not {count}")
    return txt


def wrap(src, txt):
    """A function the host wraps: the recovered body keeps a _recovered name, in its header's declarations too."""
    return f"#define {src.stem} {src.stem}_recovered\n" + txt


def prototypes(src, txt, table):
    for old, new in table.items():
        txt = sub(src, rf"(?m)^{re.escape(old)}", new.replace("\\", r"\\"), txt, count=None)
    return txt


def x87(src, txt):
    """The original's x87 evaluation at PC24: where a wide intermediate rounds, as the executable does."""

    txt = sub(src, r"\bfloat (VEC2_Angle|creature_vec2_angle|projectile_vec2_angle)\s*\(", r"double \1(", txt, None)
    if 'extern "C" float cos(float angle);' in txt:
        for fn in ("cos", "sin"):
            txt = replace(src, txt, f"float {fn}(float angle)", f"float {fn}f(float angle)", None)
            txt = replace(src, txt, f"{fn}(angle)", f"{fn}f(angle)", None)
    if src.stem.startswith("quest_build_"):
        # VC6 leaves transcendental results wide until their first arithmetic operation. Each following add still
        # rounds at PC24. These hold across the builders that use them; checks/builder_oracle.py runs every builder.
        txt = replace(src, txt, "float angle() const", "double angle() const", None)
        txt = replace(src, txt, "return (float)atan2(y, x);", "return atan2(y, x);", None)
        # Sweep Stakes and Deja vu spill cosine to F32, keeping sine wide.
        txt = replace(src, txt, "float angle_sin = (float)sin(angle);", "double angle_sin = sin(angle);", None)
        for fn in ("cos", "sin"):
            txt = replace(
                src,
                txt,
                f"(float)radius * (float){fn}(angle)",
                f"portable_mul32((float)radius,{fn}(angle))",
                None,
            )
        txt = sub(
            src,
            r"\(float\)(cos|sin)\((.*?)\)\s*\*\s*(radius|[0-9.]+f)",
            lambda m: f"portable_mul32({m[1]}({m[2]}),{m[3]})",
            txt,
            None,
            re.DOTALL,
        )
    if src.stem == "creature_update_all":
        # 0x00426b93: `fpatan` feeds the `fadd` of 1.5707964f directly; the heading rounds once.
        txt = replace(src, txt, "return (float)atan2(value.y, value.x);", "return atan2(value.y, value.x);")
        txt = replace(
            src,
            txt,
            "float desired_heading = creature_vec2_angle(",
            "double desired_heading = creature_vec2_angle(",
        )
        # Every `fcos`/`fsin` here feeds its first `fmul` wide. Movement multiplies left to right from the
        # cosine: dt, move_scale, move_speed, then 30 (0x00426cb9), unlike the source's grouping.
        txt = sub(
            src,
            r"30\.0f \* creatures\[creature_index\]\.move_speed\s*"
            r"\* \(move_scale \* \(frame_dt \* \(float\)(cos|sin)\(movement_heading\)\)\)",
            r"portable_mul32(\1(movement_heading), frame_dt) * move_scale * creatures[creature_index].move_speed * 30.0f",
            txt,
            4,
        )
        # 4 sites, plus 4 in the 1.9.8-only movement branches that never compile here.
        txt = sub(
            src,
            r"\(float\)(cos|sin)\((\w+)\)\s*\*\s*([\w.\[\]]+)",
            r"portable_mul32(\1(\2), \3)",
            txt,
            8,
        )
    if src.stem == "projectile_update":
        for fn in ("cos", "sin"):
            txt = replace(
                src,
                txt,
                f"(float){fn}(heading) * frame_dt * 20.0f",
                f"(float)({fn}(heading) * frame_dt) * 20.0f",
            )
        # Seeker steering keeps the trig result wide into its first multiply as well.
        txt = sub(
            src,
            r"\(float\)(cos|sin)\(secondary_projectile_pool\[secondary_index\]\.angle - 1\.5707964f\) \* frame_dt \* 800\.0f",
            r"(float)(\1(secondary_projectile_pool[secondary_index].angle - 1.5707964f) * frame_dt) * 800.0f",
            txt,
            4,
        )
        # A cast trig result multiplied directly stays wide into that multiply (e.g. the hit jitter at
        # 0x004211da, the particle velocities at 0x0042219f); stored ones are spilled (0x00421dfe).
        # 14 sites, plus 8 in the 1.9.8-only branches (seeker steps, particle steering) that never compile here.
        txt = sub(src, r"\(float\)(cos|sin)\(([^()]+)\) \* ([\w.]+)", r"portable_mul32(\1(\2), \3)", txt, 22)
        # 0x004212e5: the chain link's `fpatan` stays wide; each subtraction rounds.
        txt = replace(src, txt, "float chain_angle\n", "double chain_angle\n")
        txt = replace(src, txt, "= (float)atan2f(next_position->y", "= atan2f(next_position->y")
        txt = replace(
            src,
            txt,
            "chain_angle - 1.5707964f - 3.1415927f,",
            "(float)(chain_angle - 1.5707964f) - 3.1415927f,",
        )
    if src.stem in ("creature_handle_death", "creature_update_all", "perks_update_effects", "survival_spawn_creature"):
        # `fild` loads the int XP exactly and only the first PC24 operation rounds (kills 0x0041eb5b, Radioactive
        # 0x0042704b, Jinxed 0x004070a6); converting to float first rounds it too, which past 2^24 drifts.
        adds, muls = {
            "creature_handle_death": (2, 0),
            "creature_update_all": (2, 0),
            "perks_update_effects": (1, 0),
        }.get(
            src.stem,
            (0, 1),
        )
        txt = sub(
            src,
            r"\(int\)\(\s*\(float\)player_state_table\[0\]\.experience\b",
            "(int)(float)((double)player_state_table[0].experience",
            txt,
            adds,
        )
        txt = sub(
            src,
            r"\(float\)player_state_table\[0\]\.experience \* 0\.00125f",
            "portable_mul32((double)player_state_table[0].experience, 0.00125f)",
            txt,
            muls,
        )
    if src.stem == "perk_apply":
        # Grim Deal: `fild` the XP into the PC24 multiply.
        txt = replace(
            src,
            txt,
            "(int)(player_experience * 0.18f)",
            "(int)portable_mul32((double)player_experience, 0.18f)",
        )
    if src.stem == "bonus_apply":
        # 0x00409e0b: the first link's `fpatan` stays wide; each subtraction rounds.
        txt = replace(
            src,
            txt,
            "(float)atan2(dy, dx) - 1.5707964f - 3.1415927f,",
            "(float)(atan2(dy, dx) - 1.5707964f) - 3.1415927f,",
        )
    if src.stem == "player_update_heading":
        # Regression Bullets: `fild` the XP, `fsubp` the PC24 cost, then `_ftol`.
        txt = sub(
            src,
            r"player->experience = player->experience\s*- (weapon_table\[player->weapon_id\]\.reload_time \* [0-9.]+f);",
            r"player->experience = (int)(float)((double)player->experience - \1);",
            txt,
            2,
        )
        # FCOS/FSIN remain wide until the first FMUL (e.g. 0x00414335).
        # Subsequent multipliers must still round after every PC24 operation.
        txt = sub(
            src,
            r"(cosf|sinf)\(player->heading - 1\.5707964f\)\s*\*\s*player->move_speed",
            lambda m: f"portable_mul32({m[1][:-1]}(player->heading - 1.5707964f), player->move_speed)",
            txt,
            22,
        )
        # The shot and Fire Cough spreads feed their wide trig into the first multiply too (0x00415cb2, 0x00413b61).
        txt = sub(
            src,
            r"(cosf|sinf)\(spread_angle\) \* (spread_distance|spread_radius)",
            lambda m: f"portable_mul32({m[1][:-1]}(spread_angle), {m[2]})",
            txt,
            4,
        )
        # The 60-unit aim point keeps FCOS wide into its multiply but stores FSIN first (0x00415427, 0x00415576,
        # 0x00415606).
        txt = sub(
            src,
            r"vec2_t direction\(cosf\((player->aim_heading - 1\.5707964f)\), sinf\(\1\)\);"
            r"(\s*\*\(vec2_t \*\)&player->aim = )direction \* 60\.0f( \+ \*\(vec2_t \*\)&player->position;)",
            r"vec2_t reach(portable_mul32(cos(\1), 60.0f), sinf(\1) * 60.0f);\2reach\3",
            txt,
            3,
        )
    if src.stem == "gameplay_update_and_render":
        # The level threshold, and its 1.9.8-only double-precision branch that never compiles here.
        txt = replace(src, txt, "pow(", "portable_crt_pow_pc24(", 2)
    return txt


def dialect(src, txt):
    """What a modern compiler needs from VC6 sources, wherever it applies."""

    txt = prototypes(src, txt, PROTOTYPES)
    # VC6 binds mutable references to value temporaries; the operators and helpers taking them never mutate through
    # them. List widgets are the exception: helpers take one to update it.
    txt = sub(src, r"(?<!const )\b(?!ui_list_widget_t\b)([A-Za-z_]\w*_t) &(\w+)\)", r"const \1 &\2)", txt, None)
    for fn in ("sin", "cos", "atan2", "pow", "sinf", "cosf", "atan2f"):
        txt = sub(src, rf"\b{fn}\(", f"portable_{fn}(", txt, None)
    return txt


def adapt(src, txt):
    return dialect(src, x87(src, txt))


def main():
    p = argparse.ArgumentParser(description="Rewrite editions/guards.json from the guards both targets compile.")
    p.add_argument("--root", type=Path, default=HERE.parent)
    p.add_argument(
        "--record-guards",
        nargs="*",
        metavar="HASH=CLASS",
        required=True,
        help="Classify each new or changed guard by the hash a failed check printed",
    )
    a = p.parse_args()
    assigned = dict(pair.split("=", 1) for pair in a.record_guards)
    for rel, key, cls in record_guards(a.root, guard_targets(a.root), assigned):
        print(f"Dropped {rel} {key} ({cls}): no target compiles it")
    print(f"Wrote {GUARDS}")


if __name__ == "__main__":
    main()
