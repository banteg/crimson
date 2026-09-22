"""Prove prefix initialization controls allocation across the inline row clear."""

import argparse
import json
import shutil
import struct
from pathlib import Path
from unittest.mock import patch

from controls import build, sha, sources

from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

HERE = Path(__file__).resolve().parent
ORIGINAL_OBSERVER = c2.observer_source


def observer(profile, source, deny=0):
    lines = source.splitlines()
    start = next(i for i, s in enumerate(lines) if 'void highscore_screen_update' in s)
    prefix = next(i for i, s in enumerate(lines) if 'int prefix_length = 0;' in s) - start
    two = next(i for i, s in enumerate(lines) if 'prefix_length = 2;' in s) - start
    # VC6's function-relative source lines include the declaration line.
    defines = f'#define PREFIX_LINE {prefix}\n#define TWO_LINE {two}\n#define DENY_MASK {deny}\n'
    addon = defines + (HERE / 'watch.c.in').read_text()
    s = ORIGINAL_OBSERVER(profile).replace('static HANDLE trace_file;', 'static HANDLE trace_file;\n' + addon)
    s = s.replace('    node = first;', '    watch(phase,registers,first);\n    if(phase>=12)return;\n    node = first;', 1)
    s = s.replace('base = (unsigned char *)invoke - INVOKE_RVA;',
                  'base = (unsigned char *)invoke - INVOKE_RVA;\n    c2base=(unsigned long)base;')
    s = s.replace('    trace_file = CreateFileA(',
                  '    watch_file=CreateFileA("choices.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
                  '    if(watch_file==INVALID_HANDLE_VALUE)ExitProcess(81);\n    trace_file = CreateFileA(')
    return s.replace('    CloseHandle(trace_file);', '    CloseHandle(watch_file);\n    CloseHandle(trace_file);')


def decisions(directory):
    raw = (directory / 'choices.bin').read_bytes()
    assert len(raw) % 140 == 0
    rows = [struct.unpack_from('<35I', raw, i) for i in range(0, len(raw), 140)]
    assert [r[0] for r in rows] == [12, *([113] * 7), 112]
    assert len({r[2] for r in rows}) == 1 and all(r[1] == 1 for r in rows)
    base = struct.unpack_from('<3I', (directory / 'phases.bin').read_bytes())[2]
    signed = lambda v: v - 2**32 if v >= 2**31 else v
    return {
        'single_prefix_allocation': True,
        'priority': signed(rows[0][9]),
        'cost': signed(rows[0][21]),
        'register_rva': rows[-1][10] - base,
        'choices': [{'register': r[3], 'before': r[4], 'after': r[5],
                     'costs': [signed(v) for v in r[26:35]]} for r in rows[1:-1]],
        'trace_sha256': sha(raw),
        'coff_sha256': sha(replay.normalized_coff(directory / 'replay.obj')),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    root = parser.parse_args().out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    p = c2.load_profile()
    p = dict(p, hooks=p['hooks'][:12] + [
        {'site': 0x2FE5F, 'target': 0x32F7C, 'return': True},
        {'site': 0x330C2, 'target': 0x251D, 'return': True},
    ])
    results = {}
    for name in ('baseline', 'prefix-before-clear'):
        cfg, _, _, _ = build(name, root)
        source = sources()[name][0]
        out = root / (name + '-trace')
        with patch.object(c2, 'load_profile', lambda: p), patch.object(
            c2, 'observer_source', lambda profile, source=source: observer(profile, source),
        ):
            receipt = c2.trace(cfg.directory, out)
        events = c2.read_verified(out)
        event = next(e for e in events if e['phase'] == 10 and e['function_ordinal'] == 0)
        lines = source.splitlines()
        start = next(i for i, text in enumerate(lines) if 'void highscore_screen_update' in text)
        prefix_line = next(i for i, text in enumerate(lines) if 'int prefix_length = 0;' in text) - start
        initializations = [(i, n) for i, n in enumerate(event['nodes'])
                           if n['line'] == prefix_line and n['op'] == 1
                           and len(n['dst']) == 1 and n['dst'][0]['kind'] == 1]
        clears = [(i, n) for i, n in enumerate(event['nodes']) if n['op'] == 0x111]
        assert len(initializations) == len(clears) == 1
        precedes = initializations[0][0] < clears[0][0]
        assert precedes == (name == 'prefix-before-clear')
        row = decisions(out / 'observed')
        row['pre_allocation_order'] = {
            'prefix_definition_precedes_clear': precedes,
            'prefix_opcode': initializations[0][1]['op'], 'clear_opcode': clears[0][1]['op'],
            'prefix_line': prefix_line, 'clear_line': clears[0][1]['line'],
            'prefix_ordinal': initializations[0][0], 'clear_ordinal': clears[0][0],
        }
        row.update(source_sha256=receipt['source_sha256'],
                   whole_coff_equal_except_timestamp=receipt['whole_coff_equal_except_timestamp'],
                   missing_stream_rejected=receipt['missing_stream_rejected'])
        results[name] = row
        print('Verified preserving', name, flush=True)
    assert [r['register'] for r in results['baseline']['choices'] if r['before']] == [2, 8, 4]
    assert [r['register'] for r in results['prefix-before-clear']['choices'] if r['before']] == [4]
    baseline, witness = results['baseline'], results['prefix-before-clear']
    assert baseline['priority'] == witness['priority'] == 106
    assert baseline['cost'] == witness['cost'] == 20
    assert [r['costs'] for r in baseline['choices']] == [r['costs'] for r in witness['choices']]
    assert results['baseline']['register_rva'] == 0xAC7D8  # ECX
    assert results['prefix-before-clear']['register_rva'] == 0xAC880  # EBX
    for name, deny, expected_reg in [('deny-ecx', 1 << 2, 0xAC9D0),
                                    ('deny-ecx-edi', (1 << 2) | (1 << 8), 0xAC880)]:
        out = root / name
        out.mkdir()
        shutil.copyfile(root / 'baseline-trace/replay/replay_settings.h', out / 'replay_settings.h')
        (out / 'observer.c').write_text(observer(p, sources()['baseline'][0], deny))
        with c2.compiler_environment():
            replay.compile_driver(out, 'observer.c', 'observer.obj')
            replay.link(out, 'observer.exe', 'observer.obj')
            replay.run([replay.WIBO, 'observer.exe'], out)
        row = decisions(out)
        assert row['register_rva'] == expected_reg
        changed = [r['register'] for r in row['choices'] if r['before'] != r['after']]
        assert changed == ([2] if name == 'deny-ecx' else [2, 8])
        row['changed_choices'] = changed
        results[name] = row
        print('Verified scoped', name, flush=True)
    assert results['deny-ecx-edi']['coff_sha256'] == results['prefix-before-clear']['coff_sha256']
    assert results['deny-ecx']['coff_sha256'] not in {
        results['baseline']['coff_sha256'], results['prefix-before-clear']['coff_sha256'],
    }
    result = {
        'schema': 1, 'c2_sha256': p['c2_sha256'],
        'input_hashes': {n: sha((HERE / n).read_bytes()) for n in (
            'controls.py', 'controls.json', 'watch.c.in', 'verify_compiler.py',
        )},
        'results': results,
    }
    (root / 'results.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
