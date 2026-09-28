"""Extract credits evidence from the twelve local historical executables.

Run from repository root with .venv/bin/python. Requires pefile.
Stored strings are evidence, not a claim that every string is displayed.
"""
import hashlib
import json
import re
import struct
from pathlib import Path

import pefile

ROOT = Path('analysis/historical/credits-leads')
VERSIONS = ['1.0.2', '1.3.0', '1.3.1', '1.4.0', '1.8.7', '1.9.0', '1.9.1', '1.9.3', '1.9.8', '1.9.9', '1.9.92', '1.9.93-gog']
PUSH_CALL = re.compile(rb'\x6a([\x00\x01])\x68(.{4})(?:\x6a(.)|\x68(.{4}))\xe8(.{4})', re.S)
records = []
for version in VERSIONS:
    path = Path('game_bins/crimsonland') / version / ('crimson.exe' if version in VERSIONS[:4] else 'crimsonland.exe')
    data = path.read_bytes()
    record = dict(version=version, path=str(path), sha256=hashlib.sha256(data).hexdigest())
    strings = [(m.start(), m.group().decode('cp1252')) for m in re.finditer(rb'[\x20-\x7e\xa0-\xff]{3,}', data)]
    if version in VERSIONS[:4]:
        start = data.find(b'pHx -')
        if start < 0:
            start = data.index(b'     (10tons logo by pHx)')
        end = data.index(b'Project Crimsonland') + len(b'Project Crimsonland')
        record['credits_strings_file_order'] = [dict(file_offset=hex(o), text=s) for o,s in strings if start <= o < end]
        record['team_roster'] = [s for o,s in strings if start <= o < end and ' - ' in s]
    else:
        pe = pefile.PE(data=data)
        base = pe.OPTIONAL_HEADER.ImageBase
        greet = base + pe.get_rva_from_offset(data.index(b'Greeting to:\0'))
        reference = data.index(b'\x68' + struct.pack('<I', greet))
        # Decode the call after push(string), push(index). All eight use push imm8.
        assert data[reference+5] == 0x6a and data[reference+7] == 0xe8
        call_offset = reference + 7
        target = base + pe.get_rva_from_offset(call_offset + 5) + struct.unpack_from('<i', data, call_offset+1)[0]
        calls = []
        for m in PUSH_CALL.finditer(data):
            call = m.end() - 5
            try:
                callee = base + pe.get_rva_from_offset(m.end()) + struct.unpack('<i', m[5])[0]
            except pefile.PEFormatError:
                continue
            if callee != target:
                continue
            ptr = struct.unpack('<I', m[2])[0]
            offset = pe.get_offset_from_rva(ptr-base)
            text = data[offset:data.index(b'\0', offset)].decode('cp1252')
            index = m[3][0] if m[3] is not None else struct.unpack('<I',m[4])[0]
            calls.append(dict(call_va=hex(base+pe.get_rva_from_offset(call)), index=index, flags=m[1][0], text=text, string_file_offset=hex(offset)))
        # Only the contiguous builder region around the greeting references.
        calls = [c for c in calls if abs(int(c['call_va'],16)-(base+pe.get_rva_from_offset(reference))) < 0x800]
        assert len(calls) >= 120, (version,len(calls))
        final = {}
        for c in calls:
            final[c['index']] = c['text']
        overwritten = [c for c in calls if c['text'] and final[c['index']] != c['text']]
        record.update(credits_setter_va=hex(target), setter_calls=calls,
                      final_nonempty_lines=[dict(index=i,text=s) for i,s in sorted(final.items()) if s],
                      overwritten_nonempty_lines=overwritten)
    records.append(record)
(ROOT/'all-versions.json').write_text(json.dumps(dict(schema=1, checked_at='2026-09-28', encoding='windows-1252', versions=records),ensure_ascii=False,indent=2)+'\n')
for r in records:
    print(r['version'],len(r.get('credits_strings_file_order',[])),len(r.get('setter_calls',[])),[c['text'] for c in r.get('overwritten_nonempty_lines',[])])
