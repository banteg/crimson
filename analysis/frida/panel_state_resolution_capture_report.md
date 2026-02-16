# Panel state resolution capture report

- issue: `#165` (support all resolutions)
- input_glob: `artifacts/frida/share/panel_state_resolution_capture_*.jsonl`
- files_scanned: `7`
- runs_detected: `4`

## File triage
- complete: `0`
- degraded: `4`
- partial: `3`

## Runs
### `20260216_074411_946999de` (degraded)
- `artifacts/frida/share/panel_state_resolution_capture_1024x768_20260216_074411_946999de.jsonl`: degraded, lines=1467 (error-events:3, zero-signal-captured-states:8, text-rows-with-replacement-char:635/635)
- primary by resolution:
  - `1024x768`: degraded, captured=16/18, non_captured=2, zero_signal=8

### `20260216_074532_7029125b` (degraded)
- `artifacts/frida/share/panel_state_resolution_capture_1024x768_20260216_074532_7029125b.jsonl`: partial, lines=7 (sweep-began-without-sweep_done, error-events:1)
- `artifacts/frida/share/panel_state_resolution_capture_800x600_20260216_074532_7029125b.jsonl`: degraded, lines=3761 (zero-signal-captured-states:5, max-unique-text-cap-states:1, text-rows-with-replacement-char:2760/2760)
- primary by resolution:
  - `800x600`: degraded, captured=18/18, non_captured=0, zero_signal=5
  - `1024x768`: partial, captured=0/0, non_captured=0, zero_signal=0

### `20260216_074620_e117148e` (degraded)
- `artifacts/frida/share/panel_state_resolution_capture_640x480_20260216_074620_e117148e.jsonl`: degraded, lines=3888 (zero-signal-captured-states:4, max-unique-text-cap-states:1, text-rows-with-replacement-char:2710/2710)
- `artifacts/frida/share/panel_state_resolution_capture_800x600_20260216_074620_e117148e.jsonl`: partial, lines=2 (startup-handoff-only)
- primary by resolution:
  - `640x480`: degraded, captured=18/18, non_captured=0, zero_signal=4
  - `800x600`: partial, captured=0/0, non_captured=0, zero_signal=0

### `20260216_074703_db6c8c9b` (degraded)
- `artifacts/frida/share/panel_state_resolution_capture_640x480_20260216_074703_db6c8c9b.jsonl`: partial, lines=2 (startup-handoff-only)
- `artifacts/frida/share/panel_state_resolution_capture_960x600_20260216_074703_db6c8c9b.jsonl`: degraded, lines=4341 (error-events:1, zero-signal-captured-states:5, max-unique-text-cap-states:1, text-rows-with-replacement-char:3258/3258)
- primary by resolution:
  - `640x480`: partial, captured=0/0, non_captured=0, zero_signal=0
  - `960x600`: degraded, captured=18/18, non_captured=0, zero_signal=5

## Best Coverage By Resolution
| resolution | status | run_id | captured/total | non-captured | zero-signal | file |
| --- | --- | --- | --- | --- | --- | --- |
| `640x480` | `degraded` | `20260216_074620_e117148e` | `18/18` | `0` | `4` | `artifacts/frida/share/panel_state_resolution_capture_640x480_20260216_074620_e117148e.jsonl` |
| `800x600` | `degraded` | `20260216_074532_7029125b` | `18/18` | `0` | `5` | `artifacts/frida/share/panel_state_resolution_capture_800x600_20260216_074532_7029125b.jsonl` |
| `960x600` | `degraded` | `20260216_074703_db6c8c9b` | `18/18` | `0` | `5` | `artifacts/frida/share/panel_state_resolution_capture_960x600_20260216_074703_db6c8c9b.jsonl` |
| `1024x768` | `degraded` | `20260216_074411_946999de` | `16/18` | `2` | `8` | `artifacts/frida/share/panel_state_resolution_capture_1024x768_20260216_074411_946999de.jsonl` |

## Notes
- `partial` files with only `start`/`boot_detected` are typical handoff artifacts when the launcher resolution changes after attach.
- `degraded` files indicate sweep completion with one or more non-captured states or captured states with zero panel/text/frame signal.
- High `text_rows_with_replacement_char` usually means trailing garbage in text extraction and should not be treated as literal UI strings.
