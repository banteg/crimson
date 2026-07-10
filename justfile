set shell := ["bash", "-uc"]
set windows-shell := ["powershell", "-NoLogo", "-Command"]

version := "1.9.93-gog"
game_dir := "game_bins/crimsonland/" + version
assets_dir := "artifacts/assets"
atlas_usage := "artifacts/atlas/atlas_usage.json"
atlas_frames := "artifacts/atlas/frames"
share_dir := "/mnt/c/share/frida"
frida_share_dir := "artifacts/frida/share"

default:
    @just --list

# Tests
test *args:
    uv run pytest --no-cov {{args}}

test-cov *args:
    uv run pytest --cov=crimson --cov-report=term-missing --cov-report=html --cov-report=xml {{args}}

check *args:
    uv run ruff check .
    uv run lint-imports
    uv run ty check src tests
    uv run scripts/check_docs.py
    sg scan
    sg test
    uv run pytest --no-cov {{args}}
    just check-zig

ast-grep-all:
    sg scan
    sg test
    sg scan -c sgconfig.local.yml
    sg test -c sgconfig.local.yml

check-zig:
    cd crimson-zig && zig build test --summary all
    cd crimson-zig && zig build -Doptimize=ReleaseFast
    cd crimson-zig && zig build wasm

ty:
    uv run ty check src tests

ty-tests:
    uv run ty check tests

# Lint
lint-imports:
    uv run lint-imports

zig-z004-fix:
    sg run -c sgconfig.local.yml -l zig -p 'const _NAME = _TYPE{};' -r 'const $NAME: $TYPE = .{};' crimson-zig/src -U
    sg run -c sgconfig.local.yml -l zig -p 'var _NAME = _TYPE{};' -r 'var $NAME: $TYPE = .{};' crimson-zig/src -U

# Duplication
dup-report out="artifacts/duplication/pylint-r0801.txt" min="12":
    mkdir -p "$(dirname "{{out}}")"
    uv run pylint --disable=all --enable=R0801 --min-similarity-lines={{min}} src | tee "{{out}}" || true

# Assets
extract:
    uv run crimson extract {{game_dir}} {{assets_dir}}

# Atlas
atlas-scan:
    uv run scripts/atlas_scan.py --output-json {{atlas_usage}}

atlas-export-all:
    uv run scripts/atlas_export.py --all --usage-json {{atlas_usage}} --out-root {{atlas_frames}}

atlas-export image grid:
    uv run scripts/atlas_export.py --image {{image}} --grid {{grid}}

# Fonts
font-sample:
    uv run crimson view fonts

# Docs
docs-build:
    uv run zensical build

docs-check:
    uv run scripts/check_docs.py

docs-zensical-fix:
    uv run scripts/zensical_fix_md.py docs

# Analysis
entrypoint-trace:
    uv run scripts/entrypoint_trace.py --depth 2 --skip-external

function-hotspots:
    uv run scripts/function_hotspots.py --top 12 --only-fun

dat-hotspots *args:
    uv run scripts/dat_hotspots.py {{args}}

schema-inventory *args:
    uv run scripts/schema_inventory.py {{args}}

save-status *args:
    uv run scripts/save_status.py {{args}}

weapon-table:
    uv run scripts/extract_weapon_table.py

spawn-templates:
    uv run scripts/gen_spawn_templates.py

# Ghidra
[unix]
ghidra-exe:
    ./analysis/ghidra/tooling/ghidra-analyze.sh \
      --script-path analysis/ghidra/scripts \
      -s ImportThirdPartyHeaders.java -a third_party/headers \
      -s ApplyWinapiGDT.java -a analysis/ghidra/maps/winapi_32.gdt \
      -s CreateCreditsScreenUpdate.java \
      -s CreateCreditsSecretUpdate.java \
      -s CreateQuestBuilders.java \
      -s CreateConsoleFunctions.java \
      -s CreateGameStateCallbacks.java \
      -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
      -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
      -s ExportAll.java \
      -o analysis/ghidra/raw \
      {{game_dir}}/crimsonland.exe

[unix]
ghidra-grim:
    ./analysis/ghidra/tooling/ghidra-analyze.sh \
      --script-path analysis/ghidra/scripts \
      -s ImportThirdPartyHeaders.java -a third_party/headers \
      -s ApplyWinapiGDT.java -a analysis/ghidra/maps/winapi_32.gdt \
      -s CreateGrim2DVtableFunctions.java \
      -s CreateConfigDialogProc.java \
      -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
      -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
      -s ExportAll.java \
      -o analysis/ghidra/raw \
      {{game_dir}}/grim.dll

[unix]
ghidra-sync *args:
    bash scripts/ghidra_sync.sh {{args}}

# PE metadata
pe-info target="crimsonland.exe":
    rabin2 -I {{game_dir}}/{{target}}

pe-imports target="crimsonland.exe":
    rabin2 -i {{game_dir}}/{{target}}

# Zig
zig-build:
    cd crimson-zig && zig build

zig-run:
    cd crimson-zig && zig build run

zig-test:
    cd crimson-zig && zig build test

zig-wasm:
    cd crimson-zig && zig build wasm

# WinDbg
windbg-server:
    cdb.exe -server tcp:port=5005,password=secret -logo C:\games\crimsonland_1.9.93\windbg.log -pn crimsonland.exe -noio

windbg-client:
    cdb.exe -remote tcp:server=127.0.0.1,port=5005,password=secret -bonc

windbg-tail:
    uv run scripts/windbg_tail.py

# Frida
[windows]
frida-attach script="scripts\\frida\\crimsonland_probe.js" process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "{{script}}"

[windows]
frida-unlock-secrets process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\unlock_secrets.js"

[windows]
frida-quest-spanking-count process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\quest_spanking_count.js"

[windows]
frida-azk-verify process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\azk_verify_no_unlock.js"

[windows]
frida-quest-build-dump process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\quest_build_dump.js"

[windows]
frida-demo-trial-overlay process="crimsonland.exe" addrs="" link_base="" module="":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; if ("{{addrs}}" -ne "") { $env:CRIMSON_FRIDA_ADDRS = "{{addrs}}" } else { Remove-Item Env:CRIMSON_FRIDA_ADDRS -ErrorAction SilentlyContinue }; if ("{{link_base}}" -ne "") { $env:CRIMSON_FRIDA_LINK_BASE = "{{link_base}}" } else { Remove-Item Env:CRIMSON_FRIDA_LINK_BASE -ErrorAction SilentlyContinue }; if ("{{module}}" -ne "") { $env:CRIMSON_FRIDA_MODULE = "{{module}}" } else { Remove-Item Env:CRIMSON_FRIDA_MODULE -ErrorAction SilentlyContinue }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\demo_trial_overlay_trace.js"

[windows]
frida-demo-idle-threshold process="crimsonland.exe" addrs="" link_base="" module="":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; if ("{{addrs}}" -ne "") { $env:CRIMSON_FRIDA_ADDRS = "{{addrs}}" } else { Remove-Item Env:CRIMSON_FRIDA_ADDRS -ErrorAction SilentlyContinue }; if ("{{link_base}}" -ne "") { $env:CRIMSON_FRIDA_LINK_BASE = "{{link_base}}" } else { Remove-Item Env:CRIMSON_FRIDA_LINK_BASE -ErrorAction SilentlyContinue }; if ("{{module}}" -ne "") { $env:CRIMSON_FRIDA_MODULE = "{{module}}" } else { Remove-Item Env:CRIMSON_FRIDA_MODULE -ErrorAction SilentlyContinue }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\demo_idle_threshold_trace.js"

[windows]
frida-game-over-panel-trace process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\game_over_panel_trace.js"

[windows]
frida-gameplay-state-capture process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\gameplay_state_capture.js"

[windows]
frida-gameplay-diff-capture *host_args:
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; uv run --with frida python scripts/frida/gameplay_diff_capture_host.py {{host_args}}

[windows]
frida-survival-autoplay process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\survival_autoplay.js"

[windows]
frida-panel-state-resolution-sweep process="crimsonland.exe":
    @if (-not $env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR = "C:\share\frida" }; New-Item -ItemType Directory -Force -Path "$env:CRIMSON_FRIDA_DIR" | Out-Null; frida -n "{{process}}" -l "scripts\frida\panel_state_resolution_sweep.js"

[windows]
ghidra-sync:
    wsl -e bash -lc "cd ~/dev/crimson && just ghidra-sync"

[windows]
ida-export-exe:
    $IDA_DIR="C:\\Program Files\\IDA Professional 9.2"; $OUT_DIR="analysis\\ida\\raw\\crimsonland.exe"; $NAME_MAP=(Resolve-Path analysis\\ghidra\\maps\\name_map.json).Path; $DATA_MAP=(Resolve-Path analysis\\ghidra\\maps\\data_map.json).Path; mkdir -Force $OUT_DIR | Out-Null; $OUT_DIR=(Resolve-Path $OUT_DIR).Path; & "$IDA_DIR\\idat.exe" -A -L"$OUT_DIR\\ida.log" -S"scripts\\ida_export.py $OUT_DIR $NAME_MAP $DATA_MAP" "{{game_dir}}\\crimsonland.exe"

[windows]
ida-export-grim:
    $IDA_DIR="C:\\Program Files\\IDA Professional 9.2"; $OUT_DIR="analysis\\ida\\raw\\grim.dll"; $NAME_MAP=(Resolve-Path analysis\\ghidra\\maps\\name_map.json).Path; $DATA_MAP=(Resolve-Path analysis\\ghidra\\maps\\data_map.json).Path; mkdir -Force $OUT_DIR | Out-Null; $OUT_DIR=(Resolve-Path $OUT_DIR).Path; & "$IDA_DIR\\idat.exe" -A -L"$OUT_DIR\\ida.log" -S"scripts\\ida_export.py $OUT_DIR $NAME_MAP $DATA_MAP" "{{game_dir}}\\grim.dll"

[windows]
ida-decompile-exe:
    $IDA_DIR="C:\\Program Files\\IDA Professional 9.2"; $OUT_DIR="analysis\\ida\\raw\\crimsonland.exe"; $NAME_MAP=(Resolve-Path analysis\\ghidra\\maps\\name_map.json).Path; $DATA_MAP=(Resolve-Path analysis\\ghidra\\maps\\data_map.json).Path; mkdir -Force $OUT_DIR | Out-Null; & "$IDA_DIR\\idat.exe" -A -L"$OUT_DIR\\ida_decompile.log" -S"scripts\\ida_decompile.py $OUT_DIR\\crimsonland.exe_decompiled.c $NAME_MAP $DATA_MAP" "{{game_dir}}\\crimsonland.exe"

[windows]
ida-decompile-grim:
    $IDA_DIR="C:\\Program Files\\IDA Professional 9.2"; $OUT_DIR="analysis\\ida\\raw\\grim.dll"; $NAME_MAP=(Resolve-Path analysis\\ghidra\\maps\\name_map.json).Path; $DATA_MAP=(Resolve-Path analysis\\ghidra\\maps\\data_map.json).Path; mkdir -Force $OUT_DIR | Out-Null; & "$IDA_DIR\\idat.exe" -A -L"$OUT_DIR\\ida_decompile.log" -S"scripts\\ida_decompile.py $OUT_DIR\\grim.dll_decompiled.c $NAME_MAP $DATA_MAP" "{{game_dir}}\\grim.dll"

[unix]
frida-copy-share:
    mkdir -p {{frida_share_dir}}
    for f in {{share_dir}}/*; do \
        [ -e "$f" ] || continue; \
        cp -av "$f" {{frida_share_dir}}/; \
    done

[unix]
frida-import-raw:
    mkdir -p analysis/frida/raw
    for f in grim_hits.jsonl crimsonland_frida_hits.jsonl gameplay_state_capture.jsonl gameplay_diff_capture.jsonl demo_trial_overlay_trace.jsonl demo_idle_threshold_trace.jsonl screen_fade_trace.jsonl ui_render_trace.jsonl game_over_panel_trace.jsonl survival_autoplay.jsonl azk_verify_no_unlock.jsonl creature_anim_trace.jsonl; do \
        [ -e "{{share_dir}}/$f" ] || continue; \
        cp -av "{{share_dir}}/$f" analysis/frida/raw/; \
    done
    for f in {{share_dir}}/gameplay_diff_capture.*.run*.cdt {{share_dir}}/gameplay_diff_capture.*.run*.crd {{share_dir}}/gameplay_diff_capture.*.run*.rng_evidence.json {{share_dir}}/gameplay_diff_capture.*.run*.evidence.msgpack.zst; do \
        [ -e "$f" ] || continue; \
        cp -av "$f" analysis/frida/raw/; \
    done

[unix]
capture-fixtures-import captures_dir=share_dir:
    uv run scripts/import_capture_fixtures.py --captures-dir "{{captures_dir}}"

[unix]
frida-reduce:
    uv run scripts/frida_reduce.py \
      --log analysis/frida/raw/grim_hits.jsonl \
      --log analysis/frida/raw/crimsonland_frida_hits.jsonl \
      --log analysis/frida/raw/demo_trial_overlay_trace.jsonl \
      --log analysis/frida/raw/demo_idle_threshold_trace.jsonl \
      --out-dir analysis/frida

[unix]
game-over-panel-reduce log="artifacts/frida/share/game_over_panel_trace.jsonl" out="analysis/frida/game_over_panel_trace_summary.json":
    uv run scripts/game_over_panel_trace_reduce.py --log {{log}} --out {{out}}

[unix]
panel-state-resolution-reduce glob="artifacts/frida/share/panel_state_resolution_capture_*.jsonl" out_json="analysis/frida/panel_state_resolution_capture_summary.json" out_md="analysis/frida/panel_state_resolution_capture_report.md":
    uv run scripts/panel_state_resolution_capture_reduce.py --glob "{{glob}}" --out-json "{{out_json}}" --out-md "{{out_md}}"

[unix]
demo-trial-validate log="analysis/frida/raw/demo_trial_overlay_trace.jsonl":
    uv run scripts/demo_trial_overlay_validate.py {{log}}

[unix]
demo-idle-summarize log="analysis/frida/raw/demo_idle_threshold_trace.jsonl":
    uv run scripts/demo_idle_threshold_summarize.py {{log}}

# Screenshots
[windows]
game-screenshot:
    nircmd win activate process crimsonland.exe
    sleep 1
    nircmd savescreenshotwin "screenshots\\screen.png"

zip-decompile:
    zip -r crimson.zip \
        analysis/ghidra/ \
        analysis/ida/ \
        analysis/binary_ninja/raw/*.txt \
        scripts src docs third_party/headers/crimsonland_types.h \
        -x "*__pycache__*" \
        -x "*winapi_32.gdt*"
    open -R crimson.zip
