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
    uv run pytest {{args}}

test-cov *args:
    uv run pytest --cov-report=html --cov-report=xml {{args}}

# Lint
lint-imports:
    uv run lint-imports

lint-assets:
    uv run scripts/check_asset_loader_usage.py

# Duplication
dup-report out="artifacts/duplication/pylint-r0801.txt" min="12":
    mkdir -p "$(dirname "{{out}}")"
    uv run pylint --disable=all --enable=R0801 --min-similarity-lines={{min}} src | tee "{{out}}" || true

# Profiling
[unix]
pyspy-game-record out="artifacts/profiling/pyspy.speedscope.json" duration="10" rate="100" format="speedscope" *args:
    #!/usr/bin/env bash
    set -euo pipefail

    out="{{out}}"
    duration="{{duration}}"
    rate="{{rate}}"
    format="{{format}}"

    mkdir -p "$(dirname "$out")"

    uv run crimson game {{args}} &
    launcher_pid="$!"

    pid="$launcher_pid"
    for _ in {1..40}; do
        child="$(pgrep -P "$launcher_pid" -n || true)"
        if [[ -n "$child" ]]; then
            pid="$child"
            break
        fi
        sleep 0.05
    done

    echo "game pid: $pid (launcher: $launcher_pid)"
    echo "recording ${duration}s @ ${rate}Hz (${format}) -> $out"

    user_id="$(id -u)"
    group_id="$(id -g)"
    sudo uv run py-spy record --pid "$pid" --rate "$rate" --duration "$duration" --format "$format" --output "$out" --nonblocking
    sudo chown "${user_id}:${group_id}" "$out"
    echo "saved: $out"

# Assets
extract:
    uv run paq extract {{game_dir}} {{assets_dir}}

# Atlas
atlas-scan:
    uv run scripts/atlas_scan.py --output-json {{atlas_usage}}

atlas-export-all:
    uv run scripts/atlas_export.py --all --usage-json {{atlas_usage}} --out-root {{atlas_frames}}

atlas-export image grid:
    uv run scripts/atlas_export.py --image {{image}} --grid {{grid}}

# Fonts
font-sample:
    uv run paq font --assets-dir {{assets_dir}} --out artifacts/fonts/small_font_sample.png

# Docs
docs-map-progress:
    uv run scripts/update_map_progress_docs.py

docs-build:
    uv run zensical build

docs-zensical-fix:
    uv run scripts/zensical_fix_md.py docs

# Analysis
entrypoint-trace:
    uv run scripts/entrypoint_trace.py --depth 2 --skip-external

function-hotspots:
    uv run scripts/function_hotspots.py --top 12 --only-fun

dat-hotspots *args:
    uv run scripts/dat_hotspots.py {{args}}

angr-trial-exe:
    uv run --no-project --isolated --python 3.12 --with angr \
      python scripts/angr_trial.py \
      --binary {{game_dir}}/crimsonland.exe \
      --ghidra-functions analysis/ghidra/raw/crimsonland.exe_functions.json

angr-trial-grim:
    uv run --no-project --isolated --python 3.12 --with angr \
      python scripts/angr_trial.py \
      --binary {{game_dir}}/grim.dll \
      --ghidra-functions analysis/ghidra/raw/grim.dll_functions.json

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
    cd rewrite && zig build

zig-run:
    cd rewrite && zig build run

# WinDbg
[windows]
windbg-server:
    cdb -server tcp:port=5005,password=secret -logo C:\Crimsonland\windbg.log -pn crimsonland.exe -noio

[windows]
windbg-client:
    cdb -remote tcp:server=127.0.0.1,port=5005,password=secret -bonc

[windows]
windbg-tail:
    uv run scripts/windbg_tail.py

# Frida
[windows]
frida-attach script="scripts\\frida\\crimsonland_probe.js" process="crimsonland.exe":
    $env:CRIMSON_FRIDA_DIR = if ($env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR } else { "C:\share\frida" }
    New-Item -ItemType Directory -Force -Path $env:CRIMSON_FRIDA_DIR | Out-Null
    frida -n {{process}} -l {{script}}

[windows]
frida-unlock-secrets:
    frida -n crimsonland.exe -l scripts\\frida\\unlock_secrets.js

[windows]
frida-quest-spanking-count:
    frida -n crimsonland.exe -l scripts\\frida\\quest_spanking_count.js

[windows]
frida-quest-build-dump:
    frida -n crimsonland.exe -l scripts\\frida\\quest_build_dump.js

[windows]
frida-demo-trial-overlay process="crimsonland.exe" addrs="" link_base="" module="":
    $env:CRIMSON_FRIDA_DIR = if ($env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR } else { "C:\share\frida" }
    if ("{{addrs}}" -ne "") { $env:CRIMSON_FRIDA_ADDRS = "{{addrs}}" } else { Remove-Item Env:CRIMSON_FRIDA_ADDRS -ErrorAction SilentlyContinue }
    if ("{{link_base}}" -ne "") { $env:CRIMSON_FRIDA_LINK_BASE = "{{link_base}}" } else { Remove-Item Env:CRIMSON_FRIDA_LINK_BASE -ErrorAction SilentlyContinue }
    if ("{{module}}" -ne "") { $env:CRIMSON_FRIDA_MODULE = "{{module}}" } else { Remove-Item Env:CRIMSON_FRIDA_MODULE -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force -Path $env:CRIMSON_FRIDA_DIR | Out-Null
    frida -n {{process}} -l scripts\\frida\\demo_trial_overlay_trace.js

[windows]
frida-demo-idle-threshold process="crimsonland.exe" addrs="" link_base="" module="":
    $env:CRIMSON_FRIDA_DIR = if ($env:CRIMSON_FRIDA_DIR) { $env:CRIMSON_FRIDA_DIR } else { "C:\share\frida" }
    if ("{{addrs}}" -ne "") { $env:CRIMSON_FRIDA_ADDRS = "{{addrs}}" } else { Remove-Item Env:CRIMSON_FRIDA_ADDRS -ErrorAction SilentlyContinue }
    if ("{{link_base}}" -ne "") { $env:CRIMSON_FRIDA_LINK_BASE = "{{link_base}}" } else { Remove-Item Env:CRIMSON_FRIDA_LINK_BASE -ErrorAction SilentlyContinue }
    if ("{{module}}" -ne "") { $env:CRIMSON_FRIDA_MODULE = "{{module}}" } else { Remove-Item Env:CRIMSON_FRIDA_MODULE -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force -Path $env:CRIMSON_FRIDA_DIR | Out-Null
    frida -n {{process}} -l scripts\\frida\\demo_idle_threshold_trace.js

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
frida-sync-share:
    mkdir -p {{share_dir}}
    cp -av scripts/frida/*.js scripts/frida/*.json {{share_dir}}/

[unix]
frida-import-raw:
    mkdir -p analysis/frida/raw
    for f in grim_hits.jsonl crimsonland_frida_hits.jsonl demo_trial_overlay_trace.jsonl demo_idle_threshold_trace.jsonl; do \
        [ -e "{{share_dir}}/$f" ] || continue; \
        cp -av "{{share_dir}}/$f" analysis/frida/raw/; \
    done

[unix]
frida-reduce:
    uv run scripts/frida_reduce.py \
      --log analysis/frida/raw/grim_hits.jsonl \
      --log analysis/frida/raw/crimsonland_frida_hits.jsonl \
      --log analysis/frida/raw/demo_trial_overlay_trace.jsonl \
      --log analysis/frida/raw/demo_idle_threshold_trace.jsonl \
      --out-dir analysis/frida

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
