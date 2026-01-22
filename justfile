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

# Assets
extract:
    uv run paq extract {{game_dir}} {{assets_dir}}

# Atlas
atlas-scan:
    uv run python scripts/atlas_scan.py --output-json {{atlas_usage}}

atlas-export-all:
    uv run python scripts/atlas_export.py --all --usage-json {{atlas_usage}} --out-root {{atlas_frames}}

atlas-export image grid:
    uv run python scripts/atlas_export.py --image {{image}} --grid {{grid}}

# Fonts
font-sample:
    uv run paq font --assets-dir {{assets_dir}} --out artifacts/fonts/small_font_sample.png

# Docs
docs-all-pages:
    uv run python scripts/gen_all_pages.py

docs-map-progress:
    uv run python scripts/update_map_progress_docs.py

docs-build:
    uv run zensical build

docs-zensical-fix:
    uv run python scripts/zensical_fix_md.py docs

# Analysis
entrypoint-trace:
    uv run python scripts/entrypoint_trace.py --depth 2 --skip-external

function-hotspots:
    uv run python scripts/function_hotspots.py --top 12 --only-fun

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
    uv run python scripts/save_status.py {{args}}

weapon-table:
    uv run python scripts/extract_weapon_table.py

spawn-templates:
    uv run python scripts/gen_spawn_templates.py

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
    uv run python scripts/windbg_tail.py

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
    for f in {{share_dir}}/*.jsonl; do \
        [ -e "$f" ] || continue; \
        cp -v "$f" {{frida_share_dir}}/; \
    done

# Screenshots
[windows]
game-screenshot:
    nircmd win activate process crimsonland.exe
    sleep 1
    nircmd savescreenshotwin "screenshots\\screen.png"

zip-decompile:
    zip -r crimson.zip analysis/ghidra/raw/*.c analysis/binary_ninja/*.txt analysis/ida/raw/*/*.c scripts src docs
    open -R crimson.zip
