set shell := ["bash", "-uc"]

version := "1.9.93-gog"
game_dir := "game_bins/crimsonland/" + version
assets_dir := "artifacts/assets"
atlas_usage := "artifacts/atlas/atlas_usage.json"
atlas_frames := "artifacts/atlas/frames"

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

# Analysis
entrypoint-trace:
    uv run python scripts/entrypoint_trace.py --depth 2 --skip-external

function-hotspots:
    uv run python scripts/function_hotspots.py --top 12 --only-fun

save-status *args:
    uv run python scripts/save_status.py {{args}}

weapon-table:
    uv run python scripts/extract_weapon_table.py

spawn-templates:
    uv run python scripts/gen_spawn_templates.py

# Ghidra
ghidra-exe:
    ./analysis/ghidra/tooling/ghidra-analyze.sh \
      --script-path analysis/ghidra/scripts \
      -s ImportThirdPartyHeaders.java -a third_party/headers \
      -s ApplyWinapiGDT.java -a analysis/ghidra/maps/winapi_32.gdt \
      -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
      -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
      -s ExportAll.java \
      -o analysis/ghidra/raw \
      {{game_dir}}/crimsonland.exe

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
