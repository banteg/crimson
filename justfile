set shell := ["bash", "-uc"]
set windows-shell := ["powershell", "-NoLogo", "-Command"]

version := "1.9.93-gog"
game_dir := "game_bins/crimsonland/" + version
assets_dir := "artifacts/assets"
atlas_usage := "analysis/reference/atlas_usage.json"
atlas_frames := "artifacts/atlas/frames"

default:
    @just --list

# Tests
test *args:
    uv run pytest {{args}}

check *args:
    uv run ruff check .
    uv run ty check src crimson-re/src tests
    uv run scripts/check_docs.py
    uv run crimson match resolved-name-audit --check
    uv run crimson native verify --require-game-closure --allow-absent-toolchain
    uv run crimson match regressions
    ast-grep scan
    ast-grep test
    uv run pytest {{args}}

check-zig:
    cd crimson-zig && zig build test --summary all
    cd crimson-zig && zig build -Doptimize=ReleaseFast
    cd crimson-zig && zig build wasm

ty:
    uv run ty check src crimson-re/src tests

# Assets
extract:
    uv run crimson extract {{game_dir}} {{assets_dir}}

# Atlas
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
analysis-function query program="crimsonland.exe":
    uv run scripts/analysis_view.py show "{{query}}" --program "{{program}}"

analysis-check program="crimsonland.exe" binja_live="false":
    uv run scripts/analysis_view.py check --program "{{program}}" {{ if binja_live == "true" { "--binja-live" } else { "" } }}

match-checkpoint *args:
    uv run crimson match checkpoint -j 8 {{args}}

match-shard workers="4" *args:
    uv run crimson match shard --workers {{workers}} {{args}}

match-worker-check claim *args:
    uv run crimson match worker-check "{{claim}}" {{args}}

binja-sync program="crimsonland.exe":
    bn py exec --target "{{program}}.bndb" --script scripts/binja_import_maps.py --format text --no-spill

fetch-compilers *args:
    uv run scripts/fetch_compilers.py {{args}}

binja-sync-c2:
    bn py exec --target C2.DLL.bndb --script scripts/binja_c2_apply.py --format text --no-spill

# IDA (macOS)
[macos]
ida-export-exe:
    ./analysis/ida/tooling/ida-export.sh {{game_dir}}/crimsonland.exe analysis/ida/raw/crimsonland.exe

[macos]
ida-rebuild-exe:
    ./analysis/ida/tooling/ida-export.sh --rebuild {{game_dir}}/crimsonland.exe analysis/ida/raw/crimsonland.exe

[macos]
ida-export-grim:
    ./analysis/ida/tooling/ida-export.sh {{game_dir}}/grim.dll analysis/ida/raw/grim.dll

[macos]
ida-rebuild-grim:
    ./analysis/ida/tooling/ida-export.sh --rebuild {{game_dir}}/grim.dll analysis/ida/raw/grim.dll

native-audit image="grim.dll" *args:
    uv run crimson native audit --image "{{image}}" --out-dir "analysis/native/{{image}}" {{args}}

native-link image="grim.dll" *args:
    uv run crimson native link --image "{{image}}" --out-dir "analysis/native/{{image}}/link" {{args}}

native-verify *args:
    uv run crimson native verify {{args}}

schema-inventory *args:
    uv run scripts/schema_inventory.py {{args}}

save-status *args:
    uv run scripts/save_status.py {{args}}

spawn-templates:
    uv run scripts/gen_spawn_templates.py

# Ghidra
[unix]
ghidra-exe:
    ./analysis/ghidra/tooling/ghidra-analyze.sh \
      --persistent \
      --project-dir analysis/ghidra/projects \
      --project-name crimsonland_exe \
      --script-path analysis/ghidra/scripts \
      -s ImportThirdPartyHeaders.java -a third_party/headers \
      -s ApplyWinapiGDT.java -a analysis/ghidra/maps/winapi_32.gdt \
      -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
      -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
      -s FinalizeAnalysis.java \
      -s ExportAll.java \
      -o analysis/ghidra/raw \
      {{game_dir}}/crimsonland.exe

[unix]
ghidra-rebuild-exe:
    ./analysis/ghidra/tooling/ghidra-analyze.sh \
      --rebuild \
      --project-dir analysis/ghidra/projects \
      --project-name crimsonland_exe \
      --script-path analysis/ghidra/scripts \
      -s ImportThirdPartyHeaders.java -a third_party/headers \
      -s ApplyWinapiGDT.java -a analysis/ghidra/maps/winapi_32.gdt \
      -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
      -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
      -s FinalizeAnalysis.java \
      -s ExportAll.java \
      -o analysis/ghidra/raw \
      {{game_dir}}/crimsonland.exe

[unix]
ghidra-grim:
    ./analysis/ghidra/tooling/ghidra-analyze.sh \
      --persistent \
      --project-dir analysis/ghidra/projects \
      --project-name grim_dll \
      --script-path analysis/ghidra/scripts \
      -s ImportThirdPartyHeaders.java -a third_party/headers \
      -s ApplyWinapiGDT.java -a analysis/ghidra/maps/winapi_32.gdt \
      -s CreateGrim2DVtableFunctions.java \
      -s CreateConfigDialogProc.java \
      -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
      -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
      -s FinalizeAnalysis.java \
      -s ExportAll.java \
      -o analysis/ghidra/raw \
      {{game_dir}}/grim.dll

[unix]
ghidra-rebuild-grim:
    ./analysis/ghidra/tooling/ghidra-analyze.sh \
      --rebuild \
      --project-dir analysis/ghidra/projects \
      --project-name grim_dll \
      --script-path analysis/ghidra/scripts \
      -s ImportThirdPartyHeaders.java -a third_party/headers \
      -s ApplyWinapiGDT.java -a analysis/ghidra/maps/winapi_32.gdt \
      -s CreateGrim2DVtableFunctions.java \
      -s CreateConfigDialogProc.java \
      -s ApplyNameMap.java -a analysis/ghidra/maps/name_map.json \
      -s ApplyDataMap.java -a analysis/ghidra/maps/data_map.json \
      -s FinalizeAnalysis.java \
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

[windows]
ghidra-sync:
    wsl -e bash -lc "cd ~/dev/crimson && just ghidra-sync"

# Screenshots
[windows]
game-screenshot:
    nircmd win activate process crimsonland.exe
    sleep 1
    nircmd savescreenshotwin "screenshots\\screen.png"
