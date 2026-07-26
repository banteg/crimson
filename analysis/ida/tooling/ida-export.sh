#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ida-export.sh [options] <binary> <output-dir>

Options:
  --rebuild              Create a clean database, backing up the current one.
  --database-dir <dir>   Persistent database directory
                         (default: analysis/ida/databases).

Environment:
  IDA_BIN  Path to the headless IDA executable.
  IDAUSR   Source IDA user directory. Its accepted ida.reg is copied into
           isolated temporary state for the headless run.
  IDA_VERSION
           Override the IDA version recorded in database provenance.
EOF
}

rebuild=false
database_dir=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rebuild)
            rebuild=true
            shift
            ;;
        --database-dir)
            database_dir="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -ne 2 ]]; then
    usage >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
binary="$1"
output_dir="$2"
ida_bin="${IDA_BIN:-/Applications/IDA Professional 9.4.app/Contents/MacOS/idat}"
python_bin="${PYTHON_BIN:-python3}"

if [[ "$binary" != /* ]]; then
    binary="$repo_root/$binary"
fi
if [[ "$output_dir" != /* ]]; then
    output_dir="$repo_root/$output_dir"
fi
if [[ -z "$database_dir" ]]; then
    database_dir="$repo_root/analysis/ida/databases"
elif [[ "$database_dir" != /* ]]; then
    database_dir="$repo_root/$database_dir"
fi
metadata_binary="$binary"
if [[ "$binary" == "$repo_root/"* ]]; then
    metadata_binary="${binary#"$repo_root"/}"
fi

if [[ ! -f "$binary" ]]; then
    echo "Binary not found: $binary" >&2
    exit 1
fi
if [[ ! -x "$ida_bin" ]]; then
    echo "Headless IDA not found: $ida_bin" >&2
    exit 1
fi
if ! command -v "$python_bin" >/dev/null 2>&1; then
    echo "Python interpreter not found: $python_bin" >&2
    exit 1
fi

program_name="$(basename "$binary")"
database_path="$database_dir/$program_name.i64"
provenance_path="$database_path.provenance.json"
provenance_script="$repo_root/scripts/analysis_db_provenance.py"

ida_version="${IDA_VERSION:-}"
if [[ -z "$ida_version" ]]; then
    ida_contents_dir="$(cd "$(dirname "$ida_bin")/.." && pwd)"
    ida_info_plist="$ida_contents_dir/Info.plist"
    if [[ -f "$ida_info_plist" && -x /usr/libexec/PlistBuddy ]]; then
        ida_version=$(
            /usr/libexec/PlistBuddy \
                -c "Print :CFBundleShortVersionString" \
                "$ida_info_plist" 2>/dev/null || true
        )
    fi
fi
ida_version="${ida_version:-unknown}"

provenance_args=(
    --state "$provenance_path"
    --tool ida
    --tool-version "$ida_version"
    --tool-file "$ida_bin"
    --program "$program_name"
    --binary "$binary"
)

backup_database() {
    local timestamp backup_dir
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_dir="$database_dir/backups/$program_name-$timestamp-$$"
    mkdir -p "$backup_dir"
    if [[ -f "$database_path" ]]; then
        mv "$database_path" "$backup_dir/"
    fi
    if [[ -f "$provenance_path" ]]; then
        mv "$provenance_path" "$backup_dir/"
    fi
    echo "Backed up previous IDA database state to $backup_dir"
}

mkdir -p "$database_dir"
if [[ "$rebuild" == true ]] && [[ -f "$database_path" || -f "$provenance_path" ]]; then
    backup_database
fi

reuse_database=false
if [[ -f "$database_path" ]]; then
    if ! "$python_bin" "$provenance_script" check "${provenance_args[@]}"; then
        echo "Refusing to reuse $database_path." >&2
        echo "Run this command again with --rebuild for a clean database." >&2
        exit 1
    fi
    reuse_database=true
elif [[ -f "$provenance_path" ]]; then
    echo "IDA provenance exists without its database: $provenance_path" >&2
    echo "Run this command again with --rebuild to archive the orphaned state." >&2
    exit 1
fi

working_database="$database_dir/.$program_name.$$.i64"
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/crimson-ida.XXXXXX")"
cleanup() {
    rm -f -- "$working_database"
    rm -rf -- "$temp_dir"
}
trap cleanup EXIT

source_ida_user_dir="${IDAUSR:-$HOME/.idapro}"
source_ida_registry="$source_ida_user_dir/ida.reg"
if [[ ! -f "$source_ida_registry" ]]; then
    echo "IDA registry not found: $source_ida_registry" >&2
    echo "Launch IDA once and accept its license before running headlessly." >&2
    exit 1
fi

isolated_ida_user_dir="$temp_dir/ida-user"
mkdir -p "$isolated_ida_user_dir"
cp "$source_ida_registry" "$isolated_ida_user_dir/ida.reg"

mkdir -p "$output_dir"

script="$repo_root/scripts/ida_export.py"
name_map="$repo_root/analysis/ghidra/maps/name_map.json"
data_map="$repo_root/analysis/ghidra/maps/data_map.json"

if [[ "$reuse_database" == true ]]; then
    echo "Reusing persistent IDA database: $database_path"
    cp "$database_path" "$working_database"
    IDAUSR="$isolated_ida_user_dir" "$ida_bin" \
        -A \
        -L"$temp_dir/ida.log" \
        "-S$script $output_dir $name_map $data_map $metadata_binary" \
        "$working_database"
else
    echo "Creating persistent IDA database: $database_path"
    IDAUSR="$isolated_ida_user_dir" "$ida_bin" \
        -A \
        -c \
        "-o$working_database" \
        -L"$temp_dir/ida.log" \
        "-S$script $output_dir $name_map $data_map $metadata_binary" \
        "$binary"
fi

if [[ ! -f "$working_database" ]]; then
    echo "IDA completed without saving its working database: $working_database" >&2
    exit 1
fi
mv "$working_database" "$database_path"
"$python_bin" "$provenance_script" write "${provenance_args[@]}"
