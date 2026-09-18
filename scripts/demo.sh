#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONAN_HOME="${CONAN_HOME:-$ROOT/.demo-conan-home}"
rm -rf "$CONAN_HOME"
mkdir -p "$CONAN_HOME/extensions/commands"
cp "$ROOT/extensions/commands/cmd_assurance.py" "$CONAN_HOME/extensions/commands/"

export CONAN_HOME
conan profile detect --force >/dev/null

mkdir -p "$ROOT/demo"
conan assurance \
  --requires=zlib/1.3.1 \
  -r=conancenter \
  --report="$ROOT/demo/assurance.ndjson" \
  --format=json > "$ROOT/demo/assurance.json"

python3 - "$ROOT/demo/assurance.json" <<'PY'
import json
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
items = data["evidence"]

def find(check):
    for item in items:
        if item["reference"] == "zlib/1.3.1" and item["check"] == check:
            return item
    raise SystemExit(f"missing zlib evidence for {check}")

revision = find("recipe-revision")
digest = find("source-digest")
scorecard = find("openssf-scorecard")

assert revision["status"] == "PASS", revision
assert digest["status"] == "PASS", digest
assert scorecard["status"] == "PASS", scorecard
assert any(
    "github.com/madler/zlib" in value for value in scorecard["locations"]
), scorecard

print(
    f"packages={data['packages']} observations={data['observations']} "
    f"pass={data['counts']['PASS']} fail={data['counts']['FAIL']} "
    f"unknown={data['counts']['UNKNOWN']}"
)
print(scorecard["summary"])
PY
