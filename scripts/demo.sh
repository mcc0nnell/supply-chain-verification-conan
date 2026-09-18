#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONAN_HOME="${CONAN_HOME:-$ROOT/.demo-conan-home}"
rm -rf "$CONAN_HOME"
mkdir -p "$CONAN_HOME/extensions/commands"
cp "$ROOT/extensions/commands/cmd_assurance.py" "$CONAN_HOME/extensions/commands/"

export CONAN_HOME
mkdir -p "$CONAN_HOME/profiles"
cat > "$CONAN_HOME/profiles/default" <<'PROFILE'
[settings]
os=Linux
arch=x86_64
build_type=Release
compiler=gcc
compiler.version=13
compiler.libcxx=libstdc++11
compiler.cppstd=gnu17
PROFILE

mkdir -p "$ROOT/demo"
conan assurance \
  --requires=zlib/1.3.1 \
  -r=conancenter \
  --materialize-packages \
  --verify-source-bytes \
  --verify-package-bytes \
  --report="$ROOT/demo/assurance.ndjson" \
  --receipt="$ROOT/demo/receipt.json" \
  --format=json > "$ROOT/demo/assurance.json"

python3 - "$ROOT/demo/assurance.json" "$ROOT/demo/receipt.json" <<'PY'
import json
import sys

path = sys.argv[1]
receipt_path = sys.argv[2]
data = json.load(open(path, encoding="utf-8"))
receipt = json.load(open(receipt_path, encoding="utf-8"))
items = data["evidence"]

def find(check):
    for item in items:
        if item["reference"] == "zlib/1.3.1" and item["check"] == check:
            return item
    raise SystemExit(f"missing zlib evidence for {check}")

revision = find("recipe-revision")
digest = find("source-digest")
source_bytes = find("source-artifact-bytes")
package_bytes = find("package-bytes")
scorecard = find("openssf-scorecard")

assert revision["status"] == "PASS", revision
assert digest["status"] == "PASS", digest
assert source_bytes["status"] == "PASS", source_bytes
assert package_bytes["status"] == "PASS", package_bytes
assert scorecard["status"] == "PASS", scorecard
assert any(
    "github.com/madler/zlib" in value for value in scorecard["locations"]
), scorecard

package = receipt["packages"][0]
assert package["reference"] == "zlib/1.3.1", package
assert package["recipe_revision"], package
assert package["package_id"], package
assert package["package_revision"], package
assert package["source_artifact_sha256"], package
assert package["package_tree_sha256"], package
assert len(receipt["graph_sha256"]) == 64, receipt
assert len(receipt["evidence_sha256"]) == 64, receipt

print(
    f"packages={data['packages']} observations={data['observations']} "
    f"pass={data['counts']['PASS']} fail={data['counts']['FAIL']} "
    f"unknown={data['counts']['UNKNOWN']}"
)
print(scorecard["summary"])
PY
