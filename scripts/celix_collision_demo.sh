#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/conan-assurance-celix-collision"
CONAN_HOME="$WORK/conan-home"

rm -rf "$WORK"
mkdir -p "$WORK/bundles" "$CONAN_HOME/extensions/commands"
cp "$ROOT/extensions/commands/cmd_assurance.py" "$CONAN_HOME/extensions/commands/"
export CONAN_HOME

cat > "$WORK/a.c" <<'C'
int celix_collision_value(void) { return 1; }
C

cat > "$WORK/b.c" <<'C'
int celix_collision_value(void) { return 2; }
C

cc -shared -fPIC -Wl,-soname,libcollision.so.1 -o "$WORK/libcollision-a.so" "$WORK/a.c"
cc -shared -fPIC -Wl,-soname,libcollision.so.1 -o "$WORK/libcollision-b.so" "$WORK/b.c"

python3 - "$WORK" <<'PY'
import json
import pathlib
import sys
import zipfile

root = pathlib.Path(sys.argv[1])
bundles = root / "bundles"

def write_bundle(name, symbolic, library):
    manifest = {
        "CELIX_BUNDLE_SYMBOLIC_NAME": symbolic,
        "CELIX_BUNDLE_VERSION": "version<1.0.0>",
        "CELIX_BUNDLE_MANIFEST_VERSION": "version<2.0.0>",
        "CELIX_BUNDLE_PRIVATE_LIBRARIES": ["libcollision.so.1"],
    }
    with zipfile.ZipFile(bundles / name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "META-INF/MANIFEST.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        )
        archive.write(library, "libcollision.so.1")

write_bundle("collision_a.zip", "collision.a", root / "libcollision-a.so")
write_bundle("collision_b.zip", "collision.b", root / "libcollision-b.so")

(root / "main.cc").write_text(
    """#define CELIX_MULTI_LINE_STRING(...) #__VA_ARGS__
const char *config = CELIX_MULTI_LINE_STRING(
{
  "CELIX_BUNDLES_PATH":"bundles",
  "CELIX_AUTO_START_1":"collision_a.zip,collision_b.zip",
  "CELIX_CONTAINER_NAME":"CollisionContainer"
});
""",
    encoding="utf-8",
)
PY

set +e
conan assurance \
  --celix-only \
  --celix-bundle-dir="$WORK/bundles" \
  --celix-container-config="$WORK/main.cc" \
  --report="$WORK/evidence.ndjson" \
  --receipt="$WORK/receipt.json" \
  --celix-provenance="$WORK/celix-provenance.json" \
  --fail-on-failure \
  >/dev/null 2>"$WORK/stderr.log"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
    echo "expected SONAME collision policy failure" >&2
    exit 1
fi

python3 - "$WORK/evidence.ndjson" <<'PY'
import json
import sys

rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
collision = [
    row for row in rows
    if row["check"] == "celix-runtime-library-collision"
]
assert len(collision) == 1, collision
item = collision[0]
assert item["status"] == "FAIL", item
assert "1 divergent ELF SONAME collision" in item["summary"], item
locations = "\n".join(item["locations"])
assert "libcollision.so.1" in locations, item
assert "celix-bundle:collision.a@1.0.0" in locations, item
assert "celix-bundle:collision.b@1.0.0" in locations, item

print(item["summary"])
print("policy_exit=1")
PY
