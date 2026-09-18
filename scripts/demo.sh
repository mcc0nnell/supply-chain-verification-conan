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

rm -rf "$ROOT/demo"
mkdir -p "$ROOT/demo/celix/bundles"

cat > "$ROOT/demo/celix/demo_activator.c" <<'C'
typedef struct celix_bundle_context celix_bundle_context_t;

int celix_bundleActivator_create(
    celix_bundle_context_t* ctx,
    void** user_data
) {
    (void)ctx;
    *user_data = 0;
    return 0;
}

int celix_bundleActivator_start(
    void* user_data,
    celix_bundle_context_t* ctx
) {
    (void)user_data;
    (void)ctx;
    return 0;
}

int celix_bundleActivator_stop(
    void* user_data,
    celix_bundle_context_t* ctx
) {
    (void)user_data;
    (void)ctx;
    return 0;
}

int celix_bundleActivator_destroy(
    void* user_data,
    celix_bundle_context_t* ctx
) {
    (void)user_data;
    (void)ctx;
    return 0;
}
C

cc -shared -fPIC \
  -Wl,-soname,libdemo_activator.so \
  -o "$ROOT/demo/celix/libdemo_activator.so" \
  "$ROOT/demo/celix/demo_activator.c"

python3 - "$ROOT/demo/celix" <<'PY'
import json
import pathlib
import sys
import zipfile

root = pathlib.Path(sys.argv[1])
bundles = root / "bundles"

def write_bundle(path, manifest, files):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "META-INF/MANIFEST.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        )
        for name, source in files:
            archive.write(source, name)

write_bundle(
    bundles / "demo_service.zip",
    {
        "CELIX_BUNDLE_SYMBOLIC_NAME": "demo.service",
        "CELIX_BUNDLE_VERSION": "version<1.0.0>",
        "CELIX_BUNDLE_NAME": "Demo Service",
        "CELIX_BUNDLE_ACTIVATOR_LIBRARY": "libdemo_activator.so",
        "CELIX_BUNDLE_MANIFEST_VERSION": "version<2.0.0>",
    },
    [("libdemo_activator.so", root / "libdemo_activator.so")],
)

with zipfile.ZipFile(
    bundles / "demo_config.zip",
    "w",
    compression=zipfile.ZIP_DEFLATED,
) as archive:
    archive.writestr(
        "META-INF/MANIFEST.json",
        json.dumps(
            {
                "CELIX_BUNDLE_SYMBOLIC_NAME": "demo.config",
                "CELIX_BUNDLE_VERSION": "version<1.0.0>",
                "CELIX_BUNDLE_NAME": "Demo Config",
                "CELIX_BUNDLE_MANIFEST_VERSION": "version<2.0.0>",
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    archive.writestr("config/demo.json", '{"enabled":true}\n')

(root / "config.properties").write_text(
    "CELIX_BUNDLES_PATH=bundles\n"
    "CELIX_AUTO_START_1=demo_service.zip\n"
    "CELIX_AUTO_START_3=demo_config.zip\n",
    encoding="utf-8",
)
PY

conan assurance \
  --requires=zlib/1.3.1 \
  -r=conancenter \
  --rebuild-package=zlib/1.3.1 \
  --rebuild-count=2 \
  --celix-bundle-dir="$ROOT/demo/celix/bundles" \
  --celix-container-config="$ROOT/demo/celix/config.properties" \
  --report="$ROOT/demo/assurance.ndjson" \
  --receipt="$ROOT/demo/receipt.json" \
  --provenance="$ROOT/demo/provenance.json" \
  --celix-provenance="$ROOT/demo/celix-provenance.json" \
  --format=json > "$ROOT/demo/assurance.json"

conan assurance \
  --celix-only \
  --celix-bundle-dir="$ROOT/demo/celix/bundles" \
  --celix-container-config="$ROOT/demo/celix/config.properties" \
  --receipt="$ROOT/demo/celix-only-receipt.json" \
  --celix-provenance="$ROOT/demo/celix-only-provenance.json" \
  --format=json > "$ROOT/demo/celix-only.json"

python3 - \
  "$ROOT/demo/assurance.json" \
  "$ROOT/demo/receipt.json" \
  "$ROOT/demo/provenance.json" \
  "$ROOT/demo/celix-provenance.json" \
  "$ROOT/demo/celix-only.json" \
  "$ROOT/demo/celix-only-receipt.json" \
  "$ROOT/demo/celix-only-provenance.json" <<'PY'
import json
import sys

path = sys.argv[1]
receipt_path = sys.argv[2]
provenance_path = sys.argv[3]
celix_provenance_path = sys.argv[4]
celix_only_path = sys.argv[5]
celix_only_receipt_path = sys.argv[6]
celix_only_provenance_path = sys.argv[7]
data = json.load(open(path, encoding="utf-8"))
receipt = json.load(open(receipt_path, encoding="utf-8"))
provenance = json.load(open(provenance_path, encoding="utf-8"))
celix_provenance = json.load(open(celix_provenance_path, encoding="utf-8"))
celix_only = json.load(open(celix_only_path, encoding="utf-8"))
celix_only_receipt = json.load(open(celix_only_receipt_path, encoding="utf-8"))
celix_only_provenance = json.load(open(celix_only_provenance_path, encoding="utf-8"))
items = data["evidence"]

def find(check):
    for item in items:
        if item["reference"] == "zlib/1.3.1" and item["check"] == check:
            return item
    raise SystemExit(f"missing zlib evidence for {check}")

def find_subject(reference, check):
    for item in items:
        if item["reference"] == reference and item["check"] == check:
            return item
    raise SystemExit(f"missing evidence for {reference} / {check}")

revision = find("recipe-revision")
digest = find("source-digest")
source_bytes = find("source-artifact-bytes")
package_bytes = find("package-bytes")
repeatability = find("rebuild-repeatability")
reproduction = find("consumed-binary-reproduction")
scorecard = find("openssf-scorecard")

assert revision["status"] == "PASS", revision
assert digest["status"] == "PASS", digest
assert source_bytes["status"] == "PASS", source_bytes
assert package_bytes["status"] == "PASS", package_bytes
assert repeatability["status"] == "PASS", repeatability
assert reproduction["status"] in ("PASS", "FAIL"), reproduction
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
assert package["package_payload_sha256"], package
assert len(receipt["graph_sha256"]) == 64, receipt
assert len(receipt["evidence_sha256"]) == 64, receipt

service_ref = "celix-bundle:demo.service@1.0.0"
config_ref = "celix-bundle:demo.config@1.0.0"
for reference in (service_ref, config_ref):
    for check in (
        "celix-archive-layout",
        "celix-manifest",
        "celix-library-closure",
        "celix-bundle-content",
    ):
        assert find_subject(reference, check)["status"] == "PASS", (reference, check)

container = next(
    item for item in items
    if item["check"] == "celix-container-composition"
)
collision = next(
    item for item in items
    if item["check"] == "celix-runtime-library-collision"
)
assert container["status"] == "PASS", container
assert collision["status"] == "PASS", collision
assert data["packages"] == 1, data
assert data["celix_bundles"] == 2, data
assert data["celix_containers"] == 1, data
assert data["subjects"] == 4, data

assert receipt["schema"].endswith("/v2"), receipt
assert len(receipt["subject_sha256"]) == 64, receipt
assert len(receipt["celix_subject_sha256"]) == 64, receipt
assert len(receipt["celix_bundles"]) == 2, receipt
assert len(receipt["celix_containers"]) == 1, receipt

service = next(
    bundle for bundle in receipt["celix_bundles"]
    if bundle["reference"] == service_ref
)
assert service["activator"] == "libdemo_activator.so", service
assert len(service["bundle_content_sha256"]) == 64, service
assert len(service["archive_sha256"]) == 64, service
assert len(service["manifest_sha256"]) == 64, service

composition = receipt["celix_containers"][0]
assert len(composition["composition_sha256"]) == 64, composition
assert composition["bundles"][0]["bundle"] == service_ref, composition
assert composition["bundles"][0]["level"] == 1, composition
assert composition["bundles"][1]["bundle"] == config_ref, composition
assert composition["bundles"][1]["level"] == 3, composition

assert celix_provenance["schema"].endswith("/celix-runtime/v1"), celix_provenance
assert celix_provenance["subject_sha256"] == receipt["celix_subject_sha256"], (
    celix_provenance,
    receipt,
)
assert len(celix_provenance["subject_sha256"]) == 64, celix_provenance
assert len(celix_provenance["bundle_set_sha256"]) == 64, celix_provenance
assert len(celix_provenance["container_set_sha256"]) == 64, celix_provenance
assert len(celix_provenance["bundles"]) == 2, celix_provenance
assert len(celix_provenance["containers"]) == 1, celix_provenance

assert celix_only["packages"] == 0, celix_only
assert celix_only["celix_bundles"] == 2, celix_only
assert celix_only["celix_containers"] == 1, celix_only
assert celix_only["counts"]["FAIL"] == 0, celix_only
assert celix_only["counts"]["UNKNOWN"] == 0, celix_only
assert (
    celix_only_receipt["celix_subject_sha256"]
    == receipt["celix_subject_sha256"]
), (celix_only_receipt, receipt)
assert (
    celix_only_provenance["subject_sha256"]
    == celix_provenance["subject_sha256"]
), (celix_only_provenance, celix_provenance)

rebuild = provenance["rebuilds"][0]
assert rebuild["reference"] == "zlib/1.3.1", rebuild
assert rebuild["repeatable"] is True, rebuild
assert len(set(rebuild["rebuild_payload_sha256"])) == 1, rebuild
assert len(rebuild["rebuild_payload_sha256"]) == 2, rebuild
assert len(rebuild["consumed_payload_sha256"]) == 64, rebuild

print(
    f"packages={data['packages']} observations={data['observations']} "
    f"pass={data['counts']['PASS']} fail={data['counts']['FAIL']} "
    f"unknown={data['counts']['UNKNOWN']}"
)
print(scorecard["summary"])
print(repeatability["summary"])
print(reproduction["summary"])
print("consumed payload:", rebuild["consumed_payload_sha256"])
print("clean rebuild payload:", rebuild["rebuild_payload_sha256"][0])
print("Celix subject:", receipt["celix_subject_sha256"])
print("Celix service content:", service["bundle_content_sha256"])
print("Celix composition:", composition["composition_sha256"])
PY
