"""Record compiler and local dependency source pins without modifying them."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
metadata = json.loads((root/'evidence/cargo-metadata.json').read_text())
sources = {}
def add(p):
    if p.is_file():
        sources[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
for package in metadata['packages']:
    if package['source'] is not None:
        continue  # Registry checksums are pinned by Cargo.lock.
    manifest = Path(package['manifest_path'])
    directory = manifest.parent
    add(manifest)
    add(directory/'build.rs')
    add(directory/'Cargo.lock')
    for p in sorted((directory/'src').rglob('*')):
        add(p)
    for parent in directory.parents:
        if parent == root.parent:
            break
        add(parent/'Cargo.toml')
        add(parent/'Cargo.lock')
tools = root.parent/'gloas-native-integration-v1/native/.toolchain/rust/bin'
record = dict(
    compiler=subprocess.check_output([str(tools/'rustc'), '-vV'], text=True),
    cargo=subprocess.check_output([str(tools/'cargo'), '-V'], text=True),
    rustc_sha256=hashlib.sha256((tools/'rustc').read_bytes()).hexdigest(),
    features=metadata['resolve']['nodes'],
    local_source_pins=sources,
    cargo_lock_sha256=hashlib.sha256((root/'Cargo.lock').read_bytes()).hexdigest(),
    build='cargo build --release --offline --locked --lib --bin qualify',
    scope='Local src trees, manifests and build.rs; registry checksums in Cargo.lock. Requires the existing pinned parent workspaces.',
)
target=root/'evidence'/sys.argv[1]
with target.open('x') as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps({'local_source_files':len(sources),'record':str(target)}))
