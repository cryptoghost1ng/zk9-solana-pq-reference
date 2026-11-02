"""Freeze the compiler, resolved local inputs and candidate code for shape checks."""
import hashlib,json,pathlib,re,subprocess,sys
assert __debug__
W=pathlib.Path(__file__).resolve().parent
label,phase=sys.argv[1:]
assert re.fullmatch(r'shape-[0-9]{2}',label) and phase in ['before','after']
R=W/'evidence'/label
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
metadata=json.loads((R/'metadata.json').read_text())
sources={}
def add(p):
    if p.is_file():sources[str(p.resolve())]=sha(p)
for package in metadata['packages']:
    if package['source'] is not None:continue
    manifest=pathlib.Path(package['manifest_path']);directory=manifest.parent
    add(manifest);add(directory/'build.rs');add(directory/'Cargo.lock')
    for p in sorted((directory/'src').rglob('*')):add(p)
    for parent in directory.parents:
        if parent==W.parent:break
        add(parent/'Cargo.toml');add(parent/'Cargo.lock')
for p in sorted((W/'tests').rglob('*')):add(p)
for p in W.iterdir():
    if p.suffix in ['.py','.sh','.txt','.json']:add(p)
tools=W.parent/'gloas-native-integration-v1/native/.toolchain/rust/bin'
record=dict(source_pins=sources,
    compiler=subprocess.check_output([str(tools/'rustc'),'-vV'],text=True),
    cargo=subprocess.check_output([str(tools/'cargo'),'-V'],text=True),
    compiler_sha256=sha(tools/'rustc'),cargo_sha256=sha(tools/'cargo'),
    features=metadata['resolve']['nodes'],cargo_lock_sha256=sha(W/'Cargo.lock'),
    parent=json.loads((R/'baseline.json').read_text()),
    build_flags=['--release','--offline','--locked'],proof_generated=False)
if phase=='after':assert record==json.loads((R/'environment-before.json').read_text()),'Inputs changed during candidate checks'
with (R/f'environment-{phase}.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(status='PASS_INPUT_CAPTURE',phase=phase,source_files=len(sources))))
