import hashlib,json,pathlib,shutil,subprocess,sys
assert __debug__
W=pathlib.Path(__file__).resolve().parent
subprocess.run([sys.executable,'-E','-s','-B',str(W/'qualify-shape.py')],check=True)
D=(W/'../../results/pq-public-bind-shape-v1').resolve();D.mkdir(exist_ok=False)
files=[p for name in ['src','tests','evidence'] for p in (W/name).rglob('*') if p.is_file()]
files += [p for p in W.iterdir() if p.is_file() and p.suffix in ['.rs','.toml','.lock','.json','.txt','.py','.sh']]
for p in sorted(set(files)):
    if p.name=='freeze.stdout':continue
    relative=p.relative_to(W)
    if relative==pathlib.Path('README.txt'):relative=pathlib.Path('SOURCE-DRAFT-README.txt')
    dest=D/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
(D/'README.txt').write_text('Native shape experiment complete; proof generation/verification benchmarks pending.\nRead REPORT.txt and evidence/shape-01/summary.json for scope and measurements.\nqualify-shape.py rechecks the retained evidence using pinned local dependencies.\nSOURCE-DRAFT-README.txt is the original pre-measurement source note.\nReproduce from the original work/pq-public-bind-liveness-v1 checkout with a fresh label.\nNo production readiness or security equivalence claim.\n')
pins={str(p.relative_to(D)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(D.rglob('*')) if p.is_file()}
(D/'MANIFEST.json').write_text(json.dumps(dict(schema='zk9-frozen-results-v1',milestone='pq-public-bind-shape-v1',sha256=pins,
    proof_benchmark=False,security_equivalence_proven=False,production_ready=False),indent=2)+'\n')
subprocess.run([sys.executable,'-E','-s','-B',str(D/'qualify-shape.py')],check=True)
print(json.dumps(dict(files=len(pins),manifest_sha256=hashlib.sha256((D/'MANIFEST.json').read_bytes()).hexdigest()),indent=2))
