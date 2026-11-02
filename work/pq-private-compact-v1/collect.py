"""Verify parent pins and complete measurements before freezing a new candidate."""
import json
import shutil
import statistics
import subprocess
import sys
from pathlib import Path
w=Path(__file__).resolve().parent;r=w.parents[1]
sys.path.insert(0,str(r/'work/private-rpc-product-v1/source-kit'))
from common import sha,read,save,freeze,verify
d=r/'results/pq-private-compact-v1';assert not d.exists()
parent=r/'results/pq-private-relation-v1'
parent_pin='5d5d551beec2c73610f5567913d1abff9497bc1221f6a4d6e30689013d5bbccc'
verify(parent,parent_pin)
balance=r/'results/pq-pool-component-v1'
verify(balance,'220725a8bd0dd24c98575f1cbd2621184a15a47701b68507dd2c24919d99d43f')
for name in ['Cargo.toml','Cargo.lock',*['src/'+p.name for p in (balance/'src').glob('*.rs')]]:
    assert sha(balance/name)==sha(r/'work/pq-pool-component-v1'/name),name
source=r/'work/pq-private-relation-v1'
for name in ['Cargo.toml','Cargo.lock',*['src/'+p.name for p in (parent/'src').glob('*.rs')]]:
    assert sha(parent/name)==sha(source/name),name
for name in ('graph.rs','model.rs','ledger.rs','builder.rs'):
    assert sha(w/'src'/name)==sha(parent/'src'/name),name
old_config=(parent/'src/config.rs').read_text()
assert (w/'src/config.rs').read_text()==old_config.replace('ZK9/LAB/PRIVATE-RELATION/v1/','ZK9/LAB/PRIVATE-COMPACT/v1/')
up=r/'work/pq-pool-selection-v1';expected=read(up/'SOURCE-INVENTORY.json')
assert {str(p.relative_to(up/'plonky3')) for p in (up/'plonky3').rglob('*') if p.is_file()}==set(expected)
for name,meta in expected.items():assert sha(up/'plonky3'/name)==meta['sha256'],name
assert '7 passed; 0 failed; 0 ignored' in (w/'evidence/tests-01.log').read_text()
for name in ('check-01','baseline-profile','proof-01'):
    assert read(w/'evidence'/f'{name}.process.json')['exit_code']==0
for name in ('reject-original','reject-compact'):
    assert read(w/'evidence'/f'{name}.process.json')['exit_code']==1
baseline_profile=read(w/'evidence/baseline-profile/profile.json')
assert baseline_profile['total']==(parent/'evidence/proof-01/proof.postcard').stat().st_size
series=w/'evidence/series-01';rows=read(series/'samples.json');assert len(rows)==30
hashes=[]
for i,row in enumerate(rows):
    dest=series/f'sample-{i:02}'
    raw=read(dest/'sample.json');proc=read(dest.with_name(dest.name+'.process.json'))
    assert proc['exit_code']==0 and proc['stderr']==''
    assert raw==json.loads(proc['stdout']) and raw['verified'] is True
    assert row==dict(sample=i,**raw,child_peak_rss_bytes=proc['child_peak_rss_bytes'])
    assert raw['width']==10293 and raw['height']==1024 and raw['pq_security_budget_verified'] is False
    assert raw['proof_bytes']==(dest/'proof.postcard').stat().st_size==read(dest/'profile.json')['total']
    hashes.append(sha(dest/'proof.postcard'))
assert len(set(hashes))==30
stats={}
for key in ('layout_ms','prepare_ms','init_ms','prove_ms','verify_ms','proof_bytes','child_peak_rss_bytes'):
    values=[row[key] for row in rows];median=statistics.median(values)
    stats[key]=dict(median=median,mad=statistics.median(abs(v-median) for v in values),minimum=min(values),maximum=max(values))
assert stats==read(series/'statistics.json')
old=read(parent/'QUALIFICATION.json')['statistics']
comparison={k:dict(baseline_median=old[k]['median'],compact_median=stats[k]['median'],
                   ratio=old[k]['median']/stats[k]['median'],reduction_percent=100*(1-stats[k]['median']/old[k]['median']))
            for k in ('prove_ms','verify_ms','proof_bytes')}
profile=read(w/'evidence/proof-01/profile.json')
qual=dict(status='PASS_COMPACT_PRIVATE_RELATION_DEPTH4',parent_manifest_sha256=parent_pin,
          adopted_in_product=False,public_launch_ready=False,integral_post_quantum=False,
          pq_security_budget_verified=False,durable_state=False,tree_depth=4,
          tests_passed=7,cross_version_rejections=2,samples=30,statistics=stats,comparison=comparison,
          parameters_unchanged_except_domain=True,model_graph_ledger_unchanged=True,
          upstream_files_unchanged=len(expected),width_before=21820,width_after=10293,
          binary_sha256=sha(w/'target/release/zk9-private-compact-lab'),cargo_lock_sha256=sha(w/'Cargo.lock'),
          rustc=subprocess.check_output([str(r/'work/gloas-native-integration-v1/native/.toolchain/rust/bin/rustc'),'-vV'],text=True),
          baseline_profile=baseline_profile,compact_initial_profile=profile,
          limits=['Single M1 Max desktop, browser open; no other native lab load during measurements',
                  'OS cache not flushed; separate processes for all samples',
                  'Depth4 only; not a production pool throughput benchmark',
                  'Original circuit and compact circuit use distinct domains, not interchangeable proofs',
                  'Raw proof fits4MiB mempool, not2MB RPC; no full transaction integration tested'])
save(w/'QUALIFICATION.json',qual)
text='ZK9 — Relación privada compacta, laboratorio, 14 de octubre de2026\n\n'
text+='Se conservan hashes, modelo de notas, posesión, Merkle, nullifiers y balance.\n'
text+='Cambian la asignación de registros y la representación redundante de capacidad\nSHA3. Los parámetros criptográficos son idénticos salvo el dominio de versión.\n'
text+='7 tests pasaron y30/30 muestras se verificaron, incluida deserialización.\n\n'
for key,c in comparison.items():
    text+=f'{key}: mediana {c["baseline_median"]:.3f} → {c["compact_median"]:.3f}; reducción {c["reduction_percent"]:.2f}%; razón {c["ratio"]:.3f}x.\n'
text+='\nDispersión, mínimos, máximos, memoria por proceso y datos originales: evidence/series-01.\n'
text+='Layout se mide separado, fuera de prove_ms; verify_ms incluye reconstruir el AIR.\n'
text+='Es comparación secuencial en la misma máquina, sin controlar el escritorio ni\nla caché del SO; no una garantía de rendimiento en otro dispositivo.\n\n'
text+='El perfil identificó5.588.225bytes en aperturas de filas de la traza original\ny1.396.487bytes en valores de traza fuera del dominio. Reducir columnas de21820\na10293 ataca ambos costes; no era el tamaño de los digests el coste dominante.\n\n'
text+='La prueba sola ya cabe en4MiB de mempool, pero no en2.000.000bytes de cuerpo\nRPC. Aún faltan cabeceras, firmas y codificación externa. El pool clásico actual\nlimita su transferencia a64.000bytes y usa otro verificador; no es un destino\ncompatible para estas pruebas. No se cambiaron esos límites ni el producto.\n'
text+='El límite128KiB de pqhybrid firma Payload de cuentas de formato fijo; no es\nuna ruta existente para el nuevo pago privado. Requiere módulo y versión propios.\n\n'
text+='Próximo: escalar árbol, completar representación/entrada acotada del nuevo pool,\nconsumo persistente de nullifiers y recuperación cifrada. Reutilizar el patrón\nCacheContext del módulo existente, sin habilitar un bypass clásico de emisión.\n'
text+='El árbol sigue en16posiciones y el ledger en memoria. Parámetros y composición\nPQ no revisados externamente. No acredita protección integral ni lanzamiento.\n'
(w/'REPORT.txt').write_text(text)
d.mkdir()
for name in ('Cargo.toml','Cargo.lock','cargo-local.sh','hash-vectors.json','README.txt',
             'run-one.py','measure.py','collect.py','QUALIFICATION.json','REPORT.txt','INTEGRATION.txt'):
    shutil.copy2(w/name,d/name)
shutil.copytree(w/'src',d/'src');shutil.copytree(w/'evidence',d/'evidence')
pin=freeze(d,{'scope':'Compact experimental private relation; no production adoption'})
verify(d,pin)
save(w/'FINAL-VERIFICATION.json',dict(status='PASS',manifest_sha256=pin,result_directory=str(d)))
print(json.dumps(dict(manifest_sha256=pin,comparison=comparison),indent=2))
