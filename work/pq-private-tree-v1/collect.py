"""Freeze depth32 only after complete functional and performance evidence."""
import json
import shutil
import statistics
import subprocess
import sys
from pathlib import Path
w=Path(__file__).resolve().parent;r=w.parents[1]
sys.path.insert(0,str(r/'work/private-rpc-product-v1/source-kit'))
from common import sha,read,save,freeze,verify
d=r/'results/pq-private-tree-v1';assert not d.exists()
parents={
 'pq-private-compact-v1':'d359e5ea1d620a31d9f57536a32e91a062969bc8eec036093e331a31e77963b5',
 'pq-private-relation-v1':'5d5d551beec2c73610f5567913d1abff9497bc1221f6a4d6e30689013d5bbccc',
 'pq-pool-component-v1':'220725a8bd0dd24c98575f1cbd2621184a15a47701b68507dd2c24919d99d43f'}
for name,pin in parents.items():
    frozen=r/'results'/name;source=r/'work'/name;verify(frozen,pin)
    for file in ['Cargo.toml','Cargo.lock',*['src/'+p.name for p in (frozen/'src').glob('*.rs')]]:
        assert sha(frozen/file)==sha(source/file),file
parent=r/'results/pq-private-compact-v1'
for file in ('air.rs','graph.rs','layout.rs','trace.rs','builder.rs','profile.rs'):
    assert sha(w/'src'/file)==sha(parent/'src'/file),file
assert (w/'src/config.rs').read_text()==(parent/'src/config.rs').read_text().replace('PRIVATE-COMPACT/v1','PRIVATE-TREE/v1').replace('depth4','depth32')
up=r/'work/pq-pool-selection-v1';expected=read(up/'SOURCE-INVENTORY.json')
assert {str(p.relative_to(up/'plonky3')) for p in (up/'plonky3').rglob('*') if p.is_file()}==set(expected)
for file,meta in expected.items():assert sha(up/'plonky3'/file)==meta['sha256'],file
assert '10 passed; 0 failed; 0 ignored' in (w/'evidence/tests-01.log').read_text()
for name in ('check-01','baseline-profile','proof-01'):
    assert read(w/'evidence'/f'{name}.process.json')['exit_code']==0
for name in ('reject-baseline','reject-tree'):
    assert read(w/'evidence'/f'{name}.process.json')['exit_code']==1
series=w/'evidence/series-01';rows=read(series/'samples.json');assert len(rows)==30
hashes=[]
for i,row in enumerate(rows):
    dest=series/f'sample-{i:02}';raw=read(dest/'sample.json');proc=read(dest.with_name(dest.name+'.process.json'))
    assert proc['exit_code']==0 and proc['stderr']=='' and raw['verified'] is True
    assert raw==json.loads(proc['stdout'])
    assert row==dict(sample=i,**raw,child_peak_rss_bytes=proc['child_peak_rss_bytes'])
    assert raw['width']==10405 and raw['height']==4096 and raw['hashes']==72 and raw['permutations']==148
    assert raw['proof_bytes']==(dest/'proof.postcard').stat().st_size==read(dest/'profile.json')['total']
    assert raw['production_ready'] is False and raw['pq_security_budget_verified'] is False
    hashes.append(sha(dest/'proof.postcard'))
assert len(set(hashes))==30
stats={}
for key in ('layout_ms','prepare_ms','init_ms','prove_ms','verify_ms','proof_bytes','child_peak_rss_bytes'):
    values=[row[key] for row in rows];m=statistics.median(values)
    stats[key]=dict(median=m,mad=statistics.median(abs(v-m) for v in values),minimum=min(values),maximum=max(values))
assert stats==read(series/'statistics.json')
old=read(parent/'QUALIFICATION.json')['statistics']
comparison={k:dict(depth4_median=old[k]['median'],depth32_median=stats[k]['median'],
                   depth32_over_depth4=stats[k]['median']/old[k]['median'])
            for k in ('layout_ms','prove_ms','verify_ms','proof_bytes','child_peak_rss_bytes')}
qual=dict(status='PASS_SPARSE_DEPTH32_PRIVATE_RELATION',parents=parents,
          public_launch_ready=False,adopted_in_product=False,integral_post_quantum=False,
          pq_security_budget_verified=False,durable_state=False,tree_depth=32,
          theoretical_capacity=2**32,tree_leaves_tested=10_000,tree_stored_nodes_upper_bound=20_100,
          chained_payments_tested=3,final_chained_leaf_count=18,final_spent_nullifiers=6,
          tests_passed=10,cross_version_rejections=2,samples=30,statistics=stats,comparison=comparison,
          upstream_files_unchanged=len(expected),parameters_unchanged_except_domain_depth=True,
          binary_sha256=sha(w/'target/release/zk9-private-tree-lab'),cargo_lock_sha256=sha(w/'Cargo.lock'),
          rustc=subprocess.check_output([str(r/'work/gloas-native-integration-v1/native/.toolchain/rust/bin/rustc'),'-vV'],text=True),
          limits=['Synthetic fixture has12initial notes; depth32 does not prove4billion notes tested',
                  'Ledger still cloned in memory; no persistent KV or crash/consensus behavior',
                  'Desktop/browser remain open; OS cache not flushed; native lab samples serial',
                  'Per-process native-child RSS; layout separate, verify includes AIR reconstruction',
                  'No end-to-end quantum budget reviewed; no wallet or node adoption'])
save(w/'QUALIFICATION.json',qual)
text='ZK9 — Árbol disperso de32niveles y pago privado,14 de octubre de2026\n\n'
text+='El árbol deja de reservar todas sus posiciones. Capacidad lógica2^32; solo\nse materializan nodos ocupados. Las pruebas usan32bits de dirección y el\nverificador fija la profundidad. Esto no significa probar4.294millones de notas.\n\n'
text+='Pasaron10tests,30muestras criptográficas y2rechazos entre versiones. Los\ntests contrastan raíces/caminos con Python independiente, crecen a10.000notas\ncon menos de20.100nodos y encadenan3pagos reales de laboratorio hasta18notas\ny6nullifiers consumidos, superando la capacidad anterior de16.\n\n'
for k,c in comparison.items():
    text+=f'{k}: profundidad4 {c["depth4_median"]:.3f}; profundidad32 {c["depth32_median"]:.3f}; factor {c["depth32_over_depth4"]:.3f}.\n'
text+='\nUnidades: ms,bytes y RSSbytes según campo. Mediana/MAD/mínimo/máximo y\nmuestras originales en evidence/series-01. Se separan inicialización, layout\ny traza. Cada prueba se verifica también tras deserializar.\n\n'
text+='Mismos hashes y parámetros, dominio nuevo,72hashes148permutaciones,4096filas\ny10405columnas. La tabla compara la misma máquina de forma secuencial; no\ncontrola escritorio, cachéSO ni garantiza velocidad en otros dispositivos.\n\n'
text+='Pendientes para producto: estado persistente con atomicidad/recuperación,\ndecodificación hostil acotada, versión propia del pool en el nodo y wallet,\nnotas cifradas y descubrimiento. La aplicación actual admite otro formato\nprivado de64KB; RPC tiene2MB. No se elevan límites ni se instala este candidato.\n'
text+='La profundidad32 elimina un límite del laboratorio. La composición PQ,\ntransporte, auditoría externa y operadores independientes siguen pendientes.\n'
(w/'REPORT.txt').write_text(text)
d.mkdir()
for name in ('Cargo.toml','Cargo.lock','cargo-local.sh','hash-vectors.json','tree-vectors.json',
             'generate-tree-vectors.py','README.txt','run-one.py','measure.py','collect.py','REPORT.txt','QUALIFICATION.json'):
    shutil.copy2(w/name,d/name)
shutil.copytree(w/'src',d/'src');shutil.copytree(w/'evidence',d/'evidence')
pin=freeze(d,{'scope':'Depth32 synthetic private pool relation and in-memory sparse tree; no product adoption'})
verify(d,pin)
save(w/'FINAL-VERIFICATION.json',dict(status='PASS',manifest_sha256=pin,result_directory=str(d)))
print(json.dumps(dict(manifest_sha256=pin,comparison=comparison),indent=2))
