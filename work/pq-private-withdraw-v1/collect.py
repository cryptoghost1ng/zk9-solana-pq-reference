"""Freeze only a repeated complete qualification; retain failures separately."""
import importlib.util,json,shutil
from pathlib import Path
W=Path(__file__).resolve().parent;R=W.parent.parent;D=R/'results'/W.name
spec=importlib.util.spec_from_file_location('c',R/'work/private-rpc-product-v1/source-kit/common.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
assert not D.exists()
base=c.read(W/'BASE.json')
for p in base.values():c.verify(Path(p['path']),p['manifest_sha256'])
runs=[]
for label in ('smoke-01','qualification-01','qualification-02'):
    rec=c.read(W/'evidence'/f'{label}.result.json');assert rec['status']=='PASS' and rec['child_exit']==0
    assert c.sha(W/'evidence'/f'{label}.jsonl')==rec['log_sha256']
    for p,pin in rec['source_files'].items():assert c.sha(Path(p))==pin,('source changed',p)
    rows=[json.loads(l) for l in (W/'evidence'/f'{label}.jsonl').read_text().splitlines()]
    if not rec['smoke']:
        assert len([r for r in rows if r.get('detail',{}).get('rejected_by')=='raw_verifier'])==12
        assert rows[-1]['valid_withdrawal_proofs']==4
        runs.append(rec)
assert runs[0]['source_files']==runs[1]['source_files']
env=c.read(W/'evidence/environment-01.json')
for p,pin in env['local_source_pins'].items():assert c.sha(Path(p))==pin
assert '1 passed; 0 failed' in (W/'evidence/unit-01.log').read_text()
current='d049e25865e04ba4cc1fb964c18f2fa9649cad8161709ee070f900c5a7996616'
assert c.sha(R/'CURRENT.json')==current
for case in ('single-with-change','maximum-withdrawal','two-inputs','wallet-built'):
    a=(W/'evidence/qualification-01'/f'{case}.wire').read_bytes();b=(W/'evidence/qualification-02'/f'{case}.wire').read_bytes()
    assert a!=b
    if case!='wallet-built':assert a[:465]==b[:465]
qualification=dict(status='PASS_REPEATED_NATIVE_WITHDRAWAL_COMPONENT',runs=runs,unit_tests=1,
    valid_withdrawals_per_run=4,valid_old_payment_per_run=1,raw_malicious_proof_rejections_per_run=12,
    real_encrypted_output_packets=True,keeper_adopted=False,bank_payout_executed=False,bridge=False,
    public_network=False,production_ready=False,current_sha256=current)
D.mkdir()
for name in ('src','source','evidence'):shutil.copytree(W/name,D/name)
for p in W.iterdir():
    if p.is_file() and p.name!='fixture-helper':shutil.copy2(p,D/p.name)
(D/'bin').mkdir();shutil.copy2(W/'target/release/qualify',D/'bin/qualify');shutil.copy2(W/'fixture-helper',D/'bin/fixture-helper')
c.save(D/'QUALIFICATION.json',qualification)
report='''ZK9 — componente nativo de retirada, comprobado dos veces

La retirada pública tiene importe y destinatario propios, ligados a la prueba.
El cambio sigue siendo privado y la comisión es independiente. No se acredita
dinero en una cuenta ni se conecta aún este formato al keeper o a la wallet.

Cada ejecución completa prueba cuatro retiradas válidas: una entrada con cambio,
dos entradas, valor máximo menos comisión y constructor de wallet con relleno.
También genera/verifica un pago anterior y comprueba rechazo cruzado de pruebas
y sobres. Prueba14 alteraciones públicas,19 del sobre,12 truncamientos y5 de
la prueba. Los paquetes de ambas salidas se cifran y descifran realmente con
ML-KEM-1024/AES-256-GCM. El ciphertext sigue siendo AD, no cifrado probado en AIR.

Cada ejecución genera12 pruebas de trazas hostiles y el verificador crudo las
rechaza: creación de valor, wraparound, carry, destinatario, modo, relleno no
cero, alias del módulo, pertenencia, propiedad y flag booleano/estacionario.
Son rechazos criptográficos posteriores al prover, no sólo filtros del host.
La prueba unitaria cubre límites65535/65536/u64MAX y sumas por encima de u64.

No es auditoría independiente ni demostración de protección cuántica integral.
El siguiente hito debe integrar el pago público atómico con reserva y comisión,
nullifiers compartidos entre pago/retirada, transacciones firmadas y escaneo.
Bridge, red pública y lanzamiento siguen pendientes.
'''
for i,r in enumerate(runs,1):report+=f"\nEjecución{i}: {r['wall_seconds']:.2f}s, RSS{r['peak_rss']} {r['peak_rss_units']}; observación funcional, no benchmark.\n"
(D/'REPORT.txt').write_text(report)
pin=c.freeze(D,{'scope':'native-withdrawal-component-only','parents':base});files=c.verify(D,pin)
assert c.sha(R/'CURRENT.json')==current
c.save(W/'evidence/final-verification.json',dict(status='PASS',manifest_sha256=pin,files=len(files)))
print(json.dumps(dict(status='PASS',manifest_sha256=pin,files=len(files),artifact=str(D))))
