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
        assert len([r for r in rows if r.get('detail',{}).get('rejected_by')=='raw_verifier'])==13
        assert rows[-1]['valid_withdrawal_proofs']==4
        runs.append(rec)
assert runs[0]['source_files']==runs[1]['source_files']
assert c.sha(W/'reference20.wire')==c.sha(Path(base['withdraw20']['path'])/'evidence/qualification-01/single-with-change.wire')
abi=[]
for name,label in [('abi-01','qualification-01'),('abi-02','qualification-02')]:
    a=c.read(W/'evidence'/name/'RESULT.json');assert a['status']=='PASS' and a['label']==label and len(a['runs'])==4
    assert a['client_sha256']==c.sha(W/'bin/c-verify')
    assert a['staticlib_sha256']==c.sha(W/'target/release/libzk9_private_withdraw32_lab.a')
    for item in a['runs']:
        assert item['exit']==0 and item['detail']['checks']==48 and item['detail']['status']=='PASS'
        assert item['wire_sha256']==c.sha(W/'evidence'/label/(item['case']+'.wire'))
        assert (W/'evidence'/name/(item['case']+'.exit-code')).read_text().strip()=='0'
    abi.append(a)
env=c.read(W/'evidence/environment-01.json')
for p,pin in env['local_source_pins'].items():assert c.sha(Path(p))==pin
assert '1 passed; 0 failed' in (W/'evidence/unit-01.log').read_text()
current='d049e25865e04ba4cc1fb964c18f2fa9649cad8161709ee070f900c5a7996616'
assert c.sha(R/'CURRENT.json')==current
for case in ('single-with-change','maximum-withdrawal','two-inputs','wallet-built'):
    a=(W/'evidence/qualification-01'/f'{case}.wire').read_bytes();b=(W/'evidence/qualification-02'/f'{case}.wire').read_bytes()
    assert a!=b
    if case!='wallet-built':assert a[:477]==b[:477]
qualification=dict(status='PASS_REPEATED_NATIVE_WITHDRAWAL32_COMPONENT',runs=runs,unit_tests=1,
    valid_withdrawals_per_run=4,valid_old_payment_per_run=1,raw_malicious_proof_rejections_per_run=13,
    recipient_bytes=32,public_values=297,header_bytes=481,valid_old_withdrawal_verified_per_run=1,
    withdrawal20_cross_rejections_per_run=6,c_abi=abi,protected_registration_verified=False,
    real_encrypted_output_packets=True,keeper_adopted=False,bank_payout_executed=False,bridge=False,
    public_network=False,production_ready=False,current_sha256=current)
D.mkdir()
for name in ('src','source','evidence'):shutil.copytree(W/name,D/name)
for p in W.iterdir():
    if p.is_file() and p.name!='fixture-helper':shutil.copy2(p,D/p.name)
(D/'bin').mkdir();shutil.copy2(W/'target/release/qualify',D/'bin/qualify');shutil.copy2(W/'fixture-helper',D/'bin/fixture-helper')
shutil.copy2(W/'bin/c-verify',D/'bin/c-verify');shutil.copy2(W/'target/release/libzk9_private_withdraw32_lab.a',D/'bin/libzk9_private_withdraw32_lab.a')
for name in ('include','c-tests'):shutil.copytree(W/name,D/name)
c.save(D/'QUALIFICATION.json',qualification)
report='''ZK9 — componente nativo de retirada a dirección32, comprobado dos veces

La retirada pública tiene importe y destinatario propios, ligados a la prueba.
El cambio sigue siendo privado y la comisión es independiente. No se acredita
dinero en una cuenta ni se conecta aún este formato al keeper o a la wallet.
Conserva los32bytes usados por pqaccounts.Address. El circuito no comprueba
registro de cuenta protegida: esa comprobación corresponde al estado del nodo.
No trunca direcciones ni acepta el anterior formato de20bytes. Verifica una
retirada20 real congelada antes de rechazar ambas direcciones de conversión,
incluyendo reencapsular la prueba en un sobre sintácticamente válido.

Cada ejecución completa prueba cuatro retiradas válidas: una entrada con cambio,
dos entradas, valor máximo menos comisión y constructor de wallet con relleno.
También genera/verifica un pago anterior y comprueba rechazo cruzado de pruebas
y sobres. Prueba16 alteraciones públicas,21 del sobre,12 truncamientos y5 de
la prueba. Los paquetes de ambas salidas se cifran y descifran realmente con
ML-KEM-1024/AES-256-GCM. El ciphertext sigue siendo AD, no cifrado probado en AIR.

Cada ejecución genera13 pruebas de trazas hostiles y el verificador crudo las
rechaza: creación de valor, wraparound, carry, destinatario (inicio y cola), modo, relleno no
cero, alias del módulo, pertenencia, propiedad y flag booleano/estacionario.
Son rechazos criptográficos posteriores al prover, no sólo filtros del host.
La prueba unitaria cubre límites65535/65536/u64MAX y sumas por encima de u64.

La interfaz nativa se comprueba desde un clienteC enlazado con la biblioteca
estática real. Dos tandas de cuatro procesos nuevos,48comprobaciones cada uno:
inicio explícito/idempotente, estado no inicializado, buffers nulos, límites,
contexto/fee incorrectos, prueba válida repetida, v1 rechazado,14alteraciones,
truncamiento y prueba válida después de entradas inválidas. No modifica saldos.

No es auditoría independiente ni demostración de protección cuántica integral.
El siguiente hito debe integrar el pago público atómico con reserva y comisión,
nullifiers compartidos entre pago/retirada, transacciones firmadas y escaneo.
Bridge, red pública y lanzamiento siguen pendientes.
'''
for i,r in enumerate(runs,1):report+=f"\nEjecución{i}: {r['wall_seconds']:.2f}s, RSS{r['peak_rss']} {r['peak_rss_units']}; observación funcional, no benchmark.\n"
(D/'REPORT.txt').write_text(report)
pin=c.freeze(D,{'scope':'native-withdrawal32-component-only','parents':base});files=c.verify(D,pin)
assert c.sha(R/'CURRENT.json')==current
c.save(W/'evidence/final-verification.json',dict(status='PASS',manifest_sha256=pin,files=len(files)))
print(json.dumps(dict(status='PASS',manifest_sha256=pin,files=len(files),artifact=str(D))))
