"""Freeze only after two complete sequential verifier qualifications."""
import importlib.util
import json
from pathlib import Path
import shutil

W=Path(__file__).resolve().parent
R=W.parent.parent
D=R/'results/pq-private-send-v1'
spec=importlib.util.spec_from_file_location('lab_common', R/'work/private-rpc-product-v1/source-kit/common.py')
common=importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
if D.exists():
    raise SystemExit('frozen result already exists')
base=common.read(W/'BASE.json')
for entry in base.values():
    common.verify(Path(entry['path']),entry['manifest_sha256'])
environment=common.read(W/'evidence/environment-01.json')
for path,pin in environment['local_source_pins'].items():
    assert common.sha(Path(path))==pin, ('dependency source changed',path)
runs=[]
for name in ('qualification-01','qualification-02'):
    record=common.read(W/'evidence'/f'{name}.result.json')
    assert record['status']=='PASS' and record['child_exit']==0
    assert common.sha(W/'evidence'/f'{name}.jsonl')==record['log_sha256']
    assert common.sha(W/'target/release/qualify')==record['binary_sha256']
    for path,pin in record['source_files'].items():
        assert common.sha(W/path)==pin, ('source changed',path)
    rows=[json.loads(line) for line in (W/'evidence'/f'{name}.jsonl').read_text().splitlines()]
    attacks=[row for row in rows if row.get('detail',{}).get('rejected_by')=='verifier']
    assert len(attacks)==7 and all(row['status']=='PASS' for row in attacks)
    runs.append(record)
assert runs[0]['source_files']==runs[1]['source_files']
for case in ('one-real-input','two-real-inputs','one-u64-max','wallet-constructed-one-input'):
    a=(W/'evidence/qualification-01'/f'{case}.wire').read_bytes()
    b=(W/'evidence/qualification-02'/f'{case}.wire').read_bytes()
    assert a!=b, ('unexpected identical randomized proof',case)
    if case!='wallet-constructed-one-input':
        assert a[:436]==b[:436] and a[440:3904]==b[440:3904]
unit=(W/'evidence/unit-01.log').read_text()
assert '3 passed; 0 failed' in unit
current_pin=common.sha(R/'CURRENT.json')
qualification=dict(status='PASS_COMPONENT_ONLY',launch_ready=False,
    runs=runs,unit_tests=3,malicious_trace_rejections_per_run=7,
    scope='One-or-two-input payment relation, native witness construction and v2 wire; synthetic keys and placeholder packets.',
    adoption='Not installed; keeper/App and wallet send integration pending.',
    current_sha256_unchanged=current_pin)
common.save(W/'QUALIFICATION.json',qualification)
report='''ZK9 — una o dos entradas privadas, componente verificado

El circuito permite gastar una sola nota manteniendo dos posiciones públicas.
La segunda sólo puede omitir pertenencia cuando sus 64 bits de importe son cero.
La primera conserva propiedad y pertenencia obligatorias. El indicador privado
es booleano y constante; todo el calendario de hashes se mantiene fijo.

Constructor nativo: recibe notas seleccionadas y árbol local, comprueba raíz,
propietario, compromiso e índice; calcula cambio/comisión con límites u64 y
genera aleatoriedad de salidas/relleno con el sistema operativo. No autentica
consenso, reserva notas, cifra paquetes ni envía pagos por sí mismo.

Verificación: tres tests de constructor pasan. Dos procesos independientes
completan 14 casos cada uno; ambos generan/verifican pagos de una entrada, dos
entradas, valor u64 máximo y construcción desde nota local. Comprueban aislamiento
del protocolo anterior, 11 alteraciones públicas, cinco de prueba, 16 de sobre,
nueve truncamientos y otros rechazos de formato/balance. Siete trazas hostiles
por proceso son convertidas en pruebas por el prover de release y rechazadas
por el verificador, incluyendo el importe 2013265921 disfrazado de valor cero.
Los tests de flag booleano y estacionario usan una nota cero que SÍ pertenece
al árbol, para aislar esas condiciones de la condición de pertenencia.

Las pruebas aleatorias difieren entre ejecuciones. Los escenarios fijos mantienen
los mismos campos públicos y paquetes. Los paquetes son placeholders sintéticos:
este hito no prueba de nuevo ML-KEM ni crea transacciones válidas para el nodo.
Se conserva la evidencia del primer build fallido por tipos distintos de prueba
entre crates; se corrigió el test diferencial mediante serialización canónica.

'''
for i,record in enumerate(runs,1):
    report+=f"Ejecución {i}: {record['wall_seconds']:.3f} s para toda la batería; RSS máximo {record['peak_rss']} {record['peak_rss_units']}.\n"
report+='''
No son benchmarks ni resultados de mainnet. Falta adoptar wire v2/perfil nuevo
en keeper/App, conservar árbol completo en wallet, reservas y outbox cifradas,
revisión nativa, cifrado de paquetes, envío/reintento y recuperación integral.
El esquema de copias debe versionarse explícitamente. No cambia CURRENT ni el
producto instalado. La red pública, operadores independientes, revisión externa
y protección poscuántica integral siguen pendientes.
'''
(W/'REPORT.txt').write_text(report)
D.mkdir()
for name in ('src','evidence'):
    shutil.copytree(W/name,D/name)
for name in ('Cargo.toml','Cargo.lock','cargo-local.sh','BASE.json','PROTOCOL.txt','README.txt',
             'run_qualification.py','capture_environment.py','collect.py','QUALIFICATION.json','REPORT.txt'):
    shutil.copy2(W/name,D/name)
(D/'bin').mkdir()
shutil.copy2(W/'target/release/qualify',D/'bin/qualify')
pin=common.freeze(D,{'scope':'experimental-one-or-two-input-private-payment-v2','parents':base})
files=common.verify(D,pin)
assert common.sha(R/'CURRENT.json')==current_pin
common.save(W/'FINAL-VERIFICATION.json',dict(status='PASS',manifest_sha256=pin,files=len(files),current_unchanged=True))
print(json.dumps({'status':'PASS','result':str(D),'manifest_sha256':pin,'files':len(files)}),flush=True)
