"""Freeze source and evidence only after two successful complete fresh runs."""
import json, re, shutil, subprocess, sys
from pathlib import Path
W=Path(__file__).resolve().parent;R=W.parents[1]
S=R/'work/gloas-native-integration-v1/native'
sys.path.insert(0,str(R/'work/private-rpc-product-v1/source-kit'))
from common import sha,read,save,freeze,verify
parents={
 'pq-private-tree-v1':'c72b2107472319f36206831f3f5489b6f66cf69b3f871f5cba08d5c7fd11634d',
 'pq-private-wire-v1':'c0bcbd865e0bf166955cb9674daa9784a8f94bd5c488434760d25c532197fe02',
 'pq-private-compact-v1':'d359e5ea1d620a31d9f57536a32e91a062969bc8eec036093e331a31e77963b5',
 'pq-private-relation-v1':'5d5d551beec2c73610f5567913d1abff9497bc1221f6a4d6e30689013d5bbccc',
 'pq-pool-component-v1':'220725a8bd0dd24c98575f1cbd2621184a15a47701b68507dd2c24919d99d43f',
 'pq-pool-selection-v1':'88e2a85cdf0028bfd744d403fbe7cdd139cf7e9e2cbb985bc016af0080760e83'}
for name,pin in parents.items():
 entries=verify(R/'results'/name,pin)
 for p in entries:
  if p in ('Cargo.toml','Cargo.lock') or p.startswith('src/'):
   assert sha(R/'results'/name/p)==sha(R/'work'/name/p),(name,p)
backend=read(R/'results/pq-pool-selection-v1/SOURCE-INVENTORY.json')
for path,entry in backend.items():
 source=R/'work/pq-pool-selection-v1/plonky3'/path
 assert source.is_file() and not source.is_symlink() and sha(source)==entry['sha256'],path
assert (W/'src/config.rs').read_text()==(R/'work/pq-private-tree-v1/src/config.rs').read_text().replace('PRIVATE-TREE/v1','NOTE-DELIVERY/v1').replace('/2in2out/p3-', '/2in2out/ciphertext-SHA3-512/p3-')
assert (W/'src/bounded.rs').read_text()==(R/'work/pq-private-wire-v1/src/bounded.rs').read_text().replace('zk9_private_tree_lab::PaymentProof','crate::PaymentProof')
transcript=R/'work/pq-pool-selection-v1/plonky3/uni-stark/src/transcript.rs'
assert '.add_public_scalars::<F, FieldToFieldCodec<F>>(PUBLIC_VALUES, public_values)' in transcript.read_text()
assert '.observe_public_scalars::<F, FieldToFieldCodec<F>>(PUBLIC_VALUES, public_values)' in transcript.read_text()
logs=(W/'evidence/go-tests-final.log').read_text()
for name in ('TestSeedRecoveryAndRandomizedEncryption','TestRejectWrongRecipientContextSlotAndEveryPacketByte','TestAuthenticatedWrongPlaintextStillRejected'):
 assert logs.count('--- PASS: '+name+' (')==2,name
assert '--- FAIL:' not in logs and '\nPASS\n' in logs
assert 'Finished `release` profile [optimized]' in (W/'evidence/rust-build-01.log').read_text()
runs=[]
for name in ('cross-02','cross-03'):
 d=W/'evidence'/name
 assert read(d/'summary.json')['status']=='PASS'
 procs=read(d/'processes.json');assert len(procs)==3 and all(x['exit_code']==0 for x in procs)
 process=read(d/'proof-process.json');assert process['exit_code']==0 and process['child_count']==1 and process['max_rss_bytes']>0
 checks=read(d/'verified/checks.json');assert checks['status']=='PASS_BOUND_DELIVERY_LAB'
 assert checks['amounts']==[900000,599999] and checks['fee']==1 and len(checks['rejections'])==95
 assert checks['envelope_bytes']==(d/'verified/envelope.bin').stat().st_size
 assert checks['public_fields']==276 and checks['packet_bytes']==1732
 assert 'restored two wallets from seeds: total=1499999' in (d/'restore.log').read_text()
 assert sha(d/'fixture/fixture.json')==sha(d/'verified/fixture.json')
 runs.append(dict(name=name,checks=checks,process=process,envelope_sha256=sha(d/'verified/envelope.bin')))
assert runs[0]['checks']['recipient_commitments']==runs[1]['checks']['recipient_commitments']
assert runs[0]['envelope_sha256']!=runs[1]['envelope_sha256']
for i in range(2):
 assert runs[0]['checks']['delivery_hashes'][i]!=runs[1]['checks']['delivery_hashes'][i]
 assert sha(W/f'evidence/cross-02/fixture/packet-{i}.bin')!=sha(W/f'evidence/cross-03/fixture/packet-{i}.bin')
q=dict(status='PASS_BOUND_ENCRYPTED_NOTE_DELIVERY_LAB',parent_manifests=parents,
 rustc=subprocess.check_output([str(S/'.toolchain/rust/bin/rustc'),'-vV'],text=True),
 go=subprocess.check_output(['sh',str(W/'go-local.sh'),'version'],text=True),
 go_build_environment=json.loads(subprocess.check_output(['sh',str(W/'go-local.sh'),'env','-json','GOOS','GOARCH','GOFLAGS','GOTOOLCHAIN'],text=True)),
 go_compiler_sha256=sha(S/'.toolchain/go/bin/go'),rust_compiler_sha256=sha(S/'.toolchain/rust/bin/rustc'),
 platform=subprocess.check_output(['uname','-a'],text=True),cargo_lock_sha256=sha(W/'Cargo.lock'),
 go_mod_sha256=sha(W/'source/go.mod'),binary_sha256=sha(W/'target/release/zk9-note-delivery'),
 transcript_source_sha256=sha(transcript),crypto_parameters_changed=False,
 transcript_domain_and_public_shape_changed=True,public_values=276,packet_bytes=1732,
 release_profile=dict(opt_level=3,lto='thin',codegen_units=1,overflow_checks=True),
 go_parent_tests=3,go_repetitions=2,go_packet_byte_mutations_per_repetition=1732,
 go_truncations_per_repetition=1732,authenticated_wrong_plaintexts_per_repetition=5,
 full_cross_language_runs=runs,candidate_only=True,integral_post_quantum=False,
 node_integrated=False,wallet_ui_integrated=False,durable_note_discovery=False,public_launch_ready=False,
 limits=['Static recipient key: no forward secrecy; ML-KEM key privacy/anonymity not established',
 'Digest binding authenticates sender-selected ciphertext, not correct plaintext encryption',
 'Authenticated recipient addresses, accepted chain state, durable availability and wallet discovery pending',
 'Two synthetic functional runs are not performance qualification or external security review',
 'cross-01 completed Rust checks but macOS time -l failed on sandbox sysctl; whole run not qualified'])
save(W/'QUALIFICATION.json',q)
lines=['ZK9 — Entrega de notas cifradas vinculada a la prueba, candidato experimental','',
 'Implementados cifrado ML-KEM-1024/HKDF-SHA512/AES-256-GCM y recuperación',
 'desde semilla para notas del nuevo pool. Dos paquetes de1732bytes forman',
 'parte obligatoria de un nuevo formato. Sus huellas SHA3-512, con contexto,',
 'compromiso de salida y posición, entran en el transcript de la prueba STARK.',
 'No se modificaron los padres congelados ni el nodo/wallet instalados.','',
 'Tres pruebas Go pasan dos veces: recuperación, aleatoriedad y separación de',
 'claves; rechazo de cada byte alterado y cada truncamiento de1732bytes;',
 'rechazo de otro destinatario/contexto/posición y plaintext incorrecto incluso',
 'con AEAD auténtico. La recuperación vuelve a comprobar dueño y compromiso.','',
 'Dos ejecuciones completas independientes pasan Go->Rust->Go: cifran dos',
 'notas, contrastan hashes entre lenguajes, generan y verifican una prueba real,',
 'rechazan95variantes hostiles por ejecución y recuperan ambas notas desde las',
 'semillas en otro proceso. Saldos900000 y599999; comisión1. Los ciphertexts y',
 'las pruebas difieren entre ejecuciones, como corresponde a la aleatoriedad.','']
for run in runs:
 c=run['checks'];p=run['process']
 lines.append(f"{run['name']}: prueba+traza {c['prove_ms_including_trace']:.3f}ms; verificación {c['verify_ms']:.3f}ms; sobre {c['envelope_bytes']}bytes; RSS máximo del proceso {p['max_rss_bytes']}bytes.")
lines += ['', 'Son dos observaciones funcionales; no una serie estadística de rendimiento.',
 'Primer intento: las comprobaciones Rust terminaron, pero time -l falló al',
 'consultar sysctl en sandbox. Se conserva el fallo y se usó un supervisor',
 'nuevo con un único hijo y getrusage, sin elevar permisos, en ambos runs finales.','',
 'Alcance: un intermediario no puede modificar ni quitar los paquetes y conservar',
 'la prueba válida. No impide censurar toda la transacción. Un emisor malicioso',
 'puede construir una prueba nueva con ciphertext inútil: no se prueba cifrado',
 'correcto dentro del circuito. El destinatario valida el contenido al recibirlo.',
 'ML-KEM no acredita por sí solo anonimato del destinatario; clave estática sin',
 'secreto hacia adelante. La composición y el presupuesto PQ siguen sin review.','',
 'Falta adoptar el formato en keeper/App, persistir/publicar los paquetes,',
 'implementar descubrimiento y recuperación duradera de wallet, autenticar',
 'direcciones y probar reorganizaciones. Después sigue la integración de UI,',
 'transporte, custodia protegida y operadores independientes. No hay lanzamiento',
 'público, depósitos/retiros reales, venta ni garantía de protección PQ integral.']
(W/'REPORT.txt').write_text('\n'.join(lines)+'\n')
D=R/'results/pq-note-delivery-v1';D.mkdir(exist_ok=False)
for name in ('Cargo.toml','Cargo.lock','cargo-local.sh','go-local.sh','run-checks.py','measure-one.py','collect.py','README.txt','QUALIFICATION.json','REPORT.txt'):
 shutil.copy2(W/name,D/name)
for name in ('src','source','evidence'):shutil.copytree(W/name,D/name)
(D/'bin').mkdir();shutil.copy2(W/'target/release/zk9-note-delivery',D/'bin/zk9-note-delivery')
pin=freeze(D,{'scope':'Experimental proof-bound encrypted note delivery and seed recovery; no node/UI adoption'})
verify(D,pin)
current=R/'CURRENT.json';before=current.read_bytes();backup=W/'CURRENT.before-delivery.json'
assert not backup.exists();backup.write_bytes(before)
old=json.loads(before);new=json.loads(before);key='pq_private_note_delivery_lab_candidate';assert key not in old
new[key]={**q,'result_directory':str(D),'manifest_sha256':pin}
assert current.read_bytes()==before
staged=R/'CURRENT.delivery-staged.json';assert not staged.exists()
staged.write_text(json.dumps(new,indent=2)+'\n');staged.replace(current)
now=read(current);assert {k:v for k,v in now.items() if k!=key}==old
save(W/'CURRENT-UPDATE.json',dict(status='PASS',backup_sha256=sha(backup),current_sha256=sha(current),siblings_unchanged=True,key=key))
save(W/'FINAL-VERIFICATION.json',dict(status='PASS',manifest_sha256=pin,result_directory=str(D)))
print(json.dumps(dict(status=q['status'],manifest_sha256=pin),indent=2))
