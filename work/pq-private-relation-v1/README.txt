ZK9 — Relación privada experimental 2 entradas / 2 salidas

Este candidato no está instalado en la wallet ni en el nodo. No emite moneda,
no admite depósitos y no es una mainnet. Es un avance sobre la conservación
aislada: ahora prueba posesión del secreto, pertenencia, identificadores de
gasto, destinatarios, rangos y conservación en un mismo AIR con ocultamiento.

Modelo de laboratorio
- Árbol binario fijo de profundidad4 (16 posiciones). Los tests inicializan12
  notas sintéticas y4 posiciones vacías. El verificador fija esa profundidad.
- Cada propietario se identifica por SHA3-512("ZK9ADR01" || secreto32).
- Nota: SHA3-512("ZK9NOT01" || red32 || génesis32 || activo32 || propietario64
  || rho32 || cantidad_u64_little_endian).
- Nullifier: SHA3-512("ZK9NUL01" || red32 || génesis32 || secreto32 || nota64).
  Vincula autorización y nota en esa red; repetir una nota repite el nullifier.
- Nodo Merkle: SHA3-512("ZK9MRK01" || nivel_u32_LE || izquierda64 || derecha64).
  Cada dirección del camino es booleana. Ambos caminos terminan en la raíz
  pública que el estado de prueba debe autorizar.
- Cantidades64bits, comisión pública, dos entradas = dos salidas + comisión.
  Reutiliza las restricciones de limb16 y acarreos acotados ya probadas.
- Inputs públicos: comisión, red, génesis, activo, raíz,2nullifiers,2salidas.
  Los destinatarios y cantidades privadas están ligados a esos compromisos.

No usar estos formatos para fondos reales todavía. Las semillas y notas de
fixture son públicas/predictibles. Las máscaras de la prueba se generan con
entropía real del SO, independiente de los fixtures y sin fallback determinista.

Composición
Plonky3 f98331687e47106a64ab82a77e2e1d0d66c9161b, fuente upstream sin editar.
Se reutiliza KeccakAir mediante un adaptador de ventanas: su circuito ve solo
sus columnas, sin cambiar sus restricciones. Un programa fijo conecta36
permutaciones en16hashes SHA3-512. El AIR obliga al orden de los bloques,
reinicio del estado entre hashes, absorción XOR de72bytes, preservación de la
capacidad, padding0x06/0x80 y extracción de los512bits finales. No basta con
comprobar hashes en código fuera del circuito. Los bits privados se mantienen
iguales entre filas y se vinculan al resto de restricciones en la misma prueba.
El oracle nativo tiny-keccak se contrasta con vectores Python hashlib; el
generador compara también cada absorción manual con su SHA3-512 nativo.
Referencia del estándar: https://csrc.nist.gov/pubs/fips/202/final
Esto no es certificación FIPS ni auditoría de la composición.

Prueba: HidingFriPcs, dos MMCS con ocultamiento; BabyBear/extensión8; 64consultas,
blowup8, folding2, polinomiofinal1, sin grinding,8codewords de máscara,
16sales de campo por hoja. MMCS Keccak-f sponge padding-free salida512bits,
rate9palabras/capacity16; transcript SHA3-512 y dominio fijo distinto del
componente anterior. Los MMCS siguen la construcción de Plonky3; no afirmar
que su hash padding-free sea la función SHA3-512 estandarizada.
No hay prueba EC/pairing de envoltura. Esto NO fija un presupuesto PQ integral:
FRI, batching, campo/extensión, Fiat–Shamir/QROM y ocultamiento deben revisarse
como composición, con el tamaño real de este AIR. Duplicar el digest no basta.
El verificador no acepta parámetros ni tamaños de traza elegidos por la prueba.
Cada prueba realiza nuevos compromisos; no se expone private prover data reusable.

Estado de prueba
ledger.rs recibe contexto y árbol inicial de la autoridad del test, no de una
transacción. Exige raíz autorizada, contexto esperado, capacidad disponible,
nullifiers nuevos, salidas nuevas y prueba válida. Construye el estado siguiente
aparte y solo lo sustituye tras validar todo. No hay ruta clásica alternativa.
Este estado vive en memoria y requiere &mut exclusivo: no acredita durabilidad,
SQLite, recuperación tras corte, atomicidad en consenso ni doble gasto entre
procesos. No confundirlo con el estado desplegado de ZK9.

Reproducción, desde esta carpeta
sh cargo-local.sh build --locked --offline --release
sh cargo-local.sh test --locked --offline --release -- --test-threads=1
target/release/zk9-private-relation-lab check NUEVA_CARPETA_CHECK
target/release/zk9-private-relation-lab prove NUEVA_CARPETA_PROOF

Rust1.98.1 aislado; Cargo.lock y fuentes locales congeladas en resultados.
Las carpetas deben ser nuevas. El ejecutable nunca abre wallets personales ni
conecta a una red. Inicialización/preparación/probar/verificar se miden por
separado. Se verifica también la prueba deserializada. El proceso solo exporta
prueba y métricas de fixtures sintéticos; no exporta máscaras ni semillas del SO.

Pendientes para el objetivo público
Revisar parámetros criptográficos/privacidad; árbol y límites de producción;
decodificación hostil acotada; notas cifradas/discovery/recuperación compatibles;
integrar depósito/salida y consumo duradero de nullifiers en el nodo real;
impedir bypass de emisión clásico; integrar wallet y firmante; transporte y
consenso PQ completos; operadores independientes y revisión externa. La ruta
externa del bridge conserva dependencias de seguridad de las redes externas.
