ZK9 — Componente experimental de conservación con HidingFriPcs

NO es un pool ni una transacción privada completa. NO adopción en producto.
Revisión upstream: f98331687e47106a64ab82a77e2e1d0d66c9161b.
Fuente: ../pq-pool-selection-v1/plonky3; no modificada por este experimento.
Rust aislado 1.98.1, host aarch64-apple-darwin. Cargo.lock fija terceros.

Configuración: BabyBear, extensión de grado8, 64 consultas, blowup8, folding2,
polinomio final longitud1, sin grinding, 8 codewords aleatorios, 16 sales de
campo por hoja, ambos MMCS hiding. Hash/MMCS Keccak-f sponge de salida256bits
y transcript Keccak256, siguiendo la construcción del test upstream. Este
hash y esta composición NO justifican una promesa de 128bits PQ integral.
Semillas privadas independientes obtenidas de SysRng, sin fallback determinista.
Dominio de transcript fijo, parámetros del verificador compilados, height512.

AIR:326 columnas booleanas; cantidades de64bits descompuestas en4limbos16bits;
cinco cantidades (2entradas,2salidas,fee); tres acarreos internos con rango
-2..1. Acarreos inicial/final0. Las ecuaciones tienen magnitud muy inferior al
módulo BabyBear: no basta una igualdad modular con overflow para crear saldo.
Las filas se mantienen constantes mediante restricciones de transición.
Fee público y contexto red/génesis/activo de32bytes, codificado sin pérdida
en limb16. El transcript vincula contexto; NO acredita activo de una nota real.
El enunciado existencial aislado es débil y útil solo como pieza de circuito:
no hay compromisos de notas, ownership, Merkle, nullifiers ni estado de gasto.

Ejecutar desde la carpeta del experimento:
sh cargo-local.sh test --locked --offline --release -- --test-threads=1
sh cargo-local.sh build --locked --offline --release
target/release/zk9-hiding-balance-component 1 NUEVA_CARPETA
target/release/zk9-hiding-balance-component 30 OTRA_CARPETA_NUEVA

Inicialización, preparación, prueba, verificación, serialización y lectura se
cronometran por separado. Datos de prueba sintéticos fijos; entropía de máscaras
no reproducible ni almacenada. Verificador independiente y roundtrip de cada
prueba. Tamaño varía por consultas aleatorias; no exigir igualdad de bytes.
No comparar estas cifras con un pago MASP completo.

Tests: aritmética extrema, rechazo de inflación/desbordamiento en generador,
traces maliciosas pasadas directamente al prover real en release y rechazadas
por el verificador; bindings red/genesis/activo/fee, alteración de compromisos,
randomización ausente/alterada, degree, aperturas, datos truncados, presupuesto
de ocultamiento insuficiente, máscaras frescas en mismo/nuevo config.
Que las pruebas difieran no constituye una demostración de zero knowledge.

Historial: build-01 compiló con warning de strip por libLLVM de rust-objcopy.
Se fija strip=none explícito en el perfil posterior. smoke.time.txt registra
un intento prematuro de ejecutar el binario antes de terminar su build; falló
sin ejecutar prueba. Conservarlo, no contarlo como benchmark.
smoke-02 produjo y verificó la prueba, pero /usr/bin/time -l salió1 porque el
sandbox deniega sysctl kern.clockrate. Las series posteriores usan subprocess
y resource de Python y registran salida real del binario y RSS del proceso.

Pendiente: relación completa de notas; hash/campos/presupuesto PQ revisados;
decodificación hostil y límites de recursos; consumo atómico y raíces; cifrado,
discovery y recuperación de las mismas notas; integración wallet/consenso;
medición controlada sin navegación concurrente y revisión independiente.
