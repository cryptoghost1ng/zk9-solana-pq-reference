# ¿Se puede acortar la publicación patrocinada sin tocar la criptografía? (medición local)

Todo local y sintético: un validador aislado en loopback, claves públicas de fixture, cargas reales archivadas. **No es mainnet, no verifica pruebas en este directorio ni demuestra privacidad.**
Nace de una pregunta del usuario (2026-11-01): «¿mido la retirada y pruebo subidas en paralelo?». No se modifica ningún archivo congelado: los scripts nuevos derivan de otros
(`solana-proof-buffer-v1/trial.mjs`, que sigue como estaba) y la sonda de anchura depende por ruta de los crates congelados sin cambiarlos.

## Qué se midió

| Qué | Cómo | Evidencia |
|---|---|---|
| Composición real de 4 pagos archivados (2 envíos v3, 2 retiradas v2) | decodifica las 23.825 transacciones capturadas de `privacy-live-02` y las agrupa por pago y etapa | `analyze_capsule.py` → `evidence/capsule-analysis-01.json`; `analyze_capsule_v2.py` (añade cómputo total, cotas de empaquetado, renta, fases) → `capsule-analysis-02.json` |
| Estrategias de subida de trozos con el programa real de búfer | `bench.mjs`, derivado de `trial.mjs`: mismo validador, mismo programa, misma instrucción de trozo; cargas = los wires reales de envío (2,97 MB) y retirada (4,01 MB); cada caso verifica byte a byte y cierra la cuenta | `run_bench.py` → `evidence/smoke-01.*`, `bench-01.*`, `bench-02.*` |
| Anchura de la traza de tres relaciones | `width-probe/` (Rust): construye la AIR sin probar nada | `evidence/width-01.stdout` |
| Tamaño de la prueba frente a la anchura | `size_model.py`: recta ajustada con los dos envíos y contrastada con las retiradas | `evidence/size-model-01.json` |

## Resultados

**1. Dónde se va el tiempo en el relay real** (4 pagos archivados de `solana-multiwallet-privacy-v1/evidence/privacy-live-02/public-capsule`):

| | Envío (wire 2,97 MB) | Retirada (wire 3,99–4,01 MB) |
|---|---|---|
| Transacciones del pago | 5.117–5.123 | 6.767–6.798 |
| Subida de trozos (900 B) | 3.302–3.307 tx · 1.786–1.788 s · 0,541 s/tx (≈ 30 min) | 4.433–4.452 tx · 2.397–2.410 s · 0,541 s/tx (≈ 40 min) |
| Etapas del verificador | 1.812–1.813 tx · 982–983 s · 0,542 s/tx (≈ 16 min) | 2.331–2.343 tx · 1.258–1.267 s · 0,54 s/tx (≈ 21 min) |
| Cómputo del verificador | 1,58 mil millones de CU, 62 % del tope de 1,4 M por tx | 1,99 mil millones de CU, 61 % del tope |
| Trozos: cómputo por tx | 7.689 CU (0,5 % del tope) | 7.689 CU |
| Renta depositada (cuenta de búfer + recibo) | 21,42–21,45 + 2,29 = 23,7 SOL | 28,76–28,88 + 2,93 = 31,7–31,8 SOL |
| Comisiones de red | 0,026 SOL | 0,034 SOL |
| Transacciones de cierre observadas | 0 | 0 |

Las dos fases cuestan **lo mismo por transacción (≈0,54 s)** aunque una gaste 7.689 CU y la otra ≈1 M: el tiempo es espera de confirmación, no cómputo. Mis ejecuciones de hoy (`full-03`, `full-04`) dan 0,52–0,53 s: coherente.
Los ≈55,6 SOL sintéticos que gastó el sponsor en `full-04` son, casi enteros, esa renta (23,7 + 31,7 ≈ 55,4); las comisiones son ≈0,06 SOL.
**Ningún pago capturado cierra sus cuentas**: el programa de búfer tiene instrucción de cierre (se usa en `trial.mjs`) pero el relay no la ejecuta, así que esa renta queda depositada.

**2. Estrategias de subida** (`bench-01` y `bench-02`, dos observaciones; Apple M1 Max de 10 núcleos, validador Agave 3.1.10, programa de búfer `887788bb…`; cada caso comprueba que los bytes guardados son los del wire archivado):

| Estrategia | s por trozo (obs. 1 / obs. 2) | Subida completa del envío, 3.302 trozos | Aceleración frente al relay real (0,541 s/trozo) |
|---|---|---|---|
| Confirmar cada trozo antes del siguiente, sondeo cada 50 ms (150 trozos) | 0,485 / 0,541 | ≈ 1.600 / 1.785 s | ≈ 1× |
| Cadencia del relay: blockhash, simulación previa, envío con preflight, pausa de 150 ms, 2 lecturas de la cuenta (150 trozos) | 0,485 / 0,542 | ≈ 1.600 / 1.790 s | ≈ 1× |
| Ventana de 8, con barrera de lote | 0,0667 / 0,0676 | 220 / 223 s | ≈ 8× |
| Ventana de 32, con barrera de lote | 0,0169 / 0,0169 | 56,0 / 55,9 s | ≈ 32× |
| Ventana de 128, con barrera de lote | 0,0041 / 0,0041 | 13,7 / 13,7 s | ≈ 132× |
| 64 trabajadores sin barrera | 0,0084 / 0,0084 | 27,9 / 27,9 s | ≈ 64× |
| 64 trabajadores, carga del tamaño de la retirada (4.452 trozos) | 0,0084 / 0,0084 | 37,4 / 37,4 s | — |

Lecturas: (a) las estrategias con ventana se reproducen entre observaciones dentro del 1,5 %. (b) Confirmar de uno en uno cuesta lo mismo con o sin simulaciones, pausas y lecturas: el suelo es la confirmación (≈1,2–1,35 slots de 400 ms).
La cadencia secuencial varió entre observaciones (0,485 frente a 0,541 s); en la segunda coincide con la del relay real (0,541). No he identificado la causa de esa variación (hipótesis: la fase del sondeo respecto al reloj de slots). Por eso
**retiro lo que dije antes de una diferencia inexplicada del 10 % entre mi réplica y el relay real**: es variación entre ejecuciones. (c) Leer la cuenta completa de 3 MB tarda 11 ms (mediana de 5). (d) La batería original, con lotes de 32,
subió 4.347 trozos en 66 s (≈0,0152 s/trozo): coincide con mi ventana de 32.

**3. Anchura y tamaño.** La sonda reproduce **exactamente** los dos controles positivos (envío v2 = 10.406 columnas, envío v3 = 7.525) y mide la **retirada v2 en 10.729 columnas** (6.795 registros, 148 bloques de Keccak).
Con solo los dos envíos (3.893.829 B y 2.968.715 B) la recta es **321,11 B por columna + 552 KB**, y predice las retiradas archivadas (prueba de 3.985.621 y 4.002.466 B) con errores de **+0,30 % y −0,12 %**, un punto no usado en el ajuste.
La pendiente tiene explicación previa: 256 B de filas abiertas (64 consultas × 4 B) + 64 B de aperturas fuera de dominio (2 puntos × 8 coeficientes × 4 B) = 320.
Si la retirada ganara la misma reducción absoluta que el envío v3 (−2.881 columnas), el modelo da ≈3,07 MB en vez de ≈4,0 MB (**hipótesis**: no se sabe si el cambio de enlace público de v3 es aplicable a esa relación).
**Predicción fallida, registrada antes de compilar** (`width-probe/PREDICTION.txt`): esperaba ≈10.214 columnas (aceptado 9.900–10.500) a partir del cómputo de la etapa Merkle; salió 10.729 (+5 %). Causa probable: esa etapa no es proporcional
solo a la anchura (un ajuste de dos puntos da 58,3 K CU por columna + 84 M CU fijos); es un ajuste de dos puntos, no una validación.

## Proyección (aritmética mía sobre las medidas, NO medida de extremo a extremo)

Tiempo de un pago = transacciones × ≈0,54 s. Sustituyendo solo la fase de subida por una ventana de 128 (o de 32):

| | Hoy | Subida por ventanas | Además, verificador al 90 % del tope de CU* |
|---|---|---|---|
| Envío | ≈ 46 min | ≈ 17 min (−62 a −64 %) | ≈ 12 min (−73 a −75 %) |
| Retirada | ≈ 61 min | ≈ 21–22 min (−63 a −65 %) | ≈ 15 min (−75 a −76 %) |

\* El emisor pide el máximo de trabajo por etapa, simula y, si se pasa del cómputo, lo divide entre dos; por eso las etapas rinden entre un 48 % y un 87 % del tope. Si pudiera dimensionarlas al 90 %
bastarían ≈1.252 transacciones en el envío (frente a 1.812) y ≈1.580 en la retirada (frente a 2.340). Supone que el cómputo crece linealmente con el trabajo pedido, que **no he verificado**.
Con empaquetado perfecto al 100 % las cotas son 1.127 y 1.420. Lo que queda tras ambos cambios son las etapas del verificador, en serie: no se pueden enviar en ventana porque cada una lee el estado que dejó la anterior.

## Qué habría que cambiar en el relay (hecho después: `../solana-relay-windowed-v1`)

**Actualización (2026-11-01):** la subida por ventanas se implementó como revisión nueva y cualificada (`../solana-relay-windowed-v1`, ventana de 64) y se midió de extremo a extremo (`full-05`): relay 1.010 s en el envío y 1.344 s en la retirada, frente a 2.719 y 3.513 s;
la proyección de este documento (≈17 y ≈21–22 min) se cumplió (16,8 y 22,4 min). Lo que sigue sin hacer es el dimensionado de etapas y el cierre de cuentas. El texto de abajo es el análisis previo a la implementación.

El diario (`solana-private-relay-v1/relay-publication.mjs`) admite **un único intento pendiente** (`pending`), firma y lo guarda de forma duradera antes de liberar los bytes, y no deja preparar otro
mientras haya uno sin resolver. La subida por ventanas exige: una acción `chunks` con una lista de trozos (hoy `chunk` es uno solo); `pending` como lista para esa acción; una confirmación duradera por
lote en vez de dos por transacción; reconciliación al reiniciar (qué trozos faltan lo dice la lectura exacta de la cuenta, que la política ya hace); y contar los reintentos dentro de los topes de
financiación (12.000 intentos, 80 SOL por petición). Los trozos son idempotentes (la batería comprueba que el programa cuenta una vez el reintento exacto y rechaza uno distinto, un escritor no autorizado y un índice fuera de rango),
lo que hace segura la repetición, pero esto cambia código cualificado y exige una revisión nueva con sus pruebas y mutantes; no es un parche.
El dimensionado de etapas también toca `publication-sender.mjs`. El cierre de las cuentas para recuperar la renta es una acción más que hoy no existe.

## Límites y qué NO se ha verificado

- Es un validador local de un nodo: no hay red real, pérdida de paquetes, prioridad ni límites de cómputo por cuenta de un bloque. En mainnet, los 1,6–2,0 mil millones de CU del verificador por pago son un coste real aparte.
- Las medidas de subida son de bytes al programa de búfer, no del relay con la subida integrada; no hay pago completo con ventanas ni se ha probado su recuperación tras un reinicio.
- Dos observaciones en un solo Mac; los tiempos no son estadística ni un resultado de mainnet. La variación de las estrategias secuenciales entre observaciones (11 %) no está explicada.
- Los cuatro pagos archivados son de `privacy-live-02`; el relay actual puede diferir en detalles.
- La proyección del dimensionado al 90 % supone cómputo lineal en el trabajo pedido.
- Nada de esto cambia el estado criptográfico: parámetros, pruebas y seguridad no se tocan.

## Reproducción

```
python3 -B analyze_capsule_v2.py NUEVA-ETIQUETA
python3 -B run_bench.py NUEVA-ETIQUETA            # ≈ 12 min, serializa con offline_guard, exige que no haya otro validador
cd width-probe && ./cargo-local.sh build --offline && ./target/debug/zk9-width-probe
python3 -B size_model.py NUEVA-ETIQUETA
```
