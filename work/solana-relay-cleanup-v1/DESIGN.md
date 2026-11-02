# Revisión de limpieza de la publicación patrocinada: cierre de cuentas (candidato local)

Todo local y sintético: un solo Mac, un solo operador, fondos de prueba. **No es la red pública, no demuestra anonimato ni privacidad, no cambia la criptografía.**
Nace de la medición de `full-05` (2026-11-02): el relay deja depositados **≈ 55,7 SOL** por pago completo (≈ 23,7 SOL del envío y ≈ 31,7 SOL de la retirada: la renta del búfer de la prueba y la del recibo del verificador),
porque nunca cierra las cuentas que crea. Los programas ya saben cerrar (búfer opcode 3, verificadores opcode 2; `../solana-rent-recovery-review-v1`, `SOURCE_REVIEW_COMPLETE_NOT_INTEGRATED`).
Esta revisión integra el cierre. **Los archivos congelados y los calificados no se tocan**: todo lo nuevo vive en este directorio y en `../solana-onion-relay-service-v3/serve.mjs`;
`make_revision.py` genera los archivos de aquí desde los calificados por **parches de texto exacto** (cada uno comprobado una sola vez) y deja `evidence/diffs-01` con los `diff -u`.

## Historia: por qué hay un enrutador (hallazgo de `full-06`)

La primera generación de este directorio pasó 60 pruebas y 29 mutantes y **no limpiaba nada en el pago real**. El emisor de liquidación informa `settled` dentro de su propio paso (reconcilia por sí mismo) y el supervisor del servicio deja de dar pasos a una petición en cuanto oye `settled`; el bloque de limpieza, al principio de `LocalRelayTask.step()`, no se alcanzaba nunca. Las pruebas con modelo no podían verlo: la tarea solo se comprobaba como texto y `harness.mjs` no ejecuta `LocalRelayTask.step()`. El pago completo real lo mostró (el relay imprimió `finished` del envío sin ningún evento `cleanup`; las dos cuentas seguían abiertas). Las instrucciones de cierre en sí eran correctas: ejecutadas contra los **programas reales** en el validador que seguía vivo, las dos aterrizaron sin error y devolvieron la renta entera (recibo 2 288 865 600 lamports, búfer 21 477 564 720, menos 5 000 de comisión cada uno, medido en el saldo de cada transacción). La segunda generación (esta) enruta todo resultado por `routeStepResult`; la primera se conserva en `evidence/generation-1-sources` y sus pruebas, con una nota, en `evidence/checks-02` y `mutation-02`.

## Qué cambia

Cuando el pool ha **liquidado** un pago —la transición exacta reconciliada desde el historial validado, no un mensaje del relay ni una firma confirmada—, el relay cierra, **en este orden**,
(1) el recibo del verificador y (2) el búfer de la prueba, y devuelve su renta al sponsor que la pagó. Cada cierre es **un intento firmado más del mismo diario** (durable antes de salir, con su techo de comisión y sus topes),
no un camino nuevo: lo que el diario ya garantiza para publicar (nada sale antes de su commit, un reinicio suelta exactamente los bytes guardados, una caducidad exige prueba) vale igual para limpiar.

| Pieza | Archivo | Frente al calificado |
|---|---|---|
| Política | `cleanup-policy.mjs` | de la política congelada de `../solana-relay-performance-v1/candidate/publication-policy.mjs`: dos pasos fijos más, `buffer-close` (programa de búfer, opcode 3) y `receipt-close` (verificador, opcode 2), sobre las cuentas de la petición y firmados solo por el sponsor |
| Diario | `relay-publication.mjs` | acción `close` con `which` ∈ {`receipt`,`buffer`}: ningún otro destino, ningún campo extra |
| Emisor | `publication-sender.mjs` | modo limpieza (`beginCleanup()`): elige cerrar el recibo si existe; si no, comprueba que el búfer **sigue sellado, completo y con exactamente la prueba que tenemos** y lo cierra; si no queda nada, `cleaned`. El efecto de un cierre es que **la cuenta ya no exista** (se lee, no se confía en el estado de la transacción) |
| Tarea | `relay-task.mjs` | opción `cleanup` (booleana, validada antes de reservar fondos, por defecto sí). Solo un pago **`settled`** se limpia (uno `conflicted` conserva sus cuentas hasta que lo mire una persona). Un cierre que aterriza con error **lanza**. Hasta terminar devuelve `phase: 'cleanup'` y solo entonces `settled`. **`routeStepResult`** (exportada) es lo único que hay entre el resultado de un paso de publicación/liquidación y el supervisor: convierte el `settled` que trae el propio emisor de liquidación en `cleanup_pending` mientras queden cuentas abiertas |
| Servicio | `../solana-onion-relay-service-v3/serve.mjs` | el de v2 con `CLEANUP = true` fijado en el archivo, y un evento `cleanup` por cambio de paso |
| Modelo del clúster | `harness.mjs` | el de las ventanas más un recibo, los dos cierres, las devoluciones y lecturas atrasadas |

`relay-repository.mjs`, `relay-funding.mjs` y `publication-adapter.mjs` son reexportaciones de los de `../solana-relay-windowed-v1` (sin copia).

## El protocolo de la limpieza

1. **Cuándo**: solo con la transición del pool reconciliada (`settled`) y la opción activa. El diario sigue enlazado durante la limpieza (`isSettling` también es cierto mientras se limpia).
2. **Qué**: primero el recibo, luego el búfer. Un recibo ausente no impide cerrar el búfer, ni a la inversa. Con las dos cuentas ausentes no se envía nada.
3. **Antes de cerrar el búfer** se vuelve a leer: debe estar sellado y sin trozos pendientes, y `journal.buffer` comprueba byte a byte que guarda exactamente la prueba de la petición. Es la evidencia pública para una auditoría independiente; la prueba también queda en `requests/<id>.request` del relay.
4. **Firmar y guardar**: igual que cualquier paso: probar sin firmar, firmar, verificar contra la política, guardar en un commit con su débito (un techo de comisión), soltar.
5. **Resolver**: confirmado solo cuando la cuenta **ya no existe**; si el nodo contesta con una lectura atrasada, el paso queda `awaiting_progress` y no se da por hecho. Caducado solo con la prueba habitual (firma ausente en dos consultas y altura de bloque posterior).
6. **Fallar**: un cierre que aterriza con error se registra como `failed`, la cuenta se queda y la tarea lanza; el supervisor reintenta y aparca tras cinco fallos seguidos. El tope de intentos por petición cuenta también los cierres.
7. **Reiniciar**: lo guardado manda; un reinicio entre los dos cierres no repite el primero y termina el segundo; tras un commit sin envío se suelta lo guardado sin firmar otra vez.

## Qué sigue sin hacer esta revisión (límites, no fallos)

- **El nivel de compromiso es el de la reconciliación existente (`confirmed`)**, no `finalized`: si una liquidación confirmada se revirtiera tras cerrar el búfer, habría que volver a subir la prueba. Es el mismo riesgo de reorganización que ya tiene el relay al dar un pago por liquidado; en un clúster real convendría esperar a `finalized`.
- **La reserva de fondos no se acredita**: el tope total (`totalLamports` de `serve.mjs`) sigue contando la renta que ya volvió. Un relay de larga vida necesita que el operador lo reinicie o lo suba; reciclar la reserva automáticamente exigiría una transición contable durable (la revisión de recuperación lo desaconseja sin ella).
- **El relay da por cerrada una cuenta ausente**; no verifica la cuantía devuelta. La cuantía la mide el conductor de `full-06` con el saldo real del sponsor, no el relay.
- **Admisión de uno en uno**: mientras limpia (segundos) el relay responde `busy` a una petición nueva.
- **Un pago `conflicted` no se limpia** y no hay herramienta manual todavía.
- **Dos procesos del relay sobre la misma base** no se prueban aparte para la limpieza; dependen de la misma concurrencia optimista del diario que la publicación.
- **El modelo del clúster** (`harness.mjs`) codifica lo que dicen las fuentes de los programas; que los binarios fijados se comportan así solo lo muestra el pago completo real (abajo).

## Qué está verificado en este directorio

- **`checks.mjs`: las 40 pruebas de las ventanas, sin una coma cambiada** (regresión), y **`cleanup-checks.mjs`: 22 pruebas nuevas** (`run_checks.py`, `evidence/checks-03`; `checks-01` se conserva: el recuento
  de la propia corredora estaba mal; `checks-02` es de la primera generación; ver sus `NOTE.txt`), con SQLite real, firmas Ed25519 reales, el decodificador real y el modelo del clúster:
  - **C1–C4**: orden recibo → búfer, cada uno una vez, y el sponsor recupera las dos rentas sin que se mueva nada más; nada se cierra mientras se publica; el búfer solo se cierra si guarda exactamente nuestra prueba; nunca uno sin sellar o incompleto.
  - **C5–C6**: las instrucciones de cierre son exactamente las del verificador y del programa de búfer, sobre las cuentas de la petición, firmadas solo por el sponsor; no se puede nombrar otro destino ni añadir campos; un cierre guardado y rebautizado se rechaza al reabrir.
  - **C7–C12**: reinicio entre los cierres; reinicio tras el commit y antes del envío; cierre que aterriza con error (queda, y el tope de intentos lo acota); respuesta de envío incierta; caducidad con prueba; un cierre cuenta solo si la cuenta ya no existe (lectura atrasada).
  - **C13–C16**: el techo de comisión por cierre y el tope por petición; nada que hacer cuando ya está todo cerrado (y nadie resucita una cuenta cerrada); recibo o búfer ausentes; la retirada se limpia igual.
  - **C17–C20**: la tarea valida la opción antes de reservar fondos y limpia por defecto; solo un pago liquidado, fallo fatal y diario enlazado (estático); un descriptor guardado no canónico (trabajo o renta) se rechaza para los dos cierres; el modo publicación sigue diciendo `verified`.
  - **C21–C22**: el enrutador retiene `settled` mientras haya cuentas abiertas y solo entonces (dinámico: opción desactivada, ya limpiado, estado de la tarea, resultados que no son `settled`, opciones no booleanas, el `id`); la tarea le pasa todo resultado de publicación y liquidación (estático).
- **`mutation_control.py`: 36 mutantes** (`evidence/mutation-03`; `mutation-01` y `mutation-02` se conservan como historia, ver sus `NOTE.txt`): cada uno aplicado a una copia y detectado por una prueba **con nombre**.
- **Pago completo real** (`../solana-onion-e2e-v1/run_payment_v5.py`). Cuatro ejecuciones, todas conservadas: `full-06` (primera generación; el fallo que encontró el defecto del enrutado), `full-07` (56 de 57: falló una cota mía) y `full-08` (56 de 59: el validador de prueba había olvidado las transacciones
  antiguas, ver sus `NOTE.txt`) y **`full-09`: `PASS_ONION_PAYMENT_FULL`, 59 de 59**. En `full-09` el validador conserva todo su libro mayor (`managed-validator-ledger.mjs`) y el conductor lo suma entero: 11.918 transacciones, ninguna no disponible, y la suma de los cambios de saldo del sponsor
  coincide con la diferencia de saldo (128.592.520 lamports). Las cuatro cuentas (recibo y búfer de cada pago) devolvieron exactamente lo depositado; el relay cerró recibo y luego búfer de los dos pagos y dio la petición por terminada ≈1 s después; lo demás que pagó el sponsor es
  59.605.000 de comisiones (11.913 transacciones a 5.000 y 4 de creación a 10.000) y **68.987.520 de registros permanentes del pool, exactamente la predicción escrita antes de la ejecución** a partir de la fuente del programa.
  Registro: `evidence/cleanup-qualification-02` = `PASS_CLEANUP_QUALIFICATION` (`cleanup-qualification-01` queda como historia de `full-07` y `full-08`). Una sola ejecución con este libro mayor (no una pareja), una máquina, validador local. Las pruebas de la tarea (C17, C18, C20, C22) son en parte estáticas; la cadena tarea → servicio → relay real solo la ejerce un pago completo.
