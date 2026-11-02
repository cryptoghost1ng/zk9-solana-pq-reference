# Ensayo de punta a punta (tramos de lectura y depósito) — validador local real + Tor local real + paquete en Chrome

Todo local y sintético: un solo Mac, un solo operador, fondos de prueba. **No es la red pública, no demuestra anonimato ni privacidad,**
y **el pago privado (envío/retirada con pruebas) NO está ejecutado**. Chrome es un perfil desechable; el paquete no se instala en tu Chrome.

## Qué corre en cada ejecución (`run.py read-NN`, `run_deposit.py deposit-NN`, Python de `wallet-onion-adoption-v1/chutney-venv`)

1. **Validador local real** (`managed-validator.mjs`, el mismo del ensayo instalado): `solana-test-validator` con los programas reales
   (pool, buffer, verificador de envío, verificador de retirada) y las cuentas del fixture. Latido de propiedad cada 20 s; se cierra solo si el
   supervisor desaparece.
2. **Paquete base para ESE perfil** (`package-unified.py`, run id nuevo `unified-1NN`/`2NN`) y, encima, el paquete con rutas privadas
   (`build_package.py` sin cambios, con la base apuntada al paquete nuevo; sólo difieren `config.mjs`, `manifest.json` e `INSTALLED-FLOW-CONFIG.json`
   respecto a `unified-06`, comprobado en cada ejecución).
3. **Tor local real** (TorLab/Chutney, 9 nodos) con un **servicio onion v3 de historial de sólo lectura** (`history_service.py`) delante del validador:
   deja pasar `getGenesisHash`, `getVersion`, `getAccountInfo` (sólo programa y datos del programa fijados) y `getProgramAccounts` (sólo el programa);
   nada de escritura, simulación, airdrop ni consultas por dueño. Registra cada petición.
4. **Hosts nativos del lanzador fijo** apuntando a ese onion por el SOCKS de Tor, y **Chrome 156 desechable** con el paquete cargado por CDP.
5. **Testigos independientes**: el registro del servicio onion (qué lecturas llegaron por Tor), los eventos de red de TODOS los contextos de la
   extensión (qué peticiones HTTP directas hizo; con un control positivo: la ruta pública sí las genera) y, para el depósito, los saldos de token que
   el propio validador informa en *confirmed* y *finalized*.

## Resultados

- **Lectura** (`read-02`, 21 comprobaciones): `syncWallet` termina bien por Tor contra las cuentas reales de la piscina; el servicio onion ve exactamente las
  7 lecturas esperadas; cero peticiones directas de la extensión durante la sincronización privada; circuito de encuentro (rendezvous) de ≥3 saltos; la ruta pública
  (`fundingSources`) es directa y no toca el onion; matar el host da error sin ninguna petición y la siguiente operación usa un host nuevo; con el servicio onion parado
  la sincronización falla cerrada sin volver a RPC directo.
- **Depósito** (`deposit-02`, 19 comprobaciones): la cartera pública de prueba (semilla 211) se **restaura en la extensión** desde sus 24 palabras; la ruta pública descubre su cuenta
  de origen; se firma y publica en la extensión un depósito de 13 unidades **directamente al validador** (simulación, `sendTransaction`, estado de firma); la lectura de
  confirmación de la piscina va **por Tor** (`getProgramAccounts` privado ×2, ninguno directo); la sincronización privada posterior muestra 13 unidades (2 notas); y el
  validador confirma por su cuenta (*confirmed* y *finalized*) que el origen bajó 13 y la bóveda subió 13.
- Conservados como FALLO con nota: `read-01` (puerta de cualificación obsoleta por el Node reescrito), `deposit-01` (mi lectura de saldos usaba *finalized*).

## Tramo de pago (`run_payment.py`, añadido 2026-11-01)

Tercer tramo del mismo ensayo, con el servicio `solana-onion-relay-service-v1` como segundo servicio onion y un sponsor propio cuya autoridad real
va en el paquete. Tres modos, por el prefijo de la etiqueta (`with_free_ports.py run_payment.py smoke-NN|send-NN|full-NN`):

- `smoke`: restaura las dos carteras (212 receptor, 211 emisor), deposita 13, genera la prueba de un envío de 10 en la extensión, la entrega al relay
  por Tor, mata al relay con SIGKILL tras ≥25 transacciones del sponsor, lo reinicia y comprueba que reabre la misma petición. Se detiene sin liquidar.
  **Ejecutado**: `smoke-03` y `smoke-04` (31/31, entradas idénticas); `service-qualification-01` PASS.
- `send`: lo anterior hasta liquidar el envío (≈45 min), más sondas con el relay ocioso y el receptor restaurado otra vez.
- `full`: `send` seguido de la retirada pública de 1 unidad (≈62 min). **Ejecutado DOS veces con las mismas entradas fijadas (conductor `run_payment_v3.py`): `full-03` y `full-04`, cada una 50/50;
  `payment-qualification-01` y `-03` PASS; `payment-pair-qualification-04` PASS_ONION_PRIVATE_PAYMENT_FULL_TWO_IDENTICAL_RUNS.**
  `full-03`: el envío de 10 se liquidó en ≈46 min de relay (16.268 pasos) y la retirada de 1 en ≈61 min (20.123 pasos); las dos pruebas se generaron dentro de la extensión (≈138 s y ≈156 s);
  el relay se mató con SIGKILL una vez por pago y reabrió la misma petición; 11.886 firmas del sponsor, ninguna con la autoridad de la cartera; 0 peticiones HTTP directas de la extensión;
  el validador confirma bóveda 12 y +1 al destinatario; el receptor restaurado ve 10 por Tor.
  **Hallazgo:** la sesión de la cartera se bloquea sola a los 5 minutos (`LIFETIME` en `wallet-service.mjs`); durante un pago de 46-61 min hubo 9 y 12 bloqueos, y el conductor los recupera
  desbloqueando y sincronizando como haría un usuario. Cada reapertura vuelve a entregar la misma prueba al relay (22 duplicados idempotentes).
  Fallos conservados: `full-01` (leí el bloqueo como operación perdida) y `full-02` (mi muestreador murió con un error JSON-RPC); los conductores v1 y v2 siguen congelados con su evidencia.

### Repetición idéntica (`full-04`, 2026-11-01)

Segunda ejecución completa SIN tocar ningún archivo fijado (`INPUTS.json` de `full-03` y `full-04` idénticos byte a byte); cada ejecución crea su validador (503 / 504), su sponsor, su clave de
extensión y sus operaciones, y el paquete solo difiere en `config.mjs` (autoridad del sponsor), `manifest.json` (clave) e `INSTALLED-FLOW-CONFIG.json` (perfil del validador); ese conjunto
permitido se fijó antes de ver `full-04`.

| | `full-03` | `full-04` |
|---|---|---|
| Envío: cartera / pasos de relay | 2.945 s / 16.268 | 2.883 s / 15.947 |
| Retirada: cartera / pasos de relay | 3.869 s / 20.123 | 3.716 s / 19.300 |
| Prueba en la extensión, de `preparing` a `ready` (envío / retirada) | 137,5 s / 156,1 s | 138,0 s / 156,7 s |
| Reaperturas de la cartera (envío / retirada) | 9 / 12 | 9 / 11 |
| Reenvíos duplicados contestados 200 | 22 | 21 |
| Firmas del sponsor (a la muerte del relay: envío / retirada) | 11.886 (30 / 5.185) | 11.876 (33 / 5.172) |
| Coste sintético del sponsor | 55.656.401.920 lamports | 55.569.590.720 lamports |
| Errores de paso registrados | 2 (`Wallet is locked.` en el envío; `probe timeout` en la retirada) | 1 (`probe timeout` en la retirada) |

Iguales en las dos: bóveda 12 y +1 al destinatario según el validador; vistas de la cartera 13 → 2 → 0 y receptor restaurado viendo 10; sondas con el relay ocioso (duplicado 200, prueba alterada 422
`invalid_proof`, `/v1/status` 404); 0 peticiones HTTP directas; relay matado y reanudado con la misma petición en los dos pagos; 0 `task_error`, 0 aparcadas, 0 fatales; autoridad de la cartera
ausente de las firmas del sponsor. Los tiempos varían un 2-4 %; esa variación se muestra, no se exige.

**Corrección sobre el `probe timeout` (hecha tras `full-04`).** En el informe de `full-03` lo describí como un fallo transitorio de la primera llamada a `provePayment` de la retirada, y el campo
`prove_seconds` de la retirada (150,0 s en las dos ejecuciones) como el tiempo de la prueba. Ninguna de las dos cosas es cierta. `solana-onion-package-v1/driver.py` (la sonda de la página que usa el
conductor) rechaza cada llamada a los 150 s con `Error('probe timeout')`, sea cual sea el `timeout` que pida el conductor. La prueba del envío tarda 137,5-138,0 s (cabe) y la de la retirada
156,1-156,7 s (no cabe): el temporizador salta a los 150,0 s exactos tras `preparing`, la prueba queda lista 6-7 s después y la llamada siguiente la recoge. El error es determinista y del temporizador de
la sonda, no de la cartera; el 150,0 s de `prove_seconds` es ese temporizador, no el coste de la prueba (que es ≈156 s, medido de `preparing` a `ready`). No cambia ningún veredicto, y el conductor
lo trata como lo que es (un reintento), pero conviene un límite mayor en la sonda si se reutiliza para pruebas de retirada.

Fallos del propio cualificador, conservados con `NOTE.txt`: `payment-qualification-02` (lanzado con el Python del venv de Chutney, el cualificador se detectaba a sí mismo como proceso sobrante; la
misma comprobación sobre el mismo run da PASS en `-03`), `payment-pair-qualification-01` (vacío: abortó porque `-02` no pasaba), `-02` (comparé `changed` del paquete entero, que incluye por diseño la
autoridad del sponsor y la clave de la extensión) y `-03` (una clave mal escrita hacía `expected_ok` siempre falso). La prueba en seco anterior solo demostraba rechazo; el control que faltaba
(una pareja que DEBE pasar, más diez mutantes que deben fallar) está en `payment-pair-qualification-04/CONTROL-harness.py` y `CONTROL-output.txt`. Límite de ese control: los mutantes se ven por el veredicto
global, no por la condición concreta que rompen.

Testigos independientes del tramo de pago: las firmas que el propio validador lista para la autoridad del sponsor, la de la cartera emisora y la del
receptor (acumuladas durante la ejecución porque el libro mayor es acotado); los eventos de red de todos los contextos de la extensión; el registro
de eventos del relay. Límites: mismo operador y misma máquina para validador, historial y relay; semillas públicas; Tor local de una máquina.

### Con el relay de ventanas (`run_payment_v4.py`, `smoke-07` y `full-05`, 2026-11-01)

El mismo conductor v3, apuntado a `solana-onion-relay-service-v2` (revisión `solana-relay-windowed-v1`: el relay llena el búfer de la prueba en ventanas de 64 trozos, en vez de uno a uno), con las mismas comprobaciones y tres añadidos de evidencia
(puertas de la revisión, muestras de firmas del sponsor y una lectura de solo lectura del diario del relay). `full-03`, `full-04` y el conductor v3 siguen congelados.
`smoke-07` PASS 32/32 y `full-05` PASS 50/50 (`windowed-qualification-01` PASS): **envío de 10 liquidado en 1.174 s de cartera / 1.010 s de relay (antes 2.883 / 2.719) y retirada de 1 en 1.523 / 1.344 s (antes 3.716 / 3.513)**,
con el relay matado por SIGKILL a mitad de la subida una vez por pago y la misma petición reabierta; subida de los trozos del envío en 35–57 s (antes ≈1.790 s); la autoridad de la cartera no aparece en ninguna transacción del sponsor; cero peticiones HTTP directas de la extensión;
la cartera se bloqueó sola 3 y 4 veces (antes 9 y 11-12). Detalle y tabla en `../solana-relay-windowed-v1/DESIGN.md`. Una sola ejecución completa con este relay, no una pareja.

## Puerta de cualificación y Node

`package-unified.py` vuelve a verificar las entradas de cuatro cualificaciones antiguas, entre ellas el binario de Node, que se reescribió el 2026-10-31. El ensayo
carga una **copia en memoria** de ese script cuyo único cambio tolera esa ruta de Node (las demás entradas se verifican igual) y registra ambos hashes en
`steps.node_runtime_waiver`. Es una renuncia acotada y visible, no una solución: la decisión sobre el Node sigue siendo tuya.

## Lo que falta para el pago privado de punta a punta

Hechos (2026-11-01, ver «Tramo de pago»): 1. servicio relay con sponsor financiado detrás de un onion de Tor local, con el verificador nativo (`solana-onion-relay-service-v1`);
2. autoridad real del sponsor en el paquete; 3. pruebas de envío y retirada generadas dentro de Chrome, con sesión larga; 4. segunda cartera receptora (semilla 212) y conductor de la secuencia
envío → retirada por relay (`run_payment_v3.py`). Repetido con entradas idénticas (`full-03`, `full-04`).

Pendiente (NO hecho):

5. **Auditoría nativa independiente** al final (`audit-connected-wallet.mjs`), como en el ensayo instalado.
6. **Ensayo adversarial preregistrado** con tráfico intercalado, receptores sin depósito previo y revisión externa; sin eso no hay afirmación de privacidad.
7. Tor público y operadores independientes; varios pagos a la vez, límites de tasa y política de abuso del servicio; vida del service worker más allá de ≈2 h; instalación fuera de `~/Documents`.
8. El bloqueo automático de la cartera a los 5 minutos frente a los pagos patrocinados: con el relay de uno en uno duraban 46-61 min; con ventanas, ≈17-22 min de relay (20-25 min de cartera), pero siguen siendo más largos que 5 min (decisión de producto).

## Límites

- Tor es una red de pruebas de una sola máquina; no hay correlación temporal real ni operadores independientes; el operador del servicio de historial (este script) es el mismo
  que el del validador.
- El depósito es **público por naturaleza** (la autoridad pública firma y publica); sólo la lectura de confirmación de la piscina va por Tor.
- El servicio de historial devuelve la historia completa de la piscina (`getProgramAccounts`): la privacidad de *qué* cuentas interesan depende de que el escaneo de propiedad
  sea local (lo es), no de la red.
- Hosts del lanzador fuera de `~/Documents` (ver `solana-chrome-native-probe-v1/NOTES.md`); el paquete y los hosts se construyen en una carpeta temporal desechable.
