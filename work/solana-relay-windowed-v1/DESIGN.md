# Revisión con ventanas de la publicación patrocinada (candidato local)

Todo local y sintético: un solo Mac, un solo operador, fondos de prueba. **No es la red pública, no demuestra anonimato ni privacidad, no cambia la criptografía.**
Nace de la medición de `../solana-upload-pipeline-v1` (2026-11-01): el 65 % de las transacciones de un pago patrocinado son trozos de subida de 900 B que el relay confirma **de uno en uno**
(≈ 0,54 s cada uno, el tiempo de una confirmación), y subirlos por ventanas costó 30–120× menos en el programa real de búfer. Esta revisión lo lleva al relay.
**Los archivos congelados no se tocan**: todo lo nuevo vive en este directorio y en `../solana-onion-relay-service-v2/serve.mjs`; `run_checks.py` comprueba los hashes de los cinco archivos de los que deriva.

## Qué cambia

Hasta ahora el diario de publicación (`../solana-private-relay-v1/relay-publication.mjs`) admitía **un único intento pendiente**: firmaba una transacción, la hacía durable, la soltaba, y no preparaba otra hasta resolverla.
La revisión cambia `pending` a una **lista**. Crear cuentas, sellar el búfer y cada paso del verificador siguen siendo de uno en uno; **solo los trozos** del búfer pueden estar varios a la vez
(hasta `MAX_WINDOW = 128` distintos), porque el programa de búfer cuenta una vez el reintento exacto de un trozo y los trozos no dependen unos de otros.

| Pieza | Archivo | Frente al congelado |
|---|---|---|
| Diario v2 | `relay-publication.mjs` | `pending` es una lista; `prepareChunks` / `simulations` / `signBatch` / `resolveMany`; versión `zk9-sponsored-publication-journal-v2` |
| Repositorio | `relay-repository.mjs` | misma base SQLite; en la vía financiada la lista solo puede encogerse o pasar de vacía a una ventana entera; registro de ventana hasta 512 KiB (el resto sigue en 32 KiB) |
| Financiación | `relay-funding.mjs` | cotiza una ventana como **N techos de comisión** (más la renta de una creación) y comprueba el saldo del sponsor para toda ella; la liquidación sigue usando la función congelada |
| Emisor | `publication-sender.mjs` | firma una ventana, la guarda en **un** commit, la suelta junta, la resuelve junta; ventana 1 = el emisor original |
| Adaptador | `publication-adapter.mjs` | la superficie del diario que ve el emisor (estaba en línea en `relay-task.mjs`) |
| Tarea | `relay-task.mjs` | `LocalRelayTask` con el diario v2, el emisor con ventana y la financiación v2; la liquidación es la congelada |
| Servicio | `../solana-onion-relay-service-v2/serve.mjs` | el mismo `serve.mjs` con esos módulos y `WINDOW = 64`; `relay-http`, `relay-store` y `relay-tasks` son los del servicio v1 sin copia |

`evidence/diffs-01` guarda los `diff -u` contra los congelados. La derivación de cuentas (`relay-transport.mjs`) es la misma: una petición da las mismas cuentas con o sin ventanas.

## El protocolo de una ventana

1. **Elegir**: el búfer dice qué trozos faltan; la ventana son los primeros `window` (ni uno más).
2. **Probar**: una transacción sin firmar por trozo, simulada en el nodo; si **cualquiera** es rechazada se para antes de firmar nada.
3. **Firmar y guardar**: todas las transacciones se firman, se verifican contra la política y se guardan **en un solo commit** junto con **un solo débito** (N techos de comisión). Hasta que ese commit vuelve, ningún byte sale.
4. **Soltar**: se envían las que el clúster aún no conoce, con simulación previa del propio nodo.
5. **Resolver**: con **una** consulta de estados se separan las aterrizadas; solo se dan por confirmadas las que además **se ven en el búfer** (la misma comprobación de efecto del emisor original); las confirmadas se resuelven juntas en **un** commit.
6. **Caducar**: solo cuando la altura de bloque finalizada pasa la vida del blockhash y una **segunda** consulta no encuentra la firma, se resuelve como caducada (con la prueba que el diario exige: `missingAfterExpiry` y altura mayor). Una firma que aparece en la segunda consulta se confirma, no se caduca; una solo `processed` ni se confirma ni se caduca ni se reenvía con un blockhash muerto.
7. **Fallar**: un trozo que aterriza con error se registra como `failed` (y es lo último que muestra `last`); se resuelve el resto y el paso **no sigue en silencio** (lanza), de modo que el supervisor lo cuenta como fallo y aparca tras cinco seguidos.
8. **Reiniciar**: lo guardado manda. Una ventana con commit pero sin envío se suelta tal cual (los mismos bytes, sin firmar otra vez); una ventana mayor que la configurada tras el reinicio se termina igualmente; las ventanas siguientes respetan el tamaño nuevo.

Se descartó a propósito la segunda simulación **firmada** previa a cada envío (la del emisor original): el `sendTransaction` con preflight del nodo hace la misma comprobación y un rechazo acaba igual (no aterriza y queda pendiente).

## Contabilidad y límites

- Cada intento firmado cuesta el **techo** de comisión del operador (10 000 lamports en `serve.mjs`), no la cotización; una ventana de 64 se debita como 64 techos de una vez. La renta de crear cuentas se suma como antes.
- Los topes de `LocalRelayTask` se aplican a la lista entera: 12 000 intentos firmados por petición (cuenta cada trozo de cada ventana, también los reintentos tras una caducidad) y 80 SOL por petición.
- Un registro de ventana de 128 intentos pesa ≈ 230 KB; el límite de 512 KiB se dimensionó para 128 (una prueba fija `MAX_WINDOW = 128`).

## Qué está verificado en este directorio

- **`checks.mjs`: 40 pruebas** (`evidence/checks-02`, `run_checks.py`; `checks-01` se conserva superado) con SQLite real, firmas Ed25519 reales, el decodificador de transacciones real y un modelo del clúster
  (`harness.mjs`: formato real del búfer, reglas reales de trozo y sello, ciclo de vida del blockhash, estados con latencia, inyección de fallos):
  - **J1–J9, el diario**: arranca vacío; una ventana se firma y se guarda en **un** commit con **un** débito de N techos; nada nuevo mientras haya algo pendiente; la ventana debe ser no vacía, distinta, en rango y ≤ 128;
    una lista manipulada (otra `raw`, duplicada, un sello junto a trozos, más pendientes que firmas, el objeto del formato antiguo, la etiqueta v1, un hash de petición o un transporte ajeno, 129 trozos válidos) se rechaza al reabrir;
    `resolveMany` resuelve solo lo listado y rechaza lo demás (también un resultado inválido en una entrada que no es la última); una caducidad exige la prueba de firma ausente **y** altura posterior; los tickets son de un solo tipo y de una sola vez.
  - **R1–R10, repositorio y financiación**: se cobra el techo (no la cotización) por intento; un encogimiento no cuesta nada y un débito sobre una resolución se rechaza; solo se entra en una lista vacía y un intento retenido no se reemplaza ni se duplica;
    el tope por petición acota el coste **acumulado** y una ventana rechazada no guarda ni cobra; el tope de intentos cuenta la ventana entera; cualquier comisión fuera de tope, nula, o un saldo insuficiente o más viejo que las cotizaciones rechaza **toda** la ventana;
    la liquidación conserva sus reglas de un solo intento; tamaños de registro; una ventana y su débito son durables **juntos o ninguno de los dos** con SIGKILL del proceso (antes y después del commit); a la API de comisiones solo va el mensaje sin firmar.
  - **S1–S18, el emisor**: una fase de trozos completa con ventana 128 (cada trozo una vez, un commit para firmar y otro para resolver cada ventana, el búfer igual al wire, nada se suelta antes de su commit); ventana 1 = emisor original;
    reinicio tras el commit y antes del envío (se sueltan exactamente los bytes guardados, sin firmar otra vez) y con otra ventana configurada; aterrizaje parcial (solo se reenvía lo que el clúster no vio, con los mismos bytes);
    caducidad con prueba (y el trozo vuelve en una ventana nueva); una firma que aparece en la segunda consulta se confirma; un trozo que aterriza con error se registra como fallido y el paso no sigue en silencio;
    efecto no visible en el búfer = `awaiting_progress`; commit que falla = nada suelto, nada pendiente, nada cobrado; simulación rechazada = nada firmado; solo `processed` ni confirma ni caduca ni reenvía con un blockhash muerto;
    un RPC incoherente (otra firma, lista corta de estados, pendientes cambiados antes del reenvío) se rechaza.
  - **A1–A3, adaptador y tarea**: el id de petición se comprueba en cada llamada; `LocalRelayTask.open` valida la ventana antes de reservar fondos, enlaza el diario y la financiación v2 y reabre igual; el cableado hacia el emisor con ventana (estático).
- **Control de mutaciones: 79 mutantes, todos detectados por una prueba con nombre** (`evidence/mutation-03`; `mutation_control.py`; 28 en el diario, 11 en el repositorio, 10 en la financiación, 21 en el emisor, 4 en el adaptador y 5 en la tarea).
  `mutation-01` falló por mi propia prueba A2 (ruta del enlace simbólico frente a la ruta real de los hashes) y `mutation-02` detectó 77 de 79: los dos huecos eran de las pruebas (J6 y S9) y se cerraron antes de `mutation-03`; ambos se conservan con su nota.
- Los cinco archivos congelados de los que deriva siguen **byte a byte** como estaban al empezar (`run_checks.py` los pinea y falla si cambia uno).

## Ejecución en el sistema completo (2026-11-01)

Con `../solana-onion-e2e-v1/run_payment_v4.py` (el conductor v3 apuntado a `../solana-onion-relay-service-v2`; mismas comprobaciones, más: las puertas de esta revisión, cada muestra de firmas del sponsor y una lectura de solo lectura del diario SQLite del relay):
validador local con los programas reales, Tor local de una máquina con dos servicios onion, Chrome 156 desechable, el relay con su sponsor propio.

- **`smoke-07`** PASS 32/32: prueba de un envío de 10 en la extensión (138 s), relay con ventana 64; **1.602 firmas del sponsor en los primeros ≈14 s de publicación** (el relay de uno en uno hace ≈30 en ese tiempo); SIGKILL del relay en plena subida de trozos,
  reapertura de la misma petición (mismo sha256, mismo sponsor); a los ≈35 s de publicación el diario tenía 3.137 intentos firmados, 0 pendientes.
- **`full-05`** PASS 50/50: envío de 10 + retirada pública de 1, un SIGKILL del relay por pago a mitad de la subida y la misma petición reabierta las dos veces; el validador confirma bóveda 12 y +1 al destinatario; la autoridad de la cartera no aparece en ninguna transacción del sponsor
  (con control positivo); la extensión no hizo ninguna petición HTTP directa; `task_error` 0, `parked` 0.

| | `full-04` (relay de uno en uno) | `full-05` (ventana 64) |
|---|---|---|
| Envío: relay, de admitido a liquidado | 2.719 s · 15.947 pasos | **1.010 s · 5.972 pasos** (−63 %) |
| Envío: cartera, de aprobar a liquidado | 2.883 s | 1.174 s (−59 %) |
| Retirada: relay | 3.513 s · 19.300 pasos | **1.344 s · 7.368 pasos** (−62 %) |
| Retirada: cartera | 3.716 s | 1.523 s (−59 %) |
| Subida de los trozos, envío (3.302) | ≈1.790 s | entre 35 y 57 s (con el SIGKILL dentro) |
| Subida de los trozos, retirada (≈4.450) | ≈2.400 s | entre 70 y 90 s (con el SIGKILL dentro) |
| Verificador (en serie, sin cambios) | ≈16 min · ≈21 min | ≈16 min · ≈21 min |
| Intentos firmados en el diario | — | 5.127 · 6.800 |
| Firmas del sponsor | 11.876 | 11.828 |
| Bloqueos automáticos de la cartera (5 min) | 9 y 11 | 3 y 4 |
| SOL sintéticos gastados por el sponsor | 55,57 | 55,72 (casi todo, renta de cuentas que nadie cierra) |

La proyección de la medición (≈17 min el envío, ≈21–22 min la retirada) se cumple: 16,8 y 22,4 min de relay. Lo que queda es el verificador, en serie, y el cierre de cuentas.
`evidence/windowed-qualification-01` (`qualify.py`): PASS_WINDOWED_RELAY_QUALIFICATION. **Una sola ejecución completa**: no hay pareja idéntica como para `full-03`/`full-04`.

## Límites

- El control de mutaciones y las pruebas usan un **modelo** del clúster (`harness.mjs`): formato real del búfer, reglas reales de trozo y sello, transacciones decodificadas y verificadas con el decodificador real, SQLite real y firmas Ed25519 reales;
  no modelan el programa verificador, la piscina, forks ni latencias reales.
- Es un validador local de un nodo: no hay pérdida de paquetes real, prioridad de comisión, límites por cuenta y por bloque ni admisión por QUIC de una red pública. Una ventana de 64 envíos simultáneos **no se ha probado en mainnet**.
- Los diarios v1 y v2 no son intercambiables: una petición a medias con el código congelado no se adopta con el nuevo (no hay migración).
- No se cierran las cuentas ni se recupera su renta; el dimensionado de las etapas del verificador no cambia (siguen en serie). Sin privacidad demostrada: semillas públicas de fixture, un operador, Tor local de una sola máquina.
