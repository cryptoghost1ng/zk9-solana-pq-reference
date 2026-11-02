# Servicio relay con ventanas (candidato local)

Todo local y sintético: un solo Mac, un solo operador, fondos de prueba. **No es la red pública, no demuestra anonimato ni privacidad.**
Es el servicio de `../solana-onion-relay-service-v1` (que sigue congelado, con su evidencia) con **una sola diferencia de fondo**: el relay llena el búfer de la prueba **en ventanas** de trozos en vez de
de uno en uno. La razón y las pruebas están en `../solana-relay-windowed-v1/DESIGN.md`; la medición que lo motivó, en `../solana-upload-pipeline-v1/DESIGN.md`.

## Qué es esto

Solo `serve.mjs`: la misma composición del servicio v1 (escucha solo en 127.0.0.1, sponsor y semilla de transporte propios y persistentes, una petición activa, reapertura desde el almacén tras un fallo o un reinicio)
con tres cambios, que se ven con `diff -u ../solana-onion-relay-service-v1/serve.mjs serve.mjs` (también en `../solana-relay-windowed-v1/evidence/diffs-01/serve.diff`):

| Cambio | Detalle |
|---|---|
| Módulos | `LocalRelayTask` y `RelayRepository` salen de `../solana-relay-windowed-v1` (diario v2, financiación v2, emisor con ventana); la liquidación, la petición, la oferta y el verificador nativo siguen siendo los congelados |
| Ventana | `WINDOW = 64`: hasta 64 trozos distintos firmados, guardados en un commit, soltados y resueltos juntos; lo fija el hash de este archivo, no el entorno |
| Evento `ready` | lleva `window`, para que la evidencia diga con qué ventana corrió |

`relay-http.mjs`, `relay-store.mjs` y `relay-tasks.mjs` NO se copian: se importan del servicio v1 tal cual. El resto (cabecera `Host`, dos rutas, un solo pago activo, sin estado en la respuesta) no cambia.

## Cómo se ejercita

`../solana-onion-e2e-v1/run_payment_v4.py` es el conductor v3 sin cambios de lógica, apuntado a este servicio, con tres añadidos de evidencia: comprueba las puertas de la revisión
(`checks-02` y `mutation-03` de `solana-relay-windowed-v1`), registra cada muestra de firmas del sponsor, y lee del diario SQLite del relay (solo lectura) cuántos intentos se firmaron, el tamaño del registro y lo debitado.
Mismos modos: `smoke-NN` (mata al relay con SIGKILL a mitad de la publicación y comprueba que reabre la misma petición) y `full-NN` (envío de 10 + retirada pública de 1).

## Límites

Los de `../solana-relay-windowed-v1/DESIGN.md`, y además: un solo pago activo, sin límites de tasa ni política de abuso; sin privacidad demostrada (semillas públicas de fixture, un operador, Tor local de una sola máquina).
