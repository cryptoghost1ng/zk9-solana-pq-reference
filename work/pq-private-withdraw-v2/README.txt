ZK9 — laboratorio de retiradas nativas, candidato32 separado.
Solo claves/fondos sintéticos. No toca CURRENT, wallet instalada ni red pública.

Usar el Python aislado documentado en los traspasos, siempre -E -s -B.
Dependencias locales indicadas en Cargo.lock y evidence/environment-01.json.
No descargar/actualizar dependencias automáticamente ni cambiar el shell global.
Esta distribución requiere los workspaces locales ya fijados; no es portable.

Preparación en work/pq-private-withdraw-v2:
  sh go-local.sh build -o ../fixture-helper .
  sh cargo-local.sh test --release --offline --locked --lib
  sh cargo-local.sh build --release --offline --locked --lib --bin qualify
  sh cargo-local.sh metadata --offline --locked --format-version 1 > evidence/cargo-metadata.json
  PYTHON -E -s -B capture_environment.py environment-01.json
No sobrescribir evidencia existente: para reproducir en otro directorio, conservar
rutas relativas a los workspaces y usar nuevas etiquetas/registro de entorno.

Ensayos en SERIE, sin otros builds/validadores del laboratorio:
  PYTHON -E -s -B run_qualification.py smoke-01 smoke
  PYTHON -E -s -B run_qualification.py qualification-01
  PYTHON -E -s -B run_qualification.py qualification-02
  PYTHON -E -s -B run_abi.py abi-01 qualification-01
  PYTHON -E -s -B run_abi.py abi-02 qualification-02
  PYTHON -E -s -B collect.py

Todos los importes están en unidades mínimas. Una retirada revela importe y
destinatario público; el origen privado permanece sujeto a las garantías y
límites del esquema experimental. No es una retirada ejecutada por el nodo.

Antes de las tandas, compilar c-tests/verify.c enlazando target/release/
libzk9_private_withdraw32_lab.a con clang (ver evidence/c-build-01.log y
c-toolchain.json). El driver exige bin/c-verify existente y capturado.
reference20.wire es la prueba real congelada del padre, verificada antes del
rechazo cruzado. No volver a generar el padre ni cambiar archivos capturados.
El candidato32 todavía no abona la cuenta: requiere registro protected del
keeper, transacción firmada, contabilidad atómica, escaneo y UI.
