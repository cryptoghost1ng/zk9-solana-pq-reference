ZK9 — laboratorio de retiradas nativas, candidato separado.
Solo claves/fondos sintéticos. No toca CURRENT, wallet instalada ni red pública.

Usar el Python aislado documentado en los traspasos, siempre -E -s -B.
Dependencias locales indicadas en Cargo.lock y evidence/environment-01.json.
No descargar/actualizar dependencias automáticamente ni cambiar el shell global.
Esta distribución requiere los workspaces locales ya fijados; no es portable.

Preparación en work/pq-private-withdraw-v1:
  sh go-local.sh build -o ../fixture-helper .
  sh cargo-local.sh test --release --offline --locked --lib
  sh cargo-local.sh build --release --offline --locked --bin qualify
  sh cargo-local.sh metadata --offline --locked --format-version 1 > evidence/cargo-metadata.json
  PYTHON -E -s -B capture_environment.py environment-01.json
No sobrescribir evidencia existente: para reproducir en otro directorio, conservar
rutas relativas a los workspaces y usar nuevas etiquetas/registro de entorno.

Ensayos en SERIE, sin otros builds/validadores del laboratorio:
  PYTHON -E -s -B run_qualification.py smoke-01 smoke
  PYTHON -E -s -B run_qualification.py qualification-01
  PYTHON -E -s -B run_qualification.py qualification-02
  PYTHON -E -s -B collect.py

Todos los importes están en unidades mínimas. Una retirada revela importe y
destinatario público; el origen privado permanece sujeto a las garantías y
límites del esquema experimental. No es una retirada ejecutada por el nodo.
