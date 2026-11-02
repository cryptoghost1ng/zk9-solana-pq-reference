ZK9 — circuito y constructor nativo para gastar una o dos notas

ALCANCE: laboratorio local, sin fondos reales. No cambia la wallet instalada.
PROTOCOL.txt especifica el cambio incompatible y lo pendiente de integración.
Los paquetes del ejecutable qualify son placeholders sintéticos. No son pagos
enviables al nodo ni una comprobación nueva del cifrado ML-KEM.

Reproducción en este workspace
1. Trabajar en zk9-chain/work/pq-private-send-v1. Si se parte del resultado
   congelado, copiar su contenido a una NUEVA carpeta bajo zk9-chain/work/;
   nunca ejecutar o escribir pruebas dentro de results/.
2. Mantener los proyectos hermanos fijados por BASE.json, Cargo.lock y
   evidence/environment-01.json. cargo-local.sh utiliza exclusivamente el Rust
   aislado de work/gloas-native-integration-v1/native/.toolchain; no cambia el
   shell ni la instalación global. El entorno se identifica con rustc -vV.
3. Desde la carpeta de trabajo:
   sh cargo-local.sh test --release --offline --locked --lib
   sh cargo-local.sh build --release --offline --locked --bin qualify
4. Ejecutar con el Python fijado del backend, flags -E -s -B:
   python -E -s -B run_qualification.py mi-ejecucion-nueva
   python -E -s -B run_qualification.py mi-segunda-ejecucion
   Sustituir python por la ruta absoluta del runtime. Los nombres deben ser
   nuevos; el supervisor no sobrescribe evidencia previa.
5. Ambas deben terminar con status PASS y child_exit 0. Revisar los 14 casos
   JSONL y los siete rechazos por el VERIFICADOR, no sólo fallos del generador.

Qué verifica
- Una entrada real con relleno externo al árbol; dos entradas reales; u64::MAX;
  un pago producido por prepare.rs desde una nota y árbol locales.
- Vinculación de datos públicos y paquetes; pruebas alteradas; encuadres
  truncados/no canónicos; rechazo del protocolo anterior en ambos sentidos.
- Trazas hostiles: saldo en relleno, importe igual al módulo BabyBear, ausencia
  de pertenencia/propiedad, flag no booleano y flag no constante. El prover
  subyacente produce las pruebas en release y el verificador las rechaza.
- Casos de importe insuficiente, overflow, notas ajenas/duplicadas y raíz falsa.

El supervisor registra tiempo total y RSS de un proceso de comprobación, con
múltiples operaciones. Son observaciones funcionales, NO benchmarks de prueba
aislada ni una serie de rendimiento de mainnet. El segundo run comprueba
repetibilidad funcional, sin requerir igualdad de pruebas aleatorias.

Seguridad pendiente
La raíz debe venir del cliente autenticado; no basta un JSON recibido por RPC.
El constructor no verifica historial de gastos ni reserva notas. Estas tareas
deben integrarse con el estado cifrado y la outbox, junto con revisión nativa,
paquetes ML-KEM, nuevo perfil/keeper y recuperación de envíos interrumpidos.
