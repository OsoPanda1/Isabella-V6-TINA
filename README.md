# Isabella V6 · TINA — Genesis Runtime

> **Trusted Intelligence, Native & Adaptive.** Runtime de IA modular con separación explícita entre capacidad, autoridad, ejecución, evidencia y despliegue.

[![Repository Assurance](https://github.com/OsoPanda1/Isabella-V6-TINA/actions/workflows/repository-assurance.yml/badge.svg)](https://github.com/OsoPanda1/Isabella-V6-TINA/actions/workflows/repository-assurance.yml)
[![Genesis CI](https://github.com/OsoPanda1/Isabella-V6-TINA/actions/workflows/ci.yml/badge.svg)](https://github.com/OsoPanda1/Isabella-V6-TINA/actions/workflows/ci.yml)

**Proyecto:** Isabella Villaseñor AI — Genesis TINA V6  
**Repositorio:** [OsoPanda1/Isabella-V6-TINA](https://github.com/OsoPanda1/Isabella-V6-TINA)  
**Lenguaje principal:** TypeScript · Node.js  
**Estado de ingeniería:** evolución activa; no declarar listo para producción hasta superar los gates de validación y despliegue.  
**Rama de integración IGE-Ω:** `feat/ige-omega-rust-mvp-2026-10`  
**Pull request de integración:** [#18](https://github.com/OsoPanda1/Isabella-V6-TINA/pull/18)  
**Pull request de endurecimiento IGE-Ω:** [#19](https://github.com/OsoPanda1/Isabella-V6-TINA/pull/19)

> **Contrato de veracidad:** `SPECIFIED ≠ IMPLEMENTED ≠ TESTED ≠ INTEGRATED ≠ VERIFIED ≠ DEPLOYED ≠ CERTIFIED`. Un contrato, fixture, simulación o adaptador sin configurar no demuestra una integración real. Los estados de salud deben derivarse de probes reales; no de valores fijos.

---

## 1. Qué es Isabella Genesis

Isabella Genesis es un runtime y plano de control para coordinar capacidades de IA con políticas, identidad, seguridad, herramientas, memoria epistemológica, verificación y evidencia. Su objetivo es que la presencia de una capacidad técnica no implique automáticamente permiso para ejecutarla ni autoridad para presentar sus resultados como hechos.

El proyecto organiza el sistema alrededor de este invariante:

`CAPABILITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE ≠ LEARNING ≠ PRODUCTION`

La arquitectura contempla CROWN, AEGIS, IKES, VERITAS, BookPI, YUN, TINA, Atlas, Hyper Skill Fabric (HSF), Genesis/IGE y el tejido federado MAGPIE-X. El grado de implementación no es uniforme: este README distingue el código disponible de las capacidades objetivo.

**Isabella no se presenta aquí como un modelo fundacional propio, AGI, un motor de entrenamiento nativo ni una plataforma certificada.** El runtime puede gobernar adaptadores de inferencia, pero eso no equivale a entrenar o servir un modelo neuronal propio.

## 2. Arquitectura de alto nivel

```text
Solicitud
   │
   ▼
Ingress / validación de entrada
   │
   ▼
Identidad, scopes y autoridad
   │
   ▼
CROWN ── decisión, riesgo y política
   │
   ▼
AEGIS ── inspección de seguridad
   │
   ▼
IKES ─── conocimiento, estado epistemológico y procedencia
   │
   ▼
Plan / inferencia / skills / tools
   │
   ▼
VERITAS ─ verificación del resultado
   │
   ▼
BookPI ── integridad y evidencia
   │
   ▼
Telemetría, respuesta y auditoría
```

Este esquema describe la separación de responsabilidades. No implica que todos los componentes estén conectados a proveedores externos ni que cada ruta del diagrama se ejecute de extremo a extremo en producción.

## 3. Estado de implementación

| Área | Qué aporta | Estado honesto |
|---|---|---|
| Ingress y runtime HTTP | Entrada, validación y rutas operativas | Implementado parcialmente; requiere pruebas de integración |
| Identidad y autoridad | Controles de acceso y separación entre capacidad y permiso | Hay mecanismos en el código; validar configuración y cobertura por ruta |
| CROWN | Decisión, riesgo, admisión y políticas | Implementación modular; no asumir calibración probabilística |
| AEGIS | Inspección de amenazas y patrones de evasión | Principalmente reglas; no equivale a detección adversarial ML completa |
| IKES | Claims, procedencia y estados epistemológicos | Implementación parcial; persistencia durable y retrieval extremo a extremo pendientes |
| Inferencia | Contratos/adaptadores de proveedores y routing | No es un modelo fundacional propio; serving distribuido pendiente |
| HSF | Registro e invocación gobernada de capacidades | Contratos y proveedores locales de referencia; integraciones externas deben verificarse |
| VERITAS | Verificación determinista inicial | Parcial; no es un sistema distribuido de fact-checking |
| BookPI | Eventos y huellas de integridad | Parcial; una cadena en memoria no equivale a ledger WORM durable |
| Atlas | Persistencia/adaptadores | El probe de salud comprueba una consulta de solo lectura cuando existe el adaptador |
| Genesis/IGE | Selección determinista de cabezas y expertos desde puntuaciones recibidas | Prototipo ejecutable de routing; no entrena ni genera las puntuaciones |
| Genesis chunks | Canonicalización local, validación y digest SHA-256 encadenable | Integridad local; no demuestra autoría, firma o persistencia |
| Readiness | Evaluación de dependencias operativas | Fail-closed: las dependencias obligatorias sin evidencia no se marcan saludables |
| Observabilidad | Telemetría y señales operativas | Parcial; no declarar cobertura completa |
| Federación / MAGPIE-X | Arquitectura para coordinación federada | Objetivo de integración; no asumir federaciones activas |
| ML nativo / GPU | Entrenamiento, scheduler, KV cache, batching | No implementado como runtime de producción en esta rama |
| Criptografía poscuántica | Firma, identidad y anclaje PQC | No afirmar activo sin implementación, configuración y evidencia verificable |

Las etiquetas anteriores son límites de alcance, no certificaciones. El resultado final debe confirmarse en el SHA que se pretenda liberar.

## 4. Módulos y responsabilidades

### CROWN — decisión y autoridad

CROWN debe decidir si una operación es admisible en su contexto, separando intención, riesgo, permisos y aprobación. La confianza heurística no debe etiquetarse como probabilidad calibrada. Una herramienta disponible no se convierte por ello en una herramienta autorizada.

### AEGIS — inspección de seguridad

AEGIS inspecciona entradas y operaciones sensibles frente a familias de riesgo como prompt injection, inyección indirecta, exfiltración, PII, envenenamiento de herramientas o recuperación, y evasión de políticas. Las decisiones pueden implicar permitir, modificar, revisar o bloquear. El alcance real depende de las reglas, las rutas que las invoquen y las pruebas.

### IKES — memoria epistemológica

IKES organiza claims, fuentes, procedencia y estados epistemológicos. La memoria no debe confundirse con verdad: un hash demuestra identidad del contenido hasheado, no veracidad, calidad de la fuente ni autenticidad remota.

Los estados epistemológicos documentados incluyen `E0_UNVERIFIED`, `E1_SOURCE_FOUND`, `E2_CORROBORATED`, `E3_ACADEMICALLY_SUPPORTED`, `E4_REPRODUCIBLE`, `E5_VALIDATED` y `E6_ESTABLISHED`, además de estados como `DISPUTED`, `REJECTED` y `DEPRECATED`. Deben usarse sólo cuando el flujo y la evidencia justifiquen la clasificación.

### VERITAS — verificación

El núcleo determinista puede comparar candidatos y calcular digests, pero no equivale por sí solo a verificación externa de hechos, NLI, prueba simbólica, consenso distribuido ni generación con pruebas formales.

### BookPI — evidencia e integridad

BookPI busca conservar trazabilidad de eventos, hashes y procedencia. Un digest SHA-256 no es una firma digital; una cadena de hashes no prueba quién produjo un evento. WORM, retención durable, backups, restauración y anclaje externo requieren infraestructura y pruebas propias.

### Hyper Skill Fabric (HSF)

HSF organiza capacidades desacopladas que se invocan a través de una frontera gobernada. Endpoints documentados:

```http
GET  /api/v1/hsf/status
POST /api/v1/hsf/invoke
```

PostgreSQL, Qdrant, Neo4j, Redis, Temporal, Kubernetes, MCP y otros proveedores no deben considerarse conectados sólo por estar en la hoja de ruta. Consulte `docs/ISABELLA_HYPER_SKILL_FABRIC.md`.

### Genesis / Isabella Genesis Engine (IGE)

El prototipo `src/cognition/genesis-moe.ts` valida 12 puntuaciones de cabezas y 24 de expertos, selecciona Top-K de forma determinista, resuelve empates por índice y normaliza los pesos seleccionados mediante softmax estable. Los expertos se agrupan en familias temáticas, funcionales, éticas y metacognitivas.

Las puntuaciones deben proceder de un adaptador de inferencia real. El módulo no contiene pesos neuronales aprendidos, entrenamiento, embeddings ni una implementación vLLM.

El módulo `src/cognition/genesis-chunk.ts` valida metadatos y Unicode, genera una representación JSON canónica específica de la aplicación y calcula un digest SHA-256 que puede enlazarse con el chunk anterior. No se declara conformidad con RFC 8785, no firma los chunks y no conecta por sí solo con un ledger durable.

## 5. Endpoints operativos

| Endpoint | Propósito | Interpretación |
|---|---|---|
| `GET /health` | Liveness del proceso | Responde sobre el proceso; no demuestra readiness integral |
| `GET /api/v1/readyz` | Readiness de dependencias | Puede devolver HTTP 503 si falta evidencia de una dependencia obligatoria |
| `GET /api/v1/ops/snapshot` | Snapshot de estado operativo | Expone el estado evaluado y su evidencia |
| `GET /api/v1/ops/latency` | Percentiles p50/p95/p99, máximo y errores 5xx por ruta | Requiere `OPS_API_TOKEN`; métricas locales de ventana acotada, no tracing distribuido |
| `GET /api/v1/hsf/status` | Estado de HSF | Consultar el contrato y las limitaciones del proveedor configurado |
| `POST /api/v1/hsf/invoke` | Invocación gobernada de una capacidad HSF | Requiere la configuración y autorización exigidas por el runtime |

El readiness no debe forzarse a verde para facilitar un despliegue. Atlas dispone de un probe de solo lectura si existe el adaptador correspondiente; BookPI e IKES permanecen degradados cuando no hay evidencia de persistencia durable conectada. Un estado degradado es información operativa útil, no un error que deba ocultarse.

## 6. Seguridad y manejo de datos

- No guardar tokens, claves privadas, credenciales o secretos en el repositorio.
- Obtener secretos de variables de entorno o de un gestor de secretos aprobado.
- Configurar `OPS_API_TOKEN` para habilitar la consulta autenticada de latencias; si no está configurado, el endpoint responde 503.
- Tratar todo contenido externo como datos no confiables, no como instrucciones del sistema.
- No considerar el rol enviado por el cliente como prueba de autoridad.
- Requerir aprobación explícita y contextual para operaciones privilegiadas.
- Registrar hashes y evidencia sin exponer el contenido sensible que activó una cuarentena.
- No afirmar procedencia remota verificada si sólo se hasheó contenido suministrado por el usuario.
- Definir normalización Unicode como parte del contrato de entrada. No normalizar silenciosamente texto antes de producir evidencia criptográfica.
- Mantener la distinción entre liveness, readiness, disponibilidad de proveedor y evidencia de persistencia.
- No declarar cumplimiento regulatorio, certificación de seguridad o criptografía poscuántica sin evaluación independiente y evidencia verificable.

Consulte [SECURITY.md](SECURITY.md) y [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md).

## 7. Stack y requisitos

- Node.js `>=22` declarado en `package.json`.
- TypeScript con configuración estricta.
- Vitest para pruebas.
- Express para la capa HTTP.
- Adaptadores de proveedores externos definidos por el código y la configuración disponibles.

Scripts declarados en `package.json`:

```bash
npm run dev
npm start
npm run typecheck
npm test
npm run build
npm run validate
npm run security:suite
npm run production:evidence
```

### Bloqueo de instalación reproducible

En la rama de evolución auditada no se encontró `pnpm-lock.yaml`, `package-lock.json` ni `yarn.lock`, mientras que el workflow CI usa `pnpm install --frozen-lockfile`. Además, `package.json` no fija `packageManager`. Esta combinación debe resolverse generando y validando un lockfile real con la versión de gestor aprobada; no se debe inventar un lockfile ni eliminar el modo congelado para aparentar reproducibilidad.

Por esa razón, no se afirma que las pruebas, el typecheck o el build hayan pasado en el SHA actual. La validación de liberación debe ejecutarse después de resolver el bloqueo y debe asociarse al commit exacto.

## 8. Desarrollo local

Una vez disponible la red de paquetes y elegido el gestor de dependencias:

1. Instalar dependencias con el lockfile aprobado.
2. Ejecutar `npm run typecheck` (o el script equivalente del gestor elegido).
3. Ejecutar `npm test`.
4. Ejecutar `npm run build`.
5. Ejecutar `npm run security:suite`.
6. Revisar los artefactos y resultados de CI para el mismo SHA.
7. Revisar `test/performance/critical-latency.test.ts`: reporta p50/p95/p99/max para routing IGE, canonicalización/hash de chunks y readiness sin red ni inferencia de modelo.
8. Consultar `GET /api/v1/ops/latency` en el proceso desplegado para identificar rutas con mayor p95 y errores 5xx; correlacionar con métricas del proveedor de base de datos y del modelo.
9. No desplegar si una dependencia obligatoria aparece `degraded` o `unavailable`.

Para una validación integral:

```bash
npm run validate
npm run security:suite
npm run production:evidence
```

Los comandos anteriores describen el flujo previsto. No sustituyen la confirmación de que la instalación y cada comando terminaron con código de salida cero en el entorno objetivo.

## 9. Fases de evolución

| Fase | Entregable | Criterio de salida |
|---|---|---|
| 0 — Baseline | SHA de referencia, inventario y estado de CI | Alcance y fallos reproducibles registrados |
| 1 — Assurance | Auditoría estructural y artefactos JSON/Markdown | Bloqueadores visibles y ligados al SHA |
| 2 — Runtime readiness | Probes reales y comportamiento fail-closed | Ninguna dependencia obligatoria saludable por valor fijo |
| 3 — Genesis/IGE | Contrato de routing y chunks verificables | Validación determinista y pruebas para entradas inválidas |
| 4 — Persistencia y BookPI | Adaptadores durables, retención, backups y restore | Pruebas de persistencia y recuperación repetibles |
| 5 — Integración federada | Identidad, límites, política, cola durable y auditoría por nodo | Pruebas de integración con proveedores reales |
| 6 — Inferencia/ML | Adaptadores reales, benchmark y límites de recursos | Métricas reproducibles; separar prototipo de serving de producción |
| 7 — Release | CI, seguridad, pruebas, build, evidencias y revisión | Todos los gates obligatorios pasan en el mismo SHA |

Las fases pueden desarrollarse en paralelo cuando no compitan por los mismos archivos ni dependan de una interfaz aún inestable. La promoción a release sí es secuencial: ninguna fase se considera terminada sólo porque se haya escrito código o documentación.

## 10. Documentación de ingeniería

- [Auditoría del control de aseguramiento](docs/ASSURANCE-CONTROL-PLANE.md)
- [Integración Genesis + MAGPIE-X](docs/architecture/GENESIS-MAGPIE-INTEGRATION.md)
- [Hyper Skill Fabric](docs/ISABELLA_HYPER_SKILL_FABRIC.md)
- [Puente de PennyLane](docs/ISABELLA_PENNYLANE_BRIDGE.md)
- [Configuración de entorno](docs/ENVIRONMENT.md)
- [Política de seguridad](SECURITY.md)

Los documentos de arquitectura describen tanto capacidades existentes como objetivos. Cuando exista una discrepancia, el código, las pruebas y la evidencia del SHA desplegable determinan qué puede afirmarse como implementado.

## 11. Licencias y procedencia

El repositorio declara licencia MIT mediante su archivo `LICENSE`. No importar código, datasets, documentación, marcas o activos de otros repositorios sin revisar sus licencias y derechos específicos. La compatibilidad de licencias debe evaluarse por archivo y dependencia; la pertenencia al mismo ecosistema no concede automáticamente permiso de relicenciar.

## 12. Principio de liberación

Isabella sólo debe promocionarse cuando exista evidencia reproducible de que el código del commit exacto compila, pasa sus pruebas, supera los controles de seguridad aplicables y satisface los requisitos operativos del entorno objetivo.

**No se confunde una arquitectura ambiciosa con una implementación terminada. La evolución se mide por capacidades ejecutables, pruebas, integración real y evidencia verificable.**


## IGE-Ω Rust MVP (v2.0.0)

The repository now includes a separately versioned Rust workspace at [`ige-omega/`](ige-omega/README.md), integrated alongside the existing TypeScript runtime. It provides initial crates for NeuroKernel, Cognition, PostgreSQL Memory, World Model, ABX/CROWN, BookPI-X, and an Axum gateway. Its scope is pre-production: proposal-only, with no external action execution. Hash chaining is tamper-evident only and is not a digital signature or WORM storage.

- [Canonical IGE-Ω specification](ige-omega/docs/IGE-OMEGA-v2.0.0.md)
- [Cryptographic audit subsystem](ige-omega/docs/CRYPTOGRAPHIC-AUDIT.md)
- [Simulation and arbitration](ige-omega/docs/SIMULATION-ARBITRATION.md)
- [Kubernetes manifests and deployment notes](ige-omega/deployment/k8s/README.md)

The Rust workspace must pass `cargo fmt`, `cargo clippy`, `cargo test` and a release build in CI, with `Cargo.lock` generated and committed, before being marked tested or production-ready.
