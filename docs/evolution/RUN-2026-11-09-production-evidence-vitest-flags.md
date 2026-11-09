# Corrida de Mejora y Evolución — 2026-11-09

- **Commit base:** `8dddc96` (`main`)
- **Objetivo:** Que el gate de evidencia de producción lea el resultado real de
  vitest bajo `npm` y `pnpm`, en vez de reportar `0/0` y fallar con la suite en verde.
- **Criterio de selección:** severidad=4 probabilidad=4 coste=1 → 4×4×(6−1) = **80**
- **Dominio:** `release_gates` (plano 17, PRODUCTION_CONTROL) | **ControlIds:**
  `EV-17-PRODUCTION_CONTROL.release_gates.correctness.validator`,
  `EV-17-PRODUCTION_CONTROL.release_gates.reliability.telemetry`
- **Diff:** `scripts/production-evidence.mjs` (**1 archivo, 4 líneas netas**)
- **Verificación:** `typecheck=fail(pre-existente)` `test=ok` `build=fail(pre-existente)`
- **Evidencia:** `evd_1df1b87b66f045e003a0ead9`, `evd_f0d0d3cd650481d1f2c579f5`
- **Propuesta:** `evo-2026-11-09-production-evidence-vitest-flags`
- **Estado:** `draft` | `requiresHumanApproval: true`

## Brecha (F1)

`scripts/production-evidence.mjs` invocaba vitest así:

```js
const cmd = ["exec", "vitest", "run", "--reporter=json", `--outputFile=${outputFileArg}`];
```

Bajo `npm exec` las banderas `--reporter=json` y `--outputFile=…` **no llegan a
vitest**: npm las consume como configuración propia y emite
`npm warn Unknown cli config "--reporter"`. Vitest corre con su reporter por
defecto, **no se escribe** `evidence/.vitest-report.json`, y el resumen queda en
`parsed: false`, `testsTotal: 0`, `testsPassed: 0`.

Efecto: el gate declara `GATE DE PRODUCCIÓN FALLÓ` con **502/502 pruebas en
verde** — un falso negativo de confiabilidad que degrada la evidencia
(auto_generated) que consumen `deploy-production.yml` y la decisión GO/NO-GO.
Es reproducible: `npm exec vitest run --reporter=json --outputFile=X` no crea
`X`; `npm exec -- vitest run …` sí.

## Cambio (F4)

Mínimo, un solo comportamiento, sin tocar la lógica del gate:

```js
const cmd = ["exec", "--", "vitest", "run", "--reporter=json", `--outputFile=${outputFileArg}`];
```

El separador `--` marca el fin de las banderas del gestor de paquetes. Verificado
que funciona igual bajo `pnpm exec` (que ya pasaba las banderas directamente) y
bajo `npm exec` (que era el caso roto).

## Línea base (F0) vs. después

| Puerta | Antes | Después |
|---|---|---|
| `typecheck` | **FAIL** — 19 errores en 3 archivos (pre-existente) | FAIL — mismos 19 (sin cambio) |
| `test` | PASS — 98 archivos, 502 pruebas | PASS — 98 archivos, 502 pruebas |
| `build` | **FAIL** — 15 errores (pre-existente) | FAIL — mismos 15 (sin cambio) |
| `scripts/production-evidence.mjs` (bajo npm) | FAIL — `tests: 0/0`, `parsed=false` | lee `tests: 502/502`, `parsed=true` |

Los 19 errores de `typecheck` y 15 de `build` son **pre-existentes** en `main` y
están cubiertos por la corrida `evolution/2026-10-24-restore-typecheck-gate`
(PR #21, en draft). Esta corrida **no** los repite (regla de idempotencia) ni los
toca.

## Invariante de gobernanza

La evidencia se **generó** con los módulos reales del repositorio:

- `createEvidence` → ambos registros con `digest` íntegro (`verifyEvidenceIntegrity=true`).
- `validateProposal` → propuesta válida (`release_gates` es dominio conocido; 100
  controles en el dominio; ≥1 `changeBlock`; ≥1 `evidenceRef`).
- `canPromoteToVerified` con un control `wired` y **sin** verificador inyectado
  devuelve **`false`**.

Un `passed: true` autoemitido sigue siendo una afirmación, no una verificación.
La promoción a `verified` exige verificación independiente y arbitraje humano.

## Hallazgo fuera de alcance (no corregido)

`.github/workflows/ci.yml` ejecuta `pnpm install --frozen-lockfile`, pero `main`
**no contiene `pnpm-lock.yaml`** (solo `package-lock.json` está gitignored). La
puerta `verify` no puede instalar hoy. No se corrige aquí: introducir un lockfile
es un cambio de cadena de suministro y de CI, fuera de los límites duros de esta
corrida; merece su propia corrida con revisión dedicada.

## Riesgos y rollback

- **Riesgo:** bajo. Un único archivo de evidencia, cambio aditivo en la
  construcción del argv; no cambia la lógica de decisión ni los umbrales.
- **Compatibilidad:** `--` es válido en `npm exec` y `pnpm exec`; verificado en
  ambos.
- **Rollback:** `git revert` del commit (1 archivo, 4 líneas) o restaurar la
  línea original del argv.

## No se tocó

`src/security/**`, `src/identity/**`, `.github/**`, `.env*`, `package.json`,
`tsconfig*.json`, `src/**`, `test/**`, y ningún archivo fuera del diff.
