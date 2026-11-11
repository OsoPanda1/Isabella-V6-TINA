# Corrida de Mejora y Evolución — 2026-11-11

- **Commit base:** `8dddc96` (`main`)
- **Objetivo:** Unificar la tabla de transiciones de `ControlState` en una sola
  fuente de verdad, impidiendo el salto `declared → verified` que omitía el paso
  `wired` (el que exige aprobación humana).
- **Criterio de selección:** severidad=4 probabilidad=3 coste=2 → 4×3×(6−2) = **48**
- **Dominio:** `verification` | **ControlIds:** `EV-03-CROWN.verification.correctness.invariant`, `EV-03-CROWN.verification.correctness.contract`
- **Diff:** `src/evolution/state-machine.ts`, `src/evolution/engine.ts`, `test/evolution/engine.test.ts` (**3 archivos, 57 líneas netas**)
- **Verificación:** `typecheck=sin errores nuevos` `test=ok (504/504)` `build=sin errores nuevos`
- **Evidencia:** `evd_57a013ea0bfc951b1cd1739e`, `evd_f30d8e5adce7075ce72675a0`
- **Propuesta:** `evo-2026-11-11-unify-control-transitions`
- **Estado:** `draft` | `requiresHumanApproval: true`

## Línea base (F0)

| Puerta | Antes (main `8dddc96`) | Después |
|---|---|---|
| `pnpm typecheck` | **FAIL** — 19 errores en 3 archivos | FAIL — los **mismos 19**, 0 nuevos |
| `pnpm test` | PASS — 98 archivos, 502 pruebas | PASS — 98 archivos, **504 pruebas** |
| `pnpm build` | **FAIL** — 15 errores en 2 archivos | FAIL — los **mismos 15**, 0 nuevos |

Los 19 errores de `typecheck` (y los 15 de `build`) son **preexistentes** en
`main` y están en `src/cognition/epistemic-evaluator.ts`, `src/server.ts` y
`test/cognition/epistemic-evaluator.test.ts`. Ya tienen su propia corrida
abierta: PR #21 (`evolution/2026-10-24-restore-typecheck-gate`). No se tocan
aquí (idempotencia §5). Esta corrida **no introduce errores nuevos**.

## Brecha seleccionada (F1–F2)

`src/evolution` tenía **dos tablas de transición independientes** para el mismo
tipo `ControlState`:

- `src/evolution/engine.ts` (`TRANSITIONS`) — la usada por `applyControlState`,
  la ruta real de mutación.
- `src/evolution/state-machine.ts` (`evolveControlState`) — exportada por el
  barril `src/evolution/index.ts`.

Divergían en una transición: `evolveControlState("declared","verified")`
**aceptaba** el salto, mientras que `engine.allowTransition("declared","verified")`
lo **rechazaba**. Ese salto omite `wired`, el paso que exige aprobación humana
(`applyControlState` deniega `wired` sin `humanApprover`). Es decir, la
máquina de estados permitía alcanzar `verified` sin pasar por el control de
autoridad humana que el invariante operativo de `AGENTS.md` exige.

Evidencia del hallazgo (antes del cambio), con el módulo real:

```
declared -> verified: state-machine=true engine=false
declared -> declared: state-machine=true engine=false   (no-op de identidad)
...
divergences: 5
```

## Cambio (F4)

Mínimo y sin cambio de comportamiento salvo cerrar el salto:

1. `state-machine.ts` define la tabla canónica `CONTROL_TRANSITIONS` y
   `allowControlTransition`; `evolveControlState` la consulta. Se conserva el
   no-op de identidad (`previous === next`).
2. `engine.ts` elimina su tabla duplicada y `allowTransition` delega en
   `allowControlTransition`. Se conserva la firma pública `allowTransition`.
3. `test/evolution/engine.test.ts` añade dos pruebas: (a) rechazo de
   `declared → verified`; (b) paridad entre `allowTransition` y
   `evolveControlState` en las 12 transiciones no identidad.

Ningún archivo tocado es `src/security/**` ni `src/identity/**`; sin
dependencias nuevas; sin cambios de contrato público (`allowTransition`,
`evolveControlState`, `CONTROL_STATE_ORDER` conservan su firma; `CONTROL_TRANSITIONS`
y `allowControlTransition` son adiciones).

## Invariante de gobernanza

La evidencia se **generó** con los módulos reales del repositorio:

- `createEvidence` → ambos registros con `digest` íntegro (`verifyEvidenceIntegrity=true`).
- `validateProposal` → la propuesta valida (controlIds del dominio declarado,
  3 `changeBlock`, 2 `evidenceRef`).
- `canPromoteToVerified` con un control y **sin** verificador inyectado devuelve
  **`false`**: un `passed: true` autoemitido es una afirmación, no una verificación.

Ningún control pasa a `verified` ni a `wired` desde esta corrida.

## Hallazgos fuera de alcance (no corregidos)

- **Typecheck/build rojos en `main`:** cubierto por PR #21. No se duplica.
- **Lockfile ausente:** `main` no contiene `pnpm-lock.yaml`, pero `.github/workflows/ci.yml`
  ejecuta `pnpm install --frozen-lockfile`. Cambio de cadena de suministro;
  merece su propia corrida con revisión dedicada.

## No se tocó

`src/security/**`, `src/identity/**`, `.github/**`, `.env*`, `package.json`,
`tsconfig*.json`, `src/evolution/catalog.ts`, `src/evolution/evidence.ts`,
`src/evolution/proposals.ts`, y ningún archivo fuera de los 3 del diff.
