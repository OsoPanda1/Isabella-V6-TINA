# Corrida de Mejora y Evolución — 2026-10-24

- **Commit base:** `8dddc96` (`main`)
- **Objetivo:** Restaurar la puerta de `typecheck`: 19 errores TS en 3 archivos → 0, sin cambiar comportamiento.
- **Criterio de selección:** severidad=5 probabilidad=5 coste=1 → 5×5×(6−1) = **125**
- **Dominio:** `cicd` | **ControlIds:** `EV-17-PRODUCTION_CONTROL.cicd.correctness.validator`, `EV-17-PRODUCTION_CONTROL.cicd.reliability.telemetry`
- **Diff:** `src/cognition/epistemic-evaluator.ts`, `src/server.ts`, `test/cognition/epistemic-evaluator.test.ts` (**3 archivos, 12 líneas netas**)
- **Verificación:** `typecheck=ok` `test=ok` `build=ok`
- **Evidencia:** `evd_f9ecc39d6e6f8cc22ea20832`, `evd_1745240d9d91e9d432847ad8`
- **Propuesta:** `evo-2026-10-24-restore-typecheck-gate`
- **Estado:** `draft` | `requiresHumanApproval: true`

## Línea base (F0)

| Puerta | Antes | Después |
|---|---|---|
| `pnpm typecheck` | **FAIL** — 19 errores en 3 archivos | **PASS** — exit 0 |
| `pnpm test` | PASS — 98 archivos, 502 pruebas | PASS — 98 archivos, 502 pruebas |
| `pnpm build` | PASS | PASS |

Errores de línea base, por causa raíz:

- 14 × `TS18048` (`'spec' is possibly 'undefined'`) en `src/cognition/epistemic-evaluator.ts` — `EPISTEMIC_LADDER_SPEC` estaba tipado `Record<string, …>` y se indexaba con una unión literal bajo `noUncheckedIndexedAccess`.
- 1 × `TS2322` en el mismo archivo — el elemento `ladder` perdía el tipo del nivel.
- 1 × `TS2339` (`Property 'originalUrl' does not exist on type 'IncomingMessage'`) en `src/server.ts` — `originalUrl` es de Express, no de `IncomingMessage`.
- 4 × `TS2532` en `test/cognition/epistemic-evaluator.test.ts` — índice no verificado en un array `string[]`.

## Cambio (F4)

Mínimo y sin cambio de comportamiento:

1. `EpistemicLevel` como tipo exportado; `EPISTEMIC_LADDER_SPEC` pasa a `Readonly<Record<EpistemicLevel, EpistemicLadderStep>>` y `assignedLevel` usa ese tipo.
2. `src/server.ts` lee la ruta de `req.url` (presente en `IncomingMessage`) en vez de `req.originalUrl`.
3. La prueba fija la lista de niveles con `as const`.

Ningún archivo tocado es `src/security/**` ni `src/identity/**`; no hay dependencias nuevas; no hay cambios de contrato público (`EpistemicLevel` es un alias aditivo del literal que ya estaba en la firma).

## Invariante de gobernanza

La evidencia se **generó** con los módulos reales del repositorio:

- `createEvidence` → ambos registros con `digest` íntegro (`verifyEvidenceIntegrity=true`).
- `canPromoteToVerified` con un control `wired` y **sin** verificador inyectado devuelve **`false`**.

Un `passed: true` autoemitido sigue siendo una afirmación, no una verificación. La promoción exige verificación independiente y arbitraje humano.

## Hallazgo fuera de alcance (no corregido en esta corrida)

`.github/workflows/ci.yml` ejecuta `pnpm install --frozen-lockfile`, pero `main` **no contiene `pnpm-lock.yaml`**. La puerta `verify` no puede instalar hoy. No se corrige aquí porque introducir un lockfile es un cambio de cadena de suministro, excede el objetivo único de esta corrida y merece su propia corrida con revisión dedicada.

## No se tocó

`src/security/**`, `src/identity/**`, `.github/**`, `.env*`, `package.json`, `tsconfig*.json`, `src/evolution/**`, y ningún archivo fuera de los 3 del diff.
