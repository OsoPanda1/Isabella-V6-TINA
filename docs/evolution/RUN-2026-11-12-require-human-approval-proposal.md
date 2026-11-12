# Corrida de Mejora y Evolución — 2026-11-12

- **Commit base:** `8dddc96` (`main`)
- **Objetivo:** Exigir `requiresHumanApproval: true` en `validateProposal` para
  que una propuesta que renuncia a la aprobación humana no pueda validar.
- **Criterio de selección:** severidad=3 probabilidad=5 coste=1 → 3×5×(6−1) = **75**
- **Dominio:** `human_oversight` | **ControlIds:** `EV-11-GOVERNANCE.human_oversight.governance.validator`
- **Diff:** `src/evolution/proposals.ts`, `test/evolution/proposals.test.ts` (**2 archivos, 42 líneas netas**)
- **Verificación:** `typecheck=sin errores nuevos (19 preexistentes)` `test=ok (507/507)` `build=sin errores nuevos (15 preexistentes)`
- **Evidencia:** `evd_42fc93f6d6c7fa6652013b16`, `evd_c1bdeacf0bbecb8f30b6e24e`
- **Propuesta:** `evo-2026-11-12-require-human-approval-proposal`
- **Estado:** `draft` | `requiresHumanApproval: true`

## Línea base (F0)

| Puerta | Antes (main `8dddc96`) | Después |
|---|---|---|
| `pnpm typecheck` | **FAIL** — 19 errores en 3 archivos | FAIL — los **mismos 19**, 0 nuevos |
| `pnpm test` | PASS — 98 archivos, 502 pruebas | PASS — **99 archivos, 507 pruebas** |
| `pnpm build` | **FAIL** — 15 errores en 2 archivos | FAIL — los **mismos 15**, 0 nuevos |

Los 19 errores de `typecheck` (y los 15 de `build`) son **preexistentes** en
`main` (`src/cognition/epistemic-evaluator.ts`, `src/server.ts`,
`test/cognition/epistemic-evaluator.test.ts`) y ya tienen su corrida abierta:
PR #21. Esta corrida **no introduce errores nuevos** (idempotencia §5).

## Brecha seleccionada (F1–F2)

La instrucción canónica (§F7 / §7) y la de esta corrida (§9) exigen que toda
`EvolutionProposal` válida lleve `requiresHumanApproval: true`. Sin embargo,
`validateProposal` (`src/evolution/proposals.ts`) verificaba controlIds,
changeBlocks y evidenceRefs, pero **no** el campo `requiresHumanApproval`.

Evidencia del hallazgo (antes del cambio), con el módulo real:

```
$ npx tsx -e 'validateProposal({... requiresHumanApproval: false ...})'
GAP CONFIRMED: requiresHumanApproval=false VALIDATED (no throw)
```

Es decir, una propuesta que **renuncia explícitamente** al arbitraje humano
pasaba la validación: el invariante operativo de `AGENTS.md`
(«la conciencia humana decide, aprueba, arbitra») quedaba eludible por
configuración de la propia propuesta. No había ninguna prueba que cubriera
`proposals.ts`.

**Qué duele:** el validador del contrato de evolución admitía propuestas sin
aprobación humana. **Por qué ahora:** es una brecha de gobernanza de coste
mínimo (una guarda) y verificable con una prueba. **Qué NO se toca:** el
`EvolutionProposal` público, `evidence.ts`, `catalog.ts`, `state-machine.ts`,
`engine.ts`, `src/security/**`, `src/identity/**`, CI y `.env*`.

## Cambio (F4)

Mínimo y sin cambio de contrato público:

1. `src/evolution/proposals.ts` — `validateProposal` añade una guarda final:
   si `requiresHumanApproval !== true`, lanza
   `EVOLUTION: proposal requires human approval.`
2. `test/evolution/proposals.test.ts` (nuevo) — cubre: aceptación de una
   propuesta completa; rechazo con `requiresHumanApproval=false`; dominio
   desconocido; controles fuera del dominio; propuesta sin controles/bloques/evidencia.

El tipo `EvolutionProposal` y la firma de `validateProposal` **no cambian**
(0 cambios de API pública). Sin dependencias nuevas. Sin `any`, `as never` ni
`require()` dinámico.

## Invariante de gobernanza

La evidencia se **generó** con los módulos reales del repositorio:

- `createEvidence` → ambos registros con `digest` íntegro (`verifyEvidenceIntegrity=true`).
- `validateProposal` → la propuesta valida (controlId del dominio declarado,
  2 `changeBlock`, 2 `evidenceRef`, `requiresHumanApproval: true`).
- `canPromoteToVerified` con el control y **sin** verificador inyectado devuelve
  **`false`**: un `passed: true` autoemitido es una afirmación, no una verificación.

Ningún control pasa a `verified` ni a `wired` desde esta corrida.

## Hallazgos fuera de alcance (no corregidos)

- **Typecheck/build rojos en `main`:** cubierto por PR #21. No se duplica.
- **Lockfile ausente:** `main` no contiene `pnpm-lock.yaml` pero CI ejecuta
  `pnpm install --frozen-lockfile`. Cambio de cadena de suministro; merece su
  propia corrida. `pnpm install` local generó `pnpm-lock.yaml` (no versionado en
  `main`); **no se commitea** en esta corrida.
- **Transiciones de `ControlState`:** cubierto por PR #23. No se duplica.

## No se tocó

`src/security/**`, `src/identity/**`, `.github/**`, `.env*`, `package.json`,
`tsconfig*.json`, `src/evolution/evidence.ts`, `src/evolution/catalog.ts`,
`src/evolution/state-machine.ts`, `src/evolution/engine.ts`, y ningún archivo
fuera de los 2 del diff.
