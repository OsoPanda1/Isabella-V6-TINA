# Corrida de Mejora y Evolución — 2026-11-16

> Este PR fue creado por un agente de IA (OpenHands) en nombre del usuario, como
> parte de la corrida diaria `/mejora-y-evolucion`. La persona decide, aprueba y
> ejecuta el merge.

- **Commit base:** `8dddc96` (`main`)
- **Objetivo:** exigir verificación criptográfica de la aprobación humana en el
  sandbox ORION (`runSandbox`), en lugar de aceptarla por su forma
  (`decision === "ALLOW"`).
- **Criterio de selección:** severidad=4 · probabilidad=4 · coste=1 →
  4×4×(6−1) = **80**
- **Dominio V5:** `sandbox` | **ControlIds:**
  `EV-10-AGENT_RUNTIME.sandbox.security.invariant`,
  `EV-10-AGENT_RUNTIME.sandbox.governance.validator`
- **Diff:** `src/orion/sandbox.ts`, `test/orion/sandbox.test.ts`
  (**2 archivos, 32 líneas netas**)
- **Verificación:** `typecheck=sin errores nuevos` · `test=ok (504/504)` ·
  `build=sin errores nuevos`
- **Evidencia:** `evd_17e0a6d15c568ed7bd9aaeea`, `evd_6ba666197dd32eca66b57260`
- **Propuesta:** `evo-2026-11-16-orion-sandbox-verify-approval`
- **Estado:** `draft` | `requiresHumanApproval: true`

## Línea base (F0)

| Puerta | Antes (`main` `8dddc96`) | Después |
|---|---|---|
| `pnpm typecheck` | **FAIL** — 19 errores en 3 archivos | FAIL — los **mismos 19**, 0 nuevos |
| `pnpm test` | PASS — 98 archivos, 502 pruebas | PASS — 98 archivos, **504 pruebas** |
| `pnpm build` | **FAIL** — 15 errores en 2 archivos | FAIL — los **mismos 15**, 0 nuevos |

Los 19 errores de `typecheck` (y los 15 de `build`) son **preexistentes** en
`main`, en `src/cognition/epistemic-evaluator.ts`, `src/server.ts` y
`test/cognition/epistemic-evaluator.test.ts`. Ya tienen corrida abierta: PR #21
(`evolution/2026-10-24-restore-typecheck-gate`). No se tocan aquí (idempotencia
§5). Esta corrida **no introduce errores nuevos**.

## Brecha seleccionada (F1–F2)

`src/orion/sandbox.ts` era el **único** consumidor de `ApprovalRef` que aceptaba
una aprobación humana por su **forma** y no por su **firma**:

```ts
if (NOT_REPLAYABLE.has(proposal.riskTier) && ctx.approval?.decision !== "ALLOW") { … }
```

El resto de consumidores sí verifican la firma ligada al method-id:

- `src/crown/capability.ts` → `verifyHumanApproval(req.approval, { methodId, … })`
- `src/tools/registry.ts` → `verifyHumanApproval(authorization.approval, { methodId: tool.methodId, … })`
- `src/skills/registry.ts` → `verifyHumanApproval(authorization.approval, { methodId: skill.methodId, … })`
- `src/identity/pdp.ts` → `verifyHumanApproval(approval, target)`

Una aprobación **forjada** —un objeto con `decision: "ALLOW"` pero sin firma
válida, sin binding de method-id y sin expiración— hacía que `runSandbox`
representara propuestas `HIGH`/`CRITICAL` en el plano paralelo, eludiendo el paso
de autoridad humana que exige el invariante operativo de `AGENTS.md`
(`CAPABILITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE ≠ LEARNING ≠ PRODUCTION`).

Evidencia del hallazgo (antes del cambio), con el módulo real:

```
$ npx tsx repro-orion.ts
passed: true | reason: 40 controles representados sin desviaciones en el plano paralelo
```

Donde `approval` era un objeto forjado con `decision: "ALLOW"` y firma `"s"`.

## Cambio (F4)

Mínimo y sin cambio de contrato público:

1. `src/orion/sandbox.ts` importa `verifyHumanApproval` y sustituye la
   comprobación de forma por `verifyHumanApproval(ctx.approval, { methodId: proposal.methodId })`.
   La firma de `runSandbox` no cambia.
2. `test/orion/sandbox.test.ts` añade dos pruebas negativas: (a) aprobación
   forjada sin firma; (b) aprobación firmada para **otro** method-id. Ambas
   **fallan sin el cambio y pasan con él** (verificado con `git stash`).

## Invariante de gobernanza

La evidencia se **generó** con los módulos reales del repositorio:

- `createEvidence` → ambos registros con `digest` íntegro (`verifyEvidenceIntegrity=true`).
- `validateProposal` → la propuesta valida (controlIds del dominio declarado,
  2 `changeBlock`, 2 `evidenceRef`).
- `canPromoteToVerified` **sin** verificador inyectado devuelve `false`: un
  `passed: true` autoemitido es una **afirmación**, no una verificación.

Ningún control pasa a `verified` ni a `wired` desde esta corrida.

## No se tocó

`src/security/**`, `src/identity/**`, `.github/**`, `.env*`, `package.json`,
`tsconfig*.json`, `src/orion/proposal.ts`, `src/pipeline/conductor.ts` y ningún
archivo fuera de los 2 del diff.

## Riesgos y rollback

- **Riesgo:** una aprobación válida emitida sin `ISABELLA_APPROVAL_TRUSTED_*`
  configurado en runtime de producción no verificaría (fail-closed). Es el
  comportamiento **deseado** y coincide con CROWN/TOOLS/SKILLS/PDP.
- **Rollback:** `git revert` del commit; el diff son 2 archivos y no cambia API
  pública ni persistencia.
