---
name: mejora-y-evolucion
description: >-
  Instrucción quirúrgica de mejora y evolución para Isabella Villaseñor AI.
  Ejecuta una corrida diaria acotada: un objetivo, un diff pequeño, evidencia
  reproducible y un PR en draft sujeto a aprobación humana. Úsala cuando se
  pida "mejora y evolución", "evolucionar el repositorio", "corrida diaria de
  mejora", "densificar controles" o "/mejora-y-evolucion".
triggers:
- /mejora-y-evolucion
---

# Mejora y Evolución Quirúrgica — Isabella Villaseñor AI

Lee y aplica íntegramente `docs/evolution/INSTRUCCION-MEJORA-Y-EVOLUCION.md` del
repositorio objetivo. Este archivo es la versión ejecutable y autocontenida de
esa instrucción.

## Invariante rector

`CAPABILITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE ≠ LEARNING ≠ PRODUCTION`

Tú propones, mides y verificas localmente. La persona decide, aprueba y ejecuta
el merge. Un test verde demuestra capacidad computacional; no demuestra
autoridad, ni facultad, ni producción.

## Contrato de la corrida

Una corrida = **un objetivo** = **un diff acotado** = **un PR en `draft`**.

Si el diff excede un límite duro, **no se ejecuta**: se emite una propuesta y se
detiene.

## Límites duros

| Límite | Valor | Al exceder |
|---|---:|---|
| Objetivos por corrida | 1 | detener |
| Archivos modificados | ≤ 5 | detener |
| Líneas netas | ≤ 200 | detener |
| Dependencias nuevas | 0 | detener |
| `src/security/**`, `src/identity/**`, CI, `.env*` | 0 cambios | detener y escalar |
| Contrato/API pública | 0 cambios | detener y escalar |
| `any`, `as never`, `require()` dinámico | 0 nuevos | detener |

## No-objetivos

Prohibido: reescribir módulos completos, migrar frameworks o gestores de
paquetes, refactors cosméticos masivos, reformatear archivos que no se corrigen,
tocar secretos o `.env.local`, silenciar pruebas, relajar tipos, y presentar
simulación o fixtures como integración real.

## Procedimiento

**F0 — Línea base (solo lectura).** `git rev-parse HEAD`, `git status
--porcelain` vacío, y registrar el estado actual de `pnpm typecheck`,
`pnpm test`, `pnpm build`.

**F1 — Reconocimiento acotado (solo lectura).** Inventario de `src/` y
`test/`; `TODO` sin dueño/fecha; tipos laxos; duplicación evidente; fallos
actuales de verificación; divergencias código ↔ `docs/spec/**`. No escribir nada.

**F2 — Selección de una sola brecha.**
`puntuación = severidad(1-5) × probabilidad(1-5) × (6 − coste(1-5))`.
Desempate: `seguridad > correctitud > confiabilidad > rendimiento > deuda`.

**F3 — Declaración.** Dominio V5 conocido (`src/evolution/domains.ts`),
`objective` en una frase, `controlIds` del mismo dominio, `changeBlocks` y
`evidenceRefs` previstos.

**F4 — Implementación mínima.** El cambio más pequeño que cierra la brecha.
Comentarios y nombres de archivo en español; identificadores en inglés. Sin
`any`, sin `as never`, sin `require()` dinámico. Todo `TODO` nuevo lleva dueño y
fecha.

**F5 — Verificación local (obligatoria, en este orden).**
```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```
Registra la salida real. Si algo falla, corrige o detén la corrida; no declares
éxito.

**F6 — Evidencia.** Registros conforme a `src/evolution/evidence.ts`
(`createEvidence`): `controlId`, `kind`, `uri` https, `commitSha`, `observedAt`,
`passed`, `details`. Un `passed: true` autoemitido es una afirmación, no una
verificación.

**F7 — Propuesta.** `EvolutionProposal` válida (`src/evolution/proposals.ts`):
`controlIds` del dominio declarado, ≥1 `changeBlock`, ≥1 `evidenceRef`,
`requiresHumanApproval: true`.

**F8 — Entrega.** Rama `evolution/<YYYY-MM-DD>-<slug>`; commit etiquetado
`engine-generated`; **PR en `draft`**. Nunca push directo a `main`, nunca
`force` sobre ramas compartidas.

**F9 — Informe.** Obligatorio (§8 de la instrucción). Sin informe, la corrida no
está completa.

## Parada segura

Detén y reporta sin ejecutar cuando el objetivo toque autoridad, política,
secretos o aislamiento de tenants; cuando la spec y el código se contradigan sin
arbitraje; cuando el diff exceda un límite; o cuando el resultado no sea
verificable con evidencia reproducible.

## Idempotencia

Si ya existe una rama o PR `evolution/<slug>`, no repitas la mejora. Deduplica
hallazgos contra `docs/audit/**` y `docs/evolution/**`.

## Registro y salida

Registra el cambio de estado de capacidad en BookPI (ledger append-only). Deja
como artefactos: informe, evidencia y propuesta.
