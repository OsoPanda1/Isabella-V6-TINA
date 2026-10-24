# Instrucción de Mejora y Evolución Quirúrgica — Isabella Villaseñor AI

**Versión:** 2.0.0
**Estado:** `draft | auto_generated`
**Cadencia:** una corrida al día (una mejora verificable por corrida).
**Invariante rector:** `CAPABILITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE ≠ LEARNING ≠ PRODUCTION`
**Autoridad:** la IA propone, mide y verifica localmente; la persona decide, aprueba y ejecuta el merge.

---

## 0. Contrato de la corrida

Una corrida = **un objetivo** = **un diff acotado** = **un PR en `draft`**.

- La mejora se **declara** antes de implementarse (issue o `control state`).
- La evidencia se **genera**, no se proclama: un test verde demuestra capacidad
  computacional, nunca autoridad ni producción.
- Nada pasa a `verified` sin evidencia reproducible **y** aprobación humana con
  nombre. Nada pasa a `wired` desde esta corrida.
- Si el diff excede los límites duros (§1), la corrida **se degrada a propuesta**
  y **no se ejecuta**.

## 1. Límites duros (esto es lo que hace la corrida quirúrgica)

| Límite | Valor | Acción al exceder |
|---|---:|---|
| Objetivos por corrida | 1 | detener |
| Archivos modificados | ≤ 5 | detener |
| Líneas netas (añadidas + eliminadas) | ≤ 200 | detener |
| Dependencias nuevas | 0 | detener |
| Cambios en `src/security/**`, `src/identity/**`, CI, `.env*` | 0 | detener y escalar |
| Cambios de contrato/API pública | 0 | detener y escalar |
| `any` nuevos, `as never`, `require()` dinámico | 0 | detener |

**Regla de degradación:** cualquier detención por límite produce una
`EvolutionProposal` (§7), no un commit.

## 2. No-objetivos (prohibido en esta corrida)

- Reescribir o "modernizar" módulos completos.
- Migrar frameworks, gestores de paquetes o motores de build.
- Refactors cosméticos masivos, renombrados globales, reformateos de archivos
  que no se están corrigiendo.
- Regenerar secretos, tocar `.env.local`, o añadir telemetría con egress.
- Silenciar pruebas, relajar tipos, o ampliar `skip`/`only`.
- Presentar simulación, fixture o adaptador sin configurar como integración real.

## 3. Fases

### F0 — Contexto y línea base (solo lectura)
1. Confirmar repo, rama y commit base: `git rev-parse HEAD`.
2. Confirmar árbol limpio: `git status --porcelain` debe estar vacío.
3. Fijar la línea base con los comandos de verificación del repo.
4. Registrar el digest de la matriz de control: `pnpm vitest run test/evolution`.

### F1 — Reconocimiento acotado (solo lectura, sin modificar nada)
Medir **antes** de tocar. Recolectar, como máximo, estas señales:

- Inventario: archivos bajo `src/`, archivos de prueba, rutas, scripts.
- Deuda verificable: `TODO` sin dueño/fecha, tipos laxos, duplicación evidente.
- Estado de verificación: qué falla hoy (`typecheck`, `test`, `build`).
- Divergencias código ↔ spec en `docs/spec/**` y `docs/evolution/**`.

**Prohibido** en esta fase: escribir, formatear o "de paso" arreglar algo.

### F2 — Selección quirúrgica (una sola brecha)
Elegir **una** brecha con criterio explícito y reproducible:

```
puntuación = severidad(1-5) × probabilidad(1-5) × (6 − coste_de_cambio(1-5))
```

Desempate en este orden estricto:
`seguridad > correctitud > confiabilidad > rendimiento > deuda estructural`.

Se debe poder responder en una frase: **qué duele, por qué ahora, y qué NO se
toca**.

### F3 — Declaración de intención
Declarar antes de implementar:
- `proposalDomain` (dominio V5 conocido; ver `src/evolution/domains.ts`).
- `objective` en una frase.
- `controlIds` afectados (del mismo dominio).
- `changeBlocks` previstos (`CREATE|UPDATE|DELETE` + `expectedInvariant`).
- `evidenceRefs` que se van a producir.

### F4 — Implementación mínima verificable
- El cambio más pequeño que cierra la brecha.
- Un comportamiento por cambio; sin efectos colaterales no declarados.
- Comentarios y nombres de archivo en español; identificadores en inglés.
- Sin `any`, sin `as never`, sin `require()` dinámico.
- Todo `TODO` nuevo lleva dueño y fecha, o no se escribe.

### F5 — Verificación local (obligatoria, en este orden)
```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```
Registrar la salida real. Si algo falla, **no** se declara éxito: se corrige o se
detiene la corrida.

### F6 — Evidencia
Crear registros con el contrato real de `src/evolution/evidence.ts`
(`createEvidence`): `controlId`, `kind`, `uri` (https), `commitSha`,
`observedAt`, `passed`, `details`. Un `passed: true` autoemitido es **una
afirmación**, no una verificación: la promoción exige un verificador inyectado
(`canPromoteToVerified`).

### F7 — Propuesta de evolución
Emitir una `EvolutionProposal` (`src/evolution/proposals.ts`) válida:
`controlIds` del dominio declarado, ≥1 `changeBlock`, ≥1 `evidenceRef`,
`requiresHumanApproval: true`.

### F8 — Entrega
- Rama: `evolution/<YYYY-MM-DD>-<slug>`.
- Commit con la etiqueta de origen: `engine-generated` | `human-approved` |
  `human-authored`.
- **PR en `draft`**. Nunca push directo a `main`. Nunca `force` sobre ramas
  compartidas.
- El PR describe: brecha, criterio de selección, diff, evidencia, riesgos y
  plan de rollback.

### F9 — Informe
Emitir el informe del §8. Sin el informe, la corrida no cuenta como completa.

## 4. Criterio de parada segura

Detener la corrida y reportar (sin ejecutar) cuando:
- El objetivo toca autoridad, política, secretos o aislamiento de tenants.
- La spec y el código se contradicen y el arbitraje no está resuelto.
- El diff previsto excede cualquier límite de §1.
- No hay forma de verificar el resultado con evidencia reproducible.

## 5. Idempotencia y anti-duplicación

- Si ya existe una rama o PR `evolution/<slug>` abierto, **no repetir** la mejora.
- Deduplicar hallazgos contra `docs/audit/**` y `docs/evolution/**`.
- Una mejora ya aplicada y verificada no se vuelve a proponer.

## 6. Registro

Todo cambio de estado de capacidad se registra en BookPI (ledger append-only).
La corrida deja: informe, evidencia y propuesta como artefactos trazables.

## 7. Formato de la propuesta (JSON)

```json
{
  "proposalId": "evo-<YYYY-MM-DD>-<slug>",
  "proposalDomain": "<dominio V5>",
  "objective": "<una frase>",
  "controlIds": ["<control del dominio>"],
  "changeBlocks": [
    { "path": "src/...", "change": "UPDATE", "reason": "...", "expectedInvariant": "..." }
  ],
  "evidenceRefs": ["evd_..."],
  "requiresHumanApproval": true
}
```

## 8. Formato del informe (obligatorio)

```markdown
# Corrida de Mejora y Evolución — <YYYY-MM-DD>
- Commit base: <sha>
- Objetivo: <una frase>
- Criterio de selección: severidad=<n> probabilidad=<n> coste=<n> → <puntuación>
- Dominio: <dominio V5>  |  ControlIds: <ids>
- Diff: <archivos> (<n> archivos, <m> líneas netas)
- Verificación: typecheck=<ok|fail> test=<ok|fail> build=<ok|fail>
- Evidencia: <evd_...>
- Propuesta: <proposalId>
- PR: <url> (draft)
- Estado: draft  |  requiresHumanApproval: true
- Riesgos y rollback: <...>
- No se tocó: <lista explícita>
```

## 9. Invariantes heredados de `AGENTS.md`

- No borrar historia; no `force` sobre ramas compartidas.
- No ocultar errores: se reportan y se corrigen en el abierto.
- `TODO` sin dueño y sin fecha está prohibido.
- Aprobar PRs sin revisión está prohibido.
- En conflicto entre código y spec, gana la spec; la divergencia se archiva para
  arbitraje humano.
- Un test verde no es una facultad, ni una autoridad, ni producción.
