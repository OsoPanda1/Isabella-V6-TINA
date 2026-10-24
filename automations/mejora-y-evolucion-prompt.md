# Corrida diaria de Mejora y Evolución Quirúrgica

Repositorio objetivo: `OsoPanda1/Isabella-V6-TINA` (rama `main`).
Instrucción canónica: `docs/evolution/INSTRUCCION-MEJORA-Y-EVOLUCION.md` (si existe en el repo).
Comando: `/mejora-y-evolucion` (plugin `mejora-y-evolucion`).

Invariante rector: `CAPABILITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE ≠ LEARNING ≠ PRODUCTION`.
Tú propones, mides y verificas localmente; la persona decide, aprueba y ejecuta el merge.

---

Ejecuta **una** corrida quirúrgica de mejora y evolución. Una corrida = un
objetivo = un diff acotado = un PR en `draft`.

## 1. Línea base (solo lectura)
- `git rev-parse HEAD` y confirma `git status --porcelain` vacío.
- Registra el estado actual de: `pnpm typecheck`, `pnpm test`, `pnpm build`.

## 2. Reconocimiento acotado (solo lectura, sin modificar nada)
Recolecta señales verificables:
- Inventario de `src/` y `test/`.
- `TODO` sin dueño y sin fecha.
- Tipos laxos (`any`, `as never`) y duplicación evidente.
- Fallos actuales de typecheck/test/build.
- Divergencias entre el código y `docs/spec/**` o `docs/evolution/**`.

## 3. Selección de UNA sola brecha
`puntuación = severidad(1-5) × probabilidad(1-5) × (6 − coste_de_cambio(1-5))`.
Desempate estricto: `seguridad > correctitud > confiabilidad > rendimiento > deuda estructural`.
Responde en una frase: qué duele, por qué ahora, y qué NO se toca.

## 4. Límites duros — si el diff los excede, DETENTE y emite propuesta
- Objetivos por corrida: 1.
- Archivos modificados: ≤ 5.
- Líneas netas (añadidas + eliminadas): ≤ 200.
- Dependencias nuevas: 0.
- Cambios en `src/security/**`, `src/identity/**`, CI o `.env*`: 0. Si es necesario, detente y escala.
- Cambios de contrato/API pública: 0. Si es necesario, detente y escala.
- `any` nuevos, `as never`, `require()` dinámico: 0.

## 5. No-objetivos (prohibido)
No reescribas módulos completos; no migres frameworks ni gestores de paquetes;
no hagas refactors cosméticos masivos ni reformateos de archivos que no estás
corrigiendo; no toques secretos ni `.env.local`; no silencies pruebas ni relajes
tipos; no presentes simulación o fixtures como integración real.

## 6. Declaración antes de implementar
Declara: dominio V5 (ver `src/evolution/domains.ts`), `objective` en una frase,
`controlIds` del mismo dominio, `changeBlocks` (`CREATE|UPDATE|DELETE` +
`expectedInvariant`) y `evidenceRefs` previstos.

## 7. Implementación mínima verificable
El cambio más pequeño que cierra la brecha. Un comportamiento por cambio.
Comentarios y nombres de archivo en español; identificadores en inglés. Todo
`TODO` nuevo lleva dueño y fecha.

## 8. Verificación local (obligatoria, en este orden)
```
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```
Registra la salida real. Si algo falla, corrige o detente; no declares éxito.

## 9. Evidencia y propuesta
- Evidencia conforme a `src/evolution/evidence.ts` (`createEvidence`):
  `controlId`, `kind`, `uri` https, `commitSha`, `observedAt`, `passed`, `details`.
  Un `passed: true` autoemitido es una afirmación, no una verificación.
- Propuesta válida conforme a `src/evolution/proposals.ts`: `controlIds` del
  dominio declarado, ≥1 `changeBlock`, ≥1 `evidenceRef`, `requiresHumanApproval: true`.

## 10. Entrega
- Rama: `evolution/<YYYY-MM-DD>-<slug>`.
- Commit etiquetado `engine-generated`.
- **PR en `draft`** contra `main`. Nunca push directo a `main`. Nunca `force`
  sobre ramas compartidas.
- El PR describe: brecha, criterio de selección, diff, evidencia, riesgos y plan de rollback.

## 11. Idempotencia
Si ya existe una rama o PR `evolution/<slug>`, no repitas la mejora. Deduplica
hallazgos contra `docs/audit/**` y `docs/evolution/**`.

## 12. Parada segura
Detente y reporta sin ejecutar si el objetivo toca autoridad, política, secretos
o aislamiento de tenants; si la spec y el código se contradicen sin arbitraje; si
el diff excede un límite; o si el resultado no es verificable con evidencia.

## 13. Informe final (obligatorio)
```markdown
# Corrida de Mejora y Evolución — <YYYY-MM-DD>
- Commit base: <sha>
- Objetivo: <una frase>
- Criterio: severidad=<n> probabilidad=<n> coste=<n> → <puntuación>
- Dominio: <dominio V5> | ControlIds: <ids>
- Diff: <archivos> (<n> archivos, <m> líneas netas)
- Verificación: typecheck=<ok|fail> test=<ok|fail> build=<ok|fail>
- Evidencia: <evd_...>
- Propuesta: <proposalId>
- PR: <url> (draft)
- Estado: draft | requiresHumanApproval: true
- Riesgos y rollback: <...>
- No se tocó: <lista explícita>
```

Si no hay ninguna brecha que cumpla los límites, no fuerces un cambio:
reporta "sin cambio justificable" y explica por qué.
