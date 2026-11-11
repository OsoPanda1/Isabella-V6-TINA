/**
 * Máquina de estados de controles V5.
 * Estados: declared → wired → verified → blocked.
 * La densificación es un aumento de evidencia, no una autoproclamación.
 */
import type { ControlState } from "../core/types";

export const CONTROL_STATE_ORDER: ControlState[] = [
  "declared",
  "wired",
  "verified",
  "blocked",
];

export const MAX_EVIDENCE_INDEX = CONTROL_STATE_ORDER.indexOf("verified");

export function stateRank(state: ControlState): number {
  const rank = CONTROL_STATE_ORDER.indexOf(state);
  if (rank === -1) {
    throw new Error(`Estado desconocido: ${state}`);
  }
  return rank;
}

/**
 * Transiciones autorizadas del ciclo de vida de un control V5.
 * Fuente única: el motor (`engine.ts`) y `evolveControlState` leen de esta
 * tabla, de modo que no puedan divergir. Un control no puede saltar de
 * `declared` a `verified`: `wired` es el paso que exige aprobación humana y no
 * se omite.
 */
export const CONTROL_TRANSITIONS: Readonly<Record<ControlState, readonly ControlState[]>> = {
  declared: ["wired", "blocked"],
  wired: ["verified", "blocked", "declared"],
  verified: ["blocked", "declared"],
  blocked: ["declared"],
};

export function allowControlTransition(previous: ControlState, next: ControlState): boolean {
  return CONTROL_TRANSITIONS[previous].includes(next);
}

export function evolveControlState(previous: ControlState, next: ControlState): ControlState {
  if (previous === next) {
    return previous;
  }
  if (!allowControlTransition(previous, next)) {
    throw new Error(`Transición de control no autorizada: ${previous} → ${next}`);
  }
  return next;
}