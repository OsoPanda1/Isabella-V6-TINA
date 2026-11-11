import type { ControlState, EvolutionControl } from "../core/types";
import { generateControls } from "./catalog";
import { allowControlTransition, evolveControlState } from "./state-machine";

export interface WiringRegistry {
  controls: ReadonlyMap<string, EvolutionControl>;
  mode: "memory" | "external";
}

export interface EngineResult {
  controlId: string;
  previousState: ControlState;
  nextState: ControlState;
  evidenceRef?: string;
  humanApprover?: string;
}

/** La densificación sólo puede moverse por las transiciones canónicas. */
export function allowTransition(previous: ControlState, next: ControlState): boolean {
  return allowControlTransition(previous, next);
}

/**
 * La evolución no puede auto-registrarse como confiable: un nodo de IA no puede
 * pasar un control a `wired` por sí mismo; se requiere un aprobador humano.
 */
export function applyControlState(
  control: EvolutionControl,
  next: ControlState,
  opts: { evidenceRef?: string; humanApprover?: string } = {},
): EngineResult {
  if (!allowTransition(control.state, next)) {
    throw new Error(
      `Transición inválida: ${control.state} → ${next} para ${control.id}`,
    );
  }
  if (next === "wired" && !opts.humanApprover) {
    throw new Error(
      `Transición denegada: ${control.id} a 'wired' exige aprobación humana (Invariante Operativo).`,
    );
  }
  return {
    controlId: control.id,
    previousState: control.state,
    nextState: next,
    evidenceRef: opts.evidenceRef,
    humanApprover: opts.humanApprover,
  };
}

export function createEngine(): WiringRegistry {
  const controls = new Map(generateControls().map((c) => [c.id, c]));
  return { controls, mode: "memory" };
}

export { evolveControlState };
export type { EvolutionControl };