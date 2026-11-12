import { describe, expect, it } from "vitest";
import { validateProposal, type EvolutionProposal } from "../../src/evolution/proposals";

const controlId = "EV-11-GOVERNANCE.human_oversight.governance.validator";

function proposal(overrides: Partial<EvolutionProposal> = {}): EvolutionProposal {
  return {
    proposalId: "evo-test",
    proposalDomain: "human_oversight",
    objective: "probar la validación de propuestas",
    controlIds: [controlId],
    changeBlocks: [
      { path: "src/evolution/proposals.ts", change: "UPDATE", reason: "razón", expectedInvariant: "invariante" },
    ],
    evidenceRefs: ["evd_test"],
    requiresHumanApproval: true,
    ...overrides,
  };
}

describe("evolution/proposals", () => {
  it("acepta una propuesta completa con aprobación humana", () => {
    expect(() => validateProposal(proposal())).not.toThrow();
  });

  it("rechaza una propuesta que renuncia a la aprobación humana", () => {
    expect(() => validateProposal(proposal({ requiresHumanApproval: false }))).toThrow(/human approval/);
  });

  it("rechaza un dominio desconocido", () => {
    expect(() => validateProposal(proposal({ proposalDomain: "dominio_inexistente" }))).toThrow(/unknown proposal domain/);
  });

  it("rechaza controles fuera del dominio declarado", () => {
    expect(() => validateProposal(proposal({ controlIds: ["EV-03-CROWN.intent.governance.invariant"] }))).toThrow(
      /outside its declared domain/,
    );
  });

  it("rechaza una propuesta sin controles, bloques de cambio o evidencia", () => {
    expect(() => validateProposal(proposal({ controlIds: [] }))).toThrow(/at least one control/);
    expect(() => validateProposal(proposal({ changeBlocks: [] }))).toThrow(/at least one change block/);
    expect(() => validateProposal(proposal({ evidenceRefs: [] }))).toThrow(/reproducible evidence/);
  });
});
