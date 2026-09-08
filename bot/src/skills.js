// Static mirror of the pinned SDK's bundled workflow catalog. Re-run `npm run register` after
// upgrading GJC if the bundled skill set changes, so slash commands stay in sync.
export const GJC_SKILLS = [
  {
    name: "deep-interview",
    description: "Socratic requirements interview -> session-scoped spec (read-only, no code edits)",
  },
  {
    name: "ralplan",
    description: "Consensus planning (Planner/Architect/Critic) -> session-scoped pending-approval plan",
  },
  {
    name: "autoresearch",
    description: "Goal-directed research -> evidence-backed verdict, not implementation",
  },
  {
    name: "ultragoal",
    description: "Durable session-scoped multi-goal execution ledger",
  },
];
