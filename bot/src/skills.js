// Static mirror of `gjc skills list --json`. Re-run `npm run register` after
// upgrading GJC if the bundled skill set changes, so slash commands stay in sync.
export const GJC_SKILLS = [
  {
    name: "deep-interview",
    description: "Socratic requirements interview -> spec under .gjc/specs (read-only, no code edits)",
  },
  {
    name: "ralplan",
    description: "Consensus planning (Planner/Architect/Critic) -> pending-approval plan under .gjc/plans",
  },
  {
    name: "team",
    description: "tmux-backed coordinated multi-worker execution (requires an approved plan)",
  },
  {
    name: "ultragoal",
    description: "Durable multi-goal execution ledger under .gjc/ultragoal",
  },
];
