function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }

  for (const nestedValue of Object.values(value)) {
    deepFreeze(nestedValue);
  }

  return Object.freeze(value);
}

export const DEPLOYMENT_FORMAT_REGISTRY = deepFreeze({
  bot: {
    domain: "bot-mapping-reader",
    formats: [
      { formatId: "admission:admission-ack@1", marker: { version: 1, kind: "admission-ack" }, source: "shared/admission-envelope.js" },
      { formatId: "admission:admission-grant@1", marker: { version: 1, kind: "admission-grant" }, source: "shared/admission-envelope.js" },
      { formatId: "admission:admission-request@1", marker: { version: 1, kind: "admission-request" }, source: "shared/admission-envelope.js" },
      { formatId: "admission:finality-proof@1", marker: { version: 1, kind: "finality-proof" }, source: "shared/admission-envelope.js" },
      { formatId: "channels:gjc-management-channels/v2", marker: { version: 2, managementStamp: "gjc-management-channels/v2" }, source: "shared/mapping-envelope.js" },
      { formatId: "control:management-control-root@1", marker: { version: 1, kind: "management-control-root", managementStamp: "gjc-management-control/v1" }, source: "shared/mapping-envelope.js" },
      { formatId: "floor:authority-epoch-floor@1", marker: { version: 1, kind: "authority-epoch-floor" }, source: "shared/managed-authority-proof.js" },
      { formatId: "floor:fence-generation-floor@1", marker: { version: 1, kind: "fence-generation-floor" }, source: "shared/managed-authority-proof.js" },
      { formatId: "floor:reader-version-floor@1:null", marker: { version: 1, kind: "reader-version-floor", readerVersionFloor: null }, source: "shared/genesis-envelope.js" },
      { formatId: "floor:reader-version-floor@1:reader-2", marker: { version: 1, kind: "reader-version-floor", readerVersionFloor: 2 }, source: "shared/genesis-envelope.js" },
      { formatId: "floor:token-generation-floor@1", marker: { version: 1, kind: "token-generation-floor" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:attested-token-floor-proof@1", marker: { version: 1, kind: "attested-token-floor-proof" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:authority-baseline@1", marker: { version: 1, kind: "authority-baseline" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:authority-commit-snapshot@1", marker: { version: 1, kind: "authority-commit-snapshot" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:authority-epoch@1", marker: { version: 1, kind: "authority-epoch" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:authority-reservation@1", marker: { version: 1, kind: "authority-reservation" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:genesis-authority-receipt@1", marker: { version: 1, kind: "genesis-authority-receipt", sequence: 2 }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:genesis-authority-request@1", marker: { version: 1, kind: "genesis-authority-request", sequence: 1 }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:genesis-finality@1", marker: { version: 1, kind: "genesis-finality" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:genesis-precommit-proof@1", marker: { version: 1, kind: "genesis-precommit-proof" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:genesis-receipt@1", marker: { version: 1, kind: "genesis-receipt" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:genesis-request@1", marker: { version: 1, kind: "genesis-request" }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:reader-fence-binding@1:reader-2", marker: { version: 1, kind: "reader-fence-binding", readerVersion: 2 }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:reader-lease-binding@1:reader-2", marker: { version: 1, kind: "reader-lease-binding", readerVersion: 2 }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:reader-projection@1:reader-2", marker: { version: 1, kind: "reader-projection", readerVersion: 2 }, source: "shared/genesis-envelope.js" },
      { formatId: "genesis:token-config-attestation@1", marker: { version: 1, kind: "token-config-attestation", managedGrammarVersion: 1 }, source: "shared/genesis-envelope.js" },
      { formatId: "history:managed-history-marker@1", marker: { version: 1, kind: "managed-history-marker" }, source: "shared/successor-envelope.js" },
      { formatId: "mapping:mappingVersion/1", marker: { mappingVersion: 1 }, source: "shared/mapping-envelope.js" },
      { formatId: "publication:publication-c@1", marker: { version: 1, kind: "publication-c" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-k@1", marker: { version: 1, kind: "publication-k" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-p@1", marker: { version: 1, kind: "publication-p" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-q@1", marker: { version: 1, kind: "publication-q" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-s@1", marker: { version: 1, kind: "publication-s" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-state@1", marker: { version: 1, kind: "publication-state" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-transaction@1", marker: { version: 1, kind: "publication-transaction" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-u@1", marker: { version: 1, kind: "publication-u" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-y@1", marker: { version: 1, kind: "publication-y" }, source: "shared/publication-envelope.js" },
      { formatId: "publication:publication-zp@1", marker: { version: 1, kind: "publication-zp" }, source: "shared/publication-envelope.js" },
      { formatId: "reader-state:readerVersion/2", marker: { readerVersion: 2 }, source: "shared/genesis-envelope.js" },
      { formatId: "recovery:genesis-suffix-recovery@1", marker: { version: 1, kind: "genesis-suffix-recovery" }, source: "shared/recovery-envelope.js" },
      { formatId: "recovery:manual-cleanup@1", marker: { version: 1, kind: "manual-cleanup" }, source: "shared/recovery-envelope.js" },
      { formatId: "recovery:mapping-recovery-bk@1", marker: { version: 1, kind: "mapping-recovery-bk" }, source: "shared/recovery-envelope.js" },
      { formatId: "recovery:mapping-recovery-pub@1", marker: { version: 1, kind: "mapping-recovery-pub" }, source: "shared/recovery-envelope.js" },
      { formatId: "recovery:mapping-recovery-rc@1", marker: { version: 1, kind: "mapping-recovery-rc" }, source: "shared/recovery-envelope.js" },
      { formatId: "recovery:mapping-recovery-tx@1", marker: { version: 1, kind: "mapping-recovery-tx" }, source: "shared/recovery-envelope.js" },
      { formatId: "successor:authority-close-proof@1", marker: { version: 1, kind: "authority-close-proof" }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-ack@1:reader-2", marker: { version: 1, kind: "authority-successor-ack", readerVersion: 2 }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-baseline@1", marker: { version: 1, kind: "authority-successor-baseline" }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-fence@1:reader-2", marker: { version: 1, kind: "authority-successor-fence", readerVersion: 2 }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-finality@1", marker: { version: 1, kind: "authority-successor-finality" }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-head@1", marker: { version: 1, kind: "authority-successor-head" }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-lease@1:reader-2", marker: { version: 1, kind: "authority-successor-lease", readerVersion: 2 }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-reader-projection@1:reader-2", marker: { version: 1, kind: "authority-successor-reader-projection", readerVersion: 2 }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-receipt@1", marker: { version: 1, kind: "authority-successor-receipt" }, source: "shared/successor-envelope.js" },
      { formatId: "successor:authority-successor-request@1", marker: { version: 1, kind: "authority-successor-request" }, source: "shared/successor-envelope.js" },
      { formatId: "wrapper:legacy-retained-wrapper@1:reader-null", marker: { version: 1, kind: "legacy-retained-wrapper", managementStamp: "gjc-management-envelope/v1", readerVersion: null }, source: "shared/mapping-envelope.js" },
      { formatId: "wrapper:managed-v1-wrapper@1:reader-2", marker: { version: 1, kind: "managed-v1-wrapper", managementStamp: "gjc-management-envelope/v1", readerVersion: 2 }, source: "shared/mapping-envelope.js" },
      { formatId: "wrapper:managed-v1-wrapper@1:reader-null", marker: { version: 1, kind: "managed-v1-wrapper", managementStamp: "gjc-management-envelope/v1", readerVersion: null }, source: "shared/mapping-envelope.js" },
    ],
  },
  daemonAppSession: {
    domain: "daemon-app-session",
    formats: [
      { formatId: "sdk-session:transcript@5", marker: { type: "session", version: 5 }, source: "@gajae-code/coding-agent/src/session/session-manager.ts" },
    ],
  },
  workspaceLifecycle: {
    domain: "workspace-lifecycle",
    formats: [
      { formatId: "workspace:manual-cleanup@1", marker: { version: 1, kind: "manual-cleanup" }, source: "shared/recovery-envelope.js" },
      { formatId: "workspace:workspace-lifecycle-checkpoint@1", marker: { version: 1, kind: "workspace-lifecycle-checkpoint" }, source: "shared/workspace-lifecycle-envelope.js" },
      { formatId: "workspace:workspace-lifecycle-head@1", marker: { version: 1, kind: "workspace-lifecycle-head" }, source: "shared/workspace-lifecycle-envelope.js" },
      { formatId: "workspace:workspace-lifecycle-transaction@1", marker: { version: 1, kind: "workspace-lifecycle-transaction" }, source: "shared/workspace-lifecycle-envelope.js" },
    ],
  },
});
