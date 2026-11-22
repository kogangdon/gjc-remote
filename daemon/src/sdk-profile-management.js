import { buildSdkProfileManagementResult, validateSdkProfileManagementRequest } from '@gjc-remote/shared/sdk-profile-management.js';

// The native target authority binds an installation's manager and recipient,
// but does not authenticate the sender of a management request. Until native
// ingress can issue that proof, even status must not resolve a profile or read
// the decision store. Registration remains independent of this refusal.
export function createSdkProfileManagement() {
  return async function handle(request) {
    validateSdkProfileManagementRequest(request);
    return buildSdkProfileManagementResult({
      requestId: request.requestId,
      operation: request.operation,
      ok: false,
      code: 'MANAGEMENT_UNAVAILABLE',
    }, request);
  };
}
