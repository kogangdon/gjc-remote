import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSdkProfileManagementRequest,
  parseSdkProfileManagementResult,
  validateSdkProfileManagementResult,
} from '@gjc-remote/shared/sdk-profile-management.js';
import { createSdkProfileManagement } from '../src/sdk-profile-management.js';

const requests = ['status', 'allow', 'withdraw'].map(operation =>
  buildSdkProfileManagementRequest({
    operation,
    requestId: `${operation}-1`,
    ...(operation === 'status' ? {} : { expectedDecisionFingerprint: 'a'.repeat(64) }),
    ...(operation === 'allow' ? { candidateId: 'b'.repeat(64) } : {}),
  })
);

function forbiddenDependencies() {
  const calls = [];
  const options = {};
  for (const name of ['store', 'observeCandidate', 'native', 'authority']) {
    Object.defineProperty(options, name, {
      get() {
        calls.push(name);
        throw new Error('/private/profile must not be accessed');
      },
    });
  }
  return { options, calls };
}

test('unqualified status, allow and withdrawal refuse before any store or profile access', async () => {
  const { options, calls } = forbiddenDependencies();
  const handle = createSdkProfileManagement(options);
  for (const request of requests) {
    const reply = await handle(request);
    assert.deepEqual(reply, {
      type: 'sdk_profile_management_result',
      version: 1,
      requestId: request.requestId,
      operation: request.operation,
      ok: false,
      code: 'MANAGEMENT_UNAVAILABLE',
    });
    assert.equal(validateSdkProfileManagementResult(reply, request), reply);
    assert.deepEqual(parseSdkProfileManagementResult(Buffer.from(JSON.stringify(reply)), request), reply);
  }
  assert.deepEqual(calls, []);
});

test('transport credentials and JavaScript manager claims cannot qualify ingress', async () => {
  const { options, calls } = forbiddenDependencies();
  const claims = {
    token: 'daemon-token',
    role: 'management',
    managerIdentity: 'S-1-5-21-1-2-3-1001',
    authorized: true,
    trusted: true,
    enabled: true,
    channelId: 'manager-channel',
    member: true,
    authorize: () => true,
  };
  Object.defineProperties(claims, Object.getOwnPropertyDescriptors(options));
  const handle = createSdkProfileManagement(claims);
  for (const request of requests) {
    const reply = await handle(request, claims);
    assert.equal(reply.code, 'MANAGEMENT_UNAVAILABLE');
    assert.equal(validateSdkProfileManagementResult(reply, request), reply);
  }
  assert.deepEqual(calls, []);
});

test('malformed requests remain invalid rather than becoming authority or disclosing state', async () => {
  const { options, calls } = forbiddenDependencies();
  const handle = createSdkProfileManagement(options);
  const [status, allow, withdraw] = requests;
  for (const request of [
    null,
    { ...status, managerIdentity: 'S-1-5-21-1-2-3-1001' },
    { ...status, token: 'daemon-token' },
    { ...status, authorized: true },
    { ...allow, profile: { agentDir: '/private/profile' } },
    { ...allow, expectedDecisionFingerprint: null },
    { ...withdraw, candidateId: 'b'.repeat(64) },
    { ...status, operation: 'invoke' },
  ]) {
    await assert.rejects(handle(request), {
      name: 'TypeError', message: 'SDK_PROFILE_MANAGEMENT_INVALID',
    });
  }
  assert.deepEqual(calls, []);
});
