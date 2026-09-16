import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { capabilitySignatures, contractRevision } from '../src/index.js';
import { createOfflineDeploymentSource } from '../src/service-offline-source.js';

const require = createRequire(import.meta.url);
const addonPath = fileURLToPath(new URL('../build/Release/native_control.node', import.meta.url));
const sourcePath = fileURLToPath(new URL('../src/addon.cc', import.meta.url));

const storeSignatures = {
  open_service_root: ['rootKind', 'roles', 'access'],
  open_service_directory: ['parentHandle', 'name', 'access', 'expectedIdentity', 'lockHandle'],
  acquire_service_lock: ['controlRootHandle', 'scope', 'serviceKey', 'mode'],
  close_service_handle: ['handle'],
  read_service_file: ['parentHandle', 'name', 'maxBytes'],
  publish_service_file_atomic: ['parentHandle', 'name', 'bytes', 'expected', 'lockHandle'],
  remove_service_object_exact: ['parentHandle', 'name', 'expected', 'lockHandle'],
  list_service_directory: ['directoryHandle', 'maxEntries', 'lockHandle'],
  publish_service_directory_no_replace: ['sourceDirectoryHandle', 'destinationParentHandle', 'name', 'expectedSourceIdentity', 'artifactLockHandle'],
  open_linux_service_scope: ['roles', 'serviceKey', 'access'],
  read_linux_service_object: ['scopeHandle', 'objectKind'],
  publish_linux_service_object: ['scopeHandle', 'objectKind', 'bytes', 'expected', 'lockHandle'],
  remove_linux_service_object: ['scopeHandle', 'objectKind', 'expected', 'lockHandle'],
  begin_service_artifact_write: ['parentHandle', 'name', 'expectedSize', 'expectedSha256', 'artifactLockHandle'],
  write_service_artifact_chunk: ['writerHandle', 'expectedOffset', 'bytes'],
  finish_service_artifact_write: ['writerHandle', 'finalProfile'],
  open_service_artifact_reader: ['parentHandle', 'name', 'maxBytes', 'expectedFacts', 'artifactLockHandle'],
  read_service_artifact_chunk: ['readerHandle', 'expectedOffset', 'maxBytes'],
  remove_service_artifact_file_exact: ['parentHandle', 'name', 'expectedFacts', 'artifactLockHandle'],
  seal_service_directory: ['directoryHandle', 'expectedIdentity', 'artifactLockHandle'],
  open_service_artifact_source: ['path', 'maxBytes', 'expectedFacts', 'roles'],
};

function addon() {
  assert.equal(existsSync(addonPath), true, 'revision-4 native addon must be built before this integration gate');
  return require(addonPath);
}

function sourceReaderRoles(native) {
  const current = native.current_os_principal();
  const kind = process.platform === 'win32' ? 'sid' : 'uid';
  const system = { kind, value: kind === 'sid' ? 'S-1-5-18' : 'uid:0' };
  assert.equal(current?.kind, kind);
  // Read existing user principals only; no account or service is provisioned.
  // Only the current M/S caller operates, so this is not workload ACL evidence.
  let observed;
  if (kind === 'sid') {
    const result = spawnSync('powershell.exe', [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      'Get-LocalUser | ForEach-Object { $_.SID.Value }',
    ], { encoding: 'utf8', timeout: 10_000, windowsHide: true });
    assert.equal(result.error, undefined, 'read-only local user enumeration must run');
    assert.equal(result.status, 0, 'read-only local user enumeration must succeed');
    observed = result.stdout.split(/\r?\n/).map((value) => value.trim())
      .filter((value) => /^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/.test(value));
  } else {
    observed = readFileSync('/etc/passwd', 'utf8').split('\n')
      .map((line) => line.split(':')[2])
      .filter((uid) => /^(0|[1-9][0-9]*)$/.test(uid))
      .map((uid) => `uid:${uid}`);
  }
  const candidates = [...new Set(observed)]
    .filter((value) => value !== current.value && value !== system.value);
  assert.ok(
    candidates.length >= (current.value === system.value ? 4 : 3),
    'source reader evidence requires five distinct existing users; absence is not a passing skip',
  );
  const management = current.value === system.value
    ? { kind, value: candidates.shift() }
    : current;
  return {
    management,
    bot: { kind, value: candidates[0] },
    recovery: { kind, value: candidates[1] },
    daemon: { kind, value: candidates[2] },
    system,
  };
}

test('revision 4 exposes the exact service store and Linux object substrate', () => {
  assert.equal(contractRevision, 4);
  assert.deepEqual(
    Object.fromEntries(Object.keys(storeSignatures).map((name) => [name, capabilitySignatures[name]])),
    storeSignatures,
  );
  const native = addon();
  for (const name of Object.keys(storeSignatures)) assert.equal(typeof native[name], 'function', name);
});

test('ordinary suite rejects store calls without native retained authority and performs no fixed-root mutation', () => {
  const native = addon();
  for (const invoke of [
    () => native.open_service_root('not-a-root', {}, 'create-new'),
    () => native.open_service_directory({}, 'transaction', 'read-existing', {}, null),
    () => native.acquire_service_lock({}, 'artifact', null, 'exclusive'),
    () => native.close_service_handle({}),
    () => native.read_service_file({}, 'record.json', 1024),
    () => native.publish_service_file_atomic({}, 'record.json', Buffer.from('{}'), null, {}),
    () => native.remove_service_object_exact({}, 'record.json', {}, {}),
    () => native.list_service_directory({}, 10, {}),
    () => native.publish_service_directory_no_replace({}, {}, '0'.repeat(64), {}, {}),
    () => native.begin_service_artifact_write({}, 'archive.bin', 0, '0'.repeat(64), {}),
    () => native.write_service_artifact_chunk({}, 0, Buffer.from('x')),
    () => native.finish_service_artifact_write({}, 'service-staging-file'),
    () => native.open_service_artifact_reader({}, 'archive.bin', 1, null, {}),
    () => native.read_service_artifact_chunk({}, 0, 1),
    () => native.remove_service_artifact_file_exact({}, 'archive.bin', {}, {}),
    () => native.seal_service_directory({}, {}, {}),
    () => native.open_service_artifact_source('relative.bin', 1, null, {}),
  ]) {
    assert.throws(invoke, (error) => error.code === 'SERVICE_INVALID' && error.writes === 0);
  }
});

test('native store source fixes roots, witnesses, profiles, lock ordering, and no-replace publication', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const lockSource = source.slice(
    source.indexOf('bool ServiceLockNames'),
    source.indexOf('napi_value CloseServiceHandle'),
  );
  const publishStart = source.indexOf('napi_value PublishServiceFileAtomic');
  const publishEnd = source.indexOf('napi_value ListServiceDirectory', publishStart);
  assert.ok(publishStart >= 0 && publishEnd > publishStart);
  const publishSource = source.slice(publishStart, publishEnd);
  assert.equal(lockSource.length > 0, true);
  assert.equal(publishSource.length > 0, true);
  for (const literal of [
    '/var/lib/gjc-remote',
    '/opt/gjc-remote',
    'service-control',
    '.staging',
    'releases',
    'GJC_REMOTE_SERVICE_ROOT_V1',
    'GJC_REMOTE_SERVICE_LOCK_V1',
    'GJC_REMOTE_SERVICE_CONTAINER_V1',
    'GJC_REMOTE_SERVICE_SHAWL_PARENT_V1',
    'service-internal-container-directory',
    'service-preserved-container-directory',
    'service-control-directory',
    'service-control-file',
  ]) assert.equal(source.includes(literal), true, literal);
  assert.match(lockSource, /scope == "artifact"[\s\S]*\*rank = 1/);
  assert.match(lockSource, /scope == "shared-template"[\s\S]*\*rank = 2/);
  assert.match(lockSource, /scope == "service-key"[\s\S]*\*rank = 3/);
  assert.match(lockSource, /LOCKFILE_FAIL_IMMEDIATELY/);
  assert.match(lockSource, /LOCK_NB/);
  assert.match(publishSource, /RenameAt2\([\s\S]*expected_present \? 2u : 1u/);
  assert.match(publishSource, /ReplaceFileW\([\s\S]*REPLACEFILE_WRITE_THROUGH/);
  assert.match(source, /name == "floor" \|\| name == "tombstone" \|\|[\s\S]*name == "locks"/);
  assert.match(source, /"rootPath", root->root_path/);
  assert.match(source, /GJC_REMOTE_SERVICE_ROOT_V1\\n"[\s\S]*<< root_path << "\\n"/);
  assert.match(source, /kind != expected_kind \|\| path != expected_path/);
  assert.doesNotMatch(source, /GJC_REMOTE_SERVICE_(?:ROOT|LOCK).*getenv/);
});

test('fixed intermediary bootstrap reserves durable history before exposure and keeps status zero-write', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const prepareStart = source.indexOf('ServiceContainerState PrepareServiceBaseContainer');
  const prepareEnd = source.indexOf('bool ServiceStoreNamedDirectoryExact', prepareStart);
  const openStart = source.indexOf('napi_value OpenServiceRoot');
  const openEnd = source.indexOf('bool ServiceLockNames', openStart);
  assert.ok(prepareStart >= 0 && prepareEnd > prepareStart);
  assert.ok(openStart >= 0 && openEnd > openStart);
  const prepare = source.slice(prepareStart, prepareEnd);
  const open = source.slice(openStart, openEnd);

  assert.match(source, /GJC_REMOTE_SERVICE_CONTAINER_V1/);
  assert.match(source, /service-internal-container-directory/);
  assert.match(source, /spec->anchor_path = "\/var\/lib"/);
  assert.match(source, /spec->anchor_path = "\/opt"/);
  assert.match(source, /spec->name = "gjc-remote"/);
  assert.match(source, /FOLDERID_ProgramData/);
  assert.match(prepare, /ServiceStoreOpenBootstrapAnchor\(\s*spec\.anchor_path, false/);
  assert.match(prepare, /ServiceStoreOpenBootstrapAnchor\(\s*spec\.anchor_path, true/);
  assert.ok(
    prepare.indexOf('spec.anchor_path, false') <
      prepare.indexOf('spec.anchor_path, true'),
    'existing-container inspection must not request ancestor creation rights',
  );
  assert.match(prepare, /VerifyBootstrapAnchor\(anchor, roles, true\)/);
  assert.ok(
    prepare.indexOf('CreateServiceStoreFile(') < prepare.indexOf('RenameWindowsRelative('),
    'the external history witness must precede fixed-name Windows exposure',
  );
  assert.ok(
    prepare.indexOf('CreateServiceStoreFile(') < prepare.indexOf('RenameAt2('),
    'the external history witness must precede fixed-name Linux exposure',
  );
  assert.match(prepare, /container_present && witness_present/);
  assert.match(prepare, /disposition == "managed"/);
  const dispositionStart = source.indexOf('bool ServiceContainerWitnessNonce(');
  const dispositionEnd = source.indexOf('\n#ifdef _WIN32', dispositionStart);
  assert.ok(dispositionStart >= 0 && dispositionEnd > dispositionStart);
  assert.match(
    source.slice(dispositionStart, dispositionEnd),
    /\(\*disposition == "managed" \|\|\s*\*disposition == "external"\)/,
  );
  assert.match(prepare, /ServiceContainerWitnessNonce\([\s\S]*disposition == "managed"[\s\S]*: VerifyBootstrapAnchor\(container, roles\)/);
  assert.match(prepare, /container_present && witness_absent/);
  assert.match(prepare, /looks_managed/);
  assert.match(prepare, /ServiceContainerHasLifecycleEvidence/);
  assert.match(prepare, /ServiceContainerWitnessContent\(\s*spec, "external"/);
  assert.match(prepare, /ServiceStoreOpenRelativeContainer\(\s*mutation_anchor, spec\.name, true/);
  assert.match(prepare, /PrincipalCanAccess\(\s*observed_container, geteuid\(\),\s*S_IWUSR \| S_IXUSR, false\)/);
  assert.match(prepare, /if \(!create \|\| looks_managed \|\| lifecycle_evidence\)[\s\S]*ServiceContainerState::ManualCleanup/);
  assert.match(prepare, /!safe_external \? ServiceContainerState::AccessDenied/);
  assert.ok(
    prepare.indexOf('ServiceContainerHasLifecycleEvidence') <
      prepare.indexOf('ServiceContainerWitnessContent(\n            spec, "external"'),
    'existing service/history evidence must be ruled out before external-container registration',
  );
  assert.match(prepare, /container_absent && witness_absent/);
  assert.match(prepare, /\.gjc-service-" \+ spec\.identity \+ "\.pending"/);
  assert.match(prepare, /pending_absent/);
  assert.match(prepare, /ServiceContainerState::ManualCleanup/);
  assert.match(prepare, /if \(!create\)[\s\S]*ServiceContainerState::Absent/);
  assert.match(prepare, /ServiceContainerWitnessContent\([\s\S]*anchor_identity[\s\S]*created_identity/);
  assert.doesNotMatch(prepare, /set_exact_role_acl|ApplyExactRoleAcl|mapping|inventory/);
  assert.match(open, /PrepareServiceBaseContainer\(\s*root_kind, roles, create/);
  assert.match(open, /base_state == ServiceContainerState::Absent[\s\S]*napi_get_null/);
  assert.match(open, /ServiceStoreOpenFixedParent\(\s*parent_path, create/);
  assert.doesNotMatch(open, /parent_path, access == ServiceStoreAccess::Write/);
  assert.match(source, /role == 0 \|\| role == 2 \|\| role == 4 \? 7 : 5/);
  assert.match(source, /PrincipalCanAccess\(directory, roles\.bot, S_IXUSR, false\)/);
  assert.match(source, /PrincipalCanAccess\(directory, roles\.daemon, S_IXUSR, false\)/);
  assert.match(source, /WindowsPrincipalHasDirectoryAccess\(\s*directory, roles\.bot/);
  assert.match(source, /WindowsPrincipalHasDirectoryAccess\(\s*directory, roles\.daemon/);
  assert.match(source, /if \(!operating_system_anchor\)[\s\S]*FILE_ADD_SUBDIRECTORY \| GENERIC_WRITE/);
  assert.match(source, /FILE_DELETE_CHILD \| DELETE \| WRITE_DAC \| WRITE_OWNER/);
  const anchorVerifyStart = source.indexOf('bool VerifyBootstrapAnchor');
  const anchorVerifyEnd = source.indexOf('enum class ServiceContainerState', anchorVerifyStart);
  assert.doesNotMatch(
    source.slice(anchorVerifyStart, anchorVerifyEnd),
    /SetSecurityInfo|acl_set_|chmod|chown/,
  );
  const revalidateStart = source.indexOf('bool RevalidateServiceStoreRoot');
  const revalidateEnd = source.indexOf('napi_value ServiceRootBindingValue', revalidateStart);
  const revalidate = source.slice(revalidateStart, revalidateEnd);
  assert.match(revalidate, /PrepareServiceBaseContainer\(\s*root->root_kind, root->roles, false/);
  assert.match(revalidate, /base_writes != 0/);
});

test('root witnesses bind the canonical retained root path before creation or validation receipts', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const helperStart = source.indexOf('bool CaptureServiceStoreObjectPath(');
  const helperEnd = source.indexOf('napi_value ServiceRootBindingValue', helperStart);
  const openStart = source.indexOf('napi_value OpenServiceRoot');
  const openEnd = source.indexOf('std::string ServiceLockWitnessContent', openStart);
  assert.ok(helperStart >= 0 && helperEnd > helperStart);
  assert.ok(openStart >= 0 && openEnd > openStart);
  const helper = source.slice(helperStart, helperEnd);
  const open = source.slice(openStart, openEnd);

  assert.match(helper, /CanonicalInventoryParent\(object, &identity, &canonical\)/);
  assert.match(helper, /"\/proc\/self\/fd\/" \+ std::to_string\(object\)/);
  assert.match(open, /std::string root_path;/);
  assert.equal(
    (open.match(/CaptureServiceStoreObjectPath\(\s*root_handle, &root_path\)/g) ?? []).length,
    2,
    'new and existing roots must each capture their retained canonical path',
  );
  assert.ok(
    open.indexOf('CaptureServiceStoreObjectPath(\n            root_handle, &root_path)') <
      open.indexOf('witness_bytes = ServiceRootWitnessContent('),
    'new-root path capture must precede witness creation',
  );
  assert.ok(
    open.lastIndexOf('CaptureServiceStoreObjectPath(\n            root_handle, &root_path)') <
      open.indexOf('ServiceRootWitnessNonce('),
    'existing-root path capture must precede witness validation',
  );
  assert.match(open, /handle->root_path = root_path;/);
  assert.doesNotMatch(open, /CaptureServiceStoreRootPath\(handle, &handle->root_path\)/);
});

test('root bootstrap failures preserve prior writes and ambiguity', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const openStart = source.indexOf('napi_value OpenServiceRoot');
  const openEnd = source.indexOf('std::string ServiceLockWitnessContent', openStart);
  const open = source.slice(openStart, openEnd);
  assert.match(
    open,
    /if \(!InventoryRandomName\(&nonce_wide\)\)[\s\S]*writes == 0 \? "SERVICE_IO_FAILED"[\s\S]*"SERVICE_MANUAL_CLEANUP"[\s\S]*writes != 0/,
  );
  assert.match(
    open,
    /if \(!InventoryRandomName\(&root_nonce\)\)[\s\S]*writes == 0 \? "SERVICE_IO_FAILED"[\s\S]*"SERVICE_MANUAL_CLEANUP"[\s\S]*writes != 0/,
  );
  assert.match(
    open,
    /if \(!ValidServiceFingerprint\(binding_fingerprint\)\)[\s\S]*writes == 0 \? "SERVICE_CRYPTO_UNAVAILABLE"[\s\S]*"SERVICE_MANUAL_CLEANUP"[\s\S]*writes != 0/,
  );
  assert.match(
    open,
    /if \(!handle\)[\s\S]*writes == 0 \? "SERVICE_IO_FAILED"[\s\S]*"SERVICE_MANUAL_CLEANUP"[\s\S]*writes != 0/,
  );
  assert.match(
    open,
    /if \(create\)[\s\S]*writes == 0 \? "SERVICE_ALREADY_EXISTS"[\s\S]*"SERVICE_MANUAL_CLEANUP"[\s\S]*writes != 0/,
  );
});

test('Windows bootstrap preflights durability rights before any intermediary write', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const fixedStart = source.lastIndexOf('bool ServiceStoreOpenFixedParent');
  const fixedEnd = source.indexOf('bool CaptureExternalAncestorIdentity', fixedStart);
  const bootstrapStart = source.indexOf('bool ServiceStoreOpenBootstrapAnchor', fixedEnd);
  const bootstrapEnd = source.indexOf('bool ServiceContainerEntryIsLifecycleEvidence', bootstrapStart);
  const prepareStart = source.indexOf('ServiceContainerState PrepareServiceBaseContainer');
  const prepareEnd = source.indexOf('bool ServiceStoreNamedDirectoryExact', prepareStart);
  const fixed = source.slice(fixedStart, fixedEnd);
  const bootstrap = source.slice(bootstrapStart, bootstrapEnd);
  const prepare = source.slice(prepareStart, prepareEnd);
  assert.match(
    fixed,
    /write\s*\?\s*FILE_GENERIC_READ \| FILE_GENERIC_WRITE \| READ_CONTROL/,
  );
  assert.match(fixed, /:\s*FILE_GENERIC_READ \| READ_CONTROL/);
  assert.match(
    bootstrap,
    /create\s*\?\s*FILE_GENERIC_READ \| FILE_GENERIC_WRITE \| READ_CONTROL/,
  );
  assert.match(bootstrap, /:\s*kWindowsTraversalAccess \| READ_CONTROL/);
  const mutationOpens = [...prepare.matchAll(
    /ServiceStoreOpenBootstrapAnchor\(\s*spec\.anchor_path, true/g,
  )].map((match) => match.index);
  assert.equal(mutationOpens.length, 2);
  const externalWrite = prepare.indexOf('CreateServiceStoreFile(');
  const managedWrite = prepare.lastIndexOf('CreateServiceStoreDirectory(');
  assert.ok(externalWrite >= 0 && managedWrite >= 0);
  assert.ok(
    mutationOpens[0] < externalWrite,
    'durability-capable same-anchor access must precede external history registration',
  );
  assert.ok(
    mutationOpens[1] < managedWrite,
    'durability-capable same-anchor access must precede managed-container creation',
  );
  assert.match(prepare, /SameServicePhysicalIdentity\(\s*mutation_identity, anchor_identity\)/);
});

test('owned Windows ACLs retain M/R/S security-administration rights without widening workloads', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const rightsStart = source.indexOf('ACCESS_MASK WindowsServiceFileRights');
  const rightsEnd = source.indexOf('bool BuildWindowsServiceFileAcl', rightsStart);
  const applyStart = source.indexOf('bool ApplyWindowsServiceFileAcl');
  const applyEnd = source.indexOf('#else', applyStart);
  const rights = source.slice(rightsStart, rightsEnd);
  const apply = source.slice(applyStart, applyEnd);
  assert.match(rights, /ServiceProfileOwned\(profile\)/);
  assert.match(rights, /role == 0 \|\| role == 2 \|\| role == 4/);
  assert.match(rights, /WRITE_DAC \| WRITE_OWNER/);
  assert.match(source, /return !ServiceProfileExternal\(profile\) &&\s*profile != ServiceAclProfile::PreservedContainerDirectory/);
  assert.match(source, /profile != ServiceAclProfile::PreservedContainerDirectory/);
  assert.doesNotMatch(rights, /role == 1 \|\| role == 3/);
  assert.match(apply, /GetSecurityInfo\([\s\S]*OWNER_SECURITY_INFORMATION/);
  assert.match(apply, /owner_matches \? ERROR_SUCCESS[\s\S]*SetSecurityInfo\([\s\S]*OWNER_SECURITY_INFORMATION/);
  assert.ok(
    apply.indexOf('owner_matches ? ERROR_SUCCESS') <
      apply.indexOf('DACL_SECURITY_INFORMATION'),
    'an already-correct management owner must not be reassigned during DACL updates',
  );
  assert.match(apply, /!owner_matches && owner_update == ERROR_SUCCESS[\s\S]*\*mutated = true/);
});

test('artifact streaming is bounded, sequential, poisoned on I/O failure, and requires a sealed closure', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const begin = source.indexOf('napi_value BeginServiceArtifactWrite');
  const publish = source.indexOf('napi_value PublishServiceDirectoryNoReplace');
  assert.notEqual(begin, -1);
  assert.notEqual(publish, -1);
  const streaming = source.slice(begin, publish);
  assert.match(source, /kServiceArtifactMaxBytes\s*=\s*2ULL \* 1024ULL \* 1024ULL \* 1024ULL/);
  assert.match(source, /kServiceArtifactChunkMax\s*=\s*1024ULL \* 1024ULL/);
  assert.match(streaming, /expected_offset != writer->stream_offset/);
  assert.match(streaming, /writer->poisoned = true/);
  assert.match(streaming, /digest != writer->expected_sha256/);
  assert.match(streaming, /final_profile != ServiceAclProfile::StagingFile[\s\S]*ServiceAclProfile::ReleaseFile[\s\S]*ServiceAclProfile::ReleaseExecutable/);
  assert.match(streaming, /reader->completed = true/);
  const revalidationStart = source.indexOf('bool RevalidateServiceArtifactStream(ServiceStoreHandle* handle) {');
  assert.ok(revalidationStart >= 0 && revalidationStart < begin);
  assert.match(source.slice(revalidationStart, begin), /RevalidateExternalArtifactAncestors\(handle\)/);
  assert.match(streaming, /GENERIC_READ \| READ_CONTROL/);
  assert.doesNotMatch(
    source.slice(
      source.indexOf('bool OpenExternalArtifactBound'),
      source.indexOf('napi_value OpenServiceArtifactSource'),
    ),
    /GENERIC_WRITE|DELETE|FILE_DELETE_CHILD|O_WRONLY|O_RDWR|O_CREAT|O_TRUNC/,
  );
  assert.match(source.slice(publish), /source->profile != ServiceAclProfile::ReleaseDirectory/);
  assert.match(source.slice(publish), /source->children != 0/);
  assert.match(source, /100001/);
});

test('sealing and publication prove the complete bounded subtree and poison failed seals', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const sealStart = source.indexOf('napi_value SealServiceDirectory');
  const sealEnd = source.indexOf('bool ServiceStoreExpectedFileArg', sealStart);
  const closureStart = source.indexOf('bool VerifySealedServiceSubtreeRecursive');
  const closureEnd = source.indexOf('napi_value ListServiceDirectory', closureStart);
  const publishStart = source.indexOf('napi_value PublishServiceDirectoryNoReplace');
  const publishEnd = source.indexOf('bool LinuxScopeServiceKey', publishStart);
  assert.ok(sealStart >= 0 && sealEnd > sealStart);
  assert.ok(closureStart >= 0 && closureEnd > closureStart);
  assert.ok(publishStart >= 0 && publishEnd > publishStart);
  const seal = source.slice(sealStart, sealEnd);
  const closure = source.slice(closureStart, closureEnd);
  const publish = source.slice(publishStart, publishEnd);

  assert.match(seal, /VerifyCompleteSealedServiceSubtree\(\s*directory, true/);
  assert.match(seal, /VerifyCompleteSealedServiceSubtree\(\s*directory, false/);
  assert.match(seal, /after_closure\.fingerprint ==\s*before_closure\.fingerprint/);
  assert.match(seal, /FlushServiceStoreDirectory\(directory->object\)/);
  assert.doesNotMatch(seal, /FlushFileBuffers\(privileged\)/);
  assert.match(seal, /directory->poisoned = true;[\s\S]*CloseServiceStoreNative\(directory\)/);
  assert.match(source, /!ServiceStoreNativeHandleOpen\(handle\) \|\| handle->poisoned/);

  assert.match(source, /kServiceSealedFileLimit = 100001/);
  assert.match(source, /kServiceSealedDirectoryLimit[\s\S]*kServiceSealedFileLimit \* 64/);
  assert.match(source, /kServiceSealedByteLimit[\s\S]*kServiceArtifactMaxBytes \+ 32ULL \* 1024ULL \* 1024ULL/);
  assert.match(source, /kServiceSealedDepthLimit = 64/);
  assert.match(source, /kServiceSealedPathLimit = 4096/);
  assert.match(closure, /HashRetainedServiceArtifact/);
  assert.match(closure, /state->bytes/);
  assert.match(closure, /VerifySealedServiceSubtreeRecursive\(/);
  assert.match(publish, /VerifyCompleteSealedServiceSubtree\(\s*source, false/);
  assert.match(publish, /observed_closure\.fingerprint == closure\.fingerprint/);
});

test('stream failure accounting, external-source admission, and artifact GC remain fail closed', () => {
  const source = readFileSync(sourcePath, 'utf8');
  const finishStart = source.indexOf('napi_value FinishServiceArtifactWrite');
  const finishEnd = source.indexOf('bool ServiceArtifactExpectedFacts', finishStart);
  const sourceOpenStart = source.indexOf('bool OpenExternalArtifactBound');
  const sourceOpenEnd = source.indexOf('napi_value OpenServiceArtifactSource', sourceOpenStart);
  const sourceApiEnd = source.indexOf('napi_value ReadServiceArtifactChunk', sourceOpenEnd);
  const streamRevalidateStart = source.indexOf('bool RevalidateServiceArtifactStream');
  const streamRevalidateEnd = source.indexOf('bool BindServiceArtifactDependencies', streamRevalidateStart);
  const gcStart = source.indexOf('napi_value RemoveServiceArtifactFileExact');
  const gcEnd = source.indexOf('struct ServiceStoreDirectoryEntry', gcStart);
  const finish = source.slice(finishStart, finishEnd);
  const sourceOpen = source.slice(sourceOpenStart, sourceOpenEnd);
  const sourceApi = source.slice(sourceOpenEnd, sourceApiEnd);
  const streamRevalidate = source.slice(streamRevalidateStart, streamRevalidateEnd);
  const gc = source.slice(gcStart, gcEnd);

  assert.match(source, /ApplyWindowsServiceFileAcl\([\s\S]*bool\* mutated = nullptr/);
  assert.match(source, /BuildPosixServiceAcl\([\s\S]*bool\* mutated = nullptr/);
  assert.match(finish, /&acl_mutated/);
  assert.match(finish, /if \(acl_mutated\) \+\+writes/);
  assert.match(sourceOpen, /O_RDONLY \| O_NONBLOCK \| O_CLOEXEC \| O_NOFOLLOW/);
  assert.match(sourceOpen, /fstat\(reader->object, &leaf\)[\s\S]*S_ISREG\(leaf\.st_mode\)/);
  assert.match(streamRevalidate, /O_RDONLY \| O_NONBLOCK \| O_CLOEXEC \| O_NOFOLLOW/);
  assert.match(streamRevalidate, /fstat\(named, &named_metadata\)[\s\S]*S_ISREG\(named_metadata\.st_mode\)/);
  assert.ok(
    streamRevalidate.indexOf('named_regular &&') <
      streamRevalidate.indexOf('CaptureExternalServiceFileIdentity(\n            handle->object'),
    'every named external reopen must prove regular type before retained-state checks',
  );
  assert.match(sourceApi, /if \(absent\)[\s\S]*RevalidateExternalArtifactAncestors\(reader\)/);

  const lockChecks = gc.match(/ServiceLockAuthorizes\(parent, lock, true\)/g) ?? [];
  assert.ok(lockChecks.length >= 4, 'GC must bind the artifact fence at entry, before mutations, and before success');
  assert.match(gc, /if \(!ServiceLockAuthorizes\(parent, lock, true\)\)[\s\S]*"SERVICE_MANUAL_CLEANUP"/);
  assert.match(gc, /FlushServiceStoreDirectory\(parent->object\)[\s\S]*ServiceLockAuthorizes\(parent, lock, true\)/);
});

test('current management or system caller can reapply and transition an owned temporary directory ACL', () => {
  const native = addon();
  const roles = sourceReaderRoles(native);
  const current = native.current_os_principal();
  assert.ok(
    current.value === roles.management.value ||
      current.value === roles.system.value,
    'this fixture proves only the current M/S caller; it does not impersonate R/B/D',
  );
  const directory = mkdtempSync(join(tmpdir(), 'gjc-service-acl-'));
  try {
    assert.deepEqual(
      native.set_exact_service_acl(directory, roles, 'service-staging-directory'),
      { writes: 1 },
    );
    assert.equal(
      native.verify_exact_service_acl(directory, roles, 'service-staging-directory'),
      true,
    );
    assert.deepEqual(
      native.set_exact_service_acl(directory, roles, 'service-staging-directory'),
      { writes: 1 },
    );
    assert.equal(
      native.verify_exact_service_acl(directory, roles, 'service-staging-directory'),
      true,
    );
    assert.deepEqual(
      native.set_exact_service_acl(directory, roles, 'service-release-directory'),
      { writes: 1 },
    );
    assert.equal(
      native.verify_exact_service_acl(directory, roles, 'service-release-directory'),
      true,
    );
  } finally {
    rmdirSync(directory);
  }
});

test('real temporary source streams multiple chunks and detects drift under the current OS caller', async () => {
  const native = addon();
  const roles = sourceReaderRoles(native);
  const directory = mkdtempSync(join(tmpdir(), 'gjc-service-source-'));
  const handles = [];
  const openSource = (...args) => {
    const result = native.open_service_artifact_source(...args);
    if (result !== null) handles.push(result.handle);
    return result;
  };
  try {
    const bytes = Buffer.alloc(1024 * 1024 + 37);
    for (let index = 0; index < bytes.length; ++index) bytes[index] = (index * 17) & 0xff;
    const path = join(directory, 'offline.bundle');
    writeFileSync(path, bytes);
    const opened = openSource(path, bytes.length, null, roles);
    assert.equal(opened.writes, 0);
    assert.equal(opened.facts.size, bytes.length);
    assert.equal(opened.facts.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.throws(
      () => native.read_service_artifact_chunk(opened.handle, 1, 1024),
      (error) => error.code === 'SERVICE_STALE' && error.writes === 0,
    );
    const first = native.read_service_artifact_chunk(opened.handle, 0, 1024 * 1024);
    assert.equal(first.nextOffset, 1024 * 1024);
    assert.equal(first.eof, false);
    const second = native.read_service_artifact_chunk(opened.handle, first.nextOffset, 1024 * 1024);
    assert.equal(second.eof, true);
    assert.deepEqual(Buffer.concat([first.bytes, second.bytes]), bytes);
    native.close_service_handle(opened.handle);

    const reopened = openSource(path, bytes.length, opened.facts, roles);
    assert.equal(reopened.facts.sha256, opened.facts.sha256);
    native.close_service_handle(reopened.handle);

    const drifting = openSource(path, bytes.length, opened.facts, roles);
    writeFileSync(path, Buffer.concat([bytes, Buffer.from([1])]));
    assert.throws(
      () => native.read_service_artifact_chunk(drifting.handle, 0, 1024),
      (error) => error.code === 'SERVICE_STALE' && error.writes === 0,
    );
    native.close_service_handle(drifting.handle);

    const emptyPath = join(directory, 'empty.bundle');
    writeFileSync(emptyPath, Buffer.alloc(0));
    const empty = openSource(emptyPath, 0, null, roles);
    assert.equal(empty.facts.sha256, createHash('sha256').update(Buffer.alloc(0)).digest('hex'));
    assert.deepEqual(native.read_service_artifact_chunk(empty.handle, 0, 1), {
      bytes: Buffer.alloc(0),
      nextOffset: 0,
      eof: true,
      writes: 0,
    });
    native.close_service_handle(empty.handle);
    assert.equal(openSource(join(directory, 'missing.bundle'), 0, null, roles), null);

    const manifestPath = join(directory, 'offline.manifest.json');
    const manifestBytes = Buffer.from('unsigned transport fixture bytes');
    writeFileSync(manifestPath, manifestBytes);
    const source = {
      kind: 'offline',
      applicationManifestPath: manifestPath,
      applicationSignaturePath: emptyPath,
      applicationArchivePath: path,
      ...(process.platform === 'win32' ? {
        shawlManifestPath: join(directory, 'shawl.manifest.json'),
        shawlSignaturePath: join(directory, 'shawl.sig'),
        shawlExecutablePath: join(directory, 'shawl.exe'),
      } : {}),
    };
    // Raw local addon integration only, not production loader/signature proof.
    const offline = createOfflineDeploymentSource({
      native: {
        open_service_artifact_source: (file, maximum, expected) =>
          openSource(file, maximum, expected, roles),
        read_service_artifact_chunk: native.read_service_artifact_chunk,
        close_service_handle: native.close_service_handle,
      },
      source, platform: process.platform, architecture: process.arch,
    });
    try {
      const actual = await offline.readBootstrap('application');
      assert.deepEqual(actual.manifestBytes, manifestBytes);
      assert.equal(actual.signatureBytes.length, 0);
    } finally {
      offline.close();
    }
  } finally {
    for (const handle of handles.reverse()) native.close_service_handle(handle);
    rmSync(directory, { recursive: true, force: true });
  }
});

test('retained sources reject reparse ancestors and recreated same-content paths', () => {
  const native = addon();
  const roles = sourceReaderRoles(native);
  const directory = mkdtempSync(join(tmpdir(), 'gjc-service-source-binding-'));
  let opened;
  try {
    const parent = join(directory, 'retained');
    mkdirSync(parent);
    const path = join(parent, 'offline.bundle');
    const bytes = Buffer.from('retained source identity');
    writeFileSync(path, bytes);
    opened = native.open_service_artifact_source(path, bytes.length, null, roles);

    const alias = join(directory, 'alias');
    symlinkSync(parent, alias, process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(
      () => native.open_service_artifact_source(join(alias, 'offline.bundle'), bytes.length, null, roles),
      (error) => error.code === 'SERVICE_STALE' && error.writes === 0,
    );

    let renamedWhileRetained = true;
    try {
      renameSync(parent, join(directory, 'moved'));
    } catch (error) {
      // Windows may prevent renaming a directory with retained descendants.
      // Prove the original remains readable, then test recreation after close.
      assert.equal(process.platform, 'win32');
      assert.ok(['EPERM', 'EACCES', 'EBUSY'].includes(error.code));
      const retained = native.read_service_artifact_chunk(opened.handle, 0, bytes.length);
      assert.equal(retained.eof, true);
      assert.equal(retained.writes, 0);
      assert.deepEqual(retained.bytes, bytes);
      native.close_service_handle(opened.handle);
      renamedWhileRetained = false;
      renameSync(parent, join(directory, 'moved'));
    }
    mkdirSync(parent);
    writeFileSync(path, bytes);
    if (renamedWhileRetained) {
      assert.throws(
        () => native.read_service_artifact_chunk(opened.handle, 0, bytes.length),
        (error) => error.code === 'SERVICE_STALE' && error.writes === 0,
      );
    }
    assert.throws(
      () => native.open_service_artifact_source(path, bytes.length, opened.facts, roles),
      (error) => error.code === 'SERVICE_STALE' && error.writes === 0,
    );
  } finally {
    if (opened !== undefined) native.close_service_handle(opened.handle);
    rmSync(directory, { recursive: true, force: true });
  }
});

test('Linux service facade has a closed native-derived object policy and fixed link targets', () => {
  const source = readFileSync(sourcePath, 'utf8');
  for (const kind of [
    'bot-unit',
    'daemon-template',
    'daemon-dropin-directory',
    'daemon-dropin',
    'enablement-directory',
    'enablement-link',
  ]) assert.equal(source.includes(`kind == "${kind}"`), true, kind);
  assert.equal(source.includes('/etc/systemd/system/gjc-remote-bot.service'), true);
  assert.equal(source.includes('/etc/systemd/system/gjc-remote-daemon@.service'), true);
  assert.match(source, /symlinkat\(spec\.link_target\.c_str\(\)/);
  assert.match(source, /AT_SYMLINK_NOFOLLOW/);
  assert.match(source, /object_kind == "enablement-directory"/);
});

test('Linux facade and Windows HOME binding fail safely without exercising host services', () => {
  const native = addon();
  if (process.platform === 'win32') {
    for (const invoke of [
      () => native.open_linux_service_scope({}, null, 'read-existing'),
      () => native.read_linux_service_object({}, 'bot-unit'),
      () => native.publish_linux_service_object({}, 'bot-unit', Buffer.from(''), null, {}),
      () => native.remove_linux_service_object({}, 'bot-unit', {}, {}),
    ]) assert.throws(invoke, (error) => error.code === 'SERVICE_UNSUPPORTED' && error.writes === 0);
  } else {
    assert.throws(
      () => native.open_linux_service_scope({}, null, 'read-existing'),
      (error) => error.code === 'SERVICE_INVALID' && error.writes === 0,
    );
  }
  const source = readFileSync(sourcePath, 'utf8');
  assert.match(source, /"--env", "HOME=" \+ launch->home_directory/);
  assert.match(source, /"--env", "USERPROFILE=" \+ launch->home_directory/);
  assert.match(
    source,
    /arguments\.push_back\(launch->runtime_path\);\s*if \(role == "daemon"\) arguments\.push_back\("--no-env-file"\);\s*arguments\.push_back\(launch->entrypoint_path\);/,
    'only the Bun daemon suppresses automatic dotenv layers before the entrypoint',
  );
  assert.doesNotMatch(source, /wrapperEpochObserved/);
});
