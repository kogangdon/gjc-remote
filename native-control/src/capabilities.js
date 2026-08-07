export const capabilities = Object.freeze(['open_verified_parent', 'open_no_follow', 'read_identity', 'read_acl', 'path_exists_no_follow', 'set_exact_role_acl', 'verify_exact_role_acl', 'read_verified_bytes', 'create_exclusive_temp', 'flush_file', 'flush_directory_or_volume', 'replace_existing_atomic', 'create_absent_exclusive', 'ensure_control_directory', 'acquire_native_lock', 'current_os_principal', 'principal_access_check', 'remove_verified_file', 'open_verified_parent_handle', 'open_verified_object_handle', 'read_handle_identity', 'read_handle_bytes', 'write_handle_bytes', 'remove_verified_handle', 'verify_role_sid_not_group']);
export const capabilitySignatures = Object.freeze({
  open_verified_parent: ['path'], open_no_follow: ['path'], read_identity: ['path'], read_acl: ['path'], path_exists_no_follow: ['path'],
  set_exact_role_acl: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  verify_exact_role_acl: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  read_verified_bytes: ['path'], create_exclusive_temp: ['parent', 'prefix', 'bytes', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  flush_file: ['path'], flush_directory_or_volume: ['path'],
  replace_existing_atomic: ['source', 'destination', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  create_absent_exclusive: ['path', 'bytes', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  ensure_control_directory: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  acquire_native_lock: ['path', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'],
  current_os_principal: [], principal_access_check: ['path', 'kind', 'principal', 'mode', 'managementSid', 'botSid', 'recoverySid', 'systemSid', 'profile'], remove_verified_file: ['path', 'expectedBytes'],
  open_verified_parent_handle: ['path'], open_verified_object_handle: ['parentHandle', 'name'],
  read_handle_identity: ['handle'], read_handle_bytes: ['handle'], write_handle_bytes: ['handle', 'bytes'],
  remove_verified_handle: ['handle', 'expectedBytes'],
  verify_role_sid_not_group: ['sid'],
});
for (const signature of Object.values(capabilitySignatures)) Object.freeze(signature);
