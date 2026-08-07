#include <node_api.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>
#include <atomic>
#include <limits>
#include <initializer_list>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <authz.h>
#ifdef _MSC_VER
#pragma comment(lib, "authz.lib")
#endif
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/acl.h>
#include <acl/libacl.h>
#include <grp.h>
#include <pwd.h>
#endif

namespace {

void Throw(napi_env env, const char* code, const char* message, const char* operation = nullptr) {
  napi_value error, text, value;
  napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &text);
  napi_create_error(env, nullptr, text, &error);
  napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "code", value);
  if (operation != nullptr) {
    napi_create_string_utf8(env, operation, NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, error, "operation", value);
  }
  napi_throw(env, error);
}

void Refuse(napi_env env, const char* operation, const char* reason) {
  napi_value error, text, value;
  std::string message = std::string(operation) + " refused: " + reason;
  napi_create_string_utf8(env, message.c_str(), NAPI_AUTO_LENGTH, &text);
  napi_create_error(env, nullptr, text, &error);
  napi_create_string_utf8(env, "ERR_NATIVE_CONTROL_REFUSED", NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "code", value);
  napi_create_string_utf8(env, operation, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "operation", value);
  napi_create_string_utf8(env, reason, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "reason", value);
  napi_create_uint32(env, 0, &value);
  napi_set_named_property(env, error, "writes", value);
  napi_throw(env, error);
}

bool StringArg(napi_env env, napi_callback_info info, size_t index, std::string* result, size_t minimum = 1) {
  size_t argc = 16;
  napi_value args[16];
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  if (argc < minimum || index >= argc) { Throw(env, "ERR_INVALID_ARG_TYPE", "missing string argument"); return false; }
  napi_valuetype type;
  napi_typeof(env, args[index], &type);
  if (type != napi_string) { Throw(env, "ERR_INVALID_ARG_TYPE", "argument must be a string"); return false; }
  size_t length;
  napi_get_value_string_utf8(env, args[index], nullptr, 0, &length);
  result->resize(length + 1);
  napi_get_value_string_utf8(env, args[index], result->data(), length + 1, &length);
  result->resize(length);
  return true;
}

bool BufferArg(napi_env env, napi_callback_info info, size_t index, std::vector<uint8_t>* result) {
  size_t argc = 16;
  napi_value args[16];
  napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  bool is_buffer = false;
  if (argc <= index || napi_is_buffer(env, args[index], &is_buffer) != napi_ok || !is_buffer) {
    Throw(env, "ERR_INVALID_ARG_TYPE", "argument must be a Buffer");
    return false;
  }
  void* data = nullptr;
  size_t length = 0;
  napi_get_buffer_info(env, args[index], &data, &length);
  result->assign(static_cast<uint8_t*>(data), static_cast<uint8_t*>(data) + length);
  return true;
}

#ifdef _WIN32
bool SafeName(const std::string& value) {
  return !value.empty() && value != "." && value != ".." && value.find_first_of("/\\") == std::string::npos;
}
std::wstring Wide(const std::string& input) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
  if (n <= 0) return L"";
  std::wstring output(n, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), n);
  return output;
}
std::string Utf8(const std::wstring& input) {
  int n = WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
  std::string output(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), output.data(), n, nullptr, nullptr);
  return output;
}
enum class VerifiedObjectType { Any, File, Directory };
// Win32 OPEN_REPARSE_POINT does not protect intermediate components. Resolve each
// component relative to a retained directory handle through NtCreateFile instead.

struct WindowsPathParts {
  std::wstring root;
  std::vector<std::wstring> components;
};

bool SafeWideName(const std::wstring& value) {
  if (value.empty() || value == L"." || value == L".." ||
      value.find(L'\0') != std::wstring::npos ||
      value.find_first_of(L"\\/:*?<>|\"") != std::wstring::npos ||
      value.back() == L'.' || value.back() == L' ') return false;
  for (wchar_t character : value) if (character < 0x20) return false;
  std::wstring upper = value;
  for (wchar_t& character : upper) if (character >= L'a' && character <= L'z') character -= L'a' - L'A';
  return upper != L"CON" && upper != L"PRN" && upper != L"AUX" && upper != L"NUL" &&
      upper != L"COM1" && upper != L"COM2" && upper != L"COM3" && upper != L"COM4" &&
      upper != L"COM5" && upper != L"COM6" && upper != L"COM7" && upper != L"COM8" &&
      upper != L"COM9" && upper != L"LPT1" && upper != L"LPT2" && upper != L"LPT3" &&
      upper != L"LPT4" && upper != L"LPT5" && upper != L"LPT6" && upper != L"LPT7" &&
      upper != L"LPT8" && upper != L"LPT9";
}

bool ParseWindowsPath(const std::string& path, WindowsPathParts* result) {
  const std::wstring wide = Wide(path);
  if (wide.size() < 3 || wide[1] != L':' || wide[2] != L'\\' ||
      !((wide[0] >= L'A' && wide[0] <= L'Z') || (wide[0] >= L'a' && wide[0] <= L'z')) ||
      (wide.size() > 3 && wide.back() == L'\\')) {
    SetLastError(ERROR_INVALID_NAME);
    return false;
  }
  result->root = wide.substr(0, 3);
  result->components.clear();
  size_t start = 3;
  while (start < wide.size()) {
    const size_t end = wide.find(L'\\', start);
    const std::wstring component = wide.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
    if (!SafeWideName(component)) {
      SetLastError(ERROR_INVALID_NAME);
      return false;
    }
    result->components.push_back(component);
    if (end == std::wstring::npos) break;
    start = end + 1;
  }
  return true;
}

struct NativeUnicodeString {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
};
struct NativeObjectAttributes {
  ULONG Length;
  HANDLE RootDirectory;
  NativeUnicodeString* ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
};
struct NativeIoStatusBlock {
  union { LONG Status; PVOID Pointer; };
  ULONG_PTR Information;
};
using NtCreateFileFunction = LONG (NTAPI*)(
    PHANDLE, ACCESS_MASK, NativeObjectAttributes*, NativeIoStatusBlock*, PLARGE_INTEGER,
    ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
using NtSetInformationFileFunction = LONG (NTAPI*)(
    HANDLE, NativeIoStatusBlock*, PVOID, ULONG, ULONG);

NtCreateFileFunction NtCreateFileApi() {
  static NtCreateFileFunction api = reinterpret_cast<NtCreateFileFunction>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
  return api;
}
NtSetInformationFileFunction NtSetInformationFileApi() {
  static NtSetInformationFileFunction api = reinterpret_cast<NtSetInformationFileFunction>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
  return api;
}
void SetNtError(LONG status) {
  if (static_cast<ULONG>(status) == 0xC0000035u) SetLastError(ERROR_ALREADY_EXISTS);
  else if (static_cast<ULONG>(status) == 0xC0000034u) SetLastError(ERROR_FILE_NOT_FOUND);
  else if (static_cast<ULONG>(status) == 0xC000003Au) SetLastError(ERROR_PATH_NOT_FOUND);
  else if (static_cast<ULONG>(status) == 0xC0000022u) SetLastError(ERROR_ACCESS_DENIED);
  else SetLastError(ERROR_CANT_ACCESS_FILE);
}

constexpr ULONG kFileOpen = 1;
constexpr ULONG kFileCreate = 2;
constexpr ULONG kFileOpenReparsePoint = 0x00200000;
constexpr ULONG kFileSynchronousIoNonalert = 0x00000020;
constexpr ULONG kFileDirectoryFile = 0x00000001;
constexpr ULONG kFileNonDirectoryFile = 0x00000040;
constexpr ULONG kObjCaseInsensitive = 0x00000040;
constexpr ULONG kFileRenameInformation = 10;

bool VerifyWindowsHandle(HANDLE handle, VerifiedObjectType expected_type) {
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(handle, &info)) return false;
  const bool is_directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  return (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
      (expected_type == VerifiedObjectType::Any ||
       (expected_type == VerifiedObjectType::File && !is_directory) ||
       (expected_type == VerifiedObjectType::Directory && is_directory));
}

HANDLE OpenWindowsRoot(const std::wstring& root, DWORD access) {
  HANDLE handle = CreateFileW(root.c_str(), access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (handle == INVALID_HANDLE_VALUE) return handle;
  if (!VerifyWindowsHandle(handle, VerifiedObjectType::Directory)) {
    CloseHandle(handle);
    SetLastError(ERROR_CANT_ACCESS_FILE);
    return INVALID_HANDLE_VALUE;
  }
  return handle;
}

HANDLE OpenWindowsRelative(HANDLE parent, const std::wstring& name, DWORD access,
                           ULONG disposition, VerifiedObjectType expected_type,
                           PSECURITY_DESCRIPTOR security = nullptr) {
  NtCreateFileFunction create = NtCreateFileApi();
  if (create == nullptr || parent == INVALID_HANDLE_VALUE || !SafeWideName(name) ||
      name.size() > std::numeric_limits<USHORT>::max() / sizeof(wchar_t)) {
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return INVALID_HANDLE_VALUE;
  }
  NativeUnicodeString unicode{
      static_cast<USHORT>(name.size() * sizeof(wchar_t)),
      static_cast<USHORT>(name.size() * sizeof(wchar_t)),
      const_cast<PWSTR>(name.c_str())};
  NativeObjectAttributes attributes{
      sizeof(attributes), parent, &unicode, kObjCaseInsensitive, security, nullptr};
  NativeIoStatusBlock status{};
  ULONG options = kFileOpenReparsePoint | kFileSynchronousIoNonalert;
  if (expected_type == VerifiedObjectType::Directory) options |= kFileDirectoryFile;
  if (expected_type == VerifiedObjectType::File) options |= kFileNonDirectoryFile;
  HANDLE handle = INVALID_HANDLE_VALUE;
  const LONG result = create(&handle, access | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &status, nullptr,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      disposition, options, nullptr, 0);
  if (result < 0 || handle == INVALID_HANDLE_VALUE) {
    SetNtError(result);
    return INVALID_HANDLE_VALUE;
  }
  if (!VerifyWindowsHandle(handle, expected_type)) {
    CloseHandle(handle);
    SetLastError(ERROR_CANT_ACCESS_FILE);
    return INVALID_HANDLE_VALUE;
  }
  return handle;
}

constexpr DWORD kWindowsTraversalAccess =
    FILE_READ_ATTRIBUTES | FILE_TRAVERSE;
constexpr DWORD kWindowsMutationParentAccess =
    kWindowsTraversalAccess | READ_CONTROL | WRITE_DAC | WRITE_OWNER |
    FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD;
constexpr ACCESS_MASK kWindowsDirectoryMutationAccess =
    READ_CONTROL | WRITE_DAC | WRITE_OWNER |
    FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD;

bool OpenWindowsParentNoFollow(const std::string& path, HANDLE* parent, std::wstring* name,
                               DWORD directory_access = kWindowsTraversalAccess) {
  WindowsPathParts parts;
  if (!ParseWindowsPath(path, &parts) || parts.components.empty()) return false;
  const DWORD root_access = parts.components.size() == 1 ? directory_access : kWindowsTraversalAccess;
  HANDLE current = OpenWindowsRoot(parts.root, root_access);
  if (current == INVALID_HANDLE_VALUE) return false;
  for (size_t i = 0; i + 1 < parts.components.size(); ++i) {
    const DWORD component_access =
        i + 2 == parts.components.size() ? directory_access : kWindowsTraversalAccess;
    HANDLE next = OpenWindowsRelative(current, parts.components[i], component_access,
        kFileOpen, VerifiedObjectType::Directory);
    CloseHandle(current);
    if (next == INVALID_HANDLE_VALUE) return false;
    current = next;
  }
  *parent = current;
  *name = parts.components.back();
  return true;
}

HANDLE OpenWindowsPathNoFollow(const std::string& path, DWORD access,
                               VerifiedObjectType expected_type) {
  WindowsPathParts parts;
  if (!ParseWindowsPath(path, &parts)) return INVALID_HANDLE_VALUE;
  HANDLE current = OpenWindowsRoot(parts.root,
      parts.components.empty() ? access : kWindowsTraversalAccess);
  if (current == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
  if (parts.components.empty()) {
    if (expected_type != VerifiedObjectType::Directory) {
      CloseHandle(current);
      SetLastError(ERROR_CANT_ACCESS_FILE);
      return INVALID_HANDLE_VALUE;
    }
    return current;
  }
  for (size_t i = 0; i < parts.components.size(); ++i) {
    const bool final = i + 1 == parts.components.size();
    HANDLE next = OpenWindowsRelative(current, parts.components[i],
        final ? access : kWindowsTraversalAccess, kFileOpen,
        final ? expected_type : VerifiedObjectType::Directory);
    CloseHandle(current);
    if (next == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    current = next;
  }
  return current;
}

HANDLE OpenNoFollow(const std::string& path, DWORD access, DWORD, VerifiedObjectType expected_type) {
  return OpenWindowsPathNoFollow(path, access, expected_type);
}

HANDLE OpenNoFollowFile(const std::string& path, DWORD access, DWORD = OPEN_EXISTING) {
  return OpenWindowsPathNoFollow(path, access, VerifiedObjectType::File);
}

HANDLE OpenNoFollowDirectory(const std::string& path, DWORD access, DWORD = OPEN_EXISTING) {
  return OpenWindowsPathNoFollow(path, access, VerifiedObjectType::Directory);
}

HANDLE OpenNoFollowObject(const std::string& path, DWORD access, DWORD = OPEN_EXISTING) {
  return OpenWindowsPathNoFollow(path, access, VerifiedObjectType::Any);
}

// FileRenameInformation uses the retained parent handle, avoiding legacy
// path-based replacement resolution and preserving the no-follow boundary.
struct NativeFileRenameInformation {
  BOOLEAN ReplaceIfExists;
  HANDLE RootDirectory;
  ULONG FileNameLength;
  WCHAR FileName[1];
};
// FileRenameInformationEx (info class 65) uses a Flags ULONG in place of the
// legacy single ReplaceIfExists BOOLEAN, at the same aligned struct offset.
// FILE_RENAME_POSIX_SEMANTICS lets the filesystem replace a target that
// still has other open, properly-shared handles (e.g. a caller-retained
// read/write handle obtained via open_verified_object_handle); the legacy
// FileRenameInformation class can spuriously deny STATUS_ACCESS_DENIED in
// that situation even though the rename is otherwise fully authorized.
struct NativeFileRenameInformationEx {
  ULONG Flags;
  HANDLE RootDirectory;
  ULONG FileNameLength;
  WCHAR FileName[1];
};
constexpr ULONG kFileRenameInformationEx = 65;
constexpr ULONG kFileRenamePosixSemantics = 0x00000002;
constexpr ULONG kFileRenameReplaceIfExists = 0x00000001;

bool RenameWindowsRelative(HANDLE object, HANDLE parent, const std::wstring& name, bool replace) {
  NtSetInformationFileFunction set_information = NtSetInformationFileApi();
  if (set_information == nullptr || object == INVALID_HANDLE_VALUE ||
      parent == INVALID_HANDLE_VALUE || !SafeWideName(name) ||
      name.size() > (std::numeric_limits<ULONG>::max() - sizeof(NativeFileRenameInformation)) / sizeof(wchar_t)) {
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return false;
  }
  if (replace) {
    const size_t ex_bytes = sizeof(NativeFileRenameInformationEx) +
        (name.size() - 1) * sizeof(wchar_t);
    std::vector<uint8_t> ex_buffer(ex_bytes);
    auto* ex_info = reinterpret_cast<NativeFileRenameInformationEx*>(ex_buffer.data());
    ex_info->Flags = kFileRenameReplaceIfExists | kFileRenamePosixSemantics;
    ex_info->RootDirectory = parent;
    ex_info->FileNameLength = static_cast<ULONG>(name.size() * sizeof(wchar_t));
    std::memcpy(ex_info->FileName, name.data(), name.size() * sizeof(wchar_t));
    NativeIoStatusBlock ex_status{};
    const LONG ex_result = set_information(object, &ex_status, ex_info,
        static_cast<ULONG>(ex_buffer.size()), kFileRenameInformationEx);
    if (ex_result >= 0) return true;
    // STATUS_NOT_SUPPORTED / STATUS_INVALID_INFO_CLASS / STATUS_INVALID_PARAMETER
    // mean the running kernel predates FileRenameInformationEx; fall back to
    // the legacy info class below. Any other failure (e.g. a genuine ACL
    // denial) is authoritative and must not be masked by a silent retry.
    if (ex_result != static_cast<LONG>(0xC00000BBu) &&
        ex_result != static_cast<LONG>(0xC0000003u) &&
        ex_result != static_cast<LONG>(0xC000000Du)) {
      SetNtError(ex_result);
      return false;
    }
  }
  const size_t bytes = sizeof(NativeFileRenameInformation) +
      (name.size() - 1) * sizeof(wchar_t);
  std::vector<uint8_t> buffer(bytes);
  auto* info = reinterpret_cast<NativeFileRenameInformation*>(buffer.data());
  info->ReplaceIfExists = replace ? TRUE : FALSE;
  info->RootDirectory = parent;
  info->FileNameLength = static_cast<ULONG>(name.size() * sizeof(wchar_t));
  std::memcpy(info->FileName, name.data(), name.size() * sizeof(wchar_t));
  NativeIoStatusBlock status{};
  const LONG result = set_information(object, &status, info, static_cast<ULONG>(buffer.size()),
      kFileRenameInformation);
  if (result < 0) {
    SetNtError(result);
    return false;
  }
  return true;
}
bool VerifyWindowsNamedIdentity(HANDLE parent, const std::wstring& name,
                                const BY_HANDLE_FILE_INFORMATION& expected) {
  HANDLE handle = OpenWindowsRelative(parent, name, FILE_READ_ATTRIBUTES, kFileOpen,
      VerifiedObjectType::File);
  if (handle == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION actual{};
  const bool same = GetFileInformationByHandle(handle, &actual) &&
      actual.dwVolumeSerialNumber == expected.dwVolumeSerialNumber &&
      actual.nFileIndexHigh == expected.nFileIndexHigh &&
      actual.nFileIndexLow == expected.nFileIndexLow;
  CloseHandle(handle);
  return same;
}
enum class RoleProfile { Authority, ManagementAuth, BotState, ProspectiveCleanup };

bool ParseRoleProfile(const std::string& value, RoleProfile* result) {
  if (value == "authority") { *result = RoleProfile::Authority; return true; }
  if (value == "management-auth") { *result = RoleProfile::ManagementAuth; return true; }
  if (value == "bot-state") { *result = RoleProfile::BotState; return true; }
  if (value == "prospective-cleanup") { *result = RoleProfile::ProspectiveCleanup; return true; }
  return false;
}

struct RoleAcl {
  PACL acl = nullptr;
  std::vector<PSID> sids;
  ~RoleAcl() {
    if (acl) LocalFree(acl);
    for (PSID sid : sids) LocalFree(sid);
  }
};

DWORD RoleRights(RoleProfile profile, size_t role) {
  if (role == 3) return FILE_ALL_ACCESS;
  if (profile == RoleProfile::ManagementAuth) return role == 0 || role == 3 ? FILE_ALL_ACCESS : 0;
  if (profile == RoleProfile::Authority) return role == 0 ? FILE_ALL_ACCESS : FILE_GENERIC_READ;
  if (profile == RoleProfile::BotState) return role == 1 ? FILE_GENERIC_READ | FILE_GENERIC_WRITE : FILE_GENERIC_READ;
  return role == 0 ? FILE_ALL_ACCESS : FILE_GENERIC_READ;
}

bool BuildExactRoleAcl(const std::string& manager, const std::string& bot,
                       const std::string& reader, const std::string& system,
                       RoleProfile profile, RoleAcl* result) {
  const std::string values[] = {manager, bot, reader, system};
  for (const std::string& value : values) {
    std::wstring wide = Wide(value);
    PSID sid = nullptr;
    if (wide.empty() || !ConvertStringSidToSidW(wide.c_str(), &sid)) return false;
    for (PSID prior : result->sids) {
      if (EqualSid(prior, sid)) { LocalFree(sid); return false; }
    }
    result->sids.push_back(sid);
  }
  EXPLICIT_ACCESSW entries[4]{};
  for (size_t i = 0; i < 4; ++i) {
    entries[i].grfAccessPermissions = RoleRights(profile, i);
    entries[i].grfAccessMode = SET_ACCESS;
    entries[i].grfInheritance = NO_INHERITANCE;
    entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[i].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    entries[i].Trustee.ptstrName = static_cast<LPWSTR>(result->sids[i]);
  }
  return SetEntriesInAclW(4, entries, nullptr, &result->acl) == ERROR_SUCCESS;
}

bool VerifyExactRoleAcl(HANDLE handle, const std::string& manager,
                        const std::string& bot, const std::string& reader,
                        const std::string& system, RoleProfile profile) {
  RoleAcl roles;
  if (!BuildExactRoleAcl(manager, bot, reader, system, profile, &roles)) return false;
  PACL applied = nullptr;
  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
                      &applied, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  const size_t required_owner_role = profile == RoleProfile::BotState ? 1 : 0;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  ACL_SIZE_INFORMATION size{};
  bool valid = owner != nullptr && EqualSid(owner, roles.sids[required_owner_role]) &&
      GetSecurityDescriptorControl(descriptor, &control, &revision) &&
      (control & SE_DACL_PROTECTED) != 0 && applied != nullptr &&
      GetAclInformation(applied, &size, sizeof(size), AclSizeInformation) &&
      size.AceCount == 4;
  bool seen[4] = {};
  for (DWORD ace_index = 0; valid && ace_index < size.AceCount; ++ace_index) {
    void* raw = nullptr;
    if (!GetAce(applied, ace_index, &raw)) {
      valid = false;
      break;
    }
    ACE_HEADER* header = static_cast<ACE_HEADER*>(raw);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0) {
      valid = false;
      break;
    }
    ACCESS_ALLOWED_ACE* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    bool matched = false;
    for (size_t role = 0; role < 4; ++role) {
      if (!seen[role] && ace->Mask == RoleRights(profile, role) &&
          EqualSid(reinterpret_cast<PSID>(&ace->SidStart), roles.sids[role])) {
        seen[role] = true; matched = true; break;
      }
    }
    if (!matched) valid = false;
  }
  LocalFree(descriptor);
  return valid && seen[0] && seen[1] && seen[2] && seen[3];
}

bool ApplyExactRoleAcl(HANDLE handle, const std::string& manager,
                       const std::string& bot, const std::string& reader,
                       const std::string& system, RoleProfile profile) {
  RoleAcl roles;
  if (!BuildExactRoleAcl(manager, bot, reader, system, profile, &roles)) return false;
  if (SetSecurityInfo(handle, SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
      nullptr, nullptr, roles.acl, nullptr) != ERROR_SUCCESS) return false;
  return VerifyExactRoleAcl(handle, manager, bot, reader, system, profile);
}
bool VerifyNoGroupMutationAcl(HANDLE handle) {
  PACL dacl = nullptr;
  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(handle, SE_FILE_OBJECT,
                      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      &owner, nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  ACL_SIZE_INFORMATION size{};
  bool valid = descriptor != nullptr &&
      GetSecurityDescriptorControl(descriptor, &control, &revision) &&
      (control & SE_DACL_PROTECTED) != 0 && dacl != nullptr &&
      GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation) &&
      size.AceCount == 4;
  PSID configured_system_sid = nullptr;
  if (valid && !ConvertStringSidToSidW(L"S-1-5-18", &configured_system_sid)) valid = false;
  for (DWORD index = 0; valid && index < size.AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(dacl, index, &raw)) {
      valid = false;
      break;
    }
    ACE_HEADER* header = static_cast<ACE_HEADER*>(raw);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0) {
      valid = false;
      break;
    }
    ACCESS_ALLOWED_ACE* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    PSID sid = reinterpret_cast<PSID>(&ace->SidStart);
    if (!IsValidSid(sid)) { valid = false; break; }
    const bool is_configured_system_sid = EqualSid(sid, configured_system_sid);
    const bool is_owner = owner != nullptr && EqualSid(owner, sid);
    constexpr ACCESS_MASK kForeignMutationRights =
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        DELETE | WRITE_DAC | WRITE_OWNER | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY |
        FILE_DELETE_CHILD;
    const bool foreign = !is_owner && !is_configured_system_sid;
    const bool foreign_mutation_capable = foreign && (ace->Mask & kForeignMutationRights) != 0;
    if (foreign_mutation_capable) {
      valid = false;
      break;
    }
    if (foreign) {
      // Foreign (non-owner, non-system) role ACEs that grant no mutation
      // rights (already proven above) cannot expose a group-mutation or
      // foreign-mutation risk regardless of whether their SID resolves to a
      // locally or trust-known identity, so they are exempt from the
      // resolvability requirement enforced below for owner/system ACEs.
      continue;
    }
    DWORD name_length = 0, domain_length = 0;
    SID_NAME_USE use = SidTypeUnknown;
    LookupAccountSidW(nullptr, sid, nullptr, &name_length, nullptr, &domain_length, &use);
    const DWORD lookup_error = GetLastError();
    if (lookup_error == ERROR_NONE_MAPPED || lookup_error == ERROR_TRUSTED_RELATIONSHIP_FAILURE) {
      valid = false;
      break;
    }
    if (lookup_error != ERROR_INSUFFICIENT_BUFFER ||
        name_length == 0 || domain_length == 0) { valid = false; break; }
    std::vector<wchar_t> account(name_length);
    std::vector<wchar_t> domain(domain_length);
    if (!LookupAccountSidW(nullptr, sid, account.data(), &name_length, domain.data(),
                           &domain_length, &use) ||
        (!is_configured_system_sid &&
         (use == SidTypeGroup || use == SidTypeAlias || use == SidTypeWellKnownGroup))) {
      valid = false;
      break;
    }
  }
  LocalFree(configured_system_sid);
  LocalFree(descriptor);
  return valid;
}

HANDLE CreateProtectedFileNoFollow(const std::string& path, DWORD access, PACL acl) {
  SECURITY_DESCRIPTOR descriptor{};
  if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
      !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    SetLastError(ERROR_INVALID_SECURITY_DESCR);
    return INVALID_HANDLE_VALUE;
  }
  HANDLE parent = INVALID_HANDLE_VALUE;
  std::wstring name;
  if (!OpenWindowsParentNoFollow(path, &parent, &name, kWindowsMutationParentAccess)) {
    return INVALID_HANDLE_VALUE;
  }
  HANDLE handle = OpenWindowsRelative(parent, name, access, kFileCreate,
      VerifiedObjectType::File, &descriptor);
  CloseHandle(parent);
  return handle;
}

bool CreateProtectedDirectoryNoFollow(const std::string& path, PACL acl) {
  SECURITY_DESCRIPTOR descriptor{};
  if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
      !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    SetLastError(ERROR_INVALID_SECURITY_DESCR);
    return false;
  }
  HANDLE parent = INVALID_HANDLE_VALUE;
  std::wstring name;
  if (!OpenWindowsParentNoFollow(path, &parent, &name, kWindowsMutationParentAccess)) {
    return false;
  }
  HANDLE handle = OpenWindowsRelative(parent, name, READ_CONTROL | FILE_READ_ATTRIBUTES,
      kFileCreate, VerifiedObjectType::Directory, &descriptor);
  const bool created = handle != INVALID_HANDLE_VALUE;
  if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
  CloseHandle(parent);
  return created;
}
void SetIdentity(napi_env env, napi_value result, HANDLE handle) {
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(handle, &info)) return;
  napi_value v;
  napi_create_uint32(env, info.dwVolumeSerialNumber, &v); napi_set_named_property(env, result, "volumeSerial", v);
  napi_create_uint32(env, info.nFileIndexHigh, &v); napi_set_named_property(env, result, "fileIndexHigh", v);
  napi_create_uint32(env, info.nFileIndexLow, &v); napi_set_named_property(env, result, "fileIndexLow", v);
  napi_create_uint32(env, info.dwFileAttributes, &v); napi_set_named_property(env, result, "attributes", v);
  PSID owner = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS && owner != nullptr) {
    LPWSTR sid = nullptr;
    if (ConvertSidToStringSidW(owner, &sid)) {
      const std::string owner_text = Utf8(sid);
      napi_create_string_utf8(env, owner_text.c_str(), NAPI_AUTO_LENGTH, &v); napi_set_named_property(env, result, "owner", v);
      LocalFree(sid);
    }
  }
  if (descriptor) LocalFree(descriptor);
}
#else
enum class RoleProfile { Authority, ManagementAuth, BotState, ProspectiveCleanup };
bool ParseRoleProfile(const std::string& value, RoleProfile* result) {
  if (value == "authority") { *result = RoleProfile::Authority; return true; }
  if (value == "management-auth") { *result = RoleProfile::ManagementAuth; return true; }
  if (value == "bot-state") { *result = RoleProfile::BotState; return true; }
  if (value == "prospective-cleanup") { *result = RoleProfile::ProspectiveCleanup; return true; }
  return false;
}
bool ParseUid(const std::string& value, uid_t* result) {
  const std::string decimal = value.rfind("uid:", 0) == 0 ? value.substr(4) : value;
  if (decimal.empty() || decimal.find_first_not_of("0123456789") != std::string::npos ||
      (decimal.size() > 1 && decimal[0] == '0')) return false;
  errno = 0;
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(decimal.c_str(), &end, 10);
  if (errno == ERANGE || end == decimal.c_str() || *end != '\0' ||
      parsed > static_cast<unsigned long long>(std::numeric_limits<uid_t>::max())) return false;
  *result = static_cast<uid_t>(parsed);
  return true;
}
bool SafeName(const std::string& value) {
  return !value.empty() && value != "." && value != ".." && value.find_first_of("/\\") == std::string::npos;
}
bool SplitParent(const std::string& path, std::string* parent, std::string* name) {
  std::filesystem::path value = std::filesystem::u8path(path);
  *name = value.filename().u8string(); *parent = value.parent_path().u8string();
  if (parent->empty()) *parent = ".";
  return SafeName(*name);
}
int OpenDirectoryNoFollow(const std::string& path) {
  if (path.empty()) return -1;
  const bool absolute = path[0] == '/';
  int fd = open(absolute ? "/" : ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return -1;
  size_t start = absolute ? 1 : 0;
  while (start <= path.size()) {
    size_t end = path.find('/', start);
    std::string component = path.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (!component.empty() && component != ".") {
      if (!SafeName(component)) { close(fd); return -1; }
      int next = openat(fd, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (next < 0) { close(fd); return -1; }
      close(fd); fd = next;
    }
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return fd;
}
bool OpenParentNoFollow(const std::string& path, int* parent_fd, std::string* name) {
  std::string parent;
  if (!SplitParent(path, &parent, name)) return false;
  *parent_fd = OpenDirectoryNoFollow(parent);
  return *parent_fd >= 0;
}
mode_t RoleMode(RoleProfile profile, size_t role, bool directory) {
  mode_t mode;
  if (role == 3) mode = S_IRUSR | S_IWUSR;
  else if (profile == RoleProfile::ManagementAuth) mode = role == 0 || role == 3 ? S_IRUSR | S_IWUSR : 0;
  else if (profile == RoleProfile::Authority) mode = role == 0 ? S_IRUSR | S_IWUSR : S_IRUSR;
  else if (profile == RoleProfile::BotState) mode = role == 1 ? S_IRUSR | S_IWUSR : S_IRUSR;
  else mode = role == 0 ? S_IRUSR | S_IWUSR : S_IRUSR;
  if (directory) mode |= S_IXUSR;
  return mode;
}
bool SetPerms(acl_permset_t perms, mode_t mode) {
  if (acl_clear_perms(perms) != 0) return false;
  if ((mode & S_IRUSR) && acl_add_perm(perms, ACL_READ) != 0) return false;
  if ((mode & S_IWUSR) && acl_add_perm(perms, ACL_WRITE) != 0) return false;
  return !(mode & S_IXUSR) || acl_add_perm(perms, ACL_EXECUTE) == 0;
}
bool ApplyExactRoleAcl(int fd, const std::string& manager, const std::string& bot,
                       const std::string& reader, const std::string& system, RoleProfile profile) {
  uid_t roles[4];
  if (!ParseUid(manager, &roles[0]) || !ParseUid(bot, &roles[1]) || !ParseUid(reader, &roles[2]) ||
      !ParseUid(system, &roles[3]) || roles[3] != 0 ||
      roles[0] == roles[1] || roles[0] == roles[2] || roles[0] == roles[3] ||
      roles[1] == roles[2] || roles[1] == roles[3] || roles[2] == roles[3]) return false;
  struct stat st;
  if (fstat(fd, &st) != 0 || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) return false;
  const bool directory = S_ISDIR(st.st_mode);
  acl_t acl = acl_init(8);
  if (!acl) return false;
  bool ok = true; acl_entry_t entry; acl_permset_t perms;
  auto add = [&](acl_tag_t tag, const uid_t* uid, mode_t mode) {
    if (!ok || acl_create_entry(&acl, &entry) != 0 || acl_set_tag_type(entry, tag) != 0 ||
        (uid && acl_set_qualifier(entry, uid) != 0) || acl_get_permset(entry, &perms) != 0 ||
        !SetPerms(perms, mode)) ok = false;
  };
  const ssize_t required_owner_role = profile == RoleProfile::BotState ? 1 : 0;
  ssize_t owner_role = -1;
  for (size_t i = 0; i < 4; ++i) if (roles[i] == st.st_uid) owner_role = static_cast<ssize_t>(i);
  if (owner_role != required_owner_role) { acl_free(acl); return false; }
  add(ACL_USER_OBJ, nullptr, RoleMode(profile, owner_role, directory));
  for (size_t i = 0; i < 4; ++i) if (static_cast<ssize_t>(i) != owner_role) add(ACL_USER, &roles[i], RoleMode(profile, i, directory));
  add(ACL_GROUP_OBJ, nullptr, 0);
  mode_t mask = 0; for (size_t i = 0; i < 4; ++i) mask |= RoleMode(profile, i, directory);
  add(ACL_MASK, nullptr, mask); add(ACL_OTHER, nullptr, 0);
  if (!ok || acl_valid(acl) != 0 || acl_set_fd(fd, acl) != 0) ok = false;
  acl_free(acl);
  return ok;
}
bool VerifyExactRoleAcl(int fd, const std::string& manager, const std::string& bot,
                        const std::string& reader, const std::string& system, RoleProfile profile) {
  uid_t roles[4]; struct stat st;
  if (!ParseUid(manager, &roles[0]) || !ParseUid(bot, &roles[1]) || !ParseUid(reader, &roles[2]) ||
      !ParseUid(system, &roles[3]) || roles[3] != 0 || fstat(fd, &st) != 0 ||
      (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) return false;
  const bool directory = S_ISDIR(st.st_mode);
  const ssize_t required_owner_role = profile == RoleProfile::BotState ? 1 : 0;
  ssize_t owner_role = -1; for (size_t i = 0; i < 4; ++i) if (roles[i] == st.st_uid) owner_role = static_cast<ssize_t>(i);
  if (owner_role != required_owner_role) return false;
  acl_t acl = acl_get_fd(fd); if (!acl) return false;
  bool seen_user_object = false, seen_group = false, seen_mask = false, seen_other = false, seen[4] = {};
  acl_entry_t entry; int state = ACL_FIRST_ENTRY; size_t count = 0; bool ok = true;
  while (ok && acl_get_entry(acl, state, &entry) == 1) {
    state = ACL_NEXT_ENTRY; ++count; acl_tag_t tag; acl_permset_t perms;
    if (acl_get_tag_type(entry, &tag) != 0 || acl_get_permset(entry, &perms) != 0) { ok = false; break; }
    auto has = [&](acl_perm_t permission) { return acl_get_perm(perms, permission) == 1; };
    mode_t actual = (has(ACL_READ) ? S_IRUSR : 0) | (has(ACL_WRITE) ? S_IWUSR : 0) | (has(ACL_EXECUTE) ? S_IXUSR : 0);
    if (tag == ACL_USER_OBJ) { if (seen_user_object || actual != (owner_role >= 0 ? RoleMode(profile, owner_role, directory) : 0)) ok = false; seen_user_object = true; }
    else if (tag == ACL_USER) {
      uid_t* uid = static_cast<uid_t*>(acl_get_qualifier(entry)); if (!uid) { ok = false; break; }
      ssize_t role = -1; for (size_t i = 0; i < 4; ++i) if (roles[i] == *uid && static_cast<ssize_t>(i) != owner_role) role = static_cast<ssize_t>(i);
      acl_free(uid); if (role < 0 || seen[role] || actual != RoleMode(profile, role, directory)) ok = false; else seen[role] = true;
    } else if (tag == ACL_GROUP_OBJ) { if (seen_group || actual != 0) ok = false; seen_group = true; }
    else if (tag == ACL_MASK) {
      mode_t mask = 0; for (size_t i = 0; i < 4; ++i) mask |= RoleMode(profile, i, directory);
      if (seen_mask || actual != mask) ok = false;
      seen_mask = true;
    } else if (tag == ACL_OTHER) { if (seen_other || actual != 0) ok = false; seen_other = true; }
    else ok = false;
  }
  acl_free(acl);
  for (size_t i = 0; i < 4; ++i) if (static_cast<ssize_t>(i) != owner_role && !seen[i]) ok = false;
  return ok && seen_user_object && seen_group && seen_mask && seen_other && count == 7;
}
bool PrincipalGroups(uid_t principal, std::vector<gid_t>* groups) {
  struct passwd record{};
  struct passwd* result = nullptr;
  std::vector<char> buffer(4096);
  for (;;) {
    const int error = getpwuid_r(principal, &record, buffer.data(), buffer.size(), &result);
    if (error == 0 && result != nullptr) break;
    if (error != ERANGE || buffer.size() >= 1024 * 1024) return false;
    buffer.resize(buffer.size() * 2);
  }
  int count = 16;
  for (;;) {
    groups->resize(static_cast<size_t>(count));
    int capacity = count;
    if (getgrouplist(record.pw_name, record.pw_gid, groups->data(), &capacity) >= 0) {
      groups->resize(static_cast<size_t>(capacity));
      return true;
    }
    if (capacity <= count || capacity > 65536) return false;
    count = capacity;
  }
}

bool PrincipalCanAccess(int fd, uid_t principal, mode_t requested) {
  struct stat st{};
  if (fstat(fd, &st) != 0 || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) return false;
  acl_t acl = acl_get_fd(fd);
  if (!acl || acl_valid(acl) != 0) {
    if (acl) acl_free(acl);
    return false;
  }
  mode_t owner_bits = 0, named_user_bits = 0, group_object_bits = 0;
  mode_t named_group_bits = 0, other_bits = 0, mask = 0;
  bool selected_named_user = false;
  bool seen_user_object = false, seen_group_object = false, seen_other = false, seen_mask = false;
  bool has_named_entries = false;
  bool foreign_named_user_mutation = false;
  struct NamedGroupPermission { gid_t gid; mode_t bits; };
  std::vector<NamedGroupPermission> named_groups;
  acl_entry_t entry;
  int state = ACL_FIRST_ENTRY;
  int entry_result = 0;
  while ((entry_result = acl_get_entry(acl, state, &entry)) == 1) {
    state = ACL_NEXT_ENTRY;
    acl_tag_t tag;
    acl_permset_t perms;
    if (acl_get_tag_type(entry, &tag) != 0 || acl_get_permset(entry, &perms) != 0) {
      acl_free(acl);
      return false;
    }
    auto bits = [&]() {
      return (acl_get_perm(perms, ACL_READ) == 1 ? S_IRUSR : 0) |
          (acl_get_perm(perms, ACL_WRITE) == 1 ? S_IWUSR : 0) |
          (acl_get_perm(perms, ACL_EXECUTE) == 1 ? S_IXUSR : 0);
    };
    if (tag == ACL_USER_OBJ) {
      if (seen_user_object) { acl_free(acl); return false; }
      seen_user_object = true;
      owner_bits = bits();
    } else if (tag == ACL_USER) {
      has_named_entries = true;
      uid_t* qualifier = static_cast<uid_t*>(acl_get_qualifier(entry));
      if (!qualifier) { acl_free(acl); return false; }
      const mode_t user_bits = bits();
      if (*qualifier != 0 && (user_bits & S_IWUSR) != 0) {
        foreign_named_user_mutation = true;
      }
      if (principal != st.st_uid && *qualifier == principal) {
        if (selected_named_user) { acl_free(qualifier); acl_free(acl); return false; }
        named_user_bits = user_bits;
        selected_named_user = true;
      }
      acl_free(qualifier);
    } else if (tag == ACL_GROUP_OBJ) {
      if (seen_group_object) { acl_free(acl); return false; }
      seen_group_object = true;
      group_object_bits = bits();
    } else if (tag == ACL_GROUP) {
      has_named_entries = true;
      gid_t* qualifier = static_cast<gid_t*>(acl_get_qualifier(entry));
      if (!qualifier) { acl_free(acl); return false; }
      const mode_t group_bits = bits();
      named_groups.push_back({*qualifier, group_bits});
      named_group_bits |= group_bits;
      acl_free(qualifier);
    } else if (tag == ACL_MASK) {
      if (seen_mask) { acl_free(acl); return false; }
      mask = bits();
      seen_mask = true;
    } else if (tag == ACL_OTHER) {
      if (seen_other) { acl_free(acl); return false; }
      other_bits = bits();
      seen_other = true;
    } else {
      acl_free(acl);
      return false;
    }
  }
  acl_free(acl);
  if (entry_result != 0 || !seen_user_object || !seen_group_object || !seen_other ||
      (has_named_entries && !seen_mask)) return false;
  if (!seen_mask) mask = S_IRUSR | S_IWUSR | S_IXUSR;
  if ((requested & S_IWUSR) != 0 && foreign_named_user_mutation) return false;
  const bool writable_group_class =
      (group_object_bits & S_IWUSR) != 0 ||
      (named_group_bits & S_IWUSR) != 0 ||
      (other_bits & S_IWUSR) != 0;
  if ((requested & S_IWUSR) != 0 && writable_group_class) return false;
  if (principal == st.st_uid) return (owner_bits & requested) == requested;
  if (selected_named_user && (requested & S_IWUSR) != 0 &&
      (named_user_bits & S_IWUSR) != 0) return false;
  if (selected_named_user) return ((named_user_bits & mask) & requested) == requested;

  std::vector<gid_t> principal_groups;
  if (!PrincipalGroups(principal, &principal_groups)) return false;
  bool group_match = false;
  mode_t effective_group = 0;
  for (gid_t group : principal_groups) {
    if (group == st.st_gid) {
      group_match = true;
      effective_group |= group_object_bits;
    }
    for (const NamedGroupPermission& named : named_groups) {
      if (group == named.gid) {
        group_match = true;
        effective_group |= named.bits;
      }
    }
  }
  effective_group &= mask;
  if (group_match) return (effective_group & requested) == requested;
  return (other_bits & requested) == requested;
}

bool ApplyAndVerifyExactRoleAcl(int fd, const std::string& manager, const std::string& bot,
                                const std::string& reader, const std::string& system, RoleProfile profile) {
  return ApplyExactRoleAcl(fd, manager, bot, reader, system, profile) &&
      VerifyExactRoleAcl(fd, manager, bot, reader, system, profile) && fsync(fd) == 0;
}
int OpenObjectNoFollow(int parent_fd, const std::string& name, int flags, mode_t mode = 0600) {
  if (!SafeName(name)) return -1;
  const int safe_flags = flags | O_NOFOLLOW | O_CLOEXEC;
  return (safe_flags & (O_CREAT | O_TMPFILE)) != 0
      ? openat(parent_fd, name.c_str(), safe_flags, mode)
      : openat(parent_fd, name.c_str(), safe_flags);
}
void SetIdentity(napi_env env, napi_value result, int fd) {
  struct stat st;
  if (fstat(fd, &st) != 0) return;
  napi_value v;
  const std::string device = std::to_string(static_cast<uint64_t>(st.st_dev));
  const std::string inode = std::to_string(static_cast<uint64_t>(st.st_ino));
  const std::string owner = "uid:" + std::to_string(static_cast<uint64_t>(st.st_uid));
  napi_create_string_utf8(env, device.c_str(), NAPI_AUTO_LENGTH, &v); napi_set_named_property(env, result, "device", v);
  napi_create_string_utf8(env, inode.c_str(), NAPI_AUTO_LENGTH, &v); napi_set_named_property(env, result, "inode", v);
  napi_create_uint32(env, static_cast<uint32_t>(st.st_mode), &v); napi_set_named_property(env, result, "mode", v);
  napi_create_string_utf8(env, owner.c_str(), NAPI_AUTO_LENGTH, &v); napi_set_named_property(env, result, "owner", v);
}
#endif

napi_value OpenVerifiedParent(napi_env env, napi_callback_info info) {
  std::string path; if (!StringArg(env, info, 0, &path)) return nullptr;
  std::filesystem::path parent = std::filesystem::u8path(path).parent_path();
  if (parent.empty()) parent = ".";
#ifdef _WIN32
  HANDLE h = OpenNoFollowDirectory(parent.u8string(), READ_CONTROL | FILE_READ_ATTRIBUTES);
  if (h == INVALID_HANDLE_VALUE) { Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to open verified parent"); return nullptr; }
  napi_value result; napi_create_object(env, &result); SetIdentity(env, result, h); CloseHandle(h); return result;
#else
  int fd = OpenDirectoryNoFollow(parent.u8string());
  if (fd < 0) { Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to open verified parent"); return nullptr; }
  napi_value result; napi_create_object(env, &result); SetIdentity(env, result, fd); close(fd); return result;
#endif
}

napi_value OpenNoFollowMethod(napi_env env, napi_callback_info info) {
  std::string path; if (!StringArg(env, info, 0, &path)) return nullptr;
#ifdef _WIN32
  HANDLE h = OpenNoFollowObject(path, READ_CONTROL | FILE_READ_ATTRIBUTES);
  if (h == INVALID_HANDLE_VALUE) { Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to open without following reparse points"); return nullptr; }
  napi_value result; napi_create_object(env, &result); SetIdentity(env, result, h); CloseHandle(h); return result;
#else
  int parent_fd = -1;
  std::string name;
  if (!OpenParentNoFollow(path, &parent_fd, &name)) {
    Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to open verified parent");
    return nullptr;
  }
  int fd = OpenObjectNoFollow(parent_fd, name, O_RDONLY);
  if (fd < 0) {
    close(parent_fd);
    Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to open without following symlinks");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  SetIdentity(env, result, fd);
  close(fd);
  close(parent_fd);
  return result;
#endif
}

napi_value ReadIdentity(napi_env env, napi_callback_info info) { return OpenNoFollowMethod(env, info); }

napi_value PathExistsNoFollow(napi_env env, napi_callback_info info) {
  std::string path;
  if (!StringArg(env, info, 0, &path)) return nullptr;
  bool exists = false;
#ifdef _WIN32
  HANDLE handle = OpenNoFollowObject(path, FILE_READ_ATTRIBUTES);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
      Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to test path existence without following reparse points");
      return nullptr;
    }
  } else {
    exists = true;
    CloseHandle(handle);
  }
#else
  int parent_fd = -1;
  std::string name;
  if (!OpenParentNoFollow(path, &parent_fd, &name)) {
    if (errno != ENOENT) {
      Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to test verified parent existence");
      return nullptr;
    }
  } else {
    struct stat st {};
    if (fstatat(parent_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) exists = true;
    else if (errno != ENOENT) {
      close(parent_fd);
      Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to test path existence without following symlinks");
      return nullptr;
    }
    close(parent_fd);
  }
#endif
  napi_value result;
  napi_get_boolean(env, exists, &result);
  return result;
}

napi_value ReadAcl(napi_env env, napi_callback_info info) {
  std::string path; if (!StringArg(env, info, 0, &path)) return nullptr;
#ifdef _WIN32
  HANDLE handle = OpenNoFollowObject(path, READ_CONTROL);
  if (handle == INVALID_HANDLE_VALUE) { Throw(env, "ERR_NATIVE_CONTROL_ACL", "unable to open ACL without following reparse points"); return nullptr; }
  PSECURITY_DESCRIPTOR sd = nullptr;
  DWORD status = GetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                                 nullptr, nullptr, nullptr, nullptr, &sd);
  CloseHandle(handle);
  if (status != ERROR_SUCCESS) { Throw(env, "ERR_NATIVE_CONTROL_ACL", "unable to read ACL"); return nullptr; }
  LPWSTR sddl = nullptr;
  if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &sddl, nullptr)) { LocalFree(sd); Throw(env, "ERR_NATIVE_CONTROL_ACL", "unable to encode ACL"); return nullptr; }
  std::string text = Utf8(sddl); LocalFree(sddl); LocalFree(sd);
  napi_value result; napi_create_string_utf8(env, text.c_str(), NAPI_AUTO_LENGTH, &result); return result;
#else
  int parent_fd = -1;
  std::string name;
  if (!OpenParentNoFollow(path, &parent_fd, &name)) {
    Throw(env, "ERR_NATIVE_CONTROL_ACL", "unable to open verified ACL parent");
    return nullptr;
  }
  int fd = OpenObjectNoFollow(parent_fd, name, O_RDONLY);
  acl_t acl = fd >= 0 ? acl_get_fd(fd) : nullptr;
  char* text = acl ? acl_to_text(acl, nullptr) : nullptr;
  if (fd >= 0) close(fd);
  close(parent_fd);
  if (acl) acl_free(acl);
  if (!text) {
    Throw(env, "ERR_NATIVE_CONTROL_ACL", "unable to read no-follow POSIX ACL");
    return nullptr;
  }
  napi_value result;
  napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &result);
  acl_free(text);
  return result;
#endif
}
napi_value VerifyExactRoleAclMethod(napi_env env, napi_callback_info info) {
  std::string path, manager, bot, reader, system, profile_text;
  if (!StringArg(env, info, 0, &path, 6) || !StringArg(env, info, 1, &manager, 6) ||
      !StringArg(env, info, 2, &bot, 6) || !StringArg(env, info, 3, &reader, 6) ||
      !StringArg(env, info, 4, &system, 6) || !StringArg(env, info, 5, &profile_text, 6)) return nullptr;
  RoleProfile profile;
  if (!ParseRoleProfile(profile_text, &profile)) {
    Refuse(env, "verify_exact_role_acl", "role profile is invalid");
    return nullptr;
  }
  bool verified = false;
#ifdef _WIN32
  HANDLE handle = OpenNoFollowObject(path, READ_CONTROL);
  verified = handle != INVALID_HANDLE_VALUE &&
      VerifyExactRoleAcl(handle, manager, bot, reader, system, profile);
  if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
#else
  int parent_fd = -1;
  std::string name;
  if (OpenParentNoFollow(path, &parent_fd, &name)) {
    int fd = OpenObjectNoFollow(parent_fd, name, O_RDONLY);
    verified = fd >= 0 && VerifyExactRoleAcl(fd, manager, bot, reader, system, profile);
    if (fd >= 0) close(fd);
    close(parent_fd);
  }
#endif
  napi_value result;
  napi_get_boolean(env, verified, &result);
  return result;
}

napi_value SetRoleAcl(napi_env env, napi_callback_info) {
  Refuse(env, "set_role_acl", "single-principal ACL replacement is unsafe; use set_exact_role_acl");
  return nullptr;
}

napi_value SetExactRoleAcl(napi_env env, napi_callback_info info) {
  std::string path, manager, bot, reader, system, profile_text;
  if (!StringArg(env, info, 0, &path, 6) || !StringArg(env, info, 1, &manager, 6) ||
      !StringArg(env, info, 2, &bot, 6) || !StringArg(env, info, 3, &reader, 6) ||
      !StringArg(env, info, 4, &system, 6) || !StringArg(env, info, 5, &profile_text, 6)) return nullptr;
#ifdef _WIN32
  WindowsPathParts supported_path;
  if (!ParseWindowsPath(path, &supported_path)) {
    Refuse(env, "set_exact_role_acl", "path is not a supported absolute handle-relative Windows path");
    return nullptr;
  }
  RoleProfile profile;
  if (!ParseRoleProfile(profile_text, &profile)) { Refuse(env, "set_exact_role_acl", "role profile is invalid"); return nullptr; }
  HANDLE handle = OpenNoFollowObject(path, READ_CONTROL | WRITE_DAC);
  if (handle == INVALID_HANDLE_VALUE) {
    Refuse(env, "set_exact_role_acl", "target cannot be opened through a verified no-follow path");
    return nullptr;
  }
  bool applied = ApplyExactRoleAcl(handle, manager, bot, reader, system, profile);
  CloseHandle(handle);
  if (!applied) {
    Throw(env, "ERR_NATIVE_CONTROL_ACL", "unable to apply protected exact role DACL");
    return nullptr;
  }
  napi_value result; napi_get_undefined(env, &result); return result;
#else
  RoleProfile profile; int parent_fd; std::string name;
  if (!ParseRoleProfile(profile_text, &profile) || !OpenParentNoFollow(path, &parent_fd, &name)) {
    Refuse(env, "set_exact_role_acl", "role profile or descriptor-relative path is invalid"); return nullptr;
  }
  int fd = OpenObjectNoFollow(parent_fd, name, O_RDWR);
  bool applied = fd >= 0 && ApplyAndVerifyExactRoleAcl(fd, manager, bot, reader, system, profile);
  if (fd >= 0) close(fd);
  close(parent_fd);
  if (!applied) { Throw(env, "ERR_NATIVE_CONTROL_ACL", "unable to apply protected exact POSIX role ACL"); return nullptr; }
  napi_value result; napi_get_undefined(env, &result); return result;
#endif
}

napi_value ReadVerifiedBytes(napi_env env, napi_callback_info info) {
  std::string path; if (!StringArg(env, info, 0, &path)) return nullptr;
#ifdef _WIN32
  HANDLE h = OpenNoFollowFile(path, GENERIC_READ);
  if (h == INVALID_HANDLE_VALUE) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND) { napi_value absent; napi_get_null(env, &absent); return absent; }
    Throw(env, "ERR_NATIVE_CONTROL_READ", "unable to read verified bytes"); return nullptr;
  }
  BY_HANDLE_FILE_INFORMATION before;
  if (!GetFileInformationByHandle(h, &before)) { CloseHandle(h); Throw(env, "ERR_NATIVE_CONTROL_READ", "unable to read verified identity"); return nullptr; }
  LARGE_INTEGER size;
  if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 || size.QuadPart > 16 * 1024 * 1024) { CloseHandle(h); Refuse(env, "read_verified_bytes", "file size is invalid or exceeds limit"); return nullptr; }
  std::vector<uint8_t> bytes(static_cast<size_t>(size.QuadPart)); DWORD read = 0;
  if ((!bytes.empty() && (!ReadFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size()))) { CloseHandle(h); Throw(env, "ERR_NATIVE_CONTROL_READ", "unable to read verified bytes"); return nullptr; }
  BY_HANDLE_FILE_INFORMATION after;
  LARGE_INTEGER after_size;
  if (!GetFileInformationByHandle(h, &after) || !GetFileSizeEx(h, &after_size) ||
      after.dwVolumeSerialNumber != before.dwVolumeSerialNumber ||
      after.nFileIndexHigh != before.nFileIndexHigh || after.nFileIndexLow != before.nFileIndexLow ||
      after_size.QuadPart != size.QuadPart) {
    CloseHandle(h); Refuse(env, "read_verified_bytes", "file identity changed while reading"); return nullptr;
  }
  CloseHandle(h);
#else
  int parent_fd = -1;
  std::string name;
  if (!OpenParentNoFollow(path, &parent_fd, &name)) {
    Throw(env, "ERR_NATIVE_CONTROL_READ", "unable to open verified parent");
    return nullptr;
  }
  int fd = OpenObjectNoFollow(parent_fd, name, O_RDONLY);
  if (fd < 0) {
    const int open_error = errno;
    close(parent_fd);
    if (open_error == ENOENT) { napi_value absent; napi_get_null(env, &absent); return absent; }
    Throw(env, "ERR_NATIVE_CONTROL_READ", "unable to read verified bytes");
    return nullptr;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > 16 * 1024 * 1024) {
    close(fd); close(parent_fd); Refuse(env, "read_verified_bytes", "file size is invalid or exceeds limit"); return nullptr;
  }
  std::vector<uint8_t> bytes(static_cast<size_t>(st.st_size)); size_t offset = 0;
  while (offset < bytes.size()) {
    ssize_t n = read(fd, bytes.data() + offset, bytes.size() - offset);
    if (n <= 0) { close(fd); close(parent_fd); Throw(env, "ERR_NATIVE_CONTROL_READ", "unable to read verified bytes"); return nullptr; }
    offset += static_cast<size_t>(n);
  }
  struct stat after, named;
  const bool stable = fstat(fd, &after) == 0 &&
      fstatat(parent_fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
      after.st_dev == st.st_dev && after.st_ino == st.st_ino && after.st_size == st.st_size &&
      named.st_dev == st.st_dev && named.st_ino == st.st_ino;
  close(fd); close(parent_fd);
  if (!stable) { Refuse(env, "read_verified_bytes", "file identity changed while reading"); return nullptr; }
#endif
  napi_value result; void* output = nullptr;
  napi_create_buffer_copy(env, bytes.size(), bytes.data(), &output, &result);
  return result;
}

bool WriteHandleBytes(
#ifdef _WIN32
  HANDLE h,
#else
  int h,
#endif
  const std::vector<uint8_t>& bytes) {
#ifdef _WIN32
  DWORD written = 0;
  return (bytes.empty() || (WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size())) && FlushFileBuffers(h);
#else
  size_t offset = 0;
  while (offset < bytes.size()) { ssize_t n = write(h, bytes.data() + offset, bytes.size() - offset); if (n <= 0) return false; offset += static_cast<size_t>(n); }
  return fsync(h) == 0;
#endif
}
#ifdef _WIN32
HANDLE OpenDurableDirectoryNoFollow(const std::string& directory_path) {
  return OpenNoFollowDirectory(directory_path, FILE_GENERIC_READ | FILE_GENERIC_WRITE);
}
// Flushes an already-opened directory handle's own metadata. The handle must
// have been opened through a verified no-follow path (e.g. via
// OpenDurableDirectoryNoFollow) with at least FILE_GENERIC_WRITE access; that
// does not require SeManageVolumePrivilege and is sufficient to make prior
// create/rename/unlink operations in this directory durable across a crash
// (see docs/adr/0003-management-mapping-envelope.md). A best-effort,
// non-fatal volume-level flush is attempted afterward for extra durability
// margin when the process happens to hold elevated privilege.
bool FlushDurableDirectoryHandle(HANDLE dir, const std::string& directory_path) {
  if (!FlushFileBuffers(dir)) return false;
  const std::wstring wdirectory = Wide(directory_path);
  wchar_t mount[MAX_PATH + 1]{};
  wchar_t volume[MAX_PATH + 1]{};
  if (!wdirectory.empty() && GetVolumePathNameW(wdirectory.c_str(), mount, MAX_PATH) &&
      GetVolumeNameForVolumeMountPointW(mount, volume, MAX_PATH)) {
    HANDLE vol = CreateFileW(volume, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (vol != INVALID_HANDLE_VALUE) {
      FlushFileBuffers(vol);
      CloseHandle(vol);
    }
  }
  return true;
}
bool FlushWindowsDirectoryNoFollow(const std::string& directory_path) {
  HANDLE dir = OpenDurableDirectoryNoFollow(directory_path);
  if (dir == INVALID_HANDLE_VALUE) return false;
  const bool ok = FlushDurableDirectoryHandle(dir, directory_path);
  CloseHandle(dir);
  return ok;
}
#endif
[[maybe_unused]] bool FlushDirectoryOrVolumePath(const std::string& path, bool path_is_directory = false) {
#ifdef _WIN32
  std::string directory_path = path;
  if (!path_is_directory) {
    std::filesystem::path parent = std::filesystem::u8path(path).parent_path();
    if (parent.empty()) parent = ".";
    directory_path = parent.u8string();
  }
  return FlushWindowsDirectoryNoFollow(directory_path);
#else
  int fd = OpenDirectoryNoFollow(path);
  if (fd < 0) return false;
  const bool flushed = fsync(fd) == 0;
  close(fd);
  return flushed;
#endif
}

napi_value CurrentOsPrincipal(napi_env env, napi_callback_info) {
#ifdef _WIN32
  HANDLE token = nullptr; DWORD size = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { Throw(env, "ERR_NATIVE_CONTROL_PRINCIPAL", "unable to read current OS principal"); return nullptr; }
  if (!GetTokenInformation(token, TokenUser, nullptr, 0, &size) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) { CloseHandle(token); Throw(env, "ERR_NATIVE_CONTROL_PRINCIPAL", "unable to read current OS principal"); return nullptr; }
  if (size == 0) { CloseHandle(token); Throw(env, "ERR_NATIVE_CONTROL_PRINCIPAL", "unable to read current OS principal"); return nullptr; }
  std::vector<uint8_t> buffer(size);
  if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) { CloseHandle(token); Throw(env, "ERR_NATIVE_CONTROL_PRINCIPAL", "unable to read current OS principal"); return nullptr; }
  CloseHandle(token); LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) { Throw(env, "ERR_NATIVE_CONTROL_PRINCIPAL", "unable to encode current OS principal"); return nullptr; }
  std::string principal = Utf8(sid); LocalFree(sid);
#else
  std::string principal = "uid:" + std::to_string(geteuid());
#endif
  napi_value result, kind, value;
#ifdef _WIN32
  napi_create_string_utf8(env, "sid", NAPI_AUTO_LENGTH, &kind);
#else
  napi_create_string_utf8(env, "uid", NAPI_AUTO_LENGTH, &kind);
#endif
  napi_create_string_utf8(env, principal.c_str(), NAPI_AUTO_LENGTH, &value);
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "kind", kind);
  napi_set_named_property(env, result, "value", value);
  return result;
}

napi_value CreateExclusiveTemp(napi_env env, napi_callback_info info) {
  std::string parent, prefix, manager, bot, reader, system, profile_text; std::vector<uint8_t> bytes;
  if (!StringArg(env, info, 0, &parent, 8) || !StringArg(env, info, 1, &prefix, 8) ||
      !BufferArg(env, info, 2, &bytes) || !StringArg(env, info, 3, &manager, 8) ||
      !StringArg(env, info, 4, &bot, 8) || !StringArg(env, info, 5, &reader, 8) ||
      !StringArg(env, info, 6, &system, 8) || !StringArg(env, info, 7, &profile_text, 8)) return nullptr;
  if (prefix.empty() || prefix.find_first_of("/\\") != std::string::npos) { Refuse(env, "create_exclusive_temp", "prefix must be a non-empty file-name component"); return nullptr; }
#ifdef _WIN32
  if (!SafeWideName(Wide(prefix))) {
    Refuse(env, "create_exclusive_temp", "prefix is not a supported Windows file-name component");
    return nullptr;
  }
  RoleProfile profile;
  if (!ParseRoleProfile(profile_text, &profile)) { Refuse(env, "create_exclusive_temp", "role profile is invalid"); return nullptr; }
  RoleAcl roles;
  if (!BuildExactRoleAcl(manager, bot, reader, system, profile, &roles)) {
    Refuse(env, "create_exclusive_temp", "protected exact role DACL cannot be constructed");
    return nullptr;
  }
  if (NtCreateFileApi() == nullptr) {
    Refuse(env, "create_exclusive_temp", "handle-relative Windows open primitive is unavailable");
    return nullptr;
  }
  HANDLE verified_parent = OpenWindowsPathNoFollow(
      parent, kWindowsMutationParentAccess, VerifiedObjectType::Directory);
  if (verified_parent == INVALID_HANDLE_VALUE) {
    Refuse(env, "create_exclusive_temp", "parent is not a supported absolute handle-relative Windows directory");
    return nullptr;
  }
  CloseHandle(verified_parent);
  for (unsigned i = 0; i < 128; ++i) {
    std::string candidate = (std::filesystem::u8path(parent) / (prefix + "." + std::to_string(i))).u8string();
    HANDLE h = CreateProtectedFileNoFollow(candidate, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | DELETE, roles.acl);
    if (h == INVALID_HANDLE_VALUE) {
      const DWORD error = GetLastError();
      if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) continue;
      Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to create exclusive temp file");
      return nullptr;
    }
    const auto discard = [&](HANDLE handle) {
      FILE_DISPOSITION_INFO disposition{};
      disposition.DeleteFile = TRUE;
      const bool removed = SetFileInformationByHandle(handle, FileDispositionInfo, &disposition, sizeof(disposition)) != FALSE;
      const bool durable = removed && FlushDirectoryOrVolumePath(parent, true);
      CloseHandle(handle);
      if (!durable) return false;
      HANDLE probe = OpenNoFollowFile(candidate, FILE_READ_ATTRIBUTES);
      if (probe != INVALID_HANDLE_VALUE) {
        CloseHandle(probe);
        return false;
      }
      const DWORD error = GetLastError();
      return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    };
    if (!VerifyExactRoleAcl(h, manager, bot, reader, system, profile)) {
      if (!discard(h)) Refuse(env, "create_exclusive_temp", "failed temp ACL cleanup is ambiguous");
      else Throw(env, "ERR_NATIVE_CONTROL_ACL", "unable to verify protected exact temp DACL");
      return nullptr;
    }
    const bool ok = WriteHandleBytes(h, bytes);
    if (!ok) {
      if (!discard(h)) Refuse(env, "create_exclusive_temp", "failed temp write cleanup is ambiguous");
      else Throw(env, "ERR_NATIVE_CONTROL_WRITE", "unable to write and flush exclusive temp file");
      return nullptr;
    }
    CloseHandle(h);
    napi_value result; napi_create_string_utf8(env, candidate.c_str(), NAPI_AUTO_LENGTH, &result); return result;
  }
  Refuse(env, "create_exclusive_temp", "exclusive name space exhausted"); return nullptr;
#else
  RoleProfile profile; int parent_fd = OpenDirectoryNoFollow(parent);
  if (!ParseRoleProfile(profile_text, &profile) || parent_fd < 0) { if (parent_fd >= 0) close(parent_fd); Refuse(env, "create_exclusive_temp", "role profile or parent path is invalid"); return nullptr; }
  for (unsigned i = 0; i < 128; ++i) {
    std::string name = prefix + "." + std::to_string(i);
    int fd = OpenObjectNoFollow(parent_fd, name, O_CREAT | O_EXCL | O_RDWR);
    if (fd < 0) { if (errno == EEXIST) continue; break; }
    const auto discard = [&](int descriptor) {
      struct stat held{}, named{};
      const bool exact = fstat(descriptor, &held) == 0 &&
          fstatat(parent_fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
          held.st_dev == named.st_dev && held.st_ino == named.st_ino;
      const bool removed = exact && unlinkat(parent_fd, name.c_str(), 0) == 0;
      const bool durable = removed && fsync(parent_fd) == 0;
      bool absent = false;
      if (removed) {
        struct stat after{};
        errno = 0;
        absent = fstatat(parent_fd, name.c_str(), &after, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
      }
      close(descriptor);
      return durable && absent;
    };
    const bool prepared = ApplyAndVerifyExactRoleAcl(fd, manager, bot, reader, system, profile) &&
        WriteHandleBytes(fd, bytes);
    if (!prepared) {
      const bool clean = discard(fd);
      close(parent_fd);
      if (!clean) Refuse(env, "create_exclusive_temp", "failed temp creation cleanup is ambiguous");
      else Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to create durable exact-ACL temp file");
      return nullptr;
    }
    if (fsync(parent_fd) != 0) {
      const bool clean = discard(fd);
      close(parent_fd);
      if (!clean) Refuse(env, "create_exclusive_temp", "failed temp parent cleanup is ambiguous");
      else Throw(env, "ERR_NATIVE_CONTROL_FLUSH", "unable to flush temp parent directory");
      return nullptr;
    }
    close(fd);
    close(parent_fd);
    std::string candidate = (std::filesystem::u8path(parent) / name).u8string();
    napi_value result; napi_create_string_utf8(env, candidate.c_str(), NAPI_AUTO_LENGTH, &result); return result;
  }
  close(parent_fd); Refuse(env, "create_exclusive_temp", "exclusive name space exhausted"); return nullptr;
#endif
}
napi_value RemoveVerifiedFile(napi_env env, napi_callback_info info) {
  std::string path; std::vector<uint8_t> expected;
  if (!StringArg(env, info, 0, &path, 2) || !BufferArg(env, info, 1, &expected)) return nullptr;
#ifdef _WIN32
  WindowsPathParts ignored_path;
  if (!ParseWindowsPath(path, &ignored_path)) {
    Refuse(env, "remove_verified_file", "path is not a supported absolute handle-relative Windows path");
    return nullptr;
  }
  HANDLE h = OpenNoFollowFile(path, GENERIC_READ | DELETE);
  if (h == INVALID_HANDLE_VALUE) { Refuse(env, "remove_verified_file", "target cannot be opened through a verified no-follow path"); return nullptr; }
  LARGE_INTEGER size; DWORD read = 0; std::vector<uint8_t> actual;
  if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 || size.QuadPart > 16 * 1024 * 1024) { CloseHandle(h); Refuse(env, "remove_verified_file", "scratch size is invalid"); return nullptr; }
  actual.resize(static_cast<size_t>(size.QuadPart));
  if ((!actual.empty() && (!ReadFile(h, actual.data(), static_cast<DWORD>(actual.size()), &read, nullptr) || read != actual.size())) || actual != expected) { CloseHandle(h); Refuse(env, "remove_verified_file", "scratch bytes do not match"); return nullptr; }
  FILE_DISPOSITION_INFO disposition{}; disposition.DeleteFile = TRUE;
  if (!SetFileInformationByHandle(h, FileDispositionInfo, &disposition, sizeof(disposition))) { CloseHandle(h); Throw(env, "ERR_NATIVE_CONTROL_REMOVE", "unable to remove verified scratch"); return nullptr; }
  CloseHandle(h);
#else
  int parent_fd = -1;
  std::string name;
  if (!OpenParentNoFollow(path, &parent_fd, &name)) {
    Refuse(env, "remove_verified_file", "descriptor-relative scratch path is invalid");
    return nullptr;
  }
  int fd = OpenObjectNoFollow(parent_fd, name, O_RDONLY);
  struct stat held{}, named{};
  std::vector<uint8_t> actual;
  bool valid = fd >= 0 && fstat(fd, &held) == 0 && S_ISREG(held.st_mode) &&
      held.st_size >= 0 && held.st_size <= 16 * 1024 * 1024;
  if (valid) {
    actual.resize(static_cast<size_t>(held.st_size));
    size_t offset = 0;
    while (offset < actual.size()) {
      ssize_t count = read(fd, actual.data() + offset, actual.size() - offset);
      if (count <= 0) { valid = false; break; }
      offset += static_cast<size_t>(count);
    }
  }
  valid = valid && actual == expected &&
      fstatat(parent_fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
      held.st_dev == named.st_dev && held.st_ino == named.st_ino &&
      unlinkat(parent_fd, name.c_str(), 0) == 0 && fsync(parent_fd) == 0;
  if (fd >= 0) close(fd);
  close(parent_fd);
  if (!valid) {
    Refuse(env, "remove_verified_file", "descriptor-relative exact deletion failed");
    return nullptr;
  }
#endif
  napi_value result; napi_get_undefined(env, &result); return result;
}

napi_value CreateAbsentExclusive(napi_env env, napi_callback_info info) {
  std::string path, manager, bot, reader, system, profile_text; std::vector<uint8_t> bytes;
  if (!StringArg(env, info, 0, &path, 7) || !BufferArg(env, info, 1, &bytes) ||
      !StringArg(env, info, 2, &manager, 7) || !StringArg(env, info, 3, &bot, 7) ||
      !StringArg(env, info, 4, &reader, 7) || !StringArg(env, info, 5, &system, 7) ||
      !StringArg(env, info, 6, &profile_text, 7)) return nullptr;
#ifdef _WIN32
  RoleProfile profile;
  if (!ParseRoleProfile(profile_text, &profile)) { Refuse(env, "create_absent_exclusive", "role profile is invalid"); return nullptr; }
  RoleAcl roles;
  if (!BuildExactRoleAcl(manager, bot, reader, system, profile, &roles)) {
    Refuse(env, "create_absent_exclusive", "protected exact role DACL cannot be constructed");
    return nullptr;
  }
  if (NtCreateFileApi() == nullptr || NtSetInformationFileApi() == nullptr) {
    Refuse(env, "create_absent_exclusive", "handle-relative Windows open and rename primitives are unavailable");
    return nullptr;
  }
  HANDLE parent = INVALID_HANDLE_VALUE;
  std::wstring name;
  if (!OpenWindowsParentNoFollow(path, &parent, &name, kWindowsMutationParentAccess)) {
    Refuse(env, "create_absent_exclusive", "path is not a supported absolute handle-relative Windows path");
    return nullptr;
  }
  SECURITY_DESCRIPTOR descriptor{};
  if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorDacl(&descriptor, TRUE, roles.acl, FALSE) ||
      !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    CloseHandle(parent);
    Refuse(env, "create_absent_exclusive", "protected exact role DACL cannot be constructed");
    return nullptr;
  }
  HANDLE temporary = INVALID_HANDLE_VALUE;
  std::wstring temporary_name;
  for (unsigned i = 0; i < 128; ++i) {
    temporary_name = name + L".create." + std::to_wstring(GetCurrentProcessId()) +
        L"." + std::to_wstring(GetTickCount64()) + L"." + std::to_wstring(i);
    temporary = OpenWindowsRelative(parent, temporary_name,
        GENERIC_READ | GENERIC_WRITE | WRITE_DAC | DELETE, kFileCreate,
        VerifiedObjectType::File, &descriptor);
    if (temporary != INVALID_HANDLE_VALUE || GetLastError() != ERROR_ALREADY_EXISTS) break;
  }
  if (temporary == INVALID_HANDLE_VALUE) {
    CloseHandle(parent);
    Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to create same-parent temporary file");
    return nullptr;
  }
  const auto discard = [&]() {
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    const bool removed = SetFileInformationByHandle(
        temporary, FileDispositionInfo, &disposition, sizeof(disposition)) != FALSE;
    const bool durable = removed && FlushDirectoryOrVolumePath(path);
    CloseHandle(temporary);
    temporary = INVALID_HANDLE_VALUE;
    return durable;
  };
  BY_HANDLE_FILE_INFORMATION temporary_info{};
  const bool owned = GetFileInformationByHandle(temporary, &temporary_info) != FALSE;
  const bool prepared = owned &&
      VerifyExactRoleAcl(temporary, manager, bot, reader, system, profile) &&
      WriteHandleBytes(temporary, bytes) &&
      GetFileInformationByHandle(temporary, &temporary_info) != FALSE;
  if (!prepared) {
    const bool clean = discard();
    CloseHandle(parent);
    if (!clean) Refuse(env, "create_absent_exclusive", "failed temporary cleanup is ambiguous");
    else Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to prepare protected absent file");
    return nullptr;
  }
  const bool renamed = RenameWindowsRelative(temporary, parent, name, false);
  if (!renamed) {
    const bool clean = discard();
    CloseHandle(parent);
    if (!clean) Refuse(env, "create_absent_exclusive", "failed temporary cleanup is ambiguous");
    else Throw(env, "ERR_NATIVE_CONTROL_CREATE", "atomic no-replace publication failed");
    return nullptr;
  }
  HANDLE published = OpenWindowsRelative(parent, name, GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
      kFileOpen, VerifiedObjectType::File);
  BY_HANDLE_FILE_INFORMATION published_info{};
  const bool verified = published != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandle(published, &published_info) &&
      published_info.dwVolumeSerialNumber == temporary_info.dwVolumeSerialNumber &&
      published_info.nFileIndexHigh == temporary_info.nFileIndexHigh &&
      published_info.nFileIndexLow == temporary_info.nFileIndexLow &&
      VerifyExactRoleAcl(published, manager, bot, reader, system, profile) &&
      GetFileInformationByHandle(temporary, &temporary_info) &&
      temporary_info.dwVolumeSerialNumber == published_info.dwVolumeSerialNumber &&
      temporary_info.nFileIndexHigh == published_info.nFileIndexHigh &&
      temporary_info.nFileIndexLow == published_info.nFileIndexLow;
  const bool durable = verified && FlushFileBuffers(published) &&
      FlushDirectoryOrVolumePath(path);
  if (published != INVALID_HANDLE_VALUE) CloseHandle(published);
  CloseHandle(temporary);
  temporary = INVALID_HANDLE_VALUE;
  CloseHandle(parent);
  if (!durable) {
    Throw(env, "ERR_NATIVE_CONTROL_CREATE", "published absent-file durability, identity, or DACL verification failed");
    return nullptr;
  }
  napi_value result; napi_get_undefined(env, &result); return result;
#else
  RoleProfile profile; int parent_fd; std::string name;
  if (!ParseRoleProfile(profile_text, &profile) || !OpenParentNoFollow(path, &parent_fd, &name)) {
    Refuse(env, "create_absent_exclusive", "role profile or descriptor-relative path is invalid");
    return nullptr;
  }
  static std::atomic<unsigned long long> sequence{0};
  const std::string temporary = "." + name + ".create." + std::to_string(getpid()) + "." +
      std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
  int fd = OpenObjectNoFollow(parent_fd, temporary, O_CREAT | O_EXCL | O_RDWR);
  if (fd < 0) {
    const int open_error = errno;
    close(parent_fd);
    if (open_error == EEXIST) {
      Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to create unique absent-file temporary");
    } else {
      Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to open absent-file temporary");
    }
    return nullptr;
  }
  struct stat held{};
  const bool owned = fstat(fd, &held) == 0 && S_ISREG(held.st_mode);
  const auto same_identity = [&](const char* entry_name) {
    struct stat named{};
    return owned && fstatat(parent_fd, entry_name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        named.st_dev == held.st_dev && named.st_ino == held.st_ino;
  };
  const auto discard = [&]() {
    const bool removed = same_identity(temporary.c_str()) &&
        unlinkat(parent_fd, temporary.c_str(), 0) == 0;
    const bool durable = removed && fsync(parent_fd) == 0;
    bool absent = false;
    if (removed) {
      struct stat after{};
      errno = 0;
      absent = fstatat(parent_fd, temporary.c_str(), &after, AT_SYMLINK_NOFOLLOW) != 0 &&
          errno == ENOENT;
    }
    close(fd);
    fd = -1;
    return durable && absent;
  };
  if (!owned || !ApplyAndVerifyExactRoleAcl(fd, manager, bot, reader, system, profile) ||
      !WriteHandleBytes(fd, bytes) || !same_identity(temporary.c_str())) {
    const bool clean = discard();
    close(parent_fd);
    if (!clean) Refuse(env, "create_absent_exclusive", "failed temporary cleanup is ambiguous");
    else Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to prepare protected absent file");
    return nullptr;
  }
#ifdef AT_EMPTY_PATH
  const bool linked = linkat(fd, "", parent_fd, name.c_str(), AT_EMPTY_PATH) == 0;
#else
  const bool linked = same_identity(temporary.c_str()) &&
      linkat(parent_fd, temporary.c_str(), parent_fd, name.c_str(), 0) == 0;
#endif
  struct stat published{};
  const bool publication_verified = linked &&
      fstatat(parent_fd, name.c_str(), &published, AT_SYMLINK_NOFOLLOW) == 0 &&
      published.st_dev == held.st_dev && published.st_ino == held.st_ino;
  if (!publication_verified || fsync(parent_fd) != 0) {
    const bool clean = discard();
    close(parent_fd);
    if (!clean) Refuse(env, "create_absent_exclusive", "failed absent-file publication cleanup is ambiguous");
    else Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to atomically publish durable exact-ACL absent file");
    return nullptr;
  }
  const bool removed = same_identity(temporary.c_str()) &&
      unlinkat(parent_fd, temporary.c_str(), 0) == 0;
  struct stat after_publish{};
  const bool destination_stable = removed &&
      fstatat(parent_fd, name.c_str(), &after_publish, AT_SYMLINK_NOFOLLOW) == 0 &&
      after_publish.st_dev == held.st_dev && after_publish.st_ino == held.st_ino &&
      fsync(parent_fd) == 0;
  close(fd);
  close(parent_fd);
  if (!removed || !destination_stable) {
    Refuse(env, "create_absent_exclusive", "published absent-file identity changed during cleanup");
    return nullptr;
  }
  napi_value result; napi_get_undefined(env, &result); return result;
#endif
}

napi_value FlushFile(napi_env env, napi_callback_info info) {
  std::string path; if (!StringArg(env, info, 0, &path)) return nullptr;
#ifdef _WIN32
  HANDLE h = OpenNoFollowFile(path, GENERIC_READ | GENERIC_WRITE);
  if (h == INVALID_HANDLE_VALUE || !FlushFileBuffers(h)) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); Throw(env, "ERR_NATIVE_CONTROL_FLUSH", "unable to flush file"); return nullptr; } CloseHandle(h);
#else
  int parent_fd = -1;
  std::string name;
  if (!OpenParentNoFollow(path, &parent_fd, &name)) {
    Throw(env, "ERR_NATIVE_CONTROL_FLUSH", "unable to open verified flush parent");
    return nullptr;
  }
  int fd = OpenObjectNoFollow(parent_fd, name, O_RDONLY);
  const bool flushed = fd >= 0 && fsync(fd) == 0;
  if (fd >= 0) close(fd);
  close(parent_fd);
  if (!flushed) {
    Throw(env, "ERR_NATIVE_CONTROL_FLUSH", "unable to flush file");
    return nullptr;
  }
#endif
  napi_value result; napi_get_undefined(env, &result); return result;
}

napi_value FlushDirectoryOrVolume(napi_env env, napi_callback_info info) {
  std::string path; if (!StringArg(env, info, 0, &path)) return nullptr;
#ifdef _WIN32
  // Primary durability contract: flush the directory's own metadata through a
  // verified no-follow handle. This does not require SeManageVolumePrivilege
  // and is sufficient to make prior create/rename/unlink operations in this
  // directory durable across a crash (see docs/adr/0003-management-mapping-envelope.md).
  HANDLE dir = OpenDurableDirectoryNoFollow(path);
  if (dir == INVALID_HANDLE_VALUE) {
    Refuse(env, "flush_directory_or_volume", "directory cannot be opened through a verified no-follow path");
    return nullptr;
  }
  // FlushDurableDirectoryHandle also attempts a best-effort, optional
  // elevated volume-level flush; its failure never overrides the
  // already-achieved directory durability (fail-closed only applies to the
  // primary directory-handle flush below).
  const bool directory_flushed = FlushDurableDirectoryHandle(dir, path);
  CloseHandle(dir);
  if (!directory_flushed) {
    // Fail closed: never claim durability that was not actually achieved.
    Refuse(env, "flush_directory_or_volume", "directory metadata flush unavailable");
    return nullptr;
  }
#else
  int fd = OpenDirectoryNoFollow(path);
  if (fd < 0 || fsync(fd) != 0) {
    if (fd >= 0) close(fd);
    Refuse(env, "flush_directory_or_volume", "directory flush unavailable");
    return nullptr;
  }
  close(fd);
#endif
  napi_value result; napi_get_undefined(env, &result); return result;
}

napi_value ReplaceExistingAtomic(napi_env env, napi_callback_info info) {
  std::string source, destination, manager, bot, reader, system, profile_text;
  if (!StringArg(env, info, 0, &source, 7) || !StringArg(env, info, 1, &destination, 7) ||
      !StringArg(env, info, 2, &manager, 7) || !StringArg(env, info, 3, &bot, 7) ||
      !StringArg(env, info, 4, &reader, 7) || !StringArg(env, info, 5, &system, 7) ||
      !StringArg(env, info, 6, &profile_text, 7)) return nullptr;
#ifdef _WIN32
  RoleProfile profile;
  if (!ParseRoleProfile(profile_text, &profile)) {
    Refuse(env, "replace_existing_atomic", "role profile is invalid");
    return nullptr;
  }
  if (NtCreateFileApi() == nullptr || NtSetInformationFileApi() == nullptr) {
    Refuse(env, "replace_existing_atomic", "handle-relative Windows open and rename primitives are unavailable");
    return nullptr;
  }
  HANDLE source_parent = INVALID_HANDLE_VALUE;
  HANDLE destination_parent = INVALID_HANDLE_VALUE;
  std::wstring source_name, destination_name;
  const bool parents_open =
      OpenWindowsParentNoFollow(source, &source_parent, &source_name, kWindowsMutationParentAccess) &&
      OpenWindowsParentNoFollow(destination, &destination_parent, &destination_name, kWindowsMutationParentAccess);
  auto close_parents = [&]() {
    if (source_parent != INVALID_HANDLE_VALUE) CloseHandle(source_parent);
    if (destination_parent != INVALID_HANDLE_VALUE) CloseHandle(destination_parent);
  };
  if (!parents_open || source_name == destination_name) {
    close_parents();
    Refuse(env, "replace_existing_atomic", "same verified parent and distinct object names are required");
    return nullptr;
  }
  BY_HANDLE_FILE_INFORMATION source_parent_info{}, destination_parent_info{};
  const bool same_parent =
      GetFileInformationByHandle(source_parent, &source_parent_info) &&
      GetFileInformationByHandle(destination_parent, &destination_parent_info) &&
      source_parent_info.dwVolumeSerialNumber == destination_parent_info.dwVolumeSerialNumber &&
      source_parent_info.nFileIndexHigh == destination_parent_info.nFileIndexHigh &&
      source_parent_info.nFileIndexLow == destination_parent_info.nFileIndexLow;
  HANDLE source_handle = same_parent
      ? OpenWindowsRelative(source_parent, source_name,
          GENERIC_READ | READ_CONTROL | DELETE, kFileOpen, VerifiedObjectType::File)
      : INVALID_HANDLE_VALUE;
  HANDLE destination_handle = same_parent
      ? OpenWindowsRelative(destination_parent, destination_name,
          GENERIC_READ | READ_CONTROL | DELETE, kFileOpen, VerifiedObjectType::File)
      : INVALID_HANDLE_VALUE;
  auto close_objects = [&]() {
    if (source_handle != INVALID_HANDLE_VALUE) CloseHandle(source_handle);
    if (destination_handle != INVALID_HANDLE_VALUE) CloseHandle(destination_handle);
  };
  BY_HANDLE_FILE_INFORMATION source_info{}, destination_info{};
  const bool verified = same_parent &&
      source_handle != INVALID_HANDLE_VALUE && destination_handle != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandle(source_handle, &source_info) &&
      GetFileInformationByHandle(destination_handle, &destination_info) &&
      VerifyExactRoleAcl(source_handle, manager, bot, reader, system, profile) &&
      VerifyExactRoleAcl(destination_handle, manager, bot, reader, system, profile);
  if (!verified) {
    close_objects();
    close_parents();
    Refuse(env, "replace_existing_atomic", "replacement source, destination, or parent is not verified");
    return nullptr;
  }
  if (!VerifyWindowsNamedIdentity(source_parent, source_name, source_info) ||
      !VerifyWindowsNamedIdentity(destination_parent, destination_name, destination_info)) {
    close_objects();
    close_parents();
    Refuse(env, "replace_existing_atomic", "replacement source or destination changed before publication");
    return nullptr;
  }
  // The kernel's replace-rename delete-check on the existing destination can
  // be denied while our own read-only handle to that same file is still
  // open; release it immediately before the rename now that its identity has
  // already been verified above.
  if (destination_handle != INVALID_HANDLE_VALUE) {
    CloseHandle(destination_handle);
    destination_handle = INVALID_HANDLE_VALUE;
  }
  if (!RenameWindowsRelative(source_handle, source_parent, destination_name, true)) {
    close_objects();
    close_parents();
    Throw(env, "ERR_NATIVE_CONTROL_REPLACE", "retained-parent atomic replacement failed");
    return nullptr;
  }
  HANDLE replaced = OpenWindowsRelative(source_parent, destination_name,
      GENERIC_READ | GENERIC_WRITE | READ_CONTROL, kFileOpen, VerifiedObjectType::File);
  BY_HANDLE_FILE_INFORMATION replaced_info{};
  const bool durable = replaced != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandle(replaced, &replaced_info) &&
      replaced_info.dwVolumeSerialNumber == source_info.dwVolumeSerialNumber &&
      replaced_info.nFileIndexHigh == source_info.nFileIndexHigh &&
      replaced_info.nFileIndexLow == source_info.nFileIndexLow &&
      VerifyExactRoleAcl(replaced, manager, bot, reader, system, profile) &&
      FlushFileBuffers(replaced) && FlushDirectoryOrVolumePath(destination);
  if (replaced != INVALID_HANDLE_VALUE) CloseHandle(replaced);
  close_objects();
  close_parents();
  if (!durable) {
    Throw(env, "ERR_NATIVE_CONTROL_REPLACE", "replacement durability, identity, or DACL verification failed");
    return nullptr;
  }
#else
  RoleProfile profile;
  int source_parent = -1, destination_parent = -1;
  std::string source_name, destination_name;
  if (!ParseRoleProfile(profile_text, &profile) || !OpenParentNoFollow(source, &source_parent, &source_name) ||
      !OpenParentNoFollow(destination, &destination_parent, &destination_name)) {
    if (source_parent >= 0) close(source_parent);
    if (destination_parent >= 0) close(destination_parent);
    Refuse(env, "replace_existing_atomic", "same verified parent and role profile are required");
    return nullptr;
  }
  struct stat source_parent_stat{}, destination_parent_stat{};
  const bool same_parent =
      fstat(source_parent, &source_parent_stat) == 0 &&
      fstat(destination_parent, &destination_parent_stat) == 0 &&
      source_parent_stat.st_dev == destination_parent_stat.st_dev &&
      source_parent_stat.st_ino == destination_parent_stat.st_ino;
  int source_fd = same_parent ? OpenObjectNoFollow(source_parent, source_name, O_RDONLY) : -1;
  int destination_fd = same_parent ? OpenObjectNoFollow(destination_parent, destination_name, O_RDONLY) : -1;
  struct stat source_stat{}, destination_stat{}, source_named{}, destination_named{};
  const bool retained =
      source_fd >= 0 && destination_fd >= 0 &&
      fstat(source_fd, &source_stat) == 0 && fstat(destination_fd, &destination_stat) == 0 &&
      fstatat(source_parent, source_name.c_str(), &source_named, AT_SYMLINK_NOFOLLOW) == 0 &&
      fstatat(destination_parent, destination_name.c_str(), &destination_named, AT_SYMLINK_NOFOLLOW) == 0 &&
      source_stat.st_dev == source_named.st_dev && source_stat.st_ino == source_named.st_ino &&
      destination_stat.st_dev == destination_named.st_dev && destination_stat.st_ino == destination_named.st_ino &&
      VerifyExactRoleAcl(source_fd, manager, bot, reader, system, profile) &&
      VerifyExactRoleAcl(destination_fd, manager, bot, reader, system, profile);
  struct stat source_before{}, destination_before{};
  const bool verified_before_rename = retained &&
      fstatat(source_parent, source_name.c_str(), &source_before, AT_SYMLINK_NOFOLLOW) == 0 &&
      fstatat(destination_parent, destination_name.c_str(), &destination_before, AT_SYMLINK_NOFOLLOW) == 0 &&
      source_before.st_dev == source_stat.st_dev && source_before.st_ino == source_stat.st_ino &&
      destination_before.st_dev == destination_stat.st_dev &&
      destination_before.st_ino == destination_stat.st_ino;
  const bool replaced = verified_before_rename &&
      renameat(source_parent, source_name.c_str(), destination_parent, destination_name.c_str()) == 0;
  int replaced_fd = replaced ? OpenObjectNoFollow(destination_parent, destination_name, O_RDONLY) : -1;
  struct stat replaced_stat{}, replaced_named{}, source_after{};
  errno = 0;
  const bool source_absent = replaced &&
      fstatat(source_parent, source_name.c_str(), &source_after, AT_SYMLINK_NOFOLLOW) != 0 &&
      errno == ENOENT;
  const bool durable =
      replaced_fd >= 0 && source_absent &&
      fstat(replaced_fd, &replaced_stat) == 0 &&
      fstatat(destination_parent, destination_name.c_str(), &replaced_named, AT_SYMLINK_NOFOLLOW) == 0 &&
      replaced_stat.st_dev == source_stat.st_dev && replaced_stat.st_ino == source_stat.st_ino &&
      replaced_named.st_dev == source_stat.st_dev && replaced_named.st_ino == source_stat.st_ino &&
      VerifyExactRoleAcl(replaced_fd, manager, bot, reader, system, profile) &&
      fsync(replaced_fd) == 0 && fsync(destination_parent) == 0;
  if (replaced_fd >= 0) close(replaced_fd);
  if (source_fd >= 0) close(source_fd);
  if (destination_fd >= 0) close(destination_fd);
  close(source_parent);
  close(destination_parent);
  if (!durable) {
    Throw(env, "ERR_NATIVE_CONTROL_REPLACE", "descriptor-relative retained-identity replacement failed");
    return nullptr;
  }
#endif
  napi_value result; napi_get_undefined(env, &result); return result;
}

struct NativeLock {
  bool released = false;
#ifdef _WIN32
  HANDLE handle;
#else
  int fd;
#endif
};
void CloseNativeLock(NativeLock* lock) {
  if (lock->released) return;
#ifdef _WIN32
  OVERLAPPED o{}; UnlockFileEx(lock->handle, 0, MAXDWORD, MAXDWORD, &o); CloseHandle(lock->handle);
#else
  flock(lock->fd, LOCK_UN); close(lock->fd);
#endif
  lock->released = true;
}
void ReleaseLock(napi_env, void* data, void*) {
  NativeLock* lock = static_cast<NativeLock*>(data);
  if (!lock) return;
  CloseNativeLock(lock);
  delete lock;
}
napi_value ReleaseNativeLock(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  void* data = nullptr;
  napi_get_cb_info(env, info, &argc, nullptr, nullptr, &data);
  NativeLock* lock = static_cast<NativeLock*>(data);
  if (!lock) {
    Throw(env, "ERR_NATIVE_CONTROL_LOCK", "invalid native lock");
    return nullptr;
  }
  CloseNativeLock(lock);
  napi_value result; napi_get_undefined(env, &result); return result;
}
napi_value AcquireNativeLock(napi_env env, napi_callback_info info) {
  std::string path, manager, bot, reader, system, profile_text;
  if (!StringArg(env, info, 0, &path, 6) || !StringArg(env, info, 1, &manager, 6) ||
      !StringArg(env, info, 2, &bot, 6) || !StringArg(env, info, 3, &reader, 6) ||
      !StringArg(env, info, 4, &system, 6) || !StringArg(env, info, 5, &profile_text, 6)) return nullptr;
  NativeLock* lock = new NativeLock();
#ifdef _WIN32
  WindowsPathParts ignored_path;
  if (!ParseWindowsPath(path, &ignored_path)) {
    delete lock;
    Refuse(env, "acquire_native_lock", "path is not a supported absolute handle-relative Windows lock path");
    return nullptr;
  }
  RoleProfile profile;
  RoleAcl roles;
  if (!ParseRoleProfile(profile_text, &profile) || !BuildExactRoleAcl(manager, bot, reader, system, profile, &roles)) {
    delete lock; Refuse(env, "acquire_native_lock", "protected exact role DACL cannot be constructed"); return nullptr;
  }
  lock->handle = OpenNoFollowFile(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL);
  if (lock->handle == INVALID_HANDLE_VALUE && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) {
    lock->handle = CreateProtectedFileNoFollow(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, roles.acl);
    if (lock->handle == INVALID_HANDLE_VALUE &&
        (GetLastError() == ERROR_FILE_EXISTS || GetLastError() == ERROR_ALREADY_EXISTS)) {
      lock->handle = OpenNoFollowFile(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL);
    }
  }
  OVERLAPPED o{};
  if (lock->handle == INVALID_HANDLE_VALUE || !VerifyExactRoleAcl(lock->handle, manager, bot, reader, system, profile) ||
      !LockFileEx(lock->handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, MAXDWORD, MAXDWORD, &o)) {
    if (lock->handle != INVALID_HANDLE_VALUE) CloseHandle(lock->handle);
    delete lock; Refuse(env, "acquire_native_lock", "exclusive native lock unavailable"); return nullptr;
  }
#else
  RoleProfile profile;
  int parent_fd;
  std::string name;
  if (!ParseRoleProfile(profile_text, &profile) || !OpenParentNoFollow(path, &parent_fd, &name)) {
    delete lock;
    Refuse(env, "acquire_native_lock", "role profile or lock path is invalid");
    return nullptr;
  }
  bool created = false;
  lock->fd = OpenObjectNoFollow(parent_fd, name, O_RDWR);
  if (lock->fd < 0 && errno == ENOENT) {
    lock->fd = OpenObjectNoFollow(parent_fd, name, O_RDWR | O_CREAT | O_EXCL);
    created = lock->fd >= 0;
  }
  const bool acl_ok = lock->fd >= 0 &&
      (created
          ? ApplyAndVerifyExactRoleAcl(lock->fd, manager, bot, reader, system, profile)
          : VerifyExactRoleAcl(lock->fd, manager, bot, reader, system, profile));
  bool ok = acl_ok && flock(lock->fd, LOCK_EX | LOCK_NB) == 0 &&
      (!created || fsync(parent_fd) == 0);
  close(parent_fd);
  if (!ok) {
    if (lock->fd >= 0) close(lock->fd);
    delete lock;
    Refuse(env, "acquire_native_lock", "exclusive exact-ACL native lock unavailable");
    return nullptr;
  }
#endif
  napi_value result, handle;
  napi_create_object(env, &result);
  napi_create_external(env, lock, ReleaseLock, nullptr, &handle);
  napi_set_named_property(env, result, "_native", handle);
  napi_value release;
  napi_create_function(env, "release", NAPI_AUTO_LENGTH, ReleaseNativeLock, lock, &release);
  napi_set_named_property(env, result, "release", release);
  return result;
}

napi_value EnsureControlDirectory(napi_env env, napi_callback_info info) {
  std::string path, manager, bot, reader, system, profile_text;
  if (!StringArg(env, info, 0, &path, 6) || !StringArg(env, info, 1, &manager, 6) ||
      !StringArg(env, info, 2, &bot, 6) || !StringArg(env, info, 3, &reader, 6) ||
      !StringArg(env, info, 4, &system, 6) || !StringArg(env, info, 5, &profile_text, 6)) return nullptr;
#ifdef _WIN32
  WindowsPathParts ignored_path;
  if (!ParseWindowsPath(path, &ignored_path)) {
    Refuse(env, "ensure_control_directory", "path is not a supported absolute handle-relative Windows directory");
    return nullptr;
  }
  RoleProfile profile;
  RoleAcl roles;
  if (!ParseRoleProfile(profile_text, &profile) || !BuildExactRoleAcl(manager, bot, reader, system, profile, &roles)) {
    Refuse(env, "ensure_control_directory", "protected exact role DACL cannot be constructed"); return nullptr;
  }
  HANDLE h = OpenNoFollowDirectory(path, READ_CONTROL);
  if (h == INVALID_HANDLE_VALUE && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) {
    if (!CreateProtectedDirectoryNoFollow(path, roles.acl) && GetLastError() != ERROR_ALREADY_EXISTS) {
      Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to securely create control directory"); return nullptr;
    }
    h = OpenNoFollowDirectory(path, READ_CONTROL);
  }
  BY_HANDLE_FILE_INFORMATION metadata{};
  bool valid = h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(h, &metadata) &&
      (metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
      VerifyExactRoleAcl(h, manager, bot, reader, system, profile);
  if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
  if (!valid) { Refuse(env, "ensure_control_directory", "control directory is not protected by the exact role DACL"); return nullptr; }
  napi_value result; napi_get_undefined(env, &result); return result;
#else
  RoleProfile profile;
  int parent_fd;
  std::string name;
  if (!ParseRoleProfile(profile_text, &profile) || !OpenParentNoFollow(path, &parent_fd, &name)) {
    Refuse(env, "ensure_control_directory", "role profile or control path is invalid");
    return nullptr;
  }
  bool created = false;
  if (mkdirat(parent_fd, name.c_str(), 0700) == 0) {
    created = true;
  } else if (errno != EEXIST) {
    close(parent_fd);
    Throw(env, "ERR_NATIVE_CONTROL_CREATE", "unable to create descriptor-relative control directory");
    return nullptr;
  }
  int fd = OpenObjectNoFollow(parent_fd, name, O_RDONLY | O_DIRECTORY);
  const bool acl_ok = fd >= 0 &&
      (created
          ? ApplyAndVerifyExactRoleAcl(fd, manager, bot, reader, system, profile)
          : VerifyExactRoleAcl(fd, manager, bot, reader, system, profile));
  const bool ok = acl_ok && (!created || fsync(parent_fd) == 0);
  if (fd >= 0) close(fd);
  close(parent_fd);
  if (!ok) {
    Refuse(env, "ensure_control_directory", "control directory is not an exact-role no-follow directory");
    return nullptr;
  }
  napi_value result; napi_get_undefined(env, &result); return result;
#endif
}

napi_value PrincipalAccessCheck(napi_env env, napi_callback_info info) {
  std::string path, kind, principal, mode;
  if (!StringArg(env, info, 0, &path, 4) || !StringArg(env, info, 1, &kind, 4) ||
      !StringArg(env, info, 2, &principal, 4) || !StringArg(env, info, 3, &mode, 4)) return nullptr;
  if (mode != "read" && mode != "write") {
    Refuse(env, "principal_access_check", "access mode must be read or write");
    return nullptr;
  }
#ifdef _WIN32
  if (kind != "sid") { Refuse(env, "principal_access_check", "Windows principal must be a SID"); return nullptr; }
  PSID sid = nullptr;
  if (!ConvertStringSidToSidW(Wide(principal).c_str(), &sid)) { Refuse(env, "principal_access_check", "principal SID is invalid"); return nullptr; }
  HANDLE handle = OpenNoFollowObject(path, READ_CONTROL | FILE_READ_ATTRIBUTES);
  if (handle == INVALID_HANDLE_VALUE) { LocalFree(sid); Throw(env, "ERR_NATIVE_CONTROL_PROBE", "unable to open target without following reparse points"); return nullptr; }
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  DWORD status = GetSecurityInfo(handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &dacl, nullptr, &descriptor);
  if (status != ERROR_SUCCESS) {
    CloseHandle(handle);
    LocalFree(sid);
    Throw(env, "ERR_NATIVE_CONTROL_PROBE", "unable to read target DACL");
    return nullptr;
  }
  const bool no_group_acl = VerifyNoGroupMutationAcl(handle);
  ACCESS_MASK desired_access = FILE_GENERIC_READ;
  BY_HANDLE_FILE_INFORMATION metadata{};
  if (mode == "write") {
    if (!GetFileInformationByHandle(handle, &metadata)) {
      CloseHandle(handle);
      LocalFree(descriptor);
      LocalFree(sid);
      napi_value result;
      napi_get_boolean(env, false, &result);
      return result;
    }
    desired_access = (metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
      ? kWindowsDirectoryMutationAccess
      : FILE_GENERIC_WRITE;
  }
  CloseHandle(handle);
  bool allowed = false;
  AUTHZ_RESOURCE_MANAGER_HANDLE manager = nullptr;
  AUTHZ_CLIENT_CONTEXT_HANDLE context = nullptr;
  if (dacl != nullptr && AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, nullptr, nullptr, nullptr,
      L"native-control", &manager)) {
    LUID identifier{};
    // AUTHZ_SKIP_TOKEN_GROUPS avoids LSA-based group-membership expansion for
    // the principal SID, which would otherwise require the SID to resolve to
    // a real, queryable local/domain security principal. principal_access_check
    // must be able to evaluate hypothetical/remote role principals (e.g. other
    // fleet members) that are never expected to exist as local accounts; the
    // access check is still evaluated strictly against the target's actual
    // DACL using only the exact SID supplied.
    if (AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS, sid, manager, nullptr, identifier, nullptr, &context)) {
      ACCESS_MASK granted = 0;
      DWORD access_error = ERROR_ACCESS_DENIED;
      AUTHZ_ACCESS_REQUEST request{};
      request.DesiredAccess = desired_access;
      AUTHZ_ACCESS_REPLY reply{};
      reply.ResultListLength = 1;
      reply.GrantedAccessMask = &granted;
      reply.Error = &access_error;
      allowed = no_group_acl &&
          AuthzAccessCheck(0, context, &request, nullptr, descriptor, nullptr, 0, &reply, nullptr) &&
          access_error == ERROR_SUCCESS && (granted & request.DesiredAccess) == request.DesiredAccess;
    }
  }
  if (context) AuthzFreeContext(context);
  if (manager) AuthzFreeResourceManager(manager);
  LocalFree(descriptor); LocalFree(sid);
  napi_value result;
  napi_get_boolean(env, allowed, &result);
  return result;
#else
  uid_t parsed = 0;
  if (kind != "uid" || !ParseUid(principal, &parsed)) {
    Refuse(env, "principal_access_check", "POSIX principal must be a canonical numeric UID");
    return nullptr;
  }
  int parent_fd = -1;
  std::string name;
  if (!OpenParentNoFollow(path, &parent_fd, &name)) {
    Throw(env, "ERR_NATIVE_CONTROL_PROBE", "unable to open verified target parent");
    return nullptr;
  }
  int fd = OpenObjectNoFollow(parent_fd, name, O_RDONLY);
  const bool allowed = fd >= 0 && PrincipalCanAccess(fd, parsed, mode == "read" ? S_IRUSR : S_IWUSR);
  if (fd >= 0) close(fd);
  close(parent_fd);
  napi_value result;
  napi_get_boolean(env, allowed, &result);
  return result;
#endif
}

struct VerifiedHandle {
#ifdef _WIN32
  HANDLE handle = INVALID_HANDLE_VALUE;
  std::string path;
#else
  int fd = -1;
  int parent_fd = -1;
  std::string name;
#endif
};
void ReleaseVerifiedHandle(napi_env, void* data, void*) {
  auto* value = static_cast<VerifiedHandle*>(data);
  if (!value) return;
#ifdef _WIN32
  if (value->handle != INVALID_HANDLE_VALUE) CloseHandle(value->handle);
#else
  if (value->fd >= 0) close(value->fd);
  if (value->parent_fd >= 0) close(value->parent_fd);
#endif
  delete value;
}
bool HandleArg(napi_env env, napi_callback_info info, size_t index, VerifiedHandle** result) {
  size_t argc = 16; napi_value args[16]; napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
  if (argc <= index || napi_get_value_external(env, args[index], reinterpret_cast<void**>(result)) != napi_ok || !*result) { Throw(env, "ERR_INVALID_ARG_TYPE", "argument must be a verified native handle"); return false; }
  return true;
}
napi_value OpenVerifiedParentHandle(napi_env env, napi_callback_info info) {
  std::string path; if (!StringArg(env, info, 0, &path)) return nullptr;
  std::filesystem::path parent = std::filesystem::u8path(path).parent_path(); if (parent.empty()) parent = ".";
  auto* value = new VerifiedHandle();
#ifdef _WIN32
  value->path = parent.u8string(); value->handle = OpenNoFollowDirectory(value->path, READ_CONTROL | FILE_READ_ATTRIBUTES);
  if (value->handle == INVALID_HANDLE_VALUE) { delete value; Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to retain verified parent handle"); return nullptr; }
#else
  value->fd = OpenDirectoryNoFollow(parent.u8string());
  if (value->fd < 0) { delete value; Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to retain verified parent handle"); return nullptr; }
#endif
  napi_value result; napi_create_external(env, value, ReleaseVerifiedHandle, nullptr, &result); return result;
}
napi_value OpenVerifiedObjectHandle(napi_env env, napi_callback_info info) {
  VerifiedHandle* parent; std::string name;
  if (!HandleArg(env, info, 0, &parent) || !StringArg(env, info, 1, &name, 2)) return nullptr;
  if (!SafeName(name)) { Refuse(env, "open_verified_object_handle", "object name must be one path component"); return nullptr; }
  auto* value = new VerifiedHandle();
#ifdef _WIN32
  value->handle = OpenWindowsRelative(parent->handle, Wide(name),
      GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE, kFileOpen,
      VerifiedObjectType::File);
  if (value->handle == INVALID_HANDLE_VALUE) { delete value; napi_value absent; napi_get_null(env, &absent); return absent; }
#else
  value->fd = openat(parent->fd, name.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  if (value->fd < 0) { delete value; if (errno == ENOENT) { napi_value absent; napi_get_null(env, &absent); return absent; } Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to open descriptor-relative object"); return nullptr; }
  value->parent_fd = dup(parent->fd); value->name = name;
  if (value->parent_fd < 0) { ReleaseVerifiedHandle(env, value, nullptr); Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to retain object parent"); return nullptr; }
#endif
  napi_value result; napi_create_external(env, value, ReleaseVerifiedHandle, nullptr, &result); return result;
}
napi_value ReadHandleBytes(napi_env env, napi_callback_info info) {
  VerifiedHandle* value; if (!HandleArg(env, info, 0, &value)) return nullptr;
#ifdef _WIN32
  LARGE_INTEGER size; if (!GetFileSizeEx(value->handle, &size) || size.QuadPart < 0 || size.QuadPart > 16 * 1024 * 1024 || SetFilePointer(value->handle, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) { Refuse(env, "read_handle_bytes", "verified object size or offset is invalid"); return nullptr; }
  size_t length = static_cast<size_t>(size.QuadPart);
#else
  struct stat st; if (fstat(value->fd, &st) != 0 || st.st_size < 0 || st.st_size > 16 * 1024 * 1024 || lseek(value->fd, 0, SEEK_SET) < 0) { Refuse(env, "read_handle_bytes", "verified object size or offset is invalid"); return nullptr; }
  size_t length = static_cast<size_t>(st.st_size);
#endif
  std::vector<uint8_t> bytes(length); size_t offset = 0;
  while (offset < bytes.size()) {
#ifdef _WIN32
    DWORD count = 0; if (!ReadFile(value->handle, bytes.data() + offset, static_cast<DWORD>(bytes.size() - offset), &count, nullptr) || count == 0) { Throw(env, "ERR_NATIVE_CONTROL_READ", "unable to read verified handle"); return nullptr; } offset += count;
#else
    ssize_t count = read(value->fd, bytes.data() + offset, bytes.size() - offset); if (count <= 0) { Throw(env, "ERR_NATIVE_CONTROL_READ", "unable to read verified handle"); return nullptr; } offset += static_cast<size_t>(count);
#endif
  }
  napi_value result; void* output; napi_create_buffer_copy(env, bytes.size(), bytes.data(), &output, &result); return result;
}
napi_value WriteHandleBytesMethod(napi_env env, napi_callback_info info) {
  VerifiedHandle* value; std::vector<uint8_t> bytes;
  if (!HandleArg(env, info, 0, &value) || !BufferArg(env, info, 1, &bytes)) return nullptr;
#ifdef _WIN32
  if (SetFilePointer(value->handle, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER || !SetEndOfFile(value->handle) || !WriteHandleBytes(value->handle, bytes)) { Throw(env, "ERR_NATIVE_CONTROL_WRITE", "unable to write through verified handle"); return nullptr; }
#else
  if (ftruncate(value->fd, 0) != 0 || lseek(value->fd, 0, SEEK_SET) < 0 || !WriteHandleBytes(value->fd, bytes)) { Throw(env, "ERR_NATIVE_CONTROL_WRITE", "unable to write through verified handle"); return nullptr; }
#endif
  napi_value result; napi_get_undefined(env, &result); return result;
}
napi_value RemoveVerifiedHandle(napi_env env, napi_callback_info info) {
  VerifiedHandle* value; std::vector<uint8_t> expected;
  if (!HandleArg(env, info, 0, &value) || !BufferArg(env, info, 1, &expected)) return nullptr;
  napi_value bytes = ReadHandleBytes(env, info); if (!bytes) return nullptr;
  void* raw; size_t size; napi_get_buffer_info(env, bytes, &raw, &size);
  if (size != expected.size() || std::memcmp(raw, expected.data(), size) != 0) { Refuse(env, "remove_verified_handle", "verified handle bytes do not match"); return nullptr; }
#ifdef _WIN32
  FILE_DISPOSITION_INFO disposition{}; disposition.DeleteFile = TRUE;
  if (!SetFileInformationByHandle(value->handle, FileDispositionInfo, &disposition, sizeof(disposition))) { Throw(env, "ERR_NATIVE_CONTROL_REMOVE", "unable to remove verified handle"); return nullptr; }
#else
  struct stat held, named;
  if (fstat(value->fd, &held) != 0 || fstatat(value->parent_fd, value->name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 || held.st_dev != named.st_dev || held.st_ino != named.st_ino || unlinkat(value->parent_fd, value->name.c_str(), 0) != 0) { Refuse(env, "remove_verified_handle", "descriptor-relative exact deletion failed"); return nullptr; }
#endif
  napi_value result; napi_get_undefined(env, &result); return result;
}
napi_value ReadHandleIdentity(napi_env env, napi_callback_info info) {
  VerifiedHandle* value; if (!HandleArg(env, info, 0, &value)) return nullptr; napi_value result; napi_create_object(env, &result);
#ifdef _WIN32
  SetIdentity(env, result, value->handle);
#else
  SetIdentity(env, result, value->fd);
#endif
  return result;
}
napi_value NativeControlContract(napi_env env, napi_callback_info) {
  const char* capabilities[] = {
    "open_verified_parent", "open_no_follow", "read_identity", "read_acl", "path_exists_no_follow",
    "set_exact_role_acl", "verify_exact_role_acl", "read_verified_bytes", "create_exclusive_temp", "flush_file", "flush_directory_or_volume",
    "replace_existing_atomic", "create_absent_exclusive", "ensure_control_directory",
    "acquire_native_lock", "current_os_principal", "principal_access_check", "remove_verified_file",
    "open_verified_parent_handle", "open_verified_object_handle", "read_handle_identity",
    "read_handle_bytes", "write_handle_bytes", "remove_verified_handle",
  };
  napi_value result, value, array, signatures;
  napi_create_object(env, &result);
  napi_create_uint32(env, 1, &value); napi_set_named_property(env, result, "contractVersion", value);
  napi_create_uint32(env, 8, &value); napi_set_named_property(env, result, "napi", value);
  napi_create_array_with_length(env, sizeof(capabilities) / sizeof(capabilities[0]), &array);
  for (uint32_t i = 0; i < sizeof(capabilities) / sizeof(capabilities[0]); ++i) {
    napi_create_string_utf8(env, capabilities[i], NAPI_AUTO_LENGTH, &value);
    napi_set_element(env, array, i, value);
  }
  napi_set_named_property(env, result, "capabilities", array);
  napi_create_object(env, &signatures);
  auto signature = [&](const char* name, std::initializer_list<const char*> fields) {
    napi_value values, field;
    napi_create_array_with_length(env, fields.size(), &values);
    uint32_t index = 0;
    for (const char* text : fields) {
      napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &field);
      napi_set_element(env, values, index++, field);
    }
    napi_set_named_property(env, signatures, name, values);
  };
  signature("open_verified_parent", {"path"}); signature("open_no_follow", {"path"});
  signature("read_identity", {"path"}); signature("read_acl", {"path"});
  signature("path_exists_no_follow", {"path"});
  signature("set_exact_role_acl", {"path", "managementSid", "botSid", "recoverySid", "systemSid", "profile"});
  signature("verify_exact_role_acl", {"path", "managementSid", "botSid", "recoverySid", "systemSid", "profile"});
  signature("read_verified_bytes", {"path"});
  signature("create_exclusive_temp", {"parent", "prefix", "bytes", "managementSid", "botSid", "recoverySid", "systemSid", "profile"});
  signature("flush_file", {"path"}); signature("flush_directory_or_volume", {"path"});
  signature("replace_existing_atomic", {"source", "destination", "managementSid", "botSid", "recoverySid", "systemSid", "profile"});
  signature("create_absent_exclusive", {"path", "bytes", "managementSid", "botSid", "recoverySid", "systemSid", "profile"});
  signature("ensure_control_directory", {"path", "managementSid", "botSid", "recoverySid", "systemSid", "profile"});
  signature("acquire_native_lock", {"path", "managementSid", "botSid", "recoverySid", "systemSid", "profile"});
  signature("current_os_principal", {});
  signature("principal_access_check", {"path", "kind", "principal", "mode"});
  signature("remove_verified_file", {"path", "expectedBytes"});
  signature("open_verified_parent_handle", {"path"});
  signature("open_verified_object_handle", {"parentHandle", "name"});
  signature("read_handle_identity", {"handle"}); signature("read_handle_bytes", {"handle"});
  signature("write_handle_bytes", {"handle", "bytes"}); signature("remove_verified_handle", {"handle", "expectedBytes"});
  napi_set_named_property(env, result, "capabilitySignatures", signatures);
  return result;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor methods[] = {
    {"open_verified_parent", nullptr, OpenVerifiedParent, nullptr, nullptr, nullptr, napi_default, nullptr}, {"open_no_follow", nullptr, OpenNoFollowMethod, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_identity", nullptr, ReadIdentity, nullptr, nullptr, nullptr, napi_default, nullptr}, {"read_acl", nullptr, ReadAcl, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"path_exists_no_follow", nullptr, PathExistsNoFollow, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"set_role_acl", nullptr, SetRoleAcl, nullptr, nullptr, nullptr, napi_default, nullptr}, {"set_exact_role_acl", nullptr, SetExactRoleAcl, nullptr, nullptr, nullptr, napi_default, nullptr}, {"verify_exact_role_acl", nullptr, VerifyExactRoleAclMethod, nullptr, nullptr, nullptr, napi_default, nullptr}, {"read_verified_bytes", nullptr, ReadVerifiedBytes, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"create_exclusive_temp", nullptr, CreateExclusiveTemp, nullptr, nullptr, nullptr, napi_default, nullptr}, {"flush_file", nullptr, FlushFile, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"flush_directory_or_volume", nullptr, FlushDirectoryOrVolume, nullptr, nullptr, nullptr, napi_default, nullptr}, {"replace_existing_atomic", nullptr, ReplaceExistingAtomic, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"create_absent_exclusive", nullptr, CreateAbsentExclusive, nullptr, nullptr, nullptr, napi_default, nullptr}, {"ensure_control_directory", nullptr, EnsureControlDirectory, nullptr, nullptr, nullptr, napi_default, nullptr}, {"acquire_native_lock", nullptr, AcquireNativeLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"current_os_principal", nullptr, CurrentOsPrincipal, nullptr, nullptr, nullptr, napi_default, nullptr}, {"principal_access_check", nullptr, PrincipalAccessCheck, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"remove_verified_file", nullptr, RemoveVerifiedFile, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_verified_parent_handle", nullptr, OpenVerifiedParentHandle, nullptr, nullptr, nullptr, napi_default, nullptr}, {"open_verified_object_handle", nullptr, OpenVerifiedObjectHandle, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_handle_identity", nullptr, ReadHandleIdentity, nullptr, nullptr, nullptr, napi_default, nullptr}, {"read_handle_bytes", nullptr, ReadHandleBytes, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"write_handle_bytes", nullptr, WriteHandleBytesMethod, nullptr, nullptr, nullptr, napi_default, nullptr}, {"remove_verified_handle", nullptr, RemoveVerifiedHandle, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"native_control_contract", nullptr, NativeControlContract, nullptr, nullptr, nullptr, napi_default, nullptr}
  };
  napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods);
  return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
}  // namespace
