#include <node_api.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <cwctype>
#include <limits>
#include <initializer_list>
#include <thread>
#include <memory>
#include <array>
#include <cmath>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <authz.h>
#include <shlobj.h>
#ifdef _MSC_VER
#pragma comment(lib, "authz.lib")
#pragma comment(lib, "bcrypt.lib")
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
#ifdef __linux__
#include <sys/syscall.h>
#include <sys/random.h>
#endif
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
bool WindowsRandomName(std::wstring* value) {
  std::array<unsigned char, 16> bytes{};
  if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
          BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
  static constexpr wchar_t hex[] = L"0123456789abcdef";
  value->clear(); value->reserve(32);
  for (unsigned char byte : bytes) {
    value->push_back(hex[byte >> 4]);
    value->push_back(hex[byte & 15]);
  }
  return true;
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
  else if (static_cast<ULONG>(status) == 0xC0000002u ||
           static_cast<ULONG>(status) == 0xC0000010u ||
           static_cast<ULONG>(status) == 0xC00000BBu) SetLastError(ERROR_NOT_SUPPORTED);
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
// Narrower parent-directory access for primitives that only ever create,
// replace, or delete their own child object at create time (the child's own
// DACL is supplied to NtCreateFile directly, see CreateProtectedFileNoFollow
// below) and never touch the parent's own DACL/owner. Kept distinct from
// kWindowsMutationParentAccess (which still WRITE_DAC/WRITE_OWNER-provisions
// directories via CreateProtectedDirectoryNoFollow) so that a non-owner role
// granted only this narrower mask on a directory object can use the
// create/rename primitives without ever being able to re-DACL or take
// ownership of that directory.
constexpr DWORD kWindowsChildMutationParentAccess =
    kWindowsTraversalAccess | READ_CONTROL |
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
    // / STATUS_NOT_IMPLEMENTED / STATUS_INVALID_DEVICE_REQUEST mean the
    // running kernel or filesystem predates or otherwise cannot service
    // FileRenameInformationEx; fall back to the legacy info class below. Any
    // other failure (e.g. a genuine ACL denial) is authoritative and must
    // not be masked by a silent retry.
    if (ex_result != static_cast<LONG>(0xC00000BBu) &&
        ex_result != static_cast<LONG>(0xC0000003u) &&
        ex_result != static_cast<LONG>(0xC000000Du) &&
        ex_result != static_cast<LONG>(0xC0000002u) &&
        ex_result != static_cast<LONG>(0xC0000010u)) {
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
enum class RoleProfile { Authority, ManagementAuth, BotState, ProspectiveCleanup, LegacyRetained };

bool ParseRoleProfile(const std::string& value, RoleProfile* result) {
  if (value == "authority") { *result = RoleProfile::Authority; return true; }
  if (value == "management-auth") { *result = RoleProfile::ManagementAuth; return true; }
  if (value == "bot-state") { *result = RoleProfile::BotState; return true; }
  if (value == "prospective-cleanup") { *result = RoleProfile::ProspectiveCleanup; return true; }
  // "legacy-retained" is deliberately not carried by this function's exact-role-ACL
  // gate: it identifies objects (pre-existing legacy targets) that the contract
  // never requires to hold an exact role ACL, because they retain their original
  // foreign ACL. It must never be accepted for authority/bot-state/management-auth
  // or any object this process creates or mutates; PrincipalAccessCheck rejects the
  // "mutate-children" mode for it fail-closed before either platform branch runs,
  // because that mode would authorize mutating an immutable retained object. "write"
  // is evaluated for real (through the object's actual DACL) so callers can prove a
  // retained target is NOT bot-writable; a true "write" result for this profile must
  // never be used as authorization to mutate the retained object.
  if (value == "legacy-retained") { *result = RoleProfile::LegacyRetained; return true; }
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

DWORD RoleRights(RoleProfile profile, size_t role, bool directory) {
  if (role == 3) return FILE_ALL_ACCESS;
  if (profile == RoleProfile::ManagementAuth) return role == 0 || role == 3 ? FILE_ALL_ACCESS : 0;
  if (profile == RoleProfile::Authority) {
    if (role == 0) return FILE_ALL_ACCESS;
    return directory ? (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) : FILE_GENERIC_READ;
  }
  if (profile == RoleProfile::BotState) {
    if (directory) {
      if (role == 0) return FILE_ALL_ACCESS;
      // Role 1 (bot) is the child-mutation writer for this directory: it
      // needs FILE_ADD_FILE/FILE_ADD_SUBDIRECTORY (aliased into
      // FILE_GENERIC_WRITE's data bits on a directory object) plus
      // FILE_DELETE_CHILD so it can open the directory as a mutation parent
      // for the create/replace/rename primitives (see
      // kWindowsChildMutationParentAccess) without ever holding
      // WRITE_DAC/WRITE_OWNER on the M-owned directory.
      if (role == 1) {
        return FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | FILE_DELETE_CHILD;
      }
      return FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    }
    // Role 1 (bot) owns bot-state record files and needs DELETE on its own
    // handle: replace_existing_atomic/remove_verified_file/
    // RenameWindowsRelative all require DELETE on the source/target handle,
    // which Windows implicit owner rights never grant on their own.
    return role == 1 ? (FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE) : FILE_GENERIC_READ;
  }
  if (role == 0) return FILE_ALL_ACCESS;
  return directory ? (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) : FILE_GENERIC_READ;
}

// The profile's required owner: BotState's non-directory (record) objects are
// owned by the bot role (index 1) so the bot can mutate its own state files
// without holding WRITE_OWNER on objects it did not create; every other
// protected object (directories, and all non-BotState-record files) is owned
// by the management role (index 0). This must match VerifyExactRoleAcl's
// owner binding exactly, since creation is only useful if it is provably
// verifiable afterward.
size_t RequiredOwnerRole(RoleProfile profile, bool directory) {
  return (profile == RoleProfile::BotState && !directory) ? 1 : 0;
}
bool BuildExactRoleAcl(const std::string& manager, const std::string& bot,
                       const std::string& reader, const std::string& system,
                       RoleProfile profile, bool directory, RoleAcl* result) {
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
    entries[i].grfAccessPermissions = RoleRights(profile, i, directory);
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
  BY_HANDLE_FILE_INFORMATION metadata{};
  if (!GetFileInformationByHandle(handle, &metadata)) return false;
  const bool directory = (metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  RoleAcl roles;
  if (!BuildExactRoleAcl(manager, bot, reader, system, profile, directory, &roles)) return false;
  PACL applied = nullptr;
  PSID owner = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
                      &applied, nullptr, &descriptor) != ERROR_SUCCESS) return false;
  const size_t required_owner_role = RequiredOwnerRole(profile, directory);
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
      if (!seen[role] && ace->Mask == RoleRights(profile, role, directory) &&
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
  BY_HANDLE_FILE_INFORMATION metadata{};
  if (!GetFileInformationByHandle(handle, &metadata)) return false;
  const bool directory = (metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  RoleAcl roles;
  if (!BuildExactRoleAcl(manager, bot, reader, system, profile, directory, &roles)) return false;
  const PSID owner = roles.sids[RequiredOwnerRole(profile, directory)];
  if (SetSecurityInfo(handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
      owner, nullptr, roles.acl, nullptr) != ERROR_SUCCESS) return false;
  return VerifyExactRoleAcl(handle, manager, bot, reader, system, profile);
}
bool WindowsRoleSidIsGroup(const std::string& sid_text) {
  PSID sid = nullptr;
  if (!ConvertStringSidToSidW(Wide(sid_text).c_str(), &sid)) return false;
  DWORD name_length = 0, domain_length = 0;
  SID_NAME_USE use = SidTypeUnknown;
  LookupAccountSidW(nullptr, sid, nullptr, &name_length, nullptr, &domain_length, &use);
  const DWORD lookup_error = GetLastError();
  bool is_group = false;
  if (lookup_error == ERROR_INSUFFICIENT_BUFFER && name_length > 0 && domain_length > 0) {
    std::vector<wchar_t> account(name_length);
    std::vector<wchar_t> domain(domain_length);
    if (LookupAccountSidW(nullptr, sid, account.data(), &name_length, domain.data(), &domain_length, &use)) {
      is_group = use == SidTypeGroup || use == SidTypeAlias || use == SidTypeWellKnownGroup;
    }
  }
  // Any other outcome (ERROR_NONE_MAPPED, ERROR_TRUSTED_RELATIONSHIP_FAILURE, or any other lookup
  // failure) leaves the SID unresolved: it is never proven to be a group, so it stays permitted here.
  // Remote/domain role principals are legitimately unresolvable on this host and must not be rejected.
  LocalFree(sid);
  return is_group;
}

HANDLE CreateProtectedFileNoFollow(const std::string& path, DWORD access, PACL acl, PSID owner) {
  SECURITY_DESCRIPTOR descriptor{};
  if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
      !SetSecurityDescriptorOwner(&descriptor, owner, FALSE) ||
      !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    SetLastError(ERROR_INVALID_SECURITY_DESCR);
    return INVALID_HANDLE_VALUE;
  }
  HANDLE parent = INVALID_HANDLE_VALUE;
  std::wstring name;
  if (!OpenWindowsParentNoFollow(path, &parent, &name, kWindowsChildMutationParentAccess)) {
    return INVALID_HANDLE_VALUE;
  }
  HANDLE handle = OpenWindowsRelative(parent, name, access, kFileCreate,
      VerifiedObjectType::File, &descriptor);
  CloseHandle(parent);
  return handle;
}

bool CreateProtectedDirectoryNoFollow(const std::string& path, PACL acl, PSID owner) {
  SECURITY_DESCRIPTOR descriptor{};
  if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
      !SetSecurityDescriptorOwner(&descriptor, owner, FALSE) ||
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
enum class RoleProfile { Authority, ManagementAuth, BotState, ProspectiveCleanup, LegacyRetained };
bool ParseRoleProfile(const std::string& value, RoleProfile* result) {
  if (value == "authority") { *result = RoleProfile::Authority; return true; }
  if (value == "management-auth") { *result = RoleProfile::ManagementAuth; return true; }
  if (value == "bot-state") { *result = RoleProfile::BotState; return true; }
  if (value == "prospective-cleanup") { *result = RoleProfile::ProspectiveCleanup; return true; }
  if (value == "legacy-retained") { *result = RoleProfile::LegacyRetained; return true; }
  return false;
}
bool ParseUid(const std::string& value, uid_t* result) {
  if (value.rfind("uid:", 0) != 0) return false;
  const std::string decimal = value.substr(4);
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
  else if (profile == RoleProfile::BotState) mode = directory ? ((role == 0 || role == 1) ? S_IRUSR | S_IWUSR : S_IRUSR) : (role == 1 ? S_IRUSR | S_IWUSR : S_IRUSR);
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
  const ssize_t required_owner_role = (profile == RoleProfile::BotState && !directory) ? 1 : 0;
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
  const ssize_t required_owner_role = (profile == RoleProfile::BotState && !directory) ? 1 : 0;
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

bool PrincipalCanAccess(int fd, uid_t principal, mode_t requested, bool exact_role_acl) {
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
  if (!exact_role_acl && (requested & S_IWUSR) != 0 && foreign_named_user_mutation) return false;
  const bool writable_group_class =
      (group_object_bits & S_IWUSR) != 0 ||
      (named_group_bits & S_IWUSR) != 0 ||
      (other_bits & S_IWUSR) != 0;
  if ((requested & S_IWUSR) != 0 && writable_group_class) return false;
  if (principal == st.st_uid) return (owner_bits & requested) == requested;
  if (!exact_role_acl && selected_named_user && (requested & S_IWUSR) != 0 &&
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
  HANDLE handle = OpenNoFollowObject(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER);
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
// on NTFS (see docs/adr/0003-management-mapping-envelope.md). This is the
// addon's only durability primitive: no volume-level flush is attempted, so
// the process never needs SeManageVolumePrivilege. NTFS is the only
// filesystem this codepath's durability semantics are proven for; any other
// filesystem reported for the handle's volume fails closed instead of
// claiming a guarantee that cannot be backed up.
bool FlushDurableDirectoryHandle(HANDLE dir) {
  wchar_t filesystem_name[MAX_PATH + 1]{};
  if (!GetVolumeInformationByHandleW(dir, nullptr, 0, nullptr, nullptr, nullptr,
                                      filesystem_name, MAX_PATH)) {
    return false;
  }
  if (wcscmp(filesystem_name, L"NTFS") != 0) {
    return false;
  }
  return FlushFileBuffers(dir) != 0;
}
bool FlushWindowsDirectoryNoFollow(const std::string& directory_path) {
  HANDLE dir = OpenDurableDirectoryNoFollow(directory_path);
  if (dir == INVALID_HANDLE_VALUE) return false;
  const bool ok = FlushDurableDirectoryHandle(dir);
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
napi_value VerifyRoleSidNotGroupMethod(napi_env env, napi_callback_info info) {
  std::string sid_text;
  if (!StringArg(env, info, 0, &sid_text)) return nullptr;
  bool permitted = true;
#ifdef _WIN32
  permitted = !WindowsRoleSidIsGroup(sid_text);
#endif
  napi_value result;
  napi_get_boolean(env, permitted, &result);
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
  if (!BuildExactRoleAcl(manager, bot, reader, system, profile, false, &roles)) {
    Refuse(env, "create_exclusive_temp", "protected exact role DACL cannot be constructed");
    return nullptr;
  }
  if (NtCreateFileApi() == nullptr) {
    Refuse(env, "create_exclusive_temp", "handle-relative Windows open primitive is unavailable");
    return nullptr;
  }
  HANDLE verified_parent = OpenWindowsPathNoFollow(
      parent, kWindowsChildMutationParentAccess, VerifiedObjectType::Directory);
  if (verified_parent == INVALID_HANDLE_VALUE) {
    Refuse(env, "create_exclusive_temp", "parent is not a supported absolute handle-relative Windows directory");
    return nullptr;
  }
  CloseHandle(verified_parent);
  for (unsigned i = 0; i < 128; ++i) {
    std::wstring token;
    if (!WindowsRandomName(&token)) break;
    std::string candidate = (std::filesystem::u8path(parent) / (prefix + "." + Utf8(token))).u8string();
    HANDLE h = CreateProtectedFileNoFollow(candidate, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | DELETE, roles.acl,
        roles.sids[RequiredOwnerRole(profile, false)]);
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
  if (!BuildExactRoleAcl(manager, bot, reader, system, profile, false, &roles)) {
    Refuse(env, "create_absent_exclusive", "protected exact role DACL cannot be constructed");
    return nullptr;
  }
  if (NtCreateFileApi() == nullptr || NtSetInformationFileApi() == nullptr) {
    Refuse(env, "create_absent_exclusive", "handle-relative Windows open and rename primitives are unavailable");
    return nullptr;
  }
  HANDLE parent = INVALID_HANDLE_VALUE;
  std::wstring name;
  if (!OpenWindowsParentNoFollow(path, &parent, &name, kWindowsChildMutationParentAccess)) {
    Refuse(env, "create_absent_exclusive", "path is not a supported absolute handle-relative Windows path");
    return nullptr;
  }
  SECURITY_DESCRIPTOR descriptor{};
  if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorDacl(&descriptor, TRUE, roles.acl, FALSE) ||
      !SetSecurityDescriptorOwner(&descriptor, roles.sids[RequiredOwnerRole(profile, false)], FALSE) ||
      !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    CloseHandle(parent);
    Refuse(env, "create_absent_exclusive", "protected exact role DACL cannot be constructed");
    return nullptr;
  }
  HANDLE temporary = INVALID_HANDLE_VALUE;
  std::wstring temporary_name;
  for (unsigned i = 0; i < 128; ++i) {
    std::wstring token;
    if (!WindowsRandomName(&token)) break;
    temporary_name = name + L".create." + token;
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
  // Fails closed if the volume cannot be confirmed as NTFS, not just if the
  // flush itself fails (see FlushDurableDirectoryHandle).
  const bool directory_flushed = FlushDurableDirectoryHandle(dir);
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
      OpenWindowsParentNoFollow(source, &source_parent, &source_name, kWindowsChildMutationParentAccess) &&
      OpenWindowsParentNoFollow(destination, &destination_parent, &destination_name, kWindowsChildMutationParentAccess);
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

const napi_type_tag kNativeLockTypeTag = {
    0x4e61746976654c6fULL,
    0x636b3a7631000001ULL,
};

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
  if (!ParseRoleProfile(profile_text, &profile) || !BuildExactRoleAcl(manager, bot, reader, system, profile, false, &roles)) {
    delete lock; Refuse(env, "acquire_native_lock", "protected exact role DACL cannot be constructed"); return nullptr;
  }
  lock->handle = OpenNoFollowFile(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL);
  if (lock->handle == INVALID_HANDLE_VALUE && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) {
    lock->handle = CreateProtectedFileNoFollow(path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, roles.acl,
        roles.sids[RequiredOwnerRole(profile, false)]);
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
  if (napi_create_external(env, lock, ReleaseLock, nullptr, &handle) != napi_ok) {
    ReleaseLock(env, lock, nullptr);
    Throw(env, "ERR_NATIVE_CONTROL_LOCK", "unable to create native lock handle");
    return nullptr;
  }
  if (napi_type_tag_object(env, handle, &kNativeLockTypeTag) != napi_ok) {
    Throw(env, "ERR_NATIVE_CONTROL_LOCK", "unable to type-tag native lock handle");
    return nullptr;
  }
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
  if (!ParseRoleProfile(profile_text, &profile) || !BuildExactRoleAcl(manager, bot, reader, system, profile, true, &roles)) {
    Refuse(env, "ensure_control_directory", "protected exact role DACL cannot be constructed"); return nullptr;
  }
  HANDLE h = OpenNoFollowDirectory(path, READ_CONTROL);
  if (h == INVALID_HANDLE_VALUE && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) {
    if (!CreateProtectedDirectoryNoFollow(path, roles.acl, roles.sids[RequiredOwnerRole(profile, true)]) && GetLastError() != ERROR_ALREADY_EXISTS) {
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
  std::string path, kind, principal, mode, management_sid, bot_sid, reader_sid, system_sid, profile_text;
  if (!StringArg(env, info, 0, &path, 9) || !StringArg(env, info, 1, &kind, 9) ||
      !StringArg(env, info, 2, &principal, 9) || !StringArg(env, info, 3, &mode, 9) ||
      !StringArg(env, info, 4, &management_sid, 9) || !StringArg(env, info, 5, &bot_sid, 9) ||
      !StringArg(env, info, 6, &reader_sid, 9) || !StringArg(env, info, 7, &system_sid, 9) ||
      !StringArg(env, info, 8, &profile_text, 9)) return nullptr;
  if (mode != "read" && mode != "write" && mode != "mutate-children" && mode != "traverse") {
    Refuse(env, "principal_access_check", "access mode must be read, write, mutate-children, or traverse");
    return nullptr;
  }
  RoleProfile profile;
  if (!ParseRoleProfile(profile_text, &profile)) {
    Refuse(env, "principal_access_check", "role profile is invalid");
    return nullptr;
  }
  // "legacy-retained" objects deliberately never carry an exact role ACL (they retain
  // their original foreign ACL). "mutate-children" would authorize creating/replacing
  // files under a retained object, which would violate the contract that retained
  // targets stay byte-, identity-, and ACL-immutable, so it is rejected fail-closed
  // before either platform branch runs regardless of the real DACL. "write" is instead
  // evaluated normally below, through the object's real ACL via the same
  // full-group-expansion-then-fallback path used for every other profile, so a
  // retained-profile write probe reflects the actual DACL. Callers MUST NEVER treat a
  // true "write" result for this profile as authorization to mutate a retained object
  // — it may only ever be asserted false.
  if (profile == RoleProfile::LegacyRetained && mode == "mutate-children") {
    Refuse(env, "principal_access_check", "legacy-retained profile does not support the mutate-children mode");
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
  const bool exact_role_acl = VerifyExactRoleAcl(handle, management_sid, bot_sid, reader_sid, system_sid, profile);
  ACCESS_MASK desired_access = FILE_GENERIC_READ;
  BY_HANDLE_FILE_INFORMATION metadata{};
  if (mode == "write" || mode == "mutate-children" || mode == "traverse") {
    if (!GetFileInformationByHandle(handle, &metadata)) {
      CloseHandle(handle);
      LocalFree(descriptor);
      LocalFree(sid);
      napi_value result;
      napi_get_boolean(env, false, &result);
      return result;
    }
    const bool is_directory = (metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (mode == "mutate-children" || mode == "traverse") {
      if (!is_directory) {
        CloseHandle(handle);
        LocalFree(descriptor);
        LocalFree(sid);
        Refuse(env, "principal_access_check", "mutate-children/traverse modes apply only to directory targets");
        return nullptr;
      }
      // "traverse" proves the plain kWindowsTraversalAccess bits (FILE_TRAVERSE
      // among them) that every intermediate path component along the way to a
      // record inside this directory must be granted for the open to succeed
      // at all. "mutate-children" additionally proves exactly the narrowed
      // parent-directory mask that CreateProtectedFileNoFollow /
      // CreateExclusiveTemp / ReplaceExistingAtomic request when opening this
      // directory as a create/replace/rename mutation parent
      // (kWindowsChildMutationParentAccess), as distinct from the full
      // destructive kWindowsDirectoryMutationAccess class (WRITE_DAC/
      // WRITE_OWNER) that "write" mode proves/denies below.
      desired_access = mode == "traverse" ? kWindowsTraversalAccess : kWindowsChildMutationParentAccess;
    } else {
      desired_access = is_directory ? kWindowsDirectoryMutationAccess : FILE_GENERIC_WRITE;
    }
  }
  CloseHandle(handle);
  bool allowed = false;
  bool authoritative = true;
  AUTHZ_RESOURCE_MANAGER_HANDLE manager = nullptr;
  AUTHZ_CLIENT_CONTEXT_HANDLE context = nullptr;
  if (dacl != nullptr && AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, nullptr, nullptr, nullptr,
      L"native-control", &manager)) {
    LUID identifier{};
    // Try full group-membership expansion first so that role access granted
    // through a group ACE (rather than an explicit per-principal ACE) is
    // actually honoured. Only fall back to AUTHZ_SKIP_TOKEN_GROUPS when the
    // principal SID itself cannot be resolved to a real, queryable
    // local/domain security principal (ERROR_NONE_MAPPED /
    // ERROR_TRUSTED_RELATIONSHIP_FAILURE) — principal_access_check must
    // still be able to evaluate hypothetical/remote role principals (e.g.
    // other fleet members) that are never expected to exist as local
    // accounts.
    bool skipped_groups = false;
    bool initialized = AuthzInitializeContextFromSid(0, sid, manager, nullptr, identifier, nullptr, &context);
    if (!initialized) {
      const DWORD init_error = GetLastError();
      if (init_error == ERROR_NONE_MAPPED || init_error == ERROR_TRUSTED_RELATIONSHIP_FAILURE) {
        skipped_groups = true;
        initialized = AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS, sid, manager, nullptr, identifier, nullptr, &context);
      }
    }
    if (initialized) {
      ACCESS_MASK granted = 0;
      DWORD access_error = ERROR_ACCESS_DENIED;
      AUTHZ_ACCESS_REQUEST request{};
      request.DesiredAccess = desired_access;
      AUTHZ_ACCESS_REPLY reply{};
      reply.ResultListLength = 1;
      reply.GrantedAccessMask = &granted;
      reply.Error = &access_error;
      const bool access_check_ok =
          AuthzAccessCheck(0, context, &request, nullptr, descriptor, nullptr, 0, &reply, nullptr) &&
          access_error == ERROR_SUCCESS && (granted & request.DesiredAccess) == request.DesiredAccess;
      // "legacy-retained" targets never carry an exact role ACL by design (they
      // retain their original foreign ACL), so the exact-ACL gate would make every
      // read/write/traverse probe on them false regardless of the real DACL. Skip it
      // only for that profile; "mutate-children" was already rejected fail-closed
      // above (it would authorize mutating an immutable retained object), so this
      // never weakens a mutation-authorization proof. A retained-profile "write"
      // result below reflects the object's real DACL and MUST NEVER be treated by a
      // caller as authorization to mutate the retained object — it is only ever
      // asserted false by run_startup_self_test.
      const bool require_exact_acl = profile != RoleProfile::LegacyRetained;
      allowed = (!require_exact_acl || exact_role_acl) && access_check_ok;
      if (!allowed && skipped_groups &&
          (mode == "read" || profile == RoleProfile::LegacyRetained)) {
        // Write/mutation denials stay authoritative even with an unexpanded
        // context: VerifyExactRoleAcl already proves the DACL is exactly the
        // expected 4-ACE role ACL for this profile (owner plus one explicit
        // per-role allow ACE with the exact expected mask), so no group ACE
        // could ever grant additional write access here regardless of
        // expansion. Read access, however, can legitimately be granted
        // through a group ACE that an unresolvable principal's unexpanded
        // context cannot prove or disprove membership in, so a read DENY
        // here is not proof of denial. An ALLOW remains authoritative in
        // both modes because it came from an explicit ACE evaluated against
        // the real DACL.
        authoritative = false;
      }
    }
  }
  if (context) AuthzFreeContext(context);
  if (manager) AuthzFreeResourceManager(manager);
  LocalFree(descriptor); LocalFree(sid);
  if (!authoritative) {
    Refuse(env, "principal_access_check", "read denial cannot be proven without group expansion for an unresolvable principal");
    return nullptr;
  }
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
  if (fd < 0) {
    close(parent_fd);
    napi_value result;
    napi_get_boolean(env, false, &result);
    return result;
  }
  struct stat probe_stat{};
  if (fstat(fd, &probe_stat) != 0) {
    close(fd);
    close(parent_fd);
    napi_value result;
    napi_get_boolean(env, false, &result);
    return result;
  }
  if ((mode == "mutate-children" || mode == "traverse") && !S_ISDIR(probe_stat.st_mode)) {
    close(fd);
    close(parent_fd);
    Refuse(env, "principal_access_check", "mutate-children/traverse modes apply only to directory targets");
    return nullptr;
  }
  const mode_t requested = mode == "read" ? S_IRUSR
      : mode == "traverse" ? S_IXUSR
      : mode == "mutate-children" ? (S_IWUSR | S_IXUSR)
      : S_IWUSR;
  const bool exact_role_acl = VerifyExactRoleAcl(fd, management_sid, bot_sid, reader_sid, system_sid, profile);
  bool allowed;
  if (mode == "write" && S_ISDIR(probe_stat.st_mode)) {
    // POSIX rwx bits cannot express Windows' owner-only WRITE_DAC/WRITE_OWNER
    // distinction (kWindowsDirectoryMutationAccess): every RoleMode entry for
    // a directory, including non-owner roles such as bot-state's B, can
    // legitimately carry the same S_IWUSR bit as the owner. So "write" mode
    // on a directory is proven only by literal fstat ownership under a
    // verified exact-role ACL, mirroring the fact that only the FILE_ALL_ACCESS
    // owner ACE (never a non-owner role's narrower mutation-parent mask)
    // carries WRITE_DAC/WRITE_OWNER on Windows.
    allowed = exact_role_acl && parsed == probe_stat.st_uid;
  } else {
    allowed = PrincipalCanAccess(fd, parsed, requested, exact_role_acl);
  }
  close(fd);
  close(parent_fd);
  napi_value result;
  napi_get_boolean(env, allowed, &result);
  return result;
#endif
}

const napi_type_tag kVerifiedHandleTypeTag = {
    0x5665726966696564ULL,
    0x48616e646c653a01ULL,
};

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
  bool tagged = false;
  if (argc <= index ||
      napi_check_object_type_tag(env, args[index], &kVerifiedHandleTypeTag, &tagged) != napi_ok ||
      !tagged ||
      napi_get_value_external(env, args[index], reinterpret_cast<void**>(result)) != napi_ok ||
      !*result) {
    Throw(env, "ERR_INVALID_ARG_TYPE", "argument must be a verified native handle");
    return false;
  }
  return true;
}
bool CreateVerifiedHandleExternal(napi_env env, VerifiedHandle* value, napi_value* result) {
  if (napi_create_external(env, value, ReleaseVerifiedHandle, nullptr, result) != napi_ok) {
    ReleaseVerifiedHandle(env, value, nullptr);
    Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to create verified native handle");
    return false;
  }
  if (napi_type_tag_object(env, *result, &kVerifiedHandleTypeTag) != napi_ok) {
    Throw(env, "ERR_NATIVE_CONTROL_OPEN", "unable to type-tag verified native handle");
    return false;
  }
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
  napi_value result;
  if (!CreateVerifiedHandleExternal(env, value, &result)) return nullptr;
  return result;
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
  napi_value result;
  if (!CreateVerifiedHandleExternal(env, value, &result)) return nullptr;
  return result;
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

// Contract-4 inventory entry points intentionally do not reuse the legacy
// four-principal helpers above.  The inventory ACL is a five-principal object
// (M, B, R, D, and uid:0) with a different ownership matrix.
 napi_value InventoryErrorValue(napi_env env, const char* code, const char* operation,
                               uint32_t writes = 0, bool ambiguous = false) {
  napi_value error, message, value;
  napi_create_string_utf8(env, "inventory operation failed", NAPI_AUTO_LENGTH, &message);
  napi_create_error(env, nullptr, message, &error);
  napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "code", value);
  napi_create_string_utf8(env, operation, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "operation", value);
  napi_create_uint32(env, writes, &value);
  napi_set_named_property(env, error, "writes", value);
  napi_get_boolean(env, ambiguous, &value);
  napi_set_named_property(env, error, "ambiguous", value);
  return error;
}
void InventoryError(napi_env env, const char* code, const char* operation,
                    uint32_t writes = 0, bool ambiguous = false) {
  napi_throw(env, InventoryErrorValue(env, code, operation, writes, ambiguous));
}
napi_status CreateInventoryAsyncWork(napi_env env, const char* name,
                                     napi_async_execute_callback execute,
                                     napi_async_complete_callback complete,
                                     void* data, napi_async_work* result) {
  napi_value resource_name;
  const napi_status name_status =
      napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resource_name);
  if (name_status != napi_ok) return name_status;
  return napi_create_async_work(
      env, nullptr, resource_name, execute, complete, data, result);
}

bool InventoryString(napi_env env, napi_value value, std::string* text) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_string) return false;
  constexpr size_t kMaximumStringUnits = 32768;
  size_t units = 0;
  if (napi_get_value_string_utf16(env, value, nullptr, 0, &units) != napi_ok ||
      units > kMaximumStringUnits) return false;
  std::vector<char16_t> utf16;
  utf16.resize(units + 1);
  if (napi_get_value_string_utf16(env, value, utf16.data(), utf16.size(), &units) != napi_ok)
    return false;
  for (size_t index = 0; index < units; ++index) {
    const char16_t unit = utf16[index];
    if (unit == 0) return false;
    if (unit >= 0xD800 && unit <= 0xDBFF) {
      if (++index >= units || utf16[index] < 0xDC00 || utf16[index] > 0xDFFF) return false;
    } else if (unit >= 0xDC00 && unit <= 0xDFFF) {
      return false;
    }
  }
  size_t bytes = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &bytes) != napi_ok ||
      bytes > kMaximumStringUnits * 4) return false;
  text->resize(bytes + 1);
  if (napi_get_value_string_utf8(env, value, text->data(), bytes + 1, &bytes) != napi_ok)
    return false;
  text->resize(bytes);
  return true;
}

bool InventoryArgs(napi_env env, napi_callback_info info, size_t required, napi_value* args) {
  size_t argc = required;
  return napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) == napi_ok && argc == required;
}

constexpr size_t kInventoryMaxBytes = 16 * 1024 * 1024;

bool InventoryMaximumBytes(napi_env env, napi_value value, int64_t* result) {
  napi_valuetype type;
  double numeric = 0;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, value, &numeric) != napi_ok || !std::isfinite(numeric) ||
      numeric < 0 || numeric > static_cast<double>(kInventoryMaxBytes) ||
      std::floor(numeric) != numeric) return false;
  *result = static_cast<int64_t>(numeric);
  return true;
}

bool InventoryUint32(napi_env env, napi_value value, uint32_t* result) {
  napi_valuetype type;
  double numeric = 0;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, value, &numeric) != napi_ok || !std::isfinite(numeric) ||
      numeric < 0 || numeric > static_cast<double>(std::numeric_limits<uint32_t>::max()) ||
      std::floor(numeric) != numeric) return false;
  *result = static_cast<uint32_t>(numeric);
  return true;
}

bool InventoryBufferArg(napi_env env, napi_callback_info info, size_t index, std::vector<uint8_t>* result) {
  size_t argc = index + 1;
  napi_value args[6];
  bool is_buffer = false;
  void* data = nullptr;
  size_t length = 0;
  if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc <= index ||
      napi_is_buffer(env, args[index], &is_buffer) != napi_ok || !is_buffer ||
      napi_get_buffer_info(env, args[index], &data, &length) != napi_ok || length > kInventoryMaxBytes) return false;
  result->assign(static_cast<uint8_t*>(data), static_cast<uint8_t*>(data) + length);
  return true;
}

// Inventory authorization input is an untrusted capability boundary.  Do not
// read values from it until descriptors have established a plain data shape.
napi_ref gInventoryObjectPrototype = nullptr;
napi_ref gInventoryGetOwnPropertyDescriptors = nullptr;
thread_local bool gInventoryValidationActive = false;

bool InventoryOrdinaryDataObject(napi_env env, napi_value value, const char* const* names,
                                 size_t expected, napi_value* captured = nullptr) {
  if (gInventoryValidationActive) return false;
  struct ValidationGuard {
    ValidationGuard() { gInventoryValidationActive = true; }
    ~ValidationGuard() { gInventoryValidationActive = false; }
  } guard;
  auto invalid = [&]() {
    bool pending = false;
    if (napi_is_exception_pending(env, &pending) == napi_ok && pending) {
      napi_value ignored;
      napi_get_and_clear_last_exception(env, &ignored);
    }
    return false;
  };
  napi_valuetype type;
  napi_value prototype, object_prototype, get_descriptors, descriptors, keys;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_object ||
      !gInventoryObjectPrototype || !gInventoryGetOwnPropertyDescriptors ||
      napi_get_reference_value(env, gInventoryObjectPrototype, &object_prototype) != napi_ok ||
      napi_get_reference_value(env, gInventoryGetOwnPropertyDescriptors, &get_descriptors) != napi_ok ||
      napi_get_prototype(env, value, &prototype) != napi_ok) return invalid();
  bool same = false;
  if (napi_strict_equals(env, prototype, object_prototype, &same) != napi_ok || !same ||
      napi_get_all_property_names(env, value, napi_key_own_only, napi_key_all_properties,
                                  napi_key_numbers_to_strings, &keys) != napi_ok) return invalid();
  uint32_t count = 0;
  if (napi_get_array_length(env, keys, &count) != napi_ok || count != expected) return invalid();
  if (napi_call_function(env, object_prototype, get_descriptors, 1, &value, &descriptors) != napi_ok)
    return invalid();
  for (size_t i = 0; i < expected; ++i) {
    napi_value descriptor, enumerable, descriptor_value;
    bool flag = false, has_getter = false, has_setter = false;
    if (napi_get_named_property(env, descriptors, names[i], &descriptor) != napi_ok ||
        napi_typeof(env, descriptor, &type) != napi_ok || type != napi_object ||
        napi_get_named_property(env, descriptor, "enumerable", &enumerable) != napi_ok ||
        napi_get_value_bool(env, enumerable, &flag) != napi_ok || !flag ||
        napi_has_named_property(env, descriptor, "value", &flag) != napi_ok || !flag ||
        napi_has_named_property(env, descriptor, "get", &has_getter) != napi_ok || has_getter ||
        napi_has_named_property(env, descriptor, "set", &has_setter) != napi_ok || has_setter ||
        napi_get_named_property(env, descriptor, "value", &descriptor_value) != napi_ok)
      return invalid();
    if (captured) captured[i] = descriptor_value;
  }
  return true;
}

#ifdef _WIN32
bool InventoryString(napi_env env, napi_value value, std::string* text);
struct InventoryRoles { std::string management, bot, recovery, daemon, system; };

bool InventoryHostKey(const std::string& value) {
  if (value.size() != 64) return false;
  for (char c : value) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  return true;
}
bool InventoryProfile(const std::string& value, bool* directory) {
  *directory = value == "inventory-directory" || value == "reader-directory";
  return *directory || value == "inventory-file" || value == "inventory-commit" ||
      value == "inventory-fence" || value == "inventory-manual-cleanup" || value == "inventory-floor";
}
const char* InventoryParentProfile(const std::string& profile) {
  return profile == "reader-directory" || profile == "inventory-floor" ? "reader-directory" :
      "inventory-directory";
}
bool CanonicalUserSid(const std::string& text, bool system) {
  PSID sid = nullptr; SID_NAME_USE use; DWORD name = 0, domain = 0;
  if (!ConvertStringSidToSidW(Wide(text).c_str(), &sid)) return false;
  LookupAccountSidW(nullptr, sid, nullptr, &name, nullptr, &domain, &use);
  std::vector<wchar_t> n(name), d(domain);
  const bool ok = LookupAccountSidW(nullptr, sid, n.data(), &name, d.data(), &domain, &use) &&
      (system ? text == "S-1-5-18" : use == SidTypeUser);
  LPWSTR canonical = nullptr;
  const bool exact = ConvertSidToStringSidW(sid, &canonical) && text == Utf8(canonical);
  if (canonical) LocalFree(canonical); LocalFree(sid);
  return ok && exact;
}
bool InventoryRole(napi_env env, napi_value value, std::string* result, bool system) {
  napi_value captured[2];
  const char* fields[] = {"kind", "value"};
  if (!InventoryOrdinaryDataObject(env, value, fields, 2, captured)) return false;
  std::string k; return InventoryString(env, captured[0], &k) &&
      InventoryString(env, captured[1], result) &&
      k == "sid" && CanonicalUserSid(*result, system);
}
bool InventoryRolesArg(napi_env env, napi_value value, InventoryRoles* roles) {
  napi_value captured[5];
  const char* fields[] = {"management", "bot", "recovery", "daemon", "system"};
  if (!InventoryOrdinaryDataObject(env, value, fields, 5, captured)) return false;
  std::string* values[] = {&roles->management, &roles->bot, &roles->recovery, &roles->daemon, &roles->system};
  for (size_t i = 0; i != 5; ++i)
    if (!InventoryRole(env, captured[i], values[i], i == 4)) return false;
  const std::string all[] = {roles->management, roles->bot, roles->recovery, roles->daemon, roles->system};
  for (size_t i = 0; i != 5; ++i) for (size_t j = i + 1; j != 5; ++j) if (all[i] == all[j]) return false;
  return true;
}
bool CurrentInventoryActor(const InventoryRoles& roles, bool management, bool daemon_allowed,
                           bool recovery_allowed = false, bool system_allowed = false) {
  HANDLE token = nullptr; DWORD bytes = 0; bool ok = false;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
      !GetTokenInformation(token, TokenUser, nullptr, 0, &bytes) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
    std::vector<uint8_t> data(bytes);
    if (GetTokenInformation(token, TokenUser, data.data(), bytes, &bytes)) {
      LPWSTR sid = nullptr; PSID raw = reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid;
      if (ConvertSidToStringSidW(raw, &sid)) {
        const std::string current = Utf8(sid);
        ok = (system_allowed && current == roles.system) || (management && current == roles.management) ||
            (daemon_allowed && current == roles.daemon) ||
            (recovery_allowed && current == roles.recovery);
        LocalFree(sid);
      }
    }
  }
  if (token) CloseHandle(token); return ok;
}
bool InventoryPath(const std::string& path, const std::string& profile) {
  bool directory; if (!InventoryProfile(profile, &directory)) return false;
  PWSTR program_data = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &program_data))) return false;
  const std::string root = Utf8(program_data); CoTaskMemFree(program_data);
  const std::string base = root + (profile == "reader-directory" || profile == "inventory-floor" ?
      "\\gjc-remote\\native-reader\\" : "\\gjc-remote\\native\\");
  if (path.rfind(base, 0) != 0) return false;
  const std::string rest = path.substr(base.size());
  if (rest.size() < 64 || !InventoryHostKey(rest.substr(0, 64))) return false;
  if (rest.size() == 64) return directory;
  if (directory || rest[64] != '\\') return false;
  const std::string leaf = rest.substr(65);
  const char* expected = profile == "inventory-file" ? "workspace-inventory.v2.json" :
      profile == "inventory-commit" ? "inventory-commit.v1.json" :
      profile == "inventory-fence" ? "inventory-publication.lock" :
      profile == "inventory-manual-cleanup" ? "inventory-manual-cleanup.v1.json" : "inventory-floor.v1.json";
  return leaf == expected;
}
std::string WindowsFileIdText(const FILE_ID_128& file_id) {
  std::string result;
  result.reserve(sizeof(file_id.Identifier) * 2);
  char byte_text[3];
  for (uint8_t byte : file_id.Identifier) {
    std::snprintf(byte_text, sizeof(byte_text), "%02x", byte);
    result += byte_text;
  }
  return result;
}

bool InventoryFileIdVectorsValid() {
  const FILE_ID_128 ascending{{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};
  const FILE_ID_128 asymmetric{{0xff, 0x00, 0x80, 0x7f, 0x10, 0x20, 0x30, 0x40,
      0x50, 0x60, 0x70, 0x90, 0xa0, 0xb0, 0xc0, 0xd0}};
  return WindowsFileIdText(ascending) == "000102030405060708090a0b0c0d0e0f" &&
      WindowsFileIdText(asymmetric) == "ff00807f1020304050607090a0b0c0d0";
}

bool InventoryIdentity(HANDLE handle, std::string* serial, std::string* id, uint32_t* attributes, std::string* owner) {
  FILE_ID_INFO file_id{}; FILE_BASIC_INFO basic{}; PSID sid = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr; LPWSTR text = nullptr;
  const bool ok = GetFileInformationByHandleEx(handle, FileIdInfo, &file_id, sizeof(file_id)) &&
      GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic)) &&
      GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &sid, nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS &&
      sid && ConvertSidToStringSidW(sid, &text);
  if (ok) { char b[3]; *serial = ""; for (int i = 7; i >= 0; --i) { std::snprintf(b, sizeof(b), "%02x", static_cast<unsigned>((file_id.VolumeSerialNumber >> (i * 8)) & 0xff)); *serial += b; }
    *id = WindowsFileIdText(file_id.FileId);
    *attributes = basic.FileAttributes; *owner = Utf8(text);
  }
  if (text) LocalFree(text); if (descriptor) LocalFree(descriptor); return ok;
}
bool SameWindowsFileId(const FILE_ID_INFO& a, const FILE_ID_INFO& b) {
  return a.VolumeSerialNumber == b.VolumeSerialNumber &&
      std::memcmp(a.FileId.Identifier, b.FileId.Identifier, sizeof(a.FileId.Identifier)) == 0;
}
bool InventoryRandomName(std::wstring* value) {
  return WindowsRandomName(value);
}
bool CanonicalInventoryParent(HANDLE parent, FILE_ID_INFO* identity, std::wstring* path) {
  if (!GetFileInformationByHandleEx(parent, FileIdInfo, identity, sizeof(*identity))) return false;
  DWORD size = GetFinalPathNameByHandleW(parent, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (size == 0 || size > 32768) return false;
  std::vector<wchar_t> buffer(size + 1);
  const DWORD written = GetFinalPathNameByHandleW(parent, buffer.data(), static_cast<DWORD>(buffer.size()),
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (written == 0 || written >= buffer.size()) return false;
  path->assign(buffer.data(), written);
  return true;
}
bool InventoryParentStable(HANDLE retained, const FILE_ID_INFO& expected, const std::wstring& canonical_path) {
  FILE_ID_INFO held{}, named{};
  FILE_ATTRIBUTE_TAG_INFO tag{};
  HANDLE probe = CreateFileW(canonical_path.c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  const bool stable = GetFileInformationByHandleEx(retained, FileIdInfo, &held, sizeof(held)) &&
      probe != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandleEx(probe, FileIdInfo, &named, sizeof(named)) &&
      GetFileInformationByHandleEx(probe, FileAttributeTagInfo, &tag, sizeof(tag)) &&
      (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
      (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
      SameWindowsFileId(held, expected) && SameWindowsFileId(named, expected);
  if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
  return stable;
}
bool FlushInventoryParent(HANDLE retained, const FILE_ID_INFO& expected, const std::wstring& canonical_path) {
  if (!InventoryParentStable(retained, expected, canonical_path)) return false;
  HANDLE durable = CreateFileW(canonical_path.c_str(), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  FILE_ID_INFO identity{};
  FILE_ATTRIBUTE_TAG_INFO tag{};
  const bool flushed = durable != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandleEx(durable, FileIdInfo, &identity, sizeof(identity)) &&
      GetFileInformationByHandleEx(durable, FileAttributeTagInfo, &tag, sizeof(tag)) &&
      (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
      (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
      SameWindowsFileId(identity, expected) && FlushDurableDirectoryHandle(durable);
  if (durable != INVALID_HANDLE_VALUE) CloseHandle(durable);
  return flushed && InventoryParentStable(retained, expected, canonical_path);
}
std::wstring InventoryChildPath(const std::wstring& parent, const std::wstring& name) {
  return parent + (parent.empty() || parent.back() == L'\\' ? L"" : L"\\") + name;
}
void InventoryIdentityValue(napi_env env, napi_value result, HANDLE handle) {
  std::string serial, id, owner; uint32_t attributes = 0; napi_value value;
  if (!InventoryIdentity(handle, &serial, &id, &attributes, &owner)) return;
  napi_create_string_utf8(env, serial.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, result, "volumeSerial", value);
  napi_create_string_utf8(env, id.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, result, "fileId", value);
  napi_create_uint32(env, attributes, &value); napi_set_named_property(env, result, "attributes", value);
  napi_create_string_utf8(env, owner.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, result, "owner", value);
}
bool InventoryIdentityArg(napi_env env, napi_value object, HANDLE handle) {
  const char* fields[] = {"volumeSerial", "fileId", "attributes", "owner"};
  napi_value captured[4];
  if (!InventoryOrdinaryDataObject(env, object, fields, 4, captured)) return false;
  napi_value actual; napi_create_object(env, &actual); InventoryIdentityValue(env, actual, handle);
  const char* names[] = {"volumeSerial", "fileId", "attributes", "owner"};
  for (size_t index = 0; index < 4; ++index) {
    napi_value actual_value;
    if (napi_get_named_property(env, actual, names[index], &actual_value) != napi_ok) return false;
    bool equal = false;
    if (napi_strict_equals(env, captured[index], actual_value, &equal) != napi_ok || !equal)
      return false;
  } return true;
}
bool WindowsInventoryBytesEqual(HANDLE handle, const std::vector<uint8_t>& expected) {
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(handle, &size) || size.QuadPart < 0 ||
      static_cast<uint64_t>(size.QuadPart) != expected.size() ||
      SetFilePointer(handle, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != ERROR_SUCCESS) return false;
  std::vector<uint8_t> actual(expected.size());
  size_t offset = 0;
  while (offset < actual.size()) {
    DWORD read = 0;
    const DWORD remaining = static_cast<DWORD>(std::min<size_t>(actual.size() - offset, MAXDWORD));
    if (!ReadFile(handle, actual.data() + offset, remaining, &read, nullptr) || read == 0) return false;
    offset += read;
  }
  return actual == expected;
}
napi_value ResolveInventoryStateRootWindows(napi_env env, napi_callback_info info) {
  napi_value args[2]; std::string host, kind;
  if (!InventoryArgs(env, info, 2, args) || !InventoryString(env, args[0], &host) ||
      !InventoryString(env, args[1], &kind) || !InventoryHostKey(host) || (kind != "inventory" && kind != "reader")) {
    InventoryError(env, "INVENTORY_INVALID", "resolve_native_state_root"); return nullptr;
  }
  PWSTR base = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &base))) {
    InventoryError(env, "CONTAINMENT_UNSUPPORTED", "resolve_native_state_root"); return nullptr;
  }
  const std::string path = Utf8(base) + (kind == "inventory" ? "\\gjc-remote\\native\\" : "\\gjc-remote\\native-reader\\") + host;
  CoTaskMemFree(base); napi_value result; napi_create_string_utf8(env, path.c_str(), NAPI_AUTO_LENGTH, &result); return result;
}
bool ValidWindowsVolumeGuid(const std::wstring& value) {
  if (value.size() != 49 || value.rfind(L"\\\\?\\VOLUME{", 0) != 0 ||
      value[47] != L'}' || value[48] != L'\\') return false;
  for (size_t index = 11; index < 47; ++index) {
    if (index == 19 || index == 24 || index == 29 || index == 34) {
      if (value[index] != L'-') return false;
    } else if (!((value[index] >= L'0' && value[index] <= L'9') ||
                 (value[index] >= L'A' && value[index] <= L'F'))) {
      return false;
    }
  }
  return true;
}
bool ValidWindowsFileSystem(const std::wstring& value) {
  if (value.empty() || value.size() > 32) return false;
  return std::all_of(value.begin(), value.end(), [](wchar_t character) {
    return (character >= L'A' && character <= L'Z') ||
        (character >= L'0' && character <= L'9') ||
        character == L'.' || character == L'_' || character == L'-';
  });
}
napi_value ReadWorkspaceRootFactsWindows(napi_env env, napi_callback_info info) {
  napi_value args[2]; std::string path, platform;
  if (!InventoryArgs(env, info, 2, args) || !InventoryString(env, args[0], &path) ||
      !InventoryString(env, args[1], &platform)) {
    InventoryError(env, "INVENTORY_INVALID", "read_workspace_root_facts"); return nullptr;
  }
  if (platform == "windows-unc") {
    InventoryError(env, "CONTAINMENT_UNSUPPORTED", "read_workspace_root_facts"); return nullptr;
  }
  if (platform != "windows-drive") {
    InventoryError(env, "INVENTORY_INVALID", "read_workspace_root_facts"); return nullptr;
  }
  WindowsPathParts parts; if (!ParseWindowsPath(path, &parts)) {
    InventoryError(env, "CONTAINMENT_UNSUPPORTED", "read_workspace_root_facts"); return nullptr;
  }
  HANDLE handle = OpenWindowsPathNoFollow(path, FILE_READ_ATTRIBUTES | READ_CONTROL, VerifiedObjectType::Directory);
  FILE_ID_INFO file_id{}; if (handle == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(handle, FileIdInfo, &file_id, sizeof(file_id))) {
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); InventoryError(env, "WORKSPACE_ROOT_ESCAPE", "read_workspace_root_facts"); return nullptr;
  }
  FILE_ID_INFO retained_identity{};
  std::wstring canonical_path;
  if (!CanonicalInventoryParent(handle, &retained_identity, &canonical_path) ||
      !SameWindowsFileId(file_id, retained_identity)) {
    CloseHandle(handle); InventoryError(env, "WORKSPACE_ROOT_ESCAPE", "read_workspace_root_facts"); return nullptr;
  }
  wchar_t volume[MAX_PATH]; if (!GetVolumePathNameW(canonical_path.c_str(), volume, MAX_PATH)) {
    CloseHandle(handle); InventoryError(env, "CONTAINMENT_UNSUPPORTED", "read_workspace_root_facts"); return nullptr;
  }
  wchar_t guid[MAX_PATH], fs[64]; DWORD serial = 0;
  if (!GetVolumeNameForVolumeMountPointW(volume, guid, MAX_PATH) ||
      !GetVolumeInformationW(volume, nullptr, 0, &serial, nullptr, nullptr, fs, 64)) {
    CloseHandle(handle); InventoryError(env, "CONTAINMENT_UNSUPPORTED", "read_workspace_root_facts"); return nullptr;
  }
  std::string id, identity_serial; uint32_t attributes; std::string owner;
  if (!InventoryIdentity(handle, &identity_serial, &id, &attributes, &owner)) {
    CloseHandle(handle); InventoryError(env, "WORKSPACE_ROOT_ESCAPE", "read_workspace_root_facts"); return nullptr;
  }
  CloseHandle(handle);
  std::wstring volume_guid(guid); for (auto& c : volume_guid) c = static_cast<wchar_t>(std::towupper(c));
  std::wstring filesystem(fs); for (auto& c : filesystem) c = static_cast<wchar_t>(std::towupper(c));
  if (!ValidWindowsVolumeGuid(volume_guid) || !ValidWindowsFileSystem(filesystem)) {
    InventoryError(env, "CONTAINMENT_UNSUPPORTED", "read_workspace_root_facts"); return nullptr;
  }
  napi_value result, root, storage, value; napi_create_object(env, &result); napi_create_object(env, &root); napi_create_object(env, &storage);
  if (canonical_path.rfind(L"\\\\?\\", 0) == 0) canonical_path.erase(0, 4);
  const std::string canonical_work_dir = Utf8(canonical_path);
  napi_create_string_utf8(env, "windows-drive", NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, result, "sourcePlatform", value);
  napi_create_string_utf8(env, canonical_work_dir.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, result, "workDir", value);
  napi_create_string_utf8(env, "win32-root-v1", NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, root, "kind", value);
  napi_create_string_utf8(env, identity_serial.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, root, "volumeSerial", value);
  napi_create_string_utf8(env, id.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, root, "fileId", value);
  napi_create_string_utf8(env, "windows-drive-storage-v1", NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, storage, "kind", value);
  const std::string vg = Utf8(volume_guid), fssystem = Utf8(filesystem); char serial_text[9]; std::snprintf(serial_text, sizeof(serial_text), "%08X", serial);
  napi_create_string_utf8(env, vg.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, storage, "volumeGuid", value);
  napi_create_string_utf8(env, serial_text, NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, storage, "volumeSerial", value);
  napi_create_string_utf8(env, fssystem.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, storage, "fileSystem", value);
  napi_set_named_property(env, result, "rootIdentity", root); napi_set_named_property(env, result, "storageIdentity", storage); return result;
}
bool InventoryAcl(HANDLE handle, const InventoryRoles& roles, const std::string& profile) {
  const bool directory = profile == "inventory-directory" || profile == "reader-directory";
  const bool daemon_owner = profile == "reader-directory" || profile == "inventory-floor";
  const std::string owner_text = daemon_owner ? roles.daemon : roles.management;
  const std::string identities[] = {owner_text, roles.system, daemon_owner ? roles.management : roles.daemon, roles.recovery};
  PSID sids[4]{}; EXPLICIT_ACCESSW entries[4]{}; PACL acl = nullptr;
  for (size_t i = 0; i != 4; ++i) {
    if (!ConvertStringSidToSidW(Wide(identities[i]).c_str(), &sids[i])) goto done;
    entries[i].grfAccessPermissions = i < 2 ? FILE_ALL_ACCESS :
        (directory ? (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) : FILE_GENERIC_READ);
    entries[i].grfAccessMode = SET_ACCESS; entries[i].grfInheritance = NO_INHERITANCE;
    entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID; entries[i].Trustee.TrusteeType = TRUSTEE_IS_USER;
    entries[i].Trustee.ptstrName = static_cast<LPWSTR>(sids[i]);
  }
  if (SetEntriesInAclW(4, entries, nullptr, &acl) != ERROR_SUCCESS) goto done;
  if (SetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
      sids[0], nullptr, acl, nullptr) != ERROR_SUCCESS) goto done;
  for (PSID sid : sids) LocalFree(sid); LocalFree(acl); return true;
done:
  for (PSID sid : sids) if (sid) LocalFree(sid); if (acl) LocalFree(acl); return false;
}
PSECURITY_DESCRIPTOR InventorySecurityDescriptor(const InventoryRoles& roles, const std::string& profile) {
  const bool directory = profile == "inventory-directory" || profile == "reader-directory";
  const bool daemon_owner = profile == "reader-directory" || profile == "inventory-floor";
  const std::string identities[] = {daemon_owner ? roles.daemon : roles.management, roles.system,
      daemon_owner ? roles.management : roles.daemon, roles.recovery};
  PSID sids[4]{}; EXPLICIT_ACCESSW entries[4]{}; PACL acl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  for (size_t i = 0; i != 4; ++i) {
    if (!ConvertStringSidToSidW(Wide(identities[i]).c_str(), &sids[i])) goto done;
    entries[i].grfAccessPermissions = i < 2 ? FILE_ALL_ACCESS :
        (directory ? (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) : FILE_GENERIC_READ);
    entries[i].grfAccessMode = SET_ACCESS; entries[i].grfInheritance = NO_INHERITANCE;
    entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID; entries[i].Trustee.TrusteeType = TRUSTEE_IS_USER;
    entries[i].Trustee.ptstrName = static_cast<LPWSTR>(sids[i]);
  }
  if (SetEntriesInAclW(4, entries, nullptr, &acl) != ERROR_SUCCESS ||
      !(descriptor = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH))) ||
      !InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorOwner(descriptor, sids[0], FALSE) ||
      !SetSecurityDescriptorDacl(descriptor, TRUE, acl, FALSE) ||
      !SetSecurityDescriptorControl(descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    if (descriptor) LocalFree(descriptor); descriptor = nullptr;
  } else {
    DWORD bytes = 0;
    MakeSelfRelativeSD(descriptor, nullptr, &bytes);
    PSECURITY_DESCRIPTOR relative = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR, bytes));
    if (!relative || !MakeSelfRelativeSD(descriptor, relative, &bytes)) {
      if (relative) LocalFree(relative);
      relative = nullptr;
    }
    LocalFree(descriptor);
    descriptor = relative;
  }
done:
  for (PSID sid : sids) if (sid) LocalFree(sid);
  if (acl) LocalFree(acl);
  return descriptor;
}
bool VerifyInventoryAcl(HANDLE handle, const InventoryRoles& roles, const std::string& profile) {
  const bool directory = profile == "inventory-directory" || profile == "reader-directory";
  const bool daemon_owner = profile == "reader-directory" || profile == "inventory-floor";
  const std::string identities[] = {daemon_owner ? roles.daemon : roles.management, roles.system,
      daemon_owner ? roles.management : roles.daemon, roles.recovery};
  PSID expected[4]{};
  for (size_t i = 0; i != 4; ++i) {
    if (!ConvertStringSidToSidW(Wide(identities[i]).c_str(), &expected[i])) {
      for (PSID sid : expected) if (sid) LocalFree(sid);
      return false;
    }
  }
  PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
  SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0; ACL_SIZE_INFORMATION size{};
  bool ok = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, nullptr, &acl, nullptr, &sd) == ERROR_SUCCESS && owner && EqualSid(owner, expected[0]) &&
      GetSecurityDescriptorControl(sd, &control, &revision) && (control & SE_DACL_PROTECTED) != 0 &&
      acl && GetAclInformation(acl, &size, sizeof(size), AclSizeInformation) && size.AceCount == 4;
  bool seen[4]{};
  for (DWORD i = 0; ok && i < size.AceCount; ++i) {
    void* raw = nullptr;
    if (!GetAce(acl, i, &raw)) { ok = false; break; }
    ACE_HEADER* header = static_cast<ACE_HEADER*>(raw);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0) { ok = false; break; }
    ACCESS_ALLOWED_ACE* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    const ACCESS_MASK masks[] = {FILE_ALL_ACCESS, FILE_ALL_ACCESS,
        directory ? (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) : FILE_GENERIC_READ,
        directory ? (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) : FILE_GENERIC_READ};
    bool matched = false;
    for (size_t role = 0; role != 4; ++role) {
      if (!seen[role] && ace->Mask == masks[role] &&
          EqualSid(reinterpret_cast<PSID>(&ace->SidStart), expected[role])) {
        seen[role] = true; matched = true; break;
      }
    }
    if (!matched) ok = false;
  }
  if (sd) LocalFree(sd);
  for (PSID sid : expected) LocalFree(sid);
  return ok && seen[0] && seen[1] && seen[2] && seen[3];
}
bool VerifyInventoryBaseWindows(const InventoryRoles& roles, const std::string& profile) {
  PWSTR program_data = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &program_data))) return false;
  const std::string base = Utf8(program_data) +
      (std::string(InventoryParentProfile(profile)) == "reader-directory" ?
          "\\gjc-remote\\native-reader" : "\\gjc-remote\\native");
  CoTaskMemFree(program_data);
  HANDLE handle = OpenWindowsPathNoFollow(base, READ_CONTROL | FILE_READ_ATTRIBUTES,
      VerifiedObjectType::Directory);
  const bool exact = handle != INVALID_HANDLE_VALUE &&
      VerifyInventoryAcl(handle, roles, InventoryParentProfile(profile));
  if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
  return exact;
}
bool OpenInventoryParentBoundWindows(const std::string& path, const InventoryRoles& roles,
                                     const std::string& profile, DWORD access,
                                     HANDLE* parent, std::wstring* name) {
  PWSTR program_data = nullptr;
  if (FAILED(SHGetKnownFolderPath(
          FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &program_data))) return false;
  const std::string base_path = Utf8(program_data) +
      (std::string(InventoryParentProfile(profile)) == "reader-directory" ?
          "\\gjc-remote\\native-reader" : "\\gjc-remote\\native");
  CoTaskMemFree(program_data);
  if (path.rfind(base_path + "\\", 0) != 0) return false;
  const std::string relative = path.substr(base_path.size() + 1);
  const std::wstring host = Wide(relative.substr(0, 64));
  const bool host_target = relative.size() == 64;
  HANDLE base = OpenWindowsPathNoFollow(base_path,
      READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE |
          (host_target ? access : 0),
      VerifiedObjectType::Directory);
  if (base == INVALID_HANDLE_VALUE ||
      !VerifyInventoryAcl(base, roles, InventoryParentProfile(profile))) {
    if (base != INVALID_HANDLE_VALUE) CloseHandle(base);
    return false;
  }
  if (host_target) {
    *parent = base;
    *name = host;
    return true;
  }
  HANDLE host_root = OpenWindowsRelative(base, host,
      READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | access,
      kFileOpen, VerifiedObjectType::Directory);
  CloseHandle(base);
  if (host_root == INVALID_HANDLE_VALUE ||
      !VerifyInventoryAcl(host_root, roles, InventoryParentProfile(profile))) {
    if (host_root != INVALID_HANDLE_VALUE) CloseHandle(host_root);
    return false;
  }
  *parent = host_root;
  *name = Wide(relative.substr(65));
  return true;
}
napi_value EnsureInventoryDirectoryWindows(napi_env env, napi_callback_info info) {
  napi_value args[3]; std::string path, profile; InventoryRoles roles{};
  if (!InventoryArgs(env, info, 3, args) || !InventoryString(env, args[0], &path) || !InventoryRolesArg(env, args[1], &roles) ||
      !InventoryString(env, args[2], &profile) || !InventoryPath(path, profile) ||
      (profile != "inventory-directory" && profile != "reader-directory") ||
      !CurrentInventoryActor(roles, profile == "inventory-directory", profile == "reader-directory")) {
    InventoryError(env, "INVENTORY_INVALID", "ensure_inventory_directory"); return nullptr;
  }
  if (!VerifyInventoryBaseWindows(roles, profile)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "ensure_inventory_directory"); return nullptr;
  }
  HANDLE parent; std::wstring name;
  if (!OpenInventoryParentBoundWindows(
          path, roles, profile, kWindowsMutationParentAccess, &parent, &name)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "ensure_inventory_directory"); return nullptr;
  }
  if (!VerifyInventoryAcl(parent, roles, InventoryParentProfile(profile))) {
    CloseHandle(parent); InventoryError(env, "INVENTORY_ACCESS_DENIED", "ensure_inventory_directory"); return nullptr;
  }
  FILE_ID_INFO parent_id{};
  std::wstring canonical_parent;
  if (!CanonicalInventoryParent(parent, &parent_id, &canonical_parent)) {
    CloseHandle(parent);
    InventoryError(env, "CONTAINMENT_UNSUPPORTED", "ensure_inventory_directory");
    return nullptr;
  }
  auto flush_parent = [&]() {
    return FlushInventoryParent(parent, parent_id, canonical_parent);
  };
  HANDLE existing = OpenWindowsRelative(parent, name,
      READ_CONTROL | FILE_READ_ATTRIBUTES, kFileOpen, VerifiedObjectType::Directory);
  const DWORD existing_error = existing == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
  if (existing != INVALID_HANDLE_VALUE) {
    const bool ok = VerifyInventoryAcl(existing, roles, profile);
    napi_value result; napi_create_object(env, &result);
    if (ok) { napi_value identity; napi_create_object(env, &identity); InventoryIdentityValue(env, identity, existing); napi_set_named_property(env, result, "identity", identity); napi_value zero; napi_create_uint32(env, 0, &zero); napi_set_named_property(env, result, "writes", zero); }
    CloseHandle(existing); CloseHandle(parent);
    if (!ok) InventoryError(env, "INVENTORY_ACCESS_DENIED", "ensure_inventory_directory");
    return ok ? result : nullptr;
  }
  if (existing_error != ERROR_FILE_NOT_FOUND) {
    CloseHandle(parent);
    InventoryError(env, existing_error == ERROR_ACCESS_DENIED ?
        "INVENTORY_ACCESS_DENIED" : "INVENTORY_IO_FAILED", "ensure_inventory_directory");
    return nullptr;
  }
  PSECURITY_DESCRIPTOR descriptor = InventorySecurityDescriptor(roles, profile);
  HANDLE created = descriptor ? OpenWindowsRelative(parent, name,
      READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES | DELETE,
      kFileCreate, VerifiedObjectType::Directory, descriptor) : INVALID_HANDLE_VALUE;
  if (descriptor) LocalFree(descriptor);
  if (created == INVALID_HANDLE_VALUE) { CloseHandle(parent); InventoryError(env, GetLastError() == ERROR_ACCESS_DENIED ? "INVENTORY_ACCESS_DENIED" : "INVENTORY_IO_FAILED", "ensure_inventory_directory"); return nullptr; }
  const bool acl_applied = InventoryAcl(created, roles, profile);
  FILE_ID_INFO created_id{};
  const bool protected_ok = acl_applied && VerifyInventoryAcl(created, roles, profile) &&
      GetFileInformationByHandleEx(created, FileIdInfo, &created_id, sizeof(created_id));
  if (!protected_ok) {
    FILE_DISPOSITION_INFO d{TRUE};
    const bool removed = SetFileInformationByHandle(created, FileDispositionInfo, &d, sizeof(d));
    CloseHandle(created);
    HANDLE probe = OpenWindowsRelative(parent, name, FILE_READ_ATTRIBUTES,
        kFileOpen, VerifiedObjectType::Directory);
    const DWORD probe_error = probe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
    const bool durable_cleanup = removed && probe == INVALID_HANDLE_VALUE &&
        probe_error == ERROR_FILE_NOT_FOUND && flush_parent();
    CloseHandle(parent);
    const uint32_t writes = 1 + (acl_applied ? 1 : 0) + (removed ? 1 : 0);
    InventoryError(env, durable_cleanup ? "INVENTORY_ACCESS_DENIED" : "INVENTORY_MANUAL_CLEANUP",
        "ensure_inventory_directory", writes, !durable_cleanup);
    return nullptr;
  }
  CloseHandle(created);
  const bool durable = flush_parent();
  HANDLE reopened = durable ? OpenWindowsRelative(parent, name, READ_CONTROL | FILE_READ_ATTRIBUTES,
      kFileOpen, VerifiedObjectType::Directory) : INVALID_HANDLE_VALUE;
  FILE_ID_INFO reopened_id{};
  const bool verified = reopened != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandleEx(reopened, FileIdInfo, &reopened_id, sizeof(reopened_id)) &&
      SameWindowsFileId(created_id, reopened_id) && VerifyInventoryAcl(reopened, roles, profile);
  if (!verified) {
    if (reopened != INVALID_HANDLE_VALUE) CloseHandle(reopened);
    HANDLE cleanup = OpenWindowsRelative(parent, name, DELETE | FILE_READ_ATTRIBUTES,
        kFileOpen, VerifiedObjectType::Directory);
    FILE_ID_INFO cleanup_id{};
    FILE_DISPOSITION_INFO disposition{TRUE};
    const bool removed = cleanup != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandleEx(cleanup, FileIdInfo, &cleanup_id, sizeof(cleanup_id)) &&
        SameWindowsFileId(created_id, cleanup_id) &&
        SetFileInformationByHandle(cleanup, FileDispositionInfo, &disposition, sizeof(disposition));
    if (cleanup != INVALID_HANDLE_VALUE) CloseHandle(cleanup);
    HANDLE probe = OpenWindowsRelative(parent, name, FILE_READ_ATTRIBUTES,
        kFileOpen, VerifiedObjectType::Directory);
    const DWORD probe_error = probe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
    const bool cleanup_durable = removed && probe == INVALID_HANDLE_VALUE &&
        probe_error == ERROR_FILE_NOT_FOUND && flush_parent();
    CloseHandle(parent);
    InventoryError(env, cleanup_durable ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
        "ensure_inventory_directory", 2 + (removed ? 1 : 0), !cleanup_durable);
    return nullptr;
  }
  napi_value result, identity, writes; napi_create_object(env, &result); napi_create_object(env, &identity); InventoryIdentityValue(env, identity, reopened); napi_set_named_property(env, result, "identity", identity); napi_create_uint32(env, 2, &writes); napi_set_named_property(env, result, "writes", writes); CloseHandle(reopened); CloseHandle(parent); return result;
}
napi_value VerifyInventoryAclWindows(napi_env env, napi_callback_info info) {
  napi_value args[3]; std::string path, profile; InventoryRoles roles{};
  if (!InventoryArgs(env, info, 3, args) || !InventoryString(env, args[0], &path) || !InventoryRolesArg(env, args[1], &roles) ||
      !InventoryString(env, args[2], &profile) || !InventoryPath(path, profile) || !CurrentInventoryActor(roles, true, true, true, true)) { InventoryError(env, "INVENTORY_INVALID", "verify_inventory_acl"); return nullptr; }
  if (!VerifyInventoryBaseWindows(roles, profile)) { InventoryError(env, "INVENTORY_ACCESS_DENIED", "verify_inventory_acl"); return nullptr; }
  HANDLE parent = INVALID_HANDLE_VALUE;
  std::wstring name;
  const bool directory = profile.find("directory") != std::string::npos;
  HANDLE h = OpenInventoryParentBoundWindows(path, roles, profile, 0, &parent, &name) ?
      OpenWindowsRelative(parent, name, READ_CONTROL | FILE_READ_ATTRIBUTES,
          kFileOpen, directory ? VerifiedObjectType::Directory : VerifiedObjectType::File) :
      INVALID_HANDLE_VALUE;
  const bool ok = h != INVALID_HANDLE_VALUE && VerifyInventoryAcl(h, roles, profile);
  if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
  if (parent != INVALID_HANDLE_VALUE) CloseHandle(parent);
  if (!ok) { InventoryError(env, "INVENTORY_ACCESS_DENIED", "verify_inventory_acl"); return nullptr; } napi_value result; napi_get_boolean(env, true, &result); return result;
}
napi_value ReadInventoryObjectWindows(napi_env env, napi_callback_info info) {
  napi_value args[4]; std::string path, profile; InventoryRoles roles{}; int64_t maximum = 0;
  if (!InventoryArgs(env, info, 4, args) || !InventoryString(env, args[0], &path) ||
      !InventoryMaximumBytes(env, args[1], &maximum) ||
      !InventoryRolesArg(env, args[2], &roles) || !InventoryString(env, args[3], &profile) ||
      !InventoryPath(path, profile) || !CurrentInventoryActor(roles, true, true, true, true)) {
    InventoryError(env, "INVENTORY_INVALID", "read_inventory_object"); return nullptr;
  }
  if (!VerifyInventoryBaseWindows(roles, profile)) { InventoryError(env, "INVENTORY_ACCESS_DENIED", "read_inventory_object"); return nullptr; }
  HANDLE parent; std::wstring name;
  if (!OpenInventoryParentBoundWindows(
          path, roles, profile, 0, &parent, &name)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "read_inventory_object"); return nullptr;
  }
  if (!VerifyInventoryAcl(parent, roles, InventoryParentProfile(profile))) {
    CloseHandle(parent); InventoryError(env, "INVENTORY_ACCESS_DENIED", "read_inventory_object"); return nullptr;
  }
  HANDLE h = OpenWindowsRelative(parent, name, GENERIC_READ | READ_CONTROL, kFileOpen, VerifiedObjectType::File);
  const DWORD open_error = h == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
  if (h == INVALID_HANDLE_VALUE && open_error == ERROR_FILE_NOT_FOUND) {
    CloseHandle(parent); napi_value absent; napi_get_null(env, &absent); return absent;
  }
  LARGE_INTEGER length{};
  FILE_ID_INFO opened_identity{};
  if (h == INVALID_HANDLE_VALUE || !VerifyInventoryAcl(h, roles, profile) ||
      !GetFileInformationByHandleEx(h, FileIdInfo, &opened_identity, sizeof(opened_identity)) ||
      !GetFileSizeEx(h, &length) || length.QuadPart < 0 || length.QuadPart > maximum) {
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    CloseHandle(parent);
    InventoryError(env, "INVENTORY_IO_FAILED", "read_inventory_object"); return nullptr;
  }
  std::vector<uint8_t> bytes(static_cast<size_t>(length.QuadPart));
  DWORD read = 0;
  const bool ok = (bytes.empty() || (ReadFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) && read == bytes.size()));
  HANDLE named = OpenWindowsRelative(parent, name, GENERIC_READ | READ_CONTROL, kFileOpen,
      VerifiedObjectType::File);
  FILE_ID_INFO named_identity{};
  LARGE_INTEGER final_length{};
  const bool stable = ok && named != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandleEx(named, FileIdInfo, &named_identity, sizeof(named_identity)) &&
      SameWindowsFileId(opened_identity, named_identity) &&
      GetFileSizeEx(named, &final_length) && final_length.QuadPart == length.QuadPart &&
      VerifyInventoryAcl(named, roles, profile);
  if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
  CloseHandle(parent);
  if (!stable) { CloseHandle(h); InventoryError(env, "INVENTORY_IO_FAILED", "read_inventory_object"); return nullptr; }
  napi_value result, data, identity; napi_create_object(env, &result); napi_create_buffer_copy(env, bytes.size(), bytes.data(), nullptr, &data); napi_set_named_property(env, result, "bytes", data);
  napi_create_object(env, &identity); InventoryIdentityValue(env, identity, h); napi_set_named_property(env, result, "identity", identity); CloseHandle(h); return result;
}
const napi_type_tag kWindowsInventoryFenceTypeTag = {0x496e76656e746f72ULL, 0x7946656e63653a34ULL};
struct WindowsInventoryFence {
  HANDLE handle = INVALID_HANDLE_VALUE;
  napi_env env;
  napi_ref release_promise = nullptr;
  napi_ref object_ref = nullptr;
  std::atomic<bool> released{false};
  uint32_t acquisition_writes = 0;
  bool acquisition_ambiguous = false;
};
struct WindowsFenceWork {
  napi_deferred deferred;
  napi_async_work work;
  WindowsInventoryFence* fence;
  bool pending = false, failed = false, release = false;
  std::chrono::steady_clock::time_point deadline{};
};
void WindowsFenceFinalize(napi_env, void* raw, void*) {
  auto* fence = static_cast<WindowsInventoryFence*>(raw);
  if (!fence->released.exchange(true) && fence->handle != INVALID_HANDLE_VALUE) {
    OVERLAPPED o{}; UnlockFileEx(fence->handle, 0, MAXDWORD, MAXDWORD, &o); CloseHandle(fence->handle);
    fence->handle = INVALID_HANDLE_VALUE;
  }
  if (fence->release_promise) napi_delete_reference(fence->env, fence->release_promise);
  if (fence->object_ref) napi_delete_reference(fence->env, fence->object_ref);
  delete fence;
}
void WindowsFenceExecute(napi_env, void* raw) { auto* work = static_cast<WindowsFenceWork*>(raw);
  if (work->release) {
    OVERLAPPED o{};
    if (work->fence->released.exchange(true) || work->fence->handle == INVALID_HANDLE_VALUE) return;
    const bool unlocked = UnlockFileEx(work->fence->handle, 0, MAXDWORD, MAXDWORD, &o) != FALSE;
    const bool closed = CloseHandle(work->fence->handle) != FALSE;
    work->failed = !unlocked || !closed;
    if (closed) work->fence->handle = INVALID_HANDLE_VALUE;
    return;
  }
  const auto end = work->deadline; OVERLAPPED o{};
  for (;;) {
    if (std::chrono::steady_clock::now() >= end) { work->pending = true; return; }
    if (LockFileEx(work->fence->handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, MAXDWORD, MAXDWORD, &o)) {
      if (std::chrono::steady_clock::now() < end) return;
      UnlockFileEx(work->fence->handle, 0, MAXDWORD, MAXDWORD, &o);
      work->pending = true; return;
    }
    const DWORD error = GetLastError(); if (error != ERROR_LOCK_VIOLATION) { work->failed = true; return; }
    if (std::chrono::steady_clock::now() >= end) { work->pending = true; return; } std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}
napi_value AcquireInventoryFenceWindows(napi_env env, napi_callback_info info) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
  napi_value args[2]; std::string path; InventoryRoles roles{};
  if (!InventoryArgs(env, info, 2, args) || !InventoryString(env, args[0], &path) || !InventoryRolesArg(env, args[1], &roles) ||
      !InventoryPath(path, "inventory-fence") || !CurrentInventoryActor(roles, true, true)) { InventoryError(env, "INVENTORY_INVALID", "acquire_inventory_fence"); return nullptr; }
  if (!VerifyInventoryBaseWindows(roles, "inventory-fence")) { InventoryError(env, "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence"); return nullptr; }
  HANDLE verified_parent = INVALID_HANDLE_VALUE; std::wstring verified_name;
  if (!OpenInventoryParentBoundWindows(
          path, roles, "inventory-fence", 0, &verified_parent, &verified_name)) {
    if (verified_parent != INVALID_HANDLE_VALUE) CloseHandle(verified_parent);
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence"); return nullptr;
  }
  FILE_ID_INFO published_fence_id{};
  uint32_t fence_writes = 0;
  bool created_by_call = false;
  HANDLE h = OpenWindowsRelative(verified_parent, verified_name,
      GENERIC_READ | READ_CONTROL, kFileOpen, VerifiedObjectType::File);
  const DWORD initial_error = h == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
  DWORD fence_open_error = initial_error;
  CloseHandle(verified_parent);
  if (h == INVALID_HANDLE_VALUE && initial_error == ERROR_FILE_NOT_FOUND &&
      CurrentInventoryActor(roles, true, false)) {
    HANDLE parent = INVALID_HANDLE_VALUE; std::wstring name;
    if (!OpenInventoryParentBoundWindows(path, roles, "inventory-fence",
            kWindowsChildMutationParentAccess, &parent, &name)) {
      InventoryError(env, "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence"); return nullptr;
    }
    if (!VerifyInventoryAcl(parent, roles, "inventory-directory")) {
      CloseHandle(parent); InventoryError(env, "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence"); return nullptr;
    }
    FILE_ID_INFO parent_id{};
    std::wstring canonical_parent;
    if (!CanonicalInventoryParent(parent, &parent_id, &canonical_parent)) {
      CloseHandle(parent);
      InventoryError(env, "CONTAINMENT_UNSUPPORTED", "acquire_inventory_fence");
      return nullptr;
    }
    auto flush_parent = [&]() {
      return FlushInventoryParent(parent, parent_id, canonical_parent);
    };
    HANDLE temporary = INVALID_HANDLE_VALUE;
    std::wstring temporary_name;
    for (unsigned attempt = 0; attempt != 128; ++attempt) {
      std::wstring token;
      if (!InventoryRandomName(&token)) break;
      temporary_name = L".inventory-publication.lock." + token;
      temporary = OpenWindowsRelative(parent, temporary_name,
          GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE,
          kFileCreate, VerifiedObjectType::File);
      if (temporary != INVALID_HANDLE_VALUE || GetLastError() != ERROR_FILE_EXISTS) break;
    }
    FILE_ID_INFO temporary_id{};
    const bool temporary_created = temporary != INVALID_HANDLE_VALUE;
    const bool temporary_known = temporary != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandleEx(temporary, FileIdInfo, &temporary_id, sizeof(temporary_id));
    const bool acl_applied = temporary != INVALID_HANDLE_VALUE &&
        InventoryAcl(temporary, roles, "inventory-fence");
    const bool prepared = acl_applied && VerifyInventoryAcl(temporary, roles, "inventory-fence") &&
        FlushFileBuffers(temporary);
    const bool renamed = prepared && RenameWindowsRelative(temporary, parent, name, false);
    const DWORD rename_error = renamed ? ERROR_SUCCESS : GetLastError();
    bool cleaned = false;
    bool cleanup_mutated = false;
    if (!renamed && temporary != INVALID_HANDLE_VALUE) {
      FILE_DISPOSITION_INFO disposition{TRUE};
      const bool delete_pending = temporary_known &&
          SetFileInformationByHandle(temporary, FileDispositionInfo, &disposition, sizeof(disposition));
      cleanup_mutated = delete_pending;
      CloseHandle(temporary);
      temporary = INVALID_HANDLE_VALUE;
      HANDLE probe = OpenWindowsRelative(parent, temporary_name, FILE_READ_ATTRIBUTES,
          kFileOpen, VerifiedObjectType::File);
      const DWORD probe_error = probe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
      if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
      cleaned = delete_pending && probe == INVALID_HANDLE_VALUE &&
          probe_error == ERROR_FILE_NOT_FOUND && flush_parent();
    }
    if (temporary != INVALID_HANDLE_VALUE) CloseHandle(temporary);
    bool published = renamed && flush_parent();
    bool rolled_back = false;
    bool rollback_mutated = false;
    if (renamed && !published) {
      HANDLE retained = OpenWindowsRelative(parent, name, DELETE | FILE_READ_ATTRIBUTES,
          kFileOpen, VerifiedObjectType::File);
      FILE_ID_INFO retained_id{};
      FILE_DISPOSITION_INFO disposition{TRUE};
      const bool delete_pending = retained != INVALID_HANDLE_VALUE && temporary_known &&
          GetFileInformationByHandleEx(retained, FileIdInfo, &retained_id, sizeof(retained_id)) &&
          SameWindowsFileId(temporary_id, retained_id) &&
          SetFileInformationByHandle(retained, FileDispositionInfo, &disposition, sizeof(disposition));
      rollback_mutated = delete_pending;
      if (retained != INVALID_HANDLE_VALUE) CloseHandle(retained);
      HANDLE probe = OpenWindowsRelative(parent, name, FILE_READ_ATTRIBUTES,
          kFileOpen, VerifiedObjectType::File);
      const DWORD probe_error = probe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
      if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
      rolled_back = delete_pending && probe == INVALID_HANDLE_VALUE &&
          probe_error == ERROR_FILE_NOT_FOUND && flush_parent();
    }
    if (published) {
      h = OpenWindowsRelative(parent, name, GENERIC_READ | READ_CONTROL,
          kFileOpen, VerifiedObjectType::File);
      fence_open_error = h == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    }
    CloseHandle(parent);
    if (!published) {
      const uint32_t writes = (temporary_created ? 1 : 0) +
          (acl_applied ? 1 : 0) + (renamed ? 1 : 0) +
          ((cleanup_mutated || rollback_mutated) ? 1 : 0);
      InventoryError(env, (cleaned || rolled_back) ?
          (rename_error == ERROR_FILE_EXISTS || rename_error == ERROR_ALREADY_EXISTS ?
              "INVENTORY_STALE" : rename_error == ERROR_CALL_NOT_IMPLEMENTED ||
                  rename_error == ERROR_NOT_SUPPORTED ?
                      "CONTAINMENT_UNSUPPORTED" : "INVENTORY_IO_FAILED") :
          "INVENTORY_MANUAL_CLEANUP", "acquire_inventory_fence", writes,
          !(cleaned || rolled_back));
      return nullptr;
    }
    published_fence_id = temporary_id;
    fence_writes = 3;
    created_by_call = true;
  }
  FILE_ID_INFO reopened_fence_id{};
  const bool reopened_exact = h != INVALID_HANDLE_VALUE &&
      VerifyInventoryAcl(h, roles, "inventory-fence") &&
      GetFileInformationByHandleEx(h, FileIdInfo, &reopened_fence_id,
          sizeof(reopened_fence_id)) &&
      (!created_by_call || SameWindowsFileId(published_fence_id, reopened_fence_id));
  if (!reopened_exact) {
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    InventoryError(env, created_by_call ? "INVENTORY_MANUAL_CLEANUP" :
        (h == INVALID_HANDLE_VALUE && fence_open_error == ERROR_FILE_NOT_FOUND ?
            "INVENTORY_STALE" : "INVENTORY_IO_FAILED"),
        "acquire_inventory_fence", fence_writes, created_by_call);
    return nullptr;
  }
  LARGE_INTEGER fence_length{};
  if (!GetFileSizeEx(h, &fence_length) || fence_length.QuadPart != 0) {
    CloseHandle(h);
    InventoryError(env, created_by_call ? "INVENTORY_MANUAL_CLEANUP" :
        "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence", fence_writes,
        created_by_call);
    return nullptr;
  }
  auto* fence = new WindowsInventoryFence{h, env};
  fence->acquisition_writes = fence_writes;
  fence->acquisition_ambiguous = false;
  napi_value promise; napi_deferred deferred; napi_create_promise(env, &deferred, &promise);
  auto* work = new WindowsFenceWork{deferred, nullptr, fence, false, false, false, deadline};
  const napi_status create_status = CreateInventoryAsyncWork(
    env, "inventory.acquire_fence", WindowsFenceExecute,
    [](napi_env complete, napi_status, void* raw) { auto* work = static_cast<WindowsFenceWork*>(raw);
      if (work->pending || work->failed) { if (work->fence->handle != INVALID_HANDLE_VALUE) CloseHandle(work->fence->handle); napi_reject_deferred(complete, work->deferred, InventoryErrorValue(complete, work->pending ? "INVENTORY_PENDING" : "INVENTORY_IO_FAILED", "acquire_inventory_fence", work->fence->acquisition_writes, work->fence->acquisition_ambiguous)); delete work->fence; }
      else { napi_value object, release; napi_create_object(complete, &object); napi_type_tag_object(complete, object, &kWindowsInventoryFenceTypeTag);
        napi_create_function(complete, "release", NAPI_AUTO_LENGTH, [](napi_env e, napi_callback_info i) -> napi_value { void* data; napi_get_cb_info(e, i, nullptr, nullptr, nullptr, &data); auto* fence = static_cast<WindowsInventoryFence*>(data); napi_value promise;
          if (fence->release_promise) { napi_get_reference_value(e, fence->release_promise, &promise); return promise; }
          napi_deferred deferred; napi_create_promise(e, &deferred, &promise);
          if (napi_create_reference(e, promise, 1, &fence->release_promise) != napi_ok ||
              [&]() { uint32_t count = 0; return napi_reference_ref(e, fence->object_ref, &count); }() != napi_ok) {
            napi_reject_deferred(e, deferred, InventoryErrorValue(e, "INVENTORY_IO_FAILED", "release_inventory_fence", 0, true));
            return promise;
          }
          auto* release = new WindowsFenceWork{deferred, nullptr, fence, false, false, true};
          const napi_status release_create_status = CreateInventoryAsyncWork(
              e, "inventory.release_fence", WindowsFenceExecute,
              [](napi_env ce, napi_status, void* rr) {
                auto* item = static_cast<WindowsFenceWork*>(rr);
                if (item->failed) napi_reject_deferred(
                    ce, item->deferred,
                    InventoryErrorValue(ce, "INVENTORY_IO_FAILED",
                        "release_inventory_fence", 0, true));
                else {
                  napi_value u;
                  napi_get_undefined(ce, &u);
                  napi_resolve_deferred(ce, item->deferred, u);
                }
                uint32_t count = 0;
                napi_reference_unref(ce, item->fence->object_ref, &count);
                napi_delete_async_work(ce, item->work);
                delete item;
              }, release, &release->work);
          const napi_status release_queue_status =
              release_create_status == napi_ok
                  ? napi_queue_async_work(e, release->work)
                  : release_create_status;
          if (release_queue_status != napi_ok) {
            uint32_t count = 0;
            napi_reference_unref(e, fence->object_ref, &count);
            if (release->work) napi_delete_async_work(e, release->work);
            delete release;
            napi_reject_deferred(
                e, deferred,
                InventoryErrorValue(e, "INVENTORY_IO_FAILED",
                    "release_inventory_fence", 0, true));
          }
          return promise;
        }, work->fence, &release);
        napi_set_named_property(complete, object, "release", release); napi_wrap(complete, object, work->fence, WindowsFenceFinalize, nullptr, nullptr); napi_create_reference(complete, object, 0, &work->fence->object_ref); napi_resolve_deferred(complete, work->deferred, object); }
      napi_delete_async_work(complete, work->work); delete work; }, work, &work->work);
  const napi_status queue_status = create_status == napi_ok
      ? napi_queue_async_work(env, work->work)
      : create_status;
  if (queue_status != napi_ok) {
    if (work->work) napi_delete_async_work(env, work->work);
    CloseHandle(h);
    delete fence;
    delete work;
    napi_reject_deferred(env, deferred,
        InventoryErrorValue(env, "INVENTORY_IO_FAILED",
            "acquire_inventory_fence", fence_writes));
  }
  return promise;
}
napi_value PublishInventoryObjectAtomicWindows(napi_env env, napi_callback_info info) {
  napi_value args[6]; std::string path, prefix, profile; InventoryRoles roles{}; std::vector<uint8_t> bytes; napi_valuetype expected_type;
  // Keep the validation explicit: profile must be a file profile, M/SYSTEM is
  // the sole publisher, and expected identity is either null or an exact object.
  bool directory = false;
  if (!InventoryArgs(env, info, 6, args) || !InventoryString(env, args[0], &path) || !InventoryString(env, args[1], &prefix) || !SafeName(prefix) ||
      !InventoryBufferArg(env, info, 2, &bytes) || !InventoryRolesArg(env, args[4], &roles) || !InventoryString(env, args[5], &profile) ||
      !InventoryPath(path, profile) || !InventoryProfile(profile, &directory) || directory ||
      profile == "inventory-fence" ||
      napi_typeof(env, args[3], &expected_type) != napi_ok || (expected_type != napi_null && expected_type != napi_object) ||
      bytes.size() > kInventoryMaxBytes ||
      !CurrentInventoryActor(roles, profile != "inventory-floor", profile == "inventory-floor")) {
    InventoryError(env, "INVENTORY_INVALID", "publish_inventory_object_atomic"); return nullptr;
  }
  const char* identity_fields[] = {"volumeSerial", "fileId", "attributes", "owner"};
  if (expected_type == napi_object && !InventoryOrdinaryDataObject(env, args[3], identity_fields, 4)) {
    InventoryError(env, "INVENTORY_INVALID", "publish_inventory_object_atomic"); return nullptr;
  }
  if (!VerifyInventoryBaseWindows(roles, profile)) { InventoryError(env, "INVENTORY_ACCESS_DENIED", "publish_inventory_object_atomic"); return nullptr; }
  HANDLE parent; std::wstring name;
  if (!OpenInventoryParentBoundWindows(
          path, roles, profile, kWindowsChildMutationParentAccess, &parent, &name)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "publish_inventory_object_atomic"); return nullptr;
  }
  if (!VerifyInventoryAcl(parent, roles, InventoryParentProfile(profile))) {
    CloseHandle(parent); InventoryError(env, "INVENTORY_ACCESS_DENIED", "publish_inventory_object_atomic"); return nullptr;
  }
  FILE_ID_INFO parent_id{};
  std::wstring canonical_parent;
  if (!CanonicalInventoryParent(parent, &parent_id, &canonical_parent) ||
      !InventoryParentStable(parent, parent_id, canonical_parent)) {
    CloseHandle(parent); InventoryError(env, "CONTAINMENT_UNSUPPORTED", "publish_inventory_object_atomic"); return nullptr;
  }
  const std::wstring destination_path = InventoryChildPath(canonical_parent, name);
  std::wstring temp;
  HANDLE candidate = INVALID_HANDLE_VALUE;
  for (unsigned attempt = 0; attempt != 128; ++attempt) {
    std::wstring token;
    if (!InventoryRandomName(&token)) break;
    temp = L"." + Wide(prefix) + L"." + token;
    candidate = OpenWindowsRelative(parent, temp, GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE, kFileCreate, VerifiedObjectType::File);
    if (candidate != INVALID_HANDLE_VALUE || GetLastError() != ERROR_FILE_EXISTS) break;
  }
  uint32_t writes = 0;
  if (candidate == INVALID_HANDLE_VALUE) { CloseHandle(parent); InventoryError(env, "INVENTORY_IO_FAILED", "publish_inventory_object_atomic"); return nullptr; }
  FILE_ID_INFO candidate_id{};
  const bool candidate_known = GetFileInformationByHandleEx(
      candidate, FileIdInfo, &candidate_id, sizeof(candidate_id));
  writes = 1; DWORD written = 0;
  auto flush_parent = [&]() {
    return FlushInventoryParent(parent, parent_id, canonical_parent);
  };
  auto discard_candidate = [&]() {
    FILE_DISPOSITION_INFO disposition{TRUE};
    const bool delete_pending = InventoryParentStable(parent, parent_id, canonical_parent) &&
        candidate != INVALID_HANDLE_VALUE && candidate_known &&
        SetFileInformationByHandle(candidate, FileDispositionInfo, &disposition, sizeof(disposition));
    if (delete_pending) ++writes;
    if (candidate != INVALID_HANDLE_VALUE) CloseHandle(candidate);
    candidate = INVALID_HANDLE_VALUE;
    HANDLE probe = OpenWindowsRelative(parent, temp, FILE_READ_ATTRIBUTES,
        kFileOpen, VerifiedObjectType::File);
    const DWORD probe_error = probe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
    return delete_pending && probe == INVALID_HANDLE_VALUE &&
        probe_error == ERROR_FILE_NOT_FOUND && flush_parent();
  };
  if ((!bytes.empty() && (!WriteFile(candidate, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) || written != bytes.size()))) {
    const bool removed = discard_candidate(); CloseHandle(candidate); CloseHandle(parent);
    InventoryError(env, removed ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, !removed); return nullptr;
  }
  writes++;
  const bool acl_applied = InventoryAcl(candidate, roles, profile);
  if (acl_applied) ++writes;
  if (!acl_applied || !VerifyInventoryAcl(candidate, roles, profile) ||
      !FlushFileBuffers(candidate)) {
    const bool removed = discard_candidate(); CloseHandle(candidate); CloseHandle(parent);
    InventoryError(env, removed ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, !removed); return nullptr;
  }
  FILE_ID_INFO verified_candidate_id{};
  std::string candidate_serial, candidate_file, candidate_owner;
  uint32_t candidate_attributes = 0;
  if (!candidate_known ||
      !GetFileInformationByHandleEx(candidate, FileIdInfo, &verified_candidate_id,
          sizeof(verified_candidate_id)) ||
      !SameWindowsFileId(candidate_id, verified_candidate_id) ||
      !InventoryIdentity(candidate, &candidate_serial, &candidate_file, &candidate_attributes, &candidate_owner)) {
    const bool removed = discard_candidate(); CloseHandle(candidate); CloseHandle(parent);
    InventoryError(env, removed ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, !removed); return nullptr;
  }
  HANDLE previous = OpenWindowsRelative(parent, name, GENERIC_READ | READ_CONTROL | DELETE, kFileOpen, VerifiedObjectType::File);
  const DWORD previous_error = previous == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
  const bool present = previous != INVALID_HANDLE_VALUE;
  if (!present && previous_error != ERROR_FILE_NOT_FOUND) {
    const bool removed = discard_candidate();
    CloseHandle(parent);
    InventoryError(env, removed ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, !removed);
    return nullptr;
  }
  if ((!present && expected_type != napi_null) || (present && (expected_type == napi_null || !InventoryIdentityArg(env, args[3], previous)))) {
    if (previous != INVALID_HANDLE_VALUE) CloseHandle(previous);
    const bool removed = discard_candidate(); CloseHandle(candidate); CloseHandle(parent);
    InventoryError(env, removed ? "INVENTORY_STALE" : "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, !removed); return nullptr;
  }
  FILE_ID_INFO predecessor_id{};
  std::string predecessor_serial, predecessor_file, predecessor_owner;
  uint32_t predecessor_attributes = 0;
  if (present && !GetFileInformationByHandleEx(previous, FileIdInfo, &predecessor_id, sizeof(predecessor_id))) {
    CloseHandle(previous); const bool removed = discard_candidate(); CloseHandle(candidate); CloseHandle(parent);
    InventoryError(env, removed ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, !removed); return nullptr;
  }
  if (present && !InventoryIdentity(previous, &predecessor_serial, &predecessor_file,
      &predecessor_attributes, &predecessor_owner)) {
    CloseHandle(previous); const bool removed = discard_candidate(); CloseHandle(candidate); CloseHandle(parent);
    InventoryError(env, removed ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, !removed); return nullptr;
  }
  bool published = false;
  bool publication_mutated = false;
  std::wstring backup;
  if (!present) {
    publication_mutated = InventoryParentStable(parent, parent_id, canonical_parent) &&
        RenameWindowsRelative(candidate, parent, name, false);
    published = publication_mutated &&
        InventoryParentStable(parent, parent_id, canonical_parent);
  }
  else {
    CloseHandle(candidate); candidate = INVALID_HANDLE_VALUE;
    const std::wstring temporary_path = InventoryChildPath(canonical_parent, temp);
    for (unsigned attempt = 0; attempt != 128; ++attempt) {
      std::wstring token;
      if (!InventoryRandomName(&token)) break;
      backup = L"." + Wide(prefix) + L".backup." + token;
      const std::wstring backup_path = InventoryChildPath(canonical_parent, backup);
      publication_mutated = InventoryParentStable(parent, parent_id, canonical_parent) &&
          ReplaceFileW(destination_path.c_str(), temporary_path.c_str(), backup_path.c_str(),
              0, nullptr, nullptr) != FALSE;
      published = publication_mutated &&
          InventoryParentStable(parent, parent_id, canonical_parent);
      if (published || GetLastError() != ERROR_FILE_EXISTS) break;
    }
  }
  if (publication_mutated) ++writes;
  const DWORD publication_error = GetLastError();
  if (previous != INVALID_HANDLE_VALUE) CloseHandle(previous);
  if (!published) {
    bool removed = false;
    if (candidate != INVALID_HANDLE_VALUE) {
      removed = discard_candidate(); CloseHandle(candidate);
    } else {
      HANDLE leftover = OpenWindowsRelative(parent, temp, GENERIC_READ | DELETE, kFileOpen,
          VerifiedObjectType::File);
      HANDLE retained = OpenWindowsRelative(parent, name, GENERIC_READ | READ_CONTROL, kFileOpen,
          VerifiedObjectType::File);
      FILE_ID_INFO leftover_id{};
      const bool destination_is_predecessor = present && retained != INVALID_HANDLE_VALUE &&
          InventoryIdentityArg(env, args[3], retained);
      const bool leftover_is_candidate = leftover != INVALID_HANDLE_VALUE &&
          GetFileInformationByHandleEx(leftover, FileIdInfo, &leftover_id, sizeof(leftover_id)) &&
          SameWindowsFileId(leftover_id, candidate_id);
      if (retained != INVALID_HANDLE_VALUE) CloseHandle(retained);
      if (leftover != INVALID_HANDLE_VALUE) {
        FILE_DISPOSITION_INFO disposition{TRUE};
        const bool delete_pending = destination_is_predecessor && leftover_is_candidate &&
            InventoryParentStable(parent, parent_id, canonical_parent) &&
            SetFileInformationByHandle(leftover, FileDispositionInfo, &disposition, sizeof(disposition));
        if (delete_pending) ++writes;
        CloseHandle(leftover);
        leftover = INVALID_HANDLE_VALUE;
        HANDLE probe = OpenWindowsRelative(parent, temp, FILE_READ_ATTRIBUTES,
            kFileOpen, VerifiedObjectType::File);
        const DWORD probe_error = probe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
        removed = delete_pending && probe == INVALID_HANDLE_VALUE &&
            probe_error == ERROR_FILE_NOT_FOUND && flush_parent();
      }
    }
    CloseHandle(parent);
    InventoryError(env, removed ?
        (publication_error == ERROR_FILE_EXISTS || publication_error == ERROR_ALREADY_EXISTS ?
            "INVENTORY_STALE" : publication_error == ERROR_ACCESS_DENIED ?
                "INVENTORY_ACCESS_DENIED" : publication_error == ERROR_CALL_NOT_IMPLEMENTED ||
                    publication_error == ERROR_NOT_SUPPORTED ?
                        "CONTAINMENT_UNSUPPORTED" : "INVENTORY_IO_FAILED") :
        "INVENTORY_MANUAL_CLEANUP", "publish_inventory_object_atomic", writes, !removed); return nullptr;
  }
  HANDLE result = InventoryParentStable(parent, parent_id, canonical_parent) ?
      OpenWindowsRelative(parent, name, GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
          kFileOpen, VerifiedObjectType::File) : INVALID_HANDLE_VALUE;
  HANDLE displaced = present && InventoryParentStable(parent, parent_id, canonical_parent) ?
      OpenWindowsRelative(parent, backup,
          GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE,
          kFileOpen, VerifiedObjectType::File) : INVALID_HANDLE_VALUE;
  FILE_ID_INFO result_id{}, displaced_id{};
  std::string result_serial, result_file, result_owner;
  uint32_t result_attributes = 0;
  const bool result_is_candidate = result != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandleEx(result, FileIdInfo, &result_id, sizeof(result_id)) &&
      result_id.VolumeSerialNumber == candidate_id.VolumeSerialNumber &&
      std::memcmp(result_id.FileId.Identifier, candidate_id.FileId.Identifier, sizeof(candidate_id.FileId.Identifier)) == 0 &&
      InventoryIdentity(result, &result_serial, &result_file, &result_attributes, &result_owner) &&
      result_serial == candidate_serial && result_file == candidate_file &&
      result_attributes == candidate_attributes && result_owner == candidate_owner &&
      VerifyInventoryAcl(result, roles, profile) && WindowsInventoryBytesEqual(result, bytes);
  std::string displaced_serial, displaced_file, displaced_owner;
  uint32_t displaced_attributes = 0;
  const bool displaced_is_predecessor = !present || (displaced != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandleEx(displaced, FileIdInfo, &displaced_id, sizeof(displaced_id)) &&
      displaced_id.VolumeSerialNumber == predecessor_id.VolumeSerialNumber &&
      std::memcmp(displaced_id.FileId.Identifier, predecessor_id.FileId.Identifier, sizeof(predecessor_id.FileId.Identifier)) == 0 &&
      InventoryIdentity(displaced, &displaced_serial, &displaced_file, &displaced_attributes, &displaced_owner) &&
      displaced_serial == predecessor_serial && displaced_file == predecessor_file &&
      displaced_attributes == predecessor_attributes && displaced_owner == predecessor_owner);
  const bool durable = result_is_candidate && displaced_is_predecessor && FlushFileBuffers(result) &&
      (!present || FlushFileBuffers(displaced)) && flush_parent();
  if (candidate != INVALID_HANDLE_VALUE) { CloseHandle(candidate); candidate = INVALID_HANDLE_VALUE; }
  if (!durable) {
    if (result != INVALID_HANDLE_VALUE) CloseHandle(result);
    if (displaced != INVALID_HANDLE_VALUE) CloseHandle(displaced);
    if (!present) {
      HANDLE cleanup = InventoryParentStable(parent, parent_id, canonical_parent) ?
          OpenWindowsRelative(parent, name, DELETE | FILE_READ_ATTRIBUTES,
              kFileOpen, VerifiedObjectType::File) : INVALID_HANDLE_VALUE;
      FILE_ID_INFO cleanup_id{};
      FILE_DISPOSITION_INFO disposition{TRUE};
      const bool delete_pending = cleanup != INVALID_HANDLE_VALUE &&
          GetFileInformationByHandleEx(cleanup, FileIdInfo, &cleanup_id, sizeof(cleanup_id)) &&
          SameWindowsFileId(candidate_id, cleanup_id) &&
          SetFileInformationByHandle(cleanup, FileDispositionInfo, &disposition, sizeof(disposition));
      if (cleanup != INVALID_HANDLE_VALUE) CloseHandle(cleanup);
      HANDLE probe = OpenWindowsRelative(parent, name, FILE_READ_ATTRIBUTES,
          kFileOpen, VerifiedObjectType::File);
      const DWORD probe_error = probe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
      if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
      const bool rolled_back = delete_pending && probe == INVALID_HANDLE_VALUE &&
          probe_error == ERROR_FILE_NOT_FOUND && flush_parent();
      CloseHandle(parent);
      InventoryError(env, rolled_back ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
          "publish_inventory_object_atomic", writes + (delete_pending ? 1 : 0), !rolled_back);
      return nullptr;
    }
    if (!displaced_is_predecessor) {
      CloseHandle(parent);
      InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
          "publish_inventory_object_atomic", writes, true);
      return nullptr;
    }
    const std::wstring backup_path = InventoryChildPath(canonical_parent, backup);
    const std::wstring rollback_temp = InventoryChildPath(canonical_parent, temp);
    const bool rollback_mutated = InventoryParentStable(parent, parent_id, canonical_parent) &&
        ReplaceFileW(destination_path.c_str(), backup_path.c_str(), rollback_temp.c_str(),
        0, nullptr, nullptr) != FALSE;
    const bool rolled_back = rollback_mutated &&
        InventoryParentStable(parent, parent_id, canonical_parent);
    HANDLE restored = rolled_back ? OpenWindowsRelative(
        parent, name, GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        kFileOpen, VerifiedObjectType::File) : INVALID_HANDLE_VALUE;
    std::string restored_serial, restored_file, restored_owner;
    uint32_t restored_attributes = 0;
    const bool restored_exact = restored != INVALID_HANDLE_VALUE &&
        InventoryIdentity(restored, &restored_serial, &restored_file, &restored_attributes, &restored_owner) &&
        restored_serial == predecessor_serial && restored_file == predecessor_file &&
        restored_attributes == predecessor_attributes && restored_owner == predecessor_owner &&
        VerifyInventoryAcl(restored, roles, profile) && FlushFileBuffers(restored) && flush_parent();
    if (restored != INVALID_HANDLE_VALUE) CloseHandle(restored);
    if (!restored_exact) {
      CloseHandle(parent);
      InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
          "publish_inventory_object_atomic",
          writes + (rollback_mutated ? 1 : 0), true);
      return nullptr;
    }
    HANDLE residual = OpenWindowsRelative(parent, temp, GENERIC_READ | DELETE, kFileOpen, VerifiedObjectType::File);
    FILE_DISPOSITION_INFO disposition{TRUE};
    const bool residual_delete_pending = residual != INVALID_HANDLE_VALUE &&
        InventoryParentStable(parent, parent_id, canonical_parent) &&
        SetFileInformationByHandle(residual, FileDispositionInfo, &disposition, sizeof(disposition));
    if (residual != INVALID_HANDLE_VALUE) CloseHandle(residual);
    HANDLE residual_probe = OpenWindowsRelative(parent, temp, FILE_READ_ATTRIBUTES,
        kFileOpen, VerifiedObjectType::File);
    const DWORD residual_error = residual_probe == INVALID_HANDLE_VALUE ?
        GetLastError() : ERROR_SUCCESS;
    if (residual_probe != INVALID_HANDLE_VALUE) CloseHandle(residual_probe);
    const bool rollback_durable = residual_delete_pending &&
        residual_probe == INVALID_HANDLE_VALUE && residual_error == ERROR_FILE_NOT_FOUND &&
        flush_parent();
    CloseHandle(parent);
    if (!rollback_durable) {
      InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
          "publish_inventory_object_atomic",
          writes + 1 + (residual_delete_pending ? 1 : 0), true);
      return nullptr;
    }
    InventoryError(env, "INVENTORY_IO_FAILED", "publish_inventory_object_atomic", writes + 2);
    return nullptr;
  }
  if (displaced != INVALID_HANDLE_VALUE) {
    FILE_DISPOSITION_INFO disposition{TRUE};
    const bool delete_pending = InventoryParentStable(parent, parent_id, canonical_parent) &&
        SetFileInformationByHandle(displaced, FileDispositionInfo, &disposition, sizeof(disposition));
    CloseHandle(displaced);
    HANDLE backup_probe = OpenWindowsRelative(parent, backup, FILE_READ_ATTRIBUTES,
        kFileOpen, VerifiedObjectType::File);
    const DWORD backup_error = backup_probe == INVALID_HANDLE_VALUE ?
        GetLastError() : ERROR_SUCCESS;
    if (backup_probe != INVALID_HANDLE_VALUE) CloseHandle(backup_probe);
    const bool backup_durable = delete_pending && backup_probe == INVALID_HANDLE_VALUE &&
        backup_error == ERROR_FILE_NOT_FOUND && flush_parent();
    if (!backup_durable) {
      if (result != INVALID_HANDLE_VALUE) CloseHandle(result);
      CloseHandle(parent); InventoryError(env, "INVENTORY_MANUAL_CLEANUP", "publish_inventory_object_atomic",
          writes + (delete_pending ? 1 : 0), true); return nullptr;
    }
    ++writes;
  }
  HANDLE retained = InventoryParentStable(parent, parent_id, canonical_parent) ?
      OpenWindowsRelative(parent, name, GENERIC_READ | READ_CONTROL,
          kFileOpen, VerifiedObjectType::File) : INVALID_HANDLE_VALUE;
  FILE_ID_INFO retained_id{};
  const bool retained_exact = retained != INVALID_HANDLE_VALUE &&
      GetFileInformationByHandleEx(retained, FileIdInfo, &retained_id, sizeof(retained_id)) &&
      SameWindowsFileId(candidate_id, retained_id) &&
      VerifyInventoryAcl(retained, roles, profile) &&
      WindowsInventoryBytesEqual(retained, bytes);
  if (result != INVALID_HANDLE_VALUE) CloseHandle(result);
  if (!retained_exact) {
    if (retained != INVALID_HANDLE_VALUE) CloseHandle(retained);
    CloseHandle(parent);
    InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, true);
    return nullptr;
  }
  napi_value answer, identity, value; napi_create_object(env, &answer); napi_create_object(env, &identity); InventoryIdentityValue(env, identity, retained); napi_set_named_property(env, answer, "identity", identity); napi_create_uint32(env, writes, &value); napi_set_named_property(env, answer, "writes", value); CloseHandle(retained); CloseHandle(parent); return answer;
}
#else
struct InventoryRoles { uid_t management, bot, recovery, daemon, system; };

bool InventoryRandomName(std::string* value) {
  std::array<unsigned char, 16> bytes{};
#ifdef __linux__
  size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t read_bytes = getrandom(bytes.data() + offset, bytes.size() - offset, 0);
    if (read_bytes <= 0) return false;
    offset += static_cast<size_t>(read_bytes);
  }
#else
  int random = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (random < 0) return false;
  size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t read_bytes = read(random, bytes.data() + offset, bytes.size() - offset);
    if (read_bytes <= 0) { close(random); return false; }
    offset += static_cast<size_t>(read_bytes);
  }
  close(random);
#endif
  static constexpr char hex[] = "0123456789abcdef";
  value->clear(); value->reserve(32);
  for (unsigned char byte : bytes) { value->push_back(hex[byte >> 4]); value->push_back(hex[byte & 15]); }
  return true;
}

bool InventoryRole(napi_env env, napi_value value, uid_t* uid) {
  napi_value captured[2];
  const char* fields[] = {"kind", "value"};
  if (!InventoryOrdinaryDataObject(env, value, fields, 2, captured)) return false;
  std::string kind_text, principal_text;
  return InventoryString(env, captured[0], &kind_text) &&
      InventoryString(env, captured[1], &principal_text) &&
      kind_text == "uid" && ParseUid(principal_text, uid);
}

bool InventoryRolesArg(napi_env env, napi_value value, InventoryRoles* roles) {
  napi_value captured[5];
  const char* fields[] = {"management", "bot", "recovery", "daemon", "system"};
  if (!InventoryOrdinaryDataObject(env, value, fields, 5, captured)) return false;
  uid_t* values[] = {&roles->management, &roles->bot, &roles->recovery, &roles->daemon, &roles->system};
  for (size_t i = 0; i < 5; ++i)
    if (!InventoryRole(env, captured[i], values[i])) return false;
  const uid_t all[] = {roles->management, roles->bot, roles->recovery, roles->daemon, roles->system};
  if (roles->system != 0) return false;
  for (size_t i = 0; i < 5; ++i) {
    struct passwd* record = getpwuid(all[i]);
    if (record == nullptr) return false;
    for (size_t j = i + 1; j < 5; ++j) if (all[i] == all[j]) return false;
  }
  return true;
}

bool InventoryHostKey(const std::string& value) {
  if (value.size() != 64) return false;
  for (char c : value) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  return true;
}

bool InventoryProfile(const std::string& profile, bool* directory, uid_t roles[5],
                      const InventoryRoles& input) {
  roles[0] = input.management; roles[1] = input.bot; roles[2] = input.recovery;
  roles[3] = input.daemon; roles[4] = input.system;
  *directory = profile == "inventory-directory" || profile == "reader-directory";
  return *directory || profile == "inventory-file" || profile == "inventory-commit" ||
      profile == "inventory-fence" || profile == "inventory-manual-cleanup" ||
      profile == "inventory-floor";
}

const char* InventoryParentProfile(const std::string& profile) {
  return profile == "reader-directory" || profile == "inventory-floor" ? "reader-directory" :
      "inventory-directory";
}

mode_t InventoryMode(const std::string& profile, size_t role, bool directory) {
  const bool reader_root = profile == "reader-directory" || profile == "inventory-floor";
  const size_t owner = reader_root ? 3 : 0;
  mode_t bits = role == owner || role == 4 ? S_IRUSR | S_IWUSR : (role == 1 ? 0 : S_IRUSR);
  if (directory && bits != 0) bits |= S_IXUSR;
  return bits;
}

bool ApplyInventoryAcl(int fd, const InventoryRoles& input, const std::string& profile) {
  uid_t roles[5]; bool directory;
  struct stat st{};
  if (!InventoryProfile(profile, &directory, roles, input) || fstat(fd, &st) != 0 ||
      (directory != static_cast<bool>(S_ISDIR(st.st_mode)))) return false;
  const size_t owner = (profile == "reader-directory" || profile == "inventory-floor") ? 3 : 0;
  if (st.st_uid != roles[owner]) return false;
  acl_t acl = acl_init(8);
  if (!acl) return false;
  bool ok = true; acl_entry_t entry; acl_permset_t perms;
  auto add = [&](acl_tag_t tag, const uid_t* uid, mode_t mode) {
    if (!ok || acl_create_entry(&acl, &entry) != 0 || acl_set_tag_type(entry, tag) != 0 ||
        (uid && acl_set_qualifier(entry, uid) != 0) || acl_get_permset(entry, &perms) != 0 ||
        !SetPerms(perms, mode)) ok = false;
  };
  add(ACL_USER_OBJ, nullptr, InventoryMode(profile, owner, directory));
  for (size_t i = 0; i < 5; ++i) if (i != owner) add(ACL_USER, &roles[i], InventoryMode(profile, i, directory));
  mode_t mask = 0; for (size_t i = 0; i < 5; ++i) mask |= InventoryMode(profile, i, directory);
  add(ACL_GROUP_OBJ, nullptr, 0); add(ACL_MASK, nullptr, mask); add(ACL_OTHER, nullptr, 0);
  ok = ok && acl_valid(acl) == 0 && acl_set_fd(fd, acl) == 0;
  acl_free(acl);
  return ok && fsync(fd) == 0;
}

bool HasEmptyInventoryDefaultAcl(int fd) {
#ifdef __linux__
  const std::string descriptor_path = "/proc/self/fd/" + std::to_string(fd);
  acl_t defaults = acl_get_file(descriptor_path.c_str(), ACL_TYPE_DEFAULT);
  if (!defaults) return false;
  acl_entry_t entry;
  const bool empty =
      acl_get_entry(defaults, ACL_FIRST_ENTRY, &entry) == 0;
  acl_free(defaults);
  return empty;
#else
  return false;
#endif
}

const char* InventoryBasePath(const std::string& profile);
bool VerifyInventoryAclExact(int fd, const InventoryRoles& input, const std::string& profile) {
  uid_t roles[5]; bool directory = false; struct stat st{};
  if (!InventoryProfile(profile, &directory, roles, input) || fstat(fd, &st) != 0 ||
      directory != static_cast<bool>(S_ISDIR(st.st_mode))) return false;
  const size_t owner = (profile == "reader-directory" || profile == "inventory-floor") ? 3 : 0;
  if (st.st_uid != roles[owner]) return false;
  acl_t acl = acl_get_fd(fd); if (!acl) return false;
  bool user_obj = false, group = false, mask = false, other = false, seen[5] = {};
  acl_entry_t entry; int state = ACL_FIRST_ENTRY; size_t count = 0; bool ok = true;
  while (ok && acl_get_entry(acl, state, &entry) == 1) {
    state = ACL_NEXT_ENTRY; ++count; acl_tag_t tag; acl_permset_t perms;
    if (acl_get_tag_type(entry, &tag) != 0 || acl_get_permset(entry, &perms) != 0) { ok = false; break; }
    auto has = [&](acl_perm_t permission) { return acl_get_perm(perms, permission) == 1; };
    const mode_t actual = (has(ACL_READ) ? S_IRUSR : 0) | (has(ACL_WRITE) ? S_IWUSR : 0) |
        (has(ACL_EXECUTE) ? S_IXUSR : 0);
    if (tag == ACL_USER_OBJ) { ok = !user_obj && actual == InventoryMode(profile, owner, directory); user_obj = true; }
    else if (tag == ACL_USER) {
      uid_t* uid = static_cast<uid_t*>(acl_get_qualifier(entry)); ssize_t role = -1;
      if (uid) for (size_t i = 0; i < 5; ++i) if (*uid == roles[i] && i != owner) role = static_cast<ssize_t>(i);
      if (uid) acl_free(uid);
      if (role < 0 || seen[role] || actual != InventoryMode(profile, role, directory)) ok = false;
      else seen[role] = true;
    } else if (tag == ACL_GROUP_OBJ) { ok = !group && actual == 0; group = true; }
    else if (tag == ACL_MASK) {
      mode_t required = 0; for (size_t i = 0; i < 5; ++i) required |= InventoryMode(profile, i, directory);
      ok = !mask && actual == required; mask = true;
    } else if (tag == ACL_OTHER) { ok = !other && actual == 0; other = true; }
    else ok = false;
  }
  acl_free(acl);
  for (size_t i = 0; i < 5; ++i) if (i != owner && !seen[i]) ok = false;
  return ok && user_obj && group && mask && other && count == 8 &&
      (!directory || HasEmptyInventoryDefaultAcl(fd));
}

bool VerifyInventoryBasePosix(const InventoryRoles& roles, const std::string& profile) {
  const char* base_profile = InventoryParentProfile(profile);
  int base = OpenDirectoryNoFollow(InventoryBasePath(profile));
  const bool exact = base >= 0 && VerifyInventoryAclExact(base, roles, base_profile);
  if (base >= 0) close(base);
  return exact;
}

bool ValidInventoryPath(const std::string& path, const std::string& profile) {
  const std::string inventory = "/var/lib/gjc-remote/native/";
  const std::string reader = "/var/lib/gjc-remote/native-reader/";
  const std::string& base = (profile == "reader-directory" || profile == "inventory-floor") ? reader : inventory;
  if (path.rfind(base, 0) != 0) return false;
  const std::string rest = path.substr(base.size());
  if (rest.size() < 64 || !InventoryHostKey(rest.substr(0, 64))) return false;
  if (rest.size() == 64) return profile == "inventory-directory" || profile == "reader-directory";
  if (rest[64] != '/') return false;
  const std::string leaf = rest.substr(65);
  const char* expected = profile == "inventory-file" ? "workspace-inventory.v2.json" :
      profile == "inventory-commit" ? "inventory-commit.v1.json" :
      profile == "inventory-fence" ? "inventory-publication.lock" :
      profile == "inventory-manual-cleanup" ? "inventory-manual-cleanup.v1.json" :
      profile == "inventory-floor" ? "inventory-floor.v1.json" : "";
  return leaf == expected;
}

const char* InventoryBasePath(const std::string& profile) {
  return profile == "reader-directory" || profile == "inventory-floor" ?
      "/var/lib/gjc-remote/native-reader" : "/var/lib/gjc-remote/native";
}

bool OpenInventoryParentBoundPosix(const std::string& path, const InventoryRoles& roles,
                                   const std::string& profile, int* parent,
                                   std::string* name) {
  const std::string base_path = InventoryBasePath(profile);
  if (path.rfind(base_path + "/", 0) != 0) return false;
  const std::string relative = path.substr(base_path.size() + 1);
  const std::string host = relative.substr(0, 64);
  int base = OpenDirectoryNoFollow(base_path);
  if (base < 0 || !VerifyInventoryAclExact(
          base, roles, InventoryParentProfile(profile))) {
    if (base >= 0) close(base);
    return false;
  }
  if (relative.size() == 64) {
    *parent = base;
    *name = host;
    return true;
  }
  int host_root = OpenObjectNoFollow(base, host, O_RDONLY | O_DIRECTORY);
  close(base);
  if (host_root < 0 || !VerifyInventoryAclExact(
          host_root, roles, InventoryParentProfile(profile))) {
    if (host_root >= 0) close(host_root);
    return false;
  }
  *parent = host_root;
  *name = relative.substr(65);
  return true;
}

void InventoryIdentity(napi_env env, napi_value value, const struct stat& st) {
  napi_value part;
  const std::string device = std::to_string(static_cast<uint64_t>(st.st_dev));
  const std::string inode = std::to_string(static_cast<uint64_t>(st.st_ino));
  const std::string owner = "uid:" + std::to_string(static_cast<uint64_t>(st.st_uid));
  napi_create_string_utf8(env, device.c_str(), NAPI_AUTO_LENGTH, &part); napi_set_named_property(env, value, "device", part);
  napi_create_string_utf8(env, inode.c_str(), NAPI_AUTO_LENGTH, &part); napi_set_named_property(env, value, "inode", part);
  napi_create_uint32(env, static_cast<uint32_t>(st.st_mode), &part); napi_set_named_property(env, value, "mode", part);
  napi_create_string_utf8(env, owner.c_str(), NAPI_AUTO_LENGTH, &part); napi_set_named_property(env, value, "owner", part);
}

bool InventoryIdentityArg(napi_env env, napi_value value, const struct stat& st) {
  const char* expected_fields[] = {"device", "inode", "mode", "owner"};
  napi_value fields[4];
  if (!InventoryOrdinaryDataObject(env, value, expected_fields, 4, fields)) return false;
  std::string device, inode, owner;
  uint32_t mode = 0;
  return InventoryString(env, fields[0], &device) && InventoryString(env, fields[1], &inode) &&
      InventoryUint32(env, fields[2], &mode) && InventoryString(env, fields[3], &owner) &&
      device == std::to_string(static_cast<uint64_t>(st.st_dev)) &&
      inode == std::to_string(static_cast<uint64_t>(st.st_ino)) &&
      mode == static_cast<uint32_t>(st.st_mode) &&
      owner == "uid:" + std::to_string(static_cast<uint64_t>(st.st_uid));
}

void InventoryWrites(napi_env env, napi_value result, const struct stat& st, uint32_t writes) {
  napi_value identity, value;
  napi_create_object(env, &identity); InventoryIdentity(env, identity, st);
  napi_set_named_property(env, result, "identity", identity);
  napi_create_uint32(env, writes, &value); napi_set_named_property(env, result, "writes", value);
}

napi_value ResolveInventoryStateRootPosix(napi_env env, napi_callback_info info) {
  napi_value args[2]; std::string host, kind;
  if (!InventoryArgs(env, info, 2, args) || !InventoryString(env, args[0], &host) ||
      !InventoryString(env, args[1], &kind) || !InventoryHostKey(host) ||
      (kind != "inventory" && kind != "reader")) {
    InventoryError(env, "INVENTORY_INVALID", "resolve_native_state_root"); return nullptr;
  }
  const std::string path = std::string(kind == "inventory" ? "/var/lib/gjc-remote/native/" :
      "/var/lib/gjc-remote/native-reader/") + host;
  napi_value result; napi_create_string_utf8(env, path.c_str(), NAPI_AUTO_LENGTH, &result); return result;
}

napi_value ReadWorkspaceRootFactsPosix(napi_env env, napi_callback_info info) {
  napi_value args[2]; std::string path, platform;
  if (!InventoryArgs(env, info, 2, args) || !InventoryString(env, args[0], &path) ||
      path.empty() || path.size() > 4096 ||
      !InventoryString(env, args[1], &platform) || platform != "posix") {
    InventoryError(env, "INVENTORY_INVALID", "read_workspace_root_facts"); return nullptr;
  }
  int fd = OpenDirectoryNoFollow(path); struct stat st{};
  if (fd < 0 || fstat(fd, &st) != 0) { if (fd >= 0) close(fd); InventoryError(env, "WORKSPACE_ROOT_ESCAPE", "read_workspace_root_facts"); return nullptr; }
  std::string retained_path;
#ifdef __linux__
  const std::string fd_path = "/proc/self/fd/" + std::to_string(fd);
  std::array<char, 4097> canonical{};
  const ssize_t canonical_size = readlink(fd_path.c_str(), canonical.data(), canonical.size() - 1);
  if (canonical_size <= 0 || canonical_size >= static_cast<ssize_t>(canonical.size() - 1)) {
    close(fd); InventoryError(env, "CONTAINMENT_UNSUPPORTED", "read_workspace_root_facts"); return nullptr;
  }
  retained_path.assign(canonical.data(), static_cast<size_t>(canonical_size));
  if (retained_path.empty() || retained_path[0] != '/' ||
      std::any_of(retained_path.begin(), retained_path.end(),
          [](unsigned char character) { return character < 0x20 || character == 0x7f; }) ||
      retained_path.size() >= 10 && retained_path.compare(retained_path.size() - 10, 10, " (deleted)") == 0) {
    close(fd); InventoryError(env, "WORKSPACE_ROOT_ESCAPE", "read_workspace_root_facts"); return nullptr;
  }
#else
  close(fd); InventoryError(env, "CONTAINMENT_UNSUPPORTED", "read_workspace_root_facts"); return nullptr;
#endif
  napi_value result, root, storage, value; napi_create_object(env, &result); napi_create_object(env, &root); napi_create_object(env, &storage);
  napi_create_string_utf8(env, "posix", NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, result, "sourcePlatform", value);
  napi_create_string_utf8(env, retained_path.c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, result, "workDir", value);
  napi_create_string_utf8(env, "posix-root-v1", NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, root, "kind", value);
  napi_create_string_utf8(env, std::to_string(static_cast<uint64_t>(st.st_dev)).c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, root, "device", value);
  napi_create_string_utf8(env, std::to_string(static_cast<uint64_t>(st.st_ino)).c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, root, "inode", value);
  napi_create_string_utf8(env, "posix-storage-v1", NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, storage, "kind", value);
  napi_create_string_utf8(env, std::to_string(static_cast<uint64_t>(st.st_dev)).c_str(), NAPI_AUTO_LENGTH, &value); napi_set_named_property(env, storage, "device", value);
  napi_set_named_property(env, result, "rootIdentity", root); napi_set_named_property(env, result, "storageIdentity", storage); close(fd); return result;
}

napi_value EnsureInventoryDirectoryPosix(napi_env env, napi_callback_info info) {
  napi_value args[3]; std::string path, profile; InventoryRoles roles{};
  if (!InventoryArgs(env, info, 3, args) || !InventoryString(env, args[0], &path) ||
      !InventoryRolesArg(env, args[1], &roles) || !InventoryString(env, args[2], &profile) ||
      !ValidInventoryPath(path, profile) || (profile != "inventory-directory" && profile != "reader-directory")) {
    InventoryError(env, "INVENTORY_INVALID", "ensure_inventory_directory"); return nullptr;
  }
  const uid_t owner = profile == "reader-directory" ? roles.daemon : roles.management;
  if (geteuid() != owner) { InventoryError(env, "INVENTORY_ACCESS_DENIED", "ensure_inventory_directory"); return nullptr; }
  if (!VerifyInventoryBasePosix(roles, profile)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "ensure_inventory_directory"); return nullptr;
  }
  int parent = -1; std::string name;
  if (!OpenInventoryParentBoundPosix(path, roles, profile, &parent, &name)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "ensure_inventory_directory"); return nullptr;
  }
  int fd = OpenObjectNoFollow(parent, name, O_RDONLY | O_DIRECTORY);
  if (fd >= 0) {
    struct stat st{};
    const bool ok = fstat(fd, &st) == 0 && VerifyInventoryAclExact(fd, roles, profile);
    close(fd); close(parent);
    if (!ok) { InventoryError(env, "INVENTORY_ACCESS_DENIED", "ensure_inventory_directory"); return nullptr; }
    napi_value result; napi_create_object(env, &result); InventoryWrites(env, result, st, 0); return result;
  }
  if (errno != ENOENT || mkdirat(parent, name.c_str(), 0700) != 0) {
    close(parent); InventoryError(env, errno == EACCES ? "INVENTORY_ACCESS_DENIED" : "INVENTORY_IO_FAILED", "ensure_inventory_directory"); return nullptr;
  }
  fd = OpenObjectNoFollow(parent, name, O_RDONLY | O_DIRECTORY);
  struct stat created{};
  const bool created_known = fd >= 0 && fstat(fd, &created) == 0;
  const bool ownership_set = created_known && fchown(fd, owner, static_cast<gid_t>(-1)) == 0;
  const bool acl_set = ownership_set && ApplyInventoryAcl(fd, roles, profile);
  const bool ok = acl_set;
  if (fd >= 0) close(fd);
  int reopened = ok ? OpenObjectNoFollow(parent, name, O_RDONLY | O_DIRECTORY) : -1;
  struct stat reopened_identity{};
  const bool reopened_exact = reopened >= 0 && VerifyInventoryAclExact(reopened, roles, profile) &&
      fstat(reopened, &reopened_identity) == 0 &&
      reopened_identity.st_dev == created.st_dev && reopened_identity.st_ino == created.st_ino;
  if (reopened >= 0) close(reopened);
  const bool complete = ok && reopened_exact;
  if (!complete) {
    struct stat named{};
    const bool same_created = created_known &&
        fstatat(parent, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        named.st_dev == created.st_dev && named.st_ino == created.st_ino;
    const bool unlinked = same_created && unlinkat(parent, name.c_str(), AT_REMOVEDIR) == 0;
    const bool absent = unlinked &&
        fstatat(parent, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    const bool cleanup_durable = absent && fsync(parent) == 0;
    close(parent);
    InventoryError(env, cleanup_durable ? "INVENTORY_ACCESS_DENIED" :
        "INVENTORY_MANUAL_CLEANUP", "ensure_inventory_directory",
        (acl_set ? 2 : 1) + (unlinked ? 1 : 0), !cleanup_durable);
    return nullptr;
  }
  const bool durable = fsync(parent) == 0;
  if (!durable) {
    struct stat named{};
    const bool same_created = created_known &&
        fstatat(parent, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        named.st_dev == created.st_dev && named.st_ino == created.st_ino;
    const bool unlinked = same_created && unlinkat(parent, name.c_str(), AT_REMOVEDIR) == 0;
    const bool absent = unlinked &&
        fstatat(parent, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    const bool cleanup_durable = absent && fsync(parent) == 0;
    close(parent);
    InventoryError(env, cleanup_durable ? "INVENTORY_IO_FAILED" :
        "INVENTORY_MANUAL_CLEANUP", "ensure_inventory_directory",
        2 + (unlinked ? 1 : 0), !cleanup_durable);
    return nullptr;
  }
  close(parent);
  napi_value result; napi_create_object(env, &result); InventoryWrites(env, result, created, 2); return result;
}

napi_value VerifyInventoryAclPosix(napi_env env, napi_callback_info info) {
  napi_value args[3]; std::string path, profile; InventoryRoles roles{};
  if (!InventoryArgs(env, info, 3, args) || !InventoryString(env, args[0], &path) ||
      !InventoryRolesArg(env, args[1], &roles) || !InventoryString(env, args[2], &profile) || !ValidInventoryPath(path, profile)) {
    InventoryError(env, "INVENTORY_INVALID", "verify_inventory_acl"); return nullptr;
  }
  if (geteuid() != roles.management && geteuid() != roles.daemon &&
      geteuid() != roles.recovery && geteuid() != roles.system) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "verify_inventory_acl"); return nullptr;
  }
  if (!VerifyInventoryBasePosix(roles, profile)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "verify_inventory_acl"); return nullptr;
  }
  int parent = -1; std::string name;
  if (!OpenInventoryParentBoundPosix(path, roles, profile, &parent, &name)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "verify_inventory_acl"); return nullptr;
  }
  int fd = OpenObjectNoFollow(parent, name, O_RDONLY | (profile.find("directory") != std::string::npos ? O_DIRECTORY : 0));
  const bool ok = fd >= 0 && VerifyInventoryAclExact(fd, roles, profile);
  if (fd >= 0) close(fd); close(parent);
  if (!ok) { InventoryError(env, "INVENTORY_ACCESS_DENIED", "verify_inventory_acl"); return nullptr; }
  napi_value result; napi_get_boolean(env, true, &result); return result;
}

napi_value ReadInventoryObjectPosix(napi_env env, napi_callback_info info) {
  napi_value args[4]; std::string path, profile; InventoryRoles roles{}; int64_t maximum = 0;
  if (!InventoryArgs(env, info, 4, args) || !InventoryString(env, args[0], &path) ||
      !InventoryRolesArg(env, args[2], &roles) || !InventoryString(env, args[3], &profile) ||
      !ValidInventoryPath(path, profile) || !InventoryMaximumBytes(env, args[1], &maximum) ||
      (geteuid() != roles.management && geteuid() != roles.daemon && geteuid() != roles.recovery && geteuid() != 0)) {
    InventoryError(env, "INVENTORY_INVALID", "read_inventory_object"); return nullptr;
  }
  if (!VerifyInventoryBasePosix(roles, profile)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "read_inventory_object"); return nullptr;
  }
  int parent = -1; std::string name;
  if (!OpenInventoryParentBoundPosix(path, roles, profile, &parent, &name)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "read_inventory_object"); return nullptr;
  }
  if (!VerifyInventoryAclExact(parent, roles, InventoryParentProfile(profile))) {
    close(parent); InventoryError(env, "INVENTORY_ACCESS_DENIED", "read_inventory_object"); return nullptr;
  }
  int fd = OpenObjectNoFollow(parent, name, O_RDONLY);
  if (fd < 0 && errno == ENOENT) { close(parent); napi_value absent; napi_get_null(env, &absent); return absent; }
  struct stat st{};
  if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      st.st_size > maximum || st.st_size > static_cast<off_t>(kInventoryMaxBytes) ||
      !VerifyInventoryAclExact(fd, roles, profile)) {
    if (fd >= 0) close(fd); close(parent); InventoryError(env, "INVENTORY_IO_FAILED", "read_inventory_object"); return nullptr;
  }
  std::vector<uint8_t> bytes(static_cast<size_t>(st.st_size));
  size_t offset = 0;
  while (offset < bytes.size()) { const ssize_t n = read(fd, bytes.data() + offset, bytes.size() - offset); if (n <= 0) break; offset += static_cast<size_t>(n); }
  struct stat named{}, final{};
  const bool stable = offset == bytes.size() && fstat(fd, &final) == 0 &&
      final.st_dev == st.st_dev && final.st_ino == st.st_ino &&
      final.st_size == st.st_size && final.st_mode == st.st_mode && final.st_uid == st.st_uid &&
      VerifyInventoryAclExact(fd, roles, profile) &&
      fstatat(parent, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
      named.st_dev == st.st_dev && named.st_ino == st.st_ino &&
      named.st_size == st.st_size && named.st_mode == st.st_mode && named.st_uid == st.st_uid;
  if (!stable) { close(fd); close(parent); InventoryError(env, "INVENTORY_IO_FAILED", "read_inventory_object"); return nullptr; }
  napi_value result, data, identity; napi_create_object(env, &result);
  if (napi_create_buffer_copy(env, bytes.size(), bytes.data(), nullptr, &data) != napi_ok) {
    close(fd); close(parent); InventoryError(env, "INVENTORY_IO_FAILED", "read_inventory_object"); return nullptr;
  }
  napi_set_named_property(env, result, "bytes", data);
  napi_create_object(env, &identity); InventoryIdentity(env, identity, st); napi_set_named_property(env, result, "identity", identity);
  close(fd); close(parent); return result;
}

const napi_type_tag kInventoryFenceTypeTag = {0x496e76656e746f72ULL, 0x7946656e63653a31ULL};
struct InventoryFence {
  int fd = -1;
  std::atomic<bool> released{false};
  napi_env env;
  napi_ref release_promise = nullptr;
  napi_ref object_ref = nullptr;
  uint32_t acquisition_writes = 0;
};
struct FenceWork {
  napi_env env;
  napi_deferred deferred;
  napi_async_work work;
  InventoryFence* fence = nullptr;
  int fd = -1;
  bool timed_out = false;
  bool failed = false;
  std::chrono::steady_clock::time_point deadline{};
};
struct InventoryFenceReleaseWork {
  napi_deferred deferred;
  napi_async_work work;
  InventoryFence* fence;
  napi_ref fence_object;
  bool failed = false;
};
void FenceFinalize(napi_env, void* data, void*) {
  auto* fence = static_cast<InventoryFence*>(data);
  if (fence->fd >= 0) { flock(fence->fd, LOCK_UN); close(fence->fd); }
  if (fence->release_promise) napi_delete_reference(fence->env, fence->release_promise);
  if (fence->object_ref) napi_delete_reference(fence->env, fence->object_ref);
  delete fence;
}
void AcquireFenceExecute(napi_env, void* data) {
  auto* work = static_cast<FenceWork*>(data);
  const auto deadline = work->deadline;
  for (;;) {
    if (std::chrono::steady_clock::now() >= deadline) { work->timed_out = true; return; }
    if (flock(work->fd, LOCK_EX | LOCK_NB) == 0) {
      if (std::chrono::steady_clock::now() < deadline) {
        work->fence->fd = work->fd; work->fd = -1; return;
      }
      flock(work->fd, LOCK_UN); work->timed_out = true; return;
    }
    if (errno != EWOULDBLOCK && errno != EAGAIN) { work->failed = true; return; }
    if (std::chrono::steady_clock::now() >= deadline) { work->timed_out = true; return; }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}
void AcquireFenceComplete(napi_env env, napi_status, void* data) {
  auto* work = static_cast<FenceWork*>(data);
  if (work->fd >= 0) close(work->fd);
  if (work->timed_out) napi_reject_deferred(env, work->deferred,
      InventoryErrorValue(env, "INVENTORY_PENDING", "acquire_inventory_fence",
          work->fence->acquisition_writes));
  else if (work->failed) napi_reject_deferred(env, work->deferred,
      InventoryErrorValue(env, "INVENTORY_IO_FAILED", "acquire_inventory_fence",
          work->fence->acquisition_writes));
  else {
    napi_value object, release;
    napi_create_object(env, &object);
    napi_type_tag_object(env, object, &kInventoryFenceTypeTag);
    napi_create_function(env, "release", NAPI_AUTO_LENGTH,
      [](napi_env release_env, napi_callback_info release_info) -> napi_value {
        void* data = nullptr; size_t argc = 0;
        napi_get_cb_info(release_env, release_info, &argc, nullptr, nullptr, &data);
        auto* fence = static_cast<InventoryFence*>(data);
        napi_value promise;
        if (fence->release_promise) {
          napi_get_reference_value(release_env, fence->release_promise, &promise); return promise;
        }
        napi_deferred deferred; napi_create_promise(release_env, &deferred, &promise);
        napi_create_reference(release_env, promise, 1, &fence->release_promise);
        uint32_t ref_count = 0;
        if (!fence->object_ref || napi_reference_ref(release_env, fence->object_ref, &ref_count) != napi_ok) {
          napi_reject_deferred(release_env, deferred,
              InventoryErrorValue(release_env, "INVENTORY_IO_FAILED", "release_inventory_fence", 0, true));
          return promise;
        }
        auto* release_work = new InventoryFenceReleaseWork{deferred, nullptr, fence, fence->object_ref};
        const napi_status create_status = CreateInventoryAsyncWork(
          release_env, "inventory.release_fence",
          [](napi_env, void* raw) {
            auto* item = static_cast<InventoryFenceReleaseWork*>(raw);
            if (!item->fence->released.exchange(true) && item->fence->fd >= 0) {
              const bool unlocked = flock(item->fence->fd, LOCK_UN) == 0;
              const bool closed = close(item->fence->fd) == 0;
              item->failed = !unlocked || !closed;
              if (closed) item->fence->fd = -1;
            }
          },
          [](napi_env complete_env, napi_status, void* raw) {
            auto* item = static_cast<InventoryFenceReleaseWork*>(raw);
            if (item->failed) napi_reject_deferred(complete_env, item->deferred,
                InventoryErrorValue(complete_env, "INVENTORY_IO_FAILED", "release_inventory_fence", 0, true));
            else { napi_value undefined; napi_get_undefined(complete_env, &undefined); napi_resolve_deferred(complete_env, item->deferred, undefined); }
            uint32_t ref_count = 0;
            napi_reference_unref(complete_env, item->fence_object, &ref_count);
            napi_delete_async_work(complete_env, item->work); delete item;
          }, release_work, &release_work->work);
        const napi_status queue_status = create_status == napi_ok
            ? napi_queue_async_work(release_env, release_work->work)
            : create_status;
        if (queue_status != napi_ok) {
          uint32_t ref_count = 0;
          napi_reference_unref(release_env, release_work->fence_object, &ref_count);
          if (release_work->work) napi_delete_async_work(release_env, release_work->work);
          delete release_work;
          napi_reject_deferred(release_env, deferred,
              InventoryErrorValue(release_env, "INVENTORY_IO_FAILED",
                  "release_inventory_fence", 0, true));
        }
        return promise;
      }, work->fence, &release);
    napi_set_named_property(env, object, "release", release);
    napi_wrap(env, object, work->fence, FenceFinalize, nullptr, nullptr);
    napi_create_reference(env, object, 0, &work->fence->object_ref);
    napi_resolve_deferred(env, work->deferred, object);
  }
  napi_delete_async_work(env, work->work);
  if (work->timed_out || work->failed) delete work->fence;
  delete work;
}
long RenameAt2(int parent, const std::string& from, const std::string& to, unsigned int flags);
napi_value AcquireInventoryFencePosix(napi_env env, napi_callback_info info) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
  napi_value args[2]; std::string path; InventoryRoles roles{};
  if (!InventoryArgs(env, info, 2, args) || !InventoryString(env, args[0], &path) ||
      !InventoryRolesArg(env, args[1], &roles) || !ValidInventoryPath(path, "inventory-fence") ||
      (geteuid() != roles.management && geteuid() != roles.daemon)) {
    InventoryError(env, "INVENTORY_INVALID", "acquire_inventory_fence"); return nullptr;
  }
  if (!VerifyInventoryBasePosix(roles, "inventory-fence")) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence"); return nullptr;
  }
  int parent; std::string name;
  if (!OpenInventoryParentBoundPosix(path, roles, "inventory-fence", &parent, &name)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence"); return nullptr;
  }
  if (!VerifyInventoryAclExact(parent, roles, "inventory-directory")) {
    close(parent); InventoryError(env, "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence"); return nullptr;
  }
  bool created_by_call = false;
  uint32_t fence_writes = 0;
  struct stat published_identity{};
  int fd = OpenObjectNoFollow(parent, name, O_RDONLY);
  if (fd < 0 && errno == ENOENT && (geteuid() == roles.management || geteuid() == 0)) {
    std::string temporary; int created = -1;
    for (unsigned attempt = 0; attempt < 128; ++attempt) {
      std::string token;
      if (!InventoryRandomName(&token)) break;
      temporary = ".inventory-fence." + token;
      created = openat(parent, temporary.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
      if (created >= 0 || errno != EEXIST) break;
    }
    uint32_t writes = created >= 0 ? 1 : 0;
    struct stat created_identity{};
    const bool created_known = created >= 0 && fstat(created, &created_identity) == 0;
    auto discard = [&](const std::string& entry, const struct stat& expected) {
      struct stat named{};
      if (fstatat(parent, entry.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
          named.st_dev != expected.st_dev || named.st_ino != expected.st_ino ||
          unlinkat(parent, entry.c_str(), 0) != 0 ||
          fstatat(parent, entry.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return false;
      ++writes;
      return fsync(parent) == 0;
    };
    const bool ownership_set = created_known &&
        fchown(created, roles.management, static_cast<gid_t>(-1)) == 0;
    const bool acl_set = ownership_set && ApplyInventoryAcl(created, roles, "inventory-fence");
    if (acl_set) ++writes;
    const bool prepared = acl_set && VerifyInventoryAclExact(created, roles, "inventory-fence") &&
        fsync(created) == 0;
    if (created >= 0) close(created);
    int reopened = prepared ? OpenObjectNoFollow(parent, temporary, O_RDONLY) : -1;
    struct stat reopened_identity{};
    const bool reopened_exact = reopened >= 0 && fstat(reopened, &reopened_identity) == 0 &&
        reopened_identity.st_dev == created_identity.st_dev &&
        reopened_identity.st_ino == created_identity.st_ino &&
        VerifyInventoryAclExact(reopened, roles, "inventory-fence");
    if (reopened >= 0) close(reopened);
    if (!prepared) {
      const bool cleaned = created < 0 || (created_known && discard(temporary, created_identity));
      close(parent); InventoryError(env, cleaned ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
          "acquire_inventory_fence", writes, !cleaned); return nullptr;
    }
    if (!reopened_exact) {
      const bool cleaned = discard(temporary, created_identity);
      close(parent); InventoryError(env, cleaned ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
          "acquire_inventory_fence", writes, !cleaned); return nullptr;
    }
    if (RenameAt2(parent, temporary, name, 1) != 0) {
      const int failure = errno; const bool cleaned = discard(temporary, created_identity);
      if (failure != EEXIST) {
        close(parent); InventoryError(env, cleaned ? (failure == ENOSYS || failure == EINVAL ? "CONTAINMENT_UNSUPPORTED" : "INVENTORY_IO_FAILED") :
            "INVENTORY_MANUAL_CLEANUP", "acquire_inventory_fence", writes, !cleaned); return nullptr;
      }
    } else {
      ++writes;
      if (fsync(parent) != 0) {
      int named = OpenObjectNoFollow(parent, name, O_RDONLY);
      struct stat named_identity{};
      const bool proven = named >= 0 && fstat(named, &named_identity) == 0 &&
          named_identity.st_dev == created_identity.st_dev && named_identity.st_ino == created_identity.st_ino &&
          VerifyInventoryAclExact(named, roles, "inventory-fence");
      if (named >= 0) close(named);
      const bool cleaned = proven && discard(name, created_identity);
      const bool durable = cleaned && fsync(parent) == 0;
      close(parent); InventoryError(env, durable ? "INVENTORY_IO_FAILED" : "INVENTORY_MANUAL_CLEANUP",
          "acquire_inventory_fence", writes, !durable); return nullptr;
      }
      created_by_call = true;
      fence_writes = writes;
      published_identity = created_identity;
    }
    fd = OpenObjectNoFollow(parent, name, O_RDONLY);
  }
  if (fd < 0) { close(parent); InventoryError(env, errno == ENOENT ? "INVENTORY_STALE" : "INVENTORY_IO_FAILED", "acquire_inventory_fence"); return nullptr; }
  struct stat fence_stat{};
  const bool fence_ok = fstat(fd, &fence_stat) == 0 && S_ISREG(fence_stat.st_mode) && fence_stat.st_size == 0 &&
      VerifyInventoryAclExact(fd, roles, "inventory-fence") &&
      (!created_by_call || (fence_stat.st_dev == published_identity.st_dev &&
          fence_stat.st_ino == published_identity.st_ino));
  close(parent);
  if (!fence_ok) {
    close(fd);
    InventoryError(env, created_by_call ? "INVENTORY_MANUAL_CLEANUP" :
        "INVENTORY_ACCESS_DENIED", "acquire_inventory_fence", fence_writes,
        created_by_call);
    return nullptr;
  }
  napi_value promise; napi_deferred deferred; napi_create_promise(env, &deferred, &promise);
  auto* fence = new InventoryFence();
  fence->env = env;
  fence->acquisition_writes = fence_writes;
  auto* work = new FenceWork{env, deferred, nullptr, fence, fd, false, false, deadline};
  const napi_status create_status = CreateInventoryAsyncWork(
      env, "inventory.acquire_fence", AcquireFenceExecute,
      AcquireFenceComplete, work, &work->work);
  const napi_status queue_status = create_status == napi_ok
      ? napi_queue_async_work(env, work->work)
      : create_status;
  if (queue_status != napi_ok) {
    if (work->work) napi_delete_async_work(env, work->work);
    close(fd);
    delete fence;
    delete work;
    napi_reject_deferred(env, deferred,
        InventoryErrorValue(env, "INVENTORY_IO_FAILED",
            "acquire_inventory_fence", fence_writes));
  }
  return promise;
}

long RenameAt2(int parent, const std::string& from, const std::string& to, unsigned int flags) {
#ifdef __linux__
  return syscall(SYS_renameat2, parent, from.c_str(), parent, to.c_str(), flags);
#else
  errno = ENOSYS; return -1;
#endif
}
napi_value PublishInventoryObjectAtomicPosix(napi_env env, napi_callback_info info) {
  napi_value args[6]; std::string path, prefix, profile; InventoryRoles roles{}; std::vector<uint8_t> bytes;
  napi_valuetype expected_type;
  bool is_directory = false; uid_t profile_roles[5]{};
  if (!InventoryArgs(env, info, 6, args) || !InventoryString(env, args[0], &path) ||
      !InventoryString(env, args[1], &prefix) || prefix.empty() || prefix.find('/') != std::string::npos ||
      !InventoryBufferArg(env, info, 2, &bytes) || !InventoryRolesArg(env, args[4], &roles) ||
      !InventoryString(env, args[5], &profile) || !ValidInventoryPath(path, profile) ||
      !InventoryProfile(profile, &is_directory, profile_roles, roles) || is_directory ||
      profile == "inventory-fence" ||
      napi_typeof(env, args[3], &expected_type) != napi_ok ||
      (expected_type != napi_null && expected_type != napi_object) || bytes.size() > kInventoryMaxBytes ||
      geteuid() != (profile == "inventory-floor" ? roles.daemon : roles.management)) {
    InventoryError(env, "INVENTORY_INVALID", "publish_inventory_object_atomic"); return nullptr;
  }
  const char* identity_fields[] = {"device", "inode", "mode", "owner"};
  if (expected_type == napi_object && !InventoryOrdinaryDataObject(env, args[3], identity_fields, 4)) {
    InventoryError(env, "INVENTORY_INVALID", "publish_inventory_object_atomic"); return nullptr;
  }
  if (!VerifyInventoryBasePosix(roles, profile)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "publish_inventory_object_atomic"); return nullptr;
  }
  int parent; std::string name;
  if (!OpenInventoryParentBoundPosix(path, roles, profile, &parent, &name)) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "publish_inventory_object_atomic"); return nullptr;
  }
  if (!VerifyInventoryAclExact(parent, roles, InventoryParentProfile(profile))) {
    close(parent); InventoryError(env, "INVENTORY_ACCESS_DENIED", "publish_inventory_object_atomic"); return nullptr;
  }
  std::string temp; int fd = -1;
  for (unsigned attempt = 0; attempt < 128; ++attempt) {
    std::string token;
    if (!InventoryRandomName(&token)) break;
    temp = "." + prefix + "." + token;
    fd = openat(parent, temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd >= 0 || errno != EEXIST) break;
  }
  uint32_t writes = 0;
  if (fd < 0) { close(parent); InventoryError(env, "INVENTORY_IO_FAILED", "publish_inventory_object_atomic"); return nullptr; }
  writes = 1;
  struct stat candidate{};
  const bool candidate_identity_known = fstat(fd, &candidate) == 0;
  auto clean = [&](const std::string& entry, const struct stat& expected) {
    struct stat named{};
    if (fstatat(parent, entry.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        named.st_dev != expected.st_dev || named.st_ino != expected.st_ino ||
        unlinkat(parent, entry.c_str(), 0) != 0 ||
        fstatat(parent, entry.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return false;
    ++writes;
    return fsync(parent) == 0;
  };
  auto fail_clean = [&](const char* code) -> napi_value {
    const bool cleaned = candidate_identity_known && clean(temp, candidate);
    close(parent);
    InventoryError(env, cleaned ? code : "INVENTORY_MANUAL_CLEANUP",
        "publish_inventory_object_atomic", writes, !cleaned);
    return nullptr;
  };
  size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t n = write(fd, bytes.data() + offset, bytes.size() - offset);
    if (n <= 0) break;
    offset += static_cast<size_t>(n);
  }
  if (offset != bytes.size()) { close(fd); return fail_clean("INVENTORY_IO_FAILED"); }
  ++writes;
  const uid_t owner = profile == "inventory-floor" ? roles.daemon : roles.management;
  if (fchown(fd, owner, static_cast<gid_t>(-1)) != 0 ||
      !ApplyInventoryAcl(fd, roles, profile) || fsync(fd) != 0) {
    close(fd); return fail_clean("INVENTORY_IO_FAILED");
  }
  ++writes;
  const bool candidate_ok = candidate_identity_known && fstat(fd, &candidate) == 0 &&
      VerifyInventoryAclExact(fd, roles, profile);
  close(fd);
  if (!candidate_ok) return fail_clean("INVENTORY_IO_FAILED");

  auto read_exact = [&](const std::string& entry, const struct stat& expected,
                        std::vector<uint8_t>* contents) {
    int object = OpenObjectNoFollow(parent, entry, O_RDONLY);
    struct stat actual{};
    bool ok = object >= 0 && fstat(object, &actual) == 0 &&
        actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino &&
        actual.st_size >= 0 && actual.st_size <= static_cast<off_t>(kInventoryMaxBytes) &&
        VerifyInventoryAclExact(object, roles, profile);
    if (ok) {
      contents->resize(static_cast<size_t>(actual.st_size));
      size_t read_offset = 0;
      while (ok && read_offset < contents->size()) {
        const ssize_t n = read(object, contents->data() + read_offset, contents->size() - read_offset);
        if (n <= 0) { ok = false; break; }
        read_offset += static_cast<size_t>(n);
      }
      ok = ok && read_offset == contents->size();
    }
    if (object >= 0) close(object);
    return ok;
  };
  struct stat previous{};
  const int predecessor_state = fstatat(parent, name.c_str(), &previous, AT_SYMLINK_NOFOLLOW);
  const bool present = predecessor_state == 0;
  if (!present && errno != ENOENT) return fail_clean("INVENTORY_IO_FAILED");
  if ((!present && expected_type != napi_null) ||
      (present && (expected_type == napi_null || !InventoryIdentityArg(env, args[3], previous)))) {
    return fail_clean("INVENTORY_STALE");
  }
  std::vector<uint8_t> predecessor_bytes;
  if (present && !read_exact(name, previous, &predecessor_bytes)) return fail_clean("INVENTORY_IO_FAILED");

  const unsigned int NOREPLACE = 1, EXCHANGE = 2;
  if (RenameAt2(parent, temp, name, present ? EXCHANGE : NOREPLACE) != 0) {
    const int failure = errno;
    const char* code = failure == ENOSYS || failure == EINVAL ? "CONTAINMENT_UNSUPPORTED" :
        failure == EEXIST || failure == ENOTEMPTY ? "INVENTORY_STALE" :
        failure == EACCES || failure == EPERM ? "INVENTORY_ACCESS_DENIED" :
        "INVENTORY_IO_FAILED";
    return fail_clean(code);
  }
  ++writes;
  auto candidate_at_name = [&](struct stat* result) {
    std::vector<uint8_t> published;
    if (!read_exact(name, candidate, &published) || published != bytes) return false;
    return fstatat(parent, name.c_str(), result, AT_SYMLINK_NOFOLLOW) == 0 &&
        result->st_dev == candidate.st_dev && result->st_ino == candidate.st_ino;
  };
  auto reconcile = [&]() -> napi_value {
    if (present) {
      std::vector<uint8_t> retained;
      if (!read_exact(temp, previous, &retained) || retained != predecessor_bytes) {
        close(parent); InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
            "publish_inventory_object_atomic", writes, true); return nullptr;
      }
      if (RenameAt2(parent, temp, name, EXCHANGE) != 0) {
        close(parent); InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
            "publish_inventory_object_atomic", writes, true); return nullptr;
      }
      ++writes;
      std::vector<uint8_t> restored;
      if (!read_exact(name, previous, &restored) || restored != predecessor_bytes ||
          !clean(temp, candidate)) {
        close(parent); InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
            "publish_inventory_object_atomic", writes, true); return nullptr;
      }
    } else {
      struct stat named{};
      if (!candidate_at_name(&named) || !clean(name, candidate)) {
        close(parent); InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
            "publish_inventory_object_atomic", writes, true); return nullptr;
      }
    }
    close(parent);
    InventoryError(env, "INVENTORY_IO_FAILED", "publish_inventory_object_atomic", writes);
    return nullptr;
  };

  struct stat result_stat{};
  if (fsync(parent) != 0 || !candidate_at_name(&result_stat)) return reconcile();
  if (present) {
    std::vector<uint8_t> displaced;
    if (!read_exact(temp, previous, &displaced) || displaced != predecessor_bytes ||
        !clean(temp, previous)) return reconcile();
  }
  close(parent);
  napi_value result; napi_create_object(env, &result); InventoryWrites(env, result, result_stat, writes); return result;
}
#endif
napi_value ResolveInventoryStateRoot(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  return ResolveInventoryStateRootWindows(env, info);
#else
  return ResolveInventoryStateRootPosix(env, info);
#endif
}
napi_value ReadWorkspaceRootFacts(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  return ReadWorkspaceRootFactsWindows(env, info);
#else
  return ReadWorkspaceRootFactsPosix(env, info);
#endif
}
napi_value EnsureInventoryDirectory(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  return EnsureInventoryDirectoryWindows(env, info);
#else
  return EnsureInventoryDirectoryPosix(env, info);
#endif
}
napi_value VerifyInventoryAcl(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  return VerifyInventoryAclWindows(env, info);
#else
  return VerifyInventoryAclPosix(env, info);
#endif
}
napi_value AcquireInventoryFence(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  return AcquireInventoryFenceWindows(env, info);
#else
  return AcquireInventoryFencePosix(env, info);
#endif
}
napi_value ReadInventoryObject(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  return ReadInventoryObjectWindows(env, info);
#else
  return ReadInventoryObjectPosix(env, info);
#endif
}
napi_value PublishInventoryObjectAtomic(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  return PublishInventoryObjectAtomicWindows(env, info);
#else
  return PublishInventoryObjectAtomicPosix(env, info);
#endif
}
napi_value NativeControlContract(napi_env env, napi_callback_info) {
  const char* capabilities[] = {
    "open_verified_parent", "open_no_follow", "read_identity", "read_acl", "path_exists_no_follow",
    "set_exact_role_acl", "verify_exact_role_acl", "read_verified_bytes", "create_exclusive_temp", "flush_file", "flush_directory_or_volume",
    "replace_existing_atomic", "create_absent_exclusive", "ensure_control_directory",
    "acquire_native_lock", "current_os_principal", "principal_access_check", "remove_verified_file",
    "open_verified_parent_handle", "open_verified_object_handle", "read_handle_identity",
    "read_handle_bytes", "write_handle_bytes", "remove_verified_handle", "verify_role_sid_not_group",
    "resolve_native_state_root", "read_workspace_root_facts", "ensure_inventory_directory",
    "verify_inventory_acl", "acquire_inventory_fence", "read_inventory_object",
    "publish_inventory_object_atomic",
  };
  napi_value result, value, array, signatures;
  napi_create_object(env, &result);
  napi_create_uint32(env, 4, &value); napi_set_named_property(env, result, "contractVersion", value);
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
  signature("principal_access_check", {"path", "kind", "principal", "mode", "managementSid", "botSid", "recoverySid", "systemSid", "profile"});
  signature("remove_verified_file", {"path", "expectedBytes"});
  signature("open_verified_parent_handle", {"path"});
  signature("open_verified_object_handle", {"parentHandle", "name"});
  signature("read_handle_identity", {"handle"}); signature("read_handle_bytes", {"handle"});
  signature("write_handle_bytes", {"handle", "bytes"}); signature("remove_verified_handle", {"handle", "expectedBytes"});
  signature("verify_role_sid_not_group", {"sid"});
  signature("resolve_native_state_root", {"hostKey", "rootKind"});
  signature("read_workspace_root_facts", {"path", "sourcePlatform"});
  signature("ensure_inventory_directory", {"path", "roles", "profile"});
  signature("verify_inventory_acl", {"path", "roles", "profile"});
  signature("acquire_inventory_fence", {"path", "roles"});
  signature("read_inventory_object", {"path", "maxBytes", "roles", "profile"});
  signature("publish_inventory_object_atomic", {"path", "tempPrefix", "bytes", "expectedIdentity", "roles", "profile"});
  napi_set_named_property(env, result, "capabilitySignatures", signatures);
  return result;
}

napi_value Init(napi_env env, napi_value exports) {
#ifdef _WIN32
  if (!InventoryFileIdVectorsValid()) {
    napi_throw_error(env, "ERR_NATIVE_CONTROL_INIT",
        "native inventory identity self-check failed");
    return nullptr;
  }
#endif
  napi_value plain, object_prototype, global, object_ctor, get_descriptors;
  if (napi_create_object(env, &plain) != napi_ok ||
      napi_get_prototype(env, plain, &object_prototype) != napi_ok ||
      napi_get_global(env, &global) != napi_ok ||
      napi_get_named_property(env, global, "Object", &object_ctor) != napi_ok ||
      napi_get_named_property(env, object_ctor, "getOwnPropertyDescriptors", &get_descriptors) != napi_ok ||
      napi_create_reference(env, object_prototype, 1, &gInventoryObjectPrototype) != napi_ok ||
      napi_create_reference(env, get_descriptors, 1, &gInventoryGetOwnPropertyDescriptors) != napi_ok) {
    napi_throw_error(env, "ERR_NATIVE_CONTROL_INIT", "unable to capture inventory validation intrinsics");
    return nullptr;
  }
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
    {"native_control_contract", nullptr, NativeControlContract, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"verify_role_sid_not_group", nullptr, VerifyRoleSidNotGroupMethod, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"resolve_native_state_root", nullptr, ResolveInventoryStateRoot, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_workspace_root_facts", nullptr, ReadWorkspaceRootFacts, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"ensure_inventory_directory", nullptr, EnsureInventoryDirectory, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"verify_inventory_acl", nullptr, VerifyInventoryAcl, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"acquire_inventory_fence", nullptr, AcquireInventoryFence, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_inventory_object", nullptr, ReadInventoryObject, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"publish_inventory_object_atomic", nullptr, PublishInventoryObjectAtomic, nullptr, nullptr, nullptr, napi_default, nullptr}
  };
  napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods);
  return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
}  // namespace
