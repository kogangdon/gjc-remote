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
#include <cwchar>
#include <cwctype>
#include <limits>
#include <initializer_list>
#include <thread>
#include <memory>
#include <new>
#include <array>
#include <cmath>
#include <cstddef>
#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <sstream>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
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
#include <signal.h>
#include <grp.h>
#include <pwd.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <dirent.h>
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

class Sha256 {
 public:
  Sha256() {
#ifdef _WIN32
    DWORD object_bytes = 0;
    DWORD returned = 0;
    if (BCryptOpenAlgorithmProvider(
            &algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0 ||
        BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes),
            &returned, 0) != 0 ||
        returned != sizeof(object_bytes) || object_bytes == 0) {
      return;
    }
    try {
      object_.resize(object_bytes);
    } catch (...) {
      return;
    }
    valid_ = BCryptCreateHash(algorithm_, &hash_, object_.data(),
        static_cast<ULONG>(object_.size()), nullptr, 0, 0) == 0;
#elif defined(__linux__)
    transform_ = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (transform_ < 0) return;
    sockaddr_alg address{};
    address.salg_family = AF_ALG;
    std::memcpy(address.salg_type, "hash", sizeof("hash"));
    std::memcpy(address.salg_name, "sha256", sizeof("sha256"));
    if (bind(transform_, reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) != 0) {
      return;
    }
    operation_ = accept(transform_, nullptr, nullptr);
    if (operation_ < 0 ||
        fcntl(operation_, F_SETFD, FD_CLOEXEC) != 0) {
      return;
    }
    valid_ = true;
#endif
  }

  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

  ~Sha256() {
#ifdef _WIN32
    if (hash_) BCryptDestroyHash(hash_);
    if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
#elif defined(__linux__)
    if (operation_ >= 0) close(operation_);
    if (transform_ >= 0) close(transform_);
#endif
  }

  bool Update(const void* raw, size_t length) {
    if (!valid_ || finished_) return false;
    if (length == 0) return true;
#ifdef _WIN32
    const auto* input = static_cast<const uint8_t*>(raw);
    while (length > 0) {
      const ULONG chunk = static_cast<ULONG>(std::min<size_t>(
          length, std::numeric_limits<ULONG>::max()));
      if (BCryptHashData(hash_, const_cast<PUCHAR>(input), chunk, 0) != 0) {
        valid_ = false;
        return false;
      }
      input += chunk;
      length -= chunk;
    }
    return true;
#elif defined(__linux__)
    const auto* input = static_cast<const uint8_t*>(raw);
    if (!pending_.empty() &&
        !Send(pending_.data(), pending_.size(), MSG_MORE)) {
      valid_ = false;
      return false;
    }
    pending_.clear();
    constexpr size_t kChunk = 64 * 1024;
    while (length > kChunk) {
      if (!Send(input, kChunk, MSG_MORE)) {
        valid_ = false;
        return false;
      }
      input += kChunk;
      length -= kChunk;
    }
    try {
      pending_.assign(input, input + length);
    } catch (...) {
      valid_ = false;
      return false;
    }
    return true;
#else
    (void)raw;
    (void)length;
    return false;
#endif
  }

  bool Update(const std::string& value) {
    return Update(value.data(), value.size());
  }

  bool Ready() const { return valid_ && !finished_; }

  std::string Finish() {
    if (!valid_ || finished_) return "";
    std::array<uint8_t, 32> digest{};
#ifdef _WIN32
    if (BCryptFinishHash(hash_, digest.data(),
            static_cast<ULONG>(digest.size()), 0) != 0) {
      valid_ = false;
      return "";
    }
#elif defined(__linux__)
    if (!Send(pending_.data(), pending_.size(), 0)) {
      valid_ = false;
      return "";
    }
    size_t offset = 0;
    while (offset < digest.size()) {
      const ssize_t bytes = recv(operation_, digest.data() + offset,
          digest.size() - offset, 0);
      if (bytes < 0 && errno == EINTR) continue;
      if (bytes <= 0) {
        valid_ = false;
        return "";
      }
      offset += static_cast<size_t>(bytes);
    }
#else
    return "";
#endif
    finished_ = true;
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    try {
      result.reserve(64);
      for (uint8_t byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0f]);
      }
    } catch (...) {
      valid_ = false;
      return "";
    }
    return result;
  }

 private:
#ifdef __linux__
  bool Send(const void* data, size_t length, int flags) {
    for (;;) {
      const ssize_t written = send(operation_, data, length, flags);
      if (written < 0 && errno == EINTR) continue;
      return written >= 0 && static_cast<size_t>(written) == length;
    }
  }
#endif

  bool valid_ = false;
  bool finished_ = false;
#ifdef _WIN32
  BCRYPT_ALG_HANDLE algorithm_ = nullptr;
  BCRYPT_HASH_HANDLE hash_ = nullptr;
  std::vector<uint8_t> object_;
#elif defined(__linux__)
  int transform_ = -1;
  int operation_ = -1;
  std::vector<uint8_t> pending_;
#endif
};

void HashField(Sha256* hash, const std::string& value) {
  uint8_t length[8];
  const uint64_t size = value.size();
  for (size_t index = 0; index < sizeof(length); ++index) {
    length[sizeof(length) - index - 1] =
        static_cast<uint8_t>(size >> (index * 8));
  }
  hash->Update(length, sizeof(length));
  hash->Update(value);
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
                           PSECURITY_DESCRIPTOR security = nullptr,
                           DWORD share_mode =
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) {
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
      FILE_ATTRIBUTE_NORMAL, share_mode,
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
                               VerifiedObjectType expected_type,
                               DWORD final_share_mode =
                                   FILE_SHARE_READ | FILE_SHARE_WRITE |
                                   FILE_SHARE_DELETE) {
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
        final ? expected_type : VerifiedObjectType::Directory, nullptr,
        final ? final_share_mode :
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
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
  if (path.empty()) { errno = EINVAL; return -1; }
  const bool absolute = path[0] == '/';
  int fd = open(absolute ? "/" : ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return -1;
  size_t start = absolute ? 1 : 0;
  while (start <= path.size()) {
    size_t end = path.find('/', start);
    std::string component = path.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (!component.empty() && component != ".") {
      if (!SafeName(component)) { close(fd); errno = EINVAL; return -1; }
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
  if (!SplitParent(path, &parent, name)) { errno = EINVAL; return false; }
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
    if (errno == ENOENT) {
      napi_value absent;
      napi_get_null(env, &absent);
      return absent;
    }
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
  const DWORD rename_error = renamed ? ERROR_SUCCESS : GetLastError();
  if (!renamed) {
    const bool clean = discard();
    CloseHandle(parent);
    if (!clean) Refuse(env, "create_absent_exclusive", "failed temporary cleanup is ambiguous");
    else if (rename_error == ERROR_ALREADY_EXISTS || rename_error == ERROR_FILE_EXISTS) {
      Throw(env, "EEXIST", "absent-file destination already exists");
    }
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
  const int link_error = linked ? 0 : errno;
  struct stat published{};
  const bool publication_verified = linked &&
      fstatat(parent_fd, name.c_str(), &published, AT_SYMLINK_NOFOLLOW) == 0 &&
      published.st_dev == held.st_dev && published.st_ino == held.st_ino;
  if (!publication_verified || fsync(parent_fd) != 0) {
    const bool clean = discard();
    close(parent_fd);
    if (!clean) Refuse(env, "create_absent_exclusive", "failed absent-file publication cleanup is ambiguous");
    else if (link_error == EEXIST) Throw(env, "EEXIST", "absent-file destination already exists");
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
bool InventoryFenceProperties(napi_env env, napi_value object,
                              napi_value release, uint32_t writes) {
  napi_value write_count;
  if (napi_create_uint32(env, writes, &write_count) != napi_ok) return false;
  const napi_property_descriptor properties[] = {
      {"release", nullptr, nullptr, nullptr, nullptr, release,
       napi_enumerable, nullptr},
      {"writes", nullptr, nullptr, nullptr, nullptr, write_count,
       napi_enumerable, nullptr},
  };
  return napi_define_properties(
      env, object, sizeof(properties) / sizeof(properties[0]),
      properties) == napi_ok;
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
  static constexpr DWORD kMaximumAccountUnits = 4096;
  PSID sid = nullptr;
  SID_NAME_USE use = SidTypeUnknown;
  DWORD name = 0;
  DWORD domain = 0;
  if (!ConvertStringSidToSidW(Wide(text).c_str(), &sid) ||
      !sid || !IsValidSid(sid)) {
    if (sid) LocalFree(sid);
    return false;
  }
  SetLastError(ERROR_SUCCESS);
  LookupAccountSidW(nullptr, sid, nullptr, &name, nullptr, &domain, &use);
  const DWORD first_error = GetLastError();
  bool ok = false;
  if (first_error == ERROR_INSUFFICIENT_BUFFER && name > 0 &&
      name <= kMaximumAccountUnits &&
      domain <= kMaximumAccountUnits &&
      static_cast<uint64_t>(name) + domain + 1 <=
          kMaximumAccountUnits) {
    try {
      std::vector<wchar_t> n(name, L'\0');
      std::vector<wchar_t> d(std::max<DWORD>(domain, 1), L'\0');
      DWORD name_capacity = name;
      DWORD domain_capacity = domain;
      ok = LookupAccountSidW(
              nullptr, sid, n.data(), &name_capacity,
              domain == 0 ? nullptr : d.data(), &domain_capacity,
              &use) &&
          name_capacity > 0 && name_capacity <= n.size() &&
          (domain == 0 || domain_capacity <= d.size()) &&
          std::find(n.begin(), n.end(), L'\0') != n.end() &&
          (domain == 0 ||
           std::find(d.begin(), d.end(), L'\0') != d.end()) &&
          (system ? text == "S-1-5-18" : use == SidTypeUser);
    } catch (...) {
      ok = false;
    }
  }
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
  napi_value args[4]; std::string path, profile, expected_actor; InventoryRoles roles{};
  if (!InventoryArgs(env, info, 4, args) || !InventoryString(env, args[0], &path) ||
      !InventoryRolesArg(env, args[1], &roles) || !InventoryString(env, args[2], &profile) ||
      !InventoryString(env, args[3], &expected_actor) ||
      (expected_actor != "management" && expected_actor != "daemon" &&
       expected_actor != "recovery" && expected_actor != "system")) {
    InventoryError(env, "INVENTORY_INVALID", "verify_inventory_acl"); return nullptr;
  }
  const bool expected_actor_matches =
      (expected_actor == "management" && CurrentInventoryActor(roles, true, false)) ||
      (expected_actor == "daemon" && CurrentInventoryActor(roles, false, true)) ||
      (expected_actor == "recovery" && CurrentInventoryActor(roles, false, false, true)) ||
      (expected_actor == "system" && CurrentInventoryActor(roles, false, false, false, true));
  if (!expected_actor_matches) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "verify_inventory_acl"); return nullptr;
  }
  if (!InventoryPath(path, profile)) {
    InventoryError(env, "INVENTORY_INVALID", "verify_inventory_acl"); return nullptr;
  }
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
    const bool rename_attempted = prepared;
    const bool renamed = rename_attempted &&
        RenameWindowsRelative(temporary, parent, name, false);
    const DWORD rename_error = renamed ? ERROR_SUCCESS :
        rename_attempted ? GetLastError() : ERROR_GEN_FAILURE;
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
    const uint32_t creation_writes = (temporary_created ? 1 : 0) +
        (acl_applied ? 1 : 0) + (renamed ? 1 : 0) +
        ((cleanup_mutated || rollback_mutated) ? 1 : 0);
    const bool lost_create_race = rename_attempted && !renamed && cleaned &&
        (rename_error == ERROR_FILE_EXISTS ||
         rename_error == ERROR_ALREADY_EXISTS);
    if (lost_create_race) {
      h = OpenWindowsRelative(parent, name, GENERIC_READ | READ_CONTROL,
          kFileOpen, VerifiedObjectType::File);
      fence_open_error =
          h == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    }
    if (published) {
      h = OpenWindowsRelative(parent, name, GENERIC_READ | READ_CONTROL,
          kFileOpen, VerifiedObjectType::File);
      fence_open_error = h == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    }
    CloseHandle(parent);
    if (!published && !lost_create_race) {
      InventoryError(env, (cleaned || rolled_back) ?
          (rename_error == ERROR_FILE_EXISTS || rename_error == ERROR_ALREADY_EXISTS ?
              "INVENTORY_STALE" : rename_error == ERROR_CALL_NOT_IMPLEMENTED ||
                  rename_error == ERROR_NOT_SUPPORTED ?
                      "CONTAINMENT_UNSUPPORTED" : "INVENTORY_IO_FAILED") :
          "INVENTORY_MANUAL_CLEANUP", "acquire_inventory_fence",
          creation_writes,
          !(cleaned || rolled_back));
      return nullptr;
    }
    fence_writes = creation_writes;
    if (published) {
      published_fence_id = temporary_id;
      created_by_call = true;
    }
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
  napi_value promise;
  napi_deferred deferred;
  if (napi_create_promise(env, &deferred, &promise) != napi_ok) {
    CloseHandle(h);
    delete fence;
    InventoryError(env, "INVENTORY_IO_FAILED",
        "acquire_inventory_fence", fence_writes);
    return nullptr;
  }
  auto* work = new WindowsFenceWork{deferred, nullptr, fence, false, false, false, deadline};
  const napi_status create_status = CreateInventoryAsyncWork(
    env, "inventory.acquire_fence", WindowsFenceExecute,
    [](napi_env complete, napi_status, void* raw) { auto* work = static_cast<WindowsFenceWork*>(raw);
      if (work->pending || work->failed) { if (work->fence->handle != INVALID_HANDLE_VALUE) CloseHandle(work->fence->handle); napi_reject_deferred(complete, work->deferred, InventoryErrorValue(complete, work->pending ? "INVENTORY_PENDING" : "INVENTORY_IO_FAILED", "acquire_inventory_fence", work->fence->acquisition_writes, work->fence->acquisition_ambiguous)); delete work->fence; }
      else {
        napi_value object = nullptr, release = nullptr;
        napi_status setup_status = napi_create_object(complete, &object);
        if (setup_status == napi_ok) {
          setup_status = napi_type_tag_object(
              complete, object, &kWindowsInventoryFenceTypeTag);
        }
        if (setup_status == napi_ok) {
          setup_status = napi_create_function(
              complete, "release", NAPI_AUTO_LENGTH,
              [](napi_env e, napi_callback_info i) -> napi_value {
          void* data = nullptr;
          size_t argc = 0;
          if (napi_get_cb_info(
                  e, i, &argc, nullptr, nullptr, &data) != napi_ok ||
              data == nullptr) {
            InventoryError(e, "INVENTORY_IO_FAILED",
                "release_inventory_fence", 0, true);
            return nullptr;
          }
          auto* fence = static_cast<WindowsInventoryFence*>(data);
          napi_value promise;
          if (fence->release_promise) {
            if (napi_get_reference_value(
                    e, fence->release_promise, &promise) != napi_ok) {
              InventoryError(e, "INVENTORY_IO_FAILED",
                  "release_inventory_fence", 0, true);
              return nullptr;
            }
            return promise;
          }
          napi_deferred deferred;
          if (napi_create_promise(e, &deferred, &promise) != napi_ok) {
            InventoryError(e, "INVENTORY_IO_FAILED",
                "release_inventory_fence", 0, true);
            return nullptr;
          }
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
        }
        if (setup_status != napi_ok || !InventoryFenceProperties(
                complete, object, release, work->fence->acquisition_writes)) {
          if (work->fence->handle != INVALID_HANDLE_VALUE) {
            CloseHandle(work->fence->handle);
            work->fence->handle = INVALID_HANDLE_VALUE;
          }
          napi_reject_deferred(
              complete, work->deferred,
              InventoryErrorValue(complete, "INVENTORY_IO_FAILED",
                  "acquire_inventory_fence",
                  work->fence->acquisition_writes, true));
          delete work->fence;
        } else {
          const napi_status reference_status = napi_create_reference(
              complete, object, 0, &work->fence->object_ref);
          const napi_status wrap_status = reference_status == napi_ok
              ? napi_wrap(complete, object, work->fence,
                    WindowsFenceFinalize, nullptr, nullptr)
              : reference_status;
          const napi_status freeze_status = wrap_status == napi_ok
              ? napi_object_freeze(complete, object)
              : wrap_status;
          if (reference_status != napi_ok || wrap_status != napi_ok ||
              freeze_status != napi_ok) {
            bool delete_fence = wrap_status != napi_ok;
            if (wrap_status == napi_ok) {
              void* removed = nullptr;
              delete_fence =
                  napi_remove_wrap(complete, object, &removed) == napi_ok &&
                  removed == work->fence;
            }
            if (work->fence->object_ref) {
              napi_delete_reference(complete, work->fence->object_ref);
              work->fence->object_ref = nullptr;
            }
            if (work->fence->handle != INVALID_HANDLE_VALUE) {
              CloseHandle(work->fence->handle);
              work->fence->handle = INVALID_HANDLE_VALUE;
            }
            napi_reject_deferred(
                complete, work->deferred,
                InventoryErrorValue(complete, "INVENTORY_IO_FAILED",
                    "acquire_inventory_fence",
                    work->fence->acquisition_writes, true));
            if (delete_fence) delete work->fence;
          } else {
            napi_resolve_deferred(complete, work->deferred, object);
          }
        }
      }
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
  napi_value args[4]; std::string path, profile, expected_actor; InventoryRoles roles{};
  if (!InventoryArgs(env, info, 4, args) || !InventoryString(env, args[0], &path) ||
      !InventoryRolesArg(env, args[1], &roles) || !InventoryString(env, args[2], &profile) ||
      !InventoryString(env, args[3], &expected_actor) ||
      (expected_actor != "management" && expected_actor != "daemon" &&
       expected_actor != "recovery" && expected_actor != "system")) {
    InventoryError(env, "INVENTORY_INVALID", "verify_inventory_acl"); return nullptr;
  }
  const uid_t expected_uid = expected_actor == "management" ? roles.management :
      expected_actor == "daemon" ? roles.daemon :
      expected_actor == "recovery" ? roles.recovery : roles.system;
  if (geteuid() != expected_uid) {
    InventoryError(env, "INVENTORY_ACCESS_DENIED", "verify_inventory_acl"); return nullptr;
  }
  if (!ValidInventoryPath(path, profile)) {
    InventoryError(env, "INVENTORY_INVALID", "verify_inventory_acl"); return nullptr;
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
    napi_value object = nullptr, release = nullptr;
    napi_status setup_status = napi_create_object(env, &object);
    if (setup_status == napi_ok) {
      setup_status =
          napi_type_tag_object(env, object, &kInventoryFenceTypeTag);
    }
    if (setup_status == napi_ok) {
      setup_status = napi_create_function(env, "release", NAPI_AUTO_LENGTH,
      [](napi_env release_env, napi_callback_info release_info) -> napi_value {
        void* data = nullptr;
        size_t argc = 0;
        if (napi_get_cb_info(
                release_env, release_info, &argc, nullptr, nullptr,
                &data) != napi_ok ||
            data == nullptr) {
          InventoryError(release_env, "INVENTORY_IO_FAILED",
              "release_inventory_fence", 0, true);
          return nullptr;
        }
        auto* fence = static_cast<InventoryFence*>(data);
        napi_value promise;
        if (fence->release_promise) {
          if (napi_get_reference_value(
                  release_env, fence->release_promise, &promise) != napi_ok) {
            InventoryError(release_env, "INVENTORY_IO_FAILED",
                "release_inventory_fence", 0, true);
            return nullptr;
          }
          return promise;
        }
        napi_deferred deferred;
        if (napi_create_promise(
                release_env, &deferred, &promise) != napi_ok) {
          InventoryError(release_env, "INVENTORY_IO_FAILED",
              "release_inventory_fence", 0, true);
          return nullptr;
        }
        uint32_t ref_count = 0;
        if (napi_create_reference(
                release_env, promise, 1, &fence->release_promise) != napi_ok ||
            !fence->object_ref ||
            napi_reference_ref(
                release_env, fence->object_ref, &ref_count) != napi_ok) {
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
    }
    if (setup_status != napi_ok || !InventoryFenceProperties(
            env, object, release, work->fence->acquisition_writes)) {
      if (work->fence->fd >= 0) {
        flock(work->fence->fd, LOCK_UN);
        close(work->fence->fd);
        work->fence->fd = -1;
      }
      napi_reject_deferred(
          env, work->deferred,
          InventoryErrorValue(env, "INVENTORY_IO_FAILED",
              "acquire_inventory_fence",
              work->fence->acquisition_writes, true));
      work->failed = true;
    } else {
      const napi_status reference_status =
          napi_create_reference(env, object, 0, &work->fence->object_ref);
      const napi_status wrap_status = reference_status == napi_ok
          ? napi_wrap(env, object, work->fence, FenceFinalize,
                nullptr, nullptr)
          : reference_status;
      const napi_status freeze_status = wrap_status == napi_ok
          ? napi_object_freeze(env, object)
          : wrap_status;
      if (reference_status != napi_ok || wrap_status != napi_ok ||
          freeze_status != napi_ok) {
        auto* fence = work->fence;
        bool delete_fence = wrap_status != napi_ok;
        if (wrap_status == napi_ok) {
          void* removed = nullptr;
          delete_fence =
              napi_remove_wrap(env, object, &removed) == napi_ok &&
              removed == fence;
        }
        if (fence->object_ref) {
          napi_delete_reference(env, fence->object_ref);
          fence->object_ref = nullptr;
        }
        if (fence->fd >= 0) {
          flock(fence->fd, LOCK_UN);
          close(fence->fd);
          fence->fd = -1;
        }
        napi_reject_deferred(
            env, work->deferred,
            InventoryErrorValue(env, "INVENTORY_IO_FAILED",
                "acquire_inventory_fence",
                fence->acquisition_writes, true));
        if (!delete_fence) work->fence = nullptr;
        work->failed = true;
      } else {
        napi_resolve_deferred(env, work->deferred, object);
      }
    }
  }
  napi_delete_async_work(env, work->work);
  if (work->timed_out || work->failed) delete work->fence;
  delete work;
}
long RenameAt2(int from_parent, const std::string& from,
               int to_parent, const std::string& to, unsigned int flags);
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
      if (failure == EEXIST) {
        if (!cleaned) {
          close(parent);
          InventoryError(env, "INVENTORY_MANUAL_CLEANUP",
              "acquire_inventory_fence", writes, true);
          return nullptr;
        }
        fence_writes = writes;
      } else {
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
  if (fd < 0) {
    const int failure = errno;
    close(parent);
    InventoryError(env, failure == ENOENT ? "INVENTORY_STALE" :
        "INVENTORY_IO_FAILED", "acquire_inventory_fence", fence_writes);
    return nullptr;
  }
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
  napi_value promise;
  napi_deferred deferred;
  if (napi_create_promise(env, &deferred, &promise) != napi_ok) {
    close(fd);
    InventoryError(env, "INVENTORY_IO_FAILED",
        "acquire_inventory_fence", fence_writes);
    return nullptr;
  }
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

long RenameAt2(int from_parent, const std::string& from,
               int to_parent, const std::string& to, unsigned int flags) {
#ifdef __linux__
  return syscall(SYS_renameat2, from_parent, from.c_str(), to_parent, to.c_str(), flags);
#else
  (void)from_parent; (void)from; (void)to_parent; (void)to; (void)flags;
  errno = ENOSYS; return -1;
#endif
}
long RenameAt2(int parent, const std::string& from, const std::string& to, unsigned int flags) {
  return RenameAt2(parent, from, parent, to, flags);
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

void ServiceError(napi_env env, const char* code, const char* operation,
                  uint32_t writes = 0, bool ambiguous = false) {
  napi_value error, text, value;
  const std::string message = std::string(operation) + " failed";
  napi_create_string_utf8(env, message.c_str(), NAPI_AUTO_LENGTH, &text);
  napi_create_error(env, nullptr, text, &error);
  napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "code", value);
  napi_create_string_utf8(env, operation, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "operation", value);
  napi_create_uint32(env, writes, &value);
  napi_set_named_property(env, error, "writes", value);
  napi_get_boolean(env, ambiguous, &value);
  napi_set_named_property(env, error, "ambiguous", value);
  napi_throw(env, error);
}

void ServiceObservationError(napi_env env, const char* code,
                             const char* operation, const char* reason,
                             bool ambiguous = false) {
  napi_value error, text, value;
  const std::string message = std::string(operation) + " failed";
  napi_create_string_utf8(env, message.c_str(), NAPI_AUTO_LENGTH, &text);
  napi_create_error(env, nullptr, text, &error);
  napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "code", value);
  napi_create_string_utf8(env, operation, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "operation", value);
  napi_create_uint32(env, 0, &value);
  napi_set_named_property(env, error, "writes", value);
  napi_get_boolean(env, ambiguous, &value);
  napi_set_named_property(env, error, "ambiguous", value);
  napi_create_string_utf8(env, reason, NAPI_AUTO_LENGTH, &value);
  napi_set_named_property(env, error, "reason", value);
  napi_throw(env, error);
}

void ServiceSetString(napi_env env, napi_value object, const char* name,
                      const std::string& text) {
  napi_value value;
  napi_create_string_utf8(env, text.c_str(), text.size(), &value);
  napi_set_named_property(env, object, name, value);
}

void ServiceSetUint32(napi_env env, napi_value object, const char* name,
                      uint32_t number) {
  napi_value value;
  napi_create_uint32(env, number, &value);
  napi_set_named_property(env, object, name, value);
}

void ServiceSetDouble(napi_env env, napi_value object, const char* name,
                      double number) {
  napi_value value;
  napi_create_double(env, number, &value);
  napi_set_named_property(env, object, name, value);
}

void ServiceSetBoolean(napi_env env, napi_value object, const char* name,
                       bool flag) {
  napi_value value;
  napi_get_boolean(env, flag, &value);
  napi_set_named_property(env, object, name, value);
}

bool ServiceUint32(napi_env env, napi_value value, uint32_t* result,
                   uint32_t minimum = 0,
                   uint32_t maximum = std::numeric_limits<uint32_t>::max()) {
  uint32_t parsed = 0;
  if (!InventoryUint32(env, value, &parsed) || parsed < minimum ||
      parsed > maximum) return false;
  *result = parsed;
  return true;
}

bool ServiceMaximumBytes(napi_env env, napi_value value, uint64_t* result) {
  napi_valuetype type;
  double numeric = 0;
  constexpr double kMaximumServiceBytes = 2.0 * 1024 * 1024 * 1024;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, value, &numeric) != napi_ok ||
      !std::isfinite(numeric) || numeric < 0 ||
      numeric > kMaximumServiceBytes || std::floor(numeric) != numeric) {
    return false;
  }
  *result = static_cast<uint64_t>(numeric);
  return true;
}

bool ValidServiceFingerprint(const std::string& value) {
  return value.size() == 64 &&
      value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

bool ValidServiceInstanceKey(const std::string& value) {
  if (value.size() < 66 || value.size() > 97) return false;
  const size_t separator = value.size() - 65;
  if (value[separator] != '-' ||
      value.substr(separator + 1).find_first_not_of(
          "0123456789abcdef") != std::string::npos) {
    return false;
  }
  const std::string slug = value.substr(0, separator);
  if (slug.empty() || slug.size() > 32 ||
      !((slug.front() >= 'a' && slug.front() <= 'z') ||
        (slug.front() >= '0' && slug.front() <= '9')) ||
      !((slug.back() >= 'a' && slug.back() <= 'z') ||
        (slug.back() >= '0' && slug.back() <= '9'))) {
    return false;
  }
  return std::all_of(slug.begin(), slug.end(), [](char character) {
    return (character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') || character == '-';
  });
}

enum class ServiceAclProfile {
  ControlDirectory,
  ControlFile,
  StagingDirectory,
  StagingFile,
  ReleaseDirectory,
  ReleaseFile,
  ReleaseExecutable,
  BotLogDirectory,
  DaemonLogDirectory,
  InternalContainerDirectory,
  PreservedContainerDirectory,
  ExternalAnchorDirectory,
  BotConfigDirectory,
  BotConfigFile,
  DaemonConfigDirectory,
  DaemonConfigFile,
  SdkInstallDirectory,
  SdkInstallFile,
  BotRetainedDirectory,
  BotRetainedFile,
  DaemonRetainedDirectory,
  DaemonRetainedFile,
};

enum class ServiceExternalProfile {
  Config,
  RetainedState,
  SdkInstall,
};

enum class ServiceExternalAclPolicy {
  Unresolved,
  Bot,
  Daemon,
  SdkInstall,
};

bool ParseServiceExternalProfile(const std::string& text,
                                ServiceExternalProfile* profile) {
  if (text == "config") {
    *profile = ServiceExternalProfile::Config;
    return true;
  }
  if (text == "retained-state") {
    *profile = ServiceExternalProfile::RetainedState;
    return true;
  }
  if (text == "sdk-install") {
    *profile = ServiceExternalProfile::SdkInstall;
    return true;
  }
  return false;
}

ServiceAclProfile ServiceExternalDirectoryProfile(
    ServiceExternalProfile profile, ServiceExternalAclPolicy policy) {
  switch (profile) {
    case ServiceExternalProfile::Config:
      if (policy == ServiceExternalAclPolicy::Bot) {
        return ServiceAclProfile::BotConfigDirectory;
      }
      if (policy == ServiceExternalAclPolicy::Daemon) {
        return ServiceAclProfile::DaemonConfigDirectory;
      }
      return ServiceAclProfile::ExternalAnchorDirectory;
    case ServiceExternalProfile::RetainedState:
      if (policy == ServiceExternalAclPolicy::Bot) {
        return ServiceAclProfile::BotRetainedDirectory;
      }
      if (policy == ServiceExternalAclPolicy::Daemon) {
        return ServiceAclProfile::DaemonRetainedDirectory;
      }
      return ServiceAclProfile::ExternalAnchorDirectory;
    case ServiceExternalProfile::SdkInstall:
      return ServiceAclProfile::SdkInstallDirectory;
  }
  return ServiceAclProfile::ExternalAnchorDirectory;
}

ServiceAclProfile ServiceExternalFileProfile(
    ServiceExternalProfile profile, ServiceExternalAclPolicy policy) {
  switch (profile) {
    case ServiceExternalProfile::Config:
      if (policy == ServiceExternalAclPolicy::Bot) {
        return ServiceAclProfile::BotConfigFile;
      }
      if (policy == ServiceExternalAclPolicy::Daemon) {
        return ServiceAclProfile::DaemonConfigFile;
      }
      return ServiceAclProfile::ExternalAnchorDirectory;
    case ServiceExternalProfile::RetainedState:
      if (policy == ServiceExternalAclPolicy::Bot) {
        return ServiceAclProfile::BotRetainedFile;
      }
      if (policy == ServiceExternalAclPolicy::Daemon) {
        return ServiceAclProfile::DaemonRetainedFile;
      }
      return ServiceAclProfile::ExternalAnchorDirectory;
    case ServiceExternalProfile::SdkInstall:
      return ServiceAclProfile::SdkInstallFile;
  }
  return ServiceAclProfile::ExternalAnchorDirectory;
}

bool ServiceExternalPolicyAllowed(
    ServiceExternalProfile profile,
    ServiceExternalAclPolicy policy) {
  return (profile == ServiceExternalProfile::Config &&
          (policy == ServiceExternalAclPolicy::Bot ||
           policy == ServiceExternalAclPolicy::Daemon)) ||
      (profile == ServiceExternalProfile::RetainedState &&
       (policy == ServiceExternalAclPolicy::Bot ||
        policy == ServiceExternalAclPolicy::Daemon)) ||
      (profile == ServiceExternalProfile::SdkInstall &&
       policy == ServiceExternalAclPolicy::SdkInstall);
}

bool ParseServiceAclProfile(const std::string& text,
                            ServiceAclProfile* profile) {
  if (text == "service-control-directory") {
    *profile = ServiceAclProfile::ControlDirectory; return true;
  }
  if (text == "service-control-file") {
    *profile = ServiceAclProfile::ControlFile; return true;
  }
  if (text == "service-staging-directory") {
    *profile = ServiceAclProfile::StagingDirectory; return true;
  }
  if (text == "service-staging-file") {
    *profile = ServiceAclProfile::StagingFile; return true;
  }
  if (text == "service-release-directory") {
    *profile = ServiceAclProfile::ReleaseDirectory; return true;
  }
  if (text == "service-release-file") {
    *profile = ServiceAclProfile::ReleaseFile; return true;
  }
  if (text == "service-release-executable") {
    *profile = ServiceAclProfile::ReleaseExecutable; return true;
  }
  if (text == "service-bot-log-directory") {
    *profile = ServiceAclProfile::BotLogDirectory; return true;
  }
  if (text == "service-daemon-log-directory") {
    *profile = ServiceAclProfile::DaemonLogDirectory; return true;
  }
  if (text == "service-external-anchor-directory") {
    *profile = ServiceAclProfile::ExternalAnchorDirectory; return true;
  }
  if (text == "service-bot-config-directory") {
    *profile = ServiceAclProfile::BotConfigDirectory; return true;
  }
  if (text == "service-bot-config-file") {
    *profile = ServiceAclProfile::BotConfigFile; return true;
  }
  if (text == "service-daemon-config-directory") {
    *profile = ServiceAclProfile::DaemonConfigDirectory; return true;
  }
  if (text == "service-daemon-config-file") {
    *profile = ServiceAclProfile::DaemonConfigFile; return true;
  }
  if (text == "service-sdk-install-directory") {
    *profile = ServiceAclProfile::SdkInstallDirectory; return true;
  }
  if (text == "service-sdk-install-file") {
    *profile = ServiceAclProfile::SdkInstallFile; return true;
  }
  if (text == "service-bot-retained-directory") {
    *profile = ServiceAclProfile::BotRetainedDirectory; return true;
  }
  if (text == "service-bot-retained-file") {
    *profile = ServiceAclProfile::BotRetainedFile; return true;
  }
  if (text == "service-daemon-retained-directory") {
    *profile = ServiceAclProfile::DaemonRetainedDirectory; return true;
  }
  if (text == "service-daemon-retained-file") {
    *profile = ServiceAclProfile::DaemonRetainedFile; return true;
  }
  return false;
}

bool ServiceProfileDirectory(ServiceAclProfile profile) {
  return profile == ServiceAclProfile::ControlDirectory ||
      profile == ServiceAclProfile::StagingDirectory ||
      profile == ServiceAclProfile::ReleaseDirectory ||
      profile == ServiceAclProfile::BotLogDirectory ||
      profile == ServiceAclProfile::DaemonLogDirectory ||
      profile == ServiceAclProfile::InternalContainerDirectory ||
      profile == ServiceAclProfile::PreservedContainerDirectory ||
      profile == ServiceAclProfile::ExternalAnchorDirectory ||
      profile == ServiceAclProfile::BotConfigDirectory ||
      profile == ServiceAclProfile::DaemonConfigDirectory ||
      profile == ServiceAclProfile::SdkInstallDirectory ||
      profile == ServiceAclProfile::BotRetainedDirectory ||
      profile == ServiceAclProfile::DaemonRetainedDirectory;
}

bool ServiceProfileExternal(ServiceAclProfile profile) {
  return profile == ServiceAclProfile::BotLogDirectory ||
      profile == ServiceAclProfile::DaemonLogDirectory ||
      profile == ServiceAclProfile::ExternalAnchorDirectory ||
      profile == ServiceAclProfile::BotConfigDirectory ||
      profile == ServiceAclProfile::BotConfigFile ||
      profile == ServiceAclProfile::DaemonConfigDirectory ||
      profile == ServiceAclProfile::DaemonConfigFile ||
      profile == ServiceAclProfile::SdkInstallDirectory ||
      profile == ServiceAclProfile::SdkInstallFile ||
      profile == ServiceAclProfile::BotRetainedDirectory ||
      profile == ServiceAclProfile::BotRetainedFile ||
      profile == ServiceAclProfile::DaemonRetainedDirectory ||
      profile == ServiceAclProfile::DaemonRetainedFile;
}

bool ServiceProfileOwned(ServiceAclProfile profile) {
  return !ServiceProfileExternal(profile) &&
      profile != ServiceAclProfile::PreservedContainerDirectory;
}

size_t ServiceProfileOwner(ServiceAclProfile profile) {
  if (profile == ServiceAclProfile::BotLogDirectory ||
      profile == ServiceAclProfile::BotRetainedDirectory ||
      profile == ServiceAclProfile::BotRetainedFile) return 1;
  if (profile == ServiceAclProfile::DaemonLogDirectory ||
      profile == ServiceAclProfile::DaemonRetainedDirectory ||
      profile == ServiceAclProfile::DaemonRetainedFile) return 3;
  return 0;
}

uint8_t ServiceRoleMode(ServiceAclProfile profile, size_t role) {
  const bool directory = ServiceProfileDirectory(profile);
  if (profile == ServiceAclProfile::ControlDirectory ||
      profile == ServiceAclProfile::ControlFile ||
      profile == ServiceAclProfile::StagingDirectory ||
      profile == ServiceAclProfile::StagingFile) {
    return role == 0 || role == 2 || role == 4
        ? static_cast<uint8_t>(directory ? 7 : 6) : 0;
  }
  if (profile == ServiceAclProfile::ReleaseDirectory) {
    return role == 0 || role == 2 || role == 4 ? 7 : 5;
  }
  if (profile == ServiceAclProfile::InternalContainerDirectory) {
    return role == 0 || role == 2 || role == 4 ? 7 : 5;
  }
  if (profile == ServiceAclProfile::PreservedContainerDirectory) {
    return 0;
  }
  if (profile == ServiceAclProfile::ExternalAnchorDirectory) {
    return role == 0 ? 7 :
        (role == 2 || role == 4 ? 5 : 0);
  }
  if (profile == ServiceAclProfile::BotConfigDirectory ||
      profile == ServiceAclProfile::BotConfigFile ||
      profile == ServiceAclProfile::DaemonConfigDirectory ||
      profile == ServiceAclProfile::DaemonConfigFile) {
    const size_t workload =
        profile == ServiceAclProfile::BotConfigDirectory ||
                profile == ServiceAclProfile::BotConfigFile
            ? 1 : 3;
    const uint8_t read_mode = static_cast<uint8_t>(directory ? 5 : 4);
    if (role == 0) return static_cast<uint8_t>(directory ? 7 : 6);
    if (role == 2 || role == 4 || role == workload) return read_mode;
    return 0;
  }
  if (profile == ServiceAclProfile::SdkInstallDirectory ||
      profile == ServiceAclProfile::SdkInstallFile) {
    if (role == 0) return static_cast<uint8_t>(directory ? 7 : 6);
    if (role == 2 || role == 4) {
      return static_cast<uint8_t>(directory ? 5 : 4);
    }
    return role == 3 ? 5 : 0;
  }
  if (profile == ServiceAclProfile::BotRetainedDirectory ||
      profile == ServiceAclProfile::BotRetainedFile ||
      profile == ServiceAclProfile::DaemonRetainedDirectory ||
      profile == ServiceAclProfile::DaemonRetainedFile) {
    const size_t workload =
        profile == ServiceAclProfile::BotRetainedDirectory ||
                profile == ServiceAclProfile::BotRetainedFile
            ? 1 : 3;
    if (role == 0 || role == workload) {
      return static_cast<uint8_t>(directory ? 7 : 6);
    }
    return role == 2 || role == 4
        ? static_cast<uint8_t>(directory ? 5 : 4) : 0;
  }
  if (profile == ServiceAclProfile::ReleaseExecutable) return 5;
  if (profile == ServiceAclProfile::ReleaseFile) return 4;
  const size_t workload = profile == ServiceAclProfile::BotLogDirectory ? 1 : 3;
  if (role == workload || role == 4) return 7;
  return role == 0 || role == 2 ? 5 : 0;
}

#ifdef _WIN32
bool ServiceActorAuthorized(const InventoryRoles& roles) {
  return CurrentInventoryActor(roles, true, false, true, true);
}

ACCESS_MASK WindowsServiceFileRights(ServiceAclProfile profile, size_t role) {
  const uint8_t mode = ServiceRoleMode(profile, role);
  if (mode == 0) return 0;
  ACCESS_MASK rights = (mode & 4) ? FILE_GENERIC_READ : 0;
  if (mode & 2) rights |= FILE_GENERIC_WRITE;
  if (mode & 1) rights |= FILE_GENERIC_EXECUTE;
  if (!ServiceProfileExternal(profile) && (mode & 2)) {
    rights |= DELETE;
  }
  if (ServiceProfileDirectory(profile) && (mode & 2)) rights |= FILE_DELETE_CHILD;
  if (ServiceProfileOwned(profile) &&
      (role == 0 || role == 2 || role == 4)) {
    rights |= WRITE_DAC | WRITE_OWNER;
  }
  return rights;
}

bool BuildWindowsServiceFileAcl(const InventoryRoles& roles,
                                ServiceAclProfile profile, PACL* acl,
                                std::vector<PSID>* allocated) {
  const std::string values[] = {
    roles.management, roles.bot, roles.recovery, roles.daemon, roles.system,
  };
  EXPLICIT_ACCESSW entries[5]{};
  ULONG count = 0;
  for (size_t role = 0; role < 5; ++role) {
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(Wide(values[role]).c_str(), &sid)) return false;
    allocated->push_back(sid);
    const ACCESS_MASK rights = WindowsServiceFileRights(profile, role);
    if (rights == 0) continue;
    entries[count].grfAccessPermissions = rights;
    entries[count].grfAccessMode = SET_ACCESS;
    entries[count].grfInheritance = NO_INHERITANCE;
    entries[count].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[count].Trustee.TrusteeType = TRUSTEE_IS_USER;
    entries[count].Trustee.ptstrName = static_cast<LPWSTR>(sid);
    ++count;
  }
  return SetEntriesInAclW(count, entries, nullptr, acl) == ERROR_SUCCESS;
}

bool VerifyWindowsServiceFileAcl(HANDLE handle, const InventoryRoles& roles,
                                 ServiceAclProfile profile) {
  FILE_ATTRIBUTE_TAG_INFO attributes{};
  if (!GetFileInformationByHandleEx(
          handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
      (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
      ServiceProfileDirectory(profile) !=
          static_cast<bool>(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
    return false;
  }
  PACL expected_acl = nullptr;
  std::vector<PSID> expected_sids;
  if (!BuildWindowsServiceFileAcl(
          roles, profile, &expected_acl, &expected_sids)) {
    for (PSID sid : expected_sids) LocalFree(sid);
    return false;
  }
  PSID owner = nullptr;
  PACL actual_acl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  ACL_SIZE_INFORMATION size{};
  bool valid =
      GetSecurityInfo(handle, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
          &owner, nullptr, &actual_acl, nullptr, &descriptor) == ERROR_SUCCESS &&
      owner && EqualSid(owner, expected_sids[ServiceProfileOwner(profile)]) &&
      GetSecurityDescriptorControl(descriptor, &control, &revision) &&
      (control & SE_DACL_PROTECTED) != 0 && actual_acl &&
      GetAclInformation(actual_acl, &size, sizeof(size), AclSizeInformation);
  ULONG expected_count = 0;
  for (size_t role = 0; role < 5; ++role) {
    if (WindowsServiceFileRights(profile, role) != 0) ++expected_count;
  }
  valid = valid && size.AceCount == expected_count;
  bool seen[5]{};
  for (DWORD index = 0; valid && index < size.AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(actual_acl, index, &raw)) { valid = false; break; }
    auto* header = static_cast<ACE_HEADER*>(raw);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0) {
      valid = false; break;
    }
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    bool matched = false;
    for (size_t role = 0; role < 5; ++role) {
      const ACCESS_MASK rights = WindowsServiceFileRights(profile, role);
      if (rights != 0 && !seen[role] && ace->Mask == rights &&
          EqualSid(reinterpret_cast<PSID>(&ace->SidStart),
                   expected_sids[role])) {
        seen[role] = true;
        matched = true;
        break;
      }
    }
    if (!matched) valid = false;
  }
  if (descriptor) LocalFree(descriptor);
  if (expected_acl) LocalFree(expected_acl);
  for (PSID sid : expected_sids) LocalFree(sid);
  for (size_t role = 0; valid && role < 5; ++role) {
    if (WindowsServiceFileRights(profile, role) != 0 && !seen[role]) valid = false;
  }
  return valid;
}

bool ApplyWindowsServiceFileAcl(HANDLE handle, const InventoryRoles& roles,
                                ServiceAclProfile profile,
                                bool* mutated = nullptr) {
  if (mutated) *mutated = false;
  PACL acl = nullptr;
  std::vector<PSID> sids;
  if (!BuildWindowsServiceFileAcl(roles, profile, &acl, &sids)) {
    for (PSID sid : sids) LocalFree(sid);
    return false;
  }
  PSID current_owner = nullptr;
  PSECURITY_DESCRIPTOR current_descriptor = nullptr;
  const DWORD owner_status = GetSecurityInfo(
      handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
      &current_owner, nullptr, nullptr, nullptr,
      &current_descriptor);
  const bool owner_matches = owner_status == ERROR_SUCCESS &&
      current_owner &&
      EqualSid(current_owner, sids[ServiceProfileOwner(profile)]);
  DWORD owner_update = owner_status;
  if (owner_status == ERROR_SUCCESS) {
    owner_update = owner_matches ? ERROR_SUCCESS
        : SetSecurityInfo(
            handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
            sids[ServiceProfileOwner(profile)], nullptr,
            nullptr, nullptr);
    if (!owner_matches && owner_update == ERROR_SUCCESS && mutated) {
      *mutated = true;
    }
  }
  const DWORD dacl_update = owner_update == ERROR_SUCCESS
      ? SetSecurityInfo(
          handle, SE_FILE_OBJECT,
          DACL_SECURITY_INFORMATION |
              PROTECTED_DACL_SECURITY_INFORMATION,
          nullptr, nullptr, acl, nullptr)
      : owner_update;
  if (dacl_update == ERROR_SUCCESS && mutated) *mutated = true;
  if (current_descriptor) LocalFree(current_descriptor);
  if (acl) LocalFree(acl);
  for (PSID sid : sids) LocalFree(sid);
  return dacl_update == ERROR_SUCCESS &&
      VerifyWindowsServiceFileAcl(handle, roles, profile);
}
#else
bool ServiceActorAuthorized(const InventoryRoles& roles) {
  const uid_t actor = geteuid();
  return actor == roles.management || actor == roles.recovery ||
      actor == roles.system;
}

bool BuildPosixServiceAcl(int fd, const InventoryRoles& roles,
                          ServiceAclProfile profile, bool apply,
                          bool* mutated = nullptr) {
  if (mutated) *mutated = false;
  struct stat metadata{};
  if (fstat(fd, &metadata) != 0 ||
      ServiceProfileDirectory(profile) != static_cast<bool>(S_ISDIR(metadata.st_mode)) ||
      (!S_ISDIR(metadata.st_mode) && !S_ISREG(metadata.st_mode))) {
    return false;
  }
  const uid_t values[] = {
    roles.management, roles.bot, roles.recovery, roles.daemon, roles.system,
  };
  const size_t owner_role = ServiceProfileOwner(profile);
  if (apply && fchown(fd, values[owner_role], static_cast<gid_t>(-1)) != 0) {
    return false;
  }
  if (apply && mutated) *mutated = true;
  if (fstat(fd, &metadata) != 0 || metadata.st_uid != values[owner_role]) {
    return false;
  }
  if (apply) {
    acl_t acl = acl_init(9);
    if (!acl) return false;
    bool ok = true;
    acl_entry_t entry;
    acl_permset_t permissions;
    auto add = [&](acl_tag_t tag, const uid_t* uid, uint8_t mode) {
      if (!ok || acl_create_entry(&acl, &entry) != 0 ||
          acl_set_tag_type(entry, tag) != 0 ||
          (uid && acl_set_qualifier(entry, uid) != 0) ||
          acl_get_permset(entry, &permissions) != 0 ||
          acl_clear_perms(permissions) != 0 ||
          ((mode & 4) && acl_add_perm(permissions, ACL_READ) != 0) ||
          ((mode & 2) && acl_add_perm(permissions, ACL_WRITE) != 0) ||
          ((mode & 1) && acl_add_perm(permissions, ACL_EXECUTE) != 0)) {
        ok = false;
      }
    };
    add(ACL_USER_OBJ, nullptr, ServiceRoleMode(profile, owner_role));
    for (size_t role = 0; role < 5; ++role) {
      if (role != owner_role && ServiceRoleMode(profile, role) != 0) {
        add(ACL_USER, &values[role], ServiceRoleMode(profile, role));
      }
    }
    add(ACL_GROUP_OBJ, nullptr, 0);
    uint8_t mask = 0;
    for (size_t role = 0; role < 5; ++role) {
      mask |= ServiceRoleMode(profile, role);
    }
    add(ACL_MASK, nullptr, mask);
    add(ACL_OTHER, nullptr, 0);
    if (!ok || acl_valid(acl) != 0 || acl_set_fd(fd, acl) != 0) {
      ok = false;
    }
    acl_free(acl);
    if (ok && ServiceProfileDirectory(profile)) {
#ifdef __linux__
      const std::string descriptor =
          "/proc/self/fd/" + std::to_string(fd);
      if (acl_delete_def_file(descriptor.c_str()) != 0 &&
          errno != ENODATA) ok = false;
#else
      ok = false;
#endif
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (!ok) return false;
  }

  acl_t acl = acl_get_fd(fd);
  if (!acl) return false;
  bool seen_owner = false, seen_group = false, seen_mask = false,
       seen_other = false, valid = true, seen[5]{};
  size_t count = 0;
  acl_entry_t entry;
  int cursor = ACL_FIRST_ENTRY;
  while (valid && acl_get_entry(acl, cursor, &entry) == 1) {
    cursor = ACL_NEXT_ENTRY;
    ++count;
    acl_tag_t tag;
    acl_permset_t permissions;
    if (acl_get_tag_type(entry, &tag) != 0 ||
        acl_get_permset(entry, &permissions) != 0) {
      valid = false; break;
    }
    const uint8_t mode =
        (acl_get_perm(permissions, ACL_READ) == 1 ? 4 : 0) |
        (acl_get_perm(permissions, ACL_WRITE) == 1 ? 2 : 0) |
        (acl_get_perm(permissions, ACL_EXECUTE) == 1 ? 1 : 0);
    if (tag == ACL_USER_OBJ) {
      valid = !seen_owner && mode == ServiceRoleMode(profile, owner_role);
      seen_owner = true;
    } else if (tag == ACL_USER) {
      uid_t* uid = static_cast<uid_t*>(acl_get_qualifier(entry));
      if (!uid) { valid = false; break; }
      bool matched = false;
      for (size_t role = 0; role < 5; ++role) {
        if (role != owner_role && ServiceRoleMode(profile, role) != 0 &&
            !seen[role] && *uid == values[role] &&
            mode == ServiceRoleMode(profile, role)) {
          seen[role] = true;
          matched = true;
          break;
        }
      }
      acl_free(uid);
      if (!matched) valid = false;
    } else if (tag == ACL_GROUP_OBJ) {
      valid = !seen_group && mode == 0;
      seen_group = true;
    } else if (tag == ACL_MASK) {
      uint8_t expected = 0;
      for (size_t role = 0; role < 5; ++role) {
        expected |= ServiceRoleMode(profile, role);
      }
      valid = !seen_mask && mode == expected;
      seen_mask = true;
    } else if (tag == ACL_OTHER) {
      valid = !seen_other && mode == 0;
      seen_other = true;
    } else {
      valid = false;
    }
  }
  size_t expected_count = 4;
  for (size_t role = 0; role < 5; ++role) {
    if (role != owner_role && ServiceRoleMode(profile, role) != 0) {
      ++expected_count;
      if (!seen[role]) valid = false;
    }
  }
  acl_free(acl);
  if (valid && ServiceProfileDirectory(profile) &&
      !HasEmptyInventoryDefaultAcl(fd)) valid = false;
  return valid && seen_owner && seen_group && seen_mask && seen_other &&
      count == expected_count;
}
#endif

napi_value SetExactServiceAcl(napi_env env, napi_callback_info info) {
  napi_value args[3];
  std::string path, profile_text;
  InventoryRoles roles{};
  ServiceAclProfile profile;
  if (!InventoryArgs(env, info, 3, args) ||
      !InventoryString(env, args[0], &path) ||
      !InventoryRolesArg(env, args[1], &roles) ||
      !InventoryString(env, args[2], &profile_text) ||
      !ParseServiceAclProfile(profile_text, &profile) ||
      ServiceProfileExternal(profile) || path.empty() ||
      path.size() > 4096 || !ServiceActorAuthorized(roles)) {
    ServiceError(env, "SERVICE_INVALID", "set_exact_service_acl");
    return nullptr;
  }
#ifdef _WIN32
  WindowsPathParts parts;
  if (!ParseWindowsPath(path, &parts)) {
    ServiceError(env, "SERVICE_INVALID", "set_exact_service_acl");
    return nullptr;
  }
  HANDLE handle = OpenWindowsPathNoFollow(path,
      READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES,
      ServiceProfileDirectory(profile)
          ? VerifiedObjectType::Directory : VerifiedObjectType::File);
  bool mutated = false;
  const bool applied = handle != INVALID_HANDLE_VALUE &&
      ApplyWindowsServiceFileAcl(handle, roles, profile, &mutated);
  if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
#else
  if (path[0] != '/') {
    ServiceError(env, "SERVICE_INVALID", "set_exact_service_acl");
    return nullptr;
  }
  int parent = -1;
  std::string name;
  bool applied = false;
  bool mutated = false;
  if (OpenParentNoFollow(path, &parent, &name)) {
    int fd = OpenObjectNoFollow(parent, name,
        ServiceProfileDirectory(profile) ? O_RDONLY | O_DIRECTORY : O_RDWR);
    applied = fd >= 0 &&
        BuildPosixServiceAcl(fd, roles, profile, true, &mutated);
    if (fd >= 0) close(fd);
    close(parent);
  }
#endif
  if (!applied) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "set_exact_service_acl", mutated ? 1 : 0, mutated);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetUint32(env, result, "writes", mutated ? 1 : 0);
  return result;
}

napi_value VerifyExactServiceAclMethod(napi_env env, napi_callback_info info) {
  napi_value args[3];
  std::string path, profile_text;
  InventoryRoles roles{};
  ServiceAclProfile profile;
  if (!InventoryArgs(env, info, 3, args) ||
      !InventoryString(env, args[0], &path) ||
      !InventoryRolesArg(env, args[1], &roles) ||
      !InventoryString(env, args[2], &profile_text) ||
      !ParseServiceAclProfile(profile_text, &profile) || path.empty() ||
      path.size() > 4096 || !ServiceActorAuthorized(roles)) {
    ServiceError(env, "SERVICE_INVALID", "verify_exact_service_acl");
    return nullptr;
  }
  bool verified = false;
#ifdef _WIN32
  WindowsPathParts parts;
  if (!ParseWindowsPath(path, &parts)) {
    ServiceError(env, "SERVICE_INVALID", "verify_exact_service_acl");
    return nullptr;
  }
  HANDLE handle = OpenWindowsPathNoFollow(path,
      READ_CONTROL | FILE_READ_ATTRIBUTES,
      ServiceProfileDirectory(profile)
          ? VerifiedObjectType::Directory : VerifiedObjectType::File);
  verified = handle != INVALID_HANDLE_VALUE &&
      VerifyWindowsServiceFileAcl(handle, roles, profile);
  if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
#else
  if (path[0] != '/') {
    ServiceError(env, "SERVICE_INVALID", "verify_exact_service_acl");
    return nullptr;
  }
  int parent = -1;
  std::string name;
  if (OpenParentNoFollow(path, &parent, &name)) {
    int fd = OpenObjectNoFollow(parent, name,
        ServiceProfileDirectory(profile) ? O_RDONLY | O_DIRECTORY : O_RDONLY);
    verified = fd >= 0 && BuildPosixServiceAcl(fd, roles, profile, false);
    if (fd >= 0) close(fd);
    close(parent);
  }
#endif
  napi_value result;
  napi_get_boolean(env, verified, &result);
  return result;
}

bool ServiceSecurityFingerprint(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    std::string* result) {
#ifdef _WIN32
  PSID owner = nullptr;
  PSID group = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(handle, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
              DACL_SECURITY_INFORMATION,
          &owner, &group, &dacl, nullptr, &descriptor) != ERROR_SUCCESS ||
      descriptor == nullptr) {
    if (descriptor) LocalFree(descriptor);
    return false;
  }
  const DWORD bytes = GetSecurityDescriptorLength(descriptor);
  if (bytes == 0) {
    LocalFree(descriptor);
    return false;
  }
  Sha256 hash;
  const bool updated = hash.Update(descriptor, bytes);
  *result = hash.Finish();
  LocalFree(descriptor);
  return updated && ValidServiceFingerprint(*result);
#else
  acl_t acl = acl_get_fd(handle);
  if (!acl) return false;
  ssize_t length = 0;
  char* text = acl_to_text(acl, &length);
  if (!text || length < 0) {
    if (text) acl_free(text);
    acl_free(acl);
    return false;
  }
  Sha256 hash;
  const bool updated = hash.Update(text, static_cast<size_t>(length));
  *result = hash.Finish();
  acl_free(text);
  acl_free(acl);
  return updated && ValidServiceFingerprint(*result);
#endif
}

napi_value ReadFileFactsNoFollow(napi_env env, napi_callback_info info) {
  napi_value args[2];
  std::string path;
  uint64_t maximum = 0;
  if (!InventoryArgs(env, info, 2, args) ||
      !InventoryString(env, args[0], &path) || path.empty() ||
      path.size() > 4096 || !ServiceMaximumBytes(env, args[1], &maximum)) {
    ServiceError(env, "SERVICE_INVALID", "read_file_facts_no_follow");
    return nullptr;
  }
#ifdef _WIN32
  WindowsPathParts parts;
  if (!ParseWindowsPath(path, &parts)) {
    ServiceError(env, "SERVICE_INVALID", "read_file_facts_no_follow");
    return nullptr;
  }
  HANDLE handle = OpenWindowsPathNoFollow(path, GENERIC_READ | READ_CONTROL,
      VerifiedObjectType::File, FILE_SHARE_READ | FILE_SHARE_DELETE);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      napi_value absent;
      napi_get_null(env, &absent);
      return absent;
    }
    ServiceError(env, "SERVICE_IO_FAILED", "read_file_facts_no_follow");
    return nullptr;
  }
  FILE_ID_INFO before_id{}, after_id{};
  FILE_BASIC_INFO before_basic{}, after_basic{};
  FILE_STANDARD_INFO before_standard{}, after_standard{};
  std::string serial, file_id, owner, security;
  uint32_t attributes = 0;
  bool valid =
      GetFileInformationByHandleEx(handle, FileIdInfo, &before_id,
                                   sizeof(before_id)) &&
      GetFileInformationByHandleEx(handle, FileBasicInfo, &before_basic,
                                   sizeof(before_basic)) &&
      GetFileInformationByHandleEx(handle, FileStandardInfo, &before_standard,
                                   sizeof(before_standard)) &&
      before_standard.EndOfFile.QuadPart >= 0 &&
      static_cast<uint64_t>(before_standard.EndOfFile.QuadPart) <= maximum &&
      InventoryIdentity(handle, &serial, &file_id, &attributes, &owner) &&
      ServiceSecurityFingerprint(handle, &security);
  Sha256 hash;
  bool crypto_failed = !hash.Ready();
  valid = valid && !crypto_failed;
  std::array<uint8_t, 64 * 1024> buffer{};
  uint64_t read_total = 0;
  while (valid && read_total <
      static_cast<uint64_t>(before_standard.EndOfFile.QuadPart)) {
    const DWORD requested = static_cast<DWORD>(std::min<uint64_t>(
        buffer.size(),
        static_cast<uint64_t>(before_standard.EndOfFile.QuadPart) - read_total));
    DWORD read = 0;
    if (!ReadFile(handle, buffer.data(), requested, &read, nullptr) ||
        read == 0) {
      valid = false;
      break;
    }
    if (!hash.Update(buffer.data(), read)) {
      crypto_failed = true;
      valid = false;
    }
    read_total += read;
  }
  valid = valid &&
      GetFileInformationByHandleEx(handle, FileIdInfo, &after_id,
                                   sizeof(after_id)) &&
      GetFileInformationByHandleEx(handle, FileBasicInfo, &after_basic,
                                   sizeof(after_basic)) &&
      GetFileInformationByHandleEx(handle, FileStandardInfo, &after_standard,
                                   sizeof(after_standard)) &&
      SameWindowsFileId(before_id, after_id) &&
      before_basic.CreationTime.QuadPart == after_basic.CreationTime.QuadPart &&
      before_basic.LastAccessTime.QuadPart == after_basic.LastAccessTime.QuadPart &&
      before_basic.LastWriteTime.QuadPart == after_basic.LastWriteTime.QuadPart &&
      before_basic.ChangeTime.QuadPart == after_basic.ChangeTime.QuadPart &&
      before_basic.FileAttributes == after_basic.FileAttributes &&
      before_standard.EndOfFile.QuadPart == after_standard.EndOfFile.QuadPart &&
      before_standard.AllocationSize.QuadPart ==
          after_standard.AllocationSize.QuadPart &&
      before_standard.NumberOfLinks == after_standard.NumberOfLinks &&
      !before_standard.DeletePending && !after_standard.DeletePending &&
      read_total == static_cast<uint64_t>(before_standard.EndOfFile.QuadPart);
  std::string digest;
  if (valid) digest = hash.Finish();
  if (valid && !ValidServiceFingerprint(digest)) crypto_failed = true;
  valid = valid && ValidServiceFingerprint(digest);
  CloseHandle(handle);
  if (!valid) {
    ServiceError(env,
        crypto_failed ? "SERVICE_CRYPTO_UNAVAILABLE" : "SERVICE_STALE",
        "read_file_facts_no_follow");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "kind", "win32-file-v1");
  ServiceSetString(env, result, "volumeSerial", serial);
  ServiceSetString(env, result, "fileId", file_id);
  ServiceSetDouble(env, result, "size",
      static_cast<double>(before_standard.EndOfFile.QuadPart));
  ServiceSetString(env, result, "sha256", digest);
  ServiceSetUint32(env, result, "attributes", attributes);
  ServiceSetString(env, result, "owner", owner);
  ServiceSetString(env, result, "securitySha256", security);
  return result;
#else
  if (path[0] != '/') {
    ServiceError(env, "SERVICE_INVALID", "read_file_facts_no_follow");
    return nullptr;
  }
  int parent = -1;
  std::string name;
  if (!OpenParentNoFollow(path, &parent, &name)) {
    if (errno == ENOENT) {
      napi_value absent;
      napi_get_null(env, &absent);
      return absent;
    }
    ServiceError(env, "SERVICE_IO_FAILED", "read_file_facts_no_follow");
    return nullptr;
  }
  int handle = OpenObjectNoFollow(parent, name, O_RDONLY);
  const int open_error = errno;
  close(parent);
  if (handle < 0) {
    if (open_error == ENOENT) {
      napi_value absent;
      napi_get_null(env, &absent);
      return absent;
    }
    ServiceError(env, "SERVICE_IO_FAILED", "read_file_facts_no_follow");
    return nullptr;
  }
  struct stat before{}, after{};
  std::string security;
  bool valid = fstat(handle, &before) == 0 && S_ISREG(before.st_mode) &&
      before.st_size >= 0 && static_cast<uint64_t>(before.st_size) <= maximum &&
      ServiceSecurityFingerprint(handle, &security);
  Sha256 hash;
  bool crypto_failed = !hash.Ready();
  valid = valid && !crypto_failed;
  std::array<uint8_t, 64 * 1024> buffer{};
  uint64_t read_total = 0;
  while (valid && read_total < static_cast<uint64_t>(before.st_size)) {
    const ssize_t read = ::read(handle, buffer.data(), std::min<uint64_t>(
        buffer.size(), static_cast<uint64_t>(before.st_size) - read_total));
    if (read <= 0) {
      valid = false;
      break;
    }
    if (!hash.Update(buffer.data(), static_cast<size_t>(read))) {
      crypto_failed = true;
      valid = false;
    }
    read_total += static_cast<uint64_t>(read);
  }
  valid = valid && fstat(handle, &after) == 0 &&
      before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
      before.st_mode == after.st_mode && before.st_uid == after.st_uid &&
      before.st_gid == after.st_gid && before.st_size == after.st_size &&
      before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
      before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
      before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
      before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
      read_total == static_cast<uint64_t>(before.st_size);
  std::string digest;
  if (valid) digest = hash.Finish();
  if (valid && !ValidServiceFingerprint(digest)) crypto_failed = true;
  valid = valid && ValidServiceFingerprint(digest);
  close(handle);
  if (!valid) {
    ServiceError(env,
        crypto_failed ? "SERVICE_CRYPTO_UNAVAILABLE" : "SERVICE_STALE",
        "read_file_facts_no_follow");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "kind", "linux-file-v1");
  ServiceSetString(env, result, "device",
      std::to_string(static_cast<uint64_t>(before.st_dev)));
  ServiceSetString(env, result, "inode",
      std::to_string(static_cast<uint64_t>(before.st_ino)));
  ServiceSetDouble(env, result, "size", static_cast<double>(before.st_size));
  ServiceSetString(env, result, "sha256", digest);
  ServiceSetUint32(env, result, "mode",
      static_cast<uint32_t>(before.st_mode));
  ServiceSetString(env, result, "owner",
      "uid:" + std::to_string(static_cast<uint64_t>(before.st_uid)));
  ServiceSetString(env, result, "securitySha256", security);
  return result;
#endif
}

#ifdef _WIN32
bool ReadWindowsBootIdentity(std::string* boot_id) {
  struct SystemTimeOfDayInformation {
    LARGE_INTEGER boot_time;
    LARGE_INTEGER current_time;
    LARGE_INTEGER timezone_bias;
    ULONG timezone_id;
    ULONG reserved;
    ULONGLONG boot_time_bias;
    ULONGLONG sleep_time_bias;
  } value{};
  using NtQuerySystemInformationFunction =
      LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
  auto query = reinterpret_cast<NtQuerySystemInformationFunction>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                     "NtQuerySystemInformation"));
  ULONG returned = 0;
  if (!query || query(3, &value, sizeof(value), &returned) < 0 ||
      returned < sizeof(value.boot_time) || value.boot_time.QuadPart <= 0) {
    return false;
  }
  *boot_id = "win32:" + std::to_string(
      static_cast<uint64_t>(value.boot_time.QuadPart));
  return true;
}
#endif

napi_value ReadBootId(napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!InventoryArgs(env, info, 0, args)) {
    ServiceError(env, "SERVICE_INVALID", "read_boot_id");
    return nullptr;
  }
#ifdef _WIN32
  struct SystemTimeOfDayInformation {
    LARGE_INTEGER boot_time;
    LARGE_INTEGER current_time;
    LARGE_INTEGER timezone_bias;
    ULONG timezone_id;
    ULONG reserved;
    ULONGLONG boot_time_bias;
    ULONGLONG sleep_time_bias;
  } value{};
  using NtQuerySystemInformationFunction =
      LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
  auto query = reinterpret_cast<NtQuerySystemInformationFunction>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                     "NtQuerySystemInformation"));
  ULONG returned = 0;
  if (!query || query(3, &value, sizeof(value), &returned) < 0 ||
      value.boot_time.QuadPart <= 0) {
    ServiceError(env, "SERVICE_IO_FAILED", "read_boot_id");
    return nullptr;
  }
  const std::string boot =
      "win32:" + std::to_string(
          static_cast<uint64_t>(value.boot_time.QuadPart));
#else
  int handle = open("/proc/sys/kernel/random/boot_id",
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  std::array<char, 64> buffer{};
  const ssize_t bytes = handle >= 0
      ? ::read(handle, buffer.data(), buffer.size()) : -1;
  if (handle >= 0) close(handle);
  if (bytes < 36) {
    ServiceError(env, "SERVICE_IO_FAILED", "read_boot_id");
    return nullptr;
  }
  std::string id(buffer.data(), static_cast<size_t>(bytes));
  while (!id.empty() && (id.back() == '\n' || id.back() == '\r')) id.pop_back();
  bool valid = id.size() == 36;
  for (size_t index = 0; valid && index < id.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      valid = id[index] == '-';
    } else {
      valid = (id[index] >= '0' && id[index] <= '9') ||
          (id[index] >= 'a' && id[index] <= 'f');
    }
  }
  if (!valid) {
    ServiceError(env, "SERVICE_IO_FAILED", "read_boot_id");
    return nullptr;
  }
  const std::string boot = "linux:" + id;
#endif
  napi_value result;
  napi_create_string_utf8(env, boot.c_str(), boot.size(), &result);
  return result;
}

struct ServiceProcessFacts {
  uint32_t pid = 0;
  uint32_t parent_pid = 0;
  uint64_t start_time = 0;
  std::string executable;
  std::string owner;
  std::string state;
  uint32_t depth = 0;
};

enum class ProcessReadResult { Ok, Absent, Unreadable };
thread_local bool gServiceTreeOverflow = false;

#ifdef _WIN32
bool WindowsProcessParent(uint32_t pid, uint32_t* parent) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return false;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  bool found = false;
  if (Process32FirstW(snapshot, &entry)) {
    do {
      if (entry.th32ProcessID == pid) {
        *parent = entry.th32ParentProcessID;
        found = true;
        break;
      }
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return found;
}

ProcessReadResult ReadServiceProcessFacts(uint32_t pid,
                                          ServiceProcessFacts* result,
                                          const uint32_t* known_parent = nullptr,
                                          HANDLE retained = nullptr) {
  const bool owns_handle = retained == nullptr;
  HANDLE process = retained;
  if (owns_handle) {
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                          FALSE, pid);
  }
  if (!process) {
    const DWORD error = GetLastError();
    return error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_FOUND
        ? ProcessReadResult::Absent : ProcessReadResult::Unreadable;
  }
  FILETIME creation{}, exit{}, kernel{}, user{};
  DWORD path_size = 32768;
  std::vector<wchar_t> path(path_size);
  HANDLE token = nullptr;
  DWORD token_bytes = 0;
  std::string owner;
  bool valid = GetProcessTimes(process, &creation, &exit, &kernel, &user) &&
      QueryFullProcessImageNameW(process, 0, path.data(), &path_size) &&
      path_size > 0 &&
      OpenProcessToken(process, TOKEN_QUERY, &token) &&
      !GetTokenInformation(token, TokenUser, nullptr, 0, &token_bytes) &&
      GetLastError() == ERROR_INSUFFICIENT_BUFFER && token_bytes > 0;
  if (valid) {
    std::vector<uint8_t> token_data(token_bytes);
    valid = GetTokenInformation(token, TokenUser, token_data.data(),
        token_bytes, &token_bytes);
    if (valid) {
      LPWSTR sid = nullptr;
      valid = ConvertSidToStringSidW(
          reinterpret_cast<TOKEN_USER*>(token_data.data())->User.Sid, &sid);
      if (valid) {
        owner = Utf8(sid);
        LocalFree(sid);
      }
    }
  }
  DWORD exit_code = 0;
  valid = valid && GetExitCodeProcess(process, &exit_code) &&
      exit_code == STILL_ACTIVE;
  uint32_t parent = 0;
  valid = valid && (known_parent
      ? (parent = *known_parent, true)
      : WindowsProcessParent(pid, &parent));
  FILETIME creation_after{}, exit_after{}, kernel_after{}, user_after{};
  valid = valid && GetProcessTimes(process, &creation_after, &exit_after,
                                   &kernel_after, &user_after) &&
      creation.dwLowDateTime == creation_after.dwLowDateTime &&
      creation.dwHighDateTime == creation_after.dwHighDateTime;
  if (token) CloseHandle(token);
  if (owns_handle) CloseHandle(process);
  if (!valid) return ProcessReadResult::Unreadable;
  ULARGE_INTEGER started{};
  started.LowPart = creation.dwLowDateTime;
  started.HighPart = creation.dwHighDateTime;
  result->pid = pid;
  result->parent_pid = parent;
  result->start_time = started.QuadPart;
  result->executable = Utf8(std::wstring(path.data(), path_size));
  result->owner = owner;
  result->state = "running";
  return result->executable.empty()
      ? ProcessReadResult::Unreadable : ProcessReadResult::Ok;
}

bool ServiceProcessParentSnapshot(std::map<uint32_t, uint32_t>* parents) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return false;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  bool valid = Process32FirstW(snapshot, &entry) != FALSE;
  if (valid) {
    do {
      if (entry.th32ProcessID > 0) {
        (*parents)[entry.th32ProcessID] = entry.th32ParentProcessID;
      }
    } while (Process32NextW(snapshot, &entry));
    valid = GetLastError() == ERROR_NO_MORE_FILES;
  }
  CloseHandle(snapshot);
  return valid;
}
#else
bool ReadProcStat(uint32_t pid, uint32_t* parent, uint64_t* start,
                  std::string* state) {
  const std::string directory = "/proc/" + std::to_string(pid);
  int proc = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
      O_CLOEXEC);
  if (proc < 0) return false;
  int stat_file = openat(proc, "stat", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  std::array<char, 8193> bytes{};
  const ssize_t length = stat_file >= 0
      ? ::read(stat_file, bytes.data(), bytes.size() - 1) : -1;
  if (stat_file >= 0) close(stat_file);
  close(proc);
  if (length <= 0 || length >= static_cast<ssize_t>(bytes.size() - 1)) {
    return false;
  }
  const std::string text(bytes.data(), static_cast<size_t>(length));
  const size_t close = text.rfind(')');
  if (close == std::string::npos || close + 2 >= text.size()) return false;
  std::istringstream stream(text.substr(close + 2));
  std::vector<std::string> fields;
  std::string field;
  while (stream >> field) fields.push_back(field);
  if (fields.size() < 20 || fields[0].size() != 1) return false;
  errno = 0;
  char* end = nullptr;
  const unsigned long parent_value = std::strtoul(fields[1].c_str(), &end, 10);
  if (errno != 0 || end == fields[1].c_str() || *end != '\0' ||
      parent_value > std::numeric_limits<uint32_t>::max()) return false;
  errno = 0;
  end = nullptr;
  const unsigned long long start_value =
      std::strtoull(fields[19].c_str(), &end, 10);
  if (errno != 0 || end == fields[19].c_str() || *end != '\0' ||
      start_value == 0) return false;
  *parent = static_cast<uint32_t>(parent_value);
  *start = static_cast<uint64_t>(start_value);
  *state = fields[0];
  return true;
}

ProcessReadResult ReadServiceProcessFacts(uint32_t pid,
                                          ServiceProcessFacts* result,
                                          const uint32_t* known_parent = nullptr,
                                          int retained = -1) {
  const std::string directory = "/proc/" + std::to_string(pid);
  const bool owns_handle = retained < 0;
  int proc = retained;
  if (owns_handle) {
    proc = open(directory.c_str(),
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  }
  if (proc < 0) {
    return errno == ENOENT || errno == ESRCH
        ? ProcessReadResult::Absent : ProcessReadResult::Unreadable;
  }
  struct stat metadata{};
  uint32_t parent = 0;
  uint64_t start = 0;
  std::string state;
  bool valid = fstat(proc, &metadata) == 0 &&
      ReadProcStat(pid, &parent, &start, &state);
  if (known_parent && parent != *known_parent) valid = false;
  std::array<char, 4097> executable{};
  const ssize_t path_length = valid
      ? readlinkat(proc, "exe", executable.data(), executable.size() - 1) : -1;
  valid = valid && path_length > 0 &&
      path_length < static_cast<ssize_t>(executable.size() - 1);
  uint32_t parent_after = 0;
  uint64_t start_after = 0;
  std::string state_after;
  valid = valid && ReadProcStat(pid, &parent_after, &start_after, &state_after) &&
      parent == parent_after && start == start_after;
  if (owns_handle) close(proc);
  if (!valid) return ProcessReadResult::Unreadable;
  std::string path(executable.data(), static_cast<size_t>(path_length));
  static const std::string deleted = " (deleted)";
  if (path.size() >= deleted.size() &&
      path.compare(path.size() - deleted.size(), deleted.size(), deleted) == 0) {
    return ProcessReadResult::Unreadable;
  }
  result->pid = pid;
  result->parent_pid = parent;
  result->start_time = start;
  result->executable = path;
  result->owner =
      "uid:" + std::to_string(static_cast<uint64_t>(metadata.st_uid));
  result->state = state_after;
  return path.empty() || path[0] != '/'
      ? ProcessReadResult::Unreadable : ProcessReadResult::Ok;
}

bool ServiceProcessParentSnapshot(std::map<uint32_t, uint32_t>* parents) {
  DIR* proc = opendir("/proc");
  if (!proc) return false;
  bool valid = true;
  while (valid) {
    errno = 0;
    struct dirent* entry = readdir(proc);
    if (!entry) {
      valid = errno == 0;
      break;
    }
    const char* name = entry->d_name;
    if (name[0] < '1' || name[0] > '9') continue;
    bool digits = true;
    for (const char* cursor = name; *cursor; ++cursor) {
      if (*cursor < '0' || *cursor > '9') { digits = false; break; }
    }
    if (!digits) continue;
    errno = 0;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(name, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 ||
        parsed > std::numeric_limits<uint32_t>::max()) continue;
    uint32_t parent = 0;
    uint64_t start = 0;
    std::string state;
    if (ReadProcStat(static_cast<uint32_t>(parsed), &parent, &start, &state)) {
      (*parents)[static_cast<uint32_t>(parsed)] = parent;
    }
  }
  closedir(proc);
  return valid;
}
#endif

void ServiceProcessValue(napi_env env, napi_value object,
                         const ServiceProcessFacts& facts) {
  ServiceSetUint32(env, object, "pid", facts.pid);
  ServiceSetUint32(env, object, "parentPid", facts.parent_pid);
  ServiceSetString(env, object, "startTime",
      std::to_string(facts.start_time));
  ServiceSetString(env, object, "executable", facts.executable);
  ServiceSetString(env, object, "owner", facts.owner);
  ServiceSetString(env, object, "state", facts.state);
  ServiceSetUint32(env, object, "depth", facts.depth);
}

std::string ServiceProcessTreeFingerprint(
    const std::vector<ServiceProcessFacts>& processes) {
  Sha256 hash;
  HashField(&hash, "gjc-remote/service-process-tree/v1");
  for (const auto& process : processes) {
    HashField(&hash, std::to_string(process.depth));
    HashField(&hash, std::to_string(process.pid));
    HashField(&hash, std::to_string(process.parent_pid));
    HashField(&hash, std::to_string(process.start_time));
    HashField(&hash, process.executable);
    HashField(&hash, process.owner);
  }
  return hash.Finish();
}

bool ServiceProcessIdentityMatches(const ServiceProcessFacts& actual,
                                   uint32_t pid,
                                   const std::string& start,
                                   const std::string& executable,
                                   const std::string& owner) {
  return actual.pid == pid && std::to_string(actual.start_time) == start &&
      actual.executable == executable && actual.owner == owner;
}

bool BuildServiceProcessTree(uint32_t root_pid, const std::string& root_start,
                             const std::string& root_executable,
                             const std::string& root_owner,
                             std::vector<ServiceProcessFacts>* processes) {
  std::map<uint32_t, uint32_t> parents;
  if (!ServiceProcessParentSnapshot(&parents) ||
      parents.find(root_pid) == parents.end()) return false;
  std::map<uint32_t, uint32_t> depths;
  depths[root_pid] = 0;
  bool advanced = true;
  for (uint32_t pass = 0; pass < 64 && advanced; ++pass) {
    advanced = false;
    for (const auto& [pid, parent] : parents) {
      if (depths.find(pid) != depths.end()) continue;
      const auto found = depths.find(parent);
      if (found != depths.end()) {
        depths[pid] = found->second + 1;
        advanced = true;
        if (depths.size() > 1024) {
          gServiceTreeOverflow = true;
          return false;
        }
      }
    }
  }
  for (const auto& [pid, parent] : parents) {
    if (depths.find(pid) != depths.end()) continue;
    uint32_t cursor = parent;
    for (uint32_t depth = 0; depth <= 64; ++depth) {
      if (cursor == root_pid) {
        gServiceTreeOverflow = true;
        return false;
      }
      const auto next = parents.find(cursor);
      if (next == parents.end() || next->second == cursor) break;
      cursor = next->second;
    }
    if (cursor == root_pid || depths.find(cursor) != depths.end()) {
      gServiceTreeOverflow = true;
      return false;
    }
  }
  processes->clear();
  processes->reserve(depths.size());
  for (const auto& [pid, depth] : depths) {
    ServiceProcessFacts facts;
    const uint32_t parent = parents[pid];
    if (ReadServiceProcessFacts(pid, &facts, &parent) !=
        ProcessReadResult::Ok) return false;
    facts.depth = depth;
    processes->push_back(std::move(facts));
  }
  std::sort(processes->begin(), processes->end(),
      [](const ServiceProcessFacts& left,
         const ServiceProcessFacts& right) {
        return left.depth != right.depth ? left.depth < right.depth
                                        : left.pid < right.pid;
      });
  return !processes->empty() &&
      ServiceProcessIdentityMatches(
          processes->front(), root_pid, root_start, root_executable,
          root_owner);
}

bool StableServiceProcessTree(uint32_t root_pid,
                              const std::string& root_start,
                              const std::string& root_executable,
                              const std::string& root_owner,
                              std::vector<ServiceProcessFacts>* processes,
                              std::string* fingerprint) {
  std::vector<ServiceProcessFacts> first, second;
  if (!BuildServiceProcessTree(root_pid, root_start, root_executable,
                               root_owner, &first) ||
      !BuildServiceProcessTree(root_pid, root_start, root_executable,
                               root_owner, &second)) {
    return false;
  }
  const std::string first_fingerprint =
      ServiceProcessTreeFingerprint(first);
  const std::string second_fingerprint =
      ServiceProcessTreeFingerprint(second);
  if (!ValidServiceFingerprint(first_fingerprint) ||
      first_fingerprint != second_fingerprint) return false;
  *processes = std::move(second);
  *fingerprint = second_fingerprint;
  return true;
}

napi_value ReadProcessFacts(napi_env env, napi_callback_info info) {
  napi_value args[1];
  uint32_t pid = 0;
  if (!InventoryArgs(env, info, 1, args) ||
      !ServiceUint32(env, args[0], &pid, 1, 0x7fffffffu)) {
    ServiceError(env, "SERVICE_INVALID", "read_process_facts");
    return nullptr;
  }
  ServiceProcessFacts facts;
  const ProcessReadResult read = ReadServiceProcessFacts(pid, &facts);
  if (read == ProcessReadResult::Absent) {
    napi_value absent;
    napi_get_null(env, &absent);
    return absent;
  }
  if (read != ProcessReadResult::Ok) {
    ServiceError(env, "SERVICE_PROCESS_AMBIGUOUS", "read_process_facts",
                 0, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceProcessValue(env, result, facts);
  return result;
}

napi_value EnumerateProcessTree(napi_env env, napi_callback_info info) {
  napi_value args[4];
  uint32_t pid = 0;
  std::string start, executable, owner;
  if (!InventoryArgs(env, info, 4, args) ||
      !ServiceUint32(env, args[0], &pid, 1, 0x7fffffffu) ||
      !InventoryString(env, args[1], &start) || start.empty() ||
      !InventoryString(env, args[2], &executable) || executable.empty() ||
      !InventoryString(env, args[3], &owner) || owner.empty()) {
    ServiceError(env, "SERVICE_INVALID", "enumerate_process_tree");
    return nullptr;
  }
  std::vector<ServiceProcessFacts> processes;
  std::string fingerprint;
  gServiceTreeOverflow = false;
  if (!StableServiceProcessTree(pid, start, executable, owner,
                                &processes, &fingerprint)) {
    ServiceError(env,
        gServiceTreeOverflow ? "SERVICE_TREE_OVERFLOW"
                             : "SERVICE_TREE_AMBIGUOUS",
        "enumerate_process_tree", 0, true);
    return nullptr;
  }
  napi_value result, array;
  napi_create_object(env, &result);
  napi_create_array_with_length(env, processes.size(), &array);
  for (uint32_t index = 0; index < processes.size(); ++index) {
    napi_value value;
    napi_create_object(env, &value);
    ServiceProcessValue(env, value, processes[index]);
    napi_set_element(env, array, index, value);
  }
  napi_set_named_property(env, result, "processes", array);
  ServiceSetString(env, result, "treeFingerprint", fingerprint);
  ServiceSetUint32(env, result, "processCount",
                   static_cast<uint32_t>(processes.size()));
  return result;
}

#ifdef __linux__
bool ValidLinuxServiceCgroupPath(const std::string& path) {
  static const std::string prefix =
      "/sys/fs/cgroup/system.slice/";
  if (path.rfind(prefix, 0) != 0 || path.size() > 4096) return false;
  const std::string name = path.substr(prefix.size());
  if (name == "gjc-remote-bot.service") return true;
  static const std::string daemon_prefix = "gjc-remote-daemon@";
  static const std::string suffix = ".service";
  if (name.rfind(daemon_prefix, 0) != 0 ||
      name.size() <= daemon_prefix.size() + suffix.size() ||
      name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) {
    return false;
  }
  const std::string instance = name.substr(
      daemon_prefix.size(),
      name.size() - daemon_prefix.size() - suffix.size());
  return ValidServiceInstanceKey(instance);
}

bool ParseCgroupProcesses(int directory, std::set<uint32_t>* processes) {
  int file = openat(directory, "cgroup.procs",
      O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (file < 0) return false;
  std::string contents;
  std::array<char, 4096> buffer{};
  for (;;) {
    const ssize_t bytes = ::read(file, buffer.data(), buffer.size());
    if (bytes < 0) {
      if (errno == EINTR) continue;
      close(file);
      return false;
    }
    if (bytes == 0) break;
    contents.append(buffer.data(), static_cast<size_t>(bytes));
    if (contents.size() > 64 * 1024) {
      close(file);
      return false;
    }
  }
  close(file);
  std::istringstream stream(contents);
  std::string line;
  while (stream >> line) {
    errno = 0;
    char* end = nullptr;
    const unsigned long pid = std::strtoul(line.c_str(), &end, 10);
    if (errno != 0 || end == line.c_str() || *end != '\0' || pid == 0 ||
        pid > 0x7fffffffu) return false;
    processes->insert(static_cast<uint32_t>(pid));
    if (processes->size() > 1024) {
      gServiceTreeOverflow = true;
      return false;
    }
  }
  return true;
}

bool CollectCgroupProcesses(int directory, uint32_t depth,
                            uint32_t* directories,
                            std::set<uint32_t>* processes) {
  if (depth > 64 || ++*directories > 1024) {
    gServiceTreeOverflow = true;
    return false;
  }
  if (!ParseCgroupProcesses(directory, processes)) return false;
  const int duplicate = dup(directory);
  if (duplicate < 0) return false;
  DIR* entries = fdopendir(duplicate);
  if (!entries) {
    close(duplicate);
    return false;
  }
  bool valid = true;
  for (;;) {
    errno = 0;
    struct dirent* entry = readdir(entries);
    if (!entry) {
      valid = errno == 0;
      break;
    }
    if (entry->d_name[0] == '.') continue;
    struct stat metadata{};
    if (fstatat(directory, entry->d_name, &metadata,
                AT_SYMLINK_NOFOLLOW) != 0) {
      valid = false;
      break;
    }
    if (!S_ISDIR(metadata.st_mode)) continue;
    int child = openat(directory, entry->d_name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child < 0 ||
        !CollectCgroupProcesses(child, depth + 1, directories, processes)) {
      if (child >= 0) close(child);
      valid = false;
      break;
    }
    close(child);
  }
  closedir(entries);
  return valid;
}

bool BuildCgroupProcessFacts(const std::set<uint32_t>& pids,
                             std::vector<ServiceProcessFacts>* facts) {
  std::map<uint32_t, ServiceProcessFacts> values;
  for (uint32_t pid : pids) {
    ServiceProcessFacts process;
    if (ReadServiceProcessFacts(pid, &process) != ProcessReadResult::Ok) {
      return false;
    }
    values.emplace(pid, std::move(process));
  }
  for (auto& [pid, process] : values) {
    std::set<uint32_t> visited;
    uint32_t parent = process.parent_pid;
    uint32_t depth = 0;
    while (values.find(parent) != values.end()) {
      if (!visited.insert(parent).second || ++depth > 64) {
        gServiceTreeOverflow = true;
        return false;
      }
      parent = values[parent].parent_pid;
    }
    process.depth = depth;
  }
  facts->clear();
  for (auto& [pid, process] : values) {
    facts->push_back(std::move(process));
  }
  std::sort(facts->begin(), facts->end(),
      [](const ServiceProcessFacts& left,
         const ServiceProcessFacts& right) {
        return left.depth != right.depth ? left.depth < right.depth
                                        : left.pid < right.pid;
      });
  return true;
}

bool StableLinuxServiceCgroup(const std::string& path,
                              struct stat* identity,
                              std::vector<ServiceProcessFacts>* processes,
                              std::string* fingerprint) {
  int directory = OpenDirectoryNoFollow(path);
  if (directory < 0) return false;
  errno = 0;
  struct stat first_identity{}, second_identity{};
  std::set<uint32_t> first_pids, second_pids;
  uint32_t directories = 0;
  bool valid = fstat(directory, &first_identity) == 0 &&
      S_ISDIR(first_identity.st_mode) &&
      CollectCgroupProcesses(directory, 0, &directories, &first_pids);
  std::vector<ServiceProcessFacts> first, second;
  valid = valid && BuildCgroupProcessFacts(first_pids, &first);
  std::string first_fingerprint;
  if (valid) first_fingerprint = ServiceProcessTreeFingerprint(first);
  directories = 0;
  valid = valid && ValidServiceFingerprint(first_fingerprint) &&
      CollectCgroupProcesses(
      directory, 0, &directories, &second_pids) &&
      BuildCgroupProcessFacts(second_pids, &second) &&
      fstat(directory, &second_identity) == 0 &&
      first_identity.st_dev == second_identity.st_dev &&
      first_identity.st_ino == second_identity.st_ino &&
      first_pids == second_pids;
  std::string second_fingerprint;
  if (valid) second_fingerprint = ServiceProcessTreeFingerprint(second);
  valid = valid && ValidServiceFingerprint(second_fingerprint) &&
      first_fingerprint == second_fingerprint;
  close(directory);
  if (!valid) {
    errno = EIO;
    return false;
  }
  *identity = second_identity;
  *processes = std::move(second);
  *fingerprint = second_fingerprint;
  return true;
}
#endif

napi_value ReadLinuxServiceCgroup(napi_env env, napi_callback_info info) {
  napi_value args[1];
  std::string path;
  if (!InventoryArgs(env, info, 1, args) ||
      !InventoryString(env, args[0], &path) || path.empty() ||
      path.size() > 4096) {
    ServiceError(env, "SERVICE_INVALID", "read_linux_service_cgroup");
    return nullptr;
  }
#ifdef __linux__
  if (!ValidLinuxServiceCgroupPath(path)) {
    ServiceError(env, "SERVICE_INVALID", "read_linux_service_cgroup");
    return nullptr;
  }
  struct stat identity{};
  std::vector<ServiceProcessFacts> processes;
  std::string fingerprint;
  gServiceTreeOverflow = false;
  if (!StableLinuxServiceCgroup(path, &identity, &processes, &fingerprint)) {
    if (errno == ENOENT) {
      napi_value absent;
      napi_get_null(env, &absent);
      return absent;
    }
    ServiceError(env,
        gServiceTreeOverflow ? "SERVICE_TREE_OVERFLOW"
                             : "SERVICE_TREE_AMBIGUOUS",
        "read_linux_service_cgroup", 0, true);
    return nullptr;
  }
  napi_value result, identity_value, array;
  napi_create_object(env, &result);
  napi_create_object(env, &identity_value);
  ServiceSetString(env, identity_value, "device",
      std::to_string(static_cast<uint64_t>(identity.st_dev)));
  ServiceSetString(env, identity_value, "inode",
      std::to_string(static_cast<uint64_t>(identity.st_ino)));
  napi_set_named_property(env, result, "identity", identity_value);
  napi_create_array_with_length(env, processes.size(), &array);
  for (uint32_t index = 0; index < processes.size(); ++index) {
    napi_value value;
    napi_create_object(env, &value);
    ServiceProcessValue(env, value, processes[index]);
    napi_set_element(env, array, index, value);
  }
  napi_set_named_property(env, result, "processes", array);
  ServiceSetString(env, result, "treeFingerprint", fingerprint);
  ServiceSetUint32(env, result, "processCount",
                   static_cast<uint32_t>(processes.size()));
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "read_linux_service_cgroup");
  return nullptr;
#endif
}

napi_value TerminateLinuxServiceCgroup(napi_env env,
                                       napi_callback_info info) {
  napi_value args[4];
  std::string path, expected_device, expected_inode, expected_tree;
  if (!InventoryArgs(env, info, 4, args) ||
      !InventoryString(env, args[0], &path) ||
      !InventoryString(env, args[1], &expected_device) ||
      !InventoryString(env, args[2], &expected_inode) ||
      !InventoryString(env, args[3], &expected_tree)) {
    ServiceError(env, "SERVICE_INVALID",
                 "terminate_linux_service_cgroup");
    return nullptr;
  }
#ifdef __linux__
  if (!ValidLinuxServiceCgroupPath(path) ||
      expected_tree.size() != 64 ||
      expected_tree.find_first_not_of("0123456789abcdef") !=
          std::string::npos) {
    ServiceError(env, "SERVICE_INVALID",
                 "terminate_linux_service_cgroup");
    return nullptr;
  }
  struct stat identity{};
  std::vector<ServiceProcessFacts> processes;
  std::string fingerprint;
  gServiceTreeOverflow = false;
  if (!StableLinuxServiceCgroup(path, &identity, &processes, &fingerprint) ||
      std::to_string(static_cast<uint64_t>(identity.st_dev)) !=
          expected_device ||
      std::to_string(static_cast<uint64_t>(identity.st_ino)) !=
          expected_inode ||
      fingerprint != expected_tree) {
    ServiceError(env,
        gServiceTreeOverflow ? "SERVICE_TREE_OVERFLOW" : "SERVICE_STALE",
                 "terminate_linux_service_cgroup", 0, true);
    return nullptr;
  }
  for (const auto& process : processes) {
    if (process.pid <= 1 ||
        process.pid == static_cast<uint32_t>(getpid())) {
      ServiceError(env, "SERVICE_ACCESS_DENIED",
                   "terminate_linux_service_cgroup");
      return nullptr;
    }
  }
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
  struct RetainedProcess {
    int handle;
    ServiceProcessFacts facts;
  };
  std::vector<RetainedProcess> retained;
  for (const auto& process : processes) {
    const int handle = static_cast<int>(
        syscall(SYS_pidfd_open, process.pid, 0));
    ServiceProcessFacts current;
    if (handle < 0 ||
        ReadServiceProcessFacts(process.pid, &current) !=
            ProcessReadResult::Ok ||
        current.start_time != process.start_time ||
        current.executable != process.executable ||
        current.owner != process.owner) {
      if (handle >= 0) close(handle);
      for (const auto& value : retained) close(value.handle);
      ServiceError(env, "SERVICE_STALE",
                   "terminate_linux_service_cgroup", 0, true);
      return nullptr;
    }
    retained.push_back({handle, process});
  }
  struct stat final_identity{};
  std::vector<ServiceProcessFacts> final_processes;
  std::string final_fingerprint;
  if (!StableLinuxServiceCgroup(
          path, &final_identity, &final_processes, &final_fingerprint) ||
      final_identity.st_dev != identity.st_dev ||
      final_identity.st_ino != identity.st_ino ||
      final_fingerprint != fingerprint) {
    for (const auto& value : retained) close(value.handle);
    ServiceError(env,
        gServiceTreeOverflow ? "SERVICE_TREE_OVERFLOW" : "SERVICE_STALE",
                 "terminate_linux_service_cgroup", 0, true);
    return nullptr;
  }
  std::sort(retained.begin(), retained.end(),
      [](const RetainedProcess& left, const RetainedProcess& right) {
        return left.facts.depth != right.facts.depth
            ? left.facts.depth > right.facts.depth
            : left.facts.pid > right.facts.pid;
      });
  uint32_t writes = 0;
  for (const auto& process : retained) {
    if (syscall(SYS_pidfd_send_signal, process.handle, SIGKILL,
                nullptr, 0) != 0) {
      if (errno != ESRCH) {
        for (const auto& value : retained) close(value.handle);
        ServiceError(env, "SERVICE_TREE_SURVIVOR",
                     "terminate_linux_service_cgroup", writes, true);
        return nullptr;
      }
    } else {
      ++writes;
    }
  }
  for (const auto& value : retained) close(value.handle);
  const auto deadline = std::chrono::steady_clock::now() +
      std::chrono::seconds(2);
  bool empty = false;
  do {
    struct stat observed_identity{};
    std::vector<ServiceProcessFacts> observed;
    std::string observed_fingerprint;
    if (StableLinuxServiceCgroup(
            path, &observed_identity, &observed, &observed_fingerprint)) {
      if (observed_identity.st_dev != identity.st_dev ||
          observed_identity.st_ino != identity.st_ino) {
        ServiceError(env, "SERVICE_TREE_SURVIVOR",
                     "terminate_linux_service_cgroup", writes, true);
        return nullptr;
      }
      empty = observed.empty();
    } else if (errno == ENOENT) {
      ServiceError(env, "SERVICE_TREE_SURVIVOR",
                   "terminate_linux_service_cgroup", writes, true);
      return nullptr;
    }
    if (!empty) std::this_thread::sleep_for(std::chrono::milliseconds(20));
  } while (!empty && std::chrono::steady_clock::now() < deadline);
  if (!empty) {
    ServiceError(env, "SERVICE_TREE_SURVIVOR",
                 "terminate_linux_service_cgroup", writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "tree", "empty");
  ServiceSetBoolean(env, result, "forced", true);
  ServiceSetUint32(env, result, "terminated",
                   static_cast<uint32_t>(processes.size()));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "terminate_linux_service_cgroup");
  return nullptr;
#endif
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "terminate_linux_service_cgroup");
  return nullptr;
#endif
}

#ifdef _WIN32
const napi_type_tag kWin32ServiceHandleTypeTag = {
  0x36fce664bf5843d1ULL, 0xb46277c014998e20ULL,
};

struct Win32ServiceHandle {
  SC_HANDLE manager = nullptr;
  SC_HANDLE service = nullptr;
  InventoryRoles roles;
  std::string service_role;
  std::string name;
  bool mutable_access = false;
  bool created_unmarked = false;
};

struct Win32FailureAction {
  SC_ACTION_TYPE type = SC_ACTION_NONE;
  DWORD delay = 0;
};

struct Win32ServiceSnapshot {
  DWORD service_type = 0;
  DWORD start_type = 0;
  DWORD error_control = 0;
  DWORD tag_id = 0;
  std::string binary_path;
  std::string load_order_group;
  std::vector<std::string> dependencies;
  std::string account_name;
  std::string display_name;
  std::string description;
  bool delayed_auto_start = false;
  DWORD failure_reset_period = 0;
  std::string failure_reboot_message;
  std::string failure_command;
  std::vector<Win32FailureAction> failure_actions;
  bool failure_actions_on_non_crash = false;
  DWORD service_sid_type = 0;
  std::vector<std::string> required_privileges;
  DWORD trigger_count = 0;
  DWORD preshutdown_timeout = 0;
  std::string security_sha256;
  bool acl_matches = false;
  bool account_matches_role = false;
  DWORD state = 0;
  DWORD controls_accepted = 0;
  DWORD win32_exit_code = 0;
  DWORD service_exit_code = 0;
  DWORD checkpoint = 0;
  DWORD wait_hint = 0;
  DWORD process_id = 0;
  DWORD service_flags = 0;
  std::string config_fingerprint;
  std::string runtime_fingerprint;
};

void CloseWin32ServiceHandle(Win32ServiceHandle* handle) {
  if (!handle) return;
  if (handle->service) CloseServiceHandle(handle->service);
  if (handle->manager) CloseServiceHandle(handle->manager);
  handle->service = nullptr;
  handle->manager = nullptr;
}

void FinalizeWin32ServiceHandle(napi_env, void* data, void*) {
  auto* handle = static_cast<Win32ServiceHandle*>(data);
  CloseWin32ServiceHandle(handle);
  delete handle;
}

bool Win32ServiceHandleArg(napi_env env, napi_value value,
                           Win32ServiceHandle** result) {
  bool tagged = false;
  void* raw = nullptr;
  if (napi_check_object_type_tag(env, value, &kWin32ServiceHandleTypeTag,
                                &tagged) != napi_ok ||
      !tagged || napi_unwrap(env, value, &raw) != napi_ok || !raw) {
    return false;
  }
  auto* handle = static_cast<Win32ServiceHandle*>(raw);
  if (!handle->service || !handle->manager) return false;
  *result = handle;
  return true;
}

napi_value WrapWin32ServiceHandle(napi_env env,
                                  Win32ServiceHandle* handle) {
  napi_value object;
  if (napi_create_object(env, &object) != napi_ok ||
      napi_type_tag_object(env, object,
                           &kWin32ServiceHandleTypeTag) != napi_ok ||
      napi_wrap(env, object, handle, FinalizeWin32ServiceHandle, nullptr,
                nullptr) != napi_ok) {
    CloseWin32ServiceHandle(handle);
    delete handle;
    return nullptr;
  }
  return object;
}

bool ValidWin32ServiceName(const std::string& name,
                           const std::string& role) {
  if (role == "bot") return name == "GJCRemoteBot";
  static const std::string prefix = "GJCRemoteDaemon-";
  return role == "daemon" && name.rfind(prefix, 0) == 0 &&
      ValidServiceInstanceKey(name.substr(prefix.size()));
}

bool ValidWin32ServiceMarker(const std::string& marker) {
  static const std::string prefix = "gjc-remote:v1:";
  return marker.size() == prefix.size() + 64 &&
      marker.rfind(prefix, 0) == 0 &&
      marker.substr(prefix.size()).find_first_not_of(
          "0123456789abcdef") == std::string::npos;
}

bool Win32ServiceAccountMatches(const std::string& account,
                                const std::string& expected_sid) {
  const std::wstring wide = Wide(account);
  if (wide.empty()) return false;
  DWORD sid_bytes = 0;
  DWORD domain_units = 0;
  SID_NAME_USE use = SidTypeUnknown;
  LookupAccountNameW(nullptr, wide.c_str(), nullptr, &sid_bytes, nullptr,
                     &domain_units, &use);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sid_bytes == 0) {
    return false;
  }
  std::vector<uint8_t> sid(sid_bytes);
  std::vector<wchar_t> domain(domain_units);
  if (!LookupAccountNameW(nullptr, wide.c_str(), sid.data(), &sid_bytes,
                          domain.data(), &domain_units, &use) ||
      use != SidTypeUser) return false;
  PSID expected = nullptr;
  const bool valid =
      ConvertStringSidToSidW(Wide(expected_sid).c_str(), &expected) &&
      EqualSid(sid.data(), expected);
  if (expected) LocalFree(expected);
  return valid;
}

bool ResolveWin32ServiceAccountName(const std::string& expected_sid,
                                    std::wstring* account) {
  static constexpr DWORD kMaximumAccountUnits = 4096;
  PSID sid = nullptr;
  if (!ConvertStringSidToSidW(Wide(expected_sid).c_str(), &sid) ||
      !sid || !IsValidSid(sid)) {
    if (sid) LocalFree(sid);
    return false;
  }
  DWORD name_units = 0;
  DWORD domain_units = 0;
  SID_NAME_USE use = SidTypeUnknown;
  SetLastError(ERROR_SUCCESS);
  LookupAccountSidW(nullptr, sid, nullptr, &name_units, nullptr,
                    &domain_units, &use);
  const DWORD first_error = GetLastError();
  if (first_error != ERROR_INSUFFICIENT_BUFFER || name_units == 0 ||
      name_units > kMaximumAccountUnits ||
      domain_units > kMaximumAccountUnits ||
      static_cast<uint64_t>(name_units) + domain_units + 1 >
          kMaximumAccountUnits) {
    LocalFree(sid);
    return false;
  }
  bool resolved = false;
  try {
    std::vector<wchar_t> name(name_units, L'\0');
    std::vector<wchar_t> domain(
        std::max<DWORD>(domain_units, 1), L'\0');
    DWORD name_capacity = name_units;
    DWORD domain_capacity = domain_units;
    if (LookupAccountSidW(
            nullptr, sid, name.data(), &name_capacity,
            domain_units == 0 ? nullptr : domain.data(),
            &domain_capacity, &use) &&
        use == SidTypeUser) {
      size_t name_length = 0;
      while (name_length < name.size() &&
             name[name_length] != L'\0') ++name_length;
      size_t domain_length = 0;
      while (domain_length < domain_units &&
             domain[domain_length] != L'\0') ++domain_length;
      if (name_length > 0 && name_length < name.size() &&
          (domain_units == 0 || domain_length < domain.size())) {
        account->clear();
        if (domain_length != 0) {
          account->append(domain.data(), domain_length);
          account->push_back(L'\\');
        }
        account->append(name.data(), name_length);
        const std::string account_utf8 = Utf8(*account);
        resolved = !account_utf8.empty() &&
            account_utf8.size() <= kMaximumAccountUnits &&
            Win32ServiceAccountMatches(account_utf8, expected_sid);
      }
    }
  } catch (...) {
    resolved = false;
  }
  LocalFree(sid);
  if (!resolved) account->clear();
  return resolved;
}

bool BuildWin32ServiceObjectAcl(const InventoryRoles& roles, PACL* acl,
                                std::array<PSID, 3>* sids) {
  const std::string values[] = {
    roles.management, roles.recovery, roles.system,
  };
  EXPLICIT_ACCESSW entries[3]{};
  for (size_t index = 0; index < 3; ++index) {
    if (!ConvertStringSidToSidW(Wide(values[index]).c_str(),
                                &(*sids)[index])) return false;
    entries[index].grfAccessPermissions = SERVICE_ALL_ACCESS;
    entries[index].grfAccessMode = SET_ACCESS;
    entries[index].grfInheritance = NO_INHERITANCE;
    entries[index].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entries[index].Trustee.TrusteeType = TRUSTEE_IS_USER;
    entries[index].Trustee.ptstrName =
        static_cast<LPWSTR>((*sids)[index]);
  }
  return SetEntriesInAclW(3, entries, nullptr, acl) == ERROR_SUCCESS;
}

bool ExpectedWin32ServiceObjectSecurityFingerprint(
    const InventoryRoles& roles, std::string* fingerprint) {
  PACL acl = nullptr;
  std::array<PSID, 3> sids{};
  if (!BuildWin32ServiceObjectAcl(roles, &acl, &sids)) {
    if (acl) LocalFree(acl);
    for (PSID sid : sids) if (sid) LocalFree(sid);
    return false;
  }
  SECURITY_DESCRIPTOR descriptor{};
  const bool initialized =
      InitializeSecurityDescriptor(
          &descriptor, SECURITY_DESCRIPTOR_REVISION) &&
      SetSecurityDescriptorOwner(&descriptor, sids[0], FALSE) &&
      SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) &&
      SetSecurityDescriptorControl(
          &descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
  DWORD required = 0;
  const bool sized = initialized &&
      !MakeSelfRelativeSD(&descriptor, nullptr, &required) &&
      GetLastError() == ERROR_INSUFFICIENT_BUFFER && required > 0 &&
      required <= 1024 * 1024;
  std::vector<uint8_t> bytes;
  try {
    if (sized) bytes.resize(required);
  } catch (...) {
    LocalFree(acl);
    for (PSID sid : sids) if (sid) LocalFree(sid);
    return false;
  }
  const bool serialized = sized && MakeSelfRelativeSD(
      &descriptor, reinterpret_cast<PSECURITY_DESCRIPTOR>(bytes.data()),
      &required);
  Sha256 hash;
  const bool hashed = serialized && hash.Ready() &&
      hash.Update(bytes.data(), required);
  if (hashed) *fingerprint = hash.Finish();
  LocalFree(acl);
  for (PSID sid : sids) if (sid) LocalFree(sid);
  return hashed && ValidServiceFingerprint(*fingerprint);
}

bool VerifyWin32ServiceObjectAcl(SC_HANDLE service,
                                 const InventoryRoles& roles,
                                 std::string* security_sha256 = nullptr) {
  PACL expected_acl = nullptr;
  std::array<PSID, 3> expected_sids{};
  if (!BuildWin32ServiceObjectAcl(roles, &expected_acl, &expected_sids)) {
    if (expected_acl) LocalFree(expected_acl);
    for (PSID sid : expected_sids) if (sid) LocalFree(sid);
    return false;
  }
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  ACL_SIZE_INFORMATION size{};
  bool valid =
      GetSecurityInfo(service, SE_SERVICE,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
          &owner, nullptr, &dacl, nullptr, &descriptor) == ERROR_SUCCESS &&
      owner && EqualSid(owner, expected_sids[0]) && dacl &&
      GetSecurityDescriptorControl(descriptor, &control, &revision) &&
      (control & SE_DACL_PROTECTED) != 0 &&
      GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation) &&
      size.AceCount == 3;
  bool seen[3]{};
  for (DWORD index = 0; valid && index < size.AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(dacl, index, &raw)) { valid = false; break; }
    auto* header = static_cast<ACE_HEADER*>(raw);
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
        header->AceFlags != 0) {
      valid = false;
      break;
    }
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    bool matched = false;
    for (size_t role = 0; role < 3; ++role) {
      if (!seen[role] && ace->Mask == SERVICE_ALL_ACCESS &&
          EqualSid(reinterpret_cast<PSID>(&ace->SidStart),
                   expected_sids[role])) {
        seen[role] = true;
        matched = true;
        break;
      }
    }
    if (!matched) valid = false;
  }
  if (descriptor && security_sha256) {
    const DWORD bytes = GetSecurityDescriptorLength(descriptor);
    if (bytes == 0) {
      valid = false;
    } else {
      Sha256 hash;
      const bool updated = hash.Update(descriptor, bytes);
      *security_sha256 = hash.Finish();
      if (!updated || !ValidServiceFingerprint(*security_sha256)) {
        valid = false;
      }
    }
  }
  if (descriptor) LocalFree(descriptor);
  if (expected_acl) LocalFree(expected_acl);
  for (PSID sid : expected_sids) if (sid) LocalFree(sid);
  return valid && seen[0] && seen[1] && seen[2];
}

bool ApplyWin32ServiceObjectAcl(SC_HANDLE service,
                                const InventoryRoles& roles) {
  PACL acl = nullptr;
  std::array<PSID, 3> sids{};
  if (!BuildWin32ServiceObjectAcl(roles, &acl, &sids)) {
    if (acl) LocalFree(acl);
    for (PSID sid : sids) if (sid) LocalFree(sid);
    return false;
  }
  const DWORD status = SetSecurityInfo(service, SE_SERVICE,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
          PROTECTED_DACL_SECURITY_INFORMATION,
      sids[0], nullptr, acl, nullptr);
  if (acl) LocalFree(acl);
  for (PSID sid : sids) if (sid) LocalFree(sid);
  return status == ERROR_SUCCESS &&
      VerifyWin32ServiceObjectAcl(service, roles);
}

template <typename T>
bool QueryWin32ServiceConfig2(SC_HANDLE service, DWORD level,
                              std::vector<uint8_t>* bytes, T** value) {
  DWORD required = 0;
  QueryServiceConfig2W(service, level, nullptr, 0, &required);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0 ||
      required > 1024 * 1024) return false;
  bytes->resize(required);
  if (!QueryServiceConfig2W(service, level, bytes->data(), required,
                            &required)) return false;
  *value = reinterpret_cast<T*>(bytes->data());
  return true;
}

bool Win32MultiString(const wchar_t* value,
                      const std::vector<uint8_t>& buffer,
                      std::vector<std::string>* result) {
  result->clear();
  if (!value) return true;
  const auto* begin = buffer.data();
  const auto* end = begin + buffer.size();
  const auto* cursor = reinterpret_cast<const uint8_t*>(value);
  if (cursor < begin || cursor >= end ||
      (end - cursor) % sizeof(wchar_t) != 0) return false;
  size_t remaining = static_cast<size_t>(end - cursor) / sizeof(wchar_t);
  while (remaining > 0 && *value) {
    size_t length = 0;
    while (length < remaining && value[length] != L'\0') ++length;
    if (length == remaining) return false;
    result->push_back(Utf8(std::wstring(value, length)));
    value += length + 1;
    remaining -= length + 1;
  }
  return remaining > 0;
}

std::string Win32ServiceConfigFingerprint(
    const Win32ServiceHandle& handle,
    const Win32ServiceSnapshot& snapshot) {
  Sha256 hash;
  HashField(&hash, "gjc-remote/win32-service-config/v1");
  HashField(&hash, handle.name);
  HashField(&hash, handle.service_role);
  HashField(&hash, std::to_string(snapshot.service_type));
  HashField(&hash, std::to_string(snapshot.start_type));
  HashField(&hash, std::to_string(snapshot.error_control));
  HashField(&hash, std::to_string(snapshot.tag_id));
  HashField(&hash, snapshot.binary_path);
  HashField(&hash, snapshot.load_order_group);
  for (const auto& dependency : snapshot.dependencies) {
    HashField(&hash, dependency);
  }
  HashField(&hash, snapshot.account_name);
  HashField(&hash, snapshot.display_name);
  HashField(&hash, snapshot.description);
  HashField(&hash, snapshot.delayed_auto_start ? "1" : "0");
  HashField(&hash, std::to_string(snapshot.failure_reset_period));
  HashField(&hash, snapshot.failure_reboot_message);
  HashField(&hash, snapshot.failure_command);
  for (const auto& action : snapshot.failure_actions) {
    HashField(&hash, std::to_string(action.type));
    HashField(&hash, std::to_string(action.delay));
  }
  HashField(&hash,
      snapshot.failure_actions_on_non_crash ? "1" : "0");
  HashField(&hash, std::to_string(snapshot.service_sid_type));
  for (const auto& privilege : snapshot.required_privileges) {
    HashField(&hash, privilege);
  }
  HashField(&hash, std::to_string(snapshot.trigger_count));
  HashField(&hash, std::to_string(snapshot.preshutdown_timeout));
  HashField(&hash, snapshot.security_sha256);
  return hash.Finish();
}

std::string Win32ServiceRuntimeFingerprint(
    const Win32ServiceHandle& handle,
    const Win32ServiceSnapshot& snapshot) {
  Sha256 hash;
  HashField(&hash, "gjc-remote/win32-service-runtime/v1");
  HashField(&hash, handle.name);
  HashField(&hash, std::to_string(snapshot.state));
  HashField(&hash, std::to_string(snapshot.controls_accepted));
  HashField(&hash, std::to_string(snapshot.process_id));
  HashField(&hash, std::to_string(snapshot.win32_exit_code));
  HashField(&hash, std::to_string(snapshot.service_exit_code));
  HashField(&hash, std::to_string(snapshot.checkpoint));
  HashField(&hash, std::to_string(snapshot.wait_hint));
  HashField(&hash, std::to_string(snapshot.service_flags));
  return hash.Finish();
}

bool QueryWin32ServiceSnapshot(Win32ServiceHandle* handle,
                               Win32ServiceSnapshot* snapshot) {
  DWORD required = 0;
  QueryServiceConfigW(handle->service, nullptr, 0, &required);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0 ||
      required > 1024 * 1024) return false;
  std::vector<uint8_t> config_bytes(required);
  auto* config =
      reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config_bytes.data());
  if (!QueryServiceConfigW(handle->service, config, required, &required)) {
    return false;
  }
  snapshot->service_type = config->dwServiceType;
  snapshot->start_type = config->dwStartType;
  snapshot->error_control = config->dwErrorControl;
  snapshot->tag_id = config->dwTagId;
  snapshot->binary_path =
      config->lpBinaryPathName ? Utf8(config->lpBinaryPathName) : "";
  snapshot->load_order_group =
      config->lpLoadOrderGroup ? Utf8(config->lpLoadOrderGroup) : "";
  if (!Win32MultiString(config->lpDependencies, config_bytes,
                        &snapshot->dependencies)) return false;
  snapshot->account_name =
      config->lpServiceStartName ? Utf8(config->lpServiceStartName) : "";
  snapshot->display_name =
      config->lpDisplayName ? Utf8(config->lpDisplayName) : "";

  std::vector<uint8_t> description_bytes, delayed_bytes, failure_bytes,
      failure_flag_bytes, sid_bytes, privilege_bytes, trigger_bytes,
      preshutdown_bytes;
  SERVICE_DESCRIPTIONW* description = nullptr;
  SERVICE_DELAYED_AUTO_START_INFO* delayed = nullptr;
  SERVICE_FAILURE_ACTIONSW* failure = nullptr;
  SERVICE_FAILURE_ACTIONS_FLAG* failure_flag = nullptr;
  SERVICE_SID_INFO* sid = nullptr;
  SERVICE_REQUIRED_PRIVILEGES_INFOW* privileges = nullptr;
  SERVICE_TRIGGER_INFO* triggers = nullptr;
  SERVICE_PRESHUTDOWN_INFO* preshutdown = nullptr;
  if (!QueryWin32ServiceConfig2(handle->service, SERVICE_CONFIG_DESCRIPTION,
          &description_bytes, &description) ||
      !QueryWin32ServiceConfig2(handle->service,
          SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed_bytes, &delayed) ||
      !QueryWin32ServiceConfig2(handle->service,
          SERVICE_CONFIG_FAILURE_ACTIONS, &failure_bytes, &failure) ||
      !QueryWin32ServiceConfig2(handle->service,
          SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
          &failure_flag_bytes, &failure_flag) ||
      !QueryWin32ServiceConfig2(handle->service,
          SERVICE_CONFIG_SERVICE_SID_INFO, &sid_bytes, &sid) ||
      !QueryWin32ServiceConfig2(handle->service,
          SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
          &privilege_bytes, &privileges) ||
      !QueryWin32ServiceConfig2(handle->service,
          SERVICE_CONFIG_TRIGGER_INFO, &trigger_bytes, &triggers) ||
      !QueryWin32ServiceConfig2(handle->service,
          SERVICE_CONFIG_PRESHUTDOWN_INFO,
          &preshutdown_bytes, &preshutdown)) {
    return false;
  }
  snapshot->description =
      description->lpDescription ? Utf8(description->lpDescription) : "";
  snapshot->delayed_auto_start = delayed->fDelayedAutostart != FALSE;
  snapshot->failure_reset_period = failure->dwResetPeriod;
  snapshot->failure_reboot_message =
      failure->lpRebootMsg ? Utf8(failure->lpRebootMsg) : "";
  snapshot->failure_command =
      failure->lpCommand ? Utf8(failure->lpCommand) : "";
  snapshot->failure_actions.clear();
  if (failure->cActions > 16 ||
      (failure->cActions > 0 && !failure->lpsaActions)) return false;
  for (DWORD index = 0; index < failure->cActions; ++index) {
    snapshot->failure_actions.push_back({
      failure->lpsaActions[index].Type,
      failure->lpsaActions[index].Delay,
    });
  }
  snapshot->failure_actions_on_non_crash =
      failure_flag->fFailureActionsOnNonCrashFailures != FALSE;
  snapshot->service_sid_type = sid->dwServiceSidType;
  if (!Win32MultiString(privileges->pmszRequiredPrivileges,
                        privilege_bytes,
                        &snapshot->required_privileges)) return false;
  if (triggers->cTriggers != 0 || triggers->pTriggers != nullptr ||
      triggers->pReserved != nullptr) return false;
  snapshot->trigger_count = 0;
  snapshot->preshutdown_timeout = preshutdown->dwPreshutdownTimeout;

  SERVICE_STATUS_PROCESS status{};
  required = 0;
  if (!QueryServiceStatusEx(handle->service, SC_STATUS_PROCESS_INFO,
          reinterpret_cast<LPBYTE>(&status), sizeof(status), &required)) {
    return false;
  }
  snapshot->state = status.dwCurrentState;
  snapshot->controls_accepted = status.dwControlsAccepted;
  snapshot->win32_exit_code = status.dwWin32ExitCode;
  snapshot->service_exit_code = status.dwServiceSpecificExitCode;
  snapshot->checkpoint = status.dwCheckPoint;
  snapshot->wait_hint = status.dwWaitHint;
  snapshot->process_id = status.dwProcessId;
  snapshot->service_flags = status.dwServiceFlags;

  snapshot->acl_matches = VerifyWin32ServiceObjectAcl(
      handle->service, handle->roles, &snapshot->security_sha256);
  if (snapshot->security_sha256.empty()) {
    DWORD security_bytes = 0;
    QueryServiceObjectSecurity(handle->service,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, 0, &security_bytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        security_bytes == 0 || security_bytes > 1024 * 1024) return false;
    std::vector<uint8_t> security(security_bytes);
    if (!QueryServiceObjectSecurity(handle->service,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            reinterpret_cast<PSECURITY_DESCRIPTOR>(security.data()),
            security_bytes, &security_bytes)) return false;
    Sha256 security_hash;
    const bool updated =
        security_hash.Update(security.data(), security_bytes);
    snapshot->security_sha256 = security_hash.Finish();
    if (!updated ||
        !ValidServiceFingerprint(snapshot->security_sha256)) return false;
  }
  const std::string expected_account = handle->service_role == "bot"
      ? handle->roles.bot : handle->roles.daemon;
  snapshot->account_matches_role = Win32ServiceAccountMatches(
      snapshot->account_name, expected_account);
  snapshot->config_fingerprint =
      Win32ServiceConfigFingerprint(*handle, *snapshot);
  snapshot->runtime_fingerprint =
      Win32ServiceRuntimeFingerprint(*handle, *snapshot);
  return ValidServiceFingerprint(snapshot->config_fingerprint) &&
      ValidServiceFingerprint(snapshot->runtime_fingerprint);
}

const char* Win32StartTypeName(DWORD value) {
  if (value == SERVICE_DISABLED) return "disabled";
  if (value == SERVICE_DEMAND_START) return "demand";
  if (value == SERVICE_AUTO_START) return "auto";
  if (value == SERVICE_BOOT_START) return "boot";
  if (value == SERVICE_SYSTEM_START) return "system";
  return "unknown";
}

const char* Win32StateName(DWORD value) {
  if (value == SERVICE_STOPPED) return "stopped";
  if (value == SERVICE_START_PENDING) return "start-pending";
  if (value == SERVICE_STOP_PENDING) return "stop-pending";
  if (value == SERVICE_RUNNING) return "running";
  if (value == SERVICE_CONTINUE_PENDING) return "continue-pending";
  if (value == SERVICE_PAUSE_PENDING) return "pause-pending";
  if (value == SERVICE_PAUSED) return "paused";
  return "unknown";
}

const char* Win32ActionName(DWORD value) {
  if (value == SC_ACTION_NONE) return "none";
  if (value == SC_ACTION_RESTART) return "restart";
  if (value == SC_ACTION_REBOOT) return "reboot";
  if (value == SC_ACTION_RUN_COMMAND) return "run-command";
  return "unknown";
}

const char* Win32FailurePolicyName(const Win32ServiceSnapshot& snapshot) {
  if (snapshot.failure_actions.empty() &&
      snapshot.failure_reboot_message.empty() &&
      snapshot.failure_command.empty() &&
      !snapshot.failure_actions_on_non_crash) {
    return "none";
  }
  if (snapshot.failure_reset_period == 600 &&
      snapshot.failure_actions.size() == 4 &&
      snapshot.failure_reboot_message.empty() &&
      snapshot.failure_command.empty() &&
      !snapshot.failure_actions_on_non_crash &&
      std::all_of(snapshot.failure_actions.begin(),
                  snapshot.failure_actions.begin() + 3,
          [](const Win32FailureAction& action) {
            return action.type == SC_ACTION_RESTART &&
                action.delay == 10000;
          }) &&
      snapshot.failure_actions[3].type == SC_ACTION_NONE &&
      snapshot.failure_actions[3].delay == 0) {
    return "restart-3x-10s";
  }
  return "other";
}

napi_value Win32ServiceSnapshotValue(napi_env env,
                                     const Win32ServiceHandle& handle,
                                     const Win32ServiceSnapshot& snapshot) {
  napi_value result, dependencies, privileges, actions, runtime;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "name", handle.name);
  ServiceSetString(env, result, "serviceRole", handle.service_role);
  ServiceSetUint32(env, result, "serviceType", snapshot.service_type);
  ServiceSetString(env, result, "startType",
                   Win32StartTypeName(snapshot.start_type));
  ServiceSetUint32(env, result, "errorControl", snapshot.error_control);
  ServiceSetUint32(env, result, "tagId", snapshot.tag_id);
  ServiceSetString(env, result, "binaryPath", snapshot.binary_path);
  ServiceSetString(env, result, "loadOrderGroup",
                   snapshot.load_order_group);
  napi_create_array_with_length(env, snapshot.dependencies.size(),
                                &dependencies);
  for (uint32_t index = 0; index < snapshot.dependencies.size(); ++index) {
    napi_value value;
    napi_create_string_utf8(env, snapshot.dependencies[index].c_str(),
        snapshot.dependencies[index].size(), &value);
    napi_set_element(env, dependencies, index, value);
  }
  napi_set_named_property(env, result, "dependencies", dependencies);
  ServiceSetString(env, result, "accountName", snapshot.account_name);
  ServiceSetString(env, result, "displayName", snapshot.display_name);
  ServiceSetString(env, result, "description", snapshot.description);
  ServiceSetBoolean(env, result, "delayedAutoStart",
                    snapshot.delayed_auto_start);
  ServiceSetUint32(env, result, "failureResetPeriod",
                   snapshot.failure_reset_period);
  ServiceSetString(env, result, "failureRebootMessage",
                   snapshot.failure_reboot_message);
  ServiceSetString(env, result, "failureCommand",
                   snapshot.failure_command);
  napi_create_array_with_length(env, snapshot.failure_actions.size(),
                                &actions);
  for (uint32_t index = 0;
       index < snapshot.failure_actions.size(); ++index) {
    napi_value action;
    napi_create_object(env, &action);
    ServiceSetString(env, action, "type",
        Win32ActionName(snapshot.failure_actions[index].type));
    ServiceSetUint32(env, action, "delayMs",
                     snapshot.failure_actions[index].delay);
    napi_set_element(env, actions, index, action);
  }
  napi_set_named_property(env, result, "failureActions", actions);
  ServiceSetBoolean(env, result, "failureActionsOnNonCrashFailures",
                    snapshot.failure_actions_on_non_crash);
  ServiceSetString(env, result, "failurePolicy",
                   Win32FailurePolicyName(snapshot));
  ServiceSetUint32(env, result, "serviceSidType",
                   snapshot.service_sid_type);
  napi_create_array_with_length(env, snapshot.required_privileges.size(),
                                &privileges);
  for (uint32_t index = 0;
       index < snapshot.required_privileges.size(); ++index) {
    napi_value value;
    napi_create_string_utf8(env,
        snapshot.required_privileges[index].c_str(),
        snapshot.required_privileges[index].size(), &value);
    napi_set_element(env, privileges, index, value);
  }
  napi_set_named_property(env, result, "requiredPrivileges", privileges);
  ServiceSetUint32(env, result, "triggerCount", snapshot.trigger_count);
  ServiceSetUint32(env, result, "preshutdownTimeout",
                   snapshot.preshutdown_timeout);
  ServiceSetString(env, result, "securitySha256",
                   snapshot.security_sha256);
  ServiceSetBoolean(env, result, "aclMatches", snapshot.acl_matches);
  ServiceSetBoolean(env, result, "accountMatchesRole",
                    snapshot.account_matches_role);
  ServiceSetString(env, result, "configFingerprint",
                   snapshot.config_fingerprint);
  napi_create_object(env, &runtime);
  ServiceSetString(env, runtime, "state", Win32StateName(snapshot.state));
  ServiceSetUint32(env, runtime, "controlsAccepted",
                   snapshot.controls_accepted);
  ServiceSetUint32(env, runtime, "win32ExitCode",
                   snapshot.win32_exit_code);
  ServiceSetUint32(env, runtime, "serviceExitCode",
                   snapshot.service_exit_code);
  ServiceSetUint32(env, runtime, "checkpoint", snapshot.checkpoint);
  ServiceSetUint32(env, runtime, "waitHint", snapshot.wait_hint);
  ServiceSetUint32(env, runtime, "processId", snapshot.process_id);
  ServiceSetUint32(env, runtime, "serviceFlags",
                   snapshot.service_flags);
  ServiceSetString(env, runtime, "fingerprint",
                   snapshot.runtime_fingerprint);
  napi_set_named_property(env, result, "runtime", runtime);
  return result;
}

bool ExpectedWin32ServiceSnapshot(
    Win32ServiceHandle* handle, const std::string& config_fingerprint,
    const std::string& runtime_fingerprint, bool require_owned,
    Win32ServiceSnapshot* snapshot) {
  return ValidServiceFingerprint(config_fingerprint) &&
      ValidServiceFingerprint(runtime_fingerprint) &&
      QueryWin32ServiceSnapshot(handle, snapshot) &&
      snapshot->config_fingerprint == config_fingerprint &&
      snapshot->runtime_fingerprint == runtime_fingerprint &&
      snapshot->account_matches_role &&
      (!require_owned ||
       (snapshot->acl_matches &&
        ValidWin32ServiceMarker(snapshot->description)));
}

void ReportWin32MutationFailure(napi_env env, const char* operation,
                                Win32ServiceHandle* handle,
                                const Win32ServiceSnapshot& before) {
  Win32ServiceSnapshot observed;
  if (QueryWin32ServiceSnapshot(handle, &observed) &&
      observed.config_fingerprint == before.config_fingerprint &&
      observed.runtime_fingerprint == before.runtime_fingerprint) {
    ServiceError(env, "SERVICE_IO_FAILED", operation);
    return;
  }
  ServiceError(env, "SERVICE_MANUAL_CLEANUP", operation, 1, true);
}

bool Win32PasswordArg(napi_env env, napi_value value,
                      std::vector<wchar_t>* password, bool* present) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok) return false;
  if (type == napi_null) {
    *present = false;
    return true;
  }
  if (type != napi_string) return false;
  size_t utf8_bytes = 0;
  size_t utf16_units = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &utf8_bytes) !=
          napi_ok ||
      utf8_bytes > 16 * 1024 ||
      napi_get_value_string_utf16(env, value, nullptr, 0, &utf16_units) !=
          napi_ok ||
      utf16_units > 16 * 1024) return false;
  password->resize(utf16_units + 1);
  if (napi_get_value_string_utf16(env, value,
          reinterpret_cast<char16_t*>(password->data()),
          password->size(), &utf16_units) != napi_ok) return false;
  password->resize(utf16_units + 1);
  (*password)[utf16_units] = L'\0';
  for (size_t index = 0; index < utf16_units; ++index) {
    const wchar_t unit = (*password)[index];
    if (unit == L'\0') return false;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (++index >= utf16_units ||
          (*password)[index] < 0xdc00 ||
          (*password)[index] > 0xdfff) return false;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  *present = true;
  return true;
}

bool Win32Boolean(napi_env env, napi_value value, bool* result) {
  napi_valuetype type;
  return napi_typeof(env, value, &type) == napi_ok &&
      type == napi_boolean &&
      napi_get_value_bool(env, value, result) == napi_ok;
}

bool Win32NullableString(napi_env env, napi_value value,
                         std::string* result, bool* present) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok) return false;
  if (type == napi_null) {
    result->clear();
    *present = false;
    return true;
  }
  *present = true;
  return InventoryString(env, value, result);
}

bool Win32PathHasLeaf(const std::string& path,
                      const std::string& expected_lower) {
  WindowsPathParts parts;
  if (!ParseWindowsPath(path, &parts) || parts.components.empty()) {
    return false;
  }
  std::wstring leaf = parts.components.back();
  std::transform(leaf.begin(), leaf.end(), leaf.begin(),
      [](wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
      });
  return Utf8(leaf) == expected_lower;
}

bool ReadWindowsFileSha256(const std::string& path,
                           const std::string& expected) {
  if (!ValidServiceFingerprint(expected)) return false;
  HANDLE handle = OpenWindowsPathNoFollow(path, GENERIC_READ,
      VerifiedObjectType::File, FILE_SHARE_READ | FILE_SHARE_DELETE);
  if (handle == INVALID_HANDLE_VALUE) return false;
  FILE_ID_INFO before_id{}, after_id{};
  FILE_BASIC_INFO before_basic{}, after_basic{};
  FILE_STANDARD_INFO before_size{}, after_size{};
  bool valid =
      GetFileInformationByHandleEx(handle, FileIdInfo, &before_id,
                                   sizeof(before_id)) &&
      GetFileInformationByHandleEx(handle, FileBasicInfo, &before_basic,
                                   sizeof(before_basic)) &&
      GetFileInformationByHandleEx(handle, FileStandardInfo, &before_size,
                                   sizeof(before_size)) &&
      before_size.EndOfFile.QuadPart >= 0 &&
      before_size.EndOfFile.QuadPart <=
          static_cast<LONGLONG>(2ULL * 1024 * 1024 * 1024);
  Sha256 hash;
  std::array<uint8_t, 64 * 1024> buffer{};
  uint64_t total = 0;
  while (valid && total <
      static_cast<uint64_t>(before_size.EndOfFile.QuadPart)) {
    const DWORD requested = static_cast<DWORD>(std::min<uint64_t>(
        buffer.size(),
        static_cast<uint64_t>(before_size.EndOfFile.QuadPart) - total));
    DWORD read = 0;
    if (!ReadFile(handle, buffer.data(), requested, &read, nullptr) ||
        read == 0) {
      valid = false;
      break;
    }
    valid = hash.Update(buffer.data(), read);
    total += read;
  }
  valid = valid &&
      GetFileInformationByHandleEx(handle, FileIdInfo, &after_id,
                                   sizeof(after_id)) &&
      GetFileInformationByHandleEx(handle, FileBasicInfo, &after_basic,
                                   sizeof(after_basic)) &&
      GetFileInformationByHandleEx(handle, FileStandardInfo, &after_size,
                                   sizeof(after_size)) &&
      SameWindowsFileId(before_id, after_id) &&
      before_basic.CreationTime.QuadPart ==
          after_basic.CreationTime.QuadPart &&
      before_basic.LastWriteTime.QuadPart ==
          after_basic.LastWriteTime.QuadPart &&
      before_basic.ChangeTime.QuadPart ==
          after_basic.ChangeTime.QuadPart &&
      before_basic.FileAttributes == after_basic.FileAttributes &&
      before_size.EndOfFile.QuadPart == after_size.EndOfFile.QuadPart &&
      total == static_cast<uint64_t>(before_size.EndOfFile.QuadPart) &&
      hash.Finish() == expected;
  CloseHandle(handle);
  return valid;
}

bool VerifyWindowsDirectoryNoFollow(const std::string& path) {
  WindowsPathParts parts;
  if (!ParseWindowsPath(path, &parts)) return false;
  HANDLE handle = OpenWindowsPathNoFollow(path, FILE_READ_ATTRIBUTES,
      VerifiedObjectType::Directory);
  if (handle == INVALID_HANDLE_VALUE) return false;
  CloseHandle(handle);
  return true;
}

bool VerifyWindowsPathServiceAcl(const std::string& path,
                                 const InventoryRoles& roles,
                                 ServiceAclProfile profile) {
  HANDLE handle = OpenWindowsPathNoFollow(path,
      READ_CONTROL | FILE_READ_ATTRIBUTES,
      ServiceProfileDirectory(profile)
          ? VerifiedObjectType::Directory : VerifiedObjectType::File);
  const bool verified = handle != INVALID_HANDLE_VALUE &&
      VerifyWindowsServiceFileAcl(handle, roles, profile);
  if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
  return verified;
}

std::wstring QuoteWin32Argument(const std::wstring& argument) {
  std::wstring quoted;
  quoted.push_back(L'"');
  size_t backslashes = 0;
  for (wchar_t character : argument) {
    if (character == L'\\') {
      ++backslashes;
      continue;
    }
    if (character == L'"') {
      quoted.append(backslashes * 2 + 1, L'\\');
      quoted.push_back(L'"');
      backslashes = 0;
      continue;
    }
    quoted.append(backslashes, L'\\');
    backslashes = 0;
    quoted.push_back(character);
  }
  quoted.append(backslashes * 2, L'\\');
  quoted.push_back(L'"');
  return quoted;
}

struct Win32ServiceLaunch {
  std::string supervisor_path;
  std::string supervisor_sha256;
  std::string working_directory;
  std::string home_directory;
  std::string runtime_path;
  std::string runtime_sha256;
  std::string runtime_version;
  std::string runtime_source_revision;
  std::string entrypoint_path;
  std::string entrypoint_sha256;
  std::string bootstrap_path;
  std::string bootstrap_sha256;
  std::string bootstrap_closure_fingerprint;
  std::string runtime_config_root;
  std::string runtime_config_root_identity_fingerprint;
  std::string runtime_config_path;
  std::string runtime_config_sha256;
  std::string runtime_config_identity_fingerprint;
  std::string sdk_profile_path;
  std::string scope_fingerprint;
  std::string log_directory;
  std::string log_as;
  std::string log_cmd_as;
  std::string channels_config;
  bool has_channels_config = false;
  bool has_runtime_config = false;
  bool has_sdk_profile = false;
  std::string effective_config_fingerprint;
  std::string config_source_identity_fingerprint;
  std::string runtime_policy_fingerprint;
  std::string launch_fingerprint;
  std::vector<std::string> child_arguments;
  std::vector<std::pair<std::string, std::string>> environment;
  std::wstring command_line;
};

bool ValidWin32LogBase(const std::string& value,
                       const std::string& expected) {
  return value == expected && !value.empty() && value.size() <= 255 &&
      std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') ||
            character == '-';
      });
}

bool ValidCanonicalWin32LaunchPath(const std::string& value) {
  WindowsPathParts parts;
  return value.size() >= 4 && value[0] >= 'A' && value[0] <= 'Z' &&
      value.find('/') == std::string::npos && value.back() != '\\' &&
      ParseWindowsPath(value, &parts) && !parts.components.empty();
}

bool ValidWin32LaunchText(const std::string& value) {
  for (size_t index = 0; index < value.size(); ++index) {
    const uint8_t byte = static_cast<uint8_t>(value[index]);
    if (byte < 0x20 || (byte >= 0x7f && byte <= 0x9f)) return false;
    if (index + 2 < value.size() && byte == 0xe2 &&
        static_cast<uint8_t>(value[index + 1]) == 0x80 &&
        (static_cast<uint8_t>(value[index + 2]) == 0xa8 ||
         static_cast<uint8_t>(value[index + 2]) == 0xa9)) return false;
  }
  return true;
}

bool ValidWin32LaunchHash(const std::string& value, size_t length = 64) {
  return value.size() == length &&
      value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

std::string Win32JsonString(const std::string& value) {
  std::string result = "\"";
  for (unsigned char character : value) {
    if (character == '"' || character == '\\') {
      result.push_back('\\');
      result.push_back(static_cast<char>(character));
    } else if (character < 0x20) {
      static constexpr char hex[] = "0123456789abcdef";
      result += "\\u00";
      result.push_back(hex[(character >> 4) & 0x0f]);
      result.push_back(hex[character & 0x0f]);
    } else {
      result.push_back(static_cast<char>(character));
    }
  }
  result.push_back('"');
  return result;
}

std::string Win32CanonicalObject(
    const std::map<std::string, std::string>& fields) {
  std::string result = "{";
  bool first = true;
  for (const auto& field : fields) {
    if (!first) result.push_back(',');
    first = false;
    result += Win32JsonString(field.first);
    result.push_back(':');
    result += field.second;
  }
  result.push_back('}');
  return result;
}

std::map<std::string, std::string> Win32LaunchEnvironment(
    const Win32ServiceLaunch& launch, const std::string& role,
    const std::string& service_key, bool policy_template) {
  std::map<std::string, std::string> values;
  auto add = [&values](const std::string& key,
                       const std::string& value) {
    values.emplace(key, Win32JsonString(value));
  };
  add("HOME", launch.home_directory);
  add("USERPROFILE", launch.home_directory);
  add("NODE_OPTIONS", "");
  add("NODE_PATH", "");
  if (role == "daemon") {
    add("BUN_OPTIONS", "");
    add("BUN_INSPECT_PRELOAD", launch.bootstrap_path);
    add("XDG_CONFIG_HOME", launch.runtime_config_root);
    add("BUN_INSPECT", "");
    add("BUN_INSPECT_CONNECT_TO", "");
    add("GJC_CODING_AGENT_DIR", launch.sdk_profile_path);
  } else {
    add("CHANNELS_CONFIG", launch.channels_config);
  }
  add("GJC_REMOTE_SERVICE_COMPONENT", role);
  add("GJC_REMOTE_SERVICE_KEY", service_key);
  add("GJC_REMOTE_SUPERVISOR_SHA256", launch.supervisor_sha256);
  add("GJC_REMOTE_RUNTIME_VERSION", launch.runtime_version);
  add("GJC_REMOTE_RUNTIME_SOURCE_REVISION", launch.runtime_source_revision);
  add("GJC_REMOTE_RUNTIME_SHA256", launch.runtime_sha256);
  add("GJC_REMOTE_ENTRYPOINT_SHA256", launch.entrypoint_sha256);
  add("GJC_REMOTE_BOOTSTRAP_PATH", launch.bootstrap_path);
  add("GJC_REMOTE_BOOTSTRAP_SHA256", launch.bootstrap_sha256);
  add("GJC_REMOTE_BOOTSTRAP_CLOSURE_FINGERPRINT",
      launch.bootstrap_closure_fingerprint);
  add("GJC_REMOTE_RUNTIME_CONFIG_ROOT_IDENTITY_FINGERPRINT",
      launch.runtime_config_root_identity_fingerprint);
  add("GJC_REMOTE_RUNTIME_CONFIG_PATH", launch.runtime_config_path);
  add("GJC_REMOTE_RUNTIME_CONFIG_SHA256", launch.runtime_config_sha256);
  add("GJC_REMOTE_RUNTIME_CONFIG_IDENTITY_FINGERPRINT",
      launch.runtime_config_identity_fingerprint);
  add("GJC_REMOTE_SDK_PROFILE_PATH", launch.sdk_profile_path);
  add("GJC_REMOTE_SCOPE_FINGERPRINT", launch.scope_fingerprint);
  add("GJC_REMOTE_EFFECTIVE_CONFIG_FINGERPRINT",
      launch.effective_config_fingerprint);
  add("GJC_REMOTE_CONFIG_SOURCE_IDENTITY_FINGERPRINT",
      launch.config_source_identity_fingerprint);
  add("GJC_REMOTE_LAUNCH_FINGERPRINT", launch.launch_fingerprint);
  add("GJC_REMOTE_RUNTIME_POLICY_FINGERPRINT",
      policy_template ? "@runtime-policy-fingerprint"
                      : launch.runtime_policy_fingerprint);
  return values;
}

std::vector<std::string> Win32ChildArguments(
    const Win32ServiceLaunch& launch, const std::string& role) {
  if (role == "bot") {
    return {launch.runtime_path, launch.entrypoint_path};
  }
  return {launch.runtime_path, "--config", launch.runtime_config_path,
      "--no-env-file", launch.entrypoint_path};
}

std::string Win32LaunchFingerprint(
    const Win32ServiceLaunch& launch, const std::string& role,
    const std::string& service_key) {
  std::map<std::string, std::string> values{
    {"bootstrapClosureFingerprint", Win32JsonString(launch.bootstrap_closure_fingerprint)},
    {"bootstrapPath", Win32JsonString(launch.bootstrap_path)},
    {"bootstrapSha256", Win32JsonString(launch.bootstrap_sha256)},
    {"channelsConfig", launch.has_channels_config ? Win32JsonString(launch.channels_config) : "null"},
    {"configSourceIdentityFingerprint", Win32JsonString(launch.config_source_identity_fingerprint)},
    {"effectiveConfigFingerprint", Win32JsonString(launch.effective_config_fingerprint)},
    {"entrypointPath", Win32JsonString(launch.entrypoint_path)},
    {"entrypointSha256", Win32JsonString(launch.entrypoint_sha256)},
    {"homeDirectory", Win32JsonString(launch.home_directory)},
    {"logAs", Win32JsonString(launch.log_as)},
    {"logCmdAs", Win32JsonString(launch.log_cmd_as)},
    {"logDirectory", Win32JsonString(launch.log_directory)},
    {"runtimeConfigIdentityFingerprint", launch.has_runtime_config ? Win32JsonString(launch.runtime_config_identity_fingerprint) : "null"},
    {"runtimeConfigPath", launch.has_runtime_config ? Win32JsonString(launch.runtime_config_path) : "null"},
    {"runtimeConfigRoot", launch.has_runtime_config ? Win32JsonString(launch.runtime_config_root) : "null"},
    {"runtimeConfigRootIdentityFingerprint", launch.has_runtime_config ? Win32JsonString(launch.runtime_config_root_identity_fingerprint) : "null"},
    {"runtimeConfigSha256", launch.has_runtime_config ? Win32JsonString(launch.runtime_config_sha256) : "null"},
    {"runtimePath", Win32JsonString(launch.runtime_path)},
    {"runtimeSha256", Win32JsonString(launch.runtime_sha256)},
    {"runtimeSourceRevision", Win32JsonString(launch.runtime_source_revision)},
    {"runtimeVersion", Win32JsonString(launch.runtime_version)},
    {"sdkProfilePath", launch.has_sdk_profile ? Win32JsonString(launch.sdk_profile_path) : "null"},
    {"scopeFingerprint", Win32JsonString(launch.scope_fingerprint)},
    {"supervisorPath", Win32JsonString(launch.supervisor_path)},
    {"supervisorSha256", Win32JsonString(launch.supervisor_sha256)},
    {"workingDirectory", Win32JsonString(launch.working_directory)},
  };
  const std::string launch_json = Win32CanonicalObject(values);
  const std::string canonical = Win32CanonicalObject({
    {"component", Win32JsonString(role)},
    {"kind", Win32JsonString("gjc-remote/windows-service-launch/v1")},
    {"launch", launch_json},
    {"serviceKey", Win32JsonString(service_key)},
  });
  Sha256 hash;
  if (!hash.Ready() || !hash.Update(canonical)) return {};
  return hash.Finish();
}

std::string Win32RuntimePolicyFingerprint(
    const Win32ServiceLaunch& launch, const std::string& role,
    const std::string& service_key) {
  std::string argv = "[";
  bool first = true;
  for (const auto& argument : Win32ChildArguments(launch, role)) {
    if (!first) argv.push_back(',');
    first = false;
    argv += Win32JsonString(argument);
  }
  argv.push_back(']');
  const std::string environment = Win32CanonicalObject(
      Win32LaunchEnvironment(launch, role, service_key, true));
  const std::string canonical = Win32CanonicalObject({
    {"argv", argv},
    {"component", Win32JsonString(role)},
    {"environment", environment},
    {"kind", Win32JsonString("gjc-remote/windows-runtime-policy/v1")},
    {"launchFingerprint", Win32JsonString(launch.launch_fingerprint)},
    {"runtimeSourceRevision", Win32JsonString(launch.runtime_source_revision)},
    {"runtimeVersion", Win32JsonString(launch.runtime_version)},
    {"serviceKey", Win32JsonString(service_key)},
  });
  Sha256 hash;
  if (!hash.Ready() || !hash.Update(canonical)) return {};
  return hash.Finish();
}

std::string Win32ServiceLogStem(const std::string& name,
                                const std::string& role) {
  return role == "bot" ? "gjc-remote-bot" :
      "gjc-remote-daemon-" +
          name.substr(std::string("GJCRemoteDaemon-").size());
}

std::vector<std::pair<std::string, std::string>>
Win32LaunchEnvironmentEntries(const Win32ServiceLaunch& launch,
                              const std::string& role,
                              const std::string& service_key) {
  std::vector<std::pair<std::string, std::string>> values{
    {"HOME", launch.home_directory},
    {"USERPROFILE", launch.home_directory},
    {"NODE_OPTIONS", ""},
    {"NODE_PATH", ""},
  };
  if (role == "daemon") {
    values.insert(values.end(), {
      {"BUN_OPTIONS", ""},
      {"BUN_INSPECT_PRELOAD", launch.bootstrap_path},
      {"XDG_CONFIG_HOME", launch.runtime_config_root},
      {"BUN_INSPECT", ""},
      {"BUN_INSPECT_CONNECT_TO", ""},
      {"GJC_CODING_AGENT_DIR", launch.sdk_profile_path},
    });
  } else {
    values.emplace_back("CHANNELS_CONFIG", launch.channels_config);
  }
  values.insert(values.end(), {
    {"GJC_REMOTE_SERVICE_COMPONENT", role},
    {"GJC_REMOTE_SERVICE_KEY", service_key},
    {"GJC_REMOTE_SUPERVISOR_SHA256", launch.supervisor_sha256},
    {"GJC_REMOTE_RUNTIME_VERSION", launch.runtime_version},
    {"GJC_REMOTE_RUNTIME_SOURCE_REVISION", launch.runtime_source_revision},
    {"GJC_REMOTE_RUNTIME_SHA256", launch.runtime_sha256},
    {"GJC_REMOTE_ENTRYPOINT_SHA256", launch.entrypoint_sha256},
    {"GJC_REMOTE_BOOTSTRAP_PATH", launch.bootstrap_path},
    {"GJC_REMOTE_BOOTSTRAP_SHA256", launch.bootstrap_sha256},
    {"GJC_REMOTE_BOOTSTRAP_CLOSURE_FINGERPRINT",
        launch.bootstrap_closure_fingerprint},
    {"GJC_REMOTE_RUNTIME_CONFIG_ROOT_IDENTITY_FINGERPRINT",
        launch.runtime_config_root_identity_fingerprint},
    {"GJC_REMOTE_RUNTIME_CONFIG_PATH", launch.runtime_config_path},
    {"GJC_REMOTE_RUNTIME_CONFIG_SHA256", launch.runtime_config_sha256},
    {"GJC_REMOTE_RUNTIME_CONFIG_IDENTITY_FINGERPRINT",
        launch.runtime_config_identity_fingerprint},
    {"GJC_REMOTE_SDK_PROFILE_PATH", launch.sdk_profile_path},
    {"GJC_REMOTE_SCOPE_FINGERPRINT", launch.scope_fingerprint},
    {"GJC_REMOTE_EFFECTIVE_CONFIG_FINGERPRINT",
        launch.effective_config_fingerprint},
    {"GJC_REMOTE_CONFIG_SOURCE_IDENTITY_FINGERPRINT",
        launch.config_source_identity_fingerprint},
    {"GJC_REMOTE_LAUNCH_FINGERPRINT", launch.launch_fingerprint},
    {"GJC_REMOTE_RUNTIME_POLICY_FINGERPRINT",
        launch.runtime_policy_fingerprint},
  });
  return values;
}

bool VerifyWin32RuntimeConfigLaunch(const Win32ServiceLaunch& launch,
                                    const InventoryRoles& roles);
bool VerifyWin32ConfigSourceLaunch(const Win32ServiceLaunch& launch,
                                   const InventoryRoles& roles,
                                   const std::string& role);

bool CaptureWin32ServiceLaunch(napi_env env, napi_value value,
                               const std::string& name,
                               const std::string& role,
                               const InventoryRoles& roles,
                               Win32ServiceLaunch* launch) {
  static const char* const field_names[] = {
    "supervisorPath", "supervisorSha256", "workingDirectory",
    "homeDirectory", "runtimePath", "runtimeSha256", "runtimeVersion",
    "runtimeSourceRevision", "entrypointPath", "entrypointSha256",
    "bootstrapPath", "bootstrapSha256", "bootstrapClosureFingerprint",
    "runtimeConfigRoot", "runtimeConfigRootIdentityFingerprint",
    "runtimeConfigPath", "runtimeConfigSha256",
    "runtimeConfigIdentityFingerprint", "sdkProfilePath", "scopeFingerprint",
    "logDirectory", "logAs", "logCmdAs", "channelsConfig",
    "effectiveConfigFingerprint", "configSourceIdentityFingerprint",
    "runtimePolicyFingerprint",
  };
  napi_value captured[27];
  if (!InventoryOrdinaryDataObject(env, value, field_names, 27, captured)) {
    return false;
  }
  auto read = [env, captured](size_t index, std::string* result) {
    return InventoryString(env, captured[index], result) &&
        ValidWin32LaunchText(*result);
  };
  auto read_nullable = [env, captured](size_t index, std::string* result,
                                      bool* present) {
    return Win32NullableString(
               env, captured[index], result, present) &&
        (!*present || ValidWin32LaunchText(*result));
  };
  const std::string log_stem = Win32ServiceLogStem(name, role);
  if (!read(0, &launch->supervisor_path) ||
      !read(1, &launch->supervisor_sha256) ||
      !read(2, &launch->working_directory) ||
      !read(3, &launch->home_directory) ||
      !read(4, &launch->runtime_path) ||
      !read(5, &launch->runtime_sha256) ||
      !read(6, &launch->runtime_version) ||
      !read(7, &launch->runtime_source_revision) ||
      !read(8, &launch->entrypoint_path) ||
      !read(9, &launch->entrypoint_sha256) ||
      !read(10, &launch->bootstrap_path) ||
      !read(11, &launch->bootstrap_sha256) ||
      !read(12, &launch->bootstrap_closure_fingerprint) ||
      !read_nullable(13, &launch->runtime_config_root,
                     &launch->has_runtime_config) ||
      !read_nullable(14, &launch->runtime_config_root_identity_fingerprint,
                     &launch->has_runtime_config) ||
      !read_nullable(15, &launch->runtime_config_path,
                     &launch->has_runtime_config) ||
      !read_nullable(16, &launch->runtime_config_sha256,
                     &launch->has_runtime_config) ||
      !read_nullable(17, &launch->runtime_config_identity_fingerprint,
                     &launch->has_runtime_config) ||
      !read_nullable(18, &launch->sdk_profile_path,
                     &launch->has_sdk_profile) ||
      !read(19, &launch->scope_fingerprint) ||
      !read(20, &launch->log_directory) ||
      !read(21, &launch->log_as) ||
      !read(22, &launch->log_cmd_as) ||
      !read_nullable(23, &launch->channels_config,
                     &launch->has_channels_config) ||
      !read(24, &launch->effective_config_fingerprint) ||
      !read(25, &launch->config_source_identity_fingerprint) ||
      !read(26, &launch->runtime_policy_fingerprint)) return false;

  const bool daemon = role == "daemon";
  const std::string service_key = role == "bot" ? "bot" :
      name.substr(std::string("GJCRemoteDaemon-").size());
  const std::string expected_version = daemon ? "1.4.2" : "26.7.0";
  const std::string expected_revision = daemon
      ? "744846f844374847c902b5e7fd59b4342a51ef99"
      : "b4f23d3619c98bed09af93a21192f6080197a8c6";
  const std::string expected_runtime_config_root =
      launch->working_directory + "\\runtime-config";
  const std::string expected_runtime_config_path =
      expected_runtime_config_root + "\\.bunfig.toml";
  if (launch->has_runtime_config != daemon ||
      launch->has_sdk_profile != daemon ||
      launch->has_channels_config != !daemon ||
      launch->runtime_version != expected_version ||
      launch->runtime_source_revision != expected_revision ||
      !ValidWin32LaunchHash(launch->runtime_source_revision, 40) ||
      !ValidWin32LaunchHash(launch->supervisor_sha256) ||
      !ValidWin32LaunchHash(launch->runtime_sha256) ||
      !ValidWin32LaunchHash(launch->entrypoint_sha256) ||
      !ValidWin32LaunchHash(launch->bootstrap_sha256) ||
      !ValidWin32LaunchHash(launch->bootstrap_closure_fingerprint) ||
      !ValidWin32LaunchHash(launch->scope_fingerprint) ||
      !ValidWin32LaunchHash(launch->effective_config_fingerprint) ||
      !ValidWin32LaunchHash(launch->config_source_identity_fingerprint) ||
      !ValidWin32LaunchHash(launch->runtime_policy_fingerprint) ||
      !ValidCanonicalWin32LaunchPath(launch->supervisor_path) ||
      !ValidCanonicalWin32LaunchPath(launch->working_directory) ||
      !ValidCanonicalWin32LaunchPath(launch->home_directory) ||
      !ValidCanonicalWin32LaunchPath(launch->runtime_path) ||
      !ValidCanonicalWin32LaunchPath(launch->entrypoint_path) ||
      !ValidCanonicalWin32LaunchPath(launch->bootstrap_path) ||
      !ValidCanonicalWin32LaunchPath(launch->log_directory) ||
      !Win32PathHasLeaf(launch->supervisor_path, "shawl.exe") ||
      !Win32PathHasLeaf(launch->runtime_path,
          daemon ? "bun.exe" : "node.exe") ||
      !Win32PathHasLeaf(launch->entrypoint_path,
          daemon ? "daemon.js" : "bot.js") ||
      !Win32PathHasLeaf(launch->bootstrap_path,
          "service-bootstrap.js") ||
      launch->home_directory.size() > 4096 ||
      !ValidWin32LogBase(launch->log_as, log_stem + "-wrapper") ||
      !ValidWin32LogBase(launch->log_cmd_as, log_stem + "-child") ||
      (daemon &&
       (!ValidCanonicalWin32LaunchPath(launch->runtime_config_root) ||
        !ValidWin32LaunchHash(launch->runtime_config_root_identity_fingerprint) ||
        !ValidCanonicalWin32LaunchPath(launch->runtime_config_path) ||
        launch->runtime_config_sha256 !=
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ||
        !ValidWin32LaunchHash(launch->runtime_config_identity_fingerprint) ||
        !ValidCanonicalWin32LaunchPath(launch->sdk_profile_path) ||
        launch->runtime_config_root != expected_runtime_config_root ||
        launch->runtime_config_path != expected_runtime_config_path)) ||
      (!daemon && (!launch->runtime_config_root.empty() ||
          !launch->runtime_config_root_identity_fingerprint.empty() ||
          !launch->runtime_config_path.empty() ||
          !launch->runtime_config_sha256.empty() ||
          !launch->runtime_config_identity_fingerprint.empty() ||
          !launch->sdk_profile_path.empty())) ||
      (daemon && !launch->channels_config.empty()) ||
      (!daemon && !ValidCanonicalWin32LaunchPath(launch->channels_config))) {
    return false;
  }

  if (!ReadWindowsFileSha256(launch->supervisor_path,
                             launch->supervisor_sha256) ||
      !ReadWindowsFileSha256(launch->runtime_path, launch->runtime_sha256) ||
      !ReadWindowsFileSha256(launch->entrypoint_path,
                             launch->entrypoint_sha256) ||
      !ReadWindowsFileSha256(launch->bootstrap_path,
                             launch->bootstrap_sha256) ||
      !VerifyWindowsPathServiceAcl(launch->supervisor_path, roles,
          ServiceAclProfile::ReleaseExecutable) ||
      !VerifyWindowsPathServiceAcl(launch->runtime_path, roles,
          ServiceAclProfile::ReleaseExecutable) ||
      !VerifyWindowsPathServiceAcl(launch->entrypoint_path, roles,
          ServiceAclProfile::ReleaseFile) ||
      !VerifyWindowsPathServiceAcl(launch->bootstrap_path, roles,
          ServiceAclProfile::ReleaseFile) ||
      !VerifyWindowsDirectoryNoFollow(launch->working_directory) ||
      !VerifyWindowsDirectoryNoFollow(launch->home_directory) ||
      !VerifyWindowsDirectoryNoFollow(launch->log_directory)) return false;

  const ServiceAclProfile log_profile = daemon
      ? ServiceAclProfile::DaemonLogDirectory
      : ServiceAclProfile::BotLogDirectory;
  if (!VerifyWindowsPathServiceAcl(launch->log_directory, roles,
                                   log_profile) ||
      !VerifyWin32ConfigSourceLaunch(*launch, roles, role) ||
      (!daemon && !VerifyWindowsPathServiceAcl(launch->channels_config, roles,
          ServiceAclProfile::BotConfigFile)) ||
      (daemon && !VerifyWin32RuntimeConfigLaunch(*launch, roles)) ||
      (daemon && (!VerifyWindowsPathServiceAcl(launch->sdk_profile_path,
          roles, ServiceAclProfile::SdkInstallDirectory)))) return false;

  launch->launch_fingerprint = Win32LaunchFingerprint(
      *launch, role, service_key);
  const std::string expected_policy = Win32RuntimePolicyFingerprint(
      *launch, role, service_key);
  if (!ValidWin32LaunchHash(launch->launch_fingerprint) ||
      expected_policy != launch->runtime_policy_fingerprint) return false;
  launch->child_arguments = Win32ChildArguments(*launch, role);
  launch->environment = Win32LaunchEnvironmentEntries(
      *launch, role, service_key);
  std::vector<std::string> arguments = {
    launch->supervisor_path, "run", "--name", name, "--cwd",
    launch->working_directory,
  };
  for (const auto& entry : launch->environment) {
    arguments.push_back("--env");
    arguments.push_back(entry.first + "=" + entry.second);
  }
  const std::string stop_timeout = daemon ? "20000" : "30000";
  const std::vector<std::string> wrapper_options = {
    "--kill-process-tree", "--restart-if-not", "0", "--restart-delay",
    "10000", "--stop-timeout", stop_timeout, "--log-dir",
    launch->log_directory, "--log-as", launch->log_as, "--log-cmd-as",
    launch->log_cmd_as, "--log-rotate", "bytes=1048576", "--log-retain",
    "2", "--",
  };
  arguments.insert(arguments.end(), wrapper_options.begin(),
                   wrapper_options.end());
  arguments.insert(arguments.end(), launch->child_arguments.begin(),
                   launch->child_arguments.end());
  launch->command_line.clear();
  for (const auto& argument : arguments) {
    const std::wstring wide = Wide(argument);
    if (wide.empty()) return false;
    if (!launch->command_line.empty()) launch->command_line.push_back(L' ');
    launch->command_line += QuoteWin32Argument(wide);
  }
  return launch->command_line.size() <= 32767;
}
#endif

napi_value OpenWin32Service(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  napi_value args[4];
  std::string name, role, access;
  InventoryRoles roles{};
  if (!InventoryArgs(env, info, 4, args) ||
      !InventoryString(env, args[0], &name) ||
      !InventoryString(env, args[1], &role) ||
      !ValidWin32ServiceName(name, role) ||
      !InventoryString(env, args[3], &access) ||
      (access != "query" && access != "mutate") ||
      !InventoryRolesArg(env, args[2], &roles) ||
      !ServiceActorAuthorized(roles)) {
    ServiceError(env, "SERVICE_INVALID", "open_win32_service");
    return nullptr;
  }
  auto* handle = new Win32ServiceHandle();
  handle->roles = roles;
  handle->service_role = role;
  handle->name = name;
  handle->mutable_access = access == "mutate";
  handle->manager =
      OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASEW, SC_MANAGER_CONNECT);
  if (!handle->manager) {
    delete handle;
    ServiceError(env, "SERVICE_ACCESS_DENIED", "open_win32_service");
    return nullptr;
  }
  DWORD desired = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL;
  if (handle->mutable_access) {
    desired |= SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP |
        DELETE | WRITE_DAC | WRITE_OWNER;
  }
  handle->service = OpenServiceW(
      handle->manager, Wide(name).c_str(), desired);
  if (!handle->service) {
    const DWORD error = GetLastError();
    CloseWin32ServiceHandle(handle);
    delete handle;
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
      napi_value absent;
      napi_get_null(env, &absent);
      return absent;
    }
    ServiceError(env,
        error == ERROR_SERVICE_MARKED_FOR_DELETE
            ? "SERVICE_PENDING" : "SERVICE_ACCESS_DENIED",
        "open_win32_service");
    return nullptr;
  }
  napi_value result = WrapWin32ServiceHandle(env, handle);
  if (!result) {
    ServiceError(env, "SERVICE_IO_FAILED", "open_win32_service");
    return nullptr;
  }
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "open_win32_service");
  return nullptr;
#endif
}

napi_value CloseWin32Service(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  napi_value args[1];
  Win32ServiceHandle* handle = nullptr;
  if (!InventoryArgs(env, info, 1, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle)) {
    ServiceError(env, "SERVICE_INVALID", "close_win32_service");
    return nullptr;
  }
  CloseWin32ServiceHandle(handle);
  napi_value result;
  napi_get_undefined(env, &result);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "close_win32_service");
  return nullptr;
#endif
}

napi_value QueryWin32Service(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  napi_value args[1];
  Win32ServiceHandle* handle = nullptr;
  if (!InventoryArgs(env, info, 1, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle)) {
    ServiceError(env, "SERVICE_INVALID", "query_win32_service");
    return nullptr;
  }
  Win32ServiceSnapshot snapshot;
  if (!QueryWin32ServiceSnapshot(handle, &snapshot)) {
    ServiceError(env, "SERVICE_IO_FAILED", "query_win32_service");
    return nullptr;
  }
  return Win32ServiceSnapshotValue(env, *handle, snapshot);
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "query_win32_service");
  return nullptr;
#endif
}

#ifdef _WIN32
bool BuildWin32PlannedServiceSnapshot(
    const std::string& name, const std::string& role,
    const InventoryRoles& roles, const Win32ServiceLaunch& launch,
    const std::string& application_fingerprint, const std::string& phase,
    Win32ServiceSnapshot* snapshot) {
  if (phase != "trial" && phase != "final-auto" && phase != "final") {
    return false;
  }
  Win32ServiceHandle handle;
  handle.name = name;
  handle.service_role = role;
  handle.roles = roles;
  snapshot->service_type = SERVICE_WIN32_OWN_PROCESS;
  snapshot->start_type = phase == "trial"
      ? SERVICE_DEMAND_START : SERVICE_AUTO_START;
  snapshot->error_control = SERVICE_ERROR_NORMAL;
  snapshot->tag_id = 0;
  snapshot->binary_path = Utf8(launch.command_line);
  snapshot->load_order_group.clear();
  snapshot->dependencies.clear();
  const std::string& sid = role == "bot" ? roles.bot : roles.daemon;
  std::wstring account;
  if (!ResolveWin32ServiceAccountName(sid, &account)) return false;
  snapshot->account_name = Utf8(account);
  snapshot->display_name = name;
  snapshot->description = "gjc-remote:v1:" + application_fingerprint;
  snapshot->delayed_auto_start = false;
  snapshot->failure_reset_period = phase == "final" ? 600 : 0;
  snapshot->failure_reboot_message.clear();
  snapshot->failure_command.clear();
  snapshot->failure_actions.clear();
  if (phase == "final") {
    snapshot->failure_actions = {
      {SC_ACTION_RESTART, 10000},
      {SC_ACTION_RESTART, 10000},
      {SC_ACTION_RESTART, 10000},
      {SC_ACTION_NONE, 0},
    };
  }
  snapshot->failure_actions_on_non_crash = false;
  snapshot->service_sid_type = SERVICE_SID_TYPE_NONE;
  snapshot->required_privileges.clear();
  snapshot->trigger_count = 0;
  snapshot->preshutdown_timeout = 180000;
  snapshot->security_sha256.clear();
  if (!ExpectedWin32ServiceObjectSecurityFingerprint(
          roles, &snapshot->security_sha256)) return false;
  snapshot->acl_matches = true;
  snapshot->account_matches_role = true;
  snapshot->config_fingerprint =
      Win32ServiceConfigFingerprint(handle, *snapshot);
  return ValidServiceFingerprint(snapshot->config_fingerprint) &&
      ValidServiceFingerprint(snapshot->security_sha256);
}

napi_value Win32ServiceResourceDescriptorValue(
    napi_env env, const std::string& name, const std::string& role,
    const Win32ServiceSnapshot& snapshot) {
  napi_value result, dependencies, privileges, actions, null_value;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "name", name);
  ServiceSetString(env, result, "component", role);
  ServiceSetString(env, result, "serviceKey",
      role == "bot" ? "bot" :
          name.substr(std::string("GJCRemoteDaemon-").size()));
  ServiceSetString(env, result, "serviceRole", role);
  ServiceSetUint32(env, result, "serviceType", snapshot.service_type);
  ServiceSetString(env, result, "startType",
                   Win32StartTypeName(snapshot.start_type));
  ServiceSetUint32(env, result, "errorControl", snapshot.error_control);
  ServiceSetUint32(env, result, "tagId", snapshot.tag_id);
  ServiceSetString(env, result, "binaryPath", snapshot.binary_path);
  ServiceSetString(env, result, "loadOrderGroup", snapshot.load_order_group);
  napi_create_array_with_length(env, snapshot.dependencies.size(),
                                &dependencies);
  for (uint32_t index = 0; index < snapshot.dependencies.size(); ++index) {
    napi_value item;
    napi_create_string_utf8(env, snapshot.dependencies[index].c_str(),
        snapshot.dependencies[index].size(), &item);
    napi_set_element(env, dependencies, index, item);
  }
  napi_set_named_property(env, result, "dependencies", dependencies);
  ServiceSetString(env, result, "accountName", snapshot.account_name);
  ServiceSetString(env, result, "displayName", snapshot.display_name);
  ServiceSetString(env, result, "description", snapshot.description);
  ServiceSetBoolean(env, result, "delayedAutoStart",
                    snapshot.delayed_auto_start);
  ServiceSetUint32(env, result, "failureResetPeriod",
                   snapshot.failure_reset_period);
  ServiceSetString(env, result, "failureRebootMessage",
                   snapshot.failure_reboot_message);
  ServiceSetString(env, result, "failureCommand", snapshot.failure_command);
  napi_create_array_with_length(env, snapshot.failure_actions.size(),
                                &actions);
  for (uint32_t index = 0; index < snapshot.failure_actions.size(); ++index) {
    napi_value action;
    napi_create_object(env, &action);
    ServiceSetString(env, action, "type",
        Win32ActionName(snapshot.failure_actions[index].type));
    ServiceSetUint32(env, action, "delayMs",
                     snapshot.failure_actions[index].delay);
    napi_set_element(env, actions, index, action);
  }
  napi_set_named_property(env, result, "failureActions", actions);
  ServiceSetBoolean(env, result, "failureActionsOnNonCrashFailures",
                    snapshot.failure_actions_on_non_crash);
  ServiceSetString(env, result, "failurePolicy",
                   Win32FailurePolicyName(snapshot));
  ServiceSetUint32(env, result, "serviceSidType", snapshot.service_sid_type);
  napi_create_array_with_length(env, snapshot.required_privileges.size(),
                                &privileges);
  for (uint32_t index = 0; index < snapshot.required_privileges.size(); ++index) {
    napi_value item;
    napi_create_string_utf8(env, snapshot.required_privileges[index].c_str(),
        snapshot.required_privileges[index].size(), &item);
    napi_set_element(env, privileges, index, item);
  }
  napi_set_named_property(env, result, "requiredPrivileges", privileges);
  ServiceSetUint32(env, result, "triggerCount", snapshot.trigger_count);
  ServiceSetUint32(env, result, "preshutdownTimeout",
                   snapshot.preshutdown_timeout);
  ServiceSetString(env, result, "securitySha256", snapshot.security_sha256);
  ServiceSetBoolean(env, result, "aclMatches", snapshot.acl_matches);
  ServiceSetBoolean(env, result, "accountMatchesRole",
                    snapshot.account_matches_role);
  ServiceSetString(env, result, "configFingerprint",
                   snapshot.config_fingerprint);
  napi_get_null(env, &null_value);
  napi_set_named_property(env, result, "runtimeFingerprint", null_value);
  return result;
}
#endif

napi_value PlanWin32ServiceResource(napi_env env,
                                    napi_callback_info info) {
#ifdef _WIN32
  napi_value args[6];
  std::string name, role, application_fingerprint, phase;
  InventoryRoles roles{};
  if (!InventoryArgs(env, info, 6, args) ||
      !InventoryString(env, args[0], &name) ||
      !InventoryString(env, args[1], &role) ||
      !ValidWin32ServiceName(name, role) ||
      !InventoryString(env, args[3], &application_fingerprint) ||
      !ValidWin32LaunchHash(application_fingerprint) ||
      !InventoryString(env, args[4], &phase) ||
      (phase != "trial" && phase != "final-auto" && phase != "final") ||
      !InventoryRolesArg(env, args[5], &roles) ||
      !ServiceActorAuthorized(roles)) {
    ServiceError(env, "SERVICE_INVALID", "plan_win32_service_resource");
    return nullptr;
  }
  Win32ServiceLaunch launch;
  Win32ServiceSnapshot snapshot;
  if (!CaptureWin32ServiceLaunch(env, args[2], name, role, roles, &launch) ||
      !BuildWin32PlannedServiceSnapshot(name, role, roles, launch,
          application_fingerprint, phase, &snapshot)) {
    ServiceError(env, "SERVICE_INVALID", "plan_win32_service_resource");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "descriptor",
      Win32ServiceResourceDescriptorValue(env, name, role, snapshot));
  ServiceSetString(env, result, "configFingerprint",
                   snapshot.config_fingerprint);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "plan_win32_service_resource");
  return nullptr;
#endif
}

napi_value CreateWin32ServiceDisabled(napi_env env,
                                      napi_callback_info info) {
#ifdef _WIN32
  napi_value args[5];
  std::string name, role;
  InventoryRoles roles{};
  std::vector<wchar_t> password;
  bool password_present = false;
  if (!InventoryArgs(env, info, 5, args) ||
      !InventoryString(env, args[0], &name) ||
      !InventoryString(env, args[1], &role) ||
      !ValidWin32ServiceName(name, role) ||
      !Win32PasswordArg(env, args[3], &password, &password_present) ||
      !InventoryRolesArg(env, args[4], &roles) ||
      !ServiceActorAuthorized(roles)) {
    if (!password.empty()) {
      SecureZeroMemory(password.data(),
                       password.size() * sizeof(wchar_t));
    }
    ServiceError(env, "SERVICE_INVALID",
                 "create_win32_service_disabled");
    return nullptr;
  }
  const std::string& selected_sid =
      role == "bot" ? roles.bot : roles.daemon;
  std::wstring account;
  if (!ResolveWin32ServiceAccountName(selected_sid, &account)) {
    if (!password.empty()) {
      SecureZeroMemory(password.data(),
                       password.size() * sizeof(wchar_t));
    }
    ServiceError(env, "SERVICE_INVALID",
                 "create_win32_service_disabled");
    return nullptr;
  }
  Win32ServiceLaunch launch;
  if (!CaptureWin32ServiceLaunch(env, args[2], name, role, roles,
                                 &launch)) {
    if (!password.empty()) {
      SecureZeroMemory(password.data(),
                       password.size() * sizeof(wchar_t));
    }
    ServiceError(env, "SERVICE_INVALID",
                 "create_win32_service_disabled");
    return nullptr;
  }
  auto* handle = new Win32ServiceHandle();
  handle->roles = roles;
  handle->service_role = role;
  handle->name = name;
  handle->mutable_access = true;
  handle->created_unmarked = true;
  handle->manager = OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASEW,
      SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
  if (!handle->manager) {
    if (!password.empty()) {
      SecureZeroMemory(password.data(),
                       password.size() * sizeof(wchar_t));
    }
    delete handle;
    ServiceError(env, "SERVICE_ACCESS_DENIED",
                 "create_win32_service_disabled");
    return nullptr;
  }
  const std::wstring wide_name = Wide(name);
  const wchar_t empty_dependencies[] = {L'\0', L'\0'};
  handle->service = CreateServiceW(
      handle->manager, wide_name.c_str(), wide_name.c_str(),
      SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DISABLED,
      SERVICE_ERROR_NORMAL, launch.command_line.c_str(), nullptr, nullptr,
      empty_dependencies, account.c_str(),
      password_present ? password.data() : nullptr);
  if (!password.empty()) {
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
  }
  if (!handle->service) {
    const DWORD error = GetLastError();
    CloseWin32ServiceHandle(handle);
    delete handle;
    ServiceError(env,
        error == ERROR_SERVICE_EXISTS ||
                error == ERROR_DUPLICATE_SERVICE_NAME
            ? "SERVICE_ALREADY_EXISTS" : "SERVICE_ACCESS_DENIED",
        "create_win32_service_disabled");
    return nullptr;
  }
  Win32ServiceSnapshot snapshot;
  const bool exact = QueryWin32ServiceSnapshot(handle, &snapshot) &&
      snapshot.service_type == SERVICE_WIN32_OWN_PROCESS &&
      snapshot.start_type == SERVICE_DISABLED &&
      snapshot.error_control == SERVICE_ERROR_NORMAL &&
      snapshot.binary_path == Utf8(launch.command_line) &&
      snapshot.load_order_group.empty() &&
      snapshot.dependencies.empty() &&
      snapshot.account_matches_role &&
      snapshot.description.empty() &&
      !snapshot.delayed_auto_start &&
      snapshot.failure_actions.empty() &&
      snapshot.failure_reboot_message.empty() &&
      snapshot.failure_command.empty() &&
      !snapshot.failure_actions_on_non_crash &&
      snapshot.trigger_count == 0 &&
      snapshot.state == SERVICE_STOPPED &&
      snapshot.process_id == 0;
  if (!exact) {
    const bool removed = DeleteService(handle->service) != FALSE;
    CloseWin32ServiceHandle(handle);
    delete handle;
    ServiceError(env,
        removed ? "SERVICE_IO_FAILED" : "SERVICE_MANUAL_CLEANUP",
        "create_win32_service_disabled", removed ? 2 : 1, !removed);
    return nullptr;
  }
  napi_value result = WrapWin32ServiceHandle(env, handle);
  if (!result) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "create_win32_service_disabled", 1, true);
    return nullptr;
  }
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "create_win32_service_disabled");
  return nullptr;
#endif
}

napi_value ProtectWin32Service(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  napi_value args[4];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime, marker;
  if (!InventoryArgs(env, info, 4, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !InventoryString(env, args[3], &marker) ||
      !handle->mutable_access || !handle->created_unmarked ||
      !ValidWin32ServiceMarker(marker)) {
    ServiceError(env, "SERVICE_INVALID", "protect_win32_service");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, false, &before) ||
      before.start_type != SERVICE_DISABLED ||
      before.state != SERVICE_STOPPED || !before.description.empty()) {
    ServiceError(env, "SERVICE_STALE", "protect_win32_service",
                 0, true);
    return nullptr;
  }
  if (!ApplyWin32ServiceObjectAcl(handle->service, handle->roles)) {
    ReportWin32MutationFailure(
        env, "protect_win32_service", handle, before);
    return nullptr;
  }
  const std::wstring wide_marker = Wide(marker);
  SERVICE_DESCRIPTIONW description{
    const_cast<LPWSTR>(wide_marker.c_str()),
  };
  if (!ChangeServiceConfig2W(handle->service,
          SERVICE_CONFIG_DESCRIPTION, &description)) {
    ReportWin32MutationFailure(
        env, "protect_win32_service", handle, before);
    return nullptr;
  }
  Win32ServiceSnapshot after;
  if (!QueryWin32ServiceSnapshot(handle, &after) ||
      !after.acl_matches || after.description != marker ||
      after.start_type != SERVICE_DISABLED ||
      after.state != SERVICE_STOPPED) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "protect_win32_service", 2, true);
    return nullptr;
  }
  handle->created_unmarked = false;
  napi_value result = Win32ServiceSnapshotValue(env, *handle, after);
  ServiceSetUint32(env, result, "writes", 2);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "protect_win32_service");
  return nullptr;
#endif
}

napi_value SetWin32ServiceMarker(napi_env env,
                                 napi_callback_info info) {
#ifdef _WIN32
  napi_value args[4];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime, marker;
  if (!InventoryArgs(env, info, 4, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !InventoryString(env, args[3], &marker) ||
      !handle->mutable_access || !ValidWin32ServiceMarker(marker)) {
    ServiceError(env, "SERVICE_INVALID", "set_win32_service_marker");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, true, &before)) {
    ServiceError(env, "SERVICE_STALE",
                 "set_win32_service_marker", 0, true);
    return nullptr;
  }
  const std::wstring wide_marker = Wide(marker);
  SERVICE_DESCRIPTIONW description{
    const_cast<LPWSTR>(wide_marker.c_str()),
  };
  if (!ChangeServiceConfig2W(handle->service,
          SERVICE_CONFIG_DESCRIPTION, &description)) {
    ReportWin32MutationFailure(
        env, "set_win32_service_marker", handle, before);
    return nullptr;
  }
  Win32ServiceSnapshot after;
  if (!QueryWin32ServiceSnapshot(handle, &after) ||
      !after.acl_matches || after.description != marker) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "set_win32_service_marker", 1, true);
    return nullptr;
  }
  napi_value result = Win32ServiceSnapshotValue(env, *handle, after);
  ServiceSetUint32(env, result, "writes", 1);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "set_win32_service_marker");
  return nullptr;
#endif
}

napi_value ConfigureWin32ServiceLaunch(napi_env env,
                                       napi_callback_info info) {
#ifdef _WIN32
  napi_value args[4];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime;
  if (!InventoryArgs(env, info, 4, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !handle->mutable_access) {
    ServiceError(env, "SERVICE_INVALID",
                 "configure_win32_service_launch");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, true, &before) ||
      before.state != SERVICE_STOPPED ||
      (before.start_type != SERVICE_DISABLED &&
       before.start_type != SERVICE_DEMAND_START)) {
    ServiceError(env, "SERVICE_STALE",
                 "configure_win32_service_launch", 0, true);
    return nullptr;
  }
  Win32ServiceLaunch launch;
  if (!CaptureWin32ServiceLaunch(env, args[3], handle->name,
          handle->service_role, handle->roles, &launch)) {
    ServiceError(env, "SERVICE_INVALID",
                 "configure_win32_service_launch");
    return nullptr;
  }
  if (!ChangeServiceConfigW(handle->service, SERVICE_NO_CHANGE,
          SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
          launch.command_line.c_str(), nullptr, nullptr, nullptr,
          nullptr, nullptr, nullptr)) {
    ReportWin32MutationFailure(
        env, "configure_win32_service_launch", handle, before);
    return nullptr;
  }
  Win32ServiceSnapshot after;
  if (!QueryWin32ServiceSnapshot(handle, &after) ||
      !after.acl_matches ||
      !ValidWin32ServiceMarker(after.description) ||
      after.binary_path != Utf8(launch.command_line) ||
      !after.account_matches_role ||
      after.state != SERVICE_STOPPED ||
      after.start_type != before.start_type) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "configure_win32_service_launch", 1, true);
    return nullptr;
  }
  napi_value result = Win32ServiceSnapshotValue(env, *handle, after);
  ServiceSetUint32(env, result, "writes", 1);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "configure_win32_service_launch");
  return nullptr;
#endif
}

napi_value SetWin32ServiceStartType(napi_env env,
                                    napi_callback_info info) {
#ifdef _WIN32
  napi_value args[4];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime, type;
  if (!InventoryArgs(env, info, 4, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !InventoryString(env, args[3], &type) ||
      !handle->mutable_access ||
      (type != "disabled" && type != "demand" && type != "auto")) {
    ServiceError(env, "SERVICE_INVALID",
                 "set_win32_service_start_type");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, true, &before)) {
    ServiceError(env, "SERVICE_STALE",
                 "set_win32_service_start_type", 0, true);
    return nullptr;
  }
  const DWORD start_type = type == "disabled" ? SERVICE_DISABLED :
      type == "demand" ? SERVICE_DEMAND_START : SERVICE_AUTO_START;
  if (!ChangeServiceConfigW(handle->service, SERVICE_NO_CHANGE,
          start_type, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
          nullptr, nullptr, nullptr, nullptr)) {
    ReportWin32MutationFailure(
        env, "set_win32_service_start_type", handle, before);
    return nullptr;
  }
  Win32ServiceSnapshot after;
  if (!QueryWin32ServiceSnapshot(handle, &after) ||
      !after.acl_matches ||
      !ValidWin32ServiceMarker(after.description) ||
      after.start_type != start_type ||
      after.binary_path != before.binary_path ||
      !after.account_matches_role) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "set_win32_service_start_type", 1, true);
    return nullptr;
  }
  napi_value result = Win32ServiceSnapshotValue(env, *handle, after);
  ServiceSetUint32(env, result, "writes", 1);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "set_win32_service_start_type");
  return nullptr;
#endif
}

napi_value SetWin32ServiceFailureActions(napi_env env,
                                         napi_callback_info info) {
#ifdef _WIN32
  napi_value args[4];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime, policy;
  if (!InventoryArgs(env, info, 4, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !InventoryString(env, args[3], &policy) ||
      !handle->mutable_access ||
      (policy != "none" && policy != "restart-3x-10s")) {
    ServiceError(env, "SERVICE_INVALID",
                 "set_win32_service_failure_actions");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, true, &before)) {
    ServiceError(env, "SERVICE_STALE",
                 "set_win32_service_failure_actions", 0, true);
    return nullptr;
  }
  wchar_t empty[] = L"";
  SC_ACTION actions[4] = {
    {SC_ACTION_RESTART, 10000},
    {SC_ACTION_RESTART, 10000},
    {SC_ACTION_RESTART, 10000},
    {SC_ACTION_NONE, 0},
  };
  SERVICE_FAILURE_ACTIONSW configuration{};
  configuration.dwResetPeriod =
      policy == "none" ? 0 : 600;
  configuration.lpRebootMsg = empty;
  configuration.lpCommand = empty;
  configuration.cActions = policy == "none" ? 0 : 4;
  configuration.lpsaActions =
      policy == "none" ? nullptr : actions;
  if (!ChangeServiceConfig2W(handle->service,
          SERVICE_CONFIG_FAILURE_ACTIONS, &configuration)) {
    ReportWin32MutationFailure(
        env, "set_win32_service_failure_actions", handle, before);
    return nullptr;
  }
  Win32ServiceSnapshot after;
  if (!QueryWin32ServiceSnapshot(handle, &after) ||
      !after.acl_matches ||
      !ValidWin32ServiceMarker(after.description) ||
      std::string(Win32FailurePolicyName(after)) != policy ||
      after.failure_actions_on_non_crash !=
          before.failure_actions_on_non_crash) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "set_win32_service_failure_actions", 1, true);
    return nullptr;
  }
  napi_value result = Win32ServiceSnapshotValue(env, *handle, after);
  ServiceSetUint32(env, result, "writes", 1);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "set_win32_service_failure_actions");
  return nullptr;
#endif
}

napi_value SetWin32ServiceFailureActionsFlag(
    napi_env env, napi_callback_info info) {
#ifdef _WIN32
  napi_value args[4];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime;
  bool enabled = false;
  if (!InventoryArgs(env, info, 4, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !Win32Boolean(env, args[3], &enabled) ||
      enabled || !handle->mutable_access) {
    ServiceError(env, "SERVICE_INVALID",
                 "set_win32_service_failure_actions_flag");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, true, &before)) {
    ServiceError(env, "SERVICE_STALE",
                 "set_win32_service_failure_actions_flag", 0, true);
    return nullptr;
  }
  SERVICE_FAILURE_ACTIONS_FLAG flag{
    enabled ? TRUE : FALSE,
  };
  if (!ChangeServiceConfig2W(handle->service,
          SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag)) {
    ReportWin32MutationFailure(
        env, "set_win32_service_failure_actions_flag", handle, before);
    return nullptr;
  }
  Win32ServiceSnapshot after;
  if (!QueryWin32ServiceSnapshot(handle, &after) ||
      !after.acl_matches ||
      !ValidWin32ServiceMarker(after.description) ||
      after.failure_actions_on_non_crash != enabled) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "set_win32_service_failure_actions_flag", 1, true);
    return nullptr;
  }
  napi_value result = Win32ServiceSnapshotValue(env, *handle, after);
  ServiceSetUint32(env, result, "writes", 1);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "set_win32_service_failure_actions_flag");
  return nullptr;
#endif
}

napi_value StartWin32Service(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  napi_value args[3];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime;
  if (!InventoryArgs(env, info, 3, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !handle->mutable_access) {
    ServiceError(env, "SERVICE_INVALID", "start_win32_service");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, true, &before) ||
      before.start_type != SERVICE_DEMAND_START ||
      before.state != SERVICE_STOPPED || before.process_id != 0 ||
      before.delayed_auto_start ||
      std::string(Win32FailurePolicyName(before)) != "none" ||
      before.failure_actions_on_non_crash ||
      before.trigger_count != 0) {
    ServiceError(env, "SERVICE_STALE",
                 "start_win32_service", 0, true);
    return nullptr;
  }
  if (!StartServiceW(handle->service, 0, nullptr)) {
    ReportWin32MutationFailure(
        env, "start_win32_service", handle, before);
    return nullptr;
  }
  Win32ServiceSnapshot after;
  if (!QueryWin32ServiceSnapshot(handle, &after) ||
      !after.acl_matches ||
      !ValidWin32ServiceMarker(after.description) ||
      after.config_fingerprint != before.config_fingerprint ||
      (after.state != SERVICE_START_PENDING &&
       !(after.state == SERVICE_RUNNING && after.process_id != 0))) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "start_win32_service", 1, true);
    return nullptr;
  }
  napi_value result = Win32ServiceSnapshotValue(env, *handle, after);
  ServiceSetBoolean(env, result, "startRequested", true);
  ServiceSetUint32(env, result, "writes", 1);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "start_win32_service");
  return nullptr;
#endif
}

napi_value StopWin32Service(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  napi_value args[3];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime;
  if (!InventoryArgs(env, info, 3, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !handle->mutable_access) {
    ServiceError(env, "SERVICE_INVALID", "stop_win32_service");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, true, &before)) {
    ServiceError(env, "SERVICE_STALE",
                 "stop_win32_service", 0, true);
    return nullptr;
  }
  uint32_t writes = 0;
  if (before.state != SERVICE_STOPPED &&
      before.state != SERVICE_STOP_PENDING) {
    SERVICE_STATUS status{};
    const BOOL stopped =
        ControlService(handle->service, SERVICE_CONTROL_STOP, &status);
    if (!stopped && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
      ReportWin32MutationFailure(
          env, "stop_win32_service", handle, before);
      return nullptr;
    }
    if (stopped) writes = 1;
  }
  Win32ServiceSnapshot after;
  if (!QueryWin32ServiceSnapshot(handle, &after) ||
      !after.acl_matches ||
      !ValidWin32ServiceMarker(after.description) ||
      (after.state != SERVICE_STOP_PENDING &&
       after.state != SERVICE_STOPPED)) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "stop_win32_service", writes, true);
    return nullptr;
  }
  napi_value result = Win32ServiceSnapshotValue(env, *handle, after);
  ServiceSetUint32(env, result, "writes", writes);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "stop_win32_service");
  return nullptr;
#endif
}

napi_value DeleteWin32Service(napi_env env, napi_callback_info info) {
#ifdef _WIN32
  napi_value args[3];
  Win32ServiceHandle* handle = nullptr;
  std::string expected_config, expected_runtime;
  if (!InventoryArgs(env, info, 3, args) ||
      !Win32ServiceHandleArg(env, args[0], &handle) ||
      !InventoryString(env, args[1], &expected_config) ||
      !InventoryString(env, args[2], &expected_runtime) ||
      !handle->mutable_access) {
    ServiceError(env, "SERVICE_INVALID", "delete_win32_service");
    return nullptr;
  }
  Win32ServiceSnapshot before;
  if (!ExpectedWin32ServiceSnapshot(handle, expected_config,
          expected_runtime, true, &before) ||
      before.state != SERVICE_STOPPED || before.process_id != 0) {
    ServiceError(env, "SERVICE_STALE",
                 "delete_win32_service", 0, true);
    return nullptr;
  }
  if (!DeleteService(handle->service)) {
    ReportWin32MutationFailure(
        env, "delete_win32_service", handle, before);
    return nullptr;
  }
  CloseWin32ServiceHandle(handle);
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetBoolean(env, result, "deletionPending", true);
  ServiceSetUint32(env, result, "writes", 1);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED", "delete_win32_service");
  return nullptr;
#endif
}

napi_value TerminateWin32ServiceTree(napi_env env,
                                     napi_callback_info info) {
#ifdef _WIN32
  napi_value args[7];
  Win32ServiceHandle* service = nullptr;
  uint32_t root_pid = 0;
  std::string expected_config, root_start, root_executable, root_owner,
      expected_tree;
  if (!InventoryArgs(env, info, 7, args) ||
      !Win32ServiceHandleArg(env, args[0], &service) ||
      !InventoryString(env, args[1], &expected_config) ||
      !ServiceUint32(env, args[2], &root_pid, 1, 0x7fffffffu) ||
      !InventoryString(env, args[3], &root_start) ||
      !InventoryString(env, args[4], &root_executable) ||
      !InventoryString(env, args[5], &root_owner) ||
      !InventoryString(env, args[6], &expected_tree) ||
      !ValidServiceFingerprint(expected_config) ||
      !ValidServiceFingerprint(expected_tree) ||
      !service->mutable_access ||
      !Win32PathHasLeaf(root_executable, "shawl.exe")) {
    ServiceError(env, "SERVICE_INVALID",
                 "terminate_win32_service_tree");
    return nullptr;
  }
  Win32ServiceSnapshot service_snapshot;
  if (!QueryWin32ServiceSnapshot(service, &service_snapshot) ||
      service_snapshot.config_fingerprint != expected_config ||
      !service_snapshot.acl_matches ||
      !service_snapshot.account_matches_role ||
      !ValidWin32ServiceMarker(service_snapshot.description) ||
      service_snapshot.process_id != root_pid ||
      root_owner != (service->service_role == "bot"
          ? service->roles.bot : service->roles.daemon)) {
    ServiceError(env, "SERVICE_STALE",
                 "terminate_win32_service_tree", 0, true);
    return nullptr;
  }
  if (root_pid == GetCurrentProcessId()) {
    ServiceError(env, "SERVICE_ACCESS_DENIED",
                 "terminate_win32_service_tree");
    return nullptr;
  }
  std::vector<ServiceProcessFacts> processes;
  std::string fingerprint;
  gServiceTreeOverflow = false;
  if (!StableServiceProcessTree(root_pid, root_start, root_executable,
          root_owner, &processes, &fingerprint) ||
      fingerprint != expected_tree) {
    ServiceError(env,
        gServiceTreeOverflow ? "SERVICE_TREE_OVERFLOW" : "SERVICE_STALE",
                 "terminate_win32_service_tree", 0, true);
    return nullptr;
  }
  struct RetainedProcess {
    HANDLE handle = nullptr;
    ServiceProcessFacts facts;
  };
  std::vector<RetainedProcess> retained;
  for (const auto& process : processes) {
    HANDLE retained_handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE |
            SYNCHRONIZE, FALSE, process.pid);
    ServiceProcessFacts current;
    if (!retained_handle ||
        ReadServiceProcessFacts(process.pid, &current, nullptr,
                                retained_handle) != ProcessReadResult::Ok ||
        current.start_time != process.start_time ||
        current.executable != process.executable ||
        current.owner != process.owner) {
      if (retained_handle) CloseHandle(retained_handle);
      for (const auto& value : retained) CloseHandle(value.handle);
      ServiceError(env, "SERVICE_STALE",
                   "terminate_win32_service_tree", 0, true);
      return nullptr;
    }
    retained.push_back({retained_handle, process});
  }
  std::vector<ServiceProcessFacts> final_processes;
  std::string final_fingerprint;
  if (!StableServiceProcessTree(root_pid, root_start, root_executable,
          root_owner, &final_processes, &final_fingerprint) ||
      final_fingerprint != fingerprint) {
    for (const auto& value : retained) CloseHandle(value.handle);
    ServiceError(env,
        gServiceTreeOverflow ? "SERVICE_TREE_OVERFLOW" : "SERVICE_STALE",
                 "terminate_win32_service_tree", 0, true);
    return nullptr;
  }
  std::sort(retained.begin(), retained.end(),
      [](const RetainedProcess& left, const RetainedProcess& right) {
        return left.facts.depth != right.facts.depth
            ? left.facts.depth > right.facts.depth
            : left.facts.pid > right.facts.pid;
      });
  uint32_t writes = 0;
  for (const auto& process : retained) {
    if (!TerminateProcess(process.handle, ERROR_PROCESS_ABORTED)) {
      if (WaitForSingleObject(process.handle, 0) != WAIT_OBJECT_0) {
        for (const auto& value : retained) CloseHandle(value.handle);
        ServiceError(env, "SERVICE_TREE_SURVIVOR",
                     "terminate_win32_service_tree", writes, true);
        return nullptr;
      }
    } else {
      ++writes;
    }
  }
  const auto deadline = std::chrono::steady_clock::now() +
      std::chrono::seconds(2);
  bool all_stopped = true;
  for (const auto& process : retained) {
    const auto remaining = deadline - std::chrono::steady_clock::now();
    const auto milliseconds = std::chrono::duration_cast<
        std::chrono::milliseconds>(remaining).count();
    if (milliseconds < 0 ||
        WaitForSingleObject(process.handle,
            static_cast<DWORD>(std::min<int64_t>(
                milliseconds, std::numeric_limits<DWORD>::max()))) !=
            WAIT_OBJECT_0) {
      all_stopped = false;
    }
    CloseHandle(process.handle);
  }
  if (!all_stopped) {
    ServiceError(env, "SERVICE_TREE_SURVIVOR",
                 "terminate_win32_service_tree", writes, true);
    return nullptr;
  }
  ServiceProcessFacts root_after;
  if (ReadServiceProcessFacts(root_pid, &root_after) !=
      ProcessReadResult::Absent) {
    ServiceError(env, "SERVICE_TREE_SURVIVOR",
                 "terminate_win32_service_tree", writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "tree", "empty");
  ServiceSetBoolean(env, result, "forced", true);
  ServiceSetUint32(env, result, "terminated",
                   static_cast<uint32_t>(processes.size()));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "terminate_win32_service_tree");
  return nullptr;
#endif
}

// Retained, service-only filesystem capabilities. These handles deliberately
// cannot be constructed from an arbitrary path: roots are resolved here to the
// four fixed lifecycle namespaces, and every descendant keeps its parent/root
// live while binding the exact five-role tuple and physical identities.
enum class ServiceStoreHandleKind {
  Root, Directory, Lock, LinuxScope,
  ArtifactWriter, ArtifactReader, ArtifactSourceReader, ExternalRoot,
};
enum class ServiceStoreAccess { Read, Write };

struct ServiceStoreIdentity {
  ServiceAclProfile profile = ServiceAclProfile::ControlFile;
  std::string owner;
  std::string security_sha256;
#ifdef _WIN32
  std::string volume_serial;
  std::string file_id;
  uint32_t attributes = 0;
#else
  uint64_t device = 0;
  uint64_t inode = 0;
  uint32_t mode = 0;
#endif
};

const char* ServiceProfileText(ServiceAclProfile profile) {
  switch (profile) {
    case ServiceAclProfile::ControlDirectory:
      return "service-control-directory";
    case ServiceAclProfile::ControlFile:
      return "service-control-file";
    case ServiceAclProfile::StagingDirectory:
      return "service-staging-directory";
    case ServiceAclProfile::StagingFile:
      return "service-staging-file";
    case ServiceAclProfile::ReleaseDirectory:
      return "service-release-directory";
    case ServiceAclProfile::ReleaseFile:
      return "service-release-file";
    case ServiceAclProfile::ReleaseExecutable:
      return "service-release-executable";
    case ServiceAclProfile::BotLogDirectory:
      return "service-bot-log-directory";
    case ServiceAclProfile::DaemonLogDirectory:
      return "service-daemon-log-directory";
    case ServiceAclProfile::InternalContainerDirectory:
      return "service-internal-container-directory";
    case ServiceAclProfile::PreservedContainerDirectory:
      return "service-preserved-container-directory";
    case ServiceAclProfile::ExternalAnchorDirectory:
      return "service-external-anchor-directory";
    case ServiceAclProfile::BotConfigDirectory:
      return "service-bot-config-directory";
    case ServiceAclProfile::BotConfigFile:
      return "service-bot-config-file";
    case ServiceAclProfile::DaemonConfigDirectory:
      return "service-daemon-config-directory";
    case ServiceAclProfile::DaemonConfigFile:
      return "service-daemon-config-file";
    case ServiceAclProfile::SdkInstallDirectory:
      return "service-sdk-install-directory";
    case ServiceAclProfile::SdkInstallFile:
      return "service-sdk-install-file";
    case ServiceAclProfile::BotRetainedDirectory:
      return "service-bot-retained-directory";
    case ServiceAclProfile::BotRetainedFile:
      return "service-bot-retained-file";
    case ServiceAclProfile::DaemonRetainedDirectory:
      return "service-daemon-retained-directory";
    case ServiceAclProfile::DaemonRetainedFile:
      return "service-daemon-retained-file";
  }
  return "";
}

std::string ServiceStoreIdentityText(const ServiceStoreIdentity& identity) {
  std::ostringstream result;
  result << ServiceProfileText(identity.profile) << ":";
#ifdef _WIN32
  result << identity.volume_serial << ":" << identity.file_id << ":"
         << identity.attributes;
#else
  result << identity.device << ":" << identity.inode << ":"
         << identity.mode;
#endif
  result << ":" << identity.owner << ":" << identity.security_sha256;
  return result.str();
}

bool SameServiceStoreIdentity(const ServiceStoreIdentity& left,
                              const ServiceStoreIdentity& right) {
  return ServiceStoreIdentityText(left) == ServiceStoreIdentityText(right);
}

bool ParseServiceUnsignedDecimal(const std::string& text,
                                 uint64_t* result) {
  if (text.empty() ||
      (text.size() > 1 && text.front() == '0') ||
      text.find_first_not_of("0123456789") != std::string::npos) {
    return false;
  }
  errno = 0;
  char* end = nullptr;
  const unsigned long long parsed =
      std::strtoull(text.c_str(), &end, 10);
  if (errno != 0 || !end || *end != '\0') return false;
  *result = static_cast<uint64_t>(parsed);
  return true;
}

bool CaptureServiceStoreIdentity(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    const InventoryRoles& roles, ServiceAclProfile profile,
    ServiceStoreIdentity* identity) {
  if (ServiceProfileExternal(profile)) return false;
#ifdef _WIN32
  if (handle == INVALID_HANDLE_VALUE ||
      !VerifyWindowsServiceFileAcl(handle, roles, profile) ||
      !InventoryIdentity(handle, &identity->volume_serial,
                         &identity->file_id, &identity->attributes,
                         &identity->owner) ||
      !ServiceSecurityFingerprint(handle,
                                  &identity->security_sha256)) {
    return false;
  }
#else
  struct stat metadata{};
  if (handle < 0 || fstat(handle, &metadata) != 0 ||
      !BuildPosixServiceAcl(handle, roles, profile, false) ||
      !ServiceSecurityFingerprint(handle,
                                  &identity->security_sha256)) {
    return false;
  }
  identity->device = static_cast<uint64_t>(metadata.st_dev);
  identity->inode = static_cast<uint64_t>(metadata.st_ino);
  identity->mode = static_cast<uint32_t>(metadata.st_mode);
  identity->owner = "uid:" + std::to_string(metadata.st_uid);
#endif
  identity->profile = profile;
  return ValidServiceFingerprint(identity->security_sha256);
}

napi_value ServiceStoreIdentityValue(napi_env env,
                                     const ServiceStoreIdentity& identity) {
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "profile",
                   ServiceProfileText(identity.profile));
#ifdef _WIN32
  ServiceSetString(env, result, "kind", "win32-service-object-v1");
  ServiceSetString(env, result, "volumeSerial", identity.volume_serial);
  ServiceSetString(env, result, "fileId", identity.file_id);
  ServiceSetUint32(env, result, "attributes", identity.attributes);
#else
  ServiceSetString(env, result, "kind", "linux-service-object-v1");
  ServiceSetString(env, result, "device",
                   std::to_string(identity.device));
  ServiceSetString(env, result, "inode",
                   std::to_string(identity.inode));
  ServiceSetUint32(env, result, "mode", identity.mode);
#endif
  ServiceSetString(env, result, "owner", identity.owner);
  ServiceSetString(env, result, "securitySha256",
                   identity.security_sha256);
  return result;
}

bool ServiceStoreIdentityArg(napi_env env, napi_value value,
                             ServiceStoreIdentity* identity) {
#ifdef _WIN32
  const char* fields[] = {
    "profile", "kind", "volumeSerial", "fileId", "attributes",
    "owner", "securitySha256",
  };
  napi_value captured[7];
  std::string profile, kind;
  if (!InventoryOrdinaryDataObject(env, value, fields, 7, captured) ||
      !InventoryString(env, captured[0], &profile) ||
      !InventoryString(env, captured[1], &kind) ||
      !InventoryString(env, captured[2], &identity->volume_serial) ||
      !InventoryString(env, captured[3], &identity->file_id) ||
      !InventoryUint32(env, captured[4], &identity->attributes) ||
      !InventoryString(env, captured[5], &identity->owner) ||
      !InventoryString(env, captured[6], &identity->security_sha256) ||
      kind != "win32-service-object-v1") {
    return false;
  }
#else
  const char* fields[] = {
    "profile", "kind", "device", "inode", "mode", "owner",
    "securitySha256",
  };
  napi_value captured[7];
  std::string profile, kind, device, inode;
  if (!InventoryOrdinaryDataObject(env, value, fields, 7, captured) ||
      !InventoryString(env, captured[0], &profile) ||
      !InventoryString(env, captured[1], &kind) ||
      !InventoryString(env, captured[2], &device) ||
      !InventoryString(env, captured[3], &inode) ||
      !InventoryUint32(env, captured[4], &identity->mode) ||
      !InventoryString(env, captured[5], &identity->owner) ||
      !InventoryString(env, captured[6], &identity->security_sha256) ||
      kind != "linux-service-object-v1" ||
      !ParseServiceUnsignedDecimal(device, &identity->device) ||
      !ParseServiceUnsignedDecimal(inode, &identity->inode)) {
    return false;
  }
#endif
  return ParseServiceAclProfile(profile, &identity->profile) &&
      !ServiceProfileExternal(identity->profile) &&
      ValidServiceFingerprint(identity->security_sha256);
}

bool ServiceStoreNull(napi_env env, napi_value value) {
  napi_valuetype type;
  return napi_typeof(env, value, &type) == napi_ok && type == napi_null;
}

bool ServiceStoreRolesFingerprint(const InventoryRoles& roles,
                                  std::string* result) {
  Sha256 hash;
  if (!hash.Ready()) return false;
  HashField(&hash, "gjc-remote/service-roles/v1");
#ifdef _WIN32
  HashField(&hash, roles.management);
  HashField(&hash, roles.bot);
  HashField(&hash, roles.recovery);
  HashField(&hash, roles.daemon);
  HashField(&hash, roles.system);
#else
  HashField(&hash, "uid:" + std::to_string(roles.management));
  HashField(&hash, "uid:" + std::to_string(roles.bot));
  HashField(&hash, "uid:" + std::to_string(roles.recovery));
  HashField(&hash, "uid:" + std::to_string(roles.daemon));
  HashField(&hash, "uid:" + std::to_string(roles.system));
#endif
  *result = hash.Finish();
  return ValidServiceFingerprint(*result);
}

struct ServiceStoreHandle {
  napi_env env = nullptr;
  ServiceStoreHandleKind kind = ServiceStoreHandleKind::Directory;
  ServiceStoreAccess access = ServiceStoreAccess::Read;
  bool closed = false;
  bool exclusive = false;
  bool lock_held = false;
  bool poisoned = false;
  bool completed = false;
  uint32_t children = 0;
  int lock_rank = 0;
  uint64_t stream_offset = 0;
  uint64_t stream_limit = 0;
  std::string root_kind;
  std::string root_path;
  std::string root_nonce;
  std::string roles_fingerprint;
  std::string binding_fingerprint;
  std::string scope;
  std::string service_key;
  std::string name;
  std::string namespace_name;
  std::string bound_service_key;
  std::string witness_name;
  std::string witness_bytes;
  std::string fixed_parent_path;
  std::string expected_sha256;
  std::string stream_state;
  std::string external_profile;
  ServiceExternalAclPolicy external_policy =
      ServiceExternalAclPolicy::Unresolved;
  std::string external_absolute_path;
  bool external_root_absent = false;
  std::vector<std::string> external_missing_segments;
  uint64_t external_observed_entries = 0;
  uint64_t external_observed_name_bytes = 0;
  InventoryRoles roles{};
  ServiceAclProfile profile = ServiceAclProfile::ControlDirectory;
  ServiceStoreIdentity identity{};
  ServiceStoreIdentity binding_parent_identity{};
  ServiceStoreIdentity witness_identity{};
  std::map<std::string, ServiceStoreIdentity> directory_identities;
  ServiceStoreHandle* parent = nullptr;
  ServiceStoreHandle* root = nullptr;
  ServiceStoreHandle* lock = nullptr;
  napi_ref parent_ref = nullptr;
  napi_ref root_ref = nullptr;
  napi_ref lock_ref = nullptr;
  std::unique_ptr<Sha256> stream_hash;
  std::vector<std::string> external_components;
  std::vector<ServiceStoreIdentity> external_ancestor_identities;
#ifdef _WIN32
  std::vector<HANDLE> external_ancestors;
#else
  std::vector<int> external_ancestors;
#endif
#ifdef _WIN32
  HANDLE object = INVALID_HANDLE_VALUE;
  HANDLE binding_parent = INVALID_HANDLE_VALUE;
  OVERLAPPED lock_overlap{};
#else
  int object = -1;
  int binding_parent = -1;
#endif
};

const napi_type_tag kServiceStoreHandleTypeTag = {
  0x5365727669636553ULL, 0x746f7265486e6434ULL,
};
thread_local std::vector<ServiceStoreHandle*> gServiceStoreLocks;
#ifdef __linux__
bool VerifyLinuxTrustedSystemdDirectory(int directory);
#endif
bool RevalidateServiceArtifactStream(ServiceStoreHandle* handle);
bool RevalidateServiceExternalRoot(ServiceStoreHandle* handle);

bool ServiceStoreNativeHandleOpen(const ServiceStoreHandle* handle) {
#ifdef _WIN32
  return handle && !handle->closed &&
      handle->object != INVALID_HANDLE_VALUE;
#else
  return handle && !handle->closed && handle->object >= 0;
#endif
}

void ReleaseServiceStoreReferences(ServiceStoreHandle* handle) {
  if (handle->parent) {
    if (handle->parent->children > 0) --handle->parent->children;
    handle->parent = nullptr;
  }
  if (handle->parent_ref) {
    napi_delete_reference(handle->env, handle->parent_ref);
    handle->parent_ref = nullptr;
  }
  if (handle->root_ref) {
    napi_delete_reference(handle->env, handle->root_ref);
    handle->root_ref = nullptr;
  }
  if (handle->lock) {
    if (handle->lock->children > 0) --handle->lock->children;
    handle->lock = nullptr;
  }
  if (handle->lock_ref) {
    napi_delete_reference(handle->env, handle->lock_ref);
    handle->lock_ref = nullptr;
  }
}

bool CloseServiceStoreNative(ServiceStoreHandle* handle,
                             bool finalizing = false) {
  if (!handle || handle->closed) return true;
  if (!finalizing && handle->children != 0) return false;
  bool released = true;
  if (handle->kind == ServiceStoreHandleKind::Lock &&
      handle->lock_held) {
#ifdef _WIN32
    released = UnlockFileEx(handle->object, 0, MAXDWORD, MAXDWORD,
                            &handle->lock_overlap) != FALSE;
#else
    released = flock(handle->object, LOCK_UN) == 0;
#endif
    handle->lock_held = false;
    const auto found = std::find(gServiceStoreLocks.begin(),
                                 gServiceStoreLocks.end(), handle);
    if (found != gServiceStoreLocks.end()) {
      gServiceStoreLocks.erase(found);
    }
  }
#ifdef _WIN32
  for (HANDLE ancestor : handle->external_ancestors) {
    if (ancestor != INVALID_HANDLE_VALUE) {
      released = CloseHandle(ancestor) != FALSE && released;
    }
  }
  handle->external_ancestors.clear();
  if (handle->object != INVALID_HANDLE_VALUE) {
    released = CloseHandle(handle->object) != FALSE && released;
    handle->object = INVALID_HANDLE_VALUE;
  }
  if (handle->binding_parent != INVALID_HANDLE_VALUE) {
    released = CloseHandle(handle->binding_parent) != FALSE && released;
    handle->binding_parent = INVALID_HANDLE_VALUE;
  }
#else
  for (int ancestor : handle->external_ancestors) {
    if (ancestor >= 0) released = close(ancestor) == 0 && released;
  }
  handle->external_ancestors.clear();
  if (handle->object >= 0) {
    released = close(handle->object) == 0 && released;
    handle->object = -1;
  }
  if (handle->binding_parent >= 0) {
    released = close(handle->binding_parent) == 0 && released;
    handle->binding_parent = -1;
  }
#endif
  handle->closed = true;
  ReleaseServiceStoreReferences(handle);
  return released;
}

void FinalizeServiceStoreHandle(napi_env, void* raw, void*) {
  auto* handle = static_cast<ServiceStoreHandle*>(raw);
  CloseServiceStoreNative(handle, true);
  delete handle;
}

bool ServiceStoreHandleArg(napi_env env, napi_value value,
                           ServiceStoreHandle** handle,
                           bool require_open = true) {
  bool tagged = false;
  void* raw = nullptr;
  if (napi_check_object_type_tag(env, value,
          &kServiceStoreHandleTypeTag, &tagged) != napi_ok ||
      !tagged || napi_unwrap(env, value, &raw) != napi_ok || !raw) {
    return false;
  }
  *handle = static_cast<ServiceStoreHandle*>(raw);
  return !require_open || ServiceStoreNativeHandleOpen(*handle);
}

napi_value WrapServiceStoreHandle(napi_env env,
                                  ServiceStoreHandle* handle) {
  napi_value object;
  if (napi_create_object(env, &object) != napi_ok ||
      napi_type_tag_object(env, object,
                           &kServiceStoreHandleTypeTag) != napi_ok ||
      napi_wrap(env, object, handle, FinalizeServiceStoreHandle,
                nullptr, nullptr) != napi_ok) {
    CloseServiceStoreNative(handle, true);
    delete handle;
    return nullptr;
  }
  return object;
}

bool ValidServiceStoreComponent(const std::string& name) {
  if (name.empty() || name.size() > 255 || !SafeName(name) ||
      name.rfind(".gjc-service-", 0) == 0) {
    return false;
  }
  for (unsigned char character : name) {
    if (character < 0x20 || character == 0x7f) return false;
  }
#ifdef _WIN32
  return SafeWideName(Wide(name));
#else
  return true;
#endif
}

bool ValidServiceRelativePath(const std::string& path,
                              std::vector<std::string>* components) {
  if (path.empty() || path.size() > 4096 ||
      path.find('\\') != std::string::npos ||
      path.front() == '/' || path.back() == '/') return false;
  components->clear();
  size_t start = 0;
  while (start < path.size()) {
    const size_t end = path.find('/', start);
    const std::string component = path.substr(
        start, end == std::string::npos ? std::string::npos : end - start);
    if (!ValidServiceStoreComponent(component) ||
        components->size() >= 64) {
      components->clear();
      return false;
    }
    components->push_back(component);
    if (end == std::string::npos) break;
    start = end + 1;
    if (start == path.size()) {
      components->clear();
      return false;
    }
  }
  return !components->empty();
}

bool ServiceStoreServiceKey(const std::string& value) {
  return value == "bot" || ValidServiceInstanceKey(value);
}

bool ServiceControlChild(const std::string& value) {
  static const std::set<std::string> names = {
    "transaction", "manifest", "reference", "tombstone",
    "floor", "manual", "locks",
  };
  return names.find(value) != names.end();
}

ServiceAclProfile ServiceStoreRootProfile(const std::string& root_kind) {
  if (root_kind == "control") return ServiceAclProfile::ControlDirectory;
  if (root_kind == "staging") return ServiceAclProfile::StagingDirectory;
  return ServiceAclProfile::ReleaseDirectory;
}

ServiceAclProfile ServiceStoreDirectoryProfile(
    const ServiceStoreHandle* parent) {
  if (parent->root_kind == "control") {
    return ServiceAclProfile::ControlDirectory;
  }
  if (parent->root_kind == "staging") {
    return ServiceAclProfile::StagingDirectory;
  }
  return ServiceAclProfile::ReleaseDirectory;
}

ServiceAclProfile ServiceStoreFileProfile(
    const ServiceStoreHandle* parent) {
  if (parent->root_kind == "control") {
    return ServiceAclProfile::ControlFile;
  }
  if (parent->root_kind == "staging") {
    return ServiceAclProfile::StagingFile;
  }
  return ServiceAclProfile::ReleaseFile;
}

bool ServiceStoreProfileAllowed(const ServiceStoreHandle* parent,
                                ServiceAclProfile profile,
                                bool directory) {
  if (ServiceProfileDirectory(profile) != directory ||
      ServiceProfileExternal(profile)) return false;
  if (parent->root_kind == "control") {
    return profile == (directory
        ? ServiceAclProfile::ControlDirectory
        : ServiceAclProfile::ControlFile);
  }
  if (parent->root_kind == "staging") {
    if (directory) {
      return profile == ServiceAclProfile::StagingDirectory ||
          profile == ServiceAclProfile::ReleaseDirectory;
    }
    return profile == ServiceAclProfile::StagingFile ||
        profile == ServiceAclProfile::ReleaseFile ||
        profile == ServiceAclProfile::ReleaseExecutable;
  }
  return directory
      ? profile == ServiceAclProfile::ReleaseDirectory
      : profile == ServiceAclProfile::ReleaseFile ||
          profile == ServiceAclProfile::ReleaseExecutable;
}

bool CapturePhysicalDirectoryIdentity(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    ServiceStoreIdentity* identity) {
#ifdef _WIN32
  if (handle == INVALID_HANDLE_VALUE ||
      !InventoryIdentity(handle, &identity->volume_serial,
                         &identity->file_id, &identity->attributes,
                         &identity->owner) ||
      (identity->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
      (identity->attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    return false;
  }
#else
  struct stat metadata{};
  if (handle < 0 || fstat(handle, &metadata) != 0 ||
      !S_ISDIR(metadata.st_mode)) return false;
  identity->device = static_cast<uint64_t>(metadata.st_dev);
  identity->inode = static_cast<uint64_t>(metadata.st_ino);
  identity->mode = static_cast<uint32_t>(metadata.st_mode);
  identity->owner = "uid:" + std::to_string(metadata.st_uid);
#endif
  return true;
}

bool SamePhysicalDirectoryIdentity(const ServiceStoreIdentity& left,
                                   const ServiceStoreIdentity& right) {
#ifdef _WIN32
  return left.volume_serial == right.volume_serial &&
      left.file_id == right.file_id;
#else
  return left.device == right.device && left.inode == right.inode;
#endif
}

bool ResolveServiceStoreRoot(const std::string& root_kind,
                             std::string* parent_path,
                             std::string* name,
                             std::string* witness_name) {
  if (root_kind != "control" && root_kind != "staging" &&
      root_kind != "releases" && root_kind != "shawl") return false;
#ifdef _WIN32
  PWSTR raw = nullptr;
  if (FAILED(SHGetKnownFolderPath(
          FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &raw))) {
    return false;
  }
  const std::string program_data = Utf8(raw);
  CoTaskMemFree(raw);
  if (root_kind == "shawl") {
    *parent_path = program_data + "\\gjc-remote\\supervisors";
    *name = "shawl";
  } else {
    *parent_path = program_data + "\\gjc-remote";
    *name = root_kind == "control" ? "service-control" : root_kind;
  }
#else
  if (root_kind == "shawl") return false;
  if (root_kind == "control") {
    *parent_path = "/var/lib/gjc-remote";
    *name = "service-control";
  } else {
    *parent_path = "/opt/gjc-remote";
    *name = root_kind == "staging" ? ".staging" : "releases";
  }
#endif
  *witness_name = ".gjc-service-" + root_kind + "-root.v1";
  return true;
}

bool ServiceStoreRootAccess(const std::string& text,
                            ServiceStoreAccess* access,
                            bool* create) {
  *create = false;
  if (text == "read-existing") {
    *access = ServiceStoreAccess::Read;
    return true;
  }
  if (text == "write-existing") {
    *access = ServiceStoreAccess::Write;
    return true;
  }
  if (text == "create-new") {
    *access = ServiceStoreAccess::Write;
    *create = true;
    return true;
  }
  return false;
}

#ifdef _WIN32
struct WindowsServiceStoreDescriptor {
  SECURITY_DESCRIPTOR descriptor{};
  PACL acl = nullptr;
  std::vector<PSID> sids;
  bool valid = false;
  WindowsServiceStoreDescriptor(const InventoryRoles& roles,
                                ServiceAclProfile profile) {
    valid = BuildWindowsServiceFileAcl(roles, profile, &acl, &sids) &&
        InitializeSecurityDescriptor(
            &descriptor, SECURITY_DESCRIPTOR_REVISION) &&
        SetSecurityDescriptorOwner(
            &descriptor, sids[ServiceProfileOwner(profile)], FALSE) &&
        SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) &&
        SetSecurityDescriptorControl(
            &descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
  }
  ~WindowsServiceStoreDescriptor() {
    if (acl) LocalFree(acl);
    for (PSID sid : sids) if (sid) LocalFree(sid);
  }
};
#endif

bool CreateServiceStoreDirectory(
#ifdef _WIN32
    HANDLE parent, const std::wstring& name,
#else
    int parent, const std::string& name,
#endif
    const InventoryRoles& roles, ServiceAclProfile profile,
    ServiceStoreIdentity* identity, uint32_t* writes,
#ifdef _WIN32
    HANDLE* result
#else
    int* result
#endif
    ) {
#ifdef _WIN32
  WindowsServiceStoreDescriptor security(roles, profile);
  HANDLE created = security.valid ? OpenWindowsRelative(
      parent, name,
      FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL |
          DELETE | FILE_DELETE_CHILD,
      kFileCreate, VerifiedObjectType::Directory,
      &security.descriptor) : INVALID_HANDLE_VALUE;
  if (created == INVALID_HANDLE_VALUE) return false;
  ++*writes;
  if (!CaptureServiceStoreIdentity(created, roles, profile, identity)) {
    CloseHandle(created);
    return false;
  }
  *result = created;
#else
  if (mkdirat(parent, name.c_str(), 0700) != 0) return false;
  ++*writes;
  int created = openat(parent, name.c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  bool acl_mutated = false;
  const bool acl_applied = created >= 0 &&
      BuildPosixServiceAcl(
          created, roles, profile, true, &acl_mutated);
  if (acl_mutated) ++*writes;
  if (!acl_applied) {
    if (created >= 0) close(created);
    return false;
  }
  if (!CaptureServiceStoreIdentity(created, roles, profile, identity)) {
    close(created);
    return false;
  }
  *result = created;
#endif
  return true;
}

bool CreateServiceStoreFile(
#ifdef _WIN32
    HANDLE parent, const std::wstring& name,
#else
    int parent, const std::string& name,
#endif
    const InventoryRoles& roles, ServiceAclProfile profile,
    const std::vector<uint8_t>& bytes, ServiceStoreIdentity* identity,
    uint32_t* writes,
#ifdef _WIN32
    HANDLE* result
#else
    int* result
#endif
    ) {
#ifdef _WIN32
  WindowsServiceStoreDescriptor security(roles, profile);
  HANDLE created = security.valid ? OpenWindowsRelative(
      parent, name,
      GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE |
          WRITE_DAC | WRITE_OWNER,
      kFileCreate, VerifiedObjectType::File, &security.descriptor)
      : INVALID_HANDLE_VALUE;
  if (created == INVALID_HANDLE_VALUE) return false;
  ++*writes;
  size_t offset = 0;
  bool written = true;
  while (offset < bytes.size()) {
    DWORD count = 0;
    const DWORD chunk = static_cast<DWORD>(std::min<size_t>(
        bytes.size() - offset, MAXDWORD));
    if (!WriteFile(created, bytes.data() + offset, chunk,
                   &count, nullptr) || count != chunk) {
      written = false;
      break;
    }
    offset += count;
  }
  if (!written || !FlushFileBuffers(created)) {
    CloseHandle(created);
    return false;
  }
  if (!bytes.empty()) ++*writes;
#else
  int created = openat(parent, name.c_str(),
      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (created < 0) return false;
  ++*writes;
  bool acl_mutated = false;
  const bool acl_applied = BuildPosixServiceAcl(
      created, roles, profile, true, &acl_mutated);
  if (acl_mutated) ++*writes;
  if (!acl_applied) {
    close(created);
    return false;
  }
  size_t offset = 0;
  bool written = true;
  while (offset < bytes.size()) {
    const ssize_t count = write(
        created, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      written = false;
      break;
    }
    offset += static_cast<size_t>(count);
  }
  if (!written || fsync(created) != 0 || lseek(created, 0, SEEK_SET) < 0) {
    close(created);
    return false;
  }
  if (!bytes.empty()) ++*writes;
#endif
  if (!CaptureServiceStoreIdentity(
          created, roles, profile, identity)) {
#ifdef _WIN32
    CloseHandle(created);
#else
    close(created);
#endif
    return false;
  }
  *result = created;
  return true;
}

bool FlushServiceStoreDirectory(
#ifdef _WIN32
    HANDLE directory
#else
    int directory
#endif
    ) {
#ifdef _WIN32
  FILE_ID_INFO identity{};
  std::wstring canonical;
  return CanonicalInventoryParent(directory, &identity, &canonical) &&
      FlushInventoryParent(directory, identity, canonical);
#else
  return fsync(directory) == 0;
#endif
}

#ifdef _WIN32
enum class ShawlParentState {
  Ready, Absent, AccessDenied, IoFailed, ManualCleanup,
};
bool ServiceStoreReadBytes(
    HANDLE handle, size_t maximum, std::vector<uint8_t>* bytes);
bool ServiceStoreOpenFixedParent(
    const std::string& path, bool write, HANDLE* result);
bool ServiceStoreOpenRelativeDirectory(
    HANDLE parent, const std::string& name, bool write, HANDLE* result);
bool ServiceStoreOpenRelativeContainer(
    HANDLE parent, const std::string& name, bool create_children,
    HANDLE* result);
bool ServiceStoreOpenRelativeFile(
    HANDLE parent, const std::string& name, bool write, HANDLE* result);
bool CaptureExternalAncestorIdentity(
    HANDLE handle, ServiceStoreIdentity* identity);
bool SameServicePhysicalIdentity(
    const ServiceStoreIdentity& left,
    const ServiceStoreIdentity& right);

bool WindowsPrincipalHasDirectoryAccess(
    HANDLE directory, const std::string& sid_text,
    ACCESS_MASK desired) {
  PSID sid = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  PACL dacl = nullptr;
  // AuthzAccessCheck rejects a descriptor without owner and group
  // (ERROR_INVALID_PARAMETER), so the full access-check triple is required.
  if (!ConvertStringSidToSidW(Wide(sid_text).c_str(), &sid) ||
      GetSecurityInfo(
          directory, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
              DACL_SECURITY_INFORMATION,
          nullptr, nullptr, &dacl, nullptr, &descriptor) !=
          ERROR_SUCCESS ||
      !dacl) {
    if (descriptor) LocalFree(descriptor);
    if (sid) LocalFree(sid);
    return false;
  }
  AUTHZ_RESOURCE_MANAGER_HANDLE manager = nullptr;
  AUTHZ_CLIENT_CONTEXT_HANDLE context = nullptr;
  LUID identifier{};
  bool allowed = false;
  if (AuthzInitializeResourceManager(
          AUTHZ_RM_FLAG_NO_AUDIT, nullptr, nullptr, nullptr,
          L"native-control-service-bootstrap", &manager) &&
      AuthzInitializeContextFromSid(
          0, sid, manager, nullptr, identifier, nullptr, &context)) {
    ACCESS_MASK granted = 0;
    DWORD access_error = ERROR_ACCESS_DENIED;
    AUTHZ_ACCESS_REQUEST request{};
    request.DesiredAccess = desired;
    AUTHZ_ACCESS_REPLY reply{};
    reply.ResultListLength = 1;
    reply.GrantedAccessMask = &granted;
    reply.Error = &access_error;
    allowed = AuthzAccessCheck(
            0, context, &request, nullptr, descriptor,
            nullptr, 0, &reply, nullptr) &&
        access_error == ERROR_SUCCESS &&
        (granted & desired) == desired;
  }
  if (context) AuthzFreeContext(context);
  if (manager) AuthzFreeResourceManager(manager);
  LocalFree(descriptor);
  LocalFree(sid);
  return allowed;
}

bool VerifyWindowsBootstrapAnchor(
    HANDLE directory, const InventoryRoles& roles,
    bool operating_system_anchor) {
  std::vector<std::string> trusted_text = {
    roles.system, "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
  };
  if (!operating_system_anchor) {
    trusted_text.push_back(roles.management);
    trusted_text.push_back(roles.recovery);
  }
  std::vector<PSID> trusted;
  for (const std::string& text : trusted_text) {
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(Wide(text).c_str(), &sid)) {
      for (PSID item : trusted) LocalFree(item);
      return false;
    }
    trusted.push_back(sid);
  }
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  ACL_SIZE_INFORMATION size{};
  bool valid = GetSecurityInfo(
          directory, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
          &owner, nullptr, &dacl, nullptr, &descriptor) ==
          ERROR_SUCCESS &&
      owner && dacl &&
      std::any_of(trusted.begin(), trusted.end(),
          [&](PSID expected) { return EqualSid(owner, expected); }) &&
      GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation);
  ACCESS_MASK substitution =
      FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER |
      GENERIC_ALL;
  if (!operating_system_anchor) {
    substitution |=
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_ADD_FILE |
        FILE_ADD_SUBDIRECTORY | GENERIC_WRITE;
  }
  for (DWORD index = 0; valid && index < size.AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(dacl, index, &raw)) {
      valid = false;
      break;
    }
    auto* header = static_cast<ACE_HEADER*>(raw);
    if ((header->AceFlags & INHERIT_ONLY_ACE) != 0 ||
        header->AceType == ACCESS_DENIED_ACE_TYPE) {
      continue;
    }
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
      valid = false;
      break;
    }
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    if ((ace->Mask & substitution) == 0) continue;
    PSID sid = reinterpret_cast<PSID>(&ace->SidStart);
    if (std::none_of(trusted.begin(), trusted.end(),
            [&](PSID expected) { return EqualSid(sid, expected); })) {
      valid = false;
    }
  }
  if (descriptor) LocalFree(descriptor);
  for (PSID sid : trusted) LocalFree(sid);
  return valid &&
      WindowsPrincipalHasDirectoryAccess(
          directory, roles.bot, kWindowsTraversalAccess) &&
      WindowsPrincipalHasDirectoryAccess(
          directory, roles.daemon, kWindowsTraversalAccess);
}
#else
bool LinuxAclHasNoNonOwnerWrite(acl_t acl);
#endif

bool VerifyBootstrapAnchor(
#ifdef _WIN32
    HANDLE directory,
#else
    int directory,
#endif
    const InventoryRoles& roles,
    bool operating_system_anchor = false) {
#ifdef _WIN32
  return VerifyWindowsBootstrapAnchor(
      directory, roles, operating_system_anchor);
#else
  (void)operating_system_anchor;
  struct stat metadata{};
  if (fstat(directory, &metadata) != 0 ||
      !S_ISDIR(metadata.st_mode) ||
      roles.system != 0 || metadata.st_uid != roles.system) {
    return false;
  }
  acl_t access = acl_get_fd(directory);
  const bool safe = LinuxAclHasNoNonOwnerWrite(access);
  if (access) acl_free(access);
  const std::string descriptor =
      "/proc/self/fd/" + std::to_string(directory);
  errno = 0;
  acl_t defaults =
      acl_get_file(descriptor.c_str(), ACL_TYPE_DEFAULT);
  const bool defaults_safe = defaults
      ? LinuxAclHasNoNonOwnerWrite(defaults)
      : errno == ENODATA;
  if (defaults) acl_free(defaults);
  return safe && defaults_safe &&
      PrincipalCanAccess(directory, roles.bot, S_IXUSR, false) &&
      PrincipalCanAccess(directory, roles.daemon, S_IXUSR, false);
#endif
}

enum class ServiceContainerState {
  Ready, Absent, AccessDenied, IoFailed, ManualCleanup,
};

struct ServiceContainerSpec {
  std::string anchor_path;
  std::string name;
  std::string witness_name;
  std::string identity;
};

bool ResolveServiceBaseContainer(
    const std::string& root_kind, ServiceContainerSpec* spec) {
#ifdef _WIN32
  PWSTR raw = nullptr;
  if (FAILED(SHGetKnownFolderPath(
          FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &raw))) {
    return false;
  }
  spec->anchor_path = Utf8(raw);
  CoTaskMemFree(raw);
  spec->name = "gjc-remote";
  spec->witness_name = ".gjc-service-platform-container.v1";
  spec->identity = "programdata-gjc-remote";
  return !spec->anchor_path.empty();
#else
  if (root_kind == "control") {
    spec->anchor_path = "/var/lib";
    spec->witness_name = ".gjc-service-var-lib-container.v1";
    spec->identity = "var-lib-gjc-remote";
  } else if (root_kind == "staging" ||
             root_kind == "releases") {
    spec->anchor_path = "/opt";
    spec->witness_name = ".gjc-service-opt-container.v1";
    spec->identity = "opt-gjc-remote";
  } else {
    return false;
  }
  spec->name = "gjc-remote";
  return true;
#endif
}

std::string ServiceContainerWitnessContent(
    const ServiceContainerSpec& spec,
    const std::string& disposition,
    const std::string& nonce,
    const std::string& roles_fingerprint,
    const ServiceStoreIdentity& anchor_identity,
    const ServiceStoreIdentity& container_identity) {
  std::ostringstream output;
  output << "GJC_REMOTE_SERVICE_CONTAINER_V1\n"
         << spec.identity << "\n"
         << spec.name << "\n"
         << disposition << "\n"
         << nonce << "\n"
         << roles_fingerprint << "\n"
         << ServiceStoreIdentityText(anchor_identity) << "\n"
         << ServiceStoreIdentityText(container_identity) << "\n";
  return output.str();
}

bool ServiceContainerWitnessNonce(
    const std::string& bytes, const ServiceContainerSpec& spec,
    const std::string& roles_fingerprint,
    std::string* disposition, std::string* nonce) {
  std::istringstream input(bytes);
  std::string header, identity, name, roles;
  return std::getline(input, header) &&
      std::getline(input, identity) &&
      std::getline(input, name) &&
      std::getline(input, *disposition) &&
      std::getline(input, *nonce) &&
      std::getline(input, roles) &&
      header == "GJC_REMOTE_SERVICE_CONTAINER_V1" &&
      identity == spec.identity && name == spec.name &&
      (*disposition == "managed" ||
       *disposition == "external") &&
      roles == roles_fingerprint && nonce->size() == 32 &&
      nonce->find_first_not_of("0123456789abcdef") ==
          std::string::npos;
}

#ifdef _WIN32
ShawlParentState PrepareShawlServiceParent(
    const InventoryRoles& roles, bool create,
    const ServiceStoreIdentity& expected_base,
    uint32_t* writes,
    ServiceStoreIdentity* parent_identity,
    bool* ambiguous) {
  *ambiguous = false;
  PWSTR raw = nullptr;
  if (FAILED(SHGetKnownFolderPath(
          FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &raw))) {
    return ShawlParentState::IoFailed;
  }
  const std::string base_path = Utf8(raw) + "\\gjc-remote";
  CoTaskMemFree(raw);
  HANDLE base = INVALID_HANDLE_VALUE;
  if (!ServiceStoreOpenFixedParent(
          base_path, false, &base)) {
    const DWORD error = GetLastError();
    if (base != INVALID_HANDLE_VALUE) CloseHandle(base);
    return error == ERROR_ACCESS_DENIED
        ? ShawlParentState::AccessDenied
        : ShawlParentState::IoFailed;
  }
  ServiceStoreIdentity base_identity;
  const bool managed_base =
      expected_base.profile ==
          ServiceAclProfile::InternalContainerDirectory;
  if (!(managed_base
          ? CaptureServiceStoreIdentity(
              base, roles,
              ServiceAclProfile::InternalContainerDirectory,
              &base_identity)
          : VerifyBootstrapAnchor(base, roles) &&
              CaptureExternalAncestorIdentity(
                  base, &base_identity)) ||
      !SameServicePhysicalIdentity(
          base_identity, expected_base)) {
    CloseHandle(base);
    *ambiguous = true;
    return ShawlParentState::ManualCleanup;
  }
  HANDLE supervisors = INVALID_HANDLE_VALUE;
  HANDLE witness = INVALID_HANDLE_VALUE;
  const bool parent_present = ServiceStoreOpenRelativeContainer(
      base, "supervisors", false, &supervisors);
  const DWORD parent_error =
      parent_present ? ERROR_SUCCESS : GetLastError();
  const std::string witness_name =
      ".gjc-service-shawl-parent.v1";
  const bool witness_present = ServiceStoreOpenRelativeFile(
      base, witness_name, false, &witness);
  const DWORD witness_error =
      witness_present ? ERROR_SUCCESS : GetLastError();
  const bool parent_absent = !parent_present &&
      parent_error == ERROR_FILE_NOT_FOUND;
  const bool witness_absent = !witness_present &&
      witness_error == ERROR_FILE_NOT_FOUND;
  if ((!parent_present || !witness_present) &&
      !(parent_absent && witness_absent)) {
    if (supervisors != INVALID_HANDLE_VALUE) CloseHandle(supervisors);
    if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
    CloseHandle(base);
    if (!parent_present && !witness_present &&
        (parent_error == ERROR_ACCESS_DENIED ||
         witness_error == ERROR_ACCESS_DENIED)) {
      return ShawlParentState::AccessDenied;
    }
    *ambiguous = true;
    return ShawlParentState::ManualCleanup;
  }
  std::string roles_fingerprint;
  if (!ServiceStoreRolesFingerprint(roles, &roles_fingerprint)) {
    if (supervisors != INVALID_HANDLE_VALUE) CloseHandle(supervisors);
    if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
    CloseHandle(base);
    return ShawlParentState::IoFailed;
  }
  if (parent_absent && witness_absent) {
    const std::string pending_name =
        ".gjc-service-supervisors.pending";
    HANDLE pending = INVALID_HANDLE_VALUE;
    const bool pending_present = ServiceStoreOpenRelativeContainer(
        base, pending_name, false, &pending);
    const DWORD pending_error =
        pending_present ? ERROR_SUCCESS : GetLastError();
    if (pending != INVALID_HANDLE_VALUE) CloseHandle(pending);
    if (pending_present ||
        pending_error != ERROR_FILE_NOT_FOUND) {
      CloseHandle(base);
      if (pending_error == ERROR_ACCESS_DENIED) {
        return ShawlParentState::AccessDenied;
      }
      *ambiguous = true;
      return ShawlParentState::ManualCleanup;
    }
    if (!create) {
      CloseHandle(base);
      return ShawlParentState::Absent;
    }
    HANDLE mutation_base = INVALID_HANDLE_VALUE;
    if (!ServiceStoreOpenFixedParent(
            base_path, true, &mutation_base)) {
      const DWORD error = GetLastError();
      CloseHandle(base);
      return error == ERROR_ACCESS_DENIED
          ? ShawlParentState::AccessDenied
          : ShawlParentState::IoFailed;
    }
    ServiceStoreIdentity mutation_identity;
    const bool same_base =
        (managed_base
            ? CaptureServiceStoreIdentity(
                mutation_base, roles,
                ServiceAclProfile::InternalContainerDirectory,
                &mutation_identity)
            : VerifyBootstrapAnchor(mutation_base, roles) &&
                CaptureExternalAncestorIdentity(
                    mutation_base, &mutation_identity)) &&
        SameServicePhysicalIdentity(
            mutation_identity, base_identity);
    CloseHandle(base);
    base = mutation_base;
    HANDLE raced_parent = INVALID_HANDLE_VALUE;
    HANDLE raced_witness = INVALID_HANDLE_VALUE;
    HANDLE raced_pending = INVALID_HANDLE_VALUE;
    const bool parent_not_found =
        !ServiceStoreOpenRelativeContainer(
            base, "supervisors", false, &raced_parent) &&
        GetLastError() == ERROR_FILE_NOT_FOUND;
    const bool witness_not_found =
        !ServiceStoreOpenRelativeFile(
            base, witness_name, false, &raced_witness) &&
        GetLastError() == ERROR_FILE_NOT_FOUND;
    const bool pending_not_found =
        !ServiceStoreOpenRelativeContainer(
            base, pending_name, false, &raced_pending) &&
        GetLastError() == ERROR_FILE_NOT_FOUND;
    if (raced_parent != INVALID_HANDLE_VALUE) CloseHandle(raced_parent);
    if (raced_witness != INVALID_HANDLE_VALUE) CloseHandle(raced_witness);
    if (raced_pending != INVALID_HANDLE_VALUE) CloseHandle(raced_pending);
    if (!same_base || !parent_not_found ||
        !witness_not_found || !pending_not_found) {
      CloseHandle(base);
      *ambiguous = true;
      return ShawlParentState::ManualCleanup;
    }
    std::wstring nonce_wide;
    if (!InventoryRandomName(&nonce_wide)) {
      CloseHandle(base);
      return ShawlParentState::IoFailed;
    }
    const std::string nonce = Utf8(nonce_wide);
    const std::string temporary = pending_name;
    if (!CreateServiceStoreDirectory(
            base, Wide(temporary), roles,
            ServiceAclProfile::InternalContainerDirectory,
            parent_identity, writes, &supervisors)) {
      const DWORD error = GetLastError();
      CloseHandle(base);
      *ambiguous = *writes != 0;
      return *writes != 0 ? ShawlParentState::ManualCleanup
          : error == ERROR_ACCESS_DENIED
              ? ShawlParentState::AccessDenied
              : ShawlParentState::IoFailed;
    }
    if (!FlushServiceStoreDirectory(base)) {
      CloseHandle(supervisors);
      CloseHandle(base);
      *ambiguous = true;
      return ShawlParentState::ManualCleanup;
    }
    const std::string witness_text =
        "GJC_REMOTE_SERVICE_SHAWL_PARENT_V1\n" +
        nonce + "\n" +
        roles_fingerprint + "\n" +
        ServiceStoreIdentityText(base_identity) + "\n" +
        ServiceStoreIdentityText(*parent_identity) + "\n";
    const std::vector<uint8_t> bytes(
        witness_text.begin(), witness_text.end());
    ServiceStoreIdentity witness_identity;
    if (!CreateServiceStoreFile(
            base, Wide(witness_name), roles,
            ServiceAclProfile::ControlFile, bytes,
            &witness_identity, writes, &witness) ||
        !FlushServiceStoreDirectory(base)) {
      if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
      CloseHandle(supervisors);
      CloseHandle(base);
      *ambiguous = true;
      return ShawlParentState::ManualCleanup;
    }
    CloseHandle(witness);
    witness = INVALID_HANDLE_VALUE;
    const bool published = RenameWindowsRelative(
        supervisors, base, L"supervisors", false);
    if (published) ++*writes;
    const bool durable =
        published && FlushServiceStoreDirectory(base);
    HANDLE observed = INVALID_HANDLE_VALUE;
    HANDLE observed_witness = INVALID_HANDLE_VALUE;
    ServiceStoreIdentity observed_identity;
    ServiceStoreIdentity observed_witness_identity;
    std::vector<uint8_t> observed_witness_bytes;
    const bool observed_exact = durable &&
        ServiceStoreOpenRelativeDirectory(
            base, "supervisors", false, &observed) &&
        CaptureServiceStoreIdentity(
            observed, roles,
            ServiceAclProfile::InternalContainerDirectory,
            &observed_identity) &&
        SameServiceStoreIdentity(
            observed_identity, *parent_identity) &&
        ServiceStoreOpenRelativeFile(
            base, witness_name, false,
            &observed_witness) &&
        CaptureServiceStoreIdentity(
            observed_witness, roles,
            ServiceAclProfile::ControlFile,
            &observed_witness_identity) &&
        SameServiceStoreIdentity(
            observed_witness_identity, witness_identity) &&
        ServiceStoreReadBytes(
            observed_witness, 64 * 1024,
            &observed_witness_bytes) &&
        observed_witness_bytes == bytes;
    if (observed != INVALID_HANDLE_VALUE) CloseHandle(observed);
    if (observed_witness != INVALID_HANDLE_VALUE) {
      CloseHandle(observed_witness);
    }
    CloseHandle(supervisors);
    CloseHandle(base);
    if (!observed_exact) {
      *ambiguous = true;
      return ShawlParentState::ManualCleanup;
    }
    return ShawlParentState::Ready;
  }
  std::vector<uint8_t> bytes;
  ServiceStoreIdentity witness_identity;
  const bool valid = CaptureServiceStoreIdentity(
          supervisors, roles,
          ServiceAclProfile::InternalContainerDirectory,
          parent_identity) &&
      CaptureServiceStoreIdentity(
          witness, roles, ServiceAclProfile::ControlFile,
          &witness_identity) &&
      ServiceStoreReadBytes(witness, 64 * 1024, &bytes);
  std::istringstream input(std::string(bytes.begin(), bytes.end()));
  std::string header, nonce, recorded_roles;
  const bool header_valid =
      std::getline(input, header) &&
      std::getline(input, nonce) &&
      std::getline(input, recorded_roles) &&
      header == "GJC_REMOTE_SERVICE_SHAWL_PARENT_V1" &&
      recorded_roles == roles_fingerprint &&
      nonce.size() == 32 &&
      nonce.find_first_not_of("0123456789abcdef") ==
          std::string::npos;
  const std::string expected =
      "GJC_REMOTE_SERVICE_SHAWL_PARENT_V1\n" +
      nonce + "\n" + roles_fingerprint + "\n" +
      ServiceStoreIdentityText(base_identity) + "\n" +
      ServiceStoreIdentityText(*parent_identity) + "\n";
  CloseHandle(witness);
  CloseHandle(supervisors);
  CloseHandle(base);
  if (!valid || !header_valid ||
      std::string(bytes.begin(), bytes.end()) != expected) {
    *ambiguous = true;
    return ShawlParentState::ManualCleanup;
  }
  return ShawlParentState::Ready;
}
#endif

bool ServiceStoreReadBytes(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    size_t maximum, std::vector<uint8_t>* bytes) {
#ifdef _WIN32
  LARGE_INTEGER length{};
  if (!GetFileSizeEx(handle, &length) || length.QuadPart < 0 ||
      static_cast<uint64_t>(length.QuadPart) > maximum ||
      SetFilePointer(handle, 0, nullptr, FILE_BEGIN) ==
          INVALID_SET_FILE_POINTER && GetLastError() != ERROR_SUCCESS) {
    return false;
  }
  try {
    bytes->assign(static_cast<size_t>(length.QuadPart), 0);
  } catch (...) {
    return false;
  }
  size_t offset = 0;
  while (offset < bytes->size()) {
    DWORD read_bytes = 0;
    const DWORD chunk = static_cast<DWORD>(std::min<size_t>(
        bytes->size() - offset, MAXDWORD));
    if (!ReadFile(handle, bytes->data() + offset, chunk,
                  &read_bytes, nullptr) || read_bytes == 0) {
      return false;
    }
    offset += read_bytes;
  }
#else
  struct stat metadata{};
  if (fstat(handle, &metadata) != 0 || metadata.st_size < 0 ||
      static_cast<uint64_t>(metadata.st_size) > maximum ||
      lseek(handle, 0, SEEK_SET) < 0) return false;
  try {
    bytes->assign(static_cast<size_t>(metadata.st_size), 0);
  } catch (...) {
    return false;
  }
  size_t offset = 0;
  while (offset < bytes->size()) {
    const ssize_t count =
        read(handle, bytes->data() + offset, bytes->size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += static_cast<size_t>(count);
  }
#endif
  return true;
}

const std::vector<std::string>& ServiceControlDirectories() {
  static const std::vector<std::string> names = {
    "transaction", "manifest", "reference", "tombstone",
    "floor", "manual", "locks",
  };
  return names;
}

std::string ServiceRootWitnessContent(
    const std::string& root_kind, const std::string& root_path,
    const std::string& root_nonce,
    const std::string& roles_fingerprint,
    const ServiceStoreIdentity& parent_identity,
    const ServiceStoreIdentity& root_identity,
    const std::map<std::string, ServiceStoreIdentity>& directories) {
  std::ostringstream content;
  content << "GJC_REMOTE_SERVICE_ROOT_V1\n"
          << root_kind << "\n"
          << root_path << "\n"
          << root_nonce << "\n"
          << roles_fingerprint << "\n"
          << ServiceStoreIdentityText(parent_identity) << "\n"
          << ServiceStoreIdentityText(root_identity) << "\n"
          << directories.size() << "\n";
  for (const auto& [name, identity] : directories) {
    content << name << "\t" << ServiceStoreIdentityText(identity) << "\n";
  }
  return content.str();
}

bool ServiceRootWitnessNonce(const std::string& bytes,
                             const std::string& expected_kind,
                             const std::string& expected_path,
                             const std::string& expected_roles,
                             std::string* nonce) {
  std::istringstream input(bytes);
  std::string header, kind, path, roles;
  if (!std::getline(input, header) ||
      !std::getline(input, kind) ||
      !std::getline(input, path) ||
      !std::getline(input, *nonce) ||
      !std::getline(input, roles) ||
      header != "GJC_REMOTE_SERVICE_ROOT_V1" ||
      kind != expected_kind || path != expected_path ||
      roles != expected_roles ||
      nonce->size() != 32 ||
      nonce->find_first_not_of("0123456789abcdef") !=
          std::string::npos) {
    return false;
  }
  return true;
}

std::string ServiceRootBindingFingerprint(
    const std::string& witness_bytes) {
  Sha256 hash;
  if (!hash.Ready() ||
      !hash.Update("gjc-remote/service-root-binding/v1") ||
      !hash.Update(witness_bytes)) return "";
  return hash.Finish();
}

bool ServiceStoreOpenRelativeDirectory(
#ifdef _WIN32
    HANDLE parent, const std::string& name, bool write,
    HANDLE* result
#else
    int parent, const std::string& name, bool,
    int* result
#endif
    ) {
#ifdef _WIN32
  *result = OpenWindowsRelative(
      parent, Wide(name),
      FILE_GENERIC_READ | READ_CONTROL |
          (write ? FILE_GENERIC_WRITE | FILE_DELETE_CHILD | DELETE : 0),
      kFileOpen, VerifiedObjectType::Directory);
  return *result != INVALID_HANDLE_VALUE;
#else
  *result = openat(parent, name.c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  return *result >= 0;
#endif
}

bool ServiceStoreOpenRelativeContainer(
#ifdef _WIN32
    HANDLE parent, const std::string& name, bool create_children,
    HANDLE* result
#else
    int parent, const std::string& name, bool create_children,
    int* result
#endif
    ) {
#ifdef _WIN32
  *result = OpenWindowsRelative(
      parent, Wide(name),
      FILE_GENERIC_READ | READ_CONTROL |
          (create_children
              ? FILE_GENERIC_WRITE |
                  FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
              : 0),
      kFileOpen, VerifiedObjectType::Directory);
  return *result != INVALID_HANDLE_VALUE;
#else
  (void)create_children;
  *result = openat(parent, name.c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  return *result >= 0;
#endif
}

bool ServiceStoreOpenRelativeFile(
#ifdef _WIN32
    HANDLE parent, const std::string& name, bool write,
    HANDLE* result
#else
    int parent, const std::string& name, bool write,
    int* result
#endif
    ) {
#ifdef _WIN32
  *result = OpenWindowsRelative(
      parent, Wide(name),
      GENERIC_READ | READ_CONTROL |
          (write ? GENERIC_WRITE | DELETE : 0),
      kFileOpen, VerifiedObjectType::File);
  return *result != INVALID_HANDLE_VALUE;
#else
  *result = openat(parent, name.c_str(),
      (write ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW);
  return *result >= 0;
#endif
}

bool ServiceStoreOpenRelativeFileForDelete(
#ifdef _WIN32
    HANDLE parent, const std::string& name, HANDLE* result
#else
    int parent, const std::string& name, int* result
#endif
    ) {
#ifdef _WIN32
  *result = OpenWindowsRelative(
      parent, Wide(name), GENERIC_READ | READ_CONTROL | DELETE,
      kFileOpen, VerifiedObjectType::File);
  return *result != INVALID_HANDLE_VALUE;
#else
  *result = openat(parent, name.c_str(),
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  return *result >= 0;
#endif
}

bool ServiceStoreOpenFixedParent(const std::string& path, bool write,
#ifdef _WIN32
                                 HANDLE* result
#else
                                 int* result
#endif
                                 ) {
#ifdef _WIN32
  const ACCESS_MASK access = write
      ? FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL |
          FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
      : FILE_GENERIC_READ | READ_CONTROL;
  *result = OpenWindowsPathNoFollow(
      path, access,
      VerifiedObjectType::Directory);
  return *result != INVALID_HANDLE_VALUE;
#else
  (void)write;
  *result = OpenDirectoryNoFollow(path);
  return *result >= 0;
#endif
}

bool CaptureExternalAncestorIdentity(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    ServiceStoreIdentity* identity);
bool SameServicePhysicalIdentity(
    const ServiceStoreIdentity& left,
    const ServiceStoreIdentity& right);

bool ServiceStoreOpenBootstrapAnchor(
    const std::string& path, bool create,
#ifdef _WIN32
    HANDLE* result
#else
    int* result
#endif
    ) {
#ifdef _WIN32
  const ACCESS_MASK access = create
      ? FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL |
          FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
      : kWindowsTraversalAccess | READ_CONTROL;
  *result = OpenWindowsPathNoFollow(
      path, access,
      VerifiedObjectType::Directory);
  return *result != INVALID_HANDLE_VALUE;
#else
  *result = OpenDirectoryNoFollow(path);
  return *result >= 0;
#endif
}

bool ServiceContainerEntryIsLifecycleEvidence(
    const std::string& name) {
  return name == "service-control" || name == ".staging" ||
      name == "staging" || name == "releases" ||
      name == "supervisors" ||
      name.rfind(".gjc-service-", 0) == 0;
}

bool ServiceContainerHasLifecycleEvidence(
#ifdef _WIN32
    HANDLE directory,
#else
    int directory,
#endif
    bool* evidence) {
  *evidence = false;
  uint32_t observed = 0;
#ifdef _WIN32
  std::array<uint8_t, 64 * 1024> buffer{};
  bool restart = true;
  for (;;) {
    if (!GetFileInformationByHandleEx(
            directory,
            restart ? FileIdBothDirectoryRestartInfo
                    : FileIdBothDirectoryInfo,
            buffer.data(), static_cast<DWORD>(buffer.size()))) {
      return GetLastError() == ERROR_NO_MORE_FILES;
    }
    restart = false;
    size_t offset = 0;
    for (;;) {
      if (offset + sizeof(FILE_ID_BOTH_DIR_INFO) > buffer.size()) {
        return false;
      }
      const auto* record =
          reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(
              buffer.data() + offset);
      if (record->FileNameLength == 0 ||
          record->FileNameLength % sizeof(wchar_t) != 0 ||
          record->FileNameLength >
              buffer.size() - offset -
                  offsetof(FILE_ID_BOTH_DIR_INFO, FileName)) {
        return false;
      }
      const std::string name = Utf8(std::wstring(
          record->FileName,
          record->FileNameLength / sizeof(wchar_t)));
      if (name != "." && name != "..") {
        if (++observed > 100001) return false;
        if (ServiceContainerEntryIsLifecycleEvidence(name)) {
          *evidence = true;
        }
      }
      if (record->NextEntryOffset == 0) break;
      if (record->NextEntryOffset <
              offsetof(FILE_ID_BOTH_DIR_INFO, FileName) ||
          record->NextEntryOffset > buffer.size() - offset) {
        return false;
      }
      offset += record->NextEntryOffset;
    }
  }
#else
  int scan = openat(directory, ".",
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (scan < 0) return false;
  DIR* stream = fdopendir(scan);
  if (!stream) {
    close(scan);
    return false;
  }
  errno = 0;
  while (dirent* entry = readdir(stream)) {
    const std::string name(entry->d_name);
    if (name != "." && name != "..") {
      if (++observed > 100001) {
        closedir(stream);
        return false;
      }
      if (ServiceContainerEntryIsLifecycleEvidence(name)) {
        *evidence = true;
      }
    }
    errno = 0;
  }
  const int read_error = errno;
  closedir(stream);
  return read_error == 0;
#endif
}

ServiceContainerState PrepareServiceBaseContainer(
    const std::string& root_kind, const InventoryRoles& roles,
    bool create, uint32_t* writes,
    ServiceStoreIdentity* container_identity) {
  ServiceContainerSpec spec;
  if (!ResolveServiceBaseContainer(root_kind, &spec)) {
    return ServiceContainerState::IoFailed;
  }
#ifdef _WIN32
  HANDLE anchor = INVALID_HANDLE_VALUE;
  HANDLE container = INVALID_HANDLE_VALUE;
  HANDLE witness = INVALID_HANDLE_VALUE;
#else
  int anchor = -1;
  int container = -1;
  int witness = -1;
#endif
  if (!ServiceStoreOpenBootstrapAnchor(
          spec.anchor_path, false, &anchor)) {
#ifdef _WIN32
    const DWORD error = GetLastError();
    return error == ERROR_ACCESS_DENIED
        ? ServiceContainerState::AccessDenied
        : error == ERROR_FILE_NOT_FOUND ||
              error == ERROR_PATH_NOT_FOUND
            ? ServiceContainerState::ManualCleanup
            : ServiceContainerState::IoFailed;
#else
    return errno == EACCES || errno == EPERM
        ? ServiceContainerState::AccessDenied
        : errno == ENOENT
            ? ServiceContainerState::ManualCleanup
            : ServiceContainerState::IoFailed;
#endif
  }
  ServiceStoreIdentity anchor_identity;
  if (!VerifyBootstrapAnchor(anchor, roles, true) ||
      !CaptureExternalAncestorIdentity(
          anchor, &anchor_identity)) {
#ifdef _WIN32
    CloseHandle(anchor);
#else
    close(anchor);
#endif
    return ServiceContainerState::AccessDenied;
  }
  const bool container_present =
      ServiceStoreOpenRelativeContainer(
          anchor, spec.name, false, &container);
#ifdef _WIN32
  const DWORD container_error =
      container_present ? ERROR_SUCCESS : GetLastError();
#else
  const int container_error =
      container_present ? 0 : errno;
#endif
  const bool witness_present = ServiceStoreOpenRelativeFile(
      anchor, spec.witness_name, false, &witness);
#ifdef _WIN32
  const DWORD witness_error =
      witness_present ? ERROR_SUCCESS : GetLastError();
  const bool container_absent = !container_present &&
      container_error == ERROR_FILE_NOT_FOUND;
  const bool witness_absent = !witness_present &&
      witness_error == ERROR_FILE_NOT_FOUND;
  const bool inaccessible =
      container_error == ERROR_ACCESS_DENIED ||
      witness_error == ERROR_ACCESS_DENIED;
#else
  const int witness_error = witness_present ? 0 : errno;
  const bool container_absent =
      !container_present && container_error == ENOENT;
  const bool witness_absent =
      !witness_present && witness_error == ENOENT;
  const bool inaccessible =
      container_error == EACCES || container_error == EPERM ||
      witness_error == EACCES || witness_error == EPERM;
#endif
  std::string roles_fingerprint;
  if (!ServiceStoreRolesFingerprint(
          roles, &roles_fingerprint)) {
#ifdef _WIN32
    if (container != INVALID_HANDLE_VALUE) CloseHandle(container);
    if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
    CloseHandle(anchor);
#else
    if (container >= 0) close(container);
    if (witness >= 0) close(witness);
    close(anchor);
#endif
    return ServiceContainerState::IoFailed;
  }
  const std::string pending_name =
      ".gjc-service-" + spec.identity + ".pending";
  if (container_present && witness_present) {
    std::vector<uint8_t> bytes;
    ServiceStoreIdentity witness_identity;
    std::string disposition, nonce;
    const bool exact = CaptureServiceStoreIdentity(
            witness, roles, ServiceAclProfile::ControlFile,
            &witness_identity) &&
        ServiceStoreReadBytes(
            witness, 64 * 1024, &bytes) &&
        ServiceContainerWitnessNonce(
            std::string(bytes.begin(), bytes.end()), spec,
            roles_fingerprint, &disposition, &nonce) &&
        (disposition == "managed"
            ? CaptureServiceStoreIdentity(
                container, roles,
                ServiceAclProfile::InternalContainerDirectory,
                container_identity)
            : VerifyBootstrapAnchor(container, roles) &&
                CaptureExternalAncestorIdentity(
                    container, container_identity)) &&
        std::string(bytes.begin(), bytes.end()) ==
            ServiceContainerWitnessContent(
                spec, disposition, nonce, roles_fingerprint,
                anchor_identity, *container_identity);
#ifdef _WIN32
    CloseHandle(container);
    CloseHandle(witness);
    CloseHandle(anchor);
#else
    close(container);
    close(witness);
    close(anchor);
#endif
    return exact ? ServiceContainerState::Ready
                 : ServiceContainerState::ManualCleanup;
  }
  if (container_present && witness_absent) {
    ServiceStoreIdentity external_identity;
    ServiceStoreIdentity orphan_managed_identity;
    bool lifecycle_evidence = false;
    const bool looks_managed =
        CaptureServiceStoreIdentity(
            container, roles,
            ServiceAclProfile::InternalContainerDirectory,
            &orphan_managed_identity);
    const bool safe_external =
        !looks_managed &&
        VerifyBootstrapAnchor(container, roles) &&
        CaptureExternalAncestorIdentity(
            container, &external_identity);
    const bool evidence_read = safe_external &&
        ServiceContainerHasLifecycleEvidence(
            container, &lifecycle_evidence);
    if (!create || !safe_external || !evidence_read ||
        lifecycle_evidence) {
#ifdef _WIN32
      CloseHandle(container);
      CloseHandle(anchor);
#else
      close(container);
      close(anchor);
#endif
      if (!create || looks_managed || lifecycle_evidence) {
        return ServiceContainerState::ManualCleanup;
      }
      return !safe_external ? ServiceContainerState::AccessDenied
                            : ServiceContainerState::IoFailed;
    }
#ifdef _WIN32
    HANDLE pending = INVALID_HANDLE_VALUE;
    const bool pending_absent =
        !ServiceStoreOpenRelativeContainer(
            anchor, pending_name, false, &pending) &&
        GetLastError() == ERROR_FILE_NOT_FOUND;
    if (pending != INVALID_HANDLE_VALUE) CloseHandle(pending);
    HANDLE mutation_anchor = INVALID_HANDLE_VALUE;
#else
    int pending = -1;
    const bool pending_absent =
        !ServiceStoreOpenRelativeContainer(
            anchor, pending_name, false, &pending) &&
        errno == ENOENT;
    if (pending >= 0) close(pending);
    int mutation_anchor = -1;
#endif
    if (!pending_absent ||
        !ServiceStoreOpenBootstrapAnchor(
            spec.anchor_path, true, &mutation_anchor)) {
#ifdef _WIN32
      const DWORD error = GetLastError();
      CloseHandle(container);
      CloseHandle(anchor);
      if (mutation_anchor != INVALID_HANDLE_VALUE) {
        CloseHandle(mutation_anchor);
      }
      return !pending_absent
          ? ServiceContainerState::ManualCleanup
          : error == ERROR_ACCESS_DENIED
              ? ServiceContainerState::AccessDenied
              : ServiceContainerState::IoFailed;
#else
      const int error = errno;
      close(container);
      close(anchor);
      if (mutation_anchor >= 0) close(mutation_anchor);
      return !pending_absent
          ? ServiceContainerState::ManualCleanup
          : error == EACCES || error == EPERM
              ? ServiceContainerState::AccessDenied
              : ServiceContainerState::IoFailed;
#endif
    }
    ServiceStoreIdentity mutation_anchor_identity;
    const bool anchor_exact =
        VerifyBootstrapAnchor(mutation_anchor, roles, true) &&
        CaptureExternalAncestorIdentity(
            mutation_anchor, &mutation_anchor_identity) &&
        SameServicePhysicalIdentity(
            mutation_anchor_identity, anchor_identity);
#ifdef _WIN32
    HANDLE observed_container = INVALID_HANDLE_VALUE;
    HANDLE observed_witness = INVALID_HANDLE_VALUE;
    HANDLE observed_pending = INVALID_HANDLE_VALUE;
#else
    int observed_container = -1;
    int observed_witness = -1;
    int observed_pending = -1;
#endif
    ServiceStoreIdentity observed_identity;
    bool observed_evidence = false;
    const bool container_exact = anchor_exact &&
        ServiceStoreOpenRelativeContainer(
            mutation_anchor, spec.name, true,
            &observed_container) &&
        VerifyBootstrapAnchor(observed_container, roles) &&
#ifndef _WIN32
        PrincipalCanAccess(
            observed_container, geteuid(),
            S_IWUSR | S_IXUSR, false) &&
#endif
        CaptureExternalAncestorIdentity(
            observed_container, &observed_identity) &&
        SameServicePhysicalIdentity(
            observed_identity, external_identity) &&
        ServiceContainerHasLifecycleEvidence(
            observed_container, &observed_evidence) &&
        !observed_evidence;
    const bool witness_still_absent =
        !ServiceStoreOpenRelativeFile(
            mutation_anchor, spec.witness_name, false,
            &observed_witness);
#ifdef _WIN32
    const bool witness_not_found = witness_still_absent &&
        GetLastError() == ERROR_FILE_NOT_FOUND;
#else
    const bool witness_not_found = witness_still_absent &&
        errno == ENOENT;
#endif
    const bool pending_still_absent =
        !ServiceStoreOpenRelativeContainer(
            mutation_anchor, pending_name, false,
            &observed_pending);
#ifdef _WIN32
    const bool pending_not_found = pending_still_absent &&
        GetLastError() == ERROR_FILE_NOT_FOUND;
    if (observed_witness != INVALID_HANDLE_VALUE) {
      CloseHandle(observed_witness);
    }
    if (observed_pending != INVALID_HANDLE_VALUE) {
      CloseHandle(observed_pending);
    }
#else
    const bool pending_not_found = pending_still_absent &&
        errno == ENOENT;
    if (observed_witness >= 0) close(observed_witness);
    if (observed_pending >= 0) close(observed_pending);
#endif
    if (!container_exact || !witness_not_found ||
        !pending_not_found) {
#ifdef _WIN32
      if (observed_container != INVALID_HANDLE_VALUE) {
        CloseHandle(observed_container);
      }
      CloseHandle(mutation_anchor);
      CloseHandle(container);
      CloseHandle(anchor);
#else
      if (observed_container >= 0) close(observed_container);
      close(mutation_anchor);
      close(container);
      close(anchor);
#endif
      return ServiceContainerState::ManualCleanup;
    }
    std::string nonce;
#ifdef _WIN32
    std::wstring nonce_wide;
    const bool random_ready = InventoryRandomName(&nonce_wide);
    if (random_ready) nonce = Utf8(nonce_wide);
#else
    const bool random_ready = InventoryRandomName(&nonce);
#endif
    if (!random_ready) {
#ifdef _WIN32
      CloseHandle(observed_container);
      CloseHandle(mutation_anchor);
      CloseHandle(container);
      CloseHandle(anchor);
#else
      close(observed_container);
      close(mutation_anchor);
      close(container);
      close(anchor);
#endif
      return ServiceContainerState::IoFailed;
    }
    const std::string witness_text =
        ServiceContainerWitnessContent(
            spec, "external", nonce, roles_fingerprint,
            mutation_anchor_identity, observed_identity);
    const std::vector<uint8_t> witness_bytes(
        witness_text.begin(), witness_text.end());
    ServiceStoreIdentity witness_identity;
#ifdef _WIN32
    HANDLE created_witness = INVALID_HANDLE_VALUE;
#else
    int created_witness = -1;
#endif
    const bool registered = CreateServiceStoreFile(
            mutation_anchor,
#ifdef _WIN32
            Wide(spec.witness_name),
#else
            spec.witness_name,
#endif
            roles, ServiceAclProfile::ControlFile,
            witness_bytes, &witness_identity, writes,
            &created_witness) &&
        FlushServiceStoreDirectory(mutation_anchor);
#ifdef _WIN32
    HANDLE named_witness = INVALID_HANDLE_VALUE;
#else
    int named_witness = -1;
#endif
    std::vector<uint8_t> observed_witness_bytes;
    std::vector<uint8_t> named_witness_bytes;
    ServiceStoreIdentity named_witness_identity;
    ServiceStoreIdentity final_container_identity;
    const bool observed_registration = registered &&
        ServiceStoreReadBytes(
            created_witness, 64 * 1024,
            &observed_witness_bytes) &&
        observed_witness_bytes == witness_bytes &&
        ServiceStoreOpenRelativeFile(
            mutation_anchor, spec.witness_name,
            false, &named_witness) &&
        CaptureServiceStoreIdentity(
            named_witness, roles,
            ServiceAclProfile::ControlFile,
            &named_witness_identity) &&
        SameServiceStoreIdentity(
            named_witness_identity, witness_identity) &&
        ServiceStoreReadBytes(
            named_witness, 64 * 1024,
            &named_witness_bytes) &&
        named_witness_bytes == witness_bytes &&
        VerifyBootstrapAnchor(observed_container, roles) &&
        CaptureExternalAncestorIdentity(
            observed_container, &final_container_identity) &&
        SameServicePhysicalIdentity(
            final_container_identity, observed_identity);
    bool registration_collision = false;
    if (!registered && *writes == 0) {
#ifdef _WIN32
      HANDLE collision = INVALID_HANDLE_VALUE;
#else
      int collision = -1;
#endif
      registration_collision = ServiceStoreOpenRelativeFile(
          mutation_anchor, spec.witness_name, false, &collision);
#ifdef _WIN32
      if (collision != INVALID_HANDLE_VALUE) CloseHandle(collision);
#else
      if (collision >= 0) close(collision);
#endif
    }
#ifdef _WIN32
    if (created_witness != INVALID_HANDLE_VALUE) {
      CloseHandle(created_witness);
    }
    if (named_witness != INVALID_HANDLE_VALUE) {
      CloseHandle(named_witness);
    }
    CloseHandle(observed_container);
    CloseHandle(mutation_anchor);
    CloseHandle(container);
    CloseHandle(anchor);
#else
    if (created_witness >= 0) close(created_witness);
    if (named_witness >= 0) close(named_witness);
    close(observed_container);
    close(mutation_anchor);
    close(container);
    close(anchor);
#endif
    if (!observed_registration) {
      return *writes == 0 && !registration_collision
          ? ServiceContainerState::IoFailed
          : ServiceContainerState::ManualCleanup;
    }
    *container_identity = final_container_identity;
    return ServiceContainerState::Ready;
  }
  if (!(container_absent && witness_absent)) {
#ifdef _WIN32
    if (container != INVALID_HANDLE_VALUE) CloseHandle(container);
    if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
    CloseHandle(anchor);
#else
    if (container >= 0) close(container);
    if (witness >= 0) close(witness);
    close(anchor);
#endif
    return inaccessible && !container_present && !witness_present
        ? ServiceContainerState::AccessDenied
        : ServiceContainerState::ManualCleanup;
  }
#ifdef _WIN32
  HANDLE pending = INVALID_HANDLE_VALUE;
#else
  int pending = -1;
#endif
  const bool pending_present = ServiceStoreOpenRelativeContainer(
      anchor, pending_name, false, &pending);
#ifdef _WIN32
  const DWORD pending_error =
      pending_present ? ERROR_SUCCESS : GetLastError();
  if (pending != INVALID_HANDLE_VALUE) CloseHandle(pending);
  const bool pending_absent =
      !pending_present && pending_error == ERROR_FILE_NOT_FOUND;
#else
  const int pending_error = pending_present ? 0 : errno;
  if (pending >= 0) close(pending);
  const bool pending_absent =
      !pending_present && pending_error == ENOENT;
#endif
  if (!pending_absent) {
#ifdef _WIN32
    CloseHandle(anchor);
    return pending_error == ERROR_ACCESS_DENIED
        ? ServiceContainerState::AccessDenied
        : ServiceContainerState::ManualCleanup;
#else
    close(anchor);
    return pending_error == EACCES || pending_error == EPERM
        ? ServiceContainerState::AccessDenied
        : ServiceContainerState::ManualCleanup;
#endif
  }
  if (!create) {
#ifdef _WIN32
    CloseHandle(anchor);
#else
    close(anchor);
#endif
    return ServiceContainerState::Absent;
  }
#ifdef _WIN32
  HANDLE mutation_anchor = INVALID_HANDLE_VALUE;
#else
  int mutation_anchor = -1;
#endif
  if (!ServiceStoreOpenBootstrapAnchor(
          spec.anchor_path, true, &mutation_anchor)) {
#ifdef _WIN32
    const DWORD error = GetLastError();
    CloseHandle(anchor);
    return error == ERROR_ACCESS_DENIED
        ? ServiceContainerState::AccessDenied
        : ServiceContainerState::IoFailed;
#else
    const int error = errno;
    close(anchor);
    return error == EACCES || error == EPERM
        ? ServiceContainerState::AccessDenied
        : ServiceContainerState::IoFailed;
#endif
  }
  ServiceStoreIdentity mutation_identity;
  const bool same_anchor = VerifyBootstrapAnchor(
          mutation_anchor, roles, true) &&
      CaptureExternalAncestorIdentity(
          mutation_anchor, &mutation_identity) &&
      SameServicePhysicalIdentity(
          mutation_identity, anchor_identity);
#ifdef _WIN32
  CloseHandle(anchor);
#else
  close(anchor);
#endif
  anchor = mutation_anchor;
  if (!same_anchor) {
#ifdef _WIN32
    CloseHandle(anchor);
#else
    close(anchor);
#endif
    return ServiceContainerState::ManualCleanup;
  }
#ifdef _WIN32
  HANDLE raced_container = INVALID_HANDLE_VALUE;
  HANDLE raced_witness = INVALID_HANDLE_VALUE;
  HANDLE raced_pending = INVALID_HANDLE_VALUE;
#else
  int raced_container = -1;
  int raced_witness = -1;
  int raced_pending = -1;
#endif
  const bool container_still_absent =
      !ServiceStoreOpenRelativeContainer(
          anchor, spec.name, false, &raced_container);
#ifdef _WIN32
  const bool container_not_found = container_still_absent &&
      GetLastError() == ERROR_FILE_NOT_FOUND;
#else
  const bool container_not_found = container_still_absent &&
      errno == ENOENT;
#endif
  const bool witness_still_absent =
      !ServiceStoreOpenRelativeFile(
          anchor, spec.witness_name, false, &raced_witness);
#ifdef _WIN32
  const bool witness_not_found = witness_still_absent &&
      GetLastError() == ERROR_FILE_NOT_FOUND;
#else
  const bool witness_not_found = witness_still_absent &&
      errno == ENOENT;
#endif
  const bool pending_still_absent =
      !ServiceStoreOpenRelativeContainer(
          anchor, pending_name, false, &raced_pending);
#ifdef _WIN32
  const bool pending_not_found = pending_still_absent &&
      GetLastError() == ERROR_FILE_NOT_FOUND;
  if (raced_container != INVALID_HANDLE_VALUE) CloseHandle(raced_container);
  if (raced_witness != INVALID_HANDLE_VALUE) CloseHandle(raced_witness);
  if (raced_pending != INVALID_HANDLE_VALUE) CloseHandle(raced_pending);
#else
  const bool pending_not_found = pending_still_absent &&
      errno == ENOENT;
  if (raced_container >= 0) close(raced_container);
  if (raced_witness >= 0) close(raced_witness);
  if (raced_pending >= 0) close(raced_pending);
#endif
  if (!container_not_found || !witness_not_found ||
      !pending_not_found) {
#ifdef _WIN32
    CloseHandle(anchor);
#else
    close(anchor);
#endif
    return ServiceContainerState::ManualCleanup;
  }
  std::string nonce;
#ifdef _WIN32
  std::wstring nonce_wide;
  if (!InventoryRandomName(&nonce_wide)) {
    CloseHandle(anchor);
    return ServiceContainerState::IoFailed;
  }
  nonce = Utf8(nonce_wide);
#else
  if (!InventoryRandomName(&nonce)) {
    close(anchor);
    return ServiceContainerState::IoFailed;
  }
#endif
  const std::string temporary = pending_name;
  ServiceStoreIdentity created_identity;
  if (!CreateServiceStoreDirectory(
          anchor,
#ifdef _WIN32
          Wide(temporary),
#else
          temporary,
#endif
          roles, ServiceAclProfile::InternalContainerDirectory,
          &created_identity, writes, &container) ||
      !FlushServiceStoreDirectory(anchor)) {
#ifdef _WIN32
    const DWORD creation_error = GetLastError();
#else
    const int creation_error = errno;
#endif
#ifdef _WIN32
    if (container != INVALID_HANDLE_VALUE) CloseHandle(container);
    CloseHandle(anchor);
#else
    if (container >= 0) close(container);
    close(anchor);
#endif
    if (*writes != 0) return ServiceContainerState::ManualCleanup;
#ifdef _WIN32
    return creation_error == ERROR_ACCESS_DENIED
        ? ServiceContainerState::AccessDenied
        : ServiceContainerState::IoFailed;
#else
    return creation_error == EACCES || creation_error == EPERM
        ? ServiceContainerState::AccessDenied
        : ServiceContainerState::IoFailed;
#endif
  }
  const std::string witness_text =
      ServiceContainerWitnessContent(
          spec, "managed", nonce, roles_fingerprint,
          anchor_identity, created_identity);
  const std::vector<uint8_t> witness_bytes(
      witness_text.begin(), witness_text.end());
  ServiceStoreIdentity witness_identity;
  if (!CreateServiceStoreFile(
          anchor,
#ifdef _WIN32
          Wide(spec.witness_name),
#else
          spec.witness_name,
#endif
          roles, ServiceAclProfile::ControlFile,
          witness_bytes, &witness_identity, writes, &witness) ||
      !FlushServiceStoreDirectory(anchor)) {
#ifdef _WIN32
    if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
    CloseHandle(container);
    CloseHandle(anchor);
#else
    if (witness >= 0) close(witness);
    close(container);
    close(anchor);
#endif
    return ServiceContainerState::ManualCleanup;
  }
#ifdef _WIN32
  CloseHandle(witness);
  witness = INVALID_HANDLE_VALUE;
  const bool published = RenameWindowsRelative(
      container, anchor, Wide(spec.name), false);
#else
  close(witness);
  witness = -1;
  const bool published = RenameAt2(
      anchor, temporary, spec.name, 1) == 0;
#endif
  if (published) ++*writes;
  const bool durable =
      published && FlushServiceStoreDirectory(anchor);
#ifdef _WIN32
  HANDLE observed = INVALID_HANDLE_VALUE;
  HANDLE observed_witness = INVALID_HANDLE_VALUE;
#else
  int observed = -1;
  int observed_witness = -1;
#endif
  ServiceStoreIdentity observed_identity;
  ServiceStoreIdentity observed_witness_identity;
  std::vector<uint8_t> observed_witness_bytes;
  const bool observed_exact = durable &&
      ServiceStoreOpenRelativeDirectory(
          anchor, spec.name, false, &observed) &&
      CaptureServiceStoreIdentity(
          observed, roles,
          ServiceAclProfile::InternalContainerDirectory,
          &observed_identity) &&
      SameServiceStoreIdentity(
          observed_identity, created_identity) &&
      ServiceStoreOpenRelativeFile(
          anchor, spec.witness_name, false,
          &observed_witness) &&
      CaptureServiceStoreIdentity(
          observed_witness, roles,
          ServiceAclProfile::ControlFile,
          &observed_witness_identity) &&
      SameServiceStoreIdentity(
          observed_witness_identity, witness_identity) &&
      ServiceStoreReadBytes(
          observed_witness, 64 * 1024,
          &observed_witness_bytes) &&
      observed_witness_bytes == witness_bytes;
#ifdef _WIN32
  if (observed != INVALID_HANDLE_VALUE) CloseHandle(observed);
  if (observed_witness != INVALID_HANDLE_VALUE) {
    CloseHandle(observed_witness);
  }
  CloseHandle(container);
  CloseHandle(anchor);
#else
  if (observed >= 0) close(observed);
  if (observed_witness >= 0) close(observed_witness);
  close(container);
  close(anchor);
#endif
  if (!observed_exact) return ServiceContainerState::ManualCleanup;
  *container_identity = created_identity;
  return ServiceContainerState::Ready;
}

bool ServiceStoreNamedDirectoryExact(
#ifdef _WIN32
    HANDLE parent,
#else
    int parent,
#endif
    const std::string& name, const InventoryRoles& roles,
    const ServiceStoreIdentity& expected,
#ifdef _WIN32
    HANDLE* result
#else
    int* result
#endif
    ) {
  if (!ServiceStoreOpenRelativeDirectory(parent, name, false, result)) {
    return false;
  }
  ServiceStoreIdentity actual;
  if (!CaptureServiceStoreIdentity(
          *result, roles, expected.profile, &actual) ||
      !SameServiceStoreIdentity(actual, expected)) {
#ifdef _WIN32
    CloseHandle(*result);
    *result = INVALID_HANDLE_VALUE;
#else
    close(*result);
    *result = -1;
#endif
    return false;
  }
  return true;
}

bool CaptureServiceStoreObjectPath(
#ifdef _WIN32
    HANDLE object,
#else
    int object,
#endif
    std::string* path);

bool CaptureServiceStoreRootPath(ServiceStoreHandle* root,
                                 std::string* path);

bool RevalidateServiceStoreRoot(ServiceStoreHandle* root) {
  if (!ServiceStoreNativeHandleOpen(root) ||
      root->kind != ServiceStoreHandleKind::Root ||
      root->root != root) return false;
  ServiceStoreIdentity held;
  if (!CaptureServiceStoreIdentity(
          root->object, root->roles, root->profile, &held) ||
      !SameServiceStoreIdentity(held, root->identity)) return false;
  std::string retained_path;
  if (!CaptureServiceStoreRootPath(root, &retained_path) ||
      retained_path != root->root_path) return false;
  ServiceStoreIdentity prepared_base;
  uint32_t base_writes = 0;
  ServiceContainerState base_state =
      ServiceContainerState::IoFailed;
  try {
    base_state = PrepareServiceBaseContainer(
        root->root_kind, root->roles, false,
        &base_writes, &prepared_base);
  } catch (...) {
    return false;
  }
  if (base_state != ServiceContainerState::Ready ||
      base_writes != 0) {
    return false;
  }
#ifdef _WIN32
  if (root->root_kind == "shawl") {
    ServiceStoreIdentity prepared;
    uint32_t writes = 0;
    bool ambiguous = false;
    ShawlParentState shawl_state = ShawlParentState::IoFailed;
    try {
      shawl_state = PrepareShawlServiceParent(
          root->roles, false, prepared_base, &writes,
          &prepared, &ambiguous);
    } catch (...) {
      return false;
    }
    if (shawl_state != ShawlParentState::Ready ||
        writes != 0 ||
        !SameServiceStoreIdentity(
            prepared, root->binding_parent_identity)) {
      return false;
    }
  }
#endif

#ifdef _WIN32
  HANDLE named_parent = INVALID_HANDLE_VALUE;
#else
  int named_parent = -1;
#endif
  ServiceStoreIdentity parent_identity;
  if (!ServiceStoreOpenFixedParent(
          root->fixed_parent_path, false, &named_parent) ||
      !CapturePhysicalDirectoryIdentity(
          root->binding_parent, &parent_identity) ||
      !SamePhysicalDirectoryIdentity(
          parent_identity, root->binding_parent_identity)) {
#ifdef _WIN32
    if (named_parent != INVALID_HANDLE_VALUE) CloseHandle(named_parent);
#else
    if (named_parent >= 0) close(named_parent);
#endif
    return false;
  }
  ServiceStoreIdentity named_parent_identity;
  bool parent_named = false;
  if (root->root_kind == "shawl") {
    parent_named = CaptureServiceStoreIdentity(
            named_parent, root->roles,
            ServiceAclProfile::InternalContainerDirectory,
            &named_parent_identity) &&
        SameServiceStoreIdentity(
            named_parent_identity, root->binding_parent_identity);
  } else {
    const bool managed =
        prepared_base.profile ==
            ServiceAclProfile::InternalContainerDirectory;
    parent_named =
        (managed
            ? CaptureServiceStoreIdentity(
                named_parent, root->roles,
                ServiceAclProfile::InternalContainerDirectory,
                &named_parent_identity)
            : VerifyBootstrapAnchor(named_parent, root->roles) &&
                CaptureExternalAncestorIdentity(
                    named_parent, &named_parent_identity)) &&
        SameServicePhysicalIdentity(
            named_parent_identity, prepared_base) &&
        SameServicePhysicalIdentity(
            named_parent_identity, root->binding_parent_identity);
  }
#ifdef _WIN32
  CloseHandle(named_parent);
  HANDLE named_root = INVALID_HANDLE_VALUE;
#else
  close(named_parent);
  int named_root = -1;
#endif
  if (!parent_named ||
      !ServiceStoreNamedDirectoryExact(
          root->binding_parent, root->name, root->roles,
          root->identity, &named_root)) return false;
#ifdef _WIN32
  CloseHandle(named_root);
#else
  close(named_root);
#endif

  for (const auto& [name, identity] : root->directory_identities) {
#ifdef _WIN32
    HANDLE child = INVALID_HANDLE_VALUE;
#else
    int child = -1;
#endif
    if (!ServiceStoreNamedDirectoryExact(
            root->object, name, root->roles, identity, &child)) {
      return false;
    }
#ifdef _WIN32
    CloseHandle(child);
#else
    close(child);
#endif
  }

#ifdef _WIN32
  HANDLE witness = INVALID_HANDLE_VALUE;
#else
  int witness = -1;
#endif
  if (!ServiceStoreOpenRelativeFile(
          root->binding_parent, root->witness_name,
          false, &witness)) {
    return false;
  }
  ServiceStoreIdentity witness_identity;
  std::vector<uint8_t> witness_bytes;
  const bool witness_valid = CaptureServiceStoreIdentity(
          witness, root->roles, ServiceAclProfile::ControlFile,
          &witness_identity) &&
      SameServiceStoreIdentity(
          witness_identity, root->witness_identity) &&
      ServiceStoreReadBytes(witness, 64 * 1024, &witness_bytes) &&
      std::string(witness_bytes.begin(), witness_bytes.end()) ==
          root->witness_bytes;
#ifdef _WIN32
  CloseHandle(witness);
#else
  close(witness);
#endif
  return witness_valid;
}

bool RevalidateServiceStoreHandle(ServiceStoreHandle* handle) {
  if (!ServiceStoreNativeHandleOpen(handle) || handle->poisoned) {
    return false;
  }
  if (handle->kind == ServiceStoreHandleKind::ExternalRoot) {
#ifdef _WIN32
    return RevalidateServiceExternalRoot(handle);
#else
    return false;
#endif
  }
  if (handle->kind == ServiceStoreHandleKind::ArtifactWriter ||
      handle->kind == ServiceStoreHandleKind::ArtifactReader ||
      handle->kind == ServiceStoreHandleKind::ArtifactSourceReader) {
    return RevalidateServiceArtifactStream(handle);
  }
  if (handle->kind == ServiceStoreHandleKind::LinuxScope) {
#ifdef __linux__
    ServiceStoreIdentity held;
    int named = OpenDirectoryNoFollow("/etc/systemd/system");
    ServiceStoreIdentity named_identity;
    const bool valid = CapturePhysicalDirectoryIdentity(
            handle->object, &held) &&
        VerifyLinuxTrustedSystemdDirectory(handle->object) &&
        SamePhysicalDirectoryIdentity(held, handle->identity) &&
        named >= 0 &&
        VerifyLinuxTrustedSystemdDirectory(named) &&
        CapturePhysicalDirectoryIdentity(named, &named_identity) &&
        SamePhysicalDirectoryIdentity(
            named_identity, handle->identity);
    if (named >= 0) close(named);
    return valid;
#else
    return false;
#endif
  }
  if (handle->kind == ServiceStoreHandleKind::Root) {
    return RevalidateServiceStoreRoot(handle);
  }
  if (!handle->root || !RevalidateServiceStoreRoot(handle->root)) {
    return false;
  }
  if (handle->kind == ServiceStoreHandleKind::Directory) {
    if (!handle->parent ||
        !RevalidateServiceStoreHandle(handle->parent)) return false;
    ServiceStoreIdentity held;
    if (!CaptureServiceStoreIdentity(
            handle->object, handle->roles, handle->profile, &held) ||
        !SameServiceStoreIdentity(held, handle->identity)) return false;
#ifdef _WIN32
    HANDLE named = INVALID_HANDLE_VALUE;
#else
    int named = -1;
#endif
    if (!ServiceStoreNamedDirectoryExact(
            handle->parent->object, handle->name, handle->roles,
            handle->identity, &named)) return false;
#ifdef _WIN32
    CloseHandle(named);
#else
    close(named);
#endif
    return true;
  }
  ServiceStoreIdentity parent_identity;
  if (!CaptureServiceStoreIdentity(
          handle->binding_parent, handle->roles,
          ServiceAclProfile::ControlDirectory, &parent_identity) ||
      !SameServiceStoreIdentity(
          parent_identity, handle->binding_parent_identity)) {
    return false;
  }
#ifdef _WIN32
  HANDLE named = INVALID_HANDLE_VALUE;
#else
  int named = -1;
#endif
  if (!ServiceStoreOpenRelativeFile(
          handle->binding_parent, handle->name, false, &named)) {
    return false;
  }
  ServiceStoreIdentity named_identity;
  std::vector<uint8_t> empty;
  const bool named_valid = CaptureServiceStoreIdentity(
          named, handle->roles, ServiceAclProfile::ControlFile,
          &named_identity) &&
      SameServiceStoreIdentity(named_identity, handle->identity) &&
      ServiceStoreReadBytes(named, 0, &empty);
#ifdef _WIN32
  CloseHandle(named);
#else
  close(named);
#endif
  if (!named_valid) return false;

#ifdef _WIN32
  HANDLE witness = INVALID_HANDLE_VALUE;
#else
  int witness = -1;
#endif
  if (!ServiceStoreOpenRelativeFile(
          handle->root->object, handle->witness_name,
          false, &witness)) return false;
  ServiceStoreIdentity witness_identity;
  std::vector<uint8_t> bytes;
  const bool witness_valid = CaptureServiceStoreIdentity(
          witness, handle->roles, ServiceAclProfile::ControlFile,
          &witness_identity) &&
      SameServiceStoreIdentity(
          witness_identity, handle->witness_identity) &&
      ServiceStoreReadBytes(witness, 64 * 1024, &bytes) &&
      std::string(bytes.begin(), bytes.end()) ==
          handle->witness_bytes;
#ifdef _WIN32
  CloseHandle(witness);
#else
  close(witness);
#endif
  return witness_valid;
}

bool CaptureServiceStoreObjectPath(
#ifdef _WIN32
    HANDLE object,
#else
    int object,
#endif
    std::string* path) {
#ifdef _WIN32
  FILE_ID_INFO identity{};
  std::wstring canonical;
  if (!CanonicalInventoryParent(object, &identity, &canonical)) {
    return false;
  }
  if (canonical.rfind(L"\\\\?\\", 0) == 0) canonical.erase(0, 4);
  *path = Utf8(canonical);
  WindowsPathParts parsed;
  return !path->empty() && ParseWindowsPath(*path, &parsed);
#else
  const std::string descriptor =
      "/proc/self/fd/" + std::to_string(object);
  std::array<char, 4097> buffer{};
  const ssize_t length = readlink(
      descriptor.c_str(), buffer.data(), buffer.size() - 1);
  if (length <= 0 ||
      length >= static_cast<ssize_t>(buffer.size() - 1)) return false;
  path->assign(buffer.data(), static_cast<size_t>(length));
  return !path->empty() && path->front() == '/' &&
      path->back() != '/' &&
      path->find(" (deleted)") == std::string::npos;
#endif
}

bool CaptureServiceStoreRootPath(ServiceStoreHandle* root,
                                 std::string* path) {
  return root && ServiceStoreNativeHandleOpen(root) &&
      CaptureServiceStoreObjectPath(root->object, path);
}

napi_value ServiceRootBindingValue(napi_env env,
                                   const ServiceStoreHandle* root) {
  napi_value result, directories;
  napi_create_object(env, &result);
  ServiceSetUint32(env, result, "schemaVersion", 1);
  ServiceSetString(env, result, "rootKind", root->root_kind);
  ServiceSetString(env, result, "rootPath", root->root_path);
  ServiceSetString(env, result, "rootNonce", root->root_nonce);
  ServiceSetString(env, result, "rolesFingerprint",
                   root->roles_fingerprint);
  napi_set_named_property(
      env, result, "identity",
      ServiceStoreIdentityValue(env, root->identity));
  napi_create_object(env, &directories);
  for (const auto& [name, identity] : root->directory_identities) {
    napi_set_named_property(
        env, directories, name.c_str(),
        ServiceStoreIdentityValue(env, identity));
  }
  napi_set_named_property(
      env, result, "directoryIdentities", directories);
  ServiceSetString(env, result, "bindingFingerprint",
                   root->binding_fingerprint);
  return result;
}

napi_value OpenServiceRoot(napi_env env, napi_callback_info info) {
  napi_value args[3];
  std::string root_kind, access_text;
  InventoryRoles roles{};
  ServiceStoreAccess access;
  bool create = false;
  std::string parent_path, name, witness_name;
  if (!InventoryArgs(env, info, 3, args) ||
      !InventoryString(env, args[0], &root_kind) ||
      (root_kind != "control" && root_kind != "staging" &&
       root_kind != "releases" && root_kind != "shawl") ||
      !InventoryRolesArg(env, args[1], &roles) ||
      !InventoryString(env, args[2], &access_text) ||
      !ServiceStoreRootAccess(access_text, &access, &create) ||
      !ServiceActorAuthorized(roles)) {
    ServiceError(env, "SERVICE_INVALID", "open_service_root");
    return nullptr;
  }
#ifndef _WIN32
  if (root_kind == "shawl") {
    ServiceError(env, "SERVICE_UNSUPPORTED", "open_service_root");
    return nullptr;
  }
#endif
  if (!ResolveServiceStoreRoot(
          root_kind, &parent_path, &name, &witness_name)) {
    ServiceError(env, "SERVICE_IO_FAILED", "open_service_root");
    return nullptr;
  }
  std::string roles_fingerprint;
  if (!ServiceStoreRolesFingerprint(roles, &roles_fingerprint)) {
    ServiceError(env, "SERVICE_CRYPTO_UNAVAILABLE",
                 "open_service_root");
    return nullptr;
  }
  uint32_t writes = 0;
  ServiceStoreIdentity prepared_base;
  ServiceContainerState base_state =
      ServiceContainerState::IoFailed;
  try {
    base_state = PrepareServiceBaseContainer(
        root_kind, roles, create, &writes, &prepared_base);
  } catch (...) {
    ServiceError(env,
        writes == 0 ? "SERVICE_IO_FAILED"
                    : "SERVICE_MANUAL_CLEANUP",
        "open_service_root", writes, writes != 0);
    return nullptr;
  }
  if (base_state == ServiceContainerState::Absent) {
    napi_value absent;
    napi_get_null(env, &absent);
    return absent;
  }
  if (base_state != ServiceContainerState::Ready) {
    const bool ambiguous =
        base_state == ServiceContainerState::ManualCleanup;
    ServiceError(env,
        ambiguous ? "SERVICE_MANUAL_CLEANUP" :
        base_state == ServiceContainerState::AccessDenied
            ? "SERVICE_ACCESS_DENIED" : "SERVICE_IO_FAILED",
        "open_service_root", writes, ambiguous);
    return nullptr;
  }
#ifdef _WIN32
  ServiceStoreIdentity prepared_shawl_parent;
  if (root_kind == "shawl") {
    bool ambiguous = false;
    ShawlParentState state = ShawlParentState::IoFailed;
    try {
      state = PrepareShawlServiceParent(
          roles, create, prepared_base,
          &writes, &prepared_shawl_parent, &ambiguous);
    } catch (...) {
      ServiceError(env,
          writes == 0 ? "SERVICE_IO_FAILED"
                      : "SERVICE_MANUAL_CLEANUP",
          "open_service_root", writes, writes != 0);
      return nullptr;
    }
    if (state == ShawlParentState::Absent) {
      napi_value absent;
      napi_get_null(env, &absent);
      return absent;
    }
    if (state != ShawlParentState::Ready) {
      ambiguous =
          state == ShawlParentState::ManualCleanup;
      ServiceError(env,
          ambiguous ? "SERVICE_MANUAL_CLEANUP" :
          state == ShawlParentState::AccessDenied
              ? "SERVICE_ACCESS_DENIED"
              : "SERVICE_IO_FAILED",
          "open_service_root", writes, ambiguous);
      return nullptr;
    }
  }
#endif
#ifdef _WIN32
  HANDLE parent = INVALID_HANDLE_VALUE;
  HANDLE root_handle = INVALID_HANDLE_VALUE;
  HANDLE witness = INVALID_HANDLE_VALUE;
#else
  int parent = -1;
  int root_handle = -1;
  int witness = -1;
#endif
  if (!ServiceStoreOpenFixedParent(
          parent_path, create, &parent)) {
#ifdef _WIN32
    const DWORD error = GetLastError();
    const bool missing =
        error == ERROR_FILE_NOT_FOUND ||
        error == ERROR_PATH_NOT_FOUND;
    const bool denied = error == ERROR_ACCESS_DENIED;
#else
    const int error = errno;
    const bool missing = error == ENOENT;
    const bool denied = error == EACCES || error == EPERM;
#endif
    const bool ambiguous = writes != 0 || missing;
    ServiceError(env,
        ambiguous ? "SERVICE_MANUAL_CLEANUP" :
        denied ? "SERVICE_ACCESS_DENIED" : "SERVICE_IO_FAILED",
        "open_service_root", writes, ambiguous);
    return nullptr;
  }
  ServiceStoreIdentity parent_identity;
  const bool parent_valid =
#ifdef _WIN32
      root_kind == "shawl"
          ? CaptureServiceStoreIdentity(
                parent, roles,
                ServiceAclProfile::InternalContainerDirectory,
                &parent_identity) &&
              SameServiceStoreIdentity(
                parent_identity, prepared_shawl_parent)
          :
#endif
            (prepared_base.profile ==
                    ServiceAclProfile::InternalContainerDirectory
                ? CaptureServiceStoreIdentity(
                    parent, roles,
                    ServiceAclProfile::InternalContainerDirectory,
                    &parent_identity)
                : VerifyBootstrapAnchor(parent, roles) &&
                    CaptureExternalAncestorIdentity(
                        parent, &parent_identity)) &&
            SameServicePhysicalIdentity(
                parent_identity, prepared_base);
  if (!parent_valid) {
#ifdef _WIN32
    CloseHandle(parent);
#else
    close(parent);
#endif
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "open_service_root", writes, true);
    return nullptr;
  }
  const bool root_present = ServiceStoreOpenRelativeDirectory(
      parent, name, access == ServiceStoreAccess::Write, &root_handle);
#ifdef _WIN32
  const DWORD root_error =
      root_present ? ERROR_SUCCESS : GetLastError();
#else
  const int root_error = root_present ? 0 : errno;
#endif
  const bool witness_present = ServiceStoreOpenRelativeFile(
      parent, witness_name, false, &witness);
#ifdef _WIN32
  const DWORD witness_error =
      witness_present ? ERROR_SUCCESS : GetLastError();
  const bool root_absent = !root_present &&
      (root_error == ERROR_FILE_NOT_FOUND ||
       root_error == ERROR_PATH_NOT_FOUND);
  const bool witness_absent = !witness_present &&
      (witness_error == ERROR_FILE_NOT_FOUND ||
       witness_error == ERROR_PATH_NOT_FOUND);
#else
  const int witness_error = witness_present ? 0 : errno;
  const bool root_absent = !root_present && root_error == ENOENT;
  const bool witness_absent = !witness_present &&
      witness_error == ENOENT;
#endif
  ServiceStoreIdentity root_identity, witness_identity;
  std::map<std::string, ServiceStoreIdentity> directories;
  std::string root_nonce;
  std::string root_path;
  std::string witness_bytes;

  if (!root_present || !witness_present) {
#ifdef _WIN32
    if (root_handle != INVALID_HANDLE_VALUE) CloseHandle(root_handle);
    if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
#else
    if (root_handle >= 0) close(root_handle);
    if (witness >= 0) close(witness);
#endif
    if (!(root_absent && witness_absent)) {
#ifdef _WIN32
      CloseHandle(parent);
#else
      close(parent);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "open_service_root", writes, true);
      return nullptr;
    }
    if (!create) {
#ifdef _WIN32
      CloseHandle(parent);
#else
      close(parent);
#endif
      napi_value absent;
      napi_get_null(env, &absent);
      return absent;
    }
#ifdef _WIN32
    std::wstring nonce_wide;
    if (!InventoryRandomName(&nonce_wide)) {
      CloseHandle(parent);
      ServiceError(env,
          writes == 0 ? "SERVICE_IO_FAILED"
                      : "SERVICE_MANUAL_CLEANUP",
          "open_service_root", writes, writes != 0);
      return nullptr;
    }
    root_nonce = Utf8(nonce_wide);
#else
    if (!InventoryRandomName(&root_nonce)) {
      close(parent);
      ServiceError(env,
          writes == 0 ? "SERVICE_IO_FAILED"
                      : "SERVICE_MANUAL_CLEANUP",
          "open_service_root", writes, writes != 0);
      return nullptr;
    }
#endif
    if (!CreateServiceStoreDirectory(
            parent,
#ifdef _WIN32
            Wide(name),
#else
            name,
#endif
            roles, ServiceStoreRootProfile(root_kind),
            &root_identity, &writes, &root_handle)) {
#ifdef _WIN32
      CloseHandle(parent);
#else
      close(parent);
#endif
      ServiceError(env,
          writes == 0 ? "SERVICE_IO_FAILED"
                      : "SERVICE_MANUAL_CLEANUP",
          "open_service_root", writes, writes != 0);
      return nullptr;
    }
    if (!CaptureServiceStoreObjectPath(
            root_handle, &root_path)) {
#ifdef _WIN32
      CloseHandle(root_handle);
      CloseHandle(parent);
#else
      close(root_handle);
      close(parent);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "open_service_root", writes, true);
      return nullptr;
    }
    if (root_kind == "control") {
      for (const auto& child_name : ServiceControlDirectories()) {
#ifdef _WIN32
        HANDLE child = INVALID_HANDLE_VALUE;
#else
        int child = -1;
#endif
        ServiceStoreIdentity child_identity;
        if (!CreateServiceStoreDirectory(
                root_handle,
#ifdef _WIN32
                Wide(child_name),
#else
                child_name,
#endif
                roles, ServiceAclProfile::ControlDirectory,
                &child_identity, &writes, &child)) {
#ifdef _WIN32
          CloseHandle(root_handle);
          CloseHandle(parent);
#else
          close(root_handle);
          close(parent);
#endif
          ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                       "open_service_root", writes, true);
          return nullptr;
        }
        directories.emplace(child_name, child_identity);
#ifdef _WIN32
        CloseHandle(child);
#else
        close(child);
#endif
      }
      if (!FlushServiceStoreDirectory(root_handle)) {
#ifdef _WIN32
        CloseHandle(root_handle);
        CloseHandle(parent);
#else
        close(root_handle);
        close(parent);
#endif
        ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                     "open_service_root", writes, true);
        return nullptr;
      }
    }
    witness_bytes = ServiceRootWitnessContent(
        root_kind, root_path, root_nonce, roles_fingerprint,
        parent_identity, root_identity, directories);
    const std::vector<uint8_t> bytes(
        witness_bytes.begin(), witness_bytes.end());
    if (!CreateServiceStoreFile(
            parent,
#ifdef _WIN32
            Wide(witness_name),
#else
            witness_name,
#endif
            roles, ServiceAclProfile::ControlFile, bytes,
            &witness_identity, &writes, &witness) ||
        !FlushServiceStoreDirectory(parent)) {
#ifdef _WIN32
      if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
      CloseHandle(root_handle);
      CloseHandle(parent);
#else
      if (witness >= 0) close(witness);
      close(root_handle);
      close(parent);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "open_service_root", writes, true);
      return nullptr;
    }
#ifdef _WIN32
    CloseHandle(witness);
    witness = INVALID_HANDLE_VALUE;
#else
    close(witness);
    witness = -1;
#endif
  } else {
    if (create) {
#ifdef _WIN32
      CloseHandle(witness);
      CloseHandle(root_handle);
      CloseHandle(parent);
#else
      close(witness);
      close(root_handle);
      close(parent);
#endif
      ServiceError(env,
          writes == 0 ? "SERVICE_ALREADY_EXISTS"
                      : "SERVICE_MANUAL_CLEANUP",
          "open_service_root", writes, writes != 0);
      return nullptr;
    }
    if (!CaptureServiceStoreObjectPath(
            root_handle, &root_path)) {
#ifdef _WIN32
      CloseHandle(witness);
      CloseHandle(root_handle);
      CloseHandle(parent);
#else
      close(witness);
      close(root_handle);
      close(parent);
#endif
      ServiceError(env,
          writes == 0 ? "SERVICE_IO_FAILED"
                      : "SERVICE_MANUAL_CLEANUP",
          "open_service_root", writes, writes != 0);
      return nullptr;
    }
    if (!CaptureServiceStoreIdentity(
            root_handle, roles, ServiceStoreRootProfile(root_kind),
            &root_identity) ||
        !CaptureServiceStoreIdentity(
            witness, roles, ServiceAclProfile::ControlFile,
            &witness_identity)) {
#ifdef _WIN32
      CloseHandle(witness);
      CloseHandle(root_handle);
      CloseHandle(parent);
#else
      close(witness);
      close(root_handle);
      close(parent);
#endif
      ServiceError(env, "SERVICE_ACCESS_DENIED",
                   "open_service_root");
      return nullptr;
    }
    std::vector<uint8_t> bytes;
    if (!ServiceStoreReadBytes(witness, 64 * 1024, &bytes)) {
#ifdef _WIN32
      CloseHandle(witness);
      CloseHandle(root_handle);
      CloseHandle(parent);
#else
      close(witness);
      close(root_handle);
      close(parent);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "open_service_root", writes, true);
      return nullptr;
    }
    witness_bytes.assign(bytes.begin(), bytes.end());
    if (root_kind == "control") {
      for (const auto& child_name : ServiceControlDirectories()) {
#ifdef _WIN32
        HANDLE child = INVALID_HANDLE_VALUE;
#else
        int child = -1;
#endif
        if (!ServiceStoreOpenRelativeDirectory(
                root_handle, child_name, false, &child)) {
#ifdef _WIN32
          CloseHandle(witness);
          CloseHandle(root_handle);
          CloseHandle(parent);
#else
          close(witness);
          close(root_handle);
          close(parent);
#endif
          ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                       "open_service_root", writes, true);
          return nullptr;
        }
        ServiceStoreIdentity child_identity;
        const bool valid = CaptureServiceStoreIdentity(
            child, roles, ServiceAclProfile::ControlDirectory,
            &child_identity);
#ifdef _WIN32
        CloseHandle(child);
#else
        close(child);
#endif
        if (!valid) {
#ifdef _WIN32
          CloseHandle(witness);
          CloseHandle(root_handle);
          CloseHandle(parent);
#else
          close(witness);
          close(root_handle);
          close(parent);
#endif
          ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                       "open_service_root", writes, true);
          return nullptr;
        }
        directories.emplace(child_name, child_identity);
      }
    }
    if (!ServiceRootWitnessNonce(
            witness_bytes, root_kind, root_path,
            roles_fingerprint, &root_nonce) ||
        witness_bytes != ServiceRootWitnessContent(
            root_kind, root_path, root_nonce, roles_fingerprint,
            parent_identity, root_identity, directories)) {
#ifdef _WIN32
      CloseHandle(witness);
      CloseHandle(root_handle);
      CloseHandle(parent);
#else
      close(witness);
      close(root_handle);
      close(parent);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "open_service_root", writes, true);
      return nullptr;
    }
#ifdef _WIN32
    CloseHandle(witness);
    witness = INVALID_HANDLE_VALUE;
#else
    close(witness);
    witness = -1;
#endif
  }
  const std::string binding_fingerprint =
      ServiceRootBindingFingerprint(witness_bytes);
  if (!ValidServiceFingerprint(binding_fingerprint)) {
#ifdef _WIN32
    CloseHandle(root_handle);
    CloseHandle(parent);
#else
    close(root_handle);
    close(parent);
#endif
    ServiceError(env,
        writes == 0 ? "SERVICE_CRYPTO_UNAVAILABLE"
                    : "SERVICE_MANUAL_CLEANUP",
        "open_service_root", writes, writes != 0);
    return nullptr;
  }
  auto* handle = new (std::nothrow) ServiceStoreHandle();
  if (!handle) {
#ifdef _WIN32
    CloseHandle(root_handle);
    CloseHandle(parent);
#else
    close(root_handle);
    close(parent);
#endif
    ServiceError(env,
        writes == 0 ? "SERVICE_IO_FAILED"
                    : "SERVICE_MANUAL_CLEANUP",
        "open_service_root", writes, writes != 0);
    return nullptr;
  }
  handle->env = env;
  handle->kind = ServiceStoreHandleKind::Root;
  handle->access = access;
  handle->root_kind = root_kind;
  handle->root_nonce = root_nonce;
  handle->roles_fingerprint = roles_fingerprint;
  handle->binding_fingerprint = binding_fingerprint;
  handle->roles = roles;
  handle->profile = ServiceStoreRootProfile(root_kind);
  handle->identity = root_identity;
  handle->binding_parent_identity = parent_identity;
  handle->directory_identities = directories;
  handle->name = name;
  handle->witness_name = witness_name;
  handle->witness_bytes = witness_bytes;
  handle->witness_identity = witness_identity;
  handle->fixed_parent_path = parent_path;
  handle->object = root_handle;
  handle->binding_parent = parent;
  handle->root = handle;
  handle->root_path = root_path;
  napi_value wrapped = WrapServiceStoreHandle(env, handle);
  if (!wrapped) {
    ServiceError(env,
        writes == 0 ? "SERVICE_IO_FAILED"
                    : "SERVICE_MANUAL_CLEANUP",
        "open_service_root", writes, writes != 0);
    return nullptr;
  }
  if (!RevalidateServiceStoreRoot(handle)) {
    CloseServiceStoreNative(handle);
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "open_service_root", writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", wrapped);
  napi_set_named_property(
      env, result, "rootBinding",
      ServiceRootBindingValue(env, handle));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

std::string ServiceLockWitnessContent(
    const ServiceStoreHandle* root, const std::string& scope,
    const std::string& service_key,
    const ServiceStoreIdentity& lock_identity) {
  std::ostringstream content;
  content << "GJC_REMOTE_SERVICE_LOCK_V1\n"
          << root->root_nonce << "\n"
          << root->roles_fingerprint << "\n"
          << scope << "\n"
          << service_key << "\n"
          << ServiceStoreIdentityText(lock_identity) << "\n";
  return content.str();
}

bool ServiceLockNames(const std::string& scope,
                      const std::string& service_key,
                      std::string* name, std::string* witness,
                      int* rank) {
  if (scope == "artifact" && service_key.empty()) {
    *name = "artifact.lock";
    *rank = 1;
  } else if (scope == "shared-template" && service_key.empty()) {
    *name = "shared-template.lock";
    *rank = 2;
  } else if (scope == "service-key" &&
             ServiceStoreServiceKey(service_key)) {
    Sha256 hash;
    if (!hash.Ready()) return false;
    HashField(&hash, "gjc-remote/service-lock-name/v1");
    HashField(&hash, service_key);
    const std::string digest = hash.Finish();
    if (!ValidServiceFingerprint(digest)) return false;
    *name = "service-" + digest + ".lock";
    *rank = 3;
  } else {
    return false;
  }
  *witness = ".gjc-service-lock-" + name->substr(
      0, name->size() - std::string(".lock").size()) + ".v1";
  return true;
}

bool ServiceLockOrderAllowed(const ServiceStoreHandle* root,
                             int rank,
                             const std::string& service_key) {
  if (gServiceStoreLocks.empty()) return true;
  ServiceStoreHandle* previous = gServiceStoreLocks.back();
  if (!ServiceStoreNativeHandleOpen(previous) ||
      previous->kind != ServiceStoreHandleKind::Lock ||
      !previous->root ||
      previous->root->root_nonce != root->root_nonce ||
      previous->roles_fingerprint != root->roles_fingerprint ||
      previous->lock_rank > rank) return false;
  if (previous->lock_rank == rank) {
    return rank == 3 && previous->service_key < service_key;
  }
  return true;
}

bool ServiceLockAuthorizes(ServiceStoreHandle* target,
                           ServiceStoreHandle* lock,
                           bool exclusive) {
  if (!target || !lock ||
      lock->kind != ServiceStoreHandleKind::Lock ||
      !lock->lock_held || (exclusive && !lock->exclusive) ||
      target->roles_fingerprint != lock->roles_fingerprint ||
      !RevalidateServiceStoreHandle(target) ||
      !RevalidateServiceStoreHandle(lock)) {
    return false;
  }
  if (target->root_kind != "control") {
    return lock->scope == "artifact";
  }
  if (!target->bound_service_key.empty()) {
    return lock->scope == "artifact" ||
        (lock->scope == "service-key" &&
         lock->service_key == target->bound_service_key);
  }
  if (target->namespace_name == "transaction" ||
      target->namespace_name == "manifest" ||
      target->namespace_name == "tombstone" ||
      target->namespace_name == "manual") {
    return lock->scope == "artifact";
  }
  if (target->namespace_name == "shared-template") {
    return lock->scope == "artifact" ||
        lock->scope == "shared-template";
  }
  return lock->scope == "artifact";
}

napi_value AcquireServiceLock(napi_env env, napi_callback_info info) {
  napi_value args[4];
  ServiceStoreHandle* root = nullptr;
  std::string scope, service_key, mode;
  napi_valuetype service_key_type;
  if (!InventoryArgs(env, info, 4, args) ||
      !ServiceStoreHandleArg(env, args[0], &root) ||
      root->kind != ServiceStoreHandleKind::Root ||
      root->root_kind != "control" ||
      !InventoryString(env, args[1], &scope) ||
      napi_typeof(env, args[2], &service_key_type) != napi_ok ||
      !InventoryString(env, args[3], &mode) ||
      (service_key_type != napi_null &&
       !InventoryString(env, args[2], &service_key)) ||
      (mode != "exclusive" && mode != "shared-existing") ||
      !RevalidateServiceStoreRoot(root)) {
    ServiceError(env, "SERVICE_INVALID", "acquire_service_lock");
    return nullptr;
  }
  std::string name, witness_name;
  int rank = 0;
  if (!ServiceLockNames(
          scope, service_key, &name, &witness_name, &rank) ||
      !ServiceLockOrderAllowed(root, rank, service_key) ||
      (mode == "exclusive" &&
       root->access != ServiceStoreAccess::Write)) {
    ServiceError(env, "SERVICE_INVALID", "acquire_service_lock");
    return nullptr;
  }
  const auto locks_entry = root->directory_identities.find("locks");
  if (locks_entry == root->directory_identities.end()) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "acquire_service_lock", 0, true);
    return nullptr;
  }
  const ServiceStoreIdentity locks_identity = locks_entry->second;
#ifdef _WIN32
  HANDLE locks = INVALID_HANDLE_VALUE;
  HANDLE lock_file = INVALID_HANDLE_VALUE;
  HANDLE witness = INVALID_HANDLE_VALUE;
#else
  int locks = -1;
  int lock_file = -1;
  int witness = -1;
#endif
  ServiceStoreIdentity opened_locks_identity;
  if (!ServiceStoreOpenRelativeDirectory(
          root->object, "locks", mode == "exclusive", &locks) ||
      !CaptureServiceStoreIdentity(
          locks, root->roles,
          ServiceAclProfile::ControlDirectory,
          &opened_locks_identity) ||
      !SameServiceStoreIdentity(
          opened_locks_identity, locks_identity)) {
#ifdef _WIN32
    if (locks != INVALID_HANDLE_VALUE) CloseHandle(locks);
#else
    if (locks >= 0) close(locks);
#endif
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "acquire_service_lock", 0, true);
    return nullptr;
  }
  const bool lock_present = ServiceStoreOpenRelativeFile(
      locks, name, mode == "exclusive", &lock_file);
#ifdef _WIN32
  const DWORD lock_error =
      lock_present ? ERROR_SUCCESS : GetLastError();
#else
  const int lock_error = lock_present ? 0 : errno;
#endif
  const bool witness_present = ServiceStoreOpenRelativeFile(
      root->object, witness_name, false, &witness);
#ifdef _WIN32
  const DWORD witness_error =
      witness_present ? ERROR_SUCCESS : GetLastError();
  const bool lock_absent = !lock_present &&
      lock_error == ERROR_FILE_NOT_FOUND;
  const bool witness_absent = !witness_present &&
      witness_error == ERROR_FILE_NOT_FOUND;
#else
  const int witness_error = witness_present ? 0 : errno;
  const bool lock_absent = !lock_present && lock_error == ENOENT;
  const bool witness_absent = !witness_present &&
      witness_error == ENOENT;
#endif
  uint32_t writes = 0;
  ServiceStoreIdentity lock_identity, witness_identity;
  std::string witness_bytes;
  if (!lock_present || !witness_present) {
#ifdef _WIN32
    if (lock_file != INVALID_HANDLE_VALUE) CloseHandle(lock_file);
    if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
#else
    if (lock_file >= 0) close(lock_file);
    if (witness >= 0) close(witness);
#endif
    if (!(lock_absent && witness_absent)) {
#ifdef _WIN32
      CloseHandle(locks);
#else
      close(locks);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "acquire_service_lock", 0, true);
      return nullptr;
    }
    if (mode == "shared-existing") {
#ifdef _WIN32
      CloseHandle(locks);
#else
      close(locks);
#endif
      ServiceError(env, "SERVICE_PENDING",
                   "acquire_service_lock");
      return nullptr;
    }
    const std::vector<uint8_t> empty;
    if (!CreateServiceStoreFile(
            locks,
#ifdef _WIN32
            Wide(name),
#else
            name,
#endif
            root->roles, ServiceAclProfile::ControlFile, empty,
            &lock_identity, &writes, &lock_file) ||
        !FlushServiceStoreDirectory(locks)) {
#ifdef _WIN32
      if (lock_file != INVALID_HANDLE_VALUE) CloseHandle(lock_file);
      CloseHandle(locks);
#else
      if (lock_file >= 0) close(lock_file);
      close(locks);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "acquire_service_lock", writes, true);
      return nullptr;
    }
    witness_bytes = ServiceLockWitnessContent(
        root, scope, service_key, lock_identity);
    const std::vector<uint8_t> bytes(
        witness_bytes.begin(), witness_bytes.end());
    if (!CreateServiceStoreFile(
            root->object,
#ifdef _WIN32
            Wide(witness_name),
#else
            witness_name,
#endif
            root->roles, ServiceAclProfile::ControlFile, bytes,
            &witness_identity, &writes, &witness) ||
        !FlushServiceStoreDirectory(root->object)) {
#ifdef _WIN32
      if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
      CloseHandle(lock_file);
      CloseHandle(locks);
#else
      if (witness >= 0) close(witness);
      close(lock_file);
      close(locks);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "acquire_service_lock", writes, true);
      return nullptr;
    }
#ifdef _WIN32
    CloseHandle(witness);
    witness = INVALID_HANDLE_VALUE;
#else
    close(witness);
    witness = -1;
#endif
  } else {
    std::vector<uint8_t> empty;
    std::vector<uint8_t> bytes;
    const bool exact = CaptureServiceStoreIdentity(
            lock_file, root->roles, ServiceAclProfile::ControlFile,
            &lock_identity) &&
        ServiceStoreReadBytes(lock_file, 0, &empty) &&
        CaptureServiceStoreIdentity(
            witness, root->roles, ServiceAclProfile::ControlFile,
            &witness_identity) &&
        ServiceStoreReadBytes(witness, 64 * 1024, &bytes);
    witness_bytes.assign(bytes.begin(), bytes.end());
    if (!exact || witness_bytes != ServiceLockWitnessContent(
            root, scope, service_key, lock_identity)) {
#ifdef _WIN32
      CloseHandle(witness);
      CloseHandle(lock_file);
      CloseHandle(locks);
#else
      close(witness);
      close(lock_file);
      close(locks);
#endif
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "acquire_service_lock", 0, true);
      return nullptr;
    }
#ifdef _WIN32
    CloseHandle(witness);
    witness = INVALID_HANDLE_VALUE;
#else
    close(witness);
    witness = -1;
#endif
  }
  bool acquired = false;
#ifdef _WIN32
  OVERLAPPED overlap{};
  DWORD flags = LOCKFILE_FAIL_IMMEDIATELY |
      (mode == "exclusive" ? LOCKFILE_EXCLUSIVE_LOCK : 0);
  acquired = LockFileEx(
      lock_file, flags, 0, MAXDWORD, MAXDWORD, &overlap) != FALSE;
  const DWORD acquire_error = acquired ? ERROR_SUCCESS : GetLastError();
#else
  const int operation =
      (mode == "exclusive" ? LOCK_EX : LOCK_SH) | LOCK_NB;
  acquired = flock(lock_file, operation) == 0;
  const int acquire_error = acquired ? 0 : errno;
#endif
  if (!acquired) {
#ifdef _WIN32
    CloseHandle(lock_file);
    CloseHandle(locks);
    if (acquire_error == ERROR_LOCK_VIOLATION) {
#else
    close(lock_file);
    close(locks);
    if (acquire_error == EWOULDBLOCK ||
        acquire_error == EAGAIN) {
#endif
      ServiceError(env, "SERVICE_PENDING",
                   "acquire_service_lock", writes);
    } else {
      ServiceError(env, "SERVICE_IO_FAILED",
                   "acquire_service_lock", writes);
    }
    return nullptr;
  }
  auto* handle = new (std::nothrow) ServiceStoreHandle();
  if (!handle) {
#ifdef _WIN32
    UnlockFileEx(lock_file, 0, MAXDWORD, MAXDWORD, &overlap);
    CloseHandle(lock_file);
    CloseHandle(locks);
#else
    flock(lock_file, LOCK_UN);
    close(lock_file);
    close(locks);
#endif
    ServiceError(env, "SERVICE_IO_FAILED",
                 "acquire_service_lock", writes);
    return nullptr;
  }
  handle->env = env;
  handle->kind = ServiceStoreHandleKind::Lock;
  handle->access = mode == "exclusive"
      ? ServiceStoreAccess::Write : ServiceStoreAccess::Read;
  handle->exclusive = mode == "exclusive";
  handle->lock_held = true;
  handle->lock_rank = rank;
  handle->root_kind = "control";
  handle->root_nonce = root->root_nonce;
  handle->roles_fingerprint = root->roles_fingerprint;
  handle->roles = root->roles;
  handle->profile = ServiceAclProfile::ControlFile;
  handle->identity = lock_identity;
  handle->binding_parent_identity = locks_identity;
  handle->name = name;
  handle->witness_name = witness_name;
  handle->witness_bytes = witness_bytes;
  handle->witness_identity = witness_identity;
  handle->scope = scope;
  handle->service_key = service_key;
  handle->object = lock_file;
  handle->binding_parent = locks;
#ifdef _WIN32
  handle->lock_overlap = overlap;
#endif
  handle->root = root;
  handle->parent = root;
  ++root->children;
  if (napi_create_reference(
          env, args[0], 1, &handle->root_ref) != napi_ok) {
    CloseServiceStoreNative(handle, true);
    delete handle;
    ServiceError(env, "SERVICE_IO_FAILED",
                 "acquire_service_lock", writes);
    return nullptr;
  }
  napi_value wrapped = WrapServiceStoreHandle(env, handle);
  if (!wrapped) {
    ServiceError(env, "SERVICE_IO_FAILED",
                 "acquire_service_lock", writes);
    return nullptr;
  }
  if (!RevalidateServiceStoreHandle(handle)) {
    CloseServiceStoreNative(handle);
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "acquire_service_lock", writes, true);
    return nullptr;
  }
  gServiceStoreLocks.push_back(handle);
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", wrapped);
  napi_set_named_property(
      env, result, "identity",
      ServiceStoreIdentityValue(env, lock_identity));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

bool CloseWin32LogObserverValue(napi_env env, napi_value value);

napi_value CloseServiceHandle(napi_env env, napi_callback_info info) {
  napi_value args[1];
  ServiceStoreHandle* handle = nullptr;
  if (InventoryArgs(env, info, 1, args) &&
      CloseWin32LogObserverValue(env, args[0])) {
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
  }
  if (!InventoryArgs(env, info, 1, args) ||
      !ServiceStoreHandleArg(env, args[0], &handle, false)) {
    ServiceError(env, "SERVICE_INVALID", "close_service_handle");
    return nullptr;
  }
  if (handle->closed) {
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
  }
  if (handle->children != 0 ||
      (handle->kind == ServiceStoreHandleKind::Lock &&
       (!gServiceStoreLocks.empty() &&
        gServiceStoreLocks.back() != handle))) {
    ServiceError(env, "SERVICE_PENDING", "close_service_handle");
    return nullptr;
  }
  if (!CloseServiceStoreNative(handle)) {
    ServiceError(env, "SERVICE_IO_FAILED", "close_service_handle");
    return nullptr;
  }
  napi_value result;
  napi_get_undefined(env, &result);
  return result;
}

bool ServiceStoreDirectoryNameAllowed(
    const ServiceStoreHandle* parent, const std::string& name) {
  if (!ValidServiceStoreComponent(name)) return false;
  if (parent->namespace_name == "locks") return false;
  if (parent->kind == ServiceStoreHandleKind::Root) {
    if (parent->root_kind == "control") {
      return ServiceControlChild(name);
    }
    if (parent->root_kind == "releases" ||
        parent->root_kind == "shawl") {
      return ValidServiceFingerprint(name);
    }
  }
  if (parent->root_kind == "control" &&
      !parent->namespace_name.empty() &&
      parent->bound_service_key.empty() &&
      (parent->namespace_name == "transaction" ||
       parent->namespace_name == "manifest" ||
       parent->namespace_name == "tombstone" ||
       parent->namespace_name == "manual")) {
    return ServiceStoreServiceKey(name);
  }
  return true;
}

bool ServiceStoreDirectoryAccess(const std::string& text,
                                 ServiceStoreAccess* access,
                                 bool* create) {
  return ServiceStoreRootAccess(text, access, create);
}

napi_value OpenServiceDirectory(napi_env env, napi_callback_info info) {
  napi_value args[5];
  ServiceStoreHandle* parent = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string name, access_text;
  ServiceStoreAccess access;
  bool create = false;
  ServiceStoreIdentity expected;
  const bool expected_null =
      InventoryArgs(env, info, 5, args) &&
      ServiceStoreNull(env, args[3]);
  const bool lock_null = expected_null &&
      ServiceStoreNull(env, args[4]);
  if (!InventoryArgs(env, info, 5, args) ||
      !ServiceStoreHandleArg(env, args[0], &parent) ||
      (parent->kind != ServiceStoreHandleKind::Root &&
       parent->kind != ServiceStoreHandleKind::Directory) ||
      !InventoryString(env, args[1], &name) ||
      !InventoryString(env, args[2], &access_text) ||
      !ServiceStoreDirectoryAccess(access_text, &access, &create) ||
      !ServiceStoreDirectoryNameAllowed(parent, name) ||
      expected_null != create ||
      (!expected_null &&
       !ServiceStoreIdentityArg(env, args[3], &expected)) ||
      (create && lock_null) ||
      (!ServiceStoreNull(env, args[4]) &&
       !ServiceStoreHandleArg(env, args[4], &lock)) ||
      (access == ServiceStoreAccess::Write &&
       parent->access != ServiceStoreAccess::Write) ||
      !RevalidateServiceStoreHandle(parent)) {
    ServiceError(env, "SERVICE_INVALID", "open_service_directory");
    return nullptr;
  }
  if (!create &&
      (!ServiceProfileDirectory(expected.profile) ||
       !ServiceStoreProfileAllowed(parent, expected.profile, true))) {
    ServiceError(env, "SERVICE_INVALID", "open_service_directory");
    return nullptr;
  }
  bool mutation_authorized =
      ServiceLockAuthorizes(parent, lock, true);
  if ((create || access == ServiceStoreAccess::Write) &&
      parent->root_kind == "control" &&
      parent->bound_service_key.empty() &&
      (parent->namespace_name == "transaction" ||
       parent->namespace_name == "manifest" ||
       parent->namespace_name == "tombstone" ||
       parent->namespace_name == "manual") &&
      lock && lock->scope == "service-key" &&
      lock->service_key == name) {
    mutation_authorized =
        RevalidateServiceStoreHandle(parent) &&
        RevalidateServiceStoreHandle(lock) &&
        lock->exclusive &&
        parent->roles_fingerprint == lock->roles_fingerprint;
  }
  if ((create || access == ServiceStoreAccess::Write) &&
      !mutation_authorized) {
    ServiceError(env, "SERVICE_ACCESS_DENIED",
                 "open_service_directory");
    return nullptr;
  }
  if (parent->kind == ServiceStoreHandleKind::Root &&
      parent->root_kind == "control") {
    const auto recorded = parent->directory_identities.find(name);
    if (recorded == parent->directory_identities.end()) {
      ServiceError(env, "SERVICE_INVALID", "open_service_directory");
      return nullptr;
    }
    if (create) {
      ServiceError(env, "SERVICE_ALREADY_EXISTS",
                   "open_service_directory");
      return nullptr;
    }
    if (!SameServiceStoreIdentity(recorded->second, expected)) {
      ServiceError(env, "SERVICE_STALE", "open_service_directory");
      return nullptr;
    }
  }
#ifdef _WIN32
  HANDLE directory = INVALID_HANDLE_VALUE;
#else
  int directory = -1;
#endif
  uint32_t writes = 0;
  ServiceStoreIdentity identity;
  if (create) {
    const ServiceAclProfile profile =
        ServiceStoreDirectoryProfile(parent);
    if (!CreateServiceStoreDirectory(
            parent->object,
#ifdef _WIN32
            Wide(name),
#else
            name,
#endif
            parent->roles, profile, &identity, &writes,
            &directory) ||
        !FlushServiceStoreDirectory(parent->object)) {
#ifdef _WIN32
      const DWORD failure = GetLastError();
      if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
      const bool collision = writes == 0 &&
          (failure == ERROR_FILE_EXISTS ||
           failure == ERROR_ALREADY_EXISTS);
#else
      const int failure = errno;
      if (directory >= 0) close(directory);
      const bool collision = writes == 0 && failure == EEXIST;
#endif
      ServiceError(env,
          collision ? "SERVICE_ALREADY_EXISTS"
                    : writes == 0 ? "SERVICE_IO_FAILED"
                                  : "SERVICE_MANUAL_CLEANUP",
          "open_service_directory", writes, writes != 0);
      return nullptr;
    }
  } else {
    ServiceStoreIdentity actual;
    if (!ServiceStoreOpenRelativeDirectory(
            parent->object, name,
            access == ServiceStoreAccess::Write, &directory) ||
        !CaptureServiceStoreIdentity(
            directory, parent->roles,
            expected.profile, &actual) ||
        !SameServiceStoreIdentity(actual, expected)) {
#ifdef _WIN32
      if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
#else
      if (directory >= 0) close(directory);
#endif
      ServiceError(env, "SERVICE_STALE", "open_service_directory");
      return nullptr;
    }
    identity = expected;
  }
  auto* handle = new (std::nothrow) ServiceStoreHandle();
  if (!handle) {
#ifdef _WIN32
    CloseHandle(directory);
#else
    close(directory);
#endif
    ServiceError(env, writes == 0 ? "SERVICE_IO_FAILED"
                                  : "SERVICE_MANUAL_CLEANUP",
                 "open_service_directory", writes, writes != 0);
    return nullptr;
  }
  handle->env = env;
  handle->kind = ServiceStoreHandleKind::Directory;
  handle->access = access;
  handle->root_kind = parent->root_kind;
  handle->root_nonce = parent->root_nonce;
  handle->roles_fingerprint = parent->roles_fingerprint;
  handle->roles = parent->roles;
  handle->profile = identity.profile;
  handle->identity = identity;
  handle->name = name;
  handle->parent = parent;
  handle->root = parent->root;
  handle->namespace_name = parent->namespace_name;
  handle->bound_service_key = parent->bound_service_key;
  if (parent->kind == ServiceStoreHandleKind::Root &&
      parent->root_kind == "control") {
    handle->namespace_name = name;
  } else if (parent->root_kind == "control" &&
             handle->bound_service_key.empty() &&
             (handle->namespace_name == "transaction" ||
              handle->namespace_name == "manifest" ||
              handle->namespace_name == "tombstone" ||
              handle->namespace_name == "manual") &&
             ServiceStoreServiceKey(name)) {
    handle->bound_service_key = name;
  }
  handle->object = directory;
  ++parent->children;
  if (napi_create_reference(
          env, args[0], 1, &handle->parent_ref) != napi_ok) {
    CloseServiceStoreNative(handle, true);
    delete handle;
    ServiceError(env, writes == 0 ? "SERVICE_IO_FAILED"
                                  : "SERVICE_MANUAL_CLEANUP",
                 "open_service_directory", writes, writes != 0);
    return nullptr;
  }
  napi_value wrapped = WrapServiceStoreHandle(env, handle);
  if (!wrapped) {
    ServiceError(env, writes == 0 ? "SERVICE_IO_FAILED"
                                  : "SERVICE_MANUAL_CLEANUP",
                 "open_service_directory", writes, writes != 0);
    return nullptr;
  }
  if (!RevalidateServiceStoreHandle(handle)) {
    CloseServiceStoreNative(handle);
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "open_service_directory", writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", wrapped);
  napi_set_named_property(
      env, result, "identity",
      ServiceStoreIdentityValue(env, identity));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

struct ServiceStoreFileFacts {
  ServiceStoreIdentity identity;
  uint64_t size = 0;
  std::string sha256;
};

bool CaptureAllowedServiceFileIdentity(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    const ServiceStoreHandle* parent,
    ServiceStoreIdentity* identity) {
  const ServiceAclProfile candidates[] = {
    ServiceStoreFileProfile(parent),
    ServiceAclProfile::ReleaseFile,
    ServiceAclProfile::ReleaseExecutable,
  };
  for (ServiceAclProfile profile : candidates) {
    if (!ServiceStoreProfileAllowed(parent, profile, false)) continue;
    ServiceStoreIdentity candidate;
    if (CaptureServiceStoreIdentity(
            handle, parent->roles, profile, &candidate)) {
      *identity = candidate;
      return true;
    }
  }
  return false;
}

bool HashServiceStoreBytes(const std::vector<uint8_t>& bytes,
                           std::string* digest) {
  Sha256 hash;
  if (!hash.Ready() ||
      !hash.Update(bytes.data(), bytes.size())) return false;
  *digest = hash.Finish();
  return ValidServiceFingerprint(*digest);
}

bool ReadServiceStoreFileRetained(
    ServiceStoreHandle* parent, const std::string& name,
    size_t maximum, std::vector<uint8_t>* bytes,
    ServiceStoreFileFacts* facts, bool* absent) {
  *absent = false;
  if (!RevalidateServiceStoreHandle(parent)) return false;
#ifdef _WIN32
  HANDLE file = INVALID_HANDLE_VALUE;
  if (!ServiceStoreOpenRelativeFile(parent->object, name, false, &file)) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND) {
      *absent = true;
      return RevalidateServiceStoreHandle(parent);
    }
    return false;
  }
  FILE_BASIC_INFO before_basic{}, after_basic{};
  FILE_STANDARD_INFO before_standard{}, after_standard{};
  bool valid = CaptureAllowedServiceFileIdentity(
          file, parent, &facts->identity) &&
      GetFileInformationByHandleEx(
          file, FileBasicInfo, &before_basic, sizeof(before_basic)) &&
      GetFileInformationByHandleEx(
          file, FileStandardInfo, &before_standard,
          sizeof(before_standard)) &&
      !before_standard.Directory && !before_standard.DeletePending &&
      before_standard.EndOfFile.QuadPart >= 0 &&
      static_cast<uint64_t>(
          before_standard.EndOfFile.QuadPart) <= maximum &&
      ServiceStoreReadBytes(file, maximum, bytes) &&
      HashServiceStoreBytes(*bytes, &facts->sha256) &&
      GetFileInformationByHandleEx(
          file, FileBasicInfo, &after_basic, sizeof(after_basic)) &&
      GetFileInformationByHandleEx(
          file, FileStandardInfo, &after_standard,
          sizeof(after_standard)) &&
      std::memcmp(&before_basic, &after_basic,
                  sizeof(before_basic)) == 0 &&
      before_standard.EndOfFile.QuadPart ==
          after_standard.EndOfFile.QuadPart &&
      before_standard.AllocationSize.QuadPart ==
          after_standard.AllocationSize.QuadPart &&
      before_standard.NumberOfLinks ==
          after_standard.NumberOfLinks &&
      !after_standard.DeletePending;
  facts->size = bytes->size();
  HANDLE named = INVALID_HANDLE_VALUE;
  ServiceStoreIdentity named_identity;
  valid = valid && ServiceStoreOpenRelativeFile(
      parent->object, name, false, &named);
  valid = valid && CaptureAllowedServiceFileIdentity(
      named, parent, &named_identity) &&
      SameServiceStoreIdentity(
          named_identity, facts->identity);
  if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
  CloseHandle(file);
#else
  int file = -1;
  if (!ServiceStoreOpenRelativeFile(parent->object, name, false, &file)) {
    const int error = errno;
    if (error == ENOENT) {
      *absent = true;
      return RevalidateServiceStoreHandle(parent);
    }
    return false;
  }
  struct stat before{}, after{};
  bool valid = CaptureAllowedServiceFileIdentity(
          file, parent, &facts->identity) &&
      fstat(file, &before) == 0 && S_ISREG(before.st_mode) &&
      before.st_size >= 0 &&
      static_cast<uint64_t>(before.st_size) <= maximum &&
      ServiceStoreReadBytes(file, maximum, bytes) &&
      HashServiceStoreBytes(*bytes, &facts->sha256) &&
      fstat(file, &after) == 0 &&
      before.st_dev == after.st_dev &&
      before.st_ino == after.st_ino &&
      before.st_size == after.st_size &&
      before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
      before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
      before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
      before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  facts->size = bytes->size();
  int named = -1;
  ServiceStoreIdentity named_identity;
  valid = valid && ServiceStoreOpenRelativeFile(
      parent->object, name, false, &named);
  valid = valid && CaptureAllowedServiceFileIdentity(
      named, parent, &named_identity) &&
      SameServiceStoreIdentity(
          named_identity, facts->identity);
  if (named >= 0) close(named);
  close(file);
#endif
  return valid && RevalidateServiceStoreHandle(parent);
}

napi_value ServiceStoreFileFactsValue(
    napi_env env, const ServiceStoreFileFacts& facts) {
  napi_value result;
  napi_create_object(env, &result);
#ifdef _WIN32
  ServiceSetString(env, result, "kind", "win32-file-v1");
  ServiceSetString(env, result, "volumeSerial",
                   facts.identity.volume_serial);
  ServiceSetString(env, result, "fileId", facts.identity.file_id);
  ServiceSetDouble(env, result, "size",
                   static_cast<double>(facts.size));
  ServiceSetString(env, result, "sha256", facts.sha256);
  ServiceSetUint32(env, result, "attributes",
                   facts.identity.attributes);
#else
  ServiceSetString(env, result, "kind", "linux-file-v1");
  ServiceSetString(env, result, "device",
                   std::to_string(facts.identity.device));
  ServiceSetString(env, result, "inode",
                   std::to_string(facts.identity.inode));
  ServiceSetDouble(env, result, "size",
                   static_cast<double>(facts.size));
  ServiceSetString(env, result, "sha256", facts.sha256);
  ServiceSetUint32(env, result, "mode", facts.identity.mode);
#endif
  ServiceSetString(env, result, "owner", facts.identity.owner);
  ServiceSetString(env, result, "securitySha256",
                   facts.identity.security_sha256);
  return result;
}

bool ServiceStoreNumber(napi_env env, napi_value value,
                        uint64_t maximum, uint64_t* result) {
  napi_valuetype type;
  double number = 0;
  if (napi_typeof(env, value, &type) != napi_ok ||
      type != napi_number ||
      napi_get_value_double(env, value, &number) != napi_ok ||
      !std::isfinite(number) || number < 0 ||
      number > static_cast<double>(maximum) ||
      std::floor(number) != number) return false;
  *result = static_cast<uint64_t>(number);
  return true;
}

constexpr uint64_t kServiceArtifactMaxBytes =
    2ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr size_t kServiceArtifactChunkMax =
    1024ULL * 1024ULL;

bool ServiceStoreFileFactsArg(
    napi_env env, napi_value value,
    ServiceStoreFileFacts* facts,
    uint64_t maximum = kInventoryMaxBytes) {
#ifdef _WIN32
  const char* fields[] = {
    "kind", "volumeSerial", "fileId", "size", "sha256",
    "attributes", "owner", "securitySha256",
  };
  napi_value captured[8];
  std::string kind;
  if (!InventoryOrdinaryDataObject(env, value, fields, 8, captured) ||
      !InventoryString(env, captured[0], &kind) ||
      !InventoryString(env, captured[1],
                       &facts->identity.volume_serial) ||
      !InventoryString(env, captured[2], &facts->identity.file_id) ||
      !ServiceStoreNumber(env, captured[3],
                          maximum, &facts->size) ||
      !InventoryString(env, captured[4], &facts->sha256) ||
      !InventoryUint32(env, captured[5],
                       &facts->identity.attributes) ||
      !InventoryString(env, captured[6], &facts->identity.owner) ||
      !InventoryString(env, captured[7],
                       &facts->identity.security_sha256) ||
      kind != "win32-file-v1") return false;
#else
  const char* fields[] = {
    "kind", "device", "inode", "size", "sha256", "mode",
    "owner", "securitySha256",
  };
  napi_value captured[8];
  std::string kind, device, inode;
  if (!InventoryOrdinaryDataObject(env, value, fields, 8, captured) ||
      !InventoryString(env, captured[0], &kind) ||
      !InventoryString(env, captured[1], &device) ||
      !InventoryString(env, captured[2], &inode) ||
      !ServiceStoreNumber(env, captured[3],
                          maximum, &facts->size) ||
      !InventoryString(env, captured[4], &facts->sha256) ||
      !InventoryUint32(env, captured[5], &facts->identity.mode) ||
      !InventoryString(env, captured[6], &facts->identity.owner) ||
      !InventoryString(env, captured[7],
                       &facts->identity.security_sha256) ||
      !ParseServiceUnsignedDecimal(
          device, &facts->identity.device) ||
      !ParseServiceUnsignedDecimal(
          inode, &facts->identity.inode) ||
      kind != "linux-file-v1") return false;
#endif
  return ValidServiceFingerprint(facts->sha256) &&
      ValidServiceFingerprint(facts->identity.security_sha256);
}

bool CaptureExternalServiceFileIdentity(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    ServiceStoreIdentity* identity) {
#ifdef _WIN32
  if (handle == INVALID_HANDLE_VALUE ||
      !InventoryIdentity(handle, &identity->volume_serial,
                         &identity->file_id, &identity->attributes,
                         &identity->owner) ||
      (identity->attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
      (identity->attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
      !ServiceSecurityFingerprint(handle,
                                  &identity->security_sha256)) {
    return false;
  }
#else
  struct stat metadata{};
  if (handle < 0 || fstat(handle, &metadata) != 0 ||
      !S_ISREG(metadata.st_mode) ||
      !ServiceSecurityFingerprint(handle,
                                  &identity->security_sha256)) {
    return false;
  }
  identity->device = static_cast<uint64_t>(metadata.st_dev);
  identity->inode = static_cast<uint64_t>(metadata.st_ino);
  identity->mode = static_cast<uint32_t>(metadata.st_mode);
  identity->owner = "uid:" + std::to_string(metadata.st_uid);
#endif
  identity->profile = ServiceAclProfile::ControlFile;
  return ValidServiceFingerprint(identity->security_sha256);
}

bool CaptureExternalAncestorIdentity(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    ServiceStoreIdentity* identity) {
  if (!CapturePhysicalDirectoryIdentity(handle, identity) ||
      !ServiceSecurityFingerprint(
          handle, &identity->security_sha256)) return false;
#ifndef _WIN32
  const std::string descriptor =
      "/proc/self/fd/" + std::to_string(handle);
  errno = 0;
  acl_t defaults =
      acl_get_file(descriptor.c_str(), ACL_TYPE_DEFAULT);
  std::string default_text = "none";
  if (defaults) {
    ssize_t length = 0;
    char* text = acl_to_text(defaults, &length);
    if (!text || length < 0) {
      if (text) acl_free(text);
      acl_free(defaults);
      return false;
    }
    default_text.assign(text, static_cast<size_t>(length));
    acl_free(text);
    acl_free(defaults);
  } else if (errno != ENODATA) {
    return false;
  }
  Sha256 security;
  if (!security.Ready()) return false;
  HashField(&security,
            "gjc-remote/service-external-directory-security/v1");
  HashField(&security, identity->security_sha256);
  HashField(&security, default_text);
  identity->security_sha256 = security.Finish();
#endif
  identity->profile =
      ServiceAclProfile::PreservedContainerDirectory;
  return ValidServiceFingerprint(identity->security_sha256);
}

bool SameServicePhysicalIdentity(const ServiceStoreIdentity& left,
                                 const ServiceStoreIdentity& right) {
#ifdef _WIN32
  return left.volume_serial == right.volume_serial &&
      left.file_id == right.file_id &&
      left.attributes == right.attributes &&
      left.owner == right.owner &&
      left.security_sha256 == right.security_sha256;
#else
  return left.device == right.device &&
      left.inode == right.inode &&
      left.mode == right.mode &&
      left.owner == right.owner &&
      left.security_sha256 == right.security_sha256;
#endif
}

bool HashRetainedServiceArtifact(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    const ServiceStoreHandle* parent, bool external,
    uint64_t maximum, ServiceStoreFileFacts* facts) {
  ServiceStoreIdentity identity;
  bool valid = external
      ? CaptureExternalServiceFileIdentity(handle, &identity)
      : CaptureAllowedServiceFileIdentity(handle, parent, &identity);
  Sha256 hash;
  valid = valid && hash.Ready();
  uint64_t total = 0;
  std::vector<uint8_t> buffer;
  try {
    buffer.resize(kServiceArtifactChunkMax);
  } catch (...) {
    return false;
  }
#ifdef _WIN32
  FILE_BASIC_INFO before_basic{}, after_basic{};
  FILE_STANDARD_INFO before_standard{}, after_standard{};
  valid = valid &&
      GetFileInformationByHandleEx(
          handle, FileBasicInfo, &before_basic, sizeof(before_basic)) &&
      GetFileInformationByHandleEx(
          handle, FileStandardInfo, &before_standard,
          sizeof(before_standard)) &&
      !before_standard.Directory && !before_standard.DeletePending &&
      before_standard.EndOfFile.QuadPart >= 0 &&
      static_cast<uint64_t>(
          before_standard.EndOfFile.QuadPart) <= maximum &&
      SetFilePointer(handle, 0, nullptr, FILE_BEGIN) !=
          INVALID_SET_FILE_POINTER;
  while (valid) {
    DWORD read_bytes = 0;
    if (!ReadFile(handle, buffer.data(),
                  static_cast<DWORD>(buffer.size()),
                  &read_bytes, nullptr)) {
      valid = false;
      break;
    }
    if (read_bytes == 0) break;
    total += read_bytes;
    if (total > maximum ||
        !hash.Update(buffer.data(), read_bytes)) {
      valid = false;
      break;
    }
  }
  valid = valid &&
      GetFileInformationByHandleEx(
          handle, FileBasicInfo, &after_basic, sizeof(after_basic)) &&
      GetFileInformationByHandleEx(
          handle, FileStandardInfo, &after_standard,
          sizeof(after_standard)) &&
      before_basic.CreationTime.QuadPart ==
          after_basic.CreationTime.QuadPart &&
      before_basic.LastWriteTime.QuadPart ==
          after_basic.LastWriteTime.QuadPart &&
      before_basic.ChangeTime.QuadPart ==
          after_basic.ChangeTime.QuadPart &&
      before_basic.FileAttributes == after_basic.FileAttributes &&
      before_standard.EndOfFile.QuadPart ==
          after_standard.EndOfFile.QuadPart &&
      before_standard.AllocationSize.QuadPart ==
          after_standard.AllocationSize.QuadPart &&
      before_standard.NumberOfLinks ==
          after_standard.NumberOfLinks &&
      !after_standard.DeletePending &&
      total == static_cast<uint64_t>(
          before_standard.EndOfFile.QuadPart) &&
      SetFilePointer(handle, 0, nullptr, FILE_BEGIN) !=
          INVALID_SET_FILE_POINTER;
#else
  struct stat before{}, after{};
  valid = valid && fstat(handle, &before) == 0 &&
      S_ISREG(before.st_mode) && before.st_size >= 0 &&
      static_cast<uint64_t>(before.st_size) <= maximum &&
      lseek(handle, 0, SEEK_SET) >= 0;
  while (valid) {
    const ssize_t read_bytes =
        read(handle, buffer.data(), buffer.size());
    if (read_bytes < 0 && errno == EINTR) continue;
    if (read_bytes < 0) {
      valid = false;
      break;
    }
    if (read_bytes == 0) break;
    total += static_cast<uint64_t>(read_bytes);
    if (total > maximum ||
        !hash.Update(buffer.data(),
                     static_cast<size_t>(read_bytes))) {
      valid = false;
      break;
    }
  }
  valid = valid && fstat(handle, &after) == 0 &&
      before.st_dev == after.st_dev &&
      before.st_ino == after.st_ino &&
      before.st_size == after.st_size &&
      before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
      before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
      before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
      before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
      total == static_cast<uint64_t>(before.st_size) &&
      lseek(handle, 0, SEEK_SET) >= 0;
#endif
  const std::string digest = valid ? hash.Finish() : "";
  if (!valid || !ValidServiceFingerprint(digest)) return false;
  ServiceStoreIdentity final_identity;
  if (!(external
          ? CaptureExternalServiceFileIdentity(
                handle, &final_identity)
          : CaptureAllowedServiceFileIdentity(
                handle, parent, &final_identity)) ||
      !SameServicePhysicalIdentity(identity, final_identity)) {
    return false;
  }
  facts->identity = identity;
  facts->size = total;
  facts->sha256 = digest;
  return true;
}

bool SameServiceStoreFileFacts(
    const ServiceStoreFileFacts& left,
    const ServiceStoreFileFacts& right) {
  ServiceStoreIdentity left_identity = left.identity;
  ServiceStoreIdentity right_identity = right.identity;
  // The flattened read-file shape intentionally omits the ACL profile;
  // compare the physical/security facts and bytes while the retained open
  // independently verifies the allowed profile.
  left_identity.profile = ServiceAclProfile::ControlFile;
  right_identity.profile = ServiceAclProfile::ControlFile;
  return SameServiceStoreIdentity(left_identity, right_identity) &&
      left.size == right.size && left.sha256 == right.sha256;
}

bool ServiceArtifactNativeFileSize(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    uint64_t* size) {
#ifdef _WIN32
  FILE_STANDARD_INFO information{};
  if (!GetFileInformationByHandleEx(
          handle, FileStandardInfo, &information,
          sizeof(information)) ||
      information.Directory || information.DeletePending ||
      information.EndOfFile.QuadPart < 0) return false;
  *size = static_cast<uint64_t>(
      information.EndOfFile.QuadPart);
#else
  struct stat metadata{};
  if (fstat(handle, &metadata) != 0 ||
      !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
    return false;
  }
  *size = static_cast<uint64_t>(metadata.st_size);
#endif
  return true;
}

bool ServiceArtifactStateToken(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    std::string* token) {
  std::ostringstream output;
#ifdef _WIN32
  FILE_BASIC_INFO basic{};
  FILE_STANDARD_INFO standard{};
  if (!GetFileInformationByHandleEx(
          handle, FileBasicInfo, &basic, sizeof(basic)) ||
      !GetFileInformationByHandleEx(
          handle, FileStandardInfo, &standard, sizeof(standard)) ||
      standard.Directory || standard.DeletePending ||
      standard.EndOfFile.QuadPart < 0) return false;
  output << basic.CreationTime.QuadPart << ":"
         << basic.LastWriteTime.QuadPart << ":"
         << basic.ChangeTime.QuadPart << ":"
         << basic.FileAttributes << ":"
         << standard.AllocationSize.QuadPart << ":"
         << standard.EndOfFile.QuadPart << ":"
         << standard.NumberOfLinks;
#else
  struct stat metadata{};
  if (fstat(handle, &metadata) != 0 ||
      !S_ISREG(metadata.st_mode) || metadata.st_size < 0) {
    return false;
  }
  output << metadata.st_dev << ":" << metadata.st_ino << ":"
         << metadata.st_size << ":" << metadata.st_mode << ":"
         << metadata.st_uid << ":" << metadata.st_gid << ":"
         << metadata.st_nlink << ":"
         << metadata.st_mtim.tv_sec << ":"
         << metadata.st_mtim.tv_nsec << ":"
         << metadata.st_ctim.tv_sec << ":"
         << metadata.st_ctim.tv_nsec;
#endif
  *token = output.str();
  return !token->empty();
}

bool RevalidateExternalArtifactAncestors(
    ServiceStoreHandle* handle) {
  if (handle->external_ancestors.empty() ||
      handle->external_ancestor_identities.size() !=
          handle->external_ancestors.size() ||
      handle->external_components.size() + 1 !=
          handle->external_ancestors.size()) return false;
#ifdef _WIN32
  HANDLE root = OpenWindowsRoot(
      Wide(handle->fixed_parent_path),
      kWindowsTraversalAccess | READ_CONTROL);
  ServiceStoreIdentity identity;
  bool valid = root != INVALID_HANDLE_VALUE &&
      CaptureExternalAncestorIdentity(root, &identity) &&
      SameServicePhysicalIdentity(
          identity, handle->external_ancestor_identities[0]);
  if (root != INVALID_HANDLE_VALUE) CloseHandle(root);
  for (size_t index = 0; valid &&
       index < handle->external_components.size(); ++index) {
    ServiceStoreIdentity held;
    HANDLE named = OpenWindowsRelative(
        handle->external_ancestors[index],
        Wide(handle->external_components[index]),
        kWindowsTraversalAccess | READ_CONTROL, kFileOpen,
        VerifiedObjectType::Directory);
    valid = named != INVALID_HANDLE_VALUE &&
        CaptureExternalAncestorIdentity(named, &identity) &&
        CaptureExternalAncestorIdentity(
            handle->external_ancestors[index + 1], &held) &&
        SameServicePhysicalIdentity(
            identity,
            handle->external_ancestor_identities[index + 1]) &&
        SameServicePhysicalIdentity(
            held,
            handle->external_ancestor_identities[index + 1]);
    if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
  }
#else
  int root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  ServiceStoreIdentity identity;
  bool valid = root >= 0 &&
      CaptureExternalAncestorIdentity(root, &identity) &&
      SameServicePhysicalIdentity(
          identity, handle->external_ancestor_identities[0]);
  if (root >= 0) close(root);
  for (size_t index = 0; valid &&
       index < handle->external_components.size(); ++index) {
    ServiceStoreIdentity held;
    int named = openat(
        handle->external_ancestors[index],
        handle->external_components[index].c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    valid = named >= 0 &&
        CaptureExternalAncestorIdentity(named, &identity) &&
        CaptureExternalAncestorIdentity(
            handle->external_ancestors[index + 1], &held) &&
        SameServicePhysicalIdentity(
            identity,
            handle->external_ancestor_identities[index + 1]) &&
        SameServicePhysicalIdentity(
            held,
            handle->external_ancestor_identities[index + 1]);
    if (named >= 0) close(named);
  }
#endif
  return valid;
}

#ifdef _WIN32
bool CaptureServiceObservationIdentity(
    HANDLE handle, const InventoryRoles& roles,
    ServiceAclProfile profile, ServiceStoreIdentity* identity) {
  if (handle == INVALID_HANDLE_VALUE ||
      !ServiceProfileExternal(profile) ||
      !VerifyWindowsServiceFileAcl(handle, roles, profile) ||
      !InventoryIdentity(handle, &identity->volume_serial,
                         &identity->file_id, &identity->attributes,
                         &identity->owner) ||
      !ServiceSecurityFingerprint(handle,
                                  &identity->security_sha256)) {
    return false;
  }
  identity->profile = profile;
  return ValidServiceFingerprint(identity->security_sha256);
}

bool InferServiceExternalAclPolicy(
    HANDLE handle, const InventoryRoles& roles,
    ServiceExternalProfile profile, bool directory,
    ServiceExternalAclPolicy* policy,
    ServiceStoreIdentity* identity) {
  const ServiceExternalAclPolicy candidates[] = {
    ServiceExternalAclPolicy::Bot,
    ServiceExternalAclPolicy::Daemon,
    ServiceExternalAclPolicy::SdkInstall,
  };
  size_t matches = 0;
  for (ServiceExternalAclPolicy candidate : candidates) {
    if (!ServiceExternalPolicyAllowed(profile, candidate)) continue;
    const ServiceAclProfile acl_profile = directory
        ? ServiceExternalDirectoryProfile(profile, candidate)
        : ServiceExternalFileProfile(profile, candidate);
    ServiceStoreIdentity observed;
    if (!CaptureServiceObservationIdentity(
            handle, roles, acl_profile, &observed)) continue;
    ++matches;
    *policy = candidate;
    *identity = observed;
  }
  if (matches != 1) {
    SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }
  return true;
}

bool RevalidateServiceExternalRoot(ServiceStoreHandle* handle) {
  if (!handle || handle->kind != ServiceStoreHandleKind::ExternalRoot ||
      !ServiceStoreNativeHandleOpen(handle) ||
      !ServiceActorAuthorized(handle->roles) ||
      handle->external_ancestors.empty() ||
      handle->external_ancestor_identities.size() !=
          handle->external_ancestors.size() ||
      handle->external_components.size() + 1 !=
          handle->external_ancestors.size()) {
    return false;
  }
  std::string roles_fingerprint;
  ServiceExternalProfile external_profile;
  if (!ServiceStoreRolesFingerprint(handle->roles, &roles_fingerprint) ||
      roles_fingerprint != handle->roles_fingerprint ||
      !ParseServiceExternalProfile(
          handle->external_profile, &external_profile) ||
      (handle->external_root_absent
          ? handle->external_policy !=
              ServiceExternalAclPolicy::Unresolved
          : !ServiceExternalPolicyAllowed(
              external_profile, handle->external_policy))) return false;

  HANDLE root = OpenWindowsRoot(
      Wide(handle->fixed_parent_path),
      kWindowsTraversalAccess | READ_CONTROL);
  ServiceStoreIdentity current_identity;
  bool valid = root != INVALID_HANDLE_VALUE &&
      CaptureExternalAncestorIdentity(root, &current_identity) &&
      SameServicePhysicalIdentity(
          current_identity, handle->external_ancestor_identities[0]);
  if (root != INVALID_HANDLE_VALUE) CloseHandle(root);
  for (size_t index = 0; valid &&
       index < handle->external_components.size(); ++index) {
    HANDLE named = OpenWindowsRelative(
        handle->external_ancestors[index],
        Wide(handle->external_components[index]),
        kWindowsTraversalAccess | READ_CONTROL, kFileOpen,
        VerifiedObjectType::Directory);
    ServiceStoreIdentity held_identity;
    valid = named != INVALID_HANDLE_VALUE &&
        CaptureExternalAncestorIdentity(named, &current_identity) &&
        CaptureExternalAncestorIdentity(
            handle->external_ancestors[index + 1], &held_identity) &&
        SameServicePhysicalIdentity(
            current_identity,
            handle->external_ancestor_identities[index + 1]) &&
        SameServicePhysicalIdentity(
            held_identity,
            handle->external_ancestor_identities[index + 1]);
    if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
  }
  if (!valid) return false;

  if (handle->external_root_absent) {
    if (handle->external_missing_segments.empty()) return false;
    ServiceStoreIdentity held_anchor;
    if (!CaptureExternalAncestorIdentity(
            handle->object, &held_anchor) ||
        !SameServicePhysicalIdentity(
            held_anchor, handle->binding_parent_identity) ||
        !SameServicePhysicalIdentity(
            held_anchor,
            handle->external_ancestor_identities.back())) return false;
    HANDLE missing = OpenWindowsRelative(
        handle->external_ancestors.back(),
        Wide(handle->external_missing_segments.front()),
        kWindowsTraversalAccess | READ_CONTROL, kFileOpen,
        VerifiedObjectType::Directory);
    const DWORD error = missing == INVALID_HANDLE_VALUE
        ? GetLastError() : ERROR_SUCCESS;
    if (missing != INVALID_HANDLE_VALUE) CloseHandle(missing);
    return missing == INVALID_HANDLE_VALUE &&
        (error == ERROR_FILE_NOT_FOUND ||
         error == ERROR_PATH_NOT_FOUND) &&
        ServiceActorAuthorized(handle->roles);
  }

  HANDLE named_root = OpenWindowsRelative(
      handle->external_ancestors.back(), Wide(handle->name),
      FILE_GENERIC_READ | READ_CONTROL, kFileOpen,
      VerifiedObjectType::Directory);
  ServiceStoreIdentity named_identity, held_identity;
  const bool exact = named_root != INVALID_HANDLE_VALUE &&
      CaptureServiceObservationIdentity(
          named_root, handle->roles,
          ServiceExternalDirectoryProfile(
              external_profile, handle->external_policy),
          &named_identity) &&
      CaptureServiceObservationIdentity(
          handle->object, handle->roles,
          ServiceExternalDirectoryProfile(
              external_profile, handle->external_policy),
          &held_identity) &&
      SameServiceStoreIdentity(named_identity, handle->identity) &&
      SameServiceStoreIdentity(held_identity, handle->identity);
  if (named_root != INVALID_HANDLE_VALUE) CloseHandle(named_root);
  return exact && ServiceActorAuthorized(handle->roles);
}
#endif

bool RevalidateServiceArtifactStream(ServiceStoreHandle* handle) {
  if (!ServiceStoreNativeHandleOpen(handle)) return false;
  if (handle->kind == ServiceStoreHandleKind::ArtifactSourceReader) {
    if (!RevalidateExternalArtifactAncestors(handle)) return false;
#ifdef _WIN32
    HANDLE named = OpenWindowsRelative(
        handle->external_ancestors.back(), Wide(handle->name),
        GENERIC_READ | READ_CONTROL, kFileOpen,
        VerifiedObjectType::File);
#else
    int named = openat(
        handle->external_ancestors.back(), handle->name.c_str(),
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat named_metadata{};
    const bool named_regular = named >= 0 &&
        fstat(named, &named_metadata) == 0 &&
        S_ISREG(named_metadata.st_mode);
#endif
    ServiceStoreIdentity retained, named_identity;
    uint64_t retained_size = 0, named_size = 0;
    std::string retained_state, named_state;
    const bool valid =
#ifndef _WIN32
        named_regular &&
#endif
        CaptureExternalServiceFileIdentity(
            handle->object, &retained) &&
        CaptureExternalServiceFileIdentity(named, &named_identity) &&
        SameServicePhysicalIdentity(retained, handle->identity) &&
        SameServicePhysicalIdentity(named_identity, handle->identity) &&
        ServiceArtifactNativeFileSize(
            handle->object, &retained_size) &&
        ServiceArtifactNativeFileSize(named, &named_size) &&
        retained_size == named_size &&
        retained_size == handle->stream_limit &&
        ServiceArtifactStateToken(
            handle->object, &retained_state) &&
        ServiceArtifactStateToken(named, &named_state) &&
        retained_state == named_state &&
        retained_state == handle->stream_state;
#ifdef _WIN32
    if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
#else
    if (named >= 0) close(named);
#endif
    return valid;
  }
  if (!handle->parent ||
      !handle->lock ||
      !RevalidateServiceStoreHandle(handle->parent) ||
      !RevalidateServiceStoreHandle(handle->lock) ||
      handle->lock->scope != "artifact" ||
      !handle->lock->lock_held) return false;
#ifdef _WIN32
  HANDLE named = INVALID_HANDLE_VALUE;
#else
  int named = -1;
#endif
  if (!ServiceStoreOpenRelativeFile(
          handle->parent->object, handle->name, false, &named)) {
    return false;
  }
  ServiceStoreIdentity retained, named_identity;
  const bool identities = CaptureServiceStoreIdentity(
          handle->object, handle->roles, handle->profile, &retained) &&
      CaptureServiceStoreIdentity(
          named, handle->roles, handle->profile, &named_identity) &&
      SameServicePhysicalIdentity(retained, handle->identity) &&
      SameServicePhysicalIdentity(
          named_identity, handle->identity);
  uint64_t retained_size = 0, named_size = 0;
  std::string retained_state, named_state;
  const bool sizes = identities &&
      ServiceArtifactNativeFileSize(
          handle->object, &retained_size) &&
      ServiceArtifactNativeFileSize(named, &named_size) &&
      retained_size == named_size &&
      (handle->kind != ServiceStoreHandleKind::ArtifactReader ||
       retained_size == handle->stream_limit) &&
      (handle->kind != ServiceStoreHandleKind::ArtifactWriter ||
       retained_size == handle->stream_offset) &&
      (handle->kind == ServiceStoreHandleKind::ArtifactWriter ||
       (ServiceArtifactStateToken(
            handle->object, &retained_state) &&
        ServiceArtifactStateToken(named, &named_state) &&
        retained_state == named_state &&
        retained_state == handle->stream_state));
#ifdef _WIN32
  CloseHandle(named);
#else
  close(named);
#endif
  return sizes;
}

bool ServiceStoreBuffer(napi_env env, napi_value value,
                        std::vector<uint8_t>* bytes) {
  bool buffer = false;
  void* raw = nullptr;
  size_t length = 0;
  if (napi_is_buffer(env, value, &buffer) != napi_ok || !buffer ||
      napi_get_buffer_info(env, value, &raw, &length) != napi_ok ||
      length > kInventoryMaxBytes) return false;
  bytes->clear();
  if (length != 0) {
    try {
      bytes->assign(
          static_cast<uint8_t*>(raw),
          static_cast<uint8_t*>(raw) + length);
    } catch (...) {
      bytes->clear();
      return false;
    }
  }
  return true;
}

bool ServiceArtifactChunkBuffer(
    napi_env env, napi_value value,
    std::vector<uint8_t>* bytes, bool allow_empty = false) {
  bool buffer = false;
  void* raw = nullptr;
  size_t length = 0;
  if (napi_is_buffer(env, value, &buffer) != napi_ok || !buffer ||
      napi_get_buffer_info(env, value, &raw, &length) != napi_ok ||
      (!allow_empty && length == 0) ||
      length > kServiceArtifactChunkMax) return false;
  bytes->clear();
  if (length != 0) {
    try {
      bytes->assign(
          static_cast<uint8_t*>(raw),
          static_cast<uint8_t*>(raw) + length);
    } catch (...) {
      bytes->clear();
      return false;
    }
  }
  return true;
}

bool BindServiceArtifactDependencies(
    napi_env env, ServiceStoreHandle* stream,
    ServiceStoreHandle* parent, napi_value parent_value,
    ServiceStoreHandle* lock, napi_value lock_value) {
  stream->parent = parent;
  stream->root = parent->root;
  stream->lock = lock;
  ++parent->children;
  ++lock->children;
  if (napi_create_reference(
          env, parent_value, 1, &stream->parent_ref) != napi_ok ||
      napi_create_reference(
          env, lock_value, 1, &stream->lock_ref) != napi_ok) {
    ReleaseServiceStoreReferences(stream);
    return false;
  }
  return true;
}

napi_value ReadServiceFile(napi_env env, napi_callback_info info) {
  napi_value args[3];
  ServiceStoreHandle* parent = nullptr;
  std::string name;
  int64_t maximum = 0;
  if (!InventoryArgs(env, info, 3, args) ||
      !ServiceStoreHandleArg(env, args[0], &parent) ||
      (parent->kind != ServiceStoreHandleKind::Root &&
       parent->kind != ServiceStoreHandleKind::Directory) ||
      !InventoryString(env, args[1], &name) ||
      !ValidServiceStoreComponent(name) ||
      !InventoryMaximumBytes(env, args[2], &maximum)) {
    ServiceError(env, "SERVICE_INVALID", "read_service_file");
    return nullptr;
  }
  std::vector<uint8_t> bytes;
  ServiceStoreFileFacts facts;
  bool absent = false;
  if (!ReadServiceStoreFileRetained(
          parent, name, static_cast<size_t>(maximum),
          &bytes, &facts, &absent)) {
    ServiceError(env, "SERVICE_STALE", "read_service_file",
                 0, true);
    return nullptr;
  }
  if (absent) {
    napi_value result;
    napi_get_null(env, &result);
    return result;
  }
  napi_value result, data;
  napi_create_object(env, &result);
  napi_create_buffer_copy(
      env, bytes.size(), bytes.data(), nullptr, &data);
  napi_set_named_property(env, result, "bytes", data);
  napi_set_named_property(
      env, result, "facts",
      ServiceStoreFileFactsValue(env, facts));
  ServiceSetUint32(env, result, "writes", 0);
  return result;
}

napi_value BeginServiceArtifactWrite(
    napi_env env, napi_callback_info info) {
  napi_value args[5];
  ServiceStoreHandle* parent = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string name, expected_sha256;
  uint64_t expected_size = 0;
  if (!InventoryArgs(env, info, 5, args) ||
      !ServiceStoreHandleArg(env, args[0], &parent) ||
      parent->kind != ServiceStoreHandleKind::Directory ||
      parent->root_kind != "staging" ||
      parent->profile != ServiceAclProfile::StagingDirectory ||
      parent->access != ServiceStoreAccess::Write ||
      !InventoryString(env, args[1], &name) ||
      !ValidServiceStoreComponent(name) ||
      !ServiceStoreNumber(env, args[2],
                          kServiceArtifactMaxBytes,
                          &expected_size) ||
      !InventoryString(env, args[3], &expected_sha256) ||
      !ValidServiceFingerprint(expected_sha256) ||
      !ServiceStoreHandleArg(env, args[4], &lock) ||
      !ServiceLockAuthorizes(parent, lock, true)) {
    ServiceError(env, "SERVICE_INVALID",
                 "begin_service_artifact_write");
    return nullptr;
  }
#ifdef _WIN32
  HANDLE file = INVALID_HANDLE_VALUE;
#else
  int file = -1;
#endif
  ServiceStoreIdentity identity;
  const std::vector<uint8_t> empty;
  uint32_t writes = 0;
  if (!CreateServiceStoreFile(
          parent->object,
#ifdef _WIN32
          Wide(name),
#else
          name,
#endif
          parent->roles, ServiceAclProfile::StagingFile,
          empty, &identity, &writes, &file) ||
      !FlushServiceStoreDirectory(parent->object)) {
#ifdef _WIN32
    const DWORD error = GetLastError();
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    const bool collision = writes == 0 &&
        (error == ERROR_ALREADY_EXISTS ||
         error == ERROR_FILE_EXISTS);
#else
    const int error = errno;
    if (file >= 0) close(file);
    const bool collision = writes == 0 && error == EEXIST;
#endif
    ServiceError(env,
        collision ? "SERVICE_ALREADY_EXISTS"
                  : writes == 0 ? "SERVICE_IO_FAILED"
                                : "SERVICE_MANUAL_CLEANUP",
        "begin_service_artifact_write", writes, writes != 0);
    return nullptr;
  }
  auto* writer = new (std::nothrow) ServiceStoreHandle();
  if (!writer) {
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "begin_service_artifact_write", writes, true);
    return nullptr;
  }
  writer->env = env;
  writer->kind = ServiceStoreHandleKind::ArtifactWriter;
  writer->access = ServiceStoreAccess::Write;
  writer->root_kind = parent->root_kind;
  writer->root_nonce = parent->root_nonce;
  writer->roles_fingerprint = parent->roles_fingerprint;
  writer->roles = parent->roles;
  writer->profile = ServiceAclProfile::StagingFile;
  writer->identity = identity;
  writer->name = name;
  writer->stream_limit = expected_size;
  writer->expected_sha256 = expected_sha256;
  writer->object = file;
  try {
    writer->stream_hash = std::make_unique<Sha256>();
  } catch (...) {
    writer->stream_hash.reset();
  }
  if (!writer->stream_hash || !writer->stream_hash->Ready() ||
      !BindServiceArtifactDependencies(
          env, writer, parent, args[0], lock, args[4])) {
    CloseServiceStoreNative(writer, true);
    delete writer;
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "begin_service_artifact_write", writes, true);
    return nullptr;
  }
  napi_value wrapped = WrapServiceStoreHandle(env, writer);
  if (!wrapped) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "begin_service_artifact_write", writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", wrapped);
  napi_set_named_property(
      env, result, "identity",
      ServiceStoreIdentityValue(env, identity));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

napi_value WriteServiceArtifactChunk(
    napi_env env, napi_callback_info info) {
  napi_value args[3];
  ServiceStoreHandle* writer = nullptr;
  uint64_t expected_offset = 0;
  std::vector<uint8_t> bytes;
  if (!InventoryArgs(env, info, 3, args) ||
      !ServiceStoreHandleArg(env, args[0], &writer) ||
      writer->kind != ServiceStoreHandleKind::ArtifactWriter ||
      writer->completed || writer->poisoned ||
      !ServiceStoreNumber(env, args[1],
                          kServiceArtifactMaxBytes,
                          &expected_offset) ||
      !ServiceArtifactChunkBuffer(env, args[2], &bytes) ||
      expected_offset != writer->stream_offset ||
      writer->stream_offset > writer->stream_limit ||
      bytes.size() > writer->stream_limit - writer->stream_offset ||
      !RevalidateServiceArtifactStream(writer)) {
    ServiceError(env,
        writer && writer->kind ==
            ServiceStoreHandleKind::ArtifactWriter
            ? "SERVICE_STALE" : "SERVICE_INVALID",
        "write_service_artifact_chunk");
    return nullptr;
  }
  size_t offset = 0;
  bool wrote = false;
#ifdef _WIN32
  LARGE_INTEGER position{};
  position.QuadPart =
      static_cast<LONGLONG>(writer->stream_offset);
  bool valid = SetFilePointerEx(
      writer->object, position, nullptr, FILE_BEGIN) != FALSE;
  while (valid && offset < bytes.size()) {
    DWORD count = 0;
    const DWORD chunk = static_cast<DWORD>(
        bytes.size() - offset);
    if (!WriteFile(writer->object, bytes.data() + offset,
                   chunk, &count, nullptr) ||
        count == 0) {
      valid = false;
      break;
    }
    wrote = true;
    offset += count;
  }
#else
  bool valid = lseek(
      writer->object,
      static_cast<off_t>(writer->stream_offset),
      SEEK_SET) >= 0;
  while (valid && offset < bytes.size()) {
    const ssize_t count = write(
        writer->object, bytes.data() + offset,
        bytes.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      valid = false;
      break;
    }
    wrote = true;
    offset += static_cast<size_t>(count);
  }
#endif
  writer->stream_offset += offset;
  const uint32_t writes = wrote ? 1 : 0;
  if (!valid || offset != bytes.size() ||
      !writer->stream_hash->Update(
          bytes.data(), bytes.size())) {
    writer->poisoned = true;
    ServiceError(env,
        writes == 0 ? "SERVICE_IO_FAILED"
                    : "SERVICE_MANUAL_CLEANUP",
        "write_service_artifact_chunk", writes, writes != 0);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetDouble(env, result, "nextOffset",
                   static_cast<double>(writer->stream_offset));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

napi_value FinishServiceArtifactWrite(
    napi_env env, napi_callback_info info) {
  napi_value args[2];
  ServiceStoreHandle* writer = nullptr;
  std::string profile_text;
  ServiceAclProfile final_profile;
  if (!InventoryArgs(env, info, 2, args) ||
      !ServiceStoreHandleArg(env, args[0], &writer) ||
      writer->kind != ServiceStoreHandleKind::ArtifactWriter ||
      writer->completed || writer->poisoned ||
      !InventoryString(env, args[1], &profile_text) ||
      !ParseServiceAclProfile(profile_text, &final_profile) ||
      (final_profile != ServiceAclProfile::StagingFile &&
       final_profile != ServiceAclProfile::ReleaseFile &&
       final_profile != ServiceAclProfile::ReleaseExecutable) ||
      !RevalidateServiceArtifactStream(writer)) {
    ServiceError(env, "SERVICE_INVALID",
                 "finish_service_artifact_write");
    return nullptr;
  }
  const std::string digest =
      writer->stream_hash ? writer->stream_hash->Finish() : "";
  if (writer->stream_offset != writer->stream_limit ||
      !ValidServiceFingerprint(digest) ||
      digest != writer->expected_sha256) {
    writer->poisoned = true;
    const bool closed = CloseServiceStoreNative(writer);
    ServiceError(env,
        closed ? "SERVICE_STALE"
               : "SERVICE_MANUAL_CLEANUP",
        "finish_service_artifact_write", 0, !closed);
    return nullptr;
  }
  uint32_t writes = 0;
  bool acl_mutated = false;
#ifdef _WIN32
  bool valid = FlushFileBuffers(writer->object) != FALSE;
  if (valid && final_profile != writer->profile) {
    valid = ApplyWindowsServiceFileAcl(
        writer->object, writer->roles, final_profile,
        &acl_mutated);
    if (acl_mutated) ++writes;
  }
  valid = valid && FlushFileBuffers(writer->object) != FALSE;
#else
  bool valid = fsync(writer->object) == 0;
  if (valid && final_profile != writer->profile) {
    valid = BuildPosixServiceAcl(
        writer->object, writer->roles, final_profile, true,
        &acl_mutated);
    if (acl_mutated) ++writes;
  }
  valid = valid && fsync(writer->object) == 0;
#endif
  ServiceStoreIdentity final_identity;
  valid = valid && CaptureServiceStoreIdentity(
      writer->object, writer->roles, final_profile,
      &final_identity);
  if (valid) {
    writer->profile = final_profile;
    writer->identity = final_identity;
    valid = RevalidateServiceArtifactStream(writer) &&
        FlushServiceStoreDirectory(writer->parent->object);
  }
  ServiceStoreFileFacts facts;
  valid = valid && HashRetainedServiceArtifact(
      writer->object, writer->parent, false,
      kServiceArtifactMaxBytes, &facts) &&
      facts.size == writer->stream_limit &&
      facts.sha256 == digest &&
      SameServicePhysicalIdentity(
          facts.identity, final_identity);
  if (!valid) {
    writer->poisoned = true;
    CloseServiceStoreNative(writer);
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "finish_service_artifact_write", writes, true);
    return nullptr;
  }
  writer->completed = true;
  if (!CloseServiceStoreNative(writer)) {
    ServiceError(env, "SERVICE_IO_FAILED",
                 "finish_service_artifact_write", writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(
      env, result, "facts",
      ServiceStoreFileFactsValue(env, facts));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

bool ServiceArtifactExpectedFacts(
    napi_env env, napi_value value, bool* present,
    ServiceStoreFileFacts* facts) {
  if (ServiceStoreNull(env, value)) {
    *present = false;
    return true;
  }
  *present = true;
  return ServiceStoreFileFactsArg(
      env, value, facts, kServiceArtifactMaxBytes);
}

napi_value OpenServiceArtifactReader(
    napi_env env, napi_callback_info info) {
  napi_value args[5];
  ServiceStoreHandle* parent = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string name;
  uint64_t maximum = 0;
  bool expected_present = false;
  ServiceStoreFileFacts expected;
  if (!InventoryArgs(env, info, 5, args) ||
      !ServiceStoreHandleArg(env, args[0], &parent) ||
      (parent->kind != ServiceStoreHandleKind::Root &&
       parent->kind != ServiceStoreHandleKind::Directory) ||
      (parent->root_kind != "staging" &&
       parent->root_kind != "releases" &&
       parent->root_kind != "shawl") ||
      !InventoryString(env, args[1], &name) ||
      !ValidServiceStoreComponent(name) ||
      !ServiceStoreNumber(env, args[2],
                          kServiceArtifactMaxBytes, &maximum) ||
      !ServiceArtifactExpectedFacts(
          env, args[3], &expected_present, &expected) ||
      !ServiceStoreHandleArg(env, args[4], &lock) ||
      !ServiceLockAuthorizes(parent, lock, false)) {
    ServiceError(env, "SERVICE_INVALID",
                 "open_service_artifact_reader");
    return nullptr;
  }
#ifdef _WIN32
  HANDLE file = INVALID_HANDLE_VALUE;
#else
  int file = -1;
#endif
  if (!ServiceStoreOpenRelativeFile(
          parent->object, name, false, &file)) {
#ifdef _WIN32
    const bool absent = GetLastError() == ERROR_FILE_NOT_FOUND;
#else
    const bool absent = errno == ENOENT;
#endif
    if (absent && RevalidateServiceStoreHandle(parent)) {
      if (expected_present) {
        ServiceError(env, "SERVICE_STALE",
                     "open_service_artifact_reader");
        return nullptr;
      }
      napi_value result;
      napi_get_null(env, &result);
      return result;
    }
    ServiceError(env, "SERVICE_STALE",
                 "open_service_artifact_reader", 0, true);
    return nullptr;
  }
  ServiceStoreFileFacts facts;
  if (!HashRetainedServiceArtifact(
          file, parent, false, maximum, &facts) ||
      (expected_present &&
       !SameServiceStoreFileFacts(facts, expected))) {
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
    ServiceError(env, "SERVICE_STALE",
                 "open_service_artifact_reader");
    return nullptr;
  }
  auto* reader = new (std::nothrow) ServiceStoreHandle();
  if (!reader) {
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
    ServiceError(env, "SERVICE_IO_FAILED",
                 "open_service_artifact_reader");
    return nullptr;
  }
  reader->env = env;
  reader->kind = ServiceStoreHandleKind::ArtifactReader;
  reader->access = ServiceStoreAccess::Read;
  reader->root_kind = parent->root_kind;
  reader->root_nonce = parent->root_nonce;
  reader->roles_fingerprint = parent->roles_fingerprint;
  reader->roles = parent->roles;
  reader->profile = facts.identity.profile;
  reader->identity = facts.identity;
  reader->name = name;
  reader->stream_limit = facts.size;
  reader->expected_sha256 = facts.sha256;
  reader->object = file;
  try {
    reader->stream_hash = std::make_unique<Sha256>();
  } catch (...) {
    reader->stream_hash.reset();
  }
  if (!reader->stream_hash || !reader->stream_hash->Ready() ||
      !ServiceArtifactStateToken(
          reader->object, &reader->stream_state) ||
      !BindServiceArtifactDependencies(
          env, reader, parent, args[0], lock, args[4]) ||
      !RevalidateServiceArtifactStream(reader)) {
    CloseServiceStoreNative(reader, true);
    delete reader;
    ServiceError(env, "SERVICE_IO_FAILED",
                 "open_service_artifact_reader");
    return nullptr;
  }
  napi_value wrapped = WrapServiceStoreHandle(env, reader);
  if (!wrapped) {
    ServiceError(env, "SERVICE_IO_FAILED",
                 "open_service_artifact_reader");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", wrapped);
  napi_set_named_property(
      env, result, "facts",
      ServiceStoreFileFactsValue(env, facts));
  ServiceSetUint32(env, result, "writes", 0);
  return result;
}

bool ValidExternalArtifactPath(const std::string& path) {
  if (path.empty() || path.size() > 4096) return false;
#ifdef _WIN32
  WindowsPathParts parts;
  return ParseWindowsPath(path, &parts) &&
      !parts.components.empty();
#else
  return path.front() == '/' && path != "/" &&
      path.back() != '/' &&
      path.find("//") == std::string::npos &&
      path.find("/./") == std::string::npos &&
      path.find("/../") == std::string::npos &&
      path.compare(path.size() >= 2 ? path.size() - 2 : 0,
                   2, "/.") != 0 &&
      path.compare(path.size() >= 3 ? path.size() - 3 : 0,
                   3, "/..") != 0;
#endif
}

bool OpenExternalArtifactBound(
    const std::string& path, ServiceStoreHandle* reader,
    bool* absent) {
  *absent = false;
#ifdef _WIN32
  WindowsPathParts parts;
  if (!ParseWindowsPath(path, &parts) ||
      parts.components.empty()) return false;
  HANDLE current = OpenWindowsRoot(
      parts.root, kWindowsTraversalAccess | READ_CONTROL);
  if (current == INVALID_HANDLE_VALUE) return false;
  reader->fixed_parent_path = Utf8(parts.root);
  reader->external_ancestors.push_back(current);
  ServiceStoreIdentity identity;
  if (!CaptureExternalAncestorIdentity(current, &identity)) return false;
  reader->external_ancestor_identities.push_back(identity);
  for (size_t index = 0; index + 1 < parts.components.size();
       ++index) {
    HANDLE next = OpenWindowsRelative(
        current, parts.components[index],
        kWindowsTraversalAccess | READ_CONTROL,
        kFileOpen, VerifiedObjectType::Directory);
    if (next == INVALID_HANDLE_VALUE ||
        !CaptureExternalAncestorIdentity(next, &identity)) {
      if (next != INVALID_HANDLE_VALUE) CloseHandle(next);
      return false;
    }
    reader->external_components.push_back(
        Utf8(parts.components[index]));
    reader->external_ancestors.push_back(next);
    reader->external_ancestor_identities.push_back(identity);
    current = next;
  }
  reader->name = Utf8(parts.components.back());
  reader->object = OpenWindowsRelative(
      current, parts.components.back(), GENERIC_READ | READ_CONTROL,
      kFileOpen, VerifiedObjectType::File);
  if (reader->object == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    *absent = error == ERROR_FILE_NOT_FOUND;
    return *absent;
  }
#else
  if (!ValidExternalArtifactPath(path)) return false;
  std::vector<std::string> parts;
  size_t start = 1;
  while (start < path.size()) {
    const size_t end = path.find('/', start);
    const std::string part = path.substr(
        start, end == std::string::npos
            ? std::string::npos : end - start);
    if (!SafeName(part)) return false;
    parts.push_back(part);
    if (end == std::string::npos) break;
    start = end + 1;
  }
  if (parts.empty()) return false;
  int current = open(
      "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (current < 0) return false;
  reader->fixed_parent_path = "/";
  reader->external_ancestors.push_back(current);
  ServiceStoreIdentity identity;
  if (!CaptureExternalAncestorIdentity(current, &identity)) return false;
  reader->external_ancestor_identities.push_back(identity);
  for (size_t index = 0; index + 1 < parts.size(); ++index) {
    int next = openat(
        current, parts[index].c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (next < 0 ||
        !CaptureExternalAncestorIdentity(next, &identity)) {
      if (next >= 0) close(next);
      return false;
    }
    reader->external_components.push_back(parts[index]);
    reader->external_ancestors.push_back(next);
    reader->external_ancestor_identities.push_back(identity);
    current = next;
  }
  reader->name = parts.back();
  reader->object = openat(
      current, reader->name.c_str(),
      O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (reader->object < 0) {
    const int error = errno;
    *absent = error == ENOENT;
    return *absent;
  }
  struct stat leaf{};
  if (fstat(reader->object, &leaf) != 0 ||
      !S_ISREG(leaf.st_mode)) {
    close(reader->object);
    reader->object = -1;
    return false;
  }
#endif
  return true;
}

napi_value OpenServiceArtifactSource(
    napi_env env, napi_callback_info info) {
  napi_value args[4];
  std::string path;
  uint64_t maximum = 0;
  bool expected_present = false;
  ServiceStoreFileFacts expected;
  InventoryRoles roles{};
  if (!InventoryArgs(env, info, 4, args) ||
      !InventoryString(env, args[0], &path) ||
      !ValidExternalArtifactPath(path) ||
      !ServiceStoreNumber(env, args[1],
                          kServiceArtifactMaxBytes, &maximum) ||
      !ServiceArtifactExpectedFacts(
          env, args[2], &expected_present, &expected) ||
      !InventoryRolesArg(env, args[3], &roles) ||
      !ServiceActorAuthorized(roles)) {
    ServiceError(env, "SERVICE_INVALID",
                 "open_service_artifact_source");
    return nullptr;
  }
  auto* reader = new (std::nothrow) ServiceStoreHandle();
  if (!reader) {
    ServiceError(env, "SERVICE_IO_FAILED",
                 "open_service_artifact_source");
    return nullptr;
  }
  reader->env = env;
  reader->kind = ServiceStoreHandleKind::ArtifactSourceReader;
  reader->access = ServiceStoreAccess::Read;
  reader->root_kind = "external-source";
  reader->roles = roles;
  if (!ServiceStoreRolesFingerprint(
          roles, &reader->roles_fingerprint)) {
    delete reader;
    ServiceError(env, "SERVICE_CRYPTO_UNAVAILABLE",
                 "open_service_artifact_source");
    return nullptr;
  }
  bool absent = false;
  bool opened = false;
  try {
    opened = OpenExternalArtifactBound(path, reader, &absent);
  } catch (...) {
    opened = false;
  }
  if (!opened) {
    CloseServiceStoreNative(reader, true);
    delete reader;
    ServiceError(env, "SERVICE_STALE",
                 "open_service_artifact_source", 0, true);
    return nullptr;
  }
  if (absent) {
    const bool ancestors_exact =
        RevalidateExternalArtifactAncestors(reader);
    CloseServiceStoreNative(reader, true);
    delete reader;
    if (!ancestors_exact) {
      ServiceError(env, "SERVICE_STALE",
                   "open_service_artifact_source", 0, true);
      return nullptr;
    }
    if (expected_present) {
      ServiceError(env, "SERVICE_STALE",
                   "open_service_artifact_source");
      return nullptr;
    }
    napi_value result;
    napi_get_null(env, &result);
    return result;
  }
  ServiceStoreFileFacts facts;
  if (!HashRetainedServiceArtifact(
          reader->object, nullptr, true, maximum, &facts) ||
      (expected_present &&
       !SameServiceStoreFileFacts(facts, expected))) {
    CloseServiceStoreNative(reader, true);
    delete reader;
    ServiceError(env, "SERVICE_STALE",
                 "open_service_artifact_source");
    return nullptr;
  }
  reader->identity = facts.identity;
  reader->stream_limit = facts.size;
  reader->expected_sha256 = facts.sha256;
  try {
    reader->stream_hash = std::make_unique<Sha256>();
  } catch (...) {
    reader->stream_hash.reset();
  }
  if (!reader->stream_hash || !reader->stream_hash->Ready() ||
      !ServiceArtifactStateToken(
          reader->object, &reader->stream_state) ||
      !RevalidateServiceArtifactStream(reader)) {
    CloseServiceStoreNative(reader, true);
    delete reader;
    ServiceError(env, "SERVICE_IO_FAILED",
                 "open_service_artifact_source");
    return nullptr;
  }
  napi_value wrapped = WrapServiceStoreHandle(env, reader);
  if (!wrapped) {
    ServiceError(env, "SERVICE_IO_FAILED",
                 "open_service_artifact_source");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", wrapped);
  napi_set_named_property(
      env, result, "facts",
      ServiceStoreFileFactsValue(env, facts));
  ServiceSetUint32(env, result, "writes", 0);
  return result;
}

napi_value ServiceObservationAbsenceValue(
    napi_env env, const ServiceStoreIdentity& parent_identity,
    const std::vector<std::string>& missing_segments) {
  napi_value result, segments, value;
  napi_create_object(env, &result);
  napi_set_named_property(
      env, result, "parentIdentity",
      ServiceStoreIdentityValue(env, parent_identity));
  napi_create_array_with_length(env, missing_segments.size(), &segments);
  for (uint32_t index = 0; index < missing_segments.size(); ++index) {
    napi_create_string_utf8(
        env, missing_segments[index].c_str(),
        missing_segments[index].size(), &value);
    napi_set_element(env, segments, index, value);
  }
  napi_set_named_property(env, result, "missingSegments", segments);
  return result;
}

std::string ServiceObservationIdentityFingerprint(
    const ServiceStoreIdentity& identity, const char* domain) {
  Sha256 hash;
  if (!hash.Ready()) return "";
  HashField(&hash, domain);
  HashField(&hash, ServiceStoreIdentityText(identity));
  return hash.Finish();
}

void ServiceObservationSetNullableIdentity(
    napi_env env, napi_value result, const char* field,
    const ServiceStoreIdentity* identity) {
  napi_value value;
  if (identity) {
    value = ServiceStoreIdentityValue(env, *identity);
  } else {
    napi_get_null(env, &value);
  }
  napi_set_named_property(env, result, field, value);
}

#ifdef _WIN32
struct ServiceObservationScopedHandles {
  std::vector<HANDLE> values;
  ~ServiceObservationScopedHandles() {
    for (HANDLE value : values) {
      if (value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
  }
  void Add(HANDLE value) { values.push_back(value); }
};

std::string ServiceWindowsPathText(const WindowsPathParts& parts) {
  std::wstring path = parts.root;
  for (const std::wstring& component : parts.components) {
    if (path.back() != L'\\') path.push_back(L'\\');
    path += component;
  }
  return Utf8(path);
}

bool ServiceWindowsNotFound(DWORD error) {
  return error == ERROR_FILE_NOT_FOUND ||
      error == ERROR_PATH_NOT_FOUND;
}

bool ServiceSelfUnsupportedTypeError(DWORD error) {
  return error == ERROR_DIRECTORY || error == ERROR_NOT_SUPPORTED ||
      error == ERROR_CANT_ACCESS_FILE;
}

struct ServiceSelfDirectoryChain {
  std::wstring root;
  std::vector<HANDLE> handles;
  std::vector<std::wstring> components;
  std::vector<ServiceStoreIdentity> identities;
  ~ServiceSelfDirectoryChain() {
    for (HANDLE handle : handles) {
      if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
  }
  void Add(HANDLE handle, const ServiceStoreIdentity& identity) {
    handles.push_back(handle);
    identities.push_back(identity);
  }
};

struct ServiceSelfSecretBuffer {
  std::vector<uint8_t> bytes;
  ~ServiceSelfSecretBuffer() {
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
  }
};

bool ServiceSelfDenyCurrentWriteAccess(HANDLE object, bool directory);
bool ServiceSelfDenyCurrentAncestorTakeoverAccess(HANDLE object);

bool ServiceSelfLowerHex(const std::string& value, size_t length) {
  return value.size() == length &&
      value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

bool ServiceSelfCanonicalWindowsSid(const std::string& value) {
  if (value.rfind("S-", 0) != 0 ||
      value.find_first_not_of("S-0123456789") != std::string::npos) {
    return false;
  }
  PSID sid = nullptr;
  LPWSTR canonical = nullptr;
  const bool parsed = ConvertStringSidToSidW(Wide(value).c_str(), &sid) &&
      sid != nullptr && IsValidSid(sid);
  const bool serialized = parsed &&
      ConvertSidToStringSidW(sid, &canonical) && canonical != nullptr &&
      value == Utf8(canonical);
  if (canonical) LocalFree(canonical);
  if (sid) LocalFree(sid);
  return serialized;
}

bool ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
    const ServiceStoreIdentity& identity, std::string* fingerprint) {
  if (!ServiceSelfLowerHex(identity.volume_serial, 16) ||
      !ServiceSelfLowerHex(identity.file_id, 32) ||
      !ServiceSelfCanonicalWindowsSid(identity.owner) ||
      !ValidServiceFingerprint(identity.security_sha256)) return false;
  const std::string canonical =
      "{\"attributes\":" + std::to_string(identity.attributes) +
      ",\"fileId\":\"" + identity.file_id +
      "\",\"kind\":\"gjc-remote/win32-physical-security-identity/v1\",\"owner\":\"" +
      identity.owner +
      "\",\"securitySha256\":\"" + identity.security_sha256 +
      "\",\"volumeSerial\":\"" + identity.volume_serial + "\"}";
  Sha256 hash;
  if (!hash.Ready() || !hash.Update(canonical)) return false;
  *fingerprint = hash.Finish();
  return ValidServiceFingerprint(*fingerprint);
}

bool ServiceSelfWindowsBootFingerprint(
    const std::string& boot_id, std::string* fingerprint) {
  if (boot_id.rfind("win32:", 0) != 0 || boot_id.size() <= 6 ||
      boot_id.substr(6).find_first_not_of("0123456789") !=
          std::string::npos) return false;
  const std::string canonical =
      "{\"bootId\":\"" + boot_id +
      "\",\"kind\":\"windows-boot/v1\"}";
  Sha256 hash;
  if (!hash.Ready() || !hash.Update(canonical)) return false;
  *fingerprint = hash.Finish();
  return ValidServiceFingerprint(*fingerprint);
}

bool VerifyWin32RuntimeConfigLaunch(const Win32ServiceLaunch& launch,
                                    const InventoryRoles& roles) {
  HANDLE working = OpenWindowsPathNoFollow(
      launch.working_directory,
      FILE_GENERIC_READ | READ_CONTROL,
      VerifiedObjectType::Directory);
  if (working == INVALID_HANDLE_VALUE) return false;
  HANDLE root = OpenWindowsRelative(
      working, L"runtime-config", FILE_GENERIC_READ | READ_CONTROL,
      kFileOpen, VerifiedObjectType::Directory);
  HANDLE named_root = OpenWindowsPathNoFollow(
      launch.runtime_config_root,
      FILE_GENERIC_READ | READ_CONTROL,
      VerifiedObjectType::Directory);
  HANDLE file = root == INVALID_HANDLE_VALUE ? INVALID_HANDLE_VALUE
      : OpenWindowsRelative(root, L".bunfig.toml",
            GENERIC_READ | READ_CONTROL, kFileOpen,
            VerifiedObjectType::File);
  HANDLE named_file = OpenWindowsPathNoFollow(
      launch.runtime_config_path, GENERIC_READ | READ_CONTROL,
      VerifiedObjectType::File);

  ServiceStoreIdentity working_identity, named_working_identity;
  ServiceStoreIdentity root_identity, named_root_identity, final_root_identity;
  ServiceStoreIdentity file_identity, named_file_identity, final_file_identity;
  std::string root_fingerprint, file_fingerprint;
  FILE_STANDARD_INFO file_information{};
  const bool identities_exact =
      working != INVALID_HANDLE_VALUE && root != INVALID_HANDLE_VALUE &&
      named_root != INVALID_HANDLE_VALUE && file != INVALID_HANDLE_VALUE &&
      named_file != INVALID_HANDLE_VALUE &&
      CaptureExternalAncestorIdentity(working, &working_identity) &&
      CaptureExternalAncestorIdentity(
          working, &named_working_identity) &&
      SameServicePhysicalIdentity(working_identity, named_working_identity) &&
      CaptureExternalAncestorIdentity(root, &root_identity) &&
      CaptureExternalAncestorIdentity(named_root, &named_root_identity) &&
      CaptureExternalAncestorIdentity(root, &final_root_identity) &&
      SameServicePhysicalIdentity(root_identity, named_root_identity) &&
      SameServicePhysicalIdentity(root_identity, final_root_identity) &&
      CaptureExternalServiceFileIdentity(file, &file_identity) &&
      CaptureExternalServiceFileIdentity(named_file, &named_file_identity) &&
      CaptureExternalServiceFileIdentity(file, &final_file_identity) &&
      SameServicePhysicalIdentity(file_identity, named_file_identity) &&
      SameServicePhysicalIdentity(file_identity, final_file_identity) &&
      ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
          root_identity, &root_fingerprint) &&
      ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
          file_identity, &file_fingerprint) &&
      root_fingerprint == launch.runtime_config_root_identity_fingerprint &&
      file_fingerprint == launch.runtime_config_identity_fingerprint &&
      GetFileInformationByHandleEx(
          file, FileStandardInfo, &file_information,
          sizeof(file_information)) && file_information.EndOfFile.QuadPart == 0 &&
      VerifyWindowsServiceFileAcl(
          root, roles, ServiceAclProfile::DaemonConfigDirectory) &&
      VerifyWindowsServiceFileAcl(
          file, roles, ServiceAclProfile::DaemonConfigFile) &&
      VerifyWindowsServiceFileAcl(
          named_root, roles, ServiceAclProfile::DaemonConfigDirectory) &&
      VerifyWindowsServiceFileAcl(
          named_file, roles, ServiceAclProfile::DaemonConfigFile);
  const bool content_exact = identities_exact &&
      ReadWindowsFileSha256(launch.runtime_config_path,
                            launch.runtime_config_sha256);
  if (working != INVALID_HANDLE_VALUE) CloseHandle(working);
  if (root != INVALID_HANDLE_VALUE) CloseHandle(root);
  if (named_root != INVALID_HANDLE_VALUE) CloseHandle(named_root);
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  if (named_file != INVALID_HANDLE_VALUE) CloseHandle(named_file);
  return content_exact;
}

bool VerifyWin32ConfigSourceLaunch(const Win32ServiceLaunch& launch,
                                   const InventoryRoles& roles,
                                   const std::string& role) {
  const std::string source_path = launch.working_directory + "\\.env";
  HANDLE working = OpenWindowsPathNoFollow(
      launch.working_directory, FILE_GENERIC_READ | READ_CONTROL,
      VerifiedObjectType::Directory);
  HANDLE named_working = OpenWindowsPathNoFollow(
      launch.working_directory, FILE_GENERIC_READ | READ_CONTROL,
      VerifiedObjectType::Directory);
  HANDLE source = working == INVALID_HANDLE_VALUE
      ? INVALID_HANDLE_VALUE
      : OpenWindowsRelative(working, L".env", GENERIC_READ | READ_CONTROL,
            kFileOpen, VerifiedObjectType::File);
  HANDLE named_source = OpenWindowsPathNoFollow(
      source_path, GENERIC_READ | READ_CONTROL, VerifiedObjectType::File);
  ServiceStoreIdentity source_identity, named_identity, final_identity;
  ServiceStoreIdentity working_identity, named_working_identity;
  std::string source_fingerprint;
  const ServiceAclProfile profile = role == "bot"
      ? ServiceAclProfile::BotConfigFile
      : ServiceAclProfile::DaemonConfigFile;
  const bool exact = working != INVALID_HANDLE_VALUE &&
      named_working != INVALID_HANDLE_VALUE &&
      source != INVALID_HANDLE_VALUE && named_source != INVALID_HANDLE_VALUE &&
      CaptureExternalAncestorIdentity(working, &working_identity) &&
      CaptureExternalAncestorIdentity(
          named_working, &named_working_identity) &&
      SameServicePhysicalIdentity(working_identity, named_working_identity) &&
      CaptureExternalServiceFileIdentity(source, &source_identity) &&
      CaptureExternalServiceFileIdentity(named_source, &named_identity) &&
      CaptureExternalServiceFileIdentity(source, &final_identity) &&
      SameServicePhysicalIdentity(source_identity, named_identity) &&
      SameServicePhysicalIdentity(source_identity, final_identity) &&
      ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
          source_identity, &source_fingerprint) &&
      source_fingerprint == launch.config_source_identity_fingerprint &&
      VerifyWindowsServiceFileAcl(source, roles, profile) &&
      VerifyWindowsServiceFileAcl(named_source, roles, profile);
  if (working != INVALID_HANDLE_VALUE) CloseHandle(working);
  if (named_working != INVALID_HANDLE_VALUE) CloseHandle(named_working);
  if (source != INVALID_HANDLE_VALUE) CloseHandle(source);
  if (named_source != INVALID_HANDLE_VALUE) CloseHandle(named_source);
  return exact;
}

bool ServiceSelfCurrentDirectory(std::wstring* path) {
  std::vector<wchar_t> buffer;
  try {
    buffer.resize(32768);
  } catch (...) {
    return false;
  }
  const DWORD written = GetCurrentDirectoryW(
      static_cast<DWORD>(buffer.size()), buffer.data());
  if (written == 0 || written >= buffer.size()) return false;
  path->assign(buffer.data(), written);
  return true;
}

bool ServiceSelfOpenDirectoryChain(
    const std::wstring& path, ServiceSelfDirectoryChain* chain) {
  WindowsPathParts parts;
  if (!ParseWindowsPath(Utf8(path), &parts) ||
      parts.components.size() > 64) return false;
  try {
    chain->handles.reserve(parts.components.size() + 1);
    chain->components.reserve(parts.components.size());
    chain->identities.reserve(parts.components.size() + 1);
  } catch (...) {
    return false;
  }
  chain->root = parts.root;
  HANDLE current = OpenWindowsRoot(
      parts.root, kWindowsTraversalAccess | READ_CONTROL);
  ServiceStoreIdentity identity;
  const bool root_is_working_directory = parts.components.empty();
  if (current == INVALID_HANDLE_VALUE ||
      !CaptureExternalAncestorIdentity(current, &identity) ||
      !(root_is_working_directory
          ? ServiceSelfDenyCurrentWriteAccess(current, true)
          : ServiceSelfDenyCurrentAncestorTakeoverAccess(current))) {
    if (current != INVALID_HANDLE_VALUE) CloseHandle(current);
    return false;
  }
  chain->Add(current, identity);
  for (size_t index = 0; index < parts.components.size(); ++index) {
    const std::wstring& component = parts.components[index];
    HANDLE next = OpenWindowsRelative(
        current, component, kWindowsTraversalAccess | READ_CONTROL,
        kFileOpen, VerifiedObjectType::Directory);
    const bool is_working_directory = index + 1 == parts.components.size();
    if (next == INVALID_HANDLE_VALUE ||
        !CaptureExternalAncestorIdentity(next, &identity) ||
        !(is_working_directory
            ? ServiceSelfDenyCurrentWriteAccess(next, true)
            : ServiceSelfDenyCurrentAncestorTakeoverAccess(next))) {
      if (next != INVALID_HANDLE_VALUE) CloseHandle(next);
      return false;
    }
    chain->components.push_back(component);
    chain->Add(next, identity);
    current = next;
  }
  return true;
}

bool ServiceSelfDirectoryChainStable(
    const ServiceSelfDirectoryChain& chain,
    const std::wstring& expected_current_directory) {
  if (chain.handles.empty() ||
      chain.identities.size() != chain.handles.size() ||
      chain.components.size() + 1 != chain.handles.size()) return false;
  HANDLE named_root = OpenWindowsRoot(
      chain.root, kWindowsTraversalAccess | READ_CONTROL);
  ServiceStoreIdentity named_identity;
  const bool root_exact = named_root != INVALID_HANDLE_VALUE &&
      CaptureExternalAncestorIdentity(named_root, &named_identity) &&
      SameServicePhysicalIdentity(
          named_identity, chain.identities.front());
  if (named_root != INVALID_HANDLE_VALUE) CloseHandle(named_root);
  if (!root_exact) return false;
  for (size_t index = 0; index < chain.handles.size(); ++index) {
    ServiceStoreIdentity held_identity;
    if (!CaptureExternalAncestorIdentity(
            chain.handles[index], &held_identity) ||
        !SameServicePhysicalIdentity(
            held_identity, chain.identities[index])) return false;
    if (index == 0) continue;
    HANDLE named = OpenWindowsRelative(
        chain.handles[index - 1], chain.components[index - 1],
        kWindowsTraversalAccess | READ_CONTROL, kFileOpen,
        VerifiedObjectType::Directory);
    ServiceStoreIdentity actual;
    const bool exact = named != INVALID_HANDLE_VALUE &&
        CaptureExternalAncestorIdentity(named, &actual) &&
        SameServicePhysicalIdentity(actual, chain.identities[index]);
    if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
    if (!exact) return false;
  }
  std::wstring current;
  return ServiceSelfCurrentDirectory(&current) &&
      current == expected_current_directory;
}

bool ServiceSelfDenyCurrentAccess(
    HANDLE object, const ACCESS_MASK* forbidden, size_t forbidden_count) {
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  // AccessCheck fails with ERROR_INVALID_SECURITY_DESCR unless the
  // descriptor carries owner and group; the owner also contributes its
  // implicit WRITE_DAC, which a takeover-denial proof must observe.
  if (object == INVALID_HANDLE_VALUE ||
      GetSecurityInfo(
          object, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
              DACL_SECURITY_INFORMATION,
          nullptr, nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS ||
      descriptor == nullptr) {
    if (descriptor) LocalFree(descriptor);
    return false;
  }
  BOOL dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  const bool usable_dacl =
      GetSecurityDescriptorDacl(
          descriptor, &dacl_present, &dacl, &dacl_defaulted) &&
      dacl_present && dacl != nullptr;
  if (!usable_dacl) {
    LocalFree(descriptor);
    return false;
  }
  HANDLE process_token = nullptr;
  HANDLE impersonation_token = nullptr;
  const bool token_opened = OpenProcessToken(
      GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE,
      &process_token) != FALSE &&
      DuplicateToken(
          process_token, SecurityImpersonation,
          &impersonation_token) != FALSE;
  if (process_token) CloseHandle(process_token);
  if (!token_opened) {
    if (impersonation_token) CloseHandle(impersonation_token);
    LocalFree(descriptor);
    return false;
  }
  GENERIC_MAPPING mapping{
      FILE_GENERIC_READ, FILE_GENERIC_WRITE,
      FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  std::vector<uint8_t> privilege_bytes;
  try {
    privilege_bytes.resize(4096);
  } catch (...) {
    CloseHandle(impersonation_token);
    LocalFree(descriptor);
    return false;
  }
  bool denied = false;
  for (size_t index = 0; index < forbidden_count; ++index) {
    ACCESS_MASK requested = forbidden[index];
    MapGenericMask(&requested, &mapping);
    DWORD privilege_bytes_count =
        static_cast<DWORD>(privilege_bytes.size());
    DWORD granted = 0;
    BOOL access_status = FALSE;
    bool checked = AccessCheck(
        descriptor, impersonation_token, requested, &mapping,
        reinterpret_cast<PRIVILEGE_SET*>(privilege_bytes.data()),
        &privilege_bytes_count, &granted, &access_status) != FALSE;
    if (!checked && GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
        privilege_bytes_count > privilege_bytes.size() &&
        privilege_bytes_count <= 64 * 1024) {
      try {
        privilege_bytes.resize(privilege_bytes_count);
      } catch (...) {
        checked = false;
      }
      if (privilege_bytes.size() == privilege_bytes_count) {
        privilege_bytes_count =
            static_cast<DWORD>(privilege_bytes.size());
        granted = 0;
        access_status = FALSE;
        checked = AccessCheck(
            descriptor, impersonation_token, requested, &mapping,
            reinterpret_cast<PRIVILEGE_SET*>(privilege_bytes.data()),
            &privilege_bytes_count, &granted, &access_status) != FALSE;
      }
    }
    if (!checked) {
      denied = true;
      break;
    }
    if (access_status || (granted & requested) != 0) {
      denied = true;
      break;
    }
  }
  CloseHandle(impersonation_token);
  LocalFree(descriptor);
  const bool no_write_access = !denied;
  if (!no_write_access) SetLastError(ERROR_ACCESS_DENIED);
  return no_write_access;
}

bool ServiceSelfDenyCurrentWriteAccess(HANDLE object, bool directory) {
  static constexpr ACCESS_MASK forbidden[] = {
    FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA,
    FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER,
    FILE_DELETE_CHILD,
  };
  return ServiceSelfDenyCurrentAccess(
      object, forbidden,
      directory ? sizeof(forbidden) / sizeof(forbidden[0])
                : sizeof(forbidden) / sizeof(forbidden[0]) - 1);
}

bool ServiceSelfDenyCurrentAncestorTakeoverAccess(HANDLE object) {
  static constexpr ACCESS_MASK forbidden[] = {
    FILE_WRITE_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES,
    DELETE, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER,
  };
  return ServiceSelfDenyCurrentAccess(
      object, forbidden, sizeof(forbidden) / sizeof(forbidden[0]));
}

bool ServiceSelfCaptureFileIdentity(
    HANDLE file, ServiceStoreIdentity* identity,
    FILE_BASIC_INFO* basic, FILE_STANDARD_INFO* standard,
    bool require_read_only = true) {
  FILE_ATTRIBUTE_TAG_INFO tag{};
  if (file == INVALID_HANDLE_VALUE ||
      !GetFileInformationByHandleEx(
          file, FileAttributeTagInfo, &tag, sizeof(tag)) ||
      !GetFileInformationByHandleEx(
          file, FileBasicInfo, basic, sizeof(*basic)) ||
      !GetFileInformationByHandleEx(
          file, FileStandardInfo, standard, sizeof(*standard)) ||
      (tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                             FILE_ATTRIBUTE_DEVICE |
                             FILE_ATTRIBUTE_DIRECTORY)) != 0 ||
      standard->DeletePending || standard->NumberOfLinks != 1 ||
      standard->EndOfFile.QuadPart < 0 ||
      (require_read_only &&
       !ServiceSelfDenyCurrentWriteAccess(file, false)) ||
      !CaptureExternalServiceFileIdentity(file, identity)) return false;
  return true;
}

bool ServiceSelfReadFile(
    HANDLE parent, const wchar_t* name, uint64_t maximum,
    bool retain_bytes, std::vector<uint8_t>* bytes,
    std::string* digest, ServiceStoreIdentity* identity,
    uint32_t* byte_length,
    bool* output_limit) {
  *output_limit = false;
  const DWORD share_mode = FILE_SHARE_READ;
  HANDLE file = OpenWindowsRelative(
      parent, name, GENERIC_READ | READ_CONTROL,
      kFileOpen, VerifiedObjectType::File, nullptr, share_mode);
  if (file == INVALID_HANDLE_VALUE) return false;
  FILE_BASIC_INFO before_basic{}, after_basic{};
  FILE_STANDARD_INFO before_standard{}, after_standard{};
  ServiceStoreIdentity before_identity, after_identity;
  bool valid = ServiceSelfCaptureFileIdentity(
      file, &before_identity, &before_basic, &before_standard);
  if (valid && static_cast<uint64_t>(before_standard.EndOfFile.QuadPart) >
          maximum) {
    *output_limit = true;
    CloseHandle(file);
    return false;
  }
  if (valid && retain_bytes) {
    try {
      bytes->resize(static_cast<size_t>(before_standard.EndOfFile.QuadPart));
    } catch (...) {
      valid = false;
    }
  }
  if (valid && byte_length) {
    *byte_length = static_cast<uint32_t>(
        before_standard.EndOfFile.QuadPart);
  }
  Sha256 hash;
  valid = valid && (!digest || hash.Ready());
  LARGE_INTEGER position{};
  valid = valid && SetFilePointerEx(
      file, position, nullptr, FILE_BEGIN) != FALSE;
  std::array<uint8_t, 64 * 1024> chunk{};
  uint64_t total = 0;
  while (valid && total < static_cast<uint64_t>(
             before_standard.EndOfFile.QuadPart)) {
    const DWORD requested = static_cast<DWORD>(std::min<uint64_t>(
        chunk.size(), static_cast<uint64_t>(
            before_standard.EndOfFile.QuadPart) - total));
    DWORD count = 0;
    valid = ReadFile(file, chunk.data(), requested, &count, nullptr) &&
        count == requested;
    if (!valid) break;
    if (digest && !hash.Update(chunk.data(), count)) {
      valid = false;
      break;
    }
    if (retain_bytes) {
      std::memcpy(bytes->data() + static_cast<size_t>(total),
                  chunk.data(), count);
    }
    total += count;
  }
  valid = valid && total == static_cast<uint64_t>(
      before_standard.EndOfFile.QuadPart) &&
      ServiceSelfCaptureFileIdentity(
          file, &after_identity, &after_basic, &after_standard) &&
      SameServiceStoreIdentity(before_identity, after_identity) &&
      before_basic.CreationTime.QuadPart ==
          after_basic.CreationTime.QuadPart &&
      before_basic.LastWriteTime.QuadPart ==
          after_basic.LastWriteTime.QuadPart &&
      before_basic.ChangeTime.QuadPart ==
          after_basic.ChangeTime.QuadPart &&
      before_basic.FileAttributes == after_basic.FileAttributes &&
      before_standard.EndOfFile.QuadPart ==
          after_standard.EndOfFile.QuadPart &&
      before_standard.AllocationSize.QuadPart ==
          after_standard.AllocationSize.QuadPart;
  if (valid) {
    HANDLE named = OpenWindowsRelative(
        parent, name, GENERIC_READ | READ_CONTROL,
        kFileOpen, VerifiedObjectType::File, nullptr, share_mode);
    ServiceStoreIdentity named_identity;
    FILE_BASIC_INFO named_basic{};
    FILE_STANDARD_INFO named_standard{};
    valid = named != INVALID_HANDLE_VALUE &&
        ServiceSelfCaptureFileIdentity(
            named, &named_identity, &named_basic, &named_standard) &&
        SameServiceStoreIdentity(before_identity, named_identity) &&
        named_basic.CreationTime.QuadPart ==
            before_basic.CreationTime.QuadPart &&
        named_basic.LastWriteTime.QuadPart ==
            before_basic.LastWriteTime.QuadPart &&
        named_basic.ChangeTime.QuadPart ==
            before_basic.ChangeTime.QuadPart &&
        named_standard.EndOfFile.QuadPart ==
            before_standard.EndOfFile.QuadPart &&
        named_standard.AllocationSize.QuadPart ==
            before_standard.AllocationSize.QuadPart;
    if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
  }
  CloseHandle(file);
  if (!valid) return false;
  *identity = before_identity;
  if (digest) {
    *digest = hash.Finish();
    if (!ValidServiceFingerprint(*digest)) return false;
  }
  return true;
}

bool ServiceWindowsCaseFold(const std::wstring& value,
                            std::wstring* folded) {
  const int count = LCMapStringEx(
      LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE,
      value.data(), static_cast<int>(value.size()),
      nullptr, 0, nullptr, nullptr, 0);
  if (count <= 0 || count > 32768) return false;
  folded->resize(static_cast<size_t>(count));
  return LCMapStringEx(
      LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE,
      value.data(), static_cast<int>(value.size()),
      folded->data(), count, nullptr, nullptr, 0) == count;
}

bool ServiceObservationNamedChild(
    HANDLE parent, const std::string& name, bool directory,
    const InventoryRoles& roles, ServiceAclProfile profile,
    HANDLE* opened, ServiceStoreIdentity* identity) {
  *opened = OpenWindowsRelative(
      parent, Wide(name), FILE_GENERIC_READ | READ_CONTROL,
      kFileOpen,
      directory ? VerifiedObjectType::Directory
                : VerifiedObjectType::File);
  if (*opened == INVALID_HANDLE_VALUE) return false;
  FILE_ATTRIBUTE_TAG_INFO tag{};
  FILE_STANDARD_INFO standard{};
  const bool valid =
      GetFileInformationByHandleEx(
          *opened, FileAttributeTagInfo, &tag, sizeof(tag)) &&
      GetFileInformationByHandleEx(
          *opened, FileStandardInfo, &standard, sizeof(standard)) &&
      (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
      (tag.FileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
      !standard.DeletePending &&
      (directory
          ? standard.Directory != FALSE
          : standard.Directory == FALSE && standard.NumberOfLinks == 1) &&
      CaptureServiceObservationIdentity(
          *opened, roles, profile, identity);
  if (!valid) {
    CloseHandle(*opened);
    *opened = INVALID_HANDLE_VALUE;
    SetLastError(ERROR_ACCESS_DENIED);
  }
  return valid;
}

bool ServiceObservationNamedExternalChild(
    HANDLE parent, const std::string& name, bool directory,
    const InventoryRoles& roles, ServiceExternalProfile profile,
    HANDLE* opened, ServiceStoreIdentity* identity) {
  *opened = OpenWindowsRelative(
      parent, Wide(name), FILE_GENERIC_READ | READ_CONTROL,
      kFileOpen,
      directory ? VerifiedObjectType::Directory
                : VerifiedObjectType::File);
  if (*opened == INVALID_HANDLE_VALUE) return false;
  FILE_ATTRIBUTE_TAG_INFO tag{};
  FILE_STANDARD_INFO standard{};
  const bool shape_valid =
      GetFileInformationByHandleEx(
          *opened, FileAttributeTagInfo, &tag, sizeof(tag)) &&
      GetFileInformationByHandleEx(
          *opened, FileStandardInfo, &standard, sizeof(standard)) &&
      (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
      (tag.FileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
      !standard.DeletePending &&
      (directory
          ? standard.Directory != FALSE
          : standard.Directory == FALSE && standard.NumberOfLinks == 1);
  ServiceExternalAclPolicy policy =
      ServiceExternalAclPolicy::Unresolved;
  if (!shape_valid ||
      !InferServiceExternalAclPolicy(
          *opened, roles, profile, directory, &policy, identity)) {
    CloseHandle(*opened);
    *opened = INVALID_HANDLE_VALUE;
    SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }
  return true;
}

struct ServiceObservationDirectoryEntry {
  std::string name;
  std::string kind;
  ServiceStoreIdentity identity;
};

bool ServiceObservationDirectorySnapshot(
    HANDLE directory, const InventoryRoles& roles,
    ServiceExternalProfile external_profile,
    std::vector<ServiceObservationDirectoryEntry>* entries,
    bool* output_limit) {
  entries->clear();
  *output_limit = false;
  std::array<uint8_t, 64 * 1024> buffer{};
  std::set<std::wstring> folded_names;
  uint64_t name_bytes = 0;
  bool restart = true;
  for (;;) {
    if (!GetFileInformationByHandleEx(
            directory,
            restart ? FileIdBothDirectoryRestartInfo
                    : FileIdBothDirectoryInfo,
            buffer.data(), static_cast<DWORD>(buffer.size()))) {
      return GetLastError() == ERROR_NO_MORE_FILES;
    }
    restart = false;
    size_t offset = 0;
    for (;;) {
      if (offset + offsetof(FILE_ID_BOTH_DIR_INFO, FileName) >
          buffer.size()) return false;
      const auto* record = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(
          buffer.data() + offset);
      if (record->FileNameLength == 0 ||
          record->FileNameLength % sizeof(wchar_t) != 0 ||
          record->FileNameLength >
              buffer.size() - offset -
                  offsetof(FILE_ID_BOTH_DIR_INFO, FileName)) return false;
      const std::wstring wide_name(
          record->FileName,
          record->FileNameLength / sizeof(wchar_t));
      if (wide_name != L"." && wide_name != L"..") {
        const std::string name = Utf8(wide_name);
        const bool is_directory =
            (record->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (entries->size() >= 10000) {
          *output_limit = true;
          return false;
        }
        if (name.empty() || !ValidServiceStoreComponent(name) ||
            Wide(name) != wide_name ||
            (record->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (record->FileAttributes & FILE_ATTRIBUTE_DEVICE) != 0) return false;
        std::wstring folded;
        if (!ServiceWindowsCaseFold(wide_name, &folded) ||
            !folded_names.insert(std::move(folded)).second) return false;
        name_bytes += name.size();
        if (name_bytes > 64ULL * 1024ULL * 1024ULL) {
          *output_limit = true;
          return false;
        }
        ServiceObservationDirectoryEntry entry;
        entry.name = name;
        entry.kind = is_directory ? "directory" : "file";
        HANDLE child = INVALID_HANDLE_VALUE;
        if (!ServiceObservationNamedExternalChild(
                directory, name, is_directory, roles, external_profile,
                &child, &entry.identity)) return false;
        CloseHandle(child);
        entries->push_back(std::move(entry));
      }
      if (record->NextEntryOffset == 0) break;
      if (record->NextEntryOffset <
              offsetof(FILE_ID_BOTH_DIR_INFO, FileName) ||
          record->NextEntryOffset > buffer.size() - offset) return false;
      offset += record->NextEntryOffset;
    }
  }
  std::sort(entries->begin(), entries->end(),
      [](const ServiceObservationDirectoryEntry& left,
         const ServiceObservationDirectoryEntry& right) {
        return left.name < right.name;
      });
  return true;
}

bool ServiceObservationDirectoryListsEqual(
    const std::vector<ServiceObservationDirectoryEntry>& left,
    const std::vector<ServiceObservationDirectoryEntry>& right) {
  if (left.size() != right.size()) return false;
  for (size_t index = 0; index < left.size(); ++index) {
    if (left[index].name != right[index].name ||
        left[index].kind != right[index].kind ||
        !SameServiceStoreIdentity(
            left[index].identity, right[index].identity)) return false;
  }
  return true;
}

bool ServiceObservationRevalidateDirectories(
    ServiceStoreHandle* root, const std::vector<std::string>& components,
    const std::vector<ServiceStoreIdentity>& expected) {
  if (!root || root->external_root_absent ||
      components.size() != expected.size() ||
      !RevalidateServiceExternalRoot(root)) return false;
  HANDLE current = root->object;
  ServiceObservationScopedHandles opened;
  for (size_t index = 0; index < components.size(); ++index) {
    HANDLE next = INVALID_HANDLE_VALUE;
    ServiceStoreIdentity identity;
    if (!ServiceObservationNamedChild(
            current, components[index], true, root->roles,
            expected[index].profile, &next, &identity) ||
        !SameServiceStoreIdentity(identity, expected[index])) {
      if (next != INVALID_HANDLE_VALUE) CloseHandle(next);
      return false;
    }
    opened.Add(next);
    current = next;
  }
  return RevalidateServiceExternalRoot(root);
}

bool ServiceObservationFixedRootIdentity(
    const std::string& root_kind, const InventoryRoles& roles,
    uint32_t* writes, HANDLE* root, std::string* absolute_root,
    ServiceStoreIdentity* root_identity,
    ServiceStoreIdentity* anchor_identity,
    std::vector<std::string>* missing_prefix) {
  std::string parent_path, name, witness_name;
  if (!ResolveServiceStoreRoot(
          root_kind, &parent_path, &name, &witness_name)) return false;
  *absolute_root = parent_path + "\\" + name;
  *root = INVALID_HANDLE_VALUE;
  missing_prefix->clear();
  ServiceContainerState base_state = ServiceContainerState::IoFailed;
  ServiceStoreIdentity base_identity;
  try {
    base_state = PrepareServiceBaseContainer(
        root_kind, roles, false, writes, &base_identity);
  } catch (...) {
    return false;
  }
  if (*writes != 0) return false;
  if (base_state == ServiceContainerState::Absent) {
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(
            FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &raw))) {
      return false;
    }
    const std::string program_data = Utf8(raw);
    CoTaskMemFree(raw);
    HANDLE anchor = OpenWindowsPathNoFollow(
        program_data, READ_CONTROL | FILE_READ_ATTRIBUTES,
        VerifiedObjectType::Directory);
    if (anchor == INVALID_HANDLE_VALUE) return false;
    const bool trusted = VerifyBootstrapAnchor(anchor, roles, true) &&
        CaptureExternalAncestorIdentity(anchor, anchor_identity);
    CloseHandle(anchor);
    if (!trusted) return false;
    missing_prefix->push_back("gjc-remote");
    if (root_kind == "shawl") missing_prefix->push_back("supervisors");
    missing_prefix->push_back(name);
    return true;
  }
  if (base_state != ServiceContainerState::Ready) return false;

  ServiceStoreIdentity parent_identity = base_identity;
  if (root_kind == "shawl") {
    ServiceStoreIdentity shawl_parent_identity;
    bool ambiguous = false;
    const ShawlParentState state = PrepareShawlServiceParent(
        roles, false, base_identity, writes,
        &shawl_parent_identity, &ambiguous);
    if (*writes != 0) return false;
    if (state == ShawlParentState::Absent) {
      *anchor_identity = base_identity;
      missing_prefix->push_back("supervisors");
      missing_prefix->push_back(name);
      return true;
    }
    if (state != ShawlParentState::Ready) return false;
    parent_identity = shawl_parent_identity;
  }

  HANDLE parent = INVALID_HANDLE_VALUE;
  if (!ServiceStoreOpenFixedParent(parent_path, false, &parent)) return false;
  ServiceStoreIdentity observed_parent;
  const bool parent_exact = root_kind == "shawl"
      ? CaptureServiceStoreIdentity(
            parent, roles,
            ServiceAclProfile::InternalContainerDirectory,
            &observed_parent) &&
          SameServiceStoreIdentity(observed_parent, parent_identity)
      : (parent_identity.profile ==
                ServiceAclProfile::InternalContainerDirectory
            ? CaptureServiceStoreIdentity(
                  parent, roles,
                  ServiceAclProfile::InternalContainerDirectory,
                  &observed_parent)
            : VerifyBootstrapAnchor(parent, roles) &&
                CaptureExternalAncestorIdentity(
                    parent, &observed_parent)) &&
          SameServicePhysicalIdentity(
              observed_parent, parent_identity);
  if (!parent_exact) {
    CloseHandle(parent);
    return false;
  }
  *anchor_identity = parent_identity;
  HANDLE observed_root = INVALID_HANDLE_VALUE;
  const bool root_present = ServiceStoreOpenRelativeDirectory(
      parent, name, false, &observed_root);
  const DWORD root_error = root_present ? ERROR_SUCCESS : GetLastError();
  HANDLE witness = INVALID_HANDLE_VALUE;
  const bool witness_present = ServiceStoreOpenRelativeFile(
      parent, witness_name, false, &witness);
  const DWORD witness_error = witness_present
      ? ERROR_SUCCESS : GetLastError();
  if (!root_present || !witness_present) {
    if (observed_root != INVALID_HANDLE_VALUE) CloseHandle(observed_root);
    if (witness != INVALID_HANDLE_VALUE) CloseHandle(witness);
    const bool absent = !root_present && !witness_present &&
        ServiceWindowsNotFound(root_error) &&
        ServiceWindowsNotFound(witness_error);
    CloseHandle(parent);
    if (!absent) return false;
    missing_prefix->push_back(name);
    return true;
  }
  ServiceStoreIdentity observed_root_identity, witness_identity;
  std::vector<uint8_t> witness_bytes;
  std::string roles_fingerprint, root_path, root_nonce;
  const bool exact =
      CaptureServiceStoreIdentity(
          observed_root, roles,
          ServiceStoreRootProfile(root_kind),
          &observed_root_identity) &&
      CaptureServiceStoreIdentity(
          witness, roles, ServiceAclProfile::ControlFile,
          &witness_identity) &&
      ServiceStoreReadBytes(witness, 64 * 1024, &witness_bytes) &&
      CaptureServiceStoreObjectPath(observed_root, &root_path);
  const bool fingerprint_ready = ServiceStoreRolesFingerprint(
      roles, &roles_fingerprint);
  const bool root_binding = exact && fingerprint_ready &&
      CompareStringOrdinal(
          Wide(root_path).c_str(), static_cast<int>(Wide(root_path).size()),
          Wide(*absolute_root).c_str(),
          static_cast<int>(Wide(*absolute_root).size()), TRUE) == CSTR_EQUAL &&
      ServiceRootWitnessNonce(
          std::string(witness_bytes.begin(), witness_bytes.end()),
          root_kind, root_path, roles_fingerprint, &root_nonce) &&
      std::string(witness_bytes.begin(), witness_bytes.end()) ==
          ServiceRootWitnessContent(
              root_kind, root_path, root_nonce, roles_fingerprint,
              parent_identity, observed_root_identity, {});
  CloseHandle(witness);
  CloseHandle(parent);
  if (!root_binding) {
    CloseHandle(observed_root);
    return false;
  }
  *root_identity = observed_root_identity;
  *root = observed_root;
  return true;
}
#endif

napi_value PlanServiceArtifactLocation(
    napi_env env, napi_callback_info info) {
  napi_value args[4];
  std::string root_kind, artifact_fingerprint, relative_path;
  InventoryRoles roles{};
  std::vector<std::string> relative_components;
  std::vector<std::string> location_components;
  if (!InventoryArgs(env, info, 4, args) ||
      !InventoryString(env, args[0], &root_kind) ||
      (root_kind != "releases" && root_kind != "shawl") ||
      !InventoryString(env, args[1], &artifact_fingerprint) ||
      !ValidServiceFingerprint(artifact_fingerprint) ||
      !InventoryString(env, args[2], &relative_path) ||
      !ValidServiceRelativePath(relative_path, &relative_components) ||
      !InventoryRolesArg(env, args[3], &roles)) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "plan_service_artifact_location",
        "invalid-input");
    return nullptr;
  }
  location_components.reserve(relative_components.size() + 1);
  location_components.push_back(artifact_fingerprint);
  location_components.insert(
      location_components.end(), relative_components.begin(),
      relative_components.end());
  if (!ServiceActorAuthorized(roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED", "plan_service_artifact_location",
        "access-denied");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  uint32_t writes = 0;
  HANDLE root = INVALID_HANDLE_VALUE;
  std::string absolute_root;
  ServiceStoreIdentity root_identity, anchor_identity;
  std::vector<std::string> missing_prefix;
  bool root_observed = false;
  try {
    root_observed = ServiceObservationFixedRootIdentity(
        root_kind, roles, &writes, &root, &absolute_root,
        &root_identity, &anchor_identity, &missing_prefix);
  } catch (...) {
    root_observed = false;
  }
  if (!root_observed || writes != 0) {
    if (root != INVALID_HANDLE_VALUE) CloseHandle(root);
    const DWORD error = GetLastError();
    if (error == ERROR_ACCESS_DENIED) {
      ServiceObservationError(
          env, "SERVICE_ACCESS_DENIED",
          "plan_service_artifact_location", "access-denied");
    } else if (ServiceWindowsNotFound(error)) {
      ServiceObservationError(
          env, "SERVICE_PENDING", "plan_service_artifact_location",
          "absence-unproven", true);
    } else {
      ServiceObservationError(
          env, "SERVICE_STALE", "plan_service_artifact_location",
          "identity-changed", true);
    }
    return nullptr;
  }
  ServiceObservationScopedHandles opened;
  if (root != INVALID_HANDLE_VALUE) opened.Add(root);
  ServiceStoreIdentity existing_directory_identity;
  ServiceStoreIdentity location_anchor_identity = anchor_identity;
  bool existing_identity_present = false;
  std::vector<std::string> missing_segments = missing_prefix;
  std::string missing_first;
  std::vector<std::string> observed_relative_directories;
  std::vector<ServiceStoreIdentity> observed_relative_identities;
  size_t relative_index = 0;
  HANDLE current = root;
  ServiceStoreIdentity current_identity = root_identity;
  if (root != INVALID_HANDLE_VALUE) {
    if (!CaptureServiceStoreIdentity(
            root, roles, ServiceStoreRootProfile(root_kind),
            &current_identity)) {
      ServiceObservationError(
          env, "SERVICE_ACCESS_DENIED",
          "plan_service_artifact_location", "access-denied");
      return nullptr;
    }
    location_anchor_identity = current_identity;
    for (; relative_index + 1 < location_components.size();
         ++relative_index) {
      HANDLE next = OpenWindowsRelative(
          current, Wide(location_components[relative_index]),
          FILE_GENERIC_READ | READ_CONTROL, kFileOpen,
          VerifiedObjectType::Directory);
      if (next == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (!ServiceWindowsNotFound(error)) {
          ServiceObservationError(
              env, error == ERROR_ACCESS_DENIED
                  ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
              "plan_service_artifact_location",
              error == ERROR_ACCESS_DENIED
                  ? "access-denied" : "identity-changed",
              error != ERROR_ACCESS_DENIED);
          return nullptr;
        }
        missing_segments.assign(
            location_components.begin() + relative_index,
            location_components.end());
        missing_first = location_components[relative_index];
        existing_directory_identity = current_identity;
        existing_identity_present = true;
        break;
      }
      ServiceStoreIdentity next_identity;
      if (!CaptureServiceStoreIdentity(
              next, roles, ServiceAclProfile::ReleaseDirectory,
              &next_identity)) {
        CloseHandle(next);
        ServiceObservationError(
            env, "SERVICE_ACCESS_DENIED",
            "plan_service_artifact_location", "access-denied");
        return nullptr;
      }
      opened.Add(next);
      observed_relative_directories.push_back(
          location_components[relative_index]);
      observed_relative_identities.push_back(next_identity);
      current = next;
      current_identity = next_identity;
      location_anchor_identity = next_identity;
    }
    if (missing_segments.empty()) {
      HANDLE target = OpenWindowsRelative(
          current, Wide(location_components.back()),
          FILE_READ_ATTRIBUTES | READ_CONTROL, kFileOpen,
          VerifiedObjectType::Any);
      if (target != INVALID_HANDLE_VALUE) {
        CloseHandle(target);
        ServiceObservationError(
            env, "SERVICE_PENDING", "plan_service_artifact_location",
            "absence-unproven", true);
        return nullptr;
      }
      const DWORD error = GetLastError();
      if (!ServiceWindowsNotFound(error)) {
        ServiceObservationError(
            env, error == ERROR_ACCESS_DENIED
                ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
            "plan_service_artifact_location",
            error == ERROR_ACCESS_DENIED
                ? "access-denied" : "identity-changed",
            error != ERROR_ACCESS_DENIED);
        return nullptr;
      }
      missing_segments = {location_components.back()};
      missing_first = location_components.back();
      existing_directory_identity = current_identity;
      existing_identity_present = true;
      location_anchor_identity = current_identity;
    }
  } else {
    missing_segments.insert(
        missing_segments.end(), location_components.begin(),
        location_components.end());
  }

  if (missing_segments.empty()) {
    ServiceObservationError(
        env, "SERVICE_PENDING", "plan_service_artifact_location",
        "absence-unproven", true);
    return nullptr;
  }
  if (!ServiceActorAuthorized(roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED", "plan_service_artifact_location",
        "access-denied");
    return nullptr;
  }
  ServiceStoreIdentity verified_root_identity, verified_anchor_identity;
  HANDLE rechecked_root = INVALID_HANDLE_VALUE;
  std::string rechecked_absolute_root;
  std::vector<std::string> rechecked_prefix;
  bool rechecked = ServiceObservationFixedRootIdentity(
      root_kind, roles, &writes, &rechecked_root,
      &rechecked_absolute_root, &verified_root_identity,
      &verified_anchor_identity, &rechecked_prefix) &&
      writes == 0 && rechecked_absolute_root == absolute_root &&
      rechecked_prefix == missing_prefix &&
      SameServicePhysicalIdentity(
          anchor_identity, verified_anchor_identity) &&
      (root == INVALID_HANDLE_VALUE
          ? rechecked_root == INVALID_HANDLE_VALUE
          : rechecked_root != INVALID_HANDLE_VALUE &&
              SameServiceStoreIdentity(
                  verified_root_identity, root_identity));
  if (rechecked && rechecked_root != INVALID_HANDLE_VALUE) {
    HANDLE recheck_parent = rechecked_root;
    ServiceObservationScopedHandles rechecked_directories;
    for (size_t index = 0;
         rechecked && index < observed_relative_directories.size();
         ++index) {
      HANDLE named = OpenWindowsRelative(
          recheck_parent, Wide(observed_relative_directories[index]),
          FILE_GENERIC_READ | READ_CONTROL, kFileOpen,
          VerifiedObjectType::Directory);
      ServiceStoreIdentity named_identity;
      rechecked = named != INVALID_HANDLE_VALUE &&
          CaptureServiceStoreIdentity(
              named, roles, ServiceAclProfile::ReleaseDirectory,
              &named_identity) &&
              SameServiceStoreIdentity(
              named_identity, observed_relative_identities[index]);
      if (named != INVALID_HANDLE_VALUE) {
        rechecked_directories.Add(named);
        recheck_parent = named;
      }
    }
    HANDLE target = INVALID_HANDLE_VALUE;
    if (rechecked) {
      target = OpenWindowsRelative(
          recheck_parent, Wide(missing_first),
          FILE_READ_ATTRIBUTES | READ_CONTROL, kFileOpen,
          VerifiedObjectType::Any);
      const DWORD target_error = target == INVALID_HANDLE_VALUE
          ? GetLastError() : ERROR_SUCCESS;
      if (target != INVALID_HANDLE_VALUE) CloseHandle(target);
      rechecked = target == INVALID_HANDLE_VALUE &&
          ServiceWindowsNotFound(target_error);
    }
  }
  if (rechecked_root != INVALID_HANDLE_VALUE) CloseHandle(rechecked_root);
  if (!rechecked) {
    ServiceObservationError(
        env, "SERVICE_STALE", "plan_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  if (!ServiceActorAuthorized(roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED", "plan_service_artifact_location",
        "access-denied");
    return nullptr;
  }
  const std::string slash_path =
      artifact_fingerprint + "/" + relative_path;
  std::string absolute_path = absolute_root;
  if (!absolute_path.empty() && absolute_path.back() != '\\') {
    absolute_path.push_back('\\');
  }
  for (char character : slash_path) {
    absolute_path.push_back(character == '/' ? '\\' : character);
  }
  const std::string anchor_fingerprint =
      ServiceObservationIdentityFingerprint(
          location_anchor_identity,
          "gjc-remote/windows-location-anchor/v1");
  if (!ValidServiceFingerprint(anchor_fingerprint)) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "plan_service_artifact_location",
        "io", true);
    return nullptr;
  }
  Sha256 intent_hash;
  if (!intent_hash.Ready()) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "plan_service_artifact_location",
        "io");
    return nullptr;
  }
  HashField(&intent_hash, "gjc-remote/windows-location-intent/v1");
  HashField(&intent_hash, root_kind);
  HashField(&intent_hash, artifact_fingerprint);
  HashField(&intent_hash, relative_path);
  HashField(&intent_hash, absolute_root);
  HashField(&intent_hash, absolute_path);
  HashField(&intent_hash, anchor_fingerprint);
  HashField(&intent_hash, "missing-segments");
  HashField(&intent_hash, std::to_string(missing_segments.size()));
  for (const std::string& segment : missing_segments) {
    HashField(&intent_hash, segment);
  }
  if (existing_identity_present) {
    HashField(&intent_hash,
              ServiceStoreIdentityText(existing_directory_identity));
  } else {
    HashField(&intent_hash, "no-existing-release-directory");
  }
  const std::string intent_fingerprint = intent_hash.Finish();
  if (!ValidServiceFingerprint(intent_fingerprint)) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "plan_service_artifact_location",
        "io");
    return nullptr;
  }
  napi_value result, value, segments;
  napi_create_object(env, &result);
  ServiceSetUint32(env, result, "schemaVersion", 1);
  ServiceSetString(env, result, "rootKind", root_kind);
  ServiceSetString(env, result, "artifactFingerprint",
                   artifact_fingerprint);
  ServiceSetString(env, result, "relativePath", relative_path);
  ServiceSetString(env, result, "absoluteRoot", absolute_root);
  ServiceSetString(env, result, "absolutePath", absolute_path);
  ServiceSetString(env, result, "anchorIdentityFingerprint",
                   anchor_fingerprint);
  napi_create_array_with_length(env, missing_segments.size(), &segments);
  for (uint32_t index = 0; index < missing_segments.size(); ++index) {
    napi_create_string_utf8(
        env, missing_segments[index].c_str(),
        missing_segments[index].size(), &value);
    napi_set_element(env, segments, index, value);
  }
  napi_set_named_property(env, result, "missingSegments", segments);
  ServiceObservationSetNullableIdentity(
      env, result, "existingDirectoryIdentity",
      existing_identity_present ? &existing_directory_identity : nullptr);
  ServiceSetString(env, result, "intentFingerprint",
                   intent_fingerprint);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(
      env, "SERVICE_UNSUPPORTED", "plan_service_artifact_location",
      "unsupported");
  return nullptr;
#endif
}

napi_value ResolveServiceArtifactLocation(
    napi_env env, napi_callback_info info) {
  napi_value args[3];
  ServiceStoreHandle* directory = nullptr;
  std::string relative_path, expected_sha256;
  std::vector<std::string> components;
  if (!InventoryArgs(env, info, 3, args) ||
      !ServiceStoreHandleArg(env, args[0], &directory) ||
      (directory->kind != ServiceStoreHandleKind::Root &&
       directory->kind != ServiceStoreHandleKind::Directory) ||
      (directory->root_kind != "releases" &&
       directory->root_kind != "shawl") ||
      directory->profile != ServiceAclProfile::ReleaseDirectory ||
      !InventoryString(env, args[1], &relative_path) ||
      !ValidServiceRelativePath(relative_path, &components) ||
      !InventoryString(env, args[2], &expected_sha256) ||
      !ValidServiceFingerprint(expected_sha256)) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "resolve_service_artifact_location",
        "invalid-input");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  if (!ServiceActorAuthorized(directory->roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED",
        "resolve_service_artifact_location", "access-denied");
    return nullptr;
  }
  if (!RevalidateServiceStoreHandle(directory)) {
    ServiceObservationError(
        env, "SERVICE_STALE", "resolve_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  std::string directory_path;
  if (!CaptureServiceStoreObjectPath(directory->object, &directory_path)) {
    ServiceObservationError(
        env, "SERVICE_STALE", "resolve_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  ServiceObservationScopedHandles opened;
  std::vector<ServiceStoreIdentity> relative_directory_identities;
  std::vector<std::string> relative_directory_components;
  HANDLE current = directory->object;
  for (size_t index = 0; index + 1 < components.size(); ++index) {
    HANDLE next = OpenWindowsRelative(
        current, Wide(components[index]),
        FILE_GENERIC_READ | READ_CONTROL, kFileOpen,
        VerifiedObjectType::Directory);
    if (next == INVALID_HANDLE_VALUE) {
      const DWORD error = GetLastError();
      ServiceObservationError(
          env, error == ERROR_ACCESS_DENIED
              ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
          "resolve_service_artifact_location",
          error == ERROR_ACCESS_DENIED
              ? "access-denied" : "identity-changed",
          error != ERROR_ACCESS_DENIED);
      return nullptr;
    }
    ServiceStoreIdentity identity;
    if (!CaptureServiceStoreIdentity(
            next, directory->roles,
            ServiceAclProfile::ReleaseDirectory, &identity)) {
      CloseHandle(next);
      ServiceObservationError(
          env, "SERVICE_ACCESS_DENIED",
          "resolve_service_artifact_location", "access-denied");
      return nullptr;
    }
    opened.Add(next);
    relative_directory_components.push_back(components[index]);
    relative_directory_identities.push_back(identity);
    current = next;
  }
  const std::string leaf = components.back();
  HANDLE file = OpenWindowsRelative(
      current, Wide(leaf), GENERIC_READ | READ_CONTROL,
      kFileOpen, VerifiedObjectType::File);
  if (file == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    ServiceObservationError(
        env, error == ERROR_ACCESS_DENIED
            ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
        "resolve_service_artifact_location",
        error == ERROR_ACCESS_DENIED
            ? "access-denied" : "identity-changed",
        error != ERROR_ACCESS_DENIED);
    return nullptr;
  }
  opened.Add(file);
  ServiceStoreIdentity file_identity;
  if (!CaptureServiceStoreIdentity(
          file, directory->roles,
          ServiceAclProfile::ReleaseFile, &file_identity) &&
      !CaptureServiceStoreIdentity(
          file, directory->roles,
          ServiceAclProfile::ReleaseExecutable, &file_identity)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED",
        "resolve_service_artifact_location", "access-denied");
    return nullptr;
  }
  FILE_STANDARD_INFO before_standard{}, after_standard{};
  FILE_BASIC_INFO before_basic{}, after_basic{};
  if (!GetFileInformationByHandleEx(
          file, FileStandardInfo, &before_standard,
          sizeof(before_standard)) ||
      !GetFileInformationByHandleEx(
          file, FileBasicInfo, &before_basic, sizeof(before_basic)) ||
      before_standard.Directory || before_standard.DeletePending ||
      before_standard.NumberOfLinks != 1 ||
      (before_basic.FileAttributes & FILE_ATTRIBUTE_DEVICE) != 0) {
    ServiceObservationError(
        env, "SERVICE_STALE", "resolve_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  ServiceStoreFileFacts file_facts;
  if (!HashRetainedServiceArtifact(
          file, nullptr, true, kServiceArtifactMaxBytes,
          &file_facts) ||
      file_facts.sha256 != expected_sha256 ||
      !GetFileInformationByHandleEx(
          file, FileStandardInfo, &after_standard,
          sizeof(after_standard)) ||
      !GetFileInformationByHandleEx(
          file, FileBasicInfo, &after_basic, sizeof(after_basic)) ||
      before_standard.NumberOfLinks != 1 ||
      after_standard.NumberOfLinks != 1 ||
      before_basic.CreationTime.QuadPart !=
          after_basic.CreationTime.QuadPart ||
      before_basic.LastWriteTime.QuadPart !=
          after_basic.LastWriteTime.QuadPart ||
      before_basic.ChangeTime.QuadPart !=
          after_basic.ChangeTime.QuadPart ||
      before_basic.FileAttributes != after_basic.FileAttributes ||
      before_standard.EndOfFile.QuadPart !=
          after_standard.EndOfFile.QuadPart ||
      before_standard.AllocationSize.QuadPart !=
          after_standard.AllocationSize.QuadPart ||
      !SameServiceStoreIdentity(
          file_identity,
          [&]() {
            ServiceStoreIdentity after_identity;
            if (!CaptureServiceStoreIdentity(
                    file, directory->roles, file_identity.profile,
                    &after_identity)) return ServiceStoreIdentity{};
            return after_identity;
          }())) {
    ServiceObservationError(
        env, "SERVICE_STALE", "resolve_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  HANDLE named = OpenWindowsRelative(
      current, Wide(leaf), GENERIC_READ | READ_CONTROL,
      kFileOpen, VerifiedObjectType::File);
  ServiceStoreIdentity named_identity;
  const bool named_exact = named != INVALID_HANDLE_VALUE &&
      CaptureServiceStoreIdentity(
          named, directory->roles, file_identity.profile,
          &named_identity) &&
      SameServiceStoreIdentity(named_identity, file_identity);
  if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
  if (!named_exact) {
    ServiceObservationError(
        env, "SERVICE_STALE", "resolve_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  if (!ServiceActorAuthorized(directory->roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED",
        "resolve_service_artifact_location", "access-denied");
    return nullptr;
  }
  if (!RevalidateServiceStoreHandle(directory)) {
    ServiceObservationError(
        env, "SERVICE_STALE", "resolve_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  if (!relative_directory_components.empty()) {
    HANDLE verify_current = directory->object;
    for (size_t index = 0;
         index < relative_directory_components.size(); ++index) {
      HANDLE check = OpenWindowsRelative(
          verify_current,
          Wide(relative_directory_components[index]),
          FILE_GENERIC_READ | READ_CONTROL, kFileOpen,
          VerifiedObjectType::Directory);
      ServiceStoreIdentity check_identity;
      const bool exact = check != INVALID_HANDLE_VALUE &&
          CaptureServiceStoreIdentity(
              check, directory->roles,
              ServiceAclProfile::ReleaseDirectory,
              &check_identity) &&
          SameServiceStoreIdentity(
              check_identity,
              relative_directory_identities[index]);
      if (check != INVALID_HANDLE_VALUE) CloseHandle(check);
      if (!exact) {
        ServiceObservationError(
            env, "SERVICE_STALE",
            "resolve_service_artifact_location",
            "identity-changed", true);
        return nullptr;
      }
      verify_current = opened.values[index];
    }
  }
  ServiceStoreIdentity containing_directory_identity;
  const ServiceAclProfile containing_profile =
      ServiceAclProfile::ReleaseDirectory;
  if (!CaptureServiceStoreIdentity(
          current, directory->roles, containing_profile,
          &containing_directory_identity)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED",
        "resolve_service_artifact_location", "access-denied");
    return nullptr;
  }
  DWORD path_size = GetFinalPathNameByHandleW(
      file, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (path_size == 0 || path_size > 32768) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "resolve_service_artifact_location",
        "io", true);
    return nullptr;
  }
  std::vector<wchar_t> path_buffer(path_size + 1);
  const DWORD path_length = GetFinalPathNameByHandleW(
      file, path_buffer.data(), static_cast<DWORD>(path_buffer.size()),
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (path_length == 0 || path_length >= path_buffer.size()) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "resolve_service_artifact_location",
        "io", true);
    return nullptr;
  }
  std::wstring canonical_file(path_buffer.data(), path_length);
  if (canonical_file.rfind(L"\\\\?\\", 0) == 0) {
    canonical_file.erase(0, 4);
  }
  const std::string absolute_path = Utf8(canonical_file);
  WindowsPathParts parsed_file;
  if (directory_path.empty()) {
    ServiceObservationError(
        env, "SERVICE_STALE", "resolve_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  const std::string parent_prefix = directory_path +
      (directory_path.back() == '\\' ? "" : "\\");
  const std::wstring wide_file = Wide(absolute_path);
  const std::wstring wide_prefix = Wide(parent_prefix);
  std::wstring expected_relative = Wide(relative_path);
  std::replace(expected_relative.begin(), expected_relative.end(), L'/', L'\\');
  if (!ParseWindowsPath(absolute_path, &parsed_file) ||
      wide_file.size() <= wide_prefix.size() ||
      CompareStringOrdinal(
          wide_file.data(), static_cast<int>(wide_prefix.size()),
          wide_prefix.data(), static_cast<int>(wide_prefix.size()), TRUE) !=
          CSTR_EQUAL ||
      CompareStringOrdinal(
          wide_file.data() + wide_prefix.size(),
          static_cast<int>(wide_file.size() - wide_prefix.size()),
          expected_relative.data(),
          static_cast<int>(expected_relative.size()), TRUE) != CSTR_EQUAL) {
    ServiceObservationError(
        env, "SERVICE_STALE", "resolve_service_artifact_location",
        "identity-changed", true);
    return nullptr;
  }
  if (!ServiceActorAuthorized(directory->roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED",
        "resolve_service_artifact_location", "access-denied");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetUint32(env, result, "schemaVersion", 1);
  ServiceSetString(env, result, "publishedPath", relative_path);
  ServiceSetString(env, result, "absolutePath", absolute_path);
  napi_set_named_property(
      env, result, "directoryIdentity",
      ServiceStoreIdentityValue(env, containing_directory_identity));
  napi_set_named_property(
      env, result, "fileIdentity",
      ServiceStoreIdentityValue(env, file_identity));
  ServiceSetString(env, result, "fileSha256", file_facts.sha256);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(
      env, "SERVICE_UNSUPPORTED", "resolve_service_artifact_location",
      "unsupported");
  return nullptr;
#endif
}

napi_value OpenServiceExternalRoot(
    napi_env env, napi_callback_info info) {
  napi_value args[3];
  std::string absolute_path, profile;
  InventoryRoles roles{};
  ServiceExternalProfile external_profile;
  if (!InventoryArgs(env, info, 3, args) ||
      !InventoryString(env, args[0], &absolute_path) ||
      absolute_path.size() > 4096 ||
      !InventoryString(env, args[1], &profile) ||
      !ParseServiceExternalProfile(profile, &external_profile) ||
      !InventoryRolesArg(env, args[2], &roles)) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "open_service_external_root",
        "invalid-input");
    return nullptr;
  }
  if (!ServiceActorAuthorized(roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED", "open_service_external_root",
        "access-denied");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  WindowsPathParts parts;
  if (!ParseWindowsPath(absolute_path, &parts) ||
      parts.components.empty() || parts.components.size() > 64) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "open_service_external_root",
        "invalid-input");
    return nullptr;
  }
  auto* handle = new (std::nothrow) ServiceStoreHandle();
  if (!handle) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "open_service_external_root", "io");
    return nullptr;
  }
  handle->env = env;
  handle->kind = ServiceStoreHandleKind::ExternalRoot;
  handle->access = ServiceStoreAccess::Read;
  handle->root_kind = "external-observation";
  handle->external_profile = profile;
  handle->external_absolute_path = ServiceWindowsPathText(parts);
  handle->fixed_parent_path = Utf8(parts.root);
  handle->roles = roles;
  try {
    handle->external_ancestors.reserve(parts.components.size());
    handle->external_ancestor_identities.reserve(parts.components.size());
    handle->external_components.reserve(parts.components.size());
    handle->external_missing_segments.reserve(parts.components.size());
  } catch (...) {
    delete handle;
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "open_service_external_root", "io");
    return nullptr;
  }
  if (!ServiceStoreRolesFingerprint(
          roles, &handle->roles_fingerprint)) {
    delete handle;
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "open_service_external_root", "io");
    return nullptr;
  }
  HANDLE current = OpenWindowsRoot(
      parts.root, kWindowsTraversalAccess | READ_CONTROL);
  ServiceStoreIdentity current_identity;
  if (current == INVALID_HANDLE_VALUE ||
      !CaptureExternalAncestorIdentity(current, &current_identity)) {
    if (current != INVALID_HANDLE_VALUE) CloseHandle(current);
    delete handle;
    const DWORD error = GetLastError();
    ServiceObservationError(
        env, error == ERROR_ACCESS_DENIED
            ? "SERVICE_ACCESS_DENIED" : "SERVICE_IO_FAILED",
        "open_service_external_root",
        error == ERROR_ACCESS_DENIED ? "access-denied" : "io",
        error != ERROR_ACCESS_DENIED);
    return nullptr;
  }
  handle->external_ancestors.push_back(current);
  handle->external_ancestor_identities.push_back(current_identity);

  const auto absentFrom = [&](size_t missing_index) -> bool {
    ServiceStoreIdentity anchor_identity;
    if (!CaptureExternalAncestorIdentity(current, &anchor_identity)) {
      return false;
    }
    HANDLE retained_anchor = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(
            GetCurrentProcess(), current, GetCurrentProcess(),
            &retained_anchor, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
      return false;
    }
    handle->object = retained_anchor;
    handle->binding_parent_identity = anchor_identity;
    handle->external_root_absent = true;
    handle->external_missing_segments.clear();
    for (size_t index = missing_index;
         index < parts.components.size(); ++index) {
      handle->external_missing_segments.push_back(
          Utf8(parts.components[index]));
    }
    return !handle->external_missing_segments.empty();
  };

  bool opened_root = false;
  for (size_t index = 0; index < parts.components.size(); ++index) {
    const bool final = index + 1 == parts.components.size();
    HANDLE next = OpenWindowsRelative(
        current, parts.components[index],
        final ? FILE_GENERIC_READ | READ_CONTROL
              : kWindowsTraversalAccess | READ_CONTROL,
        kFileOpen, VerifiedObjectType::Directory);
    if (next == INVALID_HANDLE_VALUE) {
      const DWORD error = GetLastError();
      if (!ServiceWindowsNotFound(error)) {
        CloseServiceStoreNative(handle, true);
        delete handle;
        ServiceObservationError(
            env, error == ERROR_ACCESS_DENIED
                ? "SERVICE_ACCESS_DENIED"
                : error == ERROR_NOT_SUPPORTED
                    ? "SERVICE_UNSUPPORTED" : "SERVICE_IO_FAILED",
            "open_service_external_root",
            error == ERROR_ACCESS_DENIED ? "access-denied" :
                error == ERROR_NOT_SUPPORTED ? "unsupported" : "io",
            error != ERROR_ACCESS_DENIED &&
                error != ERROR_NOT_SUPPORTED);
        return nullptr;
      }
      if (!absentFrom(index)) {
        CloseServiceStoreNative(handle, true);
        delete handle;
        ServiceObservationError(
            env, "SERVICE_ACCESS_DENIED",
            "open_service_external_root", "access-denied");
        return nullptr;
      }
      break;
    }
    if (final) {
      ServiceExternalAclPolicy inferred_policy =
          ServiceExternalAclPolicy::Unresolved;
      ServiceStoreIdentity identity;
      if (!InferServiceExternalAclPolicy(
              next, roles, external_profile, true,
              &inferred_policy, &identity)) {
        CloseHandle(next);
        CloseServiceStoreNative(handle, true);
        delete handle;
        ServiceObservationError(
            env, "SERVICE_ACCESS_DENIED",
            "open_service_external_root", "access-denied");
        return nullptr;
      }
      handle->name = Utf8(parts.components[index]);
      handle->external_policy = inferred_policy;
      handle->identity = identity;
      handle->object = next;
      opened_root = true;
      break;
    }
    if (!CaptureExternalAncestorIdentity(next, &current_identity)) {
      CloseHandle(next);
      CloseServiceStoreNative(handle, true);
      delete handle;
      ServiceObservationError(
          env, "SERVICE_STALE", "open_service_external_root",
          "identity-changed", true);
      return nullptr;
    }
    handle->external_components.push_back(Utf8(parts.components[index]));
    handle->external_ancestors.push_back(next);
    handle->external_ancestor_identities.push_back(current_identity);
    current = next;
  }
  if (!opened_root && !handle->external_root_absent) {
    CloseServiceStoreNative(handle, true);
    delete handle;
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "open_service_external_root", "io",
        true);
    return nullptr;
  }
  if (handle->external_root_absent &&
      !RevalidateServiceExternalRoot(handle)) {
    CloseServiceStoreNative(handle, true);
    delete handle;
    ServiceObservationError(
        env, "SERVICE_STALE", "open_service_external_root",
        "identity-changed", true);
    return nullptr;
  }
  if (!handle->external_root_absent &&
      !RevalidateServiceExternalRoot(handle)) {
    CloseServiceStoreNative(handle, true);
    delete handle;
    ServiceObservationError(
        env, "SERVICE_STALE", "open_service_external_root",
        "identity-changed", true);
    return nullptr;
  }
  napi_value wrapped = WrapServiceStoreHandle(env, handle);
  if (!wrapped) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "open_service_external_root", "io");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", wrapped);
  ServiceSetString(env, result, "profile", profile);
  ServiceSetString(env, result, "absolutePath",
                   handle->external_absolute_path);
  ServiceObservationSetNullableIdentity(
      env, result, "rootIdentity",
      handle->external_root_absent ? nullptr : &handle->identity);
  if (handle->external_root_absent) {
    napi_set_named_property(
        env, result, "absence",
        ServiceObservationAbsenceValue(
            env, handle->binding_parent_identity,
            handle->external_missing_segments));
  } else {
    napi_value null_value;
    napi_get_null(env, &null_value);
    napi_set_named_property(env, result, "absence", null_value);
  }
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(
      env, "SERVICE_UNSUPPORTED", "open_service_external_root",
      "unsupported");
  return nullptr;
#endif
}

napi_value ReadServiceExternalObject(
    napi_env env, napi_callback_info info) {
  napi_value args[4];
  ServiceStoreHandle* external_root = nullptr;
  std::string relative_path, mode;
  uint64_t maximum = 0;
  std::vector<std::string> components;
  const bool shape = InventoryArgs(env, info, 4, args) &&
      ServiceStoreHandleArg(env, args[0], &external_root) &&
      external_root->kind == ServiceStoreHandleKind::ExternalRoot &&
      InventoryString(env, args[1], &relative_path) &&
      InventoryString(env, args[2], &mode) &&
      (relative_path.empty()
          ? mode == "directory"
          : ValidServiceRelativePath(relative_path, &components)) &&
      ServiceStoreNumber(env, args[3], 1024ULL * 1024ULL, &maximum);
  if (!shape) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "read_service_external_object",
        "invalid-input");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  ServiceExternalProfile external_profile;
  if (!ParseServiceExternalProfile(
          external_root->external_profile, &external_profile)) {
    ServiceObservationError(
        env, "SERVICE_STALE", "read_service_external_object",
        "identity-changed", true);
    return nullptr;
  }
  if (mode != "facts" && mode != "directory" &&
      mode != "bytes" && mode != "first-line") {
    ServiceObservationError(
        env, "SERVICE_UNSUPPORTED", "read_service_external_object",
        "unsupported");
    return nullptr;
  }
  const bool directory_mode = mode == "directory";
  const bool facts_mode = mode == "facts";
  const bool bytes_mode = mode == "bytes";
  const bool first_line_mode = mode == "first-line";
  const uint64_t maximum_bytes = bytes_mode
      ? 1024ULL * 1024ULL : first_line_mode ? 16ULL * 1024ULL : 0;
  if (((facts_mode || directory_mode) && maximum != 0) ||
      (bytes_mode && (maximum == 0 || maximum > maximum_bytes)) ||
      (first_line_mode &&
       (maximum == 0 || maximum > maximum_bytes))) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "read_service_external_object",
        "invalid-input");
    return nullptr;
  }
  if (!ServiceActorAuthorized(external_root->roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED", "read_service_external_object",
        "access-denied");
    return nullptr;
  }
  if (!RevalidateServiceExternalRoot(external_root)) {
    ServiceObservationError(
        env, "SERVICE_STALE", "read_service_external_object",
        "identity-changed", true);
    return nullptr;
  }
  if (external_root->external_components.size() +
          external_root->external_missing_segments.size() +
          components.size() > 64) {
    ServiceObservationError(
        env, "SERVICE_OUTPUT_LIMIT", "read_service_external_object",
        "limit");
    return nullptr;
  }
  if (external_root->external_root_absent) {
    if (!ServiceActorAuthorized(external_root->roles)) {
      ServiceObservationError(
          env, "SERVICE_ACCESS_DENIED",
          "read_service_external_object", "access-denied");
      return nullptr;
    }
    std::vector<std::string> missing =
        external_root->external_missing_segments;
    missing.insert(missing.end(), components.begin(), components.end());
    napi_value result;
    napi_create_object(env, &result);
    ServiceSetString(env, result, "kind", "absent");
    ServiceObservationSetNullableIdentity(
        env, result, "identity", nullptr);
    napi_set_named_property(
        env, result, "absence",
        ServiceObservationAbsenceValue(
            env, external_root->binding_parent_identity, missing));
    napi_value null_value;
    napi_get_null(env, &null_value);
    napi_set_named_property(env, result, "bytes", null_value);
    napi_set_named_property(env, result, "entries", null_value);
    ServiceSetUint32(env, result, "writes", 0);
    return result;
  }

  ServiceObservationScopedHandles opened;
  std::vector<std::string> parent_components;
  std::vector<ServiceStoreIdentity> parent_identities;
  HANDLE current = external_root->object;
  ServiceStoreIdentity current_identity = external_root->identity;
  for (size_t index = 0; index + 1 < components.size(); ++index) {
    HANDLE next = INVALID_HANDLE_VALUE;
    ServiceStoreIdentity identity;
    if (!ServiceObservationNamedExternalChild(
            current, components[index], true, external_root->roles,
            external_profile, &next, &identity)) {
      const DWORD error = GetLastError();
      if (!ServiceWindowsNotFound(error)) {
        ServiceObservationError(
            env, error == ERROR_ACCESS_DENIED
                ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
            "read_service_external_object",
            error == ERROR_ACCESS_DENIED
                ? "access-denied" : "identity-changed",
            error != ERROR_ACCESS_DENIED);
        return nullptr;
      }
      if (!ServiceObservationRevalidateDirectories(
              external_root, parent_components,
              parent_identities)) {
        ServiceObservationError(
            env, "SERVICE_STALE", "read_service_external_object",
            "identity-changed", true);
        return nullptr;
      }
      HANDLE recheck = OpenWindowsRelative(
          current, Wide(components[index]),
          FILE_READ_ATTRIBUTES | READ_CONTROL, kFileOpen,
          VerifiedObjectType::Any);
      const DWORD recheck_error = recheck == INVALID_HANDLE_VALUE
          ? GetLastError() : ERROR_SUCCESS;
      if (recheck != INVALID_HANDLE_VALUE) CloseHandle(recheck);
      if (!ServiceWindowsNotFound(recheck_error)) {
        ServiceObservationError(
            env, "SERVICE_STALE", "read_service_external_object",
            "absence-unproven", true);
        return nullptr;
      }
      if (!ServiceActorAuthorized(external_root->roles)) {
        ServiceObservationError(
            env, "SERVICE_ACCESS_DENIED",
            "read_service_external_object", "access-denied");
        return nullptr;
      }
      std::vector<std::string> missing(
          components.begin() + index, components.end());
      napi_value result, null_value;
      napi_create_object(env, &result);
      ServiceSetString(env, result, "kind", "absent");
      ServiceObservationSetNullableIdentity(env, result, "identity", nullptr);
      napi_set_named_property(
          env, result, "absence",
          ServiceObservationAbsenceValue(env, current_identity, missing));
      napi_get_null(env, &null_value);
      napi_set_named_property(env, result, "bytes", null_value);
      napi_set_named_property(env, result, "entries", null_value);
      ServiceSetUint32(env, result, "writes", 0);
      return result;
    }
    opened.Add(next);
    parent_components.push_back(components[index]);
    parent_identities.push_back(identity);
    current_identity = identity;
    current = next;
  }

  const bool observe_external_root = components.empty();
  const std::string leaf = observe_external_root
      ? std::string() : components.back();
  if (directory_mode) {
    HANDLE directory = observe_external_root
        ? external_root->object : INVALID_HANDLE_VALUE;
    ServiceStoreIdentity identity = observe_external_root
        ? current_identity : ServiceStoreIdentity{};
    if (!observe_external_root && !ServiceObservationNamedExternalChild(
            current, leaf, true, external_root->roles, external_profile,
            &directory, &identity)) {
      const DWORD error = GetLastError();
      if (ServiceWindowsNotFound(error)) {
        if (!ServiceObservationRevalidateDirectories(
                external_root, parent_components,
                parent_identities)) {
          ServiceObservationError(
              env, "SERVICE_STALE", "read_service_external_object",
              "identity-changed", true);
          return nullptr;
        }
        if (!ServiceActorAuthorized(external_root->roles)) {
          ServiceObservationError(
              env, "SERVICE_ACCESS_DENIED",
              "read_service_external_object", "access-denied");
          return nullptr;
        }
        HANDLE recheck = OpenWindowsRelative(
            current, Wide(leaf), FILE_READ_ATTRIBUTES | READ_CONTROL,
            kFileOpen, VerifiedObjectType::Any);
        const DWORD recheck_error = recheck == INVALID_HANDLE_VALUE
            ? GetLastError() : ERROR_SUCCESS;
        if (recheck != INVALID_HANDLE_VALUE) CloseHandle(recheck);
        if (!ServiceWindowsNotFound(recheck_error)) {
          ServiceObservationError(
              env, "SERVICE_STALE", "read_service_external_object",
              "absence-unproven", true);
          return nullptr;
        }
        napi_value result, null_value;
        napi_create_object(env, &result);
        ServiceSetString(env, result, "kind", "absent");
        ServiceObservationSetNullableIdentity(env, result, "identity", nullptr);
        std::vector<std::string> missing{leaf};
        napi_set_named_property(
            env, result, "absence",
            ServiceObservationAbsenceValue(env, current_identity, missing));
        napi_get_null(env, &null_value);
        napi_set_named_property(env, result, "bytes", null_value);
        napi_set_named_property(env, result, "entries", null_value);
        ServiceSetUint32(env, result, "writes", 0);
        return result;
      }
      ServiceObservationError(
          env, error == ERROR_ACCESS_DENIED
              ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
          "read_service_external_object",
          error == ERROR_ACCESS_DENIED
              ? "access-denied" : "identity-changed",
          error != ERROR_ACCESS_DENIED);
      return nullptr;
    }
    ServiceObservationScopedHandles directory_handle;
    if (!observe_external_root) directory_handle.Add(directory);
    FILE_BASIC_INFO before_basic{}, after_basic{};
    FILE_STANDARD_INFO before_standard{}, after_standard{};
    std::vector<ServiceObservationDirectoryEntry> first, second;
    bool output_limit = false;
    const bool before =
        GetFileInformationByHandleEx(
            directory, FileBasicInfo, &before_basic,
            sizeof(before_basic)) &&
        GetFileInformationByHandleEx(
            directory, FileStandardInfo, &before_standard,
            sizeof(before_standard)) &&
        !before_standard.DeletePending &&
        ServiceObservationDirectorySnapshot(
            directory, external_root->roles, external_profile,
            &first, &output_limit);
    if (!before && output_limit) {
      ServiceObservationError(
          env, "SERVICE_OUTPUT_LIMIT", "read_service_external_object",
          "limit");
      return nullptr;
    }
    const bool after = before &&
        ServiceObservationDirectorySnapshot(
            directory, external_root->roles, external_profile,
            &second, &output_limit) &&
        GetFileInformationByHandleEx(
            directory, FileBasicInfo, &after_basic,
            sizeof(after_basic)) &&
        GetFileInformationByHandleEx(
            directory, FileStandardInfo, &after_standard,
            sizeof(after_standard));
    ServiceStoreIdentity final_identity;
    const bool stable = after &&
        CaptureServiceObservationIdentity(
            directory, external_root->roles,
            identity.profile, &final_identity) &&
        SameServiceStoreIdentity(identity, final_identity) &&
        before_basic.CreationTime.QuadPart ==
            after_basic.CreationTime.QuadPart &&
        before_basic.LastWriteTime.QuadPart ==
            after_basic.LastWriteTime.QuadPart &&
        before_basic.ChangeTime.QuadPart ==
            after_basic.ChangeTime.QuadPart &&
        before_basic.FileAttributes == after_basic.FileAttributes &&
        before_standard.EndOfFile.QuadPart ==
            after_standard.EndOfFile.QuadPart &&
        before_standard.AllocationSize.QuadPart ==
            after_standard.AllocationSize.QuadPart &&
        before_standard.NumberOfLinks ==
            after_standard.NumberOfLinks &&
        ServiceObservationDirectoryListsEqual(first, second) &&
        [&]() {
          if (observe_external_root) {
            return ServiceObservationRevalidateDirectories(
                external_root, parent_components, parent_identities);
          }
          std::vector<std::string> checked_components = parent_components;
          checked_components.push_back(leaf);
          std::vector<ServiceStoreIdentity> checked_identities =
              parent_identities;
          checked_identities.push_back(identity);
          return ServiceObservationRevalidateDirectories(
              external_root, checked_components, checked_identities);
        }();
    if (!stable) {
      if (output_limit) {
        ServiceObservationError(
            env, "SERVICE_OUTPUT_LIMIT", "read_service_external_object",
            "limit");
      } else {
        ServiceObservationError(
            env, "SERVICE_STALE", "read_service_external_object",
            "identity-changed", true);
      }
      return nullptr;
    }
    uint64_t marker_bytes = 0;
    for (const ServiceObservationDirectoryEntry& entry : first) {
      marker_bytes += entry.name.size();
    }
    if (first.size() > 100000ULL -
            external_root->external_observed_entries ||
        marker_bytes > 64ULL * 1024ULL * 1024ULL -
            external_root->external_observed_name_bytes) {
      ServiceObservationError(
          env, "SERVICE_OUTPUT_LIMIT", "read_service_external_object",
          "limit");
      return nullptr;
    }
    external_root->external_observed_entries += first.size();
    external_root->external_observed_name_bytes += marker_bytes;
    if (!ServiceActorAuthorized(external_root->roles)) {
      ServiceObservationError(
          env, "SERVICE_ACCESS_DENIED",
          "read_service_external_object", "access-denied");
      return nullptr;
    }
    napi_value result, entries;
    napi_create_object(env, &result);
    ServiceSetString(env, result, "kind", "directory");
    napi_set_named_property(
        env, result, "identity",
        ServiceStoreIdentityValue(env, identity));
    napi_value null_value;
    napi_get_null(env, &null_value);
    napi_set_named_property(env, result, "absence", null_value);
    napi_set_named_property(env, result, "bytes", null_value);
    napi_create_array_with_length(env, first.size(), &entries);
    for (uint32_t index = 0; index < first.size(); ++index) {
      napi_value entry;
      napi_create_object(env, &entry);
      ServiceSetString(env, entry, "name", first[index].name);
      ServiceSetString(env, entry, "kind", first[index].kind);
      napi_set_named_property(
          env, entry, "identity",
          ServiceStoreIdentityValue(env, first[index].identity));
      napi_set_element(env, entries, index, entry);
    }
    napi_set_named_property(env, result, "entries", entries);
    ServiceSetUint32(env, result, "writes", 0);
    return result;
  }

  const std::wstring wide_leaf = Wide(leaf);
  HANDLE file = INVALID_HANDLE_VALUE;
  ServiceStoreIdentity identity;
  if (!ServiceObservationNamedExternalChild(
          current, leaf, false, external_root->roles, external_profile,
          &file, &identity)) {
    const DWORD error = GetLastError();
    if (ServiceWindowsNotFound(error)) {
      if (!ServiceObservationRevalidateDirectories(
              external_root, parent_components,
              parent_identities)) {
        ServiceObservationError(
            env, "SERVICE_STALE", "read_service_external_object",
            "identity-changed", true);
        return nullptr;
      }
      if (!ServiceActorAuthorized(external_root->roles)) {
        ServiceObservationError(
            env, "SERVICE_ACCESS_DENIED",
            "read_service_external_object", "access-denied");
        return nullptr;
      }
      HANDLE recheck = OpenWindowsRelative(
          current, wide_leaf, FILE_READ_ATTRIBUTES | READ_CONTROL,
          kFileOpen, VerifiedObjectType::Any);
      const DWORD recheck_error = recheck == INVALID_HANDLE_VALUE
          ? GetLastError() : ERROR_SUCCESS;
      if (recheck != INVALID_HANDLE_VALUE) CloseHandle(recheck);
      if (!ServiceWindowsNotFound(recheck_error)) {
        ServiceObservationError(
            env, "SERVICE_STALE", "read_service_external_object",
            "absence-unproven", true);
        return nullptr;
      }
      napi_value result, null_value;
      napi_create_object(env, &result);
      ServiceSetString(env, result, "kind", "absent");
      ServiceObservationSetNullableIdentity(env, result, "identity", nullptr);
      std::vector<std::string> missing{leaf};
      napi_set_named_property(
          env, result, "absence",
          ServiceObservationAbsenceValue(env, current_identity, missing));
      napi_get_null(env, &null_value);
      napi_set_named_property(env, result, "bytes", null_value);
      napi_set_named_property(env, result, "entries", null_value);
      ServiceSetUint32(env, result, "writes", 0);
      return result;
    }
    ServiceObservationError(
        env, error == ERROR_ACCESS_DENIED
            ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
        "read_service_external_object",
        error == ERROR_ACCESS_DENIED
            ? "access-denied" : "identity-changed",
        error != ERROR_ACCESS_DENIED);
    return nullptr;
  }
  ServiceObservationScopedHandles file_handle;
  file_handle.Add(file);
  FILE_BASIC_INFO before_basic{}, after_basic{};
  FILE_STANDARD_INFO before_standard{}, after_standard{};
  if (!GetFileInformationByHandleEx(
          file, FileBasicInfo, &before_basic, sizeof(before_basic)) ||
      !GetFileInformationByHandleEx(
          file, FileStandardInfo, &before_standard,
          sizeof(before_standard)) ||
      before_standard.Directory || before_standard.DeletePending ||
      before_standard.NumberOfLinks != 1 ||
      (before_basic.FileAttributes & FILE_ATTRIBUTE_DEVICE) != 0 ||
      before_standard.EndOfFile.QuadPart < 0) {
    ServiceObservationError(
        env, "SERVICE_STALE", "read_service_external_object",
        "identity-changed", true);
    return nullptr;
  }
  const bool dot_env = CompareStringOrdinal(
      wide_leaf.data(), static_cast<int>(wide_leaf.size()),
      L".env", 4, TRUE) == CSTR_EQUAL;
  if (bytes_mode && maximum > 256ULL * 1024ULL && dot_env) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "read_service_external_object",
        "invalid-input");
    return nullptr;
  }
  std::vector<uint8_t> content;
  if (bytes_mode) {
    const uint64_t size = static_cast<uint64_t>(
        before_standard.EndOfFile.QuadPart);
    if (size > maximum) {
      ServiceObservationError(
          env, "SERVICE_OUTPUT_LIMIT", "read_service_external_object",
          "limit");
      return nullptr;
    }
    try {
      content.resize(static_cast<size_t>(size));
    } catch (...) {
      ServiceObservationError(
          env, "SERVICE_IO_FAILED", "read_service_external_object",
          "io");
      return nullptr;
    }
    LARGE_INTEGER position{};
    bool read_exact = SetFilePointerEx(
        file, position, nullptr, FILE_BEGIN) != FALSE;
    size_t offset = 0;
    while (read_exact && offset < content.size()) {
      DWORD count = 0;
      const DWORD request = static_cast<DWORD>(std::min<size_t>(
          content.size() - offset, MAXDWORD));
      read_exact = ReadFile(
          file, content.data() + offset, request, &count, nullptr) &&
          count != 0;
      offset += count;
    }
    if (!read_exact || offset != content.size()) {
      ServiceObservationError(
          env, "SERVICE_STALE", "read_service_external_object",
          "identity-changed", true);
      return nullptr;
    }
  } else if (first_line_mode) {
    try {
      content.reserve(static_cast<size_t>(maximum));
    } catch (...) {
      ServiceObservationError(
          env, "SERVICE_IO_FAILED", "read_service_external_object",
          "io");
      return nullptr;
    }
    LARGE_INTEGER position{};
    if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) {
      ServiceObservationError(
          env, "SERVICE_IO_FAILED", "read_service_external_object",
          "io", true);
      return nullptr;
    }
    bool newline = false;
    while (content.size() < maximum) {
      uint8_t byte = 0;
      DWORD count = 0;
      if (!ReadFile(file, &byte, 1, &count, nullptr)) {
        ServiceObservationError(
            env, "SERVICE_IO_FAILED", "read_service_external_object",
            "io", true);
        return nullptr;
      }
      if (count == 0) break;
      content.push_back(byte);
      if (byte == '\n') {
        newline = true;
        break;
      }
    }
    if (!newline && content.size() == maximum &&
        static_cast<uint64_t>(before_standard.EndOfFile.QuadPart) >
            content.size()) {
      ServiceObservationError(
          env, "SERVICE_OUTPUT_LIMIT", "read_service_external_object",
          "limit");
      return nullptr;
    }
  }
  if (!GetFileInformationByHandleEx(
          file, FileBasicInfo, &after_basic, sizeof(after_basic)) ||
      !GetFileInformationByHandleEx(
          file, FileStandardInfo, &after_standard,
          sizeof(after_standard)) ||
      before_basic.CreationTime.QuadPart !=
          after_basic.CreationTime.QuadPart ||
      before_basic.LastWriteTime.QuadPart !=
          after_basic.LastWriteTime.QuadPart ||
      before_basic.ChangeTime.QuadPart !=
          after_basic.ChangeTime.QuadPart ||
      before_basic.FileAttributes != after_basic.FileAttributes ||
      before_standard.EndOfFile.QuadPart !=
          after_standard.EndOfFile.QuadPart ||
      before_standard.AllocationSize.QuadPart !=
          after_standard.AllocationSize.QuadPart ||
      after_standard.NumberOfLinks != 1 ||
      !CaptureServiceObservationIdentity(
          file, external_root->roles,
          identity.profile,
          &current_identity) ||
      !SameServiceStoreIdentity(identity, current_identity)) {
    ServiceObservationError(
        env, "SERVICE_STALE", "read_service_external_object",
        "identity-changed", true);
    return nullptr;
  }
  HANDLE named = OpenWindowsRelative(
      current, wide_leaf, GENERIC_READ | READ_CONTROL,
      kFileOpen, VerifiedObjectType::File);
  ServiceStoreIdentity named_identity;
  const bool named_exact = named != INVALID_HANDLE_VALUE &&
      CaptureServiceObservationIdentity(
          named, external_root->roles,
          identity.profile,
          &named_identity) &&
      SameServiceStoreIdentity(identity, named_identity);
  if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
  if (!named_exact ||
      !ServiceObservationRevalidateDirectories(
          external_root, parent_components, parent_identities)) {
    ServiceObservationError(
        env, "SERVICE_STALE", "read_service_external_object",
        "identity-changed", true);
    return nullptr;
  }
  if (!ServiceActorAuthorized(external_root->roles)) {
    ServiceObservationError(
        env, "SERVICE_ACCESS_DENIED",
        "read_service_external_object", "access-denied");
    return nullptr;
  }
  napi_value result, value;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "kind", "file");
  napi_set_named_property(
      env, result, "identity", ServiceStoreIdentityValue(env, identity));
  napi_get_null(env, &value);
  napi_set_named_property(env, result, "absence", value);
  if (bytes_mode || first_line_mode) {
    napi_create_buffer_copy(
        env, content.size(), content.data(), nullptr, &value);
  } else {
    napi_get_null(env, &value);
  }
  napi_set_named_property(env, result, "bytes", value);
  napi_get_null(env, &value);
  napi_set_named_property(env, result, "entries", value);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(
      env, "SERVICE_UNSUPPORTED", "read_service_external_object",
      "unsupported");
  return nullptr;
#endif
}



napi_value ReadWin32BootClock(
    napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!InventoryArgs(env, info, 0, args)) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "read_win32_boot_clock",
        "invalid-input");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  std::string boot_before, boot_after, boot_fingerprint;
  if (!ReadWindowsBootIdentity(&boot_before)) {
    ServiceObservationError(
        env, "SERVICE_PENDING", "read_win32_boot_clock",
        "clock-unavailable", true);
    return nullptr;
  }
  const ULONGLONG tick = GetTickCount64();
  if (tick > 9007199254740991ULL ||
      !ReadWindowsBootIdentity(&boot_after) ||
      boot_before != boot_after ||
      !ServiceSelfWindowsBootFingerprint(
          boot_before, &boot_fingerprint)) {
    ServiceObservationError(
        env, "SERVICE_PENDING", "read_win32_boot_clock",
        "clock-unavailable", true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetUint32(env, result, "schemaVersion", 1);
  ServiceSetString(env, result, "bootFingerprint", boot_fingerprint);
  ServiceSetDouble(env, result, "tickMs", static_cast<double>(tick));
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(
      env, "SERVICE_UNSUPPORTED", "read_win32_boot_clock",
      "unsupported");
  return nullptr;
#endif
}

bool ServiceSelfExecutableIdentity(
    const std::string& executable,
    ServiceStoreIdentity* identity) {
#ifdef _WIN32
  HANDLE file = OpenWindowsPathNoFollow(
      executable, FILE_READ_ATTRIBUTES | READ_CONTROL,
      VerifiedObjectType::File, FILE_SHARE_READ | FILE_SHARE_DELETE);
  if (file == INVALID_HANDLE_VALUE) return false;
  FILE_BASIC_INFO before_basic{}, after_basic{};
  FILE_STANDARD_INFO before_standard{}, after_standard{};
  ServiceStoreIdentity before_identity, after_identity;
  const bool before = ServiceSelfCaptureFileIdentity(
      file, &before_identity, &before_basic, &before_standard, false);
  const bool after = before && ServiceSelfCaptureFileIdentity(
      file, &after_identity, &after_basic, &after_standard, false);
  const bool stable = after &&
      SameServiceStoreIdentity(before_identity, after_identity) &&
      before_basic.CreationTime.QuadPart ==
          after_basic.CreationTime.QuadPart &&
      before_basic.LastWriteTime.QuadPart ==
          after_basic.LastWriteTime.QuadPart &&
      before_basic.ChangeTime.QuadPart ==
          after_basic.ChangeTime.QuadPart &&
      before_standard.EndOfFile.QuadPart ==
          after_standard.EndOfFile.QuadPart &&
      before_standard.AllocationSize.QuadPart ==
          after_standard.AllocationSize.QuadPart;
  CloseHandle(file);
  if (!stable) return false;
  HANDLE named = OpenWindowsPathNoFollow(
      executable, FILE_READ_ATTRIBUTES | READ_CONTROL,
      VerifiedObjectType::File, FILE_SHARE_READ | FILE_SHARE_DELETE);
  ServiceStoreIdentity named_identity;
  FILE_BASIC_INFO named_basic{};
  FILE_STANDARD_INFO named_standard{};
  const bool named_exact = named != INVALID_HANDLE_VALUE &&
      ServiceSelfCaptureFileIdentity(
          named, &named_identity, &named_basic, &named_standard, false) &&
      SameServiceStoreIdentity(before_identity, named_identity) &&
      named_basic.CreationTime.QuadPart ==
          before_basic.CreationTime.QuadPart &&
      named_basic.LastWriteTime.QuadPart ==
          before_basic.LastWriteTime.QuadPart &&
      named_basic.ChangeTime.QuadPart ==
          before_basic.ChangeTime.QuadPart &&
      named_standard.EndOfFile.QuadPart ==
          before_standard.EndOfFile.QuadPart &&
      named_standard.AllocationSize.QuadPart ==
          before_standard.AllocationSize.QuadPart;
  if (named != INVALID_HANDLE_VALUE) CloseHandle(named);
  if (!named_exact) return false;
  *identity = named_identity;
  return true;
#else
  (void)executable;
  (void)identity;
  return false;
#endif
}

#include "service-log-observer.inc"

napi_value ObserveSelfProcessEpoch(
    napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!InventoryArgs(env, info, 0, args)) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "observe_self_process_epoch",
        "invalid-input");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  std::string boot_before, boot_after, executable_fingerprint;
  ServiceProcessFacts before, after;
  ServiceStoreIdentity executable_identity, executable_identity_after;
  const uint32_t pid = GetCurrentProcessId();
  if (pid == 0 || !ReadWindowsBootIdentity(&boot_before) ||
      ReadServiceProcessFacts(pid, &before) != ProcessReadResult::Ok ||
      before.pid != pid || before.start_time == 0 ||
      !ServiceSelfExecutableIdentity(
          before.executable, &executable_identity) ||
      !ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
          executable_identity, &executable_fingerprint) ||
      ReadServiceProcessFacts(pid, &after) != ProcessReadResult::Ok ||
      after.pid != before.pid || after.start_time != before.start_time ||
      after.executable != before.executable ||
      !ServiceSelfExecutableIdentity(
          after.executable, &executable_identity_after) ||
      !SameServiceStoreIdentity(
          executable_identity, executable_identity_after) ||
      !ReadWindowsBootIdentity(&boot_after) ||
      boot_before != boot_after) {
    ServiceObservationError(
        env, "SERVICE_PENDING", "observe_self_process_epoch",
        "process-ambiguous", true);
    return nullptr;
  }
  const std::string canonical =
      "{\"bootId\":\"" + boot_before +
      "\",\"creationTime\":\"" +
      std::to_string(before.start_time) +
      "\",\"executableIdentityFingerprint\":\"" +
      executable_fingerprint +
      "\",\"kind\":\"gjc-remote/windows-self-epoch/v1\",\"pid\":" +
      std::to_string(pid) + "}";
  Sha256 hash;
  if (!hash.Ready() || !hash.Update(canonical)) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "observe_self_process_epoch", "io");
    return nullptr;
  }
  const std::string fingerprint = hash.Finish();
  if (!ValidServiceFingerprint(fingerprint)) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "observe_self_process_epoch", "io");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetString(
      env, result, "processEpochFingerprint", fingerprint);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(
      env, "SERVICE_UNSUPPORTED", "observe_self_process_epoch",
      "unsupported");
  return nullptr;
#endif
}

napi_value ReadSelfServiceConfig(
    napi_env env, napi_callback_info info) {
  napi_value args[1];
  if (!InventoryArgs(env, info, 0, args)) {
    ServiceObservationError(
        env, "SERVICE_INVALID", "read_self_service_config",
        "invalid-input");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  std::wstring current_directory;
  if (!ServiceSelfCurrentDirectory(&current_directory)) {
    ServiceObservationError(
        env, "SERVICE_IO_FAILED", "read_self_service_config", "io", true);
    return nullptr;
  }
  WindowsPathParts current_parts;
  if (!ParseWindowsPath(Utf8(current_directory), &current_parts) ||
      current_parts.components.size() > 64) {
    ServiceObservationError(
        env, "SERVICE_UNSUPPORTED", "read_self_service_config",
        "unsupported");
    return nullptr;
  }
  ServiceSelfDirectoryChain chain;
  if (!ServiceSelfOpenDirectoryChain(current_directory, &chain)) {
    const DWORD error = GetLastError();
    ServiceObservationError(
        env, error == ERROR_ACCESS_DENIED
            ? "SERVICE_ACCESS_DENIED" :
            ServiceSelfUnsupportedTypeError(error)
                ? "SERVICE_UNSUPPORTED" : "SERVICE_STALE",
        "read_self_service_config",
        error == ERROR_ACCESS_DENIED
            ? "access-denied" :
            ServiceSelfUnsupportedTypeError(error)
                ? "unsupported" : "identity-changed",
        error != ERROR_ACCESS_DENIED &&
            !ServiceSelfUnsupportedTypeError(error));
    return nullptr;
  }
  HANDLE current = chain.handles.back();
  const std::wstring runtime_config_name = L"runtime-config";
  HANDLE runtime_root = OpenWindowsRelative(
      current, runtime_config_name,
      kWindowsTraversalAccess | READ_CONTROL, kFileOpen,
      VerifiedObjectType::Directory);
  const DWORD runtime_root_error = runtime_root == INVALID_HANDLE_VALUE
      ? GetLastError() : ERROR_SUCCESS;
  bool runtime_config_absent = false;
  std::string runtime_root_fingerprint;
  std::string runtime_file_fingerprint;
  std::string runtime_file_sha256;
  uint32_t runtime_file_bytes = 0;
  ServiceObservationScopedHandles runtime_root_handle;
  if (runtime_root == INVALID_HANDLE_VALUE &&
      ServiceWindowsNotFound(runtime_root_error)) {
    HANDLE probe = OpenWindowsRelative(
        current, runtime_config_name,
        FILE_READ_ATTRIBUTES | READ_CONTROL, kFileOpen,
        VerifiedObjectType::Any);
    const DWORD probe_error = probe == INVALID_HANDLE_VALUE
        ? GetLastError() : ERROR_SUCCESS;
    if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
    runtime_config_absent = ServiceWindowsNotFound(probe_error) &&
        ServiceSelfDirectoryChainStable(chain, current_directory);
    if (!runtime_config_absent) {
      ServiceObservationError(
          env, "SERVICE_STALE", "read_self_service_config",
          "absence-unproven", true);
      return nullptr;
    }
  } else if (runtime_root == INVALID_HANDLE_VALUE) {
    ServiceObservationError(
        env, runtime_root_error == ERROR_ACCESS_DENIED
            ? "SERVICE_ACCESS_DENIED"
            : ServiceSelfUnsupportedTypeError(runtime_root_error)
                ? "SERVICE_UNSUPPORTED" : "SERVICE_IO_FAILED",
        "read_self_service_config",
        runtime_root_error == ERROR_ACCESS_DENIED ? "access-denied" :
            ServiceSelfUnsupportedTypeError(runtime_root_error)
                ? "unsupported" : "io",
        runtime_root_error != ERROR_ACCESS_DENIED &&
            !ServiceSelfUnsupportedTypeError(runtime_root_error));
    return nullptr;
  } else {
    try {
      runtime_root_handle.Add(runtime_root);
    } catch (...) {
      CloseHandle(runtime_root);
      ServiceObservationError(
          env, "SERVICE_IO_FAILED", "read_self_service_config", "io");
      return nullptr;
    }
    ServiceStoreIdentity runtime_root_identity;
    if (!CaptureExternalAncestorIdentity(
            runtime_root, &runtime_root_identity) ||
        !ServiceSelfDenyCurrentWriteAccess(runtime_root, true) ||
        !ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
            runtime_root_identity, &runtime_root_fingerprint)) {
      ServiceObservationError(
          env, "SERVICE_ACCESS_DENIED", "read_self_service_config",
          "access-denied");
      return nullptr;
    }
    std::vector<uint8_t> ignored_bytes;
    ServiceStoreIdentity runtime_file_identity;
    bool output_limit = false;
    if (!ServiceSelfReadFile(
            runtime_root, L".bunfig.toml", 1024ULL * 1024ULL,
            false, &ignored_bytes, &runtime_file_sha256,
            &runtime_file_identity, &runtime_file_bytes, &output_limit)) {
      const DWORD error = GetLastError();
      if (output_limit) {
        ServiceObservationError(
            env, "SERVICE_OUTPUT_LIMIT", "read_self_service_config",
            "limit");
      } else if (ServiceWindowsNotFound(error)) {
        HANDLE probe = OpenWindowsRelative(
            runtime_root, L".bunfig.toml",
            FILE_READ_ATTRIBUTES | READ_CONTROL, kFileOpen,
            VerifiedObjectType::Any);
        const DWORD probe_error = probe == INVALID_HANDLE_VALUE
            ? GetLastError() : ERROR_SUCCESS;
        if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
        if (ServiceWindowsNotFound(probe_error) &&
            ServiceSelfDirectoryChainStable(chain, current_directory)) {
          ServiceObservationError(
              env, "SERVICE_PENDING", "read_self_service_config",
              "absence-unproven", true);
        } else {
          ServiceObservationError(
              env, "SERVICE_STALE", "read_self_service_config",
              "identity-changed", true);
        }
      } else {
        ServiceObservationError(
            env, error == ERROR_ACCESS_DENIED
                ? "SERVICE_ACCESS_DENIED" :
                  ServiceSelfUnsupportedTypeError(error)
                    ? "SERVICE_UNSUPPORTED" : "SERVICE_STALE",
            "read_self_service_config",
            error == ERROR_ACCESS_DENIED ? "access-denied" :
                ServiceSelfUnsupportedTypeError(error)
                    ? "unsupported" : "identity-changed",
            error != ERROR_ACCESS_DENIED &&
                !ServiceSelfUnsupportedTypeError(error));
      }
      return nullptr;
    }
    const std::string captured_root_fingerprint = runtime_root_fingerprint;
    const std::string captured_file_fingerprint =
        ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
            runtime_file_identity, &runtime_file_fingerprint)
            ? runtime_file_fingerprint : std::string();
    HANDLE named_root = OpenWindowsRelative(
        current, runtime_config_name,
        kWindowsTraversalAccess | READ_CONTROL, kFileOpen,
        VerifiedObjectType::Directory);
    ServiceStoreIdentity named_root_identity, held_root_identity;
    const bool root_exact = named_root != INVALID_HANDLE_VALUE &&
        CaptureExternalAncestorIdentity(
            named_root, &named_root_identity) &&
        CaptureExternalAncestorIdentity(
            runtime_root, &held_root_identity) &&
        SameServicePhysicalIdentity(
            runtime_root_identity, named_root_identity) &&
        SameServicePhysicalIdentity(
            runtime_root_identity, held_root_identity) &&
        ServiceSelfDirectoryChainStable(chain, current_directory);
    if (named_root != INVALID_HANDLE_VALUE) CloseHandle(named_root);
    if (!root_exact || captured_root_fingerprint.empty() ||
        captured_file_fingerprint.empty()) {
      ServiceObservationError(
          env, "SERVICE_STALE", "read_self_service_config",
          "identity-changed", true);
      return nullptr;
    }
  }

  ServiceSelfSecretBuffer env_storage;
  std::vector<uint8_t>& env_bytes = env_storage.bytes;
  ServiceStoreIdentity env_identity;
  uint32_t env_byte_length = 0;
  bool output_limit = false;
  if (!ServiceSelfReadFile(
          current, L".env", 256ULL * 1024ULL, true,
          &env_bytes, nullptr, &env_identity, &env_byte_length,
          &output_limit)) {
    const DWORD error = GetLastError();
    ServiceObservationError(
        env, output_limit ? "SERVICE_OUTPUT_LIMIT" :
            error == ERROR_ACCESS_DENIED ? "SERVICE_ACCESS_DENIED" :
            ServiceSelfUnsupportedTypeError(error)
                ? "SERVICE_UNSUPPORTED" :
            ServiceWindowsNotFound(error) ? "SERVICE_PENDING" :
                "SERVICE_STALE",
        "read_self_service_config",
        output_limit ? "limit" : error == ERROR_ACCESS_DENIED
            ? "access-denied" :
            ServiceSelfUnsupportedTypeError(error)
                ? "unsupported" : ServiceWindowsNotFound(error)
                    ? "absence-unproven" : "identity-changed",
        !output_limit && error != ERROR_ACCESS_DENIED &&
            !ServiceSelfUnsupportedTypeError(error));
    return nullptr;
  }
  std::string source_identity_fingerprint;
  if (env_byte_length != env_bytes.size() ||
      !ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
          env_identity, &source_identity_fingerprint) ||
      !ServiceSelfDirectoryChainStable(chain, current_directory)) {
    ServiceObservationError(
        env, "SERVICE_STALE", "read_self_service_config",
        "identity-changed", true);
    return nullptr;
  }
  if (runtime_config_absent) {
    HANDLE probe = OpenWindowsRelative(
        current, runtime_config_name,
        FILE_READ_ATTRIBUTES | READ_CONTROL, kFileOpen,
        VerifiedObjectType::Any);
    const DWORD probe_error = probe == INVALID_HANDLE_VALUE
        ? GetLastError() : ERROR_SUCCESS;
    if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
    if (!ServiceWindowsNotFound(probe_error) ||
        !ServiceSelfDirectoryChainStable(chain, current_directory)) {
      ServiceObservationError(
          env, "SERVICE_STALE", "read_self_service_config",
          "absence-unproven", true);
      return nullptr;
    }
  } else {
    HANDLE root = runtime_root_handle.values.empty()
        ? INVALID_HANDLE_VALUE : runtime_root_handle.values.front();
    ServiceStoreIdentity final_root_identity, final_file_identity;
    std::string final_root_fingerprint, final_file_fingerprint;
    std::string final_file_sha256;
    uint32_t final_file_bytes = 0;
    bool final_output_limit = false;
    std::vector<uint8_t> ignored_bytes;
    const bool final_file_exact = root != INVALID_HANDLE_VALUE &&
        CaptureExternalAncestorIdentity(root, &final_root_identity) &&
        ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
            final_root_identity, &final_root_fingerprint) &&
        ServiceSelfReadFile(
            root, L".bunfig.toml", 1024ULL * 1024ULL,
            false, &ignored_bytes, &final_file_sha256,
            &final_file_identity, &final_file_bytes, &final_output_limit) &&
        ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
            final_file_identity, &final_file_fingerprint) &&
        final_root_fingerprint == runtime_root_fingerprint &&
        final_file_fingerprint == runtime_file_fingerprint &&
        final_file_sha256 == runtime_file_sha256 &&
        final_file_bytes == runtime_file_bytes &&
        ServiceSelfDirectoryChainStable(chain, current_directory);
    if (!final_file_exact) {
      ServiceObservationError(
          env, final_output_limit ? "SERVICE_OUTPUT_LIMIT" :
              GetLastError() == ERROR_ACCESS_DENIED
                  ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
          "read_self_service_config",
          final_output_limit ? "limit" :
              GetLastError() == ERROR_ACCESS_DENIED
                  ? "access-denied" : "identity-changed",
          !final_output_limit &&
              GetLastError() != ERROR_ACCESS_DENIED);
      return nullptr;
    }
  }
  ServiceSelfSecretBuffer final_env_storage;
  std::vector<uint8_t>& final_env_bytes = final_env_storage.bytes;
  ServiceStoreIdentity final_env_identity;
  uint32_t final_env_byte_length = 0;
  bool final_env_output_limit = false;
  std::string final_source_fingerprint;
  if (!ServiceSelfReadFile(
          current, L".env", 256ULL * 1024ULL, true,
          &final_env_bytes, nullptr, &final_env_identity,
          &final_env_byte_length, &final_env_output_limit) ||
      final_env_byte_length != env_byte_length ||
      final_env_bytes != env_bytes ||
      !ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
          final_env_identity, &final_source_fingerprint) ||
      final_source_fingerprint != source_identity_fingerprint ||
      !ServiceSelfDirectoryChainStable(chain, current_directory)) {
    ServiceObservationError(
        env, final_env_output_limit ? "SERVICE_OUTPUT_LIMIT" :
            GetLastError() == ERROR_ACCESS_DENIED
                ? "SERVICE_ACCESS_DENIED" : "SERVICE_STALE",
        "read_self_service_config",
        final_env_output_limit ? "limit" :
            GetLastError() == ERROR_ACCESS_DENIED
                ? "access-denied" : "identity-changed",
        !final_env_output_limit &&
            GetLastError() != ERROR_ACCESS_DENIED);
    return nullptr;
  }
  napi_value result, value;
  napi_create_object(env, &result);
  ServiceSetUint32(env, result, "schemaVersion", 1);
  ServiceSetString(
      env, result, "sourceIdentityFingerprint",
      source_identity_fingerprint);
  napi_create_buffer_copy(
      env, env_bytes.size(), env_bytes.data(), nullptr, &value);
  napi_set_named_property(env, result, "bytes", value);
  if (runtime_config_absent) {
    napi_get_null(env, &value);
    napi_set_named_property(env, result, "runtimeConfig", value);
  } else {
    napi_value runtime_config;
    napi_create_object(env, &runtime_config);
    ServiceSetString(
        env, runtime_config, "rootIdentityFingerprint",
        runtime_root_fingerprint);
    ServiceSetString(
        env, runtime_config, "fileIdentityFingerprint",
        runtime_file_fingerprint);
    ServiceSetString(
        env, runtime_config, "fileSha256", runtime_file_sha256);
    ServiceSetUint32(
        env, runtime_config, "byteLength", runtime_file_bytes);
    napi_set_named_property(
        env, result, "runtimeConfig", runtime_config);
  }
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(
      env, "SERVICE_UNSUPPORTED", "read_self_service_config",
      "unsupported");
  return nullptr;
#endif
}

napi_value ReadServiceArtifactChunk(
    napi_env env, napi_callback_info info) {
  napi_value args[3];
  ServiceStoreHandle* reader = nullptr;
  uint64_t expected_offset = 0, maximum = 0;
  if (!InventoryArgs(env, info, 3, args) ||
      !ServiceStoreHandleArg(env, args[0], &reader) ||
      (reader->kind != ServiceStoreHandleKind::ArtifactReader &&
       reader->kind !=
           ServiceStoreHandleKind::ArtifactSourceReader) ||
      reader->poisoned || reader->completed ||
      !ServiceStoreNumber(env, args[1],
                          kServiceArtifactMaxBytes,
                          &expected_offset) ||
      !ServiceStoreNumber(env, args[2],
                          kServiceArtifactChunkMax, &maximum) ||
      maximum == 0 ||
      expected_offset != reader->stream_offset ||
      reader->stream_offset > reader->stream_limit ||
      !RevalidateServiceArtifactStream(reader)) {
    ServiceError(env,
        reader && (reader->kind ==
            ServiceStoreHandleKind::ArtifactReader ||
            reader->kind ==
            ServiceStoreHandleKind::ArtifactSourceReader)
            ? "SERVICE_STALE" : "SERVICE_INVALID",
        "read_service_artifact_chunk");
    return nullptr;
  }
  const size_t requested = static_cast<size_t>(
      std::min<uint64_t>(
          maximum, reader->stream_limit - reader->stream_offset));
  std::vector<uint8_t> bytes;
  try {
    bytes.resize(requested);
  } catch (...) {
    reader->poisoned = true;
    ServiceError(env, "SERVICE_IO_FAILED",
                 "read_service_artifact_chunk");
    return nullptr;
  }
  size_t offset = 0;
#ifdef _WIN32
  LARGE_INTEGER position{};
  position.QuadPart =
      static_cast<LONGLONG>(reader->stream_offset);
  bool valid = SetFilePointerEx(
      reader->object, position, nullptr, FILE_BEGIN) != FALSE;
  while (valid && offset < bytes.size()) {
    DWORD read_bytes = 0;
    const DWORD chunk = static_cast<DWORD>(
        bytes.size() - offset);
    if (!ReadFile(reader->object, bytes.data() + offset,
                  chunk, &read_bytes, nullptr) ||
        read_bytes == 0) {
      valid = false;
      break;
    }
    offset += read_bytes;
  }
#else
  bool valid = lseek(
      reader->object,
      static_cast<off_t>(reader->stream_offset),
      SEEK_SET) >= 0;
  while (valid && offset < bytes.size()) {
    const ssize_t read_bytes = read(
        reader->object, bytes.data() + offset,
        bytes.size() - offset);
    if (read_bytes < 0 && errno == EINTR) continue;
    if (read_bytes <= 0) {
      valid = false;
      break;
    }
    offset += static_cast<size_t>(read_bytes);
  }
#endif
  if (!valid || offset != bytes.size() ||
      !reader->stream_hash->Update(
          bytes.data(), bytes.size())) {
    reader->poisoned = true;
    ServiceError(env, "SERVICE_STALE",
                 "read_service_artifact_chunk", 0, true);
    return nullptr;
  }
  reader->stream_offset += bytes.size();
  const bool eof =
      reader->stream_offset == reader->stream_limit;
  if (eof) {
    const std::string digest = reader->stream_hash->Finish();
    if (!ValidServiceFingerprint(digest) ||
        digest != reader->expected_sha256 ||
        !RevalidateServiceArtifactStream(reader)) {
      reader->poisoned = true;
      ServiceError(env, "SERVICE_STALE",
                   "read_service_artifact_chunk", 0, true);
      return nullptr;
    }
    reader->completed = true;
  }
  napi_value result, data;
  napi_create_object(env, &result);
  napi_create_buffer_copy(
      env, bytes.size(), bytes.data(), nullptr, &data);
  napi_set_named_property(env, result, "bytes", data);
  ServiceSetDouble(env, result, "nextOffset",
                   static_cast<double>(reader->stream_offset));
  ServiceSetBoolean(env, result, "eof", eof);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
}

bool ServiceStoreTemporaryName(std::string* name,
                               const char* purpose);

napi_value RemoveServiceArtifactFileExact(
    napi_env env, napi_callback_info info) {
  napi_value args[4];
  ServiceStoreHandle* parent = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string name;
  ServiceStoreFileFacts expected;
  if (!InventoryArgs(env, info, 4, args) ||
      !ServiceStoreHandleArg(env, args[0], &parent) ||
      (parent->kind != ServiceStoreHandleKind::Root &&
       parent->kind != ServiceStoreHandleKind::Directory) ||
      (parent->root_kind != "staging" &&
       parent->root_kind != "releases" &&
       parent->root_kind != "shawl") ||
      parent->access != ServiceStoreAccess::Write ||
      !InventoryString(env, args[1], &name) ||
      !ValidServiceStoreComponent(name) ||
      !ServiceStoreFileFactsArg(
          env, args[2], &expected,
          kServiceArtifactMaxBytes) ||
      !ServiceStoreHandleArg(env, args[3], &lock) ||
      !ServiceLockAuthorizes(parent, lock, true)) {
    ServiceError(env, "SERVICE_INVALID",
                 "remove_service_artifact_file_exact");
    return nullptr;
  }
#ifdef _WIN32
  HANDLE file = INVALID_HANDLE_VALUE;
#else
  int file = -1;
#endif
  if (!ServiceStoreOpenRelativeFileForDelete(
          parent->object, name, &file)) {
    ServiceError(env, "SERVICE_STALE",
                 "remove_service_artifact_file_exact");
    return nullptr;
  }
  ServiceStoreFileFacts actual;
  if (!HashRetainedServiceArtifact(
          file, parent, false,
          kServiceArtifactMaxBytes, &actual) ||
      !SameServiceStoreFileFacts(actual, expected)) {
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
    ServiceError(env, "SERVICE_STALE",
                 "remove_service_artifact_file_exact");
    return nullptr;
  }
  if (!ServiceLockAuthorizes(parent, lock, true)) {
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
    ServiceError(env, "SERVICE_STALE",
                 "remove_service_artifact_file_exact");
    return nullptr;
  }
  std::string quarantine;
  if (!ServiceStoreTemporaryName(
          &quarantine, "artifact-remove")) {
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
    ServiceError(env, "SERVICE_IO_FAILED",
                 "remove_service_artifact_file_exact");
    return nullptr;
  }
#ifdef _WIN32
  const bool quarantined = RenameWindowsRelative(
      file, parent->object, Wide(quarantine), false);
#else
  const bool quarantined = RenameAt2(
      parent->object, name, quarantine, 1) == 0;
#endif
  if (!quarantined) {
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
    ServiceError(env, "SERVICE_STALE",
                 "remove_service_artifact_file_exact");
    return nullptr;
  }
  uint32_t writes = 1;
#ifdef _WIN32
  HANDLE displaced_file = INVALID_HANDLE_VALUE;
#else
  int displaced_file = -1;
#endif
  ServiceStoreFileFacts displaced;
  const bool displaced_exact =
      ServiceStoreOpenRelativeFileForDelete(
          parent->object, quarantine, &displaced_file) &&
      HashRetainedServiceArtifact(
          displaced_file, parent, false,
          kServiceArtifactMaxBytes, &displaced) &&
      SameServiceStoreFileFacts(displaced, expected) &&
      SameServiceStoreFileFacts(displaced, actual);
  if (!displaced_exact) {
#ifdef _WIN32
    if (displaced_file != INVALID_HANDLE_VALUE) {
      CloseHandle(displaced_file);
    }
    CloseHandle(file);
#else
    if (displaced_file >= 0) close(displaced_file);
    close(file);
#endif
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
        "remove_service_artifact_file_exact",
        writes, true);
    return nullptr;
  }
  if (!ServiceLockAuthorizes(parent, lock, true)) {
#ifdef _WIN32
    CloseHandle(displaced_file);
    CloseHandle(file);
#else
    close(displaced_file);
    close(file);
#endif
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "remove_service_artifact_file_exact", writes, true);
    return nullptr;
  }
#ifdef _WIN32
  FILE_DISPOSITION_INFO disposition{TRUE};
  const bool removed = SetFileInformationByHandle(
      displaced_file, FileDispositionInfo, &disposition,
      sizeof(disposition)) != FALSE;
  CloseHandle(displaced_file);
  CloseHandle(file);
#else
  close(displaced_file);
  close(file);
  const bool removed = unlinkat(
      parent->object, quarantine.c_str(), 0) == 0;
#endif
  if (removed) ++writes;
#ifdef _WIN32
  HANDLE original = INVALID_HANDLE_VALUE;
  HANDLE residual = INVALID_HANDLE_VALUE;
  const bool original_absent =
      !ServiceStoreOpenRelativeFile(
          parent->object, name, false, &original) &&
      GetLastError() == ERROR_FILE_NOT_FOUND;
  if (original != INVALID_HANDLE_VALUE) CloseHandle(original);
  const bool residual_absent =
      !ServiceStoreOpenRelativeFile(
          parent->object, quarantine, false, &residual) &&
      GetLastError() == ERROR_FILE_NOT_FOUND;
  if (residual != INVALID_HANDLE_VALUE) CloseHandle(residual);
#else
  struct stat metadata{};
  const bool original_absent = fstatat(
      parent->object, name.c_str(), &metadata,
      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
  const bool residual_absent = fstatat(
      parent->object, quarantine.c_str(), &metadata,
      AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
#endif
  const bool durable = removed && original_absent &&
      residual_absent &&
      FlushServiceStoreDirectory(parent->object) &&
      RevalidateServiceStoreHandle(parent) &&
      ServiceLockAuthorizes(parent, lock, true);
  if (!durable) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "remove_service_artifact_file_exact",
                 writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetBoolean(env, result, "removed", true);
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

struct ServiceStoreDirectoryEntry {
  std::string name;
  ServiceStoreIdentity identity;
};

bool EnumerateServiceStoreDirectory(
    ServiceStoreHandle* directory, uint32_t maximum,
    bool include_internal,
    std::vector<ServiceStoreDirectoryEntry>* entries,
    bool* overflow);

struct ServiceSealedClosure {
  uint64_t files = 0;
  uint64_t directories = 0;
  uint64_t bytes = 0;
  std::string fingerprint;
};

bool VerifyCompleteSealedServiceSubtree(
    ServiceStoreHandle* directory, bool allow_staging_root,
    ServiceSealedClosure* closure, bool* overflow);

napi_value SealServiceDirectory(
    napi_env env, napi_callback_info info) {
  napi_value args[3];
  ServiceStoreHandle* directory = nullptr;
  ServiceStoreHandle* lock = nullptr;
  ServiceStoreIdentity expected;
  if (!InventoryArgs(env, info, 3, args) ||
      !ServiceStoreHandleArg(env, args[0], &directory) ||
      directory->kind != ServiceStoreHandleKind::Directory ||
      directory->root_kind != "staging" ||
      directory->profile != ServiceAclProfile::StagingDirectory ||
      directory->access != ServiceStoreAccess::Write ||
      directory->children != 0 ||
      !ServiceStoreIdentityArg(env, args[1], &expected) ||
      expected.profile != ServiceAclProfile::StagingDirectory ||
      !SameServiceStoreIdentity(directory->identity, expected) ||
      !ServiceStoreHandleArg(env, args[2], &lock) ||
      !ServiceLockAuthorizes(directory, lock, true)) {
    ServiceError(env, "SERVICE_INVALID",
                 "seal_service_directory");
    return nullptr;
  }
  ServiceSealedClosure before_closure;
  bool overflow = false;
  if (!VerifyCompleteSealedServiceSubtree(
          directory, true, &before_closure, &overflow)) {
    ServiceError(env,
        overflow ? "SERVICE_PENDING" : "SERVICE_STALE",
        "seal_service_directory", 0, !overflow);
    return nullptr;
  }
  if (!ServiceLockAuthorizes(directory, lock, true)) {
    ServiceError(env, "SERVICE_STALE",
                 "seal_service_directory");
    return nullptr;
  }
  uint32_t writes = 0;
  bool applied = false;
  bool acl_mutated = false;
#ifdef _WIN32
  HANDLE privileged = OpenWindowsRelative(
      directory->parent->object, Wide(directory->name),
      FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC | WRITE_OWNER |
          DELETE | FILE_DELETE_CHILD,
      kFileOpen, VerifiedObjectType::Directory);
  ServiceStoreIdentity privileged_identity;
  applied = privileged != INVALID_HANDLE_VALUE &&
      CaptureServiceStoreIdentity(
          privileged, directory->roles,
          ServiceAclProfile::StagingDirectory,
          &privileged_identity) &&
      SameServiceStoreIdentity(privileged_identity, expected) &&
      ApplyWindowsServiceFileAcl(
          privileged, directory->roles,
          ServiceAclProfile::ReleaseDirectory, &acl_mutated);
  if (acl_mutated) ++writes;
  if (privileged != INVALID_HANDLE_VALUE) CloseHandle(privileged);
  applied = applied &&
      FlushServiceStoreDirectory(directory->object);
#else
  applied = BuildPosixServiceAcl(
      directory->object, directory->roles,
      ServiceAclProfile::ReleaseDirectory, true, &acl_mutated);
  if (acl_mutated) ++writes;
  applied = applied && fsync(directory->object) == 0;
#endif
  ServiceStoreIdentity sealed;
  applied = applied && CaptureServiceStoreIdentity(
      directory->object, directory->roles,
      ServiceAclProfile::ReleaseDirectory, &sealed);
  if (applied) {
    directory->profile = ServiceAclProfile::ReleaseDirectory;
    directory->identity = sealed;
    ServiceSealedClosure after_closure;
    bool after_overflow = false;
    applied =
        FlushServiceStoreDirectory(directory->parent->object) &&
        RevalidateServiceStoreHandle(directory) &&
        VerifyCompleteSealedServiceSubtree(
            directory, false, &after_closure, &after_overflow) &&
        after_closure.files == before_closure.files &&
        after_closure.directories ==
            before_closure.directories &&
        after_closure.bytes == before_closure.bytes &&
        after_closure.fingerprint ==
            before_closure.fingerprint &&
        ServiceLockAuthorizes(directory, lock, true);
  }
  if (!applied) {
    directory->poisoned = true;
    CloseServiceStoreNative(directory);
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "seal_service_directory", writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", args[0]);
  napi_set_named_property(
      env, result, "identity",
      ServiceStoreIdentityValue(env, sealed));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

bool ServiceStoreExpectedFileArg(
    napi_env env, napi_value value, bool* present,
    ServiceStoreFileFacts* facts, std::vector<uint8_t>* bytes) {
  if (ServiceStoreNull(env, value)) {
    *present = false;
    return true;
  }
  napi_value captured[2];
  const char* fields[] = {"facts", "bytes"};
  *present = InventoryOrdinaryDataObject(
      env, value, fields, 2, captured);
  if (!*present ||
      !ServiceStoreFileFactsArg(env, captured[0], facts)) return false;
  if (!ServiceStoreBuffer(env, captured[1], bytes) ||
      facts->size != bytes->size()) return false;
  std::string digest;
  return HashServiceStoreBytes(*bytes, &digest) &&
      digest == facts->sha256;
}

bool ServiceStoreTemporaryName(std::string* name,
                               const char* purpose) {
#ifdef _WIN32
  std::wstring token;
  if (!InventoryRandomName(&token)) return false;
  *name = ".gjc-service-" + std::string(purpose) + "-" +
      Utf8(token);
#else
  std::string token;
  if (!InventoryRandomName(&token)) return false;
  *name = ".gjc-service-" + std::string(purpose) + "-" + token;
#endif
  return true;
}

bool RemoveServiceStoreNamedFile(
    ServiceStoreHandle* parent, const std::string& name,
    const ServiceStoreFileFacts& expected,
    const std::vector<uint8_t>& expected_bytes,
    uint32_t* writes, bool flush_parent,
    bool* ambiguous) {
  *ambiguous = false;
  std::vector<uint8_t> actual_bytes;
  ServiceStoreFileFacts actual;
  bool absent = false;
  if (!ReadServiceStoreFileRetained(
          parent, name, kInventoryMaxBytes,
          &actual_bytes, &actual, &absent) ||
      absent || actual_bytes != expected_bytes ||
      !SameServiceStoreFileFacts(actual, expected)) {
    return false;
  }
  std::string backup;
  if (!ServiceStoreTemporaryName(&backup, "remove")) return false;
#ifdef _WIN32
  HANDLE retained = INVALID_HANDLE_VALUE;
  if (!ServiceStoreOpenRelativeFile(
          parent->object, name, true, &retained)) return false;
  ServiceStoreIdentity retained_identity;
  if (!CaptureAllowedServiceFileIdentity(
          retained, parent, &retained_identity) ||
      !SameServiceStoreIdentity(
          retained_identity, actual.identity) ||
      !RenameWindowsRelative(
          retained, parent->object, Wide(backup), false)) {
    if (retained != INVALID_HANDLE_VALUE) CloseHandle(retained);
    return false;
  }
  ++*writes;
  CloseHandle(retained);
#else
  if (RenameAt2(parent->object, name, backup, 1) != 0) return false;
  ++*writes;
#endif
  std::vector<uint8_t> displaced_bytes;
  ServiceStoreFileFacts displaced;
  bool displaced_absent = false;
  const bool displaced_exact = ReadServiceStoreFileRetained(
      parent, backup, kInventoryMaxBytes,
      &displaced_bytes, &displaced, &displaced_absent) &&
      !displaced_absent && displaced_bytes == expected_bytes &&
      SameServiceStoreFileFacts(displaced, expected);
  if (!displaced_exact) {
#ifdef _WIN32
    HANDLE displaced_handle = INVALID_HANDLE_VALUE;
    const bool restored = ServiceStoreOpenRelativeFile(
            parent->object, backup, true, &displaced_handle) &&
        RenameWindowsRelative(
            displaced_handle, parent->object, Wide(name), false);
    if (displaced_handle != INVALID_HANDLE_VALUE) {
      CloseHandle(displaced_handle);
    }
#else
    const bool restored =
        RenameAt2(parent->object, backup, name, 1) == 0;
#endif
    if (restored) ++*writes;
    *ambiguous = !restored ||
        !FlushServiceStoreDirectory(parent->object);
    return false;
  }
#ifdef _WIN32
  HANDLE displaced_handle = INVALID_HANDLE_VALUE;
  FILE_DISPOSITION_INFO disposition{TRUE};
  const bool removed = ServiceStoreOpenRelativeFile(
          parent->object, backup, true, &displaced_handle) &&
      SetFileInformationByHandle(
          displaced_handle, FileDispositionInfo,
          &disposition, sizeof(disposition));
  if (displaced_handle != INVALID_HANDLE_VALUE) {
    CloseHandle(displaced_handle);
  }
#else
  const bool removed =
      unlinkat(parent->object, backup.c_str(), 0) == 0;
#endif
  if (removed) ++*writes;
  std::vector<uint8_t> ignored_bytes;
  ServiceStoreFileFacts ignored_facts;
  bool backup_absent = false;
  const bool absent_proven = ReadServiceStoreFileRetained(
      parent, backup, 0, &ignored_bytes, &ignored_facts,
      &backup_absent) && backup_absent;
  bool original_absent = false;
  const bool original_proven = ReadServiceStoreFileRetained(
      parent, name, 0, &ignored_bytes, &ignored_facts,
      &original_absent) && original_absent;
  const bool durable = !flush_parent ||
      FlushServiceStoreDirectory(parent->object);
  *ambiguous = !removed || !absent_proven ||
      !original_proven || !durable;
  return !*ambiguous;
}

napi_value PublishServiceFileAtomic(napi_env env,
                                    napi_callback_info info) {
  napi_value args[5];
  ServiceStoreHandle* parent = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string name;
  std::vector<uint8_t> bytes, expected_bytes;
  ServiceStoreFileFacts expected;
  bool expected_present = false;
  if (!InventoryArgs(env, info, 5, args) ||
      !ServiceStoreHandleArg(env, args[0], &parent) ||
      (parent->kind != ServiceStoreHandleKind::Root &&
       parent->kind != ServiceStoreHandleKind::Directory) ||
      parent->access != ServiceStoreAccess::Write ||
      !InventoryString(env, args[1], &name) ||
      !ValidServiceStoreComponent(name) ||
      parent->namespace_name == "locks" ||
      !ServiceStoreBuffer(env, args[2], &bytes) ||
      !ServiceStoreExpectedFileArg(
          env, args[3], &expected_present,
          &expected, &expected_bytes) ||
      !ServiceStoreHandleArg(env, args[4], &lock) ||
      !ServiceLockAuthorizes(parent, lock, true)) {
    ServiceError(env, "SERVICE_INVALID",
                 "publish_service_file_atomic");
    return nullptr;
  }
  std::vector<uint8_t> prior_bytes;
  ServiceStoreFileFacts prior;
  bool absent = false;
  if (!ReadServiceStoreFileRetained(
          parent, name, kInventoryMaxBytes,
          &prior_bytes, &prior, &absent)) {
    ServiceError(env, "SERVICE_STALE",
                 "publish_service_file_atomic", 0, true);
    return nullptr;
  }
  if ((!expected_present && !absent) ||
      (expected_present &&
       (absent || prior_bytes != expected_bytes ||
        !SameServiceStoreFileFacts(prior, expected)))) {
    ServiceError(env,
        !expected_present ? "SERVICE_ALREADY_EXISTS"
                          : "SERVICE_STALE",
        "publish_service_file_atomic");
    return nullptr;
  }
  std::string temporary;
  if (!ServiceStoreTemporaryName(&temporary, "publish")) {
    ServiceError(env, "SERVICE_IO_FAILED",
                 "publish_service_file_atomic");
    return nullptr;
  }
#ifdef _WIN32
  HANDLE candidate = INVALID_HANDLE_VALUE;
#else
  int candidate = -1;
#endif
  ServiceStoreIdentity candidate_identity;
  uint32_t writes = 0;
  if (!CreateServiceStoreFile(
          parent->object,
#ifdef _WIN32
          Wide(temporary),
#else
          temporary,
#endif
          parent->roles, ServiceStoreFileProfile(parent), bytes,
          &candidate_identity, &writes, &candidate)) {
    ServiceError(env, writes == 0 ? "SERVICE_IO_FAILED"
                                  : "SERVICE_MANUAL_CLEANUP",
                 "publish_service_file_atomic", writes,
                 writes != 0);
    return nullptr;
  }
  ServiceStoreFileFacts candidate_facts;
  candidate_facts.identity = candidate_identity;
  candidate_facts.size = bytes.size();
  if (!HashServiceStoreBytes(bytes, &candidate_facts.sha256)) {
#ifdef _WIN32
    CloseHandle(candidate);
#else
    close(candidate);
#endif
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "publish_service_file_atomic", writes, true);
    return nullptr;
  }
  std::string backup;
  bool published = false;
#ifdef _WIN32
  if (!expected_present) {
    published = RenameWindowsRelative(
        candidate, parent->object, Wide(name), false);
  } else {
    FILE_ID_INFO parent_id{};
    std::wstring canonical_parent;
    if (!CanonicalInventoryParent(
            parent->object, &parent_id, &canonical_parent) ||
        !InventoryParentStable(
            parent->object, parent_id, canonical_parent)) {
      CloseHandle(candidate);
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "publish_service_file_atomic", writes, true);
      return nullptr;
    }
    for (unsigned attempt = 0; attempt < 128; ++attempt) {
      if (!ServiceStoreTemporaryName(&backup, "displaced")) break;
      const std::wstring backup_path =
          InventoryChildPath(canonical_parent, Wide(backup));
      HANDLE collision = INVALID_HANDLE_VALUE;
      if (!ServiceStoreOpenRelativeFile(
              parent->object, backup, false, &collision)) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) break;
        published = ReplaceFileW(
            InventoryChildPath(
                canonical_parent, Wide(name)).c_str(),
            InventoryChildPath(
                canonical_parent, Wide(temporary)).c_str(),
            backup_path.c_str(), REPLACEFILE_WRITE_THROUGH,
            nullptr, nullptr) != FALSE;
        if (published || GetLastError() != ERROR_FILE_EXISTS) break;
      } else {
        CloseHandle(collision);
      }
    }
  }
#else
  published = RenameAt2(
      parent->object, temporary, name,
      expected_present ? 2u : 1u) == 0;
#endif
  if (!published) {
#ifdef _WIN32
    const DWORD publication_error = GetLastError();
#else
    const int publication_error = errno;
#endif
#ifdef _WIN32
    CloseHandle(candidate);
#else
    close(candidate);
#endif
    std::vector<uint8_t> observed_bytes;
    ServiceStoreFileFacts observed_facts;
    bool observed_absent = false;
    const bool target_observed = ReadServiceStoreFileRetained(
        parent, name, kInventoryMaxBytes, &observed_bytes,
        &observed_facts, &observed_absent);
    const bool target_unchanged = target_observed &&
        (expected_present
            ? !observed_absent &&
                observed_bytes == expected_bytes &&
                SameServiceStoreFileFacts(
                    observed_facts, expected)
            : observed_absent);
    std::vector<uint8_t> candidate_bytes;
    ServiceStoreFileFacts retained_candidate;
    bool candidate_absent = false;
    const bool candidate_unchanged =
        ReadServiceStoreFileRetained(
            parent, temporary, kInventoryMaxBytes,
            &candidate_bytes, &retained_candidate,
            &candidate_absent) &&
        !candidate_absent && candidate_bytes == bytes &&
        SameServiceStoreIdentity(
            retained_candidate.identity, candidate_identity);
    bool backup_absent = true;
    if (!backup.empty()) {
      std::vector<uint8_t> backup_bytes;
      ServiceStoreFileFacts backup_facts;
      backup_absent = false;
      if (!ReadServiceStoreFileRetained(
              parent, backup, 0, &backup_bytes,
              &backup_facts, &backup_absent)) {
        backup_absent = false;
      }
    }
    bool cleanup_ambiguous =
        !target_unchanged || !candidate_unchanged || !backup_absent;
    if (!cleanup_ambiguous) {
      const bool cleaned = RemoveServiceStoreNamedFile(
          parent, temporary, candidate_facts, bytes,
          &writes, true, &cleanup_ambiguous);
      cleanup_ambiguous = cleanup_ambiguous || !cleaned;
    }
    ServiceError(env,
        cleanup_ambiguous ? "SERVICE_MANUAL_CLEANUP"
                          : (!expected_present
#ifdef _WIN32
                              && (publication_error == ERROR_ALREADY_EXISTS ||
                                  publication_error == ERROR_FILE_EXISTS)
#else
                              && publication_error == EEXIST
#endif
                             )
                              ? "SERVICE_ALREADY_EXISTS"
                              : "SERVICE_IO_FAILED",
        "publish_service_file_atomic", writes,
        cleanup_ambiguous);
    return nullptr;
  }
  ++writes;
#ifdef _WIN32
  CloseHandle(candidate);
#else
  close(candidate);
  if (expected_present) backup = temporary;
#endif
  std::vector<uint8_t> published_bytes;
  ServiceStoreFileFacts published_facts;
  bool published_absent = false;
  const bool published_exact = ReadServiceStoreFileRetained(
      parent, name, kInventoryMaxBytes,
      &published_bytes, &published_facts, &published_absent) &&
      !published_absent && published_bytes == bytes &&
      SameServiceStoreIdentity(
          published_facts.identity, candidate_identity) &&
      FlushServiceStoreDirectory(parent->object);
  if (!published_exact) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "publish_service_file_atomic", writes, true);
    return nullptr;
  }
  if (expected_present) {
    bool cleanup_ambiguous = false;
    if (!RemoveServiceStoreNamedFile(
            parent, backup, expected, expected_bytes,
            &writes, true, &cleanup_ambiguous)) {
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "publish_service_file_atomic", writes, true);
      return nullptr;
    }
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(
      env, result, "facts",
      ServiceStoreFileFactsValue(env, published_facts));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

bool CaptureAllowedServiceDirectoryIdentity(
#ifdef _WIN32
    HANDLE handle,
#else
    int handle,
#endif
    const ServiceStoreHandle* parent,
    ServiceStoreIdentity* identity) {
  const ServiceAclProfile candidates[] = {
    ServiceStoreDirectoryProfile(parent),
    ServiceAclProfile::ReleaseDirectory,
  };
  for (ServiceAclProfile profile : candidates) {
    if (!ServiceStoreProfileAllowed(parent, profile, true)) continue;
    ServiceStoreIdentity candidate;
    if (CaptureServiceStoreIdentity(
            handle, parent->roles, profile, &candidate)) {
      *identity = candidate;
      return true;
    }
  }
  return false;
}

bool EnumerateServiceStoreDirectory(
    ServiceStoreHandle* directory, uint32_t maximum,
    bool include_internal,
    std::vector<ServiceStoreDirectoryEntry>* entries,
    bool* overflow) {
  entries->clear();
  *overflow = false;
  if (!RevalidateServiceStoreHandle(directory)) return false;
#ifdef _WIN32
  std::array<uint8_t, 64 * 1024> buffer{};
  bool restart = true;
  for (;;) {
    if (!GetFileInformationByHandleEx(
            directory->object,
            restart ? FileIdBothDirectoryRestartInfo
                    : FileIdBothDirectoryInfo,
            buffer.data(), static_cast<DWORD>(buffer.size()))) {
      if (GetLastError() == ERROR_NO_MORE_FILES) break;
      return false;
    }
    restart = false;
    size_t offset = 0;
    for (;;) {
      if (offset + sizeof(FILE_ID_BOTH_DIR_INFO) > buffer.size()) {
        return false;
      }
      const auto* record =
          reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(
              buffer.data() + offset);
      if (record->FileNameLength == 0 ||
          record->FileNameLength % sizeof(wchar_t) != 0 ||
          record->FileNameLength >
              buffer.size() - offset -
                  offsetof(FILE_ID_BOTH_DIR_INFO, FileName)) {
        return false;
      }
      const std::wstring wide_name(
          record->FileName,
          record->FileNameLength / sizeof(wchar_t));
      const std::string name = Utf8(wide_name);
      if (name != "." && name != "..") {
        const bool internal =
            name.rfind(".gjc-service-", 0) == 0;
        const bool persistent_lock_witness =
            !include_internal && internal &&
            directory->kind == ServiceStoreHandleKind::Root &&
            directory->root_kind == "control" &&
            name.rfind(".gjc-service-lock-", 0) == 0;
        if (persistent_lock_witness) {
          if (record->NextEntryOffset == 0) break;
          if (record->NextEntryOffset <
                  offsetof(FILE_ID_BOTH_DIR_INFO, FileName) ||
              record->NextEntryOffset > buffer.size() - offset) {
            return false;
          }
          offset += record->NextEntryOffset;
          continue;
        }
        if (internal && !include_internal) return false;
        if (!ValidServiceStoreComponent(name)) return false;
        if (entries->size() >= maximum) {
          *overflow = true;
          return false;
        }
        const bool is_directory =
            (record->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        HANDLE child = OpenWindowsRelative(
            directory->object, wide_name,
            FILE_GENERIC_READ | READ_CONTROL,
            kFileOpen, is_directory
                ? VerifiedObjectType::Directory
                : VerifiedObjectType::File);
        ServiceStoreIdentity identity;
        const bool valid = child != INVALID_HANDLE_VALUE &&
            (is_directory
                ? CaptureAllowedServiceDirectoryIdentity(
                    child, directory, &identity)
                : CaptureAllowedServiceFileIdentity(
                    child, directory, &identity));
        if (child != INVALID_HANDLE_VALUE) CloseHandle(child);
        if (!valid) return false;
        entries->push_back({name, identity});
      }
      if (record->NextEntryOffset == 0) break;
      if (record->NextEntryOffset <
              offsetof(FILE_ID_BOTH_DIR_INFO, FileName) ||
          record->NextEntryOffset > buffer.size() - offset) {
        return false;
      }
      offset += record->NextEntryOffset;
    }
  }
#else
  int scan = openat(directory->object, ".",
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (scan < 0) return false;
  DIR* stream = fdopendir(scan);
  if (!stream) {
    close(scan);
    return false;
  }
  errno = 0;
  while (dirent* entry = readdir(stream)) {
    const std::string name(entry->d_name);
    if (name == "." || name == "..") {
      errno = 0;
      continue;
    }
    const bool internal =
        name.rfind(".gjc-service-", 0) == 0;
    const bool persistent_lock_witness =
        !include_internal && internal &&
        directory->kind == ServiceStoreHandleKind::Root &&
        directory->root_kind == "control" &&
        name.rfind(".gjc-service-lock-", 0) == 0;
    if (persistent_lock_witness) {
      errno = 0;
      continue;
    }
    if (internal && !include_internal) {
      closedir(stream);
      return false;
    }
    if (!ValidServiceStoreComponent(name)) {
      closedir(stream);
      return false;
    }
    if (entries->size() >= maximum) {
      *overflow = true;
      closedir(stream);
      return false;
    }
    struct stat metadata{};
    if (fstatat(directory->object, name.c_str(), &metadata,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        (!S_ISDIR(metadata.st_mode) && !S_ISREG(metadata.st_mode))) {
      closedir(stream);
      return false;
    }
    int child = openat(directory->object, name.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
            (S_ISDIR(metadata.st_mode) ? O_DIRECTORY : 0));
    ServiceStoreIdentity identity;
    const bool valid = child >= 0 &&
        (S_ISDIR(metadata.st_mode)
            ? CaptureAllowedServiceDirectoryIdentity(
                child, directory, &identity)
            : CaptureAllowedServiceFileIdentity(
                child, directory, &identity));
    if (child >= 0) close(child);
    if (!valid) {
      closedir(stream);
      return false;
    }
    entries->push_back({name, identity});
    errno = 0;
  }
  const int read_error = errno;
  closedir(stream);
  if (read_error != 0) return false;
#endif
  std::sort(entries->begin(), entries->end(),
      [](const ServiceStoreDirectoryEntry& left,
         const ServiceStoreDirectoryEntry& right) {
        return left.name < right.name;
      });
  return RevalidateServiceStoreHandle(directory);
}

struct ServiceSealedClosureState {
  uint64_t files = 0;
  uint64_t directories = 0;
  uint64_t bytes = 0;
  Sha256 hash;
};

constexpr uint64_t kServiceSealedFileLimit = 100001;
constexpr uint64_t kServiceSealedDirectoryLimit =
    kServiceSealedFileLimit * 64;
constexpr uint64_t kServiceSealedByteLimit =
    kServiceArtifactMaxBytes + 32ULL * 1024ULL * 1024ULL;
constexpr uint32_t kServiceSealedDepthLimit = 64;
constexpr size_t kServiceSealedPathLimit = 4096;

bool ServiceIdentityIsDirectory(
    const ServiceStoreIdentity& identity) {
#ifdef _WIN32
  return (identity.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
  return S_ISDIR(identity.mode);
#endif
}

bool ServiceDirectoryStateToken(
#ifdef _WIN32
    HANDLE directory,
#else
    int directory,
#endif
    std::string* token) {
  std::ostringstream output;
#ifdef _WIN32
  FILE_BASIC_INFO basic{};
  FILE_STANDARD_INFO standard{};
  if (!GetFileInformationByHandleEx(
          directory, FileBasicInfo, &basic, sizeof(basic)) ||
      !GetFileInformationByHandleEx(
          directory, FileStandardInfo, &standard,
          sizeof(standard)) ||
      !standard.Directory || standard.DeletePending) return false;
  output << basic.CreationTime.QuadPart << ":"
         << basic.LastWriteTime.QuadPart << ":"
         << basic.ChangeTime.QuadPart << ":"
         << basic.FileAttributes << ":"
         << standard.NumberOfLinks;
#else
  struct stat metadata{};
  if (fstat(directory, &metadata) != 0 ||
      !S_ISDIR(metadata.st_mode)) return false;
  output << metadata.st_dev << ":" << metadata.st_ino << ":"
         << metadata.st_mode << ":" << metadata.st_uid << ":"
         << metadata.st_gid << ":" << metadata.st_nlink << ":"
         << metadata.st_mtim.tv_sec << ":"
         << metadata.st_mtim.tv_nsec << ":"
         << metadata.st_ctim.tv_sec << ":"
         << metadata.st_ctim.tv_nsec;
#endif
  *token = output.str();
  return !token->empty();
}

bool VerifySealedServiceSubtreeRecursive(
    ServiceStoreHandle* directory, const std::string& prefix,
    uint32_t depth, bool allow_staging_root,
    ServiceSealedClosureState* state, bool* overflow) {
  if (!directory || directory->poisoned ||
      depth > kServiceSealedDepthLimit ||
      prefix.size() > kServiceSealedPathLimit ||
      (directory->profile != ServiceAclProfile::ReleaseDirectory &&
       !(allow_staging_root && depth == 0 &&
         directory->profile ==
             ServiceAclProfile::StagingDirectory))) {
    return false;
  }
  std::string before_state;
  if (!ServiceDirectoryStateToken(
          directory->object, &before_state)) return false;
  std::vector<ServiceStoreDirectoryEntry> entries;
  bool immediate_overflow = false;
  if (!EnumerateServiceStoreDirectory(
          directory, 100001, false, &entries,
          &immediate_overflow)) {
    *overflow = *overflow || immediate_overflow;
    return false;
  }
  if (entries.empty()) return false;
  for (const auto& entry : entries) {
    const std::string relative = prefix.empty()
        ? entry.name : prefix + "/" + entry.name;
    if (relative.size() > kServiceSealedPathLimit) {
      *overflow = true;
      return false;
    }
    const bool child_directory =
        ServiceIdentityIsDirectory(entry.identity);
    if (child_directory) {
      if (entry.identity.profile !=
              ServiceAclProfile::ReleaseDirectory ||
          depth + 1 >= kServiceSealedDepthLimit ||
          ++state->directories >
              kServiceSealedDirectoryLimit) {
        *overflow =
            state->directories > kServiceSealedDirectoryLimit ||
            depth + 1 >= kServiceSealedDepthLimit;
        return false;
      }
#ifdef _WIN32
      HANDLE child = OpenWindowsRelative(
          directory->object, Wide(entry.name),
          FILE_GENERIC_READ | READ_CONTROL,
          kFileOpen, VerifiedObjectType::Directory);
#else
      int child = openat(
          directory->object, entry.name.c_str(),
          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
#endif
      ServiceStoreHandle nested;
      nested.kind = ServiceStoreHandleKind::Directory;
      nested.access = ServiceStoreAccess::Read;
      nested.root_kind = directory->root_kind;
      nested.root_nonce = directory->root_nonce;
      nested.roles_fingerprint = directory->roles_fingerprint;
      nested.roles = directory->roles;
      nested.profile = ServiceAclProfile::ReleaseDirectory;
      nested.identity = entry.identity;
      nested.name = entry.name;
      nested.parent = directory;
      nested.root = directory->root;
      nested.object = child;
      HashField(&state->hash, "directory");
      HashField(&state->hash, relative);
      HashField(&state->hash,
                ServiceStoreIdentityText(entry.identity));
      const bool valid =
#ifdef _WIN32
          child != INVALID_HANDLE_VALUE &&
#else
          child >= 0 &&
#endif
          VerifySealedServiceSubtreeRecursive(
              &nested, relative, depth + 1, false,
              state, overflow);
#ifdef _WIN32
      if (child != INVALID_HANDLE_VALUE) CloseHandle(child);
      nested.object = INVALID_HANDLE_VALUE;
#else
      if (child >= 0) close(child);
      nested.object = -1;
#endif
      nested.closed = true;
      if (!valid) return false;
      continue;
    }
    if (entry.identity.profile != ServiceAclProfile::ReleaseFile &&
        entry.identity.profile !=
            ServiceAclProfile::ReleaseExecutable) {
      return false;
    }
    if (depth + 1 > kServiceSealedDepthLimit ||
        ++state->files > kServiceSealedFileLimit) {
      *overflow = true;
      return false;
    }
#ifdef _WIN32
    HANDLE child = OpenWindowsRelative(
        directory->object, Wide(entry.name),
        GENERIC_READ | READ_CONTROL,
        kFileOpen, VerifiedObjectType::File);
#else
    int child = openat(
        directory->object, entry.name.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
#endif
    ServiceStoreFileFacts facts;
    const bool valid =
#ifdef _WIN32
        child != INVALID_HANDLE_VALUE &&
#else
        child >= 0 &&
#endif
        HashRetainedServiceArtifact(
            child, directory, false,
            kServiceArtifactMaxBytes, &facts) &&
        SameServicePhysicalIdentity(
            facts.identity, entry.identity) &&
        facts.identity.profile == entry.identity.profile &&
        state->bytes <= kServiceSealedByteLimit &&
        facts.size <= kServiceSealedByteLimit - state->bytes;
#ifdef _WIN32
    if (child != INVALID_HANDLE_VALUE) CloseHandle(child);
#else
    if (child >= 0) close(child);
#endif
    if (!valid) return false;
    state->bytes += facts.size;
    HashField(&state->hash, "file");
    HashField(&state->hash, relative);
    HashField(&state->hash,
              ServiceStoreIdentityText(facts.identity));
    HashField(&state->hash, std::to_string(facts.size));
    HashField(&state->hash, facts.sha256);
  }
  std::string after_state;
  return ServiceDirectoryStateToken(
          directory->object, &after_state) &&
      before_state == after_state &&
      RevalidateServiceStoreHandle(directory);
}

bool VerifyCompleteSealedServiceSubtree(
    ServiceStoreHandle* directory, bool allow_staging_root,
    ServiceSealedClosure* closure, bool* overflow) {
  *overflow = false;
  try {
    ServiceSealedClosureState state;
    if (!state.hash.Ready()) return false;
    HashField(&state.hash,
              "gjc-remote/service-sealed-closure/v1");
    if (!VerifySealedServiceSubtreeRecursive(
            directory, "", 0, allow_staging_root,
            &state, overflow) ||
        state.files == 0) {
      return false;
    }
    closure->files = state.files;
    closure->directories = state.directories;
    closure->bytes = state.bytes;
    closure->fingerprint = state.hash.Finish();
    return ValidServiceFingerprint(closure->fingerprint);
  } catch (...) {
    return false;
  }
}

napi_value ListServiceDirectory(napi_env env,
                                napi_callback_info info) {
  napi_value args[3];
  ServiceStoreHandle* directory = nullptr;
  ServiceStoreHandle* lock = nullptr;
  uint32_t maximum = 0;
  if (!InventoryArgs(env, info, 3, args) ||
      !ServiceStoreHandleArg(env, args[0], &directory) ||
      (directory->kind != ServiceStoreHandleKind::Root &&
       directory->kind != ServiceStoreHandleKind::Directory) ||
      !InventoryUint32(env, args[1], &maximum) ||
      maximum == 0 ||
      maximum > (directory->root_kind == "control"
          ? 100000u : 100001u) ||
      !ServiceStoreHandleArg(env, args[2], &lock) ||
      !ServiceLockAuthorizes(directory, lock, false)) {
    ServiceError(env, "SERVICE_INVALID",
                 "list_service_directory");
    return nullptr;
  }
  std::vector<ServiceStoreDirectoryEntry> entries;
  bool overflow = false;
  if (!EnumerateServiceStoreDirectory(
          directory, maximum, false, &entries, &overflow)) {
    ServiceError(env,
        overflow ? "SERVICE_PENDING" : "SERVICE_STALE",
        "list_service_directory", 0, true);
    return nullptr;
  }
  napi_value result, values;
  napi_create_object(env, &result);
  napi_set_named_property(
      env, result, "directoryIdentity",
      ServiceStoreIdentityValue(env, directory->identity));
  napi_create_array_with_length(env, entries.size(), &values);
  for (size_t index = 0; index < entries.size(); ++index) {
    napi_value entry;
    napi_create_object(env, &entry);
    ServiceSetString(env, entry, "name", entries[index].name);
    napi_set_named_property(
        env, entry, "identity",
        ServiceStoreIdentityValue(env, entries[index].identity));
    napi_set_element(env, values, static_cast<uint32_t>(index), entry);
  }
  napi_set_named_property(env, result, "entries", values);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
}

bool ServiceStoreDirectoryExpectedArg(
    napi_env env, napi_value value,
    ServiceStoreIdentity* identity) {
  napi_value captured[1];
  const char* fields[] = {"identity"};
  return InventoryOrdinaryDataObject(
      env, value, fields, 1, captured) &&
      ServiceStoreIdentityArg(env, captured[0], identity) &&
      ServiceProfileDirectory(identity->profile);
}

napi_value RemoveServiceObjectExact(
    napi_env env, napi_callback_info info) {
  napi_value args[4];
  ServiceStoreHandle* parent = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string name;
  ServiceStoreIdentity expected_directory;
  ServiceStoreFileFacts expected_file;
  std::vector<uint8_t> expected_bytes;
  bool file = false;
  bool expected_present = false;
  if (!InventoryArgs(env, info, 4, args) ||
      !ServiceStoreHandleArg(env, args[0], &parent) ||
      (parent->kind != ServiceStoreHandleKind::Root &&
       parent->kind != ServiceStoreHandleKind::Directory) ||
      parent->access != ServiceStoreAccess::Write ||
      !InventoryString(env, args[1], &name) ||
      !ValidServiceStoreComponent(name) ||
      parent->namespace_name == "floor" ||
      parent->namespace_name == "tombstone" ||
      parent->namespace_name == "locks" ||
      (parent->kind == ServiceStoreHandleKind::Root &&
       parent->root_kind == "control" &&
       (name == "floor" || name == "tombstone" ||
        name == "locks")) ||
      !ServiceStoreHandleArg(env, args[3], &lock) ||
      !ServiceLockAuthorizes(parent, lock, true)) {
    ServiceError(env, "SERVICE_INVALID",
                 "remove_service_object_exact");
    return nullptr;
  }
  if (ServiceStoreExpectedFileArg(
          env, args[2], &expected_present,
          &expected_file, &expected_bytes) &&
      expected_present) {
    file = true;
  } else {
    bool pending = false;
    if (napi_is_exception_pending(env, &pending) == napi_ok && pending) {
      napi_value ignored;
      napi_get_and_clear_last_exception(env, &ignored);
    }
    if (!ServiceStoreDirectoryExpectedArg(
            env, args[2], &expected_directory) ||
        !ServiceStoreProfileAllowed(
            parent, expected_directory.profile, true)) {
      ServiceError(env, "SERVICE_INVALID",
                   "remove_service_object_exact");
      return nullptr;
    }
  }
  uint32_t writes = 0;
  bool ambiguous = false;
  if (file) {
    if (!RemoveServiceStoreNamedFile(
            parent, name, expected_file, expected_bytes,
            &writes, true, &ambiguous)) {
      ServiceError(env,
          ambiguous ? "SERVICE_MANUAL_CLEANUP"
                    : "SERVICE_STALE",
          "remove_service_object_exact", writes, ambiguous);
      return nullptr;
    }
  } else {
#ifdef _WIN32
    HANDLE directory = INVALID_HANDLE_VALUE;
#else
    int directory = -1;
#endif
    if (!ServiceStoreNamedDirectoryExact(
            parent->object, name, parent->roles,
            expected_directory, &directory)) {
      ServiceError(env, "SERVICE_STALE",
                   "remove_service_object_exact");
      return nullptr;
    }
    auto temporary_handle = new (std::nothrow) ServiceStoreHandle();
    if (!temporary_handle) {
#ifdef _WIN32
      CloseHandle(directory);
#else
      close(directory);
#endif
      ServiceError(env, "SERVICE_IO_FAILED",
                   "remove_service_object_exact");
      return nullptr;
    }
    temporary_handle->env = env;
    temporary_handle->kind = ServiceStoreHandleKind::Directory;
    temporary_handle->access = ServiceStoreAccess::Read;
    temporary_handle->root_kind = parent->root_kind;
    temporary_handle->root_nonce = parent->root_nonce;
    temporary_handle->roles_fingerprint =
        parent->roles_fingerprint;
    temporary_handle->roles = parent->roles;
    temporary_handle->profile = expected_directory.profile;
    temporary_handle->identity = expected_directory;
    temporary_handle->name = name;
    temporary_handle->parent = parent;
    temporary_handle->root = parent->root;
    temporary_handle->namespace_name = parent->namespace_name;
    temporary_handle->bound_service_key =
        parent->bound_service_key;
    temporary_handle->object = directory;
    std::vector<ServiceStoreDirectoryEntry> children;
    bool overflow = false;
    const bool empty = EnumerateServiceStoreDirectory(
        temporary_handle, 1, true, &children, &overflow) &&
        children.empty();
    temporary_handle->parent = nullptr;
    CloseServiceStoreNative(temporary_handle, true);
    delete temporary_handle;
#ifdef _WIN32
    directory = INVALID_HANDLE_VALUE;
#else
    directory = -1;
#endif
    if (!empty) {
      ServiceError(env,
          overflow || !children.empty()
              ? "SERVICE_PENDING" : "SERVICE_STALE",
          "remove_service_object_exact", 0,
          !overflow && children.empty());
      return nullptr;
    }
    ServiceStoreIdentity reopened_identity;
    if (!ServiceStoreOpenRelativeDirectory(
            parent->object, name, true, &directory) ||
        !CaptureAllowedServiceDirectoryIdentity(
            directory, parent, &reopened_identity) ||
        !SameServiceStoreIdentity(
            reopened_identity, expected_directory)) {
#ifdef _WIN32
      if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
#else
      if (directory >= 0) close(directory);
#endif
      ServiceError(env, "SERVICE_STALE",
                   "remove_service_object_exact");
      return nullptr;
    }
    std::string backup;
    if (!ServiceStoreTemporaryName(&backup, "remove-dir")) {
      ServiceError(env, "SERVICE_IO_FAILED",
                   "remove_service_object_exact");
      return nullptr;
    }
#ifdef _WIN32
    if (!RenameWindowsRelative(
            directory, parent->object, Wide(backup), false)) {
      CloseHandle(directory);
      ServiceError(env, "SERVICE_STALE",
                   "remove_service_object_exact");
      return nullptr;
    }
    ++writes;
    CloseHandle(directory);
    HANDLE moved = INVALID_HANDLE_VALUE;
#else
    if (RenameAt2(
            parent->object, name, backup, 1) != 0) {
      close(directory);
      ServiceError(env, "SERVICE_STALE",
                   "remove_service_object_exact");
      return nullptr;
    }
    ++writes;
    close(directory);
    int moved = -1;
#endif
    const bool moved_exact = ServiceStoreNamedDirectoryExact(
        parent->object, backup, parent->roles,
        expected_directory, &moved);
    if (!moved_exact) {
#ifdef _WIN32
      if (moved != INVALID_HANDLE_VALUE) CloseHandle(moved);
#else
      if (moved >= 0) close(moved);
#endif
      ambiguous = true;
    } else {
#ifdef _WIN32
      FILE_DISPOSITION_INFO disposition{TRUE};
      const bool removed = SetFileInformationByHandle(
          moved, FileDispositionInfo, &disposition,
          sizeof(disposition));
      CloseHandle(moved);
#else
      close(moved);
      const bool removed = unlinkat(
          parent->object, backup.c_str(), AT_REMOVEDIR) == 0;
#endif
      if (removed) ++writes;
      bool original_absent = false;
#ifdef _WIN32
      HANDLE original = INVALID_HANDLE_VALUE;
      original_absent = !ServiceStoreOpenRelativeDirectory(
          parent->object, name, false, &original) &&
          GetLastError() == ERROR_FILE_NOT_FOUND;
      if (original != INVALID_HANDLE_VALUE) CloseHandle(original);
#else
      int original = -1;
      original_absent = !ServiceStoreOpenRelativeDirectory(
          parent->object, name, false, &original) &&
          errno == ENOENT;
      if (original >= 0) close(original);
#endif
      ambiguous = !removed || !original_absent ||
          !FlushServiceStoreDirectory(parent->object);
    }
    if (ambiguous) {
      ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                   "remove_service_object_exact", writes, true);
      return nullptr;
    }
  }
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetBoolean(env, result, "removed", true);
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

bool ServiceStoreSameVolume(const ServiceStoreIdentity& left,
                            const ServiceStoreIdentity& right) {
#ifdef _WIN32
  return left.volume_serial == right.volume_serial;
#else
  return left.device == right.device;
#endif
}

bool RebindPublishedServiceDirectory(
    napi_env env, ServiceStoreHandle* source,
    napi_value destination_object,
    ServiceStoreHandle* destination,
    const std::string& name,
    const ServiceStoreIdentity& identity) {
  napi_ref new_parent_ref = nullptr;
  if (napi_create_reference(
          env, destination_object, 1, &new_parent_ref) != napi_ok) {
    return false;
  }
  if (source->parent && source->parent->children > 0) {
    --source->parent->children;
  }
  if (source->parent_ref) {
    napi_delete_reference(env, source->parent_ref);
  }
  source->parent = destination;
  source->parent_ref = new_parent_ref;
  ++destination->children;
  source->root = destination->root;
  source->root_kind = destination->root_kind;
  source->root_nonce = destination->root_nonce;
  source->roles_fingerprint = destination->roles_fingerprint;
  source->roles = destination->roles;
  source->profile = identity.profile;
  source->identity = identity;
  source->name = name;
  source->namespace_name = destination->namespace_name;
  source->bound_service_key = destination->bound_service_key;
  return true;
}

napi_value PublishServiceDirectoryNoReplace(
    napi_env env, napi_callback_info info) {
  napi_value args[5];
  ServiceStoreHandle* source = nullptr;
  ServiceStoreHandle* destination = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string name;
  ServiceStoreIdentity expected;
  if (!InventoryArgs(env, info, 5, args) ||
      !ServiceStoreHandleArg(env, args[0], &source) ||
      source->kind != ServiceStoreHandleKind::Directory ||
      source->root_kind != "staging" ||
      source->access != ServiceStoreAccess::Write ||
      source->profile != ServiceAclProfile::ReleaseDirectory ||
      source->children != 0 ||
      !source->parent ||
      !ServiceStoreHandleArg(env, args[1], &destination) ||
      (destination->kind != ServiceStoreHandleKind::Root &&
       destination->kind != ServiceStoreHandleKind::Directory) ||
      (destination->root_kind != "releases" &&
       destination->root_kind != "shawl") ||
      destination->access != ServiceStoreAccess::Write ||
      !InventoryString(env, args[2], &name) ||
      !ValidServiceFingerprint(name) ||
      !ServiceStoreIdentityArg(env, args[3], &expected) ||
      !SameServiceStoreIdentity(source->identity, expected) ||
      !ServiceStoreHandleArg(env, args[4], &lock) ||
      lock->scope != "artifact" ||
      !ServiceLockAuthorizes(source, lock, true) ||
      !ServiceLockAuthorizes(destination, lock, true) ||
      source->roles_fingerprint != destination->roles_fingerprint ||
      !ServiceStoreSameVolume(
          source->identity, destination->identity)) {
    ServiceError(env, "SERVICE_INVALID",
                 "publish_service_directory_no_replace");
    return nullptr;
  }
  ServiceSealedClosure closure;
  bool closure_overflow = false;
  if (!VerifyCompleteSealedServiceSubtree(
          source, false, &closure, &closure_overflow)) {
    ServiceError(env,
        closure_overflow ? "SERVICE_PENDING" : "SERVICE_STALE",
        "publish_service_directory_no_replace", 0,
        !closure_overflow);
    return nullptr;
  }
#ifdef _WIN32
  HANDLE collision = INVALID_HANDLE_VALUE;
#else
  int collision = -1;
#endif
  if (ServiceStoreOpenRelativeDirectory(
          destination->object, name, false, &collision)) {
#ifdef _WIN32
    CloseHandle(collision);
#else
    close(collision);
#endif
    ServiceError(env, "SERVICE_ALREADY_EXISTS",
                 "publish_service_directory_no_replace");
    return nullptr;
  }
#ifdef _WIN32
  if (GetLastError() != ERROR_FILE_NOT_FOUND) {
#else
  if (errno != ENOENT) {
#endif
    ServiceError(env, "SERVICE_STALE",
                 "publish_service_directory_no_replace", 0, true);
    return nullptr;
  }
  uint32_t writes = 0;
  const ServiceStoreIdentity published_identity = source->identity;
  if (!ServiceLockAuthorizes(source, lock, true) ||
      !ServiceLockAuthorizes(destination, lock, true)) {
    ServiceError(env, "SERVICE_STALE",
                 "publish_service_directory_no_replace");
    return nullptr;
  }
#ifdef _WIN32
  const bool renamed = RenameWindowsRelative(
      source->object, destination->object, Wide(name), false);
  const DWORD rename_error = renamed ? ERROR_SUCCESS : GetLastError();
#else
  const bool renamed = RenameAt2(
      source->parent->object, source->name,
      destination->object, name, 1) == 0;
  const int rename_error = renamed ? 0 : errno;
#endif
  if (!renamed) {
    ServiceError(env,
#ifdef _WIN32
        rename_error == ERROR_ALREADY_EXISTS ||
            rename_error == ERROR_FILE_EXISTS
#else
        rename_error == EEXIST || rename_error == ENOTEMPTY
#endif
            ? "SERVICE_ALREADY_EXISTS" : "SERVICE_IO_FAILED",
        "publish_service_directory_no_replace", writes);
    return nullptr;
  }
  ++writes;
  const bool durable =
      FlushServiceStoreDirectory(source->parent->object) &&
      FlushServiceStoreDirectory(destination->object);
  const bool rebound = RebindPublishedServiceDirectory(
      env, source, args[1], destination, name,
      published_identity);
  if (!rebound) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "publish_service_directory_no_replace",
                 writes, true);
    return nullptr;
  }
#ifdef _WIN32
  HANDLE reopened = INVALID_HANDLE_VALUE;
#else
  int reopened = -1;
#endif
  const bool observed = ServiceStoreNamedDirectoryExact(
      destination->object, name, destination->roles,
      published_identity, &reopened);
#ifdef _WIN32
  if (reopened != INVALID_HANDLE_VALUE) CloseHandle(reopened);
#else
  if (reopened >= 0) close(reopened);
#endif
  ServiceSealedClosure observed_closure;
  bool observed_overflow = false;
  const bool closure_exact =
      VerifyCompleteSealedServiceSubtree(
          source, false, &observed_closure,
          &observed_overflow) &&
      observed_closure.files == closure.files &&
      observed_closure.directories == closure.directories &&
      observed_closure.bytes == closure.bytes &&
      observed_closure.fingerprint == closure.fingerprint;
  if (!durable || !observed || !closure_exact ||
      !RevalidateServiceStoreHandle(source) ||
      !ServiceLockAuthorizes(source, lock, true) ||
      !ServiceLockAuthorizes(destination, lock, true)) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "publish_service_directory_no_replace",
                 writes, true);
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", args[0]);
  napi_set_named_property(
      env, result, "identity",
      ServiceStoreIdentityValue(env, published_identity));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}

bool LinuxScopeServiceKey(napi_env env, napi_value value,
                          std::string* service_key,
                          bool* present) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok) return false;
  if (type == napi_null) {
    *present = false;
    service_key->clear();
    return true;
  }
  *present = true;
  return InventoryString(env, value, service_key) &&
      ServiceStoreServiceKey(*service_key);
}

#ifdef __linux__
bool LinuxAclHasNoNonOwnerWrite(acl_t acl) {
  if (!acl) return false;
  acl_entry_t entry;
  int id = ACL_FIRST_ENTRY;
  while (acl_get_entry(acl, id, &entry) == 1) {
    id = ACL_NEXT_ENTRY;
    acl_tag_t tag;
    acl_permset_t permissions;
    if (acl_get_tag_type(entry, &tag) != 0 ||
        acl_get_permset(entry, &permissions) != 0) return false;
    if (tag != ACL_USER_OBJ &&
        acl_get_perm(permissions, ACL_WRITE) == 1) {
      return false;
    }
  }
  return true;
}

bool VerifyLinuxTrustedSystemdDirectory(int directory) {
  struct stat metadata{};
  if (directory < 0 || fstat(directory, &metadata) != 0 ||
      !S_ISDIR(metadata.st_mode) || metadata.st_uid != 0 ||
      (metadata.st_mode & 0022) != 0) return false;
  acl_t access = acl_get_fd(directory);
  const bool access_valid = LinuxAclHasNoNonOwnerWrite(access);
  if (access) acl_free(access);
  if (!access_valid) return false;
  const std::string descriptor =
      "/proc/self/fd/" + std::to_string(directory);
  acl_t defaults =
      acl_get_file(descriptor.c_str(), ACL_TYPE_DEFAULT);
  if (!defaults) return errno == ENODATA;
  const bool default_valid = LinuxAclHasNoNonOwnerWrite(defaults);
  acl_free(defaults);
  return default_valid;
}

napi_value LinuxParentIdentityValue(
    napi_env env, const ServiceStoreIdentity& identity) {
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "kind", "linux-parent-v1");
  ServiceSetString(env, result, "device",
                   std::to_string(identity.device));
  ServiceSetString(env, result, "inode",
                   std::to_string(identity.inode));
  ServiceSetUint32(env, result, "mode", identity.mode);
  ServiceSetString(env, result, "owner", identity.owner);
  return result;
}
#endif

napi_value OpenLinuxServiceScope(napi_env env,
                                 napi_callback_info info) {
#ifdef __linux__
  napi_value args[3];
  InventoryRoles roles{};
  std::string service_key, access_text;
  bool service_key_present = false;
  if (!InventoryArgs(env, info, 3, args) ||
      !InventoryRolesArg(env, args[0], &roles) ||
      !LinuxScopeServiceKey(
          env, args[1], &service_key, &service_key_present) ||
      !InventoryString(env, args[2], &access_text) ||
      (access_text != "read-existing" &&
       access_text != "mutate") ||
      (service_key_present &&
       !ServiceStoreServiceKey(service_key)) ||
      !ServiceActorAuthorized(roles) ||
      (access_text == "mutate" &&
       (geteuid() != roles.system || roles.system != 0))) {
    ServiceError(env, "SERVICE_INVALID",
                 "open_linux_service_scope");
    return nullptr;
  }
  int directory = OpenDirectoryNoFollow("/etc/systemd/system");
  ServiceStoreIdentity identity;
  if (directory < 0 ||
      !VerifyLinuxTrustedSystemdDirectory(directory) ||
      !CapturePhysicalDirectoryIdentity(directory, &identity)) {
    if (directory >= 0) close(directory);
    ServiceError(env, "SERVICE_ACCESS_DENIED",
                 "open_linux_service_scope");
    return nullptr;
  }
  std::string roles_fingerprint;
  if (!ServiceStoreRolesFingerprint(
          roles, &roles_fingerprint)) {
    close(directory);
    ServiceError(env, "SERVICE_CRYPTO_UNAVAILABLE",
                 "open_linux_service_scope");
    return nullptr;
  }
  auto* handle = new (std::nothrow) ServiceStoreHandle();
  if (!handle) {
    close(directory);
    ServiceError(env, "SERVICE_IO_FAILED",
                 "open_linux_service_scope");
    return nullptr;
  }
  handle->env = env;
  handle->kind = ServiceStoreHandleKind::LinuxScope;
  handle->access = access_text == "mutate"
      ? ServiceStoreAccess::Write : ServiceStoreAccess::Read;
  handle->root_kind = "linux-systemd";
  handle->roles = roles;
  handle->roles_fingerprint = roles_fingerprint;
  handle->service_key =
      service_key_present ? service_key : "";
  handle->identity = identity;
  handle->object = directory;
  napi_value wrapped = WrapServiceStoreHandle(env, handle);
  if (!wrapped) {
    ServiceError(env, "SERVICE_IO_FAILED",
                 "open_linux_service_scope");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", wrapped);
  napi_set_named_property(
      env, result, "parentIdentity",
      LinuxParentIdentityValue(env, identity));
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "open_linux_service_scope");
  return nullptr;
#endif
}

#ifdef __linux__
enum class LinuxServiceObjectType {
  File, Directory, Symlink,
};

struct LinuxServiceObjectSpec {
  LinuxServiceObjectType type = LinuxServiceObjectType::File;
  std::string parent_name;
  std::string leaf_name;
  std::string link_target;
  bool owned_parent = false;
  bool global_directory = false;
};

bool ResolveLinuxServiceObject(const ServiceStoreHandle* scope,
                               const std::string& kind,
                               LinuxServiceObjectSpec* spec) {
  if (kind == "bot-unit" && scope->service_key == "bot") {
    spec->leaf_name = "gjc-remote-bot.service";
    return true;
  }
  if (kind == "daemon-template" && scope->service_key.empty()) {
    spec->leaf_name = "gjc-remote-daemon@.service";
    return true;
  }
  if ((kind == "daemon-dropin-directory" ||
       kind == "daemon-dropin") &&
      ValidServiceInstanceKey(scope->service_key)) {
    spec->parent_name = "gjc-remote-daemon@" +
        scope->service_key + ".service.d";
    if (kind == "daemon-dropin-directory") {
      spec->type = LinuxServiceObjectType::Directory;
      spec->leaf_name = spec->parent_name;
      spec->parent_name.clear();
    } else {
      spec->leaf_name = "50-gjc-release.conf";
      spec->owned_parent = true;
    }
    return true;
  }
  if (kind == "enablement-directory" &&
      scope->service_key.empty()) {
    spec->type = LinuxServiceObjectType::Directory;
    spec->leaf_name = "multi-user.target.wants";
    spec->global_directory = true;
    return true;
  }
  if (kind == "enablement-link" &&
      (scope->service_key == "bot" ||
       ValidServiceInstanceKey(scope->service_key))) {
    spec->type = LinuxServiceObjectType::Symlink;
    spec->parent_name = "multi-user.target.wants";
    spec->leaf_name = scope->service_key == "bot"
        ? "gjc-remote-bot.service"
        : "gjc-remote-daemon@" + scope->service_key + ".service";
    spec->link_target = scope->service_key == "bot"
        ? "/etc/systemd/system/gjc-remote-bot.service"
        : "/etc/systemd/system/gjc-remote-daemon@.service";
    spec->global_directory = true;
    return true;
  }
  return false;
}

struct LinuxSymlinkFacts {
  uint64_t device = 0;
  uint64_t inode = 0;
  uint32_t mode = 0;
  std::string owner;
};

bool SameLinuxSymlinkFacts(const LinuxSymlinkFacts& left,
                           const LinuxSymlinkFacts& right) {
  return left.device == right.device &&
      left.inode == right.inode &&
      left.mode == right.mode && left.owner == right.owner;
}

napi_value LinuxSymlinkFactsValue(
    napi_env env, const LinuxSymlinkFacts& facts) {
  napi_value result;
  napi_create_object(env, &result);
  ServiceSetString(env, result, "kind", "linux-symlink-v1");
  ServiceSetString(env, result, "device",
                   std::to_string(facts.device));
  ServiceSetString(env, result, "inode",
                   std::to_string(facts.inode));
  ServiceSetUint32(env, result, "mode", facts.mode);
  ServiceSetString(env, result, "owner", facts.owner);
  return result;
}

bool LinuxSymlinkFactsArg(napi_env env, napi_value value,
                          LinuxSymlinkFacts* facts) {
  const char* fields[] = {
    "kind", "device", "inode", "mode", "owner",
  };
  napi_value captured[5];
  std::string kind, device, inode;
  return InventoryOrdinaryDataObject(
          env, value, fields, 5, captured) &&
      InventoryString(env, captured[0], &kind) &&
      kind == "linux-symlink-v1" &&
      InventoryString(env, captured[1], &device) &&
      InventoryString(env, captured[2], &inode) &&
      ParseServiceUnsignedDecimal(device, &facts->device) &&
      ParseServiceUnsignedDecimal(inode, &facts->inode) &&
      InventoryUint32(env, captured[3], &facts->mode) &&
      InventoryString(env, captured[4], &facts->owner);
}

bool LinuxParentIdentityArg(napi_env env, napi_value value,
                            ServiceStoreIdentity* identity) {
  const char* fields[] = {
    "kind", "device", "inode", "mode", "owner",
  };
  napi_value captured[5];
  std::string kind, device, inode;
  return InventoryOrdinaryDataObject(
          env, value, fields, 5, captured) &&
      InventoryString(env, captured[0], &kind) &&
      kind == "linux-parent-v1" &&
      InventoryString(env, captured[1], &device) &&
      InventoryString(env, captured[2], &inode) &&
      ParseServiceUnsignedDecimal(device, &identity->device) &&
      ParseServiceUnsignedDecimal(inode, &identity->inode) &&
      InventoryUint32(env, captured[3], &identity->mode) &&
      InventoryString(env, captured[4], &identity->owner);
}

struct LinuxServiceObjectSnapshot {
  std::string object_kind;
  std::string state;
  ServiceStoreIdentity parent_identity;
  bool container_present = false;
  bool container_owned = false;
  ServiceStoreIdentity container_identity;
  ServiceStoreIdentity directory_identity;
  ServiceStoreFileFacts file_facts;
  LinuxSymlinkFacts link_facts;
  std::vector<uint8_t> bytes;
  std::string target;
};

bool ReadLinuxOwnedServiceFile(
    int parent, const std::string& name,
    const InventoryRoles& roles,
    ServiceStoreFileFacts* facts,
    std::vector<uint8_t>* bytes, bool* absent) {
  *absent = false;
  int file = openat(parent, name.c_str(),
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (file < 0) {
    if (errno == ENOENT) {
      *absent = true;
      return true;
    }
    return false;
  }
  struct stat before{}, after{}, named{};
  bool valid = fstat(file, &before) == 0 &&
      S_ISREG(before.st_mode) &&
      before.st_size >= 0 &&
      static_cast<uint64_t>(before.st_size) <=
          kInventoryMaxBytes &&
      CaptureServiceStoreIdentity(
          file, roles, ServiceAclProfile::ControlFile,
          &facts->identity) &&
      ServiceStoreReadBytes(
          file, kInventoryMaxBytes, bytes) &&
      HashServiceStoreBytes(*bytes, &facts->sha256) &&
      fstat(file, &after) == 0 &&
      fstatat(parent, name.c_str(), &named,
              AT_SYMLINK_NOFOLLOW) == 0 &&
      before.st_dev == after.st_dev &&
      before.st_ino == after.st_ino &&
      before.st_size == after.st_size &&
      before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
      before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
      before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
      before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
      after.st_dev == named.st_dev &&
      after.st_ino == named.st_ino &&
      S_ISREG(named.st_mode);
  facts->size = bytes->size();
  close(file);
  return valid;
}

bool ReadLinuxSymlink(int parent, const std::string& name,
                      LinuxSymlinkFacts* facts,
                      std::string* target, bool* absent) {
  *absent = false;
  struct stat before{}, after{};
  if (fstatat(parent, name.c_str(), &before,
              AT_SYMLINK_NOFOLLOW) != 0) {
    if (errno == ENOENT) {
      *absent = true;
      return true;
    }
    return false;
  }
  if (!S_ISLNK(before.st_mode) || before.st_uid != 0 ||
      before.st_size < 0 || before.st_size > 4096) return false;
  std::array<char, 4097> buffer{};
  const ssize_t length = readlinkat(
      parent, name.c_str(), buffer.data(), buffer.size() - 1);
  if (length < 1 ||
      length >= static_cast<ssize_t>(buffer.size() - 1) ||
      fstatat(parent, name.c_str(), &after,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      before.st_dev != after.st_dev ||
      before.st_ino != after.st_ino ||
      before.st_size != after.st_size ||
      before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
      before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
      !S_ISLNK(after.st_mode)) return false;
  target->assign(buffer.data(), static_cast<size_t>(length));
  facts->device = static_cast<uint64_t>(after.st_dev);
  facts->inode = static_cast<uint64_t>(after.st_ino);
  facts->mode = static_cast<uint32_t>(after.st_mode);
  facts->owner = "uid:" + std::to_string(after.st_uid);
  return true;
}

bool OpenLinuxObjectContainer(
    ServiceStoreHandle* scope,
    const LinuxServiceObjectSpec& spec,
    int* parent, ServiceStoreIdentity* identity,
    bool* parent_absent) {
  *parent_absent = false;
  if (spec.parent_name.empty()) {
    *parent = dup(scope->object);
    if (*parent < 0 ||
        !CapturePhysicalDirectoryIdentity(*parent, identity)) {
      if (*parent >= 0) close(*parent);
      return false;
    }
    return true;
  }
  *parent = openat(scope->object, spec.parent_name.c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (*parent < 0) {
    if (errno == ENOENT) {
      *parent_absent = true;
      return true;
    }
    return false;
  }
  const bool valid = spec.owned_parent
      ? CaptureServiceStoreIdentity(
          *parent, scope->roles,
          ServiceAclProfile::ControlDirectory, identity)
      : VerifyLinuxTrustedSystemdDirectory(*parent) &&
          CapturePhysicalDirectoryIdentity(*parent, identity);
  if (!valid) {
    close(*parent);
    *parent = -1;
  }
  return valid;
}

bool ReadLinuxServiceObjectSnapshot(
    ServiceStoreHandle* scope, const std::string& object_kind,
    LinuxServiceObjectSnapshot* snapshot) {
  LinuxServiceObjectSpec spec;
  if (!ResolveLinuxServiceObject(
          scope, object_kind, &spec) ||
      !RevalidateServiceStoreHandle(scope)) return false;
  snapshot->object_kind = object_kind;
  snapshot->parent_identity = scope->identity;
  int parent = -1;
  bool parent_absent = false;
  if (!OpenLinuxObjectContainer(
          scope, spec, &parent,
          &snapshot->container_identity, &parent_absent)) {
    return false;
  }
  if (parent_absent) {
    snapshot->state = "parent-absent";
    return RevalidateServiceStoreHandle(scope);
  }
  snapshot->container_present = !spec.parent_name.empty();
  snapshot->container_owned = spec.owned_parent;
  bool absent = false;
  bool valid = false;
  if (spec.type == LinuxServiceObjectType::File) {
    valid = ReadLinuxOwnedServiceFile(
        parent, spec.leaf_name, scope->roles,
        &snapshot->file_facts, &snapshot->bytes, &absent);
    snapshot->state = absent ? "absent" : "file";
  } else if (spec.type == LinuxServiceObjectType::Directory) {
    int directory = openat(parent, spec.leaf_name.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0 && errno == ENOENT) {
      absent = true;
      valid = true;
    } else if (directory >= 0) {
      valid = spec.global_directory
          ? VerifyLinuxTrustedSystemdDirectory(directory) &&
              CapturePhysicalDirectoryIdentity(
                  directory, &snapshot->directory_identity)
          : CaptureServiceStoreIdentity(
              directory, scope->roles,
              ServiceAclProfile::ControlDirectory,
              &snapshot->directory_identity);
      close(directory);
    }
    snapshot->state = absent ? "absent" : "directory";
  } else {
    valid = ReadLinuxSymlink(
        parent, spec.leaf_name, &snapshot->link_facts,
        &snapshot->target, &absent);
    valid = valid && (absent ||
        snapshot->target == spec.link_target);
    snapshot->state = absent ? "absent" : "symlink";
  }
  close(parent);
  return valid && RevalidateServiceStoreHandle(scope);
}

napi_value LinuxServiceObjectSnapshotValue(
    napi_env env, const LinuxServiceObjectSnapshot& snapshot) {
  napi_value result, null_value, data;
  napi_create_object(env, &result);
  napi_get_null(env, &null_value);
  ServiceSetString(env, result, "objectKind",
                   snapshot.object_kind);
  ServiceSetString(env, result, "state", snapshot.state);
  napi_set_named_property(
      env, result, "parentIdentity",
      LinuxParentIdentityValue(env, snapshot.parent_identity));
  napi_set_named_property(
      env, result, "containerIdentity",
      snapshot.container_present
          ? (snapshot.container_owned
              ? ServiceStoreIdentityValue(
                  env, snapshot.container_identity)
              : LinuxParentIdentityValue(
                  env, snapshot.container_identity))
          : null_value);
  if (snapshot.state == "file") {
    napi_create_buffer_copy(
        env, snapshot.bytes.size(), snapshot.bytes.data(),
        nullptr, &data);
    napi_set_named_property(env, result, "bytes", data);
    napi_set_named_property(
        env, result, "facts",
        ServiceStoreFileFactsValue(env, snapshot.file_facts));
    napi_set_named_property(env, result, "target", null_value);
  } else if (snapshot.state == "directory") {
    napi_set_named_property(env, result, "bytes", null_value);
    napi_set_named_property(
        env, result, "facts",
        snapshot.object_kind == "enablement-directory"
            ? LinuxParentIdentityValue(
                env, snapshot.directory_identity)
            : ServiceStoreIdentityValue(
                env, snapshot.directory_identity));
    napi_set_named_property(env, result, "target", null_value);
  } else if (snapshot.state == "symlink") {
    napi_set_named_property(env, result, "bytes", null_value);
    napi_set_named_property(
        env, result, "facts",
        LinuxSymlinkFactsValue(env, snapshot.link_facts));
    ServiceSetString(env, result, "target", snapshot.target);
  } else {
    napi_set_named_property(env, result, "bytes", null_value);
    napi_set_named_property(env, result, "facts", null_value);
    napi_set_named_property(env, result, "target", null_value);
  }
  return result;
}

napi_value LinuxServiceObjectResultValue(
    napi_env env, const LinuxServiceObjectSnapshot& snapshot,
    uint32_t writes) {
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(
      env, result, "snapshot",
      LinuxServiceObjectSnapshotValue(env, snapshot));
  ServiceSetUint32(env, result, "writes", writes);
  return result;
}
#endif

napi_value ReadLinuxServiceObject(napi_env env,
                                  napi_callback_info info) {
#ifdef __linux__
  napi_value args[2];
  ServiceStoreHandle* scope = nullptr;
  std::string object_kind;
  if (!InventoryArgs(env, info, 2, args) ||
      !ServiceStoreHandleArg(env, args[0], &scope) ||
      scope->kind != ServiceStoreHandleKind::LinuxScope ||
      !InventoryString(env, args[1], &object_kind)) {
    ServiceError(env, "SERVICE_INVALID",
                 "read_linux_service_object");
    return nullptr;
  }
  LinuxServiceObjectSnapshot snapshot;
  if (!ReadLinuxServiceObjectSnapshot(
          scope, object_kind, &snapshot)) {
    ServiceError(env, "SERVICE_STALE",
                 "read_linux_service_object", 0, true);
    return nullptr;
  }
  return LinuxServiceObjectResultValue(env, snapshot, 0);
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "read_linux_service_object");
  return nullptr;
#endif
}

#ifdef __linux__
bool LinuxPhysicalIdentityMatches(
    const ServiceStoreIdentity& left,
    const ServiceStoreIdentity& right) {
  return left.device == right.device &&
      left.inode == right.inode &&
      left.mode == right.mode && left.owner == right.owner;
}

bool LinuxServiceSnapshotMatchesValue(
    napi_env env, napi_value value,
    const LinuxServiceObjectSnapshot& actual) {
  const char* fields[] = {
    "objectKind", "state", "parentIdentity",
    "containerIdentity", "bytes", "facts", "target",
  };
  napi_value captured[7];
  std::string object_kind, state;
  if (!InventoryOrdinaryDataObject(
          env, value, fields, 7, captured) ||
      !InventoryString(env, captured[0], &object_kind) ||
      !InventoryString(env, captured[1], &state) ||
      object_kind != actual.object_kind ||
      state != actual.state) return false;
  ServiceStoreIdentity parent;
  if (!LinuxParentIdentityArg(env, captured[2], &parent) ||
      !LinuxPhysicalIdentityMatches(
          parent, actual.parent_identity)) return false;
  if (actual.container_present) {
    ServiceStoreIdentity container;
    const bool parsed = actual.container_owned
        ? ServiceStoreIdentityArg(env, captured[3], &container)
        : LinuxParentIdentityArg(env, captured[3], &container);
    if (!parsed ||
        (actual.container_owned
            ? !SameServiceStoreIdentity(
                container, actual.container_identity)
            : !LinuxPhysicalIdentityMatches(
                container, actual.container_identity))) {
      return false;
    }
  } else if (!ServiceStoreNull(env, captured[3])) {
    return false;
  }
  if (actual.state == "file") {
    std::vector<uint8_t> bytes;
    ServiceStoreFileFacts facts;
    return ServiceStoreBuffer(env, captured[4], &bytes) &&
        bytes == actual.bytes &&
        ServiceStoreFileFactsArg(env, captured[5], &facts) &&
        SameServiceStoreFileFacts(
            facts, actual.file_facts) &&
        ServiceStoreNull(env, captured[6]);
  }
  if (actual.state == "directory") {
    ServiceStoreIdentity directory;
    const bool parsed =
        actual.object_kind == "enablement-directory"
            ? LinuxParentIdentityArg(
                env, captured[5], &directory)
            : ServiceStoreIdentityArg(
                env, captured[5], &directory);
    return ServiceStoreNull(env, captured[4]) && parsed &&
        (actual.object_kind == "enablement-directory"
            ? LinuxPhysicalIdentityMatches(
                directory, actual.directory_identity)
            : SameServiceStoreIdentity(
                directory, actual.directory_identity)) &&
        ServiceStoreNull(env, captured[6]);
  }
  if (actual.state == "symlink") {
    LinuxSymlinkFacts facts;
    std::string target;
    return ServiceStoreNull(env, captured[4]) &&
        LinuxSymlinkFactsArg(env, captured[5], &facts) &&
        SameLinuxSymlinkFacts(facts, actual.link_facts) &&
        InventoryString(env, captured[6], &target) &&
        target == actual.target;
  }
  return (actual.state == "absent" ||
          actual.state == "parent-absent") &&
      ServiceStoreNull(env, captured[4]) &&
      ServiceStoreNull(env, captured[5]) &&
      ServiceStoreNull(env, captured[6]);
}

bool LinuxServiceMutationLock(
    ServiceStoreHandle* scope, const std::string& object_kind,
    ServiceStoreHandle* lock) {
  if (!scope || !lock ||
      scope->kind != ServiceStoreHandleKind::LinuxScope ||
      scope->access != ServiceStoreAccess::Write ||
      lock->kind != ServiceStoreHandleKind::Lock ||
      !lock->exclusive || !lock->lock_held ||
      scope->roles_fingerprint != lock->roles_fingerprint ||
      !RevalidateServiceStoreHandle(scope) ||
      !RevalidateServiceStoreHandle(lock)) return false;
  if (lock->scope == "artifact") return true;
  if (object_kind == "daemon-template" ||
      object_kind == "enablement-directory") {
    return lock->scope == "shared-template" &&
        lock->service_key.empty();
  }
  return lock->scope == "service-key" &&
      lock->service_key == scope->service_key;
}

bool CreateLinuxGlobalEnablementDirectory(
    int parent, const std::string& name,
    ServiceStoreIdentity* identity, uint32_t* writes) {
  if (mkdirat(parent, name.c_str(), 0755) != 0) return false;
  ++*writes;
  int directory = openat(parent, name.c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory < 0) return false;
  bool configured = fchown(directory, 0, 0) == 0 &&
      fchmod(directory, 0755) == 0;
  acl_t access = configured
      ? acl_from_text("u::rwx,g::r-x,o::r-x") : nullptr;
  configured = configured && access &&
      acl_set_fd(directory, access) == 0;
  if (access) acl_free(access);
  const std::string descriptor =
      "/proc/self/fd/" + std::to_string(directory);
  if (configured &&
      acl_delete_def_file(descriptor.c_str()) != 0 &&
      errno != ENODATA) configured = false;
  if (configured) ++*writes;
  configured = configured &&
      VerifyLinuxTrustedSystemdDirectory(directory) &&
      CapturePhysicalDirectoryIdentity(directory, identity);
  close(directory);
  return configured;
}

bool PublishLinuxOwnedFile(
    ServiceStoreHandle* scope, int parent,
    const std::string& name, const std::vector<uint8_t>& bytes,
    const LinuxServiceObjectSnapshot& before,
    bool replace, uint32_t* writes) {
  std::string temporary;
  if (!ServiceStoreTemporaryName(
          &temporary, "linux-unit")) return false;
  ServiceStoreIdentity candidate_identity;
  int candidate = -1;
  if (!CreateServiceStoreFile(
          parent, temporary, scope->roles,
          ServiceAclProfile::ControlFile, bytes,
          &candidate_identity, writes, &candidate)) {
    return false;
  }
  close(candidate);
  const bool renamed = RenameAt2(
      parent, temporary, name, replace ? 2u : 1u) == 0;
  if (!renamed) return false;
  ++*writes;
  ServiceStoreFileFacts published;
  std::vector<uint8_t> published_bytes;
  bool absent = false;
  if (!ReadLinuxOwnedServiceFile(
          parent, name, scope->roles,
          &published, &published_bytes, &absent) ||
      absent || published_bytes != bytes ||
      !SameServiceStoreIdentity(
          published.identity, candidate_identity)) {
    return false;
  }
  if (replace) {
    ServiceStoreFileFacts displaced;
    std::vector<uint8_t> displaced_bytes;
    bool displaced_absent = false;
    if (!ReadLinuxOwnedServiceFile(
            parent, temporary, scope->roles,
            &displaced, &displaced_bytes, &displaced_absent) ||
        displaced_absent ||
        displaced_bytes != before.bytes ||
        !SameServiceStoreFileFacts(
            displaced, before.file_facts)) {
      return false;
    }
    if (unlinkat(parent, temporary.c_str(), 0) != 0) return false;
    ++*writes;
  }
  return fsync(parent) == 0;
}

bool CreateLinuxServiceSymlink(
    int parent, const LinuxServiceObjectSpec& spec,
    LinuxSymlinkFacts* facts, uint32_t* writes) {
  if (symlinkat(spec.link_target.c_str(), parent,
                spec.leaf_name.c_str()) != 0) return false;
  ++*writes;
  bool absent = false;
  std::string target;
  return ReadLinuxSymlink(
          parent, spec.leaf_name, facts, &target, &absent) &&
      !absent && target == spec.link_target &&
      fsync(parent) == 0;
}
#endif

napi_value PublishLinuxServiceObject(
    napi_env env, napi_callback_info info) {
#ifdef __linux__
  napi_value args[5];
  ServiceStoreHandle* scope = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string object_kind;
  if (!InventoryArgs(env, info, 5, args) ||
      !ServiceStoreHandleArg(env, args[0], &scope) ||
      scope->kind != ServiceStoreHandleKind::LinuxScope ||
      !InventoryString(env, args[1], &object_kind) ||
      !ServiceStoreHandleArg(env, args[4], &lock) ||
      !LinuxServiceMutationLock(scope, object_kind, lock)) {
    ServiceError(env, "SERVICE_INVALID",
                 "publish_linux_service_object");
    return nullptr;
  }
  LinuxServiceObjectSpec spec;
  if (!ResolveLinuxServiceObject(scope, object_kind, &spec)) {
    ServiceError(env, "SERVICE_INVALID",
                 "publish_linux_service_object");
    return nullptr;
  }
  std::vector<uint8_t> bytes;
  const bool bytes_null = ServiceStoreNull(env, args[2]);
  if ((spec.type == LinuxServiceObjectType::File &&
       (bytes_null || !ServiceStoreBuffer(env, args[2], &bytes))) ||
      (spec.type != LinuxServiceObjectType::File && !bytes_null)) {
    ServiceError(env, "SERVICE_INVALID",
                 "publish_linux_service_object");
    return nullptr;
  }
  LinuxServiceObjectSnapshot before;
  if (!ReadLinuxServiceObjectSnapshot(
          scope, object_kind, &before)) {
    ServiceError(env, "SERVICE_STALE",
                 "publish_linux_service_object", 0, true);
    return nullptr;
  }
  const bool expected_null = ServiceStoreNull(env, args[3]);
  if ((!expected_null &&
       !LinuxServiceSnapshotMatchesValue(
           env, args[3], before)) ||
      (!expected_null &&
       spec.type != LinuxServiceObjectType::File) ||
      (expected_null && before.state != "absent" &&
       before.state != "parent-absent") ||
      (!expected_null && before.state != "file")) {
    ServiceError(env,
        expected_null ? "SERVICE_ALREADY_EXISTS"
                      : "SERVICE_STALE",
        "publish_linux_service_object");
    return nullptr;
  }
  int parent = -1;
  ServiceStoreIdentity parent_identity;
  bool parent_absent = false;
  if (!OpenLinuxObjectContainer(
          scope, spec, &parent, &parent_identity,
          &parent_absent) ||
      (parent_absent &&
       spec.type != LinuxServiceObjectType::Directory)) {
    if (parent >= 0) close(parent);
    ServiceError(env, "SERVICE_STALE",
                 "publish_linux_service_object");
    return nullptr;
  }
  uint32_t writes = 0;
  bool changed = false;
  if (spec.type == LinuxServiceObjectType::File) {
    changed = PublishLinuxOwnedFile(
        scope, parent, spec.leaf_name, bytes,
        before, !expected_null, &writes);
  } else if (spec.type == LinuxServiceObjectType::Directory) {
    ServiceStoreIdentity identity;
    if (spec.global_directory) {
      changed = CreateLinuxGlobalEnablementDirectory(
          parent, spec.leaf_name, &identity, &writes);
    } else {
      int created = -1;
      changed = CreateServiceStoreDirectory(
          parent, spec.leaf_name, scope->roles,
          ServiceAclProfile::ControlDirectory,
          &identity, &writes, &created);
      if (created >= 0) close(created);
    }
    changed = changed && fsync(parent) == 0;
  } else {
    LinuxSymlinkFacts facts;
    changed = CreateLinuxServiceSymlink(
        parent, spec, &facts, &writes);
  }
  if (parent >= 0) close(parent);
  if (!changed) {
    ServiceError(env,
        writes == 0 ? "SERVICE_IO_FAILED"
                    : "SERVICE_MANUAL_CLEANUP",
        "publish_linux_service_object", writes,
        writes != 0);
    return nullptr;
  }
  LinuxServiceObjectSnapshot after;
  if (!ReadLinuxServiceObjectSnapshot(
          scope, object_kind, &after) ||
      (spec.type == LinuxServiceObjectType::File &&
       (after.state != "file" || after.bytes != bytes)) ||
      (spec.type == LinuxServiceObjectType::Directory &&
       after.state != "directory") ||
      (spec.type == LinuxServiceObjectType::Symlink &&
       (after.state != "symlink" ||
        after.target != spec.link_target))) {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "publish_linux_service_object", writes, true);
    return nullptr;
  }
  return LinuxServiceObjectResultValue(env, after, writes);
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "publish_linux_service_object");
  return nullptr;
#endif
}

#ifdef __linux__
bool LinuxDirectoryEmpty(int directory) {
  int scan = openat(directory, ".",
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (scan < 0) return false;
  DIR* stream = fdopendir(scan);
  if (!stream) {
    close(scan);
    return false;
  }
  bool empty = true;
  errno = 0;
  while (dirent* entry = readdir(stream)) {
    if (std::strcmp(entry->d_name, ".") != 0 &&
        std::strcmp(entry->d_name, "..") != 0) {
      empty = false;
      break;
    }
    errno = 0;
  }
  const bool valid = !empty || errno == 0;
  closedir(stream);
  return valid && empty;
}

bool RemoveLinuxOwnedFile(
    ServiceStoreHandle* scope, int parent,
    const LinuxServiceObjectSpec& spec,
    const LinuxServiceObjectSnapshot& expected,
    uint32_t* writes) {
  std::string quarantine;
  if (!ServiceStoreTemporaryName(
          &quarantine, "linux-remove")) return false;
  if (RenameAt2(parent, spec.leaf_name,
                quarantine, 1) != 0) return false;
  ++*writes;
  ServiceStoreFileFacts moved;
  std::vector<uint8_t> bytes;
  bool absent = false;
  if (!ReadLinuxOwnedServiceFile(
          parent, quarantine, scope->roles,
          &moved, &bytes, &absent) ||
      absent || bytes != expected.bytes ||
      !SameServiceStoreFileFacts(
          moved, expected.file_facts)) {
    return false;
  }
  if (unlinkat(parent, quarantine.c_str(), 0) != 0) return false;
  ++*writes;
  struct stat probe{};
  return fstatat(parent, spec.leaf_name.c_str(), &probe,
                 AT_SYMLINK_NOFOLLOW) != 0 &&
      errno == ENOENT && fsync(parent) == 0;
}

bool RemoveLinuxServiceSymlink(
    int parent, const LinuxServiceObjectSpec& spec,
    const LinuxServiceObjectSnapshot& expected,
    uint32_t* writes) {
  std::string quarantine;
  if (!ServiceStoreTemporaryName(
          &quarantine, "linux-unlink")) return false;
  if (RenameAt2(parent, spec.leaf_name,
                quarantine, 1) != 0) return false;
  ++*writes;
  LinuxSymlinkFacts moved;
  std::string target;
  bool absent = false;
  if (!ReadLinuxSymlink(
          parent, quarantine, &moved, &target, &absent) ||
      absent || target != expected.target ||
      !SameLinuxSymlinkFacts(
          moved, expected.link_facts)) {
    return false;
  }
  if (unlinkat(parent, quarantine.c_str(), 0) != 0) return false;
  ++*writes;
  struct stat probe{};
  return fstatat(parent, spec.leaf_name.c_str(), &probe,
                 AT_SYMLINK_NOFOLLOW) != 0 &&
      errno == ENOENT && fsync(parent) == 0;
}
#endif

napi_value RemoveLinuxServiceObject(
    napi_env env, napi_callback_info info) {
#ifdef __linux__
  napi_value args[4];
  ServiceStoreHandle* scope = nullptr;
  ServiceStoreHandle* lock = nullptr;
  std::string object_kind;
  if (!InventoryArgs(env, info, 4, args) ||
      !ServiceStoreHandleArg(env, args[0], &scope) ||
      scope->kind != ServiceStoreHandleKind::LinuxScope ||
      !InventoryString(env, args[1], &object_kind) ||
      object_kind == "enablement-directory" ||
      !ServiceStoreHandleArg(env, args[3], &lock) ||
      !LinuxServiceMutationLock(scope, object_kind, lock)) {
    ServiceError(env, "SERVICE_INVALID",
                 "remove_linux_service_object");
    return nullptr;
  }
  LinuxServiceObjectSpec spec;
  LinuxServiceObjectSnapshot before;
  if (!ResolveLinuxServiceObject(scope, object_kind, &spec) ||
      !ReadLinuxServiceObjectSnapshot(
          scope, object_kind, &before) ||
      before.state == "absent" ||
      before.state == "parent-absent" ||
      !LinuxServiceSnapshotMatchesValue(
          env, args[2], before)) {
    ServiceError(env, "SERVICE_STALE",
                 "remove_linux_service_object");
    return nullptr;
  }
  int parent = -1;
  ServiceStoreIdentity parent_identity;
  bool parent_absent = false;
  if (!OpenLinuxObjectContainer(
          scope, spec, &parent, &parent_identity,
          &parent_absent) || parent_absent) {
    if (parent >= 0) close(parent);
    ServiceError(env, "SERVICE_STALE",
                 "remove_linux_service_object");
    return nullptr;
  }
  uint32_t writes = 0;
  bool removed = false;
  if (spec.type == LinuxServiceObjectType::File) {
    removed = RemoveLinuxOwnedFile(
        scope, parent, spec, before, &writes);
  } else if (spec.type == LinuxServiceObjectType::Symlink) {
    removed = RemoveLinuxServiceSymlink(
        parent, spec, before, &writes);
  } else {
    int directory = openat(parent, spec.leaf_name.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    ServiceStoreIdentity identity;
    const bool exact = directory >= 0 &&
        CaptureServiceStoreIdentity(
            directory, scope->roles,
            ServiceAclProfile::ControlDirectory, &identity) &&
        SameServiceStoreIdentity(
            identity, before.directory_identity) &&
        LinuxDirectoryEmpty(directory);
    if (directory >= 0) close(directory);
    if (exact) {
      std::string quarantine;
      if (ServiceStoreTemporaryName(
              &quarantine, "linux-rmdir") &&
          RenameAt2(parent, spec.leaf_name,
                    quarantine, 1) == 0) {
        ++writes;
        int moved = openat(parent, quarantine.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        ServiceStoreIdentity moved_identity;
        const bool moved_exact = moved >= 0 &&
            CaptureServiceStoreIdentity(
                moved, scope->roles,
                ServiceAclProfile::ControlDirectory,
                &moved_identity) &&
            SameServiceStoreIdentity(
                moved_identity, before.directory_identity) &&
            LinuxDirectoryEmpty(moved);
        if (moved >= 0) close(moved);
        if (moved_exact &&
            unlinkat(parent, quarantine.c_str(),
                     AT_REMOVEDIR) == 0) {
          ++writes;
          removed = fsync(parent) == 0;
        }
      }
    }
  }
  close(parent);
  if (!removed) {
    ServiceError(env,
        writes == 0 ? "SERVICE_STALE"
                    : "SERVICE_MANUAL_CLEANUP",
        "remove_linux_service_object", writes,
        writes != 0);
    return nullptr;
  }
  LinuxServiceObjectSnapshot after;
  if (!ReadLinuxServiceObjectSnapshot(
          scope, object_kind, &after) ||
      after.state != "absent") {
    ServiceError(env, "SERVICE_MANUAL_CLEANUP",
                 "remove_linux_service_object", writes, true);
    return nullptr;
  }
  return LinuxServiceObjectResultValue(env, after, writes);
#else
  ServiceError(env, "SERVICE_UNSUPPORTED",
               "remove_linux_service_object");
  return nullptr;
#endif
}

#ifdef __linux__
// Returns true when `target` denotes the workspace root itself or any object
// strictly inside it. `root` is a canonical absolute path with no trailing
// slash (validated by the caller). The kernel appends " (deleted)" to a
// readlink of an unlinked object; that suffix is stripped before comparison so
// a process still holding a now-deleted workspace file is counted as a holder.
bool ResidualTargetUnderRoot(std::string target, const std::string& root) {
  static const char kDeleted[] = " (deleted)";
  const size_t deletedLen = sizeof(kDeleted) - 1;
  if (target.size() >= deletedLen &&
      target.compare(target.size() - deletedLen, deletedLen, kDeleted) == 0) {
    target.resize(target.size() - deletedLen);
  }
  if (target.empty() || target[0] != '/') return false;
  if (target == root) return true;
  return target.size() > root.size() &&
         target.compare(0, root.size(), root) == 0 &&
         target[root.size()] == '/';
}

// readlink a single /proc magic symlink into `out`. Returns false on any error
// (ENOENT/ESRCH when the process exited mid-scan, EACCES when the link belongs
// to a different security context) or on an over-long / truncated target, so an
// unreadable link never contributes a false holder and never aborts the scan.
bool ResidualReadLink(const std::string& link, std::string* out) {
  std::array<char, 4097> buffer{};
  const ssize_t size = readlink(link.c_str(), buffer.data(), buffer.size() - 1);
  if (size <= 0 || size >= static_cast<ssize_t>(buffer.size() - 1)) return false;
  out->assign(buffer.data(), static_cast<size_t>(size));
  return true;
}
#endif

// enumerate_workspace_process_holders(workDir, sourcePlatform) -> [{ pid }]
//
// Returns the set of process ids that still hold the workspace open before a
// reset/delete generation teardown. A process is a holder when its current
// working directory, root, main executable, or ANY open file descriptor
// resolves (no-follow, via the kernel /proc magic symlinks) to the workspace
// root or an object strictly inside it. The list is the residual-process
// absence proof consumed by workspace-residual-process.js: an EMPTY array
// authorises destruction, a non-empty array blocks it.
//
// Scope and fail-closed posture (Linux, the Compose/WSL serving target chosen
// for this slice): the scan mirrors lsof/fuser semantics over same-namespace
// processes. A /proc entry that cannot be inspected (the process exited, or its
// links belong to a different uid/security context) is skipped rather than
// counted, because a coding-session child sharing the workspace mount always
// runs in this namespace and uid and is therefore inspectable; a link we cannot
// read provably is not such a child. mmap-only holders (a workspace file mapped
// with its descriptor already closed, visible only in /proc/<pid>/maps) are a
// documented non-goal of this slice. The Windows handle-scan is slice S7.2b;
// until then the capability is registered on every platform - so the native ABI
// contract is identical - but only Linux performs a real scan.
napi_value EnumerateWorkspaceProcessHolders(napi_env env, napi_callback_info info) {
  napi_value args[2]; std::string workDir, platform;
  if (!InventoryArgs(env, info, 2, args) || !InventoryString(env, args[0], &workDir) ||
      workDir.empty() || workDir.size() > 4096 ||
      !InventoryString(env, args[1], &platform)) {
    InventoryError(env, "INVENTORY_INVALID", "enumerate_workspace_process_holders"); return nullptr;
  }
#ifdef __linux__
  // workDir must already be canonical: any '//', '/./', '/../', '/.' or '/..'
  // segment can never match a kernel-canonical /proc symlink target, so a
  // non-canonical root would silently enumerate zero holders and falsely
  // authorise destruction. Reject it here rather than fail open.
  if (platform != "posix" || workDir[0] != '/' || workDir == "/" || workDir.back() == '/' ||
      workDir.find("//") != std::string::npos ||
      workDir.find("/./") != std::string::npos ||
      workDir.find("/../") != std::string::npos ||
      (workDir.size() >= 2 && workDir.compare(workDir.size() - 2, 2, "/.") == 0) ||
      (workDir.size() >= 3 && workDir.compare(workDir.size() - 3, 3, "/..") == 0)) {
    InventoryError(env, "INVENTORY_INVALID", "enumerate_workspace_process_holders"); return nullptr;
  }
  DIR* proc = opendir("/proc");
  if (proc == nullptr) {
    InventoryError(env, "WORKSPACE_RESIDUAL_SCAN_FAILED", "enumerate_workspace_process_holders"); return nullptr;
  }
  std::vector<uint32_t> holders;
  struct dirent* entry;
  // readdir returning nullptr means end-of-stream ONLY when errno is still 0; a
  // non-zero errno is a real read error, and continuing would emit a truncated
  // holder list (a false absence). Reset errno before every readdir - including
  // over the `continue` paths and after strtoul clobbers it - and treat a
  // non-zero errno on a null return as a scan failure.
  while (true) {
    errno = 0;
    entry = readdir(proc);
    if (entry == nullptr) {
      if (errno != 0) {
        closedir(proc);
        InventoryError(env, "WORKSPACE_RESIDUAL_SCAN_FAILED", "enumerate_workspace_process_holders"); return nullptr;
      }
      break;
    }
    const char* name = entry->d_name;
    if (name[0] < '1' || name[0] > '9') continue;
    bool allDigits = true;
    for (const char* c = name; *c != '\0'; ++c) {
      if (*c < '0' || *c > '9') { allDigits = false; break; }
    }
    if (!allDigits) continue;
    errno = 0;
    const unsigned long pidLong = strtoul(name, nullptr, 10);
    if (errno != 0 || pidLong == 0 || pidLong > 0x7fffffffUL) continue;
    const std::string base = std::string("/proc/") + name;
    bool holds = false;
    std::string target;
    for (const char* leaf : {"/cwd", "/root", "/exe"}) {
      if (ResidualReadLink(base + leaf, &target) && ResidualTargetUnderRoot(target, workDir)) {
        holds = true; break;
      }
    }
    if (!holds) {
      const std::string fdDir = base + "/fd";
      DIR* fds = opendir(fdDir.c_str());
      if (fds != nullptr) {
        struct dirent* fd;
        // Same errno discipline for the per-process fd stream: a read error here
        // could hide the descriptor that proves this pid is a holder.
        while (!holds) {
          errno = 0;
          fd = readdir(fds);
          if (fd == nullptr) {
            if (errno != 0) {
              closedir(fds); closedir(proc);
              InventoryError(env, "WORKSPACE_RESIDUAL_SCAN_FAILED", "enumerate_workspace_process_holders"); return nullptr;
            }
            break;
          }
          if (fd->d_name[0] == '.') continue;
          if (ResidualReadLink(fdDir + "/" + fd->d_name, &target) &&
              ResidualTargetUnderRoot(target, workDir)) {
            holds = true;
          }
        }
        closedir(fds);
      }
    }
    if (holds) holders.push_back(static_cast<uint32_t>(pidLong));
  }
  closedir(proc);
  napi_value result, element, value;
  napi_create_array_with_length(env, holders.size(), &result);
  for (uint32_t i = 0; i < holders.size(); ++i) {
    napi_create_object(env, &element);
    napi_create_uint32(env, holders[i], &value);
    napi_set_named_property(env, element, "pid", value);
    napi_set_element(env, result, i, element);
  }
  return result;
#else
  (void)platform;
  InventoryError(env, "CONTAINMENT_UNSUPPORTED", "enumerate_workspace_process_holders"); return nullptr;
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
    "enumerate_workspace_process_holders",
    "set_exact_service_acl", "verify_exact_service_acl",
    "read_file_facts_no_follow", "read_boot_id", "read_process_facts",
    "enumerate_process_tree", "read_linux_service_cgroup",
    "terminate_linux_service_cgroup", "open_win32_service",
    "close_win32_service", "query_win32_service",
    "plan_win32_service_resource", "create_win32_service_disabled", "protect_win32_service",
    "set_win32_service_marker", "configure_win32_service_launch",
    "set_win32_service_start_type",
    "set_win32_service_failure_actions",
    "set_win32_service_failure_actions_flag", "start_win32_service",
    "stop_win32_service", "delete_win32_service",
    "terminate_win32_service_tree",
    "open_service_root", "open_service_directory",
    "acquire_service_lock", "close_service_handle",
    "read_service_file", "publish_service_file_atomic",
    "remove_service_object_exact", "list_service_directory",
    "publish_service_directory_no_replace",
    "open_linux_service_scope", "read_linux_service_object",
    "publish_linux_service_object", "remove_linux_service_object",
    "begin_service_artifact_write",
    "write_service_artifact_chunk",
    "finish_service_artifact_write",
    "open_service_artifact_reader",
    "read_service_artifact_chunk",
    "remove_service_artifact_file_exact",
    "seal_service_directory",
    "open_service_artifact_source",
    "plan_service_artifact_location",
    "resolve_service_artifact_location",
    "open_service_external_root",
    "read_service_external_object",
    "open_win32_service_log_observer",
    "read_win32_service_log_observer",
    "read_win32_boot_clock",
    "observe_self_process_epoch",
    "read_self_service_config",
  };
  napi_value result, value, array, signatures;
  napi_create_object(env, &result);
  napi_create_uint32(env, 5, &value); napi_set_named_property(env, result, "contractVersion", value);
  napi_create_uint32(env, 1, &value); napi_set_named_property(env, result, "contractRevision", value);
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
  signature("verify_inventory_acl", {"path", "roles", "profile", "expectedActor"});
  signature("acquire_inventory_fence", {"path", "roles"});
  signature("read_inventory_object", {"path", "maxBytes", "roles", "profile"});
  signature("publish_inventory_object_atomic", {"path", "tempPrefix", "bytes", "expectedIdentity", "roles", "profile"});
  signature("enumerate_workspace_process_holders", {"workDir", "sourcePlatform"});
  signature("set_exact_service_acl", {"path", "roles", "profile"});
  signature("verify_exact_service_acl", {"path", "roles", "profile"});
  signature("read_file_facts_no_follow", {"path", "maxBytes"});
  signature("read_boot_id", {});
  signature("read_process_facts", {"pid"});
  signature("enumerate_process_tree", {"rootPid", "rootStartTime", "rootExecutable", "rootOwner"});
  signature("read_linux_service_cgroup", {"cgroupPath"});
  signature("terminate_linux_service_cgroup", {"cgroupPath", "expectedDevice", "expectedInode", "expectedTreeFingerprint"});
  signature("open_win32_service", {"name", "serviceRole", "roles", "access"});
  signature("close_win32_service", {"serviceHandle"});
  signature("query_win32_service", {"serviceHandle"});
  signature("plan_win32_service_resource", {"name", "serviceRole", "launch", "applicationManifestFingerprint", "phase", "roles"});
  signature("create_win32_service_disabled", {"name", "serviceRole", "launch", "servicePassword", "roles"});
  signature("protect_win32_service", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint", "transitionMarker"});
  signature("set_win32_service_marker", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint", "transitionMarker"});
  signature("configure_win32_service_launch", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint", "launch"});
  signature("set_win32_service_start_type", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint", "startType"});
  signature("set_win32_service_failure_actions", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint", "failurePolicy"});
  signature("set_win32_service_failure_actions_flag", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint", "enabled"});
  signature("start_win32_service", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint"});
  signature("stop_win32_service", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint"});
  signature("delete_win32_service", {"serviceHandle", "expectedConfigFingerprint", "expectedRuntimeFingerprint"});
  signature("terminate_win32_service_tree", {"serviceHandle", "expectedConfigFingerprint", "rootPid", "rootStartTime", "rootExecutable", "rootOwner", "expectedTreeFingerprint"});
  signature("open_service_root", {"rootKind", "roles", "access"});
  signature("open_service_directory", {"parentHandle", "name", "access", "expectedIdentity", "lockHandle"});
  signature("acquire_service_lock", {"controlRootHandle", "scope", "serviceKey", "mode"});
  signature("close_service_handle", {"handle"});
  signature("read_service_file", {"parentHandle", "name", "maxBytes"});
  signature("publish_service_file_atomic", {"parentHandle", "name", "bytes", "expected", "lockHandle"});
  signature("remove_service_object_exact", {"parentHandle", "name", "expected", "lockHandle"});
  signature("list_service_directory", {"directoryHandle", "maxEntries", "lockHandle"});
  signature("publish_service_directory_no_replace", {"sourceDirectoryHandle", "destinationParentHandle", "name", "expectedSourceIdentity", "artifactLockHandle"});
  signature("open_linux_service_scope", {"roles", "serviceKey", "access"});
  signature("read_linux_service_object", {"scopeHandle", "objectKind"});
  signature("publish_linux_service_object", {"scopeHandle", "objectKind", "bytes", "expected", "lockHandle"});
  signature("remove_linux_service_object", {"scopeHandle", "objectKind", "expected", "lockHandle"});
  signature("begin_service_artifact_write", {"parentHandle", "name", "expectedSize", "expectedSha256", "artifactLockHandle"});
  signature("write_service_artifact_chunk", {"writerHandle", "expectedOffset", "bytes"});
  signature("finish_service_artifact_write", {"writerHandle", "finalProfile"});
  signature("open_service_artifact_reader", {"parentHandle", "name", "maxBytes", "expectedFacts", "artifactLockHandle"});
  signature("read_service_artifact_chunk", {"readerHandle", "expectedOffset", "maxBytes"});
  signature("remove_service_artifact_file_exact", {"parentHandle", "name", "expectedFacts", "artifactLockHandle"});
  signature("seal_service_directory", {"directoryHandle", "expectedIdentity", "artifactLockHandle"});
  signature("open_service_artifact_source", {"path", "maxBytes", "expectedFacts", "roles"});
  signature("plan_service_artifact_location", {"rootKind", "artifactFingerprint", "relativePath", "roles"});
  signature("resolve_service_artifact_location", {"directoryHandle", "relativePath", "expectedFileSha256"});
  signature("open_service_external_root", {"absolutePath", "profile", "roles"});
  signature("read_service_external_object", {"externalRootHandle", "relativePath", "mode", "maxBytes"});
  signature("open_win32_service_log_observer", {"serviceHandle", "launch", "resumeCursor"});
  signature("read_win32_service_log_observer", {"observerHandle", "expectedCursorFingerprint", "maxBytes"});
  signature("read_win32_boot_clock", {});
  signature("observe_self_process_epoch", {});
  signature("read_self_service_config", {});
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
    {"publish_inventory_object_atomic", nullptr, PublishInventoryObjectAtomic, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"enumerate_workspace_process_holders", nullptr, EnumerateWorkspaceProcessHolders, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"set_exact_service_acl", nullptr, SetExactServiceAcl, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"verify_exact_service_acl", nullptr, VerifyExactServiceAclMethod, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_file_facts_no_follow", nullptr, ReadFileFactsNoFollow, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_boot_id", nullptr, ReadBootId, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_process_facts", nullptr, ReadProcessFacts, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"enumerate_process_tree", nullptr, EnumerateProcessTree, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_linux_service_cgroup", nullptr, ReadLinuxServiceCgroup, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"terminate_linux_service_cgroup", nullptr, TerminateLinuxServiceCgroup, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_win32_service", nullptr, OpenWin32Service, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"close_win32_service", nullptr, CloseWin32Service, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"query_win32_service", nullptr, QueryWin32Service, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"plan_win32_service_resource", nullptr, PlanWin32ServiceResource, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"create_win32_service_disabled", nullptr, CreateWin32ServiceDisabled, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"protect_win32_service", nullptr, ProtectWin32Service, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"set_win32_service_marker", nullptr, SetWin32ServiceMarker, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"configure_win32_service_launch", nullptr, ConfigureWin32ServiceLaunch, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"set_win32_service_start_type", nullptr, SetWin32ServiceStartType, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"set_win32_service_failure_actions", nullptr, SetWin32ServiceFailureActions, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"set_win32_service_failure_actions_flag", nullptr, SetWin32ServiceFailureActionsFlag, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"start_win32_service", nullptr, StartWin32Service, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"stop_win32_service", nullptr, StopWin32Service, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"delete_win32_service", nullptr, DeleteWin32Service, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"terminate_win32_service_tree", nullptr, TerminateWin32ServiceTree, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_service_root", nullptr, OpenServiceRoot, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_service_directory", nullptr, OpenServiceDirectory, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"acquire_service_lock", nullptr, AcquireServiceLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"close_service_handle", nullptr, CloseServiceHandle, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_service_file", nullptr, ReadServiceFile, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"publish_service_file_atomic", nullptr, PublishServiceFileAtomic, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"remove_service_object_exact", nullptr, RemoveServiceObjectExact, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"list_service_directory", nullptr, ListServiceDirectory, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"publish_service_directory_no_replace", nullptr, PublishServiceDirectoryNoReplace, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_linux_service_scope", nullptr, OpenLinuxServiceScope, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_linux_service_object", nullptr, ReadLinuxServiceObject, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"publish_linux_service_object", nullptr, PublishLinuxServiceObject, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"remove_linux_service_object", nullptr, RemoveLinuxServiceObject, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"begin_service_artifact_write", nullptr, BeginServiceArtifactWrite, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"write_service_artifact_chunk", nullptr, WriteServiceArtifactChunk, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"finish_service_artifact_write", nullptr, FinishServiceArtifactWrite, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_service_artifact_reader", nullptr, OpenServiceArtifactReader, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_service_artifact_chunk", nullptr, ReadServiceArtifactChunk, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"remove_service_artifact_file_exact", nullptr, RemoveServiceArtifactFileExact, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"seal_service_directory", nullptr, SealServiceDirectory, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_service_artifact_source", nullptr, OpenServiceArtifactSource, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"plan_service_artifact_location", nullptr, PlanServiceArtifactLocation, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"resolve_service_artifact_location", nullptr, ResolveServiceArtifactLocation, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_service_external_root", nullptr, OpenServiceExternalRoot, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_service_external_object", nullptr, ReadServiceExternalObject, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"open_win32_service_log_observer", nullptr, OpenWin32ServiceLogObserver, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_win32_service_log_observer", nullptr, ReadWin32ServiceLogObserver, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_win32_boot_clock", nullptr, ReadWin32BootClock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"observe_self_process_epoch", nullptr, ObserveSelfProcessEpoch, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"read_self_service_config", nullptr, ReadSelfServiceConfig, nullptr, nullptr, nullptr, napi_default, nullptr}
  };
  napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods);
  return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
}  // namespace
