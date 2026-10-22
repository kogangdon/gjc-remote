// Owned-child fixture only: no SDK, services, account changes or unrelated process cleanup.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "../src/windows-lineage.h"
#include <cstdint>
#include <string>
#include <vector>

namespace {
constexpr int kInvalid = 90;
constexpr int kSpawnFailed = 91;
constexpr int kNotContained = 92;
constexpr int kBreakawayEscaped = 93;
constexpr int kUnexpectedBreakawayError = 94;
constexpr int kOutputFailed = 95;
constexpr int kIdentityFailed = 96;

struct Process {
  PROCESS_INFORMATION info{};
  ~Process() {
    if (info.hThread) CloseHandle(info.hThread);
    if (info.hProcess) CloseHandle(info.hProcess);
  }
};

bool Delay(const wchar_t* text, DWORD* result) {
  if (!text || !*text) return false;
  uint64_t value = 0;
  for (const wchar_t* p = text; *p; ++p) {
    if (*p < L'0' || *p > L'9') return false;
    value = value * 10 + (*p - L'0');
    if (value > 60000) return false;
  }
  *result = static_cast<DWORD>(value);
  return true;
}

std::wstring Quote(const std::wstring& value) {
  std::wstring output = L"\"";
  size_t slashes = 0;
  for (wchar_t c : value) {
    if (c == L'\\') { ++slashes; continue; }
    output.append(c == L'\"' ? slashes * 2 + 1 : slashes, L'\\');
    slashes = 0;
    output.push_back(c);
  }
  output.append(slashes * 2, L'\\');
  output.push_back(L'\"');
  return output;
}

bool Self(std::wstring* result) {
  std::vector<wchar_t> path(32768);
  DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (!length || length >= path.size()) return false;
  result->assign(path.data(), length);
  return true;
}

// Output is optional when the launching controller supplies no stdout. When a handle
// exists, writes must be complete; partial/broken output is a fixture failure.
bool Emit(const std::string& message) {
  if (message.empty() || message.size() > 256) return false;
  HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (!output || output == INVALID_HANDLE_VALUE) return true;
  SetLastError(ERROR_SUCCESS);
  if (GetFileType(output) == FILE_TYPE_UNKNOWN && GetLastError() == ERROR_INVALID_HANDLE)
    return true;
  DWORD written = 0;
  return WriteFile(output, message.data(), static_cast<DWORD>(message.size()), &written, nullptr) &&
      written == message.size();
}

bool Spawn(const std::wstring& self, const std::vector<std::wstring>& args,
           DWORD flags, Process* process, DWORD* error) {
  std::wstring command = Quote(self);
  for (const auto& arg : args) command += L" " + Quote(arg);
  if (command.size() >= 32767) { *error = ERROR_FILENAME_EXCED_RANGE; return false; }
  std::vector<wchar_t> buffer(command.begin(), command.end());
  buffer.push_back(0);
  SIZE_T length = 0;
  if (InitializeProcThreadAttributeList(nullptr, 1, 0, &length) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER || !length) {
    *error = GetLastError();
    return false;
  }
  std::vector<unsigned char> attributes(length);
  auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
  if (!InitializeProcThreadAttributeList(list, 1, 0, &length)) {
    *error = GetLastError();
    return false;
  }
  struct DeleteAttributes {
    LPPROC_THREAD_ATTRIBUTE_LIST list;
    ~DeleteAttributes() { DeleteProcThreadAttributeList(list); }
  } cleanup{list};
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = list;
  windows_lineage::InheritedOutput output;
  output.Attach(list, startup);
  // No breakaway flags on any normal spawn, no fallback, no post-launch assignment.
  if (!CreateProcessW(self.c_str(), buffer.data(), nullptr, nullptr, TRUE,
                      flags | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                      nullptr, nullptr, &startup.StartupInfo, &process->info)) {
    *error = GetLastError();
    return false;
  }
  *error = 0;
  return true;
}

int SpoofParent(const std::wstring& self, const wchar_t* parentText, DWORD delay) {
  uint64_t parentId = 0;
  if (!parentText || !*parentText) return kInvalid;
  for (const wchar_t* p = parentText; *p; ++p) {
    if (*p < L'0' || *p > L'9') return kInvalid;
    parentId = parentId * 10 + (*p - L'0');
    if (parentId > MAXDWORD) return kInvalid;
  }
  // The caller supplies its own test worker PID, never an unrelated process.
  HANDLE parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, static_cast<DWORD>(parentId));
  if (!parent) return GetLastError() == ERROR_ACCESS_DENIED ? 0 : kSpawnFailed;
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<unsigned char> storage(size);
  auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  if (!InitializeProcThreadAttributeList(attributes, 1, 0, &size)) {
    CloseHandle(parent);
    return kSpawnFailed;
  }
  if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                 &parent, sizeof(parent), nullptr, nullptr)) {
    DeleteProcThreadAttributeList(attributes);
    CloseHandle(parent);
    return kSpawnFailed;
  }
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.lpAttributeList = attributes;
  const std::wstring command = Quote(self) + L" escaped-wait " + std::to_wstring(delay);
  std::vector<wchar_t> buffer(command.begin(), command.end());
  buffer.push_back(0);
  Process child;
  // Deliberately no BREAKAWAY flag, no inherited handles and no uncontained
  // retry. A kernel-enforced denial is a valid negative outcome for this probe.
  const BOOL created = CreateProcessW(self.c_str(), buffer.data(), nullptr, nullptr,
      FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr,
      &startup.StartupInfo, &child.info);
  const DWORD error = created ? 0 : GetLastError();
  DeleteProcThreadAttributeList(attributes);
  CloseHandle(parent);
  if (!created) return error == ERROR_ACCESS_DENIED ? 0 : kSpawnFailed;
  std::vector<unsigned char> members(8192);
  auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(members.data());
  if (!QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, list,
                                 static_cast<DWORD>(members.size()), nullptr)) return kIdentityFailed;
  bool selfPresent = false, childPresent = false;
  for (DWORD index = 0; index < list->NumberOfProcessIdsInList; ++index) {
    selfPresent |= list->ProcessIdList[index] == GetCurrentProcessId();
    childPresent |= list->ProcessIdList[index] == child.info.dwProcessId;
  }
  if (!selfPresent) return kIdentityFailed;
  const bool live = WaitForSingleObject(child.info.hProcess, 0) == WAIT_TIMEOUT;
  if (!childPresent && live) {
    Emit("SPOOF_PARENT_ESCAPED " + std::to_string(child.info.dwProcessId) + "\n");
    // The exact owned child has a finite delay and exits by itself. Do not
    // terminate or mutate anything outside the retained job to hide this bug.
    DWORD exit = STILL_ACTIVE;
    if (WaitForSingleObject(child.info.hProcess, delay + 5000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(child.info.hProcess, &exit)) return kIdentityFailed;
    Emit("OWNED_ESCAPED_TERMINAL " + std::to_string(child.info.dwProcessId) +
         " " + std::to_string(exit) + "\n");
    return kBreakawayEscaped;
  }
  return 0;
}

int Run(int argc, wchar_t** argv) {
  if (argc < 2) return kInvalid;
  if (std::wstring(argv[1]) == L"escaped-wait") {
    DWORD delay = 0;
    if (argc != 3 || !Delay(argv[2], &delay)) return kInvalid;
    Sleep(delay);  // Only the explicitly owned adversarial probe uses this mode.
    return 0;
  }
  BOOL contained = FALSE;
  if (!IsProcessInJob(GetCurrentProcess(), nullptr, &contained) || !contained) return kNotContained;
  std::wstring self;
  if (!Self(&self)) return kIdentityFailed;
  const std::wstring mode = argv[1];
  DWORD delay = 0, grandchildDelay = 0;
  if (mode == L"spoof-parent") {
    if (argc != 4 || !Delay(argv[3], &delay)) return kInvalid;
    return SpoofParent(self, argv[2], delay);
  }
  if (mode == L"wait") {
    if (argc != 3 || !Delay(argv[2], &delay)) return kInvalid;
    if (!Emit("WAIT " + std::to_string(GetCurrentProcessId()) + "\n")) return kOutputFailed;
    Sleep(delay);
    return 0;
  }
  if (mode == L"spawn-exit") {
    if (argc != 3 || !Delay(argv[2], &delay)) return kInvalid;
    Process child;
    DWORD error = 0;
    if (!Spawn(self, {L"wait", std::to_wstring(delay)}, 0, &child, &error)) {
      Emit("SPAWN_FAILED " + std::to_string(error) + "\n");
      return kSpawnFailed;
    }
    return Emit("SPAWN_EXIT " + std::to_string(child.info.dwProcessId) + "\n") ? 0 : kOutputFailed;
  }
  if (mode == L"late" || mode == L"__late") {
    if (argc != 4 || !Delay(argv[2], &delay) || !Delay(argv[3], &grandchildDelay)) return kInvalid;
    Process child;
    DWORD error = 0;
    if (mode == L"late") {
      if (!Spawn(self, {L"__late", std::to_wstring(delay), std::to_wstring(grandchildDelay)},
                 0, &child, &error)) {
        Emit("SPAWN_FAILED " + std::to_string(error) + "\n");
        return kSpawnFailed;
      }
      // Root exits before the intermediate's delayed spawn. No snapshot repairs it.
      return Emit("LATE_ROOT_EXIT " + std::to_string(child.info.dwProcessId) + "\n") ? 0 : kOutputFailed;
    }
    Sleep(delay);
    if (!Spawn(self, {L"wait", std::to_wstring(grandchildDelay)}, 0, &child, &error)) {
      Emit("SPAWN_FAILED " + std::to_string(error) + "\n");
      return kSpawnFailed;
    }
    return Emit("LATE_GRANDCHILD " + std::to_string(child.info.dwProcessId) + "\n") ? 0 : kOutputFailed;
  }
  if (mode == L"tree" || mode == L"__tree") {
    if (argc != 3 || !Delay(argv[2], &delay)) return kInvalid;
    Process child;
    DWORD error = 0;
    if (!Spawn(self, {mode == L"tree" ? L"__tree" : L"wait", std::to_wstring(delay)},
               0, &child, &error)) {
      Emit("SPAWN_FAILED " + std::to_string(error) + "\n");
      return kSpawnFailed;
    }
    if (!Emit("TREE_BRANCH " + std::to_string(GetCurrentProcessId()) + " " +
              std::to_string(child.info.dwProcessId) + "\n")) return kOutputFailed;
    // Controller synchronizes on three exact fixture images, not a count that
    // might include operating-system console companions.
    Sleep(delay);
    return 0;
  }
  if (mode == L"breakaway") {
    if (argc != 3 || !Delay(argv[2], &delay)) return kInvalid;
    Process child;
    DWORD error = 0;
    if (Spawn(self, {L"wait", std::to_wstring(delay)}, CREATE_BREAKAWAY_FROM_JOB, &child, &error)) {
      // This is a containment failure, never success or an uncontained retry. The
      // finite child exits on its own; fixture never kills anything outside its job.
      Emit("BREAKAWAY_ESCAPED " + std::to_string(child.info.dwProcessId) + "\n");
      return kBreakawayEscaped;
    }
    if (error != ERROR_ACCESS_DENIED) {
      Emit("BREAKAWAY_UNEXPECTED_ERROR " + std::to_string(error) + "\n");
      return kUnexpectedBreakawayError;
    }
    if (!Emit("BREAKAWAY_DENIED\n")) return kOutputFailed;
    Sleep(delay);  // Keep the denied-attempt scope observable before normal exit.
    return 0;
  }
  return kInvalid;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  int result = kIdentityFailed;
  try {
    if (!Emit("STARTED " + std::to_string(GetCurrentProcessId()) + "\n")) return kOutputFailed;
    result = Run(argc, argv);
  } catch (...) {
    Emit("FIXTURE_NATIVE_FAILURE\n");
  }
  if (!Emit("TERMINAL " + std::to_string(GetCurrentProcessId()) + " " +
            std::to_string(result) + "\n")) return kOutputFailed;
  return result;
}
