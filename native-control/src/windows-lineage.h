#pragma once

#ifndef _WIN32
#error Windows lineage requires Win32.
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

// Source-owned creation-time containment. This is not a service/SCM handoff API.
namespace windows_lineage {

class Handle {
 public:
  explicit Handle(HANDLE value = nullptr) : value_(value) {}
  ~Handle() { Reset(); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  HANDLE Get() const { return value_; }
  void Reset(HANDLE value = nullptr) {
    if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    value_ = value;
  }
 private:
  HANDLE value_;
};

struct Effects {
  bool jobCreated = false;
  bool rootCreated = false;
  bool rootResumed = false;
  bool forced = false;
  uint32_t terminationCalls = 0;
  uint32_t cleanupTerminationCalls = 0;
};

struct Error : std::exception {
  std::string code;
  std::string message;
  DWORD win32;
  Effects effects;
  bool ambiguous;
  std::wstring scopeId, rootExecutable, rootOwner;
  DWORD rootPid = 0;
  uint64_t rootStartTime = 0;
  Error(const char* c, const char* m, DWORD w = 0, Effects e = {}, bool a = false)
      : code(c), message(m), win32(w), effects(e), ambiguous(a) {}
  const char* what() const noexcept override { return message.c_str(); }
};

inline bool Text(const std::wstring& text) {
  if (text.empty() || text.size() > 4096) return false;
  for (size_t i = 0; i < text.size(); ++i) {
    unsigned c = text[i];
    if (!c) return false;
    if (c >= 0xd800 && c <= 0xdbff) {
      if (++i == text.size() || text[i] < 0xdc00 || text[i] > 0xdfff) return false;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

inline bool Hash(const std::wstring& text) {
  if (text.size() != 64) return false;
  for (wchar_t c : text)
    if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) return false;
  return true;
}

inline std::wstring CurrentBootId() {
  struct SystemTimeOfDayInformation {
    LARGE_INTEGER boot_time, current_time, timezone_bias;
    ULONG timezone_id, reserved;
    ULONGLONG boot_time_bias, sleep_time_bias;
  } value{};
  using Query = LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
  auto query = reinterpret_cast<Query>(GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
  ULONG returned = 0;
  if (!query || query(3, &value, sizeof(value), &returned) < 0 ||
      returned < sizeof(value.boot_time) || value.boot_time.QuadPart <= 0)
    throw Error("LINEAGE_TRACKING_LOST", "Native boot identity unavailable");
  return L"win32:" + std::to_wstring(static_cast<uint64_t>(value.boot_time.QuadPart));
}

// Only these temporary duplicates may cross a process creation boundary. The
// owning job, image, root and process/thread handles are never inheritable.
class InheritedOutput {
 public:
  InheritedOutput() {
    Duplicate(STD_OUTPUT_HANDLE, out_);
    Duplicate(STD_ERROR_HANDLE, err_);
    handles_[0] = out_.Get();
    handles_[1] = err_.Get();
  }
  void Attach(LPPROC_THREAD_ATTRIBUTE_LIST attributes, STARTUPINFOEXW& startup) {
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   handles_, sizeof(handles_), nullptr, nullptr))
      throw Error("LINEAGE_TRACKING_LOST", "Cannot restrict inherited output handles", GetLastError());
    startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = nullptr;
    startup.StartupInfo.hStdOutput = handles_[0];
    startup.StartupInfo.hStdError = handles_[1];
  }
 private:
  static void Duplicate(DWORD id, Handle& target) {
    HANDLE source = GetStdHandle(id);
    if (source && source != INVALID_HANDLE_VALUE) {
      DWORD flags = 0;
      if (GetHandleInformation(source, &flags)) {
        HANDLE copy = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &copy,
                             0, TRUE, DUPLICATE_SAME_ACCESS))
          throw Error("LINEAGE_TRACKING_LOST", "Cannot duplicate output handle", GetLastError());
        target.Reset(copy);
        return;
      }
      if (GetLastError() != ERROR_INVALID_HANDLE)
        throw Error("LINEAGE_TRACKING_LOST", "Cannot validate output handle", GetLastError());
    }
    // An absent output stream has an explicit write-only null sink, not an
    // uninitialized standard handle or a broad inheritance fallback.
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    target.Reset(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (target.Get() == INVALID_HANDLE_VALUE)
      throw Error("LINEAGE_TRACKING_LOST", "Cannot open null output sink", GetLastError());
  }
  Handle out_, err_;
  HANDLE handles_[2]{};
};

inline std::wstring CanonicalSid(const std::wstring& text) {
  PSID sid = nullptr;
  if (!Text(text) || !ConvertStringSidToSidW(text.c_str(), &sid))
    throw Error("LINEAGE_INVALID", "Invalid role SID", GetLastError());
  LPWSTR rendered = nullptr;
  BOOL ok = IsValidSid(sid) && ConvertSidToStringSidW(sid, &rendered);
  DWORD error = ok ? 0 : GetLastError();
  std::wstring result;
  try { if (ok) result.assign(rendered); }
  catch (...) { if (rendered) LocalFree(rendered); LocalFree(sid); throw; }
  if (rendered) LocalFree(rendered);
  LocalFree(sid);
  if (!ok) throw Error("LINEAGE_INVALID", "Cannot canonicalize role SID", error);
  return result;
}

struct WindowsLineageBinding {
  std::wstring serviceKey, bootId, configFingerprint, roleSid, lifetimeId;
  void Validate() const {
    if (!Text(serviceKey) || !Text(bootId) || !Hash(configFingerprint) ||
        !Text(lifetimeId) || CanonicalSid(roleSid) != roleSid)
      throw Error("LINEAGE_INVALID", "Invalid exact lineage binding");
    if (bootId != CurrentBootId())
      throw Error("LINEAGE_INVALID", "Binding does not identify the current native boot");
  }
  bool operator==(const WindowsLineageBinding& b) const {
    return serviceKey == b.serviceKey && bootId == b.bootId &&
        configFingerprint == b.configFingerprint && roleSid == b.roleSid &&
        lifetimeId == b.lifetimeId;
  }
};

inline std::wstring TokenOwner(HANDLE process) {
  HANDLE raw = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &raw))
    throw Error("LINEAGE_TRACKING_LOST", "Cannot open root token", GetLastError());
  Handle token(raw);
  DWORD length = 0;
  if (GetTokenInformation(raw, TokenUser, nullptr, 0, &length) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER || !length)
    throw Error("LINEAGE_TRACKING_LOST", "Cannot size root owner", GetLastError());
  std::vector<unsigned char> bytes(length);
  if (!GetTokenInformation(raw, TokenUser, bytes.data(), length, &length))
    throw Error("LINEAGE_TRACKING_LOST", "Cannot query root owner", GetLastError());
  auto* user = reinterpret_cast<TOKEN_USER*>(bytes.data());
  LPWSTR rendered = nullptr;
  if (!IsValidSid(user->User.Sid) || !ConvertSidToStringSidW(user->User.Sid, &rendered))
    throw Error("LINEAGE_TRACKING_LOST", "Cannot render root owner", GetLastError());
  std::wstring owner;
  try { owner.assign(rendered); }
  catch (...) { LocalFree(rendered); throw; }
  LocalFree(rendered);
  return owner;
}

inline std::wstring Quote(const std::wstring& value) {
  std::wstring out = L"\"";
  size_t slashes = 0;
  for (wchar_t c : value) {
    if (c == L'\\') { ++slashes; continue; }
    if (c == L'\"') out.append(slashes * 2 + 1, L'\\');
    else out.append(slashes, L'\\');
    slashes = 0;
    out.push_back(c);
  }
  out.append(slashes * 2, L'\\');
  out.push_back(L'\"');
  return out;
}

inline std::wstring FinalPath(HANDLE file) {
  std::vector<wchar_t> buffer(32768);
  DWORD length = GetFinalPathNameByHandleW(file, buffer.data(),
      static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!length || length >= buffer.size())
    throw Error("LINEAGE_INVALID", "Cannot resolve executable identity", GetLastError());
  return std::wstring(buffer.data(), length);
}

inline uint64_t CreationTime(HANDLE process) {
  FILETIME created{}, exited{}, kernel{}, user{};
  if (!GetProcessTimes(process, &created, &exited, &kernel, &user))
    throw Error("LINEAGE_TRACKING_LOST", "Cannot query root incarnation", GetLastError());
  uint64_t value = (uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
  if (!value) throw Error("LINEAGE_TRACKING_LOST", "Missing root incarnation");
  return value;
}

// `closed` is only the kernel fact that the sealed retained job reached zero
// active processes and the retained root exited. `coverageComplete` claims
// complete causal-lineage coverage, which ordinary job inheritance cannot
// prove: same-user code can still create a child with
// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS designating a parent outside the job
// (demonstrated by the owned spoof-parent probe). An inheritance-only scope
// therefore NEVER reports coverageComplete=true; that would require an
// enforced creation-authority boundary (separate authority).
struct Receipt {
  WindowsLineageBinding binding;
  std::wstring scopeId, operationId, rootExecutable, rootOwner;
  DWORD rootPid = 0;
  uint64_t rootStartTime = 0;
  DWORD activeProcesses = 0, totalProcesses = 0;
  bool coverageComplete = false, sealed = false, closed = false;
  // Sticky tripwire: an escape of the controller-designated-parent kind was
  // actually observed during the scope lifetime. Absence is never proof.
  bool escapeDetected = false;

  bool rootExited = false;
  DWORD rootExitCode = STILL_ACTIVE;
  bool forced = false;
  uint32_t terminationCalls = 0;
};

struct LiveMember {
  DWORD pid;
  uint64_t startTime;
  std::wstring executable;
};

class WindowsLineageScope {
 public:
  explicit WindowsLineageScope(WindowsLineageBinding binding) : binding_(std::move(binding)) {
    binding_.Validate();
  }
  WindowsLineageScope(const WindowsLineageScope&) = delete;
  WindowsLineageScope& operator=(const WindowsLineageScope&) = delete;
  // Destruction only releases handles, even with live descendants. Never kill-on-close.
  ~WindowsLineageScope() = default;
  const Effects& GetEffects() const { return effects_; }
  void DescribeError(Error& error) const {
    error.effects = effects_;
    error.scopeId = scopeId_;
    error.rootPid = rootPid_;
    error.rootStartTime = rootStartTime_;
    error.rootExecutable = executable_;
    error.rootOwner = owner_;
  }
  void Close() {
    released_ = true;
    image_.Reset();
    root_.Reset();
    job_.Reset();
  }

  void CreateContained(const std::wstring& executable, const std::vector<std::wstring>& args) {
    binding_.Validate();  // Native boot comparison precedes every launch effect.
    if (released_ || attempted_ || sealed_)
      throw Error("LINEAGE_STALE", "A scope permits exactly one root launch", 0, effects_);
    attempted_ = true;
    try {
      if (!Text(executable) || args.size() > 128 ||
          !(executable.size() > 2 &&
            ((executable[1] == L':' && (executable[2] == L'\\' || executable[2] == L'/')) ||
             (executable[0] == L'\\' && executable[1] == L'\\'))))
        throw Error("LINEAGE_INVALID", "Executable must be an absolute path");
      // Sharing READ only denies writes and delete/rename for the entire retained lifetime.
      image_.Reset(CreateFileW(executable.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
      if (image_.Get() == INVALID_HANDLE_VALUE)
        throw Error("LINEAGE_INVALID", "Cannot lock executable read-only", GetLastError());
      BY_HANDLE_FILE_INFORMATION imageInfo{};
      if (!GetFileInformationByHandle(image_.Get(), &imageInfo) ||
          (imageInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        throw Error("LINEAGE_INVALID", "Executable is not a regular file", GetLastError());
      executable_ = FinalPath(image_.Get());
      std::wstring command = Quote(executable_);
      for (const auto& arg : args) {
        // Empty argv entries are legal; embedded NUL and malformed UTF-16 are not.
        if (!arg.empty() && !Text(arg)) throw Error("LINEAGE_INVALID", "Invalid argument");
        command += L" " + Quote(arg);
        if (command.size() >= 32767) throw Error("LINEAGE_INVALID", "Command line too long");
      }
      if (command.size() >= 32767) throw Error("LINEAGE_INVALID", "Command line too long");
      unsigned char random[32];
      if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw Error("LINEAGE_TRACKING_LOST", "Cannot generate scope identity");
      static const wchar_t hex[] = L"0123456789abcdef";
      for (unsigned char byte : random) {
        scopeId_.push_back(hex[byte >> 4]); scopeId_.push_back(hex[byte & 15]);
      }
      job_.Reset(CreateJobObjectW(nullptr, nullptr));
      if (!job_.Get()) throw Error("LINEAGE_TRACKING_LOST", "Cannot create job", GetLastError());
      effects_.jobCreated = true;
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
      // In particular: no BREAKAWAY_OK, SILENT_BREAKAWAY_OK or KILL_ON_JOB_CLOSE.
      if (!SetInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation,
                                   &limits, sizeof(limits)))
        throw Error("LINEAGE_TRACKING_LOST", "Cannot configure non-breakaway job", GetLastError());
      CheckLimits();
      AttributeList attributes;
      HANDLE job = job_.Get();
      if (!UpdateProcThreadAttribute(attributes.Get(), 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                                     &job, sizeof(job), nullptr, nullptr))
        throw Error("LINEAGE_TRACKING_LOST", "Cannot set creation-time job list", GetLastError());
      STARTUPINFOEXW startup{};
      startup.StartupInfo.cb = sizeof(startup);
      startup.lpAttributeList = attributes.Get();
      InheritedOutput output;
      output.Attach(attributes.Get(), startup);
      PROCESS_INFORMATION process{};
      std::vector<wchar_t> mutableCommand(command.begin(), command.end());
      mutableCommand.push_back(0);
      if (!CreateProcessW(executable_.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
                          EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                          nullptr, nullptr, &startup.StartupInfo, &process))
        throw Error("LINEAGE_TRACKING_LOST", "Contained CreateProcess failed; no fallback", GetLastError());
      root_.Reset(process.hProcess);
      Handle thread(process.hThread);
      effects_.rootCreated = true;
      rootPid_ = process.dwProcessId;
      try {
        BOOL member = FALSE;
        if (!rootPid_ || GetProcessId(root_.Get()) != rootPid_ ||
            !IsProcessInJob(root_.Get(), job_.Get(), &member) || !member)
          throw Error("LINEAGE_TRACKING_LOST", "Suspended root is not in exact job", GetLastError());
        rootStartTime_ = CreationTime(root_.Get());
        owner_ = TokenOwner(root_.Get());
        if (owner_ != binding_.roleSid)
          throw Error("LINEAGE_INVALID", "Root token owner differs from supplied role SID");
        std::vector<wchar_t> imageName(32768);
        DWORD length = static_cast<DWORD>(imageName.size());
        if (!QueryFullProcessImageNameW(root_.Get(), 0, imageName.data(), &length))
          throw Error("LINEAGE_TRACKING_LOST", "Cannot confirm suspended root image", GetLastError());
        Handle actual(CreateFileW(std::wstring(imageName.data(), length).c_str(), GENERIC_READ,
                                  FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        BY_HANDLE_FILE_INFORMATION actualInfo{};
        if (actual.Get() == INVALID_HANDLE_VALUE ||
            !GetFileInformationByHandle(actual.Get(), &actualInfo) ||
            imageInfo.dwVolumeSerialNumber != actualInfo.dwVolumeSerialNumber ||
            imageInfo.nFileIndexHigh != actualInfo.nFileIndexHigh ||
            imageInfo.nFileIndexLow != actualInfo.nFileIndexLow ||
            FinalPath(actual.Get()) != executable_)
          throw Error("LINEAGE_TRACKING_LOST", "Suspended root image identity mismatch", GetLastError());
        CheckLimits();
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = Accounting();
        if (accounting.ActiveProcesses != 1 || accounting.TotalProcesses != 1 ||
            WaitForSingleObject(root_.Get(), 0) != WAIT_TIMEOUT)
          throw Error("LINEAGE_TRACKING_LOST", "Unexpected pre-resume job/root state");
        // A new suspended primary thread has exactly one suspend count. No user code ran yet.
        DWORD previous = ResumeThread(thread.Get());
        if (previous != 1) {
          // A successful but unexpected ResumeThread is an ambiguous execution effect.
          if (previous != DWORD(-1)) effects_.rootResumed = true;
          throw Error("LINEAGE_TRACKING_LOST", "Cannot establish exact primary-thread resume", GetLastError(), {}, previous != DWORD(-1));
        }
        effects_.rootResumed = true;
        started_ = true;
        Seal();
      } catch (Error& error) {
        // Only the owned, never-resumed suspended process may be cleaned up here.
        if (!effects_.rootResumed) {
          ++effects_.cleanupTerminationCalls;
          BOOL terminated = TerminateProcess(root_.Get(), ERROR_PROCESS_ABORTED);
          DWORD waited = terminated ? WaitForSingleObject(root_.Get(), 5000) : WAIT_FAILED;
          if (!terminated || waited != WAIT_OBJECT_0) error.ambiguous = true;
        } else {
          error.ambiguous = true;
        }
        throw;
      } catch (...) {
        // Allocation failures after creation must not leave a hidden suspended root.
        bool ambiguous = true;
        if (!effects_.rootResumed) {
          ++effects_.cleanupTerminationCalls;
          ambiguous = !TerminateProcess(root_.Get(), ERROR_PROCESS_ABORTED) ||
              WaitForSingleObject(root_.Get(), 5000) != WAIT_OBJECT_0;
        }
        throw Error("LINEAGE_TRACKING_LOST", "Native failure after root creation", 0, effects_, ambiguous);
      }
    } catch (Error& error) {
      error.effects = effects_;
      throw;
    }
  }

  void Seal() {
    if (released_ || !started_ || !effects_.rootResumed)
      throw Error("LINEAGE_STALE", "Cannot seal an unstarted scope", 0, effects_);
    sealed_ = true;
  }

  Receipt Observe(const WindowsLineageBinding& binding, const std::wstring& operationId) {
    Authenticate(binding, operationId);
    try {
      CheckLimits();
      if (GetProcessId(root_.Get()) != rootPid_ || CreationTime(root_.Get()) != rootStartTime_)
        throw Error("LINEAGE_TRACKING_LOST", "Retained root incarnation changed");
      DWORD waited = WaitForSingleObject(root_.Get(), 0);
      if (waited != WAIT_TIMEOUT && waited != WAIT_OBJECT_0)
        throw Error("LINEAGE_TRACKING_LOST", "Cannot wait retained root", GetLastError());
      auto accounting = Accounting();
      bool closed = sealed_ && started_ && accounting.ActiveProcesses == 0 && waited == WAIT_OBJECT_0;
      // Root signalling and job accounting are separate reads, not an atomic snapshot.
      // A transition between them can only delay closure, never establish it early.
      if (closureObserved_ && !closed)
        throw Error("LINEAGE_TRACKING_LOST", "Inconsistent sealed kernel closure");
      closureObserved_ = closureObserved_ || closed;
      DetectEscapes();
      Receipt r;
      r.binding = binding_; r.scopeId = scopeId_; r.operationId = operationId;
      r.rootPid = rootPid_; r.rootStartTime = rootStartTime_;
      r.rootExecutable = executable_; r.rootOwner = owner_;
      r.activeProcesses = accounting.ActiveProcesses; r.totalProcesses = accounting.TotalProcesses;
      // Fail closed: without an enforced creation-authority boundary, complete
      // lineage coverage is unprovable and must never be claimed (test06).
      r.coverageComplete = false; r.sealed = sealed_; r.closed = closed;
      r.escapeDetected = escapeDetected_;
      r.rootExited = waited == WAIT_OBJECT_0;
      if (r.rootExited && !GetExitCodeProcess(root_.Get(), &r.rootExitCode))
        throw Error("LINEAGE_TRACKING_LOST", "Cannot query retained root exit code", GetLastError());
      r.forced = effects_.forced; r.terminationCalls = effects_.terminationCalls;
      return r;
    } catch (Error& error) {
      trackingLost_ = true;
      error.effects = effects_;
      error.ambiguous = true;
      throw;
    }
  }

  // Bounded, nonauthoritative diagnostics for the owned fixture. Members may
  // exit between reads. This list is never used to prove complete coverage,
  // decide closure, select termination targets, or substitute for kernel zero.
  std::vector<LiveMember> LiveMembers(const WindowsLineageBinding& binding,
                                     const std::wstring& operationId) const {
    Authenticate(binding, operationId);
    CheckLimits();
    constexpr DWORD limit = 4096;
    const DWORD capacity = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) +
        limit * sizeof(ULONG_PTR);
    std::vector<unsigned char> bytes(capacity);
    auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(bytes.data());
    if (!QueryInformationJobObject(job_.Get(), JobObjectBasicProcessIdList,
                                   list, capacity, nullptr) ||
        list->NumberOfProcessIdsInList > limit ||
        list->NumberOfAssignedProcesses > limit)
      throw Error("LINEAGE_TRACKING_LOST", "Owned-member diagnostic unavailable or overflowing", GetLastError());
    std::vector<LiveMember> result;
    for (DWORD index = 0; index < list->NumberOfProcessIdsInList; ++index) {
      ULONG_PTR id = list->ProcessIdList[index];
      if (id == 0 || id > MAXDWORD)
        throw Error("LINEAGE_TRACKING_LOST", "Invalid diagnostic member PID");
      Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                  FALSE, static_cast<DWORD>(id)));
      BOOL member = FALSE;
      if (!process.Get() || !IsProcessInJob(process.Get(), job_.Get(), &member) ||
          !member || WaitForSingleObject(process.Get(), 0) != WAIT_TIMEOUT)
        continue;  // A raced exit is not absence/closure evidence.
      std::vector<wchar_t> image(32768);
      DWORD length = static_cast<DWORD>(image.size());
      if (!QueryFullProcessImageNameW(process.Get(), 0, image.data(), &length))
        continue;
      result.push_back({static_cast<DWORD>(id), CreationTime(process.Get()),
                        std::wstring(image.data(), length)});
    }
    return result;
  }

  Receipt Terminate(const WindowsLineageBinding& binding, const std::wstring& operationId, DWORD timeoutMs) {
    Authenticate(binding, operationId);
    if (!timeoutMs || timeoutMs > 60000)
      throw Error("LINEAGE_INVALID", "Timeout must be 1..60000 milliseconds", 0, effects_);
    Receipt before = Observe(binding, operationId);
    if (before.closed) return before;
    if (effects_.terminationCalls == std::numeric_limits<uint32_t>::max())
      throw Error("LINEAGE_TRACKING_LOST", "Termination counter overflow", 0, effects_);
    ++effects_.terminationCalls;
    if (!TerminateJobObject(job_.Get(), ERROR_PROCESS_ABORTED))
      throw Error("LINEAGE_TRACKING_LOST", "Scoped TerminateJobObject failed", GetLastError(), effects_, true);
    effects_.forced = true;
    ULONGLONG began = GetTickCount64();
    for (;;) {
      Receipt receipt = Observe(binding, operationId);
      if (receipt.closed) return receipt;
      ULONGLONG elapsed = GetTickCount64() - began;
      if (elapsed >= timeoutMs)
        throw Error("LINEAGE_SURVIVOR", "Scoped termination did not reach kernel zero", 0, effects_, true);
      Sleep(static_cast<DWORD>(std::min<ULONGLONG>(10, timeoutMs - elapsed)));
    }
  }

  // Conservative tripwire, never closure evidence: a live process whose
  // designated parent is this controller but which is outside the retained
  // job escaped ordinary inheritance. The controller must route all of its
  // own child creation through scopes for this check to be meaningful.
  void DetectEscapes() {
    if (escapeDetected_ || !started_ || released_) return;
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.Get() || snapshot.Get() == INVALID_HANDLE_VALUE)
      throw Error("LINEAGE_TRACKING_LOST", "Escape tripwire snapshot unavailable", GetLastError());
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    const DWORD controller = GetCurrentProcessId();
    for (BOOL ok = Process32FirstW(snapshot.Get(), &entry); ok; ok = Process32NextW(snapshot.Get(), &entry)) {
      if (entry.th32ParentProcessID != controller) continue;
      const DWORD pid = entry.th32ProcessID;
      if (!pid || pid == rootPid_) continue;
      Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
      // A raced exit or inaccessible process is not evidence of absence.
      if (!process.Get() || WaitForSingleObject(process.Get(), 0) != WAIT_TIMEOUT) continue;
      // Children that predate the retained root are not this scope's lineage.
      if (CreationTime(process.Get()) < rootStartTime_) continue;
      BOOL member = FALSE;
      if (!IsProcessInJob(process.Get(), job_.Get(), &member))
        throw Error("LINEAGE_TRACKING_LOST", "Escape tripwire membership check failed", GetLastError());
      if (!member) escapeDetected_ = true;
    }
  }

 private:
  class AttributeList {
   public:
    AttributeList() {
      SIZE_T length = 0;
      if (InitializeProcThreadAttributeList(nullptr, 2, 0, &length) ||
          GetLastError() != ERROR_INSUFFICIENT_BUFFER || !length)
        throw Error("LINEAGE_TRACKING_LOST", "Cannot size process attributes", GetLastError());
      storage_.resize(length);
      list_ = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
      if (!InitializeProcThreadAttributeList(list_, 2, 0, &length)) {
        list_ = nullptr;
        throw Error("LINEAGE_TRACKING_LOST", "Cannot initialize process attributes", GetLastError());
      }
    }
    ~AttributeList() { if (list_) DeleteProcThreadAttributeList(list_); }
    LPPROC_THREAD_ATTRIBUTE_LIST Get() const { return list_; }
   private:
    std::vector<unsigned char> storage_;
    LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
  };

  void Authenticate(const WindowsLineageBinding& binding, const std::wstring& operationId) const {
    binding.Validate();
    if (!(binding == binding_) || !Text(operationId))
      throw Error("LINEAGE_INVALID", "Exact binding and nonempty operation ID required", 0, effects_);
    if (released_ || !job_.Get() || !root_.Get() || !started_)
      throw Error("LINEAGE_STALE", "Released or unstarted lineage handle", 0, effects_);
    if (trackingLost_)
      throw Error("LINEAGE_TRACKING_LOST", "Scope tracking was irreversibly lost", 0, effects_, true);
  }
  void CheckLimits() const {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    DWORD returned = 0;
    if (!QueryInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation,
                                  &limits, sizeof(limits), &returned) || returned != sizeof(limits) ||
        limits.BasicLimitInformation.LimitFlags != 0)
      throw Error("LINEAGE_TRACKING_LOST", "Cannot prove unchanged non-breakaway/no-kill limits", GetLastError());
  }
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION Accounting() {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION value{};
    DWORD returned = 0;
    if (!QueryInformationJobObject(job_.Get(), JobObjectBasicAccountingInformation,
                                  &value, sizeof(value), &returned) || returned != sizeof(value) ||
        value.TotalProcesses == 0 || value.TotalProcesses == MAXDWORD ||
        value.TotalProcesses < lastTotal_ || value.ActiveProcesses > value.TotalProcesses ||
        value.TotalTerminatedProcesses > value.TotalProcesses)
      throw Error("LINEAGE_TRACKING_LOST", "Kernel accounting unavailable, inconsistent or overflowing", GetLastError());
    lastTotal_ = value.TotalProcesses;
    return value;
  }

  WindowsLineageBinding binding_;
  Handle job_, root_, image_;
  Effects effects_;
  std::wstring scopeId_, executable_, owner_;
  DWORD rootPid_ = 0, lastTotal_ = 0;
  uint64_t rootStartTime_ = 0;
  bool attempted_ = false, started_ = false, sealed_ = false, released_ = false;
  bool trackingLost_ = false, closureObserved_ = false, escapeDetected_ = false;
};

}  // namespace windows_lineage
