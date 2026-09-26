// Read-only Shawl 1.9.0 two-family startup log observer (native ABI 5).
//
// This fragment is textually included by addon.cc (single translation unit)
// after the self-observation helpers it reuses.  It never writes, creates,
// renames, or re-ACLs anything: it enumerates the launch log directory through
// a no-follow directory handle, opens the family files relative to it with
// full sharing (so Shawl can keep appending, rotating, and cleaning up), and
// proves byte continuity by file identity plus a SHA-256 of every observed
// prefix.
//
// The driver passes `--log-rotate bytes=1048576`: flexi_logger rotates only
// after a write crosses the limit, so the half-size rotation leaves headroom
// under the 2 MiB per-file cursor bound for the record that crosses it.
//
// Shawl 1.9.0 (flexi_logger 0.29.3, Naming::Timestamps, append, KeepLogFiles)
// names each family `<base>_rCURRENT.log` for the live file and
// `<base>_rYYYY-MM-DD_HH-MM-SS[.restart-NNNN].log` for rotated files.  A
// rotation renames the live file (identity preserved) and creates a new live
// file; cleanup deletes the oldest rotated files.  Anything the observer cannot
// prove to be exactly that history is refused; continuity is only ever
// "complete".

const napi_type_tag kWin32LogObserverTypeTag = {
  0x5b1f0c7e9a4d4c21ULL, 0x8e3a6f2d17c94b05ULL,
};

constexpr uint64_t kLogObserverFileBytes = 2ULL * 1024 * 1024;
constexpr uint64_t kLogObserverLogicalBytes = 16ULL * 1024 * 1024;
constexpr uint64_t kLogObserverCursorBytes = 16ULL * 1024 * 1024;
constexpr uint64_t kLogObserverPartialLineBytes = 16384;
constexpr size_t kLogObserverFilesPerFamily = 3;
constexpr uint32_t kLogObserverPageBytes = 1024 * 1024;
constexpr uint64_t kLogObserverObserverBytes = 16ULL * 1024 * 1024;
constexpr size_t kLogObserverDirectoryEntries = 10000;
constexpr size_t kLogObserverFamilyEntries = 8;
constexpr size_t kLogObserverTreeProcesses = 256;
constexpr int kLogObserverAttempts = 4;

struct LogObserverFile {
  std::string identity;
  uint64_t logical_start = 0;
  uint64_t observed = 0;
  std::string prefix_sha256;
  // Private: whether the file carried a rotated (frozen) name, and its length,
  // when this observer last saw it.  Not part of the public cursor.
  bool rotated = false;
  uint64_t seen_length = 0;
};

struct LogObserverFamily {
  std::string family;
  std::string base;
  std::string directory_identity;
  std::vector<LogObserverFile> files;
  uint64_t next = 0;
  uint64_t partial = 0;
};

struct Win32LogObserver {
  bool closed = false;
  std::string service_key;
  std::string boot_fingerprint;
  std::string config_fingerprint;
  std::string log_directory;
  std::string supervisor_path;
  std::string runtime_path;
  LogObserverFamily families[2];
  std::string cursor_fingerprint;
  // Child epoch pinned at open; empty when the service had no child yet.
  std::string child_epoch;
  uint64_t bytes_read = 0;
#if defined(_WIN32) && defined(_WIN64)
  SC_HANDLE manager = nullptr;
  SC_HANDLE service = nullptr;
#endif
};

void CloseWin32LogObserver(Win32LogObserver* observer) {
  if (!observer) return;
#if defined(_WIN32) && defined(_WIN64)
  if (observer->service) CloseServiceHandle(observer->service);
  if (observer->manager) CloseServiceHandle(observer->manager);
  observer->service = nullptr;
  observer->manager = nullptr;
#endif
  observer->closed = true;
}

void FinalizeWin32LogObserver(napi_env, void* data, void*) {
  auto* observer = static_cast<Win32LogObserver*>(data);
  CloseWin32LogObserver(observer);
  delete observer;
}

bool Win32LogObserverArg(napi_env env, napi_value value,
                         Win32LogObserver** result) {
  napi_valuetype type;
  bool tagged = false;
  void* raw = nullptr;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_object ||
      napi_check_object_type_tag(env, value, &kWin32LogObserverTypeTag,
                                 &tagged) != napi_ok ||
      !tagged || napi_unwrap(env, value, &raw) != napi_ok || !raw) {
    return false;
  }
  *result = static_cast<Win32LogObserver*>(raw);
  return true;
}

// close_service_handle accepts observer handles.  Returns true when `value`
// was an observer (now closed, idempotently).
bool CloseWin32LogObserverValue(napi_env env, napi_value value) {
  Win32LogObserver* observer = nullptr;
  if (!Win32LogObserverArg(env, value, &observer)) return false;
  CloseWin32LogObserver(observer);
  return true;
}

bool LogObserverHash(const std::string& text, std::string* fingerprint) {
  Sha256 hash;
  if (!hash.Ready() || !hash.Update(text)) return false;
  *fingerprint = hash.Finish();
  return ValidServiceFingerprint(*fingerprint);
}

bool LogObserverAbsence(const LogObserverFamily& family,
                        std::string* fingerprint) {
  return LogObserverHash(
      "{\"baseName\":\"" + family.base +
      "\",\"directoryIdentityFingerprint\":\"" + family.directory_identity +
      "\",\"family\":\"" + family.family +
      "\",\"kind\":\"gjc-remote/win32-log-family-absence/v1\"}",
      fingerprint);
}

// Canonical JSON of a FamilyCursor (keys sorted, matching shared canonicalJson).
bool LogObserverFamilyCanonical(const LogObserverFamily& family,
                                std::string* text) {
  std::string absence = "null";
  if (family.files.empty()) {
    std::string fingerprint;
    if (!LogObserverAbsence(family, &fingerprint)) return false;
    absence = "\"" + fingerprint + "\"";
  }
  std::string files;
  for (const auto& file : family.files) {
    if (!files.empty()) files += ",";
    files += "{\"identityFingerprint\":\"" + file.identity +
        "\",\"logicalStartOffset\":" + std::to_string(file.logical_start) +
        ",\"observedLength\":" + std::to_string(file.observed) +
        ",\"prefixSha256\":\"" + file.prefix_sha256 + "\"}";
  }
  *text = "{\"absenceFingerprint\":" + absence +
      ",\"baseName\":\"" + family.base +
      "\",\"directoryIdentityFingerprint\":\"" + family.directory_identity +
      "\",\"family\":\"" + family.family +
      "\",\"files\":[" + files +
      "],\"nextLogicalOffset\":" + std::to_string(family.next) +
      ",\"partialLineBytes\":" + std::to_string(family.partial) + "}";
  return true;
}

// cursorFingerprint = sha256(canonicalJson(cursor set without cursorFingerprint)).
bool LogObserverCursorFingerprint(const Win32LogObserver& observer,
                                  const LogObserverFamily* families,
                                  std::string* fingerprint) {
  std::string wrapper, child;
  if (!LogObserverFamilyCanonical(families[0], &wrapper) ||
      !LogObserverFamilyCanonical(families[1], &child)) return false;
  return LogObserverHash(
      "{\"bootFingerprint\":\"" + observer.boot_fingerprint +
      "\",\"configFingerprint\":\"" + observer.config_fingerprint +
      "\",\"families\":[" + wrapper + "," + child +
      "],\"schemaVersion\":1,\"serviceKey\":\"" + observer.service_key +
      "\"}",
      fingerprint);
}

void LogObserverSetNull(napi_env env, napi_value object, const char* name) {
  napi_value value;
  napi_get_null(env, &value);
  napi_set_named_property(env, object, name, value);
}

napi_value LogObserverCursorValue(napi_env env,
                                  const Win32LogObserver& observer,
                                  const LogObserverFamily* families,
                                  const std::string& fingerprint) {
  napi_value set, list;
  napi_create_object(env, &set);
  ServiceSetUint32(env, set, "schemaVersion", 1);
  ServiceSetString(env, set, "bootFingerprint", observer.boot_fingerprint);
  ServiceSetString(env, set, "serviceKey", observer.service_key);
  ServiceSetString(env, set, "configFingerprint", observer.config_fingerprint);
  napi_create_array_with_length(env, 2, &list);
  for (uint32_t index = 0; index < 2; ++index) {
    const LogObserverFamily& family = families[index];
    napi_value object, files;
    napi_create_object(env, &object);
    ServiceSetString(env, object, "family", family.family);
    ServiceSetString(env, object, "baseName", family.base);
    ServiceSetString(env, object, "directoryIdentityFingerprint",
                     family.directory_identity);
    napi_create_array_with_length(env, family.files.size(), &files);
    for (size_t position = 0; position < family.files.size(); ++position) {
      const LogObserverFile& file = family.files[position];
      napi_value entry;
      napi_create_object(env, &entry);
      ServiceSetString(env, entry, "identityFingerprint", file.identity);
      ServiceSetDouble(env, entry, "logicalStartOffset",
                       static_cast<double>(file.logical_start));
      ServiceSetDouble(env, entry, "observedLength",
                       static_cast<double>(file.observed));
      ServiceSetString(env, entry, "prefixSha256", file.prefix_sha256);
      napi_set_element(env, files, static_cast<uint32_t>(position), entry);
    }
    napi_set_named_property(env, object, "files", files);
    ServiceSetDouble(env, object, "nextLogicalOffset",
                     static_cast<double>(family.next));
    ServiceSetDouble(env, object, "partialLineBytes",
                     static_cast<double>(family.partial));
    std::string absence;
    if (family.files.empty() && LogObserverAbsence(family, &absence)) {
      ServiceSetString(env, object, "absenceFingerprint", absence);
    } else {
      LogObserverSetNull(env, object, "absenceFingerprint");
    }
    napi_set_element(env, list, index, object);
  }
  napi_set_named_property(env, set, "families", list);
  ServiceSetString(env, set, "cursorFingerprint", fingerprint);
  return set;
}

// Validates cross-family cursor limits and the public family invariants.
bool LogObserverCursorWithinLimits(const LogObserverFamily* families) {
  uint64_t total = 0;
  for (int index = 0; index < 2; ++index) {
    const LogObserverFamily& family = families[index];
    if (family.files.size() > kLogObserverFilesPerFamily ||
        family.next > kLogObserverLogicalBytes ||
        family.partial > kLogObserverPartialLineBytes) return false;
    if (family.files.empty()) {
      if (family.next != 0 || family.partial != 0) return false;
      continue;
    }
    uint64_t end = family.files.front().logical_start;
    for (const auto& file : family.files) {
      if (file.logical_start != end || file.observed > kLogObserverFileBytes)
        return false;
      end = file.logical_start + file.observed;
      total += file.observed;
      if (end > kLogObserverLogicalBytes || total > kLogObserverCursorBytes)
        return false;
    }
    if (family.next != end || family.partial > family.next) return false;
  }
  return true;
}

#if defined(_WIN32) && defined(_WIN64)

enum class LogObserverStatus { Ok, Retry, Stale, Limit, Denied, Failed };

struct LogObserverOutcome {
  LogObserverStatus status = LogObserverStatus::Ok;
  const char* reason = "";
};

LogObserverOutcome LogObserverFail(LogObserverStatus status,
                                   const char* reason) {
  LogObserverOutcome outcome;
  outcome.status = status;
  outcome.reason = reason;
  return outcome;
}

LogObserverStatus LogObserverOpenError(DWORD error) {
  if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
      error == ERROR_DELETE_PENDING || error == ERROR_SHARING_VIOLATION) {
    return LogObserverStatus::Retry;
  }
  if (error == ERROR_ACCESS_DENIED) return LogObserverStatus::Denied;
  return LogObserverStatus::Failed;
}

bool LogObserverIdentity(HANDLE handle, const char* kind,
                         std::string* fingerprint) {
  FILE_ID_INFO info{};
  if (!GetFileInformationByHandleEx(handle, FileIdInfo, &info, sizeof(info)))
    return false;
  char serial[17];
  std::snprintf(serial, sizeof(serial), "%016llx",
                static_cast<unsigned long long>(info.VolumeSerialNumber));
  return LogObserverHash(
      std::string("{\"fileId\":\"") + WindowsFileIdText(info.FileId) +
      "\",\"kind\":\"" + kind + "\",\"volumeSerial\":\"" + serial + "\"}",
      fingerprint);
}

// 0 = not a family file, 1 = rotated, 2 = live (rCURRENT).
int LogObserverNameKind(const std::string& name, const std::string& base) {
  const std::string prefix = base + "_r";
  const std::string suffix = ".log";
  if (name.size() <= prefix.size() + suffix.size() ||
      name.compare(0, prefix.size(), prefix) != 0 ||
      name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) {
    return 0;
  }
  const std::string infix = name.substr(
      prefix.size(), name.size() - prefix.size() - suffix.size());
  if (infix == "CURRENT") return 2;
  static const char kPattern[] = "dddd-dd-dd_dd-dd-dd";
  const size_t stamp = sizeof(kPattern) - 1;
  static const std::string kRestart = ".restart-";
  if (infix.size() != stamp && infix.size() != stamp + kRestart.size() + 4)
    return 0;
  auto digit = [](char value) { return value >= '0' && value <= '9'; };
  for (size_t index = 0; index < stamp; ++index) {
    if (kPattern[index] == 'd' ? !digit(infix[index])
                               : infix[index] != kPattern[index]) return 0;
  }
  if (infix.size() > stamp) {
    if (infix.compare(stamp, kRestart.size(), kRestart) != 0) return 0;
    for (size_t index = stamp + kRestart.size(); index < infix.size(); ++index)
      if (!digit(infix[index])) return 0;
  }
  return 1;
}

struct LogObserverEntry {
  std::string name;
  std::string identity;
  uint64_t length = 0;
  bool rotated = false;
};

LogObserverOutcome LogObserverListDirectory(HANDLE directory,
                                            std::vector<std::string>* names) {
  names->clear();
  alignas(8) static thread_local uint8_t buffer[64 * 1024];
  bool restart = true;
  for (;;) {
    if (!GetFileInformationByHandleEx(
            directory,
            restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo,
            buffer, static_cast<DWORD>(sizeof(buffer)))) {
      const DWORD error = GetLastError();
      if (error == ERROR_NO_MORE_FILES) return LogObserverOutcome{};
      return LogObserverFail(error == ERROR_ACCESS_DENIED
          ? LogObserverStatus::Denied : LogObserverStatus::Failed, "io");
    }
    restart = false;
    size_t offset = 0;
    for (;;) {
      if (offset + offsetof(FILE_ID_BOTH_DIR_INFO, FileName) > sizeof(buffer))
        return LogObserverFail(LogObserverStatus::Failed, "io");
      const auto* record =
          reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(buffer + offset);
      if (record->FileNameLength % sizeof(wchar_t) != 0 ||
          record->FileNameLength > sizeof(buffer) - offset -
              offsetof(FILE_ID_BOTH_DIR_INFO, FileName)) {
        return LogObserverFail(LogObserverStatus::Failed, "io");
      }
      const std::wstring wide(record->FileName,
                              record->FileNameLength / sizeof(wchar_t));
      if ((record->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
          !wide.empty()) {
        if (names->size() >= kLogObserverDirectoryEntries)
          return LogObserverFail(LogObserverStatus::Limit, "output-limit");
        names->push_back(Utf8(wide));
      }
      if (record->NextEntryOffset == 0) break;
      offset += record->NextEntryOffset;
    }
  }
}

// Enumerates one family: identity and length of every family file, ordered as
// rotated files by name (timestamp, then restart index) and the live file last.
LogObserverOutcome LogObserverScanFamily(
    HANDLE directory, const std::vector<std::string>& names,
    const std::string& base, std::vector<LogObserverEntry>* entries) {
  entries->clear();
  std::vector<LogObserverEntry> rotated;
  std::vector<LogObserverEntry> live;
  for (const auto& name : names) {
    const int kind = LogObserverNameKind(name, base);
    if (kind == 0) continue;
    if (rotated.size() + live.size() >= kLogObserverFamilyEntries)
      return LogObserverFail(LogObserverStatus::Limit, "output-limit");
    HANDLE file = OpenWindowsRelative(directory, Wide(name),
        FILE_READ_ATTRIBUTES, kFileOpen, VerifiedObjectType::File);
    if (file == INVALID_HANDLE_VALUE) {
      const DWORD error = GetLastError();
      return LogObserverFail(LogObserverOpenError(error),
          error == ERROR_ACCESS_DENIED ? "access-denied" : "log-continuity");
    }
    LogObserverEntry entry;
    entry.name = name;
    entry.rotated = kind == 1;
    LARGE_INTEGER length{};
    const bool ok = LogObserverIdentity(
        file, "gjc-remote/win32-log-file-identity/v1", &entry.identity) &&
        GetFileSizeEx(file, &length) && length.QuadPart >= 0;
    CloseHandle(file);
    if (!ok) return LogObserverFail(LogObserverStatus::Failed, "io");
    entry.length = static_cast<uint64_t>(length.QuadPart);
    (entry.rotated ? rotated : live).push_back(entry);
  }
  if (live.size() > 1) return LogObserverFail(LogObserverStatus::Stale,
                                              "log-continuity");
  std::sort(rotated.begin(), rotated.end(),
            [](const LogObserverEntry& left, const LogObserverEntry& right) {
              return left.name < right.name;
            });
  *entries = rotated;
  for (const auto& entry : live) entries->push_back(entry);
  for (size_t left = 0; left < entries->size(); ++left)
    for (size_t right = left + 1; right < entries->size(); ++right)
      if ((*entries)[left].identity == (*entries)[right].identity)
        return LogObserverFail(LogObserverStatus::Stale, "log-continuity");
  return LogObserverOutcome{};
}

struct LogObserverFileRead {
  std::string verify_sha256;  // sha256 of bytes [0, verify_length)
  std::string end_sha256;     // sha256 of bytes [0, end)
  std::vector<uint8_t> copied;  // bytes [copy_from, end)
  int64_t last_newline = -1;    // offset of the last '\n' in [copy_from, end)
};

// Opens `name` relative to the directory, proves it is still `identity`, and
// reads [0, end) once, hashing both prefixes and copying the new suffix.
LogObserverOutcome LogObserverReadFile(
    HANDLE directory, const std::string& name, const std::string& identity,
    uint64_t verify_length, uint64_t end, uint64_t copy_from,
    LogObserverFileRead* read) {
  HANDLE file = OpenWindowsRelative(directory, Wide(name),
      FILE_READ_DATA | FILE_READ_ATTRIBUTES, kFileOpen,
      VerifiedObjectType::File);
  if (file == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    return LogObserverFail(LogObserverOpenError(error),
        error == ERROR_ACCESS_DENIED ? "access-denied" : "log-continuity");
  }
  std::string opened;
  LARGE_INTEGER length{};
  if (!LogObserverIdentity(
          file, "gjc-remote/win32-log-file-identity/v1", &opened) ||
      !GetFileSizeEx(file, &length) || length.QuadPart < 0) {
    CloseHandle(file);
    return LogObserverFail(LogObserverStatus::Failed, "io");
  }
  if (opened != identity) {
    CloseHandle(file);
    return LogObserverFail(LogObserverStatus::Retry, "log-continuity");
  }
  if (static_cast<uint64_t>(length.QuadPart) < end) {
    CloseHandle(file);
    return LogObserverFail(LogObserverStatus::Stale, "log-truncated");
  }
  Sha256 verify_hash, end_hash;
  if (!verify_hash.Ready() || !end_hash.Ready()) {
    CloseHandle(file);
    return LogObserverFail(LogObserverStatus::Failed, "io");
  }
  read->copied.clear();
  read->last_newline = -1;
  if (end > copy_from) read->copied.reserve(static_cast<size_t>(end - copy_from));
  std::vector<uint8_t> chunk(64 * 1024);
  uint64_t position = 0;
  bool ok = true;
  while (ok && position < end) {
    const DWORD want = static_cast<DWORD>(
        std::min<uint64_t>(chunk.size(), end - position));
    DWORD got = 0;
    if (!ReadFile(file, chunk.data(), want, &got, nullptr) || got == 0) {
      ok = false;
      break;
    }
    const uint8_t* bytes = chunk.data();
    if (position < verify_length) {
      const uint64_t take = std::min<uint64_t>(got, verify_length - position);
      ok = verify_hash.Update(bytes, static_cast<size_t>(take));
    }
    ok = ok && end_hash.Update(bytes, got);
    for (DWORD index = 0; ok && index < got; ++index) {
      const uint64_t at = position + index;
      if (at < copy_from) continue;
      read->copied.push_back(bytes[index]);
      if (bytes[index] == '\n') read->last_newline = static_cast<int64_t>(at);
    }
    position += got;
  }
  CloseHandle(file);
  if (!ok || position != end) {
    return LogObserverFail(LogObserverStatus::Stale, "log-truncated");
  }
  read->verify_sha256 = verify_hash.Finish();
  read->end_sha256 = end_hash.Finish();
  if (!ValidServiceFingerprint(read->verify_sha256) ||
      !ValidServiceFingerprint(read->end_sha256)) {
    return LogObserverFail(LogObserverStatus::Failed, "io");
  }
  return LogObserverOutcome{};
}

struct LogObserverChunk {
  std::string family;
  std::string identity;
  uint64_t logical_offset = 0;
  std::vector<uint8_t> bytes;
};

LogObserverOutcome LogObserverUpdatePartial(uint64_t* partial,
                                            const LogObserverFileRead& read,
                                            uint64_t copy_from, uint64_t end) {
  if (read.last_newline >= 0) {
    *partial = end - static_cast<uint64_t>(read.last_newline + 1);
  } else {
    *partial += end - copy_from;
  }
  if (*partial > kLogObserverPartialLineBytes)
    return LogObserverFail(LogObserverStatus::Limit, "output-limit");
  return LogObserverOutcome{};
}

// Initial capture: the cursor starts at the current end of every family file.
LogObserverOutcome LogObserverCaptureFamily(
    HANDLE directory, const std::vector<LogObserverEntry>& entries,
    LogObserverFamily* family) {
  if (entries.size() > kLogObserverFilesPerFamily)
    return LogObserverFail(LogObserverStatus::Limit, "output-limit");
  family->files.clear();
  uint64_t offset = 0;
  uint64_t partial = 0;
  for (const auto& entry : entries) {
    if (entry.length > kLogObserverFileBytes)
      return LogObserverFail(LogObserverStatus::Limit, "output-limit");
    LogObserverFileRead read;
    LogObserverOutcome outcome = LogObserverReadFile(
        directory, entry.name, entry.identity, 0, entry.length, 0, &read);
    if (outcome.status != LogObserverStatus::Ok) return outcome;
    outcome = LogObserverUpdatePartial(&partial, read, 0, entry.length);
    if (outcome.status != LogObserverStatus::Ok) return outcome;
    LogObserverFile file;
    file.identity = entry.identity;
    file.logical_start = offset;
    file.observed = entry.length;
    file.prefix_sha256 = read.end_sha256;
    file.rotated = entry.rotated;
    file.seen_length = entry.length;
    family->files.push_back(file);
    offset += entry.length;
    if (offset > kLogObserverLogicalBytes)
      return LogObserverFail(LogObserverStatus::Limit, "output-limit");
  }
  family->next = offset;
  family->partial = family->files.empty() ? 0 : partial;
  return LogObserverOutcome{};
}

// Resume: every cursor file must still exist with its identity, at least its
// observed length, and the exact observed prefix.  Nothing is re-read past it.
LogObserverOutcome LogObserverVerifyFamily(
    HANDLE directory, const std::vector<LogObserverEntry>& entries,
    LogObserverFamily* family) {
  size_t last_index = 0;
  for (size_t position = 0; position < family->files.size(); ++position) {
    LogObserverFile& file = family->files[position];
    size_t index = entries.size();
    for (size_t candidate = 0; candidate < entries.size(); ++candidate)
      if (entries[candidate].identity == file.identity) index = candidate;
    if (index == entries.size() || (position > 0 && index <= last_index))
      return LogObserverFail(LogObserverStatus::Stale, "log-continuity");
    last_index = index;
    const LogObserverEntry& entry = entries[index];
    if (entry.length < file.observed ||
        (position + 1 < family->files.size() && !entry.rotated))
      return LogObserverFail(LogObserverStatus::Stale, "log-continuity");
    LogObserverFileRead read;
    const LogObserverOutcome outcome = LogObserverReadFile(
        directory, entry.name, entry.identity, file.observed, file.observed,
        file.observed, &read);
    if (outcome.status != LogObserverStatus::Ok) return outcome;
    if (read.verify_sha256 != file.prefix_sha256)
      return LogObserverFail(LogObserverStatus::Stale, "log-prefix-changed");
    file.rotated = entry.rotated;
    file.seen_length = entry.length;
  }
  return LogObserverOutcome{};
}

// Advances one family by at most *budget bytes.  Works on a copy; the caller
// commits only when both families and the process epochs verified.
LogObserverOutcome LogObserverAdvanceFamily(
    HANDLE directory, const std::vector<LogObserverEntry>& entries,
    LogObserverFamily* family, uint64_t* budget,
    std::vector<LogObserverChunk>* chunks, bool* eof) {
  struct Kept { LogObserverFile file; size_t entry; };
  std::vector<Kept> kept;
  std::vector<bool> used(entries.size(), false);
  for (const auto& file : family->files) {
    size_t index = entries.size();
    for (size_t candidate = 0; candidate < entries.size(); ++candidate)
      if (entries[candidate].identity == file.identity) index = candidate;
    if (index == entries.size()) {
      // Only a fully consumed, already rotated head file may be cleaned up.
      if (kept.empty() && file.rotated && file.observed == file.seen_length)
        continue;
      return LogObserverFail(LogObserverStatus::Stale, "log-continuity");
    }
    const LogObserverEntry& entry = entries[index];
    if ((!kept.empty() && index <= kept.back().entry) ||
        (file.rotated && !entry.rotated) ||
        (file.rotated && entry.length != file.seen_length) ||
        entry.length < file.observed)
      return LogObserverFail(LogObserverStatus::Stale, "log-continuity");
    used[index] = true;
    kept.push_back(Kept{file, index});
  }
  for (size_t position = 0; position + 1 < kept.size(); ++position)
    if (!entries[kept[position].entry].rotated)
      return LogObserverFail(LogObserverStatus::Stale, "log-continuity");
  for (size_t index = 0; index < entries.size(); ++index) {
    if (used[index]) continue;
    // New files are strictly later history: after every kept file, and only
    // once the kept live file has itself been rotated.
    if (!kept.empty() &&
        (index <= kept.back().entry || !entries[kept.back().entry].rotated))
      return LogObserverFail(LogObserverStatus::Stale, "log-continuity");
  }

  std::vector<LogObserverFile> out;
  uint64_t partial = family->partial;
  bool complete = true;
  for (auto& item : kept) {
    LogObserverFile file = item.file;
    const LogObserverEntry& entry = entries[item.entry];
    const uint64_t take = std::min<uint64_t>(entry.length - file.observed,
                                             *budget);
    const uint64_t end = file.observed + take;
    if (end > kLogObserverFileBytes)
      return LogObserverFail(LogObserverStatus::Limit, "output-limit");
    LogObserverFileRead read;
    LogObserverOutcome outcome = LogObserverReadFile(
        directory, entry.name, entry.identity, file.observed, end,
        file.observed, &read);
    if (outcome.status != LogObserverStatus::Ok) return outcome;
    if (read.verify_sha256 != file.prefix_sha256)
      return LogObserverFail(LogObserverStatus::Stale, "log-prefix-changed");
    if (take > 0) {
      outcome = LogObserverUpdatePartial(&partial, read, file.observed, end);
      if (outcome.status != LogObserverStatus::Ok) return outcome;
      chunks->push_back(LogObserverChunk{family->family, file.identity,
          file.logical_start + file.observed, std::move(read.copied)});
      *budget -= take;
    }
    file.observed = end;
    file.prefix_sha256 = read.end_sha256;
    file.rotated = entry.rotated;
    file.seen_length = entry.length;
    if (end < entry.length) complete = false;
    out.push_back(file);
  }
  for (size_t index = 0; index < entries.size(); ++index) {
    if (used[index]) continue;
    // Cursor files must be logically contiguous: admit the next file only
    // after its predecessor is fully consumed and frozen.
    if (!out.empty() &&
        (!out.back().rotated || out.back().observed != out.back().seen_length)) {
      complete = false;
      break;
    }
    const LogObserverEntry& entry = entries[index];
    const uint64_t start = out.empty()
        ? family->next : out.back().logical_start + out.back().observed;
    const uint64_t take = std::min<uint64_t>(entry.length, *budget);
    if (take > kLogObserverFileBytes)
      return LogObserverFail(LogObserverStatus::Limit, "output-limit");
    LogObserverFileRead read;
    LogObserverOutcome outcome = LogObserverReadFile(
        directory, entry.name, entry.identity, 0, take, 0, &read);
    if (outcome.status != LogObserverStatus::Ok) return outcome;
    if (take > 0) {
      outcome = LogObserverUpdatePartial(&partial, read, 0, take);
      if (outcome.status != LogObserverStatus::Ok) return outcome;
      chunks->push_back(LogObserverChunk{family->family, entry.identity, start,
                                         std::move(read.copied)});
      *budget -= take;
    }
    LogObserverFile file;
    file.identity = entry.identity;
    file.logical_start = start;
    file.observed = take;
    file.prefix_sha256 = read.end_sha256;
    file.rotated = entry.rotated;
    file.seen_length = entry.length;
    if (take < entry.length) complete = false;
    out.push_back(file);
  }
  while (out.size() > kLogObserverFilesPerFamily && out.front().rotated &&
         out.front().observed == out.front().seen_length) {
    out.erase(out.begin());
  }
  if (out.size() > kLogObserverFilesPerFamily)
    return LogObserverFail(LogObserverStatus::Limit, "output-limit");
  if (out.empty() && family->next != 0)
    return LogObserverFail(LogObserverStatus::Stale, "log-continuity");
  family->next = out.empty()
      ? 0 : out.back().logical_start + out.back().observed;
  family->partial = out.empty() ? 0 : partial;
  family->files = std::move(out);
  if (family->next > kLogObserverLogicalBytes)
    return LogObserverFail(LogObserverStatus::Limit, "output-limit");
  *eof = complete;
  return LogObserverOutcome{};
}

HANDLE LogObserverOpenDirectory(const Win32LogObserver& observer,
                                std::string* identity) {
  HANDLE directory = OpenWindowsPathNoFollow(
      observer.log_directory,
      FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
      VerifiedObjectType::Directory);
  if (directory == INVALID_HANDLE_VALUE) return directory;
  if (!LogObserverIdentity(
          directory, "gjc-remote/win32-log-directory-identity/v1", identity)) {
    CloseHandle(directory);
    SetLastError(ERROR_CANT_ACCESS_FILE);
    return INVALID_HANDLE_VALUE;
  }
  return directory;
}

bool LogObserverSamePath(const std::string& left, const std::string& right) {
  const std::wstring a = Wide(left);
  const std::wstring b = Wide(right);
  return !a.empty() && !b.empty() &&
      CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(),
                           static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

// Same formula as observe_self_process_epoch, so the child epoch equals the
// processEpochFingerprint the application binds into its startup events.
bool LogObserverProcessEpoch(const std::string& boot_id,
                             const ServiceProcessFacts& facts,
                             std::string* fingerprint) {
  ServiceStoreIdentity identity;
  std::string executable_fingerprint;
  if (!ServiceSelfExecutableIdentity(facts.executable, &identity) ||
      !ServiceSelfWin32PhysicalSecurityIdentityFingerprint(
          identity, &executable_fingerprint)) return false;
  return LogObserverHash(
      "{\"bootId\":\"" + boot_id +
      "\",\"creationTime\":\"" + std::to_string(facts.start_time) +
      "\",\"executableIdentityFingerprint\":\"" + executable_fingerprint +
      "\",\"kind\":\"gjc-remote/windows-self-epoch/v1\",\"pid\":" +
      std::to_string(facts.pid) + "}",
      fingerprint);
}

struct LogObserverEpochs {
  bool present = false;
  std::string wrapper;
  std::string child;
  std::string tree;
};

// Wrapper = SCM service process (must be the launch supervisor); child = its
// unique direct runtime child.  No child yet => all epochs absent.
LogObserverOutcome LogObserverReadEpochs(const Win32LogObserver& observer,
                                         LogObserverEpochs* epochs) {
  *epochs = LogObserverEpochs{};
  SERVICE_STATUS_PROCESS status{};
  DWORD needed = 0;
  if (!QueryServiceStatusEx(observer.service, SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<LPBYTE>(&status),
                            sizeof(status), &needed)) {
    return LogObserverFail(GetLastError() == ERROR_ACCESS_DENIED
        ? LogObserverStatus::Denied : LogObserverStatus::Retry,
        "process-ambiguous");
  }
  if (status.dwProcessId == 0 || status.dwCurrentState == SERVICE_STOPPED)
    return LogObserverOutcome{};
  std::string boot_id;
  if (!ReadWindowsBootIdentity(&boot_id))
    return LogObserverFail(LogObserverStatus::Retry, "process-ambiguous");
  ServiceProcessFacts wrapper;
  const ProcessReadResult wrapper_read =
      ReadServiceProcessFacts(status.dwProcessId, &wrapper);
  if (wrapper_read != ProcessReadResult::Ok) {
    return LogObserverFail(LogObserverStatus::Retry, "process-ambiguous");
  }
  if (!LogObserverSamePath(wrapper.executable, observer.supervisor_path))
    return LogObserverFail(LogObserverStatus::Stale, "stale-epoch");

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    return LogObserverFail(LogObserverStatus::Retry, "process-ambiguous");
  std::vector<std::pair<uint32_t, uint32_t>> table;  // pid, parent
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      table.emplace_back(entry.th32ProcessID, entry.th32ParentProcessID);
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);

  std::vector<ServiceProcessFacts> tree{wrapper};
  std::vector<ServiceProcessFacts> runtime_children;
  for (size_t cursor = 0; cursor < tree.size(); ++cursor) {
    const ServiceProcessFacts parent = tree[cursor];
    for (const auto& row : table) {
      if (row.second != parent.pid || row.first == parent.pid ||
          row.first == 0) continue;
      ServiceProcessFacts child;
      const ProcessReadResult child_read =
          ReadServiceProcessFacts(row.first, &child);
      if (child_read == ProcessReadResult::Absent) continue;
      if (child_read != ProcessReadResult::Ok)
        return LogObserverFail(LogObserverStatus::Retry, "process-ambiguous");
      // A reused parent pid is not ancestry.
      if (child.parent_pid != parent.pid ||
          child.start_time < parent.start_time) continue;
      if (tree.size() >= kLogObserverTreeProcesses)
        return LogObserverFail(LogObserverStatus::Limit, "output-limit");
      tree.push_back(child);
      if (cursor == 0 &&
          LogObserverSamePath(child.executable, observer.runtime_path)) {
        runtime_children.push_back(child);
      }
    }
  }
  if (runtime_children.empty()) return LogObserverOutcome{};
  if (runtime_children.size() != 1)
    return LogObserverFail(LogObserverStatus::Stale, "stale-epoch");
  if (!LogObserverProcessEpoch(boot_id, wrapper, &epochs->wrapper) ||
      !LogObserverProcessEpoch(boot_id, runtime_children[0], &epochs->child))
    return LogObserverFail(LogObserverStatus::Retry, "process-ambiguous");
  std::sort(tree.begin(), tree.end(),
            [](const ServiceProcessFacts& left,
               const ServiceProcessFacts& right) {
              return left.pid < right.pid;
            });
  std::string processes;
  for (const auto& process : tree) {
    if (!processes.empty()) processes += ",";
    processes += "{\"creationTime\":\"" + std::to_string(process.start_time) +
        "\",\"parentPid\":" + std::to_string(process.parent_pid) +
        ",\"pid\":" + std::to_string(process.pid) + "}";
  }
  if (!LogObserverHash(
          "{\"childEpochFingerprint\":\"" + epochs->child +
          "\",\"kind\":\"gjc-remote/win32-log-observer-tree/v1\",\"processes\":[" +
          processes + "],\"wrapperEpochFingerprint\":\"" + epochs->wrapper +
          "\"}",
          &epochs->tree)) {
    return LogObserverFail(LogObserverStatus::Failed, "io");
  }
  epochs->present = true;
  return LogObserverOutcome{};
}

bool LogObserverSameEpochs(const LogObserverEpochs& left,
                           const LogObserverEpochs& right) {
  return left.present == right.present && left.wrapper == right.wrapper &&
      left.child == right.child;
}

bool LogObserverClock(std::string* boot_fingerprint, ULONGLONG* tick) {
  std::string before, after;
  if (!ReadWindowsBootIdentity(&before)) return false;
  *tick = GetTickCount64();
  return *tick <= 9007199254740991ULL &&
      ReadWindowsBootIdentity(&after) && before == after &&
      ServiceSelfWindowsBootFingerprint(before, boot_fingerprint);
}

napi_value LogObserverClockValue(napi_env env, const std::string& fingerprint,
                                 ULONGLONG tick) {
  napi_value clock;
  napi_create_object(env, &clock);
  ServiceSetUint32(env, clock, "schemaVersion", 1);
  ServiceSetString(env, clock, "bootFingerprint", fingerprint);
  ServiceSetDouble(env, clock, "tickMs", static_cast<double>(tick));
  ServiceSetUint32(env, clock, "writes", 0);
  return clock;
}

void LogObserverSetEpochs(napi_env env, napi_value object,
                          const LogObserverEpochs& epochs) {
  if (!epochs.present) {
    LogObserverSetNull(env, object, "wrapperEpochFingerprint");
    LogObserverSetNull(env, object, "childEpochFingerprint");
    LogObserverSetNull(env, object, "treeFingerprint");
    return;
  }
  ServiceSetString(env, object, "wrapperEpochFingerprint", epochs.wrapper);
  ServiceSetString(env, object, "childEpochFingerprint", epochs.child);
  ServiceSetString(env, object, "treeFingerprint", epochs.tree);
}

void LogObserverThrow(napi_env env, const char* operation,
                      const LogObserverOutcome& outcome) {
  switch (outcome.status) {
    case LogObserverStatus::Stale:
      ServiceObservationError(env, "SERVICE_STALE", operation,
                              outcome.reason, true);
      return;
    case LogObserverStatus::Limit:
      ServiceObservationError(env, "SERVICE_OUTPUT_LIMIT", operation,
                              "output-limit");
      return;
    case LogObserverStatus::Denied:
      ServiceObservationError(env, "SERVICE_ACCESS_DENIED", operation,
                              "access-denied");
      return;
    case LogObserverStatus::Retry:
      ServiceObservationError(env, "SERVICE_PENDING", operation,
                              outcome.reason, true);
      return;
    default:
      ServiceObservationError(env, "SERVICE_IO_FAILED", operation, "io",
                              true);
      return;
  }
}

// One consistent observation of both families between two equal epoch reads.
// mode 0 = initial capture, 1 = resume verification, 2 = page read.
LogObserverOutcome LogObserverObserve(
    const Win32LogObserver& observer, int mode, LogObserverFamily* families,
    uint64_t budget, std::vector<LogObserverChunk>* chunks, bool* eof,
    LogObserverEpochs* epochs) {
  LogObserverOutcome outcome;
  for (int attempt = 0; attempt < kLogObserverAttempts; ++attempt) {
    LogObserverFamily work[2] = {families[0], families[1]};
    std::vector<LogObserverChunk> collected;
    uint64_t remaining = budget;
    bool complete = true;
    LogObserverEpochs before, after;
    outcome = LogObserverReadEpochs(observer, &before);
    if (outcome.status != LogObserverStatus::Ok) {
      if (outcome.status == LogObserverStatus::Retry) continue;
      return outcome;
    }
    std::string directory_identity;
    HANDLE directory = LogObserverOpenDirectory(observer, &directory_identity);
    if (directory == INVALID_HANDLE_VALUE) {
      const DWORD error = GetLastError();
      outcome = LogObserverFail(
          error == ERROR_ACCESS_DENIED ? LogObserverStatus::Denied
          : error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
              ? LogObserverStatus::Stale : LogObserverStatus::Failed,
          error == ERROR_ACCESS_DENIED ? "access-denied" : "log-continuity");
      return outcome;
    }
    std::vector<std::string> names;
    outcome = LogObserverListDirectory(directory, &names);
    for (int index = 0;
         outcome.status == LogObserverStatus::Ok && index < 2; ++index) {
      if (mode == 0) {
        work[index].directory_identity = directory_identity;
      } else if (work[index].directory_identity != directory_identity) {
        outcome = LogObserverFail(LogObserverStatus::Stale, "log-continuity");
        break;
      }
      std::vector<LogObserverEntry> entries;
      outcome = LogObserverScanFamily(directory, names, work[index].base,
                                      &entries);
      if (outcome.status != LogObserverStatus::Ok) break;
      bool family_eof = true;
      if (mode == 0) {
        outcome = LogObserverCaptureFamily(directory, entries, &work[index]);
      } else if (mode == 1) {
        outcome = LogObserverVerifyFamily(directory, entries, &work[index]);
      } else {
        outcome = LogObserverAdvanceFamily(directory, entries, &work[index],
                                           &remaining, &collected,
                                           &family_eof);
      }
      complete = complete && family_eof;
    }
    CloseHandle(directory);
    if (outcome.status == LogObserverStatus::Ok) {
      outcome = LogObserverReadEpochs(observer, &after);
      if (outcome.status == LogObserverStatus::Ok &&
          !LogObserverSameEpochs(before, after)) {
        outcome = LogObserverFail(LogObserverStatus::Retry,
                                  "process-ambiguous");
      }
    }
    if (outcome.status == LogObserverStatus::Retry) continue;
    if (outcome.status != LogObserverStatus::Ok) return outcome;
    if (!LogObserverCursorWithinLimits(work))
      return LogObserverFail(LogObserverStatus::Limit, "output-limit");
    families[0] = std::move(work[0]);
    families[1] = std::move(work[1]);
    *chunks = std::move(collected);
    *eof = complete;
    *epochs = after;
    return LogObserverOutcome{};
  }
  return outcome;
}

bool LogObserverHexValue(napi_env env, napi_value value, std::string* text) {
  return InventoryString(env, value, text) && ValidServiceFingerprint(*text);
}

bool LogObserverCount(napi_env env, napi_value value, uint64_t maximum,
                      uint64_t* result) {
  napi_valuetype type;
  double numeric = 0;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_number ||
      napi_get_value_double(env, value, &numeric) != napi_ok ||
      !std::isfinite(numeric) || numeric < 0 ||
      numeric > static_cast<double>(maximum) ||
      std::floor(numeric) != numeric) return false;
  *result = static_cast<uint64_t>(numeric);
  return true;
}

bool LogObserverArray(napi_env env, napi_value value, uint32_t maximum,
                      uint32_t* length) {
  bool is_array = false;
  return napi_is_array(env, value, &is_array) == napi_ok && is_array &&
      napi_get_array_length(env, value, length) == napi_ok &&
      *length <= maximum;
}

// Parses a resume cursor into `families` and returns its fingerprint.  The
// JS layer validated the schema; native recomputes the fingerprint so every
// bound field is authenticated before any filesystem check trusts it.
bool LogObserverParseResume(napi_env env, napi_value value,
                            const Win32LogObserver& observer,
                            LogObserverFamily* families,
                            std::string* fingerprint) {
  static const char* const set_names[] = {
    "schemaVersion", "bootFingerprint", "serviceKey", "configFingerprint",
    "families", "cursorFingerprint",
  };
  static const char* const family_names[] = {
    "family", "baseName", "directoryIdentityFingerprint", "files",
    "nextLogicalOffset", "partialLineBytes", "absenceFingerprint",
  };
  static const char* const file_names[] = {
    "identityFingerprint", "logicalStartOffset", "observedLength",
    "prefixSha256",
  };
  napi_value set[6];
  uint64_t schema = 0;
  std::string boot, key, config;
  uint32_t count = 0;
  if (!InventoryOrdinaryDataObject(env, value, set_names, 6, set) ||
      !LogObserverCount(env, set[0], 1, &schema) || schema != 1 ||
      !LogObserverHexValue(env, set[1], &boot) ||
      !InventoryString(env, set[2], &key) ||
      !LogObserverHexValue(env, set[3], &config) ||
      !LogObserverArray(env, set[4], 2, &count) || count != 2 ||
      !LogObserverHexValue(env, set[5], fingerprint)) return false;
  if (boot != observer.boot_fingerprint || key != observer.service_key ||
      config != observer.config_fingerprint) return false;
  for (uint32_t index = 0; index < 2; ++index) {
    napi_value element, fields[7];
    std::string family, base, directory;
    uint32_t file_count = 0;
    uint64_t next = 0, partial = 0;
    if (napi_get_element(env, set[4], index, &element) != napi_ok ||
        !InventoryOrdinaryDataObject(env, element, family_names, 7, fields) ||
        !InventoryString(env, fields[0], &family) ||
        family != families[index].family ||
        !InventoryString(env, fields[1], &base) ||
        base != families[index].base ||
        !LogObserverHexValue(env, fields[2], &directory) ||
        !LogObserverArray(env, fields[3],
                          static_cast<uint32_t>(kLogObserverFilesPerFamily),
                          &file_count) ||
        !LogObserverCount(env, fields[4], kLogObserverLogicalBytes, &next) ||
        !LogObserverCount(env, fields[5], kLogObserverPartialLineBytes,
                          &partial)) return false;
    families[index].directory_identity = directory;
    families[index].files.clear();
    for (uint32_t position = 0; position < file_count; ++position) {
      napi_value file_value, file_fields[4];
      LogObserverFile file;
      if (napi_get_element(env, fields[3], position, &file_value) != napi_ok ||
          !InventoryOrdinaryDataObject(env, file_value, file_names, 4,
                                       file_fields) ||
          !LogObserverHexValue(env, file_fields[0], &file.identity) ||
          !LogObserverCount(env, file_fields[1], kLogObserverLogicalBytes,
                            &file.logical_start) ||
          !LogObserverCount(env, file_fields[2], kLogObserverFileBytes,
                            &file.observed) ||
          !LogObserverHexValue(env, file_fields[3], &file.prefix_sha256))
        return false;
      families[index].files.push_back(file);
    }
    families[index].next = next;
    families[index].partial = partial;
    napi_valuetype absence_type;
    std::string absence, expected_absence;
    if (napi_typeof(env, fields[6], &absence_type) != napi_ok) return false;
    if (families[index].files.empty()) {
      if (!LogObserverHexValue(env, fields[6], &absence) ||
          !LogObserverAbsence(families[index], &expected_absence) ||
          absence != expected_absence) return false;
    } else if (absence_type != napi_null) {
      return false;
    }
  }
  std::string recomputed;
  return LogObserverCursorWithinLimits(families) &&
      LogObserverCursorFingerprint(observer, families, &recomputed) &&
      recomputed == *fingerprint;
}

#endif  // defined(_WIN32) && defined(_WIN64)

napi_value OpenWin32ServiceLogObserver(napi_env env,
                                       napi_callback_info info) {
  const char* operation = "open_win32_service_log_observer";
  napi_value args[3];
  if (!InventoryArgs(env, info, 3, args)) {
    ServiceObservationError(env, "SERVICE_INVALID", operation,
                            "invalid-input");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  Win32ServiceHandle* service = nullptr;
  Win32ServiceLaunch launch;
  napi_valuetype resume_type;
  if (!Win32ServiceHandleArg(env, args[0], &service) ||
      !CaptureWin32ServiceLaunch(env, args[1], service->name,
                                 service->service_role, service->roles,
                                 &launch) ||
      napi_typeof(env, args[2], &resume_type) != napi_ok ||
      (resume_type != napi_null && resume_type != napi_object)) {
    ServiceObservationError(env, "SERVICE_INVALID", operation,
                            "invalid-input");
    return nullptr;
  }
  static const std::string daemon_prefix = "GJCRemoteDaemon-";
  const bool bot = service->service_role == "bot";
  const std::string service_key = bot
      ? "bot" : service->name.substr(daemon_prefix.size());
  const std::string base = bot
      ? "gjc-remote-bot" : "gjc-remote-daemon-" + service_key;
  if ((!bot && service->name.rfind(daemon_prefix, 0) != 0) ||
      launch.log_as != base + "-wrapper" ||
      launch.log_cmd_as != base + "-child" ||
      !ValidServiceFingerprint(launch.effective_config_fingerprint)) {
    ServiceObservationError(env, "SERVICE_INVALID", operation,
                            "invalid-input");
    return nullptr;
  }
  auto* observer = new Win32LogObserver();
  observer->service_key = service_key;
  observer->config_fingerprint = launch.effective_config_fingerprint;
  observer->log_directory = launch.log_directory;
  observer->supervisor_path = launch.supervisor_path;
  observer->runtime_path = launch.runtime_path;
  observer->families[0].family = "wrapper";
  observer->families[0].base = base + "-wrapper";
  observer->families[1].family = "child";
  observer->families[1].base = base + "-child";
  observer->manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  observer->service = observer->manager == nullptr ? nullptr
      : OpenServiceW(observer->manager, Wide(service->name).c_str(),
                     SERVICE_QUERY_STATUS);
  std::string boot_before;
  ULONGLONG tick_before = 0;
  if (observer->service == nullptr) {
    const DWORD error = GetLastError();
    CloseWin32LogObserver(observer);
    delete observer;
    ServiceObservationError(env,
        error == ERROR_ACCESS_DENIED ? "SERVICE_ACCESS_DENIED"
                                     : "SERVICE_STALE",
        operation,
        error == ERROR_ACCESS_DENIED ? "access-denied" : "identity-changed",
        error != ERROR_ACCESS_DENIED);
    return nullptr;
  }
  if (!LogObserverClock(&boot_before, &tick_before)) {
    CloseWin32LogObserver(observer);
    delete observer;
    ServiceObservationError(env, "SERVICE_PENDING", operation,
                            "clock-unavailable", true);
    return nullptr;
  }
  observer->boot_fingerprint = boot_before;
  std::string resume_fingerprint;
  if (resume_type == napi_object &&
      !LogObserverParseResume(env, args[2], *observer, observer->families,
                              &resume_fingerprint)) {
    CloseWin32LogObserver(observer);
    delete observer;
    ServiceObservationError(env, "SERVICE_STALE", operation,
                            "log-cursor-invalid", true);
    return nullptr;
  }
  std::vector<LogObserverChunk> chunks;
  bool eof = true;
  LogObserverEpochs epochs;
  const LogObserverOutcome outcome = LogObserverObserve(
      *observer, resume_type == napi_object ? 1 : 0, observer->families, 0,
      &chunks, &eof, &epochs);
  std::string boot_after;
  ULONGLONG tick_after = 0;
  std::string fingerprint;
  if (outcome.status != LogObserverStatus::Ok) {
    CloseWin32LogObserver(observer);
    delete observer;
    LogObserverThrow(env, operation, outcome);
    return nullptr;
  }
  if (!LogObserverClock(&boot_after, &tick_after) ||
      boot_after != boot_before ||
      !LogObserverCursorFingerprint(*observer, observer->families,
                                    &fingerprint) ||
      (resume_type == napi_object && fingerprint != resume_fingerprint)) {
    CloseWin32LogObserver(observer);
    delete observer;
    ServiceObservationError(env, "SERVICE_STALE", operation,
                            "log-cursor-invalid", true);
    return nullptr;
  }
  observer->cursor_fingerprint = fingerprint;
  observer->child_epoch = epochs.present ? epochs.child : "";
  napi_value handle;
  if (napi_create_object(env, &handle) != napi_ok ||
      napi_type_tag_object(env, handle, &kWin32LogObserverTypeTag) != napi_ok ||
      napi_wrap(env, handle, observer, FinalizeWin32LogObserver, nullptr,
                nullptr) != napi_ok) {
    CloseWin32LogObserver(observer);
    delete observer;
    ServiceObservationError(env, "SERVICE_IO_FAILED", operation, "io");
    return nullptr;
  }
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "handle", handle);
  napi_set_named_property(env, result, "clock",
                          LogObserverClockValue(env, boot_after, tick_after));
  napi_set_named_property(env, result, "cursor",
      LogObserverCursorValue(env, *observer, observer->families, fingerprint));
  LogObserverSetEpochs(env, result, epochs);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(env, "SERVICE_UNSUPPORTED", operation,
                          "unsupported");
  return nullptr;
#endif
}

napi_value ReadWin32ServiceLogObserver(napi_env env,
                                       napi_callback_info info) {
  const char* operation = "read_win32_service_log_observer";
  napi_value args[3];
  if (!InventoryArgs(env, info, 3, args)) {
    ServiceObservationError(env, "SERVICE_INVALID", operation,
                            "invalid-input");
    return nullptr;
  }
#if defined(_WIN32) && defined(_WIN64)
  Win32LogObserver* observer = nullptr;
  std::string expected;
  uint32_t max_bytes = 0;
  if (!Win32LogObserverArg(env, args[0], &observer) ||
      !LogObserverHexValue(env, args[1], &expected) ||
      !InventoryUint32(env, args[2], &max_bytes) || max_bytes == 0 ||
      max_bytes > kLogObserverPageBytes) {
    ServiceObservationError(env, "SERVICE_INVALID", operation,
                            "invalid-input");
    return nullptr;
  }
  if (observer->closed || observer->service == nullptr) {
    ServiceObservationError(env, "SERVICE_STALE", operation,
                            "observer-closed", true);
    return nullptr;
  }
  if (expected != observer->cursor_fingerprint) {
    ServiceObservationError(env, "SERVICE_STALE", operation,
                            "log-cursor-invalid", true);
    return nullptr;
  }
  if (observer->bytes_read >= kLogObserverObserverBytes) {
    ServiceObservationError(env, "SERVICE_OUTPUT_LIMIT", operation,
                            "output-limit");
    return nullptr;
  }
  std::string boot_before;
  ULONGLONG tick_before = 0;
  if (!LogObserverClock(&boot_before, &tick_before)) {
    ServiceObservationError(env, "SERVICE_PENDING", operation,
                            "clock-unavailable", true);
    return nullptr;
  }
  if (boot_before != observer->boot_fingerprint) {
    ServiceObservationError(env, "SERVICE_STALE", operation, "reboot", true);
    return nullptr;
  }
  const uint64_t budget = std::min<uint64_t>(
      max_bytes, kLogObserverObserverBytes - observer->bytes_read);
  LogObserverFamily families[2] = {observer->families[0],
                                   observer->families[1]};
  std::vector<LogObserverChunk> chunks;
  bool eof = true;
  LogObserverEpochs epochs;
  const LogObserverOutcome outcome = LogObserverObserve(
      *observer, 2, families, budget, &chunks, &eof, &epochs);
  if (outcome.status != LogObserverStatus::Ok) {
    LogObserverThrow(env, operation, outcome);
    return nullptr;
  }
  if (!observer->child_epoch.empty() &&
      (!epochs.present || epochs.child != observer->child_epoch)) {
    ServiceObservationError(env, "SERVICE_STALE", operation, "stale-epoch",
                            true);
    return nullptr;
  }
  std::string boot_after, fingerprint;
  ULONGLONG tick_after = 0;
  if (!LogObserverClock(&boot_after, &tick_after) ||
      boot_after != observer->boot_fingerprint ||
      !LogObserverCursorFingerprint(*observer, families, &fingerprint)) {
    ServiceObservationError(env, "SERVICE_PENDING", operation,
                            "clock-unavailable", true);
    return nullptr;
  }
  uint64_t page_bytes = 0;
  for (const auto& chunk : chunks) page_bytes += chunk.bytes.size();
  napi_value before_cursor = LogObserverCursorValue(
      env, *observer, observer->families, observer->cursor_fingerprint);
  napi_value after_cursor =
      LogObserverCursorValue(env, *observer, families, fingerprint);
  napi_value list;
  napi_create_array_with_length(env, chunks.size(), &list);
  for (size_t index = 0; index < chunks.size(); ++index) {
    const LogObserverChunk& chunk = chunks[index];
    napi_value object, bytes;
    void* ignored = nullptr;
    napi_create_object(env, &object);
    ServiceSetString(env, object, "family", chunk.family);
    ServiceSetString(env, object, "fileIdentityFingerprint", chunk.identity);
    ServiceSetDouble(env, object, "logicalOffset",
                     static_cast<double>(chunk.logical_offset));
    if (napi_create_buffer_copy(env, chunk.bytes.size(),
                                chunk.bytes.empty() ? nullptr
                                                    : chunk.bytes.data(),
                                &ignored, &bytes) != napi_ok) {
      ServiceObservationError(env, "SERVICE_IO_FAILED", operation, "io");
      return nullptr;
    }
    napi_set_named_property(env, object, "bytes", bytes);
    napi_set_element(env, list, static_cast<uint32_t>(index), object);
  }
  // Commit only after every fallible step: a failed read leaves the observer
  // at its previous cursor so the caller's CAS stays exact.
  observer->families[0] = std::move(families[0]);
  observer->families[1] = std::move(families[1]);
  observer->cursor_fingerprint = fingerprint;
  observer->bytes_read += page_bytes;
  napi_value result;
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "clock",
                          LogObserverClockValue(env, boot_after, tick_after));
  napi_set_named_property(env, result, "beforeCursor", before_cursor);
  napi_set_named_property(env, result, "afterCursor", after_cursor);
  LogObserverSetEpochs(env, result, epochs);
  napi_set_named_property(env, result, "chunks", list);
  napi_value eof_value, continuity;
  napi_get_boolean(env, eof, &eof_value);
  napi_set_named_property(env, result, "eof", eof_value);
  napi_create_string_utf8(env, "complete", NAPI_AUTO_LENGTH, &continuity);
  napi_set_named_property(env, result, "continuity", continuity);
  ServiceSetUint32(env, result, "writes", 0);
  return result;
#else
  ServiceObservationError(env, "SERVICE_UNSUPPORTED", operation,
                          "unsupported");
  return nullptr;
#endif
}
