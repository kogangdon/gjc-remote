// Test-only adapter: compile directly into a fresh isolated addon, never the production loader.
#ifndef NAPI_VERSION
#define NAPI_VERSION 8
#endif
#include <node_api.h>
#include "../src/windows-lineage.h"
#include <cmath>
#include <new>

namespace {
using namespace windows_lineage;

const napi_type_tag kScopeTag = {0x8bbde2a9dd864b17ULL, 0xa1efa0a12d8a15c3ULL};
struct State {
  napi_ref objectPrototype = nullptr;
  napi_ref arrayPrototype = nullptr;
  napi_ref descriptors = nullptr;
  bool validating = false;
};
struct Owned {
  napi_env env;
  std::unique_ptr<WindowsLineageScope> scope;
};

void Check(napi_status status) {
  if (status != napi_ok)
    throw Error("LINEAGE_TRACKING_LOST", "N-API operation failed; native result may be undelivered", 0, {}, true);
}
void Invalid(const char* message) { throw Error("LINEAGE_INVALID", message); }

napi_value String(napi_env env, const std::wstring& text) {
  static_assert(sizeof(wchar_t) == sizeof(char16_t), "Windows UTF-16 required");
  napi_value value;
  Check(napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(text.data()), text.size(), &value));
  return value;
}
napi_value Ascii(napi_env env, const std::string& text) {
  napi_value value;
  Check(napi_create_string_utf8(env, text.data(), text.size(), &value));
  return value;
}
napi_value Boolean(napi_env env, bool flag) {
  napi_value value; Check(napi_get_boolean(env, flag, &value)); return value;
}
napi_value Number(napi_env env, uint32_t number) {
  napi_value value; Check(napi_create_uint32(env, number, &value)); return value;
}
void Set(napi_env env, napi_value object, const char* key, napi_value value) {
  // Define own data properties: do not invoke inherited Object.prototype setters.
  napi_property_descriptor descriptor{key, nullptr, nullptr, nullptr, nullptr, value,
                                     napi_default_jsproperty, nullptr};
  Check(napi_define_properties(env, object, 1, &descriptor));
}
napi_value Object(napi_env env) {
  napi_value value; Check(napi_create_object(env, &value)); return value;
}

std::wstring ReadString(napi_env env, napi_value value, bool empty = false) {
  napi_valuetype type;
  Check(napi_typeof(env, value, &type));
  if (type != napi_string) Invalid("Expected a primitive string");
  size_t size = 0, copied = 0;
  Check(napi_get_value_string_utf16(env, value, nullptr, 0, &size));
  if (size > 4096 || (!empty && !size)) Invalid("String length is invalid");
  std::vector<char16_t> bytes(size + 1);
  Check(napi_get_value_string_utf16(env, value, bytes.data(), bytes.size(), &copied));
  if (copied != size) Invalid("Partial string conversion");
  std::wstring text(reinterpret_cast<const wchar_t*>(bytes.data()), size);
  if ((!empty || !text.empty()) && !Text(text)) Invalid("NUL or invalid UTF-16 string");
  return text;
}

struct ValidationGuard {
  State* state;
  explicit ValidationGuard(State* s) : state(s) {
    if (state->validating) Invalid("Reentrant input validation is prohibited");
    state->validating = true;
  }
  ~ValidationGuard() { state->validating = false; }
};

// Capture own data descriptors, never read arbitrary getters from caller input.
// Intrinsics are retained at initialization, matching the production addon's pattern.
napi_value Descriptors(napi_env env, State* state, napi_value value, bool array) {
  napi_valuetype type;
  Check(napi_typeof(env, value, &type));
  if (type != napi_object) Invalid("Expected an ordinary object or array");
  napi_value prototype, expected, intrinsic, receiver, result;
  Check(napi_get_prototype(env, value, &prototype));
  Check(napi_get_reference_value(env, array ? state->arrayPrototype : state->objectPrototype, &expected));
  bool same = false, isArray = false;
  Check(napi_strict_equals(env, prototype, expected, &same));
  Check(napi_is_array(env, value, &isArray));
  if (!same || isArray != array) Invalid("Unexpected object prototype");
  Check(napi_get_reference_value(env, state->descriptors, &intrinsic));
  Check(napi_get_reference_value(env, state->objectPrototype, &receiver));
  Check(napi_call_function(env, receiver, intrinsic, 1, &value, &result));
  return result;
}

uint32_t OwnCount(napi_env env, napi_value object) {
  napi_value names;
  Check(napi_get_all_property_names(env, object, napi_key_own_only, napi_key_all_properties,
                                    napi_key_numbers_to_strings, &names));
  uint32_t count = 0; Check(napi_get_array_length(env, names, &count)); return count;
}

napi_value DataValue(napi_env env, napi_value descriptors, const char* key, bool enumerable = true) {
  bool own = false;
  napi_value name = Ascii(env, key), descriptor, value, flag;
  Check(napi_has_own_property(env, descriptors, name, &own));
  if (!own) Invalid("Missing own data property");
  Check(napi_get_property(env, descriptors, name, &descriptor));
  napi_value valueName = Ascii(env, "value");
  Check(napi_has_own_property(env, descriptor, valueName, &own));
  if (!own) Invalid("Accessor properties are prohibited");
  for (const char* accessor : {"get", "set"}) {
    Check(napi_has_own_property(env, descriptor, Ascii(env, accessor), &own));
    if (own) Invalid("Accessor properties are prohibited");
  }
  Check(napi_get_named_property(env, descriptor, "enumerable", &flag));
  bool actual = false; Check(napi_get_value_bool(env, flag, &actual));
  if (actual != enumerable) Invalid("Unexpected property enumerability");
  Check(napi_get_named_property(env, descriptor, "value", &value));
  return value;
}

WindowsLineageBinding ReadBinding(napi_env env, State* state, napi_value value) {
  ValidationGuard guard(state);
  napi_value descriptors = Descriptors(env, state, value, false);
  if (OwnCount(env, descriptors) != 5) Invalid("Binding must have exactly five own data keys");
  WindowsLineageBinding binding;
  binding.serviceKey = ReadString(env, DataValue(env, descriptors, "serviceKey"));
  binding.bootId = ReadString(env, DataValue(env, descriptors, "bootId"));
  binding.configFingerprint = ReadString(env, DataValue(env, descriptors, "configFingerprint"));
  binding.roleSid = ReadString(env, DataValue(env, descriptors, "roleSid"));
  binding.lifetimeId = ReadString(env, DataValue(env, descriptors, "lifetimeId"));
  binding.Validate();
  return binding;
}

std::vector<std::wstring> ReadArgs(napi_env env, State* state, napi_value value) {
  ValidationGuard guard(state);
  napi_value descriptors = Descriptors(env, state, value, true);
  napi_value length = DataValue(env, descriptors, "length", false);
  napi_valuetype type;
  Check(napi_typeof(env, length, &type));
  double number = 0;
  if (type != napi_number) Invalid("Invalid argument array length");
  Check(napi_get_value_double(env, length, &number));
  if (!std::isfinite(number) || number < 0 || number > 128 || std::floor(number) != number)
    Invalid("Argument array must contain at most 128 entries");
  uint32_t count = static_cast<uint32_t>(number);
  if (OwnCount(env, descriptors) != count + 1) Invalid("Sparse or extended argument arrays are prohibited");
  std::vector<std::wstring> args;
  for (uint32_t i = 0; i < count; ++i)
    args.push_back(ReadString(env, DataValue(env, descriptors, std::to_string(i).c_str()), true));
  return args;
}

napi_value BindingValue(napi_env env, const WindowsLineageBinding& binding) {
  napi_value value = Object(env);
  Set(env, value, "serviceKey", String(env, binding.serviceKey));
  Set(env, value, "bootId", String(env, binding.bootId));
  Set(env, value, "configFingerprint", String(env, binding.configFingerprint));
  Set(env, value, "roleSid", String(env, binding.roleSid));
  Set(env, value, "lifetimeId", String(env, binding.lifetimeId));
  return value;
}
napi_value EffectValue(napi_env env, const Effects& effects) {
  napi_value value = Object(env);
  Set(env, value, "jobCreated", Boolean(env, effects.jobCreated));
  Set(env, value, "rootCreated", Boolean(env, effects.rootCreated));
  Set(env, value, "rootResumed", Boolean(env, effects.rootResumed));
  Set(env, value, "forced", Boolean(env, effects.forced));
  Set(env, value, "terminationCalls", Number(env, effects.terminationCalls));
  Set(env, value, "cleanupTerminationCalls", Number(env, effects.cleanupTerminationCalls));
  return value;
}
bool Changed(const Effects& before, const Effects& after) {
  return before.jobCreated != after.jobCreated || before.rootCreated != after.rootCreated ||
      before.rootResumed != after.rootResumed || before.forced != after.forced ||
      before.terminationCalls != after.terminationCalls ||
      before.cleanupTerminationCalls != after.cleanupTerminationCalls;
}

napi_value ReceiptValue(napi_env env, const Receipt& r, const Effects& effects, bool writes) {
  napi_value value = Object(env);
  Set(env, value, "binding", BindingValue(env, r.binding));
  Set(env, value, "scopeId", String(env, r.scopeId));
  Set(env, value, "operationId", String(env, r.operationId));
  Set(env, value, "rootPid", Number(env, r.rootPid));
  // Decimal FILETIME string avoids JS Number's loss of root incarnation bits.
  Set(env, value, "rootStartTime", String(env, std::to_wstring(r.rootStartTime)));
  Set(env, value, "rootExecutable", String(env, r.rootExecutable));
  Set(env, value, "rootOwner", String(env, r.rootOwner));
  Set(env, value, "rootExited", Boolean(env, r.rootExited));
  Set(env, value, "rootExitCode", Number(env, r.rootExitCode));
  Set(env, value, "activeProcesses", Number(env, r.activeProcesses));
  Set(env, value, "totalProcesses", Number(env, r.totalProcesses));
  Set(env, value, "coverageComplete", Boolean(env, r.coverageComplete));
  Set(env, value, "escapeDetected", Boolean(env, r.escapeDetected));
  Set(env, value, "sealed", Boolean(env, r.sealed));
  Set(env, value, "closed", Boolean(env, r.closed));
  Set(env, value, "forced", Boolean(env, r.forced));
  Set(env, value, "terminationCalls", Number(env, r.terminationCalls));
  // Fixture-local mutating-call indicator, not a global/kernel-effect total.
  // Individual creation/resume/termination effects remain explicit below.
  Set(env, value, "writes", Number(env, writes ? 1 : 0));
  Set(env, value, "ambiguous", Boolean(env, false));
  Set(env, value, "effects", EffectValue(env, effects));
  return value;
}

napi_value Throw(napi_env env, const Error& error, bool writes) {
  // Replace validation-time JS exceptions with the standardized error, without conversions.
  bool pending = false;
  if (napi_is_exception_pending(env, &pending) == napi_ok && pending) {
    napi_value ignored; napi_get_and_clear_last_exception(env, &ignored);
  }
  try {
    napi_value value;
    Check(napi_create_error(env, Ascii(env, error.code), Ascii(env, error.message), &value));
    Set(env, value, "code", Ascii(env, error.code));
    Set(env, value, "win32", Number(env, error.win32));
    Set(env, value, "writes", Number(env, writes ? 1 : 0));
    Set(env, value, "ambiguous", Boolean(env, error.ambiguous));
    Set(env, value, "effects", EffectValue(env, error.effects));
    Set(env, value, "scopeId", String(env, error.scopeId));
    Set(env, value, "rootPid", Number(env, error.rootPid));
    Set(env, value, "rootStartTime", String(env, std::to_wstring(error.rootStartTime)));
    Set(env, value, "rootExecutable", String(env, error.rootExecutable));
    Set(env, value, "rootOwner", String(env, error.rootOwner));
    Check(napi_throw(env, value));
  } catch (...) {
    // A pending VM/OOM error must not be replaced by apparent success.
    napi_throw_error(env, "LINEAGE_TRACKING_LOST", "Unable to encode native effects; state is ambiguous");
  }
  return nullptr;
}

Owned* ReadHandle(napi_env env, napi_value object) {
  bool tagged = false;
  void* data = nullptr;
  if (napi_check_object_type_tag(env, object, &kScopeTag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, object, &data) != napi_ok || !data)
    Invalid("Opaque native lineage handle required");
  auto* owned = static_cast<Owned*>(data);
  if (owned->env != env || !owned->scope)
    throw Error("LINEAGE_STALE", "Closed native lineage handle");
  return owned;
}
void FinalizeOwned(napi_env, void* data, void*) { delete static_cast<Owned*>(data); }
void FinalizeState(napi_env env, void* data, void*) {
  auto* state = static_cast<State*>(data);
  if (state->objectPrototype) napi_delete_reference(env, state->objectPrototype);
  if (state->arrayPrototype) napi_delete_reference(env, state->arrayPrototype);
  if (state->descriptors) napi_delete_reference(env, state->descriptors);
  delete state;
}

// All exports share exception/effect handling; no C++ exception crosses N-API.
enum class Operation { Create, Observe, Terminate, Close, Role, Boot, Members };
napi_value Invoke(napi_env env, napi_callback_info info, Operation operation) {
  Owned* owned = nullptr;
  Effects before;
  try {
    size_t argc = 8;
    napi_value argv[8];
    void* data = nullptr;
    Check(napi_get_cb_info(env, info, &argc, argv, nullptr, &data));
    auto* state = static_cast<State*>(data);
    if (!state || state->validating) Invalid("Reentrant lineage call prohibited");
    size_t required = operation == Operation::Role || operation == Operation::Boot ? 0 :
        (operation == Operation::Create || operation == Operation::Close ? 1 :
         (operation == Operation::Observe || operation == Operation::Members ? 3 : 4));
    if (argc != required) Invalid("Exact argument count required");
    if (operation == Operation::Role) return String(env, windows_lineage::TokenOwner(GetCurrentProcess()));
    if (operation == Operation::Boot) return String(env, windows_lineage::CurrentBootId());
    if (operation == Operation::Create) {
      napi_value values[3];
      {
        ValidationGuard guard(state);
        napi_value descriptors = Descriptors(env, state, argv[0], false);
        if (OwnCount(env, descriptors) != 3) Invalid("Options must be exactly executable, args, binding");
        values[0] = DataValue(env, descriptors, "executable");
        values[1] = DataValue(env, descriptors, "args");
        values[2] = DataValue(env, descriptors, "binding");
      }
      std::wstring executable = ReadString(env, values[0]);
      auto args = ReadArgs(env, state, values[1]);
      auto binding = ReadBinding(env, state, values[2]);
      auto holder = std::make_unique<Owned>();
      holder->env = env;
      holder->scope = std::make_unique<WindowsLineageScope>(std::move(binding));
      // Allocate/tag/wrap the return capability before any process or job mutation.
      napi_value object = Object(env);
      Check(napi_type_tag_object(env, object, &kScopeTag));
      Check(napi_wrap(env, object, holder.get(), FinalizeOwned, nullptr, nullptr));
      owned = holder.release();
      owned->scope->CreateContained(executable, args);
      return object;
    }
    owned = ReadHandle(env, argv[0]);
    before = owned->scope->GetEffects();
    if (operation == Operation::Close) {
      napi_value value; Check(napi_get_undefined(env, &value));
      owned->scope->Close();
      owned->scope.reset();
      return value;
    }
    auto binding = ReadBinding(env, state, argv[1]);
    auto operationId = ReadString(env, argv[2]);
    if (operation == Operation::Members) {
      const auto members = owned->scope->LiveMembers(binding, operationId);
      napi_value values;
      Check(napi_create_array_with_length(env, members.size(), &values));
      for (uint32_t index = 0; index < members.size(); ++index) {
        napi_value value = Object(env);
        Set(env, value, "pid", Number(env, members[index].pid));
        Set(env, value, "startTime", String(env, std::to_wstring(members[index].startTime)));
        Set(env, value, "executable", String(env, members[index].executable));
        Check(napi_set_element(env, values, index, value));
      }
      return values;
    }
    Receipt receipt;
    if (operation == Operation::Observe) receipt = owned->scope->Observe(binding, operationId);
    else {
      napi_valuetype type;
      Check(napi_typeof(env, argv[3], &type));
      if (type != napi_number) Invalid("Timeout must be a number");
      double timeout = 0;
      Check(napi_get_value_double(env, argv[3], &timeout));
      if (!std::isfinite(timeout) || timeout < 1 || timeout > 60000 || std::floor(timeout) != timeout)
        Invalid("Timeout must be an integer in 1..60000");
      receipt = owned->scope->Terminate(binding, operationId, static_cast<DWORD>(timeout));
    }
    const auto& after = owned->scope->GetEffects();
    return ReceiptValue(env, receipt, after, Changed(before, after));
  } catch (Error& error) {
    if (owned && owned->scope) {
      // Retain known partial-spawn identity even if the return object was never delivered.
      try { owned->scope->DescribeError(error); }
      catch (...) { error.effects = owned->scope->GetEffects(); error.ambiguous = true; }
      if (operation == Operation::Create && !error.ambiguous &&
          (!error.effects.rootCreated || (!error.effects.rootResumed &&
                                         error.effects.cleanupTerminationCalls > 0))) {
        // The failed caller receives no capability. Release confirmed rollback
        // handles and the executable lock now, without waiting for JavaScript GC.
        // Never discard ambiguous/live ownership through this path.
        owned->scope->Close();
        owned->scope.reset();
      }
    }
    return Throw(env, error, Changed(before, error.effects));
  } catch (...) {
    Effects effects = owned && owned->scope ? owned->scope->GetEffects() : before;
    Error error("LINEAGE_TRACKING_LOST", "Unexpected native failure", 0, effects, effects.rootCreated);
    if (owned && owned->scope) {
      try { owned->scope->DescribeError(error); }
      catch (...) { error.ambiguous = true; }
    }
    return Throw(env, error, Changed(before, effects));
  }
}

napi_value SafeInvoke(napi_env env, napi_callback_info info, Operation operation) noexcept {
  try { return Invoke(env, info, operation); }
  catch (...) {
    // Last-resort allocation failure while constructing an error must not unwind
    // through the VM or pretend that a potentially mutating call succeeded.
    napi_throw_error(env, "LINEAGE_TRACKING_LOST", "Native error allocation failed; writes and state are ambiguous");
    return nullptr;
  }
}
napi_value CreateScope(napi_env e, napi_callback_info i) { return SafeInvoke(e, i, Operation::Create); }
napi_value ObserveScope(napi_env e, napi_callback_info i) { return SafeInvoke(e, i, Operation::Observe); }
napi_value TerminateScope(napi_env e, napi_callback_info i) { return SafeInvoke(e, i, Operation::Terminate); }
napi_value CloseScope(napi_env e, napi_callback_info i) { return SafeInvoke(e, i, Operation::Close); }
napi_value CurrentRoleSid(napi_env e, napi_callback_info i) { return SafeInvoke(e, i, Operation::Role); }
napi_value CurrentBootId(napi_env e, napi_callback_info i) { return SafeInvoke(e, i, Operation::Boot); }
napi_value LiveMembers(napi_env e, napi_callback_info i) { return SafeInvoke(e, i, Operation::Members); }

napi_value InitInternal(napi_env env, napi_value exports) {
  try {
    auto release = [env](State* state) noexcept { FinalizeState(env, state, nullptr); };
    std::unique_ptr<State, decltype(release)> state(new State(), release);
    napi_value global, object, array, prototype, descriptors;
    Check(napi_get_global(env, &global));
    Check(napi_get_named_property(env, global, "Object", &object));
    Check(napi_get_named_property(env, object, "prototype", &prototype));
    Check(napi_create_reference(env, prototype, 1, &state->objectPrototype));
    Check(napi_get_named_property(env, object, "getOwnPropertyDescriptors", &descriptors));
    Check(napi_create_reference(env, descriptors, 1, &state->descriptors));
    Check(napi_get_named_property(env, global, "Array", &array));
    Check(napi_get_named_property(env, array, "prototype", &prototype));
    Check(napi_create_reference(env, prototype, 1, &state->arrayPrototype));
    Check(napi_set_instance_data(env, state.get(), FinalizeState, nullptr));
    State* retained = state.release();
    napi_property_descriptor properties[] = {
      {"createScope", nullptr, CreateScope, nullptr, nullptr, nullptr, napi_default, retained},
      {"observeScope", nullptr, ObserveScope, nullptr, nullptr, nullptr, napi_default, retained},
      {"terminateScope", nullptr, TerminateScope, nullptr, nullptr, nullptr, napi_default, retained},
      {"closeScope", nullptr, CloseScope, nullptr, nullptr, nullptr, napi_default, retained},
      {"currentRoleSid", nullptr, CurrentRoleSid, nullptr, nullptr, nullptr, napi_default, retained},
      {"currentBootId", nullptr, CurrentBootId, nullptr, nullptr, nullptr, napi_default, retained},
      {"liveMembers", nullptr, LiveMembers, nullptr, nullptr, nullptr, napi_default, retained},
    };
    Check(napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));
    return exports;
  } catch (const Error& error) { return Throw(env, error, false); }
  catch (...) { return Throw(env, Error("LINEAGE_TRACKING_LOST", "Addon initialization failed"), false); }
}

napi_value Init(napi_env env, napi_value exports) noexcept {
  try { return InitInternal(env, exports); }
  catch (...) {
    napi_throw_error(env, "LINEAGE_TRACKING_LOST", "Addon initialization allocation failed; no native scope was admitted");
    return nullptr;
  }
}
}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
