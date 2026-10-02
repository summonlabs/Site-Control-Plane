// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

/// \file status.hpp
/// Explicit outcome vocabulary.
///
/// The code set deliberately keeps semantics that would otherwise collapse:
/// unknown, stale, conflicting, unsupported, invalid and indeterminate are
/// separate codes, because collapsing them loses the reason a site-level
/// decision could not be made.

namespace scp {

enum class StatusCode : std::uint16_t {
  Ok = 0,

  // Input shape.
  InvalidArgument = 10,
  InvalidIdentifier = 11,
  InvalidText = 12,
  InvalidUnicode = 13,
  InvalidEnum = 14,

  // Numeric domain.
  OutOfRange = 20,
  Overflow = 21,
  Underflow = 22,

  // Presence and identity.
  NotFound = 30,
  AlreadyExists = 31,
  DuplicateIdentity = 32,

  // Comparative semantics.
  Conflict = 40,
  StaleGeneration = 41,
  SupersededGeneration = 42,
  Indeterminate = 43,
  Unknown = 44,
  Unsupported = 45,
  UnsupportedFormatVersion = 46,

  // Authority.
  Unauthorized = 50,
  ScopeNotGranted = 51,
  GrantExpired = 52,
  GrantRevoked = 53,
  GrantNotYetValid = 54,
  GenerationFenced = 55,

  // Gating.
  PreconditionFailed = 60,
  GateClosed = 61,
  ObligationRejected = 62,

  // Durability and integrity.
  Corrupt = 70,
  InteriorCorruption = 71,
  TornTail = 72,
  ChecksumMismatch = 73,
  ChainBroken = 74,
  Truncated = 75,

  // Host and platform.
  IoError = 80,
  PermissionDenied = 81,
  Locked = 82,
  WriterExists = 83,
  LockLost = 84,
  PathInvalid = 85,

  // Resource bounds.
  LimitExceeded = 90,
  CapacityExhausted = 91,

  // Lifecycle.
  InvalidState = 100,
  Closed = 101,
  NotOpen = 102,
  Cancelled = 103,
  ShuttingDown = 104,
  Exhausted = 105,
};

/// Stable, lowercase, machine-readable slug for a code.
[[nodiscard]] std::string_view to_string(StatusCode code) noexcept;

/// Human-readable explanation appended after the slug.
[[nodiscard]] std::string_view describe(StatusCode code) noexcept;

/// True for codes that mean "no authoritative answer could be produced".
[[nodiscard]] bool is_indeterminate(StatusCode code) noexcept;

/// True for codes that indicate damaged or untrustworthy durable state.
[[nodiscard]] bool is_integrity_failure(StatusCode code) noexcept;

/// A status: a code plus a caller-facing explanation of the specific instance.
class Status {
 public:
  /// Default construction is a successful status; there is deliberately no
  /// static ok() factory, because the predicate below owns that name.
  Status() noexcept = default;
  Status(StatusCode code, std::string message);

  [[nodiscard]] bool ok() const noexcept { return code_ == StatusCode::Ok; }
  [[nodiscard]] StatusCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }

  /// "slug: message", or "ok".
  [[nodiscard]] std::string to_string() const;

 private:
  StatusCode code_ = StatusCode::Ok;
  std::string message_;
};

/// Convenience constructor so call sites read as `return fail(StatusCode::X, "...")`.
[[nodiscard]] Status fail(StatusCode code, std::string message);

/// A value or the reason there is no value. `Result<T>` never holds a `Status`
/// as a value: the two alternatives are distinct types.
template <class T>
class Result {
  static_assert(!std::is_same_v<std::remove_cvref_t<T>, Status>,
                "Result<T> cannot carry a Status value; use Status for void outcomes");
  static_assert(!std::is_reference_v<T>, "Result<T> stores values, not references");

 public:
  Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
  Result(Status status) : storage_(std::in_place_index<1>, std::move(status)) {}

  [[nodiscard]] bool has_value() const noexcept { return storage_.index() == 0; }
  explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] const Status& status() const noexcept { return std::get<1>(storage_); }

  [[nodiscard]] T& value() & { return std::get<0>(storage_); }
  [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
  [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

  [[nodiscard]] T& operator*() & { return value(); }
  [[nodiscard]] const T& operator*() const& { return value(); }
  [[nodiscard]] T* operator->() { return &value(); }
  [[nodiscard]] const T* operator->() const { return &value(); }

 private:
  std::variant<T, Status> storage_;
};

/// Chains a fallible step: returns the first failing status unchanged.
#define SCP_TRY(expr)                     \
  do {                                    \
    ::scp::Status scp_try_status_ = (expr); \
    if (!scp_try_status_.ok()) {          \
      return scp_try_status_;             \
    }                                     \
  } while (false)

/// Chains a fallible value step, binding the value to `name`.
#define SCP_TRY_ASSIGN(name, expr)              \
  auto scp_try_result_##name = (expr);          \
  if (!scp_try_result_##name.has_value()) {     \
    return scp_try_result_##name.status();      \
  }                                             \
  auto& name = scp_try_result_##name.value()

}  // namespace scp
