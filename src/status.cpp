// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/status.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace scp {

std::string_view to_string(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Ok:
      return "ok";
    case StatusCode::InvalidArgument:
      return "invalid_argument";
    case StatusCode::InvalidIdentifier:
      return "invalid_identifier";
    case StatusCode::InvalidText:
      return "invalid_text";
    case StatusCode::InvalidUnicode:
      return "invalid_unicode";
    case StatusCode::InvalidEnum:
      return "invalid_enum";
    case StatusCode::OutOfRange:
      return "out_of_range";
    case StatusCode::Overflow:
      return "overflow";
    case StatusCode::Underflow:
      return "underflow";
    case StatusCode::NotFound:
      return "not_found";
    case StatusCode::AlreadyExists:
      return "already_exists";
    case StatusCode::DuplicateIdentity:
      return "duplicate_identity";
    case StatusCode::Conflict:
      return "conflict";
    case StatusCode::StaleGeneration:
      return "stale_generation";
    case StatusCode::SupersededGeneration:
      return "superseded_generation";
    case StatusCode::Indeterminate:
      return "indeterminate";
    case StatusCode::Unknown:
      return "unknown";
    case StatusCode::Unsupported:
      return "unsupported";
    case StatusCode::UnsupportedFormatVersion:
      return "unsupported_format_version";
    case StatusCode::Unauthorized:
      return "unauthorized";
    case StatusCode::ScopeNotGranted:
      return "scope_not_granted";
    case StatusCode::GrantExpired:
      return "grant_expired";
    case StatusCode::GrantRevoked:
      return "grant_revoked";
    case StatusCode::GrantNotYetValid:
      return "grant_not_yet_valid";
    case StatusCode::GenerationFenced:
      return "generation_fenced";
    case StatusCode::PreconditionFailed:
      return "precondition_failed";
    case StatusCode::GateClosed:
      return "gate_closed";
    case StatusCode::ObligationRejected:
      return "obligation_rejected";
    case StatusCode::Corrupt:
      return "corrupt";
    case StatusCode::InteriorCorruption:
      return "interior_corruption";
    case StatusCode::TornTail:
      return "torn_tail";
    case StatusCode::ChecksumMismatch:
      return "checksum_mismatch";
    case StatusCode::ChainBroken:
      return "chain_broken";
    case StatusCode::Truncated:
      return "truncated";
    case StatusCode::IoError:
      return "io_error";
    case StatusCode::PermissionDenied:
      return "permission_denied";
    case StatusCode::Locked:
      return "locked";
    case StatusCode::WriterExists:
      return "writer_exists";
    case StatusCode::LockLost:
      return "lock_lost";
    case StatusCode::PathInvalid:
      return "path_invalid";
    case StatusCode::LimitExceeded:
      return "limit_exceeded";
    case StatusCode::CapacityExhausted:
      return "capacity_exhausted";
    case StatusCode::InvalidState:
      return "invalid_state";
    case StatusCode::Closed:
      return "closed";
    case StatusCode::NotOpen:
      return "not_open";
    case StatusCode::Cancelled:
      return "cancelled";
    case StatusCode::ShuttingDown:
      return "shutting_down";
    case StatusCode::Exhausted:
      return "exhausted";
  }
  // Only reachable for a value cast in from outside the enumeration; the switch
  // above has no default so that a new enumerator is a compile error here.
  return "unknown";
}

std::string_view describe(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Ok:
      return "the operation succeeded";
    case StatusCode::InvalidArgument:
      return "the argument is outside the accepted domain";
    case StatusCode::InvalidIdentifier:
      return "the identifier is not in the accepted form";
    case StatusCode::InvalidText:
      return "the text is not in the accepted form";
    case StatusCode::InvalidUnicode:
      return "the text is not well-formed UTF-8";
    case StatusCode::InvalidEnum:
      return "the value is not a member of the accepted enumeration";
    case StatusCode::OutOfRange:
      return "the value lies outside the permitted range";
    case StatusCode::Overflow:
      return "the result would exceed the largest representable value";
    case StatusCode::Underflow:
      return "the result would fall below the smallest representable value";
    case StatusCode::NotFound:
      return "the named object does not exist";
    case StatusCode::AlreadyExists:
      return "an object with that identity already exists";
    case StatusCode::DuplicateIdentity:
      return "the identity is already bound to a different object";
    case StatusCode::Conflict:
      return "the request conflicts with the current state";
    case StatusCode::StaleGeneration:
      return "the value belongs to a generation older than the current one";
    case StatusCode::SupersededGeneration:
      return "the value has been replaced by a newer generation";
    case StatusCode::Indeterminate:
      return "no authoritative answer could be produced";
    case StatusCode::Unknown:
      return "the answer is not known at this boundary";
    case StatusCode::Unsupported:
      return "the capability is not supported by this build";
    case StatusCode::UnsupportedFormatVersion:
      return "the durable format version is not supported by this build";
    case StatusCode::Unauthorized:
      return "the caller is not authorised for this operation";
    case StatusCode::ScopeNotGranted:
      return "the grant does not cover the requested scope";
    case StatusCode::GrantExpired:
      return "the grant is no longer valid at this instant";
    case StatusCode::GrantRevoked:
      return "the grant has been revoked";
    case StatusCode::GrantNotYetValid:
      return "the grant is not valid yet";
    case StatusCode::GenerationFenced:
      return "a newer generation has fenced this writer out";
    case StatusCode::PreconditionFailed:
      return "a required precondition does not hold";
    case StatusCode::GateClosed:
      return "a gate that must be open is closed";
    case StatusCode::ObligationRejected:
      return "an outstanding obligation refused the change";
    case StatusCode::Corrupt:
      return "the durable state is damaged";
    case StatusCode::InteriorCorruption:
      return "bytes inside a durable record are damaged";
    case StatusCode::TornTail:
      return "the final record was written only partially";
    case StatusCode::ChecksumMismatch:
      return "the stored checksum does not match the content";
    case StatusCode::ChainBroken:
      return "the record chain does not link to its predecessor";
    case StatusCode::Truncated:
      return "the input ended before the value was complete";
    case StatusCode::IoError:
      return "the host refused an input or output operation";
    case StatusCode::PermissionDenied:
      return "the host denied the required permission";
    case StatusCode::Locked:
      return "another writer holds the lock";
    case StatusCode::WriterExists:
      return "a writer for this boundary is already recorded";
    case StatusCode::LockLost:
      return "the lock was lost while it was held";
    case StatusCode::PathInvalid:
      return "the path is not acceptable";
    case StatusCode::LimitExceeded:
      return "a configured limit was exceeded";
    case StatusCode::CapacityExhausted:
      return "the resource has no remaining capacity";
    case StatusCode::InvalidState:
      return "the object is not in a state that allows this operation";
    case StatusCode::Closed:
      return "the object is closed";
    case StatusCode::NotOpen:
      return "the object is not open";
    case StatusCode::Cancelled:
      return "the operation was cancelled";
    case StatusCode::ShuttingDown:
      return "the runtime is shutting down";
    case StatusCode::Exhausted:
      return "the source has no further items";
  }
  // Only reachable for a value cast in from outside the enumeration.
  return "the code is not part of this build's status vocabulary";
}

bool is_indeterminate(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Indeterminate:
    case StatusCode::Unknown:
    case StatusCode::Unsupported:
    case StatusCode::UnsupportedFormatVersion:
    case StatusCode::StaleGeneration:
    case StatusCode::Conflict:
    case StatusCode::TornTail:
    case StatusCode::InteriorCorruption:
    case StatusCode::Corrupt:
    case StatusCode::ChecksumMismatch:
    case StatusCode::ChainBroken:
    case StatusCode::Truncated:
    case StatusCode::Exhausted:
      return true;

    case StatusCode::Ok:
    case StatusCode::InvalidArgument:
    case StatusCode::InvalidIdentifier:
    case StatusCode::InvalidText:
    case StatusCode::InvalidUnicode:
    case StatusCode::InvalidEnum:
    case StatusCode::OutOfRange:
    case StatusCode::Overflow:
    case StatusCode::Underflow:
    case StatusCode::NotFound:
    case StatusCode::AlreadyExists:
    case StatusCode::DuplicateIdentity:
    case StatusCode::SupersededGeneration:
    case StatusCode::Unauthorized:
    case StatusCode::ScopeNotGranted:
    case StatusCode::GrantExpired:
    case StatusCode::GrantRevoked:
    case StatusCode::GrantNotYetValid:
    case StatusCode::GenerationFenced:
    case StatusCode::PreconditionFailed:
    case StatusCode::GateClosed:
    case StatusCode::ObligationRejected:
    case StatusCode::IoError:
    case StatusCode::PermissionDenied:
    case StatusCode::Locked:
    case StatusCode::WriterExists:
    case StatusCode::LockLost:
    case StatusCode::PathInvalid:
    case StatusCode::LimitExceeded:
    case StatusCode::CapacityExhausted:
    case StatusCode::InvalidState:
    case StatusCode::Closed:
    case StatusCode::NotOpen:
    case StatusCode::Cancelled:
    case StatusCode::ShuttingDown:
      return false;
  }
  // An unrecognised code yields no authoritative answer, so it is indeterminate.
  return true;
}

bool is_integrity_failure(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Corrupt:
    case StatusCode::InteriorCorruption:
    case StatusCode::TornTail:
    case StatusCode::ChecksumMismatch:
    case StatusCode::ChainBroken:
    case StatusCode::Truncated:
      return true;

    case StatusCode::Ok:
    case StatusCode::InvalidArgument:
    case StatusCode::InvalidIdentifier:
    case StatusCode::InvalidText:
    case StatusCode::InvalidUnicode:
    case StatusCode::InvalidEnum:
    case StatusCode::OutOfRange:
    case StatusCode::Overflow:
    case StatusCode::Underflow:
    case StatusCode::NotFound:
    case StatusCode::AlreadyExists:
    case StatusCode::DuplicateIdentity:
    case StatusCode::Conflict:
    case StatusCode::StaleGeneration:
    case StatusCode::SupersededGeneration:
    case StatusCode::Indeterminate:
    case StatusCode::Unknown:
    case StatusCode::Unsupported:
    case StatusCode::UnsupportedFormatVersion:
    case StatusCode::Unauthorized:
    case StatusCode::ScopeNotGranted:
    case StatusCode::GrantExpired:
    case StatusCode::GrantRevoked:
    case StatusCode::GrantNotYetValid:
    case StatusCode::GenerationFenced:
    case StatusCode::PreconditionFailed:
    case StatusCode::GateClosed:
    case StatusCode::ObligationRejected:
    case StatusCode::IoError:
    case StatusCode::PermissionDenied:
    case StatusCode::Locked:
    case StatusCode::WriterExists:
    case StatusCode::LockLost:
    case StatusCode::PathInvalid:
    case StatusCode::LimitExceeded:
    case StatusCode::CapacityExhausted:
    case StatusCode::InvalidState:
    case StatusCode::Closed:
    case StatusCode::NotOpen:
    case StatusCode::Cancelled:
    case StatusCode::ShuttingDown:
    case StatusCode::Exhausted:
      return false;
  }
  // An unrecognised code is not evidence of damaged durable state.
  return false;
}

Status::Status(StatusCode code, std::string message)
    : code_(code), message_(std::move(message)) {}

std::string Status::to_string() const {
  if (ok()) {
    return "ok";
  }
  std::string rendered(scp::to_string(code_));
  if (!message_.empty()) {
    rendered += ": ";
    rendered += message_;
  }
  return rendered;
}

Status fail(StatusCode code, std::string message) { return Status(code, std::move(message)); }

}  // namespace scp
