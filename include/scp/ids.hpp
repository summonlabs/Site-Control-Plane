// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "scp/status.hpp"

/// \file ids.hpp
/// Stable identities and explicit generation/epoch counters.
///
/// Every authoritative object class has its own type. A SiteId is not an
/// EvidenceId, a Generation is not a Sequence, and none of them convert
/// implicitly: mixing them is a compile error rather than a production defect.

namespace scp {

/// 128-bit opaque identity, unique per object class.
template <class Tag>
class OpaqueId {
 public:
  constexpr OpaqueId() noexcept = default;
  constexpr OpaqueId(std::uint64_t high, std::uint64_t low) noexcept
      : high_(high), low_(low) {}

  [[nodiscard]] constexpr std::uint64_t high() const noexcept { return high_; }
  [[nodiscard]] constexpr std::uint64_t low() const noexcept { return low_; }
  [[nodiscard]] constexpr bool is_nil() const noexcept { return high_ == 0 && low_ == 0; }

  /// Lowercase hex, 32 characters, no separators.
  [[nodiscard]] std::string to_hex() const;

  /// Accepts 32 hex characters, optionally with a leading "0x".
  [[nodiscard]] static Result<OpaqueId> parse(std::string_view text);

  friend constexpr bool operator==(const OpaqueId&, const OpaqueId&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const OpaqueId& lhs,
                                                    const OpaqueId& rhs) noexcept {
    if (lhs.high_ != rhs.high_) {
      return lhs.high_ < rhs.high_ ? std::strong_ordering::less : std::strong_ordering::greater;
    }
    if (lhs.low_ != rhs.low_) {
      return lhs.low_ < rhs.low_ ? std::strong_ordering::less : std::strong_ordering::greater;
    }
    return std::strong_ordering::equal;
  }

 private:
  std::uint64_t high_ = 0;
  std::uint64_t low_ = 0;
};

/// Monotonic counter. Zero means "not set"; authoritative generations start at 1.
template <class Tag>
class Counter {
 public:
  constexpr Counter() noexcept = default;
  explicit constexpr Counter(std::uint64_t value) noexcept : value_(value) {}

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_unset() const noexcept { return value_ == 0; }

  /// Checked successor; refuses to wrap past the maximum.
  [[nodiscard]] Result<Counter> next() const;

  [[nodiscard]] static constexpr Counter first() noexcept { return Counter(1); }

  friend constexpr bool operator==(const Counter&, const Counter&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const Counter& lhs,
                                                    const Counter& rhs) noexcept {
    if (lhs.value_ == rhs.value_) {
      return std::strong_ordering::equal;
    }
    return lhs.value_ < rhs.value_ ? std::strong_ordering::less : std::strong_ordering::greater;
  }

 private:
  std::uint64_t value_ = 0;
};

struct SiteIdTag {};
struct SourceInstanceIdTag {};
struct EvidenceIdTag {};
struct SnapshotIdTag {};
struct GrantIdTag {};
struct RequestIdTag {};
struct PlanIdTag {};
struct ObligationIdTag {};
struct ConstraintIdTag {};
struct TransactionIdTag {};

using SiteId = OpaqueId<SiteIdTag>;
using SourceInstanceId = OpaqueId<SourceInstanceIdTag>;
using EvidenceId = OpaqueId<EvidenceIdTag>;
using SnapshotId = OpaqueId<SnapshotIdTag>;
using GrantId = OpaqueId<GrantIdTag>;
using RequestId = OpaqueId<RequestIdTag>;
using PlanId = OpaqueId<PlanIdTag>;
using ObligationId = OpaqueId<ObligationIdTag>;
using ConstraintId = OpaqueId<ConstraintIdTag>;
using TransactionId = OpaqueId<TransactionIdTag>;

/// Identity under which a retry is recognised as the same request.
using IdempotencyKey = OpaqueId<RequestIdTag>;

struct SiteGenerationTag {};
struct FacilityStateGenerationTag {};
struct PolicyGenerationTag {};
struct CapacityGenerationTag {};
struct SourceGenerationTag {};
struct EpochTag {};
struct SequenceTag {};
struct JournalSequenceTag {};
struct RevisionTag {};

/// Site/control-plane generation: the authority generation of this boundary.
using SiteGeneration = Counter<SiteGenerationTag>;
/// Generation of the facility-state picture a lower runtime published.
using FacilityStateGeneration = Counter<FacilityStateGenerationTag>;
/// Generation of the policy rule set a lower runtime published.
using PolicyGeneration = Counter<PolicyGenerationTag>;
/// Generation of a capacity accounting pass.
using CapacityGeneration = Counter<CapacityGenerationTag>;
/// Generation of one evidence-emitting runtime instance.
using SourceGeneration = Counter<SourceGenerationTag>;
/// Fencing epoch of an evidence source; a new epoch retires the previous one.
using Epoch = Counter<EpochTag>;
/// Monotonic sequence within one (instance, epoch) pair.
using Sequence = Counter<SequenceTag>;
/// Position in the durable journal.
using JournalSequence = Counter<JournalSequenceTag>;
/// Revision of a mutable in-memory record.
using Revision = Counter<RevisionTag>;

/// Deterministic identity derivation, used where a stable id must be derived
/// from content rather than assigned. Never uses randomness or wall-clock time.
[[nodiscard]] EvidenceId evidence_id_from(std::uint64_t high, std::uint64_t low);
[[nodiscard]] RequestId request_id_from(std::uint64_t high, std::uint64_t low);

/// Generates identities from an explicit seed so that tests, benchmarks and
/// reproductions are byte-for-byte repeatable.
class DeterministicIdSource {
 public:
  explicit DeterministicIdSource(std::uint64_t seed) noexcept : state_(seed | 1ULL) {}

  [[nodiscard]] std::uint64_t next_word() noexcept;
  [[nodiscard]] SiteId next_site() noexcept;
  [[nodiscard]] EvidenceId next_evidence() noexcept;
  [[nodiscard]] SourceInstanceId next_instance() noexcept;
  [[nodiscard]] RequestId next_request() noexcept;
  [[nodiscard]] PlanId next_plan() noexcept;
  [[nodiscard]] GrantId next_grant() noexcept;
  [[nodiscard]] SnapshotId next_snapshot() noexcept;
  [[nodiscard]] ObligationId next_obligation() noexcept;

 private:
  std::uint64_t state_;
};

}  // namespace scp

namespace std {

template <class Tag>
struct hash<scp::OpaqueId<Tag>> {
  [[nodiscard]] std::size_t operator()(const scp::OpaqueId<Tag>& id) const noexcept {
    const std::uint64_t mixed = id.high() * 0x9E3779B97F4A7C15ULL + id.low();
    return static_cast<std::size_t>(mixed ^ (mixed >> 32U));
  }
};

template <class Tag>
struct hash<scp::Counter<Tag>> {
  [[nodiscard]] std::size_t operator()(const scp::Counter<Tag>& counter) const noexcept {
    return static_cast<std::size_t>(counter.value());
  }
};

}  // namespace std
