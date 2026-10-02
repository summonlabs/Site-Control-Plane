// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/digest.hpp"
#include "scp/ids.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"
#include "scp/version.hpp"

/// \file evidence.hpp
/// The evidence ingestion and provenance layer.
///
/// The Site Control Plane owns exactly one thing: the site-level picture. Every
/// fact about capacity, power, cooling, policy, incidents, maintenance,
/// accelerators and fabric is *evidence* published by the runtime that owns it.
/// This layer records who said it, under which epoch and generation, how fresh
/// it was, and what it hashes to. It never upgrades evidence into authority, and
/// it never invents a value the publisher did not state.

namespace scp {

/// The runtime that owns a fact and is therefore its only legitimate publisher.
/// Every entry names a real DCCP boundary; none of them are this one, because
/// the Site Control Plane publishes no lower-domain facts.
enum class SourceAuthority : std::uint8_t {
  FacilityStateLedger = 1,
  FacilityCapacity = 2,
  PowerControlPlane = 3,
  ThermalControlPlane = 4,
  FacilityPolicyEngine = 5,
  IncidentStateFabric = 6,
  MaintenanceCoordinator = 7,
  AsiRuntime = 8,
  DfiRuntime = 9,
  ServiceClassRegistry = 10,
};

inline constexpr std::size_t kSourceAuthorityCount = 10;

[[nodiscard]] std::string_view to_string(SourceAuthority authority) noexcept;
[[nodiscard]] Result<SourceAuthority> source_authority_from_string(std::string_view text);

/// The shape of a piece of evidence.
enum class EvidenceKind : std::uint16_t {
  FacilityState = 1,
  Lifecycle = 2,
  Capacity = 3,
  PowerReadiness = 4,
  CoolingReadiness = 5,
  Policy = 6,
  Incident = 7,
  Maintenance = 8,
  AsiCapability = 9,
  DfiCapability = 10,
  ServiceClass = 11,
};

inline constexpr std::size_t kEvidenceKindCount = 11;

[[nodiscard]] std::string_view to_string(EvidenceKind kind) noexcept;
[[nodiscard]] Result<EvidenceKind> evidence_kind_from_string(std::string_view text);

/// True when \p authority is the boundary that owns \p kind. Evidence published
/// by a runtime that does not own the fact is rejected, not reinterpreted.
[[nodiscard]] bool is_authorized_publisher(SourceAuthority authority, EvidenceKind kind) noexcept;

/// The authority that owns \p kind. Every kind in this schema version has
/// exactly one owner, because "the runtime that owns the fact publishes the
/// fact" is the whole point of the DCCP split.
[[nodiscard]] SourceAuthority owner_of(EvidenceKind kind) noexcept;

/// True when exactly one authority owns \p kind in this schema version.
[[nodiscard]] bool has_sole_owner(EvidenceKind kind) noexcept;

enum class LifecycleState : std::uint8_t {
  Commissioning = 1,
  Active = 2,
  Draining = 3,
  Maintenance = 4,
  Emergency = 5,
  Recovering = 6,
  Isolated = 7,
  Retired = 8,
};

[[nodiscard]] std::string_view to_string(LifecycleState state) noexcept;
[[nodiscard]] Result<LifecycleState> lifecycle_state_from_string(std::string_view text);

enum class Severity : std::uint8_t {
  None = 0,
  Informational = 1,
  Minor = 2,
  Major = 3,
  Critical = 4,
};

[[nodiscard]] std::string_view to_string(Severity severity) noexcept;

enum class ReadinessLevel : std::uint8_t {
  Unknown = 0,
  Unavailable = 1,
  Degraded = 2,
  Constrained = 3,
  Ready = 4,
};

[[nodiscard]] std::string_view to_string(ReadinessLevel level) noexcept;

enum class MaintenanceMode : std::uint8_t {
  None = 0,
  Planned = 1,
  Emergency = 2,
  Overdue = 3,
};

[[nodiscard]] std::string_view to_string(MaintenanceMode mode) noexcept;

/// Where a record entered the runtime's accepted evidence set. Recovered
/// evidence is not the same thing as freshly revalidated evidence, and the
/// distinction survives into the composed snapshot.
enum class EvidenceOrigin : std::uint8_t {
  Ingested = 1,
  RecoveredFromJournal = 2,
  Revalidated = 3,
};

[[nodiscard]] std::string_view to_string(EvidenceOrigin origin) noexcept;

/// How much trust the *time* dimension of a record still carries.
enum class Freshness : std::uint8_t {
  Fresh = 1,
  Stale = 2,
  Expired = 3,
  Indeterminate = 4,
};

[[nodiscard]] std::string_view to_string(Freshness freshness) noexcept;

/// Provenance of one published fact. \c body_digest is filled by
/// \c EvidenceRecord::create and is covered by the record identity.
struct Provenance {
  SourceAuthority authority = SourceAuthority::FacilityStateLedger;
  SourceInstanceId instance{};
  Epoch epoch{};
  SourceGeneration generation{};
  Sequence sequence{};
  Timestamp issued_at{};
  /// Zero means "the publisher stated no expiry".
  Timestamp valid_until{};
  /// SHA-256 of the canonical body bytes.
  Digest body_digest{};

  friend bool operator==(const Provenance&, const Provenance&) noexcept = default;
};

/// Typed evidence bodies.
struct FacilityStateEvidence {
  FacilityStateGeneration generation{};
  Severity worst_active_severity = Severity::None;
  std::uint32_t active_incidents = 0;
  bool degraded_operation = false;
  bool emergency_declared = false;
  Digest topology_digest{};
};

/// Where the site sits in its lifecycle, as published by the boundary that
/// drives lifecycle transitions. This plane consumes the position; it does not
/// move the site through its lifecycle by publishing this evidence itself.
struct LifecycleEvidence {
  LifecycleState state = LifecycleState::Commissioning;
  Timestamp entered_at{};
  bool transition_in_progress = false;
  Digest transition_digest{};
};

struct CapacityEvidence {
  SnapshotId snapshot{};
  CapacityGeneration generation{};
  std::uint64_t total_units = 0;
  std::uint64_t committed_units = 0;
  std::uint64_t available_units = 0;
  bool oversubscribed = false;
};

/// Shared shape of the power and cooling readiness publications. Which domain it
/// describes is carried by \c EvidenceKind, not by an in-band string.
struct ReadinessEvidence {
  SnapshotId snapshot{};
  ReadinessLevel readiness = ReadinessLevel::Unknown;
  /// Integer milli-kilowatts; the runtime never uses floating point for a
  /// quantity that participates in a decision.
  std::uint64_t headroom_milli_kw = 0;
  std::uint32_t available_domains = 0;
  std::uint32_t required_domains = 0;
};

struct PolicyEvidence {
  PolicyGeneration generation{};
  Digest rules_digest{};
  std::uint32_t rule_count = 0;
};

struct IncidentEvidence {
  std::uint32_t active_incidents = 0;
  Severity worst_active_severity = Severity::None;
  bool emergency_declared = false;
  Timestamp earliest_active{};
  std::uint32_t suppressed_incidents = 0;
};

struct MaintenanceEvidence {
  MaintenanceMode mode = MaintenanceMode::None;
  std::uint32_t active_windows = 0;
  std::uint32_t scheduled_windows = 0;
  Timestamp next_window_start{};
  bool drain_in_progress = false;
  /// Whole percent of the site that has finished draining, 0..100.
  std::uint32_t drained_percent = 0;
};

/// Capability and readiness of a lower execution domain (accelerators, fabric).
struct CapabilityEvidence {
  ReadinessLevel readiness = ReadinessLevel::Unknown;
  std::uint32_t ready_domains = 0;
  std::uint32_t total_domains = 0;
  std::uint64_t ready_units = 0;
  Digest capability_digest{};
};

/// A site-level service obligation declared by the service class registry.
struct ServiceClassObligation {
  Name service_class{};
  bool protected_class = false;
  std::uint32_t minimum_ready_units = 0;
  std::uint32_t minimum_readiness_percent = 0;

  friend bool operator==(const ServiceClassObligation&, const ServiceClassObligation&) noexcept =
      default;
};

inline constexpr std::size_t kMaxServiceClasses = 64;

struct ServiceClassEvidence {
  std::uint32_t class_count = 0;
  Digest obligations_digest{};
  std::vector<ServiceClassObligation> obligations;

  friend bool operator==(const ServiceClassEvidence&, const ServiceClassEvidence&) noexcept =
      default;
};

using EvidenceBody = std::variant<FacilityStateEvidence, LifecycleEvidence, CapacityEvidence,
                                  ReadinessEvidence, PolicyEvidence, IncidentEvidence,
                                  MaintenanceEvidence, CapabilityEvidence, ServiceClassEvidence>;

/// Evidence as it travels: provenance plus an opaque, self-describing body.
///
/// The body is kept in its published encoding. A build that does not understand
/// a schema preserves the bytes and reports the record as unsupported instead of
/// discarding it or guessing.
struct EvidenceRecord {
  EvidenceId id{};
  Provenance provenance{};
  EvidenceKind kind = EvidenceKind::FacilityState;
  std::uint16_t schema_version = kEvidenceSchemaVersion;
  std::vector<std::uint8_t> body;
  EvidenceOrigin origin = EvidenceOrigin::Ingested;
  /// Set when this record was revalidated after recovery; zero otherwise.
  Timestamp revalidated_at{};

  /// Builds a record, computing the body digest and the content-addressed
  /// identity. The identity is derived, never random, so the same logical fact
  /// published twice is the same record and deduplicates exactly.
  [[nodiscard]] static Result<EvidenceRecord> create(Provenance provenance, EvidenceKind kind,
                                                     std::uint16_t schema_version,
                                                     std::vector<std::uint8_t> body);

  /// Builds a record from a typed payload.
  [[nodiscard]] static Result<EvidenceRecord> create(Provenance provenance, EvidenceKind kind,
                                                     const EvidenceBody& payload);

  /// Recomputes the digest of \c body and reports whether it matches the
  /// recorded provenance digest.
  [[nodiscard]] Result<bool> verify_body_digest() const;

  /// Recomputes the derived identity and reports whether it matches \c id.
  [[nodiscard]] Result<bool> verify_identity() const;

  /// Structural validation only: identity present, generation and sequence set,
  /// body within bounds, publisher authorized for the kind, schema understood.
  [[nodiscard]] Status validate() const;

  /// Canonical bytes of the whole record, used for chaining and for hashing the
  /// accepted evidence set.
  [[nodiscard]] std::vector<std::uint8_t> canonical_bytes() const;
};

/// Canonical encoding of a typed body. The encoding is independent of the kind,
/// so the same struct always produces the same bytes.
[[nodiscard]] Result<std::vector<std::uint8_t>> encode_body(const EvidenceBody& body);

/// Decodes \p body according to \p kind and \p schema_version. An unknown schema
/// version yields Unsupported rather than a best-effort interpretation.
[[nodiscard]] Result<EvidenceBody> decode_body(EvidenceKind kind, std::uint16_t schema_version,
                                               std::span<const std::uint8_t> body);

/// Canonical serialization of a typed body, used by the digest above.
void canonical_write(CanonicalWriter& writer, const Provenance& value);
void canonical_write(CanonicalWriter& writer, const FacilityStateEvidence& value);
void canonical_write(CanonicalWriter& writer, const LifecycleEvidence& value);
void canonical_write(CanonicalWriter& writer, const EvidenceRecord& value);
/// Reads one canonical evidence record. The reader stops exactly at the end of
/// the record and does NOT consume or reject what follows, because a record is
/// also read from inside larger containers such as a journal operation. A caller
/// that expects the record to be the whole input must call
/// \c CanonicalReader::expect_end itself.
[[nodiscard]] Result<EvidenceRecord> canonical_read_evidence(CanonicalReader& reader);
[[nodiscard]] Result<EvidenceId> derive_evidence_id(const Provenance& provenance, EvidenceKind kind,
                                                    std::uint16_t schema_version,
                                                    std::span<const std::uint8_t> body);
void canonical_write(CanonicalWriter& writer, const CapacityEvidence& value);
void canonical_write(CanonicalWriter& writer, const ReadinessEvidence& value);
void canonical_write(CanonicalWriter& writer, const PolicyEvidence& value);
void canonical_write(CanonicalWriter& writer, const IncidentEvidence& value);
void canonical_write(CanonicalWriter& writer, const MaintenanceEvidence& value);
void canonical_write(CanonicalWriter& writer, const CapabilityEvidence& value);
void canonical_write(CanonicalWriter& writer, const ServiceClassEvidence& value);

/// The evidence slot a record fills: one authority publishing one kind.
struct EvidenceSlot {
  SourceAuthority authority = SourceAuthority::FacilityStateLedger;
  EvidenceKind kind = EvidenceKind::FacilityState;

  friend bool operator==(const EvidenceSlot&, const EvidenceSlot&) noexcept = default;
  friend bool operator<(const EvidenceSlot& lhs, const EvidenceSlot& rhs) noexcept {
    if (lhs.authority != rhs.authority) {
      return static_cast<std::uint8_t>(lhs.authority) < static_cast<std::uint8_t>(rhs.authority);
    }
    return static_cast<std::uint16_t>(lhs.kind) < static_cast<std::uint16_t>(rhs.kind);
  }
};

[[nodiscard]] EvidenceSlot slot_of(const EvidenceRecord& record) noexcept;

/// Bounds applied to any evidence set the runtime will hold or accept.
inline constexpr std::size_t kMaxEvidenceRecordsPerIngest = 4096;
inline constexpr std::size_t kMaxAcceptedEvidenceRecords = 65536;

/// Freshness thresholds, supplied by the caller so that freshness is a policy
/// decision rather than a hidden constant.
struct FreshnessPolicy {
  /// Age beyond which a record with no stated expiry is Stale.
  Duration stale_after = seconds(900);
  /// Age beyond which a record with no stated expiry is Expired.
  Duration expire_after = seconds(3600);
  /// Records recovered from the journal may be allowed to age further, because
  /// their provenance is durable rather than merely recent.
  bool recovered_ages_out = true;

  friend bool operator==(const FreshnessPolicy&, const FreshnessPolicy&) noexcept = default;
};

/// Classifies the time-trust of one record at \p evaluation_time.
[[nodiscard]] Freshness classify_freshness(const EvidenceRecord& record,
                                           Timestamp evaluation_time,
                                           const FreshnessPolicy& policy);

/// True when the classification permits the record to participate in decisions.
[[nodiscard]] bool participates(Freshness freshness) noexcept;

}  // namespace scp
