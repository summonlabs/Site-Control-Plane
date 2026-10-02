// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"

/// \file site_state.hpp
/// The authoritative site-level view.
///
/// A snapshot is the composed answer to "what is this site, right now, given
/// exactly this evidence". It is a value: copying it, hashing it and comparing it
/// are all meaningful, and two runs over equivalent evidence produce equal bytes.

namespace scp {

/// The site operating state owned by this boundary.
///
/// Unknown and Conflicting are first-class states, not error paths. Unknown means
/// evidence is missing or unusable; Conflicting means publishers disagree and the
/// site plane refuses to pick a winner by arrival order.
enum class SiteState : std::uint8_t {
  Unknown = 0,
  Conflicting = 1,
  Commissioning = 2,
  Available = 3,
  Constrained = 4,
  Degraded = 5,
  Draining = 6,
  Maintenance = 7,
  Emergency = 8,
  Recovering = 9,
  Isolated = 10,
  Retired = 11,
};

inline constexpr std::size_t kSiteStateCount = 12;

[[nodiscard]] std::string_view to_string(SiteState state) noexcept;
[[nodiscard]] Result<SiteState> site_state_from_string(std::string_view text);

/// True when the state permits the site to take on new service obligations
/// directly; gating still decides formally, this is the coarse classification.
[[nodiscard]] bool admits_new_obligations(SiteState state) noexcept;

/// True when the state means "no authoritative answer" rather than a real
/// operating condition.
[[nodiscard]] bool is_indeterminate(SiteState state) noexcept;

enum class ConstraintKind : std::uint8_t {
  EvidenceIncomplete = 1,
  EvidenceConflicting = 2,
  EvidenceStale = 3,
  EvidenceUnsupported = 4,
  EvidenceUnauthorized = 5,
  CapacityHeadroomLow = 6,
  CapacityExhausted = 7,
  CapacityOversubscribed = 8,
  PowerReadinessConstrained = 9,
  PowerReadinessDegraded = 10,
  PowerReadinessUnavailable = 11,
  CoolingReadinessConstrained = 12,
  CoolingReadinessDegraded = 13,
  CoolingReadinessUnavailable = 14,
  RedundancyReduced = 15,
  AsiReadinessDegraded = 16,
  AsiReadinessUnavailable = 17,
  DfiReadinessDegraded = 18,
  DfiReadinessUnavailable = 19,
  ActiveIncidents = 20,
  CriticalIncidents = 21,
  EmergencyDeclared = 22,
  DegradedOperation = 23,
  MaintenanceActive = 24,
  MaintenanceScheduled = 25,
  MaintenanceOverdue = 26,
  DrainInProgress = 27,
  ObligationAtRisk = 28,
  ObligationUnsatisfied = 29,
  AsiReadinessConstrained = 30,
  DfiReadinessConstrained = 31,
};

inline constexpr std::size_t kConstraintKindCount = 31;

[[nodiscard]] std::string_view to_string(ConstraintKind kind) noexcept;

/// One active site-level constraint, with the evidence that produced it so the
/// constraint can be re-derived rather than taken on faith.
struct Constraint {
  ConstraintId id{};
  ConstraintKind kind = ConstraintKind::EvidenceIncomplete;
  Severity severity = Severity::None;
  /// True when the constraint forbids accepting new obligations outright.
  bool blocking = false;
  /// Short, bounded subject: a domain, service class or evidence slot name.
  std::string subject;
  std::string detail;
  /// Slot that produced the constraint. Nil when the constraint is about the
  /// evidence set as a whole.
  EvidenceSlot source{};
  Digest source_digest{};

  friend bool operator==(const Constraint&, const Constraint&) noexcept = default;
  friend bool operator<(const Constraint& lhs, const Constraint& rhs) noexcept {
    if (lhs.kind != rhs.kind) {
      return static_cast<std::uint8_t>(lhs.kind) < static_cast<std::uint8_t>(rhs.kind);
    }
    if (lhs.subject != rhs.subject) {
      return lhs.subject < rhs.subject;
    }
    return lhs.id < rhs.id;
  }
};

/// What happened to one evidence slot during reduction.
enum class SlotOutcome : std::uint8_t {
  Missing = 0,
  Accepted = 1,
  AcceptedSuperseding = 2,
  Superseded = 3,
  Conflicting = 4,
  Stale = 5,
  Expired = 6,
  Unsupported = 7,
  Unauthorized = 8,
  Indeterminate = 9,
};

[[nodiscard]] std::string_view to_string(SlotOutcome outcome) noexcept;

/// The resolution of one (authority, kind) slot. Lower generations are recorded
/// as superseded rather than dropped, so an operator can see that newer truth
/// existed and older truth lost.
struct SlotResolution {
  EvidenceSlot slot{};
  SlotOutcome outcome = SlotOutcome::Missing;
  EvidenceId accepted_id{};
  Digest accepted_digest{};
  SourceInstanceId accepted_instance{};
  Epoch accepted_epoch{};
  SourceGeneration accepted_generation{};
  Sequence accepted_sequence{};
  Freshness freshness = Freshness::Indeterminate;
  EvidenceOrigin origin = EvidenceOrigin::Ingested;
  std::vector<EvidenceId> superseded;
  std::vector<EvidenceId> conflicting;
  std::size_t duplicates_merged = 0;
  std::string detail;

  [[nodiscard]] bool accepted() const noexcept {
    return outcome == SlotOutcome::Accepted || outcome == SlotOutcome::AcceptedSuperseding;
  }
};

/// Quality of the evidence set behind a snapshot. These are not interchangeable:
/// Stale means the picture is old, Conflicting means publishers disagree, and
/// Unsupported means a publisher used a schema this build cannot read.
enum class EvidenceClassification : std::uint8_t {
  Complete = 1,
  Partial = 2,
  Stale = 3,
  Conflicting = 4,
  Unsupported = 5,
  Indeterminate = 6,
};

[[nodiscard]] std::string_view to_string(EvidenceClassification classification) noexcept;

enum class ObligationOutcome : std::uint8_t {
  Satisfied = 1,
  AtRisk = 2,
  Unsatisfied = 3,
  Unknown = 4,
};

[[nodiscard]] std::string_view to_string(ObligationOutcome outcome) noexcept;

/// Assessment of one declared service obligation against the composed site.
struct ObligationAssessment {
  ObligationId id{};
  Name service_class{};
  bool protected_class = false;
  ObligationOutcome outcome = ObligationOutcome::Unknown;
  std::uint64_t required_units = 0;
  std::uint64_t ready_units = 0;
  std::uint32_t required_readiness_percent = 0;
  std::uint32_t observed_readiness_percent = 0;
  std::string detail;

  friend bool operator<(const ObligationAssessment& lhs,
                        const ObligationAssessment& rhs) noexcept {
    return lhs.id < rhs.id;
  }
};

struct ReadinessGate;

/// Readiness of one dependency domain, as observed. \c observed is false when no
/// publisher stated a value: an unobserved domain is reported as unobserved, not
/// as zero and not as healthy.
struct DomainReadiness {
  std::string domain;
  std::uint32_t percent = 0;
  bool observed = false;
  ReadinessLevel level = ReadinessLevel::Unknown;

  friend bool operator<(const DomainReadiness& lhs, const DomainReadiness& rhs) noexcept {
    return lhs.domain < rhs.domain;
  }
};

/// The typed values extracted from the accepted evidence, carried inside the
/// snapshot so a gate or a plan can be evaluated from the snapshot alone. The
/// view is a pure function of the accepted records, whose identities and body
/// digests are recorded in the slot resolutions.
struct SiteEvidenceView {
  std::optional<FacilityStateEvidence> facility_state;
  std::optional<LifecycleEvidence> lifecycle;
  std::optional<CapacityEvidence> capacity;
  std::optional<ReadinessEvidence> power;
  std::optional<ReadinessEvidence> cooling;
  std::optional<PolicyEvidence> policy;
  std::optional<IncidentEvidence> incident;
  std::optional<MaintenanceEvidence> maintenance;
  std::optional<CapabilityEvidence> asi;
  std::optional<CapabilityEvidence> dfi;
  std::optional<ServiceClassEvidence> service_class;

  [[nodiscard]] std::size_t populated_count() const noexcept;
};

/// The composed site-level picture.
struct SiteStateSnapshot {
  SiteId site{};
  SiteGeneration site_generation{};
  /// Instant at which freshness was judged.
  Timestamp evaluation_time{};
  /// Instant at which composition ran. Never used for freshness, only reporting.
  Timestamp composed_at{};
  SiteState state = SiteState::Unknown;
  LifecycleState lifecycle = LifecycleState::Commissioning;
  EvidenceClassification classification = EvidenceClassification::Indeterminate;
  std::vector<SlotResolution> slots;
  std::vector<Constraint> constraints;
  std::vector<ReadinessGate> gates;
  std::vector<ObligationAssessment> obligations;
  std::vector<DomainReadiness> readiness_domains;
  /// Minimum observed domain readiness, in percent. Zero when no domain reported
  /// a value, which is honest: no domain observed means no readiness is claimed.
  std::uint32_t readiness_percent = 0;
  SiteEvidenceView evidence{};
  /// Digest of the accepted evidence set, in canonical slot order.
  Digest evidence_digest{};
  /// Digest of the site policy the snapshot was composed under, so a snapshot is
  /// self-describing about the thresholds that produced it.
  Digest policy_digest{};
  /// Digest of this snapshot. Equal for two snapshots over equivalent evidence
  /// evaluated at the same instant against the same policy.
  Digest snapshot_digest{};

  [[nodiscard]] const SlotResolution* find_slot(EvidenceSlot slot) const noexcept;
  [[nodiscard]] bool has_constraint(ConstraintKind kind) const noexcept;
  [[nodiscard]] std::size_t blocking_constraint_count() const noexcept;
};

/// Canonical encoding of a snapshot. Deterministic and platform independent;
/// ordering of every contained sequence is fixed by the composition engine.
void canonical_write(CanonicalWriter& writer, const SlotResolution& value);
void canonical_write(CanonicalWriter& writer, const Constraint& value);
void canonical_write(CanonicalWriter& writer, const ObligationAssessment& value);
void canonical_write(CanonicalWriter& writer, const DomainReadiness& value);

[[nodiscard]] Result<SlotResolution> canonical_read_slot_resolution(CanonicalReader& reader);
[[nodiscard]] Result<Constraint> canonical_read_constraint(CanonicalReader& reader);
[[nodiscard]] Result<ObligationAssessment> canonical_read_obligation(CanonicalReader& reader);

/// Canonical encoding of a whole snapshot. The reported composition instant is
/// deliberately excluded: it is reporting metadata, not authoritative content,
/// so two runs over equivalent evidence at the same evaluation instant produce
/// the same digest even if they ran at different wall-clock times.
void canonical_write(CanonicalWriter& writer, const SiteStateSnapshot& value);

/// Recomputes the digest a snapshot should carry. Used by tests, by the CLI and
/// by any consumer that wants to verify a snapshot it did not compose.
[[nodiscard]] Digest compute_snapshot_digest(const SiteStateSnapshot& snapshot);
[[nodiscard]] Digest compute_evidence_digest(std::span<const SlotResolution> slots);

/// A bounded, deterministic derivation of a constraint identity from its kind and
/// subject so that repeated composition yields byte-identical snapshots.
[[nodiscard]] ConstraintId constraint_id_for(ConstraintKind kind, std::string_view subject);
[[nodiscard]] ObligationId obligation_id_for(std::string_view service_class);

/// The metric names a configured ThresholdRule may reference. A policy that
/// names any other metric is rejected by SitePolicy::validate, so a rule can
/// never silently fail to apply.
inline constexpr std::string_view kMetricCapacityHeadroomPercent = "capacity-headroom-percent";
inline constexpr std::string_view kMetricAvailableCapacityUnits = "available-capacity-units";
inline constexpr std::string_view kMetricPowerHeadroomMilliKw = "power-headroom-milli-kw";
inline constexpr std::string_view kMetricCoolingHeadroomMilliKw = "cooling-headroom-milli-kw";
inline constexpr std::string_view kMetricPowerRedundancyAvailable = "power-redundancy-available";
inline constexpr std::string_view kMetricCoolingRedundancyAvailable = "cooling-redundancy-available";
inline constexpr std::string_view kMetricReadinessPercent = "readiness-percent";
inline constexpr std::string_view kMetricAsiReadinessPercent = "asi-readiness-percent";
inline constexpr std::string_view kMetricDfiReadinessPercent = "dfi-readiness-percent";
inline constexpr std::string_view kMetricActiveIncidents = "active-incidents";
inline constexpr std::string_view kMetricActiveMaintenanceWindows = "active-maintenance-windows";
inline constexpr std::string_view kMetricDrainedPercent = "drained-percent";

/// True when \p name is one of the metric names above.
[[nodiscard]] bool is_known_metric(std::string_view name) noexcept;

/// Reads the named metric out of a snapshot. Returns std::nullopt when the
/// evidence needed to compute it is absent; a missing metric is never treated as
/// zero.
[[nodiscard]] std::optional<std::uint64_t> metric_value(const SiteStateSnapshot& snapshot,
                                                        std::string_view name) noexcept;

}  // namespace scp
