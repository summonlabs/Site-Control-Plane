// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/site_state.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "scp/readiness.hpp"

namespace scp {
namespace {

void write_id(CanonicalWriter& writer, std::uint64_t high, std::uint64_t low) {
  writer.u64(high);
  writer.u64(low);
}

void write_digest(CanonicalWriter& writer, const Digest& digest) {
  writer.bytes(std::span<const std::uint8_t>(digest.bytes().data(), digest.bytes().size()));
}

/// Derives a 128-bit identity from a digest of the given canonical content.
template <class Fn>
ConstraintId identity_from_content(Fn&& write_content) {
  CanonicalWriter writer;
  write_content(writer);
  const Digest digest = Digest::of(writer.span());
  const auto& bytes = digest.bytes();
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    high = (high << 8U) | bytes[index];
    low = (low << 8U) | bytes[index + 8];
  }
  return ConstraintId(high, low);
}

}  // namespace

std::string_view to_string(SiteState state) noexcept {
  switch (state) {
    case SiteState::Unknown: return "unknown";
    case SiteState::Conflicting: return "conflicting";
    case SiteState::Commissioning: return "commissioning";
    case SiteState::Available: return "available";
    case SiteState::Constrained: return "constrained";
    case SiteState::Degraded: return "degraded";
    case SiteState::Draining: return "draining";
    case SiteState::Maintenance: return "maintenance";
    case SiteState::Emergency: return "emergency";
    case SiteState::Recovering: return "recovering";
    case SiteState::Isolated: return "isolated";
    case SiteState::Retired: return "retired";
  }
  return "unknown";
}

Result<SiteState> site_state_from_string(std::string_view text) {
  constexpr std::array<SiteState, kSiteStateCount> kAll = {
      SiteState::Unknown,    SiteState::Conflicting, SiteState::Commissioning, SiteState::Available,
      SiteState::Constrained, SiteState::Degraded,    SiteState::Draining,      SiteState::Maintenance,
      SiteState::Emergency,  SiteState::Recovering,  SiteState::Isolated,      SiteState::Retired};
  for (const SiteState candidate : kAll) {
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return fail(StatusCode::InvalidArgument, "unrecognised site state: " + std::string(text));
}

bool admits_new_obligations(SiteState state) noexcept {
  switch (state) {
    case SiteState::Available:
    case SiteState::Constrained:
      return true;
    case SiteState::Unknown:
    case SiteState::Conflicting:
    case SiteState::Commissioning:
    case SiteState::Degraded:
    case SiteState::Draining:
    case SiteState::Maintenance:
    case SiteState::Emergency:
    case SiteState::Recovering:
    case SiteState::Isolated:
    case SiteState::Retired:
      return false;
  }
  return false;
}

bool is_indeterminate(SiteState state) noexcept {
  return state == SiteState::Unknown || state == SiteState::Conflicting;
}

std::string_view to_string(ConstraintKind kind) noexcept {
  switch (kind) {
    case ConstraintKind::EvidenceIncomplete: return "evidence-incomplete";
    case ConstraintKind::EvidenceConflicting: return "evidence-conflicting";
    case ConstraintKind::EvidenceStale: return "evidence-stale";
    case ConstraintKind::EvidenceUnsupported: return "evidence-unsupported";
    case ConstraintKind::EvidenceUnauthorized: return "evidence-unauthorized";
    case ConstraintKind::CapacityHeadroomLow: return "capacity-headroom-low";
    case ConstraintKind::CapacityExhausted: return "capacity-exhausted";
    case ConstraintKind::CapacityOversubscribed: return "capacity-oversubscribed";
    case ConstraintKind::PowerReadinessConstrained: return "power-readiness-constrained";
    case ConstraintKind::PowerReadinessDegraded: return "power-readiness-degraded";
    case ConstraintKind::PowerReadinessUnavailable: return "power-readiness-unavailable";
    case ConstraintKind::CoolingReadinessConstrained: return "cooling-readiness-constrained";
    case ConstraintKind::CoolingReadinessDegraded: return "cooling-readiness-degraded";
    case ConstraintKind::CoolingReadinessUnavailable: return "cooling-readiness-unavailable";
    case ConstraintKind::RedundancyReduced: return "redundancy-reduced";
    case ConstraintKind::AsiReadinessDegraded: return "asi-readiness-degraded";
    case ConstraintKind::AsiReadinessUnavailable: return "asi-readiness-unavailable";
    case ConstraintKind::DfiReadinessDegraded: return "dfi-readiness-degraded";
    case ConstraintKind::DfiReadinessUnavailable: return "dfi-readiness-unavailable";
    case ConstraintKind::ActiveIncidents: return "active-incidents";
    case ConstraintKind::CriticalIncidents: return "critical-incidents";
    case ConstraintKind::EmergencyDeclared: return "emergency-declared";
    case ConstraintKind::DegradedOperation: return "degraded-operation";
    case ConstraintKind::MaintenanceActive: return "maintenance-active";
    case ConstraintKind::MaintenanceScheduled: return "maintenance-scheduled";
    case ConstraintKind::MaintenanceOverdue: return "maintenance-overdue";
    case ConstraintKind::DrainInProgress: return "drain-in-progress";
    case ConstraintKind::ObligationAtRisk: return "obligation-at-risk";
    case ConstraintKind::ObligationUnsatisfied: return "obligation-unsatisfied";
    case ConstraintKind::AsiReadinessConstrained: return "asi-readiness-constrained";
    case ConstraintKind::DfiReadinessConstrained: return "dfi-readiness-constrained";
  }
  return "unknown-constraint";
}

std::string_view to_string(SlotOutcome outcome) noexcept {
  switch (outcome) {
    case SlotOutcome::Missing: return "missing";
    case SlotOutcome::Accepted: return "accepted";
    case SlotOutcome::AcceptedSuperseding: return "accepted-superseding";
    case SlotOutcome::Superseded: return "superseded";
    case SlotOutcome::Conflicting: return "conflicting";
    case SlotOutcome::Stale: return "stale";
    case SlotOutcome::Expired: return "expired";
    case SlotOutcome::Unsupported: return "unsupported";
    case SlotOutcome::Unauthorized: return "unauthorized";
    case SlotOutcome::Indeterminate: return "indeterminate";
  }
  return "unknown-outcome";
}

std::string_view to_string(EvidenceClassification classification) noexcept {
  switch (classification) {
    case EvidenceClassification::Complete: return "complete";
    case EvidenceClassification::Partial: return "partial";
    case EvidenceClassification::Stale: return "stale";
    case EvidenceClassification::Conflicting: return "conflicting";
    case EvidenceClassification::Unsupported: return "unsupported";
    case EvidenceClassification::Indeterminate: return "indeterminate";
  }
  return "unknown-classification";
}

std::string_view to_string(ObligationOutcome outcome) noexcept {
  switch (outcome) {
    case ObligationOutcome::Satisfied: return "satisfied";
    case ObligationOutcome::AtRisk: return "at-risk";
    case ObligationOutcome::Unsatisfied: return "unsatisfied";
    case ObligationOutcome::Unknown: return "unknown";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Snapshot queries
// ---------------------------------------------------------------------------

const SlotResolution* SiteStateSnapshot::find_slot(EvidenceSlot slot) const noexcept {
  for (const SlotResolution& resolution : slots) {
    if (resolution.slot == slot) {
      return &resolution;
    }
  }
  return nullptr;
}

bool SiteStateSnapshot::has_constraint(ConstraintKind kind) const noexcept {
  return std::any_of(constraints.begin(), constraints.end(),
                     [kind](const Constraint& constraint) { return constraint.kind == kind; });
}

std::size_t SiteStateSnapshot::blocking_constraint_count() const noexcept {
  return static_cast<std::size_t>(
      std::count_if(constraints.begin(), constraints.end(),
                    [](const Constraint& constraint) { return constraint.blocking; }));
}

// ---------------------------------------------------------------------------
// Canonical form and digests
// ---------------------------------------------------------------------------

// The per-record codecs (SlotResolution, Constraint, ObligationAssessment,
// GateCondition, ReadinessGate) live in journal_format.cpp so that every reader
// and its matching writer are defined side by side.

void canonical_write(CanonicalWriter& writer, const SiteStateSnapshot& value) {
  write_id(writer, value.site.high(), value.site.low());
  writer.u64(value.site_generation.value());
  writer.i64(value.evaluation_time.nanos);
  writer.u8(static_cast<std::uint8_t>(value.state));
  writer.u8(static_cast<std::uint8_t>(value.lifecycle));
  writer.u8(static_cast<std::uint8_t>(value.classification));
  write_digest(writer, value.policy_digest);
  write_digest(writer, value.evidence_digest);
  writer.u32(static_cast<std::uint32_t>(value.readiness_domains.size()));
  for (const DomainReadiness& domain : value.readiness_domains) {
    canonical_write(writer, domain);
  }
  writer.u32(value.readiness_percent);

  // The digest covers authoritative content only. Two things are deliberately
  // excluded, and both exclusions are load-bearing:
  //
  //   * free-text detail strings, which explain a resolution but do not define
  //     it, so a rewording can never change a snapshot's identity;
  //   * the duplicate-merge counter, because a batch that states the same
  //     logical fact twice is the same evidence as a batch that states it once,
  //     and equivalent evidence must compose to the same digest.
  writer.u32(static_cast<std::uint32_t>(value.slots.size()));
  for (const SlotResolution& resolution : value.slots) {
    writer.u8(static_cast<std::uint8_t>(resolution.slot.authority));
    writer.u16(static_cast<std::uint16_t>(resolution.slot.kind));
    writer.u8(static_cast<std::uint8_t>(resolution.outcome));
    write_id(writer, resolution.accepted_id.high(), resolution.accepted_id.low());
    write_digest(writer, resolution.accepted_digest);
    write_id(writer, resolution.accepted_instance.high(), resolution.accepted_instance.low());
    writer.u64(resolution.accepted_epoch.value());
    writer.u64(resolution.accepted_generation.value());
    writer.u64(resolution.accepted_sequence.value());
    writer.u8(static_cast<std::uint8_t>(resolution.freshness));
    writer.u8(static_cast<std::uint8_t>(resolution.origin));
    writer.u32(static_cast<std::uint32_t>(resolution.superseded.size()));
    for (const EvidenceId& id : resolution.superseded) {
      write_id(writer, id.high(), id.low());
    }
    writer.u32(static_cast<std::uint32_t>(resolution.conflicting.size()));
    for (const EvidenceId& id : resolution.conflicting) {
      write_id(writer, id.high(), id.low());
    }
  }

  std::vector<Constraint> ordered = value.constraints;
  std::sort(ordered.begin(), ordered.end());
  writer.u32(static_cast<std::uint32_t>(ordered.size()));
  for (const Constraint& constraint : ordered) {
    write_id(writer, constraint.id.high(), constraint.id.low());
    writer.u8(static_cast<std::uint8_t>(constraint.kind));
    writer.u8(static_cast<std::uint8_t>(constraint.severity));
    writer.boolean(constraint.blocking);
    writer.text(constraint.subject);
    writer.u8(static_cast<std::uint8_t>(constraint.source.authority));
    writer.u16(static_cast<std::uint16_t>(constraint.source.kind));
    write_digest(writer, constraint.source_digest);
  }

  writer.u32(static_cast<std::uint32_t>(value.gates.size()));
  for (const ReadinessGate& gate : value.gates) {
    writer.u8(static_cast<std::uint8_t>(gate.kind));
    writer.boolean(gate.open);
    writer.u32(static_cast<std::uint32_t>(gate.conditions.size()));
    for (const GateCondition& condition : gate.conditions) {
      writer.name(condition.name);
      writer.boolean(condition.satisfied);
    }
  }

  std::vector<ObligationAssessment> obligations = value.obligations;
  std::sort(obligations.begin(), obligations.end());
  writer.u32(static_cast<std::uint32_t>(obligations.size()));
  for (const ObligationAssessment& obligation : obligations) {
    write_id(writer, obligation.id.high(), obligation.id.low());
    writer.name(obligation.service_class);
    writer.boolean(obligation.protected_class);
    writer.u8(static_cast<std::uint8_t>(obligation.outcome));
    writer.u64(obligation.required_units);
    writer.u64(obligation.ready_units);
    writer.u32(obligation.required_readiness_percent);
    writer.u32(obligation.observed_readiness_percent);
  }
}

Digest compute_evidence_digest(std::span<const SlotResolution> slots) {
  CanonicalWriter writer;
  writer.u32(static_cast<std::uint32_t>(slots.size()));
  for (const SlotResolution& resolution : slots) {
    // Only the evidence identities and their resolution participate: free-text
    // explanations are derivable and must not change what the evidence *is*.
    writer.u8(static_cast<std::uint8_t>(resolution.slot.authority));
    writer.u16(static_cast<std::uint16_t>(resolution.slot.kind));
    writer.u8(static_cast<std::uint8_t>(resolution.outcome));
    write_id(writer, resolution.accepted_id.high(), resolution.accepted_id.low());
    write_digest(writer, resolution.accepted_digest);
    writer.u8(static_cast<std::uint8_t>(resolution.freshness));
    writer.u8(static_cast<std::uint8_t>(resolution.origin));
    writer.u32(static_cast<std::uint32_t>(resolution.superseded.size()));
    for (const EvidenceId& id : resolution.superseded) {
      write_id(writer, id.high(), id.low());
    }
    writer.u32(static_cast<std::uint32_t>(resolution.conflicting.size()));
    for (const EvidenceId& id : resolution.conflicting) {
      write_id(writer, id.high(), id.low());
    }
  }
  return Digest::of(writer.span());
}

Digest compute_snapshot_digest(const SiteStateSnapshot& snapshot) {
  CanonicalWriter writer;
  canonical_write(writer, snapshot);
  return Digest::of(writer.span());
}

ConstraintId constraint_id_for(ConstraintKind kind, std::string_view subject) {
  return identity_from_content([kind, subject](CanonicalWriter& writer) {
    writer.u8(static_cast<std::uint8_t>(kind));
    writer.text(subject);
  });
}

ObligationId obligation_id_for(std::string_view service_class) {
  CanonicalWriter writer;
  writer.text(service_class);
  const Digest digest = Digest::of(writer.span());
  const auto& bytes = digest.bytes();
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    high = (high << 8U) | bytes[index];
    low = (low << 8U) | bytes[index + 8];
  }
  return ObligationId(high, low);
}

}  // namespace scp
