// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "scp/authority.hpp"
#include "scp/canonical.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/journal.hpp"
#include "scp/plan.hpp"
#include "scp/policy.hpp"
#include "scp/readiness.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"

/// \file journal_format.cpp
/// Canonical encoding of the durable journal layer and of every nested value
/// type a journal frame carries.
///
/// This file is the on-disk format. A writer and a reader that disagree by one
/// byte would silently reinterpret durable site authority, so the two halves are
/// symmetric by construction: each decoder consumes exactly the fields its
/// encoder emitted, in the same order, and each collection is preceded by a
/// count that is checked against a documented bound before any storage is
/// reserved. Unknown enumerators, over-budget lengths and short input are all
/// reported as a Status; no read path throws, and none trusts a length it has
/// not checked.

namespace scp {
namespace {

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Longest free text accepted for an observed, expected or explanatory field.
/// Short subjects and details use the tighter scp::kMaxNameBytes budget.
inline constexpr std::uint32_t kMaxDetailBytes = 4096;

/// Element bounds for the collections encoded here. The count that precedes a
/// collection is checked against the bound for that field before the vector is
/// reserved, so a damaged or hostile frame cannot drive an allocation larger
/// than the format documents.
inline constexpr std::uint32_t kMaxPreconditionCount = 64;
inline constexpr std::uint32_t kMaxGateConditionCount = 64;
inline constexpr std::uint32_t kMaxPlanConditionCount = 256;
inline constexpr std::uint32_t kMaxPlanStepCount = 256;
inline constexpr std::uint32_t kMaxSupersededIds = 128;
inline constexpr std::uint32_t kMaxConflictingIds = 128;
inline constexpr std::uint32_t kMaxGrantCount = 4096;

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

/// 128-bit identity: the high word first, then the low word.
template <class Tag>
void write_id(CanonicalWriter& writer, const OpaqueId<Tag>& id) {
  writer.u64(id.high());
  writer.u64(id.low());
}

template <class Tag>
[[nodiscard]] Result<OpaqueId<Tag>> read_id(CanonicalReader& reader) {
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  SCP_TRY(reader.u64(high));
  SCP_TRY(reader.u64(low));
  return OpaqueId<Tag>(high, low);
}

/// Counters are written as their raw scalar. Zero is the documented "unset"
/// sentinel, so no presence tag is needed or allowed.
template <class Tag>
[[nodiscard]] Result<Counter<Tag>> read_counter(CanonicalReader& reader) {
  std::uint64_t raw = 0;
  SCP_TRY(reader.u64(raw));
  return Counter<Tag>(raw);
}

/// Digests are written as their 32 raw bytes, never as hex.
void write_digest(CanonicalWriter& writer, const Digest& digest) {
  writer.bytes(std::span<const std::uint8_t>(digest.bytes().data(), digest.bytes().size()));
}

[[nodiscard]] Result<Digest> read_digest(CanonicalReader& reader) {
  std::vector<std::uint8_t> raw;
  SCP_TRY(reader.bytes(raw, static_cast<std::uint32_t>(kDigestBytes)));
  if (raw.size() != kDigestBytes) {
    return fail(StatusCode::Corrupt, "digest field is not 32 bytes");
  }
  std::array<std::uint8_t, kDigestBytes> bytes{};
  std::copy(raw.begin(), raw.end(), bytes.begin());
  return Digest(bytes);
}

[[nodiscard]] Result<Name> read_name(CanonicalReader& reader, std::string_view field) {
  std::string text;
  SCP_TRY(reader.text(text, static_cast<std::uint32_t>(kMaxNameBytes)));
  auto parsed = Name::parse(text);
  if (!parsed.has_value()) {
    return fail(StatusCode::InvalidText, std::string(field) + " is not a valid name");
  }
  return std::move(parsed).value();
}

/// Moves a decoded value into its destination, or propagates the failure.
template <class T>
[[nodiscard]] Status assign(T& destination, Result<T> result) {
  if (!result.has_value()) {
    return result.status();
  }
  destination = std::move(result).value();
  return Status{};
}

/// Writes a u32 element count followed by the elements themselves. Every value
/// that reaches this point was bounded by the reader that produced it.
template <class T, class WriteElement>
void write_sequence(CanonicalWriter& writer, const std::vector<T>& values,
                    WriteElement write_element) {
  writer.u32(static_cast<std::uint32_t>(values.size()));
  for (const T& element : values) {
    write_element(writer, element);
  }
}

/// Reads an element count, rejects it when it exceeds \p bound, and only then
/// reserves storage for the elements.
template <class T, class ReadElement>
[[nodiscard]] Result<std::vector<T>> read_sequence(CanonicalReader& reader, std::string_view field,
                                                   std::uint32_t bound,
                                                   ReadElement read_element) {
  std::uint32_t count = 0;
  SCP_TRY(reader.u32(count));
  if (count > bound) {
    return fail(StatusCode::LimitExceeded, std::string(field) + " count " + std::to_string(count) +
                                               " exceeds " + std::to_string(bound));
  }
  std::vector<T> values;
  values.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    SCP_TRY_ASSIGN(element, read_element(reader));
    values.push_back(std::move(element));
  }
  return values;
}

// ---------------------------------------------------------------------------
// Enumerators
//
// Every enum encoded in this file has exactly one decoder. The switch is
// exhaustive over the enumerators and its default rejects the raw value instead
// of casting it into the enum, so a frame written by a build that knows a newer
// enumerator is reported as InvalidEnum rather than reinterpreted.
// ---------------------------------------------------------------------------

[[nodiscard]] Result<SourceAuthority> read_source_authority(CanonicalReader& reader,
                                                            std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return SourceAuthority::FacilityStateLedger;
    case 2:
      return SourceAuthority::FacilityCapacity;
    case 3:
      return SourceAuthority::PowerControlPlane;
    case 4:
      return SourceAuthority::ThermalControlPlane;
    case 5:
      return SourceAuthority::FacilityPolicyEngine;
    case 6:
      return SourceAuthority::IncidentStateFabric;
    case 7:
      return SourceAuthority::MaintenanceCoordinator;
    case 8:
      return SourceAuthority::AsiRuntime;
    case 9:
      return SourceAuthority::DfiRuntime;
    case 10:
      return SourceAuthority::ServiceClassRegistry;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<EvidenceKind> read_evidence_kind(CanonicalReader& reader,
                                                      std::string_view field) {
  std::uint16_t raw = 0;
  SCP_TRY(reader.u16(raw));
  switch (raw) {
    case 1:
      return EvidenceKind::FacilityState;
    case 2:
      return EvidenceKind::Lifecycle;
    case 3:
      return EvidenceKind::Capacity;
    case 4:
      return EvidenceKind::PowerReadiness;
    case 5:
      return EvidenceKind::CoolingReadiness;
    case 6:
      return EvidenceKind::Policy;
    case 7:
      return EvidenceKind::Incident;
    case 8:
      return EvidenceKind::Maintenance;
    case 9:
      return EvidenceKind::AsiCapability;
    case 10:
      return EvidenceKind::DfiCapability;
    case 11:
      return EvidenceKind::ServiceClass;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<SlotOutcome> read_slot_outcome(CanonicalReader& reader,
                                                    std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 0:
      return SlotOutcome::Missing;
    case 1:
      return SlotOutcome::Accepted;
    case 2:
      return SlotOutcome::AcceptedSuperseding;
    case 3:
      return SlotOutcome::Superseded;
    case 4:
      return SlotOutcome::Conflicting;
    case 5:
      return SlotOutcome::Stale;
    case 6:
      return SlotOutcome::Expired;
    case 7:
      return SlotOutcome::Unsupported;
    case 8:
      return SlotOutcome::Unauthorized;
    case 9:
      return SlotOutcome::Indeterminate;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<Freshness> read_freshness(CanonicalReader& reader, std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return Freshness::Fresh;
    case 2:
      return Freshness::Stale;
    case 3:
      return Freshness::Expired;
    case 4:
      return Freshness::Indeterminate;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<EvidenceOrigin> read_evidence_origin(CanonicalReader& reader,
                                                          std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return EvidenceOrigin::Ingested;
    case 2:
      return EvidenceOrigin::RecoveredFromJournal;
    case 3:
      return EvidenceOrigin::Revalidated;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<ConstraintKind> read_constraint_kind(CanonicalReader& reader,
                                                          std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return ConstraintKind::EvidenceIncomplete;
    case 2:
      return ConstraintKind::EvidenceConflicting;
    case 3:
      return ConstraintKind::EvidenceStale;
    case 4:
      return ConstraintKind::EvidenceUnsupported;
    case 5:
      return ConstraintKind::EvidenceUnauthorized;
    case 6:
      return ConstraintKind::CapacityHeadroomLow;
    case 7:
      return ConstraintKind::CapacityExhausted;
    case 8:
      return ConstraintKind::CapacityOversubscribed;
    case 9:
      return ConstraintKind::PowerReadinessConstrained;
    case 10:
      return ConstraintKind::PowerReadinessDegraded;
    case 11:
      return ConstraintKind::PowerReadinessUnavailable;
    case 12:
      return ConstraintKind::CoolingReadinessConstrained;
    case 13:
      return ConstraintKind::CoolingReadinessDegraded;
    case 14:
      return ConstraintKind::CoolingReadinessUnavailable;
    case 15:
      return ConstraintKind::RedundancyReduced;
    case 16:
      return ConstraintKind::AsiReadinessDegraded;
    case 17:
      return ConstraintKind::AsiReadinessUnavailable;
    case 18:
      return ConstraintKind::DfiReadinessDegraded;
    case 19:
      return ConstraintKind::DfiReadinessUnavailable;
    case 20:
      return ConstraintKind::ActiveIncidents;
    case 21:
      return ConstraintKind::CriticalIncidents;
    case 22:
      return ConstraintKind::EmergencyDeclared;
    case 23:
      return ConstraintKind::DegradedOperation;
    case 24:
      return ConstraintKind::MaintenanceActive;
    case 25:
      return ConstraintKind::MaintenanceScheduled;
    case 26:
      return ConstraintKind::MaintenanceOverdue;
    case 27:
      return ConstraintKind::DrainInProgress;
    case 28:
      return ConstraintKind::ObligationAtRisk;
    case 29:
      return ConstraintKind::ObligationUnsatisfied;
    case 30:
      return ConstraintKind::AsiReadinessConstrained;
    case 31:
      return ConstraintKind::DfiReadinessConstrained;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<Severity> read_severity(CanonicalReader& reader, std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 0:
      return Severity::None;
    case 1:
      return Severity::Informational;
    case 2:
      return Severity::Minor;
    case 3:
      return Severity::Major;
    case 4:
      return Severity::Critical;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<ObligationOutcome> read_obligation_outcome(CanonicalReader& reader,
                                                                std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return ObligationOutcome::Satisfied;
    case 2:
      return ObligationOutcome::AtRisk;
    case 3:
      return ObligationOutcome::Unsatisfied;
    case 4:
      return ObligationOutcome::Unknown;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<GateKind> read_gate_kind(CanonicalReader& reader, std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return GateKind::NewObligation;
    case 2:
      return GateKind::MaintenanceEntry;
    case 3:
      return GateKind::ControlledDrain;
    case 4:
      return GateKind::EmergencyOperation;
    case 5:
      return GateKind::RecoveryStart;
    case 6:
      return GateKind::ReturnToService;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<AuthorityOutcome> read_authority_outcome(CanonicalReader& reader,
                                                              std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return AuthorityOutcome::Granted;
    case 2:
      return AuthorityOutcome::NoGrantFound;
    case 3:
      return AuthorityOutcome::ScopeNotGranted;
    case 4:
      return AuthorityOutcome::SiteMismatch;
    case 5:
      return AuthorityOutcome::GrantExpired;
    case 6:
      return AuthorityOutcome::GrantRevoked;
    case 7:
      return AuthorityOutcome::GrantNotYetValid;
    case 8:
      return AuthorityOutcome::GenerationFenced;
    case 9:
      return AuthorityOutcome::GrantInvalid;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<Comparison> read_comparison(CanonicalReader& reader, std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return Comparison::AtLeast;
    case 2:
      return Comparison::AtMost;
    case 3:
      return Comparison::Equal;
    case 4:
      return Comparison::NotEqual;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<PreconditionKind> read_precondition_kind(CanonicalReader& reader,
                                                              std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return PreconditionKind::SiteGenerationAtLeast;
    case 2:
      return PreconditionKind::SiteStateIs;
    case 3:
      return PreconditionKind::LifecycleIs;
    case 4:
      return PreconditionKind::GateWasOpen;
    case 5:
      return PreconditionKind::EvidenceDigestMatches;
    case 6:
      return PreconditionKind::ScopeStillGranted;
    case 7:
      return PreconditionKind::MinimumHeadroomPercent;
    case 8:
      return PreconditionKind::SiteNotRetired;
    case 9:
      return PreconditionKind::ReceiverOwnsEffect;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<PlanIntent> read_plan_intent(CanonicalReader& reader, std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return PlanIntent::AcceptObligation;
    case 2:
      return PlanIntent::ReleaseObligation;
    case 3:
      return PlanIntent::EnterMaintenance;
    case 4:
      return PlanIntent::ControlledDrain;
    case 5:
      return PlanIntent::EmergencyOperation;
    case 6:
      return PlanIntent::BeginRecovery;
    case 7:
      return PlanIntent::ReturnToService;
    case 8:
      return PlanIntent::IsolateSite;
    case 9:
      return PlanIntent::RetireSite;
    case 10:
      return PlanIntent::ResumeNormalOperation;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<SiteState> read_site_state(CanonicalReader& reader, std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 0:
      return SiteState::Unknown;
    case 1:
      return SiteState::Conflicting;
    case 2:
      return SiteState::Commissioning;
    case 3:
      return SiteState::Available;
    case 4:
      return SiteState::Constrained;
    case 5:
      return SiteState::Degraded;
    case 6:
      return SiteState::Draining;
    case 7:
      return SiteState::Maintenance;
    case 8:
      return SiteState::Emergency;
    case 9:
      return SiteState::Recovering;
    case 10:
      return SiteState::Isolated;
    case 11:
      return SiteState::Retired;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

[[nodiscard]] Result<OperationKind> read_operation_kind(CanonicalReader& reader,
                                                        std::string_view field) {
  std::uint8_t raw = 0;
  SCP_TRY(reader.u8(raw));
  switch (raw) {
    case 1:
      return OperationKind::IngestEvidence;
    case 2:
      return OperationKind::RetireEvidence;
    case 3:
      return OperationKind::AdvanceSiteGeneration;
    case 4:
      return OperationKind::RecordPlan;
    case 5:
      return OperationKind::RecordGrant;
    case 6:
      return OperationKind::RecordPolicy;
    default:
      break;
  }
  return fail(StatusCode::InvalidEnum,
              std::string(field) + " has unknown value " + std::to_string(raw));
}

// ---------------------------------------------------------------------------
// Shared fragments
// ---------------------------------------------------------------------------

/// The (authority, kind) pair that identifies an evidence slot.
void write_slot(CanonicalWriter& writer, const EvidenceSlot& slot) {
  writer.u8(static_cast<std::uint8_t>(slot.authority));
  writer.u16(static_cast<std::uint16_t>(slot.kind));
}

[[nodiscard]] Status read_slot(CanonicalReader& reader, EvidenceSlot& slot) {
  SCP_TRY(assign(slot.authority, read_source_authority(reader, "slot.authority")));
  SCP_TRY(assign(slot.kind, read_evidence_kind(reader, "slot.kind")));
  return Status{};
}

template <class Tag>
[[nodiscard]] Result<std::vector<OpaqueId<Tag>>> read_ids(CanonicalReader& reader,
                                                          std::string_view field,
                                                          std::uint32_t bound) {
  return read_sequence<OpaqueId<Tag>>(
      reader, field, bound, [](CanonicalReader& source) { return read_id<Tag>(source); });
}

/// One configurable threshold rule. Inline in SitePolicy by design: a rule has
/// no identity of its own outside the policy that carries it.
void write_threshold_rule(CanonicalWriter& writer, const ThresholdRule& value) {
  writer.name(value.rule_id);
  writer.u8(static_cast<std::uint8_t>(value.kind));
  writer.u8(static_cast<std::uint8_t>(value.severity));
  writer.u8(static_cast<std::uint8_t>(value.comparison));
  writer.u64(value.threshold);
  writer.boolean(value.blocking);
  writer.text(value.subject);
}

[[nodiscard]] Result<ThresholdRule> read_threshold_rule(CanonicalReader& reader) {
  ThresholdRule value;
  SCP_TRY(assign(value.rule_id, read_name(reader, "policy.rule.rule_id")));
  SCP_TRY(assign(value.kind, read_constraint_kind(reader, "policy.rule.kind")));
  SCP_TRY(assign(value.severity, read_severity(reader, "policy.rule.severity")));
  SCP_TRY(assign(value.comparison, read_comparison(reader, "policy.rule.comparison")));
  SCP_TRY(reader.u64(value.threshold));
  SCP_TRY(reader.boolean(value.blocking));
  SCP_TRY(reader.text(value.subject, static_cast<std::uint32_t>(kMaxNameBytes)));
  return value;
}

}  // namespace

// ---------------------------------------------------------------------------
// site_state.hpp
// ---------------------------------------------------------------------------

void canonical_write(CanonicalWriter& writer, const SlotResolution& value) {
  write_slot(writer, value.slot);
  writer.u8(static_cast<std::uint8_t>(value.outcome));
  write_id(writer, value.accepted_id);
  write_digest(writer, value.accepted_digest);
  write_id(writer, value.accepted_instance);
  writer.u64(value.accepted_epoch.value());
  writer.u64(value.accepted_generation.value());
  writer.u64(value.accepted_sequence.value());
  writer.u8(static_cast<std::uint8_t>(value.freshness));
  writer.u8(static_cast<std::uint8_t>(value.origin));
  write_sequence(writer, value.superseded,
                 [](CanonicalWriter& target, const EvidenceId& id) { write_id(target, id); });
  write_sequence(writer, value.conflicting,
                 [](CanonicalWriter& target, const EvidenceId& id) { write_id(target, id); });
  writer.u64(static_cast<std::uint64_t>(value.duplicates_merged));
  writer.text(value.detail);
}

Result<SlotResolution> canonical_read_slot_resolution(CanonicalReader& reader) {
  SlotResolution value;
  SCP_TRY(read_slot(reader, value.slot));
  SCP_TRY(assign(value.outcome, read_slot_outcome(reader, "slot_resolution.outcome")));
  SCP_TRY(assign(value.accepted_id, read_id<EvidenceIdTag>(reader)));
  SCP_TRY(assign(value.accepted_digest, read_digest(reader)));
  SCP_TRY(assign(value.accepted_instance, read_id<SourceInstanceIdTag>(reader)));
  SCP_TRY(assign(value.accepted_epoch, read_counter<EpochTag>(reader)));
  SCP_TRY(assign(value.accepted_generation, read_counter<SourceGenerationTag>(reader)));
  SCP_TRY(assign(value.accepted_sequence, read_counter<SequenceTag>(reader)));
  SCP_TRY(assign(value.freshness, read_freshness(reader, "slot_resolution.freshness")));
  SCP_TRY(assign(value.origin, read_evidence_origin(reader, "slot_resolution.origin")));
  SCP_TRY(assign(value.superseded, read_ids<EvidenceIdTag>(reader, "slot_resolution.superseded",
                                                            kMaxSupersededIds)));
  SCP_TRY(assign(value.conflicting, read_ids<EvidenceIdTag>(reader, "slot_resolution.conflicting",
                                                            kMaxConflictingIds)));
  std::uint64_t duplicates_merged = 0;
  SCP_TRY(reader.u64(duplicates_merged));
  value.duplicates_merged = static_cast<std::size_t>(duplicates_merged);
  SCP_TRY(reader.text(value.detail, kMaxDetailBytes));
  return value;
}

void canonical_write(CanonicalWriter& writer, const Constraint& value) {
  write_id(writer, value.id);
  writer.u8(static_cast<std::uint8_t>(value.kind));
  writer.u8(static_cast<std::uint8_t>(value.severity));
  writer.boolean(value.blocking);
  writer.text(value.subject);
  writer.text(value.detail);
  write_slot(writer, value.source);
  write_digest(writer, value.source_digest);
}

Result<Constraint> canonical_read_constraint(CanonicalReader& reader) {
  Constraint value;
  SCP_TRY(assign(value.id, read_id<ConstraintIdTag>(reader)));
  SCP_TRY(assign(value.kind, read_constraint_kind(reader, "constraint.kind")));
  SCP_TRY(assign(value.severity, read_severity(reader, "constraint.severity")));
  SCP_TRY(reader.boolean(value.blocking));
  SCP_TRY(reader.text(value.subject, static_cast<std::uint32_t>(kMaxNameBytes)));
  SCP_TRY(reader.text(value.detail, kMaxDetailBytes));
  SCP_TRY(read_slot(reader, value.source));
  SCP_TRY(assign(value.source_digest, read_digest(reader)));
  return value;
}

void canonical_write(CanonicalWriter& writer, const ObligationAssessment& value) {
  write_id(writer, value.id);
  writer.name(value.service_class);
  writer.boolean(value.protected_class);
  writer.u8(static_cast<std::uint8_t>(value.outcome));
  writer.u64(value.required_units);
  writer.u64(value.ready_units);
  writer.u32(value.required_readiness_percent);
  writer.u32(value.observed_readiness_percent);
  writer.text(value.detail);
}

Result<ObligationAssessment> canonical_read_obligation(CanonicalReader& reader) {
  ObligationAssessment value;
  SCP_TRY(assign(value.id, read_id<ObligationIdTag>(reader)));
  SCP_TRY(assign(value.service_class, read_name(reader, "obligation.service_class")));
  SCP_TRY(reader.boolean(value.protected_class));
  SCP_TRY(assign(value.outcome, read_obligation_outcome(reader, "obligation.outcome")));
  SCP_TRY(reader.u64(value.required_units));
  SCP_TRY(reader.u64(value.ready_units));
  SCP_TRY(reader.u32(value.required_readiness_percent));
  SCP_TRY(reader.u32(value.observed_readiness_percent));
  SCP_TRY(reader.text(value.detail, kMaxDetailBytes));
  return value;
}

// ---------------------------------------------------------------------------
// readiness.hpp
// ---------------------------------------------------------------------------

void canonical_write(CanonicalWriter& writer, const GateCondition& value) {
  writer.name(value.name);
  writer.boolean(value.satisfied);
  writer.text(value.observed);
  writer.text(value.required);
  writer.text(value.detail);
}

Result<GateCondition> canonical_read_gate_condition(CanonicalReader& reader) {
  GateCondition value;
  SCP_TRY(assign(value.name, read_name(reader, "gate_condition.name")));
  SCP_TRY(reader.boolean(value.satisfied));
  SCP_TRY(reader.text(value.observed, kMaxDetailBytes));
  SCP_TRY(reader.text(value.required, kMaxDetailBytes));
  SCP_TRY(reader.text(value.detail, kMaxDetailBytes));
  return value;
}

void canonical_write(CanonicalWriter& writer, const ReadinessGate& value) {
  writer.u8(static_cast<std::uint8_t>(value.kind));
  writer.boolean(value.open);
  write_sequence(writer, value.conditions,
                 [](CanonicalWriter& target, const GateCondition& condition) {
                   canonical_write(target, condition);
                 });
}

Result<ReadinessGate> canonical_read_gate(CanonicalReader& reader) {
  ReadinessGate value;
  SCP_TRY(assign(value.kind, read_gate_kind(reader, "gate.kind")));
  SCP_TRY(reader.boolean(value.open));
  SCP_TRY(assign(value.conditions,
                 read_sequence<GateCondition>(
                     reader, "gate.conditions", kMaxGateConditionCount,
                     [](CanonicalReader& source) { return canonical_read_gate_condition(source); })));
  return value;
}

// ---------------------------------------------------------------------------
// authority.hpp
// ---------------------------------------------------------------------------

void canonical_write(CanonicalWriter& writer, const DelegationGrant& value) {
  write_id(writer, value.id);
  write_id(writer, value.site);
  writer.name(value.grantor);
  writer.name(value.subject);
  writer.u16(value.scopes.bits());
  writer.u64(value.not_before.value());
  writer.u64(value.not_after.value());
  writer.i64(value.issued_at.nanos);
  writer.i64(value.expires_at.nanos);
  writer.boolean(value.revoked);
  write_digest(writer, value.evidence_digest);
}

Result<DelegationGrant> canonical_read_grant(CanonicalReader& reader) {
  DelegationGrant value;
  SCP_TRY(assign(value.id, read_id<GrantIdTag>(reader)));
  SCP_TRY(assign(value.site, read_id<SiteIdTag>(reader)));
  SCP_TRY(assign(value.grantor, read_name(reader, "grant.grantor")));
  SCP_TRY(assign(value.subject, read_name(reader, "grant.subject")));
  std::uint16_t scopes = 0;
  SCP_TRY(reader.u16(scopes));
  value.scopes = ScopeSet(scopes);
  SCP_TRY(assign(value.not_before, read_counter<SiteGenerationTag>(reader)));
  SCP_TRY(assign(value.not_after, read_counter<SiteGenerationTag>(reader)));
  SCP_TRY(reader.i64(value.issued_at.nanos));
  SCP_TRY(reader.i64(value.expires_at.nanos));
  SCP_TRY(reader.boolean(value.revoked));
  SCP_TRY(assign(value.evidence_digest, read_digest(reader)));
  return value;
}

void canonical_write(CanonicalWriter& writer, const AuthorityDecision& value) {
  writer.u8(static_cast<std::uint8_t>(value.outcome));
  write_id(writer, value.grant);
  writer.text(value.detail);
}

Result<AuthorityDecision> canonical_read_authority_decision(CanonicalReader& reader) {
  AuthorityDecision value;
  SCP_TRY(assign(value.outcome, read_authority_outcome(reader, "authority_decision.outcome")));
  SCP_TRY(assign(value.grant, read_id<GrantIdTag>(reader)));
  SCP_TRY(reader.text(value.detail, kMaxDetailBytes));
  return value;
}

// ---------------------------------------------------------------------------
// policy.hpp
// ---------------------------------------------------------------------------

void canonical_write(CanonicalWriter& writer, const SitePolicy& value) {
  writer.u64(value.generation.value());
  writer.i64(value.freshness.stale_after.nanos);
  writer.i64(value.freshness.expire_after.nanos);
  writer.boolean(value.freshness.recovered_ages_out);
  writer.u32(value.capacity_headroom_constrained_percent);
  writer.u32(value.capacity_headroom_degraded_percent);
  writer.u32(value.domain_readiness_degraded_percent);
  writer.u32(value.domain_readiness_unavailable_percent);
  writer.u32(value.required_redundancy_domains);
  writer.u64(value.power_headroom_floor_milli_kw);
  writer.u64(value.cooling_headroom_floor_milli_kw);
  writer.boolean(value.require_complete_evidence_for_new_obligations);
  writer.boolean(value.require_fresh_evidence_for_new_obligations);
  writer.boolean(value.require_unconflicted_evidence_for_new_obligations);
  writer.boolean(value.require_power_ready_for_new_obligations);
  writer.boolean(value.require_cooling_ready_for_new_obligations);
  writer.boolean(value.require_asi_ready_for_new_obligations);
  writer.boolean(value.require_dfi_ready_for_new_obligations);
  writer.boolean(value.require_full_redundancy_for_return_to_service);
  writer.u32(value.maintenance_minimum_readiness_percent);
  writer.u32(value.recovery_minimum_drained_percent);
  writer.u32(value.return_to_service_minimum_readiness_percent);
  writer.boolean(value.emergency_allows_partial_evidence);
  writer.boolean(value.emergency_allows_unready_domains);
  writer.u64(static_cast<std::uint64_t>(value.max_constraints));
  writer.u64(static_cast<std::uint64_t>(value.max_service_classes));
  write_sequence(writer, value.rules, [](CanonicalWriter& target, const ThresholdRule& rule) {
    write_threshold_rule(target, rule);
  });
}

Result<SitePolicy> canonical_read_policy(CanonicalReader& reader) {
  SitePolicy value;
  SCP_TRY(assign(value.generation, read_counter<PolicyGenerationTag>(reader)));
  SCP_TRY(reader.i64(value.freshness.stale_after.nanos));
  SCP_TRY(reader.i64(value.freshness.expire_after.nanos));
  SCP_TRY(reader.boolean(value.freshness.recovered_ages_out));
  SCP_TRY(reader.u32(value.capacity_headroom_constrained_percent));
  SCP_TRY(reader.u32(value.capacity_headroom_degraded_percent));
  SCP_TRY(reader.u32(value.domain_readiness_degraded_percent));
  SCP_TRY(reader.u32(value.domain_readiness_unavailable_percent));
  SCP_TRY(reader.u32(value.required_redundancy_domains));
  SCP_TRY(reader.u64(value.power_headroom_floor_milli_kw));
  SCP_TRY(reader.u64(value.cooling_headroom_floor_milli_kw));
  SCP_TRY(reader.boolean(value.require_complete_evidence_for_new_obligations));
  SCP_TRY(reader.boolean(value.require_fresh_evidence_for_new_obligations));
  SCP_TRY(reader.boolean(value.require_unconflicted_evidence_for_new_obligations));
  SCP_TRY(reader.boolean(value.require_power_ready_for_new_obligations));
  SCP_TRY(reader.boolean(value.require_cooling_ready_for_new_obligations));
  SCP_TRY(reader.boolean(value.require_asi_ready_for_new_obligations));
  SCP_TRY(reader.boolean(value.require_dfi_ready_for_new_obligations));
  SCP_TRY(reader.boolean(value.require_full_redundancy_for_return_to_service));
  SCP_TRY(reader.u32(value.maintenance_minimum_readiness_percent));
  SCP_TRY(reader.u32(value.recovery_minimum_drained_percent));
  SCP_TRY(reader.u32(value.return_to_service_minimum_readiness_percent));
  SCP_TRY(reader.boolean(value.emergency_allows_partial_evidence));
  SCP_TRY(reader.boolean(value.emergency_allows_unready_domains));
  std::uint64_t max_constraints = 0;
  SCP_TRY(reader.u64(max_constraints));
  value.max_constraints = static_cast<std::size_t>(max_constraints);
  std::uint64_t max_service_classes = 0;
  SCP_TRY(reader.u64(max_service_classes));
  value.max_service_classes = static_cast<std::size_t>(max_service_classes);
  SCP_TRY(assign(value.rules,
                 read_sequence<ThresholdRule>(
                     reader, "policy.rules", static_cast<std::uint32_t>(kMaxThresholdRules),
                     [](CanonicalReader& source) { return read_threshold_rule(source); })));
  return value;
}

// ---------------------------------------------------------------------------
// plan.hpp
// ---------------------------------------------------------------------------

void canonical_write(CanonicalWriter& writer, const Precondition& value) {
  writer.u8(static_cast<std::uint8_t>(value.kind));
  writer.text(value.subject);
  writer.text(value.expectation);
}

Result<Precondition> canonical_read_precondition(CanonicalReader& reader) {
  Precondition value;
  SCP_TRY(assign(value.kind, read_precondition_kind(reader, "precondition.kind")));
  SCP_TRY(reader.text(value.subject, kMaxDetailBytes));
  SCP_TRY(reader.text(value.expectation, kMaxDetailBytes));
  return value;
}

void canonical_write(CanonicalWriter& writer, const EffectRequest& value) {
  write_id(writer, value.id);
  write_id(writer, value.idempotency);
  writer.u8(static_cast<std::uint8_t>(value.target));
  writer.name(value.action);
  write_id(writer, value.site);
  writer.u64(value.site_generation.value());
  writer.u16(value.required_scope.bits());
  write_sequence(writer, value.preconditions,
                 [](CanonicalWriter& target, const Precondition& precondition) {
                   canonical_write(target, precondition);
                 });
  writer.bytes(std::span<const std::uint8_t>(value.arguments.data(), value.arguments.size()));
  writer.i64(value.created_at.nanos);
  writer.i64(value.deadline.nanos);
  write_id(writer, value.plan);
  write_digest(writer, value.site_snapshot_digest);
}

Result<EffectRequest> canonical_read_request(CanonicalReader& reader) {
  EffectRequest value;
  SCP_TRY(assign(value.id, read_id<RequestIdTag>(reader)));
  SCP_TRY(assign(value.idempotency, read_id<RequestIdTag>(reader)));
  SCP_TRY(assign(value.target, read_source_authority(reader, "request.target")));
  SCP_TRY(assign(value.action, read_name(reader, "request.action")));
  SCP_TRY(assign(value.site, read_id<SiteIdTag>(reader)));
  SCP_TRY(assign(value.site_generation, read_counter<SiteGenerationTag>(reader)));
  std::uint16_t required_scope = 0;
  SCP_TRY(reader.u16(required_scope));
  value.required_scope = ScopeSet(required_scope);
  SCP_TRY(assign(value.preconditions,
                 read_sequence<Precondition>(
                     reader, "request.preconditions", kMaxPreconditionCount,
                     [](CanonicalReader& source) { return canonical_read_precondition(source); })));
  SCP_TRY(reader.bytes(value.arguments, kMaxBlobBytes));
  SCP_TRY(reader.i64(value.created_at.nanos));
  SCP_TRY(reader.i64(value.deadline.nanos));
  SCP_TRY(assign(value.plan, read_id<PlanIdTag>(reader)));
  SCP_TRY(assign(value.site_snapshot_digest, read_digest(reader)));
  return value;
}

void canonical_write(CanonicalWriter& writer, const PlanCondition& value) {
  writer.name(value.name);
  writer.boolean(value.satisfied);
  writer.text(value.observed);
  writer.text(value.required);
}

Result<PlanCondition> canonical_read_plan_condition(CanonicalReader& reader) {
  PlanCondition value;
  SCP_TRY(assign(value.name, read_name(reader, "plan_condition.name")));
  SCP_TRY(reader.boolean(value.satisfied));
  SCP_TRY(reader.text(value.observed, kMaxDetailBytes));
  SCP_TRY(reader.text(value.required, kMaxDetailBytes));
  return value;
}

void canonical_write(CanonicalWriter& writer, const PlannedStep& value) {
  writer.u32(value.ordinal);
  writer.name(value.description);
  canonical_write(writer, value.request);
}

Result<PlannedStep> canonical_read_step(CanonicalReader& reader) {
  PlannedStep value;
  SCP_TRY(reader.u32(value.ordinal));
  SCP_TRY(assign(value.description, read_name(reader, "step.description")));
  SCP_TRY(assign(value.request, canonical_read_request(reader)));
  return value;
}

void canonical_write(CanonicalWriter& writer, const ActionPlan& value) {
  write_id(writer, value.id);
  write_id(writer, value.site);
  writer.u64(value.site_generation.value());
  writer.u8(static_cast<std::uint8_t>(value.intent));
  writer.i64(value.created_at.nanos);
  writer.boolean(value.permitted);
  writer.text(value.denial_reason);
  canonical_write(writer, value.authority);
  canonical_write(writer, value.gate);
  writer.u8(static_cast<std::uint8_t>(value.state));
  write_sequence(writer, value.conditions,
                 [](CanonicalWriter& target, const PlanCondition& condition) {
                   canonical_write(target, condition);
                 });
  write_sequence(writer, value.steps, [](CanonicalWriter& target, const PlannedStep& step) {
    canonical_write(target, step);
  });
  write_digest(writer, value.site_snapshot_digest);
  write_digest(writer, value.evidence_digest);
  write_digest(writer, value.plan_digest);
}

Result<ActionPlan> canonical_read_plan(CanonicalReader& reader) {
  ActionPlan value;
  SCP_TRY(assign(value.id, read_id<PlanIdTag>(reader)));
  SCP_TRY(assign(value.site, read_id<SiteIdTag>(reader)));
  SCP_TRY(assign(value.site_generation, read_counter<SiteGenerationTag>(reader)));
  SCP_TRY(assign(value.intent, read_plan_intent(reader, "plan.intent")));
  SCP_TRY(reader.i64(value.created_at.nanos));
  SCP_TRY(reader.boolean(value.permitted));
  SCP_TRY(reader.text(value.denial_reason, kMaxDetailBytes));
  SCP_TRY(assign(value.authority, canonical_read_authority_decision(reader)));
  SCP_TRY(assign(value.gate, canonical_read_gate(reader)));
  SCP_TRY(assign(value.state, read_site_state(reader, "plan.state")));
  SCP_TRY(assign(value.conditions,
                 read_sequence<PlanCondition>(
                     reader, "plan.conditions", kMaxPlanConditionCount,
                     [](CanonicalReader& source) { return canonical_read_plan_condition(source); })));
  SCP_TRY(assign(value.steps,
                 read_sequence<PlannedStep>(
                     reader, "plan.steps", kMaxPlanStepCount,
                     [](CanonicalReader& source) { return canonical_read_step(source); })));
  SCP_TRY(assign(value.site_snapshot_digest, read_digest(reader)));
  SCP_TRY(assign(value.evidence_digest, read_digest(reader)));
  SCP_TRY(assign(value.plan_digest, read_digest(reader)));
  return value;
}

// ---------------------------------------------------------------------------
// journal.hpp
// ---------------------------------------------------------------------------

void canonical_write(CanonicalWriter& writer, const JournalOperation& value) {
  writer.u8(static_cast<std::uint8_t>(value.kind));
  switch (value.kind) {
    case OperationKind::IngestEvidence:
      canonical_write(writer, value.evidence);
      return;
    case OperationKind::RetireEvidence:
      canonical_write(writer, value.evidence);
      return;
    case OperationKind::AdvanceSiteGeneration:
      writer.u64(value.site_generation.value());
      return;
    case OperationKind::RecordPlan:
      canonical_write(writer, value.plan);
      return;
    case OperationKind::RecordGrant:
      canonical_write(writer, value.grant);
      return;
    case OperationKind::RecordPolicy:
      canonical_write(writer, value.policy);
      return;
  }
}

Result<JournalOperation> canonical_read_operation(CanonicalReader& reader) {
  JournalOperation value;
  SCP_TRY(assign(value.kind, read_operation_kind(reader, "operation.kind")));
  switch (value.kind) {
    case OperationKind::IngestEvidence:
      SCP_TRY(assign(value.evidence, canonical_read_evidence(reader)));
      return value;
    case OperationKind::RetireEvidence:
      SCP_TRY(assign(value.evidence, canonical_read_evidence(reader)));
      return value;
    case OperationKind::AdvanceSiteGeneration:
      SCP_TRY(assign(value.site_generation, read_counter<SiteGenerationTag>(reader)));
      return value;
    case OperationKind::RecordPlan:
      SCP_TRY(assign(value.plan, canonical_read_plan(reader)));
      return value;
    case OperationKind::RecordGrant:
      SCP_TRY(assign(value.grant, canonical_read_grant(reader)));
      return value;
    case OperationKind::RecordPolicy:
      SCP_TRY(assign(value.policy, canonical_read_policy(reader)));
      return value;
  }
  return fail(StatusCode::InvalidEnum, "operation.kind is not representable");
}

void canonical_write(CanonicalWriter& writer, const JournalTransaction& value) {
  write_id(writer, value.id);
  write_sequence(writer, value.operations,
                 [](CanonicalWriter& target, const JournalOperation& operation) {
                   canonical_write(target, operation);
                 });
}

Result<JournalTransaction> canonical_read_transaction(CanonicalReader& reader) {
  JournalTransaction value;
  SCP_TRY(assign(value.id, read_id<TransactionIdTag>(reader)));
  SCP_TRY(assign(value.operations,
                 read_sequence<JournalOperation>(
                     reader, "transaction.operations",
                     static_cast<std::uint32_t>(kMaxOperationsPerTransaction),
                     [](CanonicalReader& source) { return canonical_read_operation(source); })));
  return value;
}

void canonical_write(CanonicalWriter& writer, const JournalSnapshot& value) {
  write_id(writer, value.site);
  writer.u64(value.site_generation.value());
  writer.u64(value.sequence.value());
  writer.i64(value.created_at.nanos);
  write_digest(writer, value.chain_digest);
  write_sequence(writer, value.evidence,
                 [](CanonicalWriter& target, const EvidenceRecord& record) {
                   canonical_write(target, record);
                 });
  write_sequence(writer, value.grants, [](CanonicalWriter& target, const DelegationGrant& grant) {
    canonical_write(target, grant);
  });
  canonical_write(writer, value.policy);
}

Result<JournalSnapshot> canonical_read_snapshot(CanonicalReader& reader) {
  JournalSnapshot value;
  SCP_TRY(assign(value.site, read_id<SiteIdTag>(reader)));
  SCP_TRY(assign(value.site_generation, read_counter<SiteGenerationTag>(reader)));
  SCP_TRY(assign(value.sequence, read_counter<JournalSequenceTag>(reader)));
  SCP_TRY(reader.i64(value.created_at.nanos));
  SCP_TRY(assign(value.chain_digest, read_digest(reader)));
  SCP_TRY(assign(value.evidence,
                 read_sequence<EvidenceRecord>(
                     reader, "snapshot.evidence",
                     static_cast<std::uint32_t>(kMaxAcceptedEvidenceRecords),
                     [](CanonicalReader& source) { return canonical_read_evidence(source); })));
  SCP_TRY(assign(value.grants,
                 read_sequence<DelegationGrant>(
                     reader, "snapshot.grants", kMaxGrantCount,
                     [](CanonicalReader& source) { return canonical_read_grant(source); })));
  SCP_TRY(assign(value.policy, canonical_read_policy(reader)));
  return value;
}

}  // namespace scp
