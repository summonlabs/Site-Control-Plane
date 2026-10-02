// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/evidence.hpp"

#include <algorithm>
#include "scp/checked.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace scp {
namespace {

void write_id(CanonicalWriter& writer, std::uint64_t high, std::uint64_t low) {
  writer.u64(high);
  writer.u64(low);
}

Status read_id(CanonicalReader& reader, const char* field, std::uint64_t& high,
               std::uint64_t& low) {
  Status status = reader.u64(high);
  if (!status.ok()) {
    return fail(status.code(), std::string(field) + ": " + status.message());
  }
  status = reader.u64(low);
  if (!status.ok()) {
    return fail(status.code(), std::string(field) + ": " + status.message());
  }
  return Status{};
}

void write_digest(CanonicalWriter& writer, const Digest& digest) {
  writer.bytes(std::span<const std::uint8_t>(digest.bytes().data(), digest.bytes().size()));
}

Status read_digest(CanonicalReader& reader, const char* field, Digest& out) {
  std::vector<std::uint8_t> buffer;
  Status status = reader.bytes(buffer, static_cast<std::uint32_t>(kDigestBytes));
  if (!status.ok()) {
    return fail(status.code(), std::string(field) + ": " + status.message());
  }
  if (buffer.size() != kDigestBytes) {
    return fail(StatusCode::Truncated, std::string(field) + ": digest must be 32 bytes");
  }
  std::array<std::uint8_t, kDigestBytes> bytes{};
  std::copy(buffer.begin(), buffer.end(), bytes.begin());
  out = Digest(bytes);
  return Status{};
}

/// Writes an enum as its underlying byte value.
template <class E>
void write_enum_u8(CanonicalWriter& writer, E value) {
  writer.u8(static_cast<std::uint8_t>(value));
}

/// Writes an enum as its underlying 16-bit value.
template <class E>
void write_enum_u16(CanonicalWriter& writer, E value) {
  writer.u16(static_cast<std::uint16_t>(value));
}

[[nodiscard]] Status unknown_enum(const char* field, std::uint64_t value) {
  return fail(StatusCode::InvalidEnum,
              std::string(field) + ": unrecognised enum value " + std::to_string(value));
}

/// Reads a byte and maps it through \p mapping, which returns false for an
/// unrecognised value. An integer is never cast directly to an enum.
template <class E, class Mapping>
Status read_enum_u8(CanonicalReader& reader, const char* field, E& out, Mapping mapping) {
  std::uint8_t raw = 0;
  const Status status = reader.u8(raw);
  if (!status.ok()) {
    return fail(status.code(), std::string(field) + ": " + status.message());
  }
  E mapped{};
  if (!mapping(raw, mapped)) {
    return unknown_enum(field, raw);
  }
  out = mapped;
  return Status{};
}

template <class E, class Mapping>
Status read_enum_u16(CanonicalReader& reader, const char* field, E& out, Mapping mapping) {
  std::uint16_t raw = 0;
  const Status status = reader.u16(raw);
  if (!status.ok()) {
    return fail(status.code(), std::string(field) + ": " + status.message());
  }
  E mapped{};
  if (!mapping(raw, mapped)) {
    return unknown_enum(field, raw);
  }
  out = mapped;
  return Status{};
}

bool map_authority(std::uint8_t raw, SourceAuthority& out) {
  switch (raw) {
    case 1: out = SourceAuthority::FacilityStateLedger; return true;
    case 2: out = SourceAuthority::FacilityCapacity; return true;
    case 3: out = SourceAuthority::PowerControlPlane; return true;
    case 4: out = SourceAuthority::ThermalControlPlane; return true;
    case 5: out = SourceAuthority::FacilityPolicyEngine; return true;
    case 6: out = SourceAuthority::IncidentStateFabric; return true;
    case 7: out = SourceAuthority::MaintenanceCoordinator; return true;
    case 8: out = SourceAuthority::AsiRuntime; return true;
    case 9: out = SourceAuthority::DfiRuntime; return true;
    case 10: out = SourceAuthority::ServiceClassRegistry; return true;
    default: return false;
  }
}

bool map_kind(std::uint16_t raw, EvidenceKind& out) {
  switch (raw) {
    case 1: out = EvidenceKind::FacilityState; return true;
    case 2: out = EvidenceKind::Lifecycle; return true;
    case 3: out = EvidenceKind::Capacity; return true;
    case 4: out = EvidenceKind::PowerReadiness; return true;
    case 5: out = EvidenceKind::CoolingReadiness; return true;
    case 6: out = EvidenceKind::Policy; return true;
    case 7: out = EvidenceKind::Incident; return true;
    case 8: out = EvidenceKind::Maintenance; return true;
    case 9: out = EvidenceKind::AsiCapability; return true;
    case 10: out = EvidenceKind::DfiCapability; return true;
    case 11: out = EvidenceKind::ServiceClass; return true;
    default: return false;
  }
}

bool map_lifecycle(std::uint8_t raw, LifecycleState& out) {
  switch (raw) {
    case 1: out = LifecycleState::Commissioning; return true;
    case 2: out = LifecycleState::Active; return true;
    case 3: out = LifecycleState::Draining; return true;
    case 4: out = LifecycleState::Maintenance; return true;
    case 5: out = LifecycleState::Emergency; return true;
    case 6: out = LifecycleState::Recovering; return true;
    case 7: out = LifecycleState::Isolated; return true;
    case 8: out = LifecycleState::Retired; return true;
    default: return false;
  }
}

bool map_severity(std::uint8_t raw, Severity& out) {
  switch (raw) {
    case 0: out = Severity::None; return true;
    case 1: out = Severity::Informational; return true;
    case 2: out = Severity::Minor; return true;
    case 3: out = Severity::Major; return true;
    case 4: out = Severity::Critical; return true;
    default: return false;
  }
}

bool map_readiness(std::uint8_t raw, ReadinessLevel& out) {
  switch (raw) {
    case 0: out = ReadinessLevel::Unknown; return true;
    case 1: out = ReadinessLevel::Unavailable; return true;
    case 2: out = ReadinessLevel::Degraded; return true;
    case 3: out = ReadinessLevel::Constrained; return true;
    case 4: out = ReadinessLevel::Ready; return true;
    default: return false;
  }
}

bool map_maintenance(std::uint8_t raw, MaintenanceMode& out) {
  switch (raw) {
    case 0: out = MaintenanceMode::None; return true;
    case 1: out = MaintenanceMode::Planned; return true;
    case 2: out = MaintenanceMode::Emergency; return true;
    case 3: out = MaintenanceMode::Overdue; return true;
    default: return false;
  }
}

bool map_origin(std::uint8_t raw, EvidenceOrigin& out) {
  switch (raw) {
    case 1: out = EvidenceOrigin::Ingested; return true;
    case 2: out = EvidenceOrigin::RecoveredFromJournal; return true;
    case 3: out = EvidenceOrigin::Revalidated; return true;
    default: return false;
  }
}


}  // namespace

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

std::string_view to_string(SourceAuthority authority) noexcept {
  switch (authority) {
    case SourceAuthority::FacilityStateLedger: return "facility-state-ledger";
    case SourceAuthority::FacilityCapacity: return "facility-capacity";
    case SourceAuthority::PowerControlPlane: return "power-control-plane";
    case SourceAuthority::ThermalControlPlane: return "thermal-control-plane";
    case SourceAuthority::FacilityPolicyEngine: return "facility-policy-engine";
    case SourceAuthority::IncidentStateFabric: return "incident-state-fabric";
    case SourceAuthority::MaintenanceCoordinator: return "maintenance-coordinator";
    case SourceAuthority::AsiRuntime: return "asi-runtime";
    case SourceAuthority::DfiRuntime: return "dfi-runtime";
    case SourceAuthority::ServiceClassRegistry: return "service-class-registry";
  }
  return "unknown-authority";
}

Result<SourceAuthority> source_authority_from_string(std::string_view text) {
  for (std::uint8_t raw = 1; raw <= static_cast<std::uint8_t>(kSourceAuthorityCount); ++raw) {
    SourceAuthority candidate{};
    if (map_authority(raw, candidate) && to_string(candidate) == text) {
      return candidate;
    }
  }
  return fail(StatusCode::InvalidArgument, "unrecognised source authority: " + std::string(text));
}

std::string_view to_string(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::FacilityState: return "facility-state";
    case EvidenceKind::Lifecycle: return "lifecycle";
    case EvidenceKind::Capacity: return "capacity";
    case EvidenceKind::PowerReadiness: return "power-readiness";
    case EvidenceKind::CoolingReadiness: return "cooling-readiness";
    case EvidenceKind::Policy: return "policy";
    case EvidenceKind::Incident: return "incident";
    case EvidenceKind::Maintenance: return "maintenance";
    case EvidenceKind::AsiCapability: return "asi-capability";
    case EvidenceKind::DfiCapability: return "dfi-capability";
    case EvidenceKind::ServiceClass: return "service-class";
  }
  return "unknown-kind";
}

Result<EvidenceKind> evidence_kind_from_string(std::string_view text) {
  for (std::uint16_t raw = 1; raw <= static_cast<std::uint16_t>(kEvidenceKindCount); ++raw) {
    EvidenceKind candidate{};
    if (map_kind(raw, candidate) && to_string(candidate) == text) {
      return candidate;
    }
  }
  return fail(StatusCode::InvalidArgument, "unrecognised evidence kind: " + std::string(text));
}

SourceAuthority owner_of(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::FacilityState:
    case EvidenceKind::Lifecycle:
      return SourceAuthority::FacilityStateLedger;
    case EvidenceKind::Capacity:
      return SourceAuthority::FacilityCapacity;
    case EvidenceKind::PowerReadiness:
      return SourceAuthority::PowerControlPlane;
    case EvidenceKind::CoolingReadiness:
      return SourceAuthority::ThermalControlPlane;
    case EvidenceKind::Policy:
      return SourceAuthority::FacilityPolicyEngine;
    case EvidenceKind::Incident:
      return SourceAuthority::IncidentStateFabric;
    case EvidenceKind::Maintenance:
      return SourceAuthority::MaintenanceCoordinator;
    case EvidenceKind::AsiCapability:
      return SourceAuthority::AsiRuntime;
    case EvidenceKind::DfiCapability:
      return SourceAuthority::DfiRuntime;
    case EvidenceKind::ServiceClass:
      return SourceAuthority::ServiceClassRegistry;
  }
  return SourceAuthority::FacilityStateLedger;
}

bool has_sole_owner(EvidenceKind kind) noexcept {
  return static_cast<std::uint16_t>(kind) >= 1 &&
         static_cast<std::uint16_t>(kind) <= static_cast<std::uint16_t>(kEvidenceKindCount);
}

bool is_authorized_publisher(SourceAuthority authority, EvidenceKind kind) noexcept {
  if (!has_sole_owner(kind)) {
    return false;
  }
  return owner_of(kind) == authority;
}

std::string_view to_string(LifecycleState state) noexcept {
  switch (state) {
    case LifecycleState::Commissioning: return "commissioning";
    case LifecycleState::Active: return "active";
    case LifecycleState::Draining: return "draining";
    case LifecycleState::Maintenance: return "maintenance";
    case LifecycleState::Emergency: return "emergency";
    case LifecycleState::Recovering: return "recovering";
    case LifecycleState::Isolated: return "isolated";
    case LifecycleState::Retired: return "retired";
  }
  return "unknown-lifecycle";
}

Result<LifecycleState> lifecycle_state_from_string(std::string_view text) {
  for (std::uint8_t raw = 1; raw <= 8; ++raw) {
    LifecycleState candidate{};
    if (map_lifecycle(raw, candidate) && to_string(candidate) == text) {
      return candidate;
    }
  }
  return fail(StatusCode::InvalidArgument, "unrecognised lifecycle state: " + std::string(text));
}

std::string_view to_string(Severity severity) noexcept {
  switch (severity) {
    case Severity::None: return "none";
    case Severity::Informational: return "informational";
    case Severity::Minor: return "minor";
    case Severity::Major: return "major";
    case Severity::Critical: return "critical";
  }
  return "unknown-severity";
}

std::string_view to_string(ReadinessLevel level) noexcept {
  switch (level) {
    case ReadinessLevel::Unknown: return "unknown";
    case ReadinessLevel::Unavailable: return "unavailable";
    case ReadinessLevel::Degraded: return "degraded";
    case ReadinessLevel::Constrained: return "constrained";
    case ReadinessLevel::Ready: return "ready";
  }
  return "unknown-readiness";
}

std::string_view to_string(MaintenanceMode mode) noexcept {
  switch (mode) {
    case MaintenanceMode::None: return "none";
    case MaintenanceMode::Planned: return "planned";
    case MaintenanceMode::Emergency: return "emergency";
    case MaintenanceMode::Overdue: return "overdue";
  }
  return "unknown-maintenance";
}

std::string_view to_string(EvidenceOrigin origin) noexcept {
  switch (origin) {
    case EvidenceOrigin::Ingested: return "ingested";
    case EvidenceOrigin::RecoveredFromJournal: return "recovered";
    case EvidenceOrigin::Revalidated: return "revalidated";
  }
  return "unknown-origin";
}

std::string_view to_string(Freshness freshness) noexcept {
  switch (freshness) {
    case Freshness::Fresh: return "fresh";
    case Freshness::Stale: return "stale";
    case Freshness::Expired: return "expired";
    case Freshness::Indeterminate: return "indeterminate";
  }
  return "unknown-freshness";
}

// ---------------------------------------------------------------------------
// Canonical form
// ---------------------------------------------------------------------------

void canonical_write(CanonicalWriter& writer, const Provenance& value) {
  write_enum_u8(writer, value.authority);
  write_id(writer, value.instance.high(), value.instance.low());
  writer.u64(value.epoch.value());
  writer.u64(value.generation.value());
  writer.u64(value.sequence.value());
  writer.i64(value.issued_at.nanos);
  writer.i64(value.valid_until.nanos);
  write_digest(writer, value.body_digest);
}

void canonical_write(CanonicalWriter& writer, const FacilityStateEvidence& value) {
  writer.u64(value.generation.value());
  write_enum_u8(writer, value.worst_active_severity);
  writer.u32(value.active_incidents);
  writer.boolean(value.degraded_operation);
  writer.boolean(value.emergency_declared);
  write_digest(writer, value.topology_digest);
}

void canonical_write(CanonicalWriter& writer, const LifecycleEvidence& value) {
  write_enum_u8(writer, value.state);
  writer.i64(value.entered_at.nanos);
  writer.boolean(value.transition_in_progress);
  write_digest(writer, value.transition_digest);
}

void canonical_write(CanonicalWriter& writer, const CapacityEvidence& value) {
  write_id(writer, value.snapshot.high(), value.snapshot.low());
  writer.u64(value.generation.value());
  writer.u64(value.total_units);
  writer.u64(value.committed_units);
  writer.u64(value.available_units);
  writer.boolean(value.oversubscribed);
}

void canonical_write(CanonicalWriter& writer, const ReadinessEvidence& value) {
  write_id(writer, value.snapshot.high(), value.snapshot.low());
  write_enum_u8(writer, value.readiness);
  writer.u64(value.headroom_milli_kw);
  writer.u32(value.available_domains);
  writer.u32(value.required_domains);
}

void canonical_write(CanonicalWriter& writer, const PolicyEvidence& value) {
  writer.u64(value.generation.value());
  write_digest(writer, value.rules_digest);
  writer.u32(value.rule_count);
}

void canonical_write(CanonicalWriter& writer, const IncidentEvidence& value) {
  writer.u32(value.active_incidents);
  write_enum_u8(writer, value.worst_active_severity);
  writer.boolean(value.emergency_declared);
  writer.i64(value.earliest_active.nanos);
  writer.u32(value.suppressed_incidents);
}

void canonical_write(CanonicalWriter& writer, const MaintenanceEvidence& value) {
  write_enum_u8(writer, value.mode);
  writer.u32(value.active_windows);
  writer.u32(value.scheduled_windows);
  writer.i64(value.next_window_start.nanos);
  writer.boolean(value.drain_in_progress);
  writer.u32(value.drained_percent);
}

void canonical_write(CanonicalWriter& writer, const CapabilityEvidence& value) {
  write_enum_u8(writer, value.readiness);
  writer.u32(value.ready_domains);
  writer.u32(value.total_domains);
  writer.u64(value.ready_units);
  write_digest(writer, value.capability_digest);
}

void canonical_write(CanonicalWriter& writer, const ServiceClassEvidence& value) {
  writer.u32(value.class_count);
  write_digest(writer, value.obligations_digest);
  writer.u32(static_cast<std::uint32_t>(value.obligations.size()));
  for (const ServiceClassObligation& obligation : value.obligations) {
    writer.name(obligation.service_class);
    writer.boolean(obligation.protected_class);
    writer.u32(obligation.minimum_ready_units);
    writer.u32(obligation.minimum_readiness_percent);
  }
}

Result<std::vector<std::uint8_t>> encode_body(const EvidenceBody& body) {
  CanonicalWriter writer;
  std::visit([&writer](const auto& value) { canonical_write(writer, value); }, body);
  if (writer.size() > kMaxBlobBytes) {
    return fail(StatusCode::LimitExceeded, "evidence body exceeds the maximum encoded size");
  }
  return writer.take();
}

namespace {

Status decode_facility_state(CanonicalReader& reader, EvidenceBody& out) {
  FacilityStateEvidence value;
  std::uint64_t generation = 0;
  SCP_TRY(reader.u64(generation));
  value.generation = FacilityStateGeneration(generation);
  SCP_TRY(read_enum_u8(reader, "facility_state.worst_active_severity", value.worst_active_severity,
                       map_severity));
  SCP_TRY(reader.u32(value.active_incidents));
  SCP_TRY(reader.boolean(value.degraded_operation));
  SCP_TRY(reader.boolean(value.emergency_declared));
  SCP_TRY(read_digest(reader, "facility_state.topology_digest", value.topology_digest));
  out = value;
  return Status{};
}

Status decode_lifecycle(CanonicalReader& reader, EvidenceBody& out) {
  LifecycleEvidence value;
  SCP_TRY(read_enum_u8(reader, "lifecycle.state", value.state, map_lifecycle));
  SCP_TRY(reader.i64(value.entered_at.nanos));
  SCP_TRY(reader.boolean(value.transition_in_progress));
  SCP_TRY(read_digest(reader, "lifecycle.transition_digest", value.transition_digest));
  out = value;
  return Status{};
}

Status decode_capacity(CanonicalReader& reader, EvidenceBody& out) {
  CapacityEvidence value;
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  SCP_TRY(read_id(reader, "capacity.snapshot", high, low));
  value.snapshot = SnapshotId(high, low);
  std::uint64_t generation = 0;
  SCP_TRY(reader.u64(generation));
  value.generation = CapacityGeneration(generation);
  SCP_TRY(reader.u64(value.total_units));
  SCP_TRY(reader.u64(value.committed_units));
  SCP_TRY(reader.u64(value.available_units));
  SCP_TRY(reader.boolean(value.oversubscribed));
  out = value;
  return Status{};
}

Status decode_readiness(CanonicalReader& reader, EvidenceBody& out) {
  ReadinessEvidence value;
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  SCP_TRY(read_id(reader, "readiness.snapshot", high, low));
  value.snapshot = SnapshotId(high, low);
  SCP_TRY(read_enum_u8(reader, "readiness.readiness", value.readiness, map_readiness));
  SCP_TRY(reader.u64(value.headroom_milli_kw));
  SCP_TRY(reader.u32(value.available_domains));
  SCP_TRY(reader.u32(value.required_domains));
  out = value;
  return Status{};
}

Status decode_policy(CanonicalReader& reader, EvidenceBody& out) {
  PolicyEvidence value;
  std::uint64_t generation = 0;
  SCP_TRY(reader.u64(generation));
  value.generation = PolicyGeneration(generation);
  SCP_TRY(read_digest(reader, "policy.rules_digest", value.rules_digest));
  SCP_TRY(reader.u32(value.rule_count));
  out = value;
  return Status{};
}

Status decode_incident(CanonicalReader& reader, EvidenceBody& out) {
  IncidentEvidence value;
  SCP_TRY(reader.u32(value.active_incidents));
  SCP_TRY(read_enum_u8(reader, "incident.worst_active_severity", value.worst_active_severity,
                       map_severity));
  SCP_TRY(reader.boolean(value.emergency_declared));
  SCP_TRY(reader.i64(value.earliest_active.nanos));
  SCP_TRY(reader.u32(value.suppressed_incidents));
  out = value;
  return Status{};
}

Status decode_maintenance(CanonicalReader& reader, EvidenceBody& out) {
  MaintenanceEvidence value;
  SCP_TRY(read_enum_u8(reader, "maintenance.mode", value.mode, map_maintenance));
  SCP_TRY(reader.u32(value.active_windows));
  SCP_TRY(reader.u32(value.scheduled_windows));
  SCP_TRY(reader.i64(value.next_window_start.nanos));
  SCP_TRY(reader.boolean(value.drain_in_progress));
  SCP_TRY(reader.u32(value.drained_percent));
  if (value.drained_percent > 100) {
    return fail(StatusCode::OutOfRange, "maintenance.drained_percent: must be 0..100");
  }
  out = value;
  return Status{};
}

Status decode_capability(CanonicalReader& reader, const char* field, EvidenceBody& out) {
  CapabilityEvidence value;
  SCP_TRY(read_enum_u8(reader, field, value.readiness, map_readiness));
  SCP_TRY(reader.u32(value.ready_domains));
  SCP_TRY(reader.u32(value.total_domains));
  SCP_TRY(reader.u64(value.ready_units));
  const std::string digest_field = std::string(field) + ".capability_digest";
  SCP_TRY(read_digest(reader, digest_field.c_str(), value.capability_digest));
  if (value.ready_domains > value.total_domains) {
    return fail(StatusCode::OutOfRange,
                std::string(field) + ": ready_domains must not exceed total_domains");
  }
  out = value;
  return Status{};
}

Status decode_service_class(CanonicalReader& reader, EvidenceBody& out) {
  ServiceClassEvidence value;
  SCP_TRY(reader.u32(value.class_count));
  SCP_TRY(read_digest(reader, "service_class.obligations_digest", value.obligations_digest));
  std::uint32_t count = 0;
  SCP_TRY(reader.u32(count));
  if (count > kMaxServiceClasses) {
    return fail(StatusCode::LimitExceeded,
                "service_class.obligations: declared " + std::to_string(count) +
                    " entries, the limit is " + std::to_string(kMaxServiceClasses));
  }
  value.obligations.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    ServiceClassObligation obligation;
    std::string name_text;
    SCP_TRY(reader.text(name_text, static_cast<std::uint32_t>(kMaxNameBytes)));
    const Result<Name> parsed = Name::parse(name_text);
    if (!parsed.has_value()) {
      return fail(parsed.status().code(), "service_class.obligations.name: " + parsed.status().message());
    }
    obligation.service_class = parsed.value();
    SCP_TRY(reader.boolean(obligation.protected_class));
    SCP_TRY(reader.u32(obligation.minimum_ready_units));
    SCP_TRY(reader.u32(obligation.minimum_readiness_percent));
    if (obligation.minimum_readiness_percent > 100) {
      return fail(StatusCode::OutOfRange,
                  "service_class.obligations.minimum_readiness_percent: must be 0..100");
    }
    value.obligations.push_back(obligation);
  }
  out = value;
  return Status{};
}

}  // namespace

Result<EvidenceBody> decode_body(EvidenceKind kind, std::uint16_t schema_version,
                                 std::span<const std::uint8_t> body) {
  if (schema_version != kEvidenceSchemaVersion) {
    return fail(StatusCode::UnsupportedFormatVersion,
                "evidence schema version " + std::to_string(schema_version) +
                    " is not supported by this build (expected " +
                    std::to_string(kEvidenceSchemaVersion) + ")");
  }
  if (body.size() > kMaxBlobBytes) {
    return fail(StatusCode::LimitExceeded, "evidence body exceeds the maximum decoded size");
  }
  CanonicalReader reader(body);
  EvidenceBody decoded{};
  Status status;
  switch (kind) {
    case EvidenceKind::FacilityState:
      status = decode_facility_state(reader, decoded);
      break;
    case EvidenceKind::Lifecycle:
      status = decode_lifecycle(reader, decoded);
      break;
    case EvidenceKind::Capacity:
      status = decode_capacity(reader, decoded);
      break;
    case EvidenceKind::PowerReadiness:
      status = decode_readiness(reader, decoded);
      break;
    case EvidenceKind::CoolingReadiness:
      status = decode_readiness(reader, decoded);
      break;
    case EvidenceKind::Policy:
      status = decode_policy(reader, decoded);
      break;
    case EvidenceKind::Incident:
      status = decode_incident(reader, decoded);
      break;
    case EvidenceKind::Maintenance:
      status = decode_maintenance(reader, decoded);
      break;
    case EvidenceKind::AsiCapability:
      status = decode_capability(reader, "asi_capability", decoded);
      break;
    case EvidenceKind::DfiCapability:
      status = decode_capability(reader, "dfi_capability", decoded);
      break;
    case EvidenceKind::ServiceClass:
      status = decode_service_class(reader, decoded);
      break;
    default:
      return fail(StatusCode::Unsupported,
                  "evidence kind " + std::to_string(static_cast<std::uint16_t>(kind)) +
                      " is not supported by this build");
  }
  if (!status.ok()) {
    return status;
  }
  status = reader.expect_end();
  if (!status.ok()) {
    return fail(status.code(), "evidence body: " + status.message());
  }
  return decoded;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

Result<EvidenceId> derive_evidence_id(const Provenance& provenance, EvidenceKind kind,
                                      std::uint16_t schema_version,
                                      std::span<const std::uint8_t> body) {
  CanonicalWriter writer;
  canonical_write(writer, provenance);
  writer.u16(static_cast<std::uint16_t>(kind));
  writer.u16(schema_version);
  writer.u32(static_cast<std::uint32_t>(body.size()));
  writer.bytes(body);
  const Digest digest = Digest::of(writer.span());
  const auto& bytes = digest.bytes();
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    high = (high << 8U) | bytes[index];
    low = (low << 8U) | bytes[index + 8];
  }
  return EvidenceId(high, low);
}

Result<EvidenceRecord> EvidenceRecord::create(Provenance provenance, EvidenceKind kind,
                                              std::uint16_t schema_version,
                                              std::vector<std::uint8_t> body) {
  if (!has_sole_owner(kind)) {
    return fail(StatusCode::Unsupported,
                "evidence kind " + std::to_string(static_cast<std::uint16_t>(kind)) +
                    " has no owning authority in this schema version");
  }
  if (!is_authorized_publisher(provenance.authority, kind)) {
    return fail(StatusCode::Unauthorized,
                std::string(to_string(provenance.authority)) + " does not own evidence kind " +
                    std::string(to_string(kind)));
  }
  if (body.size() > kMaxBlobBytes) {
    return fail(StatusCode::LimitExceeded, "evidence body exceeds the maximum encoded size");
  }
  EvidenceRecord record;
  record.kind = kind;
  record.schema_version = schema_version;
  record.body = std::move(body);
  provenance.body_digest = Digest::of(record.body);
  const Result<EvidenceId> id = derive_evidence_id(provenance, kind, schema_version, record.body);
  if (!id.has_value()) {
    return id.status();
  }
  record.id = id.value();
  record.provenance = provenance;
  return record;
}

Result<EvidenceRecord> EvidenceRecord::create(Provenance provenance, EvidenceKind kind,
                                              const EvidenceBody& payload) {
  const Result<std::vector<std::uint8_t>> body = encode_body(payload);
  if (!body.has_value()) {
    return body.status();
  }
  return create(provenance, kind, kEvidenceSchemaVersion, body.value());
}

Result<bool> EvidenceRecord::verify_body_digest() const {
  const Digest computed = Digest::of(body);
  return computed == provenance.body_digest;
}

Result<bool> EvidenceRecord::verify_identity() const {
  const Result<EvidenceId> derived =
      derive_evidence_id(provenance, kind, schema_version, body);
  if (!derived.has_value()) {
    return derived.status();
  }
  return derived.value() == id;
}

Status EvidenceRecord::validate() const {
  if (id.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "evidence identity is not set");
  }
  if (provenance.instance.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "evidence source instance is not set");
  }
  if (provenance.epoch.is_unset()) {
    return fail(StatusCode::InvalidArgument,
                "evidence epoch is not set; a source that cannot fence its own restart cannot "
                "publish authoritative evidence");
  }
  if (provenance.generation.is_unset()) {
    return fail(StatusCode::InvalidArgument, "evidence source generation is not set");
  }
  if (provenance.sequence.is_unset()) {
    return fail(StatusCode::InvalidArgument, "evidence sequence is not set");
  }
  if (!provenance.issued_at.is_set()) {
    return fail(StatusCode::InvalidArgument, "evidence issue time is not set");
  }
  if (body.size() > kMaxBlobBytes) {
    return fail(StatusCode::LimitExceeded, "evidence body exceeds the maximum encoded size");
  }
  if (!has_sole_owner(kind)) {
    return fail(StatusCode::Unsupported,
                "evidence kind has no owning authority in this schema version");
  }
  if (!is_authorized_publisher(provenance.authority, kind)) {
    return fail(StatusCode::Unauthorized,
                std::string(to_string(provenance.authority)) + " does not own evidence kind " +
                    std::string(to_string(kind)));
  }
  if (schema_version != kEvidenceSchemaVersion) {
    return fail(StatusCode::UnsupportedFormatVersion,
                "evidence schema version " + std::to_string(schema_version) +
                    " is not supported by this build");
  }
  const Result<bool> digest_ok = verify_body_digest();
  if (!digest_ok.has_value()) {
    return digest_ok.status();
  }
  if (!digest_ok.value()) {
    return fail(StatusCode::ChecksumMismatch,
                "evidence body does not match the digest recorded in its provenance");
  }
  const Result<bool> identity_ok = verify_identity();
  if (!identity_ok.has_value()) {
    return identity_ok.status();
  }
  if (!identity_ok.value()) {
    return fail(StatusCode::InvalidIdentifier,
                "evidence identity is not the identity its content derives");
  }
  return Status{};
}

std::vector<std::uint8_t> EvidenceRecord::canonical_bytes() const {
  CanonicalWriter writer;
  canonical_write(writer, *this);
  return writer.take();
}

void canonical_write(CanonicalWriter& writer, const EvidenceRecord& value) {
  write_id(writer, value.id.high(), value.id.low());
  canonical_write(writer, value.provenance);
  writer.u16(static_cast<std::uint16_t>(value.kind));
  writer.u16(value.schema_version);
  writer.bytes(value.body);
  write_enum_u8(writer, value.origin);
  writer.i64(value.revalidated_at.nanos);
}

Result<EvidenceRecord> canonical_read_evidence(CanonicalReader& reader) {
  EvidenceRecord record;
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  SCP_TRY(read_id(reader, "evidence.id", high, low));
  record.id = EvidenceId(high, low);

  Provenance provenance;
  SCP_TRY(read_enum_u8(reader, "evidence.authority", provenance.authority, map_authority));
  std::uint64_t instance_high = 0;
  std::uint64_t instance_low = 0;
  SCP_TRY(read_id(reader, "evidence.instance", instance_high, instance_low));
  provenance.instance = SourceInstanceId(instance_high, instance_low);
  std::uint64_t epoch = 0;
  SCP_TRY(reader.u64(epoch));
  provenance.epoch = Epoch(epoch);
  std::uint64_t generation = 0;
  SCP_TRY(reader.u64(generation));
  provenance.generation = SourceGeneration(generation);
  std::uint64_t sequence = 0;
  SCP_TRY(reader.u64(sequence));
  provenance.sequence = Sequence(sequence);
  SCP_TRY(reader.i64(provenance.issued_at.nanos));
  SCP_TRY(reader.i64(provenance.valid_until.nanos));
  SCP_TRY(read_digest(reader, "evidence.body_digest", provenance.body_digest));
  record.provenance = provenance;

  std::uint16_t kind = 0;
  SCP_TRY(reader.u16(kind));
  if (!map_kind(kind, record.kind)) {
    return unknown_enum("evidence.kind", kind);
  }
  SCP_TRY(reader.u16(record.schema_version));
  SCP_TRY(reader.bytes(record.body, kMaxBlobBytes));
  SCP_TRY(read_enum_u8(reader, "evidence.origin", record.origin, map_origin));
  SCP_TRY(reader.i64(record.revalidated_at.nanos));
  return record;
}

EvidenceSlot slot_of(const EvidenceRecord& record) noexcept {
  return EvidenceSlot{record.provenance.authority, record.kind};
}

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

Freshness classify_freshness(const EvidenceRecord& record, Timestamp evaluation_time,
                             const FreshnessPolicy& policy) {
  if (!record.provenance.issued_at.is_set()) {
    return Freshness::Indeterminate;
  }
  if (evaluation_time.nanos < record.provenance.issued_at.nanos) {
    // Evidence dated in the future cannot be judged: the evaluator's clock and
    // the publisher's clock disagree, and guessing which one is right would be
    // inferring a fact.
    return Freshness::Indeterminate;
  }
  if (record.provenance.valid_until.is_set()) {
    if (evaluation_time.nanos >= record.provenance.valid_until.nanos) {
      return Freshness::Expired;
    }
    return Freshness::Fresh;
  }
  if (record.origin == EvidenceOrigin::RecoveredFromJournal && !policy.recovered_ages_out) {
    return Freshness::Fresh;
  }
  const Result<std::int64_t> age =
      checked_sub(evaluation_time.nanos, record.provenance.issued_at.nanos);
  if (!age.has_value()) {
    // The gap between the evaluation instant and the publication is larger than
    // a duration can express, so the publication is arbitrarily old. Wrapping
    // the subtraction would make it look fresh, which is the one answer it is
    // definitely not.
    return Freshness::Expired;
  }
  if (age.value() > policy.expire_after.nanos) {
    return Freshness::Expired;
  }
  if (age.value() > policy.stale_after.nanos) {
    return Freshness::Stale;
  }
  return Freshness::Fresh;
}

bool participates(Freshness freshness) noexcept {
  return freshness == Freshness::Fresh;
}

}  // namespace scp

