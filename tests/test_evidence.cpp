// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

// The evidence and provenance layer: who may publish which fact, what the
// content-addressed identity covers, how a record is validated, encoded and
// decoded, and where the freshness boundary sits.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/composition.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"
#include "scp/version.hpp"
#include "test_support.hpp"

using scp::CanonicalReader;
using scp::CanonicalWriter;
using scp::Digest;
using scp::EvidenceBody;
using scp::EvidenceId;
using scp::EvidenceKind;
using scp::EvidenceRecord;
using scp::FacilityStateEvidence;
using scp::Freshness;
using scp::FreshnessPolicy;
using scp::Name;
using scp::Provenance;
using scp::ReadinessEvidence;
using scp::Result;
using scp::ServiceClassEvidence;
using scp::ServiceClassObligation;
using scp::SourceAuthority;
using scp::StatusCode;
using scp::Status;
using scp::Timestamp;

namespace {

constexpr std::array<EvidenceKind, scp::kEvidenceKindCount> kKinds = {
    EvidenceKind::FacilityState,   EvidenceKind::Lifecycle,      EvidenceKind::Capacity,
    EvidenceKind::PowerReadiness,  EvidenceKind::CoolingReadiness, EvidenceKind::Policy,
    EvidenceKind::Incident,        EvidenceKind::Maintenance,    EvidenceKind::AsiCapability,
    EvidenceKind::DfiCapability,   EvidenceKind::ServiceClass};

constexpr std::array<SourceAuthority, scp::kSourceAuthorityCount> kAuthorities = {
    SourceAuthority::FacilityStateLedger, SourceAuthority::FacilityCapacity,
    SourceAuthority::PowerControlPlane,   SourceAuthority::ThermalControlPlane,
    SourceAuthority::FacilityPolicyEngine, SourceAuthority::IncidentStateFabric,
    SourceAuthority::MaintenanceCoordinator, SourceAuthority::AsiRuntime,
    SourceAuthority::DfiRuntime,          SourceAuthority::ServiceClassRegistry};

/// Seeded, deterministic pseudo-randomness. Never a wall clock, never
/// std::random_device: the same seed produces the same sweep on every host.
std::uint64_t splitmix64(std::uint64_t& state) {
  state += 0x9E3779B97F4A7C15ULL;
  std::uint64_t value = state;
  value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
  return value ^ (value >> 31U);
}

Digest digest_of_text(std::string_view text) {
  return Digest::of(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

Name name_of(std::string_view text) {
  const Result<Name> parsed = Name::parse(text);
  if (!parsed.has_value()) {
    ::scp_test::Context::instance().note("fixture name did not parse: " + std::string(text));
    SCP_CHECK(false);
    return Name();
  }
  return parsed.value();
}

void expect_ok(const Status& status, const char* what) {
  if (!status.ok()) {
    ::scp_test::Context::instance().note(std::string(what) + " failed: " + status.to_string());
  }
  SCP_CHECK(status.ok());
}

void expect_status_code(const Status& status, StatusCode expected, const char* what) {
  if (status.code() != expected) {
    ::scp_test::Context::instance().note(std::string(what) + ": reported " + status.to_string() +
                                         " instead of " + std::string(scp::to_string(expected)));
  }
  SCP_CHECK(status.code() == expected);
}

template <class T>
void expect_error_code(const Result<T>& result, StatusCode expected, const char* what) {
  if (result.has_value()) {
    ::scp_test::Context::instance().note(std::string(what) + ": expected " +
                                         std::string(scp::to_string(expected)) +
                                         " but the call succeeded");
    SCP_CHECK(false);
    return;
  }
  expect_status_code(result.status(), expected, what);
}

/// A truncated input may surface as any member of the Truncated family; what
/// matters is that it is never accepted.
bool is_truncated_family(StatusCode code) {
  return code == StatusCode::Truncated || code == StatusCode::TornTail ||
         code == StatusCode::InteriorCorruption || code == StatusCode::Corrupt;
}

Provenance provenance_for(SourceAuthority authority, std::uint64_t seed = 1) {
  Provenance provenance;
  provenance.authority = authority;
  provenance.instance = scp_test::instance_for(seed);
  provenance.epoch = scp::Epoch(1);
  provenance.generation = scp::SourceGeneration(1);
  provenance.sequence = scp::Sequence(1);
  provenance.issued_at = scp_test::base_instant();
  return provenance;
}

// ---------------------------------------------------------------------------
// Sample payloads: every field carries a value that differs from its default,
// so a round trip that silently dropped a field would be visible.
// ---------------------------------------------------------------------------

FacilityStateEvidence sample_facility() {
  FacilityStateEvidence value;
  value.generation = scp::FacilityStateGeneration(7);
  value.worst_active_severity = scp::Severity::Major;
  value.active_incidents = 3;
  value.degraded_operation = true;
  value.emergency_declared = true;
  value.topology_digest = digest_of_text("topology");
  return value;
}

scp::LifecycleEvidence sample_lifecycle() {
  scp::LifecycleEvidence value;
  value.state = scp::LifecycleState::Recovering;
  value.entered_at = scp_test::instant_after(123);
  value.transition_in_progress = true;
  value.transition_digest = digest_of_text("transition");
  return value;
}

scp::CapacityEvidence sample_capacity() {
  scp::CapacityEvidence value;
  value.snapshot = scp::SnapshotId(0x1111111111111111ULL, 0x2222222222222222ULL);
  value.generation = scp::CapacityGeneration(9);
  value.total_units = 1000;
  value.committed_units = 250;
  value.available_units = 750;
  value.oversubscribed = true;
  return value;
}

ReadinessEvidence sample_readiness() {
  ReadinessEvidence value;
  value.snapshot = scp::SnapshotId(0x3333333333333333ULL, 0x4444444444444444ULL);
  value.readiness = scp::ReadinessLevel::Constrained;
  value.headroom_milli_kw = 123456;
  value.available_domains = 3;
  value.required_domains = 4;
  return value;
}

scp::PolicyEvidence sample_policy() {
  scp::PolicyEvidence value;
  value.generation = scp::PolicyGeneration(5);
  value.rules_digest = digest_of_text("rules");
  value.rule_count = 12;
  return value;
}

scp::IncidentEvidence sample_incident() {
  scp::IncidentEvidence value;
  value.active_incidents = 2;
  value.worst_active_severity = scp::Severity::Critical;
  value.emergency_declared = true;
  value.earliest_active = scp_test::instant_after(7);
  value.suppressed_incidents = 1;
  return value;
}

scp::MaintenanceEvidence sample_maintenance() {
  scp::MaintenanceEvidence value;
  value.mode = scp::MaintenanceMode::Overdue;
  value.active_windows = 1;
  value.scheduled_windows = 2;
  value.next_window_start = scp_test::instant_after(3600);
  value.drain_in_progress = true;
  value.drained_percent = 42;
  return value;
}

scp::CapabilityEvidence sample_capability() {
  scp::CapabilityEvidence value;
  value.readiness = scp::ReadinessLevel::Degraded;
  value.ready_domains = 3;
  value.total_domains = 8;
  value.ready_units = 99;
  value.capability_digest = digest_of_text("capability");
  return value;
}

ServiceClassEvidence sample_service_classes() {
  ServiceClassEvidence value;
  value.class_count = 2;
  value.obligations_digest = digest_of_text("obligations");
  ServiceClassObligation first;
  first.service_class = name_of("interactive-inference");
  first.protected_class = true;
  first.minimum_ready_units = 16;
  first.minimum_readiness_percent = 50;
  ServiceClassObligation second;
  second.service_class = name_of("batch-training");
  second.protected_class = false;
  second.minimum_ready_units = 4;
  second.minimum_readiness_percent = 25;
  value.obligations.push_back(first);
  value.obligations.push_back(second);
  return value;
}

EvidenceBody sample_body(EvidenceKind kind) {
  switch (kind) {
    case EvidenceKind::FacilityState: return EvidenceBody{sample_facility()};
    case EvidenceKind::Lifecycle: return EvidenceBody{sample_lifecycle()};
    case EvidenceKind::Capacity: return EvidenceBody{sample_capacity()};
    case EvidenceKind::PowerReadiness:
    case EvidenceKind::CoolingReadiness: return EvidenceBody{sample_readiness()};
    case EvidenceKind::Policy: return EvidenceBody{sample_policy()};
    case EvidenceKind::Incident: return EvidenceBody{sample_incident()};
    case EvidenceKind::Maintenance: return EvidenceBody{sample_maintenance()};
    case EvidenceKind::AsiCapability:
    case EvidenceKind::DfiCapability: return EvidenceBody{sample_capability()};
    case EvidenceKind::ServiceClass: return EvidenceBody{sample_service_classes()};
  }
  return EvidenceBody{sample_facility()};
}

// ---------------------------------------------------------------------------
// Field-by-field body comparison. The test owns these comparisons so that a
// field added to a payload without a matching codec change is caught here.
// ---------------------------------------------------------------------------

bool same_facility(const FacilityStateEvidence& lhs, const FacilityStateEvidence& rhs) {
  return lhs.generation == rhs.generation &&
         lhs.worst_active_severity == rhs.worst_active_severity &&
         lhs.active_incidents == rhs.active_incidents &&
         lhs.degraded_operation == rhs.degraded_operation &&
         lhs.emergency_declared == rhs.emergency_declared &&
         lhs.topology_digest == rhs.topology_digest;
}

bool same_lifecycle(const scp::LifecycleEvidence& lhs, const scp::LifecycleEvidence& rhs) {
  return lhs.state == rhs.state && lhs.entered_at == rhs.entered_at &&
         lhs.transition_in_progress == rhs.transition_in_progress &&
         lhs.transition_digest == rhs.transition_digest;
}

bool same_capacity(const scp::CapacityEvidence& lhs, const scp::CapacityEvidence& rhs) {
  return lhs.snapshot == rhs.snapshot && lhs.generation == rhs.generation &&
         lhs.total_units == rhs.total_units && lhs.committed_units == rhs.committed_units &&
         lhs.available_units == rhs.available_units && lhs.oversubscribed == rhs.oversubscribed;
}

bool same_readiness(const ReadinessEvidence& lhs, const ReadinessEvidence& rhs) {
  return lhs.snapshot == rhs.snapshot && lhs.readiness == rhs.readiness &&
         lhs.headroom_milli_kw == rhs.headroom_milli_kw &&
         lhs.available_domains == rhs.available_domains &&
         lhs.required_domains == rhs.required_domains;
}

bool same_policy(const scp::PolicyEvidence& lhs, const scp::PolicyEvidence& rhs) {
  return lhs.generation == rhs.generation && lhs.rules_digest == rhs.rules_digest &&
         lhs.rule_count == rhs.rule_count;
}

bool same_incident(const scp::IncidentEvidence& lhs, const scp::IncidentEvidence& rhs) {
  return lhs.active_incidents == rhs.active_incidents &&
         lhs.worst_active_severity == rhs.worst_active_severity &&
         lhs.emergency_declared == rhs.emergency_declared &&
         lhs.earliest_active == rhs.earliest_active &&
         lhs.suppressed_incidents == rhs.suppressed_incidents;
}

bool same_maintenance(const scp::MaintenanceEvidence& lhs, const scp::MaintenanceEvidence& rhs) {
  return lhs.mode == rhs.mode && lhs.active_windows == rhs.active_windows &&
         lhs.scheduled_windows == rhs.scheduled_windows &&
         lhs.next_window_start == rhs.next_window_start &&
         lhs.drain_in_progress == rhs.drain_in_progress &&
         lhs.drained_percent == rhs.drained_percent;
}

bool same_capability(const scp::CapabilityEvidence& lhs, const scp::CapabilityEvidence& rhs) {
  return lhs.readiness == rhs.readiness && lhs.ready_domains == rhs.ready_domains &&
         lhs.total_domains == rhs.total_domains && lhs.ready_units == rhs.ready_units &&
         lhs.capability_digest == rhs.capability_digest;
}

bool same_obligation(const ServiceClassObligation& lhs, const ServiceClassObligation& rhs) {
  return lhs.service_class == rhs.service_class && lhs.protected_class == rhs.protected_class &&
         lhs.minimum_ready_units == rhs.minimum_ready_units &&
         lhs.minimum_readiness_percent == rhs.minimum_readiness_percent;
}

bool same_service_classes(const ServiceClassEvidence& lhs, const ServiceClassEvidence& rhs) {
  if (lhs.class_count != rhs.class_count || lhs.obligations_digest != rhs.obligations_digest ||
      lhs.obligations.size() != rhs.obligations.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lhs.obligations.size(); ++index) {
    if (!same_obligation(lhs.obligations[index], rhs.obligations[index])) {
      return false;
    }
  }
  return true;
}

bool same_body(const EvidenceBody& lhs, const EvidenceBody& rhs) {
  if (lhs.index() != rhs.index()) {
    return false;
  }
  if (const auto* value = std::get_if<FacilityStateEvidence>(&lhs)) {
    return same_facility(*value, std::get<FacilityStateEvidence>(rhs));
  }
  if (const auto* value = std::get_if<scp::LifecycleEvidence>(&lhs)) {
    return same_lifecycle(*value, std::get<scp::LifecycleEvidence>(rhs));
  }
  if (const auto* value = std::get_if<scp::CapacityEvidence>(&lhs)) {
    return same_capacity(*value, std::get<scp::CapacityEvidence>(rhs));
  }
  if (const auto* value = std::get_if<ReadinessEvidence>(&lhs)) {
    return same_readiness(*value, std::get<ReadinessEvidence>(rhs));
  }
  if (const auto* value = std::get_if<scp::PolicyEvidence>(&lhs)) {
    return same_policy(*value, std::get<scp::PolicyEvidence>(rhs));
  }
  if (const auto* value = std::get_if<scp::IncidentEvidence>(&lhs)) {
    return same_incident(*value, std::get<scp::IncidentEvidence>(rhs));
  }
  if (const auto* value = std::get_if<scp::MaintenanceEvidence>(&lhs)) {
    return same_maintenance(*value, std::get<scp::MaintenanceEvidence>(rhs));
  }
  if (const auto* value = std::get_if<scp::CapabilityEvidence>(&lhs)) {
    return same_capability(*value, std::get<scp::CapabilityEvidence>(rhs));
  }
  const auto* value = std::get_if<ServiceClassEvidence>(&lhs);
  return value != nullptr && same_service_classes(*value, std::get<ServiceClassEvidence>(rhs));
}

/// Rebuilds a service-class body by hand so a test can place bytes the typed
/// encoder would never produce (bad UTF-8, an oversized name, a huge declared
/// count) in front of the decoder.
std::vector<std::uint8_t> service_class_body(std::string_view name, std::uint32_t declared) {
  CanonicalWriter writer;
  writer.u32(1);
  const std::array<std::uint8_t, scp::kDigestBytes> zeros{};
  writer.bytes(std::span<const std::uint8_t>(zeros.data(), zeros.size()));
  writer.u32(declared);
  if (declared >= 1U) {
    writer.bytes(name);
    writer.boolean(false);
    writer.u32(0);
    writer.u32(50);
  }
  return writer.take();
}

std::vector<std::uint8_t> obligations_body(std::size_t count) {
  CanonicalWriter writer;
  writer.u32(static_cast<std::uint32_t>(count));
  const std::array<std::uint8_t, scp::kDigestBytes> zeros{};
  writer.bytes(std::span<const std::uint8_t>(zeros.data(), zeros.size()));
  writer.u32(static_cast<std::uint32_t>(count));
  for (std::size_t index = 0; index < count; ++index) {
    writer.bytes(std::string_view("service-class-name"));
    writer.boolean(true);
    writer.u32(1);
    writer.u32(50);
  }
  return writer.take();
}

void check_identity_differs(const EvidenceId& baseline, const Provenance& provenance,
                            EvidenceKind kind, std::uint16_t schema_version,
                            std::span<const std::uint8_t> body, const char* what) {
  const Result<EvidenceId> derived = scp::derive_evidence_id(provenance, kind, schema_version, body);
  if (!derived.has_value()) {
    ::scp_test::Context::instance().note(std::string(what) + ": derivation failed: " +
                                         derived.status().to_string());
    SCP_CHECK(false);
    return;
  }
  if (derived.value() == baseline) {
    ::scp_test::Context::instance().note(std::string(what) +
                                         ": identity did not change when the field changed");
  }
  SCP_CHECK(derived.value() != baseline);
}

}  // namespace

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

SCP_TEST(every_kind_has_exactly_one_owner) {
  for (const EvidenceKind kind : kKinds) {
    SCP_CHECK(scp::has_sole_owner(kind));
    const SourceAuthority owner = scp::owner_of(kind);
    std::size_t authorized = 0;
    for (const SourceAuthority authority : kAuthorities) {
      if (scp::is_authorized_publisher(authority, kind)) {
        ++authorized;
        SCP_CHECK_EQ(authority, owner);
      }
    }
    if (authorized != 1U) {
      ::scp_test::Context::instance().note(std::string("kind ") + std::string(scp::to_string(kind)) +
                                           " has " + std::to_string(authorized) + " owners");
    }
    SCP_CHECK_EQ(authorized, std::size_t{1});
  }

  // Every other authority is refused at ingestion with Unauthorized, for every
  // kind, before any body is examined.
  const std::vector<std::uint8_t> body{0x01U, 0x02U, 0x03U};
  for (const EvidenceKind kind : kKinds) {
    const SourceAuthority owner = scp::owner_of(kind);
    std::uint64_t seed = static_cast<std::uint64_t>(kind);
    for (const SourceAuthority authority : kAuthorities) {
      if (authority == owner) {
        continue;
      }
      Provenance provenance = provenance_for(authority, 1 + (splitmix64(seed) % 5U));
      provenance.authority = authority;
      const Result<EvidenceRecord> refused =
          EvidenceRecord::create(provenance, kind, scp::kEvidenceSchemaVersion, body);
      expect_error_code(refused, StatusCode::Unauthorized, "create from a non-owner authority");
    }
  }

  // The vocabulary is symmetric: every authority name round-trips and owns the
  // kind it names.
  for (const SourceAuthority authority : kAuthorities) {
    const Result<SourceAuthority> parsed = scp::source_authority_from_string(scp::to_string(authority));
    SCP_CHECK(parsed.has_value());
    if (parsed.has_value()) {
      SCP_CHECK_EQ(parsed.value(), authority);
    }
  }
  for (const EvidenceKind kind : kKinds) {
    const Result<EvidenceKind> parsed = scp::evidence_kind_from_string(scp::to_string(kind));
    SCP_CHECK(parsed.has_value());
    if (parsed.has_value()) {
      SCP_CHECK_EQ(parsed.value(), kind);
    }
  }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

SCP_TEST(create_derives_digest_and_identity) {
  for (const EvidenceKind kind : kKinds) {
    scp_test::RecordSpec spec;
    spec.authority = scp::owner_of(kind);
    const Result<EvidenceRecord> first = scp_test::make_record(spec, kind, sample_body(kind));
    SCP_REQUIRE_OK(first);
    const EvidenceRecord& record = first.value();

    SCP_CHECK(!record.id.is_nil());
    SCP_CHECK(!record.provenance.body_digest.is_zero());

    const Result<bool> digest_ok = record.verify_body_digest();
    SCP_REQUIRE_OK(digest_ok);
    SCP_CHECK(digest_ok.value());

    const Result<bool> identity_ok = record.verify_identity();
    SCP_REQUIRE_OK(identity_ok);
    SCP_CHECK(identity_ok.value());

    expect_ok(record.validate(), "a freshly created record validates");

    // The identity is the derived one, not merely present.
    const Result<EvidenceId> derived = scp::derive_evidence_id(
        record.provenance, record.kind, record.schema_version,
        std::span<const std::uint8_t>(record.body.data(), record.body.size()));
    SCP_REQUIRE_OK(derived);
    SCP_CHECK_EQ(derived.value(), record.id);

    // Repeated creation from the same inputs is the same record.
    const Result<EvidenceRecord> second = scp_test::make_record(spec, kind, sample_body(kind));
    SCP_REQUIRE_OK(second);
    SCP_CHECK_EQ(second.value().id, record.id);
    SCP_CHECK_EQ(second.value().provenance.body_digest, record.provenance.body_digest);
    SCP_CHECK_EQ(second.value().body, record.body);
  }
}

SCP_TEST(identity_covers_every_field_but_origin) {
  const EvidenceKind kind = EvidenceKind::Capacity;
  const Result<std::vector<std::uint8_t>> encoded = scp::encode_body(sample_body(kind));
  SCP_REQUIRE_OK(encoded);
  const std::vector<std::uint8_t> body = encoded.value();
  const Provenance base = provenance_for(scp::owner_of(kind));

  const Result<EvidenceId> baseline =
      scp::derive_evidence_id(base, kind, scp::kEvidenceSchemaVersion,
                              std::span<const std::uint8_t>(body.data(), body.size()));
  SCP_REQUIRE_OK(baseline);
  const EvidenceId id = baseline.value();

  // Authority: create() refuses a non-owner, so the derivation is compared
  // directly. A record that claimed another boundary's fact would still not be
  // the record the owner would have published.
  Provenance mutated = base;
  mutated.authority = SourceAuthority::AsiRuntime;
  check_identity_differs(id, mutated, kind, scp::kEvidenceSchemaVersion, body, "authority");

  mutated = base;
  mutated.instance = scp_test::instance_for(2);
  check_identity_differs(id, mutated, kind, scp::kEvidenceSchemaVersion, body, "instance");

  mutated = base;
  mutated.epoch = scp::Epoch(2);
  check_identity_differs(id, mutated, kind, scp::kEvidenceSchemaVersion, body, "epoch");

  mutated = base;
  mutated.generation = scp::SourceGeneration(2);
  check_identity_differs(id, mutated, kind, scp::kEvidenceSchemaVersion, body, "generation");

  mutated = base;
  mutated.sequence = scp::Sequence(2);
  check_identity_differs(id, mutated, kind, scp::kEvidenceSchemaVersion, body, "sequence");

  mutated = base;
  mutated.issued_at = scp_test::instant_after(1);
  check_identity_differs(id, mutated, kind, scp::kEvidenceSchemaVersion, body, "issued_at");

  mutated = base;
  mutated.valid_until = scp_test::instant_after(600);
  check_identity_differs(id, mutated, kind, scp::kEvidenceSchemaVersion, body, "valid_until");

  check_identity_differs(id, base, EvidenceKind::Policy, scp::kEvidenceSchemaVersion, body, "kind");
  check_identity_differs(id, base, kind, static_cast<std::uint16_t>(scp::kEvidenceSchemaVersion + 1U),
                         body, "schema version");

  SCP_REQUIRE(!body.empty());
  std::vector<std::uint8_t> changed = body;
  changed[0] = static_cast<std::uint8_t>(changed[0] ^ 0x01U);
  check_identity_differs(id, base, kind, scp::kEvidenceSchemaVersion, changed, "one body byte");

  // The same content derived again is the same identity.
  const Result<EvidenceId> again =
      scp::derive_evidence_id(base, kind, scp::kEvidenceSchemaVersion,
                              std::span<const std::uint8_t>(body.data(), body.size()));
  SCP_REQUIRE_OK(again);
  SCP_CHECK_EQ(again.value(), id);
}

SCP_TEST(identical_publications_deduplicate) {
  scp_test::RecordSpec spec;
  spec.authority = scp::owner_of(EvidenceKind::FacilityState);
  const Result<EvidenceRecord> first =
      scp_test::make_record(spec, EvidenceKind::FacilityState, sample_facility());
  SCP_REQUIRE_OK(first);
  const Result<EvidenceRecord> second =
      scp_test::make_record(spec, EvidenceKind::FacilityState, sample_facility());
  SCP_REQUIRE_OK(second);

  SCP_CHECK_EQ(first.value().id, second.value().id);
  SCP_CHECK_EQ(first.value().provenance.body_digest, second.value().provenance.body_digest);

  // Origin records how a fact arrived, not which fact it is, so it does not
  // change the identity.
  EvidenceRecord recovered = second.value();
  recovered.origin = scp::EvidenceOrigin::RecoveredFromJournal;
  recovered.revalidated_at = scp_test::instant_after(5);
  const Result<bool> still_the_same = recovered.verify_identity();
  SCP_REQUIRE_OK(still_the_same);
  SCP_CHECK(still_the_same.value());

  scp::EvidenceSet set;
  const Result<bool> inserted = set.insert(first.value());
  SCP_REQUIRE_OK(inserted);
  SCP_CHECK(inserted.value());
  expect_error_code(set.insert(recovered), StatusCode::AlreadyExists, "re-inserting the same fact");
  SCP_CHECK_EQ(set.size(), std::size_t{1});
  SCP_CHECK(set.contains(first.value().id));

  // Reduction merges exact duplicates rather than reporting a conflict.
  const std::array<EvidenceRecord, 2> duplicates = {first.value(), recovered};
  const Result<scp::ReductionResult> reduction = scp::reduce_evidence(
      duplicates, scp_test::strict_policy(), scp_test::base_instant());
  SCP_REQUIRE_OK(reduction);
  SCP_CHECK_EQ(reduction.value().duplicates_merged, std::size_t{1});
  SCP_CHECK_EQ(reduction.value().conflict_count, std::size_t{0});
  SCP_CHECK_EQ(reduction.value().slots.size(), std::size_t{1});
  if (!reduction.value().slots.empty()) {
    SCP_CHECK_EQ(reduction.value().slots.front().outcome, scp::SlotOutcome::Accepted);
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

SCP_TEST(validate_rejects_malformed_records) {
  scp_test::RecordSpec spec;
  spec.authority = scp::owner_of(EvidenceKind::Capacity);
  const Result<EvidenceRecord> created =
      scp_test::make_record(spec, EvidenceKind::Capacity, sample_capacity());
  SCP_REQUIRE_OK(created);
  const EvidenceRecord good = created.value();
  expect_ok(good.validate(), "the baseline record validates");

  EvidenceRecord damaged = good;
  damaged.id = EvidenceId{};
  expect_status_code(damaged.validate(), StatusCode::InvalidIdentifier, "nil identity");

  damaged = good;
  damaged.provenance.instance = scp::SourceInstanceId{};
  expect_status_code(damaged.validate(), StatusCode::InvalidIdentifier, "nil instance");

  damaged = good;
  damaged.provenance.epoch = scp::Epoch{};
  expect_status_code(damaged.validate(), StatusCode::InvalidArgument, "unset epoch");

  damaged = good;
  damaged.provenance.generation = scp::SourceGeneration{};
  expect_status_code(damaged.validate(), StatusCode::InvalidArgument, "unset generation");

  damaged = good;
  damaged.provenance.sequence = scp::Sequence{};
  expect_status_code(damaged.validate(), StatusCode::InvalidArgument, "unset sequence");

  damaged = good;
  damaged.provenance.issued_at = Timestamp{};
  expect_status_code(damaged.validate(), StatusCode::InvalidArgument, "unset issue time");

  damaged = good;
  damaged.body[0] = static_cast<std::uint8_t>(damaged.body[0] ^ 0xFFU);
  expect_status_code(damaged.validate(), StatusCode::ChecksumMismatch, "body that does not match");

  damaged = good;
  damaged.id = EvidenceId(0xDEADBEEFULL, 0xFEEDFACEULL);
  expect_status_code(damaged.validate(), StatusCode::InvalidIdentifier,
                     "identity that is not the derived one");

  damaged = good;
  damaged.schema_version = static_cast<std::uint16_t>(scp::kEvidenceSchemaVersion + 1U);
  expect_status_code(damaged.validate(), StatusCode::UnsupportedFormatVersion,
                     "unsupported schema version");

  damaged = good;
  damaged.body.assign(scp::kMaxBlobBytes + 1U, std::uint8_t{0});
  expect_status_code(damaged.validate(), StatusCode::LimitExceeded, "body above kMaxBlobBytes");

  damaged = good;
  damaged.kind = static_cast<EvidenceKind>(99);
  expect_status_code(damaged.validate(), StatusCode::Unsupported, "kind with no owner");

  damaged = good;
  damaged.provenance.authority = SourceAuthority::DfiRuntime;
  expect_status_code(damaged.validate(), StatusCode::Unauthorized, "publisher that does not own");

  // The same limits apply when the record is built rather than validated.
  const std::vector<std::uint8_t> oversized(scp::kMaxBlobBytes + 1U, std::uint8_t{0});
  expect_error_code(EvidenceRecord::create(provenance_for(SourceAuthority::FacilityCapacity),
                                           EvidenceKind::Capacity, scp::kEvidenceSchemaVersion,
                                           oversized),
                    StatusCode::LimitExceeded, "create with a body above kMaxBlobBytes");
  expect_error_code(EvidenceRecord::create(provenance_for(SourceAuthority::FacilityCapacity),
                                           static_cast<EvidenceKind>(0), scp::kEvidenceSchemaVersion,
                                           std::vector<std::uint8_t>{}),
                    StatusCode::Unsupported, "create with a kind that has no owner");
}

// ---------------------------------------------------------------------------
// Body codec
// ---------------------------------------------------------------------------

SCP_TEST(every_kind_round_trips_through_encode_decode) {
  for (const EvidenceKind kind : kKinds) {
    const EvidenceBody original = sample_body(kind);
    const Result<std::vector<std::uint8_t>> encoded = scp::encode_body(original);
    SCP_REQUIRE_OK(encoded);
    SCP_CHECK(!encoded.value().empty());

    const Result<EvidenceBody> decoded =
        scp::decode_body(kind, scp::kEvidenceSchemaVersion, encoded.value());
    SCP_REQUIRE_OK(decoded);
    SCP_CHECK(same_body(original, decoded.value()));

    // Encoding the decoded value reproduces the same bytes.
    const Result<std::vector<std::uint8_t>> reencoded = scp::encode_body(decoded.value());
    SCP_REQUIRE_OK(reencoded);
    SCP_CHECK_EQ(reencoded.value(), encoded.value());
  }
}

SCP_TEST(decode_body_rejects_malformed_input) {
  // Unknown schema versions are refused rather than guessed at.
  const Result<std::vector<std::uint8_t>> facility_bytes =
      scp::encode_body(sample_facility());
  SCP_REQUIRE_OK(facility_bytes);
  expect_error_code(scp::decode_body(EvidenceKind::FacilityState, 0, facility_bytes.value()),
                    StatusCode::UnsupportedFormatVersion, "schema version 0");
  expect_error_code(
      scp::decode_body(EvidenceKind::FacilityState,
                       static_cast<std::uint16_t>(scp::kEvidenceSchemaVersion + 1U),
                       facility_bytes.value()),
      StatusCode::UnsupportedFormatVersion, "schema version 2");
  expect_error_code(scp::decode_body(EvidenceKind::FacilityState, 0xFFFFU, facility_bytes.value()),
                    StatusCode::UnsupportedFormatVersion, "schema version 0xFFFF");

  // Every proper prefix of an encoding is truncated, for every kind.
  for (const EvidenceKind kind : kKinds) {
    const Result<std::vector<std::uint8_t>> encoded = scp::encode_body(sample_body(kind));
    SCP_REQUIRE_OK(encoded);
    const std::vector<std::uint8_t>& bytes = encoded.value();
    for (std::size_t length = 0; length < bytes.size(); ++length) {
      const Result<EvidenceBody> decoded = scp::decode_body(
          kind, scp::kEvidenceSchemaVersion, std::span<const std::uint8_t>(bytes.data(), length));
      if (decoded.has_value()) {
        ::scp_test::Context::instance().note(std::string(scp::to_string(kind)) + " decoded from " +
                                             std::to_string(length) + " of " +
                                             std::to_string(bytes.size()) + " bytes");
        SCP_CHECK(false);
        continue;
      }
      if (!is_truncated_family(decoded.status().code())) {
        ::scp_test::Context::instance().note(
            std::string(scp::to_string(kind)) + " truncated to " + std::to_string(length) +
            " bytes reported " + decoded.status().to_string());
      }
      SCP_CHECK(is_truncated_family(decoded.status().code()));
    }
  }

  // Trailing bytes are not silently ignored.
  std::vector<std::uint8_t> with_tail = facility_bytes.value();
  with_tail.push_back(std::uint8_t{0x00});
  expect_error_code(scp::decode_body(EvidenceKind::FacilityState, scp::kEvidenceSchemaVersion,
                                     with_tail),
                    StatusCode::InvalidArgument, "a body with one trailing byte");

  // An enum byte that is not an enumerator is InvalidEnum, not a silent
  // reinterpretation.
  std::vector<std::uint8_t> facility_bad_enum = facility_bytes.value();
  // Byte 8 is the severity enumerator: generation is a u64 before it.
  SCP_REQUIRE(facility_bad_enum.size() > std::size_t{8});
  facility_bad_enum[8] = std::uint8_t{0xFF};
  expect_error_code(
      scp::decode_body(EvidenceKind::FacilityState, scp::kEvidenceSchemaVersion, facility_bad_enum),
      StatusCode::InvalidEnum, "an invalid severity enumerator");

  const Result<std::vector<std::uint8_t>> lifecycle_bytes = scp::encode_body(sample_lifecycle());
  SCP_REQUIRE_OK(lifecycle_bytes);
  std::vector<std::uint8_t> lifecycle_bad_enum = lifecycle_bytes.value();
  SCP_REQUIRE(!lifecycle_bad_enum.empty());
  lifecycle_bad_enum[0] = std::uint8_t{0x00};
  expect_error_code(scp::decode_body(EvidenceKind::Lifecycle, scp::kEvidenceSchemaVersion,
                                     lifecycle_bad_enum),
                    StatusCode::InvalidEnum, "an invalid lifecycle enumerator");

  const Result<std::vector<std::uint8_t>> readiness_bytes = scp::encode_body(sample_readiness());
  SCP_REQUIRE_OK(readiness_bytes);
  std::vector<std::uint8_t> readiness_bad_enum = readiness_bytes.value();
  readiness_bad_enum[16] = std::uint8_t{0x7F};  // snapshot (id), then readiness (u8)
  expect_error_code(scp::decode_body(EvidenceKind::PowerReadiness, scp::kEvidenceSchemaVersion,
                                     readiness_bad_enum),
                    StatusCode::InvalidEnum, "an invalid readiness enumerator");

  const Result<std::vector<std::uint8_t>> capability_bytes = scp::encode_body(sample_capability());
  SCP_REQUIRE_OK(capability_bytes);
  std::vector<std::uint8_t> capability_bad_enum = capability_bytes.value();
  capability_bad_enum[0] = std::uint8_t{0xFF};
  expect_error_code(scp::decode_body(EvidenceKind::AsiCapability, scp::kEvidenceSchemaVersion,
                                     capability_bad_enum),
                    StatusCode::InvalidEnum, "an invalid capability enumerator");

  // A declared obligation count is checked against the schema bound before any
  // storage is reserved, so a hostile count cannot drive a huge allocation.
  std::uint64_t seed = 0x5EEDULL;
  const std::array<std::uint32_t, 6> hostile_counts = {
      0xFFFFFFFFU, 0x7FFFFFFFU, 0x40000000U, 0x00FFFFFFU,
      static_cast<std::uint32_t>(scp::kMaxServiceClasses) + 1U,
      static_cast<std::uint32_t>(splitmix64(seed) & 0xFFFF0000ULL)};
  for (const std::uint32_t declared : hostile_counts) {
    const std::vector<std::uint8_t> body = service_class_body("interactive-inference", declared);
    expect_error_code(
        scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion, body),
        StatusCode::LimitExceeded, "a declared obligation count above the limit");
  }

  // The limit boundary itself is accepted below the bound and refused at it.
  const std::vector<std::uint8_t> at_limit = obligations_body(scp::kMaxServiceClasses);
  const Result<EvidenceBody> at_limit_decoded =
      scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion, at_limit);
  SCP_REQUIRE_OK(at_limit_decoded);
  const auto* decoded_classes = std::get_if<ServiceClassEvidence>(&at_limit_decoded.value());
  SCP_REQUIRE(decoded_classes != nullptr);
  SCP_CHECK_EQ(decoded_classes->obligations.size(), scp::kMaxServiceClasses);
  expect_error_code(scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion,
                                     obligations_body(scp::kMaxServiceClasses + 1U)),
                    StatusCode::LimitExceeded, "one obligation above the limit");

  // An unknown kind is refused rather than decoded as something else.
  expect_error_code(scp::decode_body(static_cast<EvidenceKind>(99), scp::kEvidenceSchemaVersion,
                                     facility_bytes.value()),
                    StatusCode::Unsupported, "an unknown evidence kind");
}

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

SCP_TEST(classify_freshness_boundaries) {
  FreshnessPolicy policy;
  policy.stale_after = scp::seconds(900);
  policy.expire_after = scp::seconds(3600);
  policy.recovered_ages_out = true;

  scp_test::RecordSpec spec;
  spec.authority = scp::owner_of(EvidenceKind::FacilityState);
  const Result<EvidenceRecord> created =
      scp_test::make_record(spec, EvidenceKind::FacilityState, sample_facility());
  SCP_REQUIRE_OK(created);
  const EvidenceRecord record = created.value();

  SCP_CHECK_EQ(scp::classify_freshness(record, scp_test::base_instant(), policy), Freshness::Fresh);
  SCP_CHECK_EQ(scp::classify_freshness(record, scp_test::instant_after(900), policy),
               Freshness::Fresh);
  SCP_CHECK_EQ(scp::classify_freshness(record, scp_test::instant_after(901), policy),
               Freshness::Stale);
  SCP_CHECK_EQ(scp::classify_freshness(record, scp_test::instant_after(3600), policy),
               Freshness::Stale);
  SCP_CHECK_EQ(scp::classify_freshness(record, scp_test::instant_after(3601), policy),
               Freshness::Expired);
  SCP_CHECK_EQ(scp::classify_freshness(record, scp_test::instant_after(-1), policy),
               Freshness::Indeterminate);

  // A stated expiry wins over the age thresholds, in both directions.
  EvidenceRecord expiring = record;
  expiring.provenance.valid_until = scp_test::instant_after(600);
  SCP_CHECK_EQ(scp::classify_freshness(expiring, scp_test::instant_after(599), policy),
               Freshness::Fresh);
  SCP_CHECK_EQ(scp::classify_freshness(expiring, scp_test::instant_after(600), policy),
               Freshness::Expired);
  SCP_CHECK_EQ(scp::classify_freshness(expiring, scp_test::instant_after(100000), policy),
               Freshness::Expired);

  EvidenceRecord long_lived = record;
  long_lived.provenance.valid_until = scp_test::instant_after(100000);
  SCP_CHECK_EQ(scp::classify_freshness(long_lived, scp_test::instant_after(99999), policy),
               Freshness::Fresh);

  // Without an issue time nothing can be judged.
  EvidenceRecord undated = record;
  undated.provenance.issued_at = Timestamp{};
  SCP_CHECK_EQ(scp::classify_freshness(undated, scp_test::base_instant(), policy),
               Freshness::Indeterminate);

  // Recovered evidence may be allowed to age further, and only when it has no
  // stated expiry of its own.
  EvidenceRecord recovered = record;
  recovered.origin = scp::EvidenceOrigin::RecoveredFromJournal;
  FreshnessPolicy recovered_policy = policy;
  recovered_policy.recovered_ages_out = false;
  SCP_CHECK_EQ(scp::classify_freshness(recovered, scp_test::instant_after(100000),
                                       recovered_policy),
               Freshness::Fresh);
  SCP_CHECK_EQ(scp::classify_freshness(recovered, scp_test::instant_after(100000), policy),
               Freshness::Expired);
  EvidenceRecord recovered_expiring = recovered;
  recovered_expiring.provenance.valid_until = scp_test::instant_after(600);
  SCP_CHECK_EQ(scp::classify_freshness(recovered_expiring, scp_test::instant_after(600),
                                       recovered_policy),
               Freshness::Expired);

  SCP_CHECK(scp::participates(Freshness::Fresh));
  SCP_CHECK(!scp::participates(Freshness::Stale));
  SCP_CHECK(!scp::participates(Freshness::Expired));
  SCP_CHECK(!scp::participates(Freshness::Indeterminate));

  // Freshness is a pure function of the instant: the same inputs always give
  // the same answer, and the evaluation instant never mutates the record.
  const Digest before = Digest::of(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(record.body.data()), record.body.size()));
  for (int repeat = 0; repeat < 3; ++repeat) {
    SCP_CHECK_EQ(scp::classify_freshness(record, scp_test::instant_after(1000), policy),
                 Freshness::Stale);
  }
  const Digest after = Digest::of(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(record.body.data()), record.body.size()));
  SCP_CHECK_EQ(before, after);
}

// ---------------------------------------------------------------------------
// Canonical record form
// ---------------------------------------------------------------------------

SCP_TEST(canonical_record_round_trip) {
  scp_test::RecordSpec spec;
  spec.authority = scp::owner_of(EvidenceKind::ServiceClass);
  const Result<EvidenceRecord> created =
      scp_test::make_record(spec, EvidenceKind::ServiceClass, sample_service_classes());
  SCP_REQUIRE_OK(created);
  EvidenceRecord original = created.value();
  original.origin = scp::EvidenceOrigin::Revalidated;
  original.revalidated_at = scp_test::instant_after(30);

  const std::vector<std::uint8_t> bytes = original.canonical_bytes();

  // Writing the same record again produces identical bytes.
  SCP_CHECK_EQ(original.canonical_bytes(), bytes);

  CanonicalReader reader(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
  const Result<EvidenceRecord> read = scp::canonical_read_evidence(reader);
  SCP_REQUIRE_OK(read);
  const EvidenceRecord& restored = read.value();
  SCP_CHECK_EQ(restored.id, original.id);
  SCP_CHECK_EQ(restored.kind, original.kind);
  SCP_CHECK_EQ(restored.schema_version, original.schema_version);
  SCP_CHECK_EQ(restored.body, original.body);
  SCP_CHECK_EQ(restored.origin, original.origin);
  SCP_CHECK_EQ(restored.revalidated_at, original.revalidated_at);
  SCP_CHECK_EQ(restored.provenance, original.provenance);
  SCP_CHECK(reader.empty());
  SCP_CHECK_EQ(restored.canonical_bytes(), bytes);

  // Every proper prefix of the canonical form is refused.
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    CanonicalReader partial(std::span<const std::uint8_t>(bytes.data(), length));
    const Result<EvidenceRecord> truncated = scp::canonical_read_evidence(partial);
    if (truncated.has_value()) {
      ::scp_test::Context::instance().note("record decoded from " + std::to_string(length) +
                                           " of " + std::to_string(bytes.size()) + " bytes");
      SCP_CHECK(false);
      continue;
    }
    if (!is_truncated_family(truncated.status().code())) {
      ::scp_test::Context::instance().note("prefix of " + std::to_string(length) +
                                           " bytes reported " + truncated.status().to_string());
    }
    SCP_CHECK(is_truncated_family(truncated.status().code()));
  }

  // The reader is a cursor: the record reader itself stops at the end of the
  // record, and the trailing bytes are then reported as unread input rather
  // than silently accepted. A caller that skips expect_end() would accept a
  // record with appended bytes.
  std::vector<std::uint8_t> with_tail = bytes;
  with_tail.push_back(0x7FU);
  CanonicalReader tailed(std::span<const std::uint8_t>(with_tail.data(), with_tail.size()));
  const Result<EvidenceRecord> tailed_record = scp::canonical_read_evidence(tailed);
  SCP_REQUIRE_OK(tailed_record);
  SCP_CHECK_EQ(tailed_record.value().id, original.id);
  SCP_CHECK_EQ(tailed_record.value().body, original.body);
  SCP_CHECK_EQ(tailed.remaining(), std::size_t{1});
  expect_status_code(tailed.expect_end(), StatusCode::InvalidArgument,
                     "expect_end with one trailing byte");

  // An unsupported schema version survives the round trip as data: the record
  // is preserved, not reinterpreted, and validate() reports it as unsupported.
  const std::vector<std::uint8_t> opaque_body{std::uint8_t{1}};
  const Result<EvidenceRecord> future = EvidenceRecord::create(
      provenance_for(SourceAuthority::ServiceClassRegistry), EvidenceKind::ServiceClass,
      static_cast<std::uint16_t>(scp::kEvidenceSchemaVersion + 1U), opaque_body);
  SCP_REQUIRE_OK(future);
  const std::vector<std::uint8_t> future_bytes = future.value().canonical_bytes();
  CanonicalReader future_reader(std::span<const std::uint8_t>(future_bytes.data(), future_bytes.size()));
  const Result<EvidenceRecord> future_read = scp::canonical_read_evidence(future_reader);
  SCP_REQUIRE_OK(future_read);
  SCP_CHECK_EQ(future_read.value().schema_version,
               static_cast<std::uint16_t>(scp::kEvidenceSchemaVersion + 1U));
  SCP_CHECK_EQ(future_read.value().body, future.value().body);
  expect_status_code(future_read.value().validate(), StatusCode::UnsupportedFormatVersion,
                     "a preserved newer-schema record");
}

// ---------------------------------------------------------------------------
// Text and numeric edges that reach evidence
// ---------------------------------------------------------------------------

SCP_TEST(service_class_name_edges) {
  const std::string too_long(scp::kMaxNameBytes + 1U, 'a');
  const std::string at_limit(scp::kMaxNameBytes, 'a');
  const std::string control = std::string("ctrl") + '\x01' + "name";
  const std::string leading = " interactive-inference";
  const std::string trailing = "interactive-inference ";
  const std::string invalid_utf8 = std::string("\xFF\xFE", 2);

  // Name::parse owns the vocabulary; the exact code is asserted for each edge.
  expect_error_code(Name::parse(""), StatusCode::InvalidArgument, "an empty name");
  expect_error_code(Name::parse(too_long), StatusCode::InvalidArgument, "a name above the limit");
  expect_error_code(Name::parse(invalid_utf8), StatusCode::InvalidUnicode, "invalid UTF-8");
  expect_error_code(Name::parse(control), StatusCode::InvalidText, "a control character");
  expect_error_code(Name::parse(std::string("del") + '\x7F'), StatusCode::InvalidText,
                    "a DEL character");
  expect_error_code(Name::parse(leading), StatusCode::InvalidText, "a leading space");
  expect_error_code(Name::parse(trailing), StatusCode::InvalidText, "a trailing space");
  expect_error_code(Name::parse(std::string("tab\t")), StatusCode::InvalidText, "a trailing tab");
  const Result<Name> boundary = Name::parse(at_limit);
  SCP_CHECK(boundary.has_value());
  if (boundary.has_value()) {
    SCP_CHECK_EQ(boundary.value().view().size(), scp::kMaxNameBytes);
  }

  // The same edges reach the decoder through a service-class obligation. The
  // decoder applies its own length budget before Name::parse runs, so an
  // oversized declared name is LimitExceeded rather than InvalidArgument.
  expect_error_code(scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion,
                                     service_class_body(too_long, 1)),
                    StatusCode::LimitExceeded, "a declared name above kMaxNameBytes");
  expect_error_code(scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion,
                                     service_class_body(invalid_utf8, 1)),
                    StatusCode::InvalidUnicode, "an invalid UTF-8 name");
  expect_error_code(scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion,
                                     service_class_body(control, 1)),
                    StatusCode::InvalidText, "a name with a control character");
  expect_error_code(scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion,
                                     service_class_body(leading, 1)),
                    StatusCode::InvalidText, "a name with leading whitespace");
  expect_error_code(scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion,
                                     service_class_body(trailing, 1)),
                    StatusCode::InvalidText, "a name with trailing whitespace");

  const Result<EvidenceBody> boundary_decoded = scp::decode_body(
      EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion, service_class_body(at_limit, 1));
  SCP_REQUIRE_OK(boundary_decoded);
  const auto* classes = std::get_if<ServiceClassEvidence>(&boundary_decoded.value());
  SCP_REQUIRE(classes != nullptr);
  SCP_CHECK_EQ(classes->obligations.size(), std::size_t{1});
  if (!classes->obligations.empty()) {
    SCP_CHECK_EQ(classes->obligations.front().service_class.view().size(), scp::kMaxNameBytes);
  }

  // A name that claims more bytes than remain is truncated, not over-read.
  std::vector<std::uint8_t> short_name = service_class_body("interactive-inference", 1);
  short_name.resize(short_name.size() - 4U);
  const Result<EvidenceBody> truncated_name = scp::decode_body(
      EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion, short_name);
  SCP_REQUIRE(!truncated_name.has_value());
  SCP_CHECK(is_truncated_family(truncated_name.status().code()));

  // Numeric edges carried inside a body are range-checked on the way in.
  std::vector<std::uint8_t> bad_percent = service_class_body("interactive-inference", 1);
  bad_percent.back() = std::uint8_t{101};
  expect_error_code(scp::decode_body(EvidenceKind::ServiceClass, scp::kEvidenceSchemaVersion,
                                     bad_percent),
                    StatusCode::OutOfRange, "a readiness percentage above 100");

  const Result<std::vector<std::uint8_t>> capability_again = scp::encode_body(sample_capability());
  SCP_REQUIRE_OK(capability_again);
  SCP_REQUIRE(capability_again.value().size() >= 5U);
  std::vector<std::uint8_t> bad_readiness = capability_again.value();
  bad_readiness[1] = std::uint8_t{200};  // readiness (u8), then ready_domains (u32)
  expect_error_code(scp::decode_body(EvidenceKind::AsiCapability, scp::kEvidenceSchemaVersion,
                                     bad_readiness),
                    StatusCode::OutOfRange, "ready_domains above total_domains");
}

SCP_TEST_MAIN("evidence")
