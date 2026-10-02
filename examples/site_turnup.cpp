// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

/// \file site_turnup.cpp
/// A worked site turn-up: one evidence record per lower-domain runtime, committed
/// step by step, with the composed site state printed after every commit. The
/// walk shows a commissioning site that is not available, a missing cooling
/// publication that keeps the site out of available (and, while the critical
/// publications are absent, leaves the site unknown), a contradictory pair of
/// capacity publications that composes to Conflicting instead of picking a
/// winner, and finally a site whose publishers agree and which reaches Available.
/// The runtime is then closed and reopened from the same directory to show that
/// the accepted state and the site generation survived.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "scp/composition.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/policy.hpp"
#include "scp/runtime.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"

namespace {

/// A run-unique directory under the host temporary directory, removed when the
/// object goes out of scope.
class TempDirectory {
 public:
  TempDirectory() {
    std::error_code error;
    const std::filesystem::path base = std::filesystem::temp_directory_path(error);
    if (error) {
      return;
    }
    const auto stamp = static_cast<std::uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    for (std::uint32_t attempt = 0; attempt < 16U; ++attempt) {
      std::filesystem::path candidate = base / ("scp-site-turnup-" + std::to_string(stamp));
      if (attempt != 0U) {
        candidate += "-" + std::to_string(attempt);
      }
      std::error_code exists_error;
      if (std::filesystem::exists(candidate, exists_error) && !exists_error) {
        continue;
      }
      std::error_code create_error;
      std::filesystem::create_directories(candidate, create_error);
      if (!create_error) {
        path_ = candidate;
        ready_ = true;
      }
      return;
    }
  }

  ~TempDirectory() {
    if (ready_) {
      std::error_code error;
      std::filesystem::remove_all(path_, error);
    }
  }

  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;

  [[nodiscard]] bool ready() const noexcept { return ready_; }
  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
  bool ready_ = false;
};

/// The instant the first publication is issued at, and the step between the
/// publications of the walk. Deterministic: the clock only moves when told to.
constexpr std::int64_t kStartNanos = 1700000000000000000LL;
constexpr std::int64_t kTurnUpSeconds = 1;

[[nodiscard]] scp::Digest digest_of(std::string_view text) {
  scp::Sha256 hasher;
  hasher.update(text);
  return hasher.finalize();
}

/// One lower-domain runtime publishing evidence for the kind it owns.
struct Publisher {
  scp::SourceAuthority authority = scp::SourceAuthority::FacilityStateLedger;
  scp::SourceInstanceId instance{};
  scp::Epoch epoch = scp::Epoch(1);
  scp::SourceGeneration generation = scp::SourceGeneration(1);
  scp::Sequence sequence = scp::Sequence(1);

  [[nodiscard]] scp::Result<scp::EvidenceRecord> publish(scp::EvidenceKind kind,
                                                         const scp::EvidenceBody& body,
                                                         scp::Timestamp issued_at) const {
    scp::Provenance provenance;
    provenance.authority = authority;
    provenance.instance = instance;
    provenance.epoch = epoch;
    provenance.generation = generation;
    provenance.sequence = sequence;
    provenance.issued_at = issued_at;
    return scp::EvidenceRecord::create(provenance, kind, body);
  }
};

[[nodiscard]] Publisher make_publisher(scp::EvidenceKind kind, scp::SourceInstanceId instance) {
  Publisher publisher;
  publisher.authority = scp::owner_of(kind);
  publisher.instance = instance;
  return publisher;
}

// ---------------------------------------------------------------------------
// Typed bodies
// ---------------------------------------------------------------------------

[[nodiscard]] scp::FacilityStateEvidence facility_state_body() {
  scp::FacilityStateEvidence value;
  value.generation = scp::FacilityStateGeneration(1);
  value.worst_active_severity = scp::Severity::None;
  value.active_incidents = 0;
  value.degraded_operation = false;
  value.emergency_declared = false;
  value.topology_digest = digest_of("site-topology-1");
  return value;
}

[[nodiscard]] scp::LifecycleEvidence lifecycle_body(scp::LifecycleState state,
                                                    scp::Timestamp entered_at) {
  scp::LifecycleEvidence value;
  value.state = state;
  value.entered_at = entered_at;
  value.transition_in_progress = false;
  value.transition_digest = digest_of("lifecycle-transition");
  return value;
}

[[nodiscard]] scp::CapacityEvidence capacity_body(std::uint64_t total_units,
                                                  std::uint64_t committed_units,
                                                  std::uint64_t available_units) {
  scp::CapacityEvidence value;
  value.snapshot = scp::SnapshotId(0x0102030405060708ULL, 0x090a0b0c0d0e0f10ULL);
  value.generation = scp::CapacityGeneration(1);
  value.total_units = total_units;
  value.committed_units = committed_units;
  value.available_units = available_units;
  value.oversubscribed = false;
  return value;
}

[[nodiscard]] scp::ReadinessEvidence readiness_body(scp::ReadinessLevel level,
                                                    std::uint64_t headroom_milli_kw) {
  scp::ReadinessEvidence value;
  value.snapshot = scp::SnapshotId(0x1112131415161718ULL, 0x191a1b1c1d1e1f20ULL);
  value.readiness = level;
  value.headroom_milli_kw = headroom_milli_kw;
  value.available_domains = 2;
  value.required_domains = 2;
  return value;
}

[[nodiscard]] scp::PolicyEvidence policy_body() {
  scp::PolicyEvidence value;
  value.generation = scp::PolicyGeneration(1);
  value.rules_digest = digest_of("lower-policy-rules-1");
  value.rule_count = 3;
  return value;
}

[[nodiscard]] scp::IncidentEvidence incident_body() {
  scp::IncidentEvidence value;
  value.active_incidents = 0;
  value.worst_active_severity = scp::Severity::None;
  value.emergency_declared = false;
  value.earliest_active = scp::Timestamp{};
  value.suppressed_incidents = 0;
  return value;
}

[[nodiscard]] scp::MaintenanceEvidence maintenance_body() {
  scp::MaintenanceEvidence value;
  value.mode = scp::MaintenanceMode::None;
  value.active_windows = 0;
  value.scheduled_windows = 0;
  value.next_window_start = scp::Timestamp{};
  value.drain_in_progress = false;
  value.drained_percent = 0;
  return value;
}

[[nodiscard]] scp::CapabilityEvidence capability_body(scp::ReadinessLevel level,
                                                      std::uint32_t ready_domains,
                                                      std::uint32_t total_domains,
                                                      std::uint64_t ready_units) {
  scp::CapabilityEvidence value;
  value.readiness = level;
  value.ready_domains = ready_domains;
  value.total_domains = total_domains;
  value.ready_units = ready_units;
  value.capability_digest = digest_of("capability-1");
  return value;
}

[[nodiscard]] scp::ServiceClassEvidence service_class_body() {
  scp::ServiceClassEvidence value;
  value.class_count = 1;
  value.obligations_digest = digest_of("service-classes-1");
  scp::ServiceClassObligation obligation;
  const scp::Result<scp::Name> name = scp::Name::parse("gold");
  if (name.has_value()) {
    obligation.service_class = name.value();
  }
  obligation.protected_class = true;
  obligation.minimum_ready_units = 100;
  obligation.minimum_readiness_percent = 90;
  value.obligations.push_back(obligation);
  return value;
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

[[nodiscard]] std::string constraints_text(const scp::SiteStateSnapshot& snapshot) {
  if (snapshot.constraints.empty()) {
    return "<none>";
  }
  std::string text;
  for (const scp::Constraint& constraint : snapshot.constraints) {
    if (!text.empty()) {
      text += "; ";
    }
    text += std::string(scp::to_string(constraint.kind)) + "[" +
            scp::escape_for_display(constraint.subject) + "]" +
            (constraint.blocking ? " blocking" : " advisory");
  }
  return text;
}

[[nodiscard]] std::string slot_text(const scp::SiteStateSnapshot& snapshot,
                                    scp::EvidenceKind kind) {
  const scp::SlotResolution* resolution =
      snapshot.find_slot(scp::EvidenceSlot{scp::owner_of(kind), kind});
  if (resolution == nullptr) {
    return "no resolution";
  }
  std::string text = std::string(scp::to_string(resolution->outcome)) + " freshness=" +
                     std::string(scp::to_string(resolution->freshness)) + " origin=" +
                     std::string(scp::to_string(resolution->origin)) + " evidence=" +
                     (resolution->accepted_id.is_nil() ? std::string("none")
                                                       : resolution->accepted_id.to_hex()) +
                     " superseded=" + std::to_string(resolution->superseded.size()) +
                     " conflicting=" + std::to_string(resolution->conflicting.size());
  return text;
}

/// Prints what the runtime publishes at \p evaluation, exactly as composed.
bool show(const scp::SiteControlPlane& runtime, scp::Timestamp evaluation,
          std::string_view label) {
  const scp::Result<scp::SiteStateSnapshot> snapshot = runtime.snapshot(evaluation);
  if (!snapshot.has_value()) {
    std::cerr << "site_turnup: " << snapshot.status().to_string() << '\n';
    return false;
  }
  const scp::SiteStateSnapshot& value = snapshot.value();
  std::cout << label << "\n";
  std::cout << "  state=" << scp::to_string(value.state)
            << " lifecycle=" << scp::to_string(value.lifecycle)
            << " classification=" << scp::to_string(value.classification)
            << " site-generation=" << value.site_generation.value()
            << " readiness-percent=" << value.readiness_percent
            << " admits-new-obligations="
            << (scp::admits_new_obligations(value.state) ? "true" : "false") << '\n';
  std::cout << "  constraints: " << constraints_text(value) << '\n';
  return true;
}

bool advance(const std::shared_ptr<scp::ManualClock>& clock) {
  const scp::Status status = clock->advance(scp::seconds(kTurnUpSeconds));
  if (!status.ok()) {
    std::cerr << "site_turnup: " << status.to_string() << '\n';
    return false;
  }
  return true;
}

/// Ingests and commits one publication step, then prints the composed state.
bool submit(const std::unique_ptr<scp::SiteControlPlane>& runtime,
            const std::shared_ptr<scp::ManualClock>& clock,
            const std::vector<scp::EvidenceRecord>& records, std::string_view label) {
  for (const scp::EvidenceRecord& record : records) {
    const scp::Status ingested = runtime->ingest(record);
    if (!ingested.ok()) {
      std::cerr << "site_turnup: ingest " << record.id.to_hex() << ": " << ingested.to_string()
                << '\n';
      return false;
    }
  }
  scp::CommitOptions options;
  options.now = clock->now();
  options.advance_generation = true;
  const scp::Result<scp::CommitOutcome> outcome = runtime->commit(options);
  if (!outcome.has_value()) {
    std::cerr << "site_turnup: commit: " << outcome.status().to_string() << '\n';
    return false;
  }
  std::cout << label << " -> committed, journal-sequence "
            << outcome.value().journal_sequence.value() << ", " << outcome.value().transaction_bytes
            << " bytes durable\n";
  return show(*runtime, clock->now(), "  composed state");
}

}  // namespace

int main() {
  TempDirectory directory;
  if (!directory.ready()) {
    std::cerr << "site_turnup: cannot create a temporary directory\n";
    return 1;
  }

  const auto clock = std::make_shared<scp::ManualClock>(scp::Timestamp{kStartNanos});
  scp::DeterministicIdSource identities(0x7e57ab1e7e57ab1eULL);
  const scp::SiteId site = identities.next_site();

  scp::RuntimeOptions options;
  options.directory = directory.path();
  options.site = site;
  options.clock = clock;

  scp::Result<std::unique_ptr<scp::SiteControlPlane>> opened = scp::SiteControlPlane::open(options);
  if (!opened.has_value()) {
    std::cerr << "site_turnup: " << opened.status().to_string() << '\n';
    return 1;
  }
  std::unique_ptr<scp::SiteControlPlane> runtime = std::move(opened).value();

  const Publisher facility_state_ledger =
      make_publisher(scp::EvidenceKind::FacilityState, identities.next_instance());
  const Publisher facility_capacity =
      make_publisher(scp::EvidenceKind::Capacity, identities.next_instance());
  const Publisher power_control_plane =
      make_publisher(scp::EvidenceKind::PowerReadiness, identities.next_instance());
  const Publisher thermal_control_plane =
      make_publisher(scp::EvidenceKind::CoolingReadiness, identities.next_instance());
  const Publisher facility_policy_engine =
      make_publisher(scp::EvidenceKind::Policy, identities.next_instance());
  const Publisher incident_state_fabric =
      make_publisher(scp::EvidenceKind::Incident, identities.next_instance());
  const Publisher maintenance_coordinator =
      make_publisher(scp::EvidenceKind::Maintenance, identities.next_instance());
  const Publisher asi_runtime =
      make_publisher(scp::EvidenceKind::AsiCapability, identities.next_instance());
  const Publisher dfi_runtime =
      make_publisher(scp::EvidenceKind::DfiCapability, identities.next_instance());
  const Publisher service_class_registry =
      make_publisher(scp::EvidenceKind::ServiceClass, identities.next_instance());

  std::cout << "site " << site.to_hex() << '\n';
  std::cout << "durable directory " << scp::escape_for_display(directory.path().string()) << '\n';
  std::cout << "evaluation instant " << clock->now().to_iso8601() << '\n';

  if (!show(*runtime, clock->now(), "step 0: nothing has published")) {
    return 1;
  }
  std::cout << "  the cooling publication is missing, and no critical publication has landed "
               "either, so the composition cannot answer at all: the site is unknown, not merely "
               "unavailable\n";

  // Step 1: the facility state ledger places the site under commissioning.
  const scp::Result<scp::EvidenceRecord> facility_state =
      facility_state_ledger.publish(scp::EvidenceKind::FacilityState, facility_state_body(),
                                    clock->now());
  if (!facility_state.has_value()) {
    std::cerr << "site_turnup: " << facility_state.status().to_string() << '\n';
    return 1;
  }
  if (!advance(clock)) {
    return 1;
  }
  const scp::Result<scp::EvidenceRecord> commissioning =
      facility_state_ledger.publish(scp::EvidenceKind::Lifecycle,
                                    lifecycle_body(scp::LifecycleState::Commissioning, clock->now()),
                                    clock->now());
  if (!commissioning.has_value()) {
    std::cerr << "site_turnup: " << commissioning.status().to_string() << '\n';
    return 1;
  }
  if (!submit(runtime, clock, {facility_state.value(), commissioning.value()},
              "step 1: the facility state ledger publishes facility-state and lifecycle=commissioning")) {
    return 1;
  }
  std::cout << "  a commissioning site is not available\n";

  // Steps 2 to 9: every other lower-domain runtime publishes, except the thermal
  // control plane, which has not reported yet.
  struct Step {
    const Publisher* publisher;
    scp::EvidenceKind kind;
    scp::EvidenceBody body;
    const char* description;
  };
  std::vector<Step> steps;
  steps.push_back(Step{&facility_capacity, scp::EvidenceKind::Capacity,
                       capacity_body(1000, 200, 800), "the capacity owner reports 800 of 1000 units free"});
  steps.push_back(Step{&power_control_plane, scp::EvidenceKind::PowerReadiness,
                       readiness_body(scp::ReadinessLevel::Ready, 5000),
                       "the power control plane reports ready"});
  steps.push_back(Step{&facility_policy_engine, scp::EvidenceKind::Policy, policy_body(),
                       "the policy engine reports its rule set"});
  steps.push_back(Step{&incident_state_fabric, scp::EvidenceKind::Incident, incident_body(),
                       "the incident fabric reports no active incident"});
  steps.push_back(Step{&maintenance_coordinator, scp::EvidenceKind::Maintenance,
                       maintenance_body(), "the maintenance coordinator reports no window"});
  steps.push_back(Step{&asi_runtime, scp::EvidenceKind::AsiCapability,
                       capability_body(scp::ReadinessLevel::Ready, 4, 4, 64),
                       "the accelerator runtime reports 4 of 4 domains ready"});
  steps.push_back(Step{&dfi_runtime, scp::EvidenceKind::DfiCapability,
                       capability_body(scp::ReadinessLevel::Ready, 8, 8, 128),
                       "the fabric runtime reports 8 of 8 domains ready"});
  steps.push_back(Step{&service_class_registry, scp::EvidenceKind::ServiceClass,
                       service_class_body(), "the service class registry declares gold"});

  std::uint32_t step_number = 2;
  for (const Step& step : steps) {
    if (!advance(clock)) {
      return 1;
    }
    const scp::Result<scp::EvidenceRecord> record =
        step.publisher->publish(step.kind, step.body, clock->now());
    if (!record.has_value()) {
      std::cerr << "site_turnup: " << record.status().to_string() << '\n';
      return 1;
    }
    std::cout << "step " << step_number << ": " << scp::to_string(step.publisher->authority) << " - "
              << step.description << '\n';
    if (!submit(runtime, clock, {record.value()}, "  publication")) {
      return 1;
    }
    ++step_number;
  }

  if (!advance(clock)) {
    return 1;
  }
  const scp::Result<scp::SiteStateSnapshot> before_cooling = runtime->snapshot(clock->now());
  if (!before_cooling.has_value()) {
    std::cerr << "site_turnup: " << before_cooling.status().to_string() << '\n';
    return 1;
  }
  std::cout << "step " << step_number
            << ": the thermal control plane has not published; the cooling slot is "
            << slot_text(before_cooling.value(), scp::EvidenceKind::CoolingReadiness) << '\n';
  std::cout << "  the site is still commissioning, and the missing cooling publication is already "
               "the only slot the site plane cannot use\n";
  ++step_number;

  // Step 10: the facility state ledger declares the site active while the cooling
  // publication is still missing.
  Publisher facility_state_ledger_2 = facility_state_ledger;
  facility_state_ledger_2.sequence = scp::Sequence(2);
  facility_state_ledger_2.generation = scp::SourceGeneration(2);
  if (!advance(clock)) {
    return 1;
  }
  const scp::Result<scp::EvidenceRecord> active =
      facility_state_ledger_2.publish(scp::EvidenceKind::Lifecycle,
                                      lifecycle_body(scp::LifecycleState::Active, clock->now()),
                                      clock->now());
  if (!active.has_value()) {
    std::cerr << "site_turnup: " << active.status().to_string() << '\n';
    return 1;
  }
  std::cout << "step " << step_number
            << ": the facility state ledger declares lifecycle=active while cooling is missing\n";
  if (!submit(runtime, clock, {active.value()}, "  publication")) {
    return 1;
  }
  ++step_number;

  // Step 11: the thermal control plane finally publishes.
  if (!advance(clock)) {
    return 1;
  }
  const scp::Result<scp::EvidenceRecord> cooling =
      thermal_control_plane.publish(scp::EvidenceKind::CoolingReadiness,
                                    readiness_body(scp::ReadinessLevel::Ready, 4000), clock->now());
  if (!cooling.has_value()) {
    std::cerr << "site_turnup: " << cooling.status().to_string() << '\n';
    return 1;
  }
  std::cout << "step " << step_number << ": the thermal control plane reports cooling ready\n";
  if (!submit(runtime, clock, {cooling.value()}, "  publication")) {
    return 1;
  }
  ++step_number;

  // Step 12: two capacity publications claim the same epoch, generation and
  // sequence with different content.
  Publisher capacity_conflict_a = facility_capacity;
  capacity_conflict_a.generation = scp::SourceGeneration(5);
  capacity_conflict_a.sequence = scp::Sequence(5);
  Publisher capacity_conflict_b = capacity_conflict_a;
  if (!advance(clock)) {
    return 1;
  }
  const scp::Result<scp::EvidenceRecord> claim_a = capacity_conflict_a.publish(
      scp::EvidenceKind::Capacity, capacity_body(1000, 200, 800), clock->now());
  const scp::Result<scp::EvidenceRecord> claim_b = capacity_conflict_b.publish(
      scp::EvidenceKind::Capacity, capacity_body(1000, 900, 100), clock->now());
  if (!claim_a.has_value() || !claim_b.has_value()) {
    std::cerr << "site_turnup: contradictory capacity publication could not be built\n";
    return 1;
  }
  std::cout << "step " << step_number
            << ": the capacity owner publishes two records at epoch 1 generation 5 sequence 5\n";
  std::cout << "  first  " << claim_a.value().id.to_hex() << " reports 800 of 1000 units free\n";
  std::cout << "  second " << claim_b.value().id.to_hex() << " reports 100 of 1000 units free\n";
  if (!submit(runtime, clock, {claim_a.value(), claim_b.value()},
              "  contradictory pair")) {
    return 1;
  }
  const scp::Result<scp::SiteStateSnapshot> conflicting = runtime->snapshot(clock->now());
  if (!conflicting.has_value()) {
    std::cerr << "site_turnup: " << conflicting.status().to_string() << '\n';
    return 1;
  }
  std::cout << "  capacity slot " << slot_text(conflicting.value(), scp::EvidenceKind::Capacity)
            << '\n';
  std::cout << "  arrival order does not decide: the slot is conflicting, so the site is "
            << scp::to_string(conflicting.value().state) << '\n';
  ++step_number;

  // Step 13: a newer capacity generation supersedes both claims.
  Publisher capacity_resolution = facility_capacity;
  capacity_resolution.generation = scp::SourceGeneration(6);
  capacity_resolution.sequence = scp::Sequence(6);
  if (!advance(clock)) {
    return 1;
  }
  const scp::Result<scp::EvidenceRecord> resolved = capacity_resolution.publish(
      scp::EvidenceKind::Capacity, capacity_body(1000, 200, 800), clock->now());
  if (!resolved.has_value()) {
    std::cerr << "site_turnup: " << resolved.status().to_string() << '\n';
    return 1;
  }
  std::cout << "step " << step_number
            << ": the capacity owner publishes generation 6, superseding both claims\n";
  if (!submit(runtime, clock, {resolved.value()}, "  publication")) {
    return 1;
  }
  const scp::Result<scp::SiteStateSnapshot> available = runtime->snapshot(clock->now());
  if (!available.has_value()) {
    std::cerr << "site_turnup: " << available.status().to_string() << '\n';
    return 1;
  }
  std::cout << "  capacity slot " << slot_text(available.value(), scp::EvidenceKind::Capacity)
            << '\n';
  std::cout << "  every publisher now agrees: state=" << scp::to_string(available.value().state)
            << " classification=" << scp::to_string(available.value().classification)
            << " constraints=" << available.value().constraints.size() << '\n';

  const scp::RuntimeStatus before_close = runtime->status();
  std::size_t recovered_origins = 0;
  const std::string evidence_digest_before = available.value().evidence_digest.to_hex();
  const scp::Status closed = runtime->close();
  if (!closed.ok()) {
    std::cerr << "site_turnup: " << closed.to_string() << '\n';
    return 1;
  }

  // Reopen the same directory: the durable state must come back.
  scp::Result<std::unique_ptr<scp::SiteControlPlane>> reopened =
      scp::SiteControlPlane::open(options);
  if (!reopened.has_value()) {
    std::cerr << "site_turnup: reopen: " << reopened.status().to_string() << '\n';
    return 1;
  }
  runtime = std::move(reopened).value();
  const scp::RuntimeStatus after_open = runtime->status();
  const scp::Result<scp::SiteStateSnapshot> after = runtime->snapshot(clock->now());
  if (!after.has_value()) {
    std::cerr << "site_turnup: " << after.status().to_string() << '\n';
    return 1;
  }
  for (const scp::SlotResolution& resolution : after.value().slots) {
    if (resolution.origin == scp::EvidenceOrigin::RecoveredFromJournal) {
      ++recovered_origins;
    }
  }

  std::cout << "\nclosed and reopened " << scp::escape_for_display(directory.path().string()) << '\n';
  std::cout << "  site-generation " << after_open.site_generation.value() << " (before the close "
            << before_close.site_generation.value() << ")\n";
  std::cout << "  accepted-evidence " << after_open.accepted_evidence << " (before the close "
            << before_close.accepted_evidence << ")\n";
  std::cout << "  journal-sequence " << after_open.journal_sequence.value() << " (before the close "
            << before_close.journal_sequence.value() << ")\n";
  std::cout << "  recovered " << (after_open.recovered ? "true" : "false")
            << " recovered-operations " << after_open.recovered_operations << '\n';
  std::cout << "  state=" << scp::to_string(after.value().state)
            << " lifecycle=" << scp::to_string(after.value().lifecycle)
            << " classification=" << scp::to_string(after.value().classification)
            << " site-generation=" << after.value().site_generation.value() << '\n';
  std::cout << "  slots that report origin=recovered: " << recovered_origins << " of "
            << after.value().slots.size() << '\n';
  std::cout << "  evidence-digest before the close " << evidence_digest_before << '\n';
  std::cout << "  evidence-digest after the reopen " << after.value().evidence_digest.to_hex()
            << '\n';
  std::cout << "  the accepted identities, the state and the generation survived; the two digests "
               "differ because origin is covered by the evidence digest and every record is now "
               "recovered rather than freshly ingested\n";

  const scp::Status final_close = runtime->close();
  if (!final_close.ok()) {
    std::cerr << "site_turnup: " << final_close.to_string() << '\n';
    return 1;
  }
  std::cout << "\ntemporary directory removed on exit: "
            << scp::escape_for_display(directory.path().string()) << '\n';
  return 0;
}
