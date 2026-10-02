// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

// The readiness gates. Every gate is driven to both open and closed from the
// healthy baseline, and each closure is asserted by condition name so that a
// gate can never close for an unnamed reason.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/composition.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/policy.hpp"
#include "scp/readiness.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"
#include "test_support.hpp"

using scp::CapabilityEvidence;
using scp::EvidenceBody;
using scp::EvidenceKind;
using scp::EvidenceRecord;
using scp::GateCondition;
using scp::GateKind;
using scp::LifecycleEvidence;
using scp::LifecycleState;
using scp::MaintenanceEvidence;
using scp::Name;
using scp::ReadinessEvidence;
using scp::ReadinessGate;
using scp::ReadinessLevel;
using scp::Result;
using scp::ServiceClassEvidence;
using scp::ServiceClassObligation;
using scp::SiteGeneration;
using scp::SitePolicy;
using scp::SiteStateSnapshot;
using scp::StatusCode;
using scp::Timestamp;

namespace {

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

std::vector<EvidenceRecord> healthy() {
  return scp_test::healthy_site_records(scp_test::base_instant(), 1);
}

constexpr std::array<GateKind, scp::kGateKindCount> kGateOrder = {
    GateKind::NewObligation,   GateKind::MaintenanceEntry, GateKind::ControlledDrain,
    GateKind::EmergencyOperation, GateKind::RecoveryStart, GateKind::ReturnToService};

Result<SiteStateSnapshot> compose(const std::vector<EvidenceRecord>& records,
                                  const SitePolicy& policy, Timestamp at) {
  scp::CompositionOptions options;
  options.site = scp_test::default_site();
  options.site_generation = SiteGeneration::first();
  options.evaluation_time = at;
  options.policy = policy;
  return scp::compose_site_state(records, options);
}

SiteStateSnapshot must_compose(const std::vector<EvidenceRecord>& records,
                               const SitePolicy& policy, Timestamp at) {
  const Result<SiteStateSnapshot> snapshot = compose(records, policy, at);
  if (!snapshot.has_value()) {
    ::scp_test::Context::instance().note("composition failed: " + snapshot.status().to_string());
    SCP_CHECK(false);
    return SiteStateSnapshot{};
  }
  return snapshot.value();
}

void put(std::vector<EvidenceRecord>& records, EvidenceKind kind, const EvidenceBody& body) {
  const auto found = std::find_if(records.begin(), records.end(),
                                  [kind](const EvidenceRecord& record) {
                                    return record.kind == kind;
                                  });
  if (found == records.end()) {
    ::scp_test::Context::instance().note("fixture has no record of kind " +
                                         std::string(scp::to_string(kind)));
    SCP_CHECK(false);
    return;
  }
  const Result<EvidenceRecord> rebuilt =
      EvidenceRecord::create(found->provenance, kind, body);
  if (!rebuilt.has_value()) {
    ::scp_test::Context::instance().note("rebuilding " + std::string(scp::to_string(kind)) +
                                         " failed: " + rebuilt.status().to_string());
    SCP_CHECK(false);
    return;
  }
  *found = rebuilt.value();
}

void drop(std::vector<EvidenceRecord>& records, EvidenceKind kind) {
  const auto found = std::find_if(records.begin(), records.end(),
                                  [kind](const EvidenceRecord& record) {
                                    return record.kind == kind;
                                  });
  if (found == records.end()) {
    ::scp_test::Context::instance().note("fixture has no record of kind " +
                                         std::string(scp::to_string(kind)));
    SCP_CHECK(false);
    return;
  }
  records.erase(found);
}

/// Adds a second publication for the same slot with the same epoch, generation
/// and sequence but different content: publishers disagreeing about one
/// instant, which is the only thing that produces a conflict.
void conflict(std::vector<EvidenceRecord>& records, EvidenceKind kind, const EvidenceBody& body) {
  const auto found = std::find_if(records.begin(), records.end(),
                                  [kind](const EvidenceRecord& record) {
                                    return record.kind == kind;
                                  });
  if (found == records.end()) {
    ::scp_test::Context::instance().note("fixture has no record of kind " +
                                         std::string(scp::to_string(kind)));
    SCP_CHECK(false);
    return;
  }
  const Result<EvidenceRecord> rebuilt = EvidenceRecord::create(found->provenance, kind, body);
  if (!rebuilt.has_value()) {
    ::scp_test::Context::instance().note("conflicting publication failed: " +
                                         rebuilt.status().to_string());
    SCP_CHECK(false);
    return;
  }
  SCP_CHECK_NE(rebuilt.value().id, found->id);
  records.push_back(rebuilt.value());
}

ServiceClassEvidence service_class(std::uint32_t minimum_units, std::uint32_t minimum_percent,
                                   bool protected_class) {
  ServiceClassEvidence evidence;
  evidence.class_count = 1;
  ServiceClassObligation obligation;
  const Result<Name> name = Name::parse("interactive-inference");
  if (name.has_value()) {
    obligation.service_class = name.value();
  } else {
    SCP_CHECK(false);
  }
  obligation.protected_class = protected_class;
  obligation.minimum_ready_units = minimum_units;
  obligation.minimum_readiness_percent = minimum_percent;
  evidence.obligations.push_back(obligation);
  return evidence;
}

ReadinessEvidence readiness(ReadinessLevel level, std::uint32_t available_domains,
                            std::uint32_t required_domains) {
  ReadinessEvidence evidence;
  evidence.snapshot = scp::SnapshotId(0x0BADF00D00000000ULL, 0x0000000000000007ULL);
  evidence.readiness = level;
  evidence.headroom_milli_kw = 4000000;
  evidence.available_domains = available_domains;
  evidence.required_domains = required_domains;
  return evidence;
}

CapabilityEvidence capability(ReadinessLevel level, std::uint32_t ready_domains,
                              std::uint32_t total_domains) {
  CapabilityEvidence evidence;
  evidence.readiness = level;
  evidence.ready_domains = ready_domains;
  evidence.total_domains = total_domains;
  evidence.ready_units = 512;
  return evidence;
}

LifecycleEvidence lifecycle(LifecycleState state) {
  LifecycleEvidence evidence;
  evidence.state = state;
  evidence.entered_at = scp_test::base_instant();
  return evidence;
}

MaintenanceEvidence maintenance(std::uint32_t drained_percent, bool drain_in_progress) {
  MaintenanceEvidence evidence;
  evidence.mode = scp::MaintenanceMode::None;
  evidence.drain_in_progress = drain_in_progress;
  evidence.drained_percent = drained_percent;
  return evidence;
}

// ---------------------------------------------------------------------------
// Gate assertions
// ---------------------------------------------------------------------------

const ReadinessGate* gate_of(const SiteStateSnapshot& snapshot, GateKind kind) {
  for (const ReadinessGate& gate : snapshot.gates) {
    if (gate.kind == kind) {
      return &gate;
    }
  }
  ::scp_test::Context::instance().note("snapshot has no gate " +
                                       std::string(scp::to_string(kind)));
  SCP_CHECK(false);
  return nullptr;
}

bool all_satisfied(const ReadinessGate& gate) {
  return std::all_of(gate.conditions.begin(), gate.conditions.end(),
                     [](const GateCondition& condition) { return condition.satisfied; });
}

bool any_unsatisfied(const ReadinessGate& gate) {
  return std::any_of(gate.conditions.begin(), gate.conditions.end(),
                     [](const GateCondition& condition) { return !condition.satisfied; });
}

std::vector<std::string> unsatisfied_names(const ReadinessGate& gate) {
  std::vector<std::string> names;
  for (const GateCondition& condition : gate.conditions) {
    if (!condition.satisfied) {
      names.push_back(std::string(condition.name.view()));
    }
  }
  std::sort(names.begin(), names.end());
  return names;
}

std::vector<std::string> sorted(std::initializer_list<std::string_view> names) {
  std::vector<std::string> result;
  result.reserve(names.size());
  for (const std::string_view name : names) {
    result.push_back(std::string(name));
  }
  std::sort(result.begin(), result.end());
  return result;
}

void expect_open(const ReadinessGate& gate, const char* what) {
  if (!gate.open) {
    std::string reasons;
    for (const std::string& name : unsatisfied_names(gate)) {
      reasons += " " + name;
    }
    ::scp_test::Context::instance().note(std::string(what) + ": gate " +
                                         std::string(scp::to_string(gate.kind)) +
                                         " is closed by:" + reasons);
  }
  SCP_CHECK(gate.open);
}

/// The gate is closed, and exactly these conditions are the unsatisfied ones.
void expect_closed_by(const ReadinessGate& gate, std::initializer_list<std::string_view> names,
                      const char* what) {
  SCP_CHECK(!gate.open);
  const std::vector<std::string> actual = unsatisfied_names(gate);
  const std::vector<std::string> expected = sorted(names);
  if (actual != expected) {
    std::string actual_text;
    for (const std::string& name : actual) {
      actual_text += " " + name;
    }
    std::string expected_text;
    for (const std::string& name : expected) {
      expected_text += " " + name;
    }
    ::scp_test::Context::instance().note(std::string(what) + ": gate " +
                                         std::string(scp::to_string(gate.kind)) + " closed by [" +
                                         actual_text + " ] but expected [" + expected_text + " ]");
  }
  SCP_CHECK(actual == expected);
}

const GateCondition* require_condition(const ReadinessGate& gate, std::string_view name) {
  const GateCondition* condition = gate.find_condition(name);
  if (condition == nullptr) {
    ::scp_test::Context::instance().note("gate " + std::string(scp::to_string(gate.kind)) +
                                         " has no condition '" + std::string(name) + "'");
    SCP_CHECK(false);
  }
  return condition;
}

void expect_condition(const ReadinessGate& gate, std::string_view name, bool satisfied,
                      const char* what) {
  const GateCondition* condition = require_condition(gate, name);
  if (condition == nullptr) {
    return;
  }
  if (condition->satisfied != satisfied) {
    ::scp_test::Context::instance().note(std::string(what) + ": condition '" +
                                         std::string(name) + "' satisfied=" +
                                         (condition->satisfied ? "true" : "false"));
  }
  SCP_CHECK_EQ(condition->satisfied, satisfied);
}

/// Every gate is the AND of its conditions, every closed gate names at least
/// one unsatisfied condition, and every condition name is a valid Name.
void check_gate_invariants(const SiteStateSnapshot& snapshot, const char* what) {
  SCP_CHECK_EQ(snapshot.gates.size(), scp::kGateKindCount);
  for (const ReadinessGate& gate : snapshot.gates) {
    SCP_CHECK_EQ(gate.open, all_satisfied(gate));
    if (!gate.open) {
      if (!any_unsatisfied(gate)) {
        ::scp_test::Context::instance().note(std::string(what) + ": gate " +
                                             std::string(scp::to_string(gate.kind)) +
                                             " is closed with no unsatisfied condition");
      }
      SCP_CHECK(any_unsatisfied(gate));
    }
    SCP_CHECK(!gate.conditions.empty());
    for (const GateCondition& condition : gate.conditions) {
      SCP_CHECK(!condition.name.empty());
      SCP_CHECK(Name::parse(condition.name.view()).has_value());
      SCP_CHECK(!condition.observed.empty());
      SCP_CHECK(!condition.required.empty());
      SCP_CHECK(!condition.detail.empty());
    }
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// The healthy baseline
// ---------------------------------------------------------------------------

SCP_TEST(healthy_baseline_opens_the_expected_gates) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());

  SCP_CHECK_EQ(snapshot.state, scp::SiteState::Available);
  SCP_CHECK_EQ(snapshot.classification, scp::EvidenceClassification::Complete);
  SCP_CHECK_EQ(snapshot.lifecycle, LifecycleState::Active);
  SCP_CHECK_EQ(snapshot.readiness_percent, std::uint32_t{100});
  SCP_CHECK(snapshot.constraints.empty());
  SCP_CHECK_EQ(snapshot.blocking_constraint_count(), std::size_t{0});
  SCP_CHECK_EQ(snapshot.obligations.size(), std::size_t{1});
  if (!snapshot.obligations.empty()) {
    SCP_CHECK_EQ(snapshot.obligations.front().outcome, scp::ObligationOutcome::Satisfied);
  }
  SCP_CHECK_EQ(snapshot.readiness_domains.size(), std::size_t{4});
  check_gate_invariants(snapshot, "healthy baseline");

  const ReadinessGate* new_obligation = gate_of(snapshot, GateKind::NewObligation);
  SCP_REQUIRE(new_obligation != nullptr);
  expect_open(*new_obligation, "healthy baseline");
  SCP_CHECK_EQ(new_obligation->conditions.size(), std::size_t{10});
  const std::array<std::string_view, 10> expected_names = {
      "site-not-retired",   "state-admits-obligation", "evidence-unconflicted",
      "evidence-complete",  "evidence-fresh",          "power-ready",
      "cooling-ready",      "accelerators-ready",      "fabric-ready",
      "no-unsatisfied-obligation"};
  for (const std::string_view name : expected_names) {
    expect_condition(*new_obligation, name, true, "healthy baseline");
  }

  const ReadinessGate* maintenance_gate = gate_of(snapshot, GateKind::MaintenanceEntry);
  SCP_REQUIRE(maintenance_gate != nullptr);
  expect_open(*maintenance_gate, "healthy baseline");

  const ReadinessGate* drain = gate_of(snapshot, GateKind::ControlledDrain);
  SCP_REQUIRE(drain != nullptr);
  expect_open(*drain, "healthy baseline");

  const ReadinessGate* emergency = gate_of(snapshot, GateKind::EmergencyOperation);
  SCP_REQUIRE(emergency != nullptr);
  expect_closed_by(*emergency, {"emergency-context"}, "no emergency is declared");

  const ReadinessGate* recovery = gate_of(snapshot, GateKind::RecoveryStart);
  SCP_REQUIRE(recovery != nullptr);
  expect_closed_by(*recovery, {"drain-complete", "lifecycle-supports-recovery"},
                   "nothing has drained and the site is not in a recoverable position");

  const ReadinessGate* returning = gate_of(snapshot, GateKind::ReturnToService);
  SCP_REQUIRE(returning != nullptr);
  expect_open(*returning, "healthy baseline");
}

// ---------------------------------------------------------------------------
// NewObligation
// ---------------------------------------------------------------------------

SCP_TEST(new_obligation_gate_closes_on_each_condition) {
  const SitePolicy policy = scp_test::strict_policy();

  {  // A conflicting slot: publishers disagree and the plane picks no winner.
    std::vector<EvidenceRecord> records = healthy();
    scp::IncidentEvidence conflicting;
    conflicting.active_incidents = 1;
    conflicting.worst_active_severity = scp::Severity::Major;
    conflict(records, EvidenceKind::Incident, EvidenceBody{conflicting});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.classification, scp::EvidenceClassification::Conflicting);
    check_gate_invariants(snapshot, "conflicting slot");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "evidence-unconflicted", false, "a conflicting slot");
  }

  {  // Missing evidence: the maintenance publication never arrived.
    std::vector<EvidenceRecord> records = healthy();
    drop(records, EvidenceKind::Maintenance);
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "missing maintenance evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"evidence-complete"}, "a missing publication");
  }

  {  // A stale publication: judged 2000s after it was issued.
    const SiteStateSnapshot snapshot =
        must_compose(healthy(), policy, scp_test::instant_after(2000));
    check_gate_invariants(snapshot, "stale evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "evidence-fresh", false, "a stale publication");
    expect_condition(*gate, "evidence-complete", false, "a stale publication");
  }

  {  // An unavailable power domain.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::PowerReadiness,
        EvidenceBody{readiness(ReadinessLevel::Unavailable, 0, 2)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "unavailable power");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "power-ready", false, "unavailable power");
    const GateCondition* condition = require_condition(*gate, "power-ready");
    SCP_REQUIRE(condition != nullptr);
    SCP_CHECK(condition->observed.find("unavailable") != std::string::npos);
    SCP_CHECK_EQ(condition->required, std::string("readiness level ready"));
  }

  {  // A degraded cooling domain.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::CoolingReadiness,
        EvidenceBody{readiness(ReadinessLevel::Degraded, 2, 2)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "degraded cooling");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "cooling-ready", false, "degraded cooling");
    const GateCondition* condition = require_condition(*gate, "cooling-ready");
    SCP_REQUIRE(condition != nullptr);
    SCP_CHECK(condition->observed.find("degraded") != std::string::npos);
  }

  {  // An unavailable accelerator domain and a degraded fabric domain.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::AsiCapability,
        EvidenceBody{capability(ReadinessLevel::Unavailable, 0, 8)});
    put(records, EvidenceKind::DfiCapability,
        EvidenceBody{capability(ReadinessLevel::Degraded, 4, 4)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "unready capability domains");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "accelerators-ready", false, "an unavailable accelerator domain");
    expect_condition(*gate, "fabric-ready", false, "a degraded fabric domain");
  }

  {  // An unsatisfied obligation, and nothing else.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::ServiceClass, EvidenceBody{service_class(1000, 50, true)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "unsatisfied obligation");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"no-unsatisfied-obligation"}, "an unsatisfied obligation");
  }

  {  // A state that does not admit obligations.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Draining)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.state, scp::SiteState::Draining);
    check_gate_invariants(snapshot, "draining");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"state-admits-obligation"}, "a draining site");
  }

  {  // A retired site accepts nothing at all.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Retired)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.state, scp::SiteState::Retired);
    check_gate_invariants(snapshot, "retired");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::NewObligation);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "site-not-retired", false, "a retired site");
    expect_condition(*gate, "state-admits-obligation", false, "a retired site");
  }
}

// ---------------------------------------------------------------------------
// MaintenanceEntry
// ---------------------------------------------------------------------------

SCP_TEST(maintenance_entry_gate_closes_on_each_condition) {
  const SitePolicy policy = scp_test::strict_policy();

  {  // The baseline is open.
    const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "healthy baseline");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::MaintenanceEntry);
    SCP_REQUIRE(gate != nullptr);
    expect_open(*gate, "healthy baseline");
  }

  {  // A declared emergency supersedes planned maintenance.
    std::vector<EvidenceRecord> records = healthy();
    scp::IncidentEvidence incident;
    incident.emergency_declared = true;
    put(records, EvidenceKind::Incident, EvidenceBody{incident});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "emergency declared");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::MaintenanceEntry);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "not-in-emergency", false, "a declared emergency");
  }

  {  // Below the maintenance readiness floor, and nothing else.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::CoolingReadiness,
        EvidenceBody{readiness(ReadinessLevel::Ready, 1, 2)});
    SitePolicy floored = policy;
    floored.maintenance_minimum_readiness_percent = 75;
    const SiteStateSnapshot snapshot = must_compose(records, floored, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.readiness_percent, std::uint32_t{50});
    check_gate_invariants(snapshot, "maintenance floor");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::MaintenanceEntry);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"readiness-floor"}, "readiness below the maintenance floor");
  }

  {  // The same site passes the floor when the policy asks for less.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::CoolingReadiness,
        EvidenceBody{readiness(ReadinessLevel::Ready, 1, 2)});
    SitePolicy floored = policy;
    floored.maintenance_minimum_readiness_percent = 50;
    const SiteStateSnapshot snapshot = must_compose(records, floored, scp_test::base_instant());
    const ReadinessGate* gate = gate_of(snapshot, GateKind::MaintenanceEntry);
    SCP_REQUIRE(gate != nullptr);
    expect_open(*gate, "readiness exactly at the maintenance floor");
  }

  {  // An unsatisfied obligation must be resolved before the site is taken out.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::ServiceClass, EvidenceBody{service_class(1000, 50, true)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    const ReadinessGate* gate = gate_of(snapshot, GateKind::MaintenanceEntry);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"no-unsatisfied-obligation"}, "an unsatisfied obligation");
  }

  {  // The maintenance publication is missing.
    std::vector<EvidenceRecord> records = healthy();
    drop(records, EvidenceKind::Maintenance);
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "missing maintenance evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::MaintenanceEntry);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"maintenance-evidence-present"}, "no maintenance publication");
  }

  {  // The lifecycle publication is missing.
    std::vector<EvidenceRecord> records = healthy();
    drop(records, EvidenceKind::Lifecycle);
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "missing lifecycle evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::MaintenanceEntry);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"maintenance-evidence-present"}, "no lifecycle publication");
  }

  {  // A retired site needs no maintenance.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Retired)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    const ReadinessGate* gate = gate_of(snapshot, GateKind::MaintenanceEntry);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"site-not-retired"}, "a retired site");
  }
}

// ---------------------------------------------------------------------------
// ControlledDrain
// ---------------------------------------------------------------------------

SCP_TEST(controlled_drain_gate_closes_on_each_condition) {
  const SitePolicy policy = scp_test::strict_policy();

  {  // Open from active.
    const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.lifecycle, LifecycleState::Active);
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ControlledDrain);
    SCP_REQUIRE(gate != nullptr);
    expect_open(*gate, "active site");
  }

  {  // A protected obligation that is already unsatisfied.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::ServiceClass, EvidenceBody{service_class(1000, 50, true)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "unsatisfied protected obligation");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ControlledDrain);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "protected-obligations-satisfied", false,
                     "an unsatisfied protected obligation");
  }

  {  // An unprotected obligation is a different thing: the drain may proceed.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::ServiceClass, EvidenceBody{service_class(1000, 50, false)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.obligations.size(), std::size_t{1});
    if (!snapshot.obligations.empty()) {
      SCP_CHECK_EQ(snapshot.obligations.front().outcome, scp::ObligationOutcome::Unsatisfied);
      SCP_CHECK(!snapshot.obligations.front().protected_class);
    }
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ControlledDrain);
    SCP_REQUIRE(gate != nullptr);
    expect_open(*gate, "an unsatisfied unprotected obligation");
  }

  {  // Conflicting evidence: a drain will not proceed on a contradiction.
    std::vector<EvidenceRecord> records = healthy();
    scp::IncidentEvidence conflicting;
    conflicting.active_incidents = 1;
    conflict(records, EvidenceKind::Incident, EvidenceBody{conflicting});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "conflicting evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ControlledDrain);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"evidence-unconflicted"}, "conflicting evidence");
  }

  {  // A site under commissioning has nothing to drain.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Commissioning)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.state, scp::SiteState::Commissioning);
    check_gate_invariants(snapshot, "commissioning");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ControlledDrain);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"lifecycle-supports-drain"}, "a commissioning site");
  }
}

// ---------------------------------------------------------------------------
// EmergencyOperation
// ---------------------------------------------------------------------------

SCP_TEST(emergency_operation_gate_follows_the_emergency) {
  const SitePolicy policy = scp_test::strict_policy();

  {  // Without a declared emergency the gate is closed and says exactly that.
    const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "no emergency");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::EmergencyOperation);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"emergency-context"}, "no declared emergency");
    const GateCondition* condition = require_condition(*gate, "emergency-context");
    SCP_REQUIRE(condition != nullptr);
    SCP_CHECK_EQ(condition->observed, std::string("not declared"));
    SCP_CHECK_EQ(condition->required, std::string("a declared emergency"));
  }

  {  // A declared emergency opens the gate even when the rest of the site is
     // unready: power is unavailable, cooling is degraded, accelerators are
     // unavailable and the protected obligation is already unsatisfied.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Emergency)});
    put(records, EvidenceKind::PowerReadiness,
        EvidenceBody{readiness(ReadinessLevel::Unavailable, 0, 2)});
    put(records, EvidenceKind::CoolingReadiness,
        EvidenceBody{readiness(ReadinessLevel::Degraded, 1, 2)});
    put(records, EvidenceKind::AsiCapability,
        EvidenceBody{capability(ReadinessLevel::Unavailable, 0, 8)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.state, scp::SiteState::Emergency);
    SCP_CHECK(snapshot.has_constraint(scp::ConstraintKind::EmergencyDeclared));
    check_gate_invariants(snapshot, "declared emergency with unready domains");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::EmergencyOperation);
    SCP_REQUIRE(gate != nullptr);
    expect_open(*gate, "a declared emergency on an unready site");
    expect_condition(*gate, "emergency-context", true, "a declared emergency");
    // The gate is deliberately permissive, so it carries no readiness condition
    // of its own while the policy allows unready domains.
    SCP_CHECK_EQ(gate->conditions.size(), std::size_t{3});
    SCP_CHECK(gate->find_condition("power-ready") == nullptr);
    SCP_CHECK(gate->find_condition("evidence-complete") == nullptr);
  }

  {  // Contradictory evidence is the one thing an emergency does not authorise.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Emergency)});
    scp::CapacityEvidence conflicting;
    conflicting.snapshot = scp::SnapshotId(0x0BADF00D00000000ULL, 0x0000000000000009ULL);
    conflicting.generation = scp::CapacityGeneration(1);
    conflicting.total_units = 100;
    conflicting.committed_units = 40;
    conflicting.available_units = 60;
    conflict(records, EvidenceKind::Capacity, EvidenceBody{conflicting});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.classification, scp::EvidenceClassification::Conflicting);
    check_gate_invariants(snapshot, "emergency with contradictory evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::EmergencyOperation);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"evidence-unconflicted"},
                     "an emergency with contradictory evidence");
    expect_condition(*gate, "emergency-context", true,
                     "the emergency is still declared");
    const GateCondition* condition = require_condition(*gate, "evidence-unconflicted");
    SCP_REQUIRE(condition != nullptr);
    SCP_CHECK_EQ(condition->observed, std::string("conflicting"));
  }

  {  // A policy that refuses to operate on partial evidence or unready domains
     // adds those conditions and closes the gate for each of them.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Emergency)});
    drop(records, EvidenceKind::DfiCapability);
    put(records, EvidenceKind::PowerReadiness,
        EvidenceBody{readiness(ReadinessLevel::Unavailable, 0, 2)});
    SitePolicy strict_emergency = policy;
    strict_emergency.emergency_allows_partial_evidence = false;
    strict_emergency.emergency_allows_unready_domains = false;
    const SiteStateSnapshot snapshot =
        must_compose(records, strict_emergency, scp_test::base_instant());
    check_gate_invariants(snapshot, "strict emergency policy");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::EmergencyOperation);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "evidence-complete", false, "partial evidence under a strict policy");
    expect_condition(*gate, "power-ready", false, "unavailable power under a strict policy");
  }
}

// ---------------------------------------------------------------------------
// RecoveryStart
// ---------------------------------------------------------------------------

SCP_TEST(recovery_start_gate_needs_a_completed_drain) {
  const SitePolicy policy = scp_test::strict_policy();

  {  // The baseline has not drained and cannot recover.
    const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
    const ReadinessGate* gate = gate_of(snapshot, GateKind::RecoveryStart);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "drain-complete", false, "nothing has drained");
    expect_condition(*gate, "lifecycle-supports-recovery", false, "an active site");
    const GateCondition* condition = require_condition(*gate, "drain-complete");
    SCP_REQUIRE(condition != nullptr);
    SCP_CHECK_EQ(condition->observed, std::string("0%"));
    SCP_CHECK_EQ(condition->required, std::string("at least 100%"));
  }

  {  // Half drained: recovery would resume work on hardware still holding state.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Draining)});
    put(records, EvidenceKind::Maintenance, EvidenceBody{maintenance(50, true)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "half drained");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::RecoveryStart);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"drain-complete"}, "a half-completed drain");
  }

  {  // Fully drained but the lifecycle is not in a position to recover.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Maintenance, EvidenceBody{maintenance(100, false)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "drained active site");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::RecoveryStart);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"lifecycle-supports-recovery"}, "an active site that has drained");
  }

  {  // Drained and recovering: the gate opens.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    put(records, EvidenceKind::Maintenance, EvidenceBody{maintenance(100, false)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "recovering and drained");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::RecoveryStart);
    SCP_REQUIRE(gate != nullptr);
    expect_open(*gate, "a drained site in a recovering position");
  }

  {  // Draining at the drain floor is the second recovering-capable position.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Draining)});
    put(records, EvidenceKind::Maintenance, EvidenceBody{maintenance(100, true)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    const ReadinessGate* gate = gate_of(snapshot, GateKind::RecoveryStart);
    SCP_REQUIRE(gate != nullptr);
    expect_open(*gate, "a fully drained site still draining");
  }

  {  // The drain floor is the policy's, not a constant.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Maintenance)});
    put(records, EvidenceKind::Maintenance, EvidenceBody{maintenance(99, true)});
    SitePolicy lower = policy;
    lower.recovery_minimum_drained_percent = 99;
    const SiteStateSnapshot at_floor = must_compose(records, lower, scp_test::base_instant());
    const ReadinessGate* open_gate = gate_of(at_floor, GateKind::RecoveryStart);
    SCP_REQUIRE(open_gate != nullptr);
    expect_open(*open_gate, "drained exactly to the configured floor");

    SitePolicy higher = policy;
    higher.recovery_minimum_drained_percent = 100;
    const SiteStateSnapshot below_floor = must_compose(records, higher, scp_test::base_instant());
    const ReadinessGate* closed_gate = gate_of(below_floor, GateKind::RecoveryStart);
    SCP_REQUIRE(closed_gate != nullptr);
    expect_closed_by(*closed_gate, {"drain-complete"}, "one percent below the configured floor");
  }
}

// ---------------------------------------------------------------------------
// ReturnToService
// ---------------------------------------------------------------------------

SCP_TEST(return_to_service_gate_closes_on_each_condition) {
  const SitePolicy policy = scp_test::strict_policy();

  {  // A healthy recovered site returns to service.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    put(records, EvidenceKind::Maintenance, EvidenceBody{maintenance(100, false)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.state, scp::SiteState::Recovering);
    check_gate_invariants(snapshot, "healthy recovered site");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(gate != nullptr);
    expect_open(*gate, "a healthy recovered site");
  }

  {  // Incomplete evidence.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    drop(records, EvidenceKind::DfiCapability);
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "incomplete evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "evidence-complete", false, "a missing publication");
    expect_condition(*gate, "fabric-ready", false, "a missing publication");
    expect_condition(*gate, "no-blocking-constraints", false, "a missing publication");
  }

  {  // Stale evidence.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    const SiteStateSnapshot snapshot =
        must_compose(records, policy, scp_test::instant_after(4000));
    check_gate_invariants(snapshot, "stale evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "evidence-fresh", false, "an expired publication");
  }

  {  // Conflicting evidence.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    scp::IncidentEvidence conflicting;
    conflicting.active_incidents = 1;
    conflict(records, EvidenceKind::Incident, EvidenceBody{conflicting});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "conflicting evidence");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "evidence-unconflicted", false, "conflicting evidence");
  }

  {  // A blocking constraint.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    scp::CapacityEvidence oversubscribed;
    oversubscribed.snapshot = scp::SnapshotId(0x0BADF00D00000000ULL, 0x000000000000000BULL);
    oversubscribed.generation = scp::CapacityGeneration(1);
    oversubscribed.total_units = 100;
    oversubscribed.committed_units = 140;
    oversubscribed.available_units = 60;
    oversubscribed.oversubscribed = true;
    put(records, EvidenceKind::Capacity, EvidenceBody{oversubscribed});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK(snapshot.has_constraint(scp::ConstraintKind::CapacityOversubscribed));
    SCP_CHECK(snapshot.blocking_constraint_count() > 0U);
    check_gate_invariants(snapshot, "blocking constraint");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(gate != nullptr);
    SCP_CHECK(!gate->open);
    expect_condition(*gate, "no-blocking-constraints", false, "an oversubscribed site");
  }

  {  // An unmet readiness floor, and nothing else.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    put(records, EvidenceKind::CoolingReadiness,
        EvidenceBody{readiness(ReadinessLevel::Ready, 1, 2)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    SCP_CHECK_EQ(snapshot.readiness_percent, std::uint32_t{50});
    check_gate_invariants(snapshot, "readiness floor");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"readiness-floor"}, "readiness below the return-to-service floor");
  }

  {  // A single unready dependency domain, and nothing else.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    put(records, EvidenceKind::AsiCapability,
        EvidenceBody{capability(ReadinessLevel::Constrained, 8, 8)});
    const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
    check_gate_invariants(snapshot, "constrained accelerators");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"accelerators-ready"}, "a constrained accelerator domain");
  }

  {  // Reduced redundancy, when the policy demands full redundancy.
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Recovering)});
    put(records, EvidenceKind::PowerReadiness,
        EvidenceBody{readiness(ReadinessLevel::Ready, 1, 2)});
    SitePolicy full = policy;
    full.require_full_redundancy_for_return_to_service = true;
    full.return_to_service_minimum_readiness_percent = 0;
    const SiteStateSnapshot snapshot = must_compose(records, full, scp_test::base_instant());
    check_gate_invariants(snapshot, "reduced redundancy");
    const ReadinessGate* gate = gate_of(snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(gate != nullptr);
    expect_closed_by(*gate, {"redundancy-restored"}, "reduced redundancy under a full policy");

    // The same site returns to service when the policy does not require it, and
    // the condition is not even evaluated.
    SitePolicy relaxed = policy;
    relaxed.require_full_redundancy_for_return_to_service = false;
    relaxed.return_to_service_minimum_readiness_percent = 0;
    const SiteStateSnapshot relaxed_snapshot =
        must_compose(records, relaxed, scp_test::base_instant());
    const ReadinessGate* relaxed_gate = gate_of(relaxed_snapshot, GateKind::ReturnToService);
    SCP_REQUIRE(relaxed_gate != nullptr);
    SCP_CHECK(relaxed_gate->find_condition("redundancy-restored") == nullptr);
    expect_open(*relaxed_gate, "reduced redundancy without a full-redundancy policy");
  }
}

// ---------------------------------------------------------------------------
// The gate set as a whole
// ---------------------------------------------------------------------------

SCP_TEST(all_gates_have_a_fixed_order_and_are_deterministic) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());

  const Result<std::vector<ReadinessGate>> first = scp::evaluate_all_gates(snapshot, policy);
  SCP_REQUIRE_OK(first);
  const Result<std::vector<ReadinessGate>> second = scp::evaluate_all_gates(snapshot, policy);
  SCP_REQUIRE_OK(second);

  SCP_CHECK_EQ(first.value().size(), scp::kGateKindCount);
  SCP_CHECK_EQ(second.value().size(), scp::kGateKindCount);
  for (std::size_t index = 0; index < kGateOrder.size(); ++index) {
    SCP_CHECK_EQ(first.value()[index].kind, kGateOrder[index]);
    SCP_CHECK_EQ(second.value()[index].kind, kGateOrder[index]);
    SCP_CHECK_EQ(first.value()[index].open, second.value()[index].open);
    SCP_CHECK_EQ(first.value()[index].conditions.size(),
                 second.value()[index].conditions.size());
    for (std::size_t position = 0; position < first.value()[index].conditions.size(); ++position) {
      const GateCondition& left = first.value()[index].conditions[position];
      const GateCondition& right = second.value()[index].conditions[position];
      SCP_CHECK_EQ(left.name, right.name);
      SCP_CHECK_EQ(left.satisfied, right.satisfied);
      SCP_CHECK_EQ(left.observed, right.observed);
      SCP_CHECK_EQ(left.required, right.required);
      SCP_CHECK_EQ(left.detail, right.detail);
    }
    // The snapshot carries the gates composition evaluated, and evaluating one
    // gate directly gives the same answer.
    SCP_CHECK_EQ(snapshot.gates[index].kind, kGateOrder[index]);
    SCP_CHECK_EQ(snapshot.gates[index].open, first.value()[index].open);
    const Result<ReadinessGate> single = scp::evaluate_gate(kGateOrder[index], snapshot, policy);
    SCP_REQUIRE_OK(single);
    SCP_CHECK_EQ(single.value().open, first.value()[index].open);
    SCP_CHECK_EQ(single.value().conditions.size(), first.value()[index].conditions.size());
  }

  // The gate vocabulary round-trips.
  for (const GateKind kind : kGateOrder) {
    SCP_CHECK(!scp::to_string(kind).empty());
    const Result<GateKind> parsed = scp::gate_kind_from_string(scp::to_string(kind));
    SCP_CHECK(parsed.has_value());
    if (parsed.has_value()) {
      SCP_CHECK_EQ(parsed.value(), kind);
    }
  }
  const Result<GateKind> unknown = scp::gate_kind_from_string("no-such-gate");
  SCP_CHECK(!unknown.has_value());
  if (!unknown.has_value()) {
    SCP_CHECK_EQ(unknown.status().code(), StatusCode::InvalidArgument);
  }

  // A snapshot that was never composed cannot be gated, and neither can an
  // impossible policy.
  const SiteStateSnapshot empty;
  const Result<ReadinessGate> no_slots = scp::evaluate_gate(GateKind::NewObligation, empty, policy);
  SCP_CHECK(!no_slots.has_value());
  if (!no_slots.has_value()) {
    SCP_CHECK_EQ(no_slots.status().code(), StatusCode::InvalidArgument);
  }

  SitePolicy impossible = policy;
  impossible.maintenance_minimum_readiness_percent = 200;
  const Result<ReadinessGate> bad_policy =
      scp::evaluate_gate(GateKind::NewObligation, snapshot, impossible);
  SCP_CHECK(!bad_policy.has_value());
  if (!bad_policy.has_value()) {
    SCP_CHECK_EQ(bad_policy.status().code(), StatusCode::OutOfRange);
  }
  const Result<std::vector<ReadinessGate>> all_bad = scp::evaluate_all_gates(snapshot, impossible);
  SCP_CHECK(!all_bad.has_value());
}

SCP_TEST(gate_condition_names_are_valid_names) {
  const SitePolicy policy = scp_test::strict_policy();
  std::vector<SiteStateSnapshot> snapshots;

  snapshots.push_back(must_compose(healthy(), policy, scp_test::base_instant()));

  {
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Emergency)});
    put(records, EvidenceKind::PowerReadiness,
        EvidenceBody{readiness(ReadinessLevel::Unavailable, 0, 2)});
    put(records, EvidenceKind::ServiceClass, EvidenceBody{service_class(1000, 50, true)});
    snapshots.push_back(must_compose(records, policy, scp_test::base_instant()));
  }
  {
    std::vector<EvidenceRecord> records = healthy();
    scp::CapacityEvidence conflicting;
    conflicting.snapshot = scp::SnapshotId(0x0BADF00D00000000ULL, 0x000000000000000DULL);
    conflicting.generation = scp::CapacityGeneration(1);
    conflicting.total_units = 100;
    conflicting.available_units = 60;
    conflict(records, EvidenceKind::Capacity, EvidenceBody{conflicting});
    snapshots.push_back(must_compose(records, policy, scp_test::base_instant()));
  }
  {
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Retired)});
    snapshots.push_back(must_compose(records, policy, scp_test::instant_after(5000)));
  }
  {
    std::vector<EvidenceRecord> records = healthy();
    put(records, EvidenceKind::Lifecycle, EvidenceBody{lifecycle(LifecycleState::Draining)});
    put(records, EvidenceKind::Maintenance, EvidenceBody{maintenance(100, true)});
    put(records, EvidenceKind::AsiCapability,
        EvidenceBody{capability(ReadinessLevel::Degraded, 3, 8)});
    snapshots.push_back(must_compose(records, policy, scp_test::base_instant()));
  }

  std::size_t conditions_seen = 0;
  for (const SiteStateSnapshot& snapshot : snapshots) {
    SCP_CHECK_EQ(snapshot.gates.size(), scp::kGateKindCount);
    for (const ReadinessGate& gate : snapshot.gates) {
      SCP_CHECK(!gate.conditions.empty());
      for (const GateCondition& condition : gate.conditions) {
        ++conditions_seen;
        SCP_CHECK(!condition.name.empty());
        const Result<Name> parsed = Name::parse(condition.name.view());
        if (!parsed.has_value()) {
          ::scp_test::Context::instance().note("gate " + std::string(scp::to_string(gate.kind)) +
                                               " has an invalid condition name '" +
                                               std::string(condition.name.view()) + "': " +
                                               parsed.status().to_string());
        }
        SCP_CHECK(parsed.has_value());
        SCP_CHECK(!condition.detail.empty());
      }
      SCP_CHECK_EQ(gate.open, all_satisfied(gate));
    }
  }
  SCP_CHECK(conditions_seen > 20U);
}

SCP_TEST_MAIN("readiness")
