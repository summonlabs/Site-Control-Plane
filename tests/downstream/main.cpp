// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

// An independent downstream consumer built against the installed package.
//
// It uses only the public headers and the exported namespaced target, exercises
// the durable path end to end, closes and reopens a real site directory, and
// proves that the package is usable without the source tree.

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "scp/composition.hpp"
#include "scp/evidence.hpp"
#include "scp/explain.hpp"
#include "scp/ids.hpp"
#include "scp/plan.hpp"
#include "scp/readiness.hpp"
#include "scp/runtime.hpp"
#include "scp/version.hpp"

namespace {

int fail(const std::string& message) {
  std::cerr << "downstream_consumer: " << message << "\n";
  return 1;
}

scp::Timestamp at(std::int64_t seconds) {
  return scp::Timestamp{1767225600000000000LL + seconds * scp::kNanosPerSecond};
}

scp::SiteId site() { return scp::SiteId(0xD09D57EA30000001ULL, 0x0000000000000001ULL); }

scp::SourceInstanceId instance(std::uint64_t seed) {
  return scp::SourceInstanceId(0xA5A5A5A500000000ULL + seed, 0x0000000000000001ULL);
}

scp::Provenance provenance(scp::SourceAuthority authority, std::uint64_t seed,
                           std::uint64_t generation, scp::Timestamp issued) {
  scp::Provenance value;
  value.authority = authority;
  value.instance = instance(seed);
  value.epoch = scp::Epoch(1);
  value.generation = scp::SourceGeneration(generation);
  value.sequence = scp::Sequence(1);
  value.issued_at = issued;
  return value;
}

std::vector<scp::EvidenceRecord> healthy(scp::Timestamp issued, std::uint64_t generation,
                                         std::string& error) {
  std::vector<scp::EvidenceRecord> records;
  const auto push = [&records, &error](const scp::Result<scp::EvidenceRecord>& record) {
    if (!record.has_value()) {
      error = record.status().to_string();
      return;
    }
    records.push_back(record.value());
  };

  scp::FacilityStateEvidence facility;
  facility.generation = scp::FacilityStateGeneration(generation);
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::FacilityStateLedger, 11, generation, issued),
      scp::EvidenceKind::FacilityState, scp::EvidenceBody{facility}));

  scp::LifecycleEvidence lifecycle;
  lifecycle.state = scp::LifecycleState::Active;
  lifecycle.entered_at = issued;
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::FacilityStateLedger, 11, generation, issued),
      scp::EvidenceKind::Lifecycle, scp::EvidenceBody{lifecycle}));

  scp::CapacityEvidence capacity;
  capacity.snapshot = scp::SnapshotId(0xABCDEF0000000001ULL, 1);
  capacity.generation = scp::CapacityGeneration(generation);
  capacity.total_units = 100;
  capacity.committed_units = 25;
  capacity.available_units = 75;
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::FacilityCapacity, 12, generation, issued),
      scp::EvidenceKind::Capacity, scp::EvidenceBody{capacity}));

  scp::ReadinessEvidence power;
  power.snapshot = scp::SnapshotId(0xABCDEF0000000002ULL, 2);
  power.readiness = scp::ReadinessLevel::Ready;
  power.headroom_milli_kw = 900000;
  power.available_domains = 2;
  power.required_domains = 2;
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::PowerControlPlane, 13, generation, issued),
      scp::EvidenceKind::PowerReadiness, scp::EvidenceBody{power}));

  scp::ReadinessEvidence cooling = power;
  cooling.snapshot = scp::SnapshotId(0xABCDEF0000000003ULL, 3);
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::ThermalControlPlane, 14, generation, issued),
      scp::EvidenceKind::CoolingReadiness, scp::EvidenceBody{cooling}));

  scp::PolicyEvidence policy;
  policy.generation = scp::PolicyGeneration(generation);
  policy.rule_count = 2;
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::FacilityPolicyEngine, 15, generation, issued),
      scp::EvidenceKind::Policy, scp::EvidenceBody{policy}));

  scp::IncidentEvidence incident;
  incident.worst_active_severity = scp::Severity::None;
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::IncidentStateFabric, 16, generation, issued),
      scp::EvidenceKind::Incident, scp::EvidenceBody{incident}));

  scp::MaintenanceEvidence maintenance;
  maintenance.mode = scp::MaintenanceMode::None;
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::MaintenanceCoordinator, 17, generation, issued),
      scp::EvidenceKind::Maintenance, scp::EvidenceBody{maintenance}));

  scp::CapabilityEvidence asi;
  asi.readiness = scp::ReadinessLevel::Ready;
  asi.ready_domains = 8;
  asi.total_domains = 8;
  asi.ready_units = 512;
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::AsiRuntime, 18, generation, issued),
      scp::EvidenceKind::AsiCapability, scp::EvidenceBody{asi}));

  scp::CapabilityEvidence dfi;
  dfi.readiness = scp::ReadinessLevel::Ready;
  dfi.ready_domains = 4;
  dfi.total_domains = 4;
  dfi.ready_units = 256;
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::DfiRuntime, 19, generation, issued),
      scp::EvidenceKind::DfiCapability, scp::EvidenceBody{dfi}));

  scp::ServiceClassEvidence classes;
  classes.class_count = 1;
  const scp::Result<scp::Name> name = scp::Name::parse("batch-inference");
  if (name.has_value()) {
    scp::ServiceClassObligation obligation;
    obligation.service_class = name.value();
    obligation.protected_class = true;
    obligation.minimum_ready_units = 8;
    obligation.minimum_readiness_percent = 50;
    classes.obligations.push_back(obligation);
  }
  push(scp::EvidenceRecord::create(
      provenance(scp::SourceAuthority::ServiceClassRegistry, 20, generation, issued),
      scp::EvidenceKind::ServiceClass, scp::EvidenceBody{classes}));

  return records;
}

}  // namespace

int main(int argc, char** argv) {
  const std::filesystem::path directory =
      argc > 1 ? std::filesystem::path(argv[1]) : std::filesystem::path("downstream-site");

  std::cout << "scp " << scp::version_string() << " from the installed package\n";

  scp::SitePolicy policy;
  policy.generation = scp::PolicyGeneration::first();

  scp::RuntimeOptions options;
  options.site = site();
  options.policy = policy;
  options.instance = instance(99);
  options.epoch = scp::Epoch(1);
  options.directory = directory;
  // A clock pinned to the instant the evidence was issued at. Without it the
  // runtime judges freshness against the wall clock, and evidence dated in the
  // future is deliberately indeterminate rather than fresh, so the consumer
  // would be testing the calendar instead of the package.
  options.clock = std::make_shared<scp::ManualClock>(at(0));

  const scp::Timestamp now = at(0);
  std::string error;
  const std::vector<scp::EvidenceRecord> records = healthy(now, 1, error);
  if (!error.empty()) {
    return fail("building evidence failed: " + error);
  }

  {
    scp::Result<std::unique_ptr<scp::SiteControlPlane>> runtime =
        scp::SiteControlPlane::open(options);
    if (!runtime.has_value()) {
      return fail("open failed: " + runtime.status().to_string());
    }
    const scp::Status ingested = runtime.value()->ingest(records);
    if (!ingested.ok()) {
      return fail("ingest failed: " + ingested.to_string());
    }
    scp::CommitOptions commit;
    commit.now = now;
    const scp::Result<scp::CommitOutcome> outcome = runtime.value()->commit(commit);
    if (!outcome.has_value()) {
      return fail("commit failed: " + outcome.status().to_string());
    }
    std::cout << "committed generation " << outcome.value().site_generation.value() << " state "
              << scp::to_string(outcome.value().state) << " operations "
              << outcome.value().operations << " journal sequence "
              << outcome.value().journal_sequence.value() << "\n";
    if (outcome.value().state != scp::SiteState::Available) {
      return fail("the site did not reach available");
    }

    scp::PlanRequest request;
    request.intent = scp::PlanIntent::AcceptObligation;
    request.principal = scp::Name::parse("downstream").value();
    request.service_class = scp::Name::parse("batch-inference").value();
    request.now = now;
    const scp::Result<scp::ActionPlan> plan = runtime.value()->plan(request);
    if (!plan.has_value()) {
      return fail("plan failed: " + plan.status().to_string());
    }
    std::cout << "plan permitted=" << (plan.value().permitted ? "yes" : "no")
              << " requests=" << plan.value().request_count() << " digest "
              << plan.value().plan_digest.to_hex().substr(0, 16) << "...\n";

    const scp::Result<scp::ExplainReport> explanation = runtime.value()->explain(now);
    if (!explanation.has_value()) {
      return fail("explain failed: " + explanation.status().to_string());
    }
    std::cout << "explanation lines " << scp::render_explanation(explanation.value()).size()
              << " gates " << explanation.value().gates.size() << "\n";
    const scp::Status closed = runtime.value()->close();
    if (!closed.ok()) {
      return fail("close failed: " + closed.to_string());
    }
  }

  {
    // Reopen from the same directory: the durable state must survive.
    scp::Result<std::unique_ptr<scp::SiteControlPlane>> runtime =
        scp::SiteControlPlane::open(options);
    if (!runtime.has_value()) {
      return fail("reopen failed: " + runtime.status().to_string());
    }
    const scp::RuntimeStatus status = runtime.value()->status();
    std::cout << "reopened generation " << status.site_generation.value() << " state "
              << scp::to_string(status.state) << " evidence " << status.accepted_evidence
              << " recovered " << (status.recovered ? "yes" : "no") << "\n";
    if (!status.recovered || status.accepted_evidence != records.size()) {
      return fail("the durable state did not survive the reopen");
    }
    if (status.state != scp::SiteState::Available) {
      return fail("the reopened site is not available");
    }
    const scp::Status closed = runtime.value()->close();
    if (!closed.ok()) {
      return fail("close failed: " + closed.to_string());
    }
  }

  std::cout << "downstream consumer ok\n";
  return 0;
}
