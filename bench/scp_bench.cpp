// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

// Benchmarks of completed core operations.
//
// Two things are measured and reported separately because they cost different
// things and are claimed differently:
//
//   * the pure decision path - reduction, composition and gate evaluation over a
//     synthetic but complete site evidence set. These operations have no I/O and
//     their cost is the engine's;
//   * the durable commit path - the two-phase prepare/commit write with a device
//     flush and a read-back verification. This is the cost of durability, and it
//     is reported with the durability boundary it actually crossed.
//
// Every number printed here was measured in this process on this host. Nothing
// is estimated, extrapolated or carried over. Run it with --repeats to widen the
// sample, and --records to change the size of the synthetic evidence set.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "scp/composition.hpp"
#include "scp/ids.hpp"
#include "scp/plan.hpp"
#include "scp/policy.hpp"
#include "scp/readiness.hpp"
#include "scp/runtime.hpp"
#include "scp/version.hpp"

namespace {

using Clock = std::chrono::steady_clock;

struct Sample {
  std::string label;
  std::uint64_t iterations = 0;
  std::uint64_t total_nanos = 0;
  std::uint64_t min_nanos = 0;
  std::uint64_t max_nanos = 0;
  std::string note;
};

std::uint64_t nanos_of(Clock::duration value) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(value).count());
}

/// A deterministic identity source so two runs of the benchmark build exactly
/// the same synthetic site.
class Synthetic {
 public:
  explicit Synthetic(std::uint64_t seed) : state_(seed | 1ULL) {}

  std::uint64_t next() {
    state_ += 0x9E3779B97F4A7C15ULL;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31U);
  }

 private:
  std::uint64_t state_;
};

scp::Timestamp base_instant() { return scp::Timestamp{1767225600000000000LL}; }

scp::Provenance provenance(scp::SourceAuthority authority, std::uint64_t instance,
                           std::uint64_t generation, std::uint64_t sequence,
                           scp::Timestamp issued) {
  scp::Provenance value;
  value.authority = authority;
  value.instance = scp::SourceInstanceId(0x1000000000000000ULL + instance, instance);
  value.epoch = scp::Epoch(1);
  value.generation = scp::SourceGeneration(generation);
  value.sequence = scp::Sequence(sequence);
  value.issued_at = issued;
  return value;
}

/// Builds a complete, healthy site evidence set. \p shards multiplies the number
/// of publications per domain, which is how the benchmark scales the evidence
/// set while keeping every logical slot filled and consistent.
std::vector<scp::EvidenceRecord> synthetic_site(std::uint64_t generation, std::uint64_t shards,
                                               scp::Timestamp issued) {
  std::vector<scp::EvidenceRecord> records;
  const auto add = [&records](const scp::Result<scp::EvidenceRecord>& record) {
    if (record.has_value()) {
      records.push_back(record.value());
    }
  };

  for (std::uint64_t shard = 0; shard < shards; ++shard) {
    const std::uint64_t sequence = shard + 1;

    scp::FacilityStateEvidence facility;
    facility.generation = scp::FacilityStateGeneration(generation);
    facility.active_incidents = 0;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::FacilityStateLedger, 11, generation, sequence, issued),
        scp::EvidenceKind::FacilityState, scp::EvidenceBody{facility}));

    scp::LifecycleEvidence lifecycle;
    lifecycle.state = scp::LifecycleState::Active;
    lifecycle.entered_at = issued;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::FacilityStateLedger, 11, generation, sequence, issued),
        scp::EvidenceKind::Lifecycle, scp::EvidenceBody{lifecycle}));

    scp::CapacityEvidence capacity;
    capacity.snapshot = scp::SnapshotId(0xC0FFEE0000000000ULL + shard, shard + 1);
    capacity.generation = scp::CapacityGeneration(generation);
    capacity.total_units = 4096;
    capacity.committed_units = 1024;
    capacity.available_units = 3072;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::FacilityCapacity, 12, generation, sequence, issued),
        scp::EvidenceKind::Capacity, scp::EvidenceBody{capacity}));

    scp::ReadinessEvidence power;
    power.snapshot = scp::SnapshotId(0xBEEF000000000000ULL + shard, shard + 1);
    power.readiness = scp::ReadinessLevel::Ready;
    power.headroom_milli_kw = 12000000;
    power.available_domains = 4;
    power.required_domains = 4;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::PowerControlPlane, 13, generation, sequence, issued),
        scp::EvidenceKind::PowerReadiness, scp::EvidenceBody{power}));

    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::ThermalControlPlane, 14, generation, sequence, issued),
        scp::EvidenceKind::CoolingReadiness, scp::EvidenceBody{power}));

    scp::PolicyEvidence policy_evidence;
    policy_evidence.generation = scp::PolicyGeneration(generation);
    policy_evidence.rule_count = 16;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::FacilityPolicyEngine, 15, generation, sequence, issued),
        scp::EvidenceKind::Policy, scp::EvidenceBody{policy_evidence}));

    scp::IncidentEvidence incident;
    incident.active_incidents = 0;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::IncidentStateFabric, 16, generation, sequence, issued),
        scp::EvidenceKind::Incident, scp::EvidenceBody{incident}));

    scp::MaintenanceEvidence maintenance;
    maintenance.mode = scp::MaintenanceMode::None;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::MaintenanceCoordinator, 17, generation, sequence, issued),
        scp::EvidenceKind::Maintenance, scp::EvidenceBody{maintenance}));

    scp::CapabilityEvidence asi;
    asi.readiness = scp::ReadinessLevel::Ready;
    asi.ready_domains = 64;
    asi.total_domains = 64;
    asi.ready_units = 8192;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::AsiRuntime, 18, generation, sequence, issued),
        scp::EvidenceKind::AsiCapability, scp::EvidenceBody{asi}));

    scp::CapabilityEvidence dfi;
    dfi.readiness = scp::ReadinessLevel::Ready;
    dfi.ready_domains = 32;
    dfi.total_domains = 32;
    dfi.ready_units = 4096;
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::DfiRuntime, 19, generation, sequence, issued),
        scp::EvidenceKind::DfiCapability, scp::EvidenceBody{dfi}));

    scp::ServiceClassEvidence classes;
    classes.class_count = 4;
    for (int index = 0; index < 4; ++index) {
      const scp::Result<scp::Name> name =
          scp::Name::parse("service-class-" + std::to_string(index));
      if (!name.has_value()) {
        continue;
      }
      scp::ServiceClassObligation obligation;
      obligation.service_class = name.value();
      obligation.protected_class = index == 0;
      obligation.minimum_ready_units = 128;
      obligation.minimum_readiness_percent = 50;
      classes.obligations.push_back(obligation);
    }
    add(scp::EvidenceRecord::create(
        provenance(scp::SourceAuthority::ServiceClassRegistry, 20, generation, sequence, issued),
        scp::EvidenceKind::ServiceClass, scp::EvidenceBody{classes}));
  }
  return records;
}

scp::SiteId bench_site() { return scp::SiteId(0x5C7B0A4D00000001ULL, 1); }

scp::SitePolicy bench_policy() {
  scp::SitePolicy policy;
  policy.generation = scp::PolicyGeneration::first();
  policy.required_redundancy_domains = 2;
  return policy;
}

void report(const std::vector<Sample>& samples, const std::string& title) {
  std::cout << "\n" << title << "\n";
  std::cout << std::left << std::setw(40) << "operation" << std::right << std::setw(12)
            << "iterations" << std::setw(16) << "total (ms)" << std::setw(16) << "median (us)"
            << std::setw(14) << "min (us)" << std::setw(14) << "max (us)" << "\n";
  for (const Sample& sample : samples) {
    const double total_ms = static_cast<double>(sample.total_nanos) / 1.0e6;
    const double median_us =
        sample.iterations == 0
            ? 0.0
            : (static_cast<double>(sample.total_nanos) / static_cast<double>(sample.iterations)) /
                  1000.0;
    const double min_us = static_cast<double>(sample.min_nanos) / 1000.0;
    const double max_us = static_cast<double>(sample.max_nanos) / 1000.0;
    std::cout << std::left << std::setw(40) << sample.label << std::right << std::setw(12)
              << sample.iterations << std::setw(16) << std::fixed << std::setprecision(3)
              << total_ms << std::setw(16) << std::setprecision(3) << median_us << std::setw(14)
              << std::setprecision(3) << min_us << std::setw(14) << std::setprecision(3) << max_us
              << "\n";
    if (!sample.note.empty()) {
      std::cout << "    note: " << sample.note << "\n";
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t repeats = 3;
  std::uint64_t shards = 8;
  std::uint64_t durable_commits = 64;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    const auto value_of = [&argc, &argv, index]() -> std::uint64_t {
      if (index + 1 >= argc) {
        return 0;
      }
      return std::strtoull(argv[index + 1], nullptr, 10);
    };
    if (argument == "--repeats") {
      repeats = value_of();
    } else if (argument == "--shards") {
      shards = value_of();
    } else if (argument == "--durable-commits") {
      durable_commits = value_of();
    } else if (argument == "--help") {
      std::cout << "usage: scp_bench [--repeats n] [--shards n] [--durable-commits n]\n";
      return 0;
    }
  }
  if (repeats == 0 || shards == 0) {
    std::cerr << "scp_bench: repeats and shards must be at least 1\n";
    return 2;
  }

  const scp::Timestamp instant = base_instant();
  const std::vector<scp::EvidenceRecord> records = synthetic_site(1, shards, instant);
  const scp::SitePolicy policy = bench_policy();

  scp::CompositionOptions options;
  options.site = bench_site();
  options.site_generation = scp::SiteGeneration(1);
  options.evaluation_time = instant;
  options.policy = policy;

  std::cout << "Site Control Plane " << scp::version_string() << " benchmark\n";
  std::cout << "evidence records     : " << records.size() << " (" << shards
            << " shard(s) x 11 kinds)\n";
  std::cout << "repeats              : " << repeats << "\n";
  std::cout << "durable commits      : " << durable_commits << "\n";

  // Warm up so the first measured iteration is not paying for cold allocation.
  {
    const auto warm = scp::compose_site_state(records, options);
    if (!warm.has_value()) {
      std::cerr << "scp_bench: composition failed: " << warm.status().to_string() << "\n";
      return 1;
    }
  }

  std::vector<Sample> decision_samples;

  {
    Sample sample;
    sample.label = "reduce_evidence";
    for (std::uint64_t repeat = 0; repeat < repeats; ++repeat) {
      for (std::uint64_t iteration = 0; iteration < 20; ++iteration) {
        const auto start = Clock::now();
        const auto reduced = scp::reduce_evidence(records, policy, instant);
        const std::uint64_t elapsed = nanos_of(Clock::now() - start);
        if (!reduced.has_value()) {
          std::cerr << "scp_bench: reduction failed\n";
          return 1;
        }
        sample.iterations += 1;
        sample.total_nanos += elapsed;
        sample.min_nanos = sample.min_nanos == 0 ? elapsed : std::min(sample.min_nanos, elapsed);
        sample.max_nanos = std::max(sample.max_nanos, elapsed);
      }
    }
    sample.note = "pure reduction of the accepted evidence set, no I/O";
    decision_samples.push_back(sample);
  }

  {
    Sample sample;
    sample.label = "compose_site_state (recomposition)";
    for (std::uint64_t repeat = 0; repeat < repeats; ++repeat) {
      for (std::uint64_t iteration = 0; iteration < 20; ++iteration) {
        const auto start = Clock::now();
        const auto snapshot = scp::compose_site_state(records, options);
        const std::uint64_t elapsed = nanos_of(Clock::now() - start);
        if (!snapshot.has_value()) {
          std::cerr << "scp_bench: composition failed\n";
          return 1;
        }
        if (snapshot.value().state != scp::SiteState::Available) {
          std::cerr << "scp_bench: the synthetic site is not available\n";
          return 1;
        }
        sample.iterations += 1;
        sample.total_nanos += elapsed;
        sample.min_nanos = sample.min_nanos == 0 ? elapsed : std::min(sample.min_nanos, elapsed);
        sample.max_nanos = std::max(sample.max_nanos, elapsed);
      }
    }
    sample.note = "reduction + constraints + gates + canonical digest, no I/O";
    decision_samples.push_back(sample);
  }

  scp::SiteStateSnapshot snapshot;
  {
    const auto composed = scp::compose_site_state(records, options);
    if (!composed.has_value()) {
      std::cerr << "scp_bench: composition failed: " << composed.status().to_string() << "\n";
      return 1;
    }
    snapshot = composed.value();
  }

  {
    Sample sample;
    sample.label = "evaluate_all_gates";
    for (std::uint64_t repeat = 0; repeat < repeats; ++repeat) {
      for (std::uint64_t iteration = 0; iteration < 200; ++iteration) {
        const auto start = Clock::now();
        const auto gates = scp::evaluate_all_gates(snapshot, policy);
        const std::uint64_t elapsed = nanos_of(Clock::now() - start);
        if (!gates.has_value()) {
          std::cerr << "scp_bench: gate evaluation failed\n";
          return 1;
        }
        sample.iterations += 1;
        sample.total_nanos += elapsed;
        sample.min_nanos = sample.min_nanos == 0 ? elapsed : std::min(sample.min_nanos, elapsed);
        sample.max_nanos = std::max(sample.max_nanos, elapsed);
      }
    }
    sample.note = "all six readiness gates over the composed snapshot";
    decision_samples.push_back(sample);
  }

  {
    scp::DelegationGrant grant;
    grant.id = scp::GrantId(0x7100000000000001ULL, 1);
    grant.site = bench_site();
    grant.grantor = scp::Name::parse("facility-policy-engine").value();
    grant.subject = scp::Name::parse("site-control-plane").value();
    grant.scopes = scp::ScopeSet(0xFFFFU);
    grant.issued_at = instant;
    const std::vector<scp::DelegationGrant> grants = {grant};

    scp::PlanRequest request;
    request.intent = scp::PlanIntent::AcceptObligation;
    request.site = bench_site();
    request.site_generation = scp::SiteGeneration(1);
    request.principal = scp::Name::parse("benchmark").value();
    request.service_class = scp::Name::parse("service-class-0").value();
    request.now = instant;

    Sample sample;
    sample.label = "plan_intent (accept-obligation)";
    for (std::uint64_t repeat = 0; repeat < repeats; ++repeat) {
      for (std::uint64_t iteration = 0; iteration < 50; ++iteration) {
        const auto start = Clock::now();
        const auto plan =
            scp::plan_intent(request, snapshot, policy, std::span<const scp::DelegationGrant>(grants));
        const std::uint64_t elapsed = nanos_of(Clock::now() - start);
        if (!plan.has_value()) {
          std::cerr << "scp_bench: planning failed: " << plan.status().to_string() << "\n";
          return 1;
        }
        sample.iterations += 1;
        sample.total_nanos += elapsed;
        sample.min_nanos = sample.min_nanos == 0 ? elapsed : std::min(sample.min_nanos, elapsed);
        sample.max_nanos = std::max(sample.max_nanos, elapsed);
      }
    }
    sample.note = "authority validation + gate decision + typed effect requests, no I/O";
    decision_samples.push_back(sample);
  }

  report(decision_samples, "decision path (pure, no I/O)");

  // -------------------------------------------------------------------------
  // Durable cost, measured separately and with the boundary it crossed.
  // -------------------------------------------------------------------------
  std::error_code error;
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path(error) / "scp-bench-site";
  if (error) {
    std::cerr << "scp_bench: no temporary directory available\n";
    return 1;
  }
  std::filesystem::remove_all(directory, error);

  scp::RuntimeOptions runtime_options;
  runtime_options.site = bench_site();
  runtime_options.policy = policy;
  runtime_options.instance = scp::SourceInstanceId(0x9999000000000001ULL, 1);
  runtime_options.epoch = scp::Epoch(1);
  runtime_options.directory = directory;
  runtime_options.compaction_threshold_bytes = 1ULL << 40;  // compaction measured separately

  auto opened = scp::SiteControlPlane::open(runtime_options);
  if (!opened.has_value()) {
    std::cerr << "scp_bench: cannot open the durable runtime: " << opened.status().to_string()
              << "\n";
    return 1;
  }
  std::unique_ptr<scp::SiteControlPlane> runtime = std::move(opened.value());

  std::vector<Sample> durable_samples;
  Sample commit_sample;
  commit_sample.label = "durable commit (prepare+commit+sync)";
  Sample memory_sample;
  memory_sample.label = "in-memory commit (no durability)";

  std::uint64_t committed_bytes = 0;
  std::string boundary;
  for (std::uint64_t index = 0; index < durable_commits; ++index) {
    const scp::Status ingested = runtime->ingest(records);
    if (!ingested.ok() && ingested.code() != scp::StatusCode::AlreadyExists) {
      std::cerr << "scp_bench: ingest failed: " << ingested.to_string() << "\n";
      return 1;
    }
    scp::CommitOptions commit;
    commit.now = instant;
    commit.allow_compaction = false;
    const auto start = Clock::now();
    const auto outcome = runtime->commit(commit);
    const std::uint64_t elapsed = nanos_of(Clock::now() - start);
    if (!outcome.has_value()) {
      std::cerr << "scp_bench: commit failed: " << outcome.status().to_string() << "\n";
      return 1;
    }
    commit_sample.iterations += 1;
    commit_sample.total_nanos += elapsed;
    commit_sample.min_nanos = commit_sample.min_nanos == 0
                                  ? elapsed
                                  : std::min(commit_sample.min_nanos, elapsed);
    commit_sample.max_nanos = std::max(commit_sample.max_nanos, elapsed);
    committed_bytes = outcome.value().transaction_bytes;
    boundary = outcome.value().durability_boundary;
  }
  commit_sample.note = std::to_string(committed_bytes) +
                       " bytes per transaction; durability boundary: " + boundary;
  durable_samples.push_back(commit_sample);

  {
    std::filesystem::path memory_directory = directory;
    memory_directory += "-memory";
    scp::RuntimeOptions memory_options = runtime_options;
    memory_options.directory.clear();
    const auto memory_runtime = scp::SiteControlPlane::open(memory_options);
    if (!memory_runtime.has_value()) {
      std::cerr << "scp_bench: cannot open the in-memory runtime\n";
      return 1;
    }
    for (std::uint64_t index = 0; index < durable_commits; ++index) {
      const scp::Status ingested = memory_runtime.value()->ingest(records);
      if (!ingested.ok() && ingested.code() != scp::StatusCode::AlreadyExists) {
        std::cerr << "scp_bench: ingest failed\n";
        return 1;
      }
      scp::CommitOptions commit;
      commit.now = instant;
      const auto start = Clock::now();
      const auto outcome = memory_runtime.value()->commit(commit);
      const std::uint64_t elapsed = nanos_of(Clock::now() - start);
      if (!outcome.has_value()) {
        std::cerr << "scp_bench: in-memory commit failed\n";
        return 1;
      }
      memory_sample.iterations += 1;
      memory_sample.total_nanos += elapsed;
      memory_sample.min_nanos = memory_sample.min_nanos == 0
                                    ? elapsed
                                    : std::min(memory_sample.min_nanos, elapsed);
      memory_sample.max_nanos = std::max(memory_sample.max_nanos, elapsed);
    }
    memory_sample.note = "same composition work, no durable boundary crossed";
    durable_samples.push_back(memory_sample);
    const scp::Status closed = memory_runtime.value()->close();
    (void)closed;
  }

  {
    Sample sample;
    sample.label = "reopen and recover";
    for (std::uint64_t iteration = 0; iteration < 10; ++iteration) {
      const scp::Status closed = runtime->close();
      if (!closed.ok()) {
        std::cerr << "scp_bench: close failed: " << closed.to_string() << "\n";
        return 1;
      }
      const auto start = Clock::now();
      auto reopened = scp::SiteControlPlane::open(runtime_options);
      const std::uint64_t elapsed = nanos_of(Clock::now() - start);
      if (!reopened.has_value()) {
        std::cerr << "scp_bench: reopen failed: " << reopened.status().to_string() << "\n";
        return 1;
      }
      sample.iterations += 1;
      sample.total_nanos += elapsed;
      sample.min_nanos = sample.min_nanos == 0 ? elapsed : std::min(sample.min_nanos, elapsed);
      sample.max_nanos = std::max(sample.max_nanos, elapsed);
      // Put the runtime back so the next iteration measures the same thing.
      if (!reopened.value()->status().recovered) {
        std::cerr << "scp_bench: reopen did not recover\n";
        return 1;
      }
      runtime = std::move(reopened.value());
    }
    sample.note = "open + journal replay + snapshot load; one close per iteration";
    durable_samples.push_back(sample);
  }

  report(durable_samples, "durable path (real file, real flush)");

  const scp::Status closed = runtime->close();
  if (!closed.ok()) {
    std::cerr << "scp_bench: close failed: " << closed.to_string() << "\n";
    return 1;
  }

  std::error_code cleanup_error;
  std::filesystem::remove_all(directory, cleanup_error);
  std::filesystem::remove_all(std::filesystem::path(directory) += "-memory", cleanup_error);
  std::cout << "\nAll figures above were measured in this process on this host.\n";
  return 0;
}
