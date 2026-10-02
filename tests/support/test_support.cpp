// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "test_support.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <system_error>
#include <utility>

namespace scp_test {
namespace {

std::uint64_t next_serial() {
  static std::uint64_t serial = 0;
  ++serial;
  return serial;
}

}  // namespace

Context& Context::instance() {
  static Context context;
  return context;
}

void Context::add_case(const std::string& name, std::function<void()> body) {
  cases_.push_back(Case{name, std::move(body)});
}

void Context::check(bool condition, const char* expression, const char* file, int line) {
  ++checks_;
  if (condition) {
    return;
  }
  ++failures_;
  Failure failure;
  failure.location = std::string(file) + ":" + std::to_string(line);
  failure.message = expression;
  current_failures_.push_back(std::move(failure));
}

bool Context::require(bool condition, const char* expression, const char* file, int line) {
  check(condition, expression, file, line);
  return condition;
}

void Context::note(const std::string& message) {
  Failure failure;
  failure.location = current_case_;
  failure.message = "note: " + message;
  current_failures_.push_back(std::move(failure));
}

int Context::run_all(const char* suite) {
  std::cout << "== " << suite << " ==" << std::endl;
  std::uint64_t case_failures = 0;
  for (const Case& test_case : cases_) {
    current_case_ = test_case.name;
    current_failures_.clear();
    test_case.body();
    if (current_failures_.empty()) {
      std::cout << "  ok   " << test_case.name << std::endl;
      continue;
    }
    ++case_failures;
    std::cout << "  FAIL " << test_case.name << std::endl;
    for (const Failure& failure : current_failures_) {
      std::cout << "       " << failure.location << ": " << failure.message << std::endl;
    }
  }
  std::cout << suite << ": " << cases_.size() << " case(s), " << checks_ << " check(s), "
            << failures_ << " failure(s)\n";
  if (case_failures != 0) {
    return 1;
  }
  return 0;
}

Registrar::Registrar(const char* name, std::function<void()> body) {
  Context::instance().add_case(name, std::move(body));
}

TempDirectory::TempDirectory(const std::string& label) {
  std::error_code error;
  const std::filesystem::path base = std::filesystem::temp_directory_path(error);
  const std::filesystem::path root =
      error ? std::filesystem::path(".") : base;
  for (int attempt = 0; attempt < 64; ++attempt) {
    const std::string name = "scp-test-" + label + "-" + std::to_string(next_serial());
    const std::filesystem::path candidate = root / name;
    if (std::filesystem::create_directories(candidate, error) && !error) {
      path_ = candidate;
      return;
    }
    error.clear();
  }
  // Falling back to a path we could not create would make every later check
  // meaningless, so this is deliberately fatal.
  std::cerr << "cannot create a temporary directory for the test suite\n";
  std::abort();
}

TempDirectory::~TempDirectory() {
  if (path_.empty()) {
    return;
  }
  std::error_code error;
  std::filesystem::remove_all(path_, error);
  (void)error;
}

std::filesystem::path TempDirectory::child(const std::string& name) const {
  return path_ / name;
}

bool copy_tree(const std::filesystem::path& from, const std::filesystem::path& to) {
  std::error_code error;
  if (!std::filesystem::create_directories(to, error) || error) {
    return false;
  }
  std::filesystem::copy(from, to,
                        std::filesystem::copy_options::recursive |
                            std::filesystem::copy_options::overwrite_existing,
                        error);
  return !error;
}

std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(stream),
                                   std::istreambuf_iterator<char>());
}

bool poke_byte(const std::filesystem::path& path, std::uint64_t offset, std::uint8_t value) {
  std::fstream stream(path, std::ios::binary | std::ios::in | std::ios::out);
  if (!stream) {
    return false;
  }
  stream.seekp(static_cast<std::streamoff>(offset));
  stream.put(static_cast<char>(value));
  stream.flush();
  return stream.good();
}

bool truncate_file(const std::filesystem::path& path, std::uint64_t size) {
  std::error_code error;
  std::filesystem::resize_file(path, size, error);
  return !error;
}

SiteId default_site() { return SiteId(0x51E7C0DE00000001ULL, 0x0000000000000001ULL); }

SourceInstanceId instance_for(std::uint64_t seed) {
  return SourceInstanceId(0x1A2B3C4D00000000ULL + seed, 0x00000000000000FFULL - seed);
}

Timestamp base_instant() { return Timestamp{1767225600000000000LL}; }

Timestamp instant_after(std::int64_t seconds) {
  return Timestamp{base_instant().nanos + seconds * kNanosPerSecond};
}

Result<EvidenceRecord> make_record(const RecordSpec& spec, EvidenceKind kind,
                                   const EvidenceBody& body) {
  Provenance provenance;
  provenance.authority = spec.authority;
  provenance.instance = instance_for(spec.instance);
  provenance.epoch = Epoch(spec.epoch);
  provenance.generation = SourceGeneration(spec.generation);
  provenance.sequence = Sequence(spec.sequence);
  provenance.issued_at = spec.issued_at.is_set() ? spec.issued_at : base_instant();
  provenance.valid_until = spec.valid_until;
  Result<EvidenceRecord> record = EvidenceRecord::create(provenance, kind, body);
  if (!record.has_value()) {
    return record.status();
  }
  record.value().origin = spec.origin;
  return record.value();
}

#define SCP_DEFINE_MAKER(name, kind_value, type)                                       \
  Result<EvidenceRecord> name(const RecordSpec& spec, type body) {                     \
    return make_record(spec, kind_value, EvidenceBody{body});                          \
  }

SCP_DEFINE_MAKER(make_facility_state, EvidenceKind::FacilityState, FacilityStateEvidence)
SCP_DEFINE_MAKER(make_lifecycle, EvidenceKind::Lifecycle, LifecycleEvidence)
SCP_DEFINE_MAKER(make_capacity, EvidenceKind::Capacity, CapacityEvidence)
SCP_DEFINE_MAKER(make_power, EvidenceKind::PowerReadiness, ReadinessEvidence)
SCP_DEFINE_MAKER(make_cooling, EvidenceKind::CoolingReadiness, ReadinessEvidence)
SCP_DEFINE_MAKER(make_policy, EvidenceKind::Policy, PolicyEvidence)
SCP_DEFINE_MAKER(make_incident, EvidenceKind::Incident, IncidentEvidence)
SCP_DEFINE_MAKER(make_maintenance, EvidenceKind::Maintenance, MaintenanceEvidence)
SCP_DEFINE_MAKER(make_asi, EvidenceKind::AsiCapability, CapabilityEvidence)
SCP_DEFINE_MAKER(make_dfi, EvidenceKind::DfiCapability, CapabilityEvidence)
SCP_DEFINE_MAKER(make_service_class, EvidenceKind::ServiceClass, ServiceClassEvidence)

#undef SCP_DEFINE_MAKER

std::vector<EvidenceRecord> healthy_site_records(Timestamp issued_at, std::uint64_t generation) {
  std::vector<EvidenceRecord> records;

  const auto push = [&records](Result<EvidenceRecord> record) {
    if (record.has_value()) {
      records.push_back(record.value());
    }
  };

  RecordSpec spec;
  spec.issued_at = issued_at;
  spec.generation = generation;

  spec.authority = SourceAuthority::FacilityStateLedger;
  spec.instance = 11;
  FacilityStateEvidence facility;
  facility.generation = FacilityStateGeneration(generation);
  facility.worst_active_severity = Severity::None;
  facility.active_incidents = 0;
  facility.degraded_operation = false;
  facility.emergency_declared = false;
  push(make_facility_state(spec, facility));

  LifecycleEvidence lifecycle;
  lifecycle.state = LifecycleState::Active;
  lifecycle.entered_at = issued_at;
  lifecycle.transition_in_progress = false;
  push(make_lifecycle(spec, lifecycle));

  spec.authority = SourceAuthority::FacilityCapacity;
  spec.instance = 12;
  CapacityEvidence capacity;
  capacity.snapshot = SnapshotId(0xC0FFEE0000000001ULL, 0x0000000000000001ULL);
  capacity.generation = CapacityGeneration(generation);
  capacity.total_units = 100;
  capacity.committed_units = 40;
  capacity.available_units = 60;
  capacity.oversubscribed = false;
  push(make_capacity(spec, capacity));

  spec.authority = SourceAuthority::PowerControlPlane;
  spec.instance = 13;
  ReadinessEvidence power;
  power.snapshot = SnapshotId(0xC0FFEE0000000002ULL, 0x0000000000000002ULL);
  power.readiness = ReadinessLevel::Ready;
  power.headroom_milli_kw = 5000000;
  power.available_domains = 2;
  power.required_domains = 2;
  push(make_power(spec, power));

  spec.authority = SourceAuthority::ThermalControlPlane;
  spec.instance = 14;
  ReadinessEvidence cooling;
  cooling.snapshot = SnapshotId(0xC0FFEE0000000003ULL, 0x0000000000000003ULL);
  cooling.readiness = ReadinessLevel::Ready;
  cooling.headroom_milli_kw = 4000000;
  cooling.available_domains = 2;
  cooling.required_domains = 2;
  push(make_cooling(spec, cooling));

  spec.authority = SourceAuthority::FacilityPolicyEngine;
  spec.instance = 15;
  PolicyEvidence policy;
  policy.generation = PolicyGeneration(generation);
  policy.rule_count = 4;
  push(make_policy(spec, policy));

  spec.authority = SourceAuthority::IncidentStateFabric;
  spec.instance = 16;
  IncidentEvidence incident;
  incident.active_incidents = 0;
  incident.worst_active_severity = Severity::None;
  incident.emergency_declared = false;
  push(make_incident(spec, incident));

  spec.authority = SourceAuthority::MaintenanceCoordinator;
  spec.instance = 17;
  MaintenanceEvidence maintenance;
  maintenance.mode = MaintenanceMode::None;
  maintenance.active_windows = 0;
  maintenance.scheduled_windows = 0;
  maintenance.drain_in_progress = false;
  maintenance.drained_percent = 0;
  push(make_maintenance(spec, maintenance));

  spec.authority = SourceAuthority::AsiRuntime;
  spec.instance = 18;
  CapabilityEvidence asi;
  asi.readiness = ReadinessLevel::Ready;
  asi.ready_domains = 8;
  asi.total_domains = 8;
  asi.ready_units = 512;
  push(make_asi(spec, asi));

  spec.authority = SourceAuthority::DfiRuntime;
  spec.instance = 19;
  CapabilityEvidence dfi;
  dfi.readiness = ReadinessLevel::Ready;
  dfi.ready_domains = 4;
  dfi.total_domains = 4;
  dfi.ready_units = 256;
  push(make_dfi(spec, dfi));

  spec.authority = SourceAuthority::ServiceClassRegistry;
  spec.instance = 20;
  ServiceClassEvidence classes;
  classes.class_count = 1;
  const Result<Name> service_class = Name::parse("interactive-inference");
  if (service_class.has_value()) {
    ServiceClassObligation obligation;
    obligation.service_class = service_class.value();
    obligation.protected_class = true;
    obligation.minimum_ready_units = 16;
    obligation.minimum_readiness_percent = 50;
    classes.obligations.push_back(obligation);
  }
  push(make_service_class(spec, classes));

  return records;
}

SitePolicy strict_policy() {
  SitePolicy policy;
  policy.generation = PolicyGeneration::first();
  policy.freshness.stale_after = seconds(900);
  policy.freshness.expire_after = seconds(3600);
  policy.capacity_headroom_constrained_percent = 10;
  policy.capacity_headroom_degraded_percent = 3;
  policy.domain_readiness_degraded_percent = 75;
  policy.domain_readiness_unavailable_percent = 25;
  policy.required_redundancy_domains = 2;
  policy.require_complete_evidence_for_new_obligations = true;
  policy.require_fresh_evidence_for_new_obligations = true;
  policy.require_unconflicted_evidence_for_new_obligations = true;
  policy.require_power_ready_for_new_obligations = true;
  policy.require_cooling_ready_for_new_obligations = true;
  policy.require_asi_ready_for_new_obligations = true;
  policy.require_dfi_ready_for_new_obligations = true;
  policy.return_to_service_minimum_readiness_percent = 90;
  return policy;
}

SitePolicy policy_with_generation(std::uint64_t generation) {
  SitePolicy policy = strict_policy();
  policy.generation = PolicyGeneration(generation);
  return policy;
}

RuntimeOptions memory_runtime_options(std::uint64_t policy_generation) {
  RuntimeOptions options;
  options.site = default_site();
  options.policy = policy_with_generation(policy_generation);
  options.instance = instance_for(99);
  options.epoch = Epoch(1);
  options.clock = std::make_shared<ManualClock>(base_instant());
  return options;
}

RuntimeOptions durable_runtime_options(const std::filesystem::path& directory,
                                       std::uint64_t policy_generation) {
  RuntimeOptions options = memory_runtime_options(policy_generation);
  options.directory = directory;
  return options;
}

std::unique_ptr<SiteControlPlane> open_runtime(const RuntimeOptions& options, const char* file,
                                               int line) {
  Result<std::unique_ptr<SiteControlPlane>> runtime = SiteControlPlane::open(options);
  if (!runtime.has_value()) {
    Context::instance().note(std::string("SiteControlPlane::open failed: ") +
                             runtime.status().to_string());
    Context::instance().check(false, "runtime opens", file, line);
    return nullptr;
  }
  return std::move(runtime.value());
}

}  // namespace scp_test
