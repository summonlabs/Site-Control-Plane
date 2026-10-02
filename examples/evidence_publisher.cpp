// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

/// \file evidence_publisher.cpp
/// One valid evidence record for every evidence kind, each built by the runtime
/// that owns the fact, and the identity properties the evidence layer promises:
/// the same logical fact published twice derives exactly the same identity, and
/// a different generation derives a different one. The program closes by showing
/// that a runtime which does not own a kind is refused with Unauthorized.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/runtime.hpp"
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
      std::filesystem::path candidate = base / ("scp-evidence-publisher-" + std::to_string(stamp));
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

/// The instant every publication in this program is issued at.
constexpr std::int64_t kIssuedAtNanos = 1700000000000000000LL;

[[nodiscard]] std::string pad(std::string_view text, std::size_t width) {
  std::string out(text);
  while (out.size() < width) {
    out.push_back(' ');
  }
  return out;
}

[[nodiscard]] scp::Digest digest_of(std::string_view text) {
  scp::Sha256 hasher;
  hasher.update(text);
  return hasher.finalize();
}

/// A representative body for each kind: the values a real publisher of that fact
/// would state, so the record is a valid instance of its schema.
[[nodiscard]] scp::EvidenceBody body_for(scp::EvidenceKind kind, scp::Timestamp issued_at) {
  switch (kind) {
    case scp::EvidenceKind::FacilityState: {
      scp::FacilityStateEvidence value;
      value.generation = scp::FacilityStateGeneration(7);
      value.worst_active_severity = scp::Severity::None;
      value.active_incidents = 0;
      value.degraded_operation = false;
      value.emergency_declared = false;
      value.topology_digest = digest_of("facility-topology-7");
      return value;
    }
    case scp::EvidenceKind::Lifecycle: {
      scp::LifecycleEvidence value;
      value.state = scp::LifecycleState::Active;
      value.entered_at = issued_at;
      value.transition_in_progress = false;
      value.transition_digest = digest_of("lifecycle-active");
      return value;
    }
    case scp::EvidenceKind::Capacity: {
      scp::CapacityEvidence value;
      value.snapshot = scp::SnapshotId(0x0123456789abcdefULL, 0xfedcba9876543210ULL);
      value.generation = scp::CapacityGeneration(3);
      value.total_units = 1000;
      value.committed_units = 250;
      value.available_units = 750;
      value.oversubscribed = false;
      return value;
    }
    case scp::EvidenceKind::PowerReadiness: {
      scp::ReadinessEvidence value;
      value.snapshot = scp::SnapshotId(0x1111222233334444ULL, 0x5555666677778888ULL);
      value.readiness = scp::ReadinessLevel::Ready;
      value.headroom_milli_kw = 4200;
      value.available_domains = 2;
      value.required_domains = 2;
      return value;
    }
    case scp::EvidenceKind::CoolingReadiness: {
      scp::ReadinessEvidence value;
      value.snapshot = scp::SnapshotId(0x9999aaaabbbbccccULL, 0xddddeeeeffff0000ULL);
      value.readiness = scp::ReadinessLevel::Constrained;
      value.headroom_milli_kw = 900;
      value.available_domains = 2;
      value.required_domains = 2;
      return value;
    }
    case scp::EvidenceKind::Policy: {
      scp::PolicyEvidence value;
      value.generation = scp::PolicyGeneration(5);
      value.rules_digest = digest_of("policy-rules-5");
      value.rule_count = 12;
      return value;
    }
    case scp::EvidenceKind::Incident: {
      scp::IncidentEvidence value;
      value.active_incidents = 1;
      value.worst_active_severity = scp::Severity::Minor;
      value.emergency_declared = false;
      value.earliest_active = issued_at;
      value.suppressed_incidents = 0;
      return value;
    }
    case scp::EvidenceKind::Maintenance: {
      scp::MaintenanceEvidence value;
      value.mode = scp::MaintenanceMode::Planned;
      value.active_windows = 0;
      value.scheduled_windows = 2;
      value.next_window_start = scp::Timestamp{kIssuedAtNanos + 3600000000000LL};
      value.drain_in_progress = false;
      value.drained_percent = 0;
      return value;
    }
    case scp::EvidenceKind::AsiCapability: {
      scp::CapabilityEvidence value;
      value.readiness = scp::ReadinessLevel::Ready;
      value.ready_domains = 4;
      value.total_domains = 4;
      value.ready_units = 64;
      value.capability_digest = digest_of("asi-capability");
      return value;
    }
    case scp::EvidenceKind::DfiCapability: {
      scp::CapabilityEvidence value;
      value.readiness = scp::ReadinessLevel::Degraded;
      value.ready_domains = 3;
      value.total_domains = 4;
      value.ready_units = 96;
      value.capability_digest = digest_of("dfi-capability");
      return value;
    }
    case scp::EvidenceKind::ServiceClass: {
      scp::ServiceClassEvidence value;
      value.class_count = 1;
      value.obligations_digest = digest_of("service-classes");
      scp::ServiceClassObligation obligation;
      obligation.service_class = scp::Name::parse("gold").value();
      obligation.protected_class = true;
      obligation.minimum_ready_units = 100;
      obligation.minimum_readiness_percent = 90;
      value.obligations.push_back(obligation);
      return value;
    }
  }
  return scp::FacilityStateEvidence{};
}

/// Builds one record as the runtime that owns the kind would publish it.
[[nodiscard]] scp::Result<scp::EvidenceRecord> publish(scp::EvidenceKind kind,
                                                       scp::SourceInstanceId instance,
                                                       scp::SourceGeneration generation,
                                                       scp::Timestamp issued_at) {
  scp::Provenance provenance;
  provenance.authority = scp::owner_of(kind);
  provenance.instance = instance;
  provenance.epoch = scp::Epoch(1);
  provenance.generation = generation;
  provenance.sequence = scp::Sequence(1);
  provenance.issued_at = issued_at;
  return scp::EvidenceRecord::create(provenance, kind, body_for(kind, issued_at));
}

[[nodiscard]] scp::EvidenceKind kind_at(std::uint16_t ordinal) {
  return static_cast<scp::EvidenceKind>(ordinal);
}

}  // namespace

int main() {
  const scp::Timestamp issued_at{kIssuedAtNanos};
  scp::DeterministicIdSource identities(0x5ca1ab1e5ca1ab1eULL);
  const scp::SiteId site = identities.next_site();

  struct Row {
    scp::EvidenceKind kind;
    scp::SourceAuthority authority;
    scp::EvidenceRecord record;
  };
  std::vector<Row> rows;
  rows.reserve(scp::kEvidenceKindCount);
  for (std::uint16_t ordinal = 1; ordinal <= static_cast<std::uint16_t>(scp::kEvidenceKindCount);
       ++ordinal) {
    const scp::EvidenceKind kind = kind_at(ordinal);
    const scp::Result<scp::EvidenceRecord> record =
        publish(kind, identities.next_instance(), scp::SourceGeneration(1), issued_at);
    if (!record.has_value()) {
      std::cerr << "evidence_publisher: " << record.status().to_string() << '\n';
      return 1;
    }
    rows.push_back(Row{kind, scp::owner_of(kind), record.value()});
  }

  std::cout << "one publication per evidence kind, built by the runtime that owns it\n";
  std::cout << pad("kind", 20) << pad("authority", 26) << pad("evidence id", 34)
            << pad("body digest", 66) << "body bytes\n";
  for (const Row& row : rows) {
    std::cout << pad(scp::to_string(row.kind), 20) << pad(scp::to_string(row.authority), 26)
              << pad(row.record.id.to_hex(), 34) << pad(row.record.provenance.body_digest.to_hex(), 66)
              << row.record.body.size() << '\n';
  }
  std::cout << '\n';

  // 1. The same logical fact, published twice, is the same record.
  const scp::Result<scp::EvidenceRecord> again =
      publish(scp::EvidenceKind::Capacity, rows[2].record.provenance.instance,
              scp::SourceGeneration(1), issued_at);
  if (!again.has_value()) {
    std::cerr << "evidence_publisher: " << again.status().to_string() << '\n';
    return 1;
  }
  const bool same_identity = again.value().id == rows[2].record.id;
  const bool same_body_digest =
      again.value().provenance.body_digest == rows[2].record.provenance.body_digest;
  const bool same_canonical_bytes = again.value().canonical_bytes() == rows[2].record.canonical_bytes();
  std::cout << "the same logical fact published twice\n";
  std::cout << "  capacity generation 1 first  id " << rows[2].record.id.to_hex() << '\n';
  std::cout << "  capacity generation 1 second id " << again.value().id.to_hex() << '\n';
  std::cout << "  identical-identity " << (same_identity ? "true" : "false") << '\n';
  std::cout << "  identical-body-digest " << (same_body_digest ? "true" : "false") << '\n';
  std::cout << "  identical-canonical-bytes " << (same_canonical_bytes ? "true" : "false") << '\n';

  // 2. A different generation is a different fact.
  const scp::Result<scp::EvidenceRecord> newer =
      publish(scp::EvidenceKind::Capacity, rows[2].record.provenance.instance,
              scp::SourceGeneration(2), issued_at);
  if (!newer.has_value()) {
    std::cerr << "evidence_publisher: " << newer.status().to_string() << '\n';
    return 1;
  }
  std::cout << "\na different generation\n";
  std::cout << "  capacity generation 1 id " << rows[2].record.id.to_hex() << '\n';
  std::cout << "  capacity generation 2 id " << newer.value().id.to_hex() << '\n';
  std::cout << "  different-identity " << (newer.value().id == rows[2].record.id ? "false" : "true")
            << '\n';

  // 3. A runtime that does not own a kind is refused with Unauthorized.
  std::cout << "\na runtime that does not own a kind\n";
  scp::Provenance wrong;
  wrong.authority = scp::SourceAuthority::ThermalControlPlane;
  wrong.instance = rows[2].record.provenance.instance;
  wrong.epoch = scp::Epoch(1);
  wrong.generation = scp::SourceGeneration(1);
  wrong.sequence = scp::Sequence(1);
  wrong.issued_at = issued_at;
  const scp::Result<scp::EvidenceRecord> refused =
      scp::EvidenceRecord::create(wrong, scp::EvidenceKind::Capacity, body_for(scp::EvidenceKind::Capacity, issued_at));
  if (refused.has_value()) {
    std::cerr << "evidence_publisher: a non-owner built a record; the schema was not enforced\n";
    return 1;
  }
  std::cout << "  build by thermal-control-plane: " << refused.status().to_string() << '\n';
  std::cout << "  status code " << scp::to_string(refused.status().code()) << '\n';

  // The same refusal reaches a runtime when a record's provenance claims an
  // authority that does not own the kind.
  TempDirectory directory;
  if (!directory.ready()) {
    std::cerr << "evidence_publisher: cannot create a temporary directory\n";
    return 1;
  }
  scp::RuntimeOptions options;
  options.directory = directory.path();
  options.site = site;
  options.clock = std::make_shared<scp::ManualClock>(issued_at);
  scp::Result<std::unique_ptr<scp::SiteControlPlane>> runtime = scp::SiteControlPlane::open(options);
  if (!runtime.has_value()) {
    std::cerr << "evidence_publisher: " << runtime.status().to_string() << '\n';
    return 1;
  }
  scp::EvidenceRecord impostor = rows[2].record;
  impostor.provenance.authority = scp::SourceAuthority::ThermalControlPlane;
  const scp::Status ingest_status = runtime.value()->ingest(impostor);
  std::cout << "  ingest by thermal-control-plane: " << ingest_status.to_string() << '\n';
  std::cout << "  status code " << scp::to_string(ingest_status.code()) << '\n';

  for (const Row& row : rows) {
    const scp::Status status = runtime.value()->ingest(row.record);
    if (!status.ok()) {
      std::cerr << "evidence_publisher: " << scp::to_string(row.kind) << ": " << status.to_string()
                << '\n';
      return 1;
    }
  }
  const scp::Result<scp::CommitOutcome> commit =
      runtime.value()->commit(scp::CommitOptions{issued_at, true, true});
  if (!commit.has_value()) {
    std::cerr << "evidence_publisher: " << commit.status().to_string() << '\n';
    return 1;
  }
  const scp::RuntimeStatus status = runtime.value()->status();
  std::cout << "\nthe owner of each kind publishes its own fact\n";
  std::cout << "  accepted-evidence " << status.accepted_evidence << '\n';
  std::cout << "  site-generation " << commit.value().site_generation.value() << '\n';
  std::cout << "  state " << scp::to_string(commit.value().state) << '\n';
  std::cout << "  classification " << scp::to_string(commit.value().classification) << '\n';
  std::cout << "  rejected-ingests " << status.rejected_ingests << '\n';
  const scp::Status closed = runtime.value()->close();
  if (!closed.ok()) {
    std::cerr << "evidence_publisher: " << closed.to_string() << '\n';
    return 1;
  }
  std::cout << "\ntemporary directory removed on exit: " << scp::escape_for_display(directory.path().string())
            << '\n';
  return 0;
}
