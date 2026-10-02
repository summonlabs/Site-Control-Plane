// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "journal_probe.hpp"
#include "scp/journal.hpp"
#include "scp/runtime.hpp"
#include "test_support.hpp"

/// \file test_recovery.cpp
/// Real close-and-reopen, restart semantics, and the compaction contract.
///
/// Every case here opens a real directory, so nothing can pass on in-memory
/// state that never reached the disk.

namespace {

constexpr const char* kJournalName = "journal.scp";
constexpr const char* kSnapshotName = "snapshot.scp";

std::vector<scp::EvidenceRecord> records_for(std::uint64_t generation) {
  return scp_test::healthy_site_records(scp_test::base_instant(), generation);
}

std::uint64_t size_of(const std::filesystem::path& path) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  return error ? 0 : static_cast<std::uint64_t>(size);
}

scp::JournalTransaction generation_transaction(std::uint64_t index) {
  scp::JournalTransaction transaction;
  transaction.id = scp::TransactionId(0x3300000000000000ULL + index, index);
  scp::JournalOperation operation;
  operation.kind = scp::OperationKind::AdvanceSiteGeneration;
  operation.site_generation = scp::SiteGeneration(index);
  transaction.operations.push_back(operation);
  return transaction;
}

}  // namespace

SCP_TEST(restart_preserves_generation_state_and_evidence) {
  scp_test::TempDirectory temp("recovery-restart");
  const std::size_t record_count = records_for(1).size();
  {
    SCP_OPEN_RUNTIME(runtime, scp_test::durable_runtime_options(temp.path()));
    SCP_CHECK_EQ(record_count, std::size_t{11});
    SCP_REQUIRE(runtime->ingest(records_for(1)).ok());
    scp::CommitOptions commit;
    commit.now = scp_test::base_instant();
    const auto outcome = runtime->commit(commit);
    SCP_REQUIRE_OK(outcome);
    SCP_CHECK_EQ(outcome.value().site_generation.value(), std::uint64_t{1});
    SCP_CHECK(outcome.value().state == scp::SiteState::Available);
    SCP_REQUIRE(runtime->close().ok());
  }
  {
    SCP_OPEN_RUNTIME(reopened, scp_test::durable_runtime_options(temp.path()));
    const scp::RuntimeStatus status = reopened->status();
    SCP_CHECK(status.recovered);
    SCP_CHECK_EQ(status.site_generation.value(), std::uint64_t{1});
    SCP_CHECK_EQ(status.accepted_evidence, record_count);
    SCP_CHECK(status.state == scp::SiteState::Available);
    const auto snapshot = reopened->snapshot(scp_test::base_instant());
    SCP_REQUIRE_OK(snapshot);
    SCP_CHECK(snapshot.value().state == scp::SiteState::Available);
    SCP_CHECK(snapshot.value().classification == scp::EvidenceClassification::Complete);
    // Recovered evidence says so, and is therefore distinguishable from
    // evidence that was freshly ingested in this process.
    const scp::SlotResolution* slot =
        snapshot.value().find_slot(scp::EvidenceSlot{scp::SourceAuthority::PowerControlPlane,
                                                     scp::EvidenceKind::PowerReadiness});
    SCP_REQUIRE(slot != nullptr);
    SCP_CHECK(slot->accepted());
    SCP_CHECK(slot->origin == scp::EvidenceOrigin::RecoveredFromJournal);
    SCP_REQUIRE(reopened->close().ok());
  }
}

SCP_TEST(second_commit_advances_generation_durably) {
  scp_test::TempDirectory temp("recovery-generations");
  {
    SCP_OPEN_RUNTIME(runtime, scp_test::durable_runtime_options(temp.path()));
    for (std::uint64_t generation = 1; generation <= 3; ++generation) {
      SCP_REQUIRE(runtime->ingest(records_for(generation)).ok());
      scp::CommitOptions commit;
      commit.now = scp_test::instant_after(static_cast<std::int64_t>(generation) * 10);
      const auto outcome = runtime->commit(commit);
      SCP_REQUIRE_OK(outcome);
      SCP_CHECK_EQ(outcome.value().site_generation.value(), generation);
    }
    SCP_REQUIRE(runtime->close().ok());
  }
  SCP_OPEN_RUNTIME(reopened, scp_test::durable_runtime_options(temp.path()));
  SCP_CHECK_EQ(reopened->status().site_generation.value(), std::uint64_t{3});
  const auto snapshot = reopened->snapshot(scp_test::instant_after(40));
  SCP_REQUIRE_OK(snapshot);
  SCP_CHECK(snapshot.value().state == scp::SiteState::Available);
  // Every generation of every slot was kept, so the newest still wins after a
  // restart and the older ones remain reportable.
  std::size_t superseded_total = 0;
  for (const scp::SlotResolution& slot : snapshot.value().slots) {
    superseded_total += slot.superseded.size();
  }
  SCP_CHECK(superseded_total >= 11);
  SCP_REQUIRE(reopened->close().ok());
}

SCP_TEST(compaction_retires_covered_frames_and_keeps_state) {
  scp_test::TempDirectory temp("recovery-compaction");
  const std::filesystem::path journal_path = temp.path() / kJournalName;
  const std::filesystem::path snapshot_path = temp.path() / kSnapshotName;

  scp::RuntimeOptions options = scp_test::durable_runtime_options(temp.path());
  options.compaction_threshold_bytes = 4096;
  std::uint64_t bytes_before = 0;
  bool compacted = false;
  {
    SCP_OPEN_RUNTIME(runtime, options);
    for (std::uint64_t generation = 1; generation <= 6; ++generation) {
      SCP_REQUIRE(runtime->ingest(records_for(generation)).ok());
      scp::CommitOptions commit;
      commit.now = scp_test::instant_after(static_cast<std::int64_t>(generation) * 10);
      commit.allow_compaction = true;
      const auto outcome = runtime->commit(commit);
      SCP_REQUIRE_OK(outcome);
      if (outcome.value().compacted) {
        compacted = true;
        SCP_CHECK(outcome.value().compaction_bytes_reclaimed > 0);
      }
    }
    bytes_before = size_of(journal_path);
    SCP_CHECK(runtime->status().compactions > 0);
    SCP_REQUIRE(runtime->close().ok());
  }
  SCP_CHECK(compacted);
  SCP_CHECK(std::filesystem::exists(snapshot_path));
  SCP_CHECK(bytes_before > 0);
  const auto probe = scp_test::probe_journal(journal_path);
  SCP_REQUIRE_OK(probe);
  SCP_CHECK(probe.value().base_sequence > 0);

  SCP_OPEN_RUNTIME(reopened, options);
  const scp::RuntimeStatus status = reopened->status();
  SCP_CHECK(status.recovered);
  SCP_CHECK_EQ(status.site_generation.value(), std::uint64_t{6});
  SCP_CHECK(status.accepted_evidence > 0);
  const auto composed = reopened->snapshot(scp_test::instant_after(70));
  SCP_REQUIRE_OK(composed);
  SCP_CHECK(composed.value().state == scp::SiteState::Available);
  SCP_CHECK(composed.value().classification == scp::EvidenceClassification::Complete);
  SCP_REQUIRE(reopened->close().ok());
}

SCP_TEST(compaction_retains_every_frame_beyond_the_snapshot) {
  scp_test::TempDirectory temp("recovery-compaction-uncommitted");
  const std::filesystem::path journal_path = temp.path() / kJournalName;

  scp::JournalOptions journal_options;
  journal_options.directory = temp.path();
  journal_options.site = scp_test::default_site();
  {
    auto opened = scp::Journal::open(journal_options);
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    for (std::uint64_t index = 1; index <= 3; ++index) {
      SCP_REQUIRE_OK(journal.commit(generation_transaction(index)));
    }
    SCP_REQUIRE_STATUS_OK(journal.close());
  }

  // Compact up to the *first* committed position only. Everything beyond it is
  // uncommitted-with-respect-to-the-snapshot and must be carried forward
  // verbatim, because retiring it would silently discard committed work.
  {
    auto opened = scp::Journal::open(journal_options);
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{3});

    scp::JournalSnapshot snapshot;
    snapshot.site = scp_test::default_site();
    snapshot.site_generation = scp::SiteGeneration(1);
    snapshot.sequence = scp::JournalSequence(1);
    snapshot.created_at = scp_test::base_instant();
    snapshot.chain_digest = journal.chain_digest();
    const auto report = journal.compact(snapshot);
    SCP_REQUIRE_OK(report);
    SCP_CHECK(report.value().snapshot_written);
    SCP_CHECK(report.value().journal_rewritten);
    SCP_CHECK_EQ(report.value().snapshot_sequence.value(), std::uint64_t{1});
    SCP_CHECK_EQ(report.value().frames_retired, std::uint64_t{2});
    SCP_CHECK_EQ(report.value().frames_retained, std::uint64_t{4});
    SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{3});
    SCP_REQUIRE_STATUS_OK(journal.close());
  }

  {
    const auto after = scp_test::probe_journal(journal_path);
    SCP_REQUIRE_OK(after);
    SCP_CHECK_EQ(after.value().base_sequence, std::uint64_t{1});
    SCP_CHECK_EQ(after.value().frames.size(), std::size_t{4});
    SCP_CHECK_EQ(scp_test::committed_sequence(after.value()), std::uint64_t{3});
    SCP_CHECK_EQ(after.value().frames.front().sequence, std::uint64_t{2});
    SCP_CHECK_EQ(after.value().frames.back().sequence, std::uint64_t{3});
    SCP_CHECK_EQ(after.value().frames.back().kind, std::uint8_t{2});
  }

  // The retained tail still replays: the snapshot covers one transaction and the
  // journal supplies the other two, with no gap and no duplicate.
  {
    auto reopened = scp::Journal::open(journal_options);
    SCP_REQUIRE_OK(reopened);
    const auto recovery = reopened.value().recover();
    SCP_REQUIRE_OK(recovery);
    SCP_CHECK(recovery.value().clean);
    SCP_CHECK(recovery.value().loaded_snapshot);
    SCP_CHECK_EQ(recovery.value().snapshot_sequence.value(), std::uint64_t{1});
    SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{2});
    SCP_CHECK_EQ(recovery.value().replayed_operations, std::size_t{2});
    SCP_CHECK_EQ(reopened.value().sequence().value(), std::uint64_t{3});
    SCP_REQUIRE_STATUS_OK(reopened.value().close());
  }
}

SCP_TEST(compaction_retires_a_fully_covered_journal) {
  // The complement of the previous case: when the snapshot covers the whole
  // journal, nothing is retained and the snapshot alone restores the position.
  scp_test::TempDirectory temp("recovery-compaction-full");
  const std::filesystem::path journal_path = temp.path() / kJournalName;
  scp::JournalOptions journal_options;
  journal_options.directory = temp.path();
  journal_options.site = scp_test::default_site();
  {
    auto opened = scp::Journal::open(journal_options);
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    for (std::uint64_t index = 1; index <= 2; ++index) {
      SCP_REQUIRE_OK(journal.commit(generation_transaction(index)));
    }
    scp::JournalSnapshot snapshot;
    snapshot.site = scp_test::default_site();
    snapshot.site_generation = scp::SiteGeneration(2);
    snapshot.sequence = scp::JournalSequence(2);
    snapshot.created_at = scp_test::base_instant();
    snapshot.chain_digest = journal.chain_digest();
    const auto report = journal.compact(snapshot);
    SCP_REQUIRE_OK(report);
    SCP_CHECK_EQ(report.value().frames_retained, std::uint64_t{0});
    SCP_CHECK_EQ(report.value().frames_retired, std::uint64_t{4});
    SCP_REQUIRE_STATUS_OK(journal.close());
    // The compacted journal is now header-only, which is a valid journal.
    SCP_CHECK_EQ(size_of(journal_path), std::uint64_t{80});
  }
  {
    auto reopened = scp::Journal::open(journal_options);
    SCP_REQUIRE_OK(reopened);
    const auto recovery = reopened.value().recover();
    SCP_REQUIRE_OK(recovery);
    SCP_CHECK(recovery.value().loaded_snapshot);
    SCP_CHECK_EQ(recovery.value().snapshot_sequence.value(), std::uint64_t{2});
    SCP_CHECK_EQ(reopened.value().sequence().value(), std::uint64_t{2});
    SCP_REQUIRE_STATUS_OK(reopened.value().close());
  }
}

SCP_TEST(compaction_refuses_a_snapshot_beyond_the_committed_position) {
  scp_test::TempDirectory temp("recovery-compaction-ahead");
  scp::JournalOptions journal_options;
  journal_options.directory = temp.path();
  journal_options.site = scp_test::default_site();
  auto opened = scp::Journal::open(journal_options);
  SCP_REQUIRE_OK(opened);
  scp::Journal journal = std::move(opened.value());
  SCP_REQUIRE_OK(journal.commit(generation_transaction(1)));

  scp::JournalSnapshot snapshot;
  snapshot.site = scp_test::default_site();
  snapshot.site_generation = scp::SiteGeneration(9);
  snapshot.sequence = scp::JournalSequence(9);
  snapshot.created_at = scp_test::base_instant();
  SCP_REQUIRE_ERROR(journal.compact(snapshot), scp::StatusCode::StaleGeneration);
  SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{1});
  SCP_REQUIRE_STATUS_OK(journal.close());
}

SCP_TEST(corrupt_snapshot_is_refused_rather_than_ignored) {
  scp_test::TempDirectory temp("recovery-snapshot-corrupt");
  const std::filesystem::path snapshot_path = temp.path() / kSnapshotName;

  scp::RuntimeOptions options = scp_test::durable_runtime_options(temp.path());
  options.compaction_threshold_bytes = 1;
  {
    SCP_OPEN_RUNTIME(runtime, options);
    SCP_REQUIRE(runtime->ingest(records_for(1)).ok());
    scp::CommitOptions commit;
    commit.now = scp_test::base_instant();
    commit.allow_compaction = true;
    const auto outcome = runtime->commit(commit);
    SCP_REQUIRE_OK(outcome);
    SCP_CHECK(outcome.value().compacted);
    SCP_REQUIRE(runtime->close().ok());
  }
  SCP_REQUIRE(std::filesystem::exists(snapshot_path));
  const std::uint64_t snapshot_size = size_of(snapshot_path);
  SCP_CHECK(snapshot_size > 20);
  // Flip a payload byte rather than writing a fixed value, so the damage is
  // guaranteed whatever the byte already held.
  const std::vector<std::uint8_t> original = scp_test::read_bytes(snapshot_path);
  SCP_REQUIRE(original.size() > 30);
  SCP_REQUIRE(scp_test::poke_byte(snapshot_path, 30,
                                  static_cast<std::uint8_t>(original[30] ^ 0xFFU)));

  const auto runtime = scp::SiteControlPlane::open(options);
  SCP_REQUIRE_ERROR(runtime, scp::StatusCode::ChecksumMismatch);
  // The refusal must not have removed the damaged file.
  SCP_CHECK_EQ(size_of(snapshot_path), snapshot_size);
}

SCP_TEST(in_memory_runtime_claims_no_durability) {
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());
  SCP_CHECK(!runtime->status().durable);
  SCP_REQUIRE(runtime->ingest(records_for(1)).ok());
  scp::CommitOptions commit;
  commit.now = scp_test::base_instant();
  const auto outcome = runtime->commit(commit);
  SCP_REQUIRE_OK(outcome);
  SCP_CHECK(outcome.value().committed);
  SCP_CHECK(outcome.value().durability_boundary.find("in-memory") != std::string::npos);
  SCP_CHECK(runtime->status().state == scp::SiteState::Available);
  SCP_REQUIRE(runtime->close().ok());
}

SCP_TEST(runtime_cancellation_never_reports_success) {
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());
  SCP_REQUIRE(runtime->ingest(records_for(1)).ok());
  SCP_REQUIRE(runtime->cancel().ok());
  SCP_CHECK(runtime->status().cancelled);
  scp::CommitOptions commit;
  commit.now = scp_test::base_instant();
  SCP_REQUIRE_ERROR(runtime->commit(commit), scp::StatusCode::Cancelled);
  // Staged work was discarded, so nothing can report success later.
  SCP_CHECK_EQ(runtime->status().pending_evidence, std::size_t{0});
  SCP_REQUIRE_STATUS_ERROR(runtime->ingest(records_for(1)), scp::StatusCode::Cancelled);
  const auto snapshot = runtime->snapshot(scp_test::base_instant());
  SCP_REQUIRE_OK(snapshot);
  SCP_CHECK(snapshot.value().state != scp::SiteState::Available);
  SCP_REQUIRE(runtime->close().ok());
}

SCP_TEST(runtime_close_is_idempotent_and_refuses_further_work) {
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());
  SCP_REQUIRE(runtime->close().ok());
  SCP_REQUIRE(runtime->close().ok());
  SCP_CHECK(!runtime->status().open);
  SCP_REQUIRE_STATUS_ERROR(runtime->ingest(records_for(1)), scp::StatusCode::Closed);
  scp::CommitOptions commit;
  commit.now = scp_test::base_instant();
  SCP_REQUIRE_ERROR(runtime->commit(commit), scp::StatusCode::Closed);
  SCP_REQUIRE_ERROR(runtime->snapshot(scp_test::base_instant()), scp::StatusCode::Closed);
}

SCP_TEST(runtime_evidence_capacity_is_bounded_and_reported) {
  scp::RuntimeOptions options = scp_test::memory_runtime_options();
  options.evidence_capacity = 3;
  SCP_OPEN_RUNTIME(runtime, options);
  // The bound is enforced while the batch is being staged, so a batch that would
  // exceed it is refused rather than silently truncated to fit.
  SCP_REQUIRE_STATUS_ERROR(runtime->ingest(records_for(1)), scp::StatusCode::CapacityExhausted);
  SCP_CHECK_EQ(runtime->status().pending_evidence, std::size_t{3});
  SCP_REQUIRE_STATUS_ERROR(runtime->ingest(records_for(2)), scp::StatusCode::CapacityExhausted);
  SCP_CHECK_EQ(runtime->status().pending_evidence, std::size_t{3});
  SCP_REQUIRE_STATUS_OK(runtime->discard_pending());
  SCP_CHECK_EQ(runtime->status().pending_evidence, std::size_t{0});
  SCP_REQUIRE_STATUS_OK(runtime->close());
}

SCP_TEST(runtime_records_grants_and_policy_durably) {
  scp_test::TempDirectory temp("recovery-grants");
  scp::GrantId grant_id(0x6100000000000001ULL, 1);
  {
    SCP_OPEN_RUNTIME(runtime, scp_test::durable_runtime_options(temp.path()));
    scp::DelegationGrant grant;
    grant.id = grant_id;
    grant.site = scp_test::default_site();
    grant.grantor = scp::Name::parse("facility-policy-engine").value();
    grant.subject = scp::Name::parse("site-control-plane").value();
    grant.scopes = scp::ScopeSet::of(scp::ActionScope::AcceptObligation)
                       .with(scp::ActionScope::RequestAcceleratorEffect);
    grant.issued_at = scp_test::base_instant();
    SCP_REQUIRE(runtime->record_grant(grant, scp_test::base_instant()).ok());
    SCP_REQUIRE_STATUS_ERROR(runtime->record_grant(grant, scp_test::base_instant()),
                      scp::StatusCode::AlreadyExists);
    scp::SitePolicy policy = scp_test::policy_with_generation(7);
    SCP_REQUIRE(runtime->record_policy(policy, scp_test::base_instant()).ok());
    SCP_REQUIRE(runtime->close().ok());
  }
  SCP_OPEN_RUNTIME(reopened, scp_test::durable_runtime_options(temp.path()));
  const std::vector<scp::DelegationGrant> grants = reopened->grants();
  SCP_CHECK_EQ(grants.size(), std::size_t{1});
  SCP_CHECK(grants[0].id == grant_id);
  SCP_CHECK_EQ(grants[0].scopes.bits(), std::uint16_t{0x0A});
  SCP_CHECK(reopened->status().policy_digest == scp::compute_policy_digest(
                                                    scp_test::policy_with_generation(7)));
  SCP_REQUIRE(reopened->close().ok());
}

SCP_TEST_MAIN("test_recovery")
