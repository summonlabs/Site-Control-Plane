// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "journal_probe.hpp"
#include "scp/journal.hpp"
#include "test_support.hpp"

/// \file test_journal.cpp
/// Durability, integrity and recovery of the journal itself.
///
/// Every case here works on a real file in a real temporary directory. Nothing
/// is mocked: the point of the layer is what actually reaches the disk.

namespace {

constexpr const char* kJournalName = "journal.scp";
constexpr const char* kSnapshotName = "snapshot.scp";

scp::JournalOptions options_for(const std::filesystem::path& directory, bool exclusive = true) {
  scp::JournalOptions options;
  options.directory = directory;
  options.site = scp_test::default_site();
  options.create_if_missing = true;
  options.exclusive_writer = exclusive;
  return options;
}

scp::JournalOperation ingest_operation(std::uint64_t generation, std::uint64_t seed) {
  scp_test::RecordSpec spec;
  spec.authority = scp::SourceAuthority::FacilityCapacity;
  spec.instance = seed;
  spec.epoch = 1;
  spec.generation = generation;
  spec.sequence = 1;
  spec.issued_at = scp_test::base_instant();
  scp::CapacityEvidence capacity;
  capacity.generation = scp::CapacityGeneration(generation);
  capacity.total_units = 100;
  capacity.committed_units = seed;
  capacity.available_units = 100 - seed;
  auto record = scp_test::make_capacity(spec, capacity);
  if (!record.has_value()) {
    return {};
  }
  scp::JournalOperation operation;
  operation.kind = scp::OperationKind::IngestEvidence;
  operation.evidence = record.value();
  return operation;
}

scp::JournalOperation generation_operation(std::uint64_t generation) {
  scp::JournalOperation operation;
  operation.kind = scp::OperationKind::AdvanceSiteGeneration;
  operation.site_generation = scp::SiteGeneration(generation);
  return operation;
}

scp::JournalTransaction transaction_of(std::uint64_t id, std::vector<scp::JournalOperation> ops) {
  scp::JournalTransaction transaction;
  transaction.id = scp::TransactionId(0x7A00000000000000ULL + id, id);
  transaction.operations = std::move(ops);
  return transaction;
}

std::uint64_t journal_size(const std::filesystem::path& directory) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(directory / kJournalName, error);
  return error ? 0 : static_cast<std::uint64_t>(size);
}

}  // namespace

SCP_TEST(journal_creates_and_recovers_empty) {
  scp_test::TempDirectory temp("journal-create");
  auto opened = scp::Journal::open(options_for(temp.path()));
  SCP_REQUIRE_OK(opened);
  scp::Journal journal = std::move(opened.value());
  SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{0});
  SCP_CHECK(std::filesystem::exists(temp.path() / kJournalName));
  SCP_CHECK(std::filesystem::exists(temp.path() / "journal.lock"));
  const auto recovery = journal.recover();
  SCP_REQUIRE_OK(recovery);
  SCP_CHECK(recovery.value().clean);
  SCP_CHECK(!recovery.value().truncated_torn_tail);
  SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{0});
  SCP_CHECK_EQ(recovery.value().replayed_operations, std::uint64_t{0});
  SCP_REQUIRE_STATUS_OK(journal.close());
}

SCP_TEST(journal_commit_is_replayable_in_order) {
  scp_test::TempDirectory temp("journal-replay");
  {
    auto opened = scp::Journal::open(options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    for (std::uint64_t index = 1; index <= 4; ++index) {
      const auto committed =
          journal.commit(transaction_of(index, {ingest_operation(index, index),
                                                generation_operation(index)}));
      SCP_REQUIRE_OK(committed);
      SCP_CHECK_EQ(committed.value().sequence.value(), index);
      SCP_CHECK_EQ(committed.value().operations, std::size_t{2});
      SCP_CHECK(!committed.value().durability_boundary.empty());
    }
    SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{4});
    SCP_REQUIRE_STATUS_OK(journal.close());
  }
  {
    auto reopened = scp::Journal::open(options_for(temp.path()));
    SCP_REQUIRE_OK(reopened);
    scp::Journal journal = std::move(reopened.value());
    SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{4});
    const auto recovery = journal.recover();
    SCP_REQUIRE_OK(recovery);
    SCP_CHECK(recovery.value().clean);
    SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{4});
    SCP_CHECK_EQ(recovery.value().replayed_operations, std::size_t{8});
    std::uint64_t expected_generation = 1;
    for (std::size_t index = 0; index < recovery.value().operations.size(); index += 2) {
      SCP_CHECK(recovery.value().operations[index].kind == scp::OperationKind::IngestEvidence);
      SCP_CHECK(recovery.value().operations[index + 1].kind ==
                scp::OperationKind::AdvanceSiteGeneration);
      SCP_CHECK_EQ(recovery.value().operations[index + 1].site_generation.value(),
                   expected_generation);
      ++expected_generation;
    }
    SCP_REQUIRE_STATUS_OK(journal.close());
  }
}

SCP_TEST(journal_rejects_impossible_transactions) {
  scp_test::TempDirectory temp("journal-reject");
  auto opened = scp::Journal::open(options_for(temp.path()));
  SCP_REQUIRE_OK(opened);
  scp::Journal journal = std::move(opened.value());

  scp::JournalTransaction empty;
  empty.id = scp::TransactionId(1, 1);
  SCP_REQUIRE_ERROR(journal.commit(empty), scp::StatusCode::InvalidArgument);

  scp::JournalTransaction nil_id = transaction_of(2, {generation_operation(1)});
  nil_id.id = scp::TransactionId();
  SCP_REQUIRE_ERROR(journal.commit(nil_id), scp::StatusCode::InvalidIdentifier);

  scp::JournalTransaction unset_generation =
      transaction_of(3, {scp::JournalOperation{}});
  unset_generation.operations[0].kind = scp::OperationKind::AdvanceSiteGeneration;
  SCP_REQUIRE_ERROR(journal.commit(unset_generation), scp::StatusCode::InvalidArgument);

  // None of the refused transactions may have moved the journal.
  SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{0});
  SCP_CHECK_EQ(journal_size(temp.path()), std::uint64_t{80});
  SCP_REQUIRE_STATUS_OK(journal.close());
}

SCP_TEST(journal_enforces_growth_bound) {
  scp_test::TempDirectory temp("journal-bound");
  scp::JournalOptions options = options_for(temp.path());
  options.max_journal_bytes = 200;
  auto opened = scp::Journal::open(options);
  SCP_REQUIRE_OK(opened);
  scp::Journal journal = std::move(opened.value());
  SCP_REQUIRE_ERROR(journal.commit(transaction_of(1, {ingest_operation(1, 3)})),
                    scp::StatusCode::LimitExceeded);
  SCP_CHECK_EQ(journal_size(temp.path()), std::uint64_t{80});
  SCP_REQUIRE_STATUS_OK(journal.close());
}

SCP_TEST(journal_enforces_operation_count_bound) {
  scp_test::TempDirectory temp("journal-ops-bound");
  scp::JournalOptions options = options_for(temp.path());
  options.max_operations_per_transaction = 2;
  auto opened = scp::Journal::open(options);
  SCP_REQUIRE_OK(opened);
  scp::Journal journal = std::move(opened.value());
  std::vector<scp::JournalOperation> operations;
  operations.push_back(generation_operation(1));
  operations.push_back(generation_operation(2));
  operations.push_back(generation_operation(3));
  SCP_REQUIRE_ERROR(journal.commit(transaction_of(1, operations)),
                    scp::StatusCode::LimitExceeded);
  SCP_CHECK_EQ(journal_size(temp.path()), std::uint64_t{80});
  SCP_REQUIRE_STATUS_OK(journal.close());
}

SCP_TEST(journal_writer_exclusion_within_a_process) {
  scp_test::TempDirectory temp("journal-lock");
  auto first = scp::Journal::open(options_for(temp.path()));
  SCP_REQUIRE_OK(first);
  scp::Journal journal = std::move(first.value());
  auto second = scp::Journal::open(options_for(temp.path()));
  SCP_REQUIRE_ERROR(second, scp::StatusCode::WriterExists);
  SCP_REQUIRE_STATUS_OK(journal.close());
  // After the first writer releases, a second opener succeeds.
  auto third = scp::Journal::open(options_for(temp.path()));
  SCP_REQUIRE_OK(third);
  SCP_REQUIRE_STATUS_OK(third.value().close());
}

SCP_TEST(journal_rejects_foreign_site_and_bad_header) {
  scp_test::TempDirectory temp("journal-header");
  {
    auto opened = scp::Journal::open(options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    SCP_REQUIRE_STATUS_OK(opened.value().close());
  }
  scp::JournalOptions other = options_for(temp.path());
  other.site = scp::SiteId(0xDEADBEEF00000000ULL, 1);
  other.exclusive_writer = false;
  auto foreign = scp::Journal::open(other);
  SCP_REQUIRE_ERROR(foreign, scp::StatusCode::Conflict);

  SCP_REQUIRE(scp_test::poke_byte(temp.path() / kJournalName, 0, 'X'));
  auto corrupted = scp::Journal::open(options_for(temp.path()));
  SCP_REQUIRE_ERROR(corrupted, scp::StatusCode::Corrupt);
}

SCP_TEST(journal_detects_truncated_header_and_tampered_version) {
  scp_test::TempDirectory temp("journal-short");
  {
    auto opened = scp::Journal::open(options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    SCP_REQUIRE_STATUS_OK(opened.value().close());
  }
  SCP_REQUIRE(scp_test::truncate_file(temp.path() / kJournalName, 20));
  auto short_file = scp::Journal::open(options_for(temp.path()));
  SCP_REQUIRE_ERROR(short_file, scp::StatusCode::Truncated);

  scp_test::TempDirectory version_temp("journal-version");
  {
    auto opened = scp::Journal::open(options_for(version_temp.path()));
    SCP_REQUIRE_OK(opened);
    SCP_REQUIRE_STATUS_OK(opened.value().close());
  }
  // Editing the declared format version without recomputing the header checksum
  // is caught by the checksum, which is strictly stronger than a version test:
  // a journal cannot be relabelled into a different format.
  SCP_REQUIRE(scp_test::poke_byte(version_temp.path() / kJournalName, 8, 9));
  auto bad_version = scp::Journal::open(options_for(version_temp.path()));
  SCP_REQUIRE_ERROR(bad_version, scp::StatusCode::ChecksumMismatch);
}

SCP_TEST(journal_recovers_torn_tail_by_truncation) {
  // A torn tail is the one damage the journal is allowed to repair: the frame
  // does not physically fit, so the write that produced it never completed.
  scp_test::TempDirectory temp("journal-torn");
  std::uint64_t committed_size = 0;
  {
    auto opened = scp::Journal::open(options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    SCP_REQUIRE_OK(journal.commit(transaction_of(1, {ingest_operation(1, 5)})));
    SCP_REQUIRE_OK(journal.commit(transaction_of(2, {ingest_operation(2, 6)})));
    committed_size = journal.committed_bytes();
    SCP_REQUIRE_STATUS_OK(journal.close());
  }
  // After two clean commits the committed end IS the end of the file, so a torn
  // tail has to be produced the way a crash produces one: a third transaction
  // whose append stopped part way through.
  {
    const auto probe = scp_test::probe_journal(temp.path() / kJournalName);
    SCP_REQUIRE_OK(probe);
    SCP_CHECK_EQ(scp_test::committed_sequence(probe.value()), std::uint64_t{2});
    const std::vector<std::uint8_t> payload = {0x10, 0x20, 0x30};
    SCP_REQUIRE(
        scp_test::append_uncommitted_prepare(temp.path() / kJournalName, probe.value(), 3, payload)
            .ok());
  }
  const std::uint64_t full = journal_size(temp.path());
  SCP_CHECK(full > committed_size);
  SCP_REQUIRE(scp_test::truncate_file(temp.path() / kJournalName, full - 4));
  {
    // Opening the damaged journal repairs it, and the repair is reported by the
    // recovery result that open() itself produced.
    auto opened = scp::Journal::open(options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    const auto recovery = journal.recover();
    SCP_REQUIRE_OK(recovery);
    SCP_CHECK(!recovery.value().clean);
    SCP_CHECK(recovery.value().truncated_torn_tail);
    SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{2});
    SCP_CHECK_EQ(recovery.value().replayed_operations, std::size_t{2});
    SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{2});
    SCP_CHECK_EQ(journal_size(temp.path()), committed_size);
    SCP_CHECK_EQ(recovery.value().recovered_bytes, committed_size);
    SCP_REQUIRE_STATUS_OK(journal.close());
  }
  {
    // The repaired journal is clean and still replays exactly the committed work.
    auto opened = scp::Journal::open(options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    const auto recovery = journal.recover();
    SCP_REQUIRE_OK(recovery);
    SCP_CHECK(recovery.value().clean);
    SCP_CHECK(!recovery.value().truncated_torn_tail);
    SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{2});
    SCP_REQUIRE_STATUS_OK(journal.close());
  }
}

SCP_TEST(journal_never_truncates_interior_corruption) {
  scp_test::TempDirectory temp("journal-interior");
  std::uint64_t size = 0;
  {
    auto opened = scp::Journal::open(options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    for (std::uint64_t index = 1; index <= 3; ++index) {
      SCP_REQUIRE_OK(journal.commit(transaction_of(index, {ingest_operation(index, index)})));
    }
    SCP_REQUIRE_STATUS_OK(journal.close());
    size = journal_size(temp.path());
  }
  // Damage a byte inside the second frame, which is not the last one.
  SCP_REQUIRE(scp_test::poke_byte(temp.path() / kJournalName, 120, 0x5A));
  auto opened = scp::Journal::open(options_for(temp.path()));
  SCP_REQUIRE_ERROR(opened, scp::StatusCode::InteriorCorruption);
  // The refusal must not have removed anything.
  const std::uint64_t after = journal_size(temp.path());
  SCP_CHECK_EQ(after, size);
}

SCP_TEST_MAIN("test_journal")
