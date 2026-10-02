// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "scp/authority.hpp"
#include "scp/canonical.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/plan.hpp"
#include "scp/policy.hpp"
#include "scp/status.hpp"
#include "scp/time.hpp"

/// \file journal.hpp
/// The durable journal and snapshot layer for site-level authority.
///
/// Completion is explicit and two-phase. An operation becomes visible only after
/// its prepare frame has been written, flushed and re-read to verify integrity,
/// and a commit frame referencing it has been written and flushed. A prepare
/// without a commit is never replayed, so a submit that fails before the commit
/// boundary is not a completion, and a crash mid-transaction leaves the previous
/// committed state intact.
///
/// Commit boundary, stated precisely: an operation is durable when
/// \c write() has returned for the commit frame bytes, the platform's device
/// flush has completed for that file, and the frame has been re-read and its
/// checksum and chain link verified. Everything before that point is intent.
///
/// Writer exclusion is enforced with a real operating-system file lock, so a
/// second process attempting to open the same site directory fails with
/// WriterExists rather than corrupting the journal.

namespace scp {

/// Frame kinds in the journal.
enum class JournalRecordKind : std::uint8_t {
  /// Begin of a two-phase transaction; carries the operations.
  TransactionPrepare = 1,
  /// Completion of a transaction; carries the digest of its prepare frame.
  TransactionCommit = 2,
  /// Free-standing annotation, never replayed into state.
  Marker = 3,
};

[[nodiscard]] std::string_view to_string(JournalRecordKind kind) noexcept;

/// Operations that participate in durable site state.
enum class OperationKind : std::uint8_t {
  IngestEvidence = 1,
  RetireEvidence = 2,
  AdvanceSiteGeneration = 3,
  RecordPlan = 4,
  RecordGrant = 5,
  RecordPolicy = 6,
};

inline constexpr std::size_t kOperationKindCount = 6;

[[nodiscard]] std::string_view to_string(OperationKind kind) noexcept;

/// One durable operation. Only the fields relevant to \c kind are encoded and
/// decoded; the others stay at their defaults.
struct JournalOperation {
  OperationKind kind = OperationKind::IngestEvidence;
  EvidenceRecord evidence{};
  SiteGeneration site_generation{};
  ActionPlan plan{};
  DelegationGrant grant{};
  SitePolicy policy{};

  [[nodiscard]] Status validate() const;
};

inline constexpr std::size_t kMaxOperationsPerTransaction = 4096;

/// A group of operations that commit together or not at all.
struct JournalTransaction {
  TransactionId id{};
  std::vector<JournalOperation> operations;
};

/// Result of one durable commit.
struct JournalCommit {
  TransactionId id{};
  JournalSequence sequence{};
  std::uint64_t operations = 0;
  std::uint64_t bytes_written = 0;
  Digest commit_frame_digest{};
  /// Named so that a report can say exactly which boundary was crossed.
  std::string durability_boundary;
};

/// On-disk layout limits. Every one of these is enforced while reading, so a
/// damaged or hostile file cannot drive unbounded allocation.
inline constexpr std::uint32_t kMaxFrameBodyBytes = 8U * 1024U * 1024U;
inline constexpr std::uint64_t kDefaultMaxJournalBytes = 256ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kMaxSnapshotBytes = 128ULL * 1024ULL * 1024ULL;

struct JournalOptions {
  /// Directory that holds journal.scp, snapshot.scp and the writer lock.
  std::filesystem::path directory;
  SiteId site{};
  bool create_if_missing = true;
  /// Upper bound on journal growth between compactions. Exceeding it fails the
  /// commit with LimitExceeded instead of growing without bound.
  std::uint64_t max_journal_bytes = kDefaultMaxJournalBytes;
  /// Cap on operations carried by one transaction.
  std::size_t max_operations_per_transaction = 256;
  /// Take the exclusive writer lock. Tests that deliberately contend set this
  /// true and expect the second opener to fail.
  bool exclusive_writer = true;
};

/// What a recovery pass found and did.
struct JournalRecoveryReport {
  /// True when the file ended exactly on a committed boundary.
  bool clean = true;
  /// True when an incomplete trailing frame was removed.
  bool truncated_torn_tail = false;
  /// True when a complete prepare frame with no commit frame was discarded.
  bool discarded_uncommitted_transaction = false;
  /// Byte offset at which the journal now ends.
  std::uint64_t recovered_bytes = 0;
  /// Byte offset where the damage was observed, when any.
  std::uint64_t damage_offset = 0;
  JournalSequence first_sequence{};
  JournalSequence last_sequence{};
  std::uint64_t committed_transactions = 0;
  std::uint64_t replayed_operations = 0;
  std::uint64_t discarded_operations = 0;
  /// True when the accepted state was seeded from a snapshot file.
  bool loaded_snapshot = false;
  JournalSequence snapshot_sequence{};
  SiteGeneration site_generation{};
  Digest chain_digest{};
  std::vector<JournalOperation> operations;
};

/// A snapshot of site-level authority at a journal position.
struct JournalSnapshot {
  SiteId site{};
  SiteGeneration site_generation{};
  /// Journal position the snapshot covers, inclusive.
  JournalSequence sequence{};
  Timestamp created_at{};
  /// Digest of the journal chain up to and including \c sequence.
  Digest chain_digest{};
  std::vector<EvidenceRecord> evidence;
  std::vector<DelegationGrant> grants;
  SitePolicy policy{};
};

struct CompactionReport {
  JournalSequence snapshot_sequence{};
  std::uint64_t bytes_before = 0;
  std::uint64_t bytes_after = 0;
  std::uint64_t frames_retained = 0;
  std::uint64_t frames_retired = 0;
  bool snapshot_written = false;
  bool journal_rewritten = false;
};

/// The journal is not internally synchronized. A single writer at a time is
/// enforced by the operating-system writer lock taken at open, and in-process
/// callers serialize with the runtime's journal lock.
class Journal {
 public:
  Journal() = default;
  Journal(Journal&& other) noexcept;
  Journal& operator=(Journal&& other) noexcept;
  Journal(const Journal&) = delete;
  Journal& operator=(const Journal&) = delete;
  ~Journal();

  /// Opens or creates the journal directory and takes the writer lock.
  [[nodiscard]] static Result<Journal> open(const JournalOptions& options);

  [[nodiscard]] bool is_open() const noexcept;
  [[nodiscard]] const std::filesystem::path& directory() const noexcept;
  [[nodiscard]] SiteId site() const noexcept;

  /// Appends a transaction with the two-phase protocol and returns once the
  /// commit boundary has been crossed. On any failure the transaction is not
  /// visible after recovery, and the journal is left exactly on its previous
  /// committed boundary.
  [[nodiscard]] Result<JournalCommit> commit(const JournalTransaction& transaction);

  /// Scans the journal from the beginning, repairs an incomplete trailing frame,
  /// and returns the committed operations in order. Never truncates a frame that
  /// is not the final frame; interior damage is reported as interior corruption.
  [[nodiscard]] Result<JournalRecoveryReport> recover();

  /// Current committed position without re-reading the whole file.
  [[nodiscard]] JournalSequence sequence() const noexcept;

  /// Digest of the most recently committed frame, or the chain base when the
  /// journal holds no committed frame of its own.
  [[nodiscard]] Digest chain_digest() const noexcept;

  /// Byte offset of the committed end of the journal.
  [[nodiscard]] std::uint64_t committed_bytes() const noexcept;

  /// Writes a snapshot atomically and retires the journal prefix it covers. The
  /// snapshot never covers an uncommitted transaction, and an uncommitted
  /// trailing prepare frame is carried forward rather than deleted.
  [[nodiscard]] Result<CompactionReport> compact(const JournalSnapshot& snapshot);

  /// Reads the snapshot file if present.
  [[nodiscard]] Result<JournalSnapshot> read_snapshot() const;

  [[nodiscard]] std::uint64_t size_bytes() const;

  [[nodiscard]] Status close();

 private:
  struct Impl;

  /// Reads the whole journal through the handle the journal already owns.
  [[nodiscard]] Result<std::vector<std::uint8_t>> read_through_handle();

  Impl* impl_ = nullptr;
};

void canonical_write(CanonicalWriter& writer, const JournalOperation& value);
[[nodiscard]] Result<JournalOperation> canonical_read_operation(CanonicalReader& reader);
void canonical_write(CanonicalWriter& writer, const JournalTransaction& value);
[[nodiscard]] Result<JournalTransaction> canonical_read_transaction(CanonicalReader& reader);
void canonical_write(CanonicalWriter& writer, const JournalSnapshot& value);
[[nodiscard]] Result<JournalSnapshot> canonical_read_snapshot(CanonicalReader& reader);

}  // namespace scp
