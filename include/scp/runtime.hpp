// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "scp/authority.hpp"
#include "scp/composition.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/explain.hpp"
#include "scp/ids.hpp"
#include "scp/journal.hpp"
#include "scp/plan.hpp"
#include "scp/policy.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/time.hpp"

/// \file runtime.hpp
/// The site control plane runtime: the object that owns a site's accepted
/// evidence, its durable journal and the published snapshot.
///
/// Concurrency contract. Every public method is safe to call from any thread.
/// The runtime holds two locks and acquires them in exactly one order:
///
///     state_mutex_  (level 1)  ->  journal_mutex_  (level 2)
///
/// The journal lock is never held while acquiring the state lock. No callback
/// supplied by a caller is ever invoked while a lock is held: this runtime takes
/// no callbacks at all. No read lock is ever upgraded in place; a method that
/// needs write access takes the write lock once, at entry. There are no
/// background workers and no asynchronous completion, so stale completion
/// mutating a newer generation is structurally impossible rather than merely
/// avoided. \c close() serializes with in-flight operations through the state
/// lock and refuses new work once shutdown has begun.

namespace scp {

/// Result of one durable commit.
struct CommitOutcome {
  bool committed = false;
  SiteGeneration site_generation{};
  SiteState state = SiteState::Unknown;
  EvidenceClassification classification = EvidenceClassification::Indeterminate;
  std::size_t operations = 0;
  JournalSequence journal_sequence{};
  std::uint64_t transaction_bytes = 0;
  Digest snapshot_digest{};
  std::uint64_t evidence_digest_low = 0;
  std::string durability_boundary;
  bool compacted = false;
  std::uint64_t compaction_bytes_reclaimed = 0;
};

struct CommitOptions {
  /// Instant the commit is evaluated at. Required.
  Timestamp now{};
  /// Advance the site generation as part of the same transaction.
  bool advance_generation = true;
  /// Ask the runtime to compact after the commit when the journal exceeds the
  /// configured threshold.
  bool allow_compaction = true;
};

struct RuntimeOptions {
  /// Directory holding the journal, the snapshot and the writer lock. Empty
  /// selects an in-memory runtime with no durable state, which is reported
  /// honestly as such rather than silently pretending to be durable.
  std::filesystem::path directory;
  SiteId site{};
  SitePolicy policy{};
  /// Identity of this site-plane instance, recorded on its own evidence.
  SourceInstanceId instance{};
  /// Fencing epoch of this instance. A higher epoch retires records from lower
  /// epochs of the same instance.
  Epoch epoch{};
  /// Clock used only to stamp derived values when the caller supplies none.
  std::shared_ptr<const Clock> clock;
  std::size_t evidence_capacity = kMaxAcceptedEvidenceRecords;
  bool create_if_missing = true;
  std::uint64_t max_journal_bytes = kDefaultMaxJournalBytes;
  std::size_t max_operations_per_transaction = 256;
  bool exclusive_writer = true;
  /// Compact automatically once the journal exceeds this size.
  std::uint64_t compaction_threshold_bytes = 8ULL * 1024ULL * 1024ULL;
  /// Record every produced plan in the journal. Off by default: a plan is a
  /// proposal, and durably recording proposals is an operator choice.
  bool record_plans = false;
  /// Bound on retained plans when \c record_plans is on.
  std::size_t max_retained_plans = 1024;
};

/// Live counters. Every value is observed, never estimated.
struct RuntimeStatus {
  bool open = false;
  bool durable = false;
  SiteId site{};
  SiteGeneration site_generation{};
  SiteState state = SiteState::Unknown;
  LifecycleState lifecycle = LifecycleState::Commissioning;
  EvidenceClassification classification = EvidenceClassification::Indeterminate;
  std::size_t accepted_evidence = 0;
  std::size_t pending_evidence = 0;
  std::size_t grants = 0;
  JournalSequence journal_sequence{};
  std::uint64_t journal_bytes = 0;
  std::uint64_t commits = 0;
  std::uint64_t committed_operations = 0;
  std::uint64_t rejected_ingests = 0;
  std::uint64_t merged_ingests = 0;
  std::uint64_t plans_produced = 0;
  std::uint64_t plans_denied = 0;
  std::uint64_t compactions = 0;
  std::uint64_t recovered_operations = 0;
  bool recovered = false;
  bool recovered_with_truncation = false;
  bool cancelled = false;
  Digest policy_digest{};
  Digest snapshot_digest{};
};

class SiteControlPlane {
 public:
  /// Opens the runtime, recovering durable state if the directory is non-empty.
  /// Recovery happens before the object is returned, so a caller never observes
  /// a half-recovered runtime.
  [[nodiscard]] static Result<std::unique_ptr<SiteControlPlane>> open(
      const RuntimeOptions& options);

  ~SiteControlPlane();
  SiteControlPlane(const SiteControlPlane&) = delete;
  SiteControlPlane& operator=(const SiteControlPlane&) = delete;
  SiteControlPlane(SiteControlPlane&&) = delete;
  SiteControlPlane& operator=(SiteControlPlane&&) = delete;

  /// Validates and stages evidence. Nothing is durable until \c commit.
  [[nodiscard]] Status ingest(const EvidenceRecord& record);
  [[nodiscard]] Status ingest(std::span<const EvidenceRecord> records);

  /// Discards staged evidence without committing it.
  [[nodiscard]] Status discard_pending();

  /// Composes the staged evidence on top of accepted evidence, without changing
  /// what the runtime publishes. Pure.
  [[nodiscard]] Result<SiteStateSnapshot> preview(Timestamp evaluation_time) const;

  /// Durably commits staged evidence and the composed state, then publishes.
  /// A cancelled runtime fails with Cancelled and publishes nothing.
  [[nodiscard]] Result<CommitOutcome> commit(const CommitOptions& options);

  /// Currently published snapshot. Recomputed on demand from accepted evidence,
  /// so it can never drift from what the journal would replay.
  [[nodiscard]] Result<SiteStateSnapshot> snapshot(Timestamp evaluation_time) const;

  /// Records a delegation grant. Durable immediately when the runtime is
  /// durable, because authority must not be lost on a crash.
  [[nodiscard]] Status record_grant(const DelegationGrant& grant, Timestamp now);

  /// Replaces the site evaluation policy. Durable immediately when durable.
  [[nodiscard]] Status record_policy(const SitePolicy& policy, Timestamp now);

  [[nodiscard]] std::vector<DelegationGrant> grants() const;

  /// Plans an intent. Never mutates lower-domain state and never mutates the site
  /// plane's published state; with \c record_plans it durably records the plan.
  [[nodiscard]] Result<ActionPlan> plan(const PlanRequest& request);

  [[nodiscard]] Result<ExplainReport> explain(Timestamp evaluation_time) const;

  [[nodiscard]] RuntimeStatus status() const;

  /// Requests cancellation. In-flight work observes it at the next publish point
  /// and fails rather than reporting success.
  [[nodiscard]] Status cancel();

  /// Closes the journal and releases the writer lock. Concurrent calls are safe
  /// and idempotent. Further work fails with Closed.
  [[nodiscard]] Status close();

 private:
  struct Impl;
  explicit SiteControlPlane(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

}  // namespace scp
