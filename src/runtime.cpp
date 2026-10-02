// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/runtime.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "platform.hpp"
#include "scp/checked.hpp"
#include "scp/readiness.hpp"
#include "scp/version.hpp"

/// Lock ordering, encoded once and honoured everywhere in this file.
///
///   state_mutex_  (level 1)   ->   journal_mutex_  (level 2)
///
/// A thread may hold the state lock and then take the journal lock, never the
/// reverse. Every public method takes the state lock exactly once at entry, and
/// no method upgrades a shared lock to an exclusive one in place because there
/// are no shared locks here at all. Nothing in this file calls code supplied by
/// a caller, so no callback can re-enter locked state. There are no worker
/// threads, no deferred work and no asynchronous completion, so a stale
/// completion mutating a newer generation is structurally impossible rather
/// than merely avoided; the only concurrency is callers arriving at once.
///
/// Cancellation is observed once, immediately before the durability boundary. A
/// commit that has crossed that boundary has already happened, is reported as
/// successful, and is not cancellable: reporting failure for work that recovery
/// will replay would make the reported outcome and the durable outcome disagree.

namespace scp {

namespace {

/// The runtime's own state, at namespace scope so the file-local helpers below
/// can take it by reference without naming the private nested Impl type.
struct RuntimeCore {
  mutable std::mutex state_mutex;
  std::mutex journal_mutex;

  RuntimeOptions options;
  std::shared_ptr<const Clock> clock;
  std::unique_ptr<Journal> journal;

  std::vector<EvidenceRecord> accepted;
  std::map<EvidenceId, std::size_t> accepted_index;
  std::vector<EvidenceRecord> pending;
  std::vector<DelegationGrant> grants;
  std::vector<ActionPlan> retained_plans;

  /// Generation of the last published picture. Unset means nothing has been
  /// committed yet, so the first commit publishes generation one.
  SiteGeneration generation{};
  JournalSequence journal_sequence{};
  Digest chain_digest{};

  RuntimeStatus status;
  bool cancelled = false;
  bool shutting_down = false;
  bool closed = false;
  std::uint64_t transaction_counter = 0;
};

}  // namespace

struct SiteControlPlane::Impl : RuntimeCore {};

namespace {

/// The generation a read-only composition should report when nothing has been
/// committed yet: the site exists, but no committed revision of its picture does.
SiteGeneration readable_generation(const RuntimeCore& impl) {
  return impl.generation.is_unset() ? SiteGeneration::first() : impl.generation;
}

Result<SiteStateSnapshot> compose_from(const RuntimeCore& impl,
                                       const std::vector<EvidenceRecord>& staged,
                                       Timestamp evaluation_time, SiteGeneration generation) {
  std::vector<EvidenceRecord> combined = impl.accepted;
  combined.insert(combined.end(), staged.begin(), staged.end());
  CompositionOptions options;
  options.site = impl.options.site;
  options.site_generation = generation;
  options.evaluation_time = evaluation_time;
  options.policy = impl.options.policy;
  return compose_site_state(combined, options);
}

Status validate_record(const EvidenceRecord& record) {
  const Status valid = record.validate();
  if (!valid.ok()) {
    return valid;
  }
  const Result<bool> identity = record.verify_identity();
  if (!identity.has_value()) {
    return identity.status();
  }
  if (!identity.value()) {
    return fail(StatusCode::InvalidIdentifier,
                "evidence identity is not the identity its content derives");
  }
  return Status{};
}

bool contains_id(const std::vector<EvidenceRecord>& records, EvidenceId id) {
  return std::any_of(records.begin(), records.end(),
                     [id](const EvidenceRecord& record) { return record.id == id; });
}

TransactionId derive_transaction_id(SiteId site, SiteGeneration generation,
                                    std::uint64_t counter) {
  CanonicalWriter writer;
  writer.text("scp.journal-transaction.v1");
  writer.u64(site.high());
  writer.u64(site.low());
  writer.u64(generation.value());
  writer.u64(counter);
  const Digest digest = Digest::of(writer.span());
  const auto& bytes = digest.bytes();
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    high = (high << 8U) | bytes[index];
    low = (low << 8U) | bytes[index + 8];
  }
  return TransactionId(high, low);
}

void refresh_status(RuntimeCore& impl, const SiteStateSnapshot& snapshot) {
  impl.status.site_generation = impl.generation;
  impl.status.state = snapshot.state;
  impl.status.lifecycle = snapshot.lifecycle;
  impl.status.classification = snapshot.classification;
  impl.status.accepted_evidence = impl.accepted.size();
  impl.status.pending_evidence = impl.pending.size();
  impl.status.grants = impl.grants.size();
  impl.status.journal_sequence = impl.journal_sequence;
  impl.status.snapshot_digest = snapshot.snapshot_digest;
  impl.status.policy_digest = compute_policy_digest(impl.options.policy);
  impl.status.cancelled = impl.cancelled;
  if (impl.journal != nullptr) {
    impl.status.journal_bytes = impl.journal->size_bytes();
  }
}

/// Requires the state lock to be held. Does not take the journal lock itself;
/// the caller decides the durability scope of the operation.
Status journal_operation(RuntimeCore& impl, const JournalOperation& operation,
                         JournalSequence& sequence_out) {
  if (impl.journal == nullptr) {
    return Status{};
  }
  JournalTransaction transaction;
  impl.transaction_counter += 1;
  transaction.id = derive_transaction_id(impl.options.site, impl.generation,
                                         impl.transaction_counter);
  transaction.operations.push_back(operation);

  std::lock_guard<std::mutex> journal_guard(impl.journal_mutex);
  const Result<JournalCommit> committed = impl.journal->commit(transaction);
  if (!committed.has_value()) {
    return committed.status();
  }
  impl.journal_sequence = committed.value().sequence;
  impl.chain_digest = committed.value().commit_frame_digest;
  sequence_out = committed.value().sequence;
  return Status{};
}

}  // namespace

SiteControlPlane::SiteControlPlane(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}

SiteControlPlane::~SiteControlPlane() {
  if (impl_ != nullptr) {
    const Status ignored = close();
    (void)ignored;
  }
}

Result<std::unique_ptr<SiteControlPlane>> SiteControlPlane::open(const RuntimeOptions& options) {
  if (options.site.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "runtime requires a site identity");
  }
  const Status policy_status = options.policy.validate();
  if (!policy_status.ok()) {
    return policy_status;
  }
  if (options.evidence_capacity == 0) {
    return fail(StatusCode::InvalidArgument, "evidence capacity must be at least one");
  }
  if (options.max_operations_per_transaction == 0) {
    return fail(StatusCode::InvalidArgument, "transaction operation bound must be at least one");
  }
  if (options.compaction_threshold_bytes == 0) {
    return fail(StatusCode::InvalidArgument, "compaction threshold must be at least one byte");
  }

  auto impl = std::make_unique<Impl>();
  impl->options = options;
  impl->clock = options.clock != nullptr ? options.clock : std::make_shared<SystemClock>();
  impl->status.site = options.site;
  impl->status.policy_digest = compute_policy_digest(options.policy);
  impl->status.durable = !options.directory.empty();

  if (!options.directory.empty()) {
    const Status directory_status = detail::ensure_directory(options.directory);
    if (!directory_status.ok()) {
      return directory_status;
    }
    JournalOptions journal_options;
    journal_options.directory = options.directory;
    journal_options.site = options.site;
    journal_options.create_if_missing = options.create_if_missing;
    journal_options.max_journal_bytes = options.max_journal_bytes;
    journal_options.max_operations_per_transaction = options.max_operations_per_transaction;
    journal_options.exclusive_writer = options.exclusive_writer;

    Result<Journal> journal = Journal::open(journal_options);
    if (!journal.has_value()) {
      return journal.status();
    }
    impl->journal = std::make_unique<Journal>(std::move(journal.value()));

    const Result<JournalRecoveryReport> recovery = impl->journal->recover();
    if (!recovery.has_value()) {
      return recovery.status();
    }
    const JournalRecoveryReport& report = recovery.value();
    impl->journal_sequence = report.last_sequence;
    impl->chain_digest = report.chain_digest;
    impl->status.recovered = true;
    impl->status.recovered_with_truncation = report.truncated_torn_tail;
    impl->status.recovered_operations = report.replayed_operations;

    if (report.loaded_snapshot) {
      const Result<JournalSnapshot> snapshot = impl->journal->read_snapshot();
      if (!snapshot.has_value()) {
        return snapshot.status();
      }
      impl->generation = snapshot.value().site_generation;
      impl->grants = snapshot.value().grants;
      impl->options.policy = snapshot.value().policy;
      for (const EvidenceRecord& record : snapshot.value().evidence) {
        EvidenceRecord recovered = record;
        recovered.origin = EvidenceOrigin::RecoveredFromJournal;
        if (impl->accepted_index.count(recovered.id) == 0U) {
          impl->accepted_index.emplace(recovered.id, impl->accepted.size());
          impl->accepted.push_back(std::move(recovered));
        }
      }
    }

    for (const JournalOperation& operation : report.operations) {
      switch (operation.kind) {
        case OperationKind::IngestEvidence: {
          EvidenceRecord record = operation.evidence;
          record.origin = EvidenceOrigin::RecoveredFromJournal;
          if (impl->accepted_index.count(record.id) == 0U) {
            impl->accepted_index.emplace(record.id, impl->accepted.size());
            impl->accepted.push_back(std::move(record));
          }
          break;
        }
        case OperationKind::RetireEvidence: {
          const auto found = impl->accepted_index.find(operation.evidence.id);
          if (found != impl->accepted_index.end()) {
            impl->accepted.erase(impl->accepted.begin() +
                                 static_cast<std::ptrdiff_t>(found->second));
            impl->accepted_index.clear();
            for (std::size_t index = 0; index < impl->accepted.size(); ++index) {
              impl->accepted_index.emplace(impl->accepted[index].id, index);
            }
          }
          break;
        }
        case OperationKind::AdvanceSiteGeneration:
          impl->generation = operation.site_generation;
          break;
        case OperationKind::RecordGrant:
          impl->grants.push_back(operation.grant);
          break;
        case OperationKind::RecordPolicy:
          impl->options.policy = operation.policy;
          break;
        case OperationKind::RecordPlan:
          impl->retained_plans.push_back(operation.plan);
          break;
      }
    }
  }

  const Timestamp now = impl->clock->now();
  const Result<SiteStateSnapshot> snapshot =
      compose_from(*impl, {}, now, readable_generation(*impl));
  if (!snapshot.has_value()) {
    return snapshot.status();
  }
  impl->status.open = true;
  refresh_status(*impl, snapshot.value());
  return std::unique_ptr<SiteControlPlane>(new SiteControlPlane(std::move(impl)));
}

Status SiteControlPlane::ingest(const EvidenceRecord& record) {
  return ingest(std::span<const EvidenceRecord>(&record, 1));
}

Status SiteControlPlane::ingest(std::span<const EvidenceRecord> records) {
  if (records.empty()) {
    return fail(StatusCode::InvalidArgument, "ingest requires at least one record");
  }
  if (records.size() > kMaxEvidenceRecordsPerIngest) {
    return fail(StatusCode::LimitExceeded,
                "ingest batch carries " + std::to_string(records.size()) +
                    " records, above the bound of " +
                    std::to_string(kMaxEvidenceRecordsPerIngest));
  }
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  if (impl_->shutting_down) {
    return fail(StatusCode::ShuttingDown, "the runtime is shutting down");
  }
  if (impl_->cancelled) {
    return fail(StatusCode::Cancelled, "the runtime was cancelled");
  }
  for (const EvidenceRecord& record : records) {
    const Status valid = validate_record(record);
    if (!valid.ok()) {
      impl_->status.rejected_ingests += 1;
      return valid;
    }
    if (impl_->accepted_index.count(record.id) != 0U || contains_id(impl_->pending, record.id)) {
      // Publishing exactly what is already known is a no-op rather than an
      // error: evidence identity is content-addressed, so an identical
      // publication is the same fact and merging it changes nothing.
      impl_->status.merged_ingests += 1;
      continue;
    }
    if (impl_->accepted.size() + impl_->pending.size() >= impl_->options.evidence_capacity) {
      return fail(StatusCode::CapacityExhausted,
                  "the accepted evidence set is at its configured capacity of " +
                      std::to_string(impl_->options.evidence_capacity) +
                      "; retire evidence or raise the bound deliberately");
    }
    impl_->pending.push_back(record);
  }
  impl_->status.pending_evidence = impl_->pending.size();
  return Status{};
}

Status SiteControlPlane::discard_pending() {
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  impl_->pending.clear();
  impl_->status.pending_evidence = 0;
  return Status{};
}

Result<SiteStateSnapshot> SiteControlPlane::preview(Timestamp evaluation_time) const {
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  const Timestamp instant = evaluation_time.is_set() ? evaluation_time : impl_->clock->now();
  return compose_from(*impl_, impl_->pending, instant, readable_generation(*impl_));
}

Result<SiteStateSnapshot> SiteControlPlane::snapshot(Timestamp evaluation_time) const {
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  const Timestamp instant = evaluation_time.is_set() ? evaluation_time : impl_->clock->now();
  return compose_from(*impl_, {}, instant, readable_generation(*impl_));
}

Result<CommitOutcome> SiteControlPlane::commit(const CommitOptions& options) {
  std::unique_lock<std::mutex> state_guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  if (impl_->shutting_down) {
    return fail(StatusCode::ShuttingDown, "the runtime is shutting down");
  }
  if (impl_->cancelled) {
    return fail(StatusCode::Cancelled,
                "the runtime was cancelled; cancelled work does not report success");
  }
  if (!options.now.is_set()) {
    return fail(StatusCode::InvalidArgument, "commit requires an evaluation instant");
  }

  SiteGeneration next_generation = impl_->generation;
  if (options.advance_generation) {
    if (impl_->generation.is_unset()) {
      // Nothing has been committed yet, so this commit publishes generation one
      // rather than skipping it.
      next_generation = SiteGeneration::first();
    } else {
      const Result<SiteGeneration> advanced = impl_->generation.next();
      if (!advanced.has_value()) {
        return advanced.status();
      }
      next_generation = advanced.value();
    }
  }

  const Result<SiteStateSnapshot> composed =
      compose_from(*impl_, impl_->pending, options.now, next_generation);
  if (!composed.has_value()) {
    return composed.status();
  }

  CommitOutcome outcome;
  outcome.site_generation = next_generation;
  outcome.state = composed.value().state;
  outcome.classification = composed.value().classification;
  outcome.snapshot_digest = composed.value().snapshot_digest;
  outcome.operations = impl_->pending.size() + (options.advance_generation ? 1U : 0U);
  outcome.durability_boundary =
      impl_->journal == nullptr
          ? "in-memory runtime: no durable boundary exists and none is claimed"
          : "not yet committed";

  // Cancellation is observed here, before the durability boundary. After this
  // point the transaction either commits and is published, or fails and is not.
  if (impl_->cancelled) {
    return fail(StatusCode::Cancelled,
                "the runtime was cancelled before the durability boundary; nothing was committed");
  }

  if (impl_->journal != nullptr) {
    JournalTransaction transaction;
    impl_->transaction_counter += 1;
    transaction.id = derive_transaction_id(impl_->options.site, next_generation,
                                           impl_->transaction_counter);
    for (const EvidenceRecord& record : impl_->pending) {
      JournalOperation operation;
      operation.kind = OperationKind::IngestEvidence;
      operation.evidence = record;
      transaction.operations.push_back(std::move(operation));
    }
    if (options.advance_generation) {
      JournalOperation operation;
      operation.kind = OperationKind::AdvanceSiteGeneration;
      operation.site_generation = next_generation;
      transaction.operations.push_back(std::move(operation));
    }
    if (transaction.operations.size() > impl_->options.max_operations_per_transaction) {
      return fail(StatusCode::LimitExceeded,
                  "this commit carries " + std::to_string(transaction.operations.size()) +
                      " operations, above the configured transaction bound of " +
                      std::to_string(impl_->options.max_operations_per_transaction));
    }

    {
      std::lock_guard<std::mutex> journal_guard(impl_->journal_mutex);
      const Result<JournalCommit> committed = impl_->journal->commit(transaction);
      if (!committed.has_value()) {
        return committed.status();
      }
      impl_->journal_sequence = committed.value().sequence;
      impl_->chain_digest = committed.value().commit_frame_digest;
      outcome.journal_sequence = committed.value().sequence;
      outcome.transaction_bytes = committed.value().bytes_written;
      outcome.durability_boundary = committed.value().durability_boundary;
    }
  }

  // Publish authoritative state. Everything above this line is intent; this is
  // the point at which the runtime's own answer changes.
  for (const EvidenceRecord& record : impl_->pending) {
    if (impl_->accepted_index.count(record.id) == 0U) {
      impl_->accepted_index.emplace(record.id, impl_->accepted.size());
      impl_->accepted.push_back(record);
    }
  }
  impl_->pending.clear();
  impl_->generation = next_generation;
  impl_->status.commits += 1;
  impl_->status.committed_operations += outcome.operations;

  if (impl_->journal != nullptr && options.allow_compaction &&
      impl_->journal->size_bytes() > impl_->options.compaction_threshold_bytes) {
    const std::uint64_t before = impl_->journal->size_bytes();
    JournalSnapshot snapshot;
    snapshot.site = impl_->options.site;
    snapshot.site_generation = impl_->generation;
    snapshot.sequence = impl_->journal_sequence;
    snapshot.created_at = options.now;
    snapshot.chain_digest = impl_->journal->chain_digest();
    snapshot.evidence = impl_->accepted;
    snapshot.grants = impl_->grants;
    snapshot.policy = impl_->options.policy;
    std::lock_guard<std::mutex> journal_guard(impl_->journal_mutex);
    const Result<CompactionReport> report = impl_->journal->compact(snapshot);
    if (report.has_value()) {
      impl_->status.compactions += 1;
      outcome.compacted = true;
      outcome.compaction_bytes_reclaimed =
          before > report.value().bytes_after ? before - report.value().bytes_after : 0U;
    } else {
      // Compaction is an optimization. A failed compaction leaves the journal
      // intact and the commit valid, so it is reported rather than escalated.
      outcome.compacted = false;
    }
  }

  outcome.committed = true;
  refresh_status(*impl_, composed.value());
  return outcome;
}

Status SiteControlPlane::record_grant(const DelegationGrant& grant, Timestamp now) {
  const Status valid = grant.validate();
  if (!valid.ok()) {
    return valid;
  }
  if (!(grant.site == impl_->options.site)) {
    return fail(StatusCode::Conflict, "the grant names a different site than this runtime");
  }
  if (!now.is_set()) {
    return fail(StatusCode::InvalidArgument, "recording a grant requires an instant");
  }
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  const bool duplicate =
      std::any_of(impl_->grants.begin(), impl_->grants.end(),
                  [&grant](const DelegationGrant& existing) { return existing.id == grant.id; });
  if (duplicate) {
    return fail(StatusCode::AlreadyExists,
                "grant " + grant.id.to_hex() + " is already recorded");
  }
  JournalOperation operation;
  operation.kind = OperationKind::RecordGrant;
  operation.grant = grant;
  JournalSequence sequence;
  SCP_TRY(journal_operation(*impl_, operation, sequence));
  impl_->grants.push_back(grant);
  impl_->status.grants = impl_->grants.size();
  return Status{};
}

Status SiteControlPlane::record_policy(const SitePolicy& policy, Timestamp now) {
  const Status valid = policy.validate();
  if (!valid.ok()) {
    return valid;
  }
  if (!now.is_set()) {
    return fail(StatusCode::InvalidArgument, "recording a policy requires an instant");
  }
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  JournalOperation operation;
  operation.kind = OperationKind::RecordPolicy;
  operation.policy = policy;
  JournalSequence sequence;
  SCP_TRY(journal_operation(*impl_, operation, sequence));
  impl_->options.policy = policy;
  impl_->status.policy_digest = compute_policy_digest(policy);
  return Status{};
}

std::vector<DelegationGrant> SiteControlPlane::grants() const {
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  return impl_->grants;
}

Result<ActionPlan> SiteControlPlane::plan(const PlanRequest& request) {
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  if (impl_->cancelled) {
    return fail(StatusCode::Cancelled, "the runtime was cancelled");
  }
  const Result<SiteStateSnapshot> snapshot =
      compose_from(*impl_, {}, request.now, readable_generation(*impl_));
  if (!snapshot.has_value()) {
    return snapshot.status();
  }
  PlanRequest effective = request;
  if (effective.site.is_nil()) {
    effective.site = impl_->options.site;
  }
  if (effective.site_generation.is_unset()) {
    effective.site_generation = readable_generation(*impl_);
  }
  if (!effective.now.is_set()) {
    effective.now = impl_->clock->now();
  }
  const Result<ActionPlan> planned =
      plan_intent(effective, snapshot.value(), impl_->options.policy, impl_->grants);
  if (!planned.has_value()) {
    return planned.status();
  }
  impl_->status.plans_produced += 1;
  if (!planned.value().permitted) {
    impl_->status.plans_denied += 1;
  } else if (impl_->options.record_plans && impl_->journal != nullptr) {
    JournalOperation operation;
    operation.kind = OperationKind::RecordPlan;
    operation.plan = planned.value();
    JournalSequence sequence;
    SCP_TRY(journal_operation(*impl_, operation, sequence));
    impl_->retained_plans.push_back(planned.value());
    while (impl_->retained_plans.size() > impl_->options.max_retained_plans) {
      impl_->retained_plans.erase(impl_->retained_plans.begin());
    }
  }
  return planned.value();
}

Result<ExplainReport> SiteControlPlane::explain(Timestamp evaluation_time) const {
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  const Timestamp instant = evaluation_time.is_set() ? evaluation_time : impl_->clock->now();
  const Result<SiteStateSnapshot> snapshot = compose_from(*impl_, {}, instant, readable_generation(*impl_));
  if (!snapshot.has_value()) {
    return snapshot.status();
  }
  ExplainReport report = explain_snapshot(snapshot.value(), impl_->options.policy);
  if (impl_->journal != nullptr) {
    report.notes.push_back("durable journal position " +
                           std::to_string(impl_->journal_sequence.value()) + ", " +
                           std::to_string(impl_->status.journal_bytes) + " bytes");
    if (impl_->status.recovered_with_truncation) {
      report.notes.push_back(
          "this runtime recovered by removing an incomplete trailing journal frame; the removed "
          "bytes were never part of a committed transaction");
    }
  } else {
    report.notes.push_back("in-memory runtime: site-level authority is not durable");
  }
  return report;
}

RuntimeStatus SiteControlPlane::status() const {
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  RuntimeStatus copy = impl_->status;
  copy.open = !impl_->closed && impl_->status.open;
  if (impl_->journal != nullptr) {
    copy.journal_bytes = impl_->journal->size_bytes();
    copy.journal_sequence = impl_->journal_sequence;
  }
  copy.accepted_evidence = impl_->accepted.size();
  copy.pending_evidence = impl_->pending.size();
  return copy;
}

Status SiteControlPlane::cancel() {
  std::lock_guard<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return fail(StatusCode::Closed, "the runtime is closed");
  }
  impl_->cancelled = true;
  impl_->status.cancelled = true;
  // Staged but uncommitted work is discarded: cancelled work must not be able to
  // report success later.
  impl_->pending.clear();
  impl_->status.pending_evidence = 0;
  return Status{};
}

Status SiteControlPlane::close() {
  std::unique_lock<std::mutex> guard(impl_->state_mutex);
  if (impl_->closed) {
    return Status{};
  }
  impl_->shutting_down = true;
  Status result;
  if (impl_->journal != nullptr) {
    std::lock_guard<std::mutex> journal_guard(impl_->journal_mutex);
    result = impl_->journal->close();
    impl_->journal.reset();
  }
  impl_->closed = true;
  impl_->status.open = false;
  return result;
}

}  // namespace scp
