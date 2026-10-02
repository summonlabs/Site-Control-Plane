// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/policy.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/time.hpp"

/// \file composition.hpp
/// The deterministic site-state composition engine.
///
/// Composition is a pure function: evidence in, snapshot out. It performs no
/// I/O, reads no clock, allocates no threads and mutates nothing. All freshness
/// decisions come from the caller-supplied evaluation instant.
///
/// Ordering guarantee: the engine first reduces evidence to one resolution per
/// (authority, kind) slot using a total order over generation, sequence and
/// content digest. Arrival order is not part of that order, so any permutation of
/// an equivalent evidence set composes to an identical snapshot digest. This is
/// the property the repository's order-independence proof rests on.

namespace scp {

/// Options for one composition pass. \c policy is captured by value so a caller
/// cannot change thresholds underneath a pass in flight.
struct CompositionOptions {
  SiteId site{};
  SiteGeneration site_generation{};
  /// Instant at which freshness is judged. Required.
  Timestamp evaluation_time{};
  /// Reported composition instant. When unset it defaults to \c evaluation_time
  /// so that a pure call has a deterministic value.
  Timestamp composed_at{};
  SitePolicy policy{};
};

/// Outcome of reducing a raw evidence set.
///
/// The buckets below are an exact partition of the *distinct identities* in the
/// input: every identity lands in exactly one of accepted, superseded,
/// conflicting, redundant or rejected, and the sum of their sizes equals the
/// number of distinct input identities. Records that repeat an identity already
/// present are counted in \c duplicates_merged instead, because they are not
/// distinct facts.
struct ReductionResult {
  /// One entry per observed slot, in canonical (authority, kind) order.
  std::vector<SlotResolution> slots;
  /// Winning records, in canonical slot order, for the slots that produced one.
  std::vector<EvidenceRecord> accepted;
  /// Records that could not participate at all: from a publisher that does not
  /// own the kind, written with a schema this build cannot read, or structurally
  /// invalid. Preserved so their existence is reportable.
  std::vector<EvidenceRecord> rejected;
  /// Readable records that lost to a newer (epoch, generation, sequence).
  std::vector<EvidenceRecord> superseded;
  /// Readable records that tie at the newest position with differing content.
  std::vector<EvidenceRecord> conflicting;
  /// Readable records that tie at the newest position with identical content but
  /// a different publisher instance: the same logical fact stated twice.
  std::vector<EvidenceRecord> redundant;
  /// Records that repeated an identity already present in the batch.
  std::size_t duplicates_merged = 0;
  std::size_t redundant_count = 0;
  std::size_t conflict_count = 0;
  std::size_t unauthorized_count = 0;
  std::size_t unsupported_count = 0;

  /// Distinct identities accounted for by the five buckets.
  [[nodiscard]] std::size_t accounted() const noexcept {
    return accepted.size() + rejected.size() + superseded.size() + conflicting.size() +
           redundant.size();
  }
};

/// Reduces evidence records to one resolution per slot.
///
/// Deterministic rules, applied identically for every slot:
///   1. Records whose publisher does not own the kind are rejected.
///   2. Records whose schema this build cannot read are reported unsupported.
///   3. Records failing structural validation are rejected.
///   4. Among the remainder the winner is the record with the greatest
///      (source generation, sequence); ties are broken by content digest order.
///   5. If two distinct digests tie at the greatest (generation, sequence) the
///      slot is Conflicting. Arrival order never picks a winner.
///   6. Every other record at a lower (generation, sequence) is Superseded, and
///      exact duplicates (same derived identity) are merged, not counted twice.
[[nodiscard]] Result<ReductionResult> reduce_evidence(std::span<const EvidenceRecord> records,
                                                      const SitePolicy& policy,
                                                      Timestamp evaluation_time);

/// Composes a snapshot from raw evidence. Pure; safe to call concurrently.
[[nodiscard]] Result<SiteStateSnapshot> compose_site_state(std::span<const EvidenceRecord> records,
                                                           const CompositionOptions& options);

/// Composes a snapshot from an already reduced evidence set.
[[nodiscard]] Result<SiteStateSnapshot> compose_site_state(const ReductionResult& reduction,
                                                           const CompositionOptions& options);

/// A bounded, de-duplicating set of accepted evidence.
///
/// The set is the in-memory authority of "what this site plane currently
/// believes", before any durable commit. It keeps every generation of every slot
/// that was accepted, so superseded truth stays reportable.
class EvidenceSet {
 public:
  explicit EvidenceSet(std::size_t capacity = kMaxAcceptedEvidenceRecords);

  /// Inserts or merges a record. Returns true when the set changed.
  /// Exact duplicates are merged and report \c AlreadyExists.
  [[nodiscard]] Result<bool> insert(const EvidenceRecord& record);

  [[nodiscard]] std::size_t size() const noexcept { return records_.size(); }
  [[nodiscard]] bool empty() const noexcept { return records_.empty(); }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] const std::vector<EvidenceRecord>& records() const noexcept { return records_; }

  [[nodiscard]] bool contains(EvidenceId id) const noexcept;
  [[nodiscard]] const EvidenceRecord* find(EvidenceId id) const noexcept;

  void clear() noexcept { records_.clear(); }

 private:
  std::vector<EvidenceRecord> records_;
  std::size_t capacity_;
};

void canonical_write(CanonicalWriter& writer, const ReductionResult& value);

}  // namespace scp
