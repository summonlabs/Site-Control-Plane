// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/composition.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/policy.hpp"
#include "scp/runtime.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/time.hpp"
#include "test_support.hpp"

/// \file test_composition_determinism.cpp
/// The order-independence proof for the composition engine.
///
/// One evidence set, many arrival orders, one answer. Every check in this file is
/// stated over observable outputs (the snapshot, its digests and its canonical
/// bytes), never over the reducer's internals.

namespace {

using scp::EvidenceKind;
using scp::EvidenceRecord;
using scp::Result;
using scp::SiteStateSnapshot;
using scp::SlotResolution;
using scp::SourceAuthority;
using scp::Timestamp;

/// Deterministic 64-bit generator. Nothing here reads a clock or a device.
class SplitMix64 {
 public:
  explicit SplitMix64(std::uint64_t seed) noexcept : state_(seed) {}

  std::uint64_t next() noexcept {
    state_ += 0x9E3779B97F4A7C15ULL;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31U);
  }

  /// Uniform enough for permutation generation; never used for a decision.
  std::uint64_t below(std::uint64_t bound) noexcept {
    return bound == 0 ? 0 : next() % bound;
  }

 private:
  std::uint64_t state_;
};

using Permutation = std::vector<std::size_t>;

Permutation identity_permutation(std::size_t count) {
  Permutation permutation(count);
  std::iota(permutation.begin(), permutation.end(), std::size_t{0});
  return permutation;
}

Permutation shuffled(const Permutation& source, std::uint64_t seed) {
  Permutation permutation = source;
  SplitMix64 generator(seed);
  if (permutation.size() > 1) {
    for (std::size_t index = permutation.size() - 1; index > 0; --index) {
      const std::size_t other = static_cast<std::size_t>(generator.below(
          static_cast<std::uint64_t>(index) + 1ULL));
      std::swap(permutation[index], permutation[other]);
    }
  }
  return permutation;
}

Permutation interleaved(const Permutation& first, const Permutation& second) {
  Permutation merged;
  merged.reserve(first.size() + second.size());
  std::size_t index = 0;
  while (index < first.size() || index < second.size()) {
    if (index < first.size()) {
      merged.push_back(first[index]);
    }
    if (index < second.size()) {
      merged.push_back(second[index]);
    }
    ++index;
  }
  return merged;
}

/// Identity, reverse, seeded shuffles, every rotation, and interleavings of the
/// two halves: enough distinct arrival orders that a reducer which consulted
/// arrival order could not survive all of them.
std::vector<Permutation> all_orderings(std::size_t count, std::uint64_t seed) {
  const Permutation base = identity_permutation(count);
  std::vector<Permutation> orderings;
  orderings.push_back(base);
  Permutation reversed = base;
  std::reverse(reversed.begin(), reversed.end());
  orderings.push_back(reversed);
  for (std::uint64_t round = 0; round < 8; ++round) {
    orderings.push_back(shuffled(base, seed + round * 0x9E3779B9ULL));
  }
  for (std::size_t rotation = 1; rotation < count; ++rotation) {
    Permutation rotated = base;
    std::rotate(rotated.begin(), rotated.begin() + static_cast<std::ptrdiff_t>(rotation),
                rotated.end());
    orderings.push_back(rotated);
  }
  const std::size_t half = count / 2;
  const Permutation first_half(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(half));
  const Permutation second_half(base.begin() + static_cast<std::ptrdiff_t>(half), base.end());
  Permutation reversed_second = second_half;
  std::reverse(reversed_second.begin(), reversed_second.end());
  orderings.push_back(interleaved(first_half, second_half));
  orderings.push_back(interleaved(second_half, first_half));
  orderings.push_back(interleaved(first_half, reversed_second));
  orderings.push_back(interleaved(reversed_second, first_half));
  return orderings;
}

std::vector<EvidenceRecord> materialize(const std::vector<EvidenceRecord>& records,
                                        const Permutation& order) {
  std::vector<EvidenceRecord> ordered;
  ordered.reserve(order.size());
  for (const std::size_t index : order) {
    ordered.push_back(records[index]);
  }
  return ordered;
}

void append(std::vector<EvidenceRecord>& into, const std::vector<EvidenceRecord>& extra) {
  into.insert(into.end(), extra.begin(), extra.end());
}

scp::CompositionOptions options_for(Timestamp evaluation_time, std::uint64_t site_generation = 1,
                                    scp::SitePolicy policy = scp_test::strict_policy()) {
  scp::CompositionOptions options;
  options.site = scp_test::default_site();
  options.site_generation = scp::SiteGeneration(site_generation);
  options.evaluation_time = evaluation_time;
  options.policy = policy;
  return options;
}

std::vector<std::uint8_t> canonical_bytes(const SiteStateSnapshot& snapshot) {
  scp::CanonicalWriter writer;
  scp::canonical_write(writer, snapshot);
  return writer.take();
}

/// Every field that decides what a slot resolved to. Two snapshots over
/// equivalent evidence must agree on all of them. The duplicate counter is
/// optional because it reports how many redundant copies arrived rather than
/// what the slot resolved to.
std::vector<std::string> compare_slots(const SiteStateSnapshot& lhs, const SiteStateSnapshot& rhs,
                                       bool include_duplicates = true) {
  std::vector<std::string> differences;
  if (lhs.slots.size() != rhs.slots.size()) {
    differences.push_back("slot count " + std::to_string(lhs.slots.size()) + " != " +
                          std::to_string(rhs.slots.size()));
    return differences;
  }
  for (std::size_t index = 0; index < lhs.slots.size(); ++index) {
    const SlotResolution& left = lhs.slots[index];
    const SlotResolution& right = rhs.slots[index];
    std::string fields;
    if (!(left.slot == right.slot)) {
      fields += " slot";
    }
    if (left.outcome != right.outcome) {
      fields += " outcome";
    }
    if (!(left.accepted_id == right.accepted_id)) {
      fields += " accepted_id";
    }
    if (!(left.accepted_digest == right.accepted_digest)) {
      fields += " accepted_digest";
    }
    if (!(left.accepted_instance == right.accepted_instance)) {
      fields += " accepted_instance";
    }
    if (!(left.accepted_epoch == right.accepted_epoch)) {
      fields += " accepted_epoch";
    }
    if (!(left.accepted_generation == right.accepted_generation)) {
      fields += " accepted_generation";
    }
    if (!(left.accepted_sequence == right.accepted_sequence)) {
      fields += " accepted_sequence";
    }
    if (left.freshness != right.freshness) {
      fields += " freshness";
    }
    if (left.origin != right.origin) {
      fields += " origin";
    }
    if (left.superseded != right.superseded) {
      fields += " superseded";
    }
    if (left.conflicting != right.conflicting) {
      fields += " conflicting";
    }
    if (include_duplicates && left.duplicates_merged != right.duplicates_merged) {
      fields += " duplicates_merged";
    }
    if (!fields.empty()) {
      differences.push_back("slot[" + std::to_string(index) + "] " +
                            std::string(scp::to_string(left.slot.kind)) + ":" + fields);
    }
  }
  return differences;
}

void note_order_difference(std::size_t ordering_index, const std::string& detail) {
  scp_test::Context::instance().note("ordering #" + std::to_string(ordering_index) + ": " + detail);
}

Result<EvidenceRecord> capacity_record(std::uint64_t epoch, std::uint64_t generation,
                                       std::uint64_t sequence, std::uint64_t instance,
                                       Timestamp issued_at, std::uint64_t available_units) {
  scp_test::RecordSpec spec;
  spec.authority = SourceAuthority::FacilityCapacity;
  spec.instance = instance;
  spec.epoch = epoch;
  spec.generation = generation;
  spec.sequence = sequence;
  spec.issued_at = issued_at;
  scp::CapacityEvidence body;
  body.snapshot = scp::SnapshotId(0xC0FFEE0000000001ULL, 0x0000000000000001ULL);
  body.generation = scp::CapacityGeneration(generation);
  body.total_units = 100;
  body.committed_units = 0;
  body.available_units = available_units;
  body.oversubscribed = false;
  return scp_test::make_capacity(spec, body);
}

Result<EvidenceRecord> capacity_record_with_schema(std::uint16_t schema_version,
                                                   std::uint64_t generation, std::uint64_t instance,
                                                   Timestamp issued_at,
                                                   std::uint64_t available_units) {
  scp::Provenance provenance;
  provenance.authority = SourceAuthority::FacilityCapacity;
  provenance.instance = scp_test::instance_for(instance);
  provenance.epoch = scp::Epoch(1);
  provenance.generation = scp::SourceGeneration(generation);
  provenance.sequence = scp::Sequence(1);
  provenance.issued_at = issued_at;
  scp::CapacityEvidence body;
  body.snapshot = scp::SnapshotId(0xC0FFEE0000000001ULL, 0x0000000000000001ULL);
  body.generation = scp::CapacityGeneration(generation);
  body.total_units = 100;
  body.committed_units = 0;
  body.available_units = available_units;
  body.oversubscribed = false;
  const Result<std::vector<std::uint8_t>> encoded = scp::encode_body(scp::EvidenceBody{body});
  if (!encoded.has_value()) {
    return encoded.status();
  }
  return EvidenceRecord::create(provenance, EvidenceKind::Capacity, schema_version,
                                encoded.value());
}

const SlotResolution* resolve_slot(const SiteStateSnapshot& snapshot, EvidenceKind kind) {
  const scp::EvidenceSlot wanted{scp::owner_of(kind), kind};
  for (const SlotResolution& resolution : snapshot.slots) {
    if (resolution.slot == wanted) {
      return &resolution;
    }
  }
  return nullptr;
}

}  // namespace

SCP_TEST(order_independence_of_the_composed_snapshot) {
  const Timestamp evaluation = scp_test::base_instant();

  // Three generations of a healthy site, so every slot holds more than one
  // publication and supersession is exercised for all of them.
  std::vector<EvidenceRecord> records = scp_test::healthy_site_records(evaluation, 7);
  append(records, scp_test::healthy_site_records(evaluation, 4));
  append(records, scp_test::healthy_site_records(evaluation, 2));
  SCP_CHECK_EQ(records.size(), 3 * scp::kEvidenceKindCount);

  const Result<SiteStateSnapshot> composed =
      scp::compose_site_state(records, options_for(evaluation));
  SCP_REQUIRE_OK(composed);
  const SiteStateSnapshot reference = composed.value();

  // The fixture itself must be non-degenerate: every slot filled by the newest
  // generation, with two older publications recorded as superseded.
  SCP_CHECK_EQ(reference.slots.size(), scp::kEvidenceKindCount);
  SCP_CHECK_EQ(reference.state, scp::SiteState::Available);
  SCP_CHECK_EQ(reference.classification, scp::EvidenceClassification::Complete);
  SCP_CHECK_EQ(reference.lifecycle, scp::LifecycleState::Active);
  SCP_CHECK_EQ(reference.readiness_percent, 100U);
  SCP_CHECK_EQ(reference.constraints.size(), std::size_t{0});
  SCP_CHECK_EQ(reference.obligations.size(), std::size_t{1});
  std::size_t superseding_slots = 0;
  std::size_t superseded_total = 0;
  for (const SlotResolution& resolution : reference.slots) {
    if (resolution.outcome == scp::SlotOutcome::AcceptedSuperseding) {
      ++superseding_slots;
    }
    superseded_total += resolution.superseded.size();
    SCP_CHECK_EQ(resolution.accepted_generation.value(), 7ULL);
  }
  SCP_CHECK_EQ(superseding_slots, scp::kEvidenceKindCount);
  SCP_CHECK_EQ(superseded_total, 2 * scp::kEvidenceKindCount);

  const std::vector<Permutation> orderings =
      all_orderings(records.size(), 0x9E3779B97F4A7C15ULL);
  SCP_CHECK(orderings.size() >= 40);
  for (std::size_t index = 0; index < orderings.size(); ++index) {
    const std::vector<EvidenceRecord> permuted = materialize(records, orderings[index]);
    const Result<SiteStateSnapshot> candidate_result =
        scp::compose_site_state(permuted, options_for(evaluation));
    if (!candidate_result.has_value()) {
      note_order_difference(index, "composition failed: " + candidate_result.status().to_string());
      SCP_CHECK(false);
      continue;
    }
    const SiteStateSnapshot& candidate = candidate_result.value();
    SCP_CHECK_EQ(candidate.snapshot_digest, reference.snapshot_digest);
    SCP_CHECK_EQ(candidate.evidence_digest, reference.evidence_digest);
    SCP_CHECK_EQ(candidate.state, reference.state);
    SCP_CHECK_EQ(candidate.classification, reference.classification);
    SCP_CHECK_EQ(candidate.lifecycle, reference.lifecycle);
    SCP_CHECK_EQ(candidate.readiness_percent, reference.readiness_percent);
    SCP_CHECK_EQ(candidate.slots.size(), reference.slots.size());
    SCP_CHECK_EQ(candidate.constraints.size(), reference.constraints.size());
    SCP_CHECK_EQ(candidate.obligations.size(), reference.obligations.size());
    const std::vector<std::string> slot_differences = compare_slots(candidate, reference);
    for (const std::string& difference : slot_differences) {
      note_order_difference(index, difference);
    }
    SCP_CHECK(slot_differences.empty());
  }
}

SCP_TEST(accepted_set_is_reported_identically_for_every_ordering) {
  const Timestamp evaluation = scp_test::base_instant();
  std::vector<EvidenceRecord> records = scp_test::healthy_site_records(evaluation, 6);
  append(records, scp_test::healthy_site_records(evaluation, 3));

  const Result<SiteStateSnapshot> forward_result =
      scp::compose_site_state(records, options_for(evaluation));
  SCP_REQUIRE_OK(forward_result);
  const SiteStateSnapshot& forward = forward_result.value();

  std::vector<EvidenceRecord> reversed = records;
  std::reverse(reversed.begin(), reversed.end());
  const Result<SiteStateSnapshot> backward_result =
      scp::compose_site_state(reversed, options_for(evaluation));
  SCP_REQUIRE_OK(backward_result);
  const SiteStateSnapshot& backward = backward_result.value();

  SCP_CHECK_EQ(forward.slots.size(), scp::kEvidenceKindCount);
  for (std::size_t index = 0; index < forward.slots.size(); ++index) {
    const SlotResolution& left = forward.slots[index];
    const SlotResolution& right = backward.slots[index];
    SCP_CHECK(left.slot == right.slot);
    SCP_CHECK_EQ(left.accepted_id, right.accepted_id);
    SCP_CHECK_EQ(left.accepted_generation, right.accepted_generation);
    SCP_CHECK_EQ(left.accepted_sequence, right.accepted_sequence);
    SCP_CHECK_EQ(left.accepted_epoch, right.accepted_epoch);
    SCP_CHECK_EQ(left.accepted_instance, right.accepted_instance);
    SCP_CHECK_EQ(left.accepted_digest, right.accepted_digest);
    SCP_CHECK_EQ(left.outcome, right.outcome);
    SCP_CHECK_EQ(left.superseded, right.superseded);
    SCP_CHECK_EQ(left.conflicting, right.conflicting);
    // The slot that lost is still named: the accepted identity came from the
    // newest generation, and the older one is listed rather than dropped.
    SCP_CHECK_EQ(left.accepted_generation.value(), 6ULL);
    SCP_CHECK_EQ(left.superseded.size(), std::size_t{1});
    SCP_CHECK_EQ(left.outcome, scp::SlotOutcome::AcceptedSuperseding);
  }
  SCP_CHECK_EQ(forward.snapshot_digest, backward.snapshot_digest);
  SCP_CHECK_EQ(forward.evidence_digest, backward.evidence_digest);
}

SCP_TEST(duplicate_records_merge_and_change_nothing) {
  const Timestamp evaluation = scp_test::base_instant();
  std::vector<EvidenceRecord> records = scp_test::healthy_site_records(evaluation, 5);
  append(records, scp_test::healthy_site_records(evaluation, 2));

  const Result<scp::ReductionResult> base_reduction =
      scp::reduce_evidence(records, scp_test::strict_policy(), evaluation);
  SCP_REQUIRE_OK(base_reduction);
  SCP_CHECK_EQ(base_reduction.value().duplicates_merged, std::size_t{0});

  const Result<SiteStateSnapshot> base_snapshot_result =
      scp::compose_site_state(records, options_for(evaluation));
  SCP_REQUIRE_OK(base_snapshot_result);
  const SiteStateSnapshot& base_snapshot = base_snapshot_result.value();

  // Every third record, inserted a second time.
  std::vector<EvidenceRecord> duplicated = records;
  std::size_t injected = 0;
  for (std::size_t index = 0; index < records.size(); index += 3) {
    duplicated.push_back(records[index]);
    ++injected;
  }
  SCP_CHECK_EQ(injected, std::size_t{8});
  SCP_CHECK_EQ(duplicated.size(), records.size() + injected);

  const Result<scp::ReductionResult> duplicated_reduction =
      scp::reduce_evidence(duplicated, scp_test::strict_policy(), evaluation);
  SCP_REQUIRE_OK(duplicated_reduction);
  SCP_CHECK_EQ(duplicated_reduction.value().duplicates_merged, injected);
  std::size_t per_slot_duplicates = 0;
  for (const SlotResolution& resolution : duplicated_reduction.value().slots) {
    per_slot_duplicates += resolution.duplicates_merged;
  }
  SCP_CHECK_EQ(per_slot_duplicates, injected);
  SCP_CHECK(compare_slots(base_snapshot, base_snapshot).empty());

  const Result<SiteStateSnapshot> duplicated_snapshot_result =
      scp::compose_site_state(duplicated, options_for(evaluation));
  SCP_REQUIRE_OK(duplicated_snapshot_result);
  const SiteStateSnapshot& duplicated_snapshot = duplicated_snapshot_result.value();

  // The accepted identity, outcome, generation, sequence and superseded list of
  // every slot are exactly what they were: a duplicate is merged, not re-resolved.
  const std::vector<std::string> resolved_differences =
      compare_slots(duplicated_snapshot, base_snapshot, false);
  for (const std::string& difference : resolved_differences) {
    scp_test::Context::instance().note(difference);
  }
  SCP_CHECK(resolved_differences.empty());
  SCP_CHECK_EQ(duplicated_snapshot.evidence_digest, base_snapshot.evidence_digest);

  // A redundant copy is merged and counted, and the digest of the composed
  // picture does not move: how many copies of a record arrived is reporting
  // metadata, not something the site believes.
  if (duplicated_snapshot.snapshot_digest != base_snapshot.snapshot_digest) {
    const std::vector<std::string> all_differences =
        compare_slots(duplicated_snapshot, base_snapshot);
    scp_test::Context::instance().note(
        "the duplicate changed the snapshot digest; slot fields that differ: " +
        std::to_string(all_differences.size()));
  }
  SCP_CHECK_EQ(duplicated_snapshot.snapshot_digest, base_snapshot.snapshot_digest);

  // Duplicating the whole set twice over merges every copy and reports the count.
  std::vector<EvidenceRecord> tripled = records;
  append(tripled, records);
  append(tripled, records);
  const Result<scp::ReductionResult> tripled_reduction =
      scp::reduce_evidence(tripled, scp_test::strict_policy(), evaluation);
  SCP_REQUIRE_OK(tripled_reduction);
  SCP_CHECK_EQ(tripled_reduction.value().duplicates_merged, 2 * records.size());
  const Result<SiteStateSnapshot> tripled_snapshot_result =
      scp::compose_site_state(tripled, options_for(evaluation));
  SCP_REQUIRE_OK(tripled_snapshot_result);
  SCP_CHECK_EQ(tripled_snapshot_result.value().evidence_digest, base_snapshot.evidence_digest);
  SCP_CHECK(compare_slots(tripled_snapshot_result.value(), base_snapshot, false).empty());
  SCP_CHECK_EQ(tripled_snapshot_result.value().snapshot_digest, base_snapshot.snapshot_digest);
}

SCP_TEST(snapshot_and_evidence_digests_self_verify) {
  const Timestamp evaluation = scp_test::base_instant();
  std::vector<EvidenceRecord> records = scp_test::healthy_site_records(evaluation, 3);
  append(records, scp_test::healthy_site_records(evaluation, 1));

  const Result<SiteStateSnapshot> composed =
      scp::compose_site_state(records, options_for(evaluation));
  SCP_REQUIRE_OK(composed);
  const SiteStateSnapshot& snapshot = composed.value();

  SCP_CHECK(!snapshot.snapshot_digest.is_zero());
  SCP_CHECK(!snapshot.evidence_digest.is_zero());
  SCP_CHECK_EQ(scp::compute_snapshot_digest(snapshot), snapshot.snapshot_digest);
  SCP_CHECK_EQ(scp::compute_evidence_digest(snapshot.slots), snapshot.evidence_digest);
  SCP_CHECK_EQ(scp::compute_policy_digest(scp_test::strict_policy()), snapshot.policy_digest);
  SCP_CHECK_EQ(snapshot.site, scp_test::default_site());
  SCP_CHECK_EQ(snapshot.site_generation.value(), 1ULL);

  // A copy verifies too, and the digest covers the composed content rather than
  // being an opaque label: changing a state changes the digest.
  SiteStateSnapshot copy = snapshot;
  SCP_CHECK_EQ(scp::compute_snapshot_digest(copy), snapshot.snapshot_digest);
  copy.state = scp::SiteState::Retired;
  SCP_CHECK_NE(scp::compute_snapshot_digest(copy), snapshot.snapshot_digest);

  // Evidence selection: the accepted identity for every slot is the newest
  // generation, and the composed view carries the typed values of those records.
  SCP_CHECK_EQ(snapshot.slots.size(), scp::kEvidenceKindCount);
  SCP_CHECK(snapshot.evidence.populated_count() == scp::kEvidenceKindCount);
  SCP_CHECK(snapshot.evidence.capacity.has_value());
  if (snapshot.evidence.capacity.has_value()) {
    SCP_CHECK_EQ(snapshot.evidence.capacity->available_units, 60ULL);
  }
  SCP_CHECK(std::is_sorted(snapshot.slots.begin(), snapshot.slots.end(),
                           [](const SlotResolution& lhs, const SlotResolution& rhs) {
                             return lhs.slot < rhs.slot;
                           }));
}

SCP_TEST(digest_changes_with_the_evaluation_instant_and_site_generation) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> records = scp_test::healthy_site_records(evaluation, 3);

  const Result<SiteStateSnapshot> baseline_result =
      scp::compose_site_state(records, options_for(evaluation, 1));
  SCP_REQUIRE_OK(baseline_result);
  const SiteStateSnapshot& baseline = baseline_result.value();

  // A different site generation is a different authoritative picture.
  const Result<SiteStateSnapshot> regenerated_result =
      scp::compose_site_state(records, options_for(evaluation, 2));
  SCP_REQUIRE_OK(regenerated_result);
  const SiteStateSnapshot& regenerated = regenerated_result.value();
  SCP_CHECK_NE(regenerated.snapshot_digest, baseline.snapshot_digest);
  SCP_CHECK_EQ(regenerated.site_generation.value(), 2ULL);
  SCP_CHECK_EQ(regenerated.state, baseline.state);
  SCP_CHECK_EQ(regenerated.classification, baseline.classification);
  SCP_CHECK_EQ(regenerated.evidence_digest, baseline.evidence_digest);
  SCP_CHECK_EQ(scp::compute_snapshot_digest(regenerated), regenerated.snapshot_digest);

  // 1000 seconds later every publication has aged past stale_after (900s): the
  // picture is not merely stamped differently, it is a different picture. Every
  // slot is stale, and staleness that reaches the critical slots leaves no
  // trustworthy picture at all, so the classification is Indeterminate and the
  // state is Unknown rather than a confident operating condition.
  const Result<SiteStateSnapshot> stale_result =
      scp::compose_site_state(records, options_for(scp_test::instant_after(1000), 1));
  SCP_REQUIRE_OK(stale_result);
  const SiteStateSnapshot& stale = stale_result.value();
  SCP_CHECK_NE(stale.snapshot_digest, baseline.snapshot_digest);
  SCP_CHECK_EQ(stale.classification, scp::EvidenceClassification::Indeterminate);
  SCP_CHECK_NE(stale.state, baseline.state);
  SCP_CHECK_EQ(stale.state, scp::SiteState::Unknown);
  SCP_CHECK_NE(stale.evidence_digest, baseline.evidence_digest);
  for (const SlotResolution& resolution : stale.slots) {
    SCP_CHECK_EQ(resolution.outcome, scp::SlotOutcome::Stale);
    SCP_CHECK_EQ(resolution.freshness, scp::Freshness::Stale);
    SCP_CHECK(!resolution.accepted());
  }
  SCP_CHECK(stale.has_constraint(scp::ConstraintKind::EvidenceStale));
  SCP_CHECK_EQ(scp::compute_snapshot_digest(stale), stale.snapshot_digest);

  // 100 seconds later the evidence is still fresh, but the instant is part of
  // the canonical form, so the digest moves with it.
  const Result<SiteStateSnapshot> soon_result =
      scp::compose_site_state(records, options_for(scp_test::instant_after(100), 1));
  SCP_REQUIRE_OK(soon_result);
  const SiteStateSnapshot& soon = soon_result.value();
  SCP_CHECK_NE(soon.snapshot_digest, baseline.snapshot_digest);
  SCP_CHECK_EQ(soon.classification, baseline.classification);
  SCP_CHECK_EQ(soon.state, baseline.state);
  SCP_CHECK_EQ(soon.evidence_digest, baseline.evidence_digest);

  // The reported composition instant is metadata: it is deliberately excluded
  // from the canonical form, so it cannot move the digest.
  scp::CompositionOptions later_composition = options_for(evaluation, 1);
  later_composition.composed_at = scp_test::instant_after(5000);
  const Result<SiteStateSnapshot> later_result =
      scp::compose_site_state(records, later_composition);
  SCP_REQUIRE_OK(later_result);
  SCP_CHECK_EQ(later_result.value().snapshot_digest, baseline.snapshot_digest);
  SCP_CHECK_EQ(later_result.value().composed_at, scp_test::instant_after(5000));
}

SCP_TEST(canonical_encoding_is_byte_identical_for_equivalent_inputs) {
  const Timestamp evaluation = scp_test::base_instant();
  std::vector<EvidenceRecord> records = scp_test::healthy_site_records(evaluation, 4);
  append(records, scp_test::healthy_site_records(evaluation, 3));

  const Result<SiteStateSnapshot> first_result =
      scp::compose_site_state(records, options_for(evaluation));
  SCP_REQUIRE_OK(first_result);
  const std::vector<std::uint8_t> first = canonical_bytes(first_result.value());
  SCP_CHECK(!first.empty());

  const Result<SiteStateSnapshot> second_result =
      scp::compose_site_state(records, options_for(evaluation));
  SCP_REQUIRE_OK(second_result);
  SCP_CHECK(canonical_bytes(second_result.value()) == first);
  SCP_CHECK_EQ(scp::Digest::of(std::span<const std::uint8_t>(first.data(), first.size())),
               first_result.value().snapshot_digest);

  std::vector<EvidenceRecord> reversed = records;
  std::reverse(reversed.begin(), reversed.end());
  const Result<SiteStateSnapshot> reversed_result =
      scp::compose_site_state(reversed, options_for(evaluation));
  SCP_REQUIRE_OK(reversed_result);
  SCP_CHECK(canonical_bytes(reversed_result.value()) == first);

  const Result<SiteStateSnapshot> other_generation_result =
      scp::compose_site_state(records, options_for(evaluation, 9));
  SCP_REQUIRE_OK(other_generation_result);
  SCP_CHECK(canonical_bytes(other_generation_result.value()) != first);
}

SCP_TEST(order_independence_through_the_runtime_ingest_path) {
  const Timestamp evaluation = scp_test::base_instant();
  std::vector<EvidenceRecord> records = scp_test::healthy_site_records(evaluation, 5);
  append(records, scp_test::healthy_site_records(evaluation, 2));
  std::vector<EvidenceRecord> reversed = records;
  std::reverse(reversed.begin(), reversed.end());

  // The same two batches staged into two independent in-memory runtimes, hand
  // over first in one order and then in the other. The published picture must be
  // the same picture, not merely an equivalent one.
  SiteStateSnapshot forward;
  {
    SCP_OPEN_RUNTIME(forward_runtime, scp_test::memory_runtime_options());
    SCP_REQUIRE_STATUS_OK(forward_runtime->ingest(records));
    const Result<SiteStateSnapshot> composed = forward_runtime->preview(evaluation);
    SCP_REQUIRE_OK(composed);
    forward = composed.value();
  }
  SiteStateSnapshot backward;
  {
    SCP_OPEN_RUNTIME(backward_runtime, scp_test::memory_runtime_options());
    SCP_REQUIRE_STATUS_OK(backward_runtime->ingest(reversed));
    const Result<SiteStateSnapshot> composed = backward_runtime->preview(evaluation);
    SCP_REQUIRE_OK(composed);
    backward = composed.value();
  }

  SCP_CHECK_EQ(forward.site_generation.value(), 1ULL);
  SCP_CHECK_EQ(forward.snapshot_digest, backward.snapshot_digest);
  SCP_CHECK_EQ(forward.evidence_digest, backward.evidence_digest);
  SCP_CHECK_EQ(forward.state, backward.state);
  SCP_CHECK_EQ(forward.classification, backward.classification);
  SCP_CHECK_EQ(forward.slots.size(), backward.slots.size());
  const std::vector<std::string> differences = compare_slots(forward, backward);
  for (const std::string& difference : differences) {
    scp_test::Context::instance().note(difference);
  }
  SCP_CHECK(differences.empty());
}

SCP_TEST(tied_publications_do_not_depend_on_arrival_order) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> healthy = scp_test::healthy_site_records(evaluation, 1);

  // Two publications tie at one (authority, kind, epoch, generation, sequence)
  // and differ only in a field the resolver cannot read. The engine documents
  // that a tie is either merged or reported as a conflict and that arrival order
  // never decides, so the resolution must be the same whichever arrives first.
  const Result<EvidenceRecord> newer_schema = capacity_record_with_schema(999, 8, 31, evaluation, 60);
  const Result<EvidenceRecord> older_schema = capacity_record_with_schema(998, 8, 32, evaluation, 10);
  SCP_REQUIRE_OK(newer_schema);
  SCP_REQUIRE_OK(older_schema);

  std::vector<EvidenceRecord> unreadable_a;
  for (const EvidenceRecord& record : healthy) {
    if (record.kind != EvidenceKind::Capacity) {
      unreadable_a.push_back(record);
    }
  }
  unreadable_a.push_back(newer_schema.value());
  unreadable_a.push_back(older_schema.value());
  std::vector<EvidenceRecord> unreadable_b = unreadable_a;
  std::swap(unreadable_b[unreadable_b.size() - 2], unreadable_b[unreadable_b.size() - 1]);

  const Result<SiteStateSnapshot> composed_a =
      scp::compose_site_state(unreadable_a, options_for(evaluation));
  SCP_REQUIRE_OK(composed_a);
  const Result<SiteStateSnapshot> composed_b =
      scp::compose_site_state(unreadable_b, options_for(evaluation));
  SCP_REQUIRE_OK(composed_b);
  const SlotResolution* slot_a = resolve_slot(composed_a.value(), EvidenceKind::Capacity);
  const SlotResolution* slot_b = resolve_slot(composed_b.value(), EvidenceKind::Capacity);
  SCP_REQUIRE(slot_a != nullptr);
  SCP_REQUIRE(slot_b != nullptr);
  SCP_CHECK_EQ(slot_a->outcome, scp::SlotOutcome::Unsupported);
  SCP_CHECK_EQ(slot_b->outcome, scp::SlotOutcome::Unsupported);
  // Arrival order is not part of the answer: the accepted identity of a slot
  // whose newest publications are all unreadable must not be "whichever came
  // first".
  if (!(slot_a->accepted_id == slot_b->accepted_id) ||
      !(composed_a.value().snapshot_digest == composed_b.value().snapshot_digest)) {
    scp_test::Context::instance().note(
        "arrival order changed the resolution of an unreadable tie: forward accepted " +
        slot_a->accepted_id.to_hex() + " (schema " +
        std::to_string(newer_schema.value().schema_version) + "), reversed accepted " +
        slot_b->accepted_id.to_hex() +
        "; the tie must be broken by identity, not by the order records were handed over.");
  }
  SCP_CHECK_EQ(slot_a->accepted_id, slot_b->accepted_id);
  SCP_CHECK_EQ(slot_a->accepted_generation, slot_b->accepted_generation);
  SCP_CHECK_EQ(composed_a.value().snapshot_digest, composed_b.value().snapshot_digest);

  // The same tie with equal content but two source instances: the digests agree,
  // the identities do not, and the losing identity is reported nowhere.
  const Result<EvidenceRecord> instance_one = capacity_record(1, 8, 1, 41, evaluation, 60);
  const Result<EvidenceRecord> instance_two = capacity_record(1, 8, 1, 42, evaluation, 60);
  SCP_REQUIRE_OK(instance_one);
  SCP_REQUIRE_OK(instance_two);
  SCP_CHECK_EQ(instance_one.value().provenance.body_digest, instance_two.value().provenance.body_digest);

  std::vector<EvidenceRecord> tied_a = healthy;
  tied_a.push_back(instance_one.value());
  tied_a.push_back(instance_two.value());
  std::vector<EvidenceRecord> tied_b = healthy;
  tied_b.push_back(instance_two.value());
  tied_b.push_back(instance_one.value());

  const Result<SiteStateSnapshot> tied_snapshot_a =
      scp::compose_site_state(tied_a, options_for(evaluation));
  SCP_REQUIRE_OK(tied_snapshot_a);
  const Result<SiteStateSnapshot> tied_snapshot_b =
      scp::compose_site_state(tied_b, options_for(evaluation));
  SCP_REQUIRE_OK(tied_snapshot_b);
  const SlotResolution* tied_slot_a = resolve_slot(tied_snapshot_a.value(), EvidenceKind::Capacity);
  const SlotResolution* tied_slot_b = resolve_slot(tied_snapshot_b.value(), EvidenceKind::Capacity);
  SCP_REQUIRE(tied_slot_a != nullptr);
  SCP_REQUIRE(tied_slot_b != nullptr);
  SCP_CHECK_EQ(tied_slot_a->outcome, scp::SlotOutcome::AcceptedSuperseding);
  SCP_CHECK_EQ(tied_slot_b->outcome, scp::SlotOutcome::AcceptedSuperseding);
  if (!(tied_slot_a->accepted_id == tied_slot_b->accepted_id)) {
    scp_test::Context::instance().note(
        "two source instances publishing the same fact at the same generation resolved to "
        "whichever arrived first: " + tied_slot_a->accepted_id.to_hex() + " vs " +
        tied_slot_b->accepted_id.to_hex() +
        "; a tie at the newest position must resolve identically for every arrival order.");
  }
  SCP_CHECK_EQ(tied_slot_a->accepted_id, tied_slot_b->accepted_id);
}

SCP_TEST_MAIN("scp.composition-determinism")
