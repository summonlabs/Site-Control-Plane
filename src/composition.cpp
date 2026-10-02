// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/composition.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "scp/checked.hpp"
#include "scp/readiness.hpp"

namespace scp {
namespace {

/// Ordering key that decides which publication wins a slot.
///
/// Epoch is the primary key because an epoch is a deliberate reincarnation of a
/// publisher: a restarted runtime with a new epoch retires everything the
/// previous incarnation said, no matter how large its generation counter had
/// grown. Within an epoch the highest (generation, sequence) wins.
struct OrderKey {
  std::uint64_t epoch = 0;
  std::uint64_t generation = 0;
  std::uint64_t sequence = 0;

  friend bool operator<(const OrderKey& lhs, const OrderKey& rhs) noexcept {
    if (lhs.epoch != rhs.epoch) {
      return lhs.epoch < rhs.epoch;
    }
    if (lhs.generation != rhs.generation) {
      return lhs.generation < rhs.generation;
    }
    return lhs.sequence < rhs.sequence;
  }
  friend bool operator==(const OrderKey&, const OrderKey&) noexcept = default;
};

OrderKey key_of(const EvidenceRecord& record) noexcept {
  return OrderKey{record.provenance.epoch.value(), record.provenance.generation.value(),
                  record.provenance.sequence.value()};
}

/// Structural validation that does not depend on the schema version, so a
/// newer-schema publication still fences an older readable one.
Status structural_status(const EvidenceRecord& record) {
  if (record.id.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "evidence identity is not set");
  }
  if (record.provenance.instance.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "evidence source instance is not set");
  }
  if (record.provenance.epoch.is_unset()) {
    return fail(StatusCode::InvalidArgument, "evidence epoch is not set");
  }
  if (record.provenance.generation.is_unset()) {
    return fail(StatusCode::InvalidArgument, "evidence source generation is not set");
  }
  if (record.provenance.sequence.is_unset()) {
    return fail(StatusCode::InvalidArgument, "evidence sequence is not set");
  }
  if (!record.provenance.issued_at.is_set()) {
    return fail(StatusCode::InvalidArgument, "evidence issue time is not set");
  }
  if (record.body.size() > kMaxBlobBytes) {
    return fail(StatusCode::LimitExceeded, "evidence body exceeds the maximum encoded size");
  }
  const Result<bool> digest_ok = record.verify_body_digest();
  if (!digest_ok.has_value()) {
    return digest_ok.status();
  }
  if (!digest_ok.value()) {
    return fail(StatusCode::ChecksumMismatch,
                "evidence body does not match the digest recorded in its provenance");
  }
  return Status{};
}

/// Exact integer percentage with an explicit failure instead of a wrapped or
/// fabricated value. Never uses floating point.
Result<std::uint32_t> safe_percent(std::uint64_t numerator, std::uint64_t denominator) {
  if (denominator == 0) {
    return std::uint32_t{0};
  }
  if (numerator >= denominator) {
    return std::uint32_t{100};
  }
  const Result<std::uint64_t> scaled = checked_mul(numerator, 100);
  if (!scaled.has_value()) {
    return fail(StatusCode::OutOfRange,
                "quantity magnitude is too large to express as a percentage");
  }
  return static_cast<std::uint32_t>(scaled.value() / denominator);
}

std::uint32_t domains_percent(std::uint32_t ready, std::uint32_t total) {
  if (total == 0) {
    return 0;
  }
  if (ready >= total) {
    return 100;
  }
  return static_cast<std::uint32_t>((static_cast<std::uint64_t>(ready) * 100ULL) /
                                    static_cast<std::uint64_t>(total));
}

/// Readiness level mapped to a percentage, used when a publisher states a level
/// but no unit counts. The mapping is fixed and documented, so a level never
/// silently becomes a different number in a different release.
std::uint32_t level_percent(ReadinessLevel level) noexcept {
  switch (level) {
    case ReadinessLevel::Ready: return 100;
    case ReadinessLevel::Constrained: return 70;
    case ReadinessLevel::Degraded: return 40;
    case ReadinessLevel::Unavailable: return 0;
    case ReadinessLevel::Unknown: return 0;
  }
  return 0;
}

struct SlotGroup {
  std::vector<const EvidenceRecord*> readable;
  std::vector<const EvidenceRecord*> unreadable;
  std::vector<const EvidenceRecord*> unauthorized;
  std::vector<const EvidenceRecord*> invalid;
  std::size_t duplicates = 0;
};

std::string describe_record(const EvidenceRecord& record) {
  return std::string(to_string(record.provenance.authority)) + "/" +
         std::string(to_string(record.kind)) + " generation " +
         std::to_string(record.provenance.generation.value()) + " sequence " +
         std::to_string(record.provenance.sequence.value());
}

void sort_ids(std::vector<EvidenceId>& ids) {
  std::sort(ids.begin(), ids.end());
  ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
}

/// Places one slot's resolutions into the snapshot, adding an explicit Missing
/// entry for a slot no publisher addressed.
void ensure_all_slots(std::vector<SlotResolution>& slots) {
  for (std::uint16_t raw = 1; raw <= static_cast<std::uint16_t>(kEvidenceKindCount); ++raw) {
    EvidenceKind kind{};
    switch (raw) {
      case 1: kind = EvidenceKind::FacilityState; break;
      case 2: kind = EvidenceKind::Lifecycle; break;
      case 3: kind = EvidenceKind::Capacity; break;
      case 4: kind = EvidenceKind::PowerReadiness; break;
      case 5: kind = EvidenceKind::CoolingReadiness; break;
      case 6: kind = EvidenceKind::Policy; break;
      case 7: kind = EvidenceKind::Incident; break;
      case 8: kind = EvidenceKind::Maintenance; break;
      case 9: kind = EvidenceKind::AsiCapability; break;
      case 10: kind = EvidenceKind::DfiCapability; break;
      case 11: kind = EvidenceKind::ServiceClass; break;
      default: continue;
    }
    const EvidenceSlot slot{owner_of(kind), kind};
    const bool present = std::any_of(slots.begin(), slots.end(),
                                     [slot](const SlotResolution& resolution) {
                                       return resolution.slot == slot;
                                     });
    if (!present) {
      SlotResolution missing;
      missing.slot = slot;
      missing.outcome = SlotOutcome::Missing;
      missing.freshness = Freshness::Indeterminate;
      missing.detail = "no publisher addressed this slot";
      slots.push_back(std::move(missing));
    }
  }
  std::sort(slots.begin(), slots.end(),
            [](const SlotResolution& lhs, const SlotResolution& rhs) { return lhs.slot < rhs.slot; });
}

}  // namespace

// ---------------------------------------------------------------------------
// Reduction
// ---------------------------------------------------------------------------

Result<ReductionResult> reduce_evidence(std::span<const EvidenceRecord> records,
                                        const SitePolicy& policy, Timestamp evaluation_time) {
  if (records.size() > kMaxEvidenceRecordsPerIngest) {
    return fail(StatusCode::LimitExceeded,
                "evidence batch carries " + std::to_string(records.size()) +
                    " records, the limit is " + std::to_string(kMaxEvidenceRecordsPerIngest));
  }
  if (!evaluation_time.is_set()) {
    return fail(StatusCode::InvalidArgument, "reduction requires an evaluation instant");
  }
  const Status policy_status = policy.validate();
  if (!policy_status.ok()) {
    return policy_status;
  }

  std::map<EvidenceSlot, SlotGroup> groups;
  std::map<EvidenceSlot, std::map<EvidenceId, std::size_t>> seen;

  for (const EvidenceRecord& record : records) {
    const EvidenceSlot slot = slot_of(record);
    SlotGroup& group = groups[slot];
    std::map<EvidenceId, std::size_t>& slot_seen = seen[slot];
    const auto existing = slot_seen.find(record.id);
    if (existing != slot_seen.end()) {
      ++existing->second;
      ++group.duplicates;
      continue;
    }
    slot_seen.emplace(record.id, 1);

    if (!has_sole_owner(record.kind)) {
      group.unauthorized.push_back(&record);
      continue;
    }
    if (!is_authorized_publisher(record.provenance.authority, record.kind)) {
      group.unauthorized.push_back(&record);
      continue;
    }
    const Status structural = structural_status(record);
    if (!structural.ok()) {
      group.invalid.push_back(&record);
      continue;
    }
    if (record.schema_version != kEvidenceSchemaVersion) {
      // Structurally sound but written by a schema this build cannot read. The
      // bytes and their provenance are preserved; the record still fences older
      // readable generations, because a newer statement exists whether or not
      // this build can interpret it.
      group.unreadable.push_back(&record);
      continue;
    }
    group.readable.push_back(&record);
  }

  ReductionResult result;
  result.duplicates_merged = 0;

  for (auto& entry : groups) {
    const EvidenceSlot slot = entry.first;
    SlotGroup& group = entry.second;
    SlotResolution resolution;
    resolution.slot = slot;
    resolution.duplicates_merged = group.duplicates;
    result.duplicates_merged += group.duplicates;
    result.unsupported_count += group.unreadable.size();
    result.unauthorized_count += group.unauthorized.size();

    std::vector<const EvidenceRecord*> considered = group.readable;
    considered.insert(considered.end(), group.unreadable.begin(), group.unreadable.end());

    const auto account_rejected = [&result, &group]() {
      for (const EvidenceRecord* record : group.unauthorized) {
        result.rejected.push_back(*record);
      }
      for (const EvidenceRecord* record : group.invalid) {
        result.rejected.push_back(*record);
      }
      for (const EvidenceRecord* record : group.unreadable) {
        result.rejected.push_back(*record);
      }
    };

    if (considered.empty()) {
      account_rejected();
      if (!group.unauthorized.empty()) {
        resolution.outcome = SlotOutcome::Unauthorized;
        resolution.detail = std::string(to_string(slot.authority)) +
                            " is not the owner of " + std::string(to_string(slot.kind));
      } else if (!group.invalid.empty()) {
        resolution.outcome = SlotOutcome::Indeterminate;
        resolution.detail = "every publication for this slot failed validation";
      } else {
        resolution.outcome = SlotOutcome::Missing;
        resolution.detail = "no publication for this slot";
      }
      result.slots.push_back(std::move(resolution));
      continue;
    }

    OrderKey best = key_of(*considered.front());
    for (const EvidenceRecord* record : considered) {
      const OrderKey key = key_of(*record);
      if (best < key) {
        best = key;
      }
    }

    std::vector<const EvidenceRecord*> readable_at_best;
    std::vector<const EvidenceRecord*> unreadable_at_best;
    std::vector<EvidenceId> superseded;
    for (const EvidenceRecord* record : considered) {
      const OrderKey key = key_of(*record);
      if (key == best) {
        if (record->schema_version == kEvidenceSchemaVersion) {
          readable_at_best.push_back(record);
        } else {
          unreadable_at_best.push_back(record);
        }
      } else if (record->schema_version == kEvidenceSchemaVersion) {
        superseded.push_back(record->id);
      }
    }

    std::vector<Digest> distinct;
    if (readable_at_best.size() > 1) {
      for (const EvidenceRecord* record : readable_at_best) {
        if (std::find(distinct.begin(), distinct.end(), record->provenance.body_digest) ==
            distinct.end()) {
          distinct.push_back(record->provenance.body_digest);
        }
      }
    }

    // Ties are broken by identity, which is content-addressed and therefore
    // independent of arrival order. This holds for the readable representative
    // and for the representative reported when the newest position is
    // unreadable: nothing about a resolution may depend on which record the
    // caller happened to hand over first.
    const auto lowest_id = [](const std::vector<const EvidenceRecord*>& candidates)
        -> const EvidenceRecord* {
      const EvidenceRecord* chosen = nullptr;
      for (const EvidenceRecord* candidate : candidates) {
        if (chosen == nullptr || candidate->id < chosen->id) {
          chosen = candidate;
        }
      }
      return chosen;
    };

    const EvidenceRecord* winner = lowest_id(readable_at_best);
    const EvidenceRecord* newest_unreadable = lowest_id(unreadable_at_best);
    if (winner != nullptr) {
      resolution.accepted_id = winner->id;
      resolution.accepted_digest = winner->provenance.body_digest;
      resolution.accepted_instance = winner->provenance.instance;
      resolution.accepted_epoch = winner->provenance.epoch;
      resolution.accepted_generation = winner->provenance.generation;
      resolution.accepted_sequence = winner->provenance.sequence;
      resolution.origin = winner->origin;
      resolution.freshness = classify_freshness(*winner, evaluation_time, policy.freshness);
      resolution.superseded = superseded;
      sort_ids(resolution.superseded);
    }

    if (!unreadable_at_best.empty()) {
      resolution.outcome = SlotOutcome::Unsupported;
      resolution.detail =
          "the newest publication for this slot declares schema version " +
          std::to_string(newest_unreadable != nullptr ? newest_unreadable->schema_version : 0) +
          ", which this build cannot read; older readable truth is not substituted";
      if (winner == nullptr && newest_unreadable != nullptr) {
        const EvidenceRecord* newest = newest_unreadable;
        resolution.accepted_id = newest->id;
        resolution.accepted_digest = newest->provenance.body_digest;
        resolution.accepted_instance = newest->provenance.instance;
        resolution.accepted_epoch = newest->provenance.epoch;
        resolution.accepted_generation = newest->provenance.generation;
        resolution.accepted_sequence = newest->provenance.sequence;
        resolution.origin = newest->origin;
      }
      result.slots.push_back(std::move(resolution));
      continue;
    }

    if (winner == nullptr) {
      resolution.outcome = SlotOutcome::Indeterminate;
      resolution.detail = "the newest publication for this slot failed validation";
      result.slots.push_back(std::move(resolution));
      continue;
    }

    if (distinct.size() > 1) {
      resolution.outcome = SlotOutcome::Conflicting;
      for (const EvidenceRecord* record : readable_at_best) {
        resolution.conflicting.push_back(record->id);
      }
      sort_ids(resolution.conflicting);
      const EvidenceRecord* anchor = lowest_id(readable_at_best);
      resolution.detail = std::to_string(distinct.size()) +
                          " publications claim the same epoch, generation and sequence for this "
                          "slot with different content (" +
                          (anchor != nullptr ? describe_record(*anchor) : std::string("unknown")) +
                          "); arrival order does not decide";
      result.conflict_count += 1;
      result.slots.push_back(std::move(resolution));
      continue;
    }

    // A stale or expired winner is still the record that won its slot; the
    // freshness axis decides whether a decision may use it, not whether it was
    // the newest statement.
    if (resolution.freshness == Freshness::Expired) {
      resolution.outcome = SlotOutcome::Expired;
      resolution.detail = "the accepted publication expired before the evaluation instant";
    } else if (resolution.freshness == Freshness::Stale) {
      resolution.outcome = SlotOutcome::Stale;
      resolution.detail = "the accepted publication is older than the staleness threshold";
    } else if (resolution.freshness == Freshness::Indeterminate) {
      resolution.outcome = SlotOutcome::Indeterminate;
      resolution.detail = "the accepted publication cannot be dated against the evaluation instant";
    } else {
      resolution.outcome = resolution.superseded.empty() ? SlotOutcome::Accepted
                                                         : SlotOutcome::AcceptedSuperseding;
      resolution.detail = resolution.superseded.empty()
                              ? "accepted; newest publication for this slot"
                              : "accepted; superseded " +
                                    std::to_string(resolution.superseded.size()) +
                                    " older publication(s)";
      if (!group.unauthorized.empty() || !group.invalid.empty()) {
        resolution.detail += "; ignored " + std::to_string(group.unauthorized.size()) +
                             " unauthorized and " + std::to_string(group.invalid.size()) +
                             " invalid publication(s)";
      }
    }

    // Only a usable resolution contributes a record to the accepted set: stale,
    // expired and conflicting publications are resolved for reporting but never
    // participate in a decision.
    // Bucket assignment, chosen so that the five buckets partition the distinct
    // identities in the batch exactly once each.
    if (resolution.outcome == SlotOutcome::Conflicting) {
      for (const EvidenceRecord* record : readable_at_best) {
        result.conflicting.push_back(*record);
      }
    } else if (winner != nullptr) {
      result.accepted.push_back(*winner);
      for (const EvidenceRecord* record : readable_at_best) {
        if (record->id != winner->id) {
          // Readable, at the winning position, but not the representative: the
          // same logical fact stated by another instance, or a statement the
          // newest unreadable publication made unusable.
          result.redundant.push_back(*record);
          resolution.duplicates_merged += 1;
        }
      }
    }
    for (const EvidenceRecord* record : considered) {
      if (record->schema_version == kEvidenceSchemaVersion &&
          std::find(resolution.superseded.begin(), resolution.superseded.end(), record->id) !=
              resolution.superseded.end()) {
        result.superseded.push_back(*record);
      }
    }
    account_rejected();
    result.slots.push_back(std::move(resolution));
  }

  std::sort(result.slots.begin(), result.slots.end(),
            [](const SlotResolution& lhs, const SlotResolution& rhs) { return lhs.slot < rhs.slot; });
  result.redundant_count = result.redundant.size();
  return result;
}

void canonical_write(CanonicalWriter& writer, const ReductionResult& value) {
  writer.u32(static_cast<std::uint32_t>(value.slots.size()));
  for (const SlotResolution& resolution : value.slots) {
    canonical_write(writer, resolution);
  }
  writer.u64(value.duplicates_merged);
  writer.u64(value.conflict_count);
  writer.u64(value.unauthorized_count);
  writer.u64(value.unsupported_count);
}

// ---------------------------------------------------------------------------
// Evidence set
// ---------------------------------------------------------------------------

EvidenceSet::EvidenceSet(std::size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

bool EvidenceSet::contains(EvidenceId id) const noexcept { return find(id) != nullptr; }

const EvidenceRecord* EvidenceSet::find(EvidenceId id) const noexcept {
  for (const EvidenceRecord& record : records_) {
    if (record.id == id) {
      return &record;
    }
  }
  return nullptr;
}

Result<bool> EvidenceSet::insert(const EvidenceRecord& record) {
  const Status valid = record.validate();
  if (!valid.ok()) {
    return valid;
  }
  if (contains(record.id)) {
    return fail(StatusCode::AlreadyExists,
                "evidence " + record.id.to_hex() + " is already accepted");
  }
  if (records_.size() >= capacity_) {
    return fail(StatusCode::CapacityExhausted,
                "accepted evidence set holds " + std::to_string(records_.size()) +
                    " records, the configured capacity is " + std::to_string(capacity_) +
                    "; retire evidence or raise the bound deliberately");
  }
  records_.push_back(record);
  return true;
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

namespace {

constexpr std::string_view kDomainPower = "power";
constexpr std::string_view kDomainCooling = "cooling";
constexpr std::string_view kDomainAccelerators = "accelerators";
constexpr std::string_view kDomainFabric = "fabric";

void apply_record(SiteEvidenceView& view, const EvidenceRecord& record) {
  const Result<EvidenceBody> body = decode_body(record.kind, record.schema_version, record.body);
  if (!body.has_value()) {
    return;
  }
  const EvidenceBody& value = body.value();
  switch (record.kind) {
    case EvidenceKind::FacilityState:
      if (const auto* typed = std::get_if<FacilityStateEvidence>(&value)) {
        view.facility_state = *typed;
      }
      break;
    case EvidenceKind::Lifecycle:
      if (const auto* typed = std::get_if<LifecycleEvidence>(&value)) {
        view.lifecycle = *typed;
      }
      break;
    case EvidenceKind::Capacity:
      if (const auto* typed = std::get_if<CapacityEvidence>(&value)) {
        view.capacity = *typed;
      }
      break;
    case EvidenceKind::PowerReadiness:
      if (const auto* typed = std::get_if<ReadinessEvidence>(&value)) {
        view.power = *typed;
      }
      break;
    case EvidenceKind::CoolingReadiness:
      if (const auto* typed = std::get_if<ReadinessEvidence>(&value)) {
        view.cooling = *typed;
      }
      break;
    case EvidenceKind::Policy:
      if (const auto* typed = std::get_if<PolicyEvidence>(&value)) {
        view.policy = *typed;
      }
      break;
    case EvidenceKind::Incident:
      if (const auto* typed = std::get_if<IncidentEvidence>(&value)) {
        view.incident = *typed;
      }
      break;
    case EvidenceKind::Maintenance:
      if (const auto* typed = std::get_if<MaintenanceEvidence>(&value)) {
        view.maintenance = *typed;
      }
      break;
    case EvidenceKind::AsiCapability:
      if (const auto* typed = std::get_if<CapabilityEvidence>(&value)) {
        view.asi = *typed;
      }
      break;
    case EvidenceKind::DfiCapability:
      if (const auto* typed = std::get_if<CapabilityEvidence>(&value)) {
        view.dfi = *typed;
      }
      break;
    case EvidenceKind::ServiceClass:
      if (const auto* typed = std::get_if<ServiceClassEvidence>(&value)) {
        view.service_class = *typed;
      }
      break;
  }
}

/// Collects constraints, refusing duplicates and enforcing the configured bound
/// rather than growing without limit.
class ConstraintSink {
 public:
  ConstraintSink(SiteStateSnapshot& snapshot, std::size_t limit)
      : snapshot_(snapshot), limit_(limit) {}

  Status add(ConstraintKind kind, Severity severity, bool blocking, std::string subject,
             std::string detail, EvidenceSlot source, const Digest& source_digest) {
    const ConstraintId id = constraint_id_for(kind, subject);
    for (const Constraint& existing : snapshot_.constraints) {
      if (existing.id == id) {
        return Status{};
      }
    }
    if (snapshot_.constraints.size() >= limit_) {
      return fail(StatusCode::LimitExceeded,
                  "composition produced more than " + std::to_string(limit_) +
                      " constraints; the site policy bound was reached");
    }
    Constraint constraint;
    constraint.id = id;
    constraint.kind = kind;
    constraint.severity = severity;
    constraint.blocking = blocking;
    constraint.subject = std::move(subject);
    constraint.detail = std::move(detail);
    constraint.source = source;
    constraint.source_digest = source_digest;
    snapshot_.constraints.push_back(std::move(constraint));
    return Status{};
  }

 private:
  SiteStateSnapshot& snapshot_;
  std::size_t limit_;
};

std::optional<std::uint32_t> capacity_headroom_percent(const SiteStateSnapshot& snapshot) {
  if (!snapshot.evidence.capacity.has_value()) {
    return std::nullopt;
  }
  const CapacityEvidence& capacity = *snapshot.evidence.capacity;
  if (capacity.total_units == 0) {
    return std::nullopt;
  }
  const Result<std::uint32_t> percent =
      safe_percent(capacity.available_units, capacity.total_units);
  if (!percent.has_value()) {
    return std::nullopt;
  }
  return percent.value();
}

std::uint32_t capability_percent(const CapabilityEvidence& capability) {
  if (capability.total_domains == 0) {
    return level_percent(capability.readiness);
  }
  return domains_percent(capability.ready_domains, capability.total_domains);
}

std::uint32_t readiness_percent(const ReadinessEvidence& readiness) {
  const std::uint32_t level = level_percent(readiness.readiness);
  if (readiness.required_domains == 0) {
    return level;
  }
  const std::uint32_t redundancy =
      domains_percent(readiness.available_domains, readiness.required_domains);
  return redundancy < level ? redundancy : level;
}

const DomainReadiness* find_domain(const SiteStateSnapshot& snapshot, std::string_view name) {
  for (const DomainReadiness& domain : snapshot.readiness_domains) {
    if (domain.domain == name) {
      return &domain;
    }
  }
  return nullptr;
}

}  // namespace

std::size_t SiteEvidenceView::populated_count() const noexcept {
  std::size_t count = 0;
  count += facility_state.has_value() ? 1U : 0U;
  count += lifecycle.has_value() ? 1U : 0U;
  count += capacity.has_value() ? 1U : 0U;
  count += power.has_value() ? 1U : 0U;
  count += cooling.has_value() ? 1U : 0U;
  count += policy.has_value() ? 1U : 0U;
  count += incident.has_value() ? 1U : 0U;
  count += maintenance.has_value() ? 1U : 0U;
  count += asi.has_value() ? 1U : 0U;
  count += dfi.has_value() ? 1U : 0U;
  count += service_class.has_value() ? 1U : 0U;
  return count;
}

void canonical_write(CanonicalWriter& writer, const DomainReadiness& value) {
  writer.text(value.domain);
  writer.u32(value.percent);
  writer.boolean(value.observed);
  writer.u8(static_cast<std::uint8_t>(value.level));
}

Result<SiteStateSnapshot> compose_site_state(const ReductionResult& reduction,
                                             const CompositionOptions& options) {
  if (options.site.is_nil()) {
    return fail(StatusCode::InvalidArgument, "composition requires a site identity");
  }
  if (options.site_generation.is_unset()) {
    return fail(StatusCode::InvalidArgument, "composition requires a site generation");
  }
  if (!options.evaluation_time.is_set()) {
    return fail(StatusCode::InvalidArgument, "composition requires an evaluation instant");
  }
  const Status policy_status = options.policy.validate();
  if (!policy_status.ok()) {
    return policy_status;
  }

  SiteStateSnapshot snapshot;
  snapshot.site = options.site;
  snapshot.site_generation = options.site_generation;
  snapshot.evaluation_time = options.evaluation_time;
  snapshot.composed_at =
      options.composed_at.is_set() ? options.composed_at : options.evaluation_time;
  snapshot.policy_digest = compute_policy_digest(options.policy);
  snapshot.slots = reduction.slots;
  ensure_all_slots(snapshot.slots);
  snapshot.evidence_digest = compute_evidence_digest(snapshot.slots);

  // Only a *usable* resolution contributes to the picture. A stale, expired,
  // indeterminate or conflicting winner is reported in its slot, but it is not
  // evidence a decision may be based on, so it must not reach the typed view.
  for (const EvidenceRecord& record : reduction.accepted) {
    bool usable = false;
    for (const SlotResolution& resolution : snapshot.slots) {
      if (resolution.accepted() && resolution.accepted_id == record.id) {
        usable = true;
        break;
      }
    }
    if (usable) {
      apply_record(snapshot.evidence, record);
    }
  }

  ConstraintSink sink(snapshot, options.policy.max_constraints);

  // 1. Evidence quality. Every slot that could not be used becomes an explicit
  //    constraint, so "we do not know" is visible rather than inferred away.
  for (const SlotResolution& resolution : snapshot.slots) {
    const std::string subject(to_string(resolution.slot.kind));
    switch (resolution.outcome) {
      case SlotOutcome::Accepted:
      case SlotOutcome::AcceptedSuperseding:
        break;
      case SlotOutcome::Missing:
        SCP_TRY(sink.add(ConstraintKind::EvidenceIncomplete, Severity::Major, true, subject,
                         "no publication from " + std::string(to_string(resolution.slot.authority)),
                         resolution.slot, resolution.accepted_digest));
        break;
      case SlotOutcome::Conflicting:
        SCP_TRY(sink.add(ConstraintKind::EvidenceConflicting, Severity::Critical, true, subject,
                         resolution.detail, resolution.slot, resolution.accepted_digest));
        break;
      case SlotOutcome::Stale:
      case SlotOutcome::Expired:
        SCP_TRY(sink.add(ConstraintKind::EvidenceStale,
                         resolution.outcome == SlotOutcome::Expired ? Severity::Major
                                                                    : Severity::Minor,
                         resolution.outcome == SlotOutcome::Expired, subject, resolution.detail,
                         resolution.slot, resolution.accepted_digest));
        break;
      case SlotOutcome::Unsupported:
        SCP_TRY(sink.add(ConstraintKind::EvidenceUnsupported, Severity::Major, true, subject,
                         resolution.detail, resolution.slot, resolution.accepted_digest));
        break;
      case SlotOutcome::Unauthorized:
        SCP_TRY(sink.add(ConstraintKind::EvidenceUnauthorized, Severity::Minor, false, subject,
                         resolution.detail, resolution.slot, resolution.accepted_digest));
        break;
      case SlotOutcome::Superseded:
      case SlotOutcome::Indeterminate:
        SCP_TRY(sink.add(ConstraintKind::EvidenceIncomplete, Severity::Major, true, subject,
                         resolution.detail, resolution.slot, resolution.accepted_digest));
        break;
    }
  }

  // 2. Typed domain facts.
  const FacilityStateEvidence* facility = snapshot.evidence.facility_state.has_value()
                                              ? &*snapshot.evidence.facility_state
                                              : nullptr;
  const IncidentEvidence* incident =
      snapshot.evidence.incident.has_value() ? &*snapshot.evidence.incident : nullptr;
  const MaintenanceEvidence* maintenance =
      snapshot.evidence.maintenance.has_value() ? &*snapshot.evidence.maintenance : nullptr;
  const CapacityEvidence* capacity =
      snapshot.evidence.capacity.has_value() ? &*snapshot.evidence.capacity : nullptr;
  const ReadinessEvidence* power =
      snapshot.evidence.power.has_value() ? &*snapshot.evidence.power : nullptr;
  const ReadinessEvidence* cooling =
      snapshot.evidence.cooling.has_value() ? &*snapshot.evidence.cooling : nullptr;
  const CapabilityEvidence* asi =
      snapshot.evidence.asi.has_value() ? &*snapshot.evidence.asi : nullptr;
  const CapabilityEvidence* dfi =
      snapshot.evidence.dfi.has_value() ? &*snapshot.evidence.dfi : nullptr;

  snapshot.lifecycle = snapshot.evidence.lifecycle.has_value()
                           ? snapshot.evidence.lifecycle->state
                           : LifecycleState::Commissioning;

  // 3. Readiness domains. An absent domain is not recorded at all, so it is
  //    reported as unobserved instead of as healthy or as zero.
  if (power != nullptr) {
    DomainReadiness domain;
    domain.domain = std::string(kDomainPower);
    domain.level = power->readiness;
    domain.percent = readiness_percent(*power);
    domain.observed = true;
    snapshot.readiness_domains.push_back(std::move(domain));
  }
  if (cooling != nullptr) {
    DomainReadiness domain;
    domain.domain = std::string(kDomainCooling);
    domain.level = cooling->readiness;
    domain.percent = readiness_percent(*cooling);
    domain.observed = true;
    snapshot.readiness_domains.push_back(std::move(domain));
  }
  if (asi != nullptr) {
    DomainReadiness domain;
    domain.domain = std::string(kDomainAccelerators);
    domain.level = asi->readiness;
    domain.percent = capability_percent(*asi);
    domain.observed = true;
    snapshot.readiness_domains.push_back(std::move(domain));
  }
  if (dfi != nullptr) {
    DomainReadiness domain;
    domain.domain = std::string(kDomainFabric);
    domain.level = dfi->readiness;
    domain.percent = capability_percent(*dfi);
    domain.observed = true;
    snapshot.readiness_domains.push_back(std::move(domain));
  }
  std::sort(snapshot.readiness_domains.begin(), snapshot.readiness_domains.end());
  {
    bool any = false;
    std::uint32_t minimum = 100;
    for (const DomainReadiness& domain : snapshot.readiness_domains) {
      if (!domain.observed) {
        continue;
      }
      any = true;
      minimum = domain.percent < minimum ? domain.percent : minimum;
    }
    snapshot.readiness_percent = any ? minimum : 0;
  }

  const std::optional<std::uint32_t> headroom = capacity_headroom_percent(snapshot);
  const bool emergency = (facility != nullptr && facility->emergency_declared) ||
                         (incident != nullptr && incident->emergency_declared) ||
                         snapshot.lifecycle == LifecycleState::Emergency;
  const Severity worst_severity =
      incident != nullptr && static_cast<std::uint8_t>(incident->worst_active_severity) >
                                 static_cast<std::uint8_t>(facility != nullptr
                                                               ? facility->worst_active_severity
                                                               : Severity::None)
          ? incident->worst_active_severity
          : (facility != nullptr ? facility->worst_active_severity : Severity::None);
  const bool degraded_operation = facility != nullptr && facility->degraded_operation;

  const bool power_unavailable = power != nullptr && power->readiness == ReadinessLevel::Unavailable;
  const bool power_degraded = power != nullptr && power->readiness == ReadinessLevel::Degraded;
  const bool power_constrained = power != nullptr && power->readiness == ReadinessLevel::Constrained;
  const bool cooling_unavailable =
      cooling != nullptr && cooling->readiness == ReadinessLevel::Unavailable;
  const bool cooling_degraded =
      cooling != nullptr && cooling->readiness == ReadinessLevel::Degraded;
  const bool cooling_constrained =
      cooling != nullptr && cooling->readiness == ReadinessLevel::Constrained;
  const std::uint32_t asi_percent = asi != nullptr ? capability_percent(*asi) : 0;
  const std::uint32_t dfi_percent = dfi != nullptr ? capability_percent(*dfi) : 0;
  const bool asi_unavailable =
      asi != nullptr && (asi->readiness == ReadinessLevel::Unavailable ||
                         asi_percent < options.policy.domain_readiness_unavailable_percent);
  const bool dfi_unavailable =
      dfi != nullptr && (dfi->readiness == ReadinessLevel::Unavailable ||
                         dfi_percent < options.policy.domain_readiness_unavailable_percent);
  const bool asi_degraded =
      asi != nullptr && !asi_unavailable &&
      (asi->readiness == ReadinessLevel::Degraded ||
       asi_percent < options.policy.domain_readiness_degraded_percent);
  const bool dfi_degraded =
      dfi != nullptr && !dfi_unavailable &&
      (dfi->readiness == ReadinessLevel::Degraded ||
       dfi_percent < options.policy.domain_readiness_degraded_percent);
  const bool asi_constrained = asi != nullptr && !asi_unavailable && !asi_degraded &&
                               asi->readiness == ReadinessLevel::Constrained;
  const bool dfi_constrained = dfi != nullptr && !dfi_unavailable && !dfi_degraded &&
                               dfi->readiness == ReadinessLevel::Constrained;

  const bool capacity_exhausted =
      capacity != nullptr && (capacity->available_units == 0 || capacity->oversubscribed);
  const bool capacity_low =
      headroom.has_value() && headroom.value() < options.policy.capacity_headroom_degraded_percent;
  const bool capacity_tight = headroom.has_value() &&
                              headroom.value() < options.policy.capacity_headroom_constrained_percent;
  const bool maintenance_active = maintenance != nullptr && maintenance->active_windows > 0;
  const bool maintenance_overdue =
      maintenance != nullptr && maintenance->mode == MaintenanceMode::Overdue;
  const bool incidents_active =
      (incident != nullptr && incident->active_incidents > 0) ||
      (facility != nullptr && facility->active_incidents > 0);

  // 4. Obligation assessment.
  if (snapshot.evidence.service_class.has_value()) {
    const ServiceClassEvidence& classes = *snapshot.evidence.service_class;
    if (classes.obligations.size() > options.policy.max_service_classes) {
      return fail(StatusCode::LimitExceeded,
                  "service class evidence carries " + std::to_string(classes.obligations.size()) +
                      " obligations, the site policy bound is " +
                      std::to_string(options.policy.max_service_classes));
    }
    const std::uint64_t capacity_available =
        capacity != nullptr ? capacity->available_units : 0;
    for (const ServiceClassObligation& obligation : classes.obligations) {
      ObligationAssessment assessment;
      assessment.id = obligation_id_for(obligation.service_class.view());
      assessment.service_class = obligation.service_class;
      assessment.protected_class = obligation.protected_class;
      assessment.required_units = obligation.minimum_ready_units;
      assessment.ready_units = capacity_available;
      assessment.required_readiness_percent = obligation.minimum_readiness_percent;
      assessment.observed_readiness_percent = snapshot.readiness_percent;

      const bool units_short = capacity == nullptr ||
                               capacity_available < obligation.minimum_ready_units;
      const bool readiness_short =
          snapshot.readiness_domains.empty() ||
          snapshot.readiness_percent < obligation.minimum_readiness_percent;
      const bool unsafe = emergency || capacity_exhausted || power_unavailable ||
                          cooling_unavailable || asi_unavailable || dfi_unavailable;
      const bool at_risk = power_degraded || cooling_degraded || asi_degraded || dfi_degraded ||
                           capacity_tight || incidents_active || maintenance_active ||
                           degraded_operation;
      if (units_short || readiness_short) {
        assessment.outcome = ObligationOutcome::Unsatisfied;
        assessment.detail = units_short
                                ? "available capacity is below the obligation minimum"
                                : "observed readiness is below the obligation minimum";
      } else if (unsafe) {
        assessment.outcome =
            obligation.protected_class ? ObligationOutcome::Unsatisfied : ObligationOutcome::AtRisk;
        assessment.detail = unsafe && emergency
                                ? "the site is in emergency operation"
                                : "a required dependency domain is unavailable";
      } else if (at_risk) {
        assessment.outcome = ObligationOutcome::AtRisk;
        assessment.detail = "a dependency domain is degraded or the site is constrained";
      } else {
        assessment.outcome = ObligationOutcome::Satisfied;
        assessment.detail = "capacity and readiness meet the declared minimums";
      }
      snapshot.obligations.push_back(std::move(assessment));
    }
  }
  std::sort(snapshot.obligations.begin(), snapshot.obligations.end());

  // 5. Derived constraints.
  if (capacity != nullptr) {
    if (capacity->oversubscribed) {
      SCP_TRY(sink.add(ConstraintKind::CapacityOversubscribed, Severity::Critical, true, "capacity",
                       "the capacity owner reports the site as oversubscribed",
                       EvidenceSlot{SourceAuthority::FacilityCapacity, EvidenceKind::Capacity},
                       Digest{}));
    }
    if (capacity_exhausted) {
      SCP_TRY(sink.add(ConstraintKind::CapacityExhausted, Severity::Critical, true, "capacity",
                       "no capacity units remain available", EvidenceSlot{}, Digest{}));
    } else if (capacity_low) {
      SCP_TRY(sink.add(ConstraintKind::CapacityHeadroomLow, Severity::Major, true, "capacity",
                       "capacity headroom is below the degraded floor", EvidenceSlot{}, Digest{}));
    } else if (capacity_tight) {
      SCP_TRY(sink.add(ConstraintKind::CapacityHeadroomLow, Severity::Minor, false, "capacity",
                       "capacity headroom is below the constrained floor", EvidenceSlot{},
                       Digest{}));
    }
  }
  if (capacity != nullptr && capacity->total_units > 0 &&
      capacity->available_units > capacity->total_units) {
    SCP_TRY(sink.add(ConstraintKind::EvidenceIncomplete, Severity::Major, true, "capacity",
                     "the capacity owner reports more available units than the site has",
                     EvidenceSlot{}, Digest{}));
  }

  const auto add_power = [&](ConstraintKind kind, Severity severity, bool blocking,
                             std::string detail) -> Status {
    return sink.add(kind, severity, blocking, std::string(kDomainPower), std::move(detail),
                    EvidenceSlot{SourceAuthority::PowerControlPlane,
                                 EvidenceKind::PowerReadiness},
                    Digest{});
  };
  const auto add_cooling = [&](ConstraintKind kind, Severity severity, bool blocking,
                               std::string detail) -> Status {
    return sink.add(kind, severity, blocking, std::string(kDomainCooling), std::move(detail),
                    EvidenceSlot{SourceAuthority::ThermalControlPlane,
                                 EvidenceKind::CoolingReadiness},
                    Digest{});
  };

  if (power != nullptr) {
    if (power->readiness == ReadinessLevel::Unknown) {
      SCP_TRY(sink.add(ConstraintKind::EvidenceIncomplete, Severity::Major, true,
                       std::string(kDomainPower),
                       "the power control plane reported an unknown readiness level",
                       EvidenceSlot{}, Digest{}));
    } else if (power_unavailable) {
      SCP_TRY(add_power(ConstraintKind::PowerReadinessUnavailable, Severity::Critical, true,
                        "the power control plane reports power unavailable"));
    } else if (power_degraded) {
      SCP_TRY(add_power(ConstraintKind::PowerReadinessDegraded, Severity::Major, true,
                        "the power control plane reports degraded power readiness"));
    } else if (power_constrained) {
      SCP_TRY(add_power(ConstraintKind::PowerReadinessConstrained, Severity::Minor, false,
                        "the power control plane reports constrained power readiness"));
    }
    if (power->headroom_milli_kw < options.policy.power_headroom_floor_milli_kw) {
      SCP_TRY(add_power(ConstraintKind::PowerReadinessConstrained, Severity::Major, false,
                        "power headroom is below the configured floor"));
    }
    if (power->required_domains > 0 &&
        power->available_domains < options.policy.required_redundancy_domains) {
      SCP_TRY(add_power(ConstraintKind::RedundancyReduced,
                        power->available_domains == 0 ? Severity::Critical : Severity::Major,
                        power->available_domains == 0,
                        "available power redundancy domains are below the required count"));
    }
  }
  if (cooling != nullptr) {
    if (cooling->readiness == ReadinessLevel::Unknown) {
      SCP_TRY(sink.add(ConstraintKind::EvidenceIncomplete, Severity::Major, true,
                       std::string(kDomainCooling),
                       "the thermal control plane reported an unknown readiness level",
                       EvidenceSlot{}, Digest{}));
    } else if (cooling_unavailable) {
      SCP_TRY(add_cooling(ConstraintKind::CoolingReadinessUnavailable, Severity::Critical, true,
                          "the thermal control plane reports cooling unavailable"));
    } else if (cooling_degraded) {
      SCP_TRY(add_cooling(ConstraintKind::CoolingReadinessDegraded, Severity::Major, true,
                          "the thermal control plane reports degraded cooling readiness"));
    } else if (cooling_constrained) {
      SCP_TRY(add_cooling(ConstraintKind::CoolingReadinessConstrained, Severity::Minor, false,
                          "the thermal control plane reports constrained cooling readiness"));
    }
    if (cooling->headroom_milli_kw < options.policy.cooling_headroom_floor_milli_kw) {
      SCP_TRY(add_cooling(ConstraintKind::CoolingReadinessConstrained, Severity::Major, false,
                          "cooling headroom is below the configured floor"));
    }
    if (cooling->required_domains > 0 &&
        cooling->available_domains < options.policy.required_redundancy_domains) {
      SCP_TRY(add_cooling(ConstraintKind::RedundancyReduced,
                          cooling->available_domains == 0 ? Severity::Critical : Severity::Major,
                          cooling->available_domains == 0,
                          "available cooling redundancy domains are below the required count"));
    }
  }

  const auto add_capability = [&](std::string_view domain, SourceAuthority authority,
                                  EvidenceKind kind, ConstraintKind constrained_kind,
                                  ConstraintKind degraded_kind, ConstraintKind unavailable_kind,
                                  bool unavailable, bool degraded, bool constrained) -> Status {
    if (unavailable) {
      return sink.add(unavailable_kind, Severity::Critical, true, std::string(domain),
                      std::string(to_string(authority)) +
                          " reports the domain unavailable for site work",
                      EvidenceSlot{authority, kind}, Digest{});
    }
    if (degraded) {
      return sink.add(degraded_kind, Severity::Major, true, std::string(domain),
                      std::string(to_string(authority)) +
                          " reports readiness below the degraded floor",
                      EvidenceSlot{authority, kind}, Digest{});
    }
    if (constrained) {
      return sink.add(constrained_kind, Severity::Minor, false, std::string(domain),
                      std::string(to_string(authority)) + " reports constrained readiness",
                      EvidenceSlot{authority, kind}, Digest{});
    }
    return Status{};
  };

  if (asi != nullptr) {
    if (asi->readiness == ReadinessLevel::Unknown) {
      SCP_TRY(sink.add(ConstraintKind::EvidenceIncomplete, Severity::Major, true,
                       std::string(kDomainAccelerators),
                       "the accelerator runtime reported an unknown readiness level",
                       EvidenceSlot{}, Digest{}));
    } else {
      SCP_TRY(add_capability(kDomainAccelerators, SourceAuthority::AsiRuntime,
                             EvidenceKind::AsiCapability, ConstraintKind::AsiReadinessConstrained,
                             ConstraintKind::AsiReadinessDegraded,
                             ConstraintKind::AsiReadinessUnavailable, asi_unavailable, asi_degraded,
                             asi_constrained));
    }
  }
  if (dfi != nullptr) {
    if (dfi->readiness == ReadinessLevel::Unknown) {
      SCP_TRY(sink.add(ConstraintKind::EvidenceIncomplete, Severity::Major, true,
                       std::string(kDomainFabric),
                       "the fabric runtime reported an unknown readiness level", EvidenceSlot{},
                       Digest{}));
    } else {
      SCP_TRY(add_capability(kDomainFabric, SourceAuthority::DfiRuntime,
                             EvidenceKind::DfiCapability, ConstraintKind::DfiReadinessConstrained,
                             ConstraintKind::DfiReadinessDegraded,
                             ConstraintKind::DfiReadinessUnavailable, dfi_unavailable, dfi_degraded,
                             dfi_constrained));
    }
  }

  if (incidents_active) {
    const std::uint32_t count = incident != nullptr ? incident->active_incidents
                                                    : (facility != nullptr ? facility->active_incidents : 0U);
    SCP_TRY(sink.add(ConstraintKind::ActiveIncidents, Severity::Minor, false, "incidents",
                     std::to_string(count) + " active incident(s) reported",
                     EvidenceSlot{SourceAuthority::IncidentStateFabric, EvidenceKind::Incident},
                     Digest{}));
  }
  if (worst_severity == Severity::Critical || worst_severity == Severity::Major) {
    SCP_TRY(sink.add(ConstraintKind::CriticalIncidents,
                     worst_severity == Severity::Critical ? Severity::Critical : Severity::Major,
                     true, "incidents",
                     std::string("worst active incident severity is ") +
                         std::string(to_string(worst_severity)),
                     EvidenceSlot{}, Digest{}));
  }
  if (emergency) {
    SCP_TRY(sink.add(ConstraintKind::EmergencyDeclared, Severity::Critical, true, "site",
                     "emergency operation has been declared", EvidenceSlot{}, Digest{}));
  }
  if (degraded_operation) {
    SCP_TRY(sink.add(ConstraintKind::DegradedOperation, Severity::Major, true, "site",
                     "the facility state ledger reports degraded operation", EvidenceSlot{},
                     Digest{}));
  }
  if (maintenance != nullptr) {
    if (maintenance->mode == MaintenanceMode::Overdue) {
      SCP_TRY(sink.add(ConstraintKind::MaintenanceOverdue, Severity::Major, true, "maintenance",
                       "a maintenance window is overdue",
                       EvidenceSlot{SourceAuthority::MaintenanceCoordinator,
                                    EvidenceKind::Maintenance},
                       Digest{}));
    }
    if (maintenance_active) {
      SCP_TRY(sink.add(ConstraintKind::MaintenanceActive,
                       maintenance->mode == MaintenanceMode::Emergency ? Severity::Critical
                                                                       : Severity::Minor,
                       maintenance->mode == MaintenanceMode::Emergency, "maintenance",
                       "maintenance windows are active", EvidenceSlot{}, Digest{}));
    }
    if (maintenance->scheduled_windows > 0) {
      SCP_TRY(sink.add(ConstraintKind::MaintenanceScheduled, Severity::Informational, false,
                       "maintenance", "maintenance windows are scheduled", EvidenceSlot{},
                       Digest{}));
    }
    if (maintenance->drain_in_progress) {
      SCP_TRY(sink.add(ConstraintKind::DrainInProgress, Severity::Minor, false, "maintenance",
                       "the site is draining", EvidenceSlot{}, Digest{}));
    }
  }
  for (const ObligationAssessment& obligation : snapshot.obligations) {
    const std::string subject(obligation.service_class.view());
    if (obligation.outcome == ObligationOutcome::Unsatisfied) {
      SCP_TRY(sink.add(ConstraintKind::ObligationUnsatisfied,
                       obligation.protected_class ? Severity::Critical : Severity::Major,
                       obligation.protected_class, subject, obligation.detail, EvidenceSlot{},
                       Digest{}));
    } else if (obligation.outcome == ObligationOutcome::AtRisk) {
      SCP_TRY(sink.add(ConstraintKind::ObligationAtRisk, Severity::Minor, false, subject,
                       obligation.detail, EvidenceSlot{}, Digest{}));
    }
  }

  // 6. Configured threshold rules. A rule whose metric cannot be observed does
  //    not fire: absence is not zero, so it is reported instead.
  for (const ThresholdRule& rule : options.policy.rules) {
    const std::optional<std::uint64_t> observed = metric_value(snapshot, rule.subject);
    if (!observed.has_value()) {
      SCP_TRY(sink.add(ConstraintKind::EvidenceIncomplete, Severity::Minor, false,
                       std::string(rule.rule_id.view()),
                       "threshold rule metric '" + rule.subject +
                           "' could not be observed from the accepted evidence",
                       EvidenceSlot{}, Digest{}));
      continue;
    }
    if (!rule_satisfied(rule, observed.value())) {
      SCP_TRY(sink.add(rule.kind, rule.severity, rule.blocking,
                       std::string(rule.rule_id.view()),
                       "observed " + std::to_string(observed.value()) + " does not satisfy " +
                           std::string(to_string(rule.comparison)) + " " +
                           std::to_string(rule.threshold),
                       EvidenceSlot{}, Digest{}));
    }
  }

  // 7. Evidence classification.
  bool any_conflict = false;
  bool any_unsupported = false;
  bool any_unusable_critical = false;
  bool any_stale = false;
  bool any_missing = false;
  for (const SlotResolution& resolution : snapshot.slots) {
    const bool critical = resolution.slot.kind == EvidenceKind::FacilityState ||
                          resolution.slot.kind == EvidenceKind::Lifecycle;
    switch (resolution.outcome) {
      case SlotOutcome::Conflicting:
        any_conflict = true;
        if (critical) {
          any_unusable_critical = true;
        }
        break;
      case SlotOutcome::Unsupported:
        any_unsupported = true;
        if (critical) {
          any_unusable_critical = true;
        }
        break;
      case SlotOutcome::Unauthorized:
        any_missing = true;
        if (critical) {
          any_unusable_critical = true;
        }
        break;
      case SlotOutcome::Missing:
      case SlotOutcome::Indeterminate:
      case SlotOutcome::Superseded:
        any_missing = true;
        if (critical) {
          any_unusable_critical = true;
        }
        break;
      case SlotOutcome::Stale:
      case SlotOutcome::Expired:
        any_stale = true;
        if (critical) {
          any_unusable_critical = true;
        }
        break;
      case SlotOutcome::Accepted:
      case SlotOutcome::AcceptedSuperseding:
        break;
    }
  }

  if (any_conflict) {
    snapshot.classification = EvidenceClassification::Conflicting;
  } else if (any_unsupported) {
    snapshot.classification = EvidenceClassification::Unsupported;
  } else if (any_unusable_critical) {
    snapshot.classification = EvidenceClassification::Indeterminate;
  } else if (any_stale) {
    snapshot.classification = EvidenceClassification::Stale;
  } else if (any_missing) {
    snapshot.classification = EvidenceClassification::Partial;
  } else {
    snapshot.classification = EvidenceClassification::Complete;
  }

  // 8. Site state.
  if (snapshot.classification == EvidenceClassification::Conflicting) {
    snapshot.state = SiteState::Conflicting;
  } else if (snapshot.classification == EvidenceClassification::Indeterminate) {
    snapshot.state = SiteState::Unknown;
  } else {
    switch (snapshot.lifecycle) {
      case LifecycleState::Retired:
        snapshot.state = SiteState::Retired;
        break;
      case LifecycleState::Isolated:
        snapshot.state = SiteState::Isolated;
        break;
      case LifecycleState::Emergency:
        snapshot.state = SiteState::Emergency;
        break;
      case LifecycleState::Maintenance:
        snapshot.state = SiteState::Maintenance;
        break;
      case LifecycleState::Draining:
        snapshot.state = SiteState::Draining;
        break;
      case LifecycleState::Recovering:
        snapshot.state = SiteState::Recovering;
        break;
      case LifecycleState::Commissioning:
        snapshot.state = SiteState::Commissioning;
        break;
      case LifecycleState::Active: {
        const bool degraded = emergency || degraded_operation ||
                              worst_severity == Severity::Critical ||
                              worst_severity == Severity::Major || power_unavailable ||
                              cooling_unavailable || asi_unavailable || dfi_unavailable ||
                              power_degraded || cooling_degraded || asi_degraded || dfi_degraded ||
                              capacity_exhausted || capacity_low || maintenance_overdue;
        const bool constrained =
            power_constrained || cooling_constrained || asi_constrained || dfi_constrained ||
            capacity_tight || incidents_active || maintenance_active ||
            (maintenance != nullptr && maintenance->scheduled_windows > 0) ||
            (maintenance != nullptr && maintenance->drain_in_progress) ||
            snapshot.classification != EvidenceClassification::Complete ||
            !snapshot.constraints.empty();
        if (degraded) {
          snapshot.state = SiteState::Degraded;
        } else if (constrained) {
          snapshot.state = SiteState::Constrained;
        } else {
          snapshot.state = SiteState::Available;
        }
        break;
      }
    }
  }

  std::sort(snapshot.constraints.begin(), snapshot.constraints.end());

  // 9. Readiness gates.
  const Result<std::vector<ReadinessGate>> gates =
      evaluate_all_gates(snapshot, options.policy);
  if (!gates.has_value()) {
    return gates.status();
  }
  snapshot.gates = gates.value();

  snapshot.snapshot_digest = compute_snapshot_digest(snapshot);
  return snapshot;
}

Result<SiteStateSnapshot> compose_site_state(std::span<const EvidenceRecord> records,
                                             const CompositionOptions& options) {
  const Result<ReductionResult> reduction =
      reduce_evidence(records, options.policy, options.evaluation_time);
  if (!reduction.has_value()) {
    return reduction.status();
  }
  return compose_site_state(reduction.value(), options);
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

bool is_known_metric(std::string_view name) noexcept {
  return name == kMetricCapacityHeadroomPercent || name == kMetricAvailableCapacityUnits ||
         name == kMetricPowerHeadroomMilliKw || name == kMetricCoolingHeadroomMilliKw ||
         name == kMetricPowerRedundancyAvailable || name == kMetricCoolingRedundancyAvailable ||
         name == kMetricReadinessPercent || name == kMetricAsiReadinessPercent ||
         name == kMetricDfiReadinessPercent || name == kMetricActiveIncidents ||
         name == kMetricActiveMaintenanceWindows || name == kMetricDrainedPercent;
}

std::optional<std::uint64_t> metric_value(const SiteStateSnapshot& snapshot,
                                          std::string_view name) noexcept {
  const SiteEvidenceView& view = snapshot.evidence;
  if (name == kMetricCapacityHeadroomPercent) {
    const std::optional<std::uint32_t> percent = capacity_headroom_percent(snapshot);
    if (!percent.has_value()) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(percent.value());
  }
  if (name == kMetricAvailableCapacityUnits) {
    if (!view.capacity.has_value()) {
      return std::nullopt;
    }
    return view.capacity->available_units;
  }
  if (name == kMetricPowerHeadroomMilliKw) {
    if (!view.power.has_value()) {
      return std::nullopt;
    }
    return view.power->headroom_milli_kw;
  }
  if (name == kMetricCoolingHeadroomMilliKw) {
    if (!view.cooling.has_value()) {
      return std::nullopt;
    }
    return view.cooling->headroom_milli_kw;
  }
  if (name == kMetricPowerRedundancyAvailable) {
    if (!view.power.has_value()) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(view.power->available_domains);
  }
  if (name == kMetricCoolingRedundancyAvailable) {
    if (!view.cooling.has_value()) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(view.cooling->available_domains);
  }
  if (name == kMetricReadinessPercent) {
    if (snapshot.readiness_domains.empty()) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(snapshot.readiness_percent);
  }
  if (name == kMetricAsiReadinessPercent || name == kMetricDfiReadinessPercent) {
    const std::string_view domain =
        name == kMetricAsiReadinessPercent ? kDomainAccelerators : kDomainFabric;
    const DomainReadiness* observed = find_domain(snapshot, domain);
    if (observed == nullptr || !observed->observed) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(observed->percent);
  }
  if (name == kMetricActiveIncidents) {
    if (view.incident.has_value()) {
      return static_cast<std::uint64_t>(view.incident->active_incidents);
    }
    if (view.facility_state.has_value()) {
      return static_cast<std::uint64_t>(view.facility_state->active_incidents);
    }
    return std::nullopt;
  }
  if (name == kMetricActiveMaintenanceWindows) {
    if (!view.maintenance.has_value()) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(view.maintenance->active_windows);
  }
  if (name == kMetricDrainedPercent) {
    if (!view.maintenance.has_value()) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(view.maintenance->drained_percent);
  }
  return std::nullopt;
}

}  // namespace scp

