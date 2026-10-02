// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "scp/authority.hpp"
#include "scp/composition.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/plan.hpp"
#include "scp/policy.hpp"
#include "scp/readiness.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"
#include "test_support.hpp"

/// \file test_staleness_and_conflict.cpp
/// Stale fencing, explicit conflict and the refusals they produce.
///
/// Every case here asserts what an operator can observe: which publication the
/// site plane accepted, which one it recorded as superseded or conflicting, the
/// constraint that was raised, the classification and state that followed, and
/// whether planning is refused.

namespace {

using scp::Constraint;
using scp::ConstraintKind;
using scp::EvidenceKind;
using scp::EvidenceRecord;
using scp::Result;
using scp::SiteStateSnapshot;
using scp::SlotOutcome;
using scp::SlotResolution;
using scp::SourceAuthority;
using scp::Timestamp;

constexpr std::uint64_t kCapacityInstance = 12;

std::vector<EvidenceRecord> without_kind(const std::vector<EvidenceRecord>& records,
                                         EvidenceKind kind) {
  std::vector<EvidenceRecord> kept;
  kept.reserve(records.size());
  for (const EvidenceRecord& record : records) {
    if (record.kind != kind) {
      kept.push_back(record);
    }
  }
  return kept;
}

void append(std::vector<EvidenceRecord>& into, const std::vector<EvidenceRecord>& extra) {
  into.insert(into.end(), extra.begin(), extra.end());
}

const EvidenceRecord* find_kind(const std::vector<EvidenceRecord>& records, EvidenceKind kind) {
  for (const EvidenceRecord& record : records) {
    if (record.kind == kind) {
      return &record;
    }
  }
  return nullptr;
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

const SlotResolution* resolve_slot(const SiteStateSnapshot& snapshot,
                                   SourceAuthority authority, EvidenceKind kind) {
  const scp::EvidenceSlot wanted{authority, kind};
  for (const SlotResolution& resolution : snapshot.slots) {
    if (resolution.slot == wanted) {
      return &resolution;
    }
  }
  return nullptr;
}

const Constraint* find_constraint(const SiteStateSnapshot& snapshot, ConstraintKind kind) {
  for (const Constraint& constraint : snapshot.constraints) {
    if (constraint.kind == kind) {
      return &constraint;
    }
  }
  return nullptr;
}

const Constraint* find_constraint(const SiteStateSnapshot& snapshot, ConstraintKind kind,
                                  const std::string& subject) {
  for (const Constraint& constraint : snapshot.constraints) {
    if (constraint.kind == kind && constraint.subject == subject) {
      return &constraint;
    }
  }
  return nullptr;
}

bool contains_id(const std::vector<scp::EvidenceId>& ids, const scp::EvidenceId& id) {
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

std::string describe(const EvidenceRecord& record) {
  return std::string(scp::to_string(record.provenance.authority)) + "/" +
         std::string(scp::to_string(record.kind)) +
         " epoch=" + std::to_string(record.provenance.epoch.value()) +
         " generation=" + std::to_string(record.provenance.generation.value()) +
         " sequence=" + std::to_string(record.provenance.sequence.value()) +
         " issued_at=" + std::to_string(record.provenance.issued_at.nanos) +
         " id=" + record.id.to_hex();
}

/// Announces a publication that reached the composed picture although its slot
/// says it may not be used.
void note_composed_unusable_evidence(bool composed, const std::string& subject) {
  if (!composed) {
    return;
  }
  scp_test::Context::instance().note(
      subject +
      " reached the composed picture although its slot outcome says it may not be used: only an "
      "accepted resolution (fresh evidence) may contribute to SiteStateSnapshot::evidence, so a "
      "stale, expired or indeterminate publication must be reported in its slot and nowhere "
      "else.");
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

Result<EvidenceRecord> capacity_record(std::uint64_t epoch, std::uint64_t generation,
                                       std::uint64_t sequence, Timestamp issued_at,
                                       std::uint64_t available_units,
                                       Timestamp valid_until = Timestamp{}) {
  scp_test::RecordSpec spec;
  spec.authority = SourceAuthority::FacilityCapacity;
  spec.instance = kCapacityInstance;
  spec.epoch = epoch;
  spec.generation = generation;
  spec.sequence = sequence;
  spec.issued_at = issued_at;
  spec.valid_until = valid_until;
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
                                                   std::uint64_t generation, Timestamp issued_at,
                                                   std::uint64_t available_units) {
  scp::Provenance provenance;
  provenance.authority = SourceAuthority::FacilityCapacity;
  provenance.instance = scp_test::instance_for(kCapacityInstance);
  provenance.epoch = scp::Epoch(1);
  provenance.generation = scp::SourceGeneration(generation);
  provenance.sequence = scp::Sequence(1);
  provenance.issued_at = issued_at;
  provenance.valid_until = Timestamp{};
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

Result<EvidenceRecord> facility_state_from_wrong_owner(const std::vector<EvidenceRecord>& records) {
  const EvidenceRecord* source = find_kind(records, EvidenceKind::FacilityState);
  if (source == nullptr) {
    return scp::fail(scp::StatusCode::NotFound, "the fixture carries no facility-state record");
  }
  EvidenceRecord forged = *source;
  forged.provenance.authority = SourceAuthority::FacilityCapacity;
  const Result<scp::EvidenceId> derived = scp::derive_evidence_id(
      forged.provenance, forged.kind, forged.schema_version, forged.body);
  if (!derived.has_value()) {
    return derived.status();
  }
  forged.id = derived.value();
  return forged;
}

std::vector<scp::DelegationGrant> accepting_grants(Timestamp issued_at) {
  scp::DelegationGrant grant;
  grant.id = scp::GrantId(0xA11CE00000000001ULL, 0x0000000000000001ULL);
  grant.site = scp_test::default_site();
  const Result<scp::Name> grantor = scp::Name::parse("facility-policy-engine");
  if (grantor.has_value()) {
    grant.grantor = grantor.value();
  }
  const Result<scp::Name> subject = scp::Name::parse("scp-operator");
  if (subject.has_value()) {
    grant.subject = subject.value();
  }
  grant.scopes = scp::scope_for_intent(scp::PlanIntent::AcceptObligation);
  grant.not_before = scp::SiteGeneration(1);
  grant.issued_at = issued_at;
  grant.expires_at = Timestamp{};
  return {grant};
}

Result<scp::ActionPlan> plan_accept(const SiteStateSnapshot& snapshot,
                                    const scp::SitePolicy& policy, Timestamp now,
                                    const std::vector<scp::DelegationGrant>& grants) {
  scp::PlanRequest request;
  request.intent = scp::PlanIntent::AcceptObligation;
  request.site = snapshot.site;
  request.site_generation = scp::SiteGeneration(1);
  request.now = now;
  const Result<scp::Name> principal = scp::Name::parse("scp-operator");
  if (!principal.has_value()) {
    return principal.status();
  }
  request.principal = principal.value();
  const Result<scp::Name> service_class = scp::Name::parse("interactive-inference");
  if (!service_class.has_value()) {
    return service_class.status();
  }
  request.service_class = service_class.value();
  request.identity_seed = 7;
  return scp::plan_intent(request, snapshot, policy, grants);
}

}  // namespace

SCP_TEST(a_stale_generation_never_overwrites_a_newer_accepted_generation) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> newer = scp_test::healthy_site_records(evaluation, 5);

  // Generation 2 says something different about capacity: 1% headroom, which is
  // below the degraded floor and would put the site in Degraded if it won.
  std::vector<EvidenceRecord> older = without_kind(
      scp_test::healthy_site_records(evaluation, 2), EvidenceKind::Capacity);
  const Result<EvidenceRecord> older_capacity = capacity_record(1, 2, 1, evaluation, 1);
  SCP_REQUIRE_OK(older_capacity);
  older.push_back(older_capacity.value());

  // The older publication on its own does produce the degraded picture, so the
  // check below cannot pass by accident.
  const Result<SiteStateSnapshot> older_only =
      scp::compose_site_state(older, options_for(evaluation));
  SCP_REQUIRE_OK(older_only);
  SCP_CHECK(older_only.value().evidence.capacity.has_value());
  SCP_CHECK_EQ(older_only.value().evidence.capacity->available_units, 1ULL);
  SCP_CHECK(older_only.value().has_constraint(ConstraintKind::CapacityHeadroomLow));
  SCP_CHECK_EQ(older_only.value().state, scp::SiteState::Degraded);

  std::vector<EvidenceRecord> newer_first = newer;
  append(newer_first, older);
  std::vector<EvidenceRecord> older_first = older;
  append(older_first, newer);

  const Result<SiteStateSnapshot> forward = scp::compose_site_state(newer_first,
                                                                   options_for(evaluation));
  SCP_REQUIRE_OK(forward);
  const Result<SiteStateSnapshot> backward = scp::compose_site_state(older_first,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(backward);

  for (const SiteStateSnapshot* candidate : {&forward.value(), &backward.value()}) {
    const SlotResolution* slot = resolve_slot(*candidate, EvidenceKind::Capacity);
    SCP_REQUIRE(slot != nullptr);
    SCP_CHECK_EQ(slot->outcome, SlotOutcome::AcceptedSuperseding);
    SCP_CHECK_EQ(slot->accepted_generation.value(), 5ULL);
    SCP_CHECK_EQ(slot->accepted_id, newer.at(2).id);
    SCP_CHECK(contains_id(slot->superseded, older_capacity.value().id));
    SCP_CHECK_EQ(slot->superseded.size(), std::size_t{1});
    // The composed values come from generation 5, not from the older statement.
    SCP_CHECK(candidate->evidence.capacity.has_value());
    SCP_CHECK_EQ(candidate->evidence.capacity->available_units, 60ULL);
    SCP_CHECK(!candidate->has_constraint(ConstraintKind::CapacityHeadroomLow));
    SCP_CHECK_EQ(candidate->state, scp::SiteState::Available);
  }

  // The fencing rule does not depend on which publication arrived first.
  SCP_CHECK_EQ(forward.value().snapshot_digest, backward.value().snapshot_digest);
  SCP_CHECK_EQ(forward.value().evidence_digest, backward.value().evidence_digest);
  SCP_CHECK_EQ(forward.value().state, backward.value().state);
  SCP_CHECK_EQ(forward.value().classification, backward.value().classification);
  const SlotResolution* forward_slot = resolve_slot(forward.value(), EvidenceKind::Capacity);
  const SlotResolution* backward_slot = resolve_slot(backward.value(), EvidenceKind::Capacity);
  SCP_REQUIRE(forward_slot != nullptr);
  SCP_REQUIRE(backward_slot != nullptr);
  SCP_CHECK_EQ(forward_slot->accepted_id, backward_slot->accepted_id);
  SCP_CHECK_EQ(forward_slot->accepted_generation, backward_slot->accepted_generation);
  SCP_CHECK_EQ(forward_slot->accepted_sequence, backward_slot->accepted_sequence);
  SCP_CHECK_EQ(forward_slot->outcome, backward_slot->outcome);
  SCP_CHECK_EQ(forward_slot->superseded, backward_slot->superseded);
}

SCP_TEST(a_higher_epoch_fences_a_larger_generation) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> base = without_kind(
      scp_test::healthy_site_records(evaluation, 1), EvidenceKind::Capacity);

  // Epoch 1 has counted a very long way; epoch 2 is a fresh incarnation that has
  // barely started. The epoch is the fence, so generation 1000 loses to
  // generation 1.
  const Result<EvidenceRecord> old_epoch = capacity_record(1, 1000, 9, evaluation, 1);
  const Result<EvidenceRecord> new_epoch = capacity_record(2, 1, 1, evaluation, 60);
  SCP_REQUIRE_OK(old_epoch);
  SCP_REQUIRE_OK(new_epoch);
  SCP_CHECK(old_epoch.value().provenance.generation.value() >
            new_epoch.value().provenance.generation.value());

  std::vector<EvidenceRecord> epoch_one_first = base;
  epoch_one_first.push_back(old_epoch.value());
  epoch_one_first.push_back(new_epoch.value());
  std::vector<EvidenceRecord> epoch_two_first = base;
  epoch_two_first.push_back(new_epoch.value());
  epoch_two_first.push_back(old_epoch.value());

  const Result<SiteStateSnapshot> forward = scp::compose_site_state(epoch_one_first,
                                                                   options_for(evaluation));
  SCP_REQUIRE_OK(forward);
  const Result<SiteStateSnapshot> backward = scp::compose_site_state(epoch_two_first,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(backward);

  for (const SiteStateSnapshot* candidate : {&forward.value(), &backward.value()}) {
    const SlotResolution* slot = resolve_slot(*candidate, EvidenceKind::Capacity);
    SCP_REQUIRE(slot != nullptr);
    SCP_CHECK_EQ(slot->outcome, SlotOutcome::AcceptedSuperseding);
    SCP_CHECK_EQ(slot->accepted_epoch.value(), 2ULL);
    SCP_CHECK_EQ(slot->accepted_generation.value(), 1ULL);
    SCP_CHECK_EQ(slot->accepted_id, new_epoch.value().id);
    SCP_CHECK(contains_id(slot->superseded, old_epoch.value().id));
    SCP_CHECK(candidate->evidence.capacity.has_value());
    SCP_CHECK_EQ(candidate->evidence.capacity->available_units, 60ULL);
    SCP_CHECK_EQ(candidate->state, scp::SiteState::Available);
  }
  SCP_CHECK_EQ(forward.value().snapshot_digest, backward.value().snapshot_digest);
}

SCP_TEST(contradictory_evidence_becomes_an_explicit_conflict_in_both_orders) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> base = without_kind(
      scp_test::healthy_site_records(evaluation, 1), EvidenceKind::Capacity);

  // Same authority, kind, epoch, generation and sequence: two publishers of the
  // same fact disagree about what the fact is.
  const Result<EvidenceRecord> left = capacity_record(1, 7, 3, evaluation, 60);
  const Result<EvidenceRecord> right = capacity_record(1, 7, 3, evaluation, 10);
  SCP_REQUIRE_OK(left);
  SCP_REQUIRE_OK(right);
  SCP_CHECK_NE(left.value().id, right.value().id);
  SCP_CHECK_NE(left.value().provenance.body_digest, right.value().provenance.body_digest);

  std::vector<EvidenceRecord> left_first = base;
  left_first.push_back(left.value());
  left_first.push_back(right.value());
  std::vector<EvidenceRecord> right_first = base;
  right_first.push_back(right.value());
  right_first.push_back(left.value());

  const Result<SiteStateSnapshot> forward = scp::compose_site_state(left_first,
                                                                   options_for(evaluation));
  SCP_REQUIRE_OK(forward);
  const Result<SiteStateSnapshot> backward = scp::compose_site_state(right_first,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(backward);

  for (const SiteStateSnapshot* candidate : {&forward.value(), &backward.value()}) {
    const SlotResolution* slot = resolve_slot(*candidate, EvidenceKind::Capacity);
    SCP_REQUIRE(slot != nullptr);
    SCP_CHECK_EQ(slot->outcome, SlotOutcome::Conflicting);
    SCP_CHECK(!slot->accepted());
    SCP_CHECK_EQ(slot->conflicting.size(), std::size_t{2});
    SCP_CHECK(contains_id(slot->conflicting, left.value().id));
    SCP_CHECK(contains_id(slot->conflicting, right.value().id));
    // No arrival-order winner: neither statement is composed into the picture.
    SCP_CHECK(!candidate->evidence.capacity.has_value());
    SCP_CHECK_EQ(candidate->classification, scp::EvidenceClassification::Conflicting);
    SCP_CHECK_EQ(candidate->state, scp::SiteState::Conflicting);
    const Constraint* constraint = find_constraint(*candidate, ConstraintKind::EvidenceConflicting);
    SCP_REQUIRE(constraint != nullptr);
    SCP_CHECK_EQ(constraint->severity, scp::Severity::Critical);
    SCP_CHECK(constraint->blocking);
    SCP_CHECK_EQ(constraint->subject, std::string("capacity"));
  }

  // Reporting a conflict is not enough on its own: nothing about the resolution
  // may depend on which of the two contradictory publications arrived first.
  const SlotResolution* forward_slot = resolve_slot(forward.value(), EvidenceKind::Capacity);
  const SlotResolution* backward_slot = resolve_slot(backward.value(), EvidenceKind::Capacity);
  SCP_REQUIRE(forward_slot != nullptr);
  SCP_REQUIRE(backward_slot != nullptr);
  if (!(forward.value().evidence_digest == backward.value().evidence_digest)) {
    scp_test::Context::instance().note(
        "the conflict resolution depended on arrival order: forward recorded accepted " +
        forward_slot->accepted_id.to_hex() + ", reversed recorded " +
        backward_slot->accepted_id.to_hex() +
        "; a contradictory slot must record the same resolution whichever statement arrived "
        "first, so that a conflict can never become an arrival-order winner.");
  }
  SCP_CHECK_EQ(forward_slot->accepted_id, backward_slot->accepted_id);
  SCP_CHECK_EQ(forward.value().snapshot_digest, backward.value().snapshot_digest);
  SCP_CHECK_EQ(forward.value().evidence_digest, backward.value().evidence_digest);

  const Result<scp::ReductionResult> reduction =
      scp::reduce_evidence(left_first, scp_test::strict_policy(), evaluation);
  SCP_REQUIRE_OK(reduction);
  SCP_CHECK_EQ(reduction.value().conflict_count, std::size_t{1});
  SCP_CHECK_EQ(reduction.value().accepted.size(), scp::kEvidenceKindCount - 1);
}

SCP_TEST(a_conflicting_slot_closes_the_new_obligation_gate_and_denies_planning) {
  const Timestamp evaluation = scp_test::base_instant();
  std::vector<EvidenceRecord> records = without_kind(
      scp_test::healthy_site_records(evaluation, 1), EvidenceKind::Capacity);
  const Result<EvidenceRecord> left = capacity_record(1, 7, 3, evaluation, 60);
  const Result<EvidenceRecord> right = capacity_record(1, 7, 3, evaluation, 10);
  SCP_REQUIRE_OK(left);
  SCP_REQUIRE_OK(right);
  records.push_back(left.value());
  records.push_back(right.value());

  const Result<SiteStateSnapshot> composed = scp::compose_site_state(records,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(composed);
  const SiteStateSnapshot& snapshot = composed.value();

  const Result<scp::ReadinessGate> gate = scp::evaluate_gate(scp::GateKind::NewObligation, snapshot,
                                                            scp_test::strict_policy());
  SCP_REQUIRE_OK(gate);
  SCP_CHECK(!gate.value().open);
  SCP_CHECK(gate.value().has_condition("evidence-unconflicted"));
  const scp::GateCondition* unconflicted = gate.value().find_condition("evidence-unconflicted");
  SCP_REQUIRE(unconflicted != nullptr);
  SCP_CHECK(!unconflicted->satisfied);
  SCP_CHECK(!unconflicted->observed.empty());
  const scp::GateCondition* admits = gate.value().find_condition("state-admits-obligation");
  SCP_REQUIRE(admits != nullptr);
  SCP_CHECK(!admits->satisfied);

  // The gate recorded inside the snapshot is the same gate.
  SCP_CHECK_EQ(snapshot.gates.size(), scp::kGateKindCount);
  bool snapshot_gate_closed = false;
  for (const scp::ReadinessGate& recorded : snapshot.gates) {
    if (recorded.kind == scp::GateKind::NewObligation) {
      snapshot_gate_closed = !recorded.open;
    }
  }
  SCP_CHECK(snapshot_gate_closed);

  const std::vector<scp::DelegationGrant> grants = accepting_grants(evaluation);
  const Result<scp::ActionPlan> plan = plan_accept(snapshot, scp_test::strict_policy(), evaluation,
                                                  grants);
  SCP_REQUIRE_OK(plan);
  SCP_CHECK(!plan.value().permitted);
  SCP_CHECK(!plan.value().gate.open);
  SCP_CHECK_EQ(plan.value().gate.kind, scp::GateKind::NewObligation);
  SCP_CHECK(!plan.value().denial_reason.empty());
  SCP_CHECK_EQ(plan.value().request_count(), std::size_t{0});
  SCP_CHECK(plan.value().validate().ok());

  // The refusal is explicit. The indeterminate-state refusal is checked before
  // the gate refusal, so the reason names the conflicting picture rather than the
  // gate; the closed gate is still recorded on the plan above.
  SCP_CHECK(plan.value().denial_reason.find("conflicting") != std::string::npos);
}

SCP_TEST(the_denial_reason_names_the_gate_that_refused) {
  const Timestamp evaluation = scp_test::base_instant();
  // Stale capacity evidence: the site state stays determinate (Constrained), so
  // the refusal comes from the gate itself.
  std::vector<EvidenceRecord> records = without_kind(
      scp_test::healthy_site_records(evaluation, 1), EvidenceKind::Capacity);
  const Result<EvidenceRecord> stale_capacity =
      capacity_record(1, 1, 1, scp_test::instant_after(-1000), 60);
  SCP_REQUIRE_OK(stale_capacity);
  records.push_back(stale_capacity.value());

  const Result<SiteStateSnapshot> composed = scp::compose_site_state(records,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(composed);
  SCP_CHECK_EQ(composed.value().state, scp::SiteState::Constrained);
  SCP_CHECK(!scp::is_indeterminate(composed.value().state));

  const Result<scp::ActionPlan> plan = plan_accept(composed.value(), scp_test::strict_policy(),
                                                  evaluation, accepting_grants(evaluation));
  SCP_REQUIRE_OK(plan);
  SCP_CHECK(!plan.value().permitted);
  SCP_CHECK(!plan.value().gate.open);
  SCP_CHECK(plan.value().denial_reason.find("gate new-obligation is closed") != std::string::npos);
  SCP_CHECK(plan.value().denial_reason.find("evidence-fresh") != std::string::npos);
  SCP_CHECK_EQ(plan.value().request_count(), std::size_t{0});
}

SCP_TEST(planning_on_a_healthy_site_is_permitted_and_produces_requests) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> records = scp_test::healthy_site_records(evaluation, 1);
  const Result<SiteStateSnapshot> composed = scp::compose_site_state(records,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(composed);

  const Result<scp::ReadinessGate> gate = scp::evaluate_gate(scp::GateKind::NewObligation,
                                                            composed.value(),
                                                            scp_test::strict_policy());
  SCP_REQUIRE_OK(gate);
  SCP_REQUIRE(gate.value().open);

  const Result<scp::ActionPlan> plan = plan_accept(composed.value(), scp_test::strict_policy(),
                                                  evaluation, accepting_grants(evaluation));
  SCP_REQUIRE_OK(plan);
  // Authority was delegated, the gate is open and the intent produces three
  // effect requests. A plan that satisfies every precondition must be permitted
  // and must carry the requests it describes.
  SCP_CHECK(plan.value().authority.granted());
  SCP_CHECK(plan.value().permitted);
  SCP_CHECK(plan.value().request_count() > 0);
  SCP_CHECK(plan.value().denial_reason.empty());
  SCP_CHECK(plan.value().validate().ok());
  // Every request addresses a boundary that owns the effect, never this plane.
  for (const scp::PlannedStep& step : plan.value().steps) {
    SCP_CHECK(!step.request.required_scope.empty());
    SCP_CHECK(step.request.site == scp_test::default_site());
    SCP_CHECK(!step.request.idempotency.is_nil());
  }
}

SCP_TEST(stale_and_expired_publications_are_reported_and_never_participate) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> base = without_kind(
      scp_test::healthy_site_records(evaluation, 1), EvidenceKind::Capacity);
  const scp::FreshnessPolicy freshness = scp_test::strict_policy().freshness;

  // Older than stale_after (900s) but younger than expire_after (3600s).
  const Result<EvidenceRecord> stale_capacity =
      capacity_record(1, 1, 1, scp_test::instant_after(-1000), 60);
  SCP_REQUIRE_OK(stale_capacity);
  SCP_CHECK_EQ(scp::classify_freshness(stale_capacity.value(), evaluation, freshness),
               scp::Freshness::Stale);

  std::vector<EvidenceRecord> stale_set = base;
  stale_set.push_back(stale_capacity.value());
  const Result<SiteStateSnapshot> stale_snapshot = scp::compose_site_state(stale_set,
                                                                          options_for(evaluation));
  SCP_REQUIRE_OK(stale_snapshot);
  const SlotResolution* stale_slot = resolve_slot(stale_snapshot.value(), EvidenceKind::Capacity);
  SCP_REQUIRE(stale_slot != nullptr);
  SCP_CHECK_EQ(stale_slot->outcome, SlotOutcome::Stale);
  SCP_CHECK_EQ(stale_slot->freshness, scp::Freshness::Stale);
  SCP_CHECK(!scp::participates(stale_slot->freshness));
  SCP_CHECK(!stale_slot->accepted());
  SCP_CHECK_EQ(stale_slot->accepted_id, stale_capacity.value().id);
  SCP_CHECK_EQ(stale_slot->accepted_generation.value(), 1ULL);
  note_composed_unusable_evidence(stale_snapshot.value().evidence.capacity.has_value(),
                                  "a stale capacity publication");
  SCP_CHECK(!stale_snapshot.value().evidence.capacity.has_value());
  SCP_CHECK_EQ(stale_snapshot.value().classification, scp::EvidenceClassification::Stale);
  SCP_CHECK_EQ(stale_snapshot.value().state, scp::SiteState::Constrained);
  const Constraint* stale_constraint = find_constraint(stale_snapshot.value(),
                                                       ConstraintKind::EvidenceStale, "capacity");
  SCP_REQUIRE(stale_constraint != nullptr);
  SCP_CHECK_EQ(stale_constraint->severity, scp::Severity::Minor);
  SCP_CHECK(!stale_constraint->blocking);
  SCP_CHECK(stale_constraint->source ==
            (scp::EvidenceSlot{SourceAuthority::FacilityCapacity, EvidenceKind::Capacity}));

  // Older than expire_after: the same constraint kind, but blocking.
  const Result<EvidenceRecord> expired_capacity =
      capacity_record(1, 1, 1, scp_test::instant_after(-4000), 60);
  SCP_REQUIRE_OK(expired_capacity);
  SCP_CHECK_EQ(scp::classify_freshness(expired_capacity.value(), evaluation, freshness),
               scp::Freshness::Expired);
  std::vector<EvidenceRecord> expired_set = base;
  expired_set.push_back(expired_capacity.value());
  const Result<SiteStateSnapshot> expired_snapshot =
      scp::compose_site_state(expired_set, options_for(evaluation));
  SCP_REQUIRE_OK(expired_snapshot);
  const SlotResolution* expired_slot = resolve_slot(expired_snapshot.value(),
                                                    EvidenceKind::Capacity);
  SCP_REQUIRE(expired_slot != nullptr);
  SCP_CHECK_EQ(expired_slot->outcome, SlotOutcome::Expired);
  SCP_CHECK_EQ(expired_slot->freshness, scp::Freshness::Expired);
  note_composed_unusable_evidence(expired_snapshot.value().evidence.capacity.has_value(),
                                  "an expired capacity publication");
  SCP_CHECK(!expired_snapshot.value().evidence.capacity.has_value());
  SCP_CHECK_EQ(expired_snapshot.value().classification, scp::EvidenceClassification::Stale);
  const Constraint* expired_constraint = find_constraint(expired_snapshot.value(),
                                                         ConstraintKind::EvidenceStale, "capacity");
  SCP_REQUIRE(expired_constraint != nullptr);
  SCP_CHECK_EQ(expired_constraint->severity, scp::Severity::Major);
  SCP_CHECK(expired_constraint->blocking);

  // A stated expiry in the past expires the record even when it was issued
  // moments ago.
  const Result<EvidenceRecord> withdrawn = capacity_record(1, 1, 1, scp_test::instant_after(-100),
                                                           60, scp_test::instant_after(-10));
  SCP_REQUIRE_OK(withdrawn);
  SCP_CHECK_EQ(scp::classify_freshness(withdrawn.value(), evaluation, freshness),
               scp::Freshness::Expired);
  std::vector<EvidenceRecord> withdrawn_set = base;
  withdrawn_set.push_back(withdrawn.value());
  const Result<SiteStateSnapshot> withdrawn_snapshot =
      scp::compose_site_state(withdrawn_set, options_for(evaluation));
  SCP_REQUIRE_OK(withdrawn_snapshot);
  const SlotResolution* withdrawn_slot = resolve_slot(withdrawn_snapshot.value(),
                                                      EvidenceKind::Capacity);
  SCP_REQUIRE(withdrawn_slot != nullptr);
  SCP_CHECK_EQ(withdrawn_slot->outcome, SlotOutcome::Expired);

  // A stated expiry in the future keeps a publication fresh past stale_after.
  const Result<EvidenceRecord> extended = capacity_record(1, 1, 1, scp_test::instant_after(-1000),
                                                          60, scp_test::instant_after(600));
  SCP_REQUIRE_OK(extended);
  SCP_CHECK_EQ(scp::classify_freshness(extended.value(), evaluation, freshness),
               scp::Freshness::Fresh);
}

SCP_TEST(a_future_dated_publication_is_indeterminate_and_unused) {
  const Timestamp evaluation = scp_test::base_instant();
  const scp::FreshnessPolicy freshness = scp_test::strict_policy().freshness;
  const std::vector<EvidenceRecord> base = without_kind(
      scp_test::healthy_site_records(evaluation, 1), EvidenceKind::Capacity);

  const Result<EvidenceRecord> future_capacity =
      capacity_record(1, 1, 1, scp_test::instant_after(100), 1);
  SCP_REQUIRE_OK(future_capacity);
  SCP_CHECK_EQ(scp::classify_freshness(future_capacity.value(), evaluation, freshness),
               scp::Freshness::Indeterminate);

  std::vector<EvidenceRecord> records = base;
  records.push_back(future_capacity.value());
  const Result<SiteStateSnapshot> composed = scp::compose_site_state(records,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(composed);
  const SlotResolution* slot = resolve_slot(composed.value(), EvidenceKind::Capacity);
  SCP_REQUIRE(slot != nullptr);
  SCP_CHECK_EQ(slot->outcome, SlotOutcome::Indeterminate);
  SCP_CHECK_EQ(slot->freshness, scp::Freshness::Indeterminate);
  SCP_CHECK(!slot->accepted());
  note_composed_unusable_evidence(composed.value().evidence.capacity.has_value(),
                                  "a future-dated capacity publication");
  SCP_CHECK(!composed.value().evidence.capacity.has_value());
  // The future-dated statement is not a zero and not a fresh fact: the site is
  // reported as Partial rather than Complete, and the 1% headroom it claims never
  // reaches the picture.
  SCP_CHECK_EQ(composed.value().classification, scp::EvidenceClassification::Partial);
  SCP_CHECK_EQ(composed.value().state, scp::SiteState::Constrained);
  SCP_CHECK(!composed.value().has_constraint(ConstraintKind::CapacityHeadroomLow));
  const Constraint* incomplete = find_constraint(composed.value(),
                                                 ConstraintKind::EvidenceIncomplete, "capacity");
  SCP_CHECK(incomplete != nullptr);

  // The same rule for a critical slot: the picture cannot be composed at all.
  const std::vector<EvidenceRecord> healthy = scp_test::healthy_site_records(evaluation, 1);
  const EvidenceRecord* facility = find_kind(healthy, EvidenceKind::FacilityState);
  SCP_REQUIRE(facility != nullptr);
  EvidenceRecord future_facility = *facility;
  future_facility.provenance.issued_at = scp_test::instant_after(100);
  const Result<scp::EvidenceId> rederived = scp::derive_evidence_id(
      future_facility.provenance, future_facility.kind, future_facility.schema_version,
      future_facility.body);
  SCP_REQUIRE_OK(rederived);
  future_facility.id = rederived.value();

  std::vector<EvidenceRecord> critical_set = without_kind(healthy, EvidenceKind::FacilityState);
  critical_set.push_back(future_facility);
  const Result<SiteStateSnapshot> critical_snapshot =
      scp::compose_site_state(critical_set, options_for(evaluation));
  SCP_REQUIRE_OK(critical_snapshot);
  const SlotResolution* critical_slot = resolve_slot(critical_snapshot.value(),
                                                     EvidenceKind::FacilityState);
  SCP_REQUIRE(critical_slot != nullptr);
  SCP_CHECK_EQ(critical_slot->outcome, SlotOutcome::Indeterminate);
  note_composed_unusable_evidence(critical_snapshot.value().evidence.facility_state.has_value(),
                                  "a future-dated facility-state publication");
  SCP_CHECK(!critical_snapshot.value().evidence.facility_state.has_value());
  SCP_CHECK_EQ(critical_snapshot.value().classification,
               scp::EvidenceClassification::Indeterminate);
  SCP_CHECK_EQ(critical_snapshot.value().state, scp::SiteState::Unknown);
}

SCP_TEST(an_unsupported_schema_does_not_let_an_older_readable_generation_win) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> base = without_kind(
      scp_test::healthy_site_records(evaluation, 1), EvidenceKind::Capacity);

  const Result<EvidenceRecord> readable = capacity_record(1, 1, 1, evaluation, 60);
  const Result<EvidenceRecord> unreadable = capacity_record_with_schema(999, 2, evaluation, 1);
  SCP_REQUIRE_OK(readable);
  SCP_REQUIRE_OK(unreadable);
  SCP_CHECK_EQ(readable.value().schema_version, scp::kEvidenceSchemaVersion);
  SCP_CHECK_EQ(unreadable.value().schema_version, static_cast<std::uint16_t>(999));

  std::vector<EvidenceRecord> records = base;
  records.push_back(readable.value());
  records.push_back(unreadable.value());
  std::vector<EvidenceRecord> reversed = base;
  reversed.push_back(unreadable.value());
  reversed.push_back(readable.value());

  const Result<scp::ReductionResult> reduction =
      scp::reduce_evidence(records, scp_test::strict_policy(), evaluation);
  SCP_REQUIRE_OK(reduction);
  SCP_CHECK_EQ(reduction.value().unsupported_count, std::size_t{1});
  const SlotResolution* reduced_slot = nullptr;
  for (const SlotResolution& resolution : reduction.value().slots) {
    if (resolution.slot.kind == EvidenceKind::Capacity) {
      reduced_slot = &resolution;
    }
  }
  SCP_REQUIRE(reduced_slot != nullptr);
  SCP_CHECK_EQ(reduced_slot->outcome, SlotOutcome::Unsupported);
  SCP_CHECK(!reduced_slot->accepted());
  SCP_CHECK_EQ(reduced_slot->accepted_generation.value(), 2ULL);
  SCP_CHECK_EQ(reduced_slot->accepted_id, unreadable.value().id);
  SCP_CHECK_EQ(reduced_slot->accepted_digest, unreadable.value().provenance.body_digest);
  SCP_CHECK(!reduced_slot->detail.empty());

  const Result<SiteStateSnapshot> composed = scp::compose_site_state(records,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(composed);
  const Result<SiteStateSnapshot> composed_reversed =
      scp::compose_site_state(reversed, options_for(evaluation));
  SCP_REQUIRE_OK(composed_reversed);
  for (const SiteStateSnapshot* candidate : {&composed.value(), &composed_reversed.value()}) {
    const SlotResolution* slot = resolve_slot(*candidate, EvidenceKind::Capacity);
    SCP_REQUIRE(slot != nullptr);
    SCP_CHECK_EQ(slot->outcome, SlotOutcome::Unsupported);
    SCP_CHECK_EQ(slot->accepted_generation.value(), 2ULL);
    // Older readable truth is not substituted for a statement this build cannot
    // read, so the slot reports no composed value at all.
    SCP_CHECK(!candidate->evidence.capacity.has_value());
    SCP_CHECK_EQ(candidate->classification, scp::EvidenceClassification::Unsupported);
    const Constraint* constraint = find_constraint(*candidate, ConstraintKind::EvidenceUnsupported,
                                                   "capacity");
    SCP_REQUIRE(constraint != nullptr);
    SCP_CHECK(constraint->blocking);
  }
  SCP_CHECK_EQ(composed.value().snapshot_digest, composed_reversed.value().snapshot_digest);

  // The readable publication on its own does compose, so the checks above are
  // not passing because a capacity record is unusable for some other reason.
  std::vector<EvidenceRecord> readable_set = base;
  readable_set.push_back(readable.value());
  const Result<SiteStateSnapshot> readable_only =
      scp::compose_site_state(readable_set, options_for(evaluation));
  SCP_REQUIRE_OK(readable_only);
  SCP_CHECK(!readable_only.value().has_constraint(ConstraintKind::EvidenceUnsupported));
  SCP_CHECK_EQ(readable_only.value().classification, scp::EvidenceClassification::Complete);
  SCP_CHECK(readable_only.value().evidence.capacity.has_value());
  SCP_CHECK_EQ(readable_only.value().evidence.capacity->available_units, 60ULL);
}

SCP_TEST(an_unauthorized_publisher_is_rejected_and_never_participates) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> healthy = scp_test::healthy_site_records(evaluation, 1);
  const EvidenceRecord* facility = find_kind(healthy, EvidenceKind::FacilityState);
  SCP_REQUIRE(facility != nullptr);

  // The facility capacity runtime does not own facility state; create() refuses
  // to build such a record at all.
  scp::Provenance wrong_owner;
  wrong_owner.authority = SourceAuthority::FacilityCapacity;
  wrong_owner.instance = scp_test::instance_for(70);
  wrong_owner.epoch = scp::Epoch(1);
  wrong_owner.generation = scp::SourceGeneration(1);
  wrong_owner.sequence = scp::Sequence(1);
  wrong_owner.issued_at = evaluation;
  const Result<EvidenceRecord> refused = EvidenceRecord::create(
      wrong_owner, EvidenceKind::FacilityState, scp::kEvidenceSchemaVersion, facility->body);
  SCP_REQUIRE_ERROR(refused, scp::StatusCode::Unauthorized);

  const Result<EvidenceRecord> forged = facility_state_from_wrong_owner(healthy);
  SCP_REQUIRE_OK(forged);
  SCP_CHECK_EQ(forged.value().validate().code(), scp::StatusCode::Unauthorized);

  std::vector<EvidenceRecord> records = without_kind(healthy, EvidenceKind::FacilityState);
  records.push_back(forged.value());
  const Result<scp::ReductionResult> reduction =
      scp::reduce_evidence(records, scp_test::strict_policy(), evaluation);
  SCP_REQUIRE_OK(reduction);
  SCP_CHECK_EQ(reduction.value().unauthorized_count, std::size_t{1});
  bool rejected_contains_forgery = false;
  for (const EvidenceRecord& record : reduction.value().rejected) {
    if (record.id == forged.value().id) {
      rejected_contains_forgery = true;
    }
  }
  if (!rejected_contains_forgery) {
    scp_test::Context::instance().note(
        "an unauthorized publication was counted but not listed: every distinct identity must "
        "appear in exactly one of accepted, superseded, conflicting, redundant or rejected "
        "(include/scp/composition.hpp:47-83), so unauthorized_count reporting a record that "
        "ReductionResult::rejected does not contain breaks the partition an operator relies on.");
  }
  SCP_CHECK(rejected_contains_forgery);

  const Result<SiteStateSnapshot> composed = scp::compose_site_state(records,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(composed);
  // The forged publication is reported against the slot its publisher claims,
  // and the real slot is reported as missing rather than silently filled.
  const SlotResolution* forged_slot = resolve_slot(composed.value(),
                                                   SourceAuthority::FacilityCapacity,
                                                   EvidenceKind::FacilityState);
  SCP_REQUIRE(forged_slot != nullptr);
  SCP_CHECK_EQ(forged_slot->outcome, SlotOutcome::Unauthorized);
  SCP_CHECK(!forged_slot->accepted());
  SCP_CHECK(!forged_slot->detail.empty());
  const SlotResolution* real_slot = resolve_slot(composed.value(), EvidenceKind::FacilityState);
  SCP_REQUIRE(real_slot != nullptr);
  SCP_CHECK_EQ(real_slot->outcome, SlotOutcome::Missing);
  SCP_CHECK(real_slot->accepted_id.is_nil());
  SCP_CHECK_EQ(composed.value().slots.size(), scp::kEvidenceKindCount + 1);
  SCP_CHECK(!composed.value().evidence.facility_state.has_value());
  SCP_CHECK_EQ(composed.value().classification, scp::EvidenceClassification::Indeterminate);
  SCP_CHECK_EQ(composed.value().state, scp::SiteState::Unknown);
  SCP_CHECK(composed.value().has_constraint(ConstraintKind::EvidenceUnauthorized));
}

SCP_TEST(missing_slots_are_explicit_and_critical_gaps_yield_unknown) {
  const Timestamp evaluation = scp_test::base_instant();

  // Nothing published at all.
  const std::vector<EvidenceRecord> nothing;
  const Result<SiteStateSnapshot> empty = scp::compose_site_state(nothing,
                                                                 options_for(evaluation));
  SCP_REQUIRE_OK(empty);
  SCP_CHECK_EQ(empty.value().slots.size(), scp::kEvidenceKindCount);
  SCP_CHECK_EQ(empty.value().constraints.size(), scp::kEvidenceKindCount);
  SCP_CHECK_EQ(empty.value().evidence.populated_count(), std::size_t{0});
  SCP_CHECK_EQ(empty.value().readiness_percent, 0U);
  SCP_CHECK_EQ(empty.value().classification, scp::EvidenceClassification::Indeterminate);
  SCP_CHECK_EQ(empty.value().state, scp::SiteState::Unknown);
  for (const SlotResolution& resolution : empty.value().slots) {
    SCP_CHECK_EQ(resolution.outcome, SlotOutcome::Missing);
    SCP_CHECK(resolution.accepted_id.is_nil());
    SCP_CHECK(!resolution.detail.empty());
  }
  SCP_CHECK(empty.value().find_slot(scp::EvidenceSlot{SourceAuthority::FacilityStateLedger,
                                                      EvidenceKind::FacilityState}) != nullptr);

  // Critical evidence missing: facility state and lifecycle. The picture cannot
  // be claimed, so the site is Unknown rather than Partial.
  const std::vector<EvidenceRecord> healthy = scp_test::healthy_site_records(evaluation, 1);
  std::vector<EvidenceRecord> without_critical = without_kind(healthy, EvidenceKind::FacilityState);
  without_critical = without_kind(without_critical, EvidenceKind::Lifecycle);
  const Result<SiteStateSnapshot> critical = scp::compose_site_state(without_critical,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(critical);
  SCP_CHECK_EQ(critical.value().classification, scp::EvidenceClassification::Indeterminate);
  SCP_CHECK_EQ(critical.value().state, scp::SiteState::Unknown);
  const SlotResolution* facility_slot = resolve_slot(critical.value(), EvidenceKind::FacilityState);
  const SlotResolution* lifecycle_slot = resolve_slot(critical.value(), EvidenceKind::Lifecycle);
  SCP_REQUIRE(facility_slot != nullptr);
  SCP_REQUIRE(lifecycle_slot != nullptr);
  SCP_CHECK_EQ(facility_slot->outcome, SlotOutcome::Missing);
  SCP_CHECK_EQ(lifecycle_slot->outcome, SlotOutcome::Missing);
  const Constraint* facility_constraint = find_constraint(critical.value(),
                                                          ConstraintKind::EvidenceIncomplete,
                                                          "facility-state");
  SCP_REQUIRE(facility_constraint != nullptr);
  SCP_CHECK(facility_constraint->blocking);
  SCP_CHECK(facility_constraint->source ==
            (scp::EvidenceSlot{SourceAuthority::FacilityStateLedger, EvidenceKind::FacilityState}));
  SCP_CHECK(find_constraint(critical.value(), ConstraintKind::EvidenceIncomplete, "lifecycle") !=
            nullptr);

  // Non-critical evidence missing: the picture is Partial but determinate.
  std::vector<EvidenceRecord> without_maintenance = without_kind(healthy,
                                                                 EvidenceKind::Maintenance);
  const Result<SiteStateSnapshot> partial = scp::compose_site_state(without_maintenance,
                                                                   options_for(evaluation));
  SCP_REQUIRE_OK(partial);
  const SlotResolution* maintenance_slot = resolve_slot(partial.value(),
                                                        EvidenceKind::Maintenance);
  SCP_REQUIRE(maintenance_slot != nullptr);
  SCP_CHECK_EQ(maintenance_slot->outcome, SlotOutcome::Missing);
  SCP_CHECK_EQ(partial.value().classification, scp::EvidenceClassification::Partial);
  SCP_CHECK_EQ(partial.value().state, scp::SiteState::Constrained);
  SCP_CHECK_NE(partial.value().state, scp::SiteState::Unknown);
  SCP_CHECK_EQ(partial.value().evidence.populated_count(), scp::kEvidenceKindCount - 1);
  const Constraint* maintenance_constraint = find_constraint(partial.value(),
                                                             ConstraintKind::EvidenceIncomplete,
                                                             "maintenance");
  SCP_REQUIRE(maintenance_constraint != nullptr);
  SCP_CHECK(maintenance_constraint->blocking);
}

SCP_TEST(an_extreme_past_instant_is_not_treated_as_fresh) {
  const Timestamp evaluation = scp_test::base_instant();
  const std::vector<EvidenceRecord> base = without_kind(
      scp_test::healthy_site_records(evaluation, 1), EvidenceKind::Capacity);

  // A publication dated at the bottom of the representable range is older than
  // every threshold by any measure, so it must be Expired, must not be accepted
  // and must not reach the composed picture. Computing the age in plain signed
  // arithmetic would overflow here, so the check below pins the answer that the
  // site plane may give.
  const Result<EvidenceRecord> ancient =
      capacity_record(1, 1, 1, Timestamp{std::numeric_limits<std::int64_t>::min()}, 1);
  SCP_REQUIRE_OK(ancient);
  const bool classified_expired = scp::classify_freshness(ancient.value(), evaluation,
                                                          scp_test::strict_policy().freshness) ==
                                  scp::Freshness::Expired;
  if (!classified_expired) {
    scp_test::Context::instance().note(
        describe(ancient.value()) +
        " is older than every threshold by any measure and must classify as Expired; an age that "
        "does not fit in the signed range must not wrap into the negative and read as Fresh.");
  }
  SCP_CHECK(classified_expired);

  std::vector<EvidenceRecord> records = base;
  records.push_back(ancient.value());
  const Result<SiteStateSnapshot> composed = scp::compose_site_state(records,
                                                                    options_for(evaluation));
  SCP_REQUIRE_OK(composed);
  const SlotResolution* slot = resolve_slot(composed.value(), EvidenceKind::Capacity);
  SCP_REQUIRE(slot != nullptr);
  SCP_CHECK_EQ(slot->outcome, SlotOutcome::Expired);
  SCP_CHECK(!composed.value().evidence.capacity.has_value());
}

SCP_TEST_MAIN("scp.staleness-and-conflict")
