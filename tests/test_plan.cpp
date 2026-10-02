// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

// The effect-request planner: a pure function that produces proposals, never
// effects. Identity, retry safety, the authority and gate decisions that permit
// or deny a plan, and the bounds that refuse rather than truncate.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "scp/authority.hpp"
#include "scp/composition.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/plan.hpp"
#include "scp/policy.hpp"
#include "scp/readiness.hpp"
#include "scp/runtime.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"
#include "test_support.hpp"

using scp::ActionPlan;
using scp::ActionScope;
using scp::AuthorityOutcome;
using scp::DelegationGrant;
using scp::EffectRequest;
using scp::EvidenceRecord;
using scp::GateKind;
using scp::GrantId;
using scp::IdempotencyKey;
using scp::Name;
using scp::PlanIntent;
using scp::PlanRequest;
using scp::PreconditionKind;
using scp::RequestId;
using scp::Result;
using scp::ScopeSet;
using scp::SiteGeneration;
using scp::SitePolicy;
using scp::SiteStateSnapshot;
using scp::SourceAuthority;
using scp::StatusCode;
using scp::Status;
using scp::Timestamp;

namespace {

constexpr std::array<PlanIntent, scp::kPlanIntentCount> kIntents = {
    PlanIntent::AcceptObligation,    PlanIntent::ReleaseObligation,
    PlanIntent::EnterMaintenance,    PlanIntent::ControlledDrain,
    PlanIntent::EmergencyOperation,  PlanIntent::BeginRecovery,
    PlanIntent::ReturnToService,     PlanIntent::IsolateSite,
    PlanIntent::RetireSite,          PlanIntent::ResumeNormalOperation};

constexpr std::array<SourceAuthority, scp::kSourceAuthorityCount> kAuthorities = {
    SourceAuthority::FacilityStateLedger, SourceAuthority::FacilityCapacity,
    SourceAuthority::PowerControlPlane,   SourceAuthority::ThermalControlPlane,
    SourceAuthority::FacilityPolicyEngine, SourceAuthority::IncidentStateFabric,
    SourceAuthority::MaintenanceCoordinator, SourceAuthority::AsiRuntime,
    SourceAuthority::DfiRuntime,          SourceAuthority::ServiceClassRegistry};

std::vector<EvidenceRecord> healthy() {
  return scp_test::healthy_site_records(scp_test::base_instant(), 1);
}

Name name_of(std::string_view text) {
  const Result<Name> parsed = Name::parse(text);
  if (!parsed.has_value()) {
    ::scp_test::Context::instance().note("fixture name did not parse: " + std::string(text));
    SCP_CHECK(false);
    return Name();
  }
  return parsed.value();
}

void expect_ok(const Status& status, const char* what) {
  if (!status.ok()) {
    ::scp_test::Context::instance().note(std::string(what) + " failed: " + status.to_string());
  }
  SCP_CHECK(status.ok());
}

Result<SiteStateSnapshot> compose(const std::vector<EvidenceRecord>& records,
                                  const SitePolicy& policy, Timestamp at,
                                  SiteGeneration generation = SiteGeneration::first()) {
  scp::CompositionOptions options;
  options.site = scp_test::default_site();
  options.site_generation = generation;
  options.evaluation_time = at;
  options.policy = policy;
  return scp::compose_site_state(records, options);
}

SiteStateSnapshot must_compose(const std::vector<EvidenceRecord>& records,
                               const SitePolicy& policy, Timestamp at,
                               SiteGeneration generation = SiteGeneration::first()) {
  const Result<SiteStateSnapshot> snapshot = compose(records, policy, at, generation);
  if (!snapshot.has_value()) {
    ::scp_test::Context::instance().note("composition failed: " + snapshot.status().to_string());
    SCP_CHECK(false);
    return SiteStateSnapshot{};
  }
  return snapshot.value();
}

DelegationGrant grant_with(ScopeSet scopes, std::uint64_t serial) {
  DelegationGrant grant;
  grant.id = GrantId(0x6B00000000000000ULL, serial);
  grant.site = scp_test::default_site();
  grant.grantor = name_of("facility-policy-engine");
  grant.subject = name_of("site-control-plane");
  grant.scopes = scopes;
  grant.not_before = SiteGeneration::first();
  grant.issued_at = scp_test::base_instant();
  grant.expires_at = scp_test::instant_after(3600);
  return grant;
}

DelegationGrant all_scopes_grant(std::uint64_t serial) {
  return grant_with(ScopeSet(0xFFFF), serial);
}

PlanRequest request_for(PlanIntent intent, SiteGeneration generation, Timestamp now) {
  PlanRequest request;
  request.intent = intent;
  request.site = scp_test::default_site();
  request.site_generation = generation;
  request.now = now;
  request.principal = name_of("site-operator");
  request.service_class = name_of("interactive-inference");
  return request;
}

/// The action each boundary owns. A request addressed to a runtime that does
/// not own the effect it asks for would be a proposal this plane has no right
/// to make, so every produced request is checked against this table.
struct ActionOwner {
  std::string_view action;
  SourceAuthority owner;
};

const std::array<ActionOwner, 23>& action_owners() {
  static const std::array<ActionOwner, 23> kOwners = {{
      {"record-obligation-acceptance", SourceAuthority::ServiceClassRegistry},
      {"reserve-accelerator-capacity", SourceAuthority::AsiRuntime},
      {"reserve-fabric-capacity", SourceAuthority::DfiRuntime},
      {"record-obligation-release", SourceAuthority::ServiceClassRegistry},
      {"open-maintenance-window", SourceAuthority::MaintenanceCoordinator},
      {"publish-maintenance-state", SourceAuthority::FacilityStateLedger},
      {"begin-controlled-drain", SourceAuthority::MaintenanceCoordinator},
      {"evacuate-accelerator-workloads", SourceAuthority::AsiRuntime},
      {"quiesce-fabric-traffic", SourceAuthority::DfiRuntime},
      {"enter-emergency-power-profile", SourceAuthority::PowerControlPlane},
      {"enter-emergency-thermal-profile", SourceAuthority::ThermalControlPlane},
      {"publish-emergency-state", SourceAuthority::FacilityStateLedger},
      {"publish-recovering-state", SourceAuthority::FacilityStateLedger},
      {"begin-recovery-sequence", SourceAuthority::MaintenanceCoordinator},
      {"restore-power-domains", SourceAuthority::PowerControlPlane},
      {"restore-cooling-domains", SourceAuthority::ThermalControlPlane},
      {"publish-active-state", SourceAuthority::FacilityStateLedger},
      {"resume-accelerator-admission", SourceAuthority::AsiRuntime},
      {"resume-fabric-admission", SourceAuthority::DfiRuntime},
      {"publish-isolated-state", SourceAuthority::FacilityStateLedger},
      {"withdraw-site-from-fabric", SourceAuthority::DfiRuntime},
      {"publish-retired-state", SourceAuthority::FacilityStateLedger},
      {"withdraw-site-service-classes", SourceAuthority::ServiceClassRegistry},
  }};
  return kOwners;
}

/// Returns the owner of \p action, or nullptr when no boundary owns it.
const SourceAuthority* owner_of_action(std::string_view action) {
  for (const ActionOwner& entry : action_owners()) {
    if (entry.action == action) {
      return &entry.owner;
    }
  }
  return nullptr;
}

bool is_known_authority(SourceAuthority authority) {
  return std::find(kAuthorities.begin(), kAuthorities.end(), authority) != kAuthorities.end();
}

/// Checks the contract every produced request must satisfy.
void check_request_contract(const ActionPlan& plan, const PlanRequest& request, const char* what) {
  const std::string label = std::string(what) + "/" +
                            std::string(scp::to_string(plan.intent));
  SCP_CHECK(!plan.steps.empty());
  std::vector<RequestId> ids;
  std::vector<IdempotencyKey> keys;
  for (const scp::PlannedStep& step : plan.steps) {
    const EffectRequest& effect = step.request;
    expect_ok(effect.validate(), label.c_str());
    SCP_CHECK(!effect.id.is_nil());
    SCP_CHECK(!effect.idempotency.is_nil());
    SCP_CHECK(!effect.action.empty());
    SCP_CHECK_EQ(effect.site, request.site);
    SCP_CHECK_EQ(effect.site_generation, request.site_generation);
    SCP_CHECK(!effect.site_generation.is_unset());
    SCP_CHECK(!effect.required_scope.empty());
    SCP_CHECK(!effect.preconditions.empty());
    SCP_CHECK(effect.created_at.is_set());
    SCP_CHECK_EQ(effect.created_at, request.now);
    SCP_CHECK_EQ(effect.plan, plan.id);
    SCP_CHECK_EQ(effect.site_snapshot_digest, plan.site_snapshot_digest);
    SCP_CHECK(is_known_authority(effect.target));
    const SourceAuthority* owner = owner_of_action(effect.action.view());
    if (owner == nullptr) {
      ::scp_test::Context::instance().note(label + ": no boundary owns action '" +
                                           std::string(effect.action.view()) + "'");
      SCP_CHECK(false);
    } else if (*owner != effect.target) {
      ::scp_test::Context::instance().note(label + ": action '" +
                                           std::string(effect.action.view()) +
                                           "' is addressed to " +
                                           std::string(scp::to_string(effect.target)) +
                                           " but is owned by " +
                                           std::string(scp::to_string(*owner)));
      SCP_CHECK(false);
    }
    ids.push_back(effect.id);
    keys.push_back(effect.idempotency);
  }
  // A plan's own requests are distinct, and its keys are distinct per effect.
  for (std::size_t left = 0; left < ids.size(); ++left) {
    for (std::size_t right = left + 1U; right < ids.size(); ++right) {
      SCP_CHECK_NE(ids[left], ids[right]);
      SCP_CHECK_NE(keys[left], keys[right]);
    }
  }
  // The fixed precondition set is present on every request.
  const std::array<PreconditionKind, 8> expected = {
      PreconditionKind::ReceiverOwnsEffect,   PreconditionKind::SiteGenerationAtLeast,
      PreconditionKind::GateWasOpen,          PreconditionKind::EvidenceDigestMatches,
      PreconditionKind::SiteNotRetired,       PreconditionKind::ScopeStillGranted,
      PreconditionKind::SiteStateIs,          PreconditionKind::MinimumHeadroomPercent};
  for (const scp::PlannedStep& step : plan.steps) {
    for (const PreconditionKind kind : expected) {
      const bool present =
          std::any_of(step.request.preconditions.begin(), step.request.preconditions.end(),
                      [kind](const scp::Precondition& precondition) {
                        return precondition.kind == kind;
                      });
      if (!present) {
        ::scp_test::Context::instance().note(label + ": request '" +
                                             std::string(step.request.action.view()) +
                                             "' is missing precondition " +
                                             std::string(scp::to_string(kind)));
      }
      SCP_CHECK(present);
    }
    for (const scp::Precondition& precondition : step.request.preconditions) {
      SCP_CHECK(!precondition.subject.empty());
      SCP_CHECK(!precondition.expectation.empty());
    }
  }
  // Ordinals are consecutive from zero, in request order.
  for (std::size_t index = 0; index < plan.steps.size(); ++index) {
    SCP_CHECK_EQ(plan.steps[index].ordinal, static_cast<std::uint32_t>(index));
  }
}

struct StepIdentity {
  SourceAuthority target = SourceAuthority::FacilityStateLedger;
  std::string action;
  IdempotencyKey key{};
  RequestId id{};

  friend bool operator==(const StepIdentity&, const StepIdentity&) = default;
};

std::vector<StepIdentity> identities_of(const ActionPlan& plan) {
  std::vector<StepIdentity> identities;
  for (const scp::PlannedStep& step : plan.steps) {
    StepIdentity identity;
    identity.target = step.request.target;
    identity.action = std::string(step.request.action.view());
    identity.key = step.request.idempotency;
    identity.id = step.request.id;
    identities.push_back(identity);
  }
  return identities;
}

/// The (target, action, key) triples, which is what retry safety is about.
std::vector<StepIdentity> keys_of(const ActionPlan& plan) {
  std::vector<StepIdentity> identities;
  for (const scp::PlannedStep& step : plan.steps) {
    StepIdentity identity;
    identity.target = step.request.target;
    identity.action = std::string(step.request.action.view());
    identity.key = step.request.idempotency;
    identities.push_back(identity);
  }
  return identities;
}

}  // namespace

// ---------------------------------------------------------------------------
// Purity
// ---------------------------------------------------------------------------

SCP_TEST(planning_never_mutates_the_site) {
  const SitePolicy policy = scp_test::strict_policy();
  const std::vector<EvidenceRecord> records = healthy();

  // A locally composed snapshot is unchanged by planning against it.
  const SiteStateSnapshot snapshot = must_compose(records, policy, scp_test::base_instant());
  const scp::Digest digest_before = scp::compute_snapshot_digest(snapshot);
  const scp::Digest evidence_digest_before = snapshot.evidence_digest;
  const scp::Digest policy_digest_before = snapshot.policy_digest;
  SCP_CHECK_EQ(digest_before, snapshot.snapshot_digest);

  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const PlanRequest request =
      request_for(PlanIntent::AcceptObligation, SiteGeneration::first(), scp_test::base_instant());
  const Result<ActionPlan> planned = scp::plan_intent(request, snapshot, policy, grants);
  SCP_REQUIRE_OK(planned);
  SCP_CHECK(planned.value().permitted);
  check_request_contract(planned.value(), request, "accept obligation");

  SCP_CHECK_EQ(scp::compute_snapshot_digest(snapshot), digest_before);
  SCP_CHECK_EQ(snapshot.snapshot_digest, digest_before);
  SCP_CHECK_EQ(snapshot.evidence_digest, evidence_digest_before);
  SCP_CHECK_EQ(snapshot.policy_digest, policy_digest_before);
  SCP_CHECK_EQ(snapshot.site_generation, SiteGeneration::first());
  SCP_CHECK_EQ(snapshot.state, scp::SiteState::Available);
  SCP_CHECK_EQ(snapshot.slots.size(), scp::kEvidenceKindCount);
  SCP_CHECK_EQ(snapshot.constraints.size(), std::size_t{0});
  SCP_CHECK_EQ(snapshot.gates.size(), scp::kGateKindCount);

  // A runtime's published state is unchanged by planning, and the evidence it
  // holds survives a close and reopen unchanged.
  scp_test::TempDirectory directory("plan-purity");
  scp::RuntimeStatus status_before_close;
  {
    const scp::Result<SiteStateSnapshot> in_memory = compose(
        records, policy, scp_test::base_instant(), SiteGeneration(4));
    SCP_REQUIRE_OK(in_memory);
    SCP_CHECK_EQ(in_memory.value().site_generation, SiteGeneration(4));
  }
  {
    SCP_OPEN_RUNTIME(runtime, scp_test::durable_runtime_options(directory.path()));
    const Status ingested = runtime->ingest(records);
    expect_ok(ingested, "ingesting healthy evidence");
    scp::CommitOptions commit;
    commit.now = scp_test::base_instant();
    const Result<scp::CommitOutcome> committed = runtime->commit(commit);
    SCP_REQUIRE_OK(committed);
    SCP_CHECK(committed.value().committed);
    expect_ok(runtime->record_grant(all_scopes_grant(1), scp_test::base_instant()),
              "recording a grant");

    const scp::RuntimeStatus before = runtime->status();
    status_before_close = before;
    const Result<SiteStateSnapshot> published = runtime->snapshot(scp_test::base_instant());
    SCP_REQUIRE_OK(published);

    const PlanRequest runtime_request =
        request_for(PlanIntent::AcceptObligation, before.site_generation,
                    scp_test::base_instant());
    const Result<ActionPlan> runtime_plan = runtime->plan(runtime_request);
    SCP_REQUIRE_OK(runtime_plan);
    SCP_CHECK(runtime_plan.value().permitted);
    check_request_contract(runtime_plan.value(), runtime_request, "runtime plan");
    SCP_CHECK_EQ(runtime_plan.value().site_snapshot_digest, published.value().snapshot_digest);

    const Result<SiteStateSnapshot> after = runtime->snapshot(scp_test::base_instant());
    SCP_REQUIRE_OK(after);
    SCP_CHECK_EQ(after.value().snapshot_digest, published.value().snapshot_digest);
    SCP_CHECK_EQ(after.value().state, published.value().state);
    SCP_CHECK_EQ(after.value().classification, published.value().classification);
    SCP_CHECK_EQ(after.value().slots.size(), published.value().slots.size());
    const scp::RuntimeStatus status_after = runtime->status();
    SCP_CHECK_EQ(status_after.accepted_evidence, before.accepted_evidence);
    SCP_CHECK_EQ(status_after.pending_evidence, before.pending_evidence);
    SCP_CHECK_EQ(status_after.site_generation, before.site_generation);
    SCP_CHECK_EQ(status_after.site, before.site);
    expect_ok(runtime->close(), "closing the durable runtime");
  }
  {
    SCP_OPEN_RUNTIME(reopened, scp_test::durable_runtime_options(directory.path()));
    const scp::RuntimeStatus recovered = reopened->status();
    const Result<SiteStateSnapshot> recovered_snapshot = reopened->snapshot(scp_test::base_instant());
    SCP_REQUIRE_OK(recovered_snapshot);
    // Nothing the planner did changed what the runtime knows: the same facts,
    // under the same identities, at the same generation. Recovery re-origins a
    // record as recovered-from-journal, which is recorded per slot and is not
    // the same thing as the fact having changed.
    SCP_CHECK_EQ(recovered.accepted_evidence, status_before_close.accepted_evidence);
    SCP_CHECK_EQ(recovered.accepted_evidence, records.size());
    SCP_CHECK_EQ(recovered.site_generation, status_before_close.site_generation);
    SCP_CHECK_EQ(recovered.grants, status_before_close.grants);
    SCP_CHECK_EQ(recovered.site, status_before_close.site);
    SCP_CHECK_EQ(recovered_snapshot.value().site_generation, recovered.site_generation);
    SCP_CHECK_EQ(recovered_snapshot.value().slots.size(), scp::kEvidenceKindCount);
    for (const scp::SlotResolution& resolution : recovered_snapshot.value().slots) {
      SCP_CHECK(resolution.accepted());
      SCP_CHECK(!resolution.accepted_id.is_nil());
      SCP_CHECK_EQ(resolution.origin, scp::EvidenceOrigin::RecoveredFromJournal);
    }
    const Result<ActionPlan> after_recovery = reopened->plan(
        request_for(PlanIntent::AcceptObligation, recovered.site_generation,
                    scp_test::base_instant()));
    SCP_REQUIRE_OK(after_recovery);
    SCP_CHECK(after_recovery.value().permitted);
  }
}

// ---------------------------------------------------------------------------
// Plan consistency
// ---------------------------------------------------------------------------

SCP_TEST(action_plan_validate_rejects_inconsistent_outcomes) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const PlanRequest request =
      request_for(PlanIntent::AcceptObligation, SiteGeneration::first(), scp_test::base_instant());
  const Result<ActionPlan> planned = scp::plan_intent(request, snapshot, policy, grants);
  SCP_REQUIRE_OK(planned);
  const ActionPlan good = planned.value();
  expect_ok(good.validate(), "a produced plan validates");
  SCP_CHECK_EQ(good.request_count(), std::size_t{3});

  ActionPlan denied_with_steps = good;
  denied_with_steps.permitted = false;
  denied_with_steps.denial_reason = "refused";
  SCP_CHECK(!denied_with_steps.steps.empty());
  expect_ok(denied_with_steps.denial_reason.empty() ? Status(StatusCode::InvalidArgument, "fixture")
                                                   : Status{},
            "the fixture carries a denial reason");
  const Status denied_status = denied_with_steps.validate();
  if (denied_status.code() != StatusCode::InvalidState) {
    ::scp_test::Context::instance().note("a denied plan with steps reported " +
                                         denied_status.to_string());
  }
  SCP_CHECK_EQ(denied_status.code(), StatusCode::InvalidState);

  ActionPlan permitted_without_steps = good;
  permitted_without_steps.steps.clear();
  SCP_CHECK(permitted_without_steps.permitted);
  const Status empty_status = permitted_without_steps.validate();
  if (empty_status.code() != StatusCode::InvalidState) {
    ::scp_test::Context::instance().note("a permitted plan without steps reported " +
                                         empty_status.to_string());
  }
  SCP_CHECK_EQ(empty_status.code(), StatusCode::InvalidState);

  // A denial is a complete outcome, so a denied plan with no steps is valid.
  ActionPlan denied_clean = permitted_without_steps;
  denied_clean.permitted = false;
  denied_clean.denial_reason = "authority refused";
  expect_ok(denied_clean.validate(), "a denied plan without steps");

  ActionPlan damaged = good;
  damaged.id = scp::PlanId{};
  SCP_CHECK_EQ(damaged.validate().code(), StatusCode::InvalidIdentifier);
  damaged = good;
  damaged.site = scp::SiteId{};
  SCP_CHECK_EQ(damaged.validate().code(), StatusCode::InvalidIdentifier);
  damaged = good;
  damaged.site_generation = SiteGeneration{};
  SCP_CHECK_EQ(damaged.validate().code(), StatusCode::InvalidArgument);
  damaged = good;
  damaged.created_at = Timestamp{};
  SCP_CHECK_EQ(damaged.validate().code(), StatusCode::InvalidArgument);
  SCP_REQUIRE(!good.steps.empty());
  damaged = good;
  damaged.steps.front().request.idempotency = IdempotencyKey{};
  SCP_CHECK_EQ(damaged.validate().code(), StatusCode::InvalidIdentifier);
  damaged = good;
  damaged.steps.front().request.required_scope = ScopeSet{};
  SCP_CHECK_EQ(damaged.validate().code(), StatusCode::InvalidArgument);
  damaged = good;
  damaged.steps.front().request.site_generation = SiteGeneration{};
  SCP_CHECK_EQ(damaged.validate().code(), StatusCode::InvalidArgument);
  damaged = good;
  damaged.steps.front().request.created_at = Timestamp{};
  SCP_CHECK_EQ(damaged.validate().code(), StatusCode::InvalidArgument);
}

SCP_TEST(plan_digest_is_recomputable_and_covers_the_plan) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const Timestamp now = scp_test::base_instant();
  const PlanRequest request =
      request_for(PlanIntent::AcceptObligation, SiteGeneration::first(), now);
  const Result<ActionPlan> planned = scp::plan_intent(request, snapshot, policy, grants);
  SCP_REQUIRE_OK(planned);
  const ActionPlan plan = planned.value();
  SCP_CHECK_EQ(scp::compute_plan_digest(plan), plan.plan_digest);
  SCP_CHECK(!plan.plan_digest.is_zero());

  ActionPlan changed = plan;
  changed.site_generation = SiteGeneration(plan.site_generation.value() + 1U);
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.intent = PlanIntent::ReleaseObligation;
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.site = scp::SiteId(0x0FF510E000000000ULL, 0x0000000000000009ULL);
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.created_at = scp_test::instant_after(1);
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.permitted = false;
  changed.denial_reason = "refused";
  changed.steps.clear();
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  SCP_REQUIRE(!plan.steps.empty());
  SCP_REQUIRE(!plan.steps.front().request.preconditions.empty());
  changed = plan;
  changed.steps.front().ordinal = 99;
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.steps.front().description = name_of("a different description");
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.steps.front().request.id = RequestId(0x1111ULL, 0x2222ULL);
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.steps.front().request.preconditions.front().expectation = "something else";
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.authority.outcome = AuthorityOutcome::GrantRevoked;
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  changed = plan;
  changed.state = scp::SiteState::Degraded;
  SCP_CHECK_NE(scp::compute_plan_digest(changed), plan.plan_digest);

  // The digest field itself is excluded from the computation, so a consumer can
  // verify a plan it did not produce.
  ActionPlan zeroed = plan;
  zeroed.plan_digest = scp::Digest{};
  SCP_CHECK_EQ(scp::compute_plan_digest(zeroed), plan.plan_digest);
  SCP_CHECK_NE(zeroed.canonical_bytes(), plan.canonical_bytes());
  SCP_CHECK_EQ(plan.canonical_bytes(), plan.canonical_bytes());

  // A different principal is a different plan, because identity is derived from
  // the principal that asked for it.
  PlanRequest other_principal = request;
  other_principal.principal = name_of("another-operator");
  const Result<ActionPlan> other = scp::plan_intent(other_principal, snapshot, policy, grants);
  SCP_REQUIRE_OK(other);
  SCP_CHECK_NE(other.value().id, plan.id);
  SCP_CHECK_NE(other.value().plan_digest, plan.plan_digest);
}

// ---------------------------------------------------------------------------
// Retry safety
// ---------------------------------------------------------------------------

SCP_TEST(planning_is_retry_safe) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const Timestamp now = scp_test::base_instant();
  const PlanRequest request =
      request_for(PlanIntent::AcceptObligation, SiteGeneration::first(), now);

  const Result<ActionPlan> first = scp::plan_intent(request, snapshot, policy, grants);
  SCP_REQUIRE_OK(first);
  const Result<ActionPlan> second = scp::plan_intent(request, snapshot, policy, grants);
  SCP_REQUIRE_OK(second);

  SCP_CHECK_EQ(first.value().id, second.value().id);
  SCP_CHECK_EQ(first.value().plan_digest, second.value().plan_digest);
  SCP_CHECK_EQ(identities_of(first.value()), identities_of(second.value()));
  SCP_CHECK_EQ(keys_of(first.value()), keys_of(second.value()));

  // The keys are per effect, not per ordinal: replanning the same intent for the
  // same generation reissues the same key for the same target and action.
  const std::vector<StepIdentity> first_keys = keys_of(first.value());
  const std::vector<StepIdentity> second_keys = keys_of(second.value());
  for (const StepIdentity& identity : first_keys) {
    const auto match =
        std::find_if(second_keys.begin(), second_keys.end(),
                     [&identity](const StepIdentity& candidate) {
                       return candidate.target == identity.target &&
                              candidate.action == identity.action;
                     });
    SCP_CHECK(match != second_keys.end());
    if (match != second_keys.end()) {
      SCP_CHECK_EQ(match->key, identity.key);
    }
  }

  // A different site generation is a different effect set.
  const Result<ActionPlan> later = scp::plan_intent(
      request_for(PlanIntent::AcceptObligation, SiteGeneration(2), now), snapshot, policy, grants);
  SCP_REQUIRE_OK(later);
  SCP_CHECK_NE(later.value().id, first.value().id);
  SCP_CHECK_NE(later.value().plan_digest, first.value().plan_digest);
  SCP_CHECK_EQ(later.value().steps.size(), first.value().steps.size());
  for (std::size_t index = 0; index < first.value().steps.size(); ++index) {
    SCP_CHECK_NE(later.value().steps[index].request.idempotency,
                 first.value().steps[index].request.idempotency);
    SCP_CHECK_EQ(later.value().steps[index].request.target,
                 first.value().steps[index].request.target);
  }

  // The identity seed changes the derived identities but not what an effect is:
  // the idempotency key is independent of it, so a replay is still recognised.
  PlanRequest reseeded = request;
  reseeded.identity_seed = 0x5EED1234ULL;
  const Result<ActionPlan> reseeded_plan = scp::plan_intent(reseeded, snapshot, policy, grants);
  SCP_REQUIRE_OK(reseeded_plan);
  SCP_CHECK_NE(reseeded_plan.value().id, first.value().id);
  SCP_CHECK_NE(identities_of(reseeded_plan.value()), identities_of(first.value()));
  SCP_CHECK_EQ(keys_of(reseeded_plan.value()), keys_of(first.value()));

  // A different principal asks for the same effect, so the effect key is the
  // same even though the plan identity is not.
  PlanRequest other_principal = request;
  other_principal.principal = name_of("another-operator");
  const Result<ActionPlan> other = scp::plan_intent(other_principal, snapshot, policy, grants);
  SCP_REQUIRE_OK(other);
  SCP_CHECK_NE(other.value().id, first.value().id);
  SCP_CHECK_EQ(keys_of(other.value()), keys_of(first.value()));
}

// ---------------------------------------------------------------------------
// Authority and gating
// ---------------------------------------------------------------------------

SCP_TEST(a_denied_plan_names_the_authority_outcome) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
  const Timestamp now = scp_test::base_instant();
  const PlanRequest request =
      request_for(PlanIntent::AcceptObligation, SiteGeneration::first(), now);

  const std::vector<DelegationGrant> none;
  const Result<ActionPlan> denied = scp::plan_intent(request, snapshot, policy, none);
  SCP_REQUIRE_OK(denied);
  SCP_CHECK(!denied.value().permitted);
  SCP_CHECK(denied.value().steps.empty());
  SCP_CHECK(!denied.value().denial_reason.empty());
  SCP_CHECK(denied.value().denial_reason.find(scp::to_string(AuthorityOutcome::NoGrantFound)) !=
            std::string::npos);
  SCP_CHECK(denied.value().denial_reason.find("authority refused") != std::string::npos);
  SCP_CHECK_EQ(denied.value().authority.outcome, AuthorityOutcome::NoGrantFound);
  SCP_CHECK(!denied.value().authority.granted());
  expect_ok(denied.value().validate(), "a denied plan validates");

  // A grant that covers only part of the required scope is still a refusal, and
  // the refusal names the scope outcome.
  const ScopeSet required = scp::scope_for_intent(PlanIntent::AcceptObligation);
  SCP_CHECK(!required.empty());
  const std::vector<DelegationGrant> partial = {
      grant_with(ScopeSet::of(ActionScope::AcceptObligation), 1)};
  const Result<ActionPlan> partial_plan = scp::plan_intent(request, snapshot, policy, partial);
  SCP_REQUIRE_OK(partial_plan);
  SCP_CHECK(!partial_plan.value().permitted);
  SCP_CHECK(partial_plan.value().denial_reason.find(
                scp::to_string(AuthorityOutcome::ScopeNotGranted)) != std::string::npos);
  SCP_CHECK(partial_plan.value().authority.granted() == false);

  // The same intent with the whole scope granted becomes a permitted plan with
  // effect requests.
  const std::vector<DelegationGrant> sufficient = {grant_with(required, 2)};
  const Result<ActionPlan> permitted = scp::plan_intent(request, snapshot, policy, sufficient);
  SCP_REQUIRE_OK(permitted);
  SCP_CHECK(permitted.value().permitted);
  SCP_CHECK(permitted.value().denial_reason.empty());
  SCP_CHECK(!permitted.value().steps.empty());
  SCP_CHECK_EQ(permitted.value().authority.outcome, AuthorityOutcome::Granted);
  SCP_CHECK_EQ(permitted.value().authority.grant, GrantId(0x6B00000000000000ULL, 2));
  SCP_CHECK(permitted.value().gate.open);
  check_request_contract(permitted.value(), request, "permitted plan");

  // A revoked or fenced grant is refused for the reason it was revoked or
  // fenced, not for a missing scope.
  DelegationGrant revoked = all_scopes_grant(3);
  revoked.revoked = true;
  const std::vector<DelegationGrant> revoked_grants = {revoked};
  const Result<ActionPlan> revoked_plan = scp::plan_intent(request, snapshot, policy, revoked_grants);
  SCP_REQUIRE_OK(revoked_plan);
  SCP_CHECK(!revoked_plan.value().permitted);
  SCP_CHECK(revoked_plan.value().denial_reason.find(
                scp::to_string(AuthorityOutcome::GrantRevoked)) != std::string::npos);

  DelegationGrant fenced = all_scopes_grant(4);
  fenced.not_after = SiteGeneration::first();
  const std::vector<DelegationGrant> fenced_grants = {fenced};
  const Result<ActionPlan> fenced_plan = scp::plan_intent(request, snapshot, policy, fenced_grants);
  SCP_REQUIRE_OK(fenced_plan);
  SCP_CHECK(!fenced_plan.value().permitted);
  SCP_CHECK(fenced_plan.value().denial_reason.find(
                scp::to_string(AuthorityOutcome::GenerationFenced)) != std::string::npos);
}

SCP_TEST(a_closed_gate_denies_the_plan_by_name) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const Timestamp now = scp_test::base_instant();

  const PlanRequest emergency = request_for(PlanIntent::EmergencyOperation,
                                            SiteGeneration::first(), now);
  SCP_CHECK_EQ(scp::gate_for_intent(PlanIntent::EmergencyOperation),
               GateKind::EmergencyOperation);
  const Result<ActionPlan> denied = scp::plan_intent(emergency, snapshot, policy, grants);
  SCP_REQUIRE_OK(denied);
  SCP_CHECK(denied.value().authority.granted());
  SCP_CHECK(!denied.value().gate.open);
  SCP_CHECK(!denied.value().permitted);
  SCP_CHECK(denied.value().steps.empty());
  SCP_CHECK(denied.value().denial_reason.find("emergency-context") != std::string::npos);
  SCP_CHECK(denied.value().denial_reason.find("gate emergency-operation is closed") !=
            std::string::npos);

  const PlanRequest recovery = request_for(PlanIntent::BeginRecovery, SiteGeneration::first(), now);
  const Result<ActionPlan> recovery_plan = scp::plan_intent(recovery, snapshot, policy, grants);
  SCP_REQUIRE_OK(recovery_plan);
  SCP_CHECK(!recovery_plan.value().permitted);
  SCP_CHECK(recovery_plan.value().denial_reason.find(
                std::string(scp::to_string(GateKind::RecoveryStart))) != std::string::npos);
}

// ---------------------------------------------------------------------------
// Policy, site and generation binding
// ---------------------------------------------------------------------------

SCP_TEST(planning_is_bound_to_the_policy_the_snapshot_was_composed_under) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const PlanRequest request =
      request_for(PlanIntent::AcceptObligation, SiteGeneration::first(), scp_test::base_instant());

  const Result<ActionPlan> matching = scp::plan_intent(request, snapshot, policy, grants);
  SCP_REQUIRE_OK(matching);
  SCP_CHECK(matching.value().permitted);

  // A policy with a different generation is a different rule set.
  const SitePolicy other_generation = scp_test::policy_with_generation(2);
  const Result<ActionPlan> mismatched =
      scp::plan_intent(request, snapshot, other_generation, grants);
  SCP_CHECK(!mismatched.has_value());
  if (!mismatched.has_value()) {
    SCP_CHECK_EQ(mismatched.status().code(), StatusCode::Conflict);
  }

  // So is the same generation with different thresholds.
  SitePolicy other_thresholds = policy;
  other_thresholds.freshness.stale_after = scp::seconds(100);
  const Result<ActionPlan> threshold_mismatch =
      scp::plan_intent(request, snapshot, other_thresholds, grants);
  SCP_CHECK(!threshold_mismatch.has_value());
  if (!threshold_mismatch.has_value()) {
    SCP_CHECK_EQ(threshold_mismatch.status().code(), StatusCode::Conflict);
  }

  // An impossible policy is reported as such, before any digest comparison.
  SitePolicy impossible = policy;
  impossible.maintenance_minimum_readiness_percent = 200;
  const Result<ActionPlan> invalid = scp::plan_intent(request, snapshot, impossible, grants);
  SCP_CHECK(!invalid.has_value());
  if (!invalid.has_value()) {
    SCP_CHECK_EQ(invalid.status().code(), StatusCode::OutOfRange);
  }
}

SCP_TEST(planning_is_bound_to_the_site_and_its_generation) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot =
      must_compose(healthy(), policy, scp_test::base_instant(), SiteGeneration(3));
  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const Timestamp now = scp_test::base_instant();

  const Result<ActionPlan> same_generation = scp::plan_intent(
      request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now), snapshot, policy, grants);
  SCP_REQUIRE_OK(same_generation);
  SCP_CHECK(same_generation.value().permitted);

  // A newer generation than the snapshot is allowed: the caller is planning
  // ahead of the snapshot it holds.
  const Result<ActionPlan> newer = scp::plan_intent(
      request_for(PlanIntent::AcceptObligation, SiteGeneration(4), now), snapshot, policy, grants);
  SCP_REQUIRE_OK(newer);
  SCP_CHECK_EQ(newer.value().site_generation, SiteGeneration(4));

  // An older generation is stale, not merely wrong.
  const Result<ActionPlan> older = scp::plan_intent(
      request_for(PlanIntent::AcceptObligation, SiteGeneration(2), now), snapshot, policy, grants);
  SCP_CHECK(!older.has_value());
  if (!older.has_value()) {
    SCP_CHECK_EQ(older.status().code(), StatusCode::StaleGeneration);
  }

  // A different site is a conflict, not a stale generation.
  PlanRequest foreign =
      request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now);
  foreign.site = scp::SiteId(0x0FF510E000000000ULL, 0x0000000000000009ULL);
  const Result<ActionPlan> other_site = scp::plan_intent(foreign, snapshot, policy, grants);
  SCP_CHECK(!other_site.has_value());
  if (!other_site.has_value()) {
    SCP_CHECK_EQ(other_site.status().code(), StatusCode::Conflict);
  }

  // A grant for another site never authorises work here.
  const std::vector<DelegationGrant> foreign_grants = {[&foreign]() {
    DelegationGrant grant = all_scopes_grant(1);
    grant.site = foreign.site;
    return grant;
  }()};
  const Result<ActionPlan> foreign_plan = scp::plan_intent(
      request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now), snapshot, policy,
      foreign_grants);
  SCP_REQUIRE_OK(foreign_plan);
  SCP_CHECK(!foreign_plan.value().permitted);
  SCP_CHECK_EQ(foreign_plan.value().authority.outcome, AuthorityOutcome::NoGrantFound);

  // Planning requires a site, a generation, an instant and a principal.
  PlanRequest incomplete = request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now);
  incomplete.site = scp::SiteId{};
  SCP_CHECK(!scp::plan_intent(incomplete, snapshot, policy, grants).has_value());
  incomplete = request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now);
  incomplete.site_generation = SiteGeneration{};
  SCP_CHECK(!scp::plan_intent(incomplete, snapshot, policy, grants).has_value());
  incomplete = request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now);
  incomplete.now = Timestamp{};
  SCP_CHECK(!scp::plan_intent(incomplete, snapshot, policy, grants).has_value());
  incomplete = request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now);
  incomplete.principal = Name();
  SCP_CHECK(!scp::plan_intent(incomplete, snapshot, policy, grants).has_value());
  incomplete = request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now);
  incomplete.max_steps = 0;
  SCP_CHECK(!scp::plan_intent(incomplete, snapshot, policy, grants).has_value());
  incomplete = request_for(PlanIntent::AcceptObligation, SiteGeneration(3), now);
  incomplete.service_class = Name();
  const Result<ActionPlan> no_class = scp::plan_intent(incomplete, snapshot, policy, grants);
  SCP_CHECK(!no_class.has_value());
  if (!no_class.has_value()) {
    SCP_CHECK_EQ(no_class.status().code(), StatusCode::InvalidArgument);
  }
}

SCP_TEST(max_steps_is_enforced_rather_than_truncated) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const Timestamp now = scp_test::base_instant();

  const PlanRequest full =
      request_for(PlanIntent::AcceptObligation, SiteGeneration::first(), now);
  const Result<ActionPlan> unbounded = scp::plan_intent(full, snapshot, policy, grants);
  SCP_REQUIRE_OK(unbounded);
  SCP_CHECK_EQ(unbounded.value().steps.size(), std::size_t{3});

  PlanRequest bounded = full;
  bounded.max_steps = 3;
  const Result<ActionPlan> exactly = scp::plan_intent(bounded, snapshot, policy, grants);
  SCP_REQUIRE_OK(exactly);
  SCP_CHECK_EQ(exactly.value().steps.size(), std::size_t{3});

  bounded.max_steps = 2;
  const Result<ActionPlan> too_small = scp::plan_intent(bounded, snapshot, policy, grants);
  SCP_CHECK(!too_small.has_value());
  if (!too_small.has_value()) {
    SCP_CHECK_EQ(too_small.status().code(), StatusCode::LimitExceeded);
  }

  bounded.max_steps = 1;
  const Result<ActionPlan> one = scp::plan_intent(bounded, snapshot, policy, grants);
  SCP_CHECK(!one.has_value());
  if (!one.has_value()) {
    SCP_CHECK_EQ(one.status().code(), StatusCode::LimitExceeded);
  }

  // A one-request intent fits inside a bound of one.
  PlanRequest release = request_for(PlanIntent::ReleaseObligation, SiteGeneration::first(), now);
  release.max_steps = 1;
  const Result<ActionPlan> release_plan = scp::plan_intent(release, snapshot, policy, grants);
  SCP_REQUIRE_OK(release_plan);
  SCP_CHECK_EQ(release_plan.value().steps.size(), std::size_t{1});

  // A denied plan never reaches the bound: it produces no steps at all.
  const std::vector<DelegationGrant> none;
  const Result<ActionPlan> denied = scp::plan_intent(bounded, snapshot, policy, none);
  SCP_REQUIRE_OK(denied);
  SCP_CHECK(!denied.value().permitted);
  SCP_CHECK(denied.value().steps.empty());
}

// ---------------------------------------------------------------------------
// Intent vocabulary
// ---------------------------------------------------------------------------

SCP_TEST(every_intent_has_a_scope_and_a_gate) {
  const SitePolicy policy = scp_test::strict_policy();
  const SiteStateSnapshot snapshot = must_compose(healthy(), policy, scp_test::base_instant());
  const std::vector<DelegationGrant> grants = {all_scopes_grant(1)};
  const Timestamp now = scp_test::base_instant();

  std::size_t permitted_count = 0;
  std::size_t denied_count = 0;
  for (const PlanIntent intent : kIntents) {
    const ScopeSet scope = scp::scope_for_intent(intent);
    SCP_CHECK(!scope.empty());
    const GateKind gate_kind = scp::gate_for_intent(intent);
    SCP_CHECK(!scp::to_string(gate_kind).empty());
    const Result<GateKind> parsed = scp::gate_kind_from_string(scp::to_string(gate_kind));
    SCP_CHECK(parsed.has_value());
    if (parsed.has_value()) {
      SCP_CHECK_EQ(parsed.value(), gate_kind);
    }
    SCP_CHECK_EQ(scp::scope_for_intent(intent).bits(), scope.bits());
    SCP_CHECK_EQ(scp::gate_for_intent(intent), gate_kind);

    const PlanRequest request = request_for(intent, SiteGeneration::first(), now);
    const Result<ActionPlan> plan = scp::plan_intent(request, snapshot, policy, grants);
    SCP_REQUIRE_OK(plan);
    const ActionPlan& produced = plan.value();
    SCP_CHECK_EQ(produced.intent, intent);
    SCP_CHECK_EQ(produced.site, request.site);
    SCP_CHECK_EQ(produced.site_generation, request.site_generation);
    SCP_CHECK_EQ(produced.gate.kind, gate_kind);
    SCP_CHECK(produced.authority.granted());
    expect_ok(produced.validate(), "a plan produced for a healthy fully granted site");

    if (produced.permitted) {
      ++permitted_count;
      SCP_CHECK(produced.denial_reason.empty());
      SCP_CHECK(!produced.steps.empty());
      check_request_contract(produced, request, "healthy fully granted site");
    } else {
      ++denied_count;
      if (produced.denial_reason.empty()) {
        ::scp_test::Context::instance().note("intent " + std::string(scp::to_string(intent)) +
                                             " was denied without a reason");
      }
      SCP_CHECK(!produced.denial_reason.empty());
      SCP_CHECK(produced.steps.empty());
      SCP_CHECK(!produced.gate.open);
    }
  }
  SCP_CHECK_EQ(kIntents.size(), scp::kPlanIntentCount);
  SCP_CHECK(permitted_count > 0U);
  SCP_CHECK(denied_count > 0U);
  SCP_CHECK_EQ(permitted_count + denied_count, kIntents.size());

  // The intent vocabulary round-trips.
  for (const PlanIntent intent : kIntents) {
    const Result<PlanIntent> parsed = scp::plan_intent_from_string(scp::to_string(intent));
    SCP_CHECK(parsed.has_value());
    if (parsed.has_value()) {
      SCP_CHECK_EQ(parsed.value(), intent);
    }
  }
  const Result<PlanIntent> unknown = scp::plan_intent_from_string("no-such-intent");
  SCP_CHECK(!unknown.has_value());
  if (!unknown.has_value()) {
    SCP_CHECK_EQ(unknown.status().code(), StatusCode::InvalidArgument);
  }

  // Scopes are per intent, not one global set: an intent that consumes a power
  // effect asks for it, and an intent that only records asks for nothing more.
  SCP_CHECK(scp::scope_for_intent(PlanIntent::EmergencyOperation)
                .contains(ActionScope::RequestPowerEffect));
  SCP_CHECK(scp::scope_for_intent(PlanIntent::EmergencyOperation)
                .contains(ActionScope::RequestCoolingEffect));
  SCP_CHECK(scp::scope_for_intent(PlanIntent::ReleaseObligation)
                .contains(ActionScope::ReleaseObligation));
  SCP_CHECK(!scp::scope_for_intent(PlanIntent::ReleaseObligation)
                 .contains(ActionScope::AcceptObligation));
  SCP_CHECK(scp::scope_for_intent(PlanIntent::ControlledDrain)
                .contains(ActionScope::ControlledDrain));
  SCP_CHECK(scp::scope_for_intent(PlanIntent::EnterMaintenance)
                .contains(ActionScope::EnterMaintenance));
  SCP_CHECK(scp::scope_for_intent(PlanIntent::IsolateSite).contains(ActionScope::IsolateSite));
  SCP_CHECK(scp::scope_for_intent(PlanIntent::RetireSite).contains(ActionScope::RetireSite));
}

SCP_TEST_MAIN("plan")
