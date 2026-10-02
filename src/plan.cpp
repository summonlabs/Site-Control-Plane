// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/plan.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace scp {
namespace {

void write_id(CanonicalWriter& writer, std::uint64_t high, std::uint64_t low) {
  writer.u64(high);
  writer.u64(low);
}

void write_digest(CanonicalWriter& writer, const Digest& digest) {
  writer.bytes(std::span<const std::uint8_t>(digest.bytes().data(), digest.bytes().size()));
}

/// A step the planner intends to request.
struct StepTemplate {
  SourceAuthority target;
  std::string_view action;
  ScopeSet scope;
  std::string_view description;
};

/// The steps an intent produces. Every target is a boundary that owns the
/// effect; none of them is this boundary, because this boundary owns no
/// lower-domain effect to request.
const std::vector<StepTemplate>& steps_for_intent(PlanIntent intent) {
  static const std::vector<StepTemplate> kAccept = {
      {SourceAuthority::ServiceClassRegistry, "record-obligation-acceptance",
       ScopeSet::of(ActionScope::AcceptObligation),
       "ask the service class registry to record that this site accepts the obligation"},
      {SourceAuthority::AsiRuntime, "reserve-accelerator-capacity",
       ScopeSet::of(ActionScope::RequestAcceleratorEffect),
       "ask the accelerator runtime to reserve execution capacity"},
      {SourceAuthority::DfiRuntime, "reserve-fabric-capacity",
       ScopeSet::of(ActionScope::RequestFabricEffect),
       "ask the fabric runtime to reserve network capacity"},
  };
  static const std::vector<StepTemplate> kRelease = {
      {SourceAuthority::ServiceClassRegistry, "record-obligation-release",
       ScopeSet::of(ActionScope::ReleaseObligation),
       "ask the service class registry to record the released obligation"},
  };
  static const std::vector<StepTemplate> kMaintenance = {
      {SourceAuthority::MaintenanceCoordinator, "open-maintenance-window",
       ScopeSet::of(ActionScope::EnterMaintenance),
       "ask the maintenance coordinator to open the window"},
      {SourceAuthority::FacilityStateLedger, "publish-maintenance-state",
       ScopeSet::of(ActionScope::EnterMaintenance),
       "ask the facility state ledger to record the maintenance posture"},
  };
  static const std::vector<StepTemplate> kDrain = {
      {SourceAuthority::MaintenanceCoordinator, "begin-controlled-drain",
       ScopeSet::of(ActionScope::ControlledDrain),
       "ask the maintenance coordinator to begin the controlled drain"},
      {SourceAuthority::AsiRuntime, "evacuate-accelerator-workloads",
       ScopeSet::of(ActionScope::RequestAcceleratorEffect),
       "ask the accelerator runtime to evacuate work from this site"},
      {SourceAuthority::DfiRuntime, "quiesce-fabric-traffic",
       ScopeSet::of(ActionScope::RequestFabricEffect),
       "ask the fabric runtime to quiesce traffic to this site"},
  };
  static const std::vector<StepTemplate> kEmergency = {
      {SourceAuthority::PowerControlPlane, "enter-emergency-power-profile",
       ScopeSet::of(ActionScope::RequestPowerEffect),
       "ask the power control plane to enter the emergency profile"},
      {SourceAuthority::ThermalControlPlane, "enter-emergency-thermal-profile",
       ScopeSet::of(ActionScope::RequestCoolingEffect),
       "ask the thermal control plane to enter the emergency profile"},
      {SourceAuthority::FacilityStateLedger, "publish-emergency-state",
       ScopeSet::of(ActionScope::EmergencyOperation),
       "ask the facility state ledger to record the emergency posture"},
  };
  static const std::vector<StepTemplate> kRecovery = {
      {SourceAuthority::FacilityStateLedger, "publish-recovering-state",
       ScopeSet::of(ActionScope::RecoveryOperation),
       "ask the facility state ledger to record the recovering posture"},
      {SourceAuthority::MaintenanceCoordinator, "begin-recovery-sequence",
       ScopeSet::of(ActionScope::RecoveryOperation),
       "ask the maintenance coordinator to run the recovery sequence"},
      {SourceAuthority::PowerControlPlane, "restore-power-domains",
       ScopeSet::of(ActionScope::RequestPowerEffect),
       "ask the power control plane to restore the drained domains"},
      {SourceAuthority::ThermalControlPlane, "restore-cooling-domains",
       ScopeSet::of(ActionScope::RequestCoolingEffect),
       "ask the thermal control plane to restore the drained domains"},
  };
  static const std::vector<StepTemplate> kReturn = {
      {SourceAuthority::FacilityStateLedger, "publish-active-state",
       ScopeSet::of(ActionScope::ReturnToService),
       "ask the facility state ledger to record the return to service"},
      {SourceAuthority::AsiRuntime, "resume-accelerator-admission",
       ScopeSet::of(ActionScope::RequestAcceleratorEffect),
       "ask the accelerator runtime to resume admission"},
      {SourceAuthority::DfiRuntime, "resume-fabric-admission",
       ScopeSet::of(ActionScope::RequestFabricEffect),
       "ask the fabric runtime to resume admission"},
  };
  static const std::vector<StepTemplate> kIsolate = {
      {SourceAuthority::FacilityStateLedger, "publish-isolated-state",
       ScopeSet::of(ActionScope::IsolateSite),
       "ask the facility state ledger to record the isolation"},
      {SourceAuthority::DfiRuntime, "withdraw-site-from-fabric",
       ScopeSet::of(ActionScope::RequestFabricEffect),
       "ask the fabric runtime to withdraw this site"},
  };
  static const std::vector<StepTemplate> kRetire = {
      {SourceAuthority::FacilityStateLedger, "publish-retired-state",
       ScopeSet::of(ActionScope::RetireSite),
       "ask the facility state ledger to record the retirement"},
      {SourceAuthority::ServiceClassRegistry, "withdraw-site-service-classes",
       ScopeSet::of(ActionScope::RetireSite),
       "ask the service class registry to withdraw this site's classes"},
  };
  static const std::vector<StepTemplate> kEmpty = {};

  switch (intent) {
    case PlanIntent::AcceptObligation: return kAccept;
    case PlanIntent::ReleaseObligation: return kRelease;
    case PlanIntent::EnterMaintenance: return kMaintenance;
    case PlanIntent::ControlledDrain: return kDrain;
    case PlanIntent::EmergencyOperation: return kEmergency;
    case PlanIntent::BeginRecovery: return kRecovery;
    case PlanIntent::ReturnToService: return kReturn;
    case PlanIntent::IsolateSite: return kIsolate;
    case PlanIntent::RetireSite: return kRetire;
    case PlanIntent::ResumeNormalOperation: return kReturn;
  }
  return kEmpty;
}

/// Deterministic identity derivation over a canonical description.
struct IdPair {
  std::uint64_t high = 0;
  std::uint64_t low = 0;
};

template <class Fn>
IdPair derive(Fn&& write_content) {
  CanonicalWriter writer;
  write_content(writer);
  const Digest digest = Digest::of(writer.span());
  IdPair pair;
  const auto& bytes = digest.bytes();
  for (std::size_t index = 0; index < 8; ++index) {
    pair.high = (pair.high << 8U) | bytes[index];
    pair.low = (pair.low << 8U) | bytes[index + 8];
  }
  return pair;
}

Result<std::vector<std::uint8_t>> plan_arguments(const PlanRequest& request,
                                                 const SiteStateSnapshot& snapshot) {
  CanonicalWriter writer;
  writer.u16(static_cast<std::uint16_t>(request.intent));
  write_id(writer, request.site.high(), request.site.low());
  writer.u64(request.site_generation.value());
  write_digest(writer, snapshot.evidence_digest);
  write_digest(writer, snapshot.snapshot_digest);
  writer.name(request.service_class);
  writer.u32(static_cast<std::uint32_t>(snapshot.readiness_percent));
  return writer.take();
}

}  // namespace

std::string_view to_string(PlanIntent intent) noexcept {
  switch (intent) {
    case PlanIntent::AcceptObligation: return "accept-obligation";
    case PlanIntent::ReleaseObligation: return "release-obligation";
    case PlanIntent::EnterMaintenance: return "enter-maintenance";
    case PlanIntent::ControlledDrain: return "controlled-drain";
    case PlanIntent::EmergencyOperation: return "emergency-operation";
    case PlanIntent::BeginRecovery: return "begin-recovery";
    case PlanIntent::ReturnToService: return "return-to-service";
    case PlanIntent::IsolateSite: return "isolate-site";
    case PlanIntent::RetireSite: return "retire-site";
    case PlanIntent::ResumeNormalOperation: return "resume-normal-operation";
  }
  return "unknown-intent";
}

Result<PlanIntent> plan_intent_from_string(std::string_view text) {
  constexpr std::array<PlanIntent, kPlanIntentCount> kAll = {
      PlanIntent::AcceptObligation,  PlanIntent::ReleaseObligation,
      PlanIntent::EnterMaintenance,  PlanIntent::ControlledDrain,
      PlanIntent::EmergencyOperation, PlanIntent::BeginRecovery,
      PlanIntent::ReturnToService,   PlanIntent::IsolateSite,
      PlanIntent::RetireSite,        PlanIntent::ResumeNormalOperation};
  for (const PlanIntent candidate : kAll) {
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return fail(StatusCode::InvalidArgument, "unrecognised plan intent: " + std::string(text));
}

std::string_view to_string(PreconditionKind kind) noexcept {
  switch (kind) {
    case PreconditionKind::SiteGenerationAtLeast: return "site-generation-at-least";
    case PreconditionKind::SiteStateIs: return "site-state-is";
    case PreconditionKind::LifecycleIs: return "lifecycle-is";
    case PreconditionKind::GateWasOpen: return "gate-was-open";
    case PreconditionKind::EvidenceDigestMatches: return "evidence-digest-matches";
    case PreconditionKind::ScopeStillGranted: return "scope-still-granted";
    case PreconditionKind::MinimumHeadroomPercent: return "minimum-headroom-percent";
    case PreconditionKind::SiteNotRetired: return "site-not-retired";
    case PreconditionKind::ReceiverOwnsEffect: return "receiver-owns-effect";
  }
  return "unknown-precondition";
}

ScopeSet scope_for_intent(PlanIntent intent) noexcept {
  ScopeSet scope;
  for (const StepTemplate& step : steps_for_intent(intent)) {
    scope = ScopeSet(static_cast<std::uint16_t>(scope.bits() | step.scope.bits()));
  }
  return scope.bits() == 0 ? ScopeSet::of(ActionScope::ObserveSite) : scope;
}

GateKind gate_for_intent(PlanIntent intent) noexcept {
  switch (intent) {
    case PlanIntent::AcceptObligation: return GateKind::NewObligation;
    case PlanIntent::ReleaseObligation: return GateKind::NewObligation;
    case PlanIntent::EnterMaintenance: return GateKind::MaintenanceEntry;
    case PlanIntent::ControlledDrain: return GateKind::ControlledDrain;
    case PlanIntent::EmergencyOperation: return GateKind::EmergencyOperation;
    case PlanIntent::BeginRecovery: return GateKind::RecoveryStart;
    case PlanIntent::ReturnToService: return GateKind::ReturnToService;
    case PlanIntent::ResumeNormalOperation: return GateKind::ReturnToService;
    case PlanIntent::IsolateSite: return GateKind::ControlledDrain;
    case PlanIntent::RetireSite: return GateKind::ReturnToService;
  }
  return GateKind::NewObligation;
}

std::vector<std::uint8_t> EffectRequest::canonical_bytes() const {
  CanonicalWriter writer;
  canonical_write(writer, *this);
  return writer.take();
}

Status EffectRequest::validate() const {
  if (id.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "effect request has no identity");
  }
  if (idempotency.is_nil()) {
    return fail(StatusCode::InvalidIdentifier,
                "effect request has no idempotency key; a retry could become a second effect");
  }
  if (action.empty()) {
    return fail(StatusCode::InvalidArgument, "effect request names no action");
  }
  if (site.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "effect request names no site");
  }
  if (site_generation.is_unset()) {
    return fail(StatusCode::InvalidArgument, "effect request carries no site generation");
  }
  if (required_scope.empty()) {
    return fail(StatusCode::InvalidArgument, "effect request consumes no delegated scope");
  }
  if (arguments.size() > kMaxBlobBytes) {
    return fail(StatusCode::LimitExceeded, "effect request arguments exceed the maximum size");
  }
  if (!created_at.is_set()) {
    return fail(StatusCode::InvalidArgument, "effect request has no creation instant");
  }
  if (deadline.is_set() && deadline.nanos <= created_at.nanos) {
    return fail(StatusCode::OutOfRange, "effect request deadline precedes its creation instant");
  }
  return Status{};
}

Digest compute_plan_digest(const ActionPlan& plan) {
  ActionPlan copy = plan;
  copy.plan_digest = Digest{};
  CanonicalWriter writer;
  canonical_write(writer, copy);
  return Digest::of(writer.span());
}

std::vector<std::uint8_t> ActionPlan::canonical_bytes() const {
  CanonicalWriter writer;
  canonical_write(writer, *this);
  return writer.take();
}

Status ActionPlan::validate() const {
  if (id.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "action plan has no identity");
  }
  if (site.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "action plan names no site");
  }
  if (site_generation.is_unset()) {
    return fail(StatusCode::InvalidArgument, "action plan carries no site generation");
  }
  if (!created_at.is_set()) {
    return fail(StatusCode::InvalidArgument, "action plan has no creation instant");
  }
  if (!permitted && !steps.empty()) {
    return fail(StatusCode::InvalidState,
                "a denied plan must not carry effect requests; denial is not a partial approval");
  }
  if (permitted && steps.empty()) {
    return fail(StatusCode::InvalidState, "a permitted plan must carry at least one effect request");
  }
  for (const PlannedStep& step : steps) {
    const Status step_status = step.request.validate();
    if (!step_status.ok()) {
      return step_status;
    }
  }
  return Status{};
}

Result<ActionPlan> plan_intent(const PlanRequest& request, const SiteStateSnapshot& snapshot,
                               const SitePolicy& policy, std::span<const DelegationGrant> grants) {
  if (request.site.is_nil()) {
    return fail(StatusCode::InvalidArgument, "planning requires a site identity");
  }
  if (!(request.site == snapshot.site)) {
    return fail(StatusCode::Conflict,
                "the request names a different site than the snapshot it was given");
  }
  if (request.site_generation.is_unset()) {
    return fail(StatusCode::InvalidArgument, "planning requires a site generation");
  }
  if (request.site_generation.value() < snapshot.site_generation.value()) {
    return fail(StatusCode::StaleGeneration,
                "the request targets an older site generation than the snapshot was composed for");
  }
  if (!request.now.is_set()) {
    return fail(StatusCode::InvalidArgument, "planning requires an instant");
  }
  if (request.principal.empty()) {
    return fail(StatusCode::InvalidArgument,
                "planning requires a principal; an anonymous plan has no authority to evaluate");
  }
  if (request.max_steps == 0) {
    return fail(StatusCode::InvalidArgument, "planning requires a non-zero step bound");
  }
  if (request.intent == PlanIntent::AcceptObligation && request.service_class.empty()) {
    return fail(StatusCode::InvalidArgument,
                "accepting an obligation requires the service class being accepted");
  }
  const Status policy_status = policy.validate();
  if (!policy_status.ok()) {
    return policy_status;
  }
  const Digest policy_digest = compute_policy_digest(policy);
  if (!(policy_digest == snapshot.policy_digest)) {
    return fail(StatusCode::Conflict,
                "the snapshot was composed under a different site policy than the one supplied; "
                "re-compose before planning so the plan cites the thresholds it was made under");
  }

  ActionPlan plan;
  plan.site = request.site;
  plan.site_generation = request.site_generation;
  plan.intent = request.intent;
  plan.created_at = request.now;
  plan.state = snapshot.state;
  plan.site_snapshot_digest = snapshot.snapshot_digest;
  plan.evidence_digest = snapshot.evidence_digest;

  const IdPair plan_words = derive([&request](CanonicalWriter& writer) {
    writer.text("scp.action-plan.v1");
    writer.u16(static_cast<std::uint16_t>(request.intent));
    write_id(writer, request.site.high(), request.site.low());
    writer.u64(request.site_generation.value());
    writer.name(request.principal);
    writer.name(request.service_class);
    writer.i64(request.now.nanos);
    writer.u64(request.identity_seed);
  });
  plan.id = PlanId(plan_words.high, plan_words.low);

  const ScopeSet required =
      request.use_scope_override ? request.scope_override : scope_for_intent(request.intent);
  plan.authority = evaluate_authority(grants, request.site, required, request.site_generation,
                                      request.now);

  const GateKind gate_kind = gate_for_intent(request.intent);
  const Result<ReadinessGate> gate = evaluate_gate(gate_kind, snapshot, policy);
  if (!gate.has_value()) {
    return gate.status();
  }
  plan.gate = gate.value();

  for (const GateCondition& condition : plan.gate.conditions) {
    PlanCondition entry;
    entry.name = condition.name;
    entry.satisfied = condition.satisfied;
    entry.observed = condition.observed;
    entry.required = condition.required;
    plan.conditions.push_back(std::move(entry));
  }

  const bool indeterminate_state = is_indeterminate(snapshot.state);
  if (!plan.authority.granted()) {
    plan.permitted = false;
    plan.denial_reason = std::string("authority refused: ") +
                         std::string(to_string(plan.authority.outcome)) + " (" +
                         plan.authority.detail + ")";
  } else if (indeterminate_state && request.intent != PlanIntent::EmergencyOperation) {
    plan.permitted = false;
    plan.denial_reason =
        std::string("the site state is ") + std::string(to_string(snapshot.state)) +
        "; no site-level action other than emergency operation is planned on an indeterminate "
        "picture";
  } else if (!plan.gate.open) {
    std::string closed;
    for (const GateCondition& condition : plan.gate.conditions) {
      if (condition.satisfied) {
        continue;
      }
      if (!closed.empty()) {
        closed += "; ";
      }
      closed += std::string(condition.name.view()) + " required " + condition.required +
                " but observed " + condition.observed;
    }
    plan.permitted = false;
    plan.denial_reason = std::string("gate ") + std::string(to_string(gate_kind)) +
                         " is closed: " + closed;
  } else {
    // Authority granted and the gate is open: the only path on which a plan
    // carries requests, and therefore the only path that may report permission.
    plan.permitted = true;
  }

  if (plan.permitted) {
    const std::vector<StepTemplate>& templates = steps_for_intent(request.intent);
    if (templates.size() > request.max_steps) {
      return fail(StatusCode::LimitExceeded,
                  "the intent produces " + std::to_string(templates.size()) +
                      " effect requests, above the caller bound of " +
                      std::to_string(request.max_steps));
    }
    const Result<std::vector<std::uint8_t>> arguments = plan_arguments(request, snapshot);
    if (!arguments.has_value()) {
      return arguments.status();
    }

    std::uint32_t ordinal = 0;
    for (const StepTemplate& step : templates) {
      PlannedStep planned;
      planned.ordinal = ordinal;
      const Result<Name> description = Name::parse(step.description);
      if (!description.has_value()) {
        return fail(description.status().code(),
                    "step description is not a valid name: " + description.status().message());
      }
      planned.description = description.value();

      EffectRequest& effect = planned.request;
      const IdPair request_words = derive([&request, &step, ordinal](CanonicalWriter& writer) {
        writer.text("scp.effect-request.v1");
        write_id(writer, request.site.high(), request.site.low());
        writer.u64(request.site_generation.value());
        writer.u16(static_cast<std::uint16_t>(request.intent));
        writer.u8(static_cast<std::uint8_t>(step.target));
        writer.text(step.action);
        writer.u32(ordinal);
        writer.u64(request.identity_seed);
      });
      effect.id = RequestId(request_words.high, request_words.low);
      // The idempotency key deliberately excludes the ordinal: re-planning the
      // same intent for the same site generation and principal must produce the
      // same key for the same target and action, so a retry is recognised as a
      // retry rather than as a second effect.
      const IdPair idempotency_words = derive([&request, &step](CanonicalWriter& writer) {
        writer.text("scp.idempotency.v1");
        write_id(writer, request.site.high(), request.site.low());
        writer.u64(request.site_generation.value());
        writer.u16(static_cast<std::uint16_t>(request.intent));
        writer.u8(static_cast<std::uint8_t>(step.target));
        writer.text(step.action);
      });
      effect.idempotency = IdempotencyKey(idempotency_words.high, idempotency_words.low);
      effect.target = step.target;
      const Result<Name> action = Name::parse(step.action);
      if (!action.has_value()) {
        return fail(action.status().code(),
                    "step action is not a valid name: " + action.status().message());
      }
      effect.action = action.value();
      effect.site = request.site;
      effect.site_generation = request.site_generation;
      effect.required_scope = step.scope;
      effect.arguments = arguments.value();
      effect.created_at = request.now;
      effect.plan = plan.id;
      effect.site_snapshot_digest = snapshot.snapshot_digest;

      const auto add_precondition = [&effect](PreconditionKind kind, std::string subject,
                                              std::string expectation) {
        Precondition precondition;
        precondition.kind = kind;
        precondition.subject = std::move(subject);
        precondition.expectation = std::move(expectation);
        effect.preconditions.push_back(std::move(precondition));
      };
      add_precondition(PreconditionKind::ReceiverOwnsEffect,
                       std::string(to_string(step.target)),
                       "the receiver owns this effect and decides whether to perform it");
      add_precondition(PreconditionKind::SiteGenerationAtLeast, "site",
                       "site generation is at least " +
                           std::to_string(request.site_generation.value()));
      add_precondition(PreconditionKind::GateWasOpen, std::string(to_string(gate_kind)),
                       "the site-level gate was open at planning time");
      add_precondition(PreconditionKind::EvidenceDigestMatches, "evidence",
                       "accepted evidence still hashes to " + snapshot.evidence_digest.to_hex());
      add_precondition(PreconditionKind::SiteNotRetired, "site", "the site is not retired");
      add_precondition(PreconditionKind::ScopeStillGranted, step.scope.to_string(),
                       "the delegation still grants this scope at the current generation");
      if (snapshot.readiness_percent > 0) {
        add_precondition(PreconditionKind::MinimumHeadroomPercent, "readiness",
                         "observed readiness is still at least " +
                             std::to_string(snapshot.readiness_percent) + " percent");
      }
      effect.preconditions.push_back(Precondition{
          PreconditionKind::SiteStateIs, "site-state",
          "the receiver re-reads the site state; this request is valid only while the site is " +
              std::string(to_string(snapshot.state))});

      const Status effect_status = effect.validate();
      if (!effect_status.ok()) {
        return effect_status;
      }
      plan.steps.push_back(std::move(planned));
      ++ordinal;
    }
  }

  plan.plan_digest = compute_plan_digest(plan);
  const Status plan_status = plan.validate();
  if (!plan_status.ok()) {
    return plan_status;
  }
  return plan;
}

}  // namespace scp
