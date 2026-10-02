// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/readiness.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace scp {
namespace {

struct SlotFacts {
  bool all_accepted = true;
  bool any_conflicting = false;
  bool any_unsupported = false;
  bool any_stale = false;
  bool any_missing = false;
};

SlotFacts slot_facts(const SiteStateSnapshot& snapshot) {
  SlotFacts facts;
  for (const SlotResolution& resolution : snapshot.slots) {
    switch (resolution.outcome) {
      case SlotOutcome::Accepted:
      case SlotOutcome::AcceptedSuperseding:
        break;
      case SlotOutcome::Conflicting:
        facts.any_conflicting = true;
        facts.all_accepted = false;
        break;
      case SlotOutcome::Unsupported:
        facts.any_unsupported = true;
        facts.all_accepted = false;
        break;
      case SlotOutcome::Stale:
      case SlotOutcome::Expired:
        facts.any_stale = true;
        facts.all_accepted = false;
        break;
      case SlotOutcome::Missing:
      case SlotOutcome::Indeterminate:
      case SlotOutcome::Unauthorized:
      case SlotOutcome::Superseded:
        facts.any_missing = true;
        facts.all_accepted = false;
        break;
    }
  }
  return facts;
}

const DomainReadiness* domain_of(const SiteStateSnapshot& snapshot, std::string_view name) {
  for (const DomainReadiness& domain : snapshot.readiness_domains) {
    if (domain.domain == name) {
      return &domain;
    }
  }
  return nullptr;
}

void add_condition(ReadinessGate& gate, std::string_view name, bool satisfied, std::string observed,
                   std::string required, std::string detail) {
  GateCondition condition;
  const Result<Name> parsed = Name::parse(name);
  if (!parsed.has_value()) {
    // Condition names are compile-time constants in this file; a name that does
    // not parse is a programming defect, and dropping the condition would hide
    // it. Record the failure as an unsatisfied condition instead.
    condition.name = Name();
    condition.satisfied = false;
    condition.observed = std::move(observed);
    condition.required = std::move(required);
    condition.detail = "internal condition name is not a valid name: " + parsed.status().message();
    gate.conditions.push_back(std::move(condition));
    return;
  }
  condition.name = parsed.value();
  condition.satisfied = satisfied;
  condition.observed = std::move(observed);
  condition.required = std::move(required);
  condition.detail = std::move(detail);
  gate.conditions.push_back(std::move(condition));
}

std::string percent_text(std::uint32_t value) { return std::to_string(value) + "%"; }


void add_domain_condition(ReadinessGate& gate, const SiteStateSnapshot& snapshot,
                          std::string_view name, const SitePolicy& policy) {
  const DomainReadiness* domain = domain_of(snapshot, name);
  const std::string label(name);
  if (domain == nullptr || !domain->observed) {
    add_condition(gate, label + "-ready", false, "unobserved",
                  "readiness level ready", "no publisher reported this dependency domain");
    return;
  }
  const bool ready = domain->level == ReadinessLevel::Ready;
  add_condition(gate, label + "-ready", ready,
                std::string(to_string(domain->level)) + " (" + percent_text(domain->percent) + ")",
                "readiness level ready",
                ready ? "the domain reported ready"
                      : "the domain is not ready for new site-level work");
  (void)policy;
}

bool unsatisfied_obligation_exists(const SiteStateSnapshot& snapshot) {
  return std::any_of(snapshot.obligations.begin(), snapshot.obligations.end(),
                     [](const ObligationAssessment& obligation) {
                       return obligation.outcome == ObligationOutcome::Unsatisfied;
                     });
}

bool protected_obligation_unsatisfied(const SiteStateSnapshot& snapshot) {
  return std::any_of(snapshot.obligations.begin(), snapshot.obligations.end(),
                     [](const ObligationAssessment& obligation) {
                       return obligation.protected_class &&
                              obligation.outcome == ObligationOutcome::Unsatisfied;
                     });
}

bool redundancy_restored(const SiteStateSnapshot& snapshot) {
  bool observed = false;
  bool all_ready = true;
  for (const DomainReadiness& domain : snapshot.readiness_domains) {
    if (domain.domain != "power" && domain.domain != "cooling") {
      continue;
    }
    observed = true;
    if (domain.percent != 100) {
      all_ready = false;
    }
  }
  return observed && all_ready;
}

}  // namespace

std::string_view to_string(GateKind kind) noexcept {
  switch (kind) {
    case GateKind::NewObligation: return "new-obligation";
    case GateKind::MaintenanceEntry: return "maintenance-entry";
    case GateKind::ControlledDrain: return "controlled-drain";
    case GateKind::EmergencyOperation: return "emergency-operation";
    case GateKind::RecoveryStart: return "recovery-start";
    case GateKind::ReturnToService: return "return-to-service";
  }
  return "unknown-gate";
}

Result<GateKind> gate_kind_from_string(std::string_view text) {
  constexpr std::array<GateKind, kGateKindCount> kAll = {
      GateKind::NewObligation,   GateKind::MaintenanceEntry, GateKind::ControlledDrain,
      GateKind::EmergencyOperation, GateKind::RecoveryStart,  GateKind::ReturnToService};
  for (const GateKind candidate : kAll) {
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return fail(StatusCode::InvalidArgument, "unrecognised gate kind: " + std::string(text));
}

bool ReadinessGate::has_condition(std::string_view name) const noexcept {
  return find_condition(name) != nullptr;
}

const GateCondition* ReadinessGate::find_condition(std::string_view name) const noexcept {
  for (const GateCondition& condition : conditions) {
    if (condition.name.view() == name) {
      return &condition;
    }
  }
  return nullptr;
}

// canonical_write for GateCondition and ReadinessGate lives in journal_format.cpp
// so that each writer sits next to its reader.

Result<ReadinessGate> evaluate_gate(GateKind kind, const SiteStateSnapshot& snapshot,
                                    const SitePolicy& policy) {
  const Status policy_status = policy.validate();
  if (!policy_status.ok()) {
    return policy_status;
  }
  if (snapshot.slots.empty()) {
    return fail(StatusCode::InvalidArgument,
                "gate evaluation requires a composed snapshot; this snapshot has no slots");
  }

  ReadinessGate gate;
  gate.kind = kind;
  const SlotFacts facts = slot_facts(snapshot);
  const bool retired = snapshot.state == SiteState::Retired ||
                       snapshot.lifecycle == LifecycleState::Retired ||
                       snapshot.state == SiteState::Isolated;
  const bool emergency_context = snapshot.state == SiteState::Emergency ||
                                 snapshot.lifecycle == LifecycleState::Emergency ||
                                 snapshot.has_constraint(ConstraintKind::EmergencyDeclared);

  switch (kind) {
    case GateKind::NewObligation: {
      add_condition(gate, "site-not-retired", !retired,
                    std::string(to_string(snapshot.state)), "not retired or isolated",
                    "a retired or isolated site accepts no new obligations");
      const bool admits = admits_new_obligations(snapshot.state);
      add_condition(gate, "state-admits-obligation", admits,
                    std::string(to_string(snapshot.state)), "available or constrained",
                    admits ? "the site state admits new obligations"
                           : "the site state does not admit new obligations");
      if (policy.require_unconflicted_evidence_for_new_obligations) {
        add_condition(gate, "evidence-unconflicted", !facts.any_conflicting,
                      facts.any_conflicting ? "conflicting" : "unconflicted", "unconflicted",
                      facts.any_conflicting
                          ? "publishers disagree and the site plane does not pick a winner"
                          : "no slot is in conflict");
      }
      if (policy.require_complete_evidence_for_new_obligations) {
        const bool complete = snapshot.classification == EvidenceClassification::Complete;
        add_condition(gate, "evidence-complete", complete,
                      std::string(to_string(snapshot.classification)), "complete",
                      complete ? "every slot is filled by an accepted publication"
                               : "some evidence is missing, unsupported or unusable");
      }
      if (policy.require_fresh_evidence_for_new_obligations) {
        add_condition(gate, "evidence-fresh", !facts.any_stale,
                      facts.any_stale ? "stale" : "fresh", "every accepted publication fresh",
                      facts.any_stale ? "at least one accepted publication is stale or expired"
                                      : "every accepted publication is within its freshness window");
      }
      if (policy.require_power_ready_for_new_obligations) {
        add_domain_condition(gate, snapshot, "power", policy);
      }
      if (policy.require_cooling_ready_for_new_obligations) {
        add_domain_condition(gate, snapshot, "cooling", policy);
      }
      if (policy.require_asi_ready_for_new_obligations) {
        add_domain_condition(gate, snapshot, "accelerators", policy);
      }
      if (policy.require_dfi_ready_for_new_obligations) {
        add_domain_condition(gate, snapshot, "fabric", policy);
      }
      const bool satisfied = !unsatisfied_obligation_exists(snapshot);
      add_condition(gate, "no-unsatisfied-obligation", satisfied,
                    satisfied ? "none unsatisfied" : "at least one unsatisfied",
                    "no unsatisfied service obligation",
                    "an obligation that is already unsatisfied must be resolved before the site "
                    "takes on more");
      break;
    }
    case GateKind::MaintenanceEntry: {
      add_condition(gate, "site-not-retired", !retired, std::string(to_string(snapshot.state)),
                    "not retired or isolated", "a retired or isolated site needs no maintenance");
      add_condition(gate, "not-in-emergency", !emergency_context,
                    emergency_context ? "emergency" : "normal", "no declared emergency",
                    emergency_context ? "emergency operation supersedes planned maintenance"
                                      : "no emergency is declared");
      const bool evidence_present = snapshot.evidence.lifecycle.has_value() &&
                                    snapshot.evidence.maintenance.has_value();
      add_condition(gate, "maintenance-evidence-present", evidence_present,
                    evidence_present ? "present" : "absent", "lifecycle and maintenance evidence",
                    evidence_present ? "the lifecycle and maintenance owners both published"
                                     : "maintenance cannot be entered without the lifecycle and "
                                       "maintenance publications");
      const bool floor_met = snapshot.readiness_percent >=
                             policy.maintenance_minimum_readiness_percent;
      add_condition(gate, "readiness-floor", floor_met, percent_text(snapshot.readiness_percent),
                    "at least " + percent_text(policy.maintenance_minimum_readiness_percent),
                    floor_met ? "observed readiness is above the maintenance floor"
                              : "observed readiness is below the maintenance floor");
      const bool no_unsatisfied = !unsatisfied_obligation_exists(snapshot);
      add_condition(gate, "no-unsatisfied-obligation", no_unsatisfied,
                    no_unsatisfied ? "none unsatisfied" : "at least one unsatisfied",
                    "no unsatisfied service obligation",
                    "an unsatisfied obligation must be resolved before the site is taken out of "
                    "service");
      break;
    }
    case GateKind::ControlledDrain: {
      add_condition(gate, "site-not-retired", !retired, std::string(to_string(snapshot.state)),
                    "not retired or isolated", "a retired or isolated site cannot drain further");
      const bool supports = snapshot.lifecycle != LifecycleState::Commissioning;
      add_condition(gate, "lifecycle-supports-drain", supports,
                    std::string(to_string(snapshot.lifecycle)), "active or beyond",
                    supports ? "the lifecycle position permits a controlled drain"
                             : "a site under commissioning has nothing to drain");
      const bool protected_ok = !protected_obligation_unsatisfied(snapshot);
      add_condition(gate, "protected-obligations-satisfied", protected_ok,
                    protected_ok ? "satisfied" : "at least one protected obligation unsatisfied",
                    "every protected obligation satisfied",
                    "draining a site with an unsatisfied protected obligation is refused");
      const bool unconflicted = !facts.any_conflicting;
      add_condition(gate, "evidence-unconflicted", unconflicted,
                    unconflicted ? "unconflicted" : "conflicting", "unconflicted",
                    "a drain is a deliberate act and will not proceed on contradictory evidence");
      break;
    }
    case GateKind::EmergencyOperation: {
      add_condition(gate, "emergency-context", emergency_context,
                    emergency_context ? "declared" : "not declared", "a declared emergency",
                    emergency_context ? "a declared emergency permits emergency operation"
                                      : "emergency operation is not an alternative to normal "
                                        "operation; declare the emergency first");
      add_condition(gate, "site-not-retired", !retired, std::string(to_string(snapshot.state)),
                    "not retired", "a retired site is not operated");
      // Contradictory evidence is never a basis for action, not even in an
      // emergency: acting on a contradiction means choosing a winner by arrival
      // order, which this plane refuses to do anywhere else either.
      add_condition(gate, "evidence-unconflicted", !facts.any_conflicting,
                    facts.any_conflicting ? "conflicting" : "unconflicted", "unconflicted",
                    facts.any_conflicting
                        ? "publishers disagree; emergency operation will not act on a contradiction"
                        : "no slot is in conflict");
      if (!policy.emergency_allows_partial_evidence) {
        const bool complete = snapshot.classification == EvidenceClassification::Complete;
        add_condition(gate, "evidence-complete", complete,
                      std::string(to_string(snapshot.classification)), "complete",
                      "policy requires complete evidence even for emergency operation");
      }
      if (!policy.emergency_allows_unready_domains) {
        add_domain_condition(gate, snapshot, "power", policy);
        add_domain_condition(gate, snapshot, "cooling", policy);
      }
      break;
    }
    case GateKind::RecoveryStart: {
      add_condition(gate, "site-not-retired", !retired, std::string(to_string(snapshot.state)),
                    "not retired", "a retired site is not recovered");
      const std::uint32_t drained = snapshot.evidence.maintenance.has_value()
                                        ? snapshot.evidence.maintenance->drained_percent
                                        : 0U;
      const bool drain_complete =
          drained >= policy.recovery_minimum_drained_percent;
      add_condition(gate, "drain-complete", drain_complete, percent_text(drained),
                    "at least " + percent_text(policy.recovery_minimum_drained_percent),
                    drain_complete ? "the drain has completed"
                                   : "recovery before the drain completes would resume work on "
                                     "hardware still holding state");
      const bool supports = snapshot.lifecycle == LifecycleState::Draining ||
                            snapshot.lifecycle == LifecycleState::Maintenance ||
                            snapshot.lifecycle == LifecycleState::Recovering ||
                            snapshot.lifecycle == LifecycleState::Emergency;
      add_condition(gate, "lifecycle-supports-recovery", supports,
                    std::string(to_string(snapshot.lifecycle)),
                    "draining, maintenance, recovering or emergency",
                    supports ? "the lifecycle position permits recovery"
                             : "the site is not in a position from which it can recover");
      if (!policy.emergency_allows_unready_domains) {
        const DomainReadiness* power = domain_of(snapshot, "power");
        const bool power_present = power != nullptr && power->observed &&
                                   power->level != ReadinessLevel::Unavailable;
        add_condition(gate, "power-available", power_present,
                      power == nullptr || !power->observed
                          ? "unobserved"
                          : std::string(to_string(power->level)),
                      "power not unavailable",
                      power_present ? "power is available for the recovery sequence"
                                    : "power must be available before recovery can be attempted");
      }
      break;
    }
    case GateKind::ReturnToService: {
      add_condition(gate, "site-not-retired", !retired, std::string(to_string(snapshot.state)),
                    "not retired", "a retired site does not return to service");
      const bool complete = snapshot.classification == EvidenceClassification::Complete;
      add_condition(gate, "evidence-complete", complete,
                    std::string(to_string(snapshot.classification)), "complete",
                    complete ? "every slot is filled by an accepted publication"
                             : "returning to service on incomplete evidence would publish a "
                               "capability the site has not demonstrated");
      add_condition(gate, "evidence-fresh", !facts.any_stale,
                    facts.any_stale ? "stale" : "fresh", "every accepted publication fresh",
                    facts.any_stale ? "at least one accepted publication is stale or expired"
                                    : "every accepted publication is within its freshness window");
      add_condition(gate, "evidence-unconflicted", !facts.any_conflicting,
                    facts.any_conflicting ? "conflicting" : "unconflicted", "unconflicted",
                    facts.any_conflicting ? "contradictory evidence must be resolved before the "
                                            "site returns to service"
                                          : "no slot is in conflict");
      const std::size_t blocking = snapshot.blocking_constraint_count();
      const bool unblocked = blocking == 0;
      add_condition(gate, "no-blocking-constraints", unblocked, std::to_string(blocking) + " blocking",
                    "0 blocking constraints",
                    unblocked ? "no blocking constraint is active"
                              : "a blocking constraint is still active");
      const bool floor_met =
          snapshot.readiness_percent >= policy.return_to_service_minimum_readiness_percent;
      add_condition(gate, "readiness-floor", floor_met, percent_text(snapshot.readiness_percent),
                    "at least " + percent_text(policy.return_to_service_minimum_readiness_percent),
                    floor_met ? "observed readiness meets the return-to-service floor"
                              : "observed readiness is below the return-to-service floor");
      add_domain_condition(gate, snapshot, "power", policy);
      add_domain_condition(gate, snapshot, "cooling", policy);
      add_domain_condition(gate, snapshot, "accelerators", policy);
      add_domain_condition(gate, snapshot, "fabric", policy);
      if (policy.require_full_redundancy_for_return_to_service) {
        const bool restored = redundancy_restored(snapshot);
        add_condition(gate, "redundancy-restored", restored,
                      restored ? "restored" : "reduced", "full power and cooling redundancy",
                      restored ? "power and cooling redundancy are restored"
                               : "the site will not return to service on reduced redundancy");
      }
      break;
    }
  }

  gate.open = std::all_of(gate.conditions.begin(), gate.conditions.end(),
                          [](const GateCondition& condition) { return condition.satisfied; });
  return gate;
}

Result<std::vector<ReadinessGate>> evaluate_all_gates(const SiteStateSnapshot& snapshot,
                                                      const SitePolicy& policy) {
  constexpr std::array<GateKind, kGateKindCount> kOrder = {
      GateKind::NewObligation,   GateKind::MaintenanceEntry, GateKind::ControlledDrain,
      GateKind::EmergencyOperation, GateKind::RecoveryStart, GateKind::ReturnToService};
  std::vector<ReadinessGate> gates;
  gates.reserve(kOrder.size());
  for (const GateKind kind : kOrder) {
    const Result<ReadinessGate> gate = evaluate_gate(kind, snapshot, policy);
    if (!gate.has_value()) {
      return gate.status();
    }
    gates.push_back(gate.value());
  }
  return gates;
}

}  // namespace scp
