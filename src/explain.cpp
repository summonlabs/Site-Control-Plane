// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/explain.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace scp {
namespace {

void add_step(ExplainReport& report, std::string code, std::string detail) {
  ExplanationStep step;
  step.code = std::move(code);
  step.detail = std::move(detail);
  report.derivations.push_back(std::move(step));
}

std::string id_text(EvidenceId id) { return id.is_nil() ? std::string("<none>") : id.to_hex(); }

std::string slot_text(const EvidenceSlot& slot) {
  return std::string(to_string(slot.authority)) + "/" + std::string(to_string(slot.kind));
}

}  // namespace

ExplainReport explain_snapshot(const SiteStateSnapshot& snapshot, const SitePolicy& policy) {
  ExplainReport report;
  report.snapshot = snapshot;
  report.gates = snapshot.gates;
  report.policy_digest = compute_policy_digest(policy);
  report.snapshot_digest = snapshot.snapshot_digest;

  add_step(report, "site",
           "site " + snapshot.site.to_hex() + " at site generation " +
               std::to_string(snapshot.site_generation.value()));
  add_step(report, "evaluation-instant",
           "evidence judged at " + snapshot.evaluation_time.to_iso8601());
  add_step(report, "policy", "site policy generation " +
                                 std::to_string(policy.generation.value()) + " digest " +
                                 report.policy_digest.to_hex());
  add_step(report, "evidence-digest",
           "accepted evidence hashes to " + snapshot.evidence_digest.to_hex());
  add_step(report, "classification",
           std::string("evidence is ") + std::string(to_string(snapshot.classification)));
  add_step(report, "lifecycle",
           std::string("published lifecycle is ") + std::string(to_string(snapshot.lifecycle)));
  add_step(report, "state", std::string("composed site state is ") +
                                std::string(to_string(snapshot.state)));

  for (const SlotResolution& resolution : snapshot.slots) {
    std::string detail = slot_text(resolution.slot) + " -> " +
                         std::string(to_string(resolution.outcome));
    if (resolution.accepted()) {
      detail += " from " + resolution.accepted_instance.to_hex();
      detail += " epoch " + std::to_string(resolution.accepted_epoch.value());
      detail += " generation " + std::to_string(resolution.accepted_generation.value());
      detail += " sequence " + std::to_string(resolution.accepted_sequence.value());
      detail += " freshness " + std::string(to_string(resolution.freshness));
      detail += " origin " + std::string(to_string(resolution.origin));
      detail += " evidence " + id_text(resolution.accepted_id);
    }
    if (!resolution.superseded.empty()) {
      detail += "; superseded " + std::to_string(resolution.superseded.size()) + " older";
    }
    if (!resolution.conflicting.empty()) {
      detail += "; conflicting " + std::to_string(resolution.conflicting.size());
    }
    if (resolution.duplicates_merged > 0) {
      detail += "; merged " + std::to_string(resolution.duplicates_merged) + " duplicate(s)";
    }
    if (!resolution.detail.empty()) {
      detail += "; " + resolution.detail;
    }
    add_step(report, "slot", std::move(detail));
  }

  for (const DomainReadiness& domain : snapshot.readiness_domains) {
    add_step(report, "domain-readiness",
             domain.domain + " = " + std::to_string(domain.percent) + "% (" +
                 std::string(to_string(domain.level)) + ")");
  }
  if (snapshot.readiness_domains.empty()) {
    add_step(report, "domain-readiness",
             "no dependency domain reported readiness; the site plane claims none");
  } else {
    add_step(report, "readiness", "observed site readiness is " +
                                      std::to_string(snapshot.readiness_percent) + "%");
  }

  for (const Constraint& constraint : snapshot.constraints) {
    add_step(report, "constraint",
             std::string(to_string(constraint.kind)) + " [" + constraint.subject + "] severity " +
                 std::string(to_string(constraint.severity)) +
                 (constraint.blocking ? " blocking" : " advisory") + ": " + constraint.detail);
    if (constraint.blocking) {
      report.blocking_constraints.push_back(constraint);
    }
  }

  for (const ObligationAssessment& obligation : snapshot.obligations) {
    add_step(report, "obligation",
             std::string(obligation.service_class.view()) + " (" +
                 (obligation.protected_class ? "protected" : "standard") + ") is " +
                 std::string(to_string(obligation.outcome)) + ": ready " +
                 std::to_string(obligation.ready_units) + " of required " +
                 std::to_string(obligation.required_units) + " units, readiness " +
                 std::to_string(obligation.observed_readiness_percent) + "% of required " +
                 std::to_string(obligation.required_readiness_percent) + "%; " +
                 obligation.detail);
    if (obligation.outcome == ObligationOutcome::Unsatisfied) {
      report.unsatisfied_obligations.push_back(obligation);
    }
  }

  for (const ReadinessGate& gate : snapshot.gates) {
    add_step(report, "gate",
             std::string(to_string(gate.kind)) + " is " + (gate.open ? "open" : "closed"));
    for (const GateCondition& condition : gate.conditions) {
      add_step(report, "gate-condition",
               std::string(to_string(gate.kind)) + "." + std::string(condition.name.view()) +
                   " = " + (condition.satisfied ? "satisfied" : "unsatisfied") + " (observed " +
                   condition.observed + ", required " + condition.required + ")");
    }
  }

  if (is_indeterminate(snapshot.state)) {
    report.notes.push_back(
        "the composed state is indeterminate; no site-level action other than a declared "
        "emergency operation is planned from it");
  }
  if (snapshot.blocking_constraint_count() > 0) {
    report.notes.push_back(std::to_string(snapshot.blocking_constraint_count()) +
                           " blocking constraint(s) are active");
  }
  if (snapshot.evidence.populated_count() < static_cast<std::size_t>(kEvidenceKindCount)) {
    report.notes.push_back("only " + std::to_string(snapshot.evidence.populated_count()) + " of " +
                           std::to_string(kEvidenceKindCount) +
                           " evidence kinds are present in the accepted set");
  }
  return report;
}

std::vector<std::string> render_explanation(const ExplainReport& report) {
  std::vector<std::string> lines;
  lines.push_back("site " + report.snapshot.site.to_hex());
  lines.push_back("site-generation " +
                  std::to_string(report.snapshot.site_generation.value()));
  lines.push_back("state " + std::string(to_string(report.snapshot.state)));
  lines.push_back("lifecycle " + std::string(to_string(report.snapshot.lifecycle)));
  lines.push_back("evidence " + std::string(to_string(report.snapshot.classification)));
  lines.push_back("readiness-percent " + std::to_string(report.snapshot.readiness_percent));
  lines.push_back("evidence-digest " + report.snapshot.evidence_digest.to_hex());
  lines.push_back("snapshot-digest " + report.snapshot_digest.to_hex());
  lines.push_back("policy-digest " + report.policy_digest.to_hex());

  lines.push_back("slots:");
  for (const SlotResolution& resolution : report.snapshot.slots) {
    lines.push_back("  " + slot_text(resolution.slot) + " " +
                    std::string(to_string(resolution.outcome)) + " freshness=" +
                    std::string(to_string(resolution.freshness)) + " origin=" +
                    std::string(to_string(resolution.origin)) + " evidence=" +
                    id_text(resolution.accepted_id) + " superseded=" +
                    std::to_string(resolution.superseded.size()) + " conflicting=" +
                    std::to_string(resolution.conflicting.size()));
  }

  lines.push_back("domains:");
  if (report.snapshot.readiness_domains.empty()) {
    lines.push_back("  <none observed>");
  }
  for (const DomainReadiness& domain : report.snapshot.readiness_domains) {
    lines.push_back("  " + domain.domain + " " + std::to_string(domain.percent) + "% " +
                    std::string(to_string(domain.level)));
  }

  lines.push_back("constraints:");
  if (report.snapshot.constraints.empty()) {
    lines.push_back("  <none>");
  }
  for (const Constraint& constraint : report.snapshot.constraints) {
    lines.push_back("  " + std::string(to_string(constraint.kind)) + " " + constraint.subject +
                    " " + std::string(to_string(constraint.severity)) +
                    (constraint.blocking ? " blocking" : " advisory") + " :: " +
                    escape_for_display(constraint.detail));
  }

  lines.push_back("obligations:");
  if (report.snapshot.obligations.empty()) {
    lines.push_back("  <none declared>");
  }
  for (const ObligationAssessment& obligation : report.snapshot.obligations) {
    lines.push_back("  " + std::string(obligation.service_class.view()) + " " +
                    std::string(to_string(obligation.outcome)) +
                    (obligation.protected_class ? " protected" : "") + " ready=" +
                    std::to_string(obligation.ready_units) + "/" +
                    std::to_string(obligation.required_units) + " readiness=" +
                    std::to_string(obligation.observed_readiness_percent) + "/" +
                    std::to_string(obligation.required_readiness_percent));
  }

  lines.push_back("gates:");
  for (const ReadinessGate& gate : report.snapshot.gates) {
    lines.push_back("  " + std::string(to_string(gate.kind)) + " " +
                    (gate.open ? "open" : "closed"));
    for (const GateCondition& condition : gate.conditions) {
      if (condition.satisfied) {
        continue;
      }
      lines.push_back("    unsatisfied " + std::string(condition.name.view()) + ": observed " +
                      escape_for_display(condition.observed) + ", required " +
                      escape_for_display(condition.required));
    }
  }

  lines.push_back("derivation:");
  for (const ExplanationStep& step : report.derivations) {
    lines.push_back("  [" + step.code + "] " + escape_for_display(step.detail));
  }

  if (!report.notes.empty()) {
    lines.push_back("notes:");
    for (const std::string& note : report.notes) {
      lines.push_back("  " + escape_for_display(note));
    }
  }
  return lines;
}

}  // namespace scp
