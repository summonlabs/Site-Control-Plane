// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "scp/authority.hpp"
#include "scp/policy.hpp"
#include "scp/readiness.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/time.hpp"

/// \file explain.hpp
/// The observability and explainability surface.
///
/// Everything this plane decides can be re-derived from values it reports:
/// which evidence won each slot, why each constraint exists, which gate condition
/// closed a transition, and which grant authorized a request. Nothing here is a
/// narrative reconstruction — the lines are generated from the same values the
/// decision used.

namespace scp {

/// One ordered derivation step. \c code is a stable, machine-readable tag.
struct ExplanationStep {
  std::string code;
  std::string detail;
};

/// Runtime counters. Monotonic except where noted; never invented.
struct RuntimeStatus;

struct ExplainReport {
  SiteStateSnapshot snapshot;
  std::vector<ReadinessGate> gates;
  std::vector<ExplanationStep> derivations;
  std::vector<Constraint> blocking_constraints;
  std::vector<ObligationAssessment> unsatisfied_obligations;
  std::vector<std::string> notes;
  Digest policy_digest{};
  Digest snapshot_digest{};
};

/// Builds an explanation of a composed snapshot. Pure.
[[nodiscard]] ExplainReport explain_snapshot(const SiteStateSnapshot& snapshot,
                                             const SitePolicy& policy);

/// Renders an explanation as stable, human-readable text. Every line is ASCII
/// with untrusted text escaped, so a report can be diffed and logged safely.
[[nodiscard]] std::vector<std::string> render_explanation(const ExplainReport& report);

}  // namespace scp
