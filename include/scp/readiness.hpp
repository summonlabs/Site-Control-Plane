// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/policy.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"

/// \file readiness.hpp
/// Dependency and readiness evaluation.
///
/// Every site-level transition is gated. A gate is open only when all of its
/// conditions hold, and each condition records the observed value that decided
/// it, so `scpctl explain` can show exactly why a change was refused. Gates are
/// re-evaluated for each plan; a gate result is never cached across generations.

namespace scp {

enum class GateKind : std::uint8_t {
  NewObligation = 1,
  MaintenanceEntry = 2,
  ControlledDrain = 3,
  EmergencyOperation = 4,
  RecoveryStart = 5,
  ReturnToService = 6,
};

inline constexpr std::size_t kGateKindCount = 6;

[[nodiscard]] std::string_view to_string(GateKind kind) noexcept;
[[nodiscard]] Result<GateKind> gate_kind_from_string(std::string_view text);

/// One evaluated condition. \c satisfied is the verdict; \c observed and
/// \c required are the values that produced it, kept as text so that the reason
/// survives into logs and reports without a second lookup.
struct GateCondition {
  Name name{};
  bool satisfied = false;
  std::string observed;
  std::string required;
  std::string detail;
};

struct ReadinessGate {
  GateKind kind = GateKind::NewObligation;
  bool open = false;
  std::vector<GateCondition> conditions;

  [[nodiscard]] bool has_condition(std::string_view name) const noexcept;
  [[nodiscard]] const GateCondition* find_condition(std::string_view name) const noexcept;
};

/// Evaluates one gate against a composed snapshot and the policy in force.
///
/// The snapshot must already have been composed with the same policy; passing a
/// snapshot composed under different thresholds is rejected rather than silently
/// evaluated against the wrong rules.
[[nodiscard]] Result<ReadinessGate> evaluate_gate(GateKind kind, const SiteStateSnapshot& snapshot,
                                                 const SitePolicy& policy);

/// Evaluates every gate. Order is fixed, so the result is deterministic.
[[nodiscard]] Result<std::vector<ReadinessGate>> evaluate_all_gates(
    const SiteStateSnapshot& snapshot, const SitePolicy& policy);

void canonical_write(CanonicalWriter& writer, const GateCondition& value);
void canonical_write(CanonicalWriter& writer, const ReadinessGate& value);

[[nodiscard]] Result<GateCondition> canonical_read_gate_condition(CanonicalReader& reader);
[[nodiscard]] Result<ReadinessGate> canonical_read_gate(CanonicalReader& reader);

}  // namespace scp
