// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"

/// \file policy.hpp
/// Site policy and the constraint evaluator's configuration.
///
/// Two different things are called "policy" in DCCP and this boundary keeps them
/// apart:
///   * the lower policy engine *authors* rules and publishes them as evidence;
///     this plane consumes that evidence and records its generation and digest;
///   * this plane owns the *site-level operating thresholds* it applies to that
///     evidence, which is what this header defines.
/// A site policy never restates a lower rule and never overrides one.

namespace scp {

/// A named threshold comparison used by configurable rules.
enum class Comparison : std::uint8_t {
  AtLeast = 1,
  AtMost = 2,
  Equal = 3,
  NotEqual = 4,
};

[[nodiscard]] std::string_view to_string(Comparison comparison) noexcept;

/// An operator-configured rule applied to a numeric site quantity.
struct ThresholdRule {
  Name rule_id{};
  ConstraintKind kind = ConstraintKind::CapacityHeadroomLow;
  Severity severity = Severity::Minor;
  Comparison comparison = Comparison::AtLeast;
  std::uint64_t threshold = 0;
  bool blocking = false;
  std::string subject;

  friend bool operator==(const ThresholdRule&, const ThresholdRule&) noexcept = default;
};

inline constexpr std::size_t kMaxThresholdRules = 64;

/// Site-level operating policy. Everything here is a threshold this boundary
/// applies to consumed evidence; nothing here re-authors a lower-domain rule.
struct SitePolicy {
  /// Generation of the site *evaluation* policy. Distinct from the lower policy
  /// engine's generation, which arrives as evidence.
  PolicyGeneration generation = PolicyGeneration::first();

  FreshnessPolicy freshness{};

  /// Capacity headroom, in whole percent of total units, below which the site is
  /// Constrained.
  std::uint32_t capacity_headroom_constrained_percent = 10;
  /// Capacity headroom below which the site is Degraded.
  std::uint32_t capacity_headroom_degraded_percent = 3;
  /// Readiness percent (ready units / total units) below which an execution
  /// domain is reported Degraded for site purposes.
  std::uint32_t domain_readiness_degraded_percent = 75;
  /// Readiness percent below which an execution domain cannot carry new work.
  std::uint32_t domain_readiness_unavailable_percent = 25;

  /// Reserved redundancy domains the site requires to be available for normal
  /// operation; a shortfall is a RedundancyReduced constraint.
  std::uint32_t required_redundancy_domains = 1;

  /// Power/cooling headroom floors, in milli-kilowatts.
  std::uint64_t power_headroom_floor_milli_kw = 0;
  std::uint64_t cooling_headroom_floor_milli_kw = 0;

  /// Evidence rules.
  bool require_complete_evidence_for_new_obligations = true;
  bool require_fresh_evidence_for_new_obligations = true;
  bool require_unconflicted_evidence_for_new_obligations = true;

  /// Readiness gates.
  bool require_power_ready_for_new_obligations = true;
  bool require_cooling_ready_for_new_obligations = true;
  bool require_asi_ready_for_new_obligations = true;
  bool require_dfi_ready_for_new_obligations = true;
  bool require_full_redundancy_for_return_to_service = false;

  /// Minimum readiness percent required before a maintenance window may start.
  std::uint32_t maintenance_minimum_readiness_percent = 0;
  /// Minimum drained percent required before recovery may begin.
  std::uint32_t recovery_minimum_drained_percent = 100;
  /// Minimum readiness percent required before the site may return to service.
  std::uint32_t return_to_service_minimum_readiness_percent = 90;

  /// Emergency operation is deliberately permissive: an emergency may proceed on
  /// partial evidence, and the snapshot records that it did.
  bool emergency_allows_partial_evidence = true;
  bool emergency_allows_unready_domains = true;

  /// Maximum number of constraints a snapshot may carry before composition
  /// reports a limit failure instead of growing without bound.
  std::size_t max_constraints = 256;
  /// Maximum number of service classes accepted from one publisher.
  std::size_t max_service_classes = kMaxServiceClasses;

  std::vector<ThresholdRule> rules;

  /// Rejects combinations that cannot mean anything (for example a "degraded"
  /// threshold above the "constrained" threshold, or an out-of-range percent).
  [[nodiscard]] Status validate() const;

  friend bool operator==(const SitePolicy&, const SitePolicy&) noexcept = default;
};

/// Canonical encoding of the policy so that a snapshot can record exactly which
/// thresholds produced it.
void canonical_write(CanonicalWriter& writer, const SitePolicy& value);
[[nodiscard]] Result<SitePolicy> canonical_read_policy(CanonicalReader& reader);
[[nodiscard]] Digest compute_policy_digest(const SitePolicy& policy);

/// Applies one threshold rule to an observed value.
[[nodiscard]] bool rule_satisfied(const ThresholdRule& rule, std::uint64_t observed) noexcept;

}  // namespace scp
