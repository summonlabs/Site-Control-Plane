// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/policy.hpp"

#include <cstdint>
#include <string>

namespace scp {

std::string_view to_string(Comparison comparison) noexcept {
  switch (comparison) {
    case Comparison::AtLeast: return "at-least";
    case Comparison::AtMost: return "at-most";
    case Comparison::Equal: return "equal";
    case Comparison::NotEqual: return "not-equal";
  }
  return "unknown-comparison";
}

Status SitePolicy::validate() const {
  if (generation.is_unset()) {
    return fail(StatusCode::InvalidArgument,
                "policy generation is not set; an unversioned policy cannot be cited as the "
                "reason for a decision");
  }
  if (freshness.stale_after.nanos < 0) {
    return fail(StatusCode::OutOfRange, "freshness.stale_after must not be negative");
  }
  if (freshness.expire_after.nanos < freshness.stale_after.nanos) {
    return fail(StatusCode::OutOfRange,
                "freshness.expire_after must not be shorter than freshness.stale_after");
  }
  if (capacity_headroom_degraded_percent > capacity_headroom_constrained_percent) {
    return fail(StatusCode::OutOfRange,
                "capacity_headroom_degraded_percent must not exceed "
                "capacity_headroom_constrained_percent; the site would be degraded before it was "
                "constrained");
  }
  if (capacity_headroom_constrained_percent > 100) {
    return fail(StatusCode::OutOfRange, "capacity_headroom_constrained_percent must be 0..100");
  }
  if (capacity_headroom_degraded_percent > 100) {
    return fail(StatusCode::OutOfRange, "capacity_headroom_degraded_percent must be 0..100");
  }
  if (domain_readiness_unavailable_percent > domain_readiness_degraded_percent) {
    return fail(StatusCode::OutOfRange,
                "domain_readiness_unavailable_percent must not exceed "
                "domain_readiness_degraded_percent");
  }
  if (domain_readiness_degraded_percent > 100) {
    return fail(StatusCode::OutOfRange, "domain_readiness_degraded_percent must be 0..100");
  }
  if (maintenance_minimum_readiness_percent > 100) {
    return fail(StatusCode::OutOfRange, "maintenance_minimum_readiness_percent must be 0..100");
  }
  if (recovery_minimum_drained_percent > 100) {
    return fail(StatusCode::OutOfRange, "recovery_minimum_drained_percent must be 0..100");
  }
  if (return_to_service_minimum_readiness_percent > 100) {
    return fail(StatusCode::OutOfRange, "return_to_service_minimum_readiness_percent must be 0..100");
  }
  if (rules.size() > kMaxThresholdRules) {
    return fail(StatusCode::LimitExceeded,
                "site policy carries " + std::to_string(rules.size()) + " threshold rules, the limit is " +
                    std::to_string(kMaxThresholdRules));
  }
  if (max_constraints == 0) {
    return fail(StatusCode::OutOfRange, "max_constraints must be at least 1");
  }
  if (max_service_classes == 0) {
    return fail(StatusCode::OutOfRange, "max_service_classes must be at least 1");
  }
  for (std::size_t index = 0; index < rules.size(); ++index) {
    const ThresholdRule& rule = rules[index];
    if (rule.rule_id.empty()) {
      return fail(StatusCode::InvalidArgument,
                  "threshold rule " + std::to_string(index) + " has no rule id");
    }
    if (rule.subject.size() > kMaxNameBytes) {
      return fail(StatusCode::LimitExceeded,
                  "threshold rule " + std::string(rule.rule_id.view()) + " has an oversized subject");
    }
  }
  return Status{};
}

Digest compute_policy_digest(const SitePolicy& policy) {
  CanonicalWriter writer;
  canonical_write(writer, policy);
  return Digest::of(writer.span());
}

bool rule_satisfied(const ThresholdRule& rule, std::uint64_t observed) noexcept {
  switch (rule.comparison) {
    case Comparison::AtLeast: return observed >= rule.threshold;
    case Comparison::AtMost: return observed <= rule.threshold;
    case Comparison::Equal: return observed == rule.threshold;
    case Comparison::NotEqual: return observed != rule.threshold;
  }
  return false;
}

}  // namespace scp
