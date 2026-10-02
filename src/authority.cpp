// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/authority.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace scp {
namespace {

struct ScopeName {
  ActionScope scope;
  std::string_view name;
};

/// Every scope, in definition order. Iteration order is fixed so that string
/// rendering and selection are deterministic.
constexpr std::array<ScopeName, kActionScopeCount> kScopeNames = {{
    {ActionScope::ObserveSite, "observe-site"},
    {ActionScope::AcceptObligation, "accept-obligation"},
    {ActionScope::ReleaseObligation, "release-obligation"},
    {ActionScope::RequestAcceleratorEffect, "request-accelerator-effect"},
    {ActionScope::RequestFabricEffect, "request-fabric-effect"},
    {ActionScope::RequestPowerEffect, "request-power-effect"},
    {ActionScope::RequestCoolingEffect, "request-cooling-effect"},
    {ActionScope::EnterMaintenance, "enter-maintenance"},
    {ActionScope::ControlledDrain, "controlled-drain"},
    {ActionScope::EmergencyOperation, "emergency-operation"},
    {ActionScope::RecoveryOperation, "recovery-operation"},
    {ActionScope::ReturnToService, "return-to-service"},
    {ActionScope::IsolateSite, "isolate-site"},
    {ActionScope::RetireSite, "retire-site"},
    {ActionScope::RecordAuthority, "record-authority"},
    {ActionScope::ManagePolicy, "manage-policy"},
}};

}  // namespace

std::string_view to_string(ActionScope scope) noexcept {
  for (const ScopeName& entry : kScopeNames) {
    if (entry.scope == scope) {
      return entry.name;
    }
  }
  return "none";
}

Result<ActionScope> action_scope_from_string(std::string_view text) {
  for (const ScopeName& entry : kScopeNames) {
    if (entry.name == text) {
      return entry.scope;
    }
  }
  return fail(StatusCode::InvalidArgument, "unrecognised action scope: " + std::string(text));
}

std::string ScopeSet::to_string() const {
  std::string result;
  for (const ScopeName& entry : kScopeNames) {
    if (!contains(entry.scope)) {
      continue;
    }
    if (!result.empty()) {
      result += ',';
    }
    result += entry.name;
  }
  return result;
}

std::string_view to_string(AuthorityOutcome outcome) noexcept {
  switch (outcome) {
    case AuthorityOutcome::Granted: return "granted";
    case AuthorityOutcome::NoGrantFound: return "no-grant-found";
    case AuthorityOutcome::ScopeNotGranted: return "scope-not-granted";
    case AuthorityOutcome::SiteMismatch: return "site-mismatch";
    case AuthorityOutcome::GrantExpired: return "grant-expired";
    case AuthorityOutcome::GrantRevoked: return "grant-revoked";
    case AuthorityOutcome::GrantNotYetValid: return "grant-not-yet-valid";
    case AuthorityOutcome::GenerationFenced: return "generation-fenced";
    case AuthorityOutcome::GrantInvalid: return "grant-invalid";
  }
  return "unknown-outcome";
}

bool is_granted(AuthorityOutcome outcome) noexcept {
  return outcome == AuthorityOutcome::Granted;
}

Status DelegationGrant::validate() const {
  if (id.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "delegation grant has no identity");
  }
  if (site.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "delegation grant names no site");
  }
  if (grantor.empty()) {
    return fail(StatusCode::InvalidArgument, "delegation grant has no grantor");
  }
  if (subject.empty()) {
    return fail(StatusCode::InvalidArgument, "delegation grant has no subject");
  }
  if (!issued_at.is_set()) {
    return fail(StatusCode::InvalidArgument, "delegation grant has no issue time");
  }
  if (expires_at.is_set() && expires_at.nanos < issued_at.nanos) {
    return fail(StatusCode::OutOfRange, "delegation grant expires before it was issued");
  }
  if (!not_after.is_unset() && not_before.value() > not_after.value()) {
    return fail(StatusCode::OutOfRange,
                "delegation grant generation fence is inverted: not_before exceeds not_after");
  }
  if (scopes.empty()) {
    return fail(StatusCode::InvalidArgument,
                "delegation grant carries no scopes; an empty delegation is not a delegation");
  }
  return Status{};
}

std::vector<std::uint8_t> DelegationGrant::canonical_bytes() const {
  CanonicalWriter writer;
  canonical_write(writer, *this);
  return writer.take();
}

AuthorityDecision evaluate_grant(const DelegationGrant& grant, SiteId site, ScopeSet required,
                                 SiteGeneration generation, Timestamp now) {
  AuthorityDecision decision;
  decision.grant = grant.id;

  const Status valid = grant.validate();
  if (!valid.ok()) {
    decision.outcome = AuthorityOutcome::GrantInvalid;
    decision.detail = valid.message();
    return decision;
  }
  if (!(grant.site == site)) {
    decision.outcome = AuthorityOutcome::SiteMismatch;
    decision.detail = "grant is scoped to a different site";
    return decision;
  }
  if (grant.revoked) {
    decision.outcome = AuthorityOutcome::GrantRevoked;
    decision.detail = "grant was revoked";
    return decision;
  }
  if (grant.expires_at.is_set() && now.nanos >= grant.expires_at.nanos) {
    decision.outcome = AuthorityOutcome::GrantExpired;
    decision.detail = "grant expired at the evaluation instant";
    return decision;
  }
  if (!grant.not_before.is_unset() && generation.value() < grant.not_before.value()) {
    decision.outcome = AuthorityOutcome::GrantNotYetValid;
    decision.detail = "grant is not valid below its lower generation bound";
    return decision;
  }
  if (!grant.not_after.is_unset() && generation.value() >= grant.not_after.value()) {
    decision.outcome = AuthorityOutcome::GenerationFenced;
    decision.detail = "grant is fenced out at the current site generation";
    return decision;
  }
  if (!grant.scopes.contains_all(required)) {
    decision.outcome = AuthorityOutcome::ScopeNotGranted;
    decision.detail = "grant covers [" + grant.scopes.to_string() + "] but [" + required.to_string() +
                      "] is required";
    return decision;
  }
  decision.outcome = AuthorityOutcome::Granted;
  decision.detail = "granted by " + std::string(grant.grantor.view()) + " to " +
                    std::string(grant.subject.view()) + " for [" + grant.scopes.to_string() + "]";
  return decision;
}

AuthorityDecision evaluate_authority(std::span<const DelegationGrant> grants, SiteId site,
                                     ScopeSet required, SiteGeneration generation, Timestamp now) {
  // Deterministic selection: grants are considered in grant-id order, so the
  // decision does not depend on the order they were recorded. The first valid
  // grant that covers the required scope wins; if none covers it, the most
  // specific failure from the first applicable grant is reported rather than a
  // bare refusal, because the reason matters operationally.
  std::vector<const DelegationGrant*> ordered;
  ordered.reserve(grants.size());
  for (const DelegationGrant& grant : grants) {
    ordered.push_back(&grant);
  }
  std::sort(ordered.begin(), ordered.end(),
            [](const DelegationGrant* lhs, const DelegationGrant* rhs) { return lhs->id < rhs->id; });

  AuthorityDecision first_failure;
  bool have_failure = false;
  for (const DelegationGrant* grant : ordered) {
    if (!(grant->site == site)) {
      continue;
    }
    const AuthorityDecision decision = evaluate_grant(*grant, site, required, generation, now);
    if (decision.granted()) {
      return decision;
    }
    if (!have_failure) {
      first_failure = decision;
      have_failure = true;
    }
  }
  if (have_failure) {
    return first_failure;
  }
  AuthorityDecision none;
  none.outcome = AuthorityOutcome::NoGrantFound;
  none.detail = "no delegation grant names this site";
  return none;
}

}  // namespace scp
