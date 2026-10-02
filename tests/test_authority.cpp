// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

// Delegated scope validation: the scope algebra, grant validity, the exact
// refusal for every way a delegation can fail to authorise an action, and the
// determinism of the selection among several grants.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "scp/authority.hpp"
#include "scp/ids.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"
#include "test_support.hpp"

using scp::ActionScope;
using scp::AuthorityDecision;
using scp::AuthorityOutcome;
using scp::DelegationGrant;
using scp::GrantId;
using scp::Name;
using scp::Result;
using scp::ScopeSet;
using scp::SiteGeneration;
using scp::SiteId;
using scp::Status;
using scp::StatusCode;
using scp::Timestamp;

namespace {

constexpr std::array<ActionScope, scp::kActionScopeCount> kScopes = {
    ActionScope::ObserveSite,        ActionScope::AcceptObligation,
    ActionScope::ReleaseObligation,  ActionScope::RequestAcceleratorEffect,
    ActionScope::RequestFabricEffect, ActionScope::RequestPowerEffect,
    ActionScope::RequestCoolingEffect, ActionScope::EnterMaintenance,
    ActionScope::ControlledDrain,    ActionScope::EmergencyOperation,
    ActionScope::RecoveryOperation,  ActionScope::ReturnToService,
    ActionScope::IsolateSite,        ActionScope::RetireSite,
    ActionScope::RecordAuthority,    ActionScope::ManagePolicy};

constexpr std::array<std::string_view, scp::kActionScopeCount> kScopeNames = {
    "observe-site",      "accept-obligation",   "release-obligation",
    "request-accelerator-effect", "request-fabric-effect", "request-power-effect",
    "request-cooling-effect", "enter-maintenance", "controlled-drain",
    "emergency-operation", "recovery-operation", "return-to-service",
    "isolate-site",      "retire-site",         "record-authority",
    "manage-policy"};

std::uint64_t splitmix64(std::uint64_t& state) {
  state += 0x9E3779B97F4A7C15ULL;
  std::uint64_t value = state;
  value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
  return value ^ (value >> 31U);
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

void expect_status_code(const Status& status, StatusCode expected, const char* what) {
  if (status.code() != expected) {
    ::scp_test::Context::instance().note(std::string(what) + ": reported " + status.to_string() +
                                         " instead of " + std::string(scp::to_string(expected)));
  }
  SCP_CHECK(status.code() == expected);
}

void expect_outcome(const AuthorityDecision& decision, AuthorityOutcome expected, const char* what) {
  if (decision.outcome != expected) {
    ::scp_test::Context::instance().note(std::string(what) + ": reported " +
                                         std::string(scp::to_string(decision.outcome)) +
                                         " instead of " + std::string(scp::to_string(expected)) +
                                         " (" + decision.detail + ")");
  }
  SCP_CHECK_EQ(decision.outcome, expected);
  SCP_CHECK(!decision.detail.empty());
}

/// A grant that covers ObserveSite for the default site, valid now.
DelegationGrant valid_grant(std::uint64_t serial) {
  DelegationGrant grant;
  grant.id = GrantId(0x6A00000000000000ULL, serial);
  grant.site = scp_test::default_site();
  grant.grantor = name_of("facility-policy-engine");
  grant.subject = name_of("site-control-plane");
  grant.scopes = ScopeSet::of(ActionScope::ObserveSite);
  grant.not_before = SiteGeneration::first();
  grant.issued_at = scp_test::base_instant();
  grant.expires_at = scp_test::instant_after(3600);
  return grant;
}

bool same_decision(const AuthorityDecision& lhs, const AuthorityDecision& rhs) {
  return lhs.outcome == rhs.outcome && lhs.grant == rhs.grant && lhs.detail == rhs.detail;
}

std::vector<DelegationGrant> mixed_grants() {
  std::vector<DelegationGrant> grants;

  DelegationGrant covering = valid_grant(10);
  covering.scopes = ScopeSet::of(ActionScope::ObserveSite).with(ActionScope::ManagePolicy);
  grants.push_back(covering);

  DelegationGrant narrow = valid_grant(11);
  grants.push_back(narrow);

  DelegationGrant missing_scope = valid_grant(12);
  missing_scope.scopes = ScopeSet::of(ActionScope::RetireSite);
  grants.push_back(missing_scope);

  DelegationGrant expired = valid_grant(13);
  expired.expires_at = scp_test::instant_after(-1);
  grants.push_back(expired);

  DelegationGrant fenced = valid_grant(14);
  fenced.not_after = SiteGeneration(2);
  grants.push_back(fenced);

  DelegationGrant foreign = valid_grant(15);
  foreign.site = SiteId(0x0FF510E000000000ULL, 0x0000000000000009ULL);
  grants.push_back(foreign);

  DelegationGrant revoked = valid_grant(16);
  revoked.revoked = true;
  grants.push_back(revoked);

  DelegationGrant invalid = valid_grant(17);
  invalid.grantor = Name();
  grants.push_back(invalid);

  return grants;
}

void permute(std::vector<DelegationGrant>& grants, std::uint64_t& state) {
  for (std::size_t index = grants.size(); index > 1U; --index) {
    const std::size_t other = static_cast<std::size_t>(splitmix64(state) % index);
    std::swap(grants[index - 1U], grants[other]);
  }
}

}  // namespace

SCP_TEST(scope_set_operations) {
  const ScopeSet empty;
  SCP_CHECK(empty.empty());
  SCP_CHECK_EQ(empty.bits(), std::uint16_t{0});
  SCP_CHECK(empty.to_string().empty());
  SCP_CHECK(!empty.contains(ActionScope::ObserveSite));
  SCP_CHECK(empty.contains_all(empty));
  SCP_CHECK(empty.contains_all(ScopeSet::of(ActionScope::RetireSite)) == false);
  SCP_CHECK(empty.with(ActionScope::IsolateSite) == ScopeSet::of(ActionScope::IsolateSite));

  const ScopeSet observe = ScopeSet::of(ActionScope::ObserveSite);
  SCP_CHECK(!observe.empty());
  SCP_CHECK(observe.contains(ActionScope::ObserveSite));
  SCP_CHECK(!observe.contains(ActionScope::ManagePolicy));
  SCP_CHECK_EQ(observe.to_string(), std::string("observe-site"));

  // Names are rendered in definition order, not insertion order.
  const ScopeSet combo =
      observe.with(ActionScope::ManagePolicy).with(ActionScope::AcceptObligation);
  SCP_CHECK_EQ(combo.to_string(), std::string("observe-site,accept-obligation,manage-policy"));
  SCP_CHECK(combo.contains_all(observe));
  SCP_CHECK(combo.contains(ActionScope::ManagePolicy));
  SCP_CHECK(combo.contains_all(combo));
  SCP_CHECK(!observe.contains_all(combo));
  SCP_CHECK(observe.intersect(combo) == observe);
  SCP_CHECK(combo.intersect(observe) == observe);
  SCP_CHECK_EQ(combo.without(ActionScope::ManagePolicy),
               ScopeSet::of(ActionScope::ObserveSite).with(ActionScope::AcceptObligation));
  SCP_CHECK_EQ(combo.without(ActionScope::RetireSite), combo);
  SCP_CHECK(observe.intersect(ScopeSet::of(ActionScope::RetireSite)).empty());
  SCP_CHECK_EQ(observe.without(ActionScope::ObserveSite), empty);
  SCP_CHECK(combo.contains_all(empty));

  // Every scope has one bit, one name, and round-trips through its name.
  std::uint16_t union_bits = 0;
  for (std::size_t index = 0; index < kScopes.size(); ++index) {
    const ScopeSet single = ScopeSet::of(kScopes[index]);
    SCP_CHECK_EQ(single.bits(), static_cast<std::uint16_t>(kScopes[index]));
    SCP_CHECK_EQ(single.to_string(), std::string(kScopeNames[index]));
    SCP_CHECK_EQ(scp::to_string(kScopes[index]), kScopeNames[index]);
    const Result<ActionScope> parsed = scp::action_scope_from_string(kScopeNames[index]);
    SCP_CHECK(parsed.has_value());
    if (parsed.has_value()) {
      SCP_CHECK_EQ(parsed.value(), kScopes[index]);
    }
    union_bits = static_cast<std::uint16_t>(union_bits | single.bits());
  }
  for (std::size_t left = 0; left < kScopes.size(); ++left) {
    for (std::size_t right = left + 1U; right < kScopes.size(); ++right) {
      SCP_CHECK_NE(kScopes[left], kScopes[right]);
      SCP_CHECK_EQ(ScopeSet::of(kScopes[left]).intersect(ScopeSet::of(kScopes[right])).bits(),
                   std::uint16_t{0});
    }
  }
  const ScopeSet everything(union_bits);
  SCP_CHECK_EQ(everything.bits(), std::uint16_t{0xFFFF});
  for (const ActionScope scope : kScopes) {
    SCP_CHECK(everything.contains(scope));
  }
  // The full set renders every name exactly once, in definition order.
  std::string expected;
  for (const std::string_view name : kScopeNames) {
    if (!expected.empty()) {
      expected += ',';
    }
    expected += std::string(name);
  }
  SCP_CHECK_EQ(everything.to_string(), expected);
  SCP_CHECK_EQ(kScopes.size(), scp::kActionScopeCount);
}

SCP_TEST(grant_validation_rejects_invalid_grants) {
  const DelegationGrant good = valid_grant(1);
  expect_status_code(good.validate(), StatusCode::Ok, "the baseline grant validates");

  DelegationGrant broken = good;
  broken.id = GrantId{};
  expect_status_code(broken.validate(), StatusCode::InvalidIdentifier, "a grant with no identity");

  broken = good;
  broken.site = SiteId{};
  expect_status_code(broken.validate(), StatusCode::InvalidIdentifier, "a grant with no site");

  broken = good;
  broken.grantor = Name();
  expect_status_code(broken.validate(), StatusCode::InvalidArgument, "a grant with no grantor");

  broken = good;
  broken.subject = Name();
  expect_status_code(broken.validate(), StatusCode::InvalidArgument, "a grant with no subject");

  broken = good;
  broken.scopes = ScopeSet{};
  expect_status_code(broken.validate(), StatusCode::InvalidArgument, "a grant with no scopes");

  broken = good;
  broken.issued_at = Timestamp{};
  expect_status_code(broken.validate(), StatusCode::InvalidArgument, "a grant with no issue time");

  broken = good;
  broken.not_before = SiteGeneration(5);
  broken.not_after = SiteGeneration(3);
  expect_status_code(broken.validate(), StatusCode::OutOfRange, "an inverted generation fence");

  broken = good;
  broken.expires_at = Timestamp{scp_test::base_instant().nanos - 1};
  expect_status_code(broken.validate(), StatusCode::OutOfRange, "a grant that expires before issue");

  // A fence with equal bounds is legal: it names exactly one generation.
  DelegationGrant exact = good;
  exact.not_before = SiteGeneration(4);
  exact.not_after = SiteGeneration(4);
  expect_status_code(exact.validate(), StatusCode::Ok, "a fence whose bounds are equal");

  // An invalid grant is reported as invalid rather than as some later refusal.
  DelegationGrant invalid_foreign = good;
  invalid_foreign.grantor = Name();
  invalid_foreign.site = SiteId(0x0FF510E000000000ULL, 0x0000000000000009ULL);
  invalid_foreign.revoked = true;
  const AuthorityDecision decision =
      scp::evaluate_grant(invalid_foreign, scp_test::default_site(),
                          ScopeSet::of(ActionScope::ObserveSite), SiteGeneration::first(),
                          scp_test::base_instant());
  expect_outcome(decision, AuthorityOutcome::GrantInvalid, "a grant that fails validation");
  SCP_CHECK_EQ(decision.grant, invalid_foreign.id);
}

SCP_TEST(evaluate_grant_refusals) {
  const SiteId site = scp_test::default_site();
  const ScopeSet required = ScopeSet::of(ActionScope::ObserveSite);
  const Timestamp now = scp_test::base_instant();
  const SiteGeneration generation = SiteGeneration::first();

  const DelegationGrant good = valid_grant(1);
  const AuthorityDecision granted = scp::evaluate_grant(good, site, required, generation, now);
  expect_outcome(granted, AuthorityOutcome::Granted, "a valid covering grant");
  SCP_CHECK(granted.granted());
  SCP_CHECK_EQ(granted.grant, good.id);
  SCP_CHECK(granted.detail.find("facility-policy-engine") != std::string::npos);

  DelegationGrant other_site = good;
  other_site.site = SiteId(0x0FF510E000000000ULL, 0x0000000000000009ULL);
  const AuthorityDecision mismatch =
      scp::evaluate_grant(other_site, site, required, generation, now);
  expect_outcome(mismatch, AuthorityOutcome::SiteMismatch, "a grant for a different site");

  DelegationGrant revoked = good;
  revoked.revoked = true;
  expect_outcome(scp::evaluate_grant(revoked, site, required, generation, now),
                 AuthorityOutcome::GrantRevoked, "a revoked grant");

  DelegationGrant expired = good;
  expired.expires_at = now;
  expect_outcome(scp::evaluate_grant(expired, site, required, generation, now),
                 AuthorityOutcome::GrantExpired, "a grant evaluated at its expiry instant");

  DelegationGrant unexpired = good;
  unexpired.expires_at = Timestamp{now.nanos + 1};
  expect_outcome(scp::evaluate_grant(unexpired, site, required, generation, now),
                 AuthorityOutcome::Granted, "a grant one nanosecond before its expiry");

  DelegationGrant not_yet = good;
  not_yet.not_before = SiteGeneration(generation.value() + 1U);
  expect_outcome(scp::evaluate_grant(not_yet, site, required, generation, now),
                 AuthorityOutcome::GrantNotYetValid, "a grant below its lower bound");

  DelegationGrant at_lower = good;
  at_lower.not_before = generation;
  expect_outcome(scp::evaluate_grant(at_lower, site, required, generation, now),
                 AuthorityOutcome::Granted, "a grant evaluated exactly at its lower bound");

  DelegationGrant fenced = good;
  fenced.not_after = generation;
  expect_outcome(scp::evaluate_grant(fenced, site, required, generation, now),
                 AuthorityOutcome::GenerationFenced, "a grant evaluated at its upper fence");

  DelegationGrant below_fence = good;
  below_fence.not_after = SiteGeneration(generation.value() + 1U);
  expect_outcome(scp::evaluate_grant(below_fence, site, required, generation, now),
                 AuthorityOutcome::Granted, "a grant evaluated one generation below its fence");

  DelegationGrant narrow = good;
  narrow.scopes = ScopeSet::of(ActionScope::RetireSite);
  const ScopeSet wider = ScopeSet::of(ActionScope::ObserveSite).with(ActionScope::ManagePolicy);
  expect_outcome(scp::evaluate_grant(narrow, site, wider, generation, now),
                 AuthorityOutcome::ScopeNotGranted, "a grant missing a required scope");

  // Every outcome renders as a stable slug and only Granted is a grant.
  constexpr std::array<AuthorityOutcome, 9> kOutcomes = {
      AuthorityOutcome::Granted,       AuthorityOutcome::NoGrantFound,
      AuthorityOutcome::ScopeNotGranted, AuthorityOutcome::SiteMismatch,
      AuthorityOutcome::GrantExpired,  AuthorityOutcome::GrantRevoked,
      AuthorityOutcome::GrantNotYetValid, AuthorityOutcome::GenerationFenced,
      AuthorityOutcome::GrantInvalid};
  for (const AuthorityOutcome outcome : kOutcomes) {
    SCP_CHECK(!scp::to_string(outcome).empty());
    SCP_CHECK_EQ(scp::is_granted(outcome), outcome == AuthorityOutcome::Granted);
  }
}

SCP_TEST(decision_is_independent_of_grant_order) {
  const SiteId site = scp_test::default_site();
  const ScopeSet required = ScopeSet::of(ActionScope::ObserveSite);
  const Timestamp now = scp_test::base_instant();
  const SiteGeneration generation = SiteGeneration(2);

  const std::vector<DelegationGrant> ordered = mixed_grants();
  const AuthorityDecision baseline =
      scp::evaluate_authority(ordered, site, required, generation, now);
  expect_outcome(baseline, AuthorityOutcome::Granted, "the mixed grant set grants the scope");
  SCP_CHECK_EQ(baseline.grant, GrantId(0x6A00000000000000ULL, 10));

  // The same grants recorded in any order give the identical decision.
  std::uint64_t state = 0xA17E0A17ULL;
  for (int attempt = 0; attempt < 12; ++attempt) {
    std::vector<DelegationGrant> shuffled = ordered;
    permute(shuffled, state);
    permute(shuffled, state);
    const AuthorityDecision decision =
        scp::evaluate_authority(shuffled, site, required, generation, now);
    if (!same_decision(decision, baseline)) {
      ::scp_test::Context::instance().note("attempt " + std::to_string(attempt) +
                                           " produced a different decision: " +
                                           std::string(scp::to_string(decision.outcome)) + " " +
                                           decision.grant.to_hex() + " " + decision.detail);
    }
    SCP_CHECK(same_decision(decision, baseline));
  }

  // Reversing the record order is the same permutation family.
  std::vector<DelegationGrant> reversed(ordered.rbegin(), ordered.rend());
  SCP_CHECK(same_decision(scp::evaluate_authority(reversed, site, required, generation, now),
                          baseline));

  // With no grant covering the requirement the reported refusal is still the
  // first applicable one in grant-id order, not an artefact of arrival order:
  // grant 10 is refused for its scopes, so it is the refusal that is reported
  // even though a later grant would fail for a different reason.
  const ScopeSet ungruntable = ScopeSet::of(ActionScope::RetireSite).with(ActionScope::ManagePolicy);
  const AuthorityDecision refusal =
      scp::evaluate_authority(ordered, site, ungruntable, generation, now);
  expect_outcome(refusal, AuthorityOutcome::ScopeNotGranted, "the first applicable refusal");
  SCP_CHECK_EQ(refusal.grant, GrantId(0x6A00000000000000ULL, 10));
  for (int attempt = 0; attempt < 6; ++attempt) {
    std::vector<DelegationGrant> shuffled = ordered;
    permute(shuffled, state);
    SCP_CHECK(same_decision(scp::evaluate_authority(shuffled, site, ungruntable, generation, now),
                            refusal));
  }
}

SCP_TEST(narrowest_sufficient_grant_is_selected_first) {
  const SiteId site = scp_test::default_site();
  const ScopeSet required = ScopeSet::of(ActionScope::ObserveSite);
  const Timestamp now = scp_test::base_instant();
  const SiteGeneration generation = SiteGeneration::first();

  DelegationGrant narrow = valid_grant(1);
  DelegationGrant broad = valid_grant(2);
  broad.scopes = ScopeSet::of(ActionScope::ObserveSite)
                     .with(ActionScope::AcceptObligation)
                     .with(ActionScope::ManagePolicy);

  const std::array<DelegationGrant, 2> narrow_first = {narrow, broad};
  const std::array<DelegationGrant, 2> broad_first = {broad, narrow};
  const AuthorityDecision first =
      scp::evaluate_authority(narrow_first, site, required, generation, now);
  const AuthorityDecision second =
      scp::evaluate_authority(broad_first, site, required, generation, now);
  expect_outcome(first, AuthorityOutcome::Granted, "a broad and a narrow grant");
  expect_outcome(second, AuthorityOutcome::Granted, "the same grants in the other order");
  SCP_CHECK_EQ(first.grant, narrow.id);
  SCP_CHECK_EQ(second.grant, narrow.id);

  // Selection is by grant-id order among the grants that cover the requirement,
  // so with the broad grant holding the lower identity it is the one reported.
  // Nothing here depends on insertion order.
  DelegationGrant narrow_late = valid_grant(9);
  DelegationGrant broad_early = valid_grant(3);
  broad_early.scopes = ScopeSet::of(ActionScope::ObserveSite)
                           .with(ActionScope::AcceptObligation)
                           .with(ActionScope::ManagePolicy);
  const std::array<DelegationGrant, 2> one = {narrow_late, broad_early};
  const std::array<DelegationGrant, 2> two = {broad_early, narrow_late};
  const AuthorityDecision lower_id_first =
      scp::evaluate_authority(one, site, required, generation, now);
  const AuthorityDecision lower_id_second =
      scp::evaluate_authority(two, site, required, generation, now);
  expect_outcome(lower_id_first, AuthorityOutcome::Granted, "covering grants with ids swapped");
  expect_outcome(lower_id_second, AuthorityOutcome::Granted, "the swapped grants reordered");
  SCP_CHECK_EQ(lower_id_first.grant, broad_early.id);
  SCP_CHECK_EQ(lower_id_second.grant, broad_early.id);
  SCP_CHECK_EQ(lower_id_first.grant, lower_id_second.grant);

  // All three grants together still report the lowest covering identity, which
  // here is the narrow grant, whatever order they are recorded in.
  const std::array<DelegationGrant, 3> all = {narrow_late, narrow, broad_early};
  const std::array<DelegationGrant, 3> all_reordered = {broad_early, narrow_late, narrow};
  SCP_CHECK_EQ(scp::evaluate_authority(all, site, required, generation, now).grant, narrow.id);
  SCP_CHECK_EQ(scp::evaluate_authority(all_reordered, site, required, generation, now).grant,
               narrow.id);
}

SCP_TEST(superset_scope_is_accepted_and_subset_refused) {
  const SiteId site = scp_test::default_site();
  const Timestamp now = scp_test::base_instant();
  const SiteGeneration generation = SiteGeneration::first();

  DelegationGrant superset = valid_grant(1);
  superset.scopes = ScopeSet::of(ActionScope::ObserveSite)
                        .with(ActionScope::AcceptObligation)
                        .with(ActionScope::ManagePolicy);
  const ScopeSet required = ScopeSet::of(ActionScope::ObserveSite)
                                .with(ActionScope::AcceptObligation);
  expect_outcome(scp::evaluate_grant(superset, site, required, generation, now),
                 AuthorityOutcome::Granted, "a grant covering a superset");

  DelegationGrant subset = valid_grant(2);
  subset.scopes = ScopeSet::of(ActionScope::ObserveSite);
  const ScopeSet broader = required.with(ActionScope::ManagePolicy);
  expect_outcome(scp::evaluate_grant(subset, site, broader, generation, now),
                 AuthorityOutcome::ScopeNotGranted, "a grant covering a subset");

  // An empty requirement needs no scope, so any valid grant satisfies it.
  expect_outcome(scp::evaluate_grant(subset, site, ScopeSet{}, generation, now),
                 AuthorityOutcome::Granted, "an empty requirement");

  // A grant that covers the requirement for the wrong generation is refused
  // even though its scopes are sufficient.
  DelegationGrant fenced = superset;
  fenced.not_after = generation;
  expect_outcome(scp::evaluate_grant(fenced, site, required, generation, now),
                 AuthorityOutcome::GenerationFenced, "a sufficient but fenced grant");
}

SCP_TEST(no_grant_and_foreign_site_do_not_mask_a_valid_grant) {
  const SiteId site = scp_test::default_site();
  const ScopeSet required = ScopeSet::of(ActionScope::ObserveSite);
  const Timestamp now = scp_test::base_instant();
  const SiteGeneration generation = SiteGeneration::first();

  const std::vector<DelegationGrant> none;
  const AuthorityDecision empty = scp::evaluate_authority(none, site, required, generation, now);
  expect_outcome(empty, AuthorityOutcome::NoGrantFound, "no grants at all");
  SCP_CHECK(empty.grant.is_nil());
  SCP_CHECK(!empty.granted());

  DelegationGrant foreign = valid_grant(1);
  foreign.site = SiteId(0x0FF510E000000000ULL, 0x0000000000000009ULL);
  const std::array<DelegationGrant, 1> only_foreign = {foreign};
  expect_outcome(scp::evaluate_authority(only_foreign, site, required, generation, now),
                 AuthorityOutcome::NoGrantFound, "only a grant for a different site");

  DelegationGrant valid = valid_grant(2);
  const std::array<DelegationGrant, 2> foreign_first = {foreign, valid};
  const std::array<DelegationGrant, 2> valid_first = {valid, foreign};
  const AuthorityDecision one =
      scp::evaluate_authority(foreign_first, site, required, generation, now);
  const AuthorityDecision two =
      scp::evaluate_authority(valid_first, site, required, generation, now);
  expect_outcome(one, AuthorityOutcome::Granted, "a foreign grant recorded before a valid one");
  expect_outcome(two, AuthorityOutcome::Granted, "a foreign grant recorded after a valid one");
  SCP_CHECK_EQ(one.grant, valid.id);
  SCP_CHECK_EQ(two.grant, valid.id);

  // A revoked grant does not mask a valid one either.
  DelegationGrant revoked = valid_grant(3);
  revoked.revoked = true;
  const std::array<DelegationGrant, 3> mixed = {foreign, revoked, valid};
  SCP_CHECK_EQ(scp::evaluate_authority(mixed, site, required, generation, now).grant, valid.id);

  // With only refusals the reported outcome is the first in grant-id order.
  const std::array<DelegationGrant, 2> refusals = {revoked, foreign};
  expect_outcome(scp::evaluate_authority(refusals, site, required, generation, now),
                 AuthorityOutcome::GrantRevoked, "only a revoked grant for this site");
}

SCP_TEST_MAIN("authority")
