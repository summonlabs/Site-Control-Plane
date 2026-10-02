// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "scp/authority.hpp"
#include "scp/canonical.hpp"
#include "scp/digest.hpp"
#include "scp/ids.hpp"
#include "scp/policy.hpp"
#include "scp/readiness.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"

/// \file plan.hpp
/// The effect-request planner.
///
/// A plan is a *proposal made of typed requests addressed to the runtimes that
/// own the effects*. The planner never mutates ASI, DFI, power, cooling,
/// maintenance, policy or incident state, and it has no API through which it
/// could: it returns values. Executing a request is the receiving boundary's
/// decision, under its own authority, on its own state.
///
/// Every emitted request carries the site generation it was computed against, the
/// delegated scope it consumes, the preconditions the receiver must re-check, and
/// an idempotency key, because a retry of the same intent must not become a second
/// effect.

namespace scp {

/// What the site plane is being asked to arrange.
enum class PlanIntent : std::uint8_t {
  AcceptObligation = 1,
  ReleaseObligation = 2,
  EnterMaintenance = 3,
  ControlledDrain = 4,
  EmergencyOperation = 5,
  BeginRecovery = 6,
  ReturnToService = 7,
  IsolateSite = 8,
  RetireSite = 9,
  ResumeNormalOperation = 10,
};

inline constexpr std::size_t kPlanIntentCount = 10;

[[nodiscard]] std::string_view to_string(PlanIntent intent) noexcept;
[[nodiscard]] Result<PlanIntent> plan_intent_from_string(std::string_view text);

/// The scope an intent consumes.
[[nodiscard]] ScopeSet scope_for_intent(PlanIntent intent) noexcept;
/// The gate an intent must pass.
[[nodiscard]] GateKind gate_for_intent(PlanIntent intent) noexcept;

enum class PreconditionKind : std::uint8_t {
  SiteGenerationAtLeast = 1,
  SiteStateIs = 2,
  LifecycleIs = 3,
  GateWasOpen = 4,
  EvidenceDigestMatches = 5,
  ScopeStillGranted = 6,
  MinimumHeadroomPercent = 7,
  SiteNotRetired = 8,
  ReceiverOwnsEffect = 9,
};

[[nodiscard]] std::string_view to_string(PreconditionKind kind) noexcept;

/// A requirement the *receiving* runtime must re-check before acting. It is
/// deliberately redundant with the local decision: the site plane's snapshot may
/// be older than the receiver's state, so the receiver validates again.
struct Precondition {
  PreconditionKind kind = PreconditionKind::SiteGenerationAtLeast;
  std::string subject;
  std::string expectation;

  friend bool operator==(const Precondition&, const Precondition&) noexcept = default;
};

/// One typed request addressed to a lower-domain runtime.
struct EffectRequest {
  RequestId id{};
  IdempotencyKey idempotency{};
  /// The boundary that owns the effect. Never this boundary.
  SourceAuthority target = SourceAuthority::FacilityStateLedger;
  Name action{};
  SiteId site{};
  /// Site generation this request was planned against.
  SiteGeneration site_generation{};
  /// Delegated scope the request consumes.
  ScopeSet required_scope{};
  std::vector<Precondition> preconditions;
  /// Canonical, target-specific arguments. Opaque to this plane.
  std::vector<std::uint8_t> arguments;
  Timestamp created_at{};
  /// Unset means the caller sets no deadline.
  Timestamp deadline{};
  /// Plan that produced this request.
  PlanId plan{};
  /// Digest of the site snapshot the request was planned from.
  Digest site_snapshot_digest{};

  [[nodiscard]] std::vector<std::uint8_t> canonical_bytes() const;
  [[nodiscard]] Status validate() const;

  friend bool operator==(const EffectRequest&, const EffectRequest&) noexcept = default;
};

struct PlannedStep {
  std::uint32_t ordinal = 0;
  Name description{};
  EffectRequest request{};
};

/// Locally evaluated condition that contributed to the decision. Unlike a
/// precondition this one is already decided and is retained as evidence.
struct PlanCondition {
  Name name{};
  bool satisfied = false;
  std::string observed;
  std::string required;
};

struct ActionPlan {
  PlanId id{};
  SiteId site{};
  SiteGeneration site_generation{};
  PlanIntent intent = PlanIntent::AcceptObligation;
  Timestamp created_at{};
  /// True only when authority and gating both passed and at least one request
  /// was produced. A denied plan carries no steps.
  bool permitted = false;
  std::string denial_reason;
  AuthorityDecision authority{};
  ReadinessGate gate{};
  SiteState state = SiteState::Unknown;
  std::vector<PlanCondition> conditions;
  std::vector<PlannedStep> steps;
  Digest site_snapshot_digest{};
  Digest evidence_digest{};
  Digest plan_digest{};

  [[nodiscard]] std::vector<std::uint8_t> canonical_bytes() const;
  [[nodiscard]] Status validate() const;
  [[nodiscard]] std::size_t request_count() const noexcept { return steps.size(); }
};

/// Recomputes the digest a plan should carry. The plan's own digest field is
/// excluded from the computation, so a consumer can verify a plan it did not
/// produce rather than having to trust the field.
[[nodiscard]] Digest compute_plan_digest(const ActionPlan& plan);

/// Everything the planner needs. The snapshot must have been composed against
/// \c policy; a mismatch is detectable because the plan records both digests.
struct PlanRequest {
  PlanIntent intent = PlanIntent::AcceptObligation;
  SiteId site{};
  SiteGeneration site_generation{};
  Timestamp now{};
  Name principal{};
  /// Service class for obligation intents. Ignored otherwise.
  Name service_class{};
  /// Overrides the scope derived from the intent. Used when a caller wants to
  /// consume a narrower or additional scope; it can never widen what a grant
  /// actually permits, because the validator still decides.
  ScopeSet scope_override{};
  bool use_scope_override = false;
  /// Bound on produced steps. Exceeding it fails rather than truncating.
  std::size_t max_steps = 32;
  /// Deterministic seed for request and plan identity derivation.
  std::uint64_t identity_seed = 1;
};

/// Plans an intent against a composed snapshot. Pure; performs no I/O.
[[nodiscard]] Result<ActionPlan> plan_intent(const PlanRequest& request,
                                             const SiteStateSnapshot& snapshot,
                                             const SitePolicy& policy,
                                             std::span<const DelegationGrant> grants);

void canonical_write(CanonicalWriter& writer, const Precondition& value);
void canonical_write(CanonicalWriter& writer, const EffectRequest& value);
void canonical_write(CanonicalWriter& writer, const PlanCondition& value);
void canonical_write(CanonicalWriter& writer, const PlannedStep& value);
void canonical_write(CanonicalWriter& writer, const ActionPlan& value);

[[nodiscard]] Result<Precondition> canonical_read_precondition(CanonicalReader& reader);
[[nodiscard]] Result<EffectRequest> canonical_read_request(CanonicalReader& reader);
[[nodiscard]] Result<PlanCondition> canonical_read_plan_condition(CanonicalReader& reader);
[[nodiscard]] Result<PlannedStep> canonical_read_step(CanonicalReader& reader);
[[nodiscard]] Result<ActionPlan> canonical_read_plan(CanonicalReader& reader);

}  // namespace scp
