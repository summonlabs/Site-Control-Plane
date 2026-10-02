// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/digest.hpp"
#include "scp/ids.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"

/// \file authority.hpp
/// Delegated scope validation.
///
/// This plane may only act inside a scope that another boundary explicitly
/// delegated to it, for a specific site, at a specific generation, until a
/// specific instant. Nothing here infers a scope from the fact that integration
/// exists: a missing grant is a refusal, not a default.

namespace scp {

enum class ActionScope : std::uint16_t {
  None = 0,
  ObserveSite = 1U << 0,
  AcceptObligation = 1U << 1,
  ReleaseObligation = 1U << 2,
  RequestAcceleratorEffect = 1U << 3,
  RequestFabricEffect = 1U << 4,
  RequestPowerEffect = 1U << 5,
  RequestCoolingEffect = 1U << 6,
  EnterMaintenance = 1U << 7,
  ControlledDrain = 1U << 8,
  EmergencyOperation = 1U << 9,
  RecoveryOperation = 1U << 10,
  ReturnToService = 1U << 11,
  IsolateSite = 1U << 12,
  RetireSite = 1U << 13,
  RecordAuthority = 1U << 14,
  ManagePolicy = 1U << 15,
};

inline constexpr std::size_t kActionScopeCount = 16;

[[nodiscard]] std::string_view to_string(ActionScope scope) noexcept;
[[nodiscard]] Result<ActionScope> action_scope_from_string(std::string_view text);

/// A set of delegated scopes. Operations on sets are checked; an empty set is a
/// legal value meaning "granted nothing".
class ScopeSet {
 public:
  constexpr ScopeSet() noexcept = default;
  explicit constexpr ScopeSet(std::uint16_t bits) noexcept : bits_(bits) {}

  [[nodiscard]] static ScopeSet of(ActionScope scope) noexcept {
    return ScopeSet(static_cast<std::uint16_t>(scope));
  }

  [[nodiscard]] constexpr std::uint16_t bits() const noexcept { return bits_; }
  [[nodiscard]] constexpr bool empty() const noexcept { return bits_ == 0; }
  [[nodiscard]] constexpr bool contains(ActionScope scope) const noexcept {
    return (bits_ & static_cast<std::uint16_t>(scope)) == static_cast<std::uint16_t>(scope);
  }
  [[nodiscard]] constexpr bool contains_all(const ScopeSet& other) const noexcept {
    return (bits_ & other.bits_) == other.bits_;
  }

  [[nodiscard]] constexpr ScopeSet with(ActionScope scope) const noexcept {
    return ScopeSet(static_cast<std::uint16_t>(bits_ | static_cast<std::uint16_t>(scope)));
  }
  [[nodiscard]] constexpr ScopeSet without(ActionScope scope) const noexcept {
    return ScopeSet(static_cast<std::uint16_t>(bits_ & ~static_cast<std::uint16_t>(scope)));
  }
  [[nodiscard]] constexpr ScopeSet intersect(const ScopeSet& other) const noexcept {
    return ScopeSet(static_cast<std::uint16_t>(bits_ & other.bits_));
  }

  /// Stable, sorted, comma-separated scope names; empty string for no scopes.
  [[nodiscard]] std::string to_string() const;

  friend constexpr bool operator==(const ScopeSet&, const ScopeSet&) noexcept = default;

 private:
  std::uint16_t bits_ = 0;
};

/// A scope delegation issued by an authority that owns the scope.
struct DelegationGrant {
  GrantId id{};
  SiteId site{};
  /// Boundary that issued the delegation.
  Name grantor{};
  /// Principal the delegation was issued to.
  Name subject{};
  ScopeSet scopes{};
  /// Lower bound: the grant is not valid below this site generation.
  SiteGeneration not_before{};
  /// Upper fence: the grant is invalid at or above this generation. Unset means
  /// no upper fence.
  SiteGeneration not_after{};
  Timestamp issued_at{};
  /// Unset means no expiry.
  Timestamp expires_at{};
  bool revoked = false;
  /// Digest of the evidence that carries the grant, so a decision can cite it.
  Digest evidence_digest{};

  [[nodiscard]] Status validate() const;
  [[nodiscard]] std::vector<std::uint8_t> canonical_bytes() const;
  friend bool operator==(const DelegationGrant&, const DelegationGrant&) noexcept = default;
};

enum class AuthorityOutcome : std::uint8_t {
  Granted = 1,
  NoGrantFound = 2,
  ScopeNotGranted = 3,
  SiteMismatch = 4,
  GrantExpired = 5,
  GrantRevoked = 6,
  GrantNotYetValid = 7,
  GenerationFenced = 8,
  GrantInvalid = 9,
};

[[nodiscard]] std::string_view to_string(AuthorityOutcome outcome) noexcept;
[[nodiscard]] bool is_granted(AuthorityOutcome outcome) noexcept;

struct AuthorityDecision {
  AuthorityOutcome outcome = AuthorityOutcome::NoGrantFound;
  GrantId grant{};
  std::string detail;

  [[nodiscard]] bool granted() const noexcept { return is_granted(outcome); }
};

/// Chooses a grant that covers \p required for \p site at \p generation and
/// \p now.
///
/// Selection is deterministic and independent of arrival order: grants are
/// considered strictly in ascending grant-id order, and the first grant that
/// grants the requirement is reported. Grant identity is therefore the tie
/// breaker, not the breadth of the scope set — two grants that both cover the
/// requirement resolve to the one with the lower identity, whatever order they
/// were recorded in and whichever is narrower.
///
/// When no grant covers the requirement, the refusal reported is the one from
/// the first applicable grant in that same order, so a caller sees a specific
/// reason rather than a bare refusal.
[[nodiscard]] AuthorityDecision evaluate_authority(std::span<const DelegationGrant> grants,
                                                   SiteId site, ScopeSet required,
                                                   SiteGeneration generation, Timestamp now);

/// Evaluates one specific grant. Used by tests and by \c scpctl.
[[nodiscard]] AuthorityDecision evaluate_grant(const DelegationGrant& grant, SiteId site,
                                               ScopeSet required, SiteGeneration generation,
                                               Timestamp now);

void canonical_write(CanonicalWriter& writer, const DelegationGrant& value);
void canonical_write(CanonicalWriter& writer, const AuthorityDecision& value);
[[nodiscard]] Result<DelegationGrant> canonical_read_grant(CanonicalReader& reader);
[[nodiscard]] Result<AuthorityDecision> canonical_read_authority_decision(CanonicalReader& reader);

}  // namespace scp
