// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <limits>

#include "scp/status.hpp"

/// \file checked.hpp
/// Checked arithmetic for capacities, counts, costs, durations and sequence
/// numbers. Every one of these can be supplied by an untrusted peer, so a
/// silently wrapped result is a correctness defect, not a performance choice.

namespace scp {

[[nodiscard]] Result<std::uint64_t> checked_add(std::uint64_t lhs, std::uint64_t rhs);
[[nodiscard]] Result<std::uint64_t> checked_sub(std::uint64_t lhs, std::uint64_t rhs);
[[nodiscard]] Result<std::uint64_t> checked_mul(std::uint64_t lhs, std::uint64_t rhs);

[[nodiscard]] Result<std::int64_t> checked_add(std::int64_t lhs, std::int64_t rhs);
[[nodiscard]] Result<std::int64_t> checked_sub(std::int64_t lhs, std::int64_t rhs);

[[nodiscard]] Result<std::uint64_t> checked_increment(std::uint64_t value);

/// Saturating conversion of an unsigned size to `std::uint32_t`.
[[nodiscard]] Result<std::uint32_t> checked_u32(std::uint64_t value);

/// Converts a signed count to unsigned, rejecting negatives.
[[nodiscard]] Result<std::uint64_t> checked_nonnegative(std::int64_t value);

/// Adds two durations expressed in nanoseconds.
[[nodiscard]] Result<std::int64_t> checked_nanos_add(std::int64_t lhs, std::int64_t rhs);

}  // namespace scp
