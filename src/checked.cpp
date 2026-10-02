// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/checked.hpp"

#include <cstdint>
#include <limits>

namespace scp {
namespace {

/// The high 64 bits of the 128-bit product of two unsigned 64-bit values.
///
/// Multiplying the four 32-bit halves keeps every intermediate inside 64 bits,
/// so this needs neither a 128-bit integer type nor a compiler intrinsic, and
/// every toolchain computes the same answer. The compiler-specific overflow
/// builtins are not portable — MSVC does not have them — and a second
/// implementation per compiler would be a second implementation to get wrong.
[[nodiscard]] std::uint64_t multiply_high(std::uint64_t lhs, std::uint64_t rhs) noexcept {
  constexpr std::uint64_t kHalfMask = 0xFFFFFFFFULL;

  const std::uint64_t lhs_low = lhs & kHalfMask;
  const std::uint64_t lhs_high = lhs >> 32U;
  const std::uint64_t rhs_low = rhs & kHalfMask;
  const std::uint64_t rhs_high = rhs >> 32U;

  const std::uint64_t low_product = lhs_low * rhs_low;
  const std::uint64_t low_by_high = lhs_low * rhs_high;
  const std::uint64_t high_by_low = lhs_high * rhs_low;

  // The carries out of the low half are summed before shifting up; shifting
  // them separately would count the middle column twice.
  const std::uint64_t middle =
      (low_product >> 32U) + (low_by_high & kHalfMask) + (high_by_low & kHalfMask);

  return lhs_high * rhs_high + (low_by_high >> 32U) + (high_by_low >> 32U) + (middle >> 32U);
}

}  // namespace

// ---------------------------------------------------------------------------
// Unsigned
// ---------------------------------------------------------------------------

Result<std::uint64_t> checked_add(std::uint64_t lhs, std::uint64_t rhs) {
  const std::uint64_t sum = lhs + rhs;
  if (sum < lhs) {
    return fail(StatusCode::Overflow, "uint64 addition overflowed");
  }
  return sum;
}

Result<std::uint64_t> checked_sub(std::uint64_t lhs, std::uint64_t rhs) {
  if (lhs < rhs) {
    return fail(StatusCode::Underflow, "uint64 subtraction underflowed");
  }
  return lhs - rhs;
}

Result<std::uint64_t> checked_mul(std::uint64_t lhs, std::uint64_t rhs) {
  if (multiply_high(lhs, rhs) != 0U) {
    return fail(StatusCode::Overflow, "uint64 multiplication overflowed");
  }
  return lhs * rhs;
}

// ---------------------------------------------------------------------------
// Signed
// ---------------------------------------------------------------------------
//
// The arithmetic below is performed in unsigned types, which wrap by
// definition, so no signed intermediate is ever formed out of range and the
// result does not depend on the compiler's optimiser. Converting the wrapped
// value back to a signed type is modular in C++20, so the round trip is exact.
//
// Addition overflows exactly when both operands share a sign that the result
// does not. Subtraction overflows exactly when the operands disagree in sign
// and the result disagrees with the left operand.

Result<std::int64_t> checked_add(std::int64_t lhs, std::int64_t rhs) {
  const std::uint64_t wrapped =
      static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs);
  const std::int64_t sum = static_cast<std::int64_t>(wrapped);
  if (((lhs ^ sum) & (rhs ^ sum)) < 0) {
    return fail(StatusCode::Overflow, "int64 addition overflowed");
  }
  return sum;
}

Result<std::int64_t> checked_sub(std::int64_t lhs, std::int64_t rhs) {
  const std::uint64_t wrapped =
      static_cast<std::uint64_t>(lhs) - static_cast<std::uint64_t>(rhs);
  const std::int64_t difference = static_cast<std::int64_t>(wrapped);
  if (((lhs ^ rhs) & (lhs ^ difference)) < 0) {
    return fail(StatusCode::Overflow, "int64 subtraction overflowed");
  }
  return difference;
}

Result<std::int64_t> checked_nanos_add(std::int64_t lhs, std::int64_t rhs) {
  const std::uint64_t wrapped =
      static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs);
  const std::int64_t sum = static_cast<std::int64_t>(wrapped);
  if (((lhs ^ sum) & (rhs ^ sum)) < 0) {
    return fail(StatusCode::Overflow, "nanosecond addition overflowed");
  }
  return sum;
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

Result<std::uint64_t> checked_increment(std::uint64_t value) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    return fail(StatusCode::Overflow, "uint64 increment overflowed");
  }
  return value + 1U;
}

Result<std::uint32_t> checked_u32(std::uint64_t value) {
  if (value > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
    return fail(StatusCode::OutOfRange, "value does not fit in a uint32");
  }
  return static_cast<std::uint32_t>(value);
}

Result<std::uint64_t> checked_nonnegative(std::int64_t value) {
  if (value < 0) {
    return fail(StatusCode::Underflow, "value is negative and has no unsigned representation");
  }
  return static_cast<std::uint64_t>(value);
}

}  // namespace scp
