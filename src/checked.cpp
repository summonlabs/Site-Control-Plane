// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/checked.hpp"

#include <cstdint>
#include <limits>

namespace scp {

Result<std::uint64_t> checked_add(std::uint64_t lhs, std::uint64_t rhs) {
  std::uint64_t sum = 0;
  if (__builtin_add_overflow(lhs, rhs, &sum)) {
    return fail(StatusCode::Overflow, "uint64 addition overflowed");
  }
  return sum;
}

Result<std::uint64_t> checked_sub(std::uint64_t lhs, std::uint64_t rhs) {
  std::uint64_t difference = 0;
  if (__builtin_sub_overflow(lhs, rhs, &difference)) {
    return fail(StatusCode::Underflow, "uint64 subtraction underflowed");
  }
  return difference;
}

Result<std::uint64_t> checked_mul(std::uint64_t lhs, std::uint64_t rhs) {
  std::uint64_t product = 0;
  if (__builtin_mul_overflow(lhs, rhs, &product)) {
    return fail(StatusCode::Overflow, "uint64 multiplication overflowed");
  }
  return product;
}

Result<std::int64_t> checked_add(std::int64_t lhs, std::int64_t rhs) {
  std::int64_t sum = 0;
  if (__builtin_add_overflow(lhs, rhs, &sum)) {
    return fail(StatusCode::Overflow, "int64 addition overflowed");
  }
  return sum;
}

Result<std::int64_t> checked_sub(std::int64_t lhs, std::int64_t rhs) {
  std::int64_t difference = 0;
  if (__builtin_sub_overflow(lhs, rhs, &difference)) {
    return fail(StatusCode::Overflow, "int64 subtraction overflowed");
  }
  return difference;
}

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

Result<std::int64_t> checked_nanos_add(std::int64_t lhs, std::int64_t rhs) {
  std::int64_t sum = 0;
  if (__builtin_add_overflow(lhs, rhs, &sum)) {
    return fail(StatusCode::Overflow, "nanosecond addition overflowed");
  }
  return sum;
}

}  // namespace scp
