// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>

#include "scp/checked.hpp"
#include "scp/status.hpp"

/// \file time.hpp
/// Explicit time and clock injection.
///
/// The composition engine is a pure function of its inputs, including the
/// evaluation instant. It never reads a clock: freshness is decided from the
/// instant the caller supplies, so the same evidence and the same instant give
/// the same snapshot on every host and in every process.

namespace scp {

/// Nanoseconds since the Unix epoch, UTC. Zero is the sentinel "unset".
struct Timestamp {
  std::int64_t nanos = 0;

  [[nodiscard]] constexpr bool is_set() const noexcept { return nanos != 0; }
  [[nodiscard]] std::string to_iso8601() const;

  friend constexpr bool operator==(const Timestamp&, const Timestamp&) noexcept = default;
  friend constexpr bool operator<(const Timestamp& lhs, const Timestamp& rhs) noexcept {
    return lhs.nanos < rhs.nanos;
  }
  friend constexpr bool operator<=(const Timestamp& lhs, const Timestamp& rhs) noexcept {
    return lhs.nanos <= rhs.nanos;
  }
  friend constexpr bool operator>(const Timestamp& lhs, const Timestamp& rhs) noexcept {
    return lhs.nanos > rhs.nanos;
  }
  friend constexpr bool operator>=(const Timestamp& lhs, const Timestamp& rhs) noexcept {
    return lhs.nanos >= rhs.nanos;
  }
};

/// A signed span of nanoseconds.
struct Duration {
  std::int64_t nanos = 0;

  friend constexpr bool operator==(const Duration&, const Duration&) noexcept = default;
  friend constexpr bool operator<(const Duration& lhs, const Duration& rhs) noexcept {
    return lhs.nanos < rhs.nanos;
  }
};

inline constexpr std::int64_t kNanosPerSecond = 1000000000LL;
inline constexpr std::int64_t kNanosPerMillisecond = 1000000LL;

[[nodiscard]] constexpr Duration seconds(std::int64_t count) noexcept {
  return Duration{count * kNanosPerSecond};
}
[[nodiscard]] constexpr Duration milliseconds(std::int64_t count) noexcept {
  return Duration{count * kNanosPerMillisecond};
}

/// True, or OutOfRange/Overflow when the sum leaves the representable range.
[[nodiscard]] Result<Timestamp> timestamp_add(Timestamp base, Duration delta);
[[nodiscard]] Result<Timestamp> timestamp_sub(Timestamp base, Duration delta);
[[nodiscard]] Result<Duration> duration_between(Timestamp earlier, Timestamp later);

/// Source of wall-clock time. Injected so tests and reproductions are exact.
class Clock {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;
  virtual ~Clock() = default;

  [[nodiscard]] virtual Timestamp now() const = 0;
};

/// Reads the system clock. This is the only place the runtime touches real time.
class SystemClock final : public Clock {
 public:
  [[nodiscard]] Timestamp now() const override;
};

/// Caller-driven clock. Ticks exactly when told to.
class ManualClock final : public Clock {
 public:
  ManualClock() = default;
  explicit ManualClock(Timestamp start) noexcept : current_(start) {}

  [[nodiscard]] Timestamp now() const override { return current_; }
  void set(Timestamp value) noexcept { current_ = value; }
  Status advance(Duration delta);

 private:
  Timestamp current_{};
};

}  // namespace scp
