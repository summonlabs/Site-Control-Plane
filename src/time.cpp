// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/time.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace scp {

namespace {

/// Floor division for a positive divisor; C++ integer division truncates toward
/// zero, which would put the sub-day remainder in the wrong day for instants
/// before the epoch.
[[nodiscard]] constexpr std::int64_t floor_div(std::int64_t value, std::int64_t divisor) noexcept {
  const std::int64_t quotient = value / divisor;
  const std::int64_t remainder = value % divisor;
  return remainder < 0 ? quotient - 1 : quotient;
}

/// Days since 1970-01-01 to proleptic Gregorian year/month/day (civil-from-days,
/// as published by Howard Hinnant). Pure integer arithmetic, no locale and no
/// C library, so the result is identical on every host and thread.
constexpr void civil_from_days(std::int64_t days, std::int64_t& year, std::uint32_t& month,
                               std::uint32_t& day) noexcept {
  const std::int64_t shifted = days + 719468;
  const std::int64_t era = (shifted >= 0 ? shifted : shifted - 146096) / 146097;
  const std::uint32_t day_of_era = static_cast<std::uint32_t>(shifted - era * 146097);
  const std::uint32_t year_of_era =
      (day_of_era - day_of_era / 1460U + day_of_era / 36524U - day_of_era / 146096U) / 365U;
  const std::int64_t year_base = static_cast<std::int64_t>(year_of_era) + era * 400;
  const std::uint32_t day_of_year =
      day_of_era - (365U * year_of_era + year_of_era / 4U - year_of_era / 100U);
  const std::uint32_t month_prime = (5U * day_of_year + 2U) / 153U;
  day = day_of_year - (153U * month_prime + 2U) / 5U + 1U;
  month = month_prime < 10U ? month_prime + 3U : month_prime - 9U;
  year = year_base + (month <= 2U ? 1 : 0);
}

/// Appends value in decimal, left-padded with zeros to at least width digits.
void append_padded(std::string& out, std::uint64_t value, std::size_t width) {
  const std::size_t start = out.size();
  do {
    const char digit = static_cast<char>('0' + static_cast<int>(value % 10U));
    out.push_back(digit);
    value /= 10U;
  } while (value != 0U);
  while (out.size() - start < width) {
    out.push_back('0');
  }
  std::reverse(out.begin() + static_cast<std::ptrdiff_t>(start), out.end());
}

}  // namespace

std::string Timestamp::to_iso8601() const {
  std::int64_t seconds = nanos / kNanosPerSecond;
  std::int64_t subsecond = nanos % kNanosPerSecond;
  if (subsecond < 0) {
    subsecond += kNanosPerSecond;
    seconds -= 1;
  }

  const std::int64_t days = floor_div(seconds, 86400);
  const std::int64_t second_of_day = seconds - days * 86400;

  std::int64_t year = 1970;
  std::uint32_t month = 1;
  std::uint32_t day = 1;
  civil_from_days(days, year, month, day);

  const std::uint64_t hour = static_cast<std::uint64_t>(second_of_day / 3600);
  const std::uint64_t minute = static_cast<std::uint64_t>((second_of_day / 60) % 60);
  const std::uint64_t second = static_cast<std::uint64_t>(second_of_day % 60);

  std::string out;
  out.reserve(32U);
  if (year < 0) {
    out.push_back('-');
    append_padded(out, static_cast<std::uint64_t>(-year), 4U);
  } else {
    append_padded(out, static_cast<std::uint64_t>(year), 4U);
  }
  out.push_back('-');
  append_padded(out, static_cast<std::uint64_t>(month), 2U);
  out.push_back('-');
  append_padded(out, static_cast<std::uint64_t>(day), 2U);
  out.push_back('T');
  append_padded(out, hour, 2U);
  out.push_back(':');
  append_padded(out, minute, 2U);
  out.push_back(':');
  append_padded(out, second, 2U);
  out.push_back('.');
  append_padded(out, static_cast<std::uint64_t>(subsecond / 1000000), 3U);
  append_padded(out, static_cast<std::uint64_t>((subsecond / 1000) % 1000), 3U);
  append_padded(out, static_cast<std::uint64_t>(subsecond % 1000), 3U);
  out.push_back('Z');
  return out;
}

Result<Timestamp> timestamp_add(Timestamp base, Duration delta) {
  const Result<std::int64_t> sum = checked_add(base.nanos, delta.nanos);
  if (!sum.has_value()) {
    return fail(sum.status().code(), "timestamp arithmetic left the representable range");
  }
  return Timestamp{sum.value()};
}

Result<Timestamp> timestamp_sub(Timestamp base, Duration delta) {
  if (delta.nanos == std::numeric_limits<std::int64_t>::min()) {
    return fail(StatusCode::Overflow,
                "timestamp subtraction cannot negate the smallest representable duration");
  }
  return timestamp_add(base, Duration{-delta.nanos});
}

Result<Duration> duration_between(Timestamp earlier, Timestamp later) {
  const Result<std::int64_t> span = checked_sub(later.nanos, earlier.nanos);
  if (!span.has_value()) {
    return fail(span.status().code(), "duration between two timestamps left the representable range");
  }
  return Duration{span.value()};
}

Timestamp SystemClock::now() const {
  const std::chrono::system_clock::time_point instant = std::chrono::system_clock::now();
  const std::chrono::nanoseconds since_epoch =
      std::chrono::duration_cast<std::chrono::nanoseconds>(instant.time_since_epoch());
  return Timestamp{static_cast<std::int64_t>(since_epoch.count())};
}

Status ManualClock::advance(Duration delta) {
  const Result<Timestamp> advanced = timestamp_add(current_, delta);
  if (!advanced.has_value()) {
    return advanced.status();
  }
  current_ = advanced.value();
  return Status();
}

}  // namespace scp
