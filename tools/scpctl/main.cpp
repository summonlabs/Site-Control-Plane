// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

/// \file main.cpp
/// scpctl: the operator-facing inspection, composition, planning and recovery
/// tool for one site.
///
/// The tool owns no state of its own. Every value it prints is read back from
/// the library, every text it prints is escaped for a terminal, and nothing is
/// estimated: a quantity the library could not produce is reported as absent
/// rather than as zero.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "scp/authority.hpp"
#include "scp/checked.hpp"
#include "scp/composition.hpp"
#include "scp/digest.hpp"
#include "scp/evidence.hpp"
#include "scp/explain.hpp"
#include "scp/ids.hpp"
#include "scp/journal.hpp"
#include "scp/plan.hpp"
#include "scp/policy.hpp"
#include "scp/readiness.hpp"
#include "scp/runtime.hpp"
#include "scp/site_state.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"
#include "scp/version.hpp"

namespace {

// ---------------------------------------------------------------------------
// Exit codes and failure reporting
// ---------------------------------------------------------------------------

constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;
constexpr int kExitState = 3;

/// The only way a command reports failure: an exit code plus the text printed to
/// stderr as "scpctl: <message>".
class CliExit {
 public:
  CliExit(int code, std::string message) : code_(code), message_(std::move(message)) {}

  [[nodiscard]] int code() const noexcept { return code_; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }

 private:
  int code_;
  std::string message_;
};

[[noreturn]] void fail(int code, std::string message) { throw CliExit(code, std::move(message)); }

/// A library failure. Damaged durable state is a state failure, not a generic
/// runtime failure, so it gets its own code.
[[noreturn]] void fail_status(const scp::Status& status) {
  fail(scp::is_integrity_failure(status.code()) ? kExitState : kExitFailure, status.to_string());
}

[[noreturn]] void usage_error(std::string message) { fail(kExitUsage, std::move(message)); }

template <class T>
[[nodiscard]] T must_call(scp::Result<T>&& result) {
  if (!result.has_value()) {
    fail_status(result.status());
  }
  return std::move(result).value();
}

template <class T>
[[nodiscard]] T must_parse(scp::Result<T>&& result) {
  if (!result.has_value()) {
    usage_error(result.status().to_string());
  }
  return std::move(result).value();
}

void must_ok(const scp::Status& status) {
  if (!status.ok()) {
    fail_status(status);
  }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

void print_line(std::string_view text) { std::cout << text << '\n'; }

std::string display(std::string_view text) { return scp::escape_for_display(text); }

template <class Tag>
[[nodiscard]] std::string id_text(const scp::OpaqueId<Tag>& id) {
  return id.is_nil() ? std::string("none") : id.to_hex();
}

[[nodiscard]] std::string timestamp_text(const scp::Timestamp& value) {
  return value.is_set() ? value.to_iso8601() : std::string("none");
}

[[nodiscard]] std::string boolean_text(bool value) { return value ? "true" : "false"; }

[[nodiscard]] std::string optional_text(const std::string& value) {
  return value.empty() ? std::string("none") : display(value);
}

/// Emits one JSON object with two-space indentation, no trailing commas and
/// strings escaped per RFC 8259.
class JsonWriter {
 public:
  explicit JsonWriter(std::ostream& out) : out_(out) {}

  void begin_object() { open('{'); }
  void end_object() { close('}'); }
  void begin_array() { open('['); }
  void end_array() { close(']'); }

  void key(std::string_view name) {
    separate();
    write_string(name);
    out_ << ": ";
    after_key_ = true;
  }

  void string(std::string_view value) {
    separate();
    write_string(value);
  }

  void number(std::uint64_t value) {
    separate();
    out_ << value;
  }

  void number(std::int64_t value) {
    separate();
    out_ << value;
  }

  void boolean(bool value) {
    separate();
    out_ << (value ? "true" : "false");
  }

 private:
  void separate() {
    if (after_key_) {
      after_key_ = false;
      return;
    }
    if (!kinds_.empty()) {
      if (!first_.back()) {
        out_ << ',';
      }
      first_.back() = false;
    }
    if (!kinds_.empty()) {
      out_ << '\n';
      for (std::size_t depth = 0; depth < kinds_.size(); ++depth) {
        out_ << "  ";
      }
    }
  }

  void open(char kind) {
    separate();
    out_ << kind;
    kinds_.push_back(kind);
    first_.push_back(true);
  }

  void close(char kind) {
    const bool empty = first_.back();
    kinds_.pop_back();
    first_.pop_back();
    if (!empty) {
      out_ << '\n';
      for (std::size_t depth = 0; depth < kinds_.size(); ++depth) {
        out_ << "  ";
      }
    }
    out_ << kind;
  }

  void write_string(std::string_view value) {
    static constexpr char kHexDigits[] = "0123456789ABCDEF";
    const bool utf8 = scp::is_valid_utf8(value);
    out_ << '"';
    for (const char raw : value) {
      const std::uint8_t byte = static_cast<std::uint8_t>(raw);
      if (byte == static_cast<std::uint8_t>('"')) {
        out_ << "\\\"";
        continue;
      }
      if (byte == static_cast<std::uint8_t>('\\')) {
        out_ << "\\\\";
        continue;
      }
      if (byte < 0x20U || byte == 0x7FU || (byte >= 0x80U && !utf8)) {
        out_ << "\\u00" << kHexDigits[(byte >> 4U) & 0x0FU] << kHexDigits[byte & 0x0FU];
        continue;
      }
      out_ << raw;
    }
    out_ << '"';
  }

  std::ostream& out_;
  std::vector<char> kinds_;
  std::vector<bool> first_;
  bool after_key_ = false;
};

// ---------------------------------------------------------------------------
// Value parsing
// ---------------------------------------------------------------------------

[[nodiscard]] bool all_digits(std::string_view text) noexcept {
  if (text.empty()) {
    return false;
  }
  for (const char ch : text) {
    if (ch < '0' || ch > '9') {
      return false;
    }
  }
  return true;
}

[[nodiscard]] std::vector<std::string_view> split_ws(std::string_view text) {
  std::vector<std::string_view> fields;
  std::size_t index = 0;
  while (index < text.size()) {
    while (index < text.size() && (text[index] == ' ' || text[index] == '\t')) {
      ++index;
    }
    const std::size_t start = index;
    while (index < text.size() && text[index] != ' ' && text[index] != '\t') {
      ++index;
    }
    if (index > start) {
      fields.push_back(text.substr(start, index - start));
    }
  }
  return fields;
}

/// Builds the InvalidArgument status a malformed field reports, naming the field
/// and quoting the offending text.
[[nodiscard]] scp::Status field_failure(std::string_view field, std::string_view text,
                                        std::string_view detail) {
  return scp::fail(scp::StatusCode::InvalidArgument,
                   std::string(field) + ": " + std::string(detail) + " in '" + display(text) + "'");
}

[[nodiscard]] scp::Result<std::int64_t> parse_i64_text(std::string_view text) {
  bool negative = false;
  std::string_view digits = text;
  if (!digits.empty() && digits.front() == '-') {
    negative = true;
    digits.remove_prefix(1U);
  }
  if (!all_digits(digits)) {
    return scp::fail(scp::StatusCode::InvalidArgument, "expected a decimal integer");
  }
  constexpr std::uint64_t kInt64Max = 9223372036854775807ULL;
  std::uint64_t magnitude = 0;
  for (const char ch : digits) {
    const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
    const scp::Result<std::uint64_t> scaled = scp::checked_mul(magnitude, 10U);
    if (!scaled.has_value()) {
      return scaled.status();
    }
    const scp::Result<std::uint64_t> added = scp::checked_add(scaled.value(), digit);
    if (!added.has_value()) {
      return added.status();
    }
    magnitude = added.value();
  }
  if (negative) {
    if (magnitude > kInt64Max + 1ULL) {
      return scp::fail(scp::StatusCode::OutOfRange, "value is below the representable range");
    }
    if (magnitude == kInt64Max + 1ULL) {
      return std::numeric_limits<std::int64_t>::min();
    }
    return -static_cast<std::int64_t>(magnitude);
  }
  if (magnitude > kInt64Max) {
    return scp::fail(scp::StatusCode::OutOfRange, "value is above the representable range");
  }
  return static_cast<std::int64_t>(magnitude);
}

[[nodiscard]] std::uint64_t parse_u64_field(std::string_view field, std::string_view text) {
  const scp::Result<std::uint64_t> value = scp::parse_u64(text);
  if (!value.has_value()) {
    usage_error(field_failure(field, text, value.status().message()).to_string());
  }
  return value.value();
}

[[nodiscard]] std::uint32_t parse_u32_field(std::string_view field, std::string_view text) {
  const std::uint64_t value = parse_u64_field(field, text);
  if (value > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
    usage_error(field_failure(field, text, "does not fit in 32 bits").to_string());
  }
  return static_cast<std::uint32_t>(value);
}

[[nodiscard]] std::uint32_t parse_percent_field(std::string_view field, std::string_view text) {
  const std::uint64_t value = parse_u64_field(field, text);
  if (value > 100U) {
    usage_error(field_failure(field, text, "must be a whole percent in 0..100").to_string());
  }
  return static_cast<std::uint32_t>(value);
}

[[nodiscard]] bool parse_bool_field(std::string_view field, std::string_view text) {
  if (text == "true") {
    return true;
  }
  if (text == "false") {
    return false;
  }
  usage_error(field_failure(field, text, "must be true or false").to_string());
}

template <class Id>
[[nodiscard]] Id parse_id_field(std::string_view field, std::string_view text) {
  const scp::Result<Id> parsed = Id::parse(text);
  if (!parsed.has_value()) {
    usage_error(field_failure(field, text, parsed.status().message()).to_string());
  }
  return parsed.value();
}

[[nodiscard]] scp::Digest parse_digest_field(std::string_view field, std::string_view text) {
  std::string_view digits = text;
  if (digits.size() >= 2U && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
    digits.remove_prefix(2U);
  }
  const scp::Result<scp::Digest> parsed = scp::Digest::parse_hex(digits);
  if (!parsed.has_value()) {
    usage_error(field_failure(field, text, parsed.status().message()).to_string());
  }
  return parsed.value();
}

[[nodiscard]] std::int64_t days_from_civil(std::int64_t year, std::uint32_t month,
                                           std::uint32_t day) noexcept {
  const std::int64_t adjusted_year = year - (month <= 2U ? 1 : 0);
  const std::int64_t era = (adjusted_year >= 0 ? adjusted_year : adjusted_year - 399) / 400;
  const std::uint32_t year_of_era =
      static_cast<std::uint32_t>(adjusted_year - era * 400);
  const int month_index = static_cast<int>(month);
  const int shifted_month = month_index > 2 ? month_index - 3 : month_index + 9;
  const std::uint32_t day_of_year =
      static_cast<std::uint32_t>((153 * shifted_month + 2) / 5) + day - 1U;
  const std::uint32_t day_of_era =
      year_of_era * 365U + year_of_era / 4U - year_of_era / 100U + day_of_year;
  return era * 146097 + static_cast<std::int64_t>(day_of_era) - 719468;
}

[[nodiscard]] std::uint32_t days_in_month(std::int64_t year, std::uint32_t month) noexcept {
  constexpr std::uint32_t kMonthDays[12] = {31U, 28U, 31U, 30U, 31U, 30U,
                                            31U, 31U, 30U, 31U, 30U, 31U};
  if (month == 2U) {
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    return leap ? 29U : 28U;
  }
  return kMonthDays[month - 1U];
}

/// Raw nanoseconds, or an ISO-8601 UTC instant. Integer arithmetic only; no
/// <ctime>, no locale and no tolerance for anything that is not exact.
[[nodiscard]] scp::Result<scp::Timestamp> parse_timestamp_text(std::string_view field,
                                                               std::string_view text) {
  if (text.empty()) {
    return field_failure(field, text, "empty timestamp");
  }
  if (all_digits(text) || (text.front() == '-' && all_digits(text.substr(1U)))) {
    const scp::Result<std::int64_t> nanos = parse_i64_text(text);
    if (!nanos.has_value()) {
      return field_failure(field, text, nanos.status().message());
    }
    return scp::Timestamp{nanos.value()};
  }

  // YYYY-MM-DD
  if (text.size() < 19U) {
    return field_failure(field, text,
                         "expected nanoseconds since the epoch or YYYY-MM-DDTHH:MM:SS[.fraction]Z");
  }
  if (text[4] != '-' || text[7] != '-') {
    return field_failure(field, text, "date must be YYYY-MM-DD");
  }
  if (!all_digits(text.substr(0U, 4U)) || !all_digits(text.substr(5U, 2U)) ||
      !all_digits(text.substr(8U, 2U))) {
    return field_failure(field, text, "date must be YYYY-MM-DD");
  }
  const std::int64_t year = static_cast<std::int64_t>(parse_u64_field(field, text.substr(0U, 4U)));
  const std::uint32_t month = parse_u32_field(field, text.substr(5U, 2U));
  const std::uint32_t day = parse_u32_field(field, text.substr(8U, 2U));
  if (month < 1U || month > 12U) {
    return field_failure(field, text, "month is out of range");
  }
  if (day < 1U || day > days_in_month(year, month)) {
    return field_failure(field, text, "day is out of range for the month");
  }
  if (text[10] != 'T' && text[10] != ' ') {
    return field_failure(field, text, "date and time must be separated by T or a space");
  }
  if (text[13] != ':' || text[16] != ':') {
    return field_failure(field, text, "time must be HH:MM:SS");
  }
  if (!all_digits(text.substr(11U, 2U)) || !all_digits(text.substr(14U, 2U)) ||
      !all_digits(text.substr(17U, 2U))) {
    return field_failure(field, text, "time must be HH:MM:SS");
  }
  const std::uint32_t hour = parse_u32_field(field, text.substr(11U, 2U));
  const std::uint32_t minute = parse_u32_field(field, text.substr(14U, 2U));
  const std::uint32_t second = parse_u32_field(field, text.substr(17U, 2U));
  if (hour > 23U || minute > 59U || second > 59U) {
    return field_failure(field, text, "time is out of range");
  }

  std::size_t index = 19U;
  std::uint32_t fraction = 0;
  if (index < text.size() && text[index] == '.') {
    ++index;
    const std::size_t start = index;
    while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
      ++index;
    }
    const std::size_t digits = index - start;
    if (digits == 0U) {
      return field_failure(field, text, "fraction has no digits");
    }
    if (digits > 9U) {
      return field_failure(field, text,
                           "fraction is finer than a nanosecond and cannot be represented exactly");
    }
    std::uint32_t scaled = 0;
    for (std::size_t position = 0; position < 9U; ++position) {
      const std::uint32_t digit =
          position < digits ? static_cast<std::uint32_t>(text[start + position] - '0') : 0U;
      scaled = scaled * 10U + digit;
    }
    fraction = scaled;
  }
  if (index < text.size() && (text[index] == 'Z' || text[index] == 'z')) {
    ++index;
  }
  if (index != text.size()) {
    return field_failure(field, text, "trailing characters after the instant");
  }

  const std::int64_t days = days_from_civil(year, month, day);
  const std::int64_t seconds_of_day =
      static_cast<std::int64_t>(hour) * 3600 + static_cast<std::int64_t>(minute) * 60 +
      static_cast<std::int64_t>(second);
  const std::int64_t seconds = days * 86400 + seconds_of_day;
  const std::uint64_t magnitude =
      static_cast<std::uint64_t>(seconds < 0 ? -seconds : seconds);
  const scp::Result<std::uint64_t> scaled = scp::checked_mul(magnitude, 1000000000ULL);
  if (!scaled.has_value()) {
    return field_failure(field, text, "instant is outside the representable range");
  }
  const scp::Result<std::uint64_t> total =
      scp::checked_add(scaled.value(), static_cast<std::uint64_t>(fraction));
  if (!total.has_value()) {
    return field_failure(field, text, "instant is outside the representable range");
  }
  constexpr std::uint64_t kInt64Max = 9223372036854775807ULL;
  if (total.value() > kInt64Max) {
    return field_failure(field, text, "instant is outside the representable range");
  }
  const std::int64_t nanos =
      seconds < 0 ? -static_cast<std::int64_t>(total.value()) : static_cast<std::int64_t>(total.value());
  return scp::Timestamp{nanos};
}

[[nodiscard]] scp::Timestamp parse_timestamp_field(std::string_view field, std::string_view text) {
  const scp::Result<scp::Timestamp> parsed = parse_timestamp_text(field, text);
  if (!parsed.has_value()) {
    usage_error(parsed.status().to_string());
  }
  return parsed.value();
}

/// <n>s, <n>m, <n>h or raw nanoseconds.
[[nodiscard]] scp::Duration parse_duration_field(std::string_view field, std::string_view text) {
  if (text.empty()) {
    usage_error(field_failure(field, text, "empty duration").to_string());
  }
  std::string_view digits = text;
  std::uint64_t multiplier = 1ULL;
  const char suffix = text.back();
  if (suffix == 's' || suffix == 'm' || suffix == 'h') {
    digits = text.substr(0U, text.size() - 1U);
    multiplier = suffix == 's' ? 1000000000ULL : (suffix == 'm' ? 60000000000ULL : 3600000000000ULL);
  }
  bool negative = false;
  if (!digits.empty() && digits.front() == '-') {
    negative = true;
    digits.remove_prefix(1U);
  }
  if (!all_digits(digits)) {
    usage_error(field_failure(field, text, "expected <n>s, <n>m, <n>h or nanoseconds").to_string());
  }
  const std::uint64_t magnitude = parse_u64_field(field, digits);
  const scp::Result<std::uint64_t> scaled = scp::checked_mul(magnitude, multiplier);
  if (!scaled.has_value()) {
    usage_error(field_failure(field, text, "duration is outside the representable range").to_string());
  }
  constexpr std::uint64_t kInt64Max = 9223372036854775807ULL;
  if (scaled.value() > kInt64Max) {
    usage_error(field_failure(field, text, "duration is outside the representable range").to_string());
  }
  const std::int64_t nanos =
      negative ? -static_cast<std::int64_t>(scaled.value()) : static_cast<std::int64_t>(scaled.value());
  return scp::Duration{nanos};
}

// ---------------------------------------------------------------------------
// Vocabulary reverse lookups
// ---------------------------------------------------------------------------

[[nodiscard]] scp::Severity severity_from_slug(std::string_view text) {
  for (std::uint8_t raw = 0; raw <= 4U; ++raw) {
    const scp::Severity candidate = static_cast<scp::Severity>(raw);
    if (scp::to_string(candidate) == text) {
      return candidate;
    }
  }
  usage_error("unrecognised severity '" + display(text) +
              "'; expected none, informational, minor, major or critical");
}

[[nodiscard]] scp::ReadinessLevel readiness_from_slug(std::string_view text) {
  for (std::uint8_t raw = 0; raw <= 4U; ++raw) {
    const scp::ReadinessLevel candidate = static_cast<scp::ReadinessLevel>(raw);
    if (scp::to_string(candidate) == text) {
      return candidate;
    }
  }
  usage_error("unrecognised readiness level '" + display(text) +
              "'; expected unknown, unavailable, degraded, constrained or ready");
}

[[nodiscard]] scp::MaintenanceMode maintenance_from_slug(std::string_view text) {
  for (std::uint8_t raw = 0; raw <= 3U; ++raw) {
    const scp::MaintenanceMode candidate = static_cast<scp::MaintenanceMode>(raw);
    if (scp::to_string(candidate) == text) {
      return candidate;
    }
  }
  usage_error("unrecognised maintenance mode '" + display(text) +
              "'; expected none, planned, emergency or overdue");
}

[[nodiscard]] scp::Comparison comparison_from_slug(std::string_view text) {
  for (std::uint8_t raw = 1; raw <= 4U; ++raw) {
    const scp::Comparison candidate = static_cast<scp::Comparison>(raw);
    if (scp::to_string(candidate) == text) {
      return candidate;
    }
  }
  usage_error("unrecognised comparison '" + display(text) +
              "'; expected at-least, at-most, equal or not-equal");
}

[[nodiscard]] scp::ConstraintKind constraint_kind_from_slug(std::string_view text) {
  for (std::uint8_t raw = 1; raw <= static_cast<std::uint8_t>(scp::kConstraintKindCount); ++raw) {
    const scp::ConstraintKind candidate = static_cast<scp::ConstraintKind>(raw);
    if (scp::to_string(candidate) == text) {
      return candidate;
    }
  }
  usage_error("unrecognised constraint kind '" + display(text) + "'");
}

[[nodiscard]] scp::ActionScope scope_from_slug(std::string_view text) {
  const scp::Result<scp::ActionScope> parsed = scp::action_scope_from_string(text);
  if (!parsed.has_value()) {
    usage_error(parsed.status().to_string());
  }
  return parsed.value();
}

// ---------------------------------------------------------------------------
// Command-line options
// ---------------------------------------------------------------------------

struct Options {
  std::set<std::string> seen;
  std::vector<std::pair<std::string, std::string>> policy_pairs;

  std::string directory;
  std::string evidence;
  std::string site;
  std::string at;
  std::string policy_file;
  std::string intent;
  std::string principal;
  std::string service_class;
  std::string scopes;
  std::string scope_override;
  std::string deadline;
  std::string grantor;
  std::string subject;
  std::string not_before;
  std::string not_after;
  std::string expires_at;
  bool revoked = false;
  bool json = false;
  bool no_advance_generation = false;

  [[nodiscard]] bool has(std::string_view name) const {
    return seen.find(std::string(name)) != seen.end();
  }

  [[nodiscard]] std::string require(std::string_view command, std::string_view name) const {
    const auto found = values.find(std::string(name));
    if (found == values.end()) {
      usage_error(std::string(command) + " requires --" + std::string(name));
    }
    return found->second;
  }

  void require_only(std::string_view command,
                    const std::vector<std::string_view>& allowed) const {
    for (const std::string& name : seen) {
      const bool permitted =
          std::any_of(allowed.begin(), allowed.end(), [&name](std::string_view candidate) {
            return candidate == std::string_view(name);
          });
      if (!permitted) {
        usage_error(std::string(command) + " does not accept --" + name);
      }
    }
  }

  std::map<std::string, std::string> values;
};

constexpr std::string_view kPolicyKeys[] = {
    "capacity-headroom-constrained-percent",
    "capacity-headroom-degraded-percent",
    "domain-readiness-degraded-percent",
    "domain-readiness-unavailable-percent",
    "required-redundancy-domains",
    "power-headroom-floor-milli-kw",
    "cooling-headroom-floor-milli-kw",
    "maintenance-minimum-readiness-percent",
    "recovery-minimum-drained-percent",
    "return-to-service-minimum-readiness-percent",
    "stale-after",
    "expire-after",
    "rule",
    "rule-with-subject"};

[[nodiscard]] bool is_policy_key(std::string_view name) {
  if (name == "policy") {
    return true;
  }
  return std::any_of(std::begin(kPolicyKeys), std::end(kPolicyKeys),
                     [name](std::string_view candidate) { return candidate == name; });
}

void set_option(Options& options, const std::string& name, const std::string& value) {
  if (options.values.count(name) != 0U && name != "rule" && name != "rule-with-subject") {
    usage_error("--" + name + " is given more than once");
  }
  options.seen.insert(name);
  options.values[name] = value;
  if (is_policy_key(name)) {
    options.policy_pairs.emplace_back(name, value);
  }
  if (name == "dir") {
    options.directory = value;
  } else if (name == "evidence") {
    options.evidence = value;
  } else if (name == "site") {
    options.site = value;
  } else if (name == "at") {
    options.at = value;
  } else if (name == "policy") {
    options.policy_file = value;
  } else if (name == "intent") {
    options.intent = value;
  } else if (name == "principal") {
    options.principal = value;
  } else if (name == "service-class") {
    options.service_class = value;
  } else if (name == "scopes") {
    options.scopes = value;
  } else if (name == "scope") {
    options.scope_override = value;
  } else if (name == "deadline") {
    options.deadline = value;
  } else if (name == "grantor") {
    options.grantor = value;
  } else if (name == "subject") {
    options.subject = value;
  } else if (name == "not-before") {
    options.not_before = value;
  } else if (name == "not-after") {
    options.not_after = value;
  } else if (name == "expires-at") {
    options.expires_at = value;
  }
}

[[nodiscard]] Options parse_options(const std::vector<std::string>& args) {
  Options options;
  for (std::size_t index = 0; index < args.size(); ++index) {
    const std::string& argument = args[index];
    if (argument.size() < 3U || argument[0] != '-' || argument[1] != '-') {
      usage_error("unexpected argument '" + display(argument) + "'");
    }
    const std::string name = argument.substr(2U);
    if (name == "json") {
      options.seen.insert(name);
      options.json = true;
      continue;
    }
    if (name == "revoked") {
      options.seen.insert(name);
      options.revoked = true;
      continue;
    }
    if (name == "no-advance-generation") {
      options.seen.insert(name);
      options.no_advance_generation = true;
      continue;
    }
    if (index + 1U >= args.size()) {
      usage_error("--" + name + " requires a value");
    }
    ++index;
    set_option(options, name, args[index]);
  }
  return options;
}

// ---------------------------------------------------------------------------
// Site policy
// ---------------------------------------------------------------------------

void apply_policy_pair(scp::SitePolicy& policy, const std::string& key, const std::string& value,
                       const std::string& origin) {
  const auto fail_pair = [&key, &value, &origin](const std::string& detail) {
    usage_error(origin + ": " + key + " " + value + ": " + detail);
  };
  if (key == "capacity-headroom-constrained-percent") {
    policy.capacity_headroom_constrained_percent = parse_percent_field(key, value);
  } else if (key == "capacity-headroom-degraded-percent") {
    policy.capacity_headroom_degraded_percent = parse_percent_field(key, value);
  } else if (key == "domain-readiness-degraded-percent") {
    policy.domain_readiness_degraded_percent = parse_percent_field(key, value);
  } else if (key == "domain-readiness-unavailable-percent") {
    policy.domain_readiness_unavailable_percent = parse_percent_field(key, value);
  } else if (key == "required-redundancy-domains") {
    policy.required_redundancy_domains = parse_u32_field(key, value);
  } else if (key == "power-headroom-floor-milli-kw") {
    policy.power_headroom_floor_milli_kw = parse_u64_field(key, value);
  } else if (key == "cooling-headroom-floor-milli-kw") {
    policy.cooling_headroom_floor_milli_kw = parse_u64_field(key, value);
  } else if (key == "maintenance-minimum-readiness-percent") {
    policy.maintenance_minimum_readiness_percent = parse_percent_field(key, value);
  } else if (key == "recovery-minimum-drained-percent") {
    policy.recovery_minimum_drained_percent = parse_percent_field(key, value);
  } else if (key == "return-to-service-minimum-readiness-percent") {
    policy.return_to_service_minimum_readiness_percent = parse_percent_field(key, value);
  } else if (key == "stale-after") {
    policy.freshness.stale_after = parse_duration_field(key, value);
  } else if (key == "expire-after") {
    policy.freshness.expire_after = parse_duration_field(key, value);
  } else if (key == "rule" || key == "rule-with-subject") {
    const std::vector<std::string_view> fields = scp::split_ascii(value, ':');
    const std::size_t minimum = key == "rule" ? 5U : 6U;
    if (fields.size() < minimum || fields.size() > minimum + 1U) {
      fail_pair(key == "rule"
                    ? "expected <id>:<kind>:<comparison>:<threshold>:<severity>[:blocking]"
                    : "expected <id>:<subject>:<kind>:<comparison>:<threshold>:<severity>[:blocking]");
    }
    std::size_t position = 0;
    scp::ThresholdRule rule;
    rule.rule_id = must_parse(scp::Name::parse(fields[position]));
    ++position;
    std::string_view subject = rule.rule_id.view();
    if (key == "rule-with-subject") {
      subject = fields[position];
      if (subject.empty()) {
        fail_pair("the subject must not be empty");
      }
      if (subject.size() > scp::kMaxNameBytes) {
        fail_pair("the subject is longer than the maximum name length");
      }
      ++position;
    }
    if (!scp::is_known_metric(subject)) {
      fail_pair("'" + std::string(subject) +
                "' is not a metric name this build can observe; see the metric list in scpctl help");
    }
    rule.subject.assign(subject);
    rule.kind = constraint_kind_from_slug(fields[position]);
    ++position;
    rule.comparison = comparison_from_slug(fields[position]);
    ++position;
    rule.threshold = parse_u64_field(key, fields[position]);
    ++position;
    rule.severity = severity_from_slug(fields[position]);
    ++position;
    if (position < fields.size()) {
      if (fields[position] != "blocking") {
        fail_pair("the optional trailing field must be 'blocking'");
      }
      rule.blocking = true;
    }
    policy.rules.push_back(rule);
    if (policy.rules.size() > scp::kMaxThresholdRules) {
      fail_pair("more than " + std::to_string(scp::kMaxThresholdRules) + " threshold rules");
    }
  } else {
    usage_error(origin + ": unknown key '" + display(key) + "'");
  }
}

void apply_policy_file(scp::SitePolicy& policy, const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) {
    fail(kExitUsage, scp::fail(scp::StatusCode::IoError,
                               "cannot read policy file '" + path.string() + "'")
                         .to_string());
  }
  std::string line;
  std::size_t number = 0;
  while (std::getline(input, line)) {
    ++number;
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::size_t comment = line.find('#');
    if (comment != std::string::npos) {
      line.erase(comment);
    }
    const std::string_view trimmed = scp::trim_ascii(line);
    if (trimmed.empty()) {
      continue;
    }
    const std::size_t separator = trimmed.find_first_of(" \t");
    if (separator == std::string_view::npos) {
      usage_error("policy file line " + std::to_string(number) + ": '" + display(trimmed) +
                  "' is not a 'key value' pair");
    }
    const std::string key(trimmed.substr(0U, separator));
    const std::string value(scp::trim_ascii(trimmed.substr(separator)));
    if (value.empty()) {
      usage_error("policy file line " + std::to_string(number) + ": key '" + display(key) +
                  "' has no value");
    }
    if (key == "policy") {
      usage_error("policy file line " + std::to_string(number) +
                  ": 'policy' is not accepted inside a policy file");
    }
    apply_policy_pair(policy, key, value, "policy file line " + std::to_string(number));
  }
  if (!input.eof() && input.fail()) {
    fail(kExitUsage, scp::fail(scp::StatusCode::IoError,
                               "cannot read policy file '" + path.string() + "'")
                         .to_string());
  }
}

[[nodiscard]] scp::SitePolicy build_policy(const Options& options) {
  scp::SitePolicy policy;
  for (const std::pair<std::string, std::string>& pair : options.policy_pairs) {
    if (pair.first == "policy") {
      apply_policy_file(policy, std::filesystem::path(pair.second));
    } else {
      apply_policy_pair(policy, pair.first, pair.second, "option --" + pair.first);
    }
  }
  const scp::Status valid = policy.validate();
  if (!valid.ok()) {
    usage_error(valid.to_string());
  }
  return policy;
}

// ---------------------------------------------------------------------------
// Evidence scripts
// ---------------------------------------------------------------------------

struct BlockLine {
  std::size_t number = 0;
  std::string key;
  std::string value;
};

struct Block {
  std::size_t start_line = 0;
  std::vector<BlockLine> lines;
};

[[nodiscard]] std::vector<Block> split_blocks(std::ifstream& input) {
  std::vector<Block> blocks;
  Block current;
  std::string line;
  std::size_t number = 0;
  while (std::getline(input, line)) {
    ++number;
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::size_t comment = line.find('#');
    if (comment != std::string::npos) {
      line.erase(comment);
    }
    const std::string_view trimmed = scp::trim_ascii(line);
    if (trimmed.empty()) {
      if (!current.lines.empty()) {
        blocks.push_back(std::move(current));
        current = Block{};
      }
      continue;
    }
    if (current.lines.empty()) {
      current.start_line = number;
    }
    const std::size_t separator = trimmed.find_first_of(" \t");
    BlockLine entry;
    entry.number = number;
    if (separator == std::string_view::npos) {
      entry.key.assign(trimmed);
    } else {
      entry.key.assign(trimmed.substr(0U, separator));
      entry.value.assign(scp::trim_ascii(trimmed.substr(separator)));
    }
    current.lines.push_back(std::move(entry));
  }
  if (!current.lines.empty()) {
    blocks.push_back(std::move(current));
  }
  return blocks;
}

[[nodiscard]] bool key_is_common(std::string_view key) {
  return key == "authority" || key == "instance" || key == "epoch" || key == "generation" ||
         key == "sequence" || key == "issued-at" || key == "valid-until" || key == "schema";
}

[[nodiscard]] bool key_is_allowed(scp::EvidenceKind kind, std::string_view key) {
  if (key_is_common(key)) {
    return true;
  }
  switch (kind) {
    case scp::EvidenceKind::FacilityState:
      return key == "worst-severity" || key == "active-incidents" || key == "degraded-operation" ||
             key == "emergency-declared" || key == "topology-digest";
    case scp::EvidenceKind::Lifecycle:
      return key == "state" || key == "entered-at" || key == "transition-in-progress" ||
             key == "transition-digest";
    case scp::EvidenceKind::Capacity:
      return key == "snapshot" || key == "total-units" || key == "committed-units" ||
             key == "available-units" || key == "oversubscribed";
    case scp::EvidenceKind::PowerReadiness:
    case scp::EvidenceKind::CoolingReadiness:
      return key == "snapshot" || key == "readiness" || key == "headroom-milli-kw" ||
             key == "available-domains" || key == "required-domains";
    case scp::EvidenceKind::Policy:
      return key == "rules-digest" || key == "rule-count";
    case scp::EvidenceKind::Incident:
      return key == "active-incidents" || key == "worst-severity" || key == "emergency-declared" ||
             key == "earliest-active" || key == "suppressed-incidents";
    case scp::EvidenceKind::Maintenance:
      return key == "mode" || key == "active-windows" || key == "scheduled-windows" ||
             key == "next-window-start" || key == "drain-in-progress" || key == "drained-percent";
    case scp::EvidenceKind::AsiCapability:
    case scp::EvidenceKind::DfiCapability:
      return key == "readiness" || key == "ready-domains" || key == "total-domains" ||
             key == "ready-units" || key == "capability-digest";
    case scp::EvidenceKind::ServiceClass:
      return key == "class-count" || key == "obligations-digest" || key == "obligation";
  }
  return false;
}

[[nodiscard]] const BlockLine* find_line(const Block& block, std::string_view key) {
  for (const BlockLine& line : block.lines) {
    if (line.key == key) {
      return &line;
    }
  }
  return nullptr;
}

[[nodiscard]] std::string block_label(const Block& block, std::string_view kind_slug) {
  return "evidence block at line " + std::to_string(block.start_line) + " (kind " +
         std::string(kind_slug) + ")";
}

[[nodiscard]] std::string require_field(const Block& block, std::string_view key,
                                        std::string_view kind_slug) {
  const BlockLine* line = find_line(block, key);
  if (line == nullptr) {
    usage_error(block_label(block, kind_slug) + " is missing required key '" + std::string(key) + "'");
  }
  if (line->value.empty()) {
    usage_error(block_label(block, kind_slug) + ": key '" + std::string(key) + "' has no value");
  }
  return line->value;
}

[[nodiscard]] scp::EvidenceRecord build_record(const Block& block, scp::EvidenceKind kind) {
  const std::string_view kind_slug = scp::to_string(kind);
  for (const BlockLine& line : block.lines) {
    if (line.key == "kind") {
      continue;
    }
    if (!key_is_allowed(kind, line.key)) {
      usage_error("line " + std::to_string(line.number) + ": unknown key '" + display(line.key) +
                  "' in " + block_label(block, kind_slug));
    }
    if (line.value.empty()) {
      usage_error("line " + std::to_string(line.number) + ": key '" + display(line.key) +
                  "' has no value");
    }
  }

  scp::Provenance provenance;
  const BlockLine* authority = find_line(block, "authority");
  if (authority != nullptr) {
    const scp::Result<scp::SourceAuthority> parsed =
        scp::source_authority_from_string(authority->value);
    if (!parsed.has_value()) {
      usage_error(block_label(block, kind_slug) + ": " + parsed.status().message());
    }
    if (!scp::is_authorized_publisher(parsed.value(), kind)) {
      usage_error(block_label(block, kind_slug) + ": " + std::string(scp::to_string(parsed.value())) +
                  " does not own evidence kind " + std::string(kind_slug));
    }
    provenance.authority = parsed.value();
  } else {
    provenance.authority = scp::owner_of(kind);
  }
  provenance.instance =
      parse_id_field<scp::SourceInstanceId>("instance", require_field(block, "instance", kind_slug));
  const std::uint64_t epoch = parse_u64_field("epoch", require_field(block, "epoch", kind_slug));
  if (epoch == 0U) {
    usage_error(block_label(block, kind_slug) + ": epoch must be at least 1");
  }
  provenance.epoch = scp::Epoch(epoch);
  const std::uint64_t generation =
      parse_u64_field("generation", require_field(block, "generation", kind_slug));
  if (generation == 0U) {
    usage_error(block_label(block, kind_slug) + ": generation must be at least 1");
  }
  provenance.generation = scp::SourceGeneration(generation);
  const std::uint64_t sequence =
      parse_u64_field("sequence", require_field(block, "sequence", kind_slug));
  if (sequence == 0U) {
    usage_error(block_label(block, kind_slug) + ": sequence must be at least 1");
  }
  provenance.sequence = scp::Sequence(sequence);
  provenance.issued_at =
      parse_timestamp_field("issued-at", require_field(block, "issued-at", kind_slug));
  if (const BlockLine* valid_until = find_line(block, "valid-until")) {
    provenance.valid_until = parse_timestamp_field("valid-until", valid_until->value);
  }
  std::uint16_t schema = scp::kEvidenceSchemaVersion;
  if (const BlockLine* schema_line = find_line(block, "schema")) {
    const std::uint64_t declared = parse_u64_field("schema", schema_line->value);
    if (declared > 65535U) {
      usage_error(block_label(block, kind_slug) + ": schema must fit in 16 bits");
    }
    schema = static_cast<std::uint16_t>(declared);
  }

  scp::EvidenceBody body;
  switch (kind) {
    case scp::EvidenceKind::FacilityState: {
      scp::FacilityStateEvidence value;
      value.generation = scp::FacilityStateGeneration(generation);
      value.worst_active_severity =
          severity_from_slug(require_field(block, "worst-severity", kind_slug));
      value.active_incidents =
          parse_u32_field("active-incidents", require_field(block, "active-incidents", kind_slug));
      value.degraded_operation =
          parse_bool_field("degraded-operation",
                           require_field(block, "degraded-operation", kind_slug));
      value.emergency_declared =
          parse_bool_field("emergency-declared",
                           require_field(block, "emergency-declared", kind_slug));
      if (const BlockLine* digest = find_line(block, "topology-digest")) {
        value.topology_digest = parse_digest_field("topology-digest", digest->value);
      }
      body = value;
      break;
    }
    case scp::EvidenceKind::Lifecycle: {
      scp::LifecycleEvidence value;
      const scp::Result<scp::LifecycleState> parsed =
          scp::lifecycle_state_from_string(require_field(block, "state", kind_slug));
      if (!parsed.has_value()) {
        usage_error(block_label(block, kind_slug) + ": " + parsed.status().message());
      }
      value.state = parsed.value();
      if (const BlockLine* entered = find_line(block, "entered-at")) {
        value.entered_at = parse_timestamp_field("entered-at", entered->value);
      }
      value.transition_in_progress =
          parse_bool_field("transition-in-progress",
                           require_field(block, "transition-in-progress", kind_slug));
      if (const BlockLine* digest = find_line(block, "transition-digest")) {
        value.transition_digest = parse_digest_field("transition-digest", digest->value);
      }
      body = value;
      break;
    }
    case scp::EvidenceKind::Capacity: {
      scp::CapacityEvidence value;
      if (const BlockLine* snapshot = find_line(block, "snapshot")) {
        value.snapshot = parse_id_field<scp::SnapshotId>("snapshot", snapshot->value);
      }
      value.generation = scp::CapacityGeneration(generation);
      value.total_units = parse_u64_field("total-units", require_field(block, "total-units", kind_slug));
      value.committed_units =
          parse_u64_field("committed-units", require_field(block, "committed-units", kind_slug));
      value.available_units =
          parse_u64_field("available-units", require_field(block, "available-units", kind_slug));
      value.oversubscribed =
          parse_bool_field("oversubscribed", require_field(block, "oversubscribed", kind_slug));
      body = value;
      break;
    }
    case scp::EvidenceKind::PowerReadiness:
    case scp::EvidenceKind::CoolingReadiness: {
      scp::ReadinessEvidence value;
      if (const BlockLine* snapshot = find_line(block, "snapshot")) {
        value.snapshot = parse_id_field<scp::SnapshotId>("snapshot", snapshot->value);
      }
      value.readiness = readiness_from_slug(require_field(block, "readiness", kind_slug));
      value.headroom_milli_kw =
          parse_u64_field("headroom-milli-kw", require_field(block, "headroom-milli-kw", kind_slug));
      value.available_domains = parse_u32_field(
          "available-domains", require_field(block, "available-domains", kind_slug));
      value.required_domains = parse_u32_field(
          "required-domains", require_field(block, "required-domains", kind_slug));
      body = value;
      break;
    }
    case scp::EvidenceKind::Policy: {
      scp::PolicyEvidence value;
      value.generation = scp::PolicyGeneration(generation);
      if (const BlockLine* digest = find_line(block, "rules-digest")) {
        value.rules_digest = parse_digest_field("rules-digest", digest->value);
      }
      value.rule_count = parse_u32_field("rule-count", require_field(block, "rule-count", kind_slug));
      body = value;
      break;
    }
    case scp::EvidenceKind::Incident: {
      scp::IncidentEvidence value;
      value.active_incidents =
          parse_u32_field("active-incidents", require_field(block, "active-incidents", kind_slug));
      value.worst_active_severity =
          severity_from_slug(require_field(block, "worst-severity", kind_slug));
      value.emergency_declared =
          parse_bool_field("emergency-declared",
                           require_field(block, "emergency-declared", kind_slug));
      if (const BlockLine* earliest = find_line(block, "earliest-active")) {
        value.earliest_active = parse_timestamp_field("earliest-active", earliest->value);
      }
      value.suppressed_incidents = parse_u32_field(
          "suppressed-incidents", require_field(block, "suppressed-incidents", kind_slug));
      body = value;
      break;
    }
    case scp::EvidenceKind::Maintenance: {
      scp::MaintenanceEvidence value;
      value.mode = maintenance_from_slug(require_field(block, "mode", kind_slug));
      value.active_windows =
          parse_u32_field("active-windows", require_field(block, "active-windows", kind_slug));
      value.scheduled_windows = parse_u32_field("scheduled-windows",
                                                require_field(block, "scheduled-windows", kind_slug));
      if (const BlockLine* next = find_line(block, "next-window-start")) {
        value.next_window_start = parse_timestamp_field("next-window-start", next->value);
      }
      value.drain_in_progress = parse_bool_field("drain-in-progress",
                                                 require_field(block, "drain-in-progress", kind_slug));
      value.drained_percent =
          parse_percent_field("drained-percent", require_field(block, "drained-percent", kind_slug));
      body = value;
      break;
    }
    case scp::EvidenceKind::AsiCapability:
    case scp::EvidenceKind::DfiCapability: {
      scp::CapabilityEvidence value;
      value.readiness = readiness_from_slug(require_field(block, "readiness", kind_slug));
      value.ready_domains =
          parse_u32_field("ready-domains", require_field(block, "ready-domains", kind_slug));
      value.total_domains =
          parse_u32_field("total-domains", require_field(block, "total-domains", kind_slug));
      if (value.ready_domains > value.total_domains) {
        usage_error(block_label(block, kind_slug) + ": ready-domains must not exceed total-domains");
      }
      value.ready_units = parse_u64_field("ready-units", require_field(block, "ready-units", kind_slug));
      if (const BlockLine* digest = find_line(block, "capability-digest")) {
        value.capability_digest = parse_digest_field("capability-digest", digest->value);
      }
      body = value;
      break;
    }
    case scp::EvidenceKind::ServiceClass: {
      scp::ServiceClassEvidence value;
      value.class_count = parse_u32_field("class-count", require_field(block, "class-count", kind_slug));
      if (const BlockLine* digest = find_line(block, "obligations-digest")) {
        value.obligations_digest = parse_digest_field("obligations-digest", digest->value);
      }
      std::size_t count = 0;
      for (const BlockLine& line : block.lines) {
        if (line.key != "obligation") {
          continue;
        }
        const std::vector<std::string_view> fields = split_ws(line.value);
        if (fields.size() != 4U) {
          usage_error("line " + std::to_string(line.number) +
                      ": an obligation is '<name> <protected:true|false> <minimum-ready-units> "
                      "<minimum-readiness-percent>'");
        }
        scp::ServiceClassObligation obligation;
        const scp::Result<scp::Name> name = scp::Name::parse(fields[0]);
        if (!name.has_value()) {
          usage_error("line " + std::to_string(line.number) + ": " + name.status().message());
        }
        obligation.service_class = name.value();
        obligation.protected_class = parse_bool_field("protected", fields[1]);
        obligation.minimum_ready_units = parse_u32_field("minimum-ready-units", fields[2]);
        obligation.minimum_readiness_percent = parse_percent_field("minimum-readiness-percent", fields[3]);
        value.obligations.push_back(std::move(obligation));
        ++count;
      }
      if (count == 0U) {
        usage_error(block_label(block, kind_slug) + " declares no obligation");
      }
      if (count > scp::kMaxServiceClasses) {
        usage_error(block_label(block, kind_slug) + " declares more than " +
                    std::to_string(scp::kMaxServiceClasses) + " obligations");
      }
      body = value;
      break;
    }
  }

  const scp::Result<std::vector<std::uint8_t>> encoded = scp::encode_body(body);
  if (!encoded.has_value()) {
    usage_error(block_label(block, kind_slug) + ": " + encoded.status().to_string());
  }
  const scp::Result<scp::EvidenceRecord> record =
      scp::EvidenceRecord::create(provenance, kind, schema, encoded.value());
  if (!record.has_value()) {
    usage_error(block_label(block, kind_slug) + ": " + record.status().to_string());
  }
  return record.value();
}

[[nodiscard]] std::vector<scp::EvidenceRecord> parse_evidence_script(
    const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) {
    fail(kExitUsage, scp::fail(scp::StatusCode::IoError,
                               "cannot read evidence script '" + path.string() + "'")
                         .to_string());
  }
  const std::vector<Block> blocks = split_blocks(input);
  if (!input.eof() && input.fail()) {
    fail(kExitUsage, scp::fail(scp::StatusCode::IoError,
                               "cannot read evidence script '" + path.string() + "'")
                         .to_string());
  }
  std::vector<scp::EvidenceRecord> records;
  records.reserve(blocks.size());
  for (const Block& block : blocks) {
    const BlockLine* kind_line = find_line(block, "kind");
    if (kind_line == nullptr) {
      usage_error("evidence block at line " + std::to_string(block.start_line) +
                  " has no 'kind' key");
    }
    for (const BlockLine& line : block.lines) {
      if (line.key == "kind" && line.number != kind_line->number) {
        usage_error("evidence block at line " + std::to_string(block.start_line) +
                    " declares 'kind' more than once");
      }
    }
    if (kind_line->value.empty()) {
      usage_error("evidence block at line " + std::to_string(block.start_line) +
                  " gives 'kind' no value");
    }
    const scp::Result<scp::EvidenceKind> kind = scp::evidence_kind_from_string(kind_line->value);
    if (!kind.has_value()) {
      usage_error("evidence block at line " + std::to_string(block.start_line) + ": " +
                  kind.status().message());
    }
    records.push_back(build_record(block, kind.value()));
  }
  return records;
}

// ---------------------------------------------------------------------------
// Runtime helpers
// ---------------------------------------------------------------------------

/// The site identity scpctl uses for a durable directory. It is derived from a
/// domain-separated digest rather than assigned, so it is stable across builds,
/// hosts and runs; a journal written by one run opens in the next.
[[nodiscard]] scp::SiteId default_site() {
  constexpr std::string_view kSeed = "scp.scpctl.site.v1";
  scp::Sha256 hasher;
  hasher.update(kSeed);
  const scp::Digest digest = hasher.finalize();
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  const auto& bytes = digest.bytes();
  for (std::size_t index = 0; index < 8U; ++index) {
    high = (high << 8U) | bytes[index];
    low = (low << 8U) | bytes[index + 8U];
  }
  return scp::SiteId(high, low);
}

[[nodiscard]] std::int64_t system_now() { return scp::SystemClock().now().nanos; }

/// Opens the runtime on p directory. When the operator states an evaluation
/// instant the runtime is driven by a manual clock fixed at that instant, so
/// every value the report carries is composed at the instant the operator named
/// rather than at whatever the host clock happened to say.
[[nodiscard]] std::unique_ptr<scp::SiteControlPlane> open_runtime(const std::filesystem::path& directory,
                                                                 const scp::SitePolicy& policy,
                                                                 const scp::Timestamp& instant) {
  scp::RuntimeOptions options;
  options.directory = directory;
  options.site = default_site();
  options.policy = policy;
  options.clock = instant.is_set()
                      ? std::shared_ptr<const scp::Clock>(std::make_shared<scp::ManualClock>(instant))
                      : std::shared_ptr<const scp::Clock>(std::make_shared<scp::SystemClock>());
  return must_call(scp::SiteControlPlane::open(options));
}

[[nodiscard]] scp::Timestamp evaluation_instant(const Options& options) {
  if (options.at.empty()) {
    return scp::Timestamp{};
  }
  return parse_timestamp_field("--at", options.at);
}

[[nodiscard]] std::int64_t required_now(const Options& options) {
  const scp::Timestamp instant = evaluation_instant(options);
  return instant.is_set() ? instant.nanos : system_now();
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

void write_snapshot_members(JsonWriter& json, const scp::SiteStateSnapshot& snapshot) {
  json.key("site");
  json.string(snapshot.site.to_hex());
  json.key("site-generation");
  json.number(snapshot.site_generation.value());
  json.key("evaluation-time");
  json.string(snapshot.evaluation_time.to_iso8601());
  json.key("composed-at");
  json.string(snapshot.composed_at.to_iso8601());
  json.key("state");
  json.string(scp::to_string(snapshot.state));
  json.key("lifecycle");
  json.string(scp::to_string(snapshot.lifecycle));
  json.key("classification");
  json.string(scp::to_string(snapshot.classification));
  json.key("readiness-percent");
  json.number(static_cast<std::uint64_t>(snapshot.readiness_percent));
  json.key("evidence-digest");
  json.string(snapshot.evidence_digest.to_hex());
  json.key("policy-digest");
  json.string(snapshot.policy_digest.to_hex());
  json.key("snapshot-digest");
  json.string(snapshot.snapshot_digest.to_hex());

  json.key("slots");
  json.begin_array();
  for (const scp::SlotResolution& resolution : snapshot.slots) {
    json.begin_object();
    json.key("authority");
    json.string(scp::to_string(resolution.slot.authority));
    json.key("kind");
    json.string(scp::to_string(resolution.slot.kind));
    json.key("outcome");
    json.string(scp::to_string(resolution.outcome));
    json.key("freshness");
    json.string(scp::to_string(resolution.freshness));
    json.key("origin");
    json.string(scp::to_string(resolution.origin));
    json.key("evidence");
    json.string(id_text(resolution.accepted_id));
    json.key("superseded");
    json.number(static_cast<std::uint64_t>(resolution.superseded.size()));
    json.key("conflicting");
    json.number(static_cast<std::uint64_t>(resolution.conflicting.size()));
    json.key("duplicates-merged");
    json.number(static_cast<std::uint64_t>(resolution.duplicates_merged));
    json.key("detail");
    json.string(resolution.detail);
    json.end_object();
  }
  json.end_array();

  json.key("domains");
  json.begin_array();
  for (const scp::DomainReadiness& domain : snapshot.readiness_domains) {
    json.begin_object();
    json.key("domain");
    json.string(domain.domain);
    json.key("percent");
    json.number(static_cast<std::uint64_t>(domain.percent));
    json.key("level");
    json.string(scp::to_string(domain.level));
    json.key("observed");
    json.boolean(domain.observed);
    json.end_object();
  }
  json.end_array();

  json.key("constraints");
  json.begin_array();
  for (const scp::Constraint& constraint : snapshot.constraints) {
    json.begin_object();
    json.key("kind");
    json.string(scp::to_string(constraint.kind));
    json.key("subject");
    json.string(constraint.subject);
    json.key("severity");
    json.string(scp::to_string(constraint.severity));
    json.key("blocking");
    json.boolean(constraint.blocking);
    json.key("detail");
    json.string(constraint.detail);
    json.end_object();
  }
  json.end_array();

  json.key("obligations");
  json.begin_array();
  for (const scp::ObligationAssessment& obligation : snapshot.obligations) {
    json.begin_object();
    json.key("service-class");
    json.string(obligation.service_class.view());
    json.key("protected");
    json.boolean(obligation.protected_class);
    json.key("outcome");
    json.string(scp::to_string(obligation.outcome));
    json.key("ready-units");
    json.number(obligation.ready_units);
    json.key("required-units");
    json.number(obligation.required_units);
    json.key("observed-readiness-percent");
    json.number(static_cast<std::uint64_t>(obligation.observed_readiness_percent));
    json.key("required-readiness-percent");
    json.number(static_cast<std::uint64_t>(obligation.required_readiness_percent));
    json.key("detail");
    json.string(obligation.detail);
    json.end_object();
  }
  json.end_array();

  json.key("gates");
  json.begin_array();
  for (const scp::ReadinessGate& gate : snapshot.gates) {
    json.begin_object();
    json.key("kind");
    json.string(scp::to_string(gate.kind));
    json.key("open");
    json.boolean(gate.open);
    json.key("conditions");
    json.begin_array();
    for (const scp::GateCondition& condition : gate.conditions) {
      json.begin_object();
      json.key("name");
      json.string(condition.name.view());
      json.key("satisfied");
      json.boolean(condition.satisfied);
      json.key("observed");
      json.string(condition.observed);
      json.key("required");
      json.string(condition.required);
      json.key("detail");
      json.string(condition.detail);
      json.end_object();
    }
    json.end_array();
    json.end_object();
  }
  json.end_array();
}

void write_explanation_json(JsonWriter& json, std::string_view command,
                            const scp::ExplainReport& report) {
  json.begin_object();
  json.key("command");
  json.string(command);
  write_snapshot_members(json, report.snapshot);
  json.key("derivations");
  json.begin_array();
  for (const scp::ExplanationStep& step : report.derivations) {
    json.begin_object();
    json.key("code");
    json.string(step.code);
    json.key("detail");
    json.string(step.detail);
    json.end_object();
  }
  json.end_array();
  json.key("blocking-constraints");
  json.begin_array();
  for (const scp::Constraint& constraint : report.blocking_constraints) {
    json.begin_object();
    json.key("kind");
    json.string(scp::to_string(constraint.kind));
    json.key("subject");
    json.string(constraint.subject);
    json.key("severity");
    json.string(scp::to_string(constraint.severity));
    json.key("detail");
    json.string(constraint.detail);
    json.end_object();
  }
  json.end_array();
  json.key("unsatisfied-obligations");
  json.begin_array();
  for (const scp::ObligationAssessment& obligation : report.unsatisfied_obligations) {
    json.begin_object();
    json.key("service-class");
    json.string(obligation.service_class.view());
    json.key("protected");
    json.boolean(obligation.protected_class);
    json.key("detail");
    json.string(obligation.detail);
    json.end_object();
  }
  json.end_array();
  json.key("notes");
  json.begin_array();
  for (const std::string& note : report.notes) {
    json.string(note);
  }
  json.end_array();
  json.end_object();
}

void print_runtime_status(const scp::RuntimeStatus& status, const std::filesystem::path& directory) {
  print_line("directory " + directory.string());
  print_line("open " + boolean_text(status.open));
  print_line("durable " + boolean_text(status.durable));
  print_line("site " + id_text(status.site));
  print_line("site-generation " + std::to_string(status.site_generation.value()));
  print_line("state " + std::string(scp::to_string(status.state)));
  print_line("lifecycle " + std::string(scp::to_string(status.lifecycle)));
  print_line("classification " + std::string(scp::to_string(status.classification)));
  print_line("accepted-evidence " + std::to_string(status.accepted_evidence));
  print_line("pending-evidence " + std::to_string(status.pending_evidence));
  print_line("grants " + std::to_string(status.grants));
  print_line("journal-sequence " + std::to_string(status.journal_sequence.value()));
  print_line("journal-bytes " + std::to_string(status.journal_bytes));
  print_line("commits " + std::to_string(status.commits));
  print_line("committed-operations " + std::to_string(status.committed_operations));
  print_line("rejected-ingests " + std::to_string(status.rejected_ingests));
  print_line("merged-ingests " + std::to_string(status.merged_ingests));
  print_line("plans-produced " + std::to_string(status.plans_produced));
  print_line("plans-denied " + std::to_string(status.plans_denied));
  print_line("compactions " + std::to_string(status.compactions));
  print_line("recovered " + boolean_text(status.recovered));
  print_line("recovered-with-truncation " + boolean_text(status.recovered_with_truncation));
  print_line("recovered-operations " + std::to_string(status.recovered_operations));
  print_line("cancelled " + boolean_text(status.cancelled));
  print_line("policy-digest " + status.policy_digest.to_hex());
  print_line("snapshot-digest " + status.snapshot_digest.to_hex());
}

void print_recovery_report(const scp::JournalRecoveryReport& report) {
  print_line("clean " + boolean_text(report.clean));
  print_line("truncated-torn-tail " + boolean_text(report.truncated_torn_tail));
  print_line("discarded-uncommitted-transaction " +
             boolean_text(report.discarded_uncommitted_transaction));
  print_line("committed-transactions " + std::to_string(report.committed_transactions));
  print_line("replayed-operations " + std::to_string(report.replayed_operations));
  print_line("discarded-operations " + std::to_string(report.discarded_operations));
  print_line("first-sequence " + std::to_string(report.first_sequence.value()));
  print_line("last-sequence " + std::to_string(report.last_sequence.value()));
  print_line("recovered-bytes " + std::to_string(report.recovered_bytes));
  print_line("damage-offset " + std::to_string(report.damage_offset));
  print_line("chain-digest " + report.chain_digest.to_hex());
  print_line("snapshot-loaded " + boolean_text(report.loaded_snapshot));
  print_line("snapshot-sequence " + std::to_string(report.snapshot_sequence.value()));
  print_line("snapshot-site-generation " + std::to_string(report.site_generation.value()));
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<std::string_view> policy_flag_names() {
  std::vector<std::string_view> names;
  names.push_back("policy");
  for (const std::string_view key : kPolicyKeys) {
    names.push_back(key);
  }
  return names;
}

[[nodiscard]] std::vector<std::string_view> with_policy(
    std::initializer_list<std::string_view> extra) {
  std::vector<std::string_view> names = policy_flag_names();
  names.insert(names.end(), extra.begin(), extra.end());
  return names;
}

[[nodiscard]] std::filesystem::path required_directory(const Options& options,
                                                       std::string_view command) {
  const std::filesystem::path directory(options.require(command, "dir"));
  if (directory.empty()) {
    usage_error(std::string(command) + " requires a non-empty --dir");
  }
  return directory;
}

void print_explanation(const scp::ExplainReport& report, bool json, std::string_view command) {
  if (json) {
    JsonWriter writer(std::cout);
    write_explanation_json(writer, command, report);
    std::cout << '\n';
    return;
  }
  for (const std::string& line : scp::render_explanation(report)) {
    print_line(line);
  }
}

int command_version() {
  print_line("scpctl " + std::string(scp::version_string()) + " (format " +
             std::to_string(scp::kFormatVersion) + ", evidence schema " +
             std::to_string(scp::kEvidenceSchemaVersion) + ")");
  return kExitOk;
}

int command_status(const Options& options) {
  options.require_only("status", with_policy({"dir", "at"}));
  const std::filesystem::path directory = required_directory(options, "status");
  const scp::SitePolicy policy = build_policy(options);
  std::unique_ptr<scp::SiteControlPlane> runtime =
      open_runtime(directory, policy, evaluation_instant(options));
  print_runtime_status(runtime->status(), directory);
  must_ok(runtime->close());
  return kExitOk;
}

int command_recover(const Options& options) {
  options.require_only("recover", {"dir"});
  const std::filesystem::path directory = required_directory(options, "recover");
  if (!std::filesystem::is_directory(directory)) {
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error) {
      fail(kExitUsage,
           scp::fail(scp::StatusCode::IoError,
                     "cannot create directory '" + directory.string() + "': " + error.message())
               .to_string());
    }
  }
  scp::JournalOptions journal_options;
  journal_options.directory = directory;
  journal_options.site = default_site();
  scp::Journal journal = must_call(scp::Journal::open(journal_options));
  const scp::JournalRecoveryReport report = must_call(journal.recover());
  print_recovery_report(report);
  must_ok(journal.close());
  return report.clean ? kExitOk : kExitState;
}

int command_compose(const Options& options) {
  options.require_only("compose", with_policy({"evidence", "site", "at", "json"}));
  const std::filesystem::path path(options.require("compose", "evidence"));
  const std::vector<scp::EvidenceRecord> records = parse_evidence_script(path);
  const scp::SitePolicy policy = build_policy(options);
  scp::CompositionOptions composition;
  composition.site = options.site.empty() ? scp::SiteId{}
                                          : parse_id_field<scp::SiteId>("--site", options.site);
  composition.site_generation = scp::SiteGeneration::first();
  composition.evaluation_time = evaluation_instant(options);
  composition.policy = policy;
  const scp::SiteStateSnapshot snapshot = must_call(scp::compose_site_state(records, composition));
  const scp::ExplainReport report = scp::explain_snapshot(snapshot, policy);
  print_explanation(report, options.json, "compose");
  return kExitOk;
}

int command_apply(const Options& options) {
  options.require_only("apply",
                       with_policy({"dir", "evidence", "at", "no-advance-generation"}));
  const std::filesystem::path directory = required_directory(options, "apply");
  const std::filesystem::path path(options.require("apply", "evidence"));
  const std::vector<scp::EvidenceRecord> records = parse_evidence_script(path);
  const scp::SitePolicy policy = build_policy(options);
  std::unique_ptr<scp::SiteControlPlane> runtime =
      open_runtime(directory, policy, evaluation_instant(options));
  for (const scp::EvidenceRecord& record : records) {
    must_ok(runtime->ingest(record));
  }
  scp::CommitOptions commit_options;
  commit_options.now = scp::Timestamp{required_now(options)};
  commit_options.advance_generation = !options.no_advance_generation;
  const scp::CommitOutcome outcome = must_call(runtime->commit(commit_options));
  const scp::RuntimeStatus status = runtime->status();
  print_line("committed " + boolean_text(outcome.committed));
  print_line("site " + id_text(status.site));
  print_line("records-in-script " + std::to_string(records.size()));
  print_line("accepted-evidence " + std::to_string(status.accepted_evidence));
  print_line("site-generation " + std::to_string(outcome.site_generation.value()));
  print_line("state " + std::string(scp::to_string(outcome.state)));
  print_line("classification " + std::string(scp::to_string(outcome.classification)));
  print_line("operations " + std::to_string(outcome.operations));
  print_line("journal-sequence " + std::to_string(outcome.journal_sequence.value()));
  print_line("bytes-written " + std::to_string(outcome.transaction_bytes));
  print_line("durability-boundary " + display(outcome.durability_boundary));
  print_line("snapshot-digest " + outcome.snapshot_digest.to_hex());
  print_line("evidence-digest-low " + std::to_string(outcome.evidence_digest_low));
  print_line("compacted " + boolean_text(outcome.compacted));
  print_line("compaction-bytes-reclaimed " + std::to_string(outcome.compaction_bytes_reclaimed));
  must_ok(runtime->close());
  return kExitOk;
}

int command_explain(const Options& options) {
  options.require_only("explain", with_policy({"dir", "at", "json"}));
  const std::filesystem::path directory = required_directory(options, "explain");
  const scp::SitePolicy policy = build_policy(options);
  const scp::Timestamp instant = evaluation_instant(options);
  std::unique_ptr<scp::SiteControlPlane> runtime = open_runtime(directory, policy, instant);
  const scp::ExplainReport report = must_call(runtime->explain(instant));
  print_explanation(report, options.json, "explain");
  must_ok(runtime->close());
  return kExitOk;
}

void write_plan_json(JsonWriter& json, const scp::ActionPlan& plan, const std::string& principal,
                     const std::string& service_class) {
  json.begin_object();
  json.key("command");
  json.string("plan");
  json.key("plan");
  json.string(plan.id.to_hex());
  json.key("site");
  json.string(plan.site.to_hex());
  json.key("site-generation");
  json.number(plan.site_generation.value());
  json.key("intent");
  json.string(scp::to_string(plan.intent));
  json.key("principal");
  json.string(principal);
  json.key("service-class");
  json.string(service_class);
  json.key("created-at");
  json.string(plan.created_at.to_iso8601());
  json.key("state");
  json.string(scp::to_string(plan.state));
  json.key("permitted");
  json.boolean(plan.permitted);
  json.key("denial-reason");
  json.string(plan.denial_reason);
  json.key("authority");
  json.begin_object();
  json.key("outcome");
  json.string(scp::to_string(plan.authority.outcome));
  json.key("grant");
  json.string(id_text(plan.authority.grant));
  json.key("detail");
  json.string(plan.authority.detail);
  json.end_object();
  json.key("gate");
  json.begin_object();
  json.key("kind");
  json.string(scp::to_string(plan.gate.kind));
  json.key("open");
  json.boolean(plan.gate.open);
  json.key("conditions");
  json.begin_array();
  for (const scp::GateCondition& condition : plan.gate.conditions) {
    json.begin_object();
    json.key("name");
    json.string(condition.name.view());
    json.key("satisfied");
    json.boolean(condition.satisfied);
    json.key("observed");
    json.string(condition.observed);
    json.key("required");
    json.string(condition.required);
    json.key("detail");
    json.string(condition.detail);
    json.end_object();
  }
  json.end_array();
  json.end_object();
  json.key("conditions");
  json.begin_array();
  for (const scp::PlanCondition& condition : plan.conditions) {
    json.begin_object();
    json.key("name");
    json.string(condition.name.view());
    json.key("satisfied");
    json.boolean(condition.satisfied);
    json.key("observed");
    json.string(condition.observed);
    json.key("required");
    json.string(condition.required);
    json.end_object();
  }
  json.end_array();
  json.key("requests");
  json.begin_array();
  for (const scp::PlannedStep& step : plan.steps) {
    const scp::EffectRequest& request = step.request;
    json.begin_object();
    json.key("ordinal");
    json.number(static_cast<std::uint64_t>(step.ordinal));
    json.key("description");
    json.string(step.description.view());
    json.key("id");
    json.string(request.id.to_hex());
    json.key("idempotency-key");
    json.string(request.idempotency.to_hex());
    json.key("target");
    json.string(scp::to_string(request.target));
    json.key("action");
    json.string(request.action.view());
    json.key("required-scope");
    json.string(request.required_scope.to_string());
    json.key("site-generation");
    json.number(request.site_generation.value());
    json.key("created-at");
    json.string(request.created_at.to_iso8601());
    json.key("deadline");
    json.string(timestamp_text(request.deadline));
    json.key("argument-bytes");
    json.number(static_cast<std::uint64_t>(request.arguments.size()));
    json.key("plan");
    json.string(request.plan.to_hex());
    json.key("site-snapshot-digest");
    json.string(request.site_snapshot_digest.to_hex());
    json.key("preconditions");
    json.begin_array();
    for (const scp::Precondition& precondition : request.preconditions) {
      json.begin_object();
      json.key("kind");
      json.string(scp::to_string(precondition.kind));
      json.key("subject");
      json.string(precondition.subject);
      json.key("expectation");
      json.string(precondition.expectation);
      json.end_object();
    }
    json.end_array();
    json.end_object();
  }
  json.end_array();
  json.key("plan-digest");
  json.string(plan.plan_digest.to_hex());
  json.key("site-snapshot-digest");
  json.string(plan.site_snapshot_digest.to_hex());
  json.key("evidence-digest");
  json.string(plan.evidence_digest.to_hex());
  json.end_object();
}

void print_plan_text(const scp::ActionPlan& plan, const std::string& principal,
                     const std::string& service_class) {
  print_line("plan " + plan.id.to_hex());
  print_line("site " + plan.site.to_hex());
  print_line("site-generation " + std::to_string(plan.site_generation.value()));
  print_line("intent " + std::string(scp::to_string(plan.intent)));
  print_line("principal " + display(principal));
  print_line("service-class " + optional_text(service_class));
  print_line("created-at " + plan.created_at.to_iso8601());
  print_line("state " + std::string(scp::to_string(plan.state)));
  print_line("permitted " + boolean_text(plan.permitted));
  print_line("denial-reason " + optional_text(plan.denial_reason));
  print_line("authority-outcome " + std::string(scp::to_string(plan.authority.outcome)));
  print_line("authority-grant " + id_text(plan.authority.grant));
  print_line("authority-detail " + display(plan.authority.detail));
  print_line("gate " + std::string(scp::to_string(plan.gate.kind)) + " " +
             (plan.gate.open ? "open" : "closed"));
  for (const scp::GateCondition& condition : plan.gate.conditions) {
    print_line("gate-condition " + std::string(condition.name.view()) + " " +
               (condition.satisfied ? "satisfied" : "unsatisfied") + " observed=" +
               display(condition.observed) + " required=" + display(condition.required) +
               " detail=" + display(condition.detail));
  }
  for (const scp::PlanCondition& condition : plan.conditions) {
    print_line("plan-condition " + std::string(condition.name.view()) + " " +
               (condition.satisfied ? "satisfied" : "unsatisfied") + " observed=" +
               display(condition.observed) + " required=" + display(condition.required));
  }
  print_line("effect-request-count " + std::to_string(plan.request_count()));
  for (const scp::PlannedStep& step : plan.steps) {
    const scp::EffectRequest& request = step.request;
    print_line("effect-request " + std::to_string(step.ordinal));
    print_line("  description " + display(step.description.view()));
    print_line("  id " + request.id.to_hex());
    print_line("  idempotency-key " + request.idempotency.to_hex());
    print_line("  target " + std::string(scp::to_string(request.target)));
    print_line("  action " + display(request.action.view()));
    print_line("  required-scope " +
               (request.required_scope.empty() ? std::string("none")
                                               : request.required_scope.to_string()));
    print_line("  site " + request.site.to_hex());
    print_line("  site-generation " + std::to_string(request.site_generation.value()));
    print_line("  created-at " + request.created_at.to_iso8601());
    print_line("  deadline " + timestamp_text(request.deadline));
    print_line("  argument-bytes " + std::to_string(request.arguments.size()));
    print_line("  plan " + request.plan.to_hex());
    print_line("  site-snapshot-digest " + request.site_snapshot_digest.to_hex());
    for (const scp::Precondition& precondition : request.preconditions) {
      print_line("  precondition " + std::string(scp::to_string(precondition.kind)) + " " +
                 display(precondition.subject) + " " + display(precondition.expectation));
    }
  }
  print_line("plan-digest " + plan.plan_digest.to_hex());
  print_line("site-snapshot-digest " + plan.site_snapshot_digest.to_hex());
  print_line("evidence-digest " + plan.evidence_digest.to_hex());
}

int command_plan(const Options& options) {
  options.require_only("plan",
                       with_policy({"dir", "intent", "principal", "service-class", "at", "scope",
                                    "deadline", "json"}));
  const std::filesystem::path directory = required_directory(options, "plan");
  const std::string service_class =
      options.has("service-class") ? options.require("plan", "service-class") : std::string();
  const std::string principal = options.require("plan", "principal");
  const scp::PlanIntent intent =
      must_parse(scp::plan_intent_from_string(options.require("plan", "intent")));
  if (intent == scp::PlanIntent::AcceptObligation && service_class.empty()) {
    usage_error("plan --intent accept-obligation requires --service-class <name>");
  }
  scp::PlanRequest request;
  request.intent = intent;
  request.site = default_site();
  request.now = scp::Timestamp{required_now(options)};
  request.principal = must_parse(scp::Name::parse(principal));
  if (!service_class.empty()) {
    request.service_class = must_parse(scp::Name::parse(service_class));
  }
  if (options.has("scope")) {
    scp::ScopeSet scopes;
    for (const std::string_view field : scp::split_ascii(options.require("plan", "scope"), ',')) {
      if (field.empty()) {
        usage_error("plan --scope has an empty scope name");
      }
      scopes = scopes.with(scope_from_slug(field));
    }
    request.scope_override = scopes;
    request.use_scope_override = true;
  }
  const scp::SitePolicy policy = build_policy(options);
  std::unique_ptr<scp::SiteControlPlane> runtime =
      open_runtime(directory, policy, scp::Timestamp{request.now.nanos});
  request.site_generation = runtime->status().site_generation;
  scp::ActionPlan plan = must_call(runtime->plan(request));
  if (options.has("deadline")) {
    const scp::Timestamp deadline = parse_timestamp_field("--deadline", options.deadline);
    if (!deadline.is_set()) {
      usage_error("plan --deadline must state a real instant");
    }
    for (scp::PlannedStep& step : plan.steps) {
      step.request.deadline = deadline;
    }
    plan.plan_digest = scp::compute_plan_digest(plan);
    must_ok(plan.validate());
  }
  if (options.json) {
    JsonWriter writer(std::cout);
    write_plan_json(writer, plan, principal, service_class);
    std::cout << '\n';
  } else {
    print_plan_text(plan, principal, service_class);
  }
  must_ok(runtime->close());
  return plan.permitted ? kExitOk : kExitState;
}

[[nodiscard]] scp::GrantId derive_grant_id(const scp::DelegationGrant& grant) {
  scp::CanonicalWriter writer;
  writer.text("scp.scpctl.delegation-grant.v1");
  writer.u64(grant.site.high());
  writer.u64(grant.site.low());
  writer.name(grant.grantor);
  writer.name(grant.subject);
  writer.u16(grant.scopes.bits());
  writer.u64(grant.not_before.value());
  writer.u64(grant.not_after.value());
  writer.i64(grant.issued_at.nanos);
  writer.i64(grant.expires_at.nanos);
  writer.boolean(grant.revoked);
  const scp::Digest digest = scp::Digest::of(writer.span());
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  const auto& bytes = digest.bytes();
  for (std::size_t index = 0; index < 8U; ++index) {
    high = (high << 8U) | bytes[index];
    low = (low << 8U) | bytes[index + 8U];
  }
  return scp::GrantId(high, low);
}

int command_grant(const Options& options) {
  options.require_only("grant", {"dir", "grantor", "subject", "scopes", "not-before", "not-after",
                                 "expires-at", "revoked", "at"});
  const std::filesystem::path directory = required_directory(options, "grant");
  scp::DelegationGrant grant;
  grant.site = default_site();
  grant.grantor = must_parse(scp::Name::parse(options.require("grant", "grantor")));
  grant.subject = must_parse(scp::Name::parse(options.require("grant", "subject")));
  const std::string scope_text = options.require("grant", "scopes");
  for (const std::string_view field : scp::split_ascii(scope_text, ',')) {
    if (field.empty()) {
      usage_error("grant --scopes has an empty scope name");
    }
    grant.scopes = grant.scopes.with(scope_from_slug(field));
  }
  if (options.has("not-before")) {
    grant.not_before = scp::SiteGeneration(parse_u64_field("--not-before", options.not_before));
  }
  if (options.has("not-after")) {
    grant.not_after = scp::SiteGeneration(parse_u64_field("--not-after", options.not_after));
  }
  grant.issued_at = scp::Timestamp{required_now(options)};
  if (options.has("expires-at")) {
    grant.expires_at = parse_timestamp_field("--expires-at", options.expires_at);
  }
  grant.revoked = options.revoked;
  grant.id = derive_grant_id(grant);
  const scp::SitePolicy policy = build_policy(options);
  std::unique_ptr<scp::SiteControlPlane> runtime =
      open_runtime(directory, policy, scp::Timestamp{grant.issued_at.nanos});
  must_ok(runtime->record_grant(grant, grant.issued_at));
  const scp::RuntimeStatus status = runtime->status();
  print_line("grant " + grant.id.to_hex());
  print_line("digest " + scp::Digest::of(grant.canonical_bytes()).to_hex());
  print_line("site " + grant.site.to_hex());
  print_line("grantor " + display(grant.grantor.view()));
  print_line("subject " + display(grant.subject.view()));
  print_line("scopes " + grant.scopes.to_string());
  print_line("not-before " + std::to_string(grant.not_before.value()));
  print_line("not-after " + std::to_string(grant.not_after.value()));
  print_line("issued-at " + grant.issued_at.to_iso8601());
  print_line("expires-at " + timestamp_text(grant.expires_at));
  print_line("revoked " + boolean_text(grant.revoked));
  print_line("recorded-grants " + std::to_string(status.grants));
  print_line("journal-sequence " + std::to_string(status.journal_sequence.value()));
  must_ok(runtime->close());
  return kExitOk;
}

int command_verify(const Options& options) {
  options.require_only("verify", with_policy({"dir", "at"}));
  const std::filesystem::path directory = required_directory(options, "verify");
  scp::JournalOptions journal_options;
  journal_options.directory = directory;
  journal_options.site = default_site();
  scp::Journal journal = must_call(scp::Journal::open(journal_options));
  const scp::JournalRecoveryReport report = must_call(journal.recover());
  const scp::Result<scp::JournalSnapshot> stored = journal.read_snapshot();
  const bool snapshot_unreadable =
      !stored.has_value() && stored.status().code() != scp::StatusCode::NotFound;
  print_recovery_report(report);
  print_line("snapshot-file-present " + boolean_text(stored.has_value() || snapshot_unreadable));
  print_line("snapshot-readable " + boolean_text(!snapshot_unreadable));
  if (snapshot_unreadable) {
    print_line("snapshot-error " + stored.status().to_string());
  }
  must_ok(journal.close());

  const scp::SitePolicy policy = build_policy(options);
  const scp::Timestamp instant = evaluation_instant(options);
  std::unique_ptr<scp::SiteControlPlane> runtime = open_runtime(directory, policy, instant);
  const scp::SiteStateSnapshot snapshot = must_call(runtime->snapshot(instant));
  const scp::RuntimeStatus status = runtime->status();
  print_line("site " + snapshot.site.to_hex());
  print_line("site-generation " + std::to_string(snapshot.site_generation.value()));
  print_line("state " + std::string(scp::to_string(snapshot.state)));
  print_line("lifecycle " + std::string(scp::to_string(snapshot.lifecycle)));
  print_line("classification " + std::string(scp::to_string(snapshot.classification)));
  print_line("accepted-evidence " + std::to_string(status.accepted_evidence));
  print_line("evidence-digest " + snapshot.evidence_digest.to_hex());
  print_line("policy-digest " + snapshot.policy_digest.to_hex());
  print_line("recomposed-snapshot-digest " + snapshot.snapshot_digest.to_hex());
  print_line("reported-snapshot-digest " + status.snapshot_digest.to_hex());
  print_line("recovered " + boolean_text(status.recovered));
  print_line("recovered-with-truncation " + boolean_text(status.recovered_with_truncation));
  print_line("recovered-operations " + std::to_string(status.recovered_operations));
  must_ok(runtime->close());
  if (!report.clean || snapshot_unreadable) {
    return kExitState;
  }
  return kExitOk;
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

[[nodiscard]] std::string usage_text() {
  return
      "Usage: scpctl <command> [options]\n"
      "\n"
      "scpctl inspects, composes, plans and recovers one site's control plane. It prints only\n"
      "values it read back from the library, and every error goes to stderr as\n"
      "'scpctl: <status>'.\n"
      "\n"
      "Exit codes: 0 success, 1 runtime or library failure, 2 usage error, 3 state or\n"
      "integrity failure (damaged or unclean durable state, or a denied plan).\n"
      "\n"
      "Commands:\n"
      "  version\n"
      "      Print the tool version, the durable format version and the evidence schema\n"
      "      version.\n"
      "\n"
      "  help | --help | -h\n"
      "      Print this text.\n"
      "\n"
      "  status --dir <path> [--at <timestamp>] [policy options]\n"
      "      Open the runtime on <path>, recovering durable state, print its status report\n"
      "      and close it.\n"
      "\n"
      "  recover --dir <path>\n"
      "      Run the journal's own recovery pass and print its report: whether the file\n"
      "      ended on a committed boundary, whether a torn tail was removed, whether an\n"
      "      uncommitted transaction was discarded, committed transactions, replayed\n"
      "      operations, the last journal sequence, the chain digest, whether a snapshot\n"
      "      was loaded and which sequence it covers, and the damage offset if any.\n"
      "      Exits 3 when the recovery was not clean.\n"
      "\n"
      "  compose --evidence <file> [--site <hex>] [--at <timestamp>] [--policy <file>]\n"
      "          [policy options] [--json]\n"
      "      Pure composition: read an evidence script, compose a snapshot with no durable\n"
      "      state and print the explanation. The site generation is 1, because there is\n"
      "      no durable generation without a runtime. Composition requires an identified\n"
      "      site and a stated evaluation instant, so --site and --at must name real\n"
      "      values; their defaults are the all-zero SiteId and 0, which the library\n"
      "      refuses.\n"
      "\n"
      "  apply --dir <path> --evidence <file> [--at <timestamp>] [--no-advance-generation]\n"
      "        [policy options]\n"
      "      Open the runtime, ingest every record in the script, commit them durably and\n"
      "      print the commit outcome.\n"
      "\n"
      "  explain --dir <path> [--at <timestamp>] [--json] [policy options]\n"
      "      Open the runtime and print render_explanation(explain(...)): every slot\n"
      "      resolution, every domain, every constraint, every obligation, every gate and\n"
      "      every derivation step behind the composed state.\n"
      "\n"
      "  plan --dir <path> --intent <name> --principal <name> [--service-class <name>]\n"
      "       [--at <timestamp>] [--scope <comma,separated,scopes>] [--deadline <timestamp>]\n"
      "       [--json] [policy options]\n"
      "      Open the runtime and plan the intent. Prints whether the plan is permitted,\n"
      "      the denial reason, the authority decision, the gate that was consulted with\n"
      "      every condition, and every emitted effect request with its target, action,\n"
      "      required scope, idempotency key, id, site generation, preconditions and\n"
      "      argument size. Exits 3 when the plan is denied.\n"
      "      Intents: accept-obligation, release-obligation, enter-maintenance,\n"
      "      controlled-drain, emergency-operation, begin-recovery, return-to-service,\n"
      "      isolate-site, retire-site, resume-normal-operation.\n"
      "\n"
      "  grant --dir <path> --grantor <name> --subject <name> --scopes <comma,separated>\n"
      "        [--not-before <n>] [--not-after <n>] [--expires-at <timestamp>] [--revoked]\n"
      "        [--at <timestamp>]\n"
      "      Record a delegation grant durably, at the instant --at names or the system\n"
      "      clock, and print its derived id and canonical digest. --not-before and\n"
      "      --not-after are site generations, not instants; 0 means no bound.\n"
      "\n"
      "  verify --dir <path> [--at <timestamp>] [policy options]\n"
      "      Open the durable state, report the recovery result, whether a snapshot file is\n"
      "      present and readable, and the digest of the snapshot the runtime recomposes\n"
      "      from the journal. Exits 3 when the journal is not clean or a snapshot file is\n"
      "      present but unreadable.\n"
      "\n"
      "Timestamps: raw nanoseconds since the Unix epoch (an integer, possibly negative) or\n"
      "an ISO-8601 UTC instant 'YYYY-MM-DDTHH:MM:SS[.fraction]Z'. A space may replace the T\n"
      "and the trailing Z may be omitted. 0 means 'no stated instant'.\n"
      "\n"
      "Policy options (accepted by every command that composes):\n"
      "  --policy <file>                             key/value lines, see below\n"
      "  --capacity-headroom-constrained-percent <n>\n"
      "  --capacity-headroom-degraded-percent <n>\n"
      "  --domain-readiness-degraded-percent <n>\n"
      "  --domain-readiness-unavailable-percent <n>\n"
      "  --required-redundancy-domains <n>\n"
      "  --power-headroom-floor-milli-kw <n>\n"
      "  --cooling-headroom-floor-milli-kw <n>\n"
      "  --maintenance-minimum-readiness-percent <n>\n"
      "  --recovery-minimum-drained-percent <n>\n"
      "  --return-to-service-minimum-readiness-percent <n>\n"
      "  --stale-after <duration>                    <n>s, <n>m, <n>h or nanoseconds\n"
      "  --expire-after <duration>\n"
      "  --rule <id>:<kind>:<comparison>:<threshold>:<severity>[:blocking]   (repeatable)\n"
      "  --rule-with-subject <id>:<subject>:<kind>:<comparison>:<threshold>:<severity>\n"
      "                      [:blocking]                                   (repeatable)\n"
      "      <kind> is a constraint kind slug, <comparison> is one of at-least, at-most,\n"
      "      equal, not-equal, and <severity> is one of none, informational, minor, major,\n"
      "      critical. A rule's subject is the metric it watches: for --rule the rule id is\n"
      "      the subject, so the rule id must itself be a metric name. Metric names:\n"
      "      capacity-headroom-percent, available-capacity-units, power-headroom-milli-kw,\n"
      "      cooling-headroom-milli-kw, power-redundancy-available,\n"
      "      cooling-redundancy-available, readiness-percent, asi-readiness-percent,\n"
      "      dfi-readiness-percent, active-incidents, active-maintenance-windows,\n"
      "      drained-percent.\n"
      "\n"
      "Policy file format: one 'key value' pair per line, where the key is one of the long\n"
      "option names above without the leading '--'. '#' starts a comment, blank lines are\n"
      "ignored, and an unknown key is a usage error naming the key.\n"
      "\n"
      "Evidence script format (the input of compose and apply): one record per block,\n"
      "blocks separated by one or more blank lines, '#' starting a comment, keys and\n"
      "values separated by any run of spaces or tabs. Every block states 'kind' plus:\n"
      "\n"
      "  common to every block:\n"
      "    authority <slug>          optional; defaults to the owner of the kind, and a\n"
      "                              slug that does not own the kind is a usage error\n"
      "    instance <32 hex chars>   required\n"
      "    epoch <n>                 required, at least 1\n"
      "    generation <n>            required, at least 1; for a kind whose body carries a\n"
      "                              generation this states it as well\n"
      "    sequence <n>              required, at least 1\n"
      "    issued-at <timestamp>     required\n"
      "    valid-until <timestamp>   optional; 0 or absent means no stated expiry\n"
      "    schema <n>                optional; defaults to the evidence schema version\n"
      "\n"
      "  kind facility-state  (authority facility-state-ledger)\n"
      "    worst-severity, active-incidents, degraded-operation, emergency-declared,\n"
      "    topology-digest (optional)\n"
      "  kind lifecycle       (authority facility-state-ledger)\n"
      "    state, entered-at (optional), transition-in-progress, transition-digest\n"
      "    (optional)\n"
      "  kind capacity        (authority facility-capacity)\n"
      "    snapshot (optional), total-units, committed-units, available-units,\n"
      "    oversubscribed\n"
      "  kind power-readiness (authority power-control-plane)\n"
      "    snapshot (optional), readiness, headroom-milli-kw, available-domains,\n"
      "    required-domains\n"
      "  kind cooling-readiness (authority thermal-control-plane)\n"
      "    the same fields as power-readiness\n"
      "  kind policy          (authority facility-policy-engine)\n"
      "    rules-digest (optional), rule-count\n"
      "  kind incident        (authority incident-state-fabric)\n"
      "    active-incidents, worst-severity, emergency-declared, earliest-active\n"
      "    (optional), suppressed-incidents\n"
      "  kind maintenance     (authority maintenance-coordinator)\n"
      "    mode (none|planned|emergency|overdue), active-windows, scheduled-windows,\n"
      "    next-window-start (optional), drain-in-progress, drained-percent\n"
      "  kind asi-capability  (authority asi-runtime)\n"
      "    readiness, ready-domains, total-domains, ready-units, capability-digest\n"
      "    (optional)\n"
      "  kind dfi-capability  (authority dfi-runtime)\n"
      "    the same fields as asi-capability\n"
      "  kind service-class   (authority service-class-registry)\n"
      "    class-count, obligations-digest (optional), and one or more lines of the form\n"
      "    'obligation <name> <protected:true|false> <minimum-ready-units>\n"
      "    <minimum-readiness-percent>'\n"
      "\n"
      "An unknown key inside a block is a usage error naming the key and its line. Hex\n"
      "accepts an optional 0x prefix; ids are 32 hex characters and digests are 64.\n"
      "\n"
      "JSON output (--json) is one object with two-space indentation, no trailing commas\n"
      "and strings escaped per RFC 8259. Keys appear in the order the report reads.\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  try {
    if (arguments.empty()) {
      std::cerr << usage_text();
      return kExitUsage;
    }
    const std::string command = arguments.front();
    if (command == "help" || command == "--help" || command == "-h") {
      if (arguments.size() != 1U) {
        usage_error("help takes no options");
      }
      std::cout << usage_text();
      return kExitOk;
    }
    if (command == "version") {
      if (arguments.size() != 1U) {
        usage_error("version takes no options");
      }
      return command_version();
    }
    const Options options =
        parse_options(std::vector<std::string>(arguments.begin() + 1, arguments.end()));
    if (command == "status") {
      return command_status(options);
    }
    if (command == "recover") {
      return command_recover(options);
    }
    if (command == "compose") {
      return command_compose(options);
    }
    if (command == "apply") {
      return command_apply(options);
    }
    if (command == "explain") {
      return command_explain(options);
    }
    if (command == "plan") {
      return command_plan(options);
    }
    if (command == "grant") {
      return command_grant(options);
    }
    if (command == "verify") {
      return command_verify(options);
    }
    usage_error("unknown command '" + display(command) + "'");
  } catch (const CliExit& exit) {
    if (!exit.message().empty()) {
      std::cerr << "scpctl: " << exit.message() << '\n';
    }
    return exit.code();
  } catch (const std::exception& error) {
    std::cerr << "scpctl: " << error.what() << '\n';
    return kExitFailure;
  }
}
