// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "scp/canonical.hpp"
#include "scp/checked.hpp"
#include "scp/digest.hpp"
#include "scp/status.hpp"
#include "scp/text.hpp"
#include "scp/time.hpp"
#include "scp/version.hpp"
#include "test_support.hpp"

/// \file test_status.cpp
/// The vocabulary the rest of the runtime speaks: outcome codes, checked
/// arithmetic, bounded text and the canonical codec.
///
/// These are the lowest-level contracts in the repository, so they are also the
/// ones whose failure modes matter most: a silently wrapped counter or a
/// length prefix trusted before it is validated are how a control plane loses
/// an argument with reality.

namespace {

const std::vector<scp::StatusCode>& every_code() {
  static const std::vector<scp::StatusCode> codes = {
      scp::StatusCode::Ok,
      scp::StatusCode::InvalidArgument,
      scp::StatusCode::InvalidIdentifier,
      scp::StatusCode::InvalidText,
      scp::StatusCode::InvalidUnicode,
      scp::StatusCode::InvalidEnum,
      scp::StatusCode::OutOfRange,
      scp::StatusCode::Overflow,
      scp::StatusCode::Underflow,
      scp::StatusCode::NotFound,
      scp::StatusCode::AlreadyExists,
      scp::StatusCode::DuplicateIdentity,
      scp::StatusCode::Conflict,
      scp::StatusCode::StaleGeneration,
      scp::StatusCode::SupersededGeneration,
      scp::StatusCode::Indeterminate,
      scp::StatusCode::Unknown,
      scp::StatusCode::Unsupported,
      scp::StatusCode::UnsupportedFormatVersion,
      scp::StatusCode::Unauthorized,
      scp::StatusCode::ScopeNotGranted,
      scp::StatusCode::GrantExpired,
      scp::StatusCode::GrantRevoked,
      scp::StatusCode::GrantNotYetValid,
      scp::StatusCode::GenerationFenced,
      scp::StatusCode::PreconditionFailed,
      scp::StatusCode::GateClosed,
      scp::StatusCode::ObligationRejected,
      scp::StatusCode::Corrupt,
      scp::StatusCode::InteriorCorruption,
      scp::StatusCode::TornTail,
      scp::StatusCode::ChecksumMismatch,
      scp::StatusCode::ChainBroken,
      scp::StatusCode::Truncated,
      scp::StatusCode::IoError,
      scp::StatusCode::PermissionDenied,
      scp::StatusCode::Locked,
      scp::StatusCode::WriterExists,
      scp::StatusCode::LockLost,
      scp::StatusCode::PathInvalid,
      scp::StatusCode::LimitExceeded,
      scp::StatusCode::CapacityExhausted,
      scp::StatusCode::InvalidState,
      scp::StatusCode::Closed,
      scp::StatusCode::NotOpen,
      scp::StatusCode::Cancelled,
      scp::StatusCode::ShuttingDown,
      scp::StatusCode::Exhausted,
  };
  return codes;
}

}  // namespace

SCP_TEST(every_status_code_has_a_stable_slug_and_a_description) {
  for (const scp::StatusCode code : every_code()) {
    const std::string_view slug = scp::to_string(code);
    SCP_CHECK(!slug.empty());
    SCP_CHECK(slug.find(' ') == std::string_view::npos);
    SCP_CHECK(!scp::describe(code).empty());
  }
  SCP_CHECK_EQ(scp::to_string(scp::StatusCode::Ok), std::string_view("ok"));
  // Slugs are unique, so a report can be parsed without guessing.
  for (std::size_t outer = 0; outer < every_code().size(); ++outer) {
    for (std::size_t inner = outer + 1; inner < every_code().size(); ++inner) {
      SCP_CHECK(scp::to_string(every_code()[outer]) != scp::to_string(every_code()[inner]));
    }
  }
}

SCP_TEST(status_carries_a_code_and_a_message) {
  const scp::Status good;
  SCP_CHECK(good.ok());
  SCP_CHECK_EQ(good.to_string(), std::string("ok"));

  const scp::Status bad = scp::fail(scp::StatusCode::GateClosed, "the gate is closed");
  SCP_CHECK(!bad.ok());
  SCP_CHECK(bad.code() == scp::StatusCode::GateClosed);
  SCP_CHECK_EQ(bad.message(), std::string("the gate is closed"));
  SCP_CHECK_EQ(bad.to_string(), std::string("gate_closed: the gate is closed"));

  const scp::Status bare = scp::fail(scp::StatusCode::Conflict, "");
  SCP_CHECK_EQ(bare.to_string(), std::string("conflict"));
}

SCP_TEST(indeterminacy_and_integrity_are_distinguished) {
  SCP_CHECK(scp::is_indeterminate(scp::StatusCode::Indeterminate));
  SCP_CHECK(scp::is_indeterminate(scp::StatusCode::Unknown));
  SCP_CHECK(scp::is_indeterminate(scp::StatusCode::StaleGeneration));
  SCP_CHECK(scp::is_indeterminate(scp::StatusCode::Conflict));
  SCP_CHECK(!scp::is_indeterminate(scp::StatusCode::InvalidArgument));
  SCP_CHECK(!scp::is_indeterminate(scp::StatusCode::GateClosed));

  SCP_CHECK(scp::is_integrity_failure(scp::StatusCode::InteriorCorruption));
  SCP_CHECK(scp::is_integrity_failure(scp::StatusCode::ChecksumMismatch));
  SCP_CHECK(scp::is_integrity_failure(scp::StatusCode::ChainBroken));
  SCP_CHECK(!scp::is_integrity_failure(scp::StatusCode::NotFound));
  SCP_CHECK(!scp::is_integrity_failure(scp::StatusCode::LimitExceeded));
}

SCP_TEST(result_holds_either_a_value_or_a_reason) {
  scp::Result<std::uint64_t> value(std::uint64_t{7});
  SCP_CHECK(value.has_value());
  SCP_CHECK_EQ(value.value(), std::uint64_t{7});
  SCP_CHECK_EQ(*value, std::uint64_t{7});

  scp::Result<std::uint64_t> failure(scp::fail(scp::StatusCode::OutOfRange, "too large"));
  SCP_CHECK(!failure.has_value());
  SCP_CHECK(failure.status().code() == scp::StatusCode::OutOfRange);
  SCP_CHECK_EQ(failure.status().message(), std::string("too large"));

  // A Result can be moved and returns its value by move.
  scp::Result<std::string> text(std::string("hello"));
  const std::string moved = std::move(text).value();
  SCP_CHECK_EQ(moved, std::string("hello"));
}

SCP_TEST(checked_arithmetic_refuses_to_wrap) {
  const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
  {
    const auto sum = scp::checked_add(std::uint64_t{2}, std::uint64_t{3});
    SCP_REQUIRE_OK(sum);
    SCP_CHECK_EQ(sum.value(), std::uint64_t{5});
  }
  {
    const auto difference = scp::checked_sub(std::uint64_t{5}, std::uint64_t{3});
    SCP_REQUIRE_OK(difference);
    SCP_CHECK_EQ(difference.value(), std::uint64_t{2});
  }
  {
    const auto product = scp::checked_mul(std::uint64_t{6}, std::uint64_t{7});
    SCP_REQUIRE_OK(product);
    SCP_CHECK_EQ(product.value(), std::uint64_t{42});
  }
  {
    const auto successor = scp::checked_increment(std::uint64_t{0});
    SCP_REQUIRE_OK(successor);
    SCP_CHECK_EQ(successor.value(), std::uint64_t{1});
  }
  {
    const auto narrowed = scp::checked_u32(4294967295ULL);
    SCP_REQUIRE_OK(narrowed);
    SCP_CHECK_EQ(narrowed.value(), std::uint32_t{4294967295U});
  }
  {
    const auto positive = scp::checked_nonnegative(9);
    SCP_REQUIRE_OK(positive);
    SCP_CHECK_EQ(positive.value(), std::uint64_t{9});
  }
  {
    const auto signed_sum = scp::checked_add(std::int64_t{-4}, std::int64_t{9});
    SCP_REQUIRE_OK(signed_sum);
    SCP_CHECK_EQ(signed_sum.value(), std::int64_t{5});
  }

  SCP_REQUIRE_ERROR(scp::checked_add(maximum, std::uint64_t{1}), scp::StatusCode::Overflow);
  SCP_REQUIRE_ERROR(scp::checked_sub(std::uint64_t{3}, std::uint64_t{5}),
                    scp::StatusCode::Underflow);
  SCP_REQUIRE_ERROR(scp::checked_mul(maximum, std::uint64_t{2}), scp::StatusCode::Overflow);
  SCP_REQUIRE_ERROR(scp::checked_increment(maximum), scp::StatusCode::Overflow);
  SCP_REQUIRE_ERROR(scp::checked_u32(static_cast<std::uint64_t>(maximum)),
                    scp::StatusCode::OutOfRange);
  SCP_REQUIRE_ERROR(scp::checked_nonnegative(-1), scp::StatusCode::Underflow);

  const std::int64_t most_negative = std::numeric_limits<std::int64_t>::min();
  SCP_REQUIRE_ERROR(scp::checked_add(most_negative, std::int64_t{-1}), scp::StatusCode::Overflow);
  // The signed helpers report Overflow for a result that leaves the signed
  // range in either direction; only the unsigned helpers distinguish the two.
  SCP_REQUIRE_ERROR(scp::checked_sub(most_negative, std::int64_t{1}), scp::StatusCode::Overflow);
}

SCP_TEST(timestamps_are_check_and_round_trip) {
  const scp::Timestamp base = scp_test::base_instant();
  SCP_CHECK(base.is_set());
  SCP_CHECK(!scp::Timestamp{}.is_set());
  const auto later = scp::timestamp_add(base, scp::seconds(60));
  SCP_REQUIRE_OK(later);
  const auto gap = scp::duration_between(base, later.value());
  SCP_REQUIRE_OK(gap);
  if (gap.has_value()) {
    SCP_CHECK_EQ(gap.value().nanos, scp::seconds(60).nanos);
  }
  SCP_REQUIRE_ERROR(scp::timestamp_add(scp::Timestamp{std::numeric_limits<std::int64_t>::max()},
                                       scp::milliseconds(1)),
                    scp::StatusCode::Overflow);
  SCP_CHECK_EQ(base.to_iso8601(), std::string("2026-01-01T00:00:00.000000000Z"));
  SCP_CHECK_EQ(scp::Timestamp{}.to_iso8601(), std::string("1970-01-01T00:00:00.000000000Z"));

  scp::ManualClock clock(base);
  SCP_CHECK(clock.now() == base);
  SCP_REQUIRE_STATUS_OK(clock.advance(scp::seconds(5)));
  SCP_CHECK_EQ(clock.now().nanos, base.nanos + scp::seconds(5).nanos);
  SCP_REQUIRE_STATUS_ERROR(clock.advance(scp::Duration{std::numeric_limits<std::int64_t>::max()}),
                           scp::StatusCode::Overflow);
  SCP_CHECK_EQ(clock.now().nanos, base.nanos + scp::seconds(5).nanos);
}

SCP_TEST(text_is_validated_before_it_is_stored) {
  SCP_REQUIRE_OK(scp::Name::parse("power-control-plane"));
  SCP_REQUIRE_ERROR(scp::Name::parse(""), scp::StatusCode::InvalidArgument);
  SCP_REQUIRE_ERROR(scp::Name::parse(" leading"), scp::StatusCode::InvalidText);
  SCP_REQUIRE_ERROR(scp::Name::parse("trailing "), scp::StatusCode::InvalidText);
  SCP_REQUIRE_ERROR(scp::Name::parse("with\ttab"), scp::StatusCode::InvalidText);
  SCP_REQUIRE_ERROR(scp::Name::parse(std::string(200, 'a')), scp::StatusCode::InvalidArgument);
  SCP_REQUIRE_ERROR(scp::Name::parse(std::string(scp::kMaxNameBytes, 'a') + "b"),
                    scp::StatusCode::InvalidArgument);

  SCP_CHECK(scp::is_valid_utf8("plain ascii"));
  SCP_CHECK(scp::is_valid_utf8("caf\xc3\xa9"));
  SCP_CHECK(!scp::is_valid_utf8("\xc3\x28"));
  SCP_CHECK(!scp::is_valid_utf8("\xed\xa0\x80"));
  SCP_CHECK(scp::is_printable_ascii("plain"));
  SCP_CHECK(!scp::is_printable_ascii("bell\x07"));

  // Escaping makes untrusted text safe for any terminal.
  SCP_CHECK_EQ(scp::escape_for_display("plain"), std::string("plain"));
  SCP_CHECK(scp::escape_for_display("\x1b[2J").find("\x1b") == std::string::npos);
  SCP_CHECK(scp::escape_for_display("back\\slash") != std::string("back\\slash"));

  {
    const auto parsed = scp::parse_u64("42");
    SCP_REQUIRE_OK(parsed);
    SCP_CHECK_EQ(parsed.value(), std::uint64_t{42});
  }
  {
    const auto hexadecimal = scp::parse_hex_u64("0xFF");
    SCP_REQUIRE_OK(hexadecimal);
    SCP_CHECK_EQ(hexadecimal.value(), std::uint64_t{255});
  }
  {
    const auto lowercase = scp::parse_hex_u64("ff");
    SCP_REQUIRE_OK(lowercase);
    SCP_CHECK_EQ(lowercase.value(), std::uint64_t{255});
  }
  SCP_REQUIRE_ERROR(scp::parse_u64(""), scp::StatusCode::InvalidArgument);
  SCP_REQUIRE_ERROR(scp::parse_u64("-1"), scp::StatusCode::InvalidArgument);
  SCP_REQUIRE_ERROR(scp::parse_u64("4 2"), scp::StatusCode::InvalidArgument);
  SCP_REQUIRE_ERROR(scp::parse_u64("99999999999999999999999"), scp::StatusCode::Overflow);
  SCP_REQUIRE_ERROR(scp::parse_hex_u64("0x"), scp::StatusCode::InvalidArgument);
}

SCP_TEST(canonical_reader_is_bounds_checked_before_it_allocates) {
  scp::CanonicalWriter writer;
  writer.u8(0xAB);
  writer.boolean(true);
  writer.u16(0x1234);
  writer.u32(0x89ABCDEF);
  writer.u64(0x0123456789ABCDEFULL);
  writer.i64(-2);
  writer.text("hello");
  const std::vector<std::uint8_t> bytes = writer.data();

  scp::CanonicalReader reader(bytes);
  std::uint8_t u8 = 0;
  bool flag = false;
  std::uint16_t u16 = 0;
  std::uint32_t u32 = 0;
  std::uint64_t u64 = 0;
  std::int64_t i64 = 0;
  std::string text;
  SCP_REQUIRE_STATUS_OK(reader.u8(u8));
  SCP_CHECK_EQ(u8, std::uint8_t{0xAB});
  SCP_REQUIRE_STATUS_OK(reader.boolean(flag));
  SCP_CHECK(flag);
  SCP_REQUIRE_STATUS_OK(reader.u16(u16));
  SCP_CHECK_EQ(u16, std::uint16_t{0x1234});
  SCP_REQUIRE_STATUS_OK(reader.u32(u32));
  SCP_CHECK_EQ(u32, std::uint32_t{0x89ABCDEFU});
  SCP_REQUIRE_STATUS_OK(reader.u64(u64));
  SCP_CHECK_EQ(u64, std::uint64_t{0x0123456789ABCDEFULL});
  SCP_REQUIRE_STATUS_OK(reader.i64(i64));
  SCP_CHECK_EQ(i64, std::int64_t{-2});
  SCP_REQUIRE_STATUS_OK(reader.text(text));
  SCP_CHECK_EQ(text, std::string("hello"));
  SCP_REQUIRE_STATUS_OK(reader.expect_end());

  // A boolean that is neither zero nor one is refused rather than coerced.
  const std::vector<std::uint8_t> bad_boolean = {0x02};
  scp::CanonicalReader boolean_reader(bad_boolean);
  bool ignored = false;
  SCP_REQUIRE_STATUS_ERROR(boolean_reader.boolean(ignored), scp::StatusCode::InvalidArgument);

  // A length prefix is validated against the limit before anything is
  // allocated, so a hostile length cannot drive a large allocation.
  scp::CanonicalWriter huge;
  huge.u32(0xFFFFFFFFU);
  scp::CanonicalReader huge_reader(huge.data());
  std::vector<std::uint8_t> buffer;
  SCP_REQUIRE_STATUS_ERROR(huge_reader.bytes(buffer), scp::StatusCode::LimitExceeded);
  SCP_CHECK(buffer.empty());

  // Every truncation of a valid encoding is reported, never read past.
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    scp::CanonicalReader truncated(std::span<const std::uint8_t>(bytes.data(), length));
    bool complete = true;
    std::uint8_t value8 = 0;
    if (!truncated.u8(value8).ok()) {
      complete = false;
    }
    if (complete) {
      bool value_flag = false;
      if (!truncated.boolean(value_flag).ok()) {
        complete = false;
      }
    }
    std::vector<std::uint8_t> rest;
    if (complete && !truncated.bytes(rest, scp::kMaxBlobBytes).ok()) {
      complete = false;
    }
    SCP_CHECK(!complete);
  }
}

SCP_TEST(digests_are_hex_stable_and_verify_known_vectors) {
  const scp::Digest empty = scp::Digest::of(std::span<const std::uint8_t>());
  SCP_CHECK_EQ(empty.to_hex(),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  const std::string abc = "abc";
  const scp::Digest of_abc = scp::Digest::of(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size()));
  SCP_CHECK_EQ(of_abc.to_hex(),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  SCP_REQUIRE_OK(scp::Digest::parse_hex(of_abc.to_hex()));
  SCP_CHECK(scp::Digest::parse_hex(of_abc.to_hex()).value() == of_abc);
  SCP_REQUIRE_ERROR(scp::Digest::parse_hex("00"), scp::StatusCode::InvalidIdentifier);
  SCP_CHECK(scp::Digest{}.is_zero());

  // Incremental hashing agrees with one-shot hashing, including little-endian
  // scalar helpers.
  scp::Sha256 incremental;
  incremental.update(std::string_view("ab"));
  incremental.update(std::string_view("c"));
  SCP_CHECK(incremental.finalize() == of_abc);
  scp::Sha256 scalars;
  const std::uint8_t raw[] = {0x34, 0x12};
  scalars.update(std::span<const std::uint8_t>(raw, 2));
  scp::Sha256 helper;
  helper.update_u16_le(0x1234);
  SCP_CHECK(scalars.finalize() == helper.finalize());
}

SCP_TEST_MAIN("test_status")
