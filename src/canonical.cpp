// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/canonical.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "scp/text.hpp"

namespace scp {

namespace {

[[nodiscard]] Status truncated_field(const char* field) {
  return fail(StatusCode::Truncated,
              std::string("canonical input ended while reading field '") + field + "'");
}

[[nodiscard]] std::span<const std::uint8_t> as_bytes(std::string_view text) noexcept {
  return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                       text.size());
}

/// Little-endian load of at most eight bytes.
[[nodiscard]] std::uint64_t load_le(std::span<const std::uint8_t> field) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < field.size(); ++index) {
    value |= static_cast<std::uint64_t>(field[index]) << (8U * index);
  }
  return value;
}

}  // namespace

void CanonicalWriter::u8(std::uint8_t value) { data_.push_back(value); }

void CanonicalWriter::boolean(bool value) {
  u8(value ? static_cast<std::uint8_t>(1U) : static_cast<std::uint8_t>(0U));
}

void CanonicalWriter::u16(std::uint16_t value) {
  data_.push_back(static_cast<std::uint8_t>(value & 0xFFU));
  data_.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void CanonicalWriter::u32(std::uint32_t value) {
  for (unsigned shift = 0; shift < 32U; shift += 8U) {
    data_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

void CanonicalWriter::u64(std::uint64_t value) {
  for (unsigned shift = 0; shift < 64U; shift += 8U) {
    data_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

void CanonicalWriter::i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }

void CanonicalWriter::bytes(std::span<const std::uint8_t> value) {
  // The writer has no error channel, so an oversized blob cannot be rejected
  // here and is deliberately not clamped either: clamping would silently change
  // the encoded value. Callers validate every blob against kMaxBlobBytes before
  // serializing, which makes a length above that bound impossible by
  // construction at this point.
  u32(static_cast<std::uint32_t>(value.size()));
  data_.insert(data_.end(), value.begin(), value.end());
}

void CanonicalWriter::bytes(std::string_view value) { bytes(as_bytes(value)); }

void CanonicalWriter::text(std::string_view value) { bytes(as_bytes(value)); }

void CanonicalWriter::name(const Name& value) { bytes(as_bytes(value.view())); }

Status CanonicalReader::take(std::size_t count, std::span<const std::uint8_t>& out) {
  if (count > remaining()) {
    out = std::span<const std::uint8_t>();
    return fail(StatusCode::Truncated, "canonical input ended before the field was complete");
  }
  out = input_.subspan(offset_, count);
  offset_ += count;
  return Status();
}

Status CanonicalReader::u8(std::uint8_t& out) {
  std::span<const std::uint8_t> field;
  if (!take(1U, field).ok()) {
    return truncated_field("u8");
  }
  out = field[0];
  return Status();
}

Status CanonicalReader::boolean(bool& out) {
  std::uint8_t value = 0;
  if (!u8(value).ok()) {
    return truncated_field("boolean");
  }
  if (value > 1U) {
    return fail(StatusCode::InvalidArgument, "boolean field is neither 0 nor 1");
  }
  out = value != 0U;
  return Status();
}

Status CanonicalReader::u16(std::uint16_t& out) {
  std::span<const std::uint8_t> field;
  if (!take(2U, field).ok()) {
    return truncated_field("u16");
  }
  out = static_cast<std::uint16_t>(load_le(field));
  return Status();
}

Status CanonicalReader::u32(std::uint32_t& out) {
  std::span<const std::uint8_t> field;
  if (!take(4U, field).ok()) {
    return truncated_field("u32");
  }
  out = static_cast<std::uint32_t>(load_le(field));
  return Status();
}

Status CanonicalReader::u64(std::uint64_t& out) {
  std::span<const std::uint8_t> field;
  if (!take(8U, field).ok()) {
    return truncated_field("u64");
  }
  out = load_le(field);
  return Status();
}

Status CanonicalReader::i64(std::int64_t& out) {
  std::uint64_t bits = 0;
  if (!u64(bits).ok()) {
    return truncated_field("i64");
  }
  out = static_cast<std::int64_t>(bits);
  return Status();
}

Status CanonicalReader::bytes(std::vector<std::uint8_t>& out, std::uint32_t limit) {
  std::uint32_t length = 0;
  if (!u32(length).ok()) {
    return truncated_field("bytes length");
  }
  if (length > limit) {
    return fail(StatusCode::LimitExceeded, "byte string length " + std::to_string(length) +
                                               " exceeds the accepted limit of " +
                                               std::to_string(limit));
  }
  const std::size_t count = static_cast<std::size_t>(length);
  if (count > remaining()) {
    return truncated_field("bytes payload");
  }
  const std::span<const std::uint8_t> payload = input_.subspan(offset_, count);
  out.assign(payload.begin(), payload.end());
  offset_ += count;
  return Status();
}

Status CanonicalReader::text(std::string& out, std::uint32_t limit) {
  std::uint32_t length = 0;
  if (!u32(length).ok()) {
    return truncated_field("text length");
  }
  if (length > limit) {
    return fail(StatusCode::LimitExceeded, "text length " + std::to_string(length) +
                                               " exceeds the accepted limit of " +
                                               std::to_string(limit));
  }
  const std::size_t count = static_cast<std::size_t>(length);
  if (count > remaining()) {
    return truncated_field("text payload");
  }
  const std::span<const std::uint8_t> payload = input_.subspan(offset_, count);
  std::string_view view;
  if (count != 0U) {
    view = std::string_view(reinterpret_cast<const char*>(payload.data()), count);
  }
  if (!is_valid_utf8(view)) {
    return fail(StatusCode::InvalidUnicode, "text field is not well-formed UTF-8");
  }
  out.assign(view);
  offset_ += count;
  return Status();
}

Status CanonicalReader::expect_end() const {
  if (remaining() != 0U) {
    return fail(StatusCode::InvalidArgument,
                "canonical input has " + std::to_string(remaining()) + " unread trailing bytes");
  }
  return Status();
}

}  // namespace scp
