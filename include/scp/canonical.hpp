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

#include "scp/status.hpp"

/// \file canonical.hpp
/// Canonical byte encoding for anything authoritative.
///
/// The encoding exists so that two logically equal values always hash to the
/// same digest and always persist to the same bytes, on every platform and in
/// every process. Rules:
///   * fixed-width little-endian scalars, no padding, no varints;
///   * every variable-length field is length-prefixed with a checked uint32;
///   * no alignment, no implicit structure layout, no locale or float formatting;
///   * maps and sets are serialized in a documented canonical order.
///
/// Reading is bounds-checked at every step, and length prefixes are validated
/// against the remaining input *before* any allocation is attempted, so a
/// malformed length cannot drive an oversized allocation.

namespace scp {

/// Upper bound on any single canonical blob the runtime will accept.
inline constexpr std::uint32_t kMaxBlobBytes = 1U << 20;  // 1 MiB

class CanonicalWriter {
 public:
  CanonicalWriter() = default;

  void u8(std::uint8_t value);
  void boolean(bool value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);
  void bytes(std::span<const std::uint8_t> value);
  void bytes(std::string_view value);
  void text(std::string_view value);
  void name(const class Name& value);

  /// Writes a presence tag followed by the value when present.
  template <class Fn>
  void optional(bool present, Fn&& write_value) {
    u8(present ? 1U : 0U);
    if (present) {
      write_value(*this);
    }
  }

  [[nodiscard]] const std::vector<std::uint8_t>& data() const noexcept { return data_; }
  [[nodiscard]] std::vector<std::uint8_t> take() noexcept { return std::move(data_); }
  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  [[nodiscard]] std::span<const std::uint8_t> span() const noexcept {
    return std::span<const std::uint8_t>(data_.data(), data_.size());
  }
  void clear() noexcept { data_.clear(); }

 private:
  std::vector<std::uint8_t> data_;
};

class CanonicalReader {
 public:
  explicit CanonicalReader(std::span<const std::uint8_t> input) noexcept : input_(input) {}

  [[nodiscard]] Status u8(std::uint8_t& out);
  [[nodiscard]] Status boolean(bool& out);
  [[nodiscard]] Status u16(std::uint16_t& out);
  [[nodiscard]] Status u32(std::uint32_t& out);
  [[nodiscard]] Status u64(std::uint64_t& out);
  [[nodiscard]] Status i64(std::int64_t& out);

  /// Bounded byte string. `limit` caps the accepted length independently of the
  /// remaining input so callers can enforce a tighter budget than 1 MiB.
  [[nodiscard]] Status bytes(std::vector<std::uint8_t>& out,
                             std::uint32_t limit = kMaxBlobBytes);
  /// Length-prefixed text, validated as UTF-8.
  [[nodiscard]] Status text(std::string& out, std::uint32_t limit = kMaxBlobBytes);

  /// \return the remaining byte count.
  [[nodiscard]] std::size_t remaining() const noexcept { return input_.size() - offset_; }
  [[nodiscard]] bool empty() const noexcept { return remaining() == 0; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

  /// Fails unless every input byte has been consumed.
  [[nodiscard]] Status expect_end() const;

 private:
  [[nodiscard]] Status take(std::size_t count, std::span<const std::uint8_t>& out);

  std::span<const std::uint8_t> input_;
  std::size_t offset_ = 0;
};

}  // namespace scp
