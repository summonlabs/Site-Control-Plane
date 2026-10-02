// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "scp/status.hpp"

/// \file text.hpp
/// Bounded, validated text used for names that reach the durable layer or the
/// operator surface. Untrusted text is validated before it is stored, hashed or
/// printed.

namespace scp {

/// Maximum encoded length of any name accepted by the runtime.
inline constexpr std::size_t kMaxNameBytes = 96;

/// Validated UTF-8 text: non-empty, at most kMaxNameBytes, no control characters,
/// no leading or trailing whitespace.
class Name {
 public:
  Name() = default;

  [[nodiscard]] static Result<Name> parse(std::string_view text);

  [[nodiscard]] const std::string& str() const noexcept { return text_; }
  [[nodiscard]] std::string_view view() const noexcept { return text_; }
  [[nodiscard]] bool empty() const noexcept { return text_.empty(); }

  friend bool operator==(const Name&, const Name&) noexcept = default;
  friend bool operator<(const Name& lhs, const Name& rhs) noexcept { return lhs.text_ < rhs.text_; }

 private:
  std::string text_;
};

/// True when the bytes are well-formed UTF-8 with no overlong encodings,
/// no surrogate code points and no code points above U+10FFFF.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

/// True when every byte is printable ASCII (0x20..0x7E), which keeps terminal
/// and log output unambiguous regardless of host code page.
[[nodiscard]] bool is_printable_ascii(std::string_view text) noexcept;

/// Escapes anything outside printable ASCII as \uXXXX so that untrusted text can
/// never inject terminal control sequences into an operator surface.
[[nodiscard]] std::string escape_for_display(std::string_view text);

/// Case-insensitive ASCII equality. Non-ASCII bytes must match exactly.
[[nodiscard]] bool ascii_iequals(std::string_view lhs, std::string_view rhs) noexcept;

/// Trims ASCII whitespace from both ends.
[[nodiscard]] std::string_view trim_ascii(std::string_view text) noexcept;

/// Splits on a single ASCII delimiter; empty fields are preserved.
[[nodiscard]] std::vector<std::string_view> split_ascii(std::string_view text, char delimiter);

/// Parses an unsigned decimal integer, rejecting signs, whitespace and overflow.
[[nodiscard]] Result<std::uint64_t> parse_u64(std::string_view text);

/// Parses a 0x-prefixed or bare hexadecimal unsigned integer.
[[nodiscard]] Result<std::uint64_t> parse_hex_u64(std::string_view text);

}  // namespace scp
