// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/text.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace scp {

namespace {

constexpr char kUpperHexDigits[] = "0123456789ABCDEF";

[[nodiscard]] constexpr bool is_ascii_space(char ch) noexcept {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\v' || ch == '\f' || ch == '\r';
}

[[nodiscard]] constexpr int hex_digit_value(char ch) noexcept {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  }
  return -1;
}

/// One decoded code point. length == 0 marks a byte position that does not
/// begin a well-formed UTF-8 sequence.
struct DecodedCodePoint {
  std::uint32_t value = 0;
  std::size_t length = 0;
};

/// Decodes the UTF-8 sequence starting at index, rejecting overlong encodings,
/// surrogates, code points above U+10FFFF, truncated sequences and stray
/// continuation bytes.
[[nodiscard]] DecodedCodePoint decode_code_point(std::string_view text, std::size_t index) noexcept {
  const std::uint8_t lead = static_cast<std::uint8_t>(text[index]);
  if (lead < 0x80U) {
    return DecodedCodePoint{lead, 1U};
  }

  std::size_t extra = 0;
  std::uint32_t value = 0;
  std::uint32_t minimum = 0;
  if ((lead & 0xE0U) == 0xC0U) {
    extra = 1U;
    value = static_cast<std::uint32_t>(lead & 0x1FU);
    minimum = 0x80U;
  } else if ((lead & 0xF0U) == 0xE0U) {
    extra = 2U;
    value = static_cast<std::uint32_t>(lead & 0x0FU);
    minimum = 0x800U;
  } else if ((lead & 0xF8U) == 0xF0U) {
    extra = 3U;
    value = static_cast<std::uint32_t>(lead & 0x07U);
    minimum = 0x10000U;
  } else {
    return DecodedCodePoint{};
  }

  if (text.size() - index - 1U < extra) {
    return DecodedCodePoint{};
  }
  for (std::size_t step = 1U; step <= extra; ++step) {
    const std::uint8_t continuation = static_cast<std::uint8_t>(text[index + step]);
    if ((continuation & 0xC0U) != 0x80U) {
      return DecodedCodePoint{};
    }
    value = (value << 6U) | static_cast<std::uint32_t>(continuation & 0x3FU);
  }

  if (value < minimum || value > 0x10FFFFU) {
    return DecodedCodePoint{};
  }
  if (value >= 0xD800U && value <= 0xDFFFU) {
    return DecodedCodePoint{};
  }
  return DecodedCodePoint{value, extra + 1U};
}

/// Appends \uXXXX, or \UXXXXXXXX for a code point outside the basic plane.
void append_unicode_escape(std::string& out, std::uint32_t code_point) {
  const int top_shift = code_point <= 0xFFFFU ? 12 : 28;
  out += code_point <= 0xFFFFU ? "\\u" : "\\U";
  for (int shift = top_shift; shift >= 0; shift -= 4) {
    const std::uint32_t nibble = (code_point >> static_cast<unsigned>(shift)) & 0x0FU;
    out.push_back(kUpperHexDigits[nibble]);
  }
}

/// Appends \xNN for a byte that is not part of a well-formed UTF-8 sequence.
void append_byte_escape(std::string& out, std::uint8_t byte) {
  out += "\\x";
  out.push_back(kUpperHexDigits[(byte >> 4U) & 0x0FU]);
  out.push_back(kUpperHexDigits[byte & 0x0FU]);
}

}  // namespace

Result<Name> Name::parse(std::string_view text) {
  if (text.empty()) {
    return fail(StatusCode::InvalidArgument, "name must not be empty");
  }
  if (text.size() > kMaxNameBytes) {
    return fail(StatusCode::InvalidArgument,
                "name is " + std::to_string(text.size()) + " bytes; the maximum is " +
                    std::to_string(kMaxNameBytes));
  }
  if (!is_valid_utf8(text)) {
    return fail(StatusCode::InvalidUnicode, "name is not well-formed UTF-8");
  }
  for (const char ch : text) {
    const std::uint8_t byte = static_cast<std::uint8_t>(ch);
    if (byte < 0x20U || byte == 0x7FU) {
      return fail(StatusCode::InvalidText, "name contains a control character");
    }
  }
  if (is_ascii_space(text.front()) || is_ascii_space(text.back())) {
    return fail(StatusCode::InvalidText, "name has leading or trailing whitespace");
  }

  Name name;
  name.text_.assign(text);
  return name;
}

bool is_valid_utf8(std::string_view text) noexcept {
  std::size_t index = 0;
  while (index < text.size()) {
    const DecodedCodePoint decoded = decode_code_point(text, index);
    if (decoded.length == 0U) {
      return false;
    }
    index += decoded.length;
  }
  return true;
}

bool is_printable_ascii(std::string_view text) noexcept {
  for (const char ch : text) {
    const std::uint8_t byte = static_cast<std::uint8_t>(ch);
    if (byte < 0x20U || byte > 0x7EU) {
      return false;
    }
  }
  return true;
}

std::string escape_for_display(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  std::size_t index = 0;
  while (index < text.size()) {
    const std::uint8_t byte = static_cast<std::uint8_t>(text[index]);
    if (byte >= 0x20U && byte <= 0x7EU) {
      if (byte == static_cast<std::uint8_t>('\\')) {
        out += "\\\\";
      } else {
        out.push_back(static_cast<char>(byte));
      }
      ++index;
      continue;
    }
    const DecodedCodePoint decoded = decode_code_point(text, index);
    if (decoded.length == 0U) {
      append_byte_escape(out, byte);
      ++index;
      continue;
    }
    append_unicode_escape(out, decoded.value);
    index += decoded.length;
  }
  return out;
}

bool ascii_iequals(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lhs.size(); ++index) {
    std::uint8_t left = static_cast<std::uint8_t>(lhs[index]);
    std::uint8_t right = static_cast<std::uint8_t>(rhs[index]);
    if (left >= static_cast<std::uint8_t>('A') && left <= static_cast<std::uint8_t>('Z')) {
      left = static_cast<std::uint8_t>(left + 32U);
    }
    if (right >= static_cast<std::uint8_t>('A') && right <= static_cast<std::uint8_t>('Z')) {
      right = static_cast<std::uint8_t>(right + 32U);
    }
    if (left != right) {
      return false;
    }
  }
  return true;
}

std::string_view trim_ascii(std::string_view text) noexcept {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && is_ascii_space(text[begin])) {
    ++begin;
  }
  while (end > begin && is_ascii_space(text[end - 1U])) {
    --end;
  }
  return text.substr(begin, end - begin);
}

std::vector<std::string_view> split_ascii(std::string_view text, char delimiter) {
  std::vector<std::string_view> fields;
  std::size_t start = 0;
  while (true) {
    const std::size_t position = text.find(delimiter, start);
    if (position == std::string_view::npos) {
      fields.push_back(text.substr(start));
      return fields;
    }
    fields.push_back(text.substr(start, position - start));
    start = position + 1U;
  }
}

Result<std::uint64_t> parse_u64(std::string_view text) {
  if (text.empty()) {
    return fail(StatusCode::InvalidArgument, "expected a decimal integer without sign or whitespace");
  }
  std::uint64_t value = 0;
  for (const char ch : text) {
    const std::uint8_t byte = static_cast<std::uint8_t>(ch);
    if (byte < static_cast<std::uint8_t>('0') || byte > static_cast<std::uint8_t>('9')) {
      return fail(StatusCode::InvalidArgument,
                  "expected only decimal digits, without sign or whitespace");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(byte - static_cast<std::uint8_t>('0'));
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
      return fail(StatusCode::Overflow, "decimal value does not fit in a uint64");
    }
    value = value * 10U + digit;
  }
  return value;
}

Result<std::uint64_t> parse_hex_u64(std::string_view text) {
  if (text.size() >= 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    text.remove_prefix(2U);
  }
  if (text.empty()) {
    return fail(StatusCode::InvalidArgument, "expected at least one hexadecimal digit");
  }
  if (text.size() > 16U) {
    return fail(StatusCode::Overflow, "hexadecimal value does not fit in a uint64");
  }
  std::uint64_t value = 0;
  for (const char ch : text) {
    const int digit = hex_digit_value(ch);
    if (digit < 0) {
      return fail(StatusCode::InvalidArgument, "expected only hexadecimal digits");
    }
    value = (value << 4U) | static_cast<std::uint64_t>(digit);
  }
  return value;
}

}  // namespace scp
