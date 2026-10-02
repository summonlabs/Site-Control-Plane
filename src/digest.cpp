// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/digest.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace scp {

namespace {

constexpr char kLowerHexDigits[] = "0123456789abcdef";

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

[[nodiscard]] constexpr std::uint32_t rotate_right(std::uint32_t value,
                                                   unsigned distance) noexcept {
  return (value >> distance) | (value << (32U - distance));
}

/// The reflected Castagnoli table. It is constant-initialized, so there is no
/// lazy initialization and no guard variable to synchronise on.
[[nodiscard]] constexpr std::array<std::uint32_t, 256> make_crc32c_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t index = 0; index < 256U; ++index) {
    std::uint32_t remainder = index;
    for (int bit = 0; bit < 8; ++bit) {
      remainder = (remainder & 1U) != 0U ? ((remainder >> 1U) ^ 0x82F63B78U) : (remainder >> 1U);
    }
    table[index] = remainder;
  }
  return table;
}

constexpr std::array<std::uint32_t, 256> kCrc32cTable = make_crc32c_table();

}  // namespace

Digest Digest::of(std::span<const std::uint8_t> bytes) {
  Sha256 hasher;
  hasher.update(bytes);
  return hasher.finalize();
}

Result<Digest> Digest::parse_hex(std::string_view text) {
  if (text.size() != 2U * kDigestBytes) {
    return fail(StatusCode::InvalidIdentifier, "a digest is exactly 64 hexadecimal characters");
  }
  const Result<std::vector<std::uint8_t>> decoded = from_hex(text);
  if (!decoded.has_value()) {
    return fail(StatusCode::InvalidIdentifier, "a digest is exactly 64 hexadecimal characters");
  }
  std::array<std::uint8_t, kDigestBytes> bytes{};
  const std::vector<std::uint8_t>& source = decoded.value();
  for (std::size_t index = 0; index < kDigestBytes; ++index) {
    bytes[index] = source[index];
  }
  return Digest(bytes);
}

std::string Digest::to_hex() const {
  return scp::to_hex(std::span<const std::uint8_t>(bytes_.data(), bytes_.size()));
}

bool Digest::is_zero() const noexcept {
  return std::all_of(bytes_.begin(), bytes_.end(), [](std::uint8_t byte) { return byte == 0U; });
}

void Sha256::reset() noexcept {
  state_ = {0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
            0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U};
  buffer_.fill(0U);
  buffered_ = 0U;
  total_bytes_ = 0U;
}

void Sha256::update(std::span<const std::uint8_t> bytes) noexcept {
  total_bytes_ += static_cast<std::uint64_t>(bytes.size());
  std::size_t index = 0;

  if (buffered_ != 0U) {
    const std::size_t wanted = buffer_.size() - buffered_;
    const std::size_t taken = bytes.size() < wanted ? bytes.size() : wanted;
    for (std::size_t step = 0; step < taken; ++step) {
      buffer_[buffered_ + step] = bytes[step];
    }
    buffered_ += taken;
    index += taken;
    if (buffered_ == buffer_.size()) {
      compress(buffer_.data());
      buffered_ = 0U;
    }
  }

  while (bytes.size() - index >= buffer_.size()) {
    compress(bytes.data() + index);
    index += buffer_.size();
  }

  if (index < bytes.size()) {
    for (std::size_t step = index; step < bytes.size(); ++step) {
      buffer_[buffered_ + (step - index)] = bytes[step];
    }
    buffered_ = bytes.size() - index;
  }
}

void Sha256::update(std::string_view text) noexcept {
  update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                       text.size()));
}

void Sha256::update_byte(std::uint8_t value) noexcept {
  buffer_[buffered_] = value;
  ++buffered_;
  ++total_bytes_;
  if (buffered_ == buffer_.size()) {
    compress(buffer_.data());
    buffered_ = 0U;
  }
}

void Sha256::update_u16_le(std::uint16_t value) noexcept {
  update_byte(static_cast<std::uint8_t>(value & 0xFFU));
  update_byte(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void Sha256::update_u32_le(std::uint32_t value) noexcept {
  update_byte(static_cast<std::uint8_t>(value & 0xFFU));
  update_byte(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
  update_byte(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
  update_byte(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
}

void Sha256::update_u64_le(std::uint64_t value) noexcept {
  for (unsigned shift = 0; shift < 64U; shift += 8U) {
    update_byte(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

Digest Sha256::finalize() noexcept {
  const std::uint64_t bit_length = total_bytes_ * 8U;

  update_byte(0x80U);
  while (buffered_ != 56U) {
    update_byte(0x00U);
  }
  for (int shift = 56; shift >= 0; shift -= 8) {
    update_byte(static_cast<std::uint8_t>((bit_length >> static_cast<unsigned>(shift)) & 0xFFU));
  }

  std::array<std::uint8_t, kDigestBytes> digest_bytes{};
  for (std::size_t index = 0; index < 8U; ++index) {
    const std::uint32_t word = state_[index];
    digest_bytes[index * 4U] = static_cast<std::uint8_t>(word >> 24U);
    digest_bytes[index * 4U + 1U] = static_cast<std::uint8_t>((word >> 16U) & 0xFFU);
    digest_bytes[index * 4U + 2U] = static_cast<std::uint8_t>((word >> 8U) & 0xFFU);
    digest_bytes[index * 4U + 3U] = static_cast<std::uint8_t>(word & 0xFFU);
  }
  return Digest(digest_bytes);
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  static constexpr std::array<std::uint32_t, 64> kRoundConstants = {
      0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U,
      0xAB1C5ED5U, 0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U, 0x80DEB1FEU,
      0x9BDC06A7U, 0xC19BF174U, 0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU,
      0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU, 0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
      0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U, 0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU,
      0x53380D13U, 0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U, 0xA2BFE8A1U, 0xA81A664BU,
      0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U, 0x19A4C116U,
      0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
      0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U, 0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U,
      0xC67178F2U};

  std::uint32_t schedule[64];
  for (std::size_t index = 0; index < 16U; ++index) {
    const std::size_t base = index * 4U;
    schedule[index] = (static_cast<std::uint32_t>(block[base]) << 24U) |
                      (static_cast<std::uint32_t>(block[base + 1U]) << 16U) |
                      (static_cast<std::uint32_t>(block[base + 2U]) << 8U) |
                      static_cast<std::uint32_t>(block[base + 3U]);
  }
  for (std::size_t index = 16U; index < 64U; ++index) {
    const std::uint32_t previous = schedule[index - 15U];
    const std::uint32_t recent = schedule[index - 2U];
    const std::uint32_t sigma0 =
        rotate_right(previous, 7U) ^ rotate_right(previous, 18U) ^ (previous >> 3U);
    const std::uint32_t sigma1 =
        rotate_right(recent, 17U) ^ rotate_right(recent, 19U) ^ (recent >> 10U);
    schedule[index] = schedule[index - 16U] + sigma0 + schedule[index - 7U] + sigma1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < 64U; ++index) {
    const std::uint32_t sum1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^ rotate_right(e, 25U);
    const std::uint32_t choose = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + sum1 + choose + kRoundConstants[index] + schedule[index];
    const std::uint32_t sum0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^ rotate_right(a, 22U);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = sum0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

std::uint32_t crc32c_extend(std::uint32_t seed, std::span<const std::uint8_t> bytes) noexcept {
  std::uint32_t remainder = seed ^ 0xFFFFFFFFU;
  for (const std::uint8_t byte : bytes) {
    const std::uint32_t index = (remainder ^ static_cast<std::uint32_t>(byte)) & 0xFFU;
    remainder = kCrc32cTable[index] ^ (remainder >> 8U);
  }
  return remainder ^ 0xFFFFFFFFU;
}

std::uint32_t crc32c(std::span<const std::uint8_t> bytes) noexcept {
  return crc32c_extend(0U, bytes);
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
  std::string out;
  out.reserve(bytes.size() * 2U);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kLowerHexDigits[(byte >> 4U) & 0x0FU]);
    out.push_back(kLowerHexDigits[byte & 0x0FU]);
  }
  return out;
}

Result<std::vector<std::uint8_t>> from_hex(std::string_view text) {
  if (text.size() % 2U != 0U) {
    return fail(StatusCode::InvalidArgument, "hexadecimal text must have an even number of digits");
  }
  std::vector<std::uint8_t> bytes;
  bytes.reserve(text.size() / 2U);
  for (std::size_t index = 0; index < text.size(); index += 2U) {
    const int high = hex_digit_value(text[index]);
    const int low = hex_digit_value(text[index + 1U]);
    if (high < 0 || low < 0) {
      return fail(StatusCode::InvalidArgument,
                  "hexadecimal text contains a character that is not a hex digit");
    }
    bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return bytes;
}

}  // namespace scp
