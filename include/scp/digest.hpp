// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "scp/status.hpp"

/// \file digest.hpp
/// First-party SHA-256 and CRC-32C.
///
/// The runtime ships no third-party cryptography: the digest is used for
/// integrity, provenance chaining and deterministic content identity, not for
/// authentication of a remote peer. That distinction is documented in the
/// README rather than papered over.

namespace scp {

inline constexpr std::size_t kDigestBytes = 32;

/// SHA-256 over a byte sequence.
class Digest {
 public:
  constexpr Digest() noexcept = default;
  explicit constexpr Digest(std::array<std::uint8_t, kDigestBytes> bytes) noexcept
      : bytes_(bytes) {}

  [[nodiscard]] static Digest of(std::span<const std::uint8_t> bytes);
  [[nodiscard]] static Result<Digest> parse_hex(std::string_view text);

  [[nodiscard]] const std::array<std::uint8_t, kDigestBytes>& bytes() const noexcept {
    return bytes_;
  }
  [[nodiscard]] std::string to_hex() const;
  [[nodiscard]] bool is_zero() const noexcept;

  friend constexpr bool operator==(const Digest&, const Digest&) noexcept = default;

 private:
  std::array<std::uint8_t, kDigestBytes> bytes_{};
};

/// Incremental SHA-256 so large canonically-serialized records can be hashed
/// without a second copy.
class Sha256 {
 public:
  Sha256() noexcept { reset(); }
  void reset() noexcept;
  void update(std::span<const std::uint8_t> bytes) noexcept;
  void update(std::string_view text) noexcept;
  void update_byte(std::uint8_t value) noexcept;
  void update_u16_le(std::uint16_t value) noexcept;
  void update_u32_le(std::uint32_t value) noexcept;
  void update_u64_le(std::uint64_t value) noexcept;

  /// Finalizes. The object must be reset before reuse.
  [[nodiscard]] Digest finalize() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
};

/// CRC-32C (Castagnoli), used for cheap frame integrity in the durable layer.
[[nodiscard]] std::uint32_t crc32c(std::span<const std::uint8_t> bytes) noexcept;
[[nodiscard]] std::uint32_t crc32c_extend(std::uint32_t seed,
                                          std::span<const std::uint8_t> bytes) noexcept;

/// Lowercase hex encoding of arbitrary bytes.
[[nodiscard]] std::string to_hex(std::span<const std::uint8_t> bytes);
[[nodiscard]] Result<std::vector<std::uint8_t>> from_hex(std::string_view text);

}  // namespace scp
