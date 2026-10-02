// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/ids.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace scp {

namespace {

constexpr std::string_view kIdentifierForm =
    "an identifier is 32 hexadecimal characters, optionally prefixed with 0x";

/// Golden-ratio increment of splitmix64, reused as the derivation step.
constexpr std::uint64_t kGoldenGamma = 0x9E3779B97F4A7C15ULL;

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

/// Writes the 16 lowercase hex digits of value, most significant first, into
/// out starting at offset.
void write_word_hex(std::uint64_t value, std::string& out, std::size_t offset) {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  for (std::size_t index = 0; index < 16U; ++index) {
    const unsigned shift = static_cast<unsigned>((15U - index) * 4U);
    const std::uint8_t nibble = static_cast<std::uint8_t>((value >> shift) & 0x0FU);
    out[offset + index] = kHexDigits[nibble];
  }
}

/// splitmix64 finalizer: spreads sequential inputs across the whole 64-bit
/// space so that identities derived from neighbouring seeds do not cluster.
[[nodiscard]] constexpr std::uint64_t splitmix64_finalize(std::uint64_t value) noexcept {
  value = (value ^ (value >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27U)) * 0x94D049BB133111EBULL;
  return value ^ (value >> 31U);
}

/// Derives the two words of an identity from a pair of source words. The low
/// word also absorbs the derived high word, so the two are not independent
/// functions of the same input.
[[nodiscard]] std::pair<std::uint64_t, std::uint64_t> mix_identity_words(std::uint64_t high,
                                                                        std::uint64_t low) noexcept {
  const std::uint64_t mixed_high = splitmix64_finalize(high);
  const std::uint64_t mixed_low = splitmix64_finalize(low + kGoldenGamma + mixed_high);
  return {mixed_high, mixed_low};
}

}  // namespace

template <class Tag>
std::string OpaqueId<Tag>::to_hex() const {
  std::string out(32U, '0');
  write_word_hex(high_, out, 0U);
  write_word_hex(low_, out, 16U);
  return out;
}

template <class Tag>
Result<OpaqueId<Tag>> OpaqueId<Tag>::parse(std::string_view text) {
  std::string_view digits = text;
  if (digits.size() >= 2U && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
    digits.remove_prefix(2U);
  }
  if (digits.size() != 32U) {
    return fail(StatusCode::InvalidIdentifier, "identifier has " + std::to_string(text.size()) +
                                                   " characters; " + std::string(kIdentifierForm));
  }
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  for (std::size_t index = 0; index < 32U; ++index) {
    const int digit = hex_digit_value(digits[index]);
    if (digit < 0) {
      return fail(StatusCode::InvalidIdentifier,
                  "identifier has a non-hexadecimal character at index " + std::to_string(index) +
                      "; " + std::string(kIdentifierForm));
    }
    if (index < 16U) {
      high = (high << 4U) | static_cast<std::uint64_t>(digit);
    } else {
      low = (low << 4U) | static_cast<std::uint64_t>(digit);
    }
  }
  return OpaqueId(high, low);
}

template <class Tag>
Result<Counter<Tag>> Counter<Tag>::next() const {
  if (value_ == std::numeric_limits<std::uint64_t>::max()) {
    return fail(StatusCode::Overflow, "counter cannot advance past its maximum value");
  }
  return Counter(value_ + 1U);
}

EvidenceId evidence_id_from(std::uint64_t high, std::uint64_t low) {
  const std::pair<std::uint64_t, std::uint64_t> words = mix_identity_words(high, low);
  return EvidenceId(words.first, words.second);
}

RequestId request_id_from(std::uint64_t high, std::uint64_t low) {
  const std::pair<std::uint64_t, std::uint64_t> words = mix_identity_words(high, low);
  return RequestId(words.first, words.second);
}

std::uint64_t DeterministicIdSource::next_word() noexcept {
  state_ += kGoldenGamma;
  return splitmix64_finalize(state_);
}

SiteId DeterministicIdSource::next_site() noexcept {
  const std::uint64_t high = next_word();
  const std::uint64_t low = next_word();
  return SiteId(high, low);
}

EvidenceId DeterministicIdSource::next_evidence() noexcept {
  const std::uint64_t high = next_word();
  const std::uint64_t low = next_word();
  return EvidenceId(high, low);
}

SourceInstanceId DeterministicIdSource::next_instance() noexcept {
  const std::uint64_t high = next_word();
  const std::uint64_t low = next_word();
  return SourceInstanceId(high, low);
}

RequestId DeterministicIdSource::next_request() noexcept {
  const std::uint64_t high = next_word();
  const std::uint64_t low = next_word();
  return RequestId(high, low);
}

PlanId DeterministicIdSource::next_plan() noexcept {
  const std::uint64_t high = next_word();
  const std::uint64_t low = next_word();
  return PlanId(high, low);
}

GrantId DeterministicIdSource::next_grant() noexcept {
  const std::uint64_t high = next_word();
  const std::uint64_t low = next_word();
  return GrantId(high, low);
}

SnapshotId DeterministicIdSource::next_snapshot() noexcept {
  const std::uint64_t high = next_word();
  const std::uint64_t low = next_word();
  return SnapshotId(high, low);
}

ObligationId DeterministicIdSource::next_obligation() noexcept {
  const std::uint64_t high = next_word();
  const std::uint64_t low = next_word();
  return ObligationId(high, low);
}

// Every identity and counter type the runtime uses is instantiated here, so the
// definitions above stay out of the header without becoming link errors.
template class OpaqueId<SiteIdTag>;
template class OpaqueId<SourceInstanceIdTag>;
template class OpaqueId<EvidenceIdTag>;
template class OpaqueId<SnapshotIdTag>;
template class OpaqueId<GrantIdTag>;
template class OpaqueId<RequestIdTag>;
template class OpaqueId<PlanIdTag>;
template class OpaqueId<ObligationIdTag>;
template class OpaqueId<ConstraintIdTag>;
template class OpaqueId<TransactionIdTag>;

template class Counter<SiteGenerationTag>;
template class Counter<FacilityStateGenerationTag>;
template class Counter<PolicyGenerationTag>;
template class Counter<CapacityGenerationTag>;
template class Counter<SourceGenerationTag>;
template class Counter<EpochTag>;
template class Counter<SequenceTag>;
template class Counter<JournalSequenceTag>;
template class Counter<RevisionTag>;

}  // namespace scp
