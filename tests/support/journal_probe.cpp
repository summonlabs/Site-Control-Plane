// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "journal_probe.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace scp_test {
namespace {

constexpr std::size_t kHeaderBytes = 80;
constexpr std::size_t kFrameHeaderBytes = 8;
constexpr std::size_t kFrameFixedBodyBytes = 56;

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 24U);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8U; ++index) {
    value |= static_cast<std::uint64_t>(bytes[offset + index]) << (8U * index);
  }
  return value;
}

Digest read_digest(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::array<std::uint8_t, scp::kDigestBytes> raw{};
  for (std::size_t index = 0; index < scp::kDigestBytes; ++index) {
    raw[index] = bytes[offset + index];
  }
  return scp::Digest(raw);
}

std::vector<std::uint8_t> read_all(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(stream),
                                   std::istreambuf_iterator<char>());
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (unsigned shift = 0; shift < 32U; shift += 8U) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64U; shift += 8U) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFULL));
  }
}

constexpr std::array<std::uint8_t, 8> kMagic = {'S', 'C', 'P', 'S', 'I', 'T', 'J', '1'};

}  // namespace

scp::Result<ProbeJournal> probe_journal(const std::filesystem::path& journal_path) {
  const std::vector<std::uint8_t> bytes = read_all(journal_path);
  if (bytes.size() < kHeaderBytes) {
    return scp::fail(scp::StatusCode::Truncated, "journal is shorter than its header");
  }
  if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
    return scp::fail(scp::StatusCode::Corrupt, "journal magic is not recognised");
  }
  const std::uint32_t stored_crc = read_u32(bytes, kHeaderBytes - 4);
  const std::uint32_t computed_crc =
      scp::crc32c(std::span<const std::uint8_t>(bytes.data(), kHeaderBytes - 4));
  if (stored_crc != computed_crc) {
    return scp::fail(scp::StatusCode::ChecksumMismatch, "journal header checksum does not match");
  }
  ProbeJournal journal;
  journal.size = bytes.size();
  journal.format_version = read_u32(bytes, 8);
  journal.base_sequence = read_u64(bytes, 36);
  journal.base_digest = read_digest(bytes, 44);

  std::uint64_t offset = kHeaderBytes;
  while (offset < bytes.size()) {
    if (bytes.size() - offset < kFrameHeaderBytes) {
      return scp::fail(scp::StatusCode::Truncated, "journal ends inside a frame header");
    }
    const std::uint32_t body_len = read_u32(bytes, static_cast<std::size_t>(offset));
    if (static_cast<std::uint64_t>(kFrameHeaderBytes) + body_len > bytes.size() - offset) {
      return scp::fail(scp::StatusCode::Truncated, "journal ends inside a frame body");
    }
    const std::uint32_t body_crc = read_u32(bytes, static_cast<std::size_t>(offset) + 4);
    const std::size_t body_at = static_cast<std::size_t>(offset) + kFrameHeaderBytes;
    const std::uint32_t actual_crc =
        scp::crc32c(std::span<const std::uint8_t>(bytes.data() + body_at, body_len));
    if (body_crc != actual_crc) {
      return scp::fail(scp::StatusCode::ChecksumMismatch, "journal frame checksum does not match");
    }
    if (body_len < kFrameFixedBodyBytes) {
      return scp::fail(scp::StatusCode::Corrupt,
                       "journal frame declares a body shorter than its fixed part");
    }
    const std::uint32_t payload_len = read_u32(bytes, body_at + 52);
    if (static_cast<std::uint64_t>(payload_len) + kFrameFixedBodyBytes != body_len) {
      return scp::fail(scp::StatusCode::Corrupt,
                       "journal frame payload length disagrees with its body size");
    }
    ProbeFrame frame;
    frame.offset = offset;
    frame.total_bytes = static_cast<std::uint64_t>(kFrameHeaderBytes) + body_len;
    frame.kind = bytes[body_at];
    frame.sequence = read_u64(bytes, body_at + 4);
    frame.previous_sequence = read_u64(bytes, body_at + 12);
    frame.previous_digest = read_digest(bytes, body_at + 20);
    frame.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(body_at + kFrameFixedBodyBytes),
                         bytes.begin() + static_cast<std::ptrdiff_t>(body_at + kFrameFixedBodyBytes +
                                                                     payload_len));
    frame.digest =
        scp::Digest::of(std::span<const std::uint8_t>(bytes.data() + static_cast<std::size_t>(offset),
                                                      static_cast<std::size_t>(frame.total_bytes)));
    journal.frames.push_back(std::move(frame));
    offset += journal.frames.back().total_bytes;
  }
  return journal;
}

std::uint64_t committed_sequence(const ProbeJournal& journal) {
  std::uint64_t sequence = journal.base_sequence;
  bool pending = false;
  for (const ProbeFrame& frame : journal.frames) {
    if (frame.kind == 1) {
      pending = true;
    } else if (frame.kind == 2 && pending) {
      sequence = frame.sequence;
      pending = false;
    }
  }
  return sequence;
}

scp::Status append_uncommitted_prepare(const std::filesystem::path& journal_path,
                                       const ProbeJournal& journal, std::uint64_t sequence,
                                       std::span<const std::uint8_t> payload) {
  std::uint64_t previous_sequence = journal.base_sequence;
  Digest previous_digest = journal.base_digest;
  if (!journal.frames.empty()) {
    previous_sequence = journal.frames.back().sequence;
    previous_digest = journal.frames.back().digest;
  }

  std::vector<std::uint8_t> body;
  body.push_back(1);  // TransactionPrepare
  body.push_back(0);
  body.push_back(1);
  body.push_back(0);
  put_u64(body, sequence);
  put_u64(body, previous_sequence);
  body.insert(body.end(), previous_digest.bytes().begin(), previous_digest.bytes().end());
  put_u32(body, static_cast<std::uint32_t>(payload.size()));
  body.insert(body.end(), payload.begin(), payload.end());

  std::vector<std::uint8_t> frame;
  put_u32(frame, static_cast<std::uint32_t>(body.size()));
  put_u32(frame, scp::crc32c(body));
  frame.insert(frame.end(), body.begin(), body.end());

  std::FILE* handle = std::fopen(journal_path.string().c_str(), "ab");
  if (handle == nullptr) {
    return scp::fail(scp::StatusCode::IoError, "cannot open the journal for the crash probe");
  }
  const std::size_t written = std::fwrite(frame.data(), 1, frame.size(), handle);
  if (written != frame.size()) {
    std::fclose(handle);
    return scp::fail(scp::StatusCode::IoError, "the crash probe could not write the prepare frame");
  }
  if (std::fflush(handle) != 0) {
    std::fclose(handle);
    return scp::fail(scp::StatusCode::IoError, "the crash probe could not flush the prepare frame");
  }
#if defined(_WIN32)
  if (_commit(_fileno(handle)) != 0) {
    std::fclose(handle);
    return scp::fail(scp::StatusCode::IoError, "the crash probe could not sync the prepare frame");
  }
#else
  if (fsync(fileno(handle)) != 0) {
    std::fclose(handle);
    return scp::fail(scp::StatusCode::IoError, "the crash probe could not sync the prepare frame");
  }
#endif
  if (std::fclose(handle) != 0) {
    return scp::fail(scp::StatusCode::IoError, "the crash probe could not close the journal");
  }
  return scp::Status{};
}

}  // namespace scp_test
