// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

#include "scp/digest.hpp"
#include "scp/status.hpp"

/// \file journal_probe.hpp
/// An independent reader for the on-disk journal format.
///
/// The probe deliberately re-implements the framing rules from the format
/// documentation instead of calling the library's own reader. That is the point:
/// it can disagree with the library, so a test that uses it is checking the
/// bytes that actually reached the disk rather than checking the library against
/// itself. It is also how the crash tests append a prepare frame that is never
/// committed.

namespace scp_test {

// See the note in test_support.hpp: the directive is confined to the test
// harness so the probe can speak the library's vocabulary directly.
using namespace scp;

struct ProbeFrame {
  std::uint64_t offset = 0;
  std::uint64_t total_bytes = 0;
  std::uint8_t kind = 0;
  std::uint64_t sequence = 0;
  std::uint64_t previous_sequence = 0;
  Digest previous_digest{};
  Digest digest{};
  std::vector<std::uint8_t> payload;
};

struct ProbeJournal {
  std::uint32_t format_version = 0;
  std::uint64_t base_sequence = 0;
  Digest base_digest{};
  std::vector<ProbeFrame> frames;
  std::uint64_t size = 0;
};

/// Parses a journal file. Fails when the header or any frame is malformed, which
/// is itself an assertion the durability tests rely on.
[[nodiscard]] scp::Result<ProbeJournal> probe_journal(const std::filesystem::path& journal_path);

/// The highest transaction sequence that has a matching commit frame.
[[nodiscard]] std::uint64_t committed_sequence(const ProbeJournal& journal);

/// Appends a prepare frame for \p sequence carrying \p payload, linked to the
/// last frame of \p journal, flushes it to the device, and returns. No commit
/// frame is written, which is exactly the state a writer that dies between the
/// two phases leaves behind.
[[nodiscard]] scp::Status append_uncommitted_prepare(const std::filesystem::path& journal_path,
                                                     const ProbeJournal& journal,
                                                     std::uint64_t sequence,
                                                     std::span<const std::uint8_t> payload);

}  // namespace scp_test
