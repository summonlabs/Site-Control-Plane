// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/journal.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "platform.hpp"

namespace scp {
namespace {

constexpr std::array<std::uint8_t, 8> kJournalMagic = {'S', 'C', 'P', 'S', 'I', 'T', 'J', '1'};
constexpr std::array<std::uint8_t, 8> kSnapshotMagic = {'S', 'C', 'P', 'S', 'I', 'T', 'S', '1'};
constexpr std::uint32_t kContainerVersion = 1;
constexpr std::size_t kHeaderBytes = 80;
constexpr std::size_t kSnapshotHeaderBytes = 20;
/// The frame header is two length-and-checksum words; the body begins at byte 8.
constexpr std::size_t kFrameHeaderBytes = 8;
constexpr std::size_t kFrameFixedBodyBytes = 56;

const char* kJournalFileName = "journal.scp";
const char* kSnapshotFileName = "snapshot.scp";
const char* kLockFileName = "journal.lock";
const char* kJournalTempName = "journal.scp.tmp";
const char* kSnapshotTempName = "snapshot.scp.tmp";

/// The durability boundary reached by one successful commit, stated in the
/// operator report exactly as it is implemented.
const char* kDurabilityBoundary =
    "prepare and commit frames written, flushed to the operating system, synced to the device, "
    "re-read and chain-verified; the transaction is visible to recovery after this point";

struct Header {
  std::uint32_t format_version = kContainerVersion;
  SiteId site{};
  Timestamp created_at{};
  JournalSequence base_sequence{};
  Digest base_digest{};
};

struct Frame {
  JournalRecordKind kind = JournalRecordKind::TransactionPrepare;
  JournalSequence sequence{};
  JournalSequence previous_sequence{};
  Digest previous_digest{};
  std::vector<std::uint8_t> payload;
  std::uint64_t offset = 0;
  std::uint64_t total_bytes = 0;
  Digest digest{};
};

struct ScanResult {
  Header header;
  std::vector<Frame> frames;
  std::vector<JournalOperation> committed;
  std::uint64_t committed_end = kHeaderBytes;
  JournalSequence first_committed_sequence{};
  JournalSequence last_sequence{};
  Digest chain_digest{};
  bool torn_tail = false;
  bool uncommitted_tail = false;
  std::uint64_t damage_offset = 0;
  std::uint64_t discarded_operations = 0;
  std::uint64_t committed_transactions = 0;
};

/// Bytes a commit frame occupies: frame header, fixed body, and the prepare digest.
constexpr std::uint64_t kCommitFrameBytes =
    kFrameHeaderBytes + kFrameFixedBodyBytes + kDigestBytes;

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
  out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64U; shift += 8U) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFULL));
  }
}

void put_bytes(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

std::uint32_t get_u32(std::span<const std::uint8_t> bytes, std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 24U);
}

std::uint64_t get_u64(std::span<const std::uint8_t> bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8U; ++index) {
    value |= static_cast<std::uint64_t>(bytes[offset + index]) << (8U * index);
  }
  return value;
}

std::vector<std::uint8_t> encode_header(const Header& header) {
  std::vector<std::uint8_t> out;
  out.reserve(kHeaderBytes);
  put_bytes(out, kJournalMagic);
  put_u32(out, header.format_version);
  put_u64(out, header.site.high());
  put_u64(out, header.site.low());
  put_u64(out, static_cast<std::uint64_t>(header.created_at.nanos));
  put_u64(out, header.base_sequence.value());
  put_bytes(out, std::span<const std::uint8_t>(header.base_digest.bytes().data(), kDigestBytes));
  const std::uint32_t crc = crc32c(std::span<const std::uint8_t>(out.data(), out.size()));
  put_u32(out, crc);
  return out;
}

Status decode_header(std::span<const std::uint8_t> bytes, Header& header) {
  if (bytes.size() < kHeaderBytes) {
    return fail(StatusCode::Truncated, "journal is shorter than its header");
  }
  if (!std::equal(kJournalMagic.begin(), kJournalMagic.end(), bytes.begin())) {
    return fail(StatusCode::Corrupt, "journal magic is not recognised");
  }
  const std::uint32_t stored_crc = get_u32(bytes, kHeaderBytes - 4);
  const std::uint32_t computed_crc =
      crc32c(std::span<const std::uint8_t>(bytes.data(), kHeaderBytes - 4));
  if (stored_crc != computed_crc) {
    return fail(StatusCode::ChecksumMismatch, "journal header checksum does not match");
  }
  header.format_version = get_u32(bytes, 8);
  if (header.format_version != kContainerVersion) {
    return fail(StatusCode::UnsupportedFormatVersion,
                "journal format version " + std::to_string(header.format_version) +
                    " is not supported by this build (expected " +
                    std::to_string(kContainerVersion) + ")");
  }
  header.site = SiteId(get_u64(bytes, 12), get_u64(bytes, 20));
  header.created_at.nanos = static_cast<std::int64_t>(get_u64(bytes, 28));
  header.base_sequence = JournalSequence(get_u64(bytes, 36));
  std::array<std::uint8_t, kDigestBytes> digest{};
  std::copy(bytes.begin() + 44, bytes.begin() + 44 + static_cast<std::ptrdiff_t>(kDigestBytes),
            digest.begin());
  header.base_digest = Digest(digest);
  return Status{};
}

/// Appends the body of \p frame to \p body, which the caller sizes and checksums.
///
/// The body is appended into a caller-owned buffer rather than returned by
/// value. That is not a stylistic choice: returning it makes the frame encoder
/// build a temporary vector and copy it, and this toolchain's optimiser then
/// reports a spurious free-on-offset diagnostic for the temporary's destructor
/// at -O3. Building the frame in one buffer removes the temporary, so the
/// warning is fixed at its cause instead of being suppressed.
void append_frame_body(std::vector<std::uint8_t>& body, const Frame& frame) {
  body.push_back(static_cast<std::uint8_t>(frame.kind));
  body.push_back(0);  // reserved
  body.push_back(static_cast<std::uint8_t>(kContainerVersion & 0xFFU));
  body.push_back(static_cast<std::uint8_t>((kContainerVersion >> 8U) & 0xFFU));
  put_u64(body, frame.sequence.value());
  put_u64(body, frame.previous_sequence.value());
  put_bytes(body, std::span<const std::uint8_t>(frame.previous_digest.bytes().data(), kDigestBytes));
  put_u32(body, static_cast<std::uint32_t>(frame.payload.size()));
  put_bytes(body, frame.payload);
}

std::vector<std::uint8_t> encode_frame(const Frame& frame) {
  std::vector<std::uint8_t> out;
  out.reserve(kFrameHeaderBytes + kFrameFixedBodyBytes + frame.payload.size());
  put_u32(out, 0);  // body length, patched below
  put_u32(out, 0);  // body checksum, patched below
  const std::size_t body_at = out.size();
  append_frame_body(out, frame);
  const std::uint32_t body_length = static_cast<std::uint32_t>(out.size() - body_at);
  const std::uint32_t checksum =
      crc32c(std::span<const std::uint8_t>(out.data() + body_at, body_length));
  out[0] = static_cast<std::uint8_t>(body_length & 0xFFU);
  out[1] = static_cast<std::uint8_t>((body_length >> 8U) & 0xFFU);
  out[2] = static_cast<std::uint8_t>((body_length >> 16U) & 0xFFU);
  out[3] = static_cast<std::uint8_t>((body_length >> 24U) & 0xFFU);
  out[4] = static_cast<std::uint8_t>(checksum & 0xFFU);
  out[5] = static_cast<std::uint8_t>((checksum >> 8U) & 0xFFU);
  out[6] = static_cast<std::uint8_t>((checksum >> 16U) & 0xFFU);
  out[7] = static_cast<std::uint8_t>((checksum >> 24U) & 0xFFU);
  return out;
}

Status decode_frame(std::span<const std::uint8_t> header_and_body, Frame& frame) {
  const std::uint32_t body_len = get_u32(header_and_body, 0);
  const std::uint32_t stored_crc = get_u32(header_and_body, 4);
  if (body_len < kFrameFixedBodyBytes) {
    return fail(StatusCode::Corrupt, "journal frame declares a body shorter than its fixed part");
  }
  if (header_and_body.size() != kFrameHeaderBytes + body_len) {
    return fail(StatusCode::Truncated, "journal frame is shorter than it declares");
  }
  const std::span<const std::uint8_t> body = header_and_body.subspan(kFrameHeaderBytes);
  if (crc32c(body) != stored_crc) {
    return fail(StatusCode::ChecksumMismatch, "journal frame checksum does not match");
  }
  switch (body[0]) {
    case 1: frame.kind = JournalRecordKind::TransactionPrepare; break;
    case 2: frame.kind = JournalRecordKind::TransactionCommit; break;
    case 3: frame.kind = JournalRecordKind::Marker; break;
    default:
      return fail(StatusCode::Corrupt,
                  "journal frame kind " + std::to_string(body[0]) + " is not recognised");
  }
  const std::uint16_t body_version = static_cast<std::uint16_t>(
      static_cast<unsigned>(body[2]) | (static_cast<unsigned>(body[3]) << 8U));
  if (body_version != kContainerVersion) {
    return fail(StatusCode::UnsupportedFormatVersion,
                "journal frame version " + std::to_string(body_version) + " is not supported");
  }
  frame.sequence = JournalSequence(get_u64(body, 4));
  frame.previous_sequence = JournalSequence(get_u64(body, 12));
  std::array<std::uint8_t, kDigestBytes> digest{};
  std::copy(body.begin() + 20, body.begin() + 20 + static_cast<std::ptrdiff_t>(kDigestBytes),
            digest.begin());
  frame.previous_digest = Digest(digest);
  const std::uint32_t payload_len = get_u32(body, 52);
  if (static_cast<std::uint64_t>(payload_len) + kFrameFixedBodyBytes != body.size()) {
    return fail(StatusCode::Corrupt, "journal frame payload length disagrees with its body size");
  }
  frame.payload.assign(body.begin() + static_cast<std::ptrdiff_t>(kFrameFixedBodyBytes), body.end());
  return Status{};
}

Status build_scan(const std::vector<std::uint8_t>& bytes, ScanResult& scan, Status& damage,
                  bool& interior) {
  if (bytes.size() < kHeaderBytes) {
    damage = fail(StatusCode::Truncated, "journal is shorter than its header");
    interior = true;
    return damage;
  }
  SCP_TRY(decode_header(bytes, scan.header));

  const std::span<const std::uint8_t> all(bytes.data(), bytes.size());
  scan.chain_digest = scan.header.base_digest;
  scan.last_sequence = scan.header.base_sequence;
  std::uint64_t offset = kHeaderBytes;
  std::optional<Frame> pending;
  std::uint64_t pending_start = kHeaderBytes;

  while (offset < bytes.size()) {
    const std::uint64_t remaining = bytes.size() - offset;
    if (remaining < kFrameHeaderBytes) {
      scan.torn_tail = true;
      scan.damage_offset = offset;
      break;
    }
    const std::uint32_t body_len = get_u32(all, static_cast<std::size_t>(offset));
    if (body_len < kFrameFixedBodyBytes || body_len > kMaxFrameBodyBytes) {
      damage = fail(StatusCode::InteriorCorruption,
                    "journal frame at offset " + std::to_string(offset) +
                        " declares an impossible body length of " + std::to_string(body_len));
      interior = true;
      scan.damage_offset = offset;
      return damage;
    }
    const std::uint64_t total = static_cast<std::uint64_t>(kFrameHeaderBytes) + body_len;
    if (total > remaining) {
      // The frame does not physically fit: the write that produced it did not
      // complete. This is the only situation in which truncation is allowed.
      scan.torn_tail = true;
      scan.damage_offset = offset;
      break;
    }
    Frame frame;
    const Status decoded = decode_frame(all.subspan(static_cast<std::size_t>(offset),
                                                    static_cast<std::size_t>(total)),
                                        frame);
    if (!decoded.ok()) {
      // A frame that is fully present but fails its checksum is damage, not a
      // torn tail: it cannot be explained by an interrupted append.
      damage = fail(StatusCode::InteriorCorruption,
                    "journal frame at offset " + std::to_string(offset) + ": " + decoded.message());
      interior = true;
      scan.damage_offset = offset;
      return damage;
    }
    frame.offset = offset;
    frame.total_bytes = total;
    frame.digest = Digest::of(all.subspan(static_cast<std::size_t>(offset),
                                          static_cast<std::size_t>(total)));

    if (frame.previous_sequence.value() != scan.last_sequence.value() ||
        !(frame.previous_digest == scan.chain_digest)) {
      damage = fail(StatusCode::ChainBroken,
                    "journal frame at offset " + std::to_string(offset) +
                        " does not link to the previous committed frame");
      interior = true;
      scan.damage_offset = offset;
      return damage;
    }

    if (frame.kind == JournalRecordKind::TransactionPrepare) {
      if (pending.has_value()) {
        damage = fail(StatusCode::InteriorCorruption,
                      "journal frame at offset " + std::to_string(offset) +
                          " begins a transaction while another prepare is unresolved");
        interior = true;
        scan.damage_offset = offset;
        return damage;
      }
      pending = frame;
      pending_start = offset;
      scan.last_sequence = frame.sequence;
      scan.chain_digest = frame.digest;
      scan.frames.push_back(frame);
      offset += total;
      continue;
    }

    if (frame.kind == JournalRecordKind::TransactionCommit) {
      if (!pending.has_value()) {
        damage = fail(StatusCode::InteriorCorruption,
                      "journal frame at offset " + std::to_string(offset) +
                          " commits a transaction that was never prepared");
        interior = true;
        scan.damage_offset = offset;
        return damage;
      }
      if (frame.sequence.value() != pending->sequence.value()) {
        damage = fail(StatusCode::InteriorCorruption,
                      "journal commit at offset " + std::to_string(offset) +
                          " names a different transaction sequence than its prepare");
        interior = true;
        scan.damage_offset = offset;
        return damage;
      }
      if (frame.payload.size() != kDigestBytes) {
        damage = fail(StatusCode::Corrupt, "journal commit frame carries a malformed reference");
        interior = true;
        scan.damage_offset = offset;
        return damage;
      }
      std::array<std::uint8_t, kDigestBytes> reference{};
      std::copy(frame.payload.begin(), frame.payload.end(), reference.begin());
      if (!(Digest(reference) == pending->digest)) {
        damage = fail(StatusCode::ChainBroken,
                      "journal commit at offset " + std::to_string(offset) +
                          " does not reference its prepare frame");
        interior = true;
        scan.damage_offset = offset;
        return damage;
      }

      CanonicalReader reader(pending->payload);
      const Result<JournalTransaction> transaction = canonical_read_transaction(reader);
      if (!transaction.has_value()) {
        damage = fail(StatusCode::Corrupt, "journal transaction payload is malformed: " +
                                               transaction.status().message());
        interior = true;
        scan.damage_offset = offset;
        return damage;
      }
      const Status end = reader.expect_end();
      if (!end.ok()) {
        damage = fail(StatusCode::Corrupt, "journal transaction payload has trailing bytes");
        interior = true;
        scan.damage_offset = offset;
        return damage;
      }
      if (scan.committed_transactions == 0) {
        scan.first_committed_sequence = frame.sequence;
      }
      for (const JournalOperation& operation : transaction.value().operations) {
        scan.committed.push_back(operation);
      }
      scan.committed_transactions += 1;
      scan.last_sequence = frame.sequence;
      scan.chain_digest = frame.digest;
      scan.frames.push_back(frame);
      pending.reset();
      offset += total;
      scan.committed_end = offset;
      continue;
    }

    // Marker frame: chained, never replayed into state.
    scan.last_sequence = frame.sequence;
    scan.chain_digest = frame.digest;
    scan.frames.push_back(frame);
    offset += total;
    scan.committed_end = offset;
  }

  if (pending.has_value()) {
    scan.uncommitted_tail = true;
    scan.discarded_operations = 0;
    CanonicalReader reader(pending->payload);
    const Result<JournalTransaction> transaction = canonical_read_transaction(reader);
    if (transaction.has_value()) {
      scan.discarded_operations = transaction.value().operations.size();
    }
    if (pending_start < scan.committed_end) {
      scan.damage_offset = pending_start;
    }
    // Roll the chain back to the last committed frame.
    scan.frames.erase(std::remove_if(scan.frames.begin(), scan.frames.end(),
                                     [&scan](const Frame& frame) {
                                       return frame.offset >= scan.committed_end;
                                     }),
                      scan.frames.end());
    scan.chain_digest = scan.header.base_digest;
    scan.last_sequence = scan.header.base_sequence;
    for (const Frame& frame : scan.frames) {
      scan.chain_digest = frame.digest;
      scan.last_sequence = frame.sequence;
    }
  }
  return Status{};
}

}  // namespace

std::string_view to_string(JournalRecordKind kind) noexcept {
  switch (kind) {
    case JournalRecordKind::TransactionPrepare: return "transaction-prepare";
    case JournalRecordKind::TransactionCommit: return "transaction-commit";
    case JournalRecordKind::Marker: return "marker";
  }
  return "unknown-record";
}

std::string_view to_string(OperationKind kind) noexcept {
  switch (kind) {
    case OperationKind::IngestEvidence: return "ingest-evidence";
    case OperationKind::RetireEvidence: return "retire-evidence";
    case OperationKind::AdvanceSiteGeneration: return "advance-site-generation";
    case OperationKind::RecordPlan: return "record-plan";
    case OperationKind::RecordGrant: return "record-grant";
    case OperationKind::RecordPolicy: return "record-policy";
  }
  return "unknown-operation";
}

Status JournalOperation::validate() const {
  switch (kind) {
    case OperationKind::IngestEvidence:
    case OperationKind::RetireEvidence:
      return evidence.validate();
    case OperationKind::AdvanceSiteGeneration:
      if (site_generation.is_unset()) {
        return fail(StatusCode::InvalidArgument,
                    "generation advance operation carries no generation");
      }
      return Status{};
    case OperationKind::RecordPlan:
      return plan.validate();
    case OperationKind::RecordGrant:
      return grant.validate();
    case OperationKind::RecordPolicy:
      return policy.validate();
  }
  return fail(StatusCode::InvalidEnum,
              "journal operation kind " + std::to_string(static_cast<std::uint8_t>(kind)) +
                  " is not recognised");
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

struct Journal::Impl {
  JournalOptions options;
  detail::File file;
  detail::WriterLock lock;
  JournalSequence sequence{};
  Digest chain_digest{};
  std::uint64_t committed_end = kHeaderBytes;
  Header header;
  std::optional<JournalRecoveryReport> cached_recovery;
  bool open = false;
};

/// Reads the whole journal through the handle the journal already owns.
///
/// A second handle on the same file is unnecessary and, on Windows, one more
/// sharing mode to get wrong; the append handle can read because it is opened
/// for update. The write buffer is flushed first so that a read cannot miss
/// bytes that are still only in the C library buffer.
Result<std::vector<std::uint8_t>> Journal::read_through_handle() {
  if (impl_ == nullptr || !impl_->open) {
    return fail(StatusCode::NotOpen, "journal is not open");
  }
  SCP_TRY(impl_->file.flush());
  const Result<std::uint64_t> size = impl_->file.size();
  if (!size.has_value()) {
    return size.status();
  }
  if (size.value() > impl_->options.max_journal_bytes) {
    return fail(StatusCode::LimitExceeded,
                "the journal is " + std::to_string(size.value()) +
                    " bytes, above the configured bound of " +
                    std::to_string(impl_->options.max_journal_bytes));
  }
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.value()));
  if (bytes.empty()) {
    return bytes;
  }
  const Result<std::size_t> got = impl_->file.read_at(0, bytes);
  if (!got.has_value()) {
    return got.status();
  }
  if (got.value() != bytes.size()) {
    return fail(StatusCode::Truncated, "the journal shrank while it was being read");
  }
  return bytes;
}

Journal::Journal(Journal&& other) noexcept : impl_(other.impl_) { other.impl_ = nullptr; }

Journal& Journal::operator=(Journal&& other) noexcept {
  if (this != &other) {
    if (impl_ != nullptr) {
      const Status ignored = close();
      (void)ignored;
    }
    impl_ = other.impl_;
    other.impl_ = nullptr;
  }
  return *this;
}

Journal::~Journal() {
  if (impl_ != nullptr) {
    const Status ignored = close();
    (void)ignored;
  }
}

bool Journal::is_open() const noexcept { return impl_ != nullptr && impl_->open; }

const std::filesystem::path& Journal::directory() const noexcept {
  static const std::filesystem::path kEmpty;
  return impl_ == nullptr ? kEmpty : impl_->options.directory;
}

SiteId Journal::site() const noexcept { return impl_ == nullptr ? SiteId{} : impl_->options.site; }

JournalSequence Journal::sequence() const noexcept {
  return impl_ == nullptr ? JournalSequence{} : impl_->sequence;
}

Digest Journal::chain_digest() const noexcept {
  return impl_ == nullptr ? Digest{} : impl_->chain_digest;
}

std::uint64_t Journal::committed_bytes() const noexcept {
  return impl_ == nullptr ? 0 : impl_->committed_end;
}

std::uint64_t Journal::size_bytes() const {
  if (impl_ == nullptr) {
    return 0;
  }
  const Result<std::uint64_t> size = detail::size_of_file(impl_->options.directory / kJournalFileName);
  return size.has_value() ? size.value() : 0;
}

Result<Journal> Journal::open(const JournalOptions& options) {
  if (options.directory.empty()) {
    return fail(StatusCode::InvalidArgument, "journal directory is empty");
  }
  if (options.site.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "journal site identity is not set");
  }

  auto impl = std::make_unique<Impl>();
  impl->options = options;

  if (options.exclusive_writer) {
    Result<detail::WriterLock> lock =
        detail::WriterLock::acquire(options.directory / kLockFileName);
    if (!lock.has_value()) {
      return lock.status();
    }
    impl->lock = std::move(lock.value());
  }

  const std::filesystem::path journal_path = options.directory / kJournalFileName;
  const Result<bool> exists = detail::path_exists(journal_path);
  if (!exists.has_value()) {
    return exists.status();
  }
  if (!exists.value()) {
    if (!options.create_if_missing) {
      return fail(StatusCode::NotFound, "journal does not exist at " + journal_path.string());
    }
    Header header;
    header.site = options.site;
    impl->header = header;
    const std::vector<std::uint8_t> encoded = encode_header(header);
    Result<detail::File> created = detail::File::open_truncate(journal_path);
    if (!created.has_value()) {
      return created.status();
    }
    SCP_TRY(created.value().write_all(encoded));
    SCP_TRY(created.value().flush_and_sync());
    SCP_TRY(created.value().close());
  }

  Result<detail::File> file = detail::File::open_append(journal_path, true);
  if (!file.has_value()) {
    return file.status();
  }
  impl->file = std::move(file.value());
  impl->committed_end = kHeaderBytes;
  impl->open = true;

  auto journal = Journal();
  journal.impl_ = impl.release();

  const Result<JournalRecoveryReport> report = journal.recover();
  if (!report.has_value()) {
    const Status ignored = journal.close();
    (void)ignored;
    return report.status();
  }
  journal.impl_->cached_recovery = report.value();
  return journal;
}

Result<JournalRecoveryReport> Journal::recover() {
  if (impl_ == nullptr || !impl_->open) {
    return fail(StatusCode::NotOpen, "journal is not open");
  }
  if (impl_->cached_recovery.has_value()) {
    // open() already scanned and repaired the journal; the caller gets that
    // result rather than paying for a second scan of the same bytes.
    JournalRecoveryReport cached = std::move(impl_->cached_recovery.value());
    impl_->cached_recovery.reset();
    return cached;
  }
  const std::filesystem::path journal_path = impl_->options.directory / kJournalFileName;
  const Result<std::vector<std::uint8_t>> bytes = read_through_handle();
  if (!bytes.has_value()) {
    return bytes.status();
  }
  const std::uint64_t size = bytes.value().size();
  JournalRecoveryReport report;
  if (size == 0) {
    return fail(StatusCode::Truncated, "journal is empty; it has no header");
  }
  ScanResult scan;
  Status damage;
  bool interior = false;
  const Status built = build_scan(bytes.value(), scan, damage, interior);
  if (!built.ok()) {
    return built;
  }
  if (interior) {
    return damage;
  }
  if (!(scan.header.site == impl_->options.site)) {
    return fail(StatusCode::Conflict,
                "journal at " + journal_path.string() + " belongs to a different site");
  }

  if (scan.committed_end != size) {
    SCP_TRY(impl_->file.truncate_to(scan.committed_end));
    SCP_TRY(impl_->file.flush_and_sync());
  }
  impl_->header = scan.header;
  impl_->sequence = scan.last_sequence;
  impl_->chain_digest = scan.chain_digest;
  impl_->committed_end = scan.committed_end;

  report.clean = !scan.torn_tail && !scan.uncommitted_tail;
  report.truncated_torn_tail = scan.torn_tail;
  report.discarded_uncommitted_transaction = scan.uncommitted_tail;
  report.recovered_bytes = scan.committed_end;
  report.damage_offset = scan.damage_offset;
  report.first_sequence = scan.first_committed_sequence;
  report.last_sequence = scan.last_sequence;
  report.committed_transactions = scan.committed_transactions;
  report.replayed_operations = scan.committed.size();
  report.discarded_operations = scan.discarded_operations;
  report.chain_digest = scan.chain_digest;
  report.site_generation = SiteGeneration{};
  report.operations = scan.committed;

  // A snapshot, when present, is reported alongside the journal position so a
  // caller can see where the recovered accepted state was seeded from.
  const std::filesystem::path snapshot_path = impl_->options.directory / kSnapshotFileName;
  const Result<bool> snapshot_exists = detail::path_exists(snapshot_path);
  if (snapshot_exists.has_value() && snapshot_exists.value()) {
    const Result<JournalSnapshot> snapshot = read_snapshot();
    if (!snapshot.has_value()) {
      // A snapshot that exists but cannot be used is an integrity failure, not a
      // reason to carry on without it: silently ignoring it would drop every
      // piece of committed evidence the compaction retired behind it. An
      // operator who wants to proceed deletes the file deliberately.
      return fail(snapshot.status().code(),
                  "the snapshot file exists but cannot be used (" +
                      snapshot.status().message() +
                      "); refusing to recover, because ignoring it would silently drop committed "
                      "evidence");
    }
    report.loaded_snapshot = true;
    report.snapshot_sequence = snapshot.value().sequence;
    report.site_generation = snapshot.value().site_generation;
  }
  return report;
}

Result<JournalCommit> Journal::commit(const JournalTransaction& transaction) {
  if (impl_ == nullptr || !impl_->open) {
    return fail(StatusCode::NotOpen, "journal is not open");
  }
  if (transaction.id.is_nil()) {
    return fail(StatusCode::InvalidIdentifier, "transaction has no identity");
  }
  if (transaction.operations.empty()) {
    return fail(StatusCode::InvalidArgument, "transaction carries no operations");
  }
  if (transaction.operations.size() > impl_->options.max_operations_per_transaction) {
    return fail(StatusCode::LimitExceeded,
                "transaction carries " + std::to_string(transaction.operations.size()) +
                    " operations, above the configured bound of " +
                    std::to_string(impl_->options.max_operations_per_transaction));
  }
  for (const JournalOperation& operation : transaction.operations) {
    const Status valid = operation.validate();
    if (!valid.ok()) {
      return valid;
    }
  }

  const Result<JournalSequence> next = impl_->sequence.next();
  if (!next.has_value()) {
    return next.status();
  }

  CanonicalWriter writer;
  canonical_write(writer, transaction);
  const std::vector<std::uint8_t> payload = writer.take();

  Frame prepare;
  prepare.kind = JournalRecordKind::TransactionPrepare;
  prepare.sequence = next.value();
  prepare.previous_sequence = impl_->sequence;
  prepare.previous_digest = impl_->chain_digest;
  prepare.payload = payload;

  const std::vector<std::uint8_t> prepare_bytes = encode_frame(prepare);
  if (prepare_bytes.size() > kMaxFrameBodyBytes) {
    return fail(StatusCode::LimitExceeded,
                "transaction encodes to " + std::to_string(prepare_bytes.size()) +
                    " bytes, above the frame bound of " + std::to_string(kMaxFrameBodyBytes));
  }
  const std::uint64_t prepare_offset = impl_->committed_end;
  const std::uint64_t projected =
      prepare_offset + prepare_bytes.size() + kCommitFrameBytes;
  if (projected > impl_->options.max_journal_bytes) {
    return fail(StatusCode::LimitExceeded,
                "committing would grow the journal to " + std::to_string(projected) +
                    " bytes, above the configured bound of " +
                    std::to_string(impl_->options.max_journal_bytes) +
                    "; compact the journal deliberately");
  }

  // Phase 1: write the prepare frame and make it durable.
  Status status = impl_->file.write_all(prepare_bytes);
  if (!status.ok()) {
    return status;
  }
  status = impl_->file.flush_and_sync();
  if (!status.ok()) {
    return status;
  }

  // Verify by reading the frame back from the device-backed file.
  {
    std::vector<std::uint8_t> readback(prepare_bytes.size());
    const Result<std::size_t> got = impl_->file.read_at(prepare_offset, readback);
    if (!got.has_value()) {
      return got.status();
    }
    if (got.value() != readback.size() ||
        !std::equal(readback.begin(), readback.end(), prepare_bytes.begin())) {
      const Status ignored = impl_->file.truncate_to(impl_->committed_end);
      (void)ignored;
      return fail(StatusCode::ChecksumMismatch,
                  "the prepare frame did not read back as written; the transaction was retired "
                  "and is not visible to recovery");
    }
  }
  const Digest prepare_digest =
      Digest::of(std::span<const std::uint8_t>(prepare_bytes.data(), prepare_bytes.size()));

  // Phase 2: commit frame referencing exactly that prepare frame.
  Frame commit_frame;
  commit_frame.kind = JournalRecordKind::TransactionCommit;
  commit_frame.sequence = next.value();
  commit_frame.previous_sequence = next.value();
  commit_frame.previous_digest = prepare_digest;
  commit_frame.payload.assign(prepare_digest.bytes().begin(), prepare_digest.bytes().end());
  const std::vector<std::uint8_t> commit_bytes = encode_frame(commit_frame);

  status = impl_->file.write_all(commit_bytes);
  if (!status.ok()) {
    const Status ignored = impl_->file.truncate_to(impl_->committed_end);
    (void)ignored;
    return status;
  }
  status = impl_->file.flush_and_sync();
  if (!status.ok()) {
    const Status ignored = impl_->file.truncate_to(impl_->committed_end);
    (void)ignored;
    return status;
  }
  {
    const std::uint64_t commit_offset = prepare_offset + prepare_bytes.size();
    std::vector<std::uint8_t> readback(commit_bytes.size());
    const Result<std::size_t> got = impl_->file.read_at(commit_offset, readback);
    if (!got.has_value()) {
      return got.status();
    }
    if (got.value() != readback.size() ||
        !std::equal(readback.begin(), readback.end(), commit_bytes.begin())) {
      const Status ignored = impl_->file.truncate_to(impl_->committed_end);
      (void)ignored;
      return fail(StatusCode::ChecksumMismatch,
                  "the commit frame did not read back as written; the transaction was retired "
                  "and is not visible to recovery");
    }
  }

  impl_->sequence = next.value();
  impl_->chain_digest = Digest::of(std::span<const std::uint8_t>(commit_bytes.data(),
                                                                 commit_bytes.size()));
  impl_->committed_end = prepare_offset + prepare_bytes.size() + commit_bytes.size();

  JournalCommit outcome;
  outcome.id = transaction.id;
  outcome.sequence = impl_->sequence;
  outcome.operations = transaction.operations.size();
  outcome.bytes_written = prepare_bytes.size() + commit_bytes.size();
  outcome.commit_frame_digest = impl_->chain_digest;
  outcome.durability_boundary = kDurabilityBoundary;
  return outcome;
}

Result<JournalSnapshot> Journal::read_snapshot() const {
  if (impl_ == nullptr) {
    return fail(StatusCode::NotOpen, "journal is not open");
  }
  const std::filesystem::path path = impl_->options.directory / kSnapshotFileName;
  const Result<bool> exists = detail::path_exists(path);
  if (!exists.has_value()) {
    return exists.status();
  }
  if (!exists.value()) {
    return fail(StatusCode::NotFound, "no snapshot exists for this journal");
  }
  const Result<std::vector<std::uint8_t>> bytes = detail::read_file(path, kMaxSnapshotBytes);
  if (!bytes.has_value()) {
    return bytes.status();
  }
  if (bytes.value().size() < kSnapshotHeaderBytes) {
    return fail(StatusCode::Truncated, "snapshot is shorter than its header");
  }
  const std::span<const std::uint8_t> all(bytes.value().data(), bytes.value().size());
  if (!std::equal(kSnapshotMagic.begin(), kSnapshotMagic.end(), all.begin())) {
    return fail(StatusCode::Corrupt, "snapshot magic is not recognised");
  }
  const std::uint32_t version = get_u32(all, 8);
  if (version != kContainerVersion) {
    return fail(StatusCode::UnsupportedFormatVersion,
                "snapshot format version " + std::to_string(version) + " is not supported");
  }
  const std::uint32_t payload_len = get_u32(all, 12);
  const std::uint32_t payload_crc = get_u32(all, 16);
  if (static_cast<std::uint64_t>(payload_len) + kSnapshotHeaderBytes != bytes.value().size()) {
    return fail(StatusCode::Corrupt, "snapshot payload length disagrees with its file size");
  }
  const std::span<const std::uint8_t> payload = all.subspan(kSnapshotHeaderBytes);
  if (crc32c(payload) != payload_crc) {
    return fail(StatusCode::ChecksumMismatch, "snapshot payload checksum does not match");
  }
  CanonicalReader reader(payload);
  const Result<JournalSnapshot> snapshot = canonical_read_snapshot(reader);
  if (!snapshot.has_value()) {
    return snapshot.status();
  }
  const Status end = reader.expect_end();
  if (!end.ok()) {
    return fail(StatusCode::Corrupt, "snapshot payload has trailing bytes");
  }
  if (!(snapshot.value().site == impl_->options.site)) {
    return fail(StatusCode::Conflict, "snapshot belongs to a different site");
  }
  if (snapshot.value().sequence.value() > impl_->sequence.value()) {
    return fail(StatusCode::StaleGeneration,
                "snapshot covers journal position " +
                    std::to_string(snapshot.value().sequence.value()) +
                    " which is beyond the committed position " +
                    std::to_string(impl_->sequence.value()));
  }
  return snapshot;
}

Result<CompactionReport> Journal::compact(const JournalSnapshot& snapshot) {
  if (impl_ == nullptr || !impl_->open) {
    return fail(StatusCode::NotOpen, "journal is not open");
  }
  if (!(snapshot.site == impl_->options.site)) {
    return fail(StatusCode::Conflict, "snapshot names a different site than the journal");
  }
  if (snapshot.sequence.value() > impl_->sequence.value()) {
    return fail(StatusCode::StaleGeneration,
                "refusing to compact: the snapshot covers journal position " +
                    std::to_string(snapshot.sequence.value()) +
                    " beyond the committed position " + std::to_string(impl_->sequence.value()));
  }

  const std::filesystem::path journal_path = impl_->options.directory / kJournalFileName;
  const std::filesystem::path snapshot_path = impl_->options.directory / kSnapshotFileName;
  const Result<std::uint64_t> before = detail::size_of_file(journal_path);
  if (!before.has_value()) {
    return before.status();
  }
  const Result<std::vector<std::uint8_t>> raw = read_through_handle();
  if (!raw.has_value()) {
    return raw.status();
  }
  ScanResult scan;
  Status damage;
  bool interior = false;
  SCP_TRY(build_scan(raw.value(), scan, damage, interior));
  if (interior) {
    return damage;
  }

  // 1. Write the snapshot, flush it, verify it by reading it back.
  CanonicalWriter writer;
  canonical_write(writer, snapshot);
  const std::vector<std::uint8_t> payload = writer.take();
  std::vector<std::uint8_t> snapshot_bytes;
  snapshot_bytes.reserve(kSnapshotHeaderBytes + payload.size());
  put_bytes(snapshot_bytes, kSnapshotMagic);
  put_u32(snapshot_bytes, kContainerVersion);
  put_u32(snapshot_bytes, static_cast<std::uint32_t>(payload.size()));
  put_u32(snapshot_bytes, crc32c(payload));
  put_bytes(snapshot_bytes, payload);
  if (snapshot_bytes.size() > kMaxSnapshotBytes) {
    return fail(StatusCode::LimitExceeded, "snapshot exceeds the maximum snapshot size");
  }
  const std::filesystem::path snapshot_temp = impl_->options.directory / kSnapshotTempName;
  SCP_TRY(detail::write_file_atomic(snapshot_temp, snapshot_path, snapshot_bytes));

  // 2. Rewrite the journal keeping only frames beyond the snapshot position, and
  //    relinking them so the chain is continuous from the snapshot.
  Header header = impl_->header;
  header.base_sequence = snapshot.sequence;
  header.base_digest = snapshot.chain_digest;
  std::vector<std::uint8_t> rebuilt;
  const std::vector<std::uint8_t> header_bytes = encode_header(header);
  rebuilt.reserve(raw.value().size());
  put_bytes(rebuilt, header_bytes);

  std::uint64_t retired = 0;
  std::uint64_t retained = 0;
  JournalSequence previous_sequence = header.base_sequence;
  Digest previous_digest = header.base_digest;
  std::size_t index = 0;
  while (index < scan.frames.size()) {
    const Frame& frame = scan.frames[index];
    if (frame.sequence.value() <= snapshot.sequence.value()) {
      ++retired;
      ++index;
      continue;
    }
    // Relinking a prepare frame changes its bytes and therefore its digest, and
    // a commit frame carries that digest in its payload. The two are rewritten
    // together so the pair stays bound: rewriting them independently would
    // produce a journal whose own recovery reports a broken chain.
    if (frame.kind == JournalRecordKind::TransactionPrepare) {
      Frame rewritten_prepare = frame;
      rewritten_prepare.previous_sequence = previous_sequence;
      rewritten_prepare.previous_digest = previous_digest;
      const std::vector<std::uint8_t> prepare_bytes = encode_frame(rewritten_prepare);
      const Digest prepare_digest =
          Digest::of(std::span<const std::uint8_t>(prepare_bytes.data(), prepare_bytes.size()));
      put_bytes(rebuilt, prepare_bytes);
      previous_sequence = rewritten_prepare.sequence;
      previous_digest = prepare_digest;
      ++retained;

      if (index + 1 < scan.frames.size() &&
          scan.frames[index + 1].kind == JournalRecordKind::TransactionCommit) {
        Frame rewritten_commit = scan.frames[index + 1];
        rewritten_commit.sequence = rewritten_prepare.sequence;
        rewritten_commit.previous_sequence = rewritten_prepare.sequence;
        rewritten_commit.previous_digest = prepare_digest;
        rewritten_commit.payload.assign(prepare_digest.bytes().begin(),
                                        prepare_digest.bytes().end());
        const std::vector<std::uint8_t> commit_bytes = encode_frame(rewritten_commit);
        put_bytes(rebuilt, commit_bytes);
        previous_sequence = rewritten_commit.sequence;
        previous_digest =
            Digest::of(std::span<const std::uint8_t>(commit_bytes.data(), commit_bytes.size()));
        ++retained;
        index += 2;
        continue;
      }
      ++index;
      continue;
    }

    Frame rewritten = frame;
    rewritten.previous_sequence = previous_sequence;
    rewritten.previous_digest = previous_digest;
    const std::vector<std::uint8_t> bytes = encode_frame(rewritten);
    put_bytes(rebuilt, bytes);
    previous_sequence = rewritten.sequence;
    previous_digest = Digest::of(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    ++retained;
    ++index;
  }

  // The live append handle must be released before the journal file is replaced:
  // on Windows an open handle without delete sharing makes the replace fail, and
  // relying on that would turn a compaction into a silent no-op.
  SCP_TRY(impl_->file.close());
  const std::filesystem::path journal_temp = impl_->options.directory / kJournalTempName;
  const Status replaced = detail::write_file_atomic(journal_temp, journal_path, rebuilt);

  // 3. Reopen the append handle and verify the rewritten journal scans cleanly.
  Result<detail::File> reopened = detail::File::open_append(journal_path, true);
  if (!reopened.has_value()) {
    return reopened.status();
  }
  impl_->file = std::move(reopened.value());
  if (!replaced.ok()) {
    return replaced;
  }
  const Result<std::vector<std::uint8_t>> check = read_through_handle();
  if (!check.has_value()) {
    return check.status();
  }
  ScanResult verified;
  Status verify_damage;
  bool verify_interior = false;
  SCP_TRY(build_scan(check.value(), verified, verify_damage, verify_interior));
  if (verify_interior) {
    return verify_damage;
  }
  impl_->header = verified.header;
  impl_->sequence = verified.last_sequence;
  impl_->chain_digest = verified.chain_digest;
  impl_->committed_end = verified.committed_end;

  CompactionReport report;
  report.snapshot_sequence = snapshot.sequence;
  report.bytes_before = before.value();
  report.bytes_after = static_cast<std::uint64_t>(rebuilt.size());
  report.frames_retained = retained;
  report.frames_retired = retired;
  report.snapshot_written = true;
  report.journal_rewritten = true;
  return report;
}

Status Journal::close() {
  if (impl_ == nullptr) {
    return Status{};
  }
  impl_->open = false;
  Status first;
  const Status closed = impl_->file.close();
  if (!closed.ok()) {
    first = closed;
  }
  const Status unlocked = impl_->lock.release();
  if (!unlocked.ok() && first.ok()) {
    first = unlocked;
  }
  delete impl_;
  impl_ = nullptr;
  return first;
}

}  // namespace scp
