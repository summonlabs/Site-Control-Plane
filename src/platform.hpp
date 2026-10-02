// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "scp/status.hpp"

/// \file platform.hpp
/// Private host adapter for the durable layer.
///
/// Nothing above this header knows which operating system it runs on. The three
/// capabilities that genuinely differ are isolated here: an explicit device
/// flush, an atomic replace, and an exclusive advisory writer lock. Each is
/// implemented with the real platform primitive rather than approximated.

namespace scp::detail {

/// A file with explicit buffering and durability boundaries.
///
/// \c flush() pushes bytes from the C library buffer into the operating system.
/// \c sync() asks the device to make them durable. Only \c sync() completes a
/// durability boundary; the distinction is preserved in the API because the
/// runtime's commit protocol depends on it.
class File {
 public:
  File() = default;
  ~File();
  File(File&& other) noexcept;
  File& operator=(File&& other) noexcept;
  File(const File&) = delete;
  File& operator=(const File&) = delete;

  [[nodiscard]] static Result<File> open_append(const std::filesystem::path& path, bool create);
  [[nodiscard]] static Result<File> open_read(const std::filesystem::path& path);
  [[nodiscard]] static Result<File> open_truncate(const std::filesystem::path& path);

  [[nodiscard]] bool is_open() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

  [[nodiscard]] Status write_all(std::span<const std::uint8_t> bytes);
  [[nodiscard]] Result<std::size_t> read_at(std::uint64_t offset, std::span<std::uint8_t> buffer);
  [[nodiscard]] Status flush();
  [[nodiscard]] Status sync();
  [[nodiscard]] Status flush_and_sync();
  [[nodiscard]] Result<std::uint64_t> size();
  [[nodiscard]] Status truncate_to(std::uint64_t size);
  [[nodiscard]] Status close();
  [[nodiscard]] std::intptr_t native_handle() const noexcept;

 private:
  File(std::FILE* handle, std::filesystem::path path);
  std::FILE* handle_ = nullptr;
  std::filesystem::path path_;
};

/// Exclusive advisory lock on a lock file, held until the object is destroyed.
/// A second process attempting to take the same lock fails with WriterExists
/// instead of proceeding.
class WriterLock {
 public:
  WriterLock() = default;
  ~WriterLock();
  WriterLock(WriterLock&& other) noexcept;
  WriterLock& operator=(WriterLock&& other) noexcept;
  WriterLock(const WriterLock&) = delete;
  WriterLock& operator=(const WriterLock&) = delete;

  [[nodiscard]] static Result<WriterLock> acquire(const std::filesystem::path& path);
  [[nodiscard]] bool held() const noexcept { return held_; }
  [[nodiscard]] Status release();

 private:
  File file_;
  bool held_ = false;
};

[[nodiscard]] Status ensure_directory(const std::filesystem::path& path);
[[nodiscard]] Result<bool> path_exists(const std::filesystem::path& path);
[[nodiscard]] Status remove_file(const std::filesystem::path& path);
/// Atomically replaces \p target with \p temp. On success \p temp no longer exists.
[[nodiscard]] Status replace_file(const std::filesystem::path& temp,
                                  const std::filesystem::path& target);
[[nodiscard]] Result<std::uint64_t> size_of_file(const std::filesystem::path& path);
[[nodiscard]] Result<std::vector<std::uint8_t>> read_file(const std::filesystem::path& path,
                                                          std::uint64_t limit);
/// Writes \p bytes to \p temp, syncs it, then atomically replaces \p target.
[[nodiscard]] Status write_file_atomic(const std::filesystem::path& temp,
                                       const std::filesystem::path& target,
                                       std::span<const std::uint8_t> bytes);

}  // namespace scp::detail
