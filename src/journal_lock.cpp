// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "platform.hpp"

#include <string>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <sys/file.h>
#include <unistd.h>
#endif

/// \file journal_lock.cpp
/// Real operating-system writer exclusion for the durable directory.
///
/// The lock is an advisory lock held on an open handle for the lifetime of the
/// writer. It is released by the operating system even if the process dies, so a
/// crashed writer never leaves a permanently wedged site directory. A second
/// writer gets WriterExists rather than a corrupt journal.

namespace scp::detail {

WriterLock::~WriterLock() {
  if (held_) {
    const Status status = release();
    (void)status;
  }
}

WriterLock::WriterLock(WriterLock&& other) noexcept
    : file_(std::move(other.file_)), held_(other.held_) {
  other.held_ = false;
}

WriterLock& WriterLock::operator=(WriterLock&& other) noexcept {
  if (this != &other) {
    if (held_) {
      const Status status = release();
      (void)status;
    }
    file_ = std::move(other.file_);
    held_ = other.held_;
    other.held_ = false;
  }
  return *this;
}

Result<WriterLock> WriterLock::acquire(const std::filesystem::path& path) {
  Result<File> file = File::open_append(path, true);
  if (!file.has_value()) {
    return file.status();
  }
  const std::intptr_t descriptor = file.value().native_handle();
  if (descriptor < 0) {
    return fail(StatusCode::IoError, "writer lock file has no usable descriptor");
  }
#if defined(_WIN32)
  const HANDLE handle = reinterpret_cast<HANDLE>(descriptor);
  OVERLAPPED overlapped{};
  const BOOL locked =
      LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped);
  if (locked == 0) {
    const DWORD error = GetLastError();
    if (error == ERROR_LOCK_VIOLATION || error == ERROR_SHARING_VIOLATION) {
      return fail(StatusCode::WriterExists,
                  "another process holds the writer lock on " + path.string());
    }
    return fail(StatusCode::IoError,
                "cannot take the writer lock on " + path.string() + ": error " +
                    std::to_string(static_cast<unsigned long>(error)));
  }
#else
  const int handle = static_cast<int>(descriptor);
  if (flock(handle, LOCK_EX | LOCK_NB) != 0) {
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      return fail(StatusCode::WriterExists,
                  "another process holds the writer lock on " + path.string());
    }
    return fail(StatusCode::IoError,
                "cannot take the writer lock on " + path.string() + ": " +
                    std::error_code(errno, std::generic_category()).message());
  }
#endif
  WriterLock lock;
  lock.file_ = std::move(file.value());
  lock.held_ = true;
  return lock;
}

Status WriterLock::release() {
  if (!held_) {
    return Status{};
  }
  held_ = false;
  const std::intptr_t descriptor = file_.native_handle();
  if (descriptor >= 0) {
#if defined(_WIN32)
    const HANDLE handle = reinterpret_cast<HANDLE>(descriptor);
    OVERLAPPED overlapped{};
    if (UnlockFileEx(handle, 0, 1, 0, &overlapped) == 0) {
      // A failed unlock is reported, but the handle close below releases the
      // lock anyway, so this is not a correctness hazard.
      const DWORD error = GetLastError();
      const Status close_status = file_.close();
      (void)close_status;
      return fail(StatusCode::LockLost,
                  "unlocking the writer lock failed: error " +
                      std::to_string(static_cast<unsigned long>(error)));
    }
#else
    const int handle = static_cast<int>(descriptor);
    if (flock(handle, LOCK_UN) != 0) {
      const Status close_status = file_.close();
      (void)close_status;
      return fail(StatusCode::LockLost, "unlocking the writer lock failed");
    }
#endif
  }
  return file_.close();
}

}  // namespace scp::detail
