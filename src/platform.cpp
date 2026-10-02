// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "platform.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <system_error>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace scp::detail {
namespace {

std::string describe_errno(int error) {
  return std::error_code(error, std::generic_category()).message();
}

Status io_failure(const char* operation, const std::filesystem::path& path, int error) {
  return fail(StatusCode::IoError, std::string(operation) + " failed for " + path.string() + ": " +
                                       describe_errno(error));
}

int last_error() noexcept { return errno; }

#if defined(_WIN32)
/// Opens a file with explicit sharing and returns a C stream for it.
///
/// The C run-time's own fopen path on this toolchain refuses a second open of a
/// file the same process already holds, which makes the journal's own append
/// handle and its recovery read incompatible and makes a writer lock report a
/// permission error instead of "another writer holds this". Sharing read, write
/// and delete explicitly is what actually describes this program's intent, and
/// it is the same policy the POSIX implementation gets for free.
Result<std::FILE*> open_shared(const std::filesystem::path& path, DWORD access, DWORD creation,
                               int descriptor_flags, const char* mode) {
  const HANDLE handle =
      CreateFileW(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, creation, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    const std::string message = path.string() + ": win32 error " + std::to_string(error);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return fail(StatusCode::NotFound, "file does not exist: " + message);
    }
    if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) {
      return fail(StatusCode::PermissionDenied, message);
    }
    return fail(StatusCode::IoError, message);
  }
  const int descriptor = _open_osfhandle(reinterpret_cast<intptr_t>(handle), descriptor_flags);
  if (descriptor < 0) {
    CloseHandle(handle);
    return fail(StatusCode::IoError, "cannot adopt the handle for " + path.string());
  }
  std::FILE* stream = _fdopen(descriptor, mode);
  if (stream == nullptr) {
    _close(descriptor);
    return fail(StatusCode::IoError, "cannot open a stream for " + path.string());
  }
  return stream;
}
#endif

}  // namespace

File::File(std::FILE* handle, std::filesystem::path path)
    : handle_(handle), path_(std::move(path)) {}

File::~File() {
  if (handle_ != nullptr) {
    std::fclose(handle_);
    handle_ = nullptr;
  }
}

File::File(File&& other) noexcept
    : handle_(other.handle_), path_(std::move(other.path_)) {
  other.handle_ = nullptr;
}

File& File::operator=(File&& other) noexcept {
  if (this != &other) {
    if (handle_ != nullptr) {
      std::fclose(handle_);
    }
    handle_ = other.handle_;
    path_ = std::move(other.path_);
    other.handle_ = nullptr;
  }
  return *this;
}

Result<File> File::open_append(const std::filesystem::path& path, bool create) {
  std::FILE* handle = nullptr;
#if defined(_WIN32)
  {
    const Result<std::FILE*> opened =
        open_shared(path, GENERIC_READ | GENERIC_WRITE,
                    create ? OPEN_ALWAYS : OPEN_EXISTING, _O_BINARY | _O_RDWR | _O_APPEND,
                    create ? "ab+" : "r+b");
    if (!opened.has_value()) {
      return opened.status();
    }
    handle = opened.value();
  }
#else
  handle = std::fopen(path.c_str(), create ? "ab+" : "r+b");
#endif
  if (handle == nullptr) {
    const int failure = last_error();
    if (!create && failure == ENOENT) {
      return fail(StatusCode::NotFound, "journal file does not exist: " + path.string());
    }
    return io_failure("open for append", path, failure);
  }
  return File(handle, path);
}

Result<File> File::open_read(const std::filesystem::path& path) {
  std::FILE* handle = nullptr;
#if defined(_WIN32)
  {
    const Result<std::FILE*> opened =
        open_shared(path, GENERIC_READ, OPEN_EXISTING, _O_BINARY | _O_RDONLY, "rb");
    if (!opened.has_value()) {
      return opened.status();
    }
    handle = opened.value();
  }
#else
  handle = std::fopen(path.c_str(), "rb");
#endif
  if (handle == nullptr) {
    const int failure = last_error();
    if (failure == ENOENT) {
      return fail(StatusCode::NotFound, "file does not exist: " + path.string());
    }
    return io_failure("open for read", path, failure);
  }
  return File(handle, path);
}

Result<File> File::open_truncate(const std::filesystem::path& path) {
  std::FILE* handle = nullptr;
#if defined(_WIN32)
  {
    const Result<std::FILE*> opened =
        open_shared(path, GENERIC_READ | GENERIC_WRITE, CREATE_ALWAYS, _O_BINARY | _O_RDWR, "wb+");
    if (!opened.has_value()) {
      return opened.status();
    }
    handle = opened.value();
  }
#else
  handle = std::fopen(path.c_str(), "wb+");
#endif
  if (handle == nullptr) {
    return io_failure("open for write", path, last_error());
  }
  return File(handle, path);
}

Status File::write_all(std::span<const std::uint8_t> bytes) {
  if (handle_ == nullptr) {
    return fail(StatusCode::NotOpen, "write on a closed file: " + path_.string());
  }
  std::size_t written = 0;
  while (written < bytes.size()) {
    const std::size_t chunk = std::fwrite(bytes.data() + written, 1, bytes.size() - written, handle_);
    if (chunk == 0) {
      return io_failure("write", path_, last_error());
    }
    written += chunk;
  }
  return Status{};
}

Result<std::size_t> File::read_at(std::uint64_t offset, std::span<std::uint8_t> buffer) {
  if (handle_ == nullptr) {
    return fail(StatusCode::NotOpen, "read on a closed file: " + path_.string());
  }
#if defined(_WIN32)
  if (_fseeki64(handle_, static_cast<__int64>(offset), SEEK_SET) != 0) {
    return io_failure("seek", path_, last_error());
  }
#else
  if (fseeko(handle_, static_cast<off_t>(offset), SEEK_SET) != 0) {
    return io_failure("seek", path_, last_error());
  }
#endif
  if (buffer.empty()) {
    return std::size_t{0};
  }
  const std::size_t got = std::fread(buffer.data(), 1, buffer.size(), handle_);
  if (got < buffer.size() && std::ferror(handle_) != 0) {
    return io_failure("read", path_, last_error());
  }
  return got;
}

Status File::flush() {
  if (handle_ == nullptr) {
    return fail(StatusCode::NotOpen, "flush on a closed file: " + path_.string());
  }
  if (std::fflush(handle_) != 0) {
    return io_failure("flush", path_, last_error());
  }
  return Status{};
}

Status File::sync() {
  if (handle_ == nullptr) {
    return fail(StatusCode::NotOpen, "sync on a closed file: " + path_.string());
  }
#if defined(_WIN32)
  const int descriptor = _fileno(handle_);
  if (descriptor < 0) {
    return io_failure("fileno", path_, last_error());
  }
  if (_commit(descriptor) != 0) {
    return io_failure("commit", path_, last_error());
  }
  const intptr_t raw = _get_osfhandle(descriptor);
  if (raw == -1) {
    return io_failure("osfhandle", path_, last_error());
  }
  if (FlushFileBuffers(reinterpret_cast<HANDLE>(raw)) == 0) {
    return fail(StatusCode::IoError,
                "FlushFileBuffers failed for " + path_.string() + ": error " +
                    std::to_string(static_cast<unsigned long>(GetLastError())));
  }
  return Status{};
#else
  const int descriptor = fileno(handle_);
  if (descriptor < 0) {
    return io_failure("fileno", path_, last_error());
  }
  if (fsync(descriptor) != 0) {
    return io_failure("fsync", path_, last_error());
  }
  return Status{};
#endif
}

Status File::flush_and_sync() {
  SCP_TRY(flush());
  SCP_TRY(sync());
  return Status{};
}

Result<std::uint64_t> File::size() {
  if (handle_ == nullptr) {
    return fail(StatusCode::NotOpen, "size on a closed file: " + path_.string());
  }
  SCP_TRY(flush());
#if defined(_WIN32)
  struct _stat64 info {};
  const int descriptor = _fileno(handle_);
  if (descriptor < 0) {
    return io_failure("fileno", path_, last_error());
  }
  if (_fstat64(descriptor, &info) != 0) {
    return io_failure("fstat", path_, last_error());
  }
  return static_cast<std::uint64_t>(info.st_size);
#else
  struct stat info {};
  const int descriptor = fileno(handle_);
  if (descriptor < 0) {
    return io_failure("fileno", path_, last_error());
  }
  if (fstat(descriptor, &info) != 0) {
    return io_failure("fstat", path_, last_error());
  }
  return static_cast<std::uint64_t>(info.st_size);
#endif
}

Status File::truncate_to(std::uint64_t size_bytes) {
  if (handle_ == nullptr) {
    return fail(StatusCode::NotOpen, "truncate on a closed file: " + path_.string());
  }
  SCP_TRY(flush());
#if defined(_WIN32)
  const int descriptor = _fileno(handle_);
  if (descriptor < 0) {
    return io_failure("fileno", path_, last_error());
  }
  if (_chsize_s(descriptor, static_cast<__int64>(size_bytes)) != 0) {
    return io_failure("truncate", path_, last_error());
  }
  if (_fseeki64(handle_, static_cast<__int64>(size_bytes), SEEK_SET) != 0) {
    return io_failure("seek", path_, last_error());
  }
#else
  const int descriptor = fileno(handle_);
  if (descriptor < 0) {
    return io_failure("fileno", path_, last_error());
  }
  if (ftruncate(descriptor, static_cast<off_t>(size_bytes)) != 0) {
    return io_failure("truncate", path_, last_error());
  }
  if (fseeko(handle_, static_cast<off_t>(size_bytes), SEEK_SET) != 0) {
    return io_failure("seek", path_, last_error());
  }
#endif
  return Status{};
}

Status File::close() {
  if (handle_ == nullptr) {
    return Status{};
  }
  std::FILE* handle = handle_;
  handle_ = nullptr;
  if (std::fclose(handle) != 0) {
    return io_failure("close", path_, last_error());
  }
  return Status{};
}

std::intptr_t File::native_handle() const noexcept {
  if (handle_ == nullptr) {
    return -1;
  }
  const int descriptor = _fileno(handle_);
  if (descriptor < 0) {
    return -1;
  }
#if defined(_WIN32)
  // The writer lock needs the operating system handle, not the C run-time
  // descriptor: passing the descriptor to LockFileEx fails with
  // ERROR_INVALID_HANDLE, and the lock file would silently never be taken.
  return static_cast<std::intptr_t>(_get_osfhandle(descriptor));
#else
  return static_cast<std::intptr_t>(descriptor);
#endif
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

Status ensure_directory(const std::filesystem::path& path) {
  std::error_code error;
  if (std::filesystem::exists(path, error)) {
    if (error) {
      return fail(StatusCode::IoError, "cannot inspect " + path.string() + ": " + error.message());
    }
    if (!std::filesystem::is_directory(path, error) || error) {
      return fail(StatusCode::PathInvalid,
                  path.string() + " exists and is not a directory");
    }
    return Status{};
  }
  if (error) {
    return fail(StatusCode::IoError, "cannot inspect " + path.string() + ": " + error.message());
  }
  if (!std::filesystem::create_directories(path, error) || error) {
    return fail(StatusCode::IoError,
                "cannot create directory " + path.string() + ": " + error.message());
  }
  return Status{};
}

Result<bool> path_exists(const std::filesystem::path& path) {
  std::error_code error;
  const bool exists = std::filesystem::exists(path, error);
  if (error) {
    return fail(StatusCode::IoError, "cannot inspect " + path.string() + ": " + error.message());
  }
  return exists;
}

Status remove_file(const std::filesystem::path& path) {
  std::error_code error;
  if (!std::filesystem::remove(path, error)) {
    if (error) {
      return fail(StatusCode::IoError,
                  "cannot remove " + path.string() + ": " + error.message());
    }
    return Status{};
  }
  return Status{};
}

Status replace_file(const std::filesystem::path& temp, const std::filesystem::path& target) {
#if defined(_WIN32)
  if (MoveFileExW(temp.c_str(), target.c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    return fail(StatusCode::IoError,
                "atomic replace of " + target.string() + " failed: error " +
                    std::to_string(static_cast<unsigned long>(GetLastError())));
  }
  return Status{};
#else
  std::error_code error;
  std::filesystem::rename(temp, target, error);
  if (error) {
    return fail(StatusCode::IoError,
                "atomic replace of " + target.string() + " failed: " + error.message());
  }
  return Status{};
#endif
}

Result<std::uint64_t> size_of_file(const std::filesystem::path& path) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    return fail(StatusCode::IoError,
                "cannot size " + path.string() + ": " + error.message());
  }
  return static_cast<std::uint64_t>(size);
}

Result<std::vector<std::uint8_t>> read_file(const std::filesystem::path& path,
                                            std::uint64_t limit) {
  const Result<std::uint64_t> size = size_of_file(path);
  if (!size.has_value()) {
    return size.status();
  }
  if (size.value() > limit) {
    return fail(StatusCode::LimitExceeded,
                path.string() + " is " + std::to_string(size.value()) +
                    " bytes, above the accepted limit of " + std::to_string(limit));
  }
  Result<File> file = File::open_read(path);
  if (!file.has_value()) {
    return file.status();
  }
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.value()));
  if (bytes.empty()) {
    return bytes;
  }
  const Result<std::size_t> got = file.value().read_at(0, bytes);
  if (!got.has_value()) {
    return got.status();
  }
  if (got.value() != bytes.size()) {
    return fail(StatusCode::Truncated,
                path.string() + " shrank while it was being read");
  }
  return bytes;
}

Status write_file_atomic(const std::filesystem::path& temp, const std::filesystem::path& target,
                         std::span<const std::uint8_t> bytes) {
  SCP_TRY(remove_file(temp));
  Result<File> file = File::open_truncate(temp);
  if (!file.has_value()) {
    return file.status();
  }
  SCP_TRY(file.value().write_all(bytes));
  SCP_TRY(file.value().flush_and_sync());
  SCP_TRY(file.value().close());
  return replace_file(temp, target);
}

}  // namespace scp::detail
