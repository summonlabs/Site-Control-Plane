// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "journal_probe.hpp"
#include "scp/journal.hpp"
#include "scp/runtime.hpp"
#include "test_support.hpp"

#if defined(_WIN32)
#include <cstdlib>
#include <process.h>
#else
#include <sys/wait.h>
#endif

/// \file test_multiprocess.cpp
/// Real independent operating-system processes.
///
/// Writer exclusion, crash-boundary and restart behaviour are claims about what
/// happens between processes, so they are tested between processes: this program
/// re-executes itself in a child mode, and the parent inspects the bytes the
/// child left behind. Nothing here is simulated in one address space.

namespace {

constexpr const char* kJournalName = "journal.scp";
constexpr int kWriterExistsExit = 3;
constexpr int kFailureExit = 4;

/// Runs a child command line and returns the child's exit code.
///
/// The command is assembled with a quoted program path so that a path containing
/// spaces would work. On Windows that interacts with a documented cmd.exe rule:
/// when a /c command line contains more than two quote characters, cmd strips
/// the first and the last one, which corrupts both the path and the final
/// argument. Wrapping the whole command in one more pair of quotes is the
/// documented remedy, and it is applied only on Windows because a POSIX shell
/// would treat the extra pair literally.
int run_child(const std::string& command) {
#if defined(_WIN32)
  const std::string wrapped = "\"" + command + "\"";
  return static_cast<int>(std::system(wrapped.c_str()));
#else
  return static_cast<int>(std::system(command.c_str()));
#endif
}

int exit_code_of(int system_result) {
#if defined(_WIN32)
  return system_result;
#else
  if (WIFEXITED(system_result)) {
    return WEXITSTATUS(system_result);
  }
  return -1;
#endif
}

std::string quoted(const std::string& text) { return "\"" + text + "\""; }

/// The absolute path of this executable.
///
/// argv[0] is not reliable: a launcher may pass a bare name, and the test would
/// then re-execute the wrong file and every child-mode case would silently test
/// nothing. On Windows the C run-time already knows the full path; on Linux the
/// kernel exposes it.
std::filesystem::path self_path(const char* argv0) {
#if defined(_WIN32)
  if (_pgmptr != nullptr) {
    std::error_code error;
    const std::filesystem::path from_run_time(_pgmptr);
    if (std::filesystem::exists(from_run_time, error) && !error) {
      return std::filesystem::absolute(from_run_time);
    }
  }
#else
  std::error_code link_error;
  const std::filesystem::path from_proc =
      std::filesystem::read_symlink("/proc/self/exe", link_error);
  if (!link_error && !from_proc.empty()) {
    return from_proc;
  }
#endif
  std::error_code error;
  const std::filesystem::path absolute = std::filesystem::absolute(argv0, error);
  return error ? std::filesystem::path(argv0) : absolute;
}

scp::JournalOptions journal_options_for(const std::filesystem::path& directory) {
  scp::JournalOptions options;
  options.directory = directory;
  options.site = scp_test::default_site();
  options.create_if_missing = true;
  options.exclusive_writer = true;
  return options;
}

scp::JournalTransaction generation_transaction(std::uint64_t index) {
  scp::JournalTransaction transaction;
  transaction.id = scp::TransactionId(0x4D00000000000000ULL + index, index);
  scp::JournalOperation operation;
  operation.kind = scp::OperationKind::AdvanceSiteGeneration;
  operation.site_generation = scp::SiteGeneration(index);
  transaction.operations.push_back(operation);
  return transaction;
}

// ---------------------------------------------------------------------------
// Child modes
// ---------------------------------------------------------------------------

int child_try_open(const std::filesystem::path& directory) {
  scp::RuntimeOptions options = scp_test::durable_runtime_options(directory);
  const auto runtime = scp::SiteControlPlane::open(options);
  if (runtime.has_value()) {
    return 0;
  }
  if (runtime.status().code() == scp::StatusCode::WriterExists) {
    std::cout << "child: refused, another writer holds the site directory\n";
    return kWriterExistsExit;
  }
  std::cerr << "child: unexpected failure: " << runtime.status().to_string() << "\n";
  return kFailureExit;
}

/// Commits \p count transactions and then terminates WITHOUT running any
/// destructor or releasing anything: the process is gone exactly as a crash
/// would leave it, and only the operating system cleans up.
int child_commit_and_die(const std::filesystem::path& directory, std::uint64_t count) {
  auto opened = scp::Journal::open(journal_options_for(directory));
  if (!opened.has_value()) {
    std::cerr << "child: " << opened.status().to_string() << "\n";
    return kFailureExit;
  }
  scp::Journal journal = std::move(opened.value());
  const std::uint64_t base = journal.sequence().value();
  for (std::uint64_t index = 1; index <= count; ++index) {
    const auto committed = journal.commit(generation_transaction(base + index));
    if (!committed.has_value()) {
      std::cerr << "child: " << committed.status().to_string() << "\n";
      return kFailureExit;
    }
  }
  std::cout.flush();
  std::_Exit(0);
}

/// Writes a prepare frame, makes it durable, and then dies before writing the
/// commit frame.
int child_prepare_and_die(const std::filesystem::path& directory) {
  {
    auto opened = scp::Journal::open(journal_options_for(directory));
    if (!opened.has_value()) {
      std::cerr << "child: " << opened.status().to_string() << "\n";
      return kFailureExit;
    }
    // Opening and closing establishes the lock file and a valid header.
    if (!opened.value().close().ok()) {
      return kFailureExit;
    }
  }
  const auto probe = scp_test::probe_journal(directory / kJournalName);
  if (!probe.has_value()) {
    std::cerr << "child: " << probe.status().to_string() << "\n";
    return kFailureExit;
  }
  const std::uint64_t next = scp_test::committed_sequence(probe.value()) + 1;
  const std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC};
  const scp::Status appended =
      scp_test::append_uncommitted_prepare(directory / kJournalName, probe.value(), next, payload);
  if (!appended.ok()) {
    std::cerr << "child: " << appended.to_string() << "\n";
    return kFailureExit;
  }
  std::cout.flush();
  std::_Exit(0);
}

/// Commits one transaction and then removes the last few bytes of the commit
/// frame, which is what an interrupted append looks like on disk.
int child_torn_and_die(const std::filesystem::path& directory) {
  {
    auto opened = scp::Journal::open(journal_options_for(directory));
    if (!opened.has_value()) {
      std::cerr << "child: " << opened.status().to_string() << "\n";
      return kFailureExit;
    }
    scp::Journal journal = std::move(opened.value());
    const std::uint64_t next = journal.sequence().value() + 1;
    const auto committed = journal.commit(generation_transaction(next));
    if (!committed.has_value()) {
      std::cerr << "child: " << committed.status().to_string() << "\n";
      return kFailureExit;
    }
    if (!journal.close().ok()) {
      return kFailureExit;
    }
  }
  std::error_code error;
  const std::filesystem::path journal_path = directory / kJournalName;
  const std::uintmax_t size = std::filesystem::file_size(journal_path, error);
  if (error || size < 8) {
    return kFailureExit;
  }
  std::filesystem::resize_file(journal_path, size - 6, error);
  if (error) {
    return kFailureExit;
  }
  std::cout.flush();
  std::_Exit(0);
}

}  // namespace

int main(int argc, char** argv) {
  const std::filesystem::path self = self_path(argv[0]);
  if (argc >= 3) {
    const std::string mode = argv[1];
    const std::filesystem::path directory = std::filesystem::path(argv[2]);
    if (mode == "--child-try-open") {
      return child_try_open(directory);
    }
    if (mode == "--child-commit-and-die") {
      const std::uint64_t count = argc >= 4 ? std::strtoull(argv[3], nullptr, 10) : 1;
      return child_commit_and_die(directory, count);
    }
    if (mode == "--child-prepare-and-die") {
      return child_prepare_and_die(directory);
    }
    if (mode == "--child-torn-and-die") {
      return child_torn_and_die(directory);
    }
  }

  scp_test::Context& context = scp_test::Context::instance();
  context.add_case("multiprocess_writer_exclusion", [&self]() {
    scp_test::TempDirectory temp("mp-lock");
    SCP_OPEN_RUNTIME(runtime, scp_test::durable_runtime_options(temp.path()));
    const std::string command =
        quoted(self.string()) + " --child-try-open " + quoted(temp.path().string());
    const int result = exit_code_of(run_child(command));
    if (result != kWriterExistsExit) {
      scp_test::Context::instance().note("command was: " + command);
    }
    SCP_CHECK_EQ(result, kWriterExistsExit);
    SCP_REQUIRE_STATUS_OK(runtime->close());
    // With the writer gone, the same child succeeds.
    const int after = exit_code_of(run_child(command));
    if (after != 0) {
      scp_test::Context::instance().note("command was: " + command);
    }
    SCP_CHECK_EQ(after, 0);
  });

  context.add_case("multiprocess_restart_sees_committed_transactions", [&self]() {
    scp_test::TempDirectory temp("mp-restart");
    const std::string command = quoted(self.string()) + " --child-commit-and-die " +
                                quoted(temp.path().string()) + " 3";
    SCP_CHECK_EQ(exit_code_of(run_child(command)), 0);
    {
      auto opened = scp::Journal::open(journal_options_for(temp.path()));
      SCP_REQUIRE_OK(opened);
      scp::Journal journal = std::move(opened.value());
      const auto recovery = journal.recover();
      SCP_REQUIRE_OK(recovery);
      SCP_CHECK(recovery.value().clean);
      SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{3});
      SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{3});
      SCP_REQUIRE_STATUS_OK(journal.close());
    }
    // Re-entering the child proves the recovered position is the real one: the
    // next transaction it writes continues from three.
    const std::string again = quoted(self.string()) + " --child-commit-and-die " +
                              quoted(temp.path().string()) + " 2";
    SCP_CHECK_EQ(exit_code_of(run_child(again)), 0);
    auto opened = scp::Journal::open(journal_options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    const auto recovery = journal.recover();
    SCP_REQUIRE_OK(recovery);
    SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{5});
    SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{5});
    SCP_REQUIRE_STATUS_OK(journal.close());
  });

  context.add_case("multiprocess_uncommitted_transaction_is_discarded", [&self]() {
    scp_test::TempDirectory temp("mp-uncommitted");
    const std::string seed = quoted(self.string()) + " --child-commit-and-die " +
                             quoted(temp.path().string()) + " 2";
    SCP_CHECK_EQ(exit_code_of(run_child(seed)), 0);

    const std::string prepare =
        quoted(self.string()) + " --child-prepare-and-die " + quoted(temp.path().string());
    SCP_CHECK_EQ(exit_code_of(run_child(prepare)), 0);

    auto opened = scp::Journal::open(journal_options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    const auto recovery = journal.recover();
    SCP_REQUIRE_OK(recovery);
    SCP_CHECK(!recovery.value().clean);
    SCP_CHECK(recovery.value().discarded_uncommitted_transaction);
    SCP_CHECK(!recovery.value().truncated_torn_tail);
    SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{2});
    SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{2});
    SCP_REQUIRE_STATUS_OK(journal.close());

    // The discarded prepare is gone, so the journal is clean on the next open.
    auto reopened = scp::Journal::open(journal_options_for(temp.path()));
    SCP_REQUIRE_OK(reopened);
    const auto second = reopened.value().recover();
    SCP_REQUIRE_OK(second);
    SCP_CHECK(second.value().clean);
    SCP_CHECK_EQ(second.value().committed_transactions, std::uint64_t{2});
    SCP_REQUIRE_STATUS_OK(reopened.value().close());
  });

  context.add_case("multiprocess_torn_tail_is_repaired", [&self]() {
    scp_test::TempDirectory temp("mp-torn");
    const std::string seed = quoted(self.string()) + " --child-commit-and-die " +
                             quoted(temp.path().string()) + " 1";
    SCP_CHECK_EQ(exit_code_of(run_child(seed)), 0);
    const std::string torn =
        quoted(self.string()) + " --child-torn-and-die " + quoted(temp.path().string());
    SCP_CHECK_EQ(exit_code_of(run_child(torn)), 0);

    auto opened = scp::Journal::open(journal_options_for(temp.path()));
    SCP_REQUIRE_OK(opened);
    scp::Journal journal = std::move(opened.value());
    const auto recovery = journal.recover();
    SCP_REQUIRE_OK(recovery);
    SCP_CHECK(!recovery.value().clean);
    SCP_CHECK(recovery.value().truncated_torn_tail);
    SCP_CHECK_EQ(recovery.value().committed_transactions, std::uint64_t{1});
    SCP_CHECK_EQ(journal.sequence().value(), std::uint64_t{1});
    SCP_REQUIRE_STATUS_OK(journal.close());
  });

  return context.run_all("test_multiprocess");
}
