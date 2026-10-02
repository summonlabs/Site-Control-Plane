// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "scp/composition.hpp"
#include "scp/evidence.hpp"
#include "scp/ids.hpp"
#include "scp/policy.hpp"
#include "scp/runtime.hpp"
#include "scp/time.hpp"

/// \file test_support.hpp
/// A minimal, dependency-free test harness plus shared fixtures.
///
/// Every check records a failure and continues; only an explicit REQUIRE stops
/// the current case. There are no timeouts anywhere in this suite: a hanging test
/// is a defect in the library, not something to kill.

namespace scp_test {

// The harness speaks the library's vocabulary directly. A using-directive is
// confined to this test-only namespace so that fixtures read as "SiteId" and
// "EvidenceRecord" rather than being qualified on every line; nothing in the
// shipped library depends on it.
using namespace scp;

struct Failure {
  std::string location;
  std::string message;
};

class Context {
 public:
  static Context& instance();

  void add_case(const std::string& name, std::function<void()> body);
  [[nodiscard]] int run_all(const char* suite);

  void check(bool condition, const char* expression, const char* file, int line);
  [[nodiscard]] bool require(bool condition, const char* expression, const char* file, int line);
  void note(const std::string& message);

  [[nodiscard]] std::uint64_t checks() const noexcept { return checks_; }
  [[nodiscard]] std::uint64_t failures() const noexcept { return failures_; }

 private:
  struct Case {
    std::string name;
    std::function<void()> body;
  };

  std::vector<Case> cases_;
  std::vector<Failure> current_failures_;
  std::string current_case_;
  std::uint64_t checks_ = 0;
  std::uint64_t failures_ = 0;
};

struct Registrar {
  Registrar(const char* name, std::function<void()> body);
};

/// A unique directory that removes itself, including on an early return.
class TempDirectory {
 public:
  explicit TempDirectory(const std::string& label);
  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;
  ~TempDirectory();

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
  [[nodiscard]] std::filesystem::path child(const std::string& name) const;

 private:
  std::filesystem::path path_;
};

/// Recursively copies a directory tree; used to damage a copy instead of the
/// original when a test deliberately corrupts durable state.
[[nodiscard]] bool copy_tree(const std::filesystem::path& from, const std::filesystem::path& to);

/// Reads a whole file as bytes.
[[nodiscard]] std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path);

/// Overwrites one byte of a file. Used by corruption tests.
[[nodiscard]] bool poke_byte(const std::filesystem::path& path, std::uint64_t offset,
                             std::uint8_t value);

/// Truncates a file to \p size bytes.
[[nodiscard]] bool truncate_file(const std::filesystem::path& path, std::uint64_t size);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A fixed, non-zero site identity used by most suites.
[[nodiscard]] SiteId default_site();

/// A fixed evidence-source instance identity derived from \p seed.
[[nodiscard]] SourceInstanceId instance_for(std::uint64_t seed);

/// A fixed timestamp: 2026-01-01T00:00:00Z in nanoseconds.
[[nodiscard]] Timestamp base_instant();
/// An instant \p seconds after base_instant().
[[nodiscard]] Timestamp instant_after(std::int64_t seconds);

/// Everything needed to build a valid evidence record, with no hidden defaults.
struct RecordSpec {
  SourceAuthority authority = SourceAuthority::FacilityStateLedger;
  std::uint64_t instance = 1;
  std::uint64_t epoch = 1;
  std::uint64_t generation = 1;
  std::uint64_t sequence = 1;
  Timestamp issued_at{};
  Timestamp valid_until{};
  EvidenceOrigin origin = EvidenceOrigin::Ingested;
};

/// Fills the provenance and builds the record. Fails only when the inputs are
/// themselves invalid; a test that wants a failure builds the record by hand.
[[nodiscard]] Result<EvidenceRecord> make_record(const RecordSpec& spec, EvidenceKind kind,
                                                 const EvidenceBody& body);

/// Convenience builders for one evidence kind each, all with valid defaults.
[[nodiscard]] Result<EvidenceRecord> make_facility_state(const RecordSpec& spec,
                                                         FacilityStateEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_lifecycle(const RecordSpec& spec, LifecycleEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_capacity(const RecordSpec& spec, CapacityEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_power(const RecordSpec& spec, ReadinessEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_cooling(const RecordSpec& spec, ReadinessEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_policy(const RecordSpec& spec, PolicyEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_incident(const RecordSpec& spec, IncidentEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_maintenance(const RecordSpec& spec,
                                                      MaintenanceEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_asi(const RecordSpec& spec, CapabilityEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_dfi(const RecordSpec& spec, CapabilityEvidence body);
[[nodiscard]] Result<EvidenceRecord> make_service_class(const RecordSpec& spec,
                                                        ServiceClassEvidence body);

/// A slice of the site that is entirely healthy: one accepted, fresh publication
/// for every evidence kind, from the owner of each kind.
[[nodiscard]] std::vector<EvidenceRecord> healthy_site_records(Timestamp issued_at,
                                                              std::uint64_t generation = 1);

/// The policy used by most suites: strict about evidence, permissive about
/// thresholds so that state transitions are driven by the evidence, not by
/// accidental defaults.
[[nodiscard]] SitePolicy strict_policy();

/// A policy with a fixed generation, for tests that compare policy digests.
[[nodiscard]] SitePolicy policy_with_generation(std::uint64_t generation);

/// Options for an in-memory runtime, so a test that is not about durability does
/// not touch the filesystem.
[[nodiscard]] RuntimeOptions memory_runtime_options(std::uint64_t policy_generation = 1);

/// Options for a durable runtime rooted at \p directory.
[[nodiscard]] RuntimeOptions durable_runtime_options(const std::filesystem::path& directory,
                                                     std::uint64_t policy_generation = 1);

/// Opens a runtime, failing the current case with a readable message when it
/// cannot be opened.
[[nodiscard]] std::unique_ptr<scp::SiteControlPlane> open_runtime(const RuntimeOptions& options,
                                                                 const char* file, int line);

}  // namespace scp_test

#define SCP_TEST(name)                                                                        \
  static void scp_test_body_##name();                                                         \
  static const ::scp_test::Registrar scp_test_registrar_##name(#name, &scp_test_body_##name); \
  static void scp_test_body_##name()

#define SCP_CHECK(expression) \
  ::scp_test::Context::instance().check((expression), #expression, __FILE__, __LINE__)

#define SCP_CHECK_EQ(lhs, rhs)                                                            \
  do {                                                                                    \
    const auto& scp_check_lhs = (lhs);                                                    \
    const auto& scp_check_rhs = (rhs);                                                    \
    ::scp_test::Context::instance().check(scp_check_lhs == scp_check_rhs,                 \
                                          #lhs " == " #rhs, __FILE__, __LINE__);          \
  } while (false)

#define SCP_CHECK_NE(lhs, rhs)                                                            \
  do {                                                                                    \
    const auto& scp_check_lhs = (lhs);                                                    \
    const auto& scp_check_rhs = (rhs);                                                    \
    ::scp_test::Context::instance().check(!(scp_check_lhs == scp_check_rhs),              \
                                          #lhs " != " #rhs, __FILE__, __LINE__);          \
  } while (false)

#define SCP_REQUIRE(expression)                                                              \
  do {                                                                                       \
    if (!::scp_test::Context::instance().require((expression), #expression, __FILE__,         \
                                                 __LINE__)) {                                 \
      return;                                                                                \
    }                                                                                        \
  } while (false)

/// Requires that a Result holds a value; on failure it records the status text.
#define SCP_REQUIRE_OK(result)                                                              \
  do {                                                                                      \
    auto&& scp_check_result = (result);                                                     \
    if (!scp_check_result.has_value()) {                                                    \
      ::scp_test::Context::instance().note(std::string(#result) + " failed: " +              \
                                           scp_check_result.status().to_string());          \
      ::scp_test::Context::instance().check(false, #result " is ok", __FILE__, __LINE__);    \
      return;                                                                               \
    }                                                                                       \
  } while (false)

/// Requires that a Status is ok. SCP_REQUIRE_OK is for Result<T>; a call that
/// returns a Status directly uses this one, so the two are never confused.
#define SCP_REQUIRE_STATUS_OK(status)                                                       \
  do {                                                                                      \
    auto&& scp_check_status = (status);                                                     \
    if (!scp_check_status.ok()) {                                                           \
      ::scp_test::Context::instance().note(std::string(#status) + " failed: " +             \
                                           scp_check_status.to_string());                   \
      ::scp_test::Context::instance().check(false, #status " is ok", __FILE__, __LINE__);    \
      return;                                                                               \
    }                                                                                       \
    ::scp_test::Context::instance().check(true, #status " is ok", __FILE__, __LINE__);       \
  } while (false)

/// Requires that a Status is an error with exactly this code.
#define SCP_REQUIRE_STATUS_ERROR(status, expected_code)                                     \
  do {                                                                                      \
    auto&& scp_check_status = (status);                                                     \
    if (scp_check_status.ok()) {                                                            \
      ::scp_test::Context::instance().check(false, #status " fails with " #expected_code,   \
                                             __FILE__, __LINE__);                            \
      return;                                                                               \
    }                                                                                       \
    if (scp_check_status.code() != (expected_code)) {                                       \
      ::scp_test::Context::instance().note(std::string(#status) + " reported " +            \
                                           scp_check_status.to_string());                   \
      ::scp_test::Context::instance().check(false, #status " fails with " #expected_code,   \
                                             __FILE__, __LINE__);                            \
      return;                                                                               \
    }                                                                                       \
    ::scp_test::Context::instance().check(true, #status " fails with " #expected_code,      \
                                           __FILE__, __LINE__);                             \
  } while (false)

/// Requires that a Result is an error with exactly this code.
#define SCP_REQUIRE_STATUS_ERROR(status, expected_code)                                        do {                                                                                            auto&& scp_check_status = (status);                                                           if (scp_check_status.ok()) {                                                                    ::scp_test::Context::instance().check(false, #status " fails with " #expected_code,                                                   __FILE__, __LINE__);                                    return;                                                                                      }                                                                                              if (scp_check_status.code() != (expected_code)) {                                                ::scp_test::Context::instance().note(std::string(#status) + " reported " +                                                          scp_check_status.to_string());                            ::scp_test::Context::instance().check(false, #status " fails with " #expected_code,                                                   __FILE__, __LINE__);                                    return;                                                                                      }                                                                                              ::scp_test::Context::instance().check(true, #status " fails with " #expected_code,                                                    __FILE__, __LINE__);                                 } while (false)
#define SCP_REQUIRE_STATUS_OK(status)                                                       do {                                                                                        auto&& scp_check_status = (status);                                                       if (!scp_check_status.ok()) {                                                               ::scp_test::Context::instance().note(std::string(#status) + " failed: " +                                                       scp_check_status.to_string());                        ::scp_test::Context::instance().check(false, #status " is ok", __FILE__, __LINE__);        return;                                                                                 }                                                                                         ::scp_test::Context::instance().check(true, #status " is ok", __FILE__, __LINE__);       } while (false)
#define SCP_REQUIRE_ERROR(result, expected_code)                                             \
  do {                                                                                       \
    auto&& scp_check_result = (result);                                                      \
    if (scp_check_result.has_value()) {                                                      \
      ::scp_test::Context::instance().check(false, #result " fails with " #expected_code,     \
                                             __FILE__, __LINE__);                             \
      return;                                                                                \
    }                                                                                        \
    if (scp_check_result.status().code() != (expected_code)) {                               \
      ::scp_test::Context::instance().note(std::string(#result) + " reported " +             \
                                           scp_check_result.status().to_string());           \
      ::scp_test::Context::instance().check(false, #result " fails with " #expected_code,     \
                                             __FILE__, __LINE__);                             \
      return;                                                                                \
    }                                                                                        \
    ::scp_test::Context::instance().check(true, #result " fails with " #expected_code,        \
                                           __FILE__, __LINE__);                              \
  } while (false)

#define SCP_TEST_MAIN(suite) int main() { return ::scp_test::Context::instance().run_all(suite); }

#define SCP_OPEN_RUNTIME(variable, options)                                     \
  auto scp_open_result = ::scp_test::open_runtime((options), __FILE__, __LINE__); \
  if (scp_open_result == nullptr) {                                             \
    return;                                                                     \
  }                                                                             \
  std::unique_ptr<scp::SiteControlPlane> variable = std::move(scp_open_result)
