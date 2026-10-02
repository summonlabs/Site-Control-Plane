// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "journal_probe.hpp"
#include "test_support.hpp"

/// \file test_cli.cpp
/// The CLI is a real program, so it is tested as one: the suite runs the built
/// executable as a separate operating-system process and asserts on its exit
/// code and its actual output. Nothing here calls into the library directly.

namespace {

#if !defined(SCP_TOOL_PATH) && !defined(SCP_TOOL_PATH_FROM_ENVIRONMENT)
#error "define SCP_TOOL_PATH, or define SCP_TOOL_PATH_FROM_ENVIRONMENT and set SCP_TOOL_PATH"
#endif

/// The tool under test. The environment variable wins so a harness can point the
/// suite at a freshly installed copy without a rebuild, which is also how the
/// suite is run on hosts whose command line cannot carry a quoted -D value.
const std::string& tool_path() {
  static const std::string path = []() {
    const char* from_environment = std::getenv("SCP_TOOL_PATH");
    if (from_environment != nullptr && from_environment[0] != '\0') {
      return std::string(from_environment);
    }
#if defined(SCP_TOOL_PATH)
    return std::string(SCP_TOOL_PATH);
#else
    return std::string();
#endif
  }();
  return path;
}

struct ToolResult {
  int exit_code = -1;
  std::string output;
};

std::string quoted(const std::string& text) { return "\"" + text + "\""; }

/// Runs the tool with \p arguments, capturing stdout and stderr together.
ToolResult run_tool(const std::string& arguments, const std::filesystem::path& working_directory,
                    const std::filesystem::path& capture) {
  std::error_code error;
  std::filesystem::remove(capture, error);
  // The command begins with a directory change, so cmd.exe's rule about a
  // leading quote never applies and no extra quoting is needed: a quoted program
  // path followed by quoted arguments is passed through intact.
  const std::string command =
      quoted(tool_path()) + " " + arguments + " > " + quoted(capture.string()) + " 2>&1";
  ToolResult result;
  const std::string with_directory =
#if defined(_WIN32)
      "cd /d " + quoted(working_directory.string()) + " && " + command;
#else
      "cd " + quoted(working_directory.string()) + " && " + command;
#endif
  result.exit_code = static_cast<int>(std::system(with_directory.c_str()));
#if !defined(_WIN32)
  if (result.exit_code != -1) {
    result.exit_code = (result.exit_code >> 8) & 0xFF;
  }
#endif
  // Read with an explicit buffer rather than an istreambuf_iterator: the
  // iterator form trips a known false positive in this toolchain's library
  // headers under -Wnull-dereference, and fixing the cause is better than
  // suppressing the warning for the whole translation unit.
  std::ifstream stream(capture, std::ios::binary);
  if (stream) {
    char buffer[4096];
    for (;;) {
      stream.read(buffer, static_cast<std::streamsize>(sizeof(buffer)));
      const std::streamsize got = stream.gcount();
      if (got > 0) {
        result.output.append(buffer, static_cast<std::size_t>(got));
      }
      if (got < static_cast<std::streamsize>(sizeof(buffer))) {
        break;
      }
    }
  }
  return result;
}

bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

/// A complete, healthy site: one block per owning runtime.
std::string healthy_script() {
  const std::string header =
      "instance 1a2b3c4d0000000b0000000000000001\n"
      "epoch 1\n"
      "generation 1\n"
      "sequence 1\n"
      "issued-at 2026-01-01T00:00:00Z\n";
  std::string script;
  const auto block = [&script, &header](const std::string& body) {
    script += body + header + "\n";
  };
  block("kind facility-state\n"
        "worst-severity none\n"
        "active-incidents 0\n"
        "degraded-operation false\n"
        "emergency-declared false\n");
  block("kind lifecycle\n"
        "state active\n"
        "transition-in-progress false\n");
  block("kind capacity\n"
        "total-units 100\n"
        "committed-units 20\n"
        "available-units 80\n"
        "oversubscribed false\n");
  block("kind power-readiness\n"
        "readiness ready\n"
        "headroom-milli-kw 5000000\n"
        "available-domains 2\n"
        "required-domains 2\n");
  block("kind cooling-readiness\n"
        "readiness ready\n"
        "headroom-milli-kw 4000000\n"
        "available-domains 2\n"
        "required-domains 2\n");
  block("kind policy\n"
        "rule-count 3\n");
  block("kind incident\n"
        "active-incidents 0\n"
        "worst-severity none\n"
        "emergency-declared false\n"
        "suppressed-incidents 0\n");
  block("kind maintenance\n"
        "mode none\n"
        "active-windows 0\n"
        "scheduled-windows 0\n"
        "drain-in-progress false\n"
        "drained-percent 0\n");
  block("kind asi-capability\n"
        "readiness ready\n"
        "ready-domains 8\n"
        "total-domains 8\n"
        "ready-units 512\n");
  block("kind dfi-capability\n"
        "readiness ready\n"
        "ready-domains 4\n"
        "total-domains 4\n"
        "ready-units 256\n");
  block("kind service-class\n"
        "class-count 1\n"
        "obligation interactive-inference true 16 50\n");
  return script;
}

void write_text(const std::filesystem::path& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream << text;
}

constexpr const char* kSite = "5c7b0a4d000000010000000000000001";

}  // namespace

SCP_TEST(cli_version_and_help) {
  scp_test::TempDirectory temp("cli-version");
  const ToolResult version = run_tool("version", temp.path(), temp.child("out.txt"));
  SCP_CHECK_EQ(version.exit_code, 0);
  SCP_CHECK(contains(version.output, "scpctl"));
  SCP_CHECK(contains(version.output, "1.0.0"));

  const ToolResult help = run_tool("help", temp.path(), temp.child("help.txt"));
  SCP_CHECK_EQ(help.exit_code, 0);
  SCP_CHECK(contains(help.output, "Usage: scpctl"));
  SCP_CHECK(contains(help.output, "Evidence script format"));
}

SCP_TEST(cli_rejects_bad_usage_with_exit_two) {
  scp_test::TempDirectory temp("cli-usage");
  const ToolResult unknown = run_tool("nonsense-command", temp.path(), temp.child("a.txt"));
  SCP_CHECK_EQ(unknown.exit_code, 2);
  SCP_CHECK(contains(unknown.output, "scpctl:"));

  const ToolResult missing = run_tool("status", temp.path(), temp.child("b.txt"));
  SCP_CHECK_EQ(missing.exit_code, 2);

  const ToolResult bad_intent =
      run_tool("plan --dir " + quoted(temp.path().string()) + " --intent not-an-intent",
               temp.path(), temp.child("c.txt"));
  SCP_CHECK_EQ(bad_intent.exit_code, 2);

  const ToolResult bad_policy =
      run_tool("status --dir " + quoted(temp.path().string()) +
                   " --capacity-headroom-constrained-percent not-a-number",
               temp.path(), temp.child("d.txt"));
  SCP_CHECK_EQ(bad_policy.exit_code, 2);
}

SCP_TEST(cli_composes_a_snapshot_without_durable_state) {
  scp_test::TempDirectory temp("cli-compose");
  const std::filesystem::path script = temp.child("site.evidence");
  write_text(script, healthy_script());

  const ToolResult composed = run_tool("compose --evidence " + quoted(script.string()) +
                                           " --site " + kSite + " --at 2026-01-01T00:00:00Z",
                                       temp.path(), temp.child("compose.txt"));
  SCP_CHECK_EQ(composed.exit_code, 0);
  SCP_CHECK(contains(composed.output, "available"));
  SCP_CHECK(contains(composed.output, "complete"));
  // Composition is pure, so it must not have created any durable state.
  SCP_CHECK(!std::filesystem::exists(temp.path() / "journal.scp"));
}

SCP_TEST(cli_apply_status_explain_and_verify_round_trip) {
  scp_test::TempDirectory temp("cli-roundtrip");
  const std::filesystem::path script = temp.child("site.evidence");
  const std::filesystem::path site = temp.child("site");
  std::filesystem::create_directories(site);
  write_text(script, healthy_script());
  const std::string directory = quoted(site.string());
  const std::string at = " --at 2026-01-01T00:00:00Z";

  const ToolResult applied =
      run_tool("apply --dir " + directory + " --evidence " + quoted(script.string()) + at,
               temp.path(), temp.child("apply.txt"));
  SCP_CHECK_EQ(applied.exit_code, 0);
  SCP_CHECK(contains(applied.output, "available"));
  SCP_CHECK(std::filesystem::exists(site / "journal.scp"));

  const ToolResult status = run_tool("status --dir " + directory + at, temp.path(),
                                     temp.child("status.txt"));
  SCP_CHECK_EQ(status.exit_code, 0);
  SCP_CHECK(contains(status.output, "available"));

  const ToolResult explained = run_tool("explain --dir " + directory + at, temp.path(),
                                        temp.child("explain.txt"));
  SCP_CHECK_EQ(explained.exit_code, 0);
  SCP_CHECK(contains(explained.output, "slots:"));
  SCP_CHECK(contains(explained.output, "gates:"));
  SCP_CHECK(contains(explained.output, "derivation:"));

  const ToolResult verified =
      run_tool("verify --dir " + directory + at, temp.path(), temp.child("verify.txt"));
  SCP_CHECK_EQ(verified.exit_code, 0);

  const ToolResult recovered = run_tool("recover --dir " + directory, temp.path(),
                                        temp.child("recover.txt"));
  SCP_CHECK_EQ(recovered.exit_code, 0);

  // Planning without a delegation is refused, and the refusal names why.
  const ToolResult denied = run_tool("plan --dir " + directory +
                                         " --intent accept-obligation --principal operator-1"
                                         " --service-class interactive-inference" + at,
                                     temp.path(), temp.child("plan-denied.txt"));
  SCP_CHECK_EQ(denied.exit_code, 3);
  SCP_CHECK(contains(denied.output, "no-grant-found") || contains(denied.output, "denied"));

  // With a grant covering the intent, the same plan is permitted and carries
  // effect requests addressed to the boundaries that own the effects.
  const ToolResult granted = run_tool(
      "grant --dir " + directory + " --grantor facility-policy-engine --subject site-control-plane"
      " --scopes observe-site,accept-obligation,request-accelerator-effect,request-fabric-effect" +
          at,
      temp.path(), temp.child("grant.txt"));
  SCP_CHECK_EQ(granted.exit_code, 0);

  const ToolResult permitted =
      run_tool("plan --dir " + directory +
                   " --intent accept-obligation --principal operator-1"
                   " --service-class interactive-inference" + at,
               temp.path(), temp.child("plan-permitted.txt"));
  SCP_CHECK_EQ(permitted.exit_code, 0);
  SCP_CHECK(contains(permitted.output, "permitted"));
}

SCP_TEST(cli_verify_reports_damaged_durable_state) {
  scp_test::TempDirectory temp("cli-damaged");
  const std::filesystem::path script = temp.child("site.evidence");
  const std::filesystem::path site = temp.child("site");
  std::filesystem::create_directories(site);
  write_text(script, healthy_script());
  const std::string directory = quoted(site.string());
  const std::string at = " --at 2026-01-01T00:00:00Z";

  const ToolResult applied =
      run_tool("apply --dir " + directory + " --evidence " + quoted(script.string()) + at,
               temp.path(), temp.child("apply.txt"));
  SCP_REQUIRE(applied.exit_code == 0);

  // Damage a frame that is not the last one: interior corruption, which the
  // runtime must refuse rather than truncate through.
  const auto probe = scp_test::probe_journal(site / "journal.scp");
  SCP_REQUIRE_OK(probe);
  SCP_CHECK(probe.value().frames.size() >= 2);
  const std::uint64_t offset = probe.value().frames.front().offset + 20;
  const std::vector<std::uint8_t> bytes = scp_test::read_bytes(site / "journal.scp");
  SCP_REQUIRE(bytes.size() > offset);
  SCP_REQUIRE(scp_test::poke_byte(site / "journal.scp", offset,
                                  static_cast<std::uint8_t>(bytes[offset] ^ 0xFFU)));

  const ToolResult verify = run_tool("verify --dir " + directory + at, temp.path(),
                                     temp.child("verify-bad.txt"));
  SCP_CHECK_EQ(verify.exit_code, 3);
  SCP_CHECK(contains(verify.output, "scpctl:"));
}

SCP_TEST(cli_json_output_is_well_formed) {
  scp_test::TempDirectory temp("cli-json");
  const std::filesystem::path script = temp.child("site.evidence");
  const std::filesystem::path site = temp.child("site");
  std::filesystem::create_directories(site);
  write_text(script, healthy_script());
  const std::string directory = quoted(site.string());

  const ToolResult seeded =
      run_tool("apply --dir " + directory + " --evidence " + quoted(script.string()) +
                   " --at 2026-01-01T00:00:00Z",
               temp.path(), temp.child("apply.txt"));
  SCP_REQUIRE(seeded.exit_code == 0);

  // JSON is offered where an operator consumes the output programmatically:
  // composition, explanation and planning.
  const std::array<std::pair<const char*, std::string>, 2> cases = {{
      {"compose-json",
       "compose --evidence " + quoted(script.string()) + " --site " + kSite +
           " --at 2026-01-01T00:00:00Z --json"},
      {"plan-json",
       "plan --dir " + directory +
           " --intent accept-obligation --principal operator-1 --service-class "
           "interactive-inference --at 2026-01-01T00:00:00Z --json"},
  }};
  for (const auto& entry : cases) {
    const ToolResult json =
        run_tool(entry.second, temp.path(), temp.child(std::string(entry.first) + ".txt"));
    // A plan without a grant is refused, but the report is still JSON.
    SCP_CHECK(json.exit_code == 0 || json.exit_code == 3);
    SCP_CHECK(json.output.find('{') != std::string::npos);
    SCP_CHECK(json.output.find('}') != std::string::npos);
    // A JSON document must not contain a bare control character outside
    // whitespace.
    bool control_free = true;
    for (const char character : json.output) {
      const unsigned char byte = static_cast<unsigned char>(character);
      if (byte < 0x20U && byte != '\n' && byte != '\r' && byte != '\t') {
        control_free = false;
      }
    }
    SCP_CHECK(control_free);
  }
}

SCP_TEST(cli_reports_a_usage_error_for_an_unreadable_evidence_script) {
  scp_test::TempDirectory temp("cli-missing-script");
  const ToolResult missing =
      run_tool("compose --evidence " + quoted(temp.child("absent.evidence").string()) + " --site " +
                   kSite + " --at 2026-01-01T00:00:00Z",
               temp.path(), temp.child("out.txt"));
  SCP_CHECK(missing.exit_code != 0);
  SCP_CHECK(contains(missing.output, "scpctl:"));

  const std::filesystem::path bad = temp.child("bad.evidence");
  write_text(bad, "kind capacity\nnot-a-key 1\n");
  const ToolResult malformed = run_tool("compose --evidence " + quoted(bad.string()) + " --site " +
                                            kSite + " --at 2026-01-01T00:00:00Z",
                                        temp.path(), temp.child("bad.txt"));
  SCP_CHECK(malformed.exit_code != 0);
  SCP_CHECK(contains(malformed.output, "scpctl:"));
}

SCP_TEST_MAIN("test_cli")
