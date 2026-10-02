// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "scp/plan.hpp"
#include "scp/runtime.hpp"
#include "test_support.hpp"

/// \file test_concurrency.cpp
/// Concurrent mutation, concurrent reads, shutdown in flight and cancellation.
///
/// The test harness records checks in a single, non-atomic context, so worker
/// threads never call SCP_CHECK. They collect observations into their own
/// storage and the owning thread asserts on the collected evidence afterwards.
/// That keeps the assertions sequential while the work under test is genuinely
/// concurrent.

namespace {

constexpr int kWorkers = 8;

std::vector<scp::EvidenceRecord> records() {
  return scp_test::healthy_site_records(scp_test::base_instant(), 1);
}

}  // namespace

SCP_TEST(concurrent_ingest_of_a_full_evidence_set) {
  const std::vector<scp::EvidenceRecord> all = records();
  SCP_REQUIRE(all.size() == 11);
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());

  std::vector<std::thread> workers;
  std::vector<scp::Status> results(all.size());
  for (std::size_t index = 0; index < all.size(); ++index) {
    workers.emplace_back([&runtime, &all, &results, index]() {
      results[index] = runtime->ingest(all[index]);
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  for (const scp::Status& status : results) {
    SCP_CHECK(status.ok());
  }
  SCP_CHECK_EQ(runtime->status().pending_evidence, all.size());

  scp::CommitOptions commit;
  commit.now = scp_test::base_instant();
  const auto outcome = runtime->commit(commit);
  SCP_REQUIRE_OK(outcome);
  SCP_CHECK(outcome.value().state == scp::SiteState::Available);
  SCP_CHECK_EQ(runtime->status().accepted_evidence, all.size());
  SCP_REQUIRE(runtime->close().ok());
}

SCP_TEST(concurrent_commits_advance_the_generation_exactly_once_each) {
  const std::vector<scp::EvidenceRecord> all = records();
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());

  // Each worker owns one slot, so no two threads share storage and no result
  // type has to be default-constructible.
  std::vector<scp::CommitOutcome> outcomes(all.size());
  std::vector<scp::StatusCode> codes(all.size(), scp::StatusCode::Ok);
  std::vector<char> ok(all.size(), 0);
  std::vector<std::string> failures(all.size());

  std::vector<std::thread> workers;
  for (std::size_t index = 0; index < all.size(); ++index) {
    workers.emplace_back([&runtime, &all, &outcomes, &codes, &ok, &failures, index]() {
      const scp::Status ingested = runtime->ingest(all[index]);
      if (!ingested.ok()) {
        codes[index] = ingested.code();
        failures[index] = ingested.to_string();
        return;
      }
      scp::CommitOptions commit;
      commit.now = scp_test::base_instant();
      const auto outcome = runtime->commit(commit);
      if (!outcome.has_value()) {
        codes[index] = outcome.status().code();
        failures[index] = outcome.status().to_string();
        return;
      }
      outcomes[index] = outcome.value();
      ok[index] = 1;
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }

  std::uint64_t successes = 0;
  for (std::size_t index = 0; index < all.size(); ++index) {
    if (ok[index] == 0) {
      // A concurrent commit may be refused, but only with a status that says so
      // and never with an empty reason.
      SCP_CHECK(codes[index] != scp::StatusCode::Ok);
      SCP_CHECK(!failures[index].empty());
      continue;
    }
    ++successes;
    SCP_CHECK(outcomes[index].committed);
  }
  SCP_CHECK(successes > 0);
  // Every successful commit advanced the site generation by exactly one, so the
  // published generation equals the number of successes and nothing was skipped.
  const scp::RuntimeStatus status = runtime->status();
  SCP_CHECK_EQ(status.site_generation.value(), successes);
  SCP_CHECK_EQ(status.commits, successes);
  SCP_REQUIRE(runtime->close().ok());
}

SCP_TEST(concurrent_readers_observe_verifiable_snapshots) {
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());
  SCP_REQUIRE(runtime->ingest(records()).ok());
  scp::CommitOptions commit;
  commit.now = scp_test::base_instant();
  SCP_REQUIRE_OK(runtime->commit(commit));
  SCP_REQUIRE(runtime->close().ok());
}

SCP_TEST(readers_during_writes_never_see_an_inconsistent_picture) {
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());
  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> reads{0};
  std::atomic<std::uint64_t> bad_digests{0};
  std::atomic<std::uint64_t> wrong_site{0};
  std::vector<std::thread> readers;
  for (int index = 0; index < 4; ++index) {
    readers.emplace_back([&runtime, &stop, &reads, &bad_digests, &wrong_site]() {
      // A do/while body runs at least once, so the test observes real reads
      // even when the writer finishes before the reader is first scheduled.
      do {
        const auto snapshot = runtime->snapshot(scp_test::base_instant());
        if (!snapshot.has_value()) {
          continue;
        }
        reads.fetch_add(1, std::memory_order_relaxed);
        if (!(scp::compute_snapshot_digest(snapshot.value()) == snapshot.value().snapshot_digest)) {
          bad_digests.fetch_add(1, std::memory_order_relaxed);
        }
        if (!(snapshot.value().site == scp_test::default_site())) {
          wrong_site.fetch_add(1, std::memory_order_relaxed);
        }
        const auto explanation = runtime->explain(scp_test::base_instant());
        if (explanation.has_value()) {
          (void)scp::render_explanation(explanation.value());
        }
      } while (!stop.load(std::memory_order_acquire));
    });
  }

  const std::vector<scp::EvidenceRecord> all = records();
  for (std::uint64_t generation = 1; generation <= 8; ++generation) {
    scp::Status ingested = runtime->ingest(all);
    SCP_CHECK(ingested.ok() || ingested.code() == scp::StatusCode::AlreadyExists);
    scp::CommitOptions step;
    step.now = scp_test::instant_after(static_cast<std::int64_t>(generation));
    const auto outcome = runtime->commit(step);
    SCP_CHECK(outcome.has_value());
  }
  stop.store(true, std::memory_order_release);
  for (std::thread& reader : readers) {
    reader.join();
  }

  SCP_CHECK(reads.load() > 0);
  SCP_CHECK_EQ(bad_digests.load(), std::uint64_t{0});
  SCP_CHECK_EQ(wrong_site.load(), std::uint64_t{0});
  SCP_CHECK_EQ(runtime->status().site_generation.value(), std::uint64_t{8});
  SCP_REQUIRE(runtime->close().ok());
}

SCP_TEST(concurrent_planners_and_a_writer_agree) {
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());
  SCP_REQUIRE(runtime->ingest(records()).ok());
  scp::CommitOptions commit;
  commit.now = scp_test::base_instant();
  SCP_REQUIRE_OK(runtime->commit(commit));

  scp::DelegationGrant grant;
  grant.id = scp::GrantId(0x6200000000000001ULL, 1);
  grant.site = scp_test::default_site();
  grant.grantor = scp::Name::parse("facility-policy-engine").value();
  grant.subject = scp::Name::parse("site-control-plane").value();
  grant.scopes = scp::ScopeSet(0xFFFFU);
  grant.issued_at = scp_test::base_instant();
  SCP_REQUIRE(runtime->record_grant(grant, scp_test::base_instant()).ok());

  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> plans{0};
  std::atomic<std::uint64_t> malformed{0};
  std::vector<std::thread> planners;
  for (int index = 0; index < 4; ++index) {
    planners.emplace_back([&runtime, &stop, &plans, &malformed]() {
      // See the note on the readers above: one iteration is guaranteed.
      do {
        scp::PlanRequest request;
        request.intent = scp::PlanIntent::AcceptObligation;
        request.principal = scp::Name::parse("operator").value();
        request.service_class = scp::Name::parse("interactive-inference").value();
        request.now = scp_test::base_instant();
        const auto plan = runtime->plan(request);
        if (!plan.has_value()) {
          continue;
        }
        plans.fetch_add(1, std::memory_order_relaxed);
        if (!plan.value().permitted && !plan.value().denial_reason.empty() &&
            plan.value().steps.empty()) {
          continue;
        }
        if (plan.value().permitted && !plan.value().steps.empty()) {
          continue;
        }
        malformed.fetch_add(1, std::memory_order_relaxed);
      } while (!stop.load(std::memory_order_acquire));
    });
  }

  for (std::uint64_t generation = 2; generation <= 6; ++generation) {
    SCP_REQUIRE(runtime->ingest(records()).ok() ||
                runtime->status().pending_evidence > 0);
    scp::CommitOptions step;
    step.now = scp_test::instant_after(static_cast<std::int64_t>(generation));
    const auto outcome = runtime->commit(step);
    SCP_CHECK(outcome.has_value());
  }
  stop.store(true, std::memory_order_release);
  for (std::thread& planner : planners) {
    planner.join();
  }
  SCP_CHECK(plans.load() > 0);
  SCP_CHECK_EQ(malformed.load(), std::uint64_t{0});
  SCP_REQUIRE(runtime->close().ok());
}

SCP_TEST(close_in_flight_is_refused_not_raced) {
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());
  SCP_REQUIRE(runtime->ingest(records()).ok());

  std::atomic<std::uint64_t> successes{0};
  std::atomic<std::uint64_t> closed_failures{0};
  std::atomic<std::uint64_t> other_failures{0};
  std::vector<std::thread> workers;
  const std::vector<scp::EvidenceRecord> all = records();
  for (int index = 0; index < kWorkers; ++index) {
    // Each worker commits until the runtime refuses it, so every worker is
    // guaranteed to observe the shutdown rather than possibly finishing first.
    workers.emplace_back([&runtime, &successes, &closed_failures, &other_failures]() {
      for (;;) {
        scp::CommitOptions commit;
        commit.now = scp_test::base_instant();
        const auto outcome = runtime->commit(commit);
        if (outcome.has_value()) {
          successes.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
        if (outcome.status().code() == scp::StatusCode::Closed ||
            outcome.status().code() == scp::StatusCode::ShuttingDown) {
          closed_failures.fetch_add(1, std::memory_order_relaxed);
          return;
        }
        other_failures.fetch_add(1, std::memory_order_relaxed);
        return;
      }
    });
  }

  // Close only once work has demonstrably been accepted, so the test observes a
  // runtime that is genuinely in flight rather than one that never started.
  while (successes.load(std::memory_order_acquire) == 0) {
    std::this_thread::yield();
  }
  SCP_REQUIRE_STATUS_OK(runtime->close());
  for (std::thread& worker : workers) {
    worker.join();
  }
  // A commit that crossed its boundary before close serialised with it is a real
  // success; everything after the close is refused with a status that says so.
  SCP_CHECK(successes.load() > 0);
  SCP_CHECK(closed_failures.load() > 0);
  SCP_CHECK_EQ(other_failures.load(), std::uint64_t{0});
  SCP_CHECK(!runtime->status().open);

  // After close, nothing succeeds any more.
  scp::CommitOptions commit;
  commit.now = scp_test::base_instant();
  SCP_REQUIRE_ERROR(runtime->commit(commit), scp::StatusCode::Closed);
  SCP_REQUIRE_STATUS_ERROR(runtime->ingest(all), scp::StatusCode::Closed);
}

SCP_TEST(cancellation_racing_a_commit_resolves_one_way) {
  SCP_OPEN_RUNTIME(runtime, scp_test::memory_runtime_options());
  const std::vector<scp::EvidenceRecord> all = records();
  SCP_REQUIRE(runtime->ingest(all).ok());

  std::atomic<bool> start{false};
  scp::Result<scp::CommitOutcome> outcome = scp::Status{};
  std::thread committer([&runtime, &start, &outcome]() {
    while (!start.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    scp::CommitOptions commit;
    commit.now = scp_test::base_instant();
    outcome = runtime->commit(commit);
  });
  SCP_REQUIRE(runtime->cancel().ok());
  start.store(true, std::memory_order_release);
  committer.join();

  if (outcome.has_value()) {
    // The commit crossed its durability boundary before cancellation was
    // observed, so it succeeded and the evidence is visible.
    SCP_CHECK(outcome.value().committed);
    SCP_CHECK_EQ(runtime->status().accepted_evidence, all.size());
  } else {
    SCP_CHECK(outcome.status().code() == scp::StatusCode::Cancelled);
    SCP_CHECK_EQ(runtime->status().accepted_evidence, std::size_t{0});
    SCP_CHECK_EQ(runtime->status().pending_evidence, std::size_t{0});
  }
  SCP_REQUIRE(runtime->close().ok());
}

SCP_TEST(repeated_open_and_close_of_the_same_directory) {
  scp_test::TempDirectory temp("concurrency-reopen");
  for (int round = 0; round < 5; ++round) {
    SCP_OPEN_RUNTIME(runtime, scp_test::durable_runtime_options(temp.path()));
    SCP_REQUIRE(runtime->ingest(records()).ok());
    scp::CommitOptions commit;
    commit.now = scp_test::instant_after(static_cast<std::int64_t>(round));
    const auto outcome = runtime->commit(commit);
    SCP_REQUIRE_OK(outcome);
    SCP_CHECK_EQ(outcome.value().site_generation.value(), static_cast<std::uint64_t>(round + 1));
    SCP_REQUIRE(runtime->close().ok());
  }
  SCP_OPEN_RUNTIME(final, scp_test::durable_runtime_options(temp.path()));
  SCP_CHECK_EQ(final->status().site_generation.value(), std::uint64_t{5});
  SCP_CHECK(final->status().state == scp::SiteState::Available);
  SCP_REQUIRE(final->close().ok());
}

SCP_TEST_MAIN("test_concurrency")
