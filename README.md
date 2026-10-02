# Site Control Plane

The canonical control-plane abstraction for **one complete physical data center
site**.

It owns site-level composition. It does not replace the runtimes that own assets,
capacity, power, cooling, policy, incidents, maintenance, accelerator execution
or fabric networking. It consumes their evidence explicitly and produces a
deterministic, auditable site-level view plus site-level decisions that are valid
only inside a scope another boundary granted to it.

**Core question.** Given a complete physical site and explicit evidence from
lower control planes, what is the site's authoritative operating state, what
obligations can it accept, what constraints are active, and what coordinated
site-level actions are permitted?

---

## Contents

- [What this owns, and what it does not](#what-this-owns-and-what-it-does-not)
- [Quick start](#quick-start)
- [The boundary in one screen](#the-boundary-in-one-screen)
- [Data model and invariants](#data-model-and-invariants)
- [Authority and generations](#authority-and-generations)
- [Evidence and freshness](#evidence-and-freshness)
- [Site lifecycle and states](#site-lifecycle-and-states)
- [Readiness gates](#readiness-gates)
- [Planning: requests, never effects](#planning-requests-never-effects)
- [Persistence and recovery](#persistence-and-recovery)
- [Concurrency](#concurrency)
- [CLI](#cli)
- [Library API](#library-api)
- [Build, test, install](#build-test-install)
- [Validation performed](#validation-performed)
- [Benchmarks](#benchmarks)
- [Platform support and limitations](#platform-support-and-limitations)
- [Repository layout](#repository-layout)
- [Relationship to adjacent boundaries](#relationship-to-adjacent-boundaries)

---

## What this owns, and what it does not

**Owned here**

| | |
| --- | --- |
| The authoritative composed operating state of exactly one site | one value, reproducible from its inputs |
| Deterministic composition of that state from consumed evidence | a pure function, no I/O, no clock reads |
| Site-level constraint evaluation against site-level thresholds | every constraint cites the evidence that produced it |
| Readiness gating for site-level transitions | six gates, each condition recorded |
| Delegated-scope validation | no default grant, no inferred scope |
| Typed site-level effect requests | addressed to the boundary that owns the effect |
| Durable site-level authority | accepted evidence, grants, policy, site generation |

**Not owned here, and never inferred**

| boundary | owns |
| --- | --- |
| Facility State Ledger | facility-state generation, topology, degraded operation, lifecycle position |
| Facility Capacity | capacity accounting and the capacity snapshot identity |
| Power Control Plane | power readiness and power redundancy |
| Thermal Control Plane | cooling readiness and cooling redundancy |
| Facility Policy Engine | policy rule authoring and the policy generation |
| Incident State Fabric | incident truth and emergency declaration |
| Maintenance Coordinator | maintenance windows, drain progress |
| ASI runtime | accelerator execution, capability and readiness |
| DFI runtime | fabric topology, paths, transport and fabric readiness |
| Service Class Registry | service classes and protected obligations |

A runtime cannot publish a fact it does not own: `EvidenceRecord::create` refuses
with `unauthorized`, and the reduction rejects a hand-built record from a
non-owner without letting it participate.

References to ASI, DFI or any other DCCP runtime in this repository are explicit
contracts, identifiers, snapshots or requests for effects — never permission to
reach into another runtime's internals. The repository stays independently useful
and swappable: a site with no neighbours still composes, and a site whose
neighbours change implementation still composes, because the only coupling is the
evidence contract.

---

## Quick start

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure        # 14 tests, no timeouts anywhere
cmake --install build --prefix ./install
```

Compose a site from an evidence script, with no durable state at all:

```
scpctl compose --evidence site.evidence --site 5c7b0a4d000000010000000000000001 \
               --at 2026-01-01T00:00:00Z
```

Commit evidence durably, then read the site back:

```
scpctl apply  --dir ./site --evidence site.evidence --at 2026-01-01T00:00:00Z
scpctl status --dir ./site --at 2026-01-01T00:00:00Z
scpctl explain --dir ./site --at 2026-01-01T00:00:00Z
scpctl verify --dir ./site
```

---

## The boundary in one screen

```
          evidence (provenance + typed body)
                     |
               [ evidence layer ]        who said it, under which epoch and generation,
                     |                   how fresh, and what it hashes to
                     v
               [ reduction ]             one resolution per (authority, kind) slot
                     |
                     v
     [ composition engine ] --- policy --- [ constraint evaluator ]
          pure, deterministic
                     |
                     v
          SiteStateSnapshot (a value)
               |          |
               |          +--> [ readiness gates ]
               |          +--> [ explainability ]
               v
       [ effect-request planner ] --- uses --- [ authority validator ]
                     |
                     v
       typed requests to other boundaries (never applied here)
                     |
                     v
       [ durable journal + snapshot ] --> [ runtime facade ]
```

`docs/ARCHITECTURE.md` is the long form. `docs/FORMAT.md` is the normative
durable-format specification. `docs/CONCURRENCY.md` is the ownership and lock
audit.

---

## Data model and invariants

**Identities.** Every authoritative object class has its own type — `SiteId`,
`EvidenceId`, `SnapshotId`, `GrantId`, `RequestId`, `PlanId`,
`ConstraintId`, `ObligationId` — and none of them converts implicitly to
another. Generations (`SiteGeneration`, `FacilityStateGeneration`,
`PolicyGeneration`, `CapacityGeneration`, `SourceGeneration`, `Epoch`,
`Sequence`, `JournalSequence`) are distinct types too. Mixing them is a compile
error rather than a production defect.

**Evidence identity is content-addressed.** A record's identity is derived by
SHA-256 over its provenance, kind, schema version and body. The same logical fact
published twice is the same record and deduplicates exactly; two different facts
at the same position are two different records that conflict.

**Determinism.** `compose_site_state` is a pure function of evidence, policy,
site generation and evaluation instant. It performs no I/O, reads no clock,
spawns no threads and mutates nothing. Two runs over equivalent evidence at the
same instant produce byte-identical snapshots and equal digests, whatever order
the evidence arrived in — a property proven over 47 explicit orderings and 240
seeded randomised scenarios, not asserted.

**The snapshot digest covers authoritative content only.** Free-text explanation
strings and the duplicate-merge counter are deliberately excluded, so rewording
an explanation cannot change a snapshot's identity and a batch that states the
same logical fact twice is the same evidence as a batch that states it once.

**Checked arithmetic.** Capacities, counts, durations, sequence numbers and
externally supplied sizes are checked. Where a quantity cannot be represented, or
a percentage cannot be expressed without overflow, the composition reports that
rather than wrapping or fabricating a value.

**Bounded everything.** Evidence batches, accepted evidence, journal growth,
frame bodies, snapshots, operations per transaction, plan steps, gate
conditions, constraints, obligations, service classes, thresholds and retained
plans each have a named bound, and exceeding one is reported as `limit_exceeded`
rather than silently truncated.

**Distinct outcomes stay distinct.** `unknown`, `stale`, `conflicting`,
`unsupported`, `invalid` and `indeterminate` are separate states throughout. A
stale snapshot never overwrites a newer accepted generation; contradictory
evidence becomes an explicit conflict instead of an arrival-order winner; a
publication whose schema this build cannot read is reported as unsupported and
does **not** let an older readable generation win.

---

## Authority and generations

The runtime may act only inside a scope another boundary explicitly delegated to
it, for a specific site, at a specific generation, until a specific instant.
`evaluate_authority` considers grants strictly in ascending grant-id order and
reports the first that covers the requirement, so the decision does not depend on
the order grants were recorded. There is no default grant and no implicit scope:
integration with a boundary is not permission to act inside it.

Outcomes: `granted`, `no_grant_found`, `scope_not_granted`, `site_mismatch`,
`grant_expired`, `grant_revoked`, `grant_not_yet_valid`, `generation_fenced`,
`grant_invalid`.

**Generations.** A site generation identifies one committed revision of the site
picture. The counter starts unset, and **the first successful commit publishes
generation 1**; a runtime that has committed nothing reports generation 0.
Source generations are per evidence publisher, and an **epoch** is a deliberate
reincarnation of a publisher instance: a restarted runtime with a new epoch
retires everything its previous incarnation said, however large its generation
counter had grown. That is the fencing rule that makes stale evidence unable to
overwrite newer accepted evidence across a restart.

---

## Evidence and freshness

A publication carries the authority that owns the fact, its runtime instance
identity, its epoch, its generation and sequence, the instant it was issued,
an optional expiry, and the digest of its body.

Freshness is judged against the caller-supplied evaluation instant, never against
a clock the engine reads:

| condition | classification |
| --- | --- |
| no stated issue instant | `indeterminate` |
| issued after the evaluation instant | `indeterminate` — two clocks disagree, and guessing which is right would be inventing a fact |
| `valid_until` at or before the evaluation instant | `expired` |
| age beyond the policy's `expire_after` | `expired` |
| age beyond the policy's `stale_after` | `stale` |
| otherwise | `fresh` |

Only `fresh` evidence reaches the typed view or a decision. Recovered evidence is
reported as `recovered` and revalidated evidence as `revalidated`, so durable
provenance is distinguishable from a fresh observation. An age that does not fit
in a signed 64-bit duration is treated as arbitrarily old, never as fresh.

---

## Site lifecycle and states

`unknown` and `conflicting` mean "no authoritative answer", and are decided
first: any conflicting slot makes the site `conflicting`; an unusable critical
slot (facility-state or lifecycle) makes it `unknown`.

Otherwise the lifecycle position published by the Maintenance Coordinator decides
the terminal states — `retired`, `isolated`, `emergency`, `maintenance`,
`draining`, `recovering`, `commissioning` — and an `active` lifecycle is
refined by the composed constraints:

| condition | state |
| --- | --- |
| emergency declared, degraded operation, a major-or-worse incident, an unavailable or degraded dependency domain, capacity exhausted or below the degraded floor, maintenance overdue | `degraded` |
| any constrained-level domain, capacity below the constrained floor, active incidents, active or scheduled maintenance, a drain in progress, incomplete or stale evidence, or any other active constraint | `constrained` |
| no constraint at all | `available` |

Every step that raised the state also produced a `Constraint` carrying its kind,
severity, blocking flag and the evidence slot that caused it, so the state is
re-derivable from the snapshot alone.

---

## Readiness gates

A gate is open only when all of its conditions hold, and each condition records
what was observed and what was required.

| gate | governs |
| --- | --- |
| `new-obligation` | accepting a new service obligation |
| `maintenance-entry` | entering a maintenance window |
| `controlled-drain` | starting a controlled drain |
| `emergency-operation` | operating under a declared emergency |
| `recovery-start` | beginning recovery |
| `return-to-service` | returning the site to service |

Emergency operation is deliberately permissive: it may proceed on partial
evidence and on domains that are not ready, and the snapshot records that it did.
It is **not** permitted on contradictory evidence. Acting on a contradiction means
choosing a winner by arrival order, which this plane refuses everywhere else, and
an emergency is not a licence to guess.

---

## Planning: requests, never effects

A plan is a value made of typed requests addressed to the boundaries that own the
effects. The planner has no API through which it could mutate another runtime, so
"site-level action plans never directly mutate ASI, DFI, power or cooling
internals" is a structural property rather than a promise.

Every emitted `EffectRequest` carries:

- the site generation it was computed against;
- the delegated scope it consumes;
- the preconditions the receiver must re-check — including that the receiver owns
  the effect, that the gate was open, that the accepted evidence still hashes to
  the same digest, that the receiver re-reads the site state, and that the
  delegation still grants the scope;
- an idempotency key derived from the site, generation, intent, target and action,
  deliberately excluding the step ordinal, so re-planning the same intent for the
  same generation reissues the same key and a retry is recognised as a retry.

A denied plan carries no steps at all, and `ActionPlan::validate` refuses a plan
that has it both ways: denial is not partial approval.

---

## Persistence and recovery

Accepted evidence, recorded delegations, the evaluation policy and the site
generation are durable. The journal is an append-only **two-phase transaction
log**, and the snapshot is the compacted state a retired journal prefix was folded
into.

1. **prepare** — the frame carrying the operations is appended, flushed to the
   operating system, synced to the device, and read back to verify what is on the
   device is what was written;
2. **commit** — a commit frame carrying the prepare frame's digest is appended,
   flushed, synced and read back the same way.

The transaction becomes visible to recovery only after phase 2 completes. A
prepare frame with no commit frame is not an error and is not replayed: it is the
exact state a writer that died between the phases leaves behind, and recovery
discards it.

**Durability boundary, stated exactly.** An operation is durable when the commit
frame's bytes have been written, the platform device flush has returned for that
file, and the frame has been read back and its checksum and chain link verified.
Everything before that point is intent.

**Damage classification.** A frame that does not physically fit is a torn tail and
is removed, because an incomplete write cannot have committed anything. A frame
that is fully present but fails its checksum, breaks the chain, or commits a
transaction that was never prepared is interior corruption: recovery refuses,
reports the byte offset, and truncates nothing. Never truncating through interior
corruption is a deliberate refusal to lose committed work quietly.

A snapshot that exists but cannot be used is also a hard failure. Ignoring it
would silently drop every piece of committed evidence the compaction retired
behind it.

`docs/FORMAT.md` specifies the byte layout, the frame kinds, the recovery table,
the compaction contract and the bounds.

---

## Concurrency

The runtime is synchronous: no worker threads, no deferred work, no asynchronous
completion. Two locks exist and are acquired in exactly one order —
`state_mutex` (level 1) then `journal_mutex` (level 2). No caller-supplied code
is ever invoked while a lock is held, because the runtime accepts no callbacks. A
read lock is never upgraded in place, because there are no shared locks.

Writer exclusion across processes is a real operating-system advisory lock
(`LockFileEx` on Windows, `flock` on POSIX) held for the lifetime of the writer,
released by the operating system even if the process dies. A second writer is
refused with `writer_exists`.

Cancellation is observed once, immediately before the durability boundary: before
it, cancellation prevents the transaction and nothing is published; after it, the
transaction has already happened and is reported as successful, because reporting
failure for work that recovery will replay would make the reported outcome and
the durable outcome disagree.

`docs/CONCURRENCY.md` walks the full audit checklist, including the hazards that
are structurally absent and why.

---

## CLI

`scpctl` is a real operator tool. It prints only values it read back from the
library, and every error goes to stderr as `scpctl: <status>`.

| command | what it does |
| --- | --- |
| `version` | tool, format and evidence-schema versions |
| `status --dir <path>` | open, recover, print the runtime's status |
| `recover --dir <path>` | the journal's own recovery report |
| `compose --evidence <file> --site <hex> --at <instant>` | pure composition, no durable state |
| `apply --dir <path> --evidence <file>` | ingest and commit durably |
| `explain --dir <path>` | every slot, domain, constraint, obligation, gate and derivation step |
| `plan --dir <path> --intent <name> --principal <name>` | plan an intent and print every effect request |
| `grant --dir <path> --grantor <name> --subject <name> --scopes <...>` | record a delegation durably |
| `verify --dir <path>` | recovery result plus a recomposed snapshot digest |

Exit codes: `0` success, `1` library failure, `2` usage error, `3` state or
integrity failure (damaged or unclean durable state, or a denied plan). `--json`
is available on `compose`, `explain` and `plan`.

Real output from a healthy eight-shard site:

```
$ scpctl apply --dir ./site --evidence site.evidence --at 2026-01-01T00:00:00Z
committed true
site-generation 1
state available
classification complete
operations 12
journal-sequence 1
durability-boundary prepare and commit frames written, flushed to the operating system,
  synced to the device, re-read and chain-verified; the transaction is visible to
  recovery after this point
snapshot-digest 1928497775a253a8df428bc6a1984e163e8e1b3107d8717b11ba2335a3bf9d70

$ scpctl plan --dir ./site --intent accept-obligation --principal operator-1 \
              --service-class interactive-inference --at 2026-01-01T00:00:00Z
permitted false
denial-reason authority refused: no-grant-found (no delegation grant names this site)
effect-request-count 0

$ scpctl grant --dir ./site --grantor facility-policy-engine --subject operator-1 \
               --scopes accept-obligation,request-accelerator-effect,request-fabric-effect
grant 1127465e0b15e03e1542f8615aa4fba0

$ scpctl plan --dir ./site --intent accept-obligation --principal operator-1 \
              --service-class interactive-inference
permitted true
effect-request-count 3
effect-request 0
  target service-class-registry
  action record-obligation-acceptance
  required-scope accept-obligation
  idempotency-key 1929395d34aa5e0c20e1c7f5c5261b15
  precondition receiver-owns-effect service-class-registry the receiver owns this effect...
  precondition evidence-digest-matches evidence accepted evidence still hashes to 1b63effb...
```

The evidence-script format, the policy-file format and every option are documented
by `scpctl help`.

---

## Library API

```cpp
#include "scp/runtime.hpp"

scp::RuntimeOptions options;
options.site = scp::SiteId(0x5C7B0A4D00000001ULL, 1);
options.directory = "./site";                  // empty selects an in-memory runtime
options.clock = std::make_shared<scp::ManualClock>(now);

auto plane = scp::SiteControlPlane::open(options);
if (!plane.has_value()) { /* plane.status() */ }
std::unique_ptr<scp::SiteControlPlane> runtime = std::move(plane.value());

if (const scp::Status ingested = runtime->ingest(records); !ingested.ok()) {
  // every failure says which record and why
}

scp::CommitOptions commit;
commit.now = now;
const auto outcome = runtime->commit(commit);
if (!outcome.has_value()) { /* nothing was published */ }
// outcome->state, ->site_generation, ->journal_sequence, ->durability_boundary

const auto snapshot = runtime->snapshot(now);   // pure recomposition
const auto report   = runtime->explain(now);    // why the site is what it is
const auto plan     = runtime->plan(request);   // typed requests, never effects
```

The engine itself is usable without any runtime, which is what makes the
determinism claim checkable:

```cpp
scp::CompositionOptions options;
options.site = site;
options.site_generation = scp::SiteGeneration(1);
options.evaluation_time = now;
options.policy = policy;

const auto snapshot = scp::compose_site_state(records, options);
```

---

## Build, test, install

Requirements: **C++20**, **CMake 3.21+**, and a compiler. No third-party runtime
dependencies — the standard library only.

| option | default | meaning |
| --- | --- | --- |
| `SCP_BUILD_TESTS` | ON | the test suite |
| `SCP_BUILD_TOOLS` | ON | the `scpctl` CLI |
| `SCP_BUILD_EXAMPLES` | ON | the worked examples |
| `SCP_BUILD_BENCHMARKS` | ON | `scp_bench` |
| `SCP_WARNINGS_AS_ERRORS` | ON | first-party warnings are errors |
| `SCP_ENABLE_ASAN` | OFF | AddressSanitizer where the toolchain supports it |
| `SCP_ENABLE_UBSAN` | OFF | UndefinedBehaviorSanitizer |

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /some/prefix
```

Installing provides a namespaced exported target and a package config usable with
`find_package`:

```cmake
find_package(SiteControlPlane 1.0 REQUIRED CONFIG)
target_link_libraries(my_consumer PRIVATE SiteControlPlane::site_control_plane)
```

`tests/downstream/` is an independent consumer that is configured, built and run
by the test suite against a fresh install of the build tree, from outside the
source tree. That is the distributability proof: an in-tree build is not evidence
that the package works.

---

## Validation performed

Every figure below is a count printed by the test binaries in the Release build on
this host. There are no timeouts anywhere in the suite: no CTest `TIMEOUT`, no
shell timeout, no GTest deadline, and no kill-and-call-it-a-pass logic.

```
ctest --test-dir build                        # Release
1/14  test_status .......................  Passed     9 cases,  1405 checks
2/14  test_evidence .....................  Passed    10 cases,  1165 checks
3/14  test_authority ....................  Passed     7 cases,   479 checks
4/14  test_readiness ....................  Passed     9 cases,  7416 checks
5/14  test_plan .........................  Passed    10 cases,  1517 checks
6/14  test_composition_determinism ......  Passed     8 cases,   734 checks
7/14  test_staleness_and_conflict .......  Passed    12 cases,   280 checks
8/14  test_property_composition .........  Passed     9 cases,  6051 checks
9/14  test_journal ......................  Passed    10 cases,    85 checks
10/14 test_recovery .....................  Passed    12 cases,   125 checks
11/14 test_multiprocess .................  Passed     4 cases,    30 checks
12/14 test_concurrency ..................  Passed     8 cases,   101 checks
13/14 test_cli ..........................  Passed     7 cases,    50 checks
14/14 downstream_consumer ...............  Passed    (install + configure + build + run)
100% tests passed, 0 failed out of 14

ctest --test-dir build-dbg                    # Debug
100% tests passed, 0 failed out of 14
```

**115 test cases, 19,438 individual checks, 0 failures, in both Debug and Release.**

What the suite actually does, beyond the counts:

- **Order independence.** The same 33-record evidence set is composed in 47
  explicit orderings (identity, reversed, eight seeded shuffles, all 33 rotations,
  four half-interleavings) and every snapshot digest, evidence digest, state,
  classification, per-slot accepted identity and constraint set compared.
- **Seeded properties.** 240 randomised scenarios per property: order
  independence, idempotence, monotone generation fencing, duplicate invariance,
  hostile input (schema 0/2/999/65535, zero and `UINT64_MAX` counters,
  `INT64_MIN`/`INT64_MAX` instants, nil and random identities) which either
  composes with verified digests or fails with a status — and never crashes or
  fabricates a digest, constraint bound enforcement at and either side of the
  limit, gate monotonicity under readiness-only improvement, and the reduction
  bucket partition.
- **Adversarial durability.** Torn tail removed and repaired; interior corruption
  detected and refused without truncation; chain break detected; a prepare frame
  with no commit discarded; a foreign site's journal refused; a tampered header
  caught by its checksum; an unsupported format version refused; a corrupt
  snapshot refused rather than ignored; growth and operation-count bounds
  enforced; compaction retiring covered frames while retaining everything beyond
  the snapshot, and refusing a snapshot beyond the committed position.
- **Real operating-system processes.** A second process is refused the writer lock
  while the first holds it and succeeds once it is released; a process that
  commits and dies without cleanup leaves exactly those transactions recoverable
  by the next process; a process that dies after writing a prepare and before its
  commit leaves a transaction that recovery discards; a process that dies leaving
  a torn tail leaves a journal recovery repairs.
- **Concurrency.** Eight threads ingesting one evidence set; eleven threads each
  committing and the published generation equalling the number of successes
  exactly; readers verifying every snapshot digest while a writer commits; four
  planners racing a writer; close serialising with in-flight commits and refusing
  everything afterwards; cancellation racing a commit and resolving one way; five
  open-commit-close cycles on one directory.
- **CLI.** Version and help; usage errors exiting 2; pure composition creating no
  durable state; apply/status/explain/verify/recover on a real directory; a denied
  plan exiting 3 and a granted one exiting 0; JSON output checked for control
  characters; a byte-flipped journal making `verify` exit 3.

**Sanitizers.** Linux CI runs the full suite under ASan+UBSan. On this Windows
host no sanitizer runtime is installed for any available toolchain (clang 19
shipped without `libclang_rt.asan*`, GCC 14.2 MinGW without `libasan`, and MSVC
without the ASan static runtime), so ASan/UBSan were **not** run here; the Linux
CI job is where that evidence comes from. See
[Platform support and limitations](#platform-support-and-limitations).

---

## Benchmarks

`scp_bench` measures **completed core operations**, not submission latency, and
reports the durable cost separately from the pure decision path. Every number
below was measured by running the Release binary on this host:

```
scp_bench --repeats 5 --shards 8 --durable-commits 64
evidence records : 88 (8 shards x 11 kinds)

decision path (pure, no I/O)
operation                            iterations   total (ms)   median (us)   min (us)   max (us)
reduce_evidence                             100        5.904        59.044     42.500     70.800
compose_site_state (recomposition)          100        9.829        98.294     69.600    150.500
evaluate_all_gates                         1000        9.660         9.660      6.400    175.000
plan_intent (accept-obligation)             250        7.234        28.935     25.700    156.100

durable path (real file, real flush)
operation                            iterations   total (ms)   median (us)   min (us)   max (us)
durable commit (prepare+commit+sync)         64      179.888      2810.745   2681.200   3346.300
in-memory commit (no durability)             64        5.406        84.475     71.400    151.600
reopen and recover                           10       10.619      1061.890    571.300   4902.400
```

Read honestly:

- A full recomposition of an 88-record site — reduction, constraint evaluation,
  all six gates and the canonical digest — is about **98 µs**, and the reduction
  alone about **59 µs**. These are pure functions with no I/O.
- A **durable commit costs about 2.8 ms**, roughly 33× the same commit without a
  durable boundary (84 µs). The difference is the device flush and the read-back
  verification of both frames, which is the price of the guarantee stated above.
  The durability boundary printed alongside the measurement is the one that was
  actually crossed.
- Reopening and recovering an already-written site is about **1.1 ms**, dominated
  by the first open in the sample (the maximum includes a cold page cache).

These are single-host, single-process, warm-cache measurements of this machine.
They are not a scalability claim: every public operation serialises on one mutex,
as `docs/CONCURRENCY.md` states.

---

## Platform support and limitations

| | |
| --- | --- |
| **Supported** | Windows (MSVC 2022, MinGW-w64 GCC 14) and Linux (GCC, Clang), 64-bit, C++20 |
| **CI** | Windows/MSVC Debug+Release, Ubuntu/GCC Debug+Release, Ubuntu/Clang Debug+Release, Ubuntu/Clang ASan+UBSan |
| **No third-party runtime dependency** | the standard library plus first-party components |

Honest limitations, stated rather than implied:

- **Cryptography.** The SHA-256 and CRC-32C in this repository are first-party and
  are used for integrity, provenance chaining and content identity. They are *not*
  a substitute for authenticated encryption, and nothing here authenticates a
  remote peer. Evidence arrives over whatever transport the operator provides.
- **No sanitizer evidence from Windows.** ASan and UBSan are exercised in Linux
  CI. On this Windows host no sanitizer runtime was installed for any available
  toolchain, so neither was run here and none is claimed.
- **One writer per site directory.** Exclusion is total. Concurrency is not a goal
  of this boundary, and throughput on many cores is bounded by one mutex.
- **In-memory runtimes are not durable**, and they say so: the commit outcome
  reports `in-memory runtime: no durable boundary exists and none is claimed`
  rather than pretending otherwise.
- **Compaction is manual or threshold-driven**, never background; there is no
  compaction thread.
- **Format version 1 is the initial format.** There is no migration path from an
  earlier version because there is no earlier version; a format change requires a
  version bump and a migration note in `docs/FORMAT.md`.
- **The site identity is chosen by the operator.** The library never invents one;
  `scpctl` derives a stable identity for itself as documented in its help.

**Untested or unclaimed:** behaviour under a real network partition between this
boundary and a lower runtime (evidence simply stops arriving, which composes to
staleness); federated multi-site operation (explicitly out of scope — this
boundary owns one site); and any performance claim under sustained multi-writer
load, which the design does not offer.

---

## Repository layout

```
include/scp/      the public API: status, ids, time, digest, canonical, text,
                  evidence, site_state, policy, readiness, authority, plan,
                  composition, journal, runtime, explain, version
src/              the implementation, plus platform.hpp for the host adapter
tools/scpctl/     the operator CLI
examples/         worked examples: site turn-up, evidence publication
bench/            the benchmark
tests/            the suites, the harness, the journal probe, and the downstream consumer
docs/             ARCHITECTURE.md, FORMAT.md, CONCURRENCY.md
cmake/            the package config template
.github/          cross-platform CI
```

---

## Relationship to adjacent boundaries

This repository is one boundary in the **Data Center Control Plane (DCCP)**, the
third arc of Summon Software Labs' Open Source Data Center Model, sitting above
the **Accelerated Systems Infrastructure (ASI)** and the **Distributed Fabric
Infrastructure (DFI)**, alongside the earlier DCCP facility boundaries.

The architectural invariant is: **own one thing exactly, consume neighbouring
truth explicitly, never infer another runtime's authority, and never absorb
another boundary merely because integration exists.**

Concretely, that means this repository reads evidence published by the facility
state, capacity, power, cooling, policy, incident, maintenance, accelerator,
fabric and service-class boundaries; decides only what the site as a whole may
do; asks those boundaries to act through typed requests carrying the scope,
generation, preconditions and idempotency identity of the request; and never
writes to their state. It composes and decides; they own and act.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
