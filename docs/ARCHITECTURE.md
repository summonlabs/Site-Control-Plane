# Architecture

The Site Control Plane is one boundary in the Data Center Control Plane (DCCP).
It owns the site-level picture and the site-level decision, and nothing else.

## Ownership

**Owned here**

* the authoritative composed operating state of exactly one physical site;
* the deterministic composition of that state from consumed evidence;
* site-level constraint evaluation against site-level thresholds;
* readiness gating for site-level transitions;
* delegated-scope validation for the scopes granted to this boundary;
* typed site-level effect requests addressed to the boundaries that own the
  effects;
* durable site-level authority: accepted evidence, recorded delegations, the
  evaluation policy, the site generation.

**Not owned here, and never inferred**

| boundary | owns |
| --- | --- |
| Facility State Ledger | facility-state generation, topology, degraded operation |
| Facility Capacity | capacity accounting and the capacity snapshot identity |
| Power Control Plane | power readiness and power redundancy |
| Thermal Control Plane | cooling readiness and cooling redundancy |
| Facility Policy Engine | policy rule authoring and the policy generation |
| Incident State Fabric | incident truth and emergency declaration |
| Maintenance Coordinator | maintenance windows, drain progress, lifecycle position |
| ASI runtime | accelerator execution, capability and readiness |
| DFI runtime | fabric topology, paths, transport and fabric readiness |
| Service Class Registry | service classes and protected obligations |

Every fact in the second table reaches this boundary as **evidence** carrying the
identity of the runtime that published it. A runtime cannot publish a fact it
does not own: `EvidenceRecord::create` refuses with `unauthorized`, and the
reduction rejects a hand-built record from a non-owner as `unauthorized` without
letting it participate.

## Components

```
            evidence (provenance + typed body)
                       |
                 [ evidence layer ]      include/scp/evidence.hpp
                       |                 src/evidence.cpp
                       v
                 [ reduction ]           canonical one-winner-per-slot
                       |                 src/composition.cpp
                       v
   [ composition engine ]  ---- policy -- [ constraint evaluator ]
        pure, no I/O                        src/composition.cpp
                       |
                       v
            SiteStateSnapshot (a value)
                 |          |
                 |          +--> [ readiness gates ]  src/readiness.cpp
                 |          +--> [ explainability ]   src/explain.cpp
                 v
        [ effect-request planner ]  src/plan.cpp
                 |          uses
                 |          |
                 |          v
                 |    [ authority validator ]  src/authority.cpp
                 v
        typed requests to other boundaries (never applied here)
                 |
                 v
        [ durable journal + snapshot ]  src/journal.cpp
                 |
                 v
        [ runtime facade ]  src/runtime.cpp
```

## The evidence model

An `EvidenceRecord` is provenance plus an opaque, self-describing body:

* **authority** — the boundary that owns the fact;
* **instance** — that boundary's runtime instance identity;
* **epoch** — a deliberate reincarnation of the instance;
* **generation** and **sequence** — monotonic inside an epoch;
* **issued_at** and **valid_until** — when the fact was true;
* **body_digest** — SHA-256 of the canonical body bytes;
* **id** — content-addressed, derived from the provenance, the kind, the schema
  version and the body.

Because the identity is derived, the same logical fact published twice is the
same record and deduplicates exactly, and two different facts at the same
position are two different records that conflict.

A body's schema version is explicit. A build that does not implement it keeps the
bytes, reports `unsupported`, and does **not** substitute an older readable
publication for the newer statement it cannot read.

## The reduction rule

For each `(authority, kind)` slot:

1. records from a non-owner are rejected;
2. records that fail structural validation or their body digest are rejected;
3. records whose schema this build does not implement participate in **fencing**
   but cannot be decoded;
4. the winner is the record with the greatest `(epoch, generation, sequence)`;
5. if the newest position is held by an unreadable record, the slot is
   `unsupported`, whatever older readable truth exists;
6. if two readable records at the newest position carry different content, the
   slot is `conflicting`; arrival order never decides;
7. every older record is recorded as `superseded`, not dropped.

Epoch is the primary key because an epoch is a deliberate reincarnation: a
restarted runtime with a new epoch retires everything its previous incarnation
said, however large its generation counter had grown. This is the fencing rule
that makes "stale snapshots cannot overwrite newer accepted generations" hold
across a restart.

## Freshness

Freshness is judged against the caller-supplied evaluation instant, never against
a clock the engine reads. A record with no stated expiry ages against the policy's
`stale_after` and `expire_after`; a record with `valid_until` expires at that
instant; a record dated after the evaluation instant is `indeterminate`, because
two clocks disagree and guessing which is right would be inventing a fact. Only
`fresh` evidence participates in a decision.

Recovered evidence is reported as `recovered` and revalidated evidence as
`revalidated`, so an operator can tell durable provenance from a fresh
observation.

## Determinism

`compose_site_state` is a pure function of evidence, policy, site generation and
evaluation instant. It performs no I/O, reads no clock, spawns no threads and
mutates nothing. Its output carries a canonical digest over:

* the site and site generation, the evaluation instant, the state, the lifecycle
  and the evidence classification;
* the policy digest;
* the evidence digest — the slot identities, their resolutions and their
  freshness, but not their explanatory text;
* every slot resolution, every constraint, every gate and every obligation in
  canonical order.

Two runs over equivalent evidence at the same instant therefore produce
byte-identical snapshots and equal digests, whatever order the evidence arrived
in. That property is proven, not asserted: `tests/test_composition_determinism.cpp`
and `tests/test_property_composition.cpp` compose the same set in many orders
and compare digests.

## Site state derivation

`unknown` and `conflicting` are first-class states meaning "no authoritative
answer", and they are decided first:

| condition | state |
| --- | --- |
| any slot conflicting | `conflicting` |
| any slot unsupported | `conflicting` is not raised; the classification is `unsupported` and the state follows the table below from the lifecycle |
| a critical slot (facility-state, lifecycle) missing, stale, expired, unsupported or unauthorized | `unknown` |

Otherwise the lifecycle position published by the Maintenance Coordinator
decides the terminal states — `retired`, `isolated`, `emergency`,
`maintenance`, `draining`, `recovering`, `commissioning` — and an `active`
lifecycle is refined by the composed constraints:

| condition | state |
| --- | --- |
| emergency declared, or degraded operation, or an incident at major severity or worse, or a dependency domain unavailable or degraded, or capacity exhausted or below the degraded floor, or maintenance overdue | `degraded` |
| any constrained-level domain, capacity below the constrained floor, active incidents, active or scheduled maintenance, a drain in progress, incomplete or stale evidence, or any other active constraint | `constrained` |
| no constraint at all | `available` |

Every step that raised the state also produced a `Constraint` carrying its kind,
severity, blocking flag and the evidence slot that caused it, so the state is
re-derivable from the snapshot alone.

## Readiness gates

Six gates govern every site-level transition. A gate is open only when all of its
conditions hold, and each condition records what was observed and what was
required:

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
It is **not** permitted on contradictory evidence. Acting on a contradiction
means choosing a winner by arrival order, which this plane refuses everywhere
else, and an emergency is not a licence to guess.

## Authority

This plane may act only inside a scope another boundary explicitly delegated to
it, for a specific site, at a specific generation, until a specific instant.
`evaluate_authority` selects deterministically: grants are considered in grant-id
order, so the decision does not depend on the order they were recorded, and the
outcome is `granted`, `no_grant_found`, `scope_not_granted`, `site_mismatch`,
`grant_expired`, `grant_revoked`, `grant_not_yet_valid`, `generation_fenced` or
`grant_invalid`. There is no default grant and no implicit scope: integration
with a boundary is not permission to act inside it.

## Planning

A plan is a value made of typed requests addressed to the boundaries that own the
effects. The planner has no API through which it could mutate another runtime, so
"site-level action plans never directly mutate ASI/DFI/power/cooling internals" is
a structural property, not a promise. Every emitted `EffectRequest` carries:

* the site generation it was computed against;
* the delegated scope it consumes;
* the preconditions the receiver must re-check, including that the receiver owns
  the effect, that the gate was open, that the evidence still hashes to the same
  digest, that the receiver re-reads the site state, and that the delegation still
  grants the scope;
* an idempotency key derived from the site, generation, intent, target and action
  — deliberately excluding the step ordinal, so re-planning the same intent for
  the same generation produces the same key and a retry is recognised as a retry.

A denied plan carries no steps at all, and `ActionPlan::validate` refuses a plan
that has it both ways. Denial is not partial approval.

## Durable authority

Accepted evidence, recorded delegations, the evaluation policy and the site
generation are durable. The journal is an append-only two-phase transaction log
with an explicit commit boundary; the snapshot is the compacted state a retired
journal prefix was folded into. `docs/FORMAT.md` is the normative specification.

After a restart the runtime replays the journal (or loads the snapshot and
replays the tail), marks the replayed evidence as recovered, fences stale
generations, and refuses to start if a snapshot exists but cannot be used —
ignoring a damaged snapshot would silently drop committed evidence.

## Where the boundary ends

The site plane does not place workloads, does not reserve capacity, does not
switch power, does not adjust cooling, does not author policy, does not own
incidents and does not move the site through its lifecycle. It composes what
those boundaries say, decides what the site may do as a whole, and asks them to
do it. It stays useful and swappable on its own: a site with no neighbors still
composes, and a site whose neighbors change implementation still composes,
because the only coupling is the evidence contract.
