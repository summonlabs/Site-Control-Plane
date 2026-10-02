# Concurrency and ownership audit

This is the audit the repository is required to contain, written against the code
that exists rather than against a design intention. Every claim below is either a
property of the code as written or is covered by a test named in
`tests/test_concurrency.cpp`.

## What concurrency exists

The runtime is **synchronous**. It starts no worker threads, owns no thread pool,
queues no deferred work and has no asynchronous completion path. The only
concurrency is:

* several callers entering one `SiteControlPlane` from different threads;
* several **processes** contending for one site directory.

The absence of background work is a design decision, not an omission: the
boundary's job is to answer a question about evidence and to write one durable
record, both of which are naturally synchronous. Removing the worker removes an
entire class of hazard instead of mitigating it.

## Lock inventory

| lock | level | protects |
| --- | --- | --- |
| `Impl::state_mutex` | 1 | accepted evidence, staged evidence, grants, generation, policy, status counters, cancellation and shutdown flags |
| `Impl::journal_mutex` | 2 | the `Journal` object: its file handle, sequence, chain digest and committed offset |
| writer lock file | process scope | the site directory itself, held for the lifetime of an open runtime |

## Lock ordering, and why it is the only order

```
state_mutex (1)  ->  journal_mutex (2)
```

A thread may take the journal lock while holding the state lock. The reverse
never happens: `Journal` never calls back into the runtime, and no code path
acquires `state_mutex` while `journal_mutex` is held. There is exactly one place
that acquires the journal lock outside a member function — the file-local
`journal_operation` helper — and it is only ever called from member functions
that already hold the state lock.

## The required audit, point by point

**Read-lock to write-lock upgrade attempts before dropping the read guard.**
There are no shared locks in this runtime. `state_mutex` is a plain
`std::mutex`; every public method takes it exclusively once, at entry, and
releases it on exit. `std::shared_mutex` is not used anywhere, so an in-place
upgrade is not expressible. The const methods that read (`snapshot`, `preview`,
`status`, `explain`) take the same exclusive lock rather than a shared one, which
is a deliberate simplification: composition is cheap relative to a durable commit
and a reader that can observe a commit boundary is worth more than reader
parallelism.

**Write locks held while calling code that can acquire the same state.**
The two locks protect disjoint state and no function acquires either twice. In
particular, `Impl::status` is mutated only while `state_mutex` is held, and
`status()` copies it under the same lock rather than returning a reference, so a
caller can never hold a torn view.

**Mutex re-entry through callbacks.**
There are no callbacks. The runtime accepts no function objects, no observers, no
completion handlers and no allocators. `Repository`-style extension points do not
exist, so re-entrancy through a caller-supplied callback is not possible.

**Event/callback emission while internal locks are held.**
Nothing is emitted under a lock. Observability is pull-based: `explain()`
composes a value and returns it. No logging, no signal, no callback and no I/O
happens while a lock is held other than the journal file operations, which are the
thing the journal lock exists to serialize.

**Shutdown while holding locks needed by workers.**
There are no workers to need a lock. `close()` takes the state lock, sets
`shutting_down`, then takes the journal lock, closes the journal and releases both.
Because there is no worker, there is nothing that could be waiting for a lock that
shutdown holds.

**Joining workers while holding state they require.**
No threads are created, so no thread is ever joined. `tests/test_concurrency.cpp`
joins threads it created itself, after the runtime work has finished.

**Reversed lock ordering in cancellation/recovery.**
`cancel()` takes only the state lock. Recovery happens inside `open`, before any
lock is reachable by another thread, because the object does not exist yet.
`record_grant`, `record_policy` and `plan` take the state lock and then, through
the helper, the journal lock — the documented order.

**Callbacks re-entering mutable state.**
Not applicable: there are no callbacks.

**Shutdown waiting on work while preventing its completion.**
`close()` waits for the state lock, which is held by at most one in-flight
operation; that operation does not need anything `close()` holds, because
`close()` takes the journal lock only after the state lock. A commit already
inside the durability boundary therefore finishes and is reported, and `close()`
proceeds afterwards. There is no path on which shutdown blocks work that needs
shutdown.

**Inconsistent nested acquisition ordering.**
There is one nested acquisition site in the whole runtime. It is the pair above,
and it appears in exactly one helper.

**Stale asynchronous completion mutating a newer generation.**
There is no asynchronous completion. Every operation runs to completion inside the
call that started it, and the generation advances only at the publish point of a
commit that holds the state lock for its whole duration.

**Races between authority revocation, recovery and publication.**
Grant recording and planning both take the state lock, so a plan cannot be
computed against a grant that is being revoked. Across processes, revocation is a
durable operation and the reader's plan re-derives authority from the grants it
has; every emitted request additionally carries a `scope-still-granted`
precondition so the receiving boundary re-checks the delegation at the current
generation instead of trusting this plane's older view.

## Cancellation

`cancel()` sets a flag and clears staged evidence. `commit` observes the flag in
exactly one place: immediately before the durability boundary.

That placement is deliberate. Before the boundary, cancellation prevents the
transaction and nothing is published. After the boundary the transaction is
already durable and recovery would replay it, so reporting failure would make the
reported outcome and the durable outcome disagree. The rule the repository claims
— *cancelled work may not later report success* — is satisfied by preventing the
work rather than by failing after it is done, and
`tests/test_concurrency.cpp:cancellation_racing_a_commit_resolves_one_way`
asserts that the two possible outcomes are mutually consistent.

## Process-level exclusion

`Journal::open` takes an exclusive advisory lock on `journal.lock`
(`LockFileEx` on Windows, `flock` on POSIX) and holds it for the lifetime of the
writer. A second writer gets `writer_exists`. The lock is released by the
operating system when the process dies, so a crashed writer never leaves a
permanently wedged site directory. `tests/test_multiprocess.cpp` proves this
between real operating-system processes, in both directions: a child is refused
while the parent holds the lock, and the same child succeeds once the parent has
closed.

## What is not covered

* The runtime does not attempt to make concurrent writers *fast*. Exclusion is
  total: one writer per site directory.
* `Journal` is not internally synchronized. It is documented as such and the
  runtime is its only in-process client, holding `journal_mutex` around every
  call.
* There is no lock-free path. Every public method serializes on the state lock, so
  throughput on many cores is bounded by that one mutex. This is honest for a
  control plane whose writes are durable commits, and it is stated here rather
  than claimed as a scalability property.
