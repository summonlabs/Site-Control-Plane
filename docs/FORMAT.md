# Durable format

This document specifies the on-disk container the Site Control Plane writes. It
is the normative reference for the format; the code, the tests and the
independent probe in `tests/support/journal_probe.cpp` all follow it.

Two containers live in a site directory:

| file | purpose |
| --- | --- |
| `journal.scp` | the append-only transaction journal |
| `snapshot.scp` | the compacted state a journal prefix was retired behind |
| `journal.lock` | the writer-exclusion lock file |

All integers are little-endian. There is no padding and no alignment. Checksums
are CRC-32C (Castagnoli, reflected, initial value `0xFFFFFFFF`, final XOR
`0xFFFFFFFF`). Frame identities are SHA-256 over the frame's own bytes,
header included.

## Format version

Both containers carry an explicit `format_version`, currently **1**. A reader
refuses a container whose version it does not implement with
`unsupported_format_version`; it never attempts a best-effort interpretation.
Because the journal header checksum covers the version field, a container cannot
be relabelled into another format: editing the version without recomputing the
checksum is reported as `checksum_mismatch`.

## Journal header — 80 bytes

| offset | size | field |
| --- | --- | --- |
| 0 | 8 | magic `SCPSITJ1` |
| 8 | 4 | `format_version` |
| 12 | 8 | site id, high word |
| 20 | 8 | site id, low word |
| 28 | 8 | creation time, nanoseconds since the Unix epoch, signed |
| 36 | 8 | chain base sequence |
| 44 | 32 | chain base digest |
| 76 | 4 | CRC-32C over bytes 0..75 |

The chain base is the link a compacted journal starts from: after compaction the
first retained frame points at the snapshot's position and digest rather than at
a frame that no longer exists.

## Frames

A frame is an 8-byte header followed by a body. The offsets below are offsets in
the frame, so the body starts at byte 8.

| offset | size | field |
| --- | --- | --- |
| 0 | 4 | body length |
| 4 | 4 | CRC-32C over the body |
| 8 | 1 | frame kind: 1 prepare, 2 commit, 3 marker |
| 9 | 1 | reserved, zero |
| 10 | 2 | body version |
| 12 | 8 | transaction sequence |
| 20 | 8 | previous sequence |
| 28 | 32 | previous frame digest |
| 60 | 4 | payload length |
| 64 | *payload length* | payload |

The fixed body is therefore 56 bytes and the minimum body length is 56.

The frame digest is SHA-256 over the frame header **and** body. Every frame
carries the digest of the frame physically before it, so deleting, reordering or
duplicating a frame is detected even when each surviving frame is individually
intact. The first frame after a header points at the header's chain base.

A commit frame's payload is exactly 32 bytes: the digest of the prepare frame it
completes. That is what binds the two phases together; a commit frame that
references anything else is `chain_broken`.

## Transaction protocol

A transaction is written in two phases:

1. **prepare** — the frame carrying the operations is appended, flushed to the
   operating system, synced to the device, and read back to verify that what is
   on the device is what was written;
2. **commit** — a commit frame carrying the prepare frame's digest is appended,
   flushed, synced and read back the same way.

The transaction becomes visible to recovery only after phase 2 completes.

**Durability boundary.** An operation is durable when the commit frame's bytes
have been written, the platform device flush has returned for that file, and the
frame has been read back and its checksum and chain link verified. Everything
before that point is intent and is not claimed.

A prepare frame with no commit frame is **not** an error and is **not** replayed.
It is the exact state a writer that died between the phases leaves behind, and
recovery discards it, reporting `discarded_uncommitted_transaction`.

## Recovery

Recovery scans from the header and classifies every deviation:

| observation | classification | action |
| --- | --- | --- |
| fewer than 12 bytes remain for a frame header | torn tail | truncate to the last committed frame |
| the declared frame extent runs past the end of the file | torn tail | truncate to the last committed frame |
| a fully present frame fails its body checksum | interior corruption | refuse; truncate nothing |
| a frame's link does not match the previous frame | interior corruption | refuse; truncate nothing |
| a prepare is followed by another prepare | interior corruption | refuse; truncate nothing |
| a commit references a different sequence or digest | interior corruption | refuse; truncate nothing |
| an unknown frame kind or frame version | corruption | refuse; truncate nothing |
| a trailing prepare with no commit | uncommitted tail | truncate the prepare, keep everything before it |
| the journal ends on a commit | clean | nothing |

The distinction is deliberate. A torn tail is provably an incomplete write, so
removing it cannot lose committed work. Anything else may be damage to state that
was already committed, so the runtime refuses and reports the byte offset rather
than truncating through it and reporting success.

## Journal operation payloads

A transaction's payload is a canonical encoding of `JournalTransaction`:
a 16-byte transaction id followed by a bounded vector of operations. Each
operation is a one-byte kind followed by only the fields that kind uses:

| kind | payload |
| --- | --- |
| 1 ingest evidence | one canonical evidence record |
| 2 retire evidence | one canonical evidence record |
| 3 advance site generation | one u64 generation |
| 4 record plan | one canonical action plan |
| 5 record grant | one canonical delegation grant |
| 6 record policy | one canonical site policy |

An unrecognised kind is `invalid_enum`. Replay is idempotent because evidence
identity is content-addressed: replaying a record that is already accepted is a
no-op, not a duplicate.

## Snapshot — 20-byte header plus payload

| offset | size | field |
| --- | --- | --- |
| 0 | 8 | magic `SCPSITS1` |
| 8 | 4 | `format_version` |
| 12 | 4 | payload length |
| 16 | 4 | CRC-32C over the payload |
| 20 | *payload length* | canonical `JournalSnapshot` |

The payload carries the site identity, the site generation, the journal sequence
the snapshot covers, its creation time, the chain digest at that position, the
accepted evidence records, the recorded grants and the site policy.

A snapshot is written to `snapshot.scp.tmp`, flushed, synced, and only then
atomically renamed over `snapshot.scp`. A snapshot whose covered sequence is
beyond the journal's committed position is refused with `stale_generation`.

## Compaction

Compaction writes a snapshot covering sequence *S* and then rewrites the journal
keeping only frames with sequence greater than *S*. Retained frames are relinked
so the chain is continuous from the snapshot. Compaction is allowed to retire
only frames that belong to committed transactions: the frame set it keeps
includes every frame beyond *S*, which by construction includes any uncommitted
trailing prepare, because an uncommitted transaction's sequence is always greater
than the last committed one. The rewritten journal is re-read and re-verified
before it replaces the original.

## Bounds

Every count read from disk is checked against a bound before anything is
allocated. Frame bodies are capped at 8 MiB, snapshots at 128 MiB, journal growth
at 256 MiB by default, and each nested vector has its own named bound (steps 256,
conditions 256, gate conditions 64, slots 64, constraints 512, obligations 128,
evidence 65536, grants 4096, operations 4096). A count beyond its bound is
reported as `limit_exceeded`, never silently clamped.

## Compatibility

Version 1 is the initial format. A change to framing, to any field's meaning, or
to the chain rules requires a version bump, a migration note here, and a test in
`tests/test_journal.cpp` or `tests/test_recovery.cpp` that reads a container
written by the previous version. There is no in-place migration yet, because
there is no previous version yet; this paragraph is the commitment, not a
description of code that exists.
