# Contributing to Site Control Plane

Site Control Plane is a Data Center Control Plane (DCCP) repository maintained by
Summon Software Labs. Contributions are welcome under the terms of the Apache
License 2.0.

## Licensing of contributions

By submitting a contribution you agree that it is licensed under the Apache
License 2.0, as described in section 5 of the [LICENSE](LICENSE). There is **no**
Contributor License Agreement to sign and no copyright assignment. You keep the
copyright to your contribution.

Do not add `Co-authored-by` trailers, generated-by notices, or attribution lines
that you cannot justify; commit authorship is recorded by Git itself.

## Before you open a pull request

1. Build both configurations with warnings-as-errors:

   ```
   cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
   cmake --build build/release
   cmake -S . -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
   cmake --build build/debug
   ```

2. Run the complete test suite in both configurations:

   ```
   ctest --test-dir build/release --output-on-failure
   ctest --test-dir build/debug --output-on-failure
   ```

   Tests are expected to terminate on their own. Do not add timeouts, watchdogs,
   or "kill the process and call it a pass" logic; a hanging test is a defect and
   must be diagnosed rather than masked.

3. Keep the public API strongly typed. Identities, generations, epochs,
   revisions and external references are distinct types with no implicit
   conversions between them, and no sentinel values where an optional or a sum
   type says the same thing more precisely.

4. Any change to the journal or snapshot format requires a format version bump,
   a migration note in `docs/FORMAT.md`, and an explicit compatibility
   statement. Recovery must never truncate through interior corruption.

5. New behaviour needs evidence. Tests assert observable behaviour, not
   implementation details, and every invariant needs a test that fails when the
   invariant is violated.

## Code quality expectations

* C++20, standard library only for the shipped library. A new third-party
  dependency must be justified in the pull request and is normally rejected when
  the standard library suffices.
* Zero first-party warnings under `/W4 /WX` (MSVC) or
  `-Wall -Wextra -Wpedantic -Werror` (GCC/Clang). Warnings are fixed at the
  cause; blanket suppression is not acceptable.
* No TODO placeholders, dead code, debug prints, machine-specific absolute
  paths, or generated junk in the tree.
* Deterministic behaviour must be reproducible: seeded randomized tests, stable
  iteration order, canonical serialization for anything persisted or hashed.
* Never fabricate authority, capacity, health, compatibility or success. Unknown,
  stale, conflicting, unsupported, invalid and indeterminate are distinct
  outcomes and must stay distinct.

## Reporting defects

Open an issue with the exact command, the observed result, and the expected
result. Durability, integrity, generation-fencing and ordering defects are
treated as release blockers; include a minimised reproduction, and the journal
or snapshot directory when the defect is in recovery.
