# Bounded caller-type correction

Previous reviewed candidate: `725c4b179bec44abef8befc2831f9dd7a09e3c7a`.
This descendant corrects only `Journal.check_binding`: require a dictionary,
an exact integer caller ID, and `admin is False` / `maintain is False` before
the unchanged complete caller-dictionary comparison. The containing commit is
the revised source identity. Mission Control main remains
`2f93acf267b99207c7f8220cb6246787a98806ec`.

The fixed login, permission and environment-qualification fields are strings;
JSON numbers, booleans, null, arrays and objects cannot compare equal to those
strings. The exact caller key set and fixed values remain enforced by the
original comparison. The ID comparison was similarly type-loose in isolation:
`265169095.0 == 265169095`. Canonical journal parsing already rejects floats,
and neither boolean equals the fixed ID. The new integer guard closes this
directly analogous binding-level defect without claiming a second canonical
recovery exploit. No schema, gate, reducer, classifier, recovery, sibling,
authority-continuity, workflow, proof-plan or D03/D04/D07 semantics change.

## Focused evidence

Run `python -B proofs/proof6/tests/test_caller_types.py` from the repo root.
The 14 methods exercise 30 independently substituted malformed canonical
histories, two direct ID-type checks, and four valid-false path controls.

- Six explicit zero cases: admin and maintain independently, at PENDING,
  SEND_ARMED and TERMINAL canonical heads.
- Float zero, string false, string zero, null and true, independently for each
  flag in both existing-terminal and missing-terminal recovery.
- Caller ID: equal-valued float, boolean, string and null in terminal ancestry;
  direct binding checks also reject float and boolean IDs.
- Each malformed history rejects complete production replay, production
  recovery, and qualified recovery-only entry. The latter retains BLOCKED
  admission. A subsequent valid normal proposal cannot reach gate output or
  mutate authority. Journal/authority PATCH counts and canonical refs stay
  unchanged throughout each malformed challenge.
- Actual boolean false passes for each flag in both recovery paths. Existing
  terminal confirmation is read-only; missing terminal gets one completion.
  A second recovery is read-only, and later fresh simulated work is admitted.

SEND_ARMED and TERMINAL do not contain separate caller objects in this schema.
Their caller is bound through the exact referenced PENDING. Fixtures replace
that caller and reconstruct direct-child ancestry and exact pending references,
without adding unknown fields. No malformed case is credited merely because
the journal was unreadable or detached.

Before the production edit, these same tests ran against the prior candidate's
unchanged journal bytes. `caller-types-before-results.txt` records 14 tests,
seven expected assertion failures and zero errors: all six zero-history tests
and the equal-valued float direct ID-binding check. The existing parser already
rejects floating-point journal encodings. After the two-line fix,
`caller-types-results.txt` records all 14 passing, without weakening assertions.
The historical commit was neither edited nor amended.

## Regression and byte preservation

Freshly rerun exact R3e source: 123 authored + 30 reviewer = 153 PASS. All 17
R3e fixture files were compared byte-for-byte with the pinned Git commit before
execution; both retained harnesses were also verified byte-identical.

Revised candidate: 53 R3f + 109 retained authored + 30 reviewer + 14 new =
206 PASS. All previous 192 tests and their assertions remain unchanged. The
historical 19 explicitly superseded R3e tests retain the prior documented
mapping; this correction adds no exclusions or replacements. Previous review
notes in REVIEW.md describe the initial 192-test candidate; this addendum and
verification.json provide the revised totals and bounded delta.

The proof plan remains byte-identical, SHA-256
`8ac4e07cd2b36e1266e0dcc155a763e151d36a888a23fb0f23d0ea545fb05c82`.
Accounting remains 56/16/0/0 = 72, with the same ten-workflow prospective budget.
build.json binds the new test plus changed journal; all other bound source
bytes are unchanged. source-build-inventory.json is regenerated using the
unchanged verifier and retains the original R3e comparison baseline.
verification.json records the immediate prior-candidate comparison separately.

Independent re-review should inspect the two-line type guard, canonical fixture
lineage, before/fix evidence, 206-test composition and remote build-bound bytes.
All provider responses are inert simulations. No provisioning, freeze, live
permission/sibling/isolation test, workflow dispatch, manifest installation,
runtime/journal ref creation, or protected configuration mutation occurred.
