# R3j bounded generic journal-confirmation hardening

Authorization: Mission Control GO_GENERIC_CONFIRMATION_HARDENING, baton 333.
Authority main: 04441e984236d17664c1200868d8cd3ade1dfb81. Contract blob
39c23543d25119b6fe0b404e84e9ad912c87d01a and matrix blob
373754b4c2721e2d78d6cfa4d48b2aad786bbbe0 are unchanged. NO_AUTHORITY_AMENDMENT.
Source parent: 27360e3fa227c9665f6447eb254864af08f4b74a, tree
c33367ed67b488b552c3a7dbd7a664400290f843.

## Historical boundary

R3i run 52 / 34731068984 failed D04_CONSUMPTION_UNCONFIRMED before actual
isolation. Its one durable CONSUMED child is
d4298a22f9c0c4bd7831625e3f08111b77b1291f, parent
2716ba3989c48b7df00003d89ea6608f63ed5e64. Record SHA-256:
ba7a1b81708915c4c485efed0e883fd1b06ab6e1f29586ecb7412090e70ceddc.
The exact historical failing read remains unknown. This successor does not
claim a proven run-52 causal fix, change its receipt, or refund consumption.
R3i remains frozen, permanently terminal for acceptance, with no actual
START/READY/END or ordinary authority PATCH. Authority remains
fdf602669253e0a5d3c09f515d4dd41004db043e (roadmap 6).

## Fixed algorithm

Journal.append fixes canonical R and parent P, validates the same lifecycle,
checks the same protections/parent, and constructs C using the unchanged
blob/tree/commit requests. It issues at most one non-force journal PATCH to C.
There is no candidate rebuild, rebase, mutation retry, or refund.

After that possible PATCH, _confirm_append takes at most three initial valid
exact-ref observations. C enters reconstruction. Only exact P permits one
fixed one-second wait before another observation; third P blocks. A different
head, malformed/missing ref, conversion/read/transport error, or backoff
response blocks immediately. PATCH response success, exception or parse loss
cannot substitute for canonical confirmation. Missing response is UNKNOWN.

After observing C, exactly one existing complete Journal.read pass must start
at C, establish its exact parent P, validate the entire ancestry and lifecycle,
and finish at stable C. Its final row must be exactly (C,R). Any failure blocks
without returning to observation. This is bounded read stabilization, not a
general retry facility or a claim of guaranteed provider availability.

## Shared lifecycle and D04 boundaries

- CONSUMED confirms reservation only; proof prerequisites still control entry.
- PENDING alone has no send permit. SEND_ARMED creates its one-use in-memory
  permit only after the full append call returns confirmed. take_send is unchanged.
- Ordinary TERMINAL retains all affirmative evidence requirements.
- D03 successful FINAL_REJECTION TERMINAL PATCH deliberately loses confirmation
  before _confirm_append. Available C does not heal that loss.
- Journal.reconcile/recover and the separate missing-TERMINAL sibling-completion
  PATCH/equivalence/winner semantics are unchanged. Default Journal.read retains
  its original complete reconstruction and stable-head rule.
- D04 repeats the existing helper.qualify immediately after exact CONSUMED
  confirmation. Less than 50 seconds of remaining helper budget, peer failure,
  or unsolicited data fails consumed before isolation. No deadline is reset.
  The actual 30-second timer and native 120-second cap remain unchanged.

## Bounded diagnostic schema

PROOF6_R3J_JOURNAL_CONFIRMATION_V1 emits PROOF6_JOURNAL_APPEND records with fixed
stage/reason enums, lifecycle, run/attempt, runtime/manifest, parent/candidate,
canonical record digest, PATCH_ENTERED boolean, call/response classification,
HTTP status, validated request ID (1..128 ASCII alphanumeric/colon/hyphen),
ordered initial heads (maximum three), reconstruction entry/final head, and
IN_PROGRESS/CONFIRMED/BLOCKED. No response body, credential, environment or
arbitrary exception string is retained. HTTP metadata is captured before body
read/JSON parsing only for the exact ordinary journal PATCH. Authority PATCH
transport is unchanged. Outer runtime result handlers retain the last fixed
snapshot. Diagnostic emission failure blocks and cannot create a send permit;
only a previously validated snapshot or minimal fixed failure record survives.

## Verification and adversarial review

The exact accepted R3i baseline is reproduced separately (528 tests and all
tracked bytes). All historical assertion/evidence files remain byte-identical.
R3j adapters retain the same 528 behavioral checks with prospective identities.
Old byte-scope assertions are mapped explicitly to r3j_scope.py: full parent
file preservation, unchanged method/module AST outside the approved delta,
exact runtime insertion check, workflow identity-only change, and exact plan
continuity except source base plus the approved journal-confirmation binding.
The old no-journal launcher mock explicitly has no new diagnostic snapshot.

test_r3j_confirmation.py exercises real append control flow across all four
ordinary lifecycle types: immediate/delayed C, persistent P, conflicting heads,
malformed/error reads, entry/final movement, ancestry/parent/record/binding
failure, PATCH ambiguity, HTTP metadata/parse loss, and diagnostic failure.
Every case asserts one PATCH, three object creations, no post-PATCH mutation,
bounded ordered observations, fixed waits, full reconstruction or fail-closed
exit, no early send permit, and no authority mutation. test_r3j_lifecycle.py
adds D04 exact-confirmation/budget/no-refund and D03/outer-receipt tests.

Full results, native Unix IPC/SCM_RIGHTS/shutdown/setup/custody checks, YAML/Bash
validation, inventory and hashes are in tests/r3j-evidence. run_r3j.py reproduces
the suite without hosted execution. New HTTP tests block socket creation.

Development test incident: an initial HTTP fixture intercepted urlopen instead
of the writer's private opener. Four requests with the literal inert test
credential and one read reached GitHub and returned 401. No valid App credential
was used. The fixture now intercepts _http.open and blocks socket creation;
protected-state read-only checks confirmed no mutation and run 52 still newest.
This is disclosed as a test-boundary error, not authorized hosted diagnostics
or evidence of provider behavior for the frozen runtime.

Adversarial conclusions: no second PATCH or rebuilt C; persistent P never
means unspent; errors/conflicts never poll again; C cannot bypass ancestry,
parent, record or stable-head checks; reconstruction cannot restart polling;
diagnostics cannot admit a send; D03 loss remains before confirmation; recovery
and sibling semantics do not enter the helper; insufficient D04 budget fails
consumed; active refs/schema bind only R3j. Future R3j requires fresh GENESIS.

Accounting remains 72 mandatory fresh, zero inherited, zero NOT_APPLICABLE;
the ten-run campaign is unchanged. Canary 48 and runs 49/50/52 confer zero
acceptance credit. R3j is source-only, NOT ACCEPTED, NOT PROVISIONED, NOT FROZEN,
NOT EXECUTED. Proof 6 is IN PROGRESS / NOT PASSED; Phase 7 is NOT AUTHORIZED.
Next gate: one independent bounded R3j source review.
