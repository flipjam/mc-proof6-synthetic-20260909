# R3f source candidate and offline review evidence

This is an unfrozen source candidate based on R3e commit
`d1a8b2fcbd5ffc3aec8f02823bb604dce542f06f`, tree
`afe54b1e709aa8b39f60fa00c387bf4ccfbd3185`. Mission Control authority was fetched
and read at `2f93acf267b99207c7f8220cb6246787a98806ec` on main. Proof 6 remains
IN PROGRESS / NOT PASSED. R3e D03 remains NOT ACCEPTED and R3d remains
FAILED / HISTORICAL. This candidate confers no acceptance credit.

Publication is limited to the synthetic task branch
`codex/proof6-r3f-implementation-candidate-20260911-01`. No runtime or journal
ref was created; no ruleset, environment, policy, secret, manifest or protected
state was changed; no Actions workflow or live acceptance case was dispatched.

## Source impact

`source-build-inventory.json` contains exact before/after Git blob and SHA-256
identities for every build-bound file and the build itself, including unchanged
dependencies. The containing Git commit identifies this candidate without a
self-referential commit field in these files.

- `journal.py`: fresh R3f ref/schema identity; complete ancestry retained; reject
  noninteger/non-JSON numeric encodings; require direct lifecycle linkage;
  expose validated arms and terminals; replace resolved-record skipping with
  full ordered reconciliation. Missing-terminal recovery admits only exact
  SEND_ARMED HEAD plus affirmative candidate observation. One completion PATCH
  per `Journal.recover` invocation, force=false, no loop/retry, full reread and
  semantic winner comparison. Existing canonical terminals are read-only.
- `writer.py`: reconstruct baseline and each exact old/candidate history;
  validate direct-child, proposal and accepted gate decision bindings. No
  arbitrary-descendant shortcut remains. Recomputed pure gate decisions are
  audit-only and never become a transport permit or resumed old authorization.
  Normal work still evaluates the gate freshly after reconciliation. Normal
  proposal digests now bind canonical parsed data, allowing reconstruction
  across harmless JSON whitespace. Accepted gate/reducer bytes are unchanged.
- `actions_runtime.py`: frozen empty requests receive complete qualification
  and exit through recovery before commit_transition. Every frozen guard also
  requalifies the caller, including both admitted R7 completion requests.
  Unfrozen empty-request bootstrap remains the existing fixed GET-only path.
- `proof_control.py` / `proof_plan.json`: retain exactly two public input keys,
  three fixed fault selectors and fixed D04 operation. Bind R3f source authority,
  proposals/order, 72 exact dispositions, grouped evidence methods, 10 workflow
  runs, one consumption per operation, and deferred live pins. O1/O2 share one
  starting state; either winner permits the same fixed subsequent D07 proposal.
- `d03_job_token.py`: only successor runtime-ref binding changes. Same worker
  ancestry/open-FD mechanism, permission verification and credential separation.
- Workflow: only successor binding, input description and step description
  change. Hosted runner, pinned external action, protected environment, read-only
  job token, sole concurrency group and cancel-in-progress=false are retained.
- `outage.py`: actual-process isolation window is 30 seconds from READY. Native
  total process cap remains 120 seconds, including setup. Completion still
  requires END and successful native supervisor exit. Slow setup may still
  exhaust the cap and fail closed; there is no caller duration control.
- `app_probes.py` (new): fixed F02 ruleset-modification and F10 same-tree direct
  runtime-child probes after confirmed D02 terminal. Targets/payloads are fixed
  and plan-bound. Unexpected success stops proof work with FAIL evidence, with
  no rollback or second probe. No authority PATCH or generic public request API.
- `sibling_canary.py` (new): fixed D07 recovery-only method described below.
- `build.json`: regenerated after final source/tests stabilized; contains all
  production dependencies, offline test scripts and the inert baseline fixture.

The reducer, gate, D03 rejection classifier, admission formatter, reconcile stub,
diagnostics, diagnostic bindings and ruleset normalization are byte-identical to
R3e. No new record type, database, service, credential, lock, lease, transaction
manager, recovery engine, workflow or generalized fault API was introduced.

## Terminal semantics and recovery

The existing terminal JSON fields are retained. Its actual sole Git parent is
the expected parent; it must be the exact protected SEND_ARMED for a possible
send, or the PENDING for the original unarmed no-send finalization. The pending
reference resolves the original operation/binding, old/candidate and gate digest
through complete canonical ancestry. The normative comparison covers the full
terminal row, full PENDING row, actual parent and exact SEND_ARMED identity. No
JSON record field is discarded as metadata. Git author/committer/time/message
have no safety interpretation. Canonical ancestry alone gives membership.

Recovery audits every prior disposition and direct gate-produced authority
advance from the pinned baseline. Older NOT_COMMITTED dispositions remain valid
after fully explained later work. Rejected-candidate observation, skipped work,
incorrect old/candidate chains, unexplained descendants, malformed canonical
records and insufficient evidence block. A valid terminal followed by legitimate
journal or authority descendants remains canonical. Supporting confirmation
receipts bind original/recovery identities, canonical terminal/head, authority,
evidence class and complete normative digest; they are not safety authority.

A missing unarmed PENDING terminal blocks rather than acquiring the new
completion exception. A missing armed terminal with authority-old also blocks.
No response log recovery or inferred completion barrier is added. Existing
canonical D03 rejection terminals are validated and confirmed read-only.

The fixed D03 hook fires only after a successful genuine-rejection terminal
PATCH result and before the first canonical confirmation GET. The original
writer result remains INDETERMINATE; its attempt-local D03 failure label is
retained. Later prospective case acceptance belongs to independent review of
the failure plus successful recovery, never rewriting that original result.
Nonqualifying responses and unexpected 2xx retain the accepted classifier rules.

R7's single qualified hosted workflow job holds the existing concurrency boundary.
It invokes production `Journal.recover` twice: the first invocation is held at
its fixed admitted transport boundary, the second independently validates the
same P and completes, then the first sends its already admitted request once.
The two commit messages have fixed different nonsafety labels, ensuring distinct
sibling identities without adding fields to the safety record. Each recovery
invocation has one PATCH; no invocation retries. The later request wins, the
delayed first must lose, and both reread the canonical winner. No new invocation
is admitted after seeing a winner. This method is only reached by frozen empty
request recovery of an unresolved D07; normal transitions cannot run it. There
is no extra worker or workflow. A later read-only recovery does not rerun it.
The live demonstration remains mandatory and has NOT been performed.

## Offline tests and exact regression disposition

Run from the repository root, with Python and Git available:

```
python -B proofs/proof6/tests/test_r3f.py
python -B proofs/proof6/tests/regression.py
python -B proofs/proof6/tests/reviewer_regression.py
python -B proofs/proof6/tests/verify_candidate.py
```

The retained regression suite also runs harmless Linux process/worker fixtures
through the existing Windows WSL Ubuntu-22.04 installation. These fixtures do
not invoke the live writer or network isolation. The new suite uses inert Git
objects/HTTP responses and a fake clock; socket creation is denied. Provider
responses and Git fast-forward behavior are simulations, not live proof.

- Prior R3e harness: 123 tests, freshly rerun against exact R3e, all passed.
- Candidate regression: 109 applicable tests passed with original assertions.
- Fourteen superseded R3e tests remain verbatim in `legacy_r3e.py` and are mapped
  individually to prospective replacements in `regression.py`. They require
  obsolete immediate D03 confirmation, unarmed auto-recovery, old D07 ordering,
  or unchanged successor source/plan bytes. No assertion was silently deleted.
- Adapter changes only fixture identities, a fixed fake-clock sequence, an
  additional inert authority GET, and real accepted-gate candidate fixtures in
  place of old fake candidates. The baseline history is a byte-exact local
  fixture from the pinned authority, never a public writer input.
- New R3f suite: 53 test methods across V1-V6, with additional parameterized
  counterexamples. Final raw results are included alongside this file.
- Supplemental retained reviewer suite: 30 tests freshly passed against exact
  R3e bytes. On R3f, 25 run with unchanged assertions; five positive-confirmation
  fixtures have explicit R3f replacements in `reviewer_regression.py`. Their
  framing, actual local socket EOF and malformed protected-evidence assertions
  remain required, while the original result is INDETERMINATE and recovery is
  read-only. `legacy_reviewer_r3e.py` preserves the local review harness verbatim,
  SHA-256 `6dba22dcefcf2ec08ac3443f25efc915e7bdf012c5b9d54ab4043efcf96baa87`.
  This supplemental suite uses only local socketpair endpoints, not GitHub.
- Combined accounting: 153 prior tests; 134 applicable unchanged-assertion
  regressions; 19 explicitly superseded tests; 58 R3f tests/replacements;
  192 candidate tests passing. The supplemental local reviewer harness has
  local hash provenance; no unverified remote publication identity is claimed.
- `legacy_r3e.py` is byte-identical to Mission Control evidence commit
  `69299e7cf12e280d03a490fd87505f121d82699b`, path
  `proofs/proof6/r3e-v2/test_candidate.py`, SHA-256
  `a5af15a4f6bc70726893dab007cfcf70c4e932e9f635c40650f06d3917248e4b`.

V1 covers fixed inputs, malformed/raw history/gate output, caller fault content,
permanent consumption, stale/replayed requests and qualified empty recovery.
V2 covers missing/unreadable/lookalike journals, broken ancestry, unknown schema,
wrong/malformed/detached/duplicate terminals and older canonical membership.
V3 covers old-only blocking, unarmed blocking, disposition contradictions, third
SHAs, explained later transitions, skipped obligations and wrong candidate/gate
chains. V4 covers original lifecycle crashes, strict pre-send confirmations,
fixed D03 hook placement, stale reads, partitions and explicit/ambiguous append
results. V5 covers H0/H1, both sibling winners, orphans, delayed-first R7,
every nested safety field, invalid winners, changed HEAD, later legitimate
descendants, no normal-mode hook, D07 delayed authority response and D03 replay.
V6 covers credential/classifier/framing regression linkage, maximum D03 body,
D04 timing, exact App probes/unexpected success, exact 72-row/budget accounting,
fixed proposal order, unchanged bytes and forbidden recovery authority calls.

Self-review found and corrected two implementation issues before publication:
the journal JSON parser accepted non-JSON numeric constants, and completion's
final check initially rejected fully explained later authority advances. The
new counterexamples remain in the final passing suite.

## Adversarial self-review and independent-review boundary

1. Recovery cannot call authority PATCH: only the fixed journal completion
   endpoint is reachable; production transport is trapped in offline tests.
2. Recovery cannot arm/take/recreate a send permit; those calls are absent and
   trapped in the fixed D07 test.
3. Old SHA alone blocks, including missing unarmed terminal recovery.
4. Invalid canonical terminals block without any corrective append or overwrite.
5. Detached/orphan objects confer no disposition authority.
6. All terminal and nested operation/evidence safety fields participate in the
   normative comparison; every changed nested D03 leaf compares unequal.
7. Later legitimate descendants do not erase older canonical terminal membership.
8. Each Journal.recover call has one completion PATCH and no local retry loop.
   The fixed R7 method uses two separately admitted calls, one request each.
9. The exception only constructs TERMINAL; PENDING/SEND_ARMED/CONSUMED appends
   keep their original one-attempt confirmation behavior.
10. Existing valid D03 terminal recovery is read-only; replay cannot resend it.
11. Public input cannot select parent, disposition, terminal, target, evidence
    or delay. Both original public keys and four fixed selectors are retained.
12. The sibling hook is absent from normal transition dispatch and tested there.
13. D04 has fixed 30/120-second constants and rejects public duration controls.
14. Accepted reducer/gate/classifier bytes remain unchanged.

Independent review should inspect the exact source/build inventory, complete
recovery graph and authority reconciliation, implicit Git-parent lifecycle
binding, full normative comparison, original D03 result preservation, the two
internal R7 invocations within one workflow, fixed App payloads, all regression
dispositions and the 72-row plan. Source review must not award actual GitHub
sibling-conflict, permission rejection, ruleset enforcement, networking-isolation
or final Proof-6 credit. Provisioning/freeze/live acceptance require separate
authority after review; this branch neither performs nor authorizes them.
