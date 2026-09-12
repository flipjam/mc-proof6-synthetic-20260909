# R3g bounded source candidate

This is source, offline verification and prospective planning only. Proof 6 is
NOT PASSED. R3g is NOT PROVISIONED, NOT FROZEN and NOT EXECUTED. Phase 7 is
unauthorized. Independent source review must precede any separately authorized
provisioning. Nothing here repairs, retries or awards credit to R3f.

## Authority and provenance

- Mission Control authority/status main: `2f93acf267b99207c7f8220cb6246787a98806ec`.
- Exact source base: `704a32834981ce1ebcfc0f963abe25297b89f304`, tree
  `bdcfc7915b3d9ca60dc5add23ecf4590cc77515a`. This branch starts there, not on
  the temporary diagnostic branch.
- Hosted diagnostic #45 / 34680020137, job 103516833238, attempt 1:
  dispatch `bcd59d11eae403a37395aa7fb7ad9bd54ab433c1`, evidence commit
  `6205c576cc12ddb0dd235a4acf3ba76d775a62ad`.
- Raw diagnostic job-log SHA-256:
  `774e397542258edcc305e0a684da87bc6f6a2fcc202ea16f3a0984bc816ede6d`.
- Image ubuntu24 / 20260907.300.1; kernel 6.17.0-1022-azure; EUID 0,
  CAP_SYS_ADMIN present, Seccomp 0, LSM unconfined. libc and unshare succeeded
  with return 0 / errno 0. Netns changed from net:[4026531833] to
  net:[4026532219]. Interfaces were exactly lo; IPv4 read succeeded with zero
  lines. IPv6 retained summary: two rows, interfaces lo. Connection failed
  with gaierror / -3; parent netns stayed unchanged; native exit was not timeout.

The old IPv4 header-count predicate rejected this successfully observed empty
route file. The offline reproduction now accepts that IPv4 observation. Raw
IPv6 rows were NOT retained by #45: `d04_fixtures.py` supplies explicitly
authored reject-route rows matching its summary. Those rows are not reconstructed
hosted bytes and do not establish what every original IPv6 field contained.
The IPv6 criteria below are frozen prospectively. Diagnostic evidence has zero
acceptance credit, and does not retrospectively supply missing #44 observations.

## Exact functional changes

`d04_capability.py` is the shared process-local libc/unshare primitive and fixed
predicate. It imports no writer, journal or gate, and never forks or reconnects.
Qualification requires every observation to succeed:

1. errno-preserving libc unshare(CLONE_NEWNET) returns 0 with cleared errno 0.
2. The current interpreter's netns changes and interfaces are exactly `["lo"]`.
3. IPv4 read succeeds. Empty bytes qualify; an exact tokenized proc header with
   no data rows qualifies. Whitespace-only, malformed, unreadable and oversized
   content fail. Every data route is conservatively rejected, even one on lo.
4. IPv6 read succeeds with at most 256 strict ten-field rows. Prefixes are at
   most 128; interface is lo, next hop is zero, gateway flag is absent. Source
   is ::/0 or ::1/128. Destination is ::1/128, ff00::/8 on lo, or ::/0 with the
   reject flag 0x200. Any other destination, source, gateway or interface fails.
5. A one-second connection attempt to fixed api.github.com:443 fails with an
   explicitly recognized Linux network/DNS/timeout result. Permission errors,
   malformed observations and unknown errors cannot qualify. DNS failure alone
   is insufficient because every namespace/interface/route condition is required.

The fixed record includes process/context identifiers, capability/seccomp/LSM,
libc/unshare return and errno, routes, connectivity, bounded exception type/errno,
stage, elapsed duration and qualification. No arbitrary exception text, broad
environment dump, credential or authorization value is emitted. Leaf stdout is
schema-validated before retention. Schema/version and predicate are bound in the
plan and build inventory.

`d04_prerequisite.py` launches one fixed absolute leaf with Python -I -B,
closed descriptors and DEVNULL stdin/stderr. Its environment contains only fixed
PATH/LANG and the five allowlisted provider runner/image keys. It has no caller
parameters, writer imports or provider API calls. Parent and leaf starting
contexts must match on kernel, euid, full effective-capability mask and
CAP_SYS_ADMIN, seccomp, LSM, runner/image keys and starting netns; PID must differ.
Parent context is checked again after the child exits. Only a schema-qualified
leaf, zero supervisor exit and matching unchanged parent qualify.

The fixed inner native command is `timeout --foreground --signal=KILL 20s`.
Here --foreground intentionally keeps the nonforking leaf in the enclosing
writer's process group. The actual writer retains the original OUTER
`timeout --signal=KILL 120s`, without --foreground, and inherits no new session.
This lets the outer kill cover the runtime, inner supervisor and leaf. A killed
inner leaf returns a failing supervisor status (124 in the native timeout
fixture); every nonzero status blocks. No reconnect/fallback child exists.

Setup runs this prerequisite before App-token acquisition in the sole workflow.
Failure stops normal downstream steps, so setup cannot qualify for a later
freeze. Success is retained as a non-acceptance setup receipt, validated before
the existing App setup diagnostic. No new credential or privilege model exists.
The trusted root leaf is not claimed to be an adversarial sandbox: the fixed
code reads only its own prescribed observations and receives no credentials.

Actual D04 ordering is frozen/caller/runtime qualification, full journal and
admission reconstruction, unspent-operation check, prerequisite, context match,
unchanged journal reread, permanent CONSUMED, then actual writer isolation.
Unresolved recovery blocks this D04 admission before any append; the existing
separately admitted recovery-only path remains the way to resolve it. This
prevents recovery from writing a terminal before a subsequently failed helper.
The recovery algorithm and terminal semantics are unchanged.

Pre-consumption failures report PRECONDITION_BLOCKED without journal/authority
mutation. An attempted but unconfirmed consumption reports
D04_CONSUMPTION_UNCONFIRMED; it never asserts unspent status. Confirmed consumption
followed by actual failure reports D04_FAILED_CONSUMED, permanently. No refund or
retry path exists. The actual writer clears its installation token, unshares
itself, requires READY, waits the fixed 30 seconds, re-observes, and emits END.
The workflow records SUPERVISOR_COMPLETED only on exit 0; failures retain numeric
exit status. A simultaneously connected qualified ordinary-client authority
probe and successful actual END/native completion remain mandatory. Helper PASS
never supplies any of them.

## Regression and preservation

Before edits, all 206 tests passed on exact R3f Git-blob bytes: 53 R3f, 109
legacy regression, 30 reviewer and 14 caller-type tests. An initial Windows
autocrlf checkout failed build hashes; restoring exact tracked blob bytes in this
fresh task worktree resolved that checkout issue before baseline verification.
The baseline source and original assertion files were not edited.

R3g retains 198 prior tests with assertion bodies preserved. `support.py` only
adapts successor fixture identities and supplies an inert prior-step setup
receipt. `r3g_regression.py` changes R3f identity literals in memory and declares
all eight replaced tests in `REPLACEMENTS`, with named focused replacements.
The 168 non-reviewer regressions deny socket creation; the 30 reviewer tests keep
their existing local socketpair fixtures. No test invokes live unshare or a
GitHub request. The separate Linux native fixtures use inert children and local
socketpairs to check descriptors, credentials, parent continuity, reaping and
nested native process-group termination; they supply no hosted capability credit.
Exact final counts, logs and hashes are in `r3g-evidence/test-results.json`.

`writer.py`, `journal.py`, `app_probes.py` and `d03_job_token.py` differ solely
by mechanical R3f-to-R3g identity replacement. Accepted reducer, gate, D03
classifier, authority transport, conflict-safe terminal completion, sibling
canary, durable recovery and other safety modules are byte-identical or covered
by that exact identity-normalization assertion. The original six assertion
files remain byte-identical. `source-inventory.json` records before/after Git
blob and SHA-256 identities for the complete build-bound source/test inventory
and all base tracked files. Historical R3f review/inventory files are retained
as historical artifacts; use this review and r3g-evidence for the candidate.

## Prospective plan

All 72 mandatory IDs have explicit canonical required action/result text,
FRESH disposition and evidence-group mappings. Counts remain 56 FRESH_R3G plus
16 NO_VALID_PRIOR_EVIDENCE_SO_FRESH, zero inherited and zero NOT_APPLICABLE.
R3f had no qualified behavioral PASS package. The diagnostic supplies provenance,
not an inherited row. `verify_r3g.py` compares each row to the exact authority
matrix blob retained in evidence, and checks workflow YAML and every Bash block.

The ten planned protected-writer executions remain:
S1 setup; freeze gate; F4 D04; F2 D02/App probes; F3 D03 confirmation loss;
R3 recovery confirmation; O1/O2 concurrent positive pair/stale loser; F7 D07;
supporting-evidence deletion; R7 conflict-safe sibling recovery; O3 consumed
replay; independent review. This is one setup, four faults, two recovery and
three ordinary runs. Direct ordinary-client negative/security probes, source
fixtures, role audit and independent review are additional required evidence
work, not ten total provider interactions. Every live proof operation remains
once-only. Failure before consumption grants neither acceptance nor automatic
authority for another workflow dispatch.

Runtime/journal names and schemas are R3g. A future fresh journal must begin at
its own bound GENESIS; it cannot inherit R3f consumption or use the R3f journal.
Provider-assigned runtime SHA, genesis identities, ruleset IDs, manifest hash,
first mutation run and deployment-policy identity remain explicitly deferred.
No semantic isolation/transport/recovery decision is deferred: source review and
separately authorized provisioning must resolve actual identities and verify
them before freeze. Setup qualification can still fail on a future runner.

## Adversarial self-review answers

1. No safety property was weakened to fit the runner. The brittle header count
   became a strict successful-read/no-data-route predicate; other checks remain.
2. Unreadable or malformed routing fails, including at the final observation.
3. Non-lo interface, external IPv6 destination/source or gateway, any IPv4 data
   route, unchanged netns or successful connection prevents qualification.
4. DNS failure alone cannot qualify; all independent observations are mandatory.
5. Netns change is mandatory in the actual process as well as the leaf.
6. Both use the same production isolate/observe implementation and policy.
7. Setup/helper PASS has explicit zero acceptance credit and cannot emit READY.
8. Actual D04 cannot consume before qualified, context-matching prerequisite and
   unchanged full journal membership checks.
9. A failed prerequisite cannot append or mutate authority. Unresolved recovery
   blocks D04 admission first, without altering accepted recovery semantics.
10. No credentials are passed to the fixed leaf; descriptors are closed and no
    credential-reading or provider-request path exists in its code.
11. No caller command/target/predicate/duration/runner/credential selector exists.
12. Failure after consumption stays consumed. Ambiguous consumption never claims
    unspent status. No refund, retry, reconnect or replacement-send path exists.
13. Diagnostics retain only bounded fixed-schema observations and allowlisted
    exception type/errno; arbitrary exception strings and secret fields fail.
14. Reducer/gate/classifier/transport/recovery/sibling semantics did not move;
    preservation and applicable regressions verify this boundary.
15. R3g requires its own future genesis; no journal or runtime was created here.
16. The source plan specifies its semantics, ordering, predicates and all rows;
    only later live identity binding and mandatory independent review remain.

Self-review corrections included the inner supervisor process-group escape,
strict unexpected-connect-error rejection, and truthful end-observation schema
and read-success reporting. A native fixture initially assumed exit 137;
measured GNU timeout --foreground returns 124 on deadline, also correctly blocked.
No unresolved consequential source issue remains for this implementer. This is
not independent acceptance or a guarantee that future hosted setup will qualify.

## Independent source-review focus

Verify exact published commit/tree, source base, build/plan/inventory/evidence
hashes; review strict route parsing and error classes; inspect credential-free
leaf launch and outer process-group coverage; challenge no-append-before-helper
and ambiguous/post-consumption failure behavior; verify shared actual-process
READY/window/END semantics; review each replacement-test mapping and 72-row
evidence group; compare preserved mechanisms by raw bytes/identity normalization.
Re-fetch protected R3f state and authority. Publication is source/status only,
and does not authorize provisioning, freeze, acceptance or Phase 7.
