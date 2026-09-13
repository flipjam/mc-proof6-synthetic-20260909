# R3i bounded pre-filter custody correction

Reviewed parent: f0fab30f43954340def4f46ac9fff1fdc3ec5afd (PARTIAL_R3I_SOURCE).
Its R3I_REVIEW.md and evidence remain historical; the claim that every forbidden
delivery was rejected before filtering was disproved by independent review.
This descendant corrects that one defect. No authority amendment is required.

## Credential-slot policy and exact correction

The existing implementation uses explicit PUBLIC_ENV, SYSTEM_ENV and WRITER_ENV
allowlists, a dedicated PROOF6_D04_STATUS_TOKEN slot, the PROOF6_APP prefix, and
GH_TOKEN/PROOF6_D03_JOB_TOKEN for other fixed execution paths. These allowlists
and the exclusive final-process custody audit are unchanged.

Before filtering, launch_environment now rejects GITHUB_TOKEN and GH_TOKEN in
all four roles. It rejects every PROOF6_ implementation slot absent from the
existing role allowlist, also retaining the earlier PROOF6_APP prefix guard.
This closes unknown implementation credential slots without guessing credential
values or applying a generic TOKEN suffix rule to ordinary runner variables.
Name presence is decisive: an empty forbidden slot rejects too.

The helper/setup-helper alone may receive the nonempty dedicated status slot.
The writer retains its existing App token/installation/slug, frozen manifest and
D04 setup qualification inputs. Setup-peer receives none of those. No role
receives an App private key through this launch boundary. The existing ordinary
writer job's separate credential path is unchanged.

Only after rejecting forbidden delivery does the launch construct its fixed
environment and exec the unchanged process. Benign runner extras, including
DEBIAN_FRONTEND and 47 modeled ordinary extras, remain filterable. A harmless
nonimplementation name ending in TOKEN is also tested as filterable; this is a
bounded implementation-slot policy, not a claim to identify arbitrary secrets
in every possible host variable. No hostile-root secrecy claim is introduced.

The only other production change is the fixed FORBIDDEN_CREDENTIAL_SLOT stage.
Its failure record contains no slot name, value, arbitrary exception string or
environment dump. The unchanged cleanup/replay path retains that failure before
returning nonzero; qualification cannot become successful to preserve logging.

## Reproduction and verification

The exact partial source and all tracked bytes were checked before changes.
Its full 433-test suite passed with its original build and plan hashes.
Real native Linux launch/exec/setup with exact retained partial source reproduced
both inherited GITHUB_TOKEN and PROOF6_NEW_API_TOKEN counterexamples separately:
helper and peer qualified, completed IPC and reaped despite forbidden delivery.
These are recorded defect reproductions, not acceptance passes.

New unit and native tests inject exactly one forbidden slot at a time, with both
empty and inert values, into clean role-specific environments. All four roles
must reject before LAUNCH_EXEC, binding/IPC/qualification or provider activity.
Native failure logs have only launch, forbidden-slot and BLOCKED records, no
socket/readiness marker, and the launcher is reaped. The native fixture denies
INET sockets, provider calls and authority/journal module paths. It never runs
the authority writer, actual isolation or a D04 consumption operation.

Positive native setup uses the same accepted permission parser and pinned runner
header against an inert masked Worker fixture, plus real process custody, Unix
IPC, identity checks, completion and reaping. It performs zero status POSTs.
It is offline evidence, not new hosted qualification. Existing unknown-runner,
permission-failure, SCM_RIGHTS, truncation, empty-packet, timeout and reaping
regressions remain intact. Final test counts/hashes are in r3i-custody-evidence.

## Adversarial scope review

GITHUB_TOKEN cannot be silently scrubbed, even empty. Unknown PROOF6_ names are
checked before filtering, independently of suffix/value. Correct-role inputs
still pass; downstream custody and every other signal function/class are AST
identical to the partial parent. All other production files, workflow, plan and
prior tests/evidence are byte-identical. No original assertion was deleted or
weakened. Native tests reproduce old success and corrected rejection, rather
than crediting a rejection caused by another already-forbidden slot.

Setup cannot reach IPC or qualification after wrong-role delivery. No new
status API or credential path exists. Live D04, isolation predicates, 30-second
window, 120-second cap, permanent consumption/no refund, transport, journal,
recovery and siblings are unchanged. Provider propagation is still an accepted
fail-closed availability limit, not guaranteed by any offline test.

## Prospective state

Plan bytes/hash and ten-run campaign are unchanged: 72 mandatory fresh,
0 inherited, 0 NOT_APPLICABLE. Canary #48, failed S1 #49 and diagnostic #50 retain
zero acceptance credit. R3i still requires a fresh future GENESIS and separate
provisioning/setup/freeze authorization after focused independent re-review.
Held R3h is unchanged, provisioned, genesis-only and never frozen; no rerun or
repair occurred. No hosted workflow or provider configuration write occurred.
R3i NOT ACCEPTED / NOT PROVISIONED / NOT FROZEN / NOT EXECUTED.
Proof 6 NOT PASSED. Phase 7 NOT AUTHORIZED.
