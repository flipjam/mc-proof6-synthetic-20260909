# R3h bounded correction source review

This is a normal descendant correction of PARTIAL_R3H_SOURCE
032076ffbcd1056c3f8f99d096e07214421e13c9. That commit and its evidence remain
historical. The accepted live-status canary at a272b335e884e88ddc88155f5bd1691d1a647606
(run 34715785446, attempt 1) is unchanged and has zero acceptance credit.

## Scope

Only the receive/completion boundary and non-consuming signal setup wiring
change production behavior. The D04 job remains structurally identical. The
ordinary job gains a dependency on a fixed setup-only job and its nonsecret,
validated qualification output. No new workflow, input, status context API,
authority credential, acceptance run, journal event or refund is introduced.
All 72 rows, their requirements/accounting, campaign order and non-S1 run
purposes remain identical to the reviewed partial source.

## Ancillary data

All receives allocate a fixed 4096-byte ancillary buffer. Native Linux limits
SCM_RIGHTS to 253 descriptors; their control representation plus credentials
fits within that bound. Every returned SCM_RIGHTS integer descriptor is closed
before validation or parsing can raise. Every control record is rejected;
all flags except MSG_EOR are rejected, including MSG_CTRUNC and MSG_TRUNC.
The real native tests receive 1, 16 and 253 descriptors and establish all are
closed, including the delivered subset after forced ancillary truncation.
The kernel closes undisclosed excess descriptors; descriptor inventory is
unchanged. The tests also construct SCM_CREDENTIALS and reject it. The protocol
does not enable SCM_PIDFD reception or any other descriptor-delivery option.
No control-bearing record may reach event_valid or a provider POST.

## Completion

After the last expected protocol response, the Linux receiver enables
SO_PASSCRED. On Linux, every queued packet then supplies SCM_CREDENTIALS,
including an empty packet queued before this option was set. Transport EOF
has no packet and no ancillary record. The common receive boundary therefore
rejects every trailing packet, including empty-then-close. Completion additionally
requires immediate POLLRDHUP with no poll error, within a five-second receive
bound. Successful writer close half-closes its write direction, checks the
helper's completion boundary, and always closes locally. Failure cleanup is
idempotent. No stream framing layer, retries or extra acceptance events exist.

Native tests cover genuine close/write-shutdown, open empty packet, empty then
close, trailing data/duplicates/malformed events/rights, idle-peer timeout and
writer-side trailing-helper rejection. Linux source references reviewed:
- https://github.com/torvalds/linux/blob/v6.8/include/net/scm.h
- https://github.com/torvalds/linux/blob/v6.8/net/unix/af_unix.c

The previously reported counterexamples were independently reproduced against
exact partial-source bytes on WSL1, and corrected reception rejected both. WSL1
has incompatible zero-length recvmsg semantics (including malformed ancillary
results), so it is not evidence for the corrected completion PASS. Native
Linux/WSL2 kernel 6.6.87.2 supplies the positive and negative socket/process
results. A temporary local Python filesystem was used; no hosted workflow ran.

## Fixed setup qualification

The existing workflow contains one new signal_setup job with exactly
Statuses write (plus unavoidable Metadata read). It is selected only for an
empty proposal/operation. All its steps require an absent frozen manifest.
On frozen empty recovery runs it does no qualification and exports no result;
the existing ordinary recovery behavior remains unchanged.

The setup helper uses the same _serve startup, initial-environment/argv/FD
custody checks, exact provider runner audit, root-owned pathname IPC and
SO_PEERCRED/cmdline validation as D04. The fixed serve-setup mode requires the
provider job identity signal_setup. Ordinary serve still requires d04_writer.
Unknown version/commit blocks before masked provider job payload is read.
The setup helper drops its token after auditing the effective grant, does not
call status_request (GET or POST), and has no App credential.

A separate qualify-setup process receives only fixed public/system environment,
readonly /dev/null stdin and write-only output pipes. It checks its own initial
custody and the helper peer identity. It exchanges only SETUP_FINISH and
SETUP_FINISHED, never READY/END. Both peers validate completion. Its native
20-second foreground command is waited/reaped by the workflow. The helper
uses the existing 105-second alarm / 120-second native supervisor and wait.
Always-run cleanup requires successful helper exit, verifies helper and peer
PIDs absent, and validates the exact run/attempt/runtime-bound result before
publishing the nonsecret output. The result cannot pass with unknown permission,
runner, wrong binding, extra fields, false custody, nonzero status POST count,
acceptance credit, or either unreaped process.

The ordinary bootstrap requires both the existing D04 isolation prerequisite
and that validated signal setup output before its unchanged App authentication
diagnostic. The normal job depends on successful setup (or a genuinely skipped
non-setup job); failure/cancellation cannot enter bootstrap. There is no setup
writer/journal construction, authority PATCH, D04 isolation or consumption in
the signal qualifier. Its peer imports only the narrow signal module and the
existing capability validator, without invoking the isolation primitive.

Native tests use the production setup modes, actual separate processes and IPC,
with synthetic masked worker records supplied to the same pinned permission
parser. All INET sockets and every status_request are forbidden. Full setup
PASS requires actual startup, handshake, shutdown and both processes reaped.
Permission/custody/IPC failures, missing helper and unknown runner fail. Source
assertions and the production bootstrap fixture forbid authority/journal/fault
paths. This is source/offline evidence only: no hosted R3h S1 has executed.

## Adversarial disposition and preserved limits

No unresolved consequential correction defect was found. No original safety
assertion was deleted: two workflow shape assertions now cover three fixed jobs,
with additional exact dependency, permission, output and unchanged-job checks.
The fixture supplies a new inert prior-step receipt; invalid/missing receipts
are tested against the real bootstrap validator.

The accepted ACCEPTABLE_FAIL_CLOSED_AVAILABILITY_LIMIT remains: preflight cannot
guarantee later provider POST or propagation. Post-consumption failure spends
D04 permanently. No refund, retry or guarantee was added. The observer policy,
HTTP-201 receipt/status-ID correlation, full context history, actual boundaries,
active-job evidence and ordinary PATCH timing/rejection remain identical.
Shared github-actions[bot] identity alone never authenticates origin.

Source tests assert byte identity to the partial source for writer, journal,
outage, D03, D04 prerequisite/predicates, App probes, admission, recovery and
sibling code. Actual 30-second isolation and 120-second writer cap are unchanged.
Canonical contract/matrix semantics remain unchanged. Hosted setup, freeze and
acceptance require later authorization and fresh provider-state verification.

Next gate: one focused independent correction re-review, limited to ancillary
validation, completion, setup qualification, hashes/tests and absence of unrelated
functional movement. R3h NOT ACCEPTED / NOT PROVISIONED / NOT FROZEN / NOT EXECUTED.
Proof 6 NOT PASSED. Phase 7 unauthorized.
