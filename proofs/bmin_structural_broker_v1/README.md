# B-MIN structural broker V1 - source candidate only

This additive implementation is for one disposable ref in
`flipjam/mc-proof6-synthetic-20260909`. It is not provisioned, frozen, dispatched,
accepted, or a proof of live credential custody. Independent exact-source review
is required before provisioning. No Mission Control or Game Factory target exists
in the executable target mapping.

## Small interface

The ordinary client supplies only UTF-8 JSON:

```json
{"schema":"BMIN_PROPOSAL_V1","action":"ADVANCE_ROADMAP","expected_state_sha256":"<64 lowercase hex digits>","expected_baton":0}
```

Only these four fields are accepted. Duplicate keys, floats, booleans as integers,
unknown/missing fields, non-JSON data and oversized proposals are rejected. The
state digest and baton describe intended transition preconditions; neither grants
authority. Canonical sorted compact ASCII JSON determines the proposal digest.
Project, subject, loop, proposal ID, repository, ref, candidate and authority are
derived internally. The accepted Proof-2 gate receives its existing vocabulary.

`Broker.submit(raw)` is the only proposal entry point. Its provider/configuration
objects are privileged composition, never deserialized from caller input. Python
object visibility is **not** a process isolation mechanism: the ordinary client
must have no execution access inside this job. The workflow input is data passed
through an environment value, never interpolated into shell source.

## Reused components and bounded adaptation

- Import unchanged `proofs/proof1/replay.py`: strict JSON/canonical reconstruction.
- Import unchanged `proofs/proof2/gate.py`: deterministic `ADVANCE_ROADMAP` gate.
- Import unchanged `proofs/proof6/write_safety_closure_v1/ruleset_view.py`: stable
  provider policy identity projection, including normalized server change time.
- Adapt minimal historical fixed-target/non-force transport, exact one-parent
  construction, protected journal ancestry and never-resend principles.

The supplied synthetic historical source has no Proof-5 rule resolver. No new
general rule language is introduced. Accepted gate rules are source-pinned;
current provider policy is resolved by exact frozen ruleset IDs plus each fixed
ref's effective rules. All relevant snapshots must match the frozen digest.
Unknown extra applicable rules and incomplete effective-rule pages fail closed.
No Q0, host inventory, campaign, accounting, compatibility, D03/D07 or old journal
module is imported. Frozen historical source and evidence are unchanged.

## Authorization and candidate

After internal ALLOW, `BMIN_AUTHORIZED_TRANSITION_V1` binds configuration,
repository ID/name, project, authority ref, NON_FORCE_FAST_FORWARD, canonical
proposal, old SHA, reconstructed state, policy, gate source/decision, event/content,
candidate SHA, runtime source/commit, App/installation, operation ID and journal
identity/lifecycle. Its digest is over canonical JSON. It never leaves the broker
as a usable token and is never accepted from the caller. There is no PKI.

The candidate contains only `history.json`, the exact prior history plus the gate's
one computed event. The predicted state must differ. Parent is exactly the old
authority. Fixed author, committer, time, message and tree bytes determine its Git
SHA internally. GitHub object creation results and a subsequent object read must
match those exact bytes/parent. Objects may be uploaded before send; those are
setup/object writes, not authority-ref advancement. No caller-supplied Git runs.

## Durable one-operation lifecycle

The separate protected `refs/heads/bmin-v1-journal` starts at a separately frozen
GENESIS. Each journal commit contains only canonical `journal.json` and exactly
one parent. Replay reads the complete bounded ancestry to GENESIS, validates the
lifecycle, reconstructs the exact internal authorization from baseline history,
and checks the exact candidate. Non-force sibling append prevents dual arming.
Journal writes have no retries; an unconfirmed append stops the invocation.

`GENESIS -> PREPARED -> SEND_ARMED -> TERMINAL(COMMITTED)`

`GENESIS -> PREPARED -> TERMINAL(NO_SEND)`

The proof supports **one operation total**, not one per caller ID. Its identity is
SHA-256 of frozen-config digest and canonical-proposal digest. PREPARED consumes
the proof lifecycle even if a crash precedes arming; a later invocation can only
finish NO_SEND. Any different proposal after preparation is blocked. Replays
after terminal return the prior disposition only if authority remains consistent.
Before preparation, rejected submissions create no operation; an independently
valid proposal may still become the sole operation.

Both before and after durable arming, the broker repeats target, authority,
reconstruction, policy and runtime checks. The adapter repeats these at its own
transport boundary, then sends exactly one fixed `PATCH` with `force: false`.
SEND_ARMED is never permission for a fresh invocation to send. The transport has
an additional in-process latch, consumed before socket work; no retries,
redirects, proxies, rebase, force, fallback or automatic resend exist.

The fixed `ONE_SEND_DROP_RESPONSE_V1` transport intentionally never reads its
PATCH response. A completed request boundary returns INDETERMINATE; socket errors
also leave SEND_ARMED. There is no caller-selectable fault mode. Unknown provider
results fail closed. The proof makes **no definitive rejection inference** from
HTTP status or observing the old ref: because this scenario discards the complete
response, there is no retained evidence sufficient to establish provider rejection.
Consequently no `PROVIDER_REJECTED` terminal is reachable in V1. NO_SEND is only
for a proven pre-arm rejection/abandoned PREPARED operation, never an armed one.

Fresh-process recovery can append a terminal journal record but cannot transmit
authority. Candidate observed means COMMITTED after exact candidate/ancestry
verification. Old observed while armed remains unresolved; neither old nor
candidate means conflict. Malformed/missing/contradictory evidence blocks. A
terminal append failure cannot erase SEND_ARMED. Failed safety checks may consume
availability; there is no automatic repair or reset.

## Trusted freeze inputs (not ordinary input)

The privileged environment must supply `BMIN_FROZEN_CONFIG` as exact JSON bytes,
`BMIN_CONFIG_SHA256` as their SHA-256, and `BMIN_APP_ID`. Config schema is
`BMIN_FROZEN_CONFIG_V1`; `core.validate_config` enumerates the exact required keys.

Fixed constants: repository/name ID `1363510385`, project same repository,
subject `bmin-synthetic-authority`, loop `bmin-synthetic-v1`, refs `bmin-v1-authority`,
`bmin-v1-journal`, `bmin-v1-runtime`, environment `bmin-structural-broker-v1`, and
scenario `ONE_SEND_DROP_RESPONSE_V1`.

Not yet provisioned: runtime commit SHA; initial authority SHA; journal genesis
SHA; exact App ID/slug/installation; six sorted ruleset IDs (integrity and update
for each fixed ref); policy digest; exact source hash map. No live values for these
are invented or inherited from old campaigns. Source hashes are raw Git blob
bytes (LF Python/YAML), enumerated by `core.SOURCE_FILES`; do not hash a Windows
CRLF checkout. The map includes workflow, broker, launcher, provider, journal,
core and all imported components. Accepted replay/gate hashes are additionally
hard-coded. The config digest is not a signature: secret-store/runtime protection
and separate out-of-band ownership are mandatory prerequisites.

`GitHub.policy()` defines the exact frozen digest input: sorted-ID stable ruleset
views including visible bypass actors, and canonically sorted complete effective
rules for all three refs. It hashes policy identity, not an assertion that a policy
is secure. Independent provisioning review must verify the required protections
below before freezing that digest. The restricted token may omit bypass actors;
freeze and runtime must use the same observable projection, while owner evidence
must separately establish the full bypass policy.

App private material is referenced only as isolated environment secret
`BMIN_APP_PRIVATE_KEY`. The pinned official token action creates a repository-only
Contents-write/Metadata-read installation token within the broker job and revokes
it afterward. Built-in GITHUB_TOKEN is Contents-read only. Token handling is never
logged. Installation scope and action installation ID/slug are checked, as are
job/workflow/ref/SHA/run-attempt and current runtime ref.

## Verification

From an LF checkout with Python and Git:

```text
python -B proofs/bmin_structural_broker_v1/verify.py --architecture-repo D:/Projects/mission-control
```

The verifier reads original Proof-1/2 baseline tests from local architectural
authority `6ba4056b4714e7481636a93cee8d4690b6d8f521` and runs them in scratch against
the reused synthetic source. It does not modify Mission Control. Python network
audit guards and socket mocks block network; native Git tests allow local file
protocol only. `verification.json` records exact source hashes, test counts and
outputs. Source/offline PASS does not prove live isolation or provider behavior.

API references: [Git references](https://docs.github.com/en/rest/git/refs),
[official token action](https://github.com/actions/create-github-app-token),
[GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).
