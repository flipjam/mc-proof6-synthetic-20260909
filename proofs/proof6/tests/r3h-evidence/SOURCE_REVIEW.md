# R3h source candidate: D04 live signal

Source only. NOT PROVISIONED, NOT FROZEN, NOT EXECUTED, NOT ACCEPTED.
Proof 6 remains IN PROGRESS / NOT PASSED. Phase 7 is not authorized.

The parent is accepted R3g source `73b686f16b052695a4c41706b4b777206a6b0ba1`.
R3g F4 run 34712070826 completed real isolation, but had no ordinary authority
PATCH during its READY/END interval because live job logs were unavailable.
Its D04 consumption is permanent. Neither R3g isolation nor the diagnostic
status canary supplies any R3h behavioral credit. All 72 rows are fresh.

## Canary and authority

Mission Control main: `d754156067cf1aa2318e7b04d7fcf47902eb9846`.
Contract blob: `39c23543d25119b6fe0b404e84e9ad912c87d01a`.
Matrix blob: `373754b4c2721e2d78d6cfa4d48b2aad786bbbe0`.
Only the landed C11/D04/F07 status-helper exception is applied.

The single diagnostic canary passed, run 34715785446 / job 103612664751 /
attempt 1. Dispatch source: `2b7d0fa62e41bc500f6bf2dc5c540910501cabc3`.
Durable evidence: `a272b335e884e88ddc88155f5bd1691d1a647606` on
`codex/proof6-r3h-live-status-canary-20260912-01` in this repository.
READY was externally observed at 2026-09-12T20:00:20.978913Z; the job was
independently observed in_progress at 20:00:21.967786Z. Actual producer END
followed 17.664246 seconds after that active-job confirmation. The diagnostic
used only Metadata:read and Statuses:write. Its preserved before/after
snapshots established repository-wide status noninterference and unchanged
protected refs, rulesets, environment, manifest and historical journal.
The evidence branch's final encoding-only commit preserves original bytes
and makes every recorded SHA-256 independently reproducible from Git blobs.

## Functional boundary

One workflow now has two mutually exclusive, exact-operation job conditions.
Both retain the same protected runtime/environment and sole fixed concurrency
group. The ordinary `writer` job retains contents:read/actions:read and its
existing same-job D03 token. The `d04_writer` job has only statuses:write;
unspecified job-token permissions are none, apart from provider metadata read.

The D04 helper starts in a separate workflow step before the App-token action.
Only that helper step and its fixed native launch/supervision path receive the
status token. The actual writer step receives no job token, no status token,
and no App private key. It retains its existing App installation token.
Public fixed runtime/configuration GETs use no credential. Only the unchanged
fixed caller-permission GET uses the existing App's metadata-read permission.
The caller decision and App grants are unchanged. No App is substituted for
the ordinary/D03 GITHUB_TOKEN, and no authority PATCH transport changes.

The helper has no writer/journal/gate imports, App-token delivery, credential
file, opposite-process environment/FD read, or generalized endpoint selector.
It uses one fixed run/attempt/runtime-bound Unix socket. SO_PEERCRED binds
the connected actual writer PID; its fixed command line and live namespace
are checked without reading its credentials. Only canonical READY then END
writer packets are allowed. Status target is the exact frozen runtime SHA;
context is `proof6/d04-signal/<run_id>/1/<runtime_sha>`. No ref is mutated to
signal. Provider calls disable proxies/redirects and have a five-second cap.

The actual writer emits local READY through the existing qualified-isolation
callback without waiting for the provider. Its unchanged 30-second loop and
fresh END predicate still precede local END. At END it checks both provider
acknowledgments; provider latency cannot extend the timer before it starts. The helper
checks schema, types, run/attempt/runtime/target/context, PID, qualification,
fresh monotonic timestamp, sequence, interval and actual namespace. END has
to be acknowledged before runtime success. A status is evidence only.

## Custody and provider dependency

Both role entry points inspect their own initial kernel environment, exact
argv and descriptor map. This catches exposure before environment popping,
extra descriptors, readable output handles and shared credential stdin.
Receipts contain names and nonsecret qualification results, never values.
The source fixes all workflow token slots; the App action's output remains
bound to the App slot. Offline role tests use synthetic sentinels only.

The sole helper ancestor inspection reads the actual Runner.Worker diagnostic
to qualify server-supplied effective permissions. Before reading its job
payload, a bounded prefix must identify runner 2.337.0 and source commit
`397b032cbf865e9c3ddfab89d533ec19325e1273`. The vendored MIT-licensed provider
source shows Worker initializing the secret masker before logging the job
message, and Tracing masking the message before output. No raw diagnostic is
retained. This is a trusted-provider source dependency, not a new claim of
secrecy against hostile root/provider introspection. Unknown runner builds
block before reading the payload and before consumption. The canary observed
runner version 2.337.0; it did not attest an R3h hosted execution.

The native offline model executes production Client/helper/custody/IPC code
with fixed-argv local wrappers, synthetic credentials and INET sockets denied.
It deliberately does not instantiate the authority writer or actually isolate
a process. It supplies execution-path regression evidence, not live isolation,
provider permissions, protected-state enforcement or acceptance evidence.
This local WSL host denied a separate credential-free CLONE_NEWNET capability
check with errno 13; it did not change namespace. The local tests therefore do
not claim IPC across a real namespace transition. The fixed socket uses a
filesystem pathname, not Linux's network-namespace-isolated abstract socket
namespace (see the Linux network_namespaces(7) and unix(7) manuals). The actual
R3h hosted integration still requires the full prospective D04 evidence.

## Readiness, deadlines and unavoidable limits

The existing credential-free isolation prerequisite is unchanged. After its
success, the writer requires a qualified helper peer and provider target/context
GET, then rereads the unchanged journal head, rechecks channel liveness and at
least 50 seconds of helper budget, and only then calls permanent consume.
Known helper/permission/provider/readiness failures leave D04 unconsumed.
Neither failed consumption confirmation nor any later signaling failure
refunds or retries D04.

The helper has a 105-second alarm and its own native 120-second process-group
cap, starting earlier than the unchanged actual writer's native 120-second
cap. The fixed shell supervisor waits for the helper's native supervisor.
An always-run cleanup confirms the helper PID disappeared and the wait result;
incomplete helpers are terminated and cannot receive completion credit.

A successful GET and exact effective permission grant cannot prove that a
later status POST will succeed or propagate within a useful interval. Public
GET rate limits and time spent confirming CONSUMED can also exhaust the
remaining budget. These limits are explicit in the plan and require independent
disposition before freeze. No hidden pre-consumption READY POST, retry, refund,
fallback surface or extra provider experiment is introduced.

## Adversarial disposition

- Repository-scoped statuses could be posted outside the intended context if
  the helper were compromised. Provider protection does not scope this token
  to one context. Fresh inspection of every reachable status authority surface
  is mandatory before freeze and throughout acceptance. The canary snapshot
  establishes only its observed interval; it is not future configuration proof.
- Stale/cross-run/duplicate/malformed IPC cannot qualify; missing actual READY
  prevents any helper READY POST. Source and tests retain real unshare and the
  accepted corrected predicates; a helper PASS cannot replace them.
- The GitHub Actions bot identity is shared across workflows. It alone cannot
  authenticate a status's origin job. The observer must retain status IDs and
  full context history; final credit requires exactly the two IDs in this
  trusted helper's HTTP-201 receipts, correlated with actual writer boundaries.
  Forged/extra/ambiguous statuses lose credit and may deny availability. They
  cannot make an early/out-of-window ordinary PATCH count or override protection.
- The ordinary probe must follow externally observed provider READY while the
  job is active, and precede actual END. A successful status alone cannot pass
  D04, satisfy protection, mutate authority, or resolve journal/recovery state.
- The App remains the sole authority/journal credential. D03/D07, reducer,
  gate, authority transport, journal/recovery and sibling behavior remain
  unchanged except exact successor identity/contract bindings where necessary.
- All 72 rows are fresh because there is no qualified R3g behavioral PASS
  package and shared runtime/workflow/security bindings changed. There is no
  implementer-awarded inherited credit or NOT_APPLICABLE row.
- Independently review the helper lifecycle, audited-runner dependency,
  public-read/App-metadata split, custody tests, repository-wide noninterference
  and the explicit pre-consumption availability limits before any provisioning
  or freeze decision. Source publication grants none of those later actions.

## Offline reproduction

Use exact Git bytes (disable Windows checkout CRLF conversion). From the
candidate root, run the following. Provider/authority transport remains inert.

```
python -B proofs/proof6/tests/r3h_regression.py
python -B proofs/proof6/tests/r3h_prior.py
python -B proofs/proof6/tests/r3h_correction.py
python -B proofs/proof6/tests/test_r3h.py
python -B proofs/proof6/tests/verify_r3h.py
```

Run `native_prerequisite_fixture.py` in Linux/WSL, and
`native_r3h_signal_fixture.py` as local WSL root. The latter uses synthetic
credentials and denies all INET sockets; root is required only to reproduce
the fixed peer/owner/descriptor boundaries. It does not run acceptance.

## Official provider source references

- https://docs.github.com/en/rest/commits/statuses
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions
- https://docs.github.com/en/rest/collaborators/collaborators#get-repository-permissions-for-a-user
- https://github.com/actions/runner/tree/397b032cbf865e9c3ddfab89d533ec19325e1273
- https://man7.org/linux/man-pages/man7/network_namespaces.7.html
- https://man7.org/linux/man-pages/man7/unix.7.html

The next gate is one independent R3h source review. No R3h runtime, journal,
provider identity, environment/ruleset update, manifest, S1, freeze or acceptance
execution is authorized or performed by this source candidate.
