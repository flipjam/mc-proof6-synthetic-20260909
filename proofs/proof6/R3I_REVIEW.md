# R3i bounded startup correction

Source base: d4d0d448026b9f0dd0728a852d757543b550208e (accepted R3h).
Authority main: 2cb629820e3bd04e7c7edaa2b2364682e4dc5f1b.
Contract/matrix blobs remain 39c23543d25119b6fe0b404e84e9ad912c87d01a /
373754b4c2721e2d78d6cfa4d48b2aad786bbbe0.

## Cause and limit

One authorized diagnostic, run #50 / 34725078051, job 103637693071, attempt 1,
directly retained the accepted helper's initial-environment rejection at line
184. There were 48 keys outside the fixed allowlist; DEBIAN_FRONTEND was one
bounded identified key. The workflow's sudo --preserve-env list was not an
exclusive environment constructor. No socket or Worker audit had yet run.
Diagnostic source: 0e8a4f6dc9af749a8ecfd65c2fa626005da5b40f. Evidence remains on
codex/proof6-r3h-s1-startup-diagnostic-20260912-01. No second hosted run occurred.
Run #49 has no recovered hidden diagnostics; #50 establishes the reproduced
source defect, not new telemetry for #49. Later hosted stages remain unproved.

## Exact correction

d04_signal.py adds four fixed launch roles. The helper and setup peer exec the
existing native timeout with the existing fixed Python argv; the native PID
recorded by the supervisor becomes that timeout PID. The actual D04 writer
launch execs the existing actions_runtime argv under the existing outer cap.
Each launch constructs the already accepted role-specific environment rather
than trusting sudo to remove all other variables. Existing environment, argv,
FD, permission, IPC, and peer checks still run in the final process.

Wrong-role status/App/job credentials are rejected BEFORE filtering. Credential
values remain in their intended execution path's environment only, never exec
argv, IPC, logs, shared files, or discovery stores. No secrecy against hostile
root introspection is claimed. The normal writer job and App authority logic
are unchanged beyond successor identity bindings.

Fixed startup-stage records and bounded exception/errno fields cover the launch,
custody, Worker/header/permission, socket, readiness and reaping boundaries.
Cleanup output is printed before its captured nonzero status can stop the
workflow. A separate fixed bounded structured helper-log replay runs only after a
failed cleanup. Successful live completion retains exactly one copy of the
original helper status receipts. Neither failure becomes success. No arbitrary exception text,
environment dump, token, Worker payload, endpoint, command, or event input is
added. The diagnostic branch's general source-line tracer is not in R3i.

All preexisting signal functions/classes are identical after removing only the
fixed stage-record calls and mechanically rebinding R3h to R3i. In particular,
ancillary closure/truncation, zero-length packet/EOF validation, effective audit,
actual writer READY/END qualification, HTTP/status origin receipts, and ordered
consumption/probe requirements do not change. Outage primitives, route predicates,
30-second interval, 120-second cap, authority transport/reducer/gate, D03/D07,
journal/recovery and sibling completion retain their previous semantics.

## Verification and adversarial review

The exact accepted R3h baseline was reproduced: 404/404 PASS, including native
Linux IPC/setup tests. Original R3h test files remain byte-identical. Successor
copies adapt identity literals; the prior structural byte check now checks the
precise launch/replay substitution and every other workflow field for equality.
The retained native-cap assertion is bound to the fixed launch-writer argv;
native tests independently prove its final actual-writer argv/custody and outer
timeout. No old assertion was deleted from history. New tests independently check the
unchanged function ASTs after removing diagnostics and the unchanged allowlists.

The new native tests reproduce rejection with exact accepted R3h source bytes;
the corrected real helper/peer pipeline passes with 48 extra environment keys,
denies every INET call, validates permission/custody/IPC, and reaps both children.
They also verify actual writer launch custody, wrong App/status delivery,
permission failure, unknown runner, socket bind errno, and retained failed
cleanup output. Final group results and hashes are in tests/r3i-evidence.

Adversarial findings: the fix enforces the original allowlist instead of adding
48 exceptions; forbidden credential delivery cannot be erased into a PASS;
successful launch alone does not qualify a helper; the existing setup handshake,
permission audit and reaping still gate its receipt. Startup logging has only
fixed stages and bounded primitive metadata. The status endpoint/event logic
is unchanged. No provider POST/propagation availability guarantee is inferred.
Future hosted S1 can still fail closed at an unexercised later stage. Any such
failure blocks freeze and has no consumption/acceptance credit.

## Prospective state

72 mandatory fresh, 0 inherited, 0 NOT_APPLICABLE; ten-run campaign unchanged.
Canary #48, failed setup #49 and diagnostic #50 supply zero acceptance credit.
Active source refs/schema/manifest/plan identities use R3i. Historical canary
and R3h provenance remain exact. Future R3i requires a new GENESIS; no provider
IDs were invented and no runtime/journal/configuration was provisioned here.
Held R3h remains unchanged, genesis-only and unfrozen.

Source candidate only: NOT ACCEPTED / NOT PROVISIONED / NOT FROZEN / NOT EXECUTED.
Proof 6 NOT PASSED. Phase 7 NOT AUTHORIZED.
Next gate: one independent bounded R3i source review, not hosted execution.
