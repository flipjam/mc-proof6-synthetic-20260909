# P6-WS-CLOSURE-V1 source candidate

Source-only implementation based exactly on R3j commit
`118e8bbe2994689e819f7ae217e43df7df3f70b9`, tree
`478f5a466690cd6c4ab96d94da25ffd052b00603`.
No live manifest, genesis, authority, runtime, environment, ruleset or credential
is supplied. Nothing here is a provisioning script. All fixtures are synthetic.

## Fixed interface and budget

The hosted input has exactly one choice, `case`: `RECOVER`,
`D03_REMOTE_REJECTION`, `D07_DROP_PATCH_RESPONSE`, or `POSTRECOVERY`.
The first two fault cases bind respectively to `P6WSV1-D03-01` /
`p6ws-v1-d03` and `P6WSV1-D07-01` / `p6ws-v1-d07`.
The normal case binds to `P6WSV1-POSTRECOVERY-01` /
`p6ws-v1-postrecovery`. There are no caller-supplied proposals, operation
authorization IDs, endpoints, refs, credentials, candidates or dispositions.

The successful path has 2 consumptions, 3 authority PATCH attempts, 2 authority
advances, 12 journal PATCH attempts and 11 journal advances. Q0 consumes zero.
The additional journal attempt is the noncanonical D07 sibling.

## Source and future freeze boundary

`build.json` binds all executable source and the new workflow, plus the unchanged
Proof-1 reducer and Proof-2 gate. Its digest is subsequently manifest-bound;
the build deliberately does not contain its own digest or a future commit SHA.
`qualification.validate_manifest` defines the complete future freeze schema.
It binds the fresh baseline history/state, genesis/schema, exact source commit
and tree, fixed runtime/ref/environment names, plan, proposals, full ruleset
snapshots, deployment/reviewer policy and credential-custody metadata.

`qualification.qualify_q0` validates separately acquired Q0 receipts. Those
receipts must first be independently reviewed and installed under the separately
authorized freeze procedure. Source fixtures cannot establish real custody,
provider protection, App permission or ordinary-client qualifications.
The ordinary client must have write role, no admin/maintain capability, a qualified
MINIPC-KWR53 credential-provider inventory, one positive-control receipt and four
distinct protected-write denial receipts. The workflow has no setup/bootstrap path and requires the
separately frozen manifest/hash/Q0 variables in the fresh environment.

Manual workflow_dispatch is the only trigger; the job additionally requires the
exact future runtime ref/workflow identity. Pushing this task branch does not run
either workflow in this repository. This candidate must undergo independent
Mission Control review before any provisioning or execution authorization.

## R3j comparison and invariants

All 15 requested safety invariants are preserved. The authority `_patch` AST is
identical except for the fixed ref literal. Permit destruction precedes the
single non-force transport; D03 substitution remains confined to that transport;
D07 drops only after transmission and before response consumption.

Byte-identical reuse: Proof-1, Proof-2, sibling completion and journal confirmation
diagnostics. D03 classifier functions have identical ASTs; its import is changed
to the pure common module and its URL is rebound to the fresh authority ref.
D03 worker inspection/permission validation is unchanged; only the fixed workflow,
runtime and environment token slot are rebound.

Changed safety-adjacent blocks:

- Writer manifest/configuration/runtime/baseline bindings use the fresh schema.
- Admission accepts only fixed manifest proposals, performs read-only reconciliation,
  requires explicit recovery for outstanding sends, rejects reuse, and requires
  canonical D07 COMMITTED before the sole normal transition.
- Gate rejection now precedes permanent fault consumption. An admitted fault is
  still consumed before candidate objects, PENDING, SEND_ARMED or transport.
- Journal bindings add fixed authorization IDs; replay enforces D03 then D07 then
  one normal case. Full frozen rulesets are compared through the same visible view;
  existing bypass validation is retained.
- Journal reconciliation uses the fresh manifest baseline; the D03 loss exception
  name changes. Confirmation, ancestry reconstruction, send permit, terminal
  semantics and conflict-safe recovery bodies are unchanged.
- Old setup helpers and excluded operation/large-campaign machinery are omitted.

`tests/source-review.json` mechanically enumerates exact changed, unchanged and
removed functions. Its assertion of invariant preservation is supported by the
listed AST comparisons and the focused behavioral tests; it is not live proof.

## Independent collector

`collector.collect(manifest, evidence, get)` accepts a read-only acquisition
function; `ReadOnlyRemote.get` implements fixed-repository GETs, refusing redirects.
The collector never imports the writer, journal or sibling mutation modules.
It independently reconstructs the entire canonical journal, baseline and gated
candidate chain; inspects source commit/tree/blob hashes; compares runtime,
rulesets and environment evidence; and checks canonical sibling and exact mutation
accounting. Ref reads bracket the inspection, so changing or stale terminal state
does not qualify. No descendant substitutes for an exact candidate.

The evidence schema is explicit in `_inspect`: frozen Q0 receipts, authority and
journal attempts, sibling object identities, and mandatory sanitized raw process
records. Raw process records must be acquired and preserved by the later campaign
collector, with credential values excluded. In fixtures these are synthetic;
their presence is no claim that real process records have been captured. A local
writer result is ignored. Missing/contradictory evidence returns NOT_PASS; read
unavailability returns BLOCKED. Neither means live acceptance.

## Verification

Use a checkout with LF bytes (`core.autocrlf=false`) or a `git archive` extraction,
because the accepted reducer/gate and build are exact-byte bound. Historical
source blobs remain unchanged. Python 3.14 and native Windows Git were used here.

Run from the repository root:

```text
python -B proofs/proof6/write_safety_closure_v1/tests/verify_source.py
python -B proofs/proof6/write_safety_closure_v1/tests/test_closure.py
python -B proofs/proof6/write_safety_closure_v1/tests/test_native_git.py
```

The focused suite disables sockets and covers the successful path and falsification
cases. The native launcher test confirms missing freeze fails closed in an isolated
Python process. The native Git test uses temporary local bare repositories and
file-only protocol to verify sibling non-force rejection. No hosted execution,
actual worker ancestry/custody qualification or live Q0 is claimed.

Provisioning, runtime freeze, live Q0, dispatch, all live operations, PR/merge,
R3k, Phase 7 and Game Factory work remain parked.
