# Bounded Q0 evidence correction

This follow-up preserves candidate `6abcacf09d390d35e6dc1aaa96e9905879efad17`
and changes only the prospective Q0 evidence model. Writer/D03/D07 transport,
journal/send/recovery, plan, budgets, launcher and workflow bytes are unchanged.
No credentials or provider metadata have been acquired live in this correction.

## Evidence versions and freeze binding

Q0 now requires `P6WSV1_Q0_V2`. Its custody policy requires
`P6WSV1_CUSTODY_V2`, an explicit ordinary execution context, a nonsecret provider
credential-record ID, an inventory SHA-256 and a provider-custody SHA-256.
The existing outer manifest and Q0 digest also bind these receipts. The obsolete
`ordinary_has_writer_secret` / `ordinary_has_admin_credential` assertions are
removed; matching a secret name or a custody boolean cannot qualify.

The source still contains no provisioned machine GUID, user SID, profile identifier,
inventory digest, provider receipt, or live manifest. Fixture values are synthetic.
The later independent Q0 acquisition/review must populate and freeze those exact
metadata values. Digests bind receipt bytes; they are not signatures or evidence
that an arbitrary submitted JSON document came from a real machine/provider.
The reviewer must acquire the inventory through the actual Mini-PC context, not
accept a caller-authored inventory or relabeled Dev-machine document.

## Actual ordinary execution context and inventory

The intended host is exactly `MINIPC-KWR53`. The frozen context includes Windows
machine GUID, execution-user SID, logon ID, acquisition/probe supervisor process ID
and executable SHA-256. The inventory's observation context, each discovery source,
and every write attempt must agree with that context. Probe timestamps must fall
inside the inventory capture interval. Actual child commands are observed under
that same supervisor; a Dev/admin process cannot supply ordinary context evidence.

All six discovery surfaces must be enumerated to completion: Git configuration and
helpers, GitHub CLI profiles, Windows credential stores, SSH configuration/agent/
public keys, process environment credential-slot names, and other reachable GitHub
providers. Each records source, context, capture ID, metadata entries, exact count,
pagination exhaustion and errors. Unknown, inaccessible, truncated or errored
inventory blocks qualification. Empty surfaces must still have a discovery record.

Every reachable GitHub profile/store target/environment slot resolves to the single
qualified ordinary credential record. Entries bind provider type, credential ID,
account login and immutable ID, locator, environment-slot name, and public SSH
fingerprint slot. The credential record binds GitHub host, provider type, store
target/account, token kind and ordinary account/role metadata. A second credential,
writer/admin identity, writer secret slot or unknown provider fails closed.

This campaign uses the same HTTPS credential for Git push and Git refs API probes.
Consequently a reachable GitHub SSH key would be an additional credential and blocks
qualification; public fingerprints may be captured in rejected inventory without
retaining private-key bytes. Non-GitHub credentials are outside the GitHub inventory.
No token values, credential hashes, private keys or environment values are fields
in this schema. Credential IDs identify provider records, never token bytes.

## Provider-side writer custody

`P6WSV1_PROVIDER_CUSTODY_V2` contains sanitized, independently acquired GET receipts
with endpoint, status, request ID, timestamp and required response projections for:

- App ID/slug and complete App permission map;
- installation ID/App binding, selection, suspension state and permissions;
- complete installation repository listing, exact repository ID/name and scope;
- exact Actions environment/deployment/reviewer policy;
- complete environment-secret listing, including name and creation/update metadata;
- exact protected runtime ref/SHA and full runtime rulesets including bypass actors.

App and installation permission maps must equal the fixed contents-write/metadata-
read map; additional administration or environment/secret privileges fail. Runtime
update/integrity rules must have no bypass actors. These permission and protection
facts establish the required inability to administer rulesets or bypass runtime
protection, rather than accepting an `admin=false` custody assertion. Secret
metadata comes from the environment-secret listing; a secret name alone fails.

Mutable provider custody is acquired independently and frozen for Q0, while the
existing campaign collector continues its runtime/ruleset/environment comparisons.
This source does not grant the ordinary client the privileged metadata-reader
credential used for that separate provider-side acquisition.

## Five distinct ordinary write receipts

The positive control and all four denials share the exact Mini-PC context,
inventory/capture binding, GitHub login/ID and credential-provider/store-record
identity. Observed execution context and credential resolution are mandatory.

| Receipt | Transport | Target |
| --- | --- | --- |
| POSITIVE_CONTROL | Git HTTPS receive-pack | fixed ordinary-control ref |
| AUTHORITY_DIRECT | Git HTTPS receive-pack | fixed authority ref |
| AUTHORITY_REFS_API | Git refs API PATCH | fixed authority ref |
| JOURNAL_REFS_API | Git refs API PATCH | fixed journal ref |
| RUNTIME_REFS_API | Git refs API PATCH | fixed runtime ref |

Every receipt binds the exact repository/ref, before/candidate/after SHA, force=false,
request shape, response provenance and provider transport identifier. Provider
commit receipts must establish an existing candidate whose sole parent is before
and whose tree differs from before: a real, consequential fast-forward attempt.
Before/after ref-read receipts must agree. Positive control must reach the candidate;
every denied protected ref must remain exactly at its original SHA.

Git receipts require a received report-status record (`unpack ok`, target ref status
and exit code); API receipts require exact PATCH body and sanitized policy-denial
classification. Neither a generic 403/422 nor a locally reported error suffices.
Each denial also requires a distinct GitHub repository rule-suite receipt binding
actor ID/name, repository, ref, before SHA, attempted candidate SHA, failed suite
result and an ACTIVE failed `update` rule from the correct frozen ruleset.
Only rule identity/result fields are used; no unstable prose match is required.
Field provenance: [GitHub repository rule-suite API](https://docs.github.com/en/rest/repos/rule-suites).

Missing provider rule-suite evidence, evaluate-only policy, malformed/nonexistent
candidate, wrong target, authentication/rate/network failure or changed protected
ref cannot qualify. If a future provider path does not expose this decisive
evidence, Q0 stays blocked; do not substitute a generic HTTP status or invent a
receipt. This schema is not a live probe specification or authorization.

`collector.collect_q0` performs pure Q0 validation plus independent GETs of the
candidate/before commits and rule-suite objects. The full campaign collector does
the same. Provider objects are compared to strict sanitized projections; historical
Q0 ref observations are not confused with later campaign heads. Missing/inconsistent
objects return NOT_PASS or BLOCKED. A structurally plausible locally fabricated
suite cannot produce PASS when the provider re-read is absent or contradictory.

## Verification

The before-correction counterexample is retained in
`tests/q0-correction-before.json`: the old validator qualified three generic
denials with neither inventory nor provider-custody receipt. It is historical
failure evidence and is not rewritten as a pass.

Run the new focused suite and retain the original regressions:

```text
python -B proofs/proof6/write_safety_closure_v1/tests/test_q0_correction.py
python -B proofs/proof6/write_safety_closure_v1/tests/test_closure.py
python -B proofs/proof6/write_safety_closure_v1/tests/test_native_git.py
python -B proofs/proof6/write_safety_closure_v1/tests/verify_source.py
```

The 30 focused tests include all 17 requested cases and further checks for forged
provider objects, mismatched candidate reads, privileged App permissions, environment/
runtime/scope mismatch, incomplete inventory, reused policy suites, type confusion,
changed unsealed inventory, wrong execution user, additional SSH identity, valid
policy-denied 422, non-policy failures and evaluate-only rules. All fixtures are
nonsecret and synthetic; socket access is disabled in source tests.
