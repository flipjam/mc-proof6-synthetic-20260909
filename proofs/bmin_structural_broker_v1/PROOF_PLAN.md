# B-MIN one-shot synthetic proof plan - NOT EXECUTED

## Exact proposition

"For one fixed synthetic authoritative ref and one fixed policy/runtime identity, an ordinary AI-facing client that possesses no privileged writer credential can only submit a bounded proposal. Only the isolated broker can transmit an authoritative mutation, and only after independently reconstructing current state, resolving current policy, obtaining deterministic ALLOW, constructing and binding the exact candidate, and revalidating the exact old authority immediately before transport. Malformed, stale, replayed, target-substitution or identity-mismatched requests cause no authority send. After any possible send, the exact operation is never resent; ambiguity blocks subsequent mutation until deterministic journal/authority reconciliation establishes the outcome."

## Prerequisites: separate owner provisioning, never source-test claims

1. Independently review the exact published source commit/tree and this proposition.
2. Provision only the three fresh B-MIN refs in the disposable synthetic repository:
   one authority, one runtime, one protected durable journal. One App, one writer.
3. Ordinary client receives no App private key/token; cannot read the privileged
   environment secret, change its config, mutate privileged runtime/workflow code,
   execute code on the privileged runner, or directly mutate the authority/journal.
   Environment deployment restrictions must exclude caller-editable refs. A job's
   `if` expression is not a substitute for provider protection of its own source.
4. Fixed authority/journal integrity rules prevent creation, deletion, rewind and
   force writes without bypass. Their update policy permits only the fixed writer
   App; runtime update policy permits no ordinary client or writer App bypass.
   Verify full rules/bypass permissions out-of-band and freeze the observable
   policy digest. Verify ordinary credentials cannot create replacement rules or
   modify applicable policy. No destructive boundary probes are authorized here.
5. Writer App is selected for this repository only; Contents-write/Metadata-read,
   no administration/policy/environment/secret/workflow management permissions.
   App cannot change its own policy or admin boundary. Owner/meta-admin authority
   remains separate, out-of-band and quiescent throughout the proof. Ruleset
   identity equality is not proof of these custody facts.
6. Verify immutable runtime SHA and every source hash, pinned dependency action,
   job/environment identity, installation ID/slug, exact project/ref mapping,
   initial authority and journal GENESIS. Freeze config in protected environment.
   No unfrozen placeholder passes `validate_config`. Verify provider returns the
   expected deterministic Git object identities before permitting the proof.
7. Verify Actions concurrency group permits one broker at a time, with no other
   privileged writer, no ref reset, no operator write, and no concurrent recovery.
   GitHub non-force updates are not compare-and-swap for arbitrary admin rewinds;
   safety requires the fixed no-rewind/no-delete boundary and sole serialized
   writer. The pre-send read and one-parent candidate reject competing siblings.
8. Verify journal ref cannot be deleted/reset/rolled back. Missing or untrusted
   durable evidence blocks; cache restoration or a new genesis is not recovery.
   A local credential inventory is not required and does not substitute for this
   actual provider/runtime boundary verification. No new Q0 is part of B-MIN.

## One execution, then reconcile and replay

- Freeze one valid BMIN_PROPOSAL_V1 against the initial synthetic state. Record
  exact source/tree/config/policy/runtime/provider identities and before authority,
  history/state digests and journal GENESIS. Offline malformed/stale/substitution
  tests establish the zero-send cases; do not spend live writes testing them.
- Invoke only the fixed manual workflow on the independently protected runtime.
  It computes ALLOW, constructs one single-parent candidate, appends PREPARED and
  SEND_ARMED, then makes one meaningful `force=false` authority update attempt.
- Fixed transport drops the response after request transmission. Preserve the
  INDETERMINATE return and exact armed journal ancestry. No retry of authority.
- A fresh interpreter invocation reconstructs journal and authority. Exact bound
  candidate observed finalizes COMMITTED. Old stays blocked (no definitive
  rejection evidence); another SHA conflicts; missing/malformed evidence blocks.
  No waiting timeout converts an old observation into a safe retry.
- Workflow next repeats the same proposal in another interpreter. It must report
  the terminal disposition/replay or block, with zero second authority send.
- Preserve exact before/after authority commits/parents/history, full journal
  ancestry GENESIS -> PREPARED -> SEND_ARMED -> TERMINAL, authorization and proposal
  digests, source/config identity, original indeterminate receipt, reconciliation
  output and replay output. Independently reconcile provider/run evidence for
  exactly one authority send. Counts of journal/object writes must be distinguished
  from authority writes; setup/journal writes do not count as authority transitions.

Any unresolved old observation, failed journal write, config drift, missing
evidence or provisioning discrepancy stops the proof. No resend, refund, automatic
reprovisioning, new operation, second valid proposal or broader claim is allowed.

No Game Factory; no valuable repository; no concurrency; no 72-row campaign;
no fresh Q0; no historical D03/D07/POSTRECOVERY; no Phase 7; no R3k.
