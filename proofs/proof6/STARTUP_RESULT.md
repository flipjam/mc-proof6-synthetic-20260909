# Diagnostic result: exact source launch defect

Classification: S1_SOURCE_DEFECT. Diagnostic workflow conclusion: FAILURE.
Run #50 / 34725078051, job 103637693071, attempt 1, dispatched source
0e8a4f6dc9af749a8ecfd65c2fa626005da5b40f.

The exact accepted R3h startup criteria rejected the initial helper environment
at d04_signal.py:184: require(set(initial_env) <= allowed). The hosted record
reports 48 unexpected environment keys; its fixed nonsecret name allowlist
identified DEBIAN_FRONTEND among them. No unknown key values or names were dumped.
PID 2098, EUID 0, token-slot-present true; first rejection at
2026-09-12T23:18:53.273836Z. Binding and initial environment/FD collection ran.
The ENOENT at line 213 was caught enumeration cleanup, not the fatal exception.

Root creation passed, socket pathname was 89 bytes, timeout PID 2095 started,
and native supervisor PID 2094 reaped it with exit 1 at 23:18:53.280581Z.
Helper startup was rejected before Worker ancestry/audit, root-mode validation,
socket creation, or IPC marker. Cleanup retained HELPER_REAPED exit 1 without
interruption; independent replay retained 39 helper records. No peer ran.
The runner banner was 2.337.0, image 20260907.300.1, kernel 6.17.0-1022-azure;
permissions were Metadata read and Statuses write only. This banner does not
substitute for the helper's unreached permission audit.

The workflow incorrectly relied on sudo --preserve-env=list to establish an
exclusive initial environment. That option adds requested preserved variables;
it does not promise removal of every other environment entry supplied by policy
or hosted startup. Primary provider documentation:
https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in
The bounded correction is an explicit fixed-role launch environment, retaining
the existing validator and preventing forbidden credential cross-delivery before
filtering. It does not expand the custody allowlist or bypass its checks.

Run #49's hidden bytes cannot be recovered. Run #50 directly reproduces this
causal defect in the same accepted startup path and hosted image; the earlier
generic exit remains historical evidence, not retroactively richer telemetry.
Later startup stages remain unproved on the hosted runner. Future S1 must still
qualify them before freeze. No additional hosted run is authorized here.

Post-run REST snapshots equal the pre-run held runtime, genesis journal,
authority, environment, sole branch policy, all existing rulesets and canary ref.
Every preexisting branch SHA is unchanged. Exactly this diagnostic branch/run
was added; run #50 is newest. Manifest remains absent. Complete status histories
on diagnostic, held runtime and authority commits are empty before and after.
Zero status POST, isolation, journal mutation, consumption or acceptance credit.

Phase B may proceed only as bounded R3i source correction based on exact d4d0d448,
with unchanged custody validation and complete offline/native verification.
R3h remains held and cannot be silently repointed to corrected source.
