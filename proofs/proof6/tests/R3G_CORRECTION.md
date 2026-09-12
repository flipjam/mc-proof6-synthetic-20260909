# R3g bounded correction after independent review

Previous source: `040fe81966f694733f37e34819fda046cf45abac`, tree
`e65661d56802945ba8d2b219127cfcc104a61e2a`, independently reviewed as
PARTIAL_R3G_SOURCE. This correction is a descendant on the same branch;
the reviewed commit and its evidence remain historical and unchanged.
The first candidate's `R3G_REVIEW.md` and `r3g-evidence/` describe that first
candidate. Use this note and `r3g-correction-evidence/` for this correction.

Scope is exactly the two reviewer defect classes. No authority amendment,
workflow redesign, new input, acceptance-case change or provisioned state.
R3g remains NOT ACCEPTED, NOT PROVISIONED, NOT FROZEN and NOT EXECUTED.
Proof 6 remains NOT PASSED; Phase 7 remains unauthorized. Publication requires
one independent bounded re-review before any later authorization.

## A. Qualified namespace evidence

`validate_record` now explicitly requires non-null context and netns_after
when qualified is true. Existing mandatory-key and syntax validation already
checks the before namespace (`context.netns`) and every non-null after
namespace against `net:\[[0-9]{1,20}\]`. The existing inequality check remains.
Thus a qualified record must have both syntactically valid namespaces and
they must differ. Null cannot pass merely by comparing unequal to a string.

Existing unsuccessful diagnostics remain representable. A context failure
can retain context=null and netns_after=null; an unshare failure can retain
a valid starting context with netns_after=null. Such records remain
unqualified and cannot satisfy prerequisite or setup admission. No successful
schema is fabricated to fill missing observations.

Tests exercise null, missing, malformed and identical namespaces through
validate_record, the real prerequisite.run and setup_qualification. The
actual D04 admission test runs the real prerequisite validator with inert
child output: rejection leaves journal/authority refs and mutation counts
unchanged and never calls actual isolation. Tests also retain legitimate
partial failure records without turning them into schema errors.

## B. Route lexical boundary

Both public route parsers check lexical input before tokenization. Accepted
characters are printable ASCII fields plus ASCII space and horizontal tab
as field separators. Lines may end in LF or CRLF; no final newline is also
supported. Bare CR is rejected. All other ASCII controls, DEL, non-ASCII
characters and Unicode whitespace are rejected before splitting.

CRLF is explicitly normalized to LF, lines are split only on literal LF,
and fields are split only on space/HT. One terminal line ending is removed;
extra blank records remain invalid. Untrusted route input no longer relies
on Python's generic split()/splitlines() whitespace classification. The
remaining splitlines() in the unrelated context-status reader is unchanged.
The exact lexical rules are bound in production source and its build hash;
the proof-plan bytes and POLICY dictionary remain unchanged.

Empty IPv4 input and valid header-only input still qualify. Strict IPv4
zero-data-route and IPv6 destination/source/interface/gateway restrictions
are unchanged. Empty IPv6 and permitted loopback/reject rows retain their
existing behavior. No connectivity or unshare semantics changed.

## Reproduction and verification

`reproduce_r3g_review.py` uses independent literal records and production
entry points, with no earlier fixture/test imports. All five counterexamples
were reproduced before the change (accepted) and rejected afterward:

- IPv4 header plus U+001F;
- IPv4 header plus U+001E;
- qualified child netns_after=null through prerequisite.run;
- the same null child through setup_qualification;
- IPv6 row with U+001F field separators.

`test_r3g_correction.py` adds 20 tests, including all 30 unsupported ASCII
control characters (C0 except HT/LF/CR, plus DEL), embedded NUL, field and
suffix variants, Unicode whitespace, bare CR, blank records, valid space/HT
and LF/CRLF cases, public isolation qualification and actual END rechecks.
No real unshare, remote request or live child is used in these new tests.

Required full rerun:

- Exact R3f source 704a32834981ce1ebcfc0f963abe25297b89f304: 206 tests.
- Existing retained R3g regressions: 198 tests, assertions unchanged.
- Existing focused R3g suite: 68 tests, assertions unchanged.
- Existing inert/native process fixtures: 3 tests, unchanged.
- New bounded correction suite: 20 tests.
- Total candidate unit/process tests: 289; reviewer reproduction is separate.
- Unmodified verify_r3g.py: complete build/source inventory, exact 72-row
  canonical mapping, workflow YAML and five Bash blocks.

Final logs/results are in r3g-correction-evidence. The exact baseline source
bytes were verified against Git before rerunning; no R3f source was edited.
Original reviewed evidence is retained byte-for-byte, not overwritten.
The new source inventory remains relative to the accepted R3f source base;
the additional correction inventory compares this correction with the exact
reviewed R3g parent and proves all other prior files unchanged.

## Self-adversarial review

- Qualified records cannot omit before/after evidence, and unequal null is
  no longer interpreted as a namespace change.
- Legitimate early failures still retain unavailable observations safely.
- Unsupported controls cannot become separators through Python tokenization.
- Malformed/control-only input cannot masquerade as an empty/header-only table.
- Empty hosted IPv4 observations and valid prospective IPv6 fixtures pass.
  The original diagnostic did not retain raw IPv6 rows; no new claim is made.
- Route safety criteria, prerequisite ordering and consumption are unchanged.
- No new credential, arbitrary-execution or caller-control surface exists.
- All five reviewed counterexamples reject after this correction.
- Only d04_capability.py changes production logic. build.json binds that file
  and the two added test programs. Plan, workflow, other production files and
  all existing test programs remain byte-identical to the reviewed parent.

No issue outside the two authorized defect classes was corrected or used to
expand scope. Independent re-review should focus on the two changes, exact
descendant commit/tree, refreshed hashes, absence of unrelated movement and
the full regression/adversarial results. An architectural redesign review is
not requested. No source/status merge, runtime/journal creation, environment
or ruleset change, manifest installation, S1, freeze or acceptance is allowed.
