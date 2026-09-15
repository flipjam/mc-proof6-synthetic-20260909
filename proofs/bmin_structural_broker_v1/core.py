"""One bounded proposal, accepted pure gate, internally constructed authorization.

No credentials, transport, caller-selected targets, or caller approvals here.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
AREA = Path(__file__).resolve().parent
REPOSITORY = 'flipjam/mc-proof6-synthetic-20260909'
REPOSITORY_ID = 1363510385
PROJECT = REPOSITORY
SUBJECT = 'bmin-synthetic-authority'
LOOP = 'bmin-synthetic-v1'
AUTHORITY = 'refs/heads/bmin-v1-authority'
JOURNAL = 'refs/heads/bmin-v1-journal'
RUNTIME = 'refs/heads/bmin-v1-runtime'
WORKFLOW = '.github/workflows/bmin-structural-broker-v1.yml'
ENVIRONMENT = 'bmin-structural-broker-v1'
SCENARIO = 'ONE_SEND_DROP_RESPONSE_V1'
SOURCE_FILES = ('proofs/proof1/replay.py', 'proofs/proof2/gate.py',
                'proofs/proof6/write_safety_closure_v1/ruleset_view.py',
                *(f'proofs/bmin_structural_broker_v1/{name}.py'
                  for name in ('core', 'journal', 'broker', 'provider', 'launcher')),
                WORKFLOW)
ACCEPTED = {
    'proofs/proof1/replay.py': 'ac9c761cf57d74ef68f35213de333c2d071c1f030ad592cae444c3bee576474e',
    'proofs/proof2/gate.py': 'e432172177d7d58d1b9424c4547f31e7223295eeb80d0a3235bd2e7092ca60bf',
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load('bmin_accepted_gate', 'proofs/proof2/gate.py')
rule_view = load('bmin_rule_view', 'proofs/proof6/write_safety_closure_v1/ruleset_view.py')
canonical = gate.proof1.canonical
digest = gate.proof1.digest


def require(value, reason='BLOCKED'):
    if not value:
        raise ValueError(reason)


def sha(value, length=40):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value))
    return value


def parse(raw):
    require(type(raw) is bytes and len(raw) <= 2_000_000)
    return json.loads(raw.decode('utf-8'), object_pairs_hook=gate.proof1.unique_object,
                      parse_float=gate.proof1.invalid_number,
                      parse_constant=gate.proof1.invalid_number)


def proposal(raw):
    require(type(raw) is bytes and len(raw) <= 4096)
    p = parse(raw)
    gate.proof1.fields(p, 'schema action expected_state_sha256 expected_baton')
    require(p['schema'] == 'BMIN_PROPOSAL_V1' and type(p['schema']) is str)
    require(p['action'] == 'ADVANCE_ROADMAP' and type(p['action']) is str)
    sha(p['expected_state_sha256'], 64)
    require(type(p['expected_baton']) is int and 0 <= p['expected_baton'] <= 2147483647)
    return p


def source_hashes():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCE_FILES}


def validate_config(c):
    """Only isolated environment configuration, never dispatch/proposal data."""
    gate.proof1.fields(c, 'schema repository repository_id project subject loop authority_ref '
                      'journal_ref runtime_ref environment scenario runtime_sha source_hashes '
                      'initial_authority_sha journal_genesis_sha policy_sha256 '
                      'app_id installation_id app_slug ruleset_ids')
    require(c['schema'] == 'BMIN_FROZEN_CONFIG_V1')
    for key, fixed in dict(repository=REPOSITORY, repository_id=REPOSITORY_ID,
                           project=PROJECT, subject=SUBJECT, loop=LOOP,
                           authority_ref=AUTHORITY, journal_ref=JOURNAL,
                           runtime_ref=RUNTIME, environment=ENVIRONMENT,
                           scenario=SCENARIO).items():
        require(type(c[key]) is type(fixed) and c[key] == fixed)
    for key in ('runtime_sha', 'initial_authority_sha', 'journal_genesis_sha'):
        sha(c[key])
    sha(c['policy_sha256'], 64)
    for key in ('app_id', 'installation_id'):
        require(type(c[key]) is int and c[key] > 0)
    require(type(c['app_slug']) is str and re.fullmatch('[a-z0-9-]{1,100}', c['app_slug']))
    require(type(c['ruleset_ids']) is list and len(c['ruleset_ids']) == 6
            and all(type(i) is int and i > 0 for i in c['ruleset_ids'])
            and c['ruleset_ids'] == sorted(set(c['ruleset_ids'])))
    require(type(c['source_hashes']) is dict and set(c['source_hashes']) == set(SOURCE_FILES))
    require(c['source_hashes'] == source_hashes())
    require(all(c['source_hashes'][p] == h for p, h in ACCEPTED.items()))
    return c


def evaluate(history, p):
    reconstructed = gate.proof1.reconstruct(history)
    # Canonical on-disk event order is required in addition to reducer validity.
    require(history['events'] == sorted(history['events'], key=lambda e: e['seq']))
    state = reconstructed['state']
    require(state['project'] == PROJECT and state['subject'] == SUBJECT
            and state['loop']['id'] == LOOP)
    intent = dict(proposal_id=digest(p), project=PROJECT, subject=SUBJECT,
                  loop_id=LOOP, expected_state_sha256=p['expected_state_sha256'],
                  expected_baton=p['expected_baton'], action=p['action'])
    decision = gate.decide(history, intent)
    return reconstructed, decision


def git_sha(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def object_plan(filename, value, parent, message):
    """Fixed single-file tree and single-parent commit; no ambient Git identity/time."""
    sha(parent)
    blob = canonical(value)
    blob_sha = git_sha('blob', blob)
    tree = b'100644 ' + filename.encode('ascii') + b'\0' + bytes.fromhex(blob_sha)
    tree_sha = git_sha('tree', tree)
    identity = 'BMIN Broker <bmin@example.invalid> 946684800 +0000'
    commit = (f'tree {tree_sha}\nparent {parent}\nauthor {identity}\n'
              f'committer {identity}\n\n{message}\n').encode('ascii')
    return dict(filename=filename, value=value, parent=parent, message=message+'\n',
                blob_sha=blob_sha, tree_sha=tree_sha, sha=git_sha('commit', commit))


def authorize(c, p, old, history):
    state, decision = evaluate(history, p)
    require(decision['decision'] == 'ALLOW', 'REJECT')
    candidate = {'version': 1, 'events': history['events'] + [decision['candidate_event']]}
    require(gate.proof1.reconstruct(candidate)['state_sha256'] != state['state_sha256'])
    operation = digest(dict(config=digest(c), proposal=digest(p)))
    plan = object_plan('history.json', candidate, old, 'BMIN transition ' + operation)
    a = dict(schema='BMIN_AUTHORIZED_TRANSITION_V1', project=PROJECT,
             repository=REPOSITORY, repository_id=REPOSITORY_ID, authority_ref=AUTHORITY,
             operation_class='NON_FORCE_FAST_FORWARD', proposal_sha256=digest(p),
             expected_old_sha=old, state_sha256=state['state_sha256'],
             policy_sha256=c['policy_sha256'], gate_source_sha256=digest(ACCEPTED),
             gate_decision_sha256=digest(decision), candidate_event_sha256=digest(decision['candidate_event']),
             candidate_content_sha256=digest(candidate), candidate_sha=plan['sha'],
             runtime_sha=c['runtime_sha'], source_sha256=digest(c['source_hashes']),
             app_id=c['app_id'], installation_id=c['installation_id'], app_slug=c['app_slug'],
             configuration_sha256=digest(c), operation_id=operation,
             journal_ref=JOURNAL, journal_genesis_sha=c['journal_genesis_sha'],
             journal_lifecycle='PREPARED>SEND_ARMED>TERMINAL')
    return a, plan
