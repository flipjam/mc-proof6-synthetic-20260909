"""Synthetic offline objects only. No live identity or qualification receipts."""
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from unittest.mock import patch
from fake_git import Git, HISTORY, w, j
from common import *
from common import _canonical, _digest
import proof_control as pc
import qualification as q
import d03_job_token as jt
from ruleset_view import visible


def rules(ref, offset, runtime=False):
    result = []
    for index, names in enumerate((['creation', 'deletion', 'non_fast_forward'], ['update'])):
        result.append(dict(id=offset+index, name='offline-'+str(offset+index), target='branch',
            source_type='Repository', source=REPO, enforcement='active',
            conditions={'ref_name': {'include': [ref], 'exclude': []}}, rules=[{'type': n} for n in names],
            updated_at='2026-09-13T00:00:00.000+00:00', bypass_actors=[] if index == 0 or runtime else [
                {'actor_id': APP_ID, 'actor_type': 'Integration', 'bypass_mode': 'always'}]))
    return result


def proposal(history, ident):
    state = q.gate().proof1.reconstruct(history)
    s = state['state']
    return dict(proposal_id=ident, project=s['project'], subject=s['subject'],
        expected_state_sha256=state['state_sha256'], loop_id=s['loop']['id'],
        expected_baton=s['loop']['baton'], action='ADVANCE_ROADMAP')


def source_tree(g):
    build = json.loads((AREA / 'build.json').read_bytes())
    names = list(build['sha256']) + ['proofs/proof6/write_safety_closure_v1/build.json']
    directories = {}
    for path in names:
        d = directories
        parts = path.split('/')
        for component in parts[:-1]:
            d = d.setdefault(component, {})
        d[parts[-1]] = g.blob((ROOT / path).read_bytes())
    def make(d):
        entries = [dict(path=k, mode='040000' if isinstance(v, dict) else '100644',
            type='tree' if isinstance(v, dict) else 'blob', sha=make(v) if isinstance(v, dict) else v) for k, v in sorted(d.items())]
        sha = hashlib.sha1(_canonical(entries)).hexdigest()
        g.objects[sha] = dict(sha=sha, tree=entries, truncated=False)
        return sha
    return make(directories)


def setup():
    g = Git()
    auth, jr, runtime = rules(REF, 801), rules(JOURNAL_REF, 901), rules(RUNTIME_REF, 1001, True)
    g.rules = {str(r['id']): r for r in auth + jr + runtime}
    build = json.loads((AREA / 'build.json').read_bytes())
    d03 = proposal(HISTORY, pc.PROPOSALS[pc.FAULTS[0]])
    d07 = proposal(HISTORY, pc.PROPOSALS[pc.FAULTS[1]])
    decision = q.gate().decide(HISTORY, d07)
    after = {'version': 1, 'events': HISTORY['events'] + [decision['candidate_event']]}
    policy = {'name': ENVIRONMENT, 'can_admins_bypass': False,
        'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True},
        'deployment_branches': [{'name': RUNTIME_REF.removeprefix('refs/heads/'), 'type': 'branch'}],
        'prevent_self_review': True, 'reviewer_ids': [999]}
    tree = source_tree(g)
    m = dict(schema='P6WSV1_MANIFEST_V1', campaign=CAMPAIGN, frozen=True, repository=REPO, repository_id=REPO_ID,
        source_base=BASE, source_commit='c'*40, source_tree=tree, build_sha256=_digest((AREA/'build.json').read_bytes()),
        runtime={'ref': RUNTIME_REF, 'sha': 'c'*40, 'tree': tree, 'workflow': WORKFLOW}, environment=ENVIRONMENT,
        concurrency=CONCURRENCY, ref=REF, baseline_commit='b'*40,
        baseline_state_sha256=q.gate().proof1.reconstruct(HISTORY)['state_sha256'], baseline_history=HISTORY,
        journal=dict(ref=j.REF, path=j.PATH, genesis_commit=g.genesis, genesis_tree=g.genesis_tree,
            genesis_content_sha256=_digest(_canonical(j.GENESIS)), schema_sha256=j.SCHEMA_SHA256,
            rulesets={'integrity': jr[0], 'update': jr[1]}), proof_plan_sha256=pc.plan()[1],
        proposals={pc.FAULTS[0]: d03, pc.FAULTS[1]: d07, '': proposal(after, pc.PROPOSALS[''])},
        budget=pc.BUDGET, app_id=APP_ID, installation_id=INSTALLATION, token_permissions=PERMISSIONS,
        authority_rulesets=auth, runtime_rulesets=runtime, environment_policy=policy,
        configuration_sha256=_digest(_canonical(dict(authority=auth, journal={'integrity': jr[0], 'update': jr[1]}, runtime=runtime, environment=policy))),
        authority_visible_sha256=_digest(_canonical([visible(r) for r in auth])), source_hashes=build['sha256'],
        custody={'writer_credential_source': 'official-installation-action/environment-secret',
            'd03_credential_source': jt.SOURCE, 'ordinary_credential_source': 'ordinary-client/operator-owned',
            'ordinary_has_writer_secret': False, 'ordinary_has_admin_credential': False,
            'environment': ENVIRONMENT, 'secret_name': 'P6WSV1_APP_PRIVATE_KEY'}, q0_evidence_sha256='0'*64)
    g.objects['c'*40] = dict(sha='c'*40, tree={'sha': tree}, parents=[{'sha': BASE}])
    g.refs[RUNTIME_REF] = 'c'*40
    ordinary = dict(**pc.CALLER, role='write', admin=False, maintain=False, credential_source='ordinary-client/operator-owned')
    q0 = dict(schema='P6WSV1_Q0_V1', campaign=CAMPAIGN, source_commit=m['source_commit'], source_tree=tree,
        build_sha256=m['build_sha256'], runtime=m['runtime'], authority={'ref': REF, 'sha': m['baseline_commit'], 'state_sha256': m['baseline_state_sha256']},
        journal={k: m['journal'][k] for k in ('ref', 'genesis_commit', 'genesis_tree', 'genesis_content_sha256', 'schema_sha256')},
        rulesets={'authority': auth, 'journal': m['journal']['rulesets'], 'runtime': runtime}, environment=policy,
        ordinary=ordinary, positive_control={'ref': CONTROL_REF, 'before': '1'*40, 'after': '2'*40,
            'status': 200, 'request_id': 'OFFLINE:CONTROL', 'identity': ordinary},
        denials=[dict(ref=ref, before=sha, after=sha, status=403, request_id='OFFLINE:DENIAL', identity=ordinary, force=False)
            for ref, sha in ((REF, m['baseline_commit']), (JOURNAL_REF, g.genesis), (RUNTIME_REF, m['source_commit']))],
        custody=m['custody'], writer_app={'id': APP_ID, 'installation': INSTALLATION, 'repositories': [REPO_ID],
            'permissions': PERMISSIONS, 'credential_source': m['custody']['writer_credential_source']},
        collector_fixtures={'source_sha256': build['sha256']['proofs/proof6/write_safety_closure_v1/collector.py'],
            'results': ['PASS'] + ['NOT_PASS']*9}, consumptions=0, protected_advances=0)
    m['q0_evidence_sha256'] = _digest(_canonical(q0))
    original_api = g.api
    def api(token, method, path, body=None):
        if method == 'GET' and path == '/installation/repositories?per_page=100':
            return dict(total_count=1, repositories=[{'id': REPO_ID, 'full_name': REPO, 'private': False}])
        if method == 'GET' and path.startswith(j.BASE + '/environments/'):
            if 'deployment-branch-policies' in path:
                return {'total_count': 1, 'branch_policies': policy['deployment_branches']}
            return dict(name=ENVIRONMENT, can_admins_bypass=False, deployment_branch_policy=policy['deployment_branch_policy'],
                protection_rules=[{'type': 'required_reviewers', 'prevent_self_review': True,
                    'reviewers': [{'type': 'User', 'reviewer': {'id': 999}}]}])
        return original_api(token, method, path, body)
    g.api = api
    return g, m, q0


def writer(g, m, operation=None, run=50):
    b = dict(run_id=run, run_attempt=1, runtime_sha=m['source_commit'],
        caller=dict(**pc.CALLER, permission='write', admin=False, maintain=False,
            environment_qualification='required separately in case evidence; not attested by account permission'),
        proof_operation=operation, proof_plan_sha256=pc.plan()[1])
    obj = w._Writer(frozen_manifest=m, installation_token='offline-token',
        action_installation_id=str(INSTALLATION), action_app_slug='mc-proof-6-gate-writer',
        runtime_guard=lambda _: None, receipt_binding=b)
    obj._call = g.api
    return obj


def worker_raw(obj):
    b = obj._journal.pending[obj._last_evidence['pending_record']]['binding']
    context = dict(repository=REPO, repository_id=str(REPO_ID), ref=RUNTIME_REF,
        workflow_ref=jt.WORKFLOW, sha=b['runtime_sha'], run_id=str(b['run_id']), run_attempt='1', event_name='workflow_dispatch')
    message = {'variables': {'system.github.token.permissions': {'value': json.dumps(jt.PERMISSIONS)},
        'system.github.job': {'value': 'writer'}}, 'contextData': {'github': {'t': 2,
        'd': [{'k': k, 'v': v} for k, v in context.items()]}}, 'jobId': '1'*8+'-'+'1'*4+'-'+'1'*4+'-'+'1'*4+'-'+'1'*12}
    return ('[fixture INFO Worker] Version: 1.0.0\n[fixture INFO Worker] Commit: '+'f'*40+
        '\n[fixture INFO Worker] Job message:\n'+json.dumps(message)).encode()


def execute(g, m, operation, run=50):
    obj = writer(g, m, operation, run)
    d03 = operation == pc.FAULTS[0]
    g.status = 403 if d03 else 200
    g.expected_token = 'offline-job-token' if d03 else 'offline-token'
    g.error_body = _canonical({'message': 'Resource not accessible by integration'}) if d03 else None
    with patch.object(w.http.client, 'HTTPSConnection', side_effect=g.connection), \
         patch.object(jt, '_worker_log', side_effect=lambda: worker_raw(obj)), \
         patch.dict(os.environ, {'GH_TOKEN': 'offline-job-token', 'P6WSV1_D03_JOB_TOKEN': 'offline-job-token'}), \
         contextlib.redirect_stdout(io.StringIO()):
        result = obj.commit_transition(_canonical(m['proposals'][operation]), operation)
    return obj, result


def campaign():
    g, m, q0 = setup()
    original = []
    for op, run in zip(pc.FAULTS, (50, 52)):
        obj, result = execute(g, m, op, run)
        original.append(result)
        with contextlib.redirect_stdout(io.StringIO()):
            recovery = writer(g, m, run=run+1).recover_only()
        assert recovery['result'] == 'RECOVERY_CONFIRMED'
    obj, result = execute(g, m, '', 54)
    original.append(result)
    return g, m, q0, original


def evidence(g, m, q0, original):
    journal = j.Journal(writer(g, m))
    rows = journal.rows
    operations = list(journal.pending.items())
    authority_attempts = []
    for (pending_sha, p), op in zip(operations, (*pc.FAULTS, '')):
        authority_attempts.append(dict(authorization=pc.AUTHORIZATIONS[op], pending=pending_sha, ref=REF,
            candidate=p['candidate'], force=False, transmitted=True,
            response={pc.FAULTS[0]: '403_EXACT_REJECTION', pc.FAULTS[1]: 'DROPPED', '': 'COMMITTED'}[op],
            credential_source=m['custody']['d03_credential_source'] if op == pc.FAULTS[0] else m['custody']['writer_credential_source']))
    canonical = {sha for sha, row in rows}
    attempts = []
    for method, path, body in g.calls:
        if method == 'PATCH':
            sha = body['sha']
            attempts.append(dict(parent=g.objects[sha]['parents'][0]['sha'], candidate=sha,
                force=False, ref=JOURNAL_REF, advanced=sha in canonical))
    loser = next(a for a in attempts if not a['advanced'])
    d07 = operations[1][0]
    sibling = dict(winner=journal.terminals[d07][0], loser=loser['candidate'], parent=loser['parent'])
    process = dict(schema='P6WSV1_SANITIZED_PROCESS_V1', manifest_sha256=_digest(_canonical(m)),
        source_commit=m['source_commit'], authority_attempts=authority_attempts, journal_attempts=attempts,
        original_results=[r['result'] for r in original],
        d03_confirmation_loss={'after_patch': True, 'before_first_confirmation': True, 'recovery_terminal_patches': 0},
        recovery_authority_attempts=0, reinvocations={'d03': 'REJECTED_BEFORE_PENDING', 'd07': 'REJECTED_BEFORE_PENDING',
            'proposal_replay': 'REJECTED_BEFORE_SEND', 'unknown_operation': 'REJECTED_BEFORE_MUTATION', 'stale_context': 'REJECTED_BEFORE_SEND'},
        process_exit_codes=[0, 0, 0, 0, 0])
    return dict(q0=q0, authority_attempts=authority_attempts, journal_attempts=attempts,
        raw_process=_canonical(process).decode(), sibling=sibling, writer_local_result='PASS')
