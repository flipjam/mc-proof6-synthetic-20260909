"""Nonsecret synthetic Mini-PC/provider receipts; no machine or network access."""
import copy
from common import (REPO, REPO_ID, REF, JOURNAL_REF, RUNTIME_REF, ENVIRONMENT,
                    APP_ID, INSTALLATION, PERMISSIONS, _canonical, _digest)
import q0_evidence as qe


def api(endpoint, body, request_id='FIXTURE:READ'):
    return {'method': 'GET', 'endpoint': endpoint, 'status': 200, 'request_id': request_id,
            'observed_at': '2026-09-13T12:03:00Z', 'body': copy.deepcopy(body)}


def upgrade(g, m, e):
    ctx = dict(hostname=qe.HOST, machine_guid='11111111-2222-3333-4444-555555555555',
        user_sid='S-1-5-21-111-222-333-1001', logon_id='0x1234', process_id=1234, executable_sha256='1'*64)
    cred = dict(credential_id='fixture-gh-profile-01', provider_type='gh', host='github.com',
        store_target='gh:github.com:peaklinesoftware', store_account='peaklinesoftware',
        account=copy.deepcopy(e['ordinary']), credential_kind='oauth')
    discovery = []
    for surface, source in qe.SURFACES.items():
        entries = [] if surface in ('ssh', 'other') else [dict(provider_type='gh',
            locator='fixture-'+surface, account_login=e['ordinary']['login'], account_id=e['ordinary']['id'],
            credential_id=cred['credential_id'], ssh_public_fingerprint=None,
            environment_slot='GH_TOKEN' if surface == 'environment' else None)]
        discovery.append(dict(surface=surface, source=source, context=copy.deepcopy(ctx), capture_id='2'*64,
            entries=entries, total_count=len(entries), next_cursor=None, errors=[]))
    inventory = dict(schema='P6WSV1_MINIPC_INVENTORY_V2', context=copy.deepcopy(ctx), observation_context=copy.deepcopy(ctx),
        capture_id='2'*64, started_at='2026-09-13T12:00:00Z', completed_at='2026-09-13T12:10:00Z',
        discovery=discovery, credentials=[cred])
    prefix = '/repos/' + REPO
    provider = dict(schema='P6WSV1_PROVIDER_CUSTODY_V2',
        app=api('/apps/mc-proof-6-gate-writer', {'id': APP_ID, 'slug': 'mc-proof-6-gate-writer', 'permissions': PERMISSIONS}),
        installation=api('/app/installations/'+str(INSTALLATION), {'id': INSTALLATION, 'app_id': APP_ID,
            'repository_selection': 'selected', 'permissions': PERMISSIONS, 'suspended_at': None}),
        repository_scope=api('/installation/repositories?per_page=100', {'total_count': 1,
            'repositories': [{'id': REPO_ID, 'full_name': REPO}], 'next_cursor': None}),
        environment=api(prefix+'/environments/'+ENVIRONMENT, m['environment_policy']),
        secret_metadata=api('/repositories/'+str(REPO_ID)+'/environments/'+ENVIRONMENT+'/secrets?per_page=100',
            {'total_count': 1, 'secrets': [{'name': 'P6WSV1_APP_PRIVATE_KEY', 'created_at': '2026-09-13T11:00:00Z',
                'updated_at': '2026-09-13T11:00:00Z'}], 'next_cursor': None}),
        runtime_ref=api(prefix+'/git/ref/'+RUNTIME_REF.removeprefix('refs/'),
            {'ref': RUNTIME_REF, 'object': {'type': 'commit', 'sha': m['source_commit']}}),
        runtime_rulesets=[api(prefix+'/rulesets/'+str(r['id']), r) for r in m['runtime_rulesets']])
    c = m['custody']
    c.pop('ordinary_has_writer_secret'); c.pop('ordinary_has_admin_credential')
    c.update(schema='P6WSV1_CUSTODY_V2', ordinary_context=ctx, ordinary_credential_id=cred['credential_id'],
        inventory_sha256=_digest(_canonical(inventory)), provider_custody_sha256=_digest(_canonical(provider)))
    e.update(schema='P6WSV1_Q0_V2', custody=c, ordinary_inventory=inventory, writer_custody=provider)
    binding = qe.inventory(c, inventory, e['ordinary'])
    receipts = []
    g.q0_provider = {}
    for index, (path, (ref, transport)) in enumerate(qe.PATHS.items()):
        if index == 0:
            tree = g.tree(g.blob(b'fixture positive control old'))
            before = g.commit(tree, [], 'offline ordinary control')
        else:
            before = {REF: m['baseline_commit'], JOURNAL_REF: m['journal']['genesis_commit'], RUNTIME_REF: m['source_commit']}[ref]
        tree = g.tree(g.blob(('fixture consequential '+path).encode('ascii')))
        candidate = g.commit(tree, [before], 'offline Q0 candidate '+path)
        after = candidate if index == 0 else before
        if transport == 'GIT_PUSH_HTTPS':
            request = {'service': 'git-receive-pack', 'url': 'https://github.com/'+REPO+'.git',
                'ref': ref, 'old': before, 'new': candidate, 'force': False}
            response = {'source': 'github-receive-pack-report-status', 'request_id': 'FIXTURE:WRITE:'+str(index),
                'unpack_status': 'ok', 'ref': ref, 'ref_status': 'ok' if index == 0 else 'ng', 'exit_code': 0 if index == 0 else 1}
        else:
            request = {'method': 'PATCH', 'endpoint': prefix+'/git/refs/'+ref.removeprefix('refs/'),
                'body': {'sha': candidate, 'force': False}}
            response = {'source': 'github-rest', 'request_id': 'FIXTURE:WRITE:'+str(index), 'status': 403,
                'classification': 'RULESET_POLICY_DENIED'}
        policy = None
        if index:
            update = (m['authority_rulesets'][1] if ref == REF else m['journal']['rulesets']['update']
                      if ref == JOURNAL_REF else m['runtime_rulesets'][1])
            body = dict(id=2000+index, actor_id=e['ordinary']['id'], actor_name=e['ordinary']['login'],
                repository_id=REPO_ID, repository_name=REPO.split('/')[1], before_sha=before, after_sha=candidate,
                ref=ref, result='fail', evaluation_result='fail', rule_evaluations=[{
                    'rule_source': {'type': 'ruleset', 'id': update['id'], 'name': update['name']},
                    'enforcement': 'active', 'result': 'fail', 'rule_type': 'update'}])
            endpoint = prefix+'/rulesets/rule-suites/'+str(body['id'])
            policy = api(endpoint, body)
            g.q0_provider[endpoint.removeprefix(prefix)] = copy.deepcopy(body)
        receipts.append(dict(path=path, repository=REPO, repository_id=REPO_ID, transport=transport,
            binding=copy.deepcopy(binding), identity=copy.deepcopy(e['ordinary']), execution_context=copy.deepcopy(ctx),
            credential_resolution={key: copy.deepcopy(binding[key]) for key in
                ('credential_id', 'provider_type', 'store_target', 'store_account', 'identity')},
            before=before, candidate=candidate, after=after, force=False,
            before_commit=api(prefix+'/git/commits/'+before, g.objects[before]),
            candidate_commit=api(prefix+'/git/commits/'+candidate, g.objects[candidate]),
            before_read=api(prefix+'/git/ref/'+ref.removeprefix('refs/'), {'ref': ref, 'object': {'type': 'commit', 'sha': before}}),
            after_read=api(prefix+'/git/ref/'+ref.removeprefix('refs/'), {'ref': ref, 'object': {'type': 'commit', 'sha': after}}),
            request=request, response=response, policy_evaluation=policy))
    e['positive_control'], e['denials'] = receipts[0], receipts[1:]
