"""P6WSV1-only nonsecret Q0 inventory, custody and write-receipt validators.

Acquisition is separate. Freeze binds independently acquired metadata bytes;
these pure validators do not inventory a machine, resolve credentials or write.
"""
import re
from datetime import datetime
from common import (REPO, REPO_ID, REF, JOURNAL_REF, RUNTIME_REF, CONTROL_REF,
                    ENVIRONMENT, APP_ID, INSTALLATION, PERMISSIONS,
                    _canonical, _digest, _require, _sha, hash64)
from proof_control import CALLER

HOST = 'MINIPC-KWR53'
PREFIX = '/repos/' + REPO
SURFACES = {'git_config': 'git-config-show-origin', 'github_cli': 'gh-auth-profile-metadata',
            'credential_store': 'windows-credential-store-metadata',
            'ssh': 'ssh-config-agent-and-public-key-metadata',
            'environment': 'process-environment-slot-names',
            'other': 'reachable-github-provider-discovery'}
PATHS = {'POSITIVE_CONTROL': (CONTROL_REF, 'GIT_PUSH_HTTPS'),
         'AUTHORITY_DIRECT': (REF, 'GIT_PUSH_HTTPS'),
         'AUTHORITY_REFS_API': (REF, 'GIT_REFS_API'),
         'JOURNAL_REFS_API': (JOURNAL_REF, 'GIT_REFS_API'),
         'RUNTIME_REFS_API': (RUNTIME_REF, 'GIT_REFS_API')}


def fields(value, names):
    _require(type(value) is dict and set(value) == set(names.split()))


def same(a, b):
    # Preserve strict bool/int distinctions throughout nested evidence.
    _require(_canonical(a) == _canonical(b))


def label(value):
    _require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:/@= +\\-]{1,256}', value)
             and not any(s in value.lower() for s in ('ghp_', 'gho_', 'github_pat_', 'bearer ', 'private key')))


def timestamp(value):
    _require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value))
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def context(value):
    fields(value, 'hostname machine_guid user_sid logon_id process_id executable_sha256')
    _require(value['hostname'] == HOST
             and type(value['machine_guid']) is str
             and re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['machine_guid'])
             and type(value['user_sid']) is str and re.fullmatch(r'S-1-5-21-\d+-\d+-\d+-\d+', value['user_sid'])
             and type(value['logon_id']) is str and re.fullmatch(r'0x[0-9a-f]+', value['logon_id'])
             and type(value['process_id']) is int and value['process_id'] > 0)
    hash64(value['executable_sha256'])


def custody_policy(c):
    fields(c, 'schema writer_credential_source d03_credential_source ordinary_credential_source '
           'environment secret_name ordinary_context ordinary_credential_id inventory_sha256 provider_custody_sha256')
    _require(c['schema'] == 'P6WSV1_CUSTODY_V2'
             and c['writer_credential_source'] == 'official-installation-action/environment-secret'
             and c['d03_credential_source'] == 'github.token/current-worker-job-message/v1'
             and c['ordinary_credential_source'] == 'ordinary-client/operator-owned'
             and c['environment'] == ENVIRONMENT and c['secret_name'] == 'P6WSV1_APP_PRIVATE_KEY')
    context(c['ordinary_context']); label(c['ordinary_credential_id'])
    hash64(c['inventory_sha256']); hash64(c['provider_custody_sha256'])


def api_receipt(r, endpoint):
    """Allowlisted, sanitized provider response projection, acquired independently."""
    fields(r, 'method endpoint status request_id observed_at body')
    _require(r['method'] == 'GET' and r['endpoint'] == endpoint
             and type(r['status']) is int and r['status'] == 200
             and type(r['request_id']) is str and re.fullmatch('[A-Za-z0-9:-]{1,128}', r['request_id']))
    timestamp(r['observed_at'])
    _require(type(r['body']) is dict)
    return r['body']


def inventory(c, i, ordinary):
    fields(i, 'schema context observation_context capture_id started_at completed_at discovery credentials')
    _require(i['schema'] == 'P6WSV1_MINIPC_INVENTORY_V2')
    same(i['context'], c['ordinary_context']); context(i['observation_context'])
    same(i['observation_context'], i['context'])
    hash64(i['capture_id'])
    _require(timestamp(i['started_at']) <= timestamp(i['completed_at']))
    # Every discovered GitHub credential must have a record; no unknown/ignored
    # extra profiles, helper credentials, env slots or SSH keys qualify.
    _require(type(i['credentials']) is list and len(i['credentials']) == 1)
    credential = i['credentials'][0]
    fields(credential, 'credential_id provider_type host store_target store_account account credential_kind')
    _require(credential['credential_id'] == c['ordinary_credential_id']
             and credential['provider_type'] in ('gh', 'gcm', 'wincred')
             and credential['host'] == 'github.com' and credential['credential_kind'] in ('oauth', 'pat'))
    label(credential['store_target']); label(credential['store_account'])
    same(credential['account'], ordinary)
    _require(type(i['discovery']) is list and len(i['discovery']) == len(SURFACES))
    _require({d['surface'] for d in i['discovery']} == set(SURFACES))
    references = 0
    for d in i['discovery']:
        fields(d, 'surface source context capture_id entries total_count next_cursor errors')
        same(d['context'], i['context'])
        _require(d['source'] == SURFACES[d['surface']] and d['capture_id'] == i['capture_id']
                 and type(d['entries']) is list and type(d['total_count']) is int
                 and d['total_count'] == len(d['entries']) and d['next_cursor'] is None and d['errors'] == [])
        for entry in d['entries']:
            fields(entry, 'provider_type locator account_login account_id credential_id ssh_public_fingerprint environment_slot')
            _require(entry['provider_type'] == credential['provider_type']
                     and entry['credential_id'] == credential['credential_id']
                     and type(entry['account_id']) is int and entry['account_id'] == CALLER['id']
                     and entry['account_login'] == CALLER['login'])
            label(entry['locator'])
            # The selected ordinary credential is HTTPS. Any reachable GitHub SSH
            # identity is another credential and must block this bounded Q0.
            _require(entry['ssh_public_fingerprint'] is None and d['surface'] != 'ssh')
            slot = entry['environment_slot']
            if d['surface'] == 'environment':
                _require(slot in ('GH_TOKEN', 'GITHUB_TOKEN'))
            else:
                _require(slot is None)
            references += 1
    _require(references > 0)
    same(_digest(_canonical(i)), c['inventory_sha256'])
    return {'context_sha256': _digest(_canonical(i['context'])), 'inventory_sha256': c['inventory_sha256'],
            'capture_id': i['capture_id'], 'credential_id': credential['credential_id'],
            'provider_type': credential['provider_type'], 'store_target': credential['store_target'],
            'store_account': credential['store_account'], 'identity': ordinary}


def provider_custody(m, receipt):
    fields(receipt, 'schema app installation repository_scope environment secret_metadata runtime_ref runtime_rulesets')
    _require(receipt['schema'] == 'P6WSV1_PROVIDER_CUSTODY_V2')
    app = api_receipt(receipt['app'], '/apps/mc-proof-6-gate-writer')
    same(app, {'id': APP_ID, 'slug': 'mc-proof-6-gate-writer', 'permissions': PERMISSIONS})
    installation = api_receipt(receipt['installation'], '/app/installations/' + str(INSTALLATION))
    same(installation, {'id': INSTALLATION, 'app_id': APP_ID, 'repository_selection': 'selected',
                       'permissions': PERMISSIONS, 'suspended_at': None})
    # Scope is a separately paginated provider listing, not inferred from App id.
    repositories = api_receipt(receipt['repository_scope'], '/installation/repositories?per_page=100')
    same(repositories, {'total_count': 1, 'repositories': [{'id': REPO_ID, 'full_name': REPO}], 'next_cursor': None})
    env = api_receipt(receipt['environment'], PREFIX + '/environments/' + ENVIRONMENT)
    same(env, m['environment_policy'])
    listing = api_receipt(receipt['secret_metadata'], '/repositories/' + str(REPO_ID) + '/environments/' + ENVIRONMENT + '/secrets?per_page=100')
    fields(listing, 'total_count secrets next_cursor')
    _require(type(listing['total_count']) is int and listing['total_count'] == 1
             and listing['next_cursor'] is None and type(listing['secrets']) is list and len(listing['secrets']) == 1)
    item = listing['secrets'][0]
    fields(item, 'name created_at updated_at')
    _require(item['name'] == m['custody']['secret_name']
             and timestamp(item['created_at']) <= timestamp(item['updated_at']))
    _require(type(receipt['runtime_rulesets']) is list and len(receipt['runtime_rulesets']) == 2)
    same(api_receipt(receipt['runtime_ref'], PREFIX + '/git/ref/' + RUNTIME_REF.removeprefix('refs/')),
         {'ref': RUNTIME_REF, 'object': {'type': 'commit', 'sha': m['source_commit']}})
    for captured, expected in zip(receipt['runtime_rulesets'], m['runtime_rulesets']):
        same(api_receipt(captured, PREFIX + '/rulesets/' + str(expected['id'])), expected)
        _require(expected['bypass_actors'] == [])
    # Exact full App and installation permission maps exclude administration,
    # environments/secrets write, and runtime update bypass; no boolean attestation.
    same(_digest(_canonical(receipt)), m['custody']['provider_custody_sha256'])


def write_receipt(m, r, path, binding):
    fields(r, 'path repository repository_id transport binding identity execution_context credential_resolution before candidate after force '
           'before_commit candidate_commit before_read after_read request response policy_evaluation')
    ref, transport = PATHS[path]
    _require(r['path'] == path and r['repository'] == REPO and type(r['repository_id']) is int
             and r['repository_id'] == REPO_ID and r['transport'] == transport and r['force'] is False)
    same(r['binding'], binding); same(r['identity'], binding['identity'])
    same(r['execution_context'], m['custody']['ordinary_context'])
    same(r['credential_resolution'], {key: binding[key] for key in
         ('credential_id', 'provider_type', 'store_target', 'store_account', 'identity')})
    before, candidate, after = _sha(r['before']), _sha(r['candidate']), _sha(r['after'])
    _require(before != candidate)
    if path != 'POSITIVE_CONTROL':
        expected = {REF: m['baseline_commit'], JOURNAL_REF: m['journal']['genesis_commit'], RUNTIME_REF: m['source_commit']}[ref]
        _require(before == expected and after == before)
    else:
        _require(after == candidate)
    old = api_receipt(r['before_commit'], PREFIX + '/git/commits/' + before)
    new = api_receipt(r['candidate_commit'], PREFIX + '/git/commits/' + candidate)
    for obj, sha in ((old, before), (new, candidate)):
        fields(obj, 'sha tree parents'); same(obj['sha'], sha)
        fields(obj['tree'], 'sha'); _sha(obj['tree']['sha'])
        _require(type(obj['parents']) is list)
        for parent in obj['parents']:
            fields(parent, 'sha'); _sha(parent['sha'])
    same(new['parents'], [{'sha': before}])
    _require(new['tree']['sha'] != old['tree']['sha'])
    for captured, sha in ((r['before_read'], before), (r['after_read'], after)):
        same(api_receipt(captured, PREFIX + '/git/ref/' + ref.removeprefix('refs/')),
             {'ref': ref, 'object': {'type': 'commit', 'sha': sha}})
    _require(timestamp(r['before_read']['observed_at']) <= timestamp(r['after_read']['observed_at']))
    if transport == 'GIT_PUSH_HTTPS':
        same(r['request'], {'service': 'git-receive-pack', 'url': 'https://github.com/' + REPO + '.git',
             'ref': ref, 'old': before, 'new': candidate, 'force': False})
        fields(r['response'], 'source request_id unpack_status ref ref_status exit_code')
        same({k: r['response'][k] for k in ('source', 'unpack_status', 'ref', 'ref_status', 'exit_code')},
             {'source': 'github-receive-pack-report-status', 'unpack_status': 'ok', 'ref': ref,
              'ref_status': 'ok' if path == 'POSITIVE_CONTROL' else 'ng', 'exit_code': 0 if path == 'POSITIVE_CONTROL' else 1})
    else:
        same(r['request'], {'method': 'PATCH', 'endpoint': PREFIX + '/git/refs/' + ref.removeprefix('refs/'),
             'body': {'sha': candidate, 'force': False}})
        fields(r['response'], 'source request_id status classification')
        _require(r['response']['source'] == 'github-rest' and type(r['response']['status']) is int
                 and r['response']['status'] in (403, 422) and r['response']['classification'] == 'RULESET_POLICY_DENIED')
    _require(type(r['response']['request_id']) is str and re.fullmatch('[A-Za-z0-9:-]{1,128}', r['response']['request_id']))
    if path == 'POSITIVE_CONTROL':
        _require(r['policy_evaluation'] is None)
        return
    # A bare transport failure is insufficient. A provider rule-suite must bind
    # the actor, ref, before/candidate and an ACTIVE update prohibition.
    captured = r['policy_evaluation']
    suite_id = captured['body']['id']
    _require(type(suite_id) is int and suite_id > 0)
    suite = api_receipt(captured, PREFIX + '/rulesets/rule-suites/' + str(suite_id))
    fields(suite, 'id actor_id actor_name repository_id repository_name before_sha after_sha ref result evaluation_result rule_evaluations')
    same({k: suite[k] for k in ('actor_id', 'actor_name', 'repository_id', 'repository_name', 'before_sha', 'after_sha', 'ref', 'result', 'evaluation_result')},
         dict(actor_id=CALLER['id'], actor_name=CALLER['login'], repository_id=REPO_ID,
              repository_name=REPO.split('/')[1], before_sha=before, after_sha=candidate, ref=ref, result='fail', evaluation_result='fail'))
    update = (m['authority_rulesets'][1] if ref == REF else m['journal']['rulesets']['update']
              if ref == JOURNAL_REF else m['runtime_rulesets'][1])
    evaluations = suite['rule_evaluations']
    _require(type(evaluations) is list and len(evaluations) > 0)
    found = False
    for evaluation in evaluations:
        fields(evaluation, 'rule_source enforcement result rule_type')
        fields(evaluation['rule_source'], 'type id name')
        _require(type(evaluation['rule_source']['id']) is int)
        if evaluation == {'rule_source': {'type': 'ruleset', 'id': update['id'], 'name': update['name']},
                          'enforcement': 'active', 'result': 'fail', 'rule_type': 'update'}:
            found = True
    _require(found)


def validate_q0_custody(m, e):
    c = m['custody']; custody_policy(c)
    binding = inventory(c, e['ordinary_inventory'], e['ordinary'])
    provider_custody(m, e['writer_custody'])
    write_receipt(m, e['positive_control'], 'POSITIVE_CONTROL', binding)
    denials = e['denials']
    _require(type(denials) is list and len(denials) == 4
             and [r['path'] for r in denials] == list(PATHS)[1:])
    for r in denials:
        write_receipt(m, r, r['path'], binding)
    for r in [e['positive_control'], *denials]:
        _require(timestamp(e['ordinary_inventory']['started_at']) <= timestamp(r['before_read']['observed_at'])
                 <= timestamp(r['after_read']['observed_at']) <= timestamp(e['ordinary_inventory']['completed_at']))
    # Distinct provider evidence, not one authority denial relabeled twice.
    _require(len({r['policy_evaluation']['body']['id'] for r in denials}) == 4
             and len({r['response']['request_id'] for r in [e['positive_control'], *denials]}) == 5)


def immutable_provider_receipts(e):
    """Frozen Q0 ref reads are historical; commits/suites can be re-read later."""
    for r in [e['positive_control'], *e['denials']]:
        yield r['before_commit']
        yield r['candidate_commit']
        if r['policy_evaluation'] is not None:
            yield r['policy_evaluation']
