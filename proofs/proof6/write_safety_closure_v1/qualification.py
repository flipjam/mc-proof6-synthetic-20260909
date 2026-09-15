"""Pure, fail-closed freeze/Q0 schema. Offline fixtures provide no live credit."""
import importlib.util
import json
from common import (EXEC_CONTRACT, EXEC_ADMISSION_SCHEMA, EXEC_MANIFEST_SCHEMA,
                    EXEC_SOURCE, EXEC_WORKFLOW, EXEC_RUNTIME_REF, ACCEPTED_SOURCE, ACCEPTED_TREE)
from common import (ROOT, AREA, CAMPAIGN, REPO, REPO_ID, REF, JOURNAL_REF,
                    RUNTIME_REF, CONTROL_REF, ENVIRONMENT, CONCURRENCY, WORKFLOW,
                    APP_ID, INSTALLATION, PERMISSIONS, BASE, _canonical, _digest,
                    _require, _sha, hash64, parse)
from proof_control import plan, FAULTS, PROPOSALS, BUDGET, CALLER
from ruleset_view import visible
from q0_evidence import custody_policy, validate_q0_custody


def gate():
    spec = importlib.util.spec_from_file_location('p6ws_accepted_gate', ROOT / 'proofs/proof2/gate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_rules(rules, ref, runtime=False):
    _require(type(rules) is list and len(rules) == 2)
    for index, rule in enumerate(rules):
        _require(type(rule['id']) is int and rule['id'] > 0
                 and rule['target'] == 'branch' and rule['enforcement'] == 'active'
                 and rule['source'] == REPO and rule['source_type'] == 'Repository'
                 and rule['conditions'] == {'ref_name': {'include': [ref], 'exclude': []}}
                 and rule['rules'] == [{'type': t} for t in (
                     ('creation', 'deletion', 'non_fast_forward') if index == 0 else ('update',))]
                 and rule['bypass_actors'] == ([] if index == 0 or runtime else [
                     {'actor_id': APP_ID, 'actor_type': 'Integration', 'bypass_mode': 'always'}]))
        visible(rule)
    _require(rules[0]['id'] != rules[1]['id'])


def validate_manifest(m, *, local=False):
    if type(m) is dict and m.get('schema') == EXEC_MANIFEST_SCHEMA:
        return validate_exec_manifest(m, local=local)
    _require(type(m) is dict and set(m) == {
        'schema', 'campaign', 'frozen', 'repository', 'repository_id', 'source_base',
        'source_commit', 'source_tree', 'build_sha256', 'runtime', 'environment',
        'concurrency', 'ref', 'baseline_commit', 'baseline_state_sha256', 'baseline_history',
        'journal', 'proof_plan_sha256', 'proposals', 'budget', 'app_id', 'installation_id',
        'token_permissions', 'authority_rulesets', 'runtime_rulesets', 'environment_policy',
        'configuration_sha256', 'authority_visible_sha256', 'source_hashes', 'custody',
        'q0_evidence_sha256'})
    _require(m['schema'] == 'P6WSV1_MANIFEST_V1' and m['campaign'] == CAMPAIGN
             and m['frozen'] is True and m['repository'] == REPO and type(m['repository_id']) is int
             and m['repository_id'] == REPO_ID and m['source_base'] == BASE
             and m['ref'] == REF and m['environment'] == ENVIRONMENT and m['concurrency'] == CONCURRENCY
             and m['app_id'] == APP_ID and type(m['app_id']) is int
             and m['installation_id'] == INSTALLATION and type(m['installation_id']) is int
             and m['token_permissions'] == PERMISSIONS
             and _canonical(m['budget']) == _canonical(BUDGET)
             and m['proof_plan_sha256'] == plan()[1])
    _sha(m['source_commit']); _sha(m['source_tree']); _sha(m['baseline_commit'])
    _require(m['source_commit'] != BASE and m['runtime'] == {
        'ref': RUNTIME_REF, 'sha': m['source_commit'], 'tree': m['source_tree'], 'workflow': WORKFLOW})
    for field in ('build_sha256', 'baseline_state_sha256', 'configuration_sha256',
                  'authority_visible_sha256', 'q0_evidence_sha256'):
        hash64(m[field])
    rules = m['authority_rulesets']
    validate_rules(rules, REF)
    validate_rules(m['runtime_rulesets'], RUNTIME_REF, runtime=True)
    j = m['journal']
    _require(set(j) == {'ref', 'path', 'genesis_commit', 'genesis_tree', 'genesis_content_sha256',
                        'schema_sha256', 'rulesets'} and j['ref'] == JOURNAL_REF and j['path'] == 'operation.json')
    _sha(j['genesis_commit']); _sha(j['genesis_tree'])
    hash64(j['genesis_content_sha256']); hash64(j['schema_sha256'])
    validate_rules([j['rulesets']['integrity'], j['rulesets']['update']], JOURNAL_REF)
    all_rules = rules + m['runtime_rulesets'] + list(j['rulesets'].values())
    _require(len({r['id'] for r in all_rules}) == 6)
    policy = m['environment_policy']
    _require(policy['name'] == ENVIRONMENT and policy['can_admins_bypass'] is False
             and policy['deployment_branch_policy'] == {'protected_branches': False, 'custom_branch_policies': True}
             and policy['deployment_branches'] == [{'name': RUNTIME_REF.removeprefix('refs/heads/'), 'type': 'branch'}]
             and policy['prevent_self_review'] is True
             and type(policy['reviewer_ids']) is list and bool(policy['reviewer_ids'])
             and all(type(i) is int and i > 0 and i != CALLER['id'] for i in policy['reviewer_ids']))
    _require(m['configuration_sha256'] == _digest(_canonical(dict(
        authority=rules, journal=j['rulesets'], runtime=m['runtime_rulesets'], environment=policy))))
    _require(m['authority_visible_sha256'] == _digest(_canonical([visible(r) for r in rules])))
    custody_policy(m['custody'])
    accepted = gate()
    state = accepted.proof1.reconstruct(m['baseline_history'])
    _require(state['state_sha256'] == m['baseline_state_sha256'])
    _require(set(m['proposals']) == set(PROPOSALS))
    # Both faults propose against the same fresh baseline; only D07 advances it.
    for op in FAULTS:
        p = m['proposals'][op]
        _require(p['proposal_id'] == PROPOSALS[op] and accepted.decide(m['baseline_history'], p)['decision'] == 'ALLOW')
    d07 = accepted.decide(m['baseline_history'], m['proposals'][FAULTS[1]])
    after = {'version': 1, 'events': m['baseline_history']['events'] + [d07['candidate_event']]}
    _require(m['proposals']['']['proposal_id'] == PROPOSALS['']
             and accepted.decide(after, m['proposals'][''])['decision'] == 'ALLOW')
    build = parse((AREA / 'build.json').read_bytes())
    _require(m['build_sha256'] == _digest((AREA / 'build.json').read_bytes())
             and m['source_hashes'] == build['sha256'])
    for name, digest in m['source_hashes'].items():
        hash64(digest)
        if local:
            _require(_digest((ROOT / name).read_bytes()) == digest)
    return m


def qualify_q0(m, evidence):
    """Only compare complete independently acquired Q0 evidence; never mutate."""
    validate_manifest(m)
    _require(set(evidence) == {'schema', 'campaign', 'source_commit', 'source_tree', 'build_sha256',
        'runtime', 'authority', 'journal', 'rulesets', 'environment', 'ordinary', 'positive_control',
        'denials', 'custody', 'writer_app', 'ordinary_inventory', 'writer_custody',
        'collector_fixtures', 'consumptions', 'protected_advances'})
    _require(_digest(_canonical(evidence)) == m['q0_evidence_sha256'])
    _require(evidence['schema'] == 'P6WSV1_Q0_V2' and evidence['campaign'] == CAMPAIGN
             and type(evidence['consumptions']) is int and evidence['consumptions'] == 0
             and type(evidence['protected_advances']) is int and evidence['protected_advances'] == 0)
    for key in ('source_commit', 'source_tree', 'build_sha256', 'runtime'):
        _require(evidence[key] == m[key])
    _require(evidence['authority'] == {'ref': REF, 'sha': m['baseline_commit'], 'state_sha256': m['baseline_state_sha256']}
             and evidence['journal'] == {k: m['journal'][k] for k in ('ref', 'genesis_commit', 'genesis_tree', 'genesis_content_sha256', 'schema_sha256')}
             and evidence['rulesets'] == {'authority': m['authority_rulesets'], 'journal': m['journal']['rulesets'], 'runtime': m['runtime_rulesets']}
             and evidence['environment'] == m['environment_policy']
             and evidence['custody'] == m['custody'])
    ordinary = evidence['ordinary']
    _require(ordinary == dict(**CALLER, role='write', admin=False, maintain=False,
        credential_source='ordinary-client/operator-owned'))
    _require(ordinary['admin'] is False and ordinary['maintain'] is False and type(ordinary['id']) is int)
    validate_q0_custody(m, evidence)
    _require(evidence['writer_app'] == {'id': APP_ID, 'installation': INSTALLATION,
        'repositories': [REPO_ID], 'permissions': PERMISSIONS,
        'credential_source': m['custody']['writer_credential_source']})
    fixtures = evidence['collector_fixtures']
    _require(set(fixtures) == {'source_sha256', 'results'}
             and fixtures['source_sha256'] == m['source_hashes']['proofs/proof6/write_safety_closure_v1/collector.py']
             and fixtures['results'] == ['PASS'] + ['NOT_PASS'] * 9)
    return {'result': 'Q0_QUALIFIED', 'consumptions': 0, 'live_credit_from_offline_tests': False}


# Immutable prospective authority, not a replacement Q0 evidence record.
EXEC_COMPAT_ADMISSION = {
    'accepted_source_commit': '6313eb40da86a179a48a87a5a28c6bc7217e4b6f',
    'accepted_source_tree': 'b22f39001d08e2df508fee953d4f96e3f2ce32be',
    'campaign': 'P6-WS-CLOSURE-V1',
    'canonical_disposition': 'Q0_SUBSTANTIVE_WRITE_SAFETY_PRECONDITION_SATISFIED__P6WSV1_Q0_COMPAT_REVIEW_V1',
    'compatibility_contract': 'P6WSV1_Q0_COMPAT_REVIEW_V1',
    'compatibility_result': 'PASS_Q0_COMPAT_REVIEW_V1',
    'compatibility_review_reviewed_mc_sha': '3303df6eebeb02c98c05b3e69585cad3c1704496',
    'historical_q0_contract': 'P6WSV1_Q0_V2',
    'historical_q0_disposition': 'NOT PASSED / EVIDENCE CONTRACT UNSATISFIED',
    'mission_control_authority_sha': '09e98051619dbe96c7c8ad0f3f8e3da852af46c0',
    'mission_control_repository': 'flipjam/mission-control',
    'review_input_sha256': 'f867ada47df87e4c218b894c49377c63ecff3ef3f88f4610630841324317fce9',
    'review_result_sha256': '75726e679ca222b9d5506a73baf08798b2e9d578b1a8f15e410e37de28e8f8fe',
    'schema': 'P6WSV1_EXEC_COMPAT_ADMISSION_V1',
    'stage_a_sha256': 'e438777d5486ca91d9c33c8f316aadf2f186c81322b495f417497c6e3d760885',
    'stage_b_sha256': '4f4e9e6ceb0f3f99a4afa2cc33a09012781cfbd2f50dd973e0cc00478ab988b6',
    'successor_contract': 'P6WSV1_EXEC_COMPAT_V1',
}
EXEC_COMPAT_ADMISSION_SHA256 = '41459434594cd31bfe12f7c0ca0594d5378f25a3d3a3c36e1661e07f9ffcd9a4'


def qualify_exec_compat(admission, digest):
    """Accept only the exact semantic owner-bound admission, without live credit."""
    _require(type(admission) is dict and set(admission) == set(EXEC_COMPAT_ADMISSION)
             and all(type(v) is str for v in admission.values())
             and admission == EXEC_COMPAT_ADMISSION)
    raw = json.dumps(admission, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')
    observed = _digest(raw)
    _require(observed == EXEC_COMPAT_ADMISSION_SHA256 and digest == observed)
    return {'result': 'EXEC_COMPAT_QUALIFIED', 'compatibility_admission_sha256': observed,
            'historical_q0_disposition': admission['historical_q0_disposition'],
            'live_credit_from_offline_tests': False}


def validate_exec_manifest(m, *, local=False):
    _require(type(m) is dict and set(m) == {
        'schema', 'campaign', 'frozen', 'repository', 'repository_id', 'source_base',
        'source_commit', 'source_tree', 'build_sha256', 'runtime', 'environment',
        'concurrency', 'ref', 'baseline_commit', 'baseline_state_sha256', 'baseline_history',
        'journal', 'proof_plan_sha256', 'proposals', 'budget', 'app_id', 'installation_id',
        'token_permissions', 'authority_rulesets', 'runtime_rulesets', 'environment_policy',
        'configuration_sha256', 'authority_visible_sha256', 'source_hashes', 'custody',
        'compatibility_admission', 'compatibility_admission_sha256', 'successor_contract',
        'source_identity', 'accepted_source_commit', 'accepted_source_tree',
        'workflow_identity', 'workflow_ref', 'workflow_sha256'})
    _require(m['schema'] == EXEC_MANIFEST_SCHEMA and m['campaign'] == CAMPAIGN
             and m['frozen'] is True and m['repository'] == REPO and type(m['repository_id']) is int
             and m['repository_id'] == REPO_ID and m['source_base'] == BASE
             and m['ref'] == REF and m['environment'] == ENVIRONMENT and m['concurrency'] == CONCURRENCY
             and m['app_id'] == APP_ID and type(m['app_id']) is int
             and m['installation_id'] == INSTALLATION and type(m['installation_id']) is int
             and m['token_permissions'] == PERMISSIONS
             and _canonical(m['budget']) == _canonical(BUDGET)
             and m['proof_plan_sha256'] == plan()[1])
    _require(m['successor_contract'] == EXEC_CONTRACT and m['source_identity'] == EXEC_SOURCE
             and m['accepted_source_commit'] == ACCEPTED_SOURCE and m['accepted_source_tree'] == ACCEPTED_TREE
             and m['source_commit'] != ACCEPTED_SOURCE and m['source_tree'] != ACCEPTED_TREE
             and m['workflow_identity'] == EXEC_WORKFLOW
             and m['workflow_ref'] == REPO + '/' + WORKFLOW + '@' + EXEC_RUNTIME_REF)
    qualify_exec_compat(m['compatibility_admission'], m['compatibility_admission_sha256'])
    _sha(m['source_commit']); _sha(m['source_tree']); _sha(m['baseline_commit'])
    _require(m['source_commit'] != BASE and m['runtime'] == {
        'ref': EXEC_RUNTIME_REF, 'sha': m['source_commit'], 'tree': m['source_tree'], 'workflow': WORKFLOW})
    for field in ('build_sha256', 'baseline_state_sha256', 'configuration_sha256',
                  'authority_visible_sha256', 'workflow_sha256'):
        hash64(m[field])
    rules = m['authority_rulesets']
    validate_rules(rules, REF)
    # IDs are mandatory, later-frozen provider inputs; no defaults or live IDs.
    validate_rules(m['runtime_rulesets'], EXEC_RUNTIME_REF, runtime=True)
    j = m['journal']
    _require(set(j) == {'ref', 'path', 'genesis_commit', 'genesis_tree', 'genesis_content_sha256',
                        'schema_sha256', 'rulesets'} and j['ref'] == JOURNAL_REF and j['path'] == 'operation.json')
    _sha(j['genesis_commit']); _sha(j['genesis_tree'])
    hash64(j['genesis_content_sha256']); hash64(j['schema_sha256'])
    validate_rules([j['rulesets']['integrity'], j['rulesets']['update']], JOURNAL_REF)
    all_rules = rules + m['runtime_rulesets'] + list(j['rulesets'].values())
    _require(len({r['id'] for r in all_rules}) == 6)
    policy = m['environment_policy']
    _require(policy['name'] == ENVIRONMENT and policy['can_admins_bypass'] is False
             and policy['deployment_branch_policy'] == {'protected_branches': False, 'custom_branch_policies': True}
             and policy['deployment_branches'] == [{'name': EXEC_RUNTIME_REF.removeprefix('refs/heads/'), 'type': 'branch'}]
             and policy['prevent_self_review'] is True
             and type(policy['reviewer_ids']) is list and bool(policy['reviewer_ids'])
             and all(type(i) is int and i > 0 and i != CALLER['id'] for i in policy['reviewer_ids']))
    _require(m['configuration_sha256'] == _digest(_canonical(dict(
        authority=rules, journal=j['rulesets'], runtime=m['runtime_rulesets'], environment=policy))))
    _require(m['authority_visible_sha256'] == _digest(_canonical([visible(r) for r in rules])))
    custody_policy(m['custody'])
    accepted = gate()
    state = accepted.proof1.reconstruct(m['baseline_history'])
    _require(state['state_sha256'] == m['baseline_state_sha256'])
    _require(set(m['proposals']) == set(PROPOSALS))
    # Both faults propose against the same fresh baseline; only D07 advances it.
    for op in FAULTS:
        p = m['proposals'][op]
        _require(p['proposal_id'] == PROPOSALS[op] and accepted.decide(m['baseline_history'], p)['decision'] == 'ALLOW')
    d07 = accepted.decide(m['baseline_history'], m['proposals'][FAULTS[1]])
    after = {'version': 1, 'events': m['baseline_history']['events'] + [d07['candidate_event']]}
    _require(m['proposals']['']['proposal_id'] == PROPOSALS['']
             and accepted.decide(after, m['proposals'][''])['decision'] == 'ALLOW')
    build = parse((AREA / 'build.json').read_bytes())
    _require(m['build_sha256'] == _digest((AREA / 'build.json').read_bytes())
             and m['source_hashes'] == build['sha256'])
    _require(m['workflow_sha256'] == m['source_hashes'][WORKFLOW])
    for name, digest in m['source_hashes'].items():
        hash64(digest)
        if local:
            _require(_digest((ROOT / name).read_bytes()) == digest)
    return m
