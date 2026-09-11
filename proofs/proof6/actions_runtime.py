"""Protected Actions launcher. No caller-selectable runtime configuration."""
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.request

from writer import _Writer, _canonical, _require, REPO, REPO_ID, REF
from admission import binding, blocked
import diagnostics as dia
from ruleset_view import visible
import proof_control

RUNTIME_REF = 'refs/heads/proof6-writer-runtime-r3d'
WORKFLOW = '.github/workflows/proof6-writer.yml'
ENVIRONMENT = 'proof6-writer'
CONCURRENCY = 'proof6-authority-writer-r3'
TOKEN_PERMISSIONS = {'contents': 'read', 'actions': 'read'}
APP_TOKEN_PERMISSIONS = {'contents': 'write', 'metadata': 'read'}
APP_ACTION = {'repository': 'actions/create-github-app-token',
              'commit': 'bcd2ba49218906704ab6c1aa796996da409d3eb1'}
RULE_FIELDS = ('id', 'name', 'target', 'source_type', 'source', 'enforcement',
               'conditions', 'rules', 'bypass_actors')


def get(path):
    request = urllib.request.Request('https://api.github.com/' + path, headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json', 'User-Agent': 'proof6-runtime-simplified'})
    # Fixed API endpoints only. Disable proxy and redirects as in the writer.
    from writer import _NoRedirect
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with http.open(request, timeout=30) as response:
        return json.load(response)


def guard(manifest):
    # Candidate cannot run against R3c bindings. Future setup must supply the
    # reviewed successor manifest with real provisioned identities; no defaults.
    _require(manifest is not None and manifest['runtime_variant'] == 'r3d')
    _require(os.environ['GITHUB_REPOSITORY'] == REPO
             and os.environ['GITHUB_REPOSITORY_ID'] == str(REPO_ID)
             and os.environ['GITHUB_REF'] == RUNTIME_REF
             and os.environ['GITHUB_WORKFLOW_REF'] == REPO + '/' + WORKFLOW + '@' + RUNTIME_REF
             and os.environ['RUNNER_ENVIRONMENT'] == 'github-hosted'
             and os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch')
    root = Path(__file__).resolve().parents[2]
    build_raw = (root / 'proofs/proof6/build.json').read_bytes()
    for path, digest in json.loads(build_raw).items():
        _require(hashlib.sha256((root / path).read_bytes()).hexdigest() == digest)
    base = 'repos/' + REPO
    ref = get(base + '/git/ref/' + RUNTIME_REF.removeprefix('refs/'))
    _require(ref['ref'] == RUNTIME_REF and ref['object']['sha'] == os.environ['GITHUB_SHA'])
    expected_view = manifest['runtime']['ruleset']
    _require(expected_view['conditions'] == {'ref_name': {'include': [RUNTIME_REF], 'exclude': []}}
             and expected_view['enforcement'] == 'active'
             and expected_view['rules'] == [{'type': 'update'}, {'type': 'deletion'}, {'type': 'non_fast_forward'}])
    rule = get(base + '/rulesets/' + str(expected_view['id']))
    _require(visible(rule) == expected_view)
    if 'current_user_can_bypass' in rule:
        _require(rule['current_user_can_bypass'] == 'never')
    rule = visible(rule)
    env = get(base + '/environments/' + ENVIRONMENT)
    policies = get(base + '/environments/' + ENVIRONMENT + '/deployment-branch-policies')
    _require(env['id'] == 21620162130 and env['name'] == ENVIRONMENT
             and env['can_admins_bypass'] is False
             and env['deployment_branch_policy'] == {
                 'protected_branches': False, 'custom_branch_policies': True})
    _require(policies['total_count'] == 1 and len(policies['branch_policies']) == 1)
    policy = policies['branch_policies'][0]
    _require(policy['id'] == manifest['runtime']['branch_policy']['id'] and policy['name'] == 'proof6-writer-runtime-r3d'
             and policy['type'] == 'branch')
    runtime = {
        'ref': RUNTIME_REF, 'sha': ref['object']['sha'], 'workflow': WORKFLOW,
        'build_sha256': hashlib.sha256(build_raw).hexdigest(),
        'ruleset': rule, 'environment_id': env['id'], 'environment': ENVIRONMENT,
        'deployment_branch_policy': env['deployment_branch_policy'],
        'branch_policy': {k: policy[k] for k in ('id', 'name', 'type')},
        'can_admins_bypass': env['can_admins_bypass'],
        'runner': 'github-hosted', 'runner_label': 'ubuntu-24.04',
        'concurrency': CONCURRENCY, 'cancel_in_progress': False,
        'github_token_permissions': TOKEN_PERMISSIONS,
        'app_token_action': APP_ACTION,
        'app_token_permissions': APP_TOKEN_PERMISSIONS,
        'app_id': 4893415,
        'app_installation_id': 160504789,
        'app_slug': 'mc-proof-6-gate-writer',
        'secret': 'PROOF6_APP_PRIVATE_KEY',
        'manifest_variable': 'PROOF6_FROZEN_MANIFEST',
        'proof_plan_sha256': proof_control.plan()[1]}
    if manifest is not None:
        _require(manifest['runtime'] == runtime)
    return runtime


def current_binding(manifest):
    return binding(manifest, int(os.environ['GITHUB_RUN_ID']),
                   int(os.environ['GITHUB_RUN_ATTEMPT']), os.environ['GITHUB_SHA'])


def main(context):
    manifest_text = os.environ.get('PROOF6_FROZEN_MANIFEST', '')
    manifest = json.loads(manifest_text) if manifest_text else None
    context['identity'] = current_binding(manifest)
    if '--prewriter-blocked' in sys.argv:
        raise ValueError('PREWRITER_STEP_FAILED')
    # The workflow puts input in the event JSON, never interpolated into code.
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    inputs = event.get('inputs') or {}
    proposal, operation, plan, plan_digest = proof_control.request(inputs)
    dia.start('DIA01')
    guard(manifest)
    dia.ok('DIA01_RUNTIME_GUARD_OK')
    if proposal or operation:
        _require(manifest is not None)
        context['identity']['caller'] = proof_control.qualify(os.environ, get)
    if manifest is not None:
        _require(os.environ['GITHUB_RUN_ATTEMPT'] == '1')
        _require(manifest['proof_plan_sha256'] == plan_digest)
    if operation:
        context['identity'].update(proof_operation=operation, proof_plan_sha256=plan_digest)
    # The official action owns key handling and returns only this short-lived token.
    # It is consumed in memory and never printed, persisted, or passed to a shell.
    dia.start('DIA02')
    token = os.environ.pop('PROOF6_APP_TOKEN', '')
    _require(bool(token))
    dia.ok('DIA02_INSTALLATION_TOKEN_PRESENT')
    dia.start('DIA03')
    action_installation_id = os.environ.pop('PROOF6_APP_INSTALLATION_ID', '')
    action_app_slug = os.environ.pop('PROOF6_APP_SLUG', '')
    _require(action_installation_id == '160504789'
             and action_app_slug == 'mc-proof-6-gate-writer')
    dia.ok('DIA03_ACTION_OUTPUTS_VERIFIED')
    writer = _Writer(frozen_manifest=manifest, installation_token=token,
                     action_installation_id=action_installation_id,
                     action_app_slug=action_app_slug, runtime_guard=guard,
                     receipt_binding=context['identity'])
    context['writer'] = writer
    if operation == proof_control.OUTAGE:
        from journal import Journal
        from outage import isolate_runtime
        token = writer._installation_access()
        writer._enforcement(token)
        journal = Journal(writer)
        def current():
            ref = get('repos/' + REPO + '/git/ref/heads/proof6-authority')
            _require(ref['ref'] == REF and ref['object']['type'] == 'commit')
            from writer import _sha
            return _sha(ref['object']['sha'])
        journal.recover(current)
        claim = journal.consume(journal.operation_binding(_canonical(plan['infrastructure']), operation))
        # Credential no longer needed. Same interpreter now loses connectivity;
        # it never invokes commit_transition, arms a send or reconnects afterward.
        writer._installation_token = ''
        token = ''
        result = isolate_runtime(lambda item: print('PROOF6_OUTAGE ' + json.dumps(
            dict(item, consumed_record=claim, **context['identity']), sort_keys=True), flush=True))
        result.update(context['identity'])
        print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
        return 0
    result = (writer.commit_transition(proposal.encode('utf-8'), operation) if proposal else
              writer.verify_setup_auth())
    if not proposal:
        result['proof_plan_sha256'] = plan_digest
        result['prospective_caller_account'] = proof_control.account_permission(get)
        result['manifest_sha256'] = writer._manifest_digest
        result['update_attempted'] = False
        result['remote_outcome'] = 'not_attempted'
    result.update(context['identity'])
    print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['result'] in ('COMMITTED', 'REJECTED', 'APP_AUTH_SETUP_VERIFIED') else 1


def execute():
    context = {'writer': None, 'identity': current_binding(None)}
    try:
        return main(context)
    except BaseException as error:
        writer = context['writer']
        evidence = None if writer is None else writer._last_evidence
        result = blocked(context['identity']) if evidence is None else dict(evidence)
        if result['update_attempted']:
            # A failure after handoff never becomes a no-update receipt.
            result.update(result='INDETERMINATE', remote_outcome='unknown')
        else:
            result['result'] = 'BLOCKED'
        print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
        dia.blocked(error)
        return 1


if __name__ == '__main__':
    sys.exit(execute())
