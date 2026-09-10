"""Protected Actions launcher. No caller-selectable runtime configuration."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

from writer import _Writer, _canonical, _require, REPO, REPO_ID, REF
from reconcile import reconcile
import diagnostics as dia
from ruleset_view import visible

RUNTIME_REF = 'refs/heads/proof6-writer-runtime-r3'
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
    rule = get(base + '/rulesets/22792054')
    expected_view = json.loads((root / 'proofs/proof6/diagnostic-bindings.json').read_bytes())['runtime_view']
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
    _require(policy['id'] == 59579447 and policy['name'] == 'proof6-writer-runtime-r3'
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
        'manifest_variable': 'PROOF6_FROZEN_MANIFEST'}
    if manifest is not None:
        _require(manifest['runtime'] == runtime)
    return runtime


def reconcile_prior_runs(manifest):
    """Serialized job admission: prior ambiguous/failed runs require disposition.

    Only frozen-interval runs count. No acceptance mutation can skip this check.
    Failed runs without a usable receipt block rather than assuming no mutation.
    """
    first = manifest['first_mutation_run_number']
    _require(type(first) is int and 1 <= first <= int(os.environ['GITHUB_RUN_NUMBER']))
    page = 1
    prior = []
    while True:
        runs = get('repos/' + REPO + '/actions/workflows/proof6-writer.yml/runs?per_page=100&page=' + str(page))
        prior.extend(run for run in runs['workflow_runs']
                     if first <= run['run_number'] < int(os.environ['GITHUB_RUN_NUMBER'])
                     and run['head_branch'] == RUNTIME_REF.removeprefix('refs/heads/')
                     and run['head_sha'] == manifest['runtime']['sha'])
        if len(runs['workflow_runs']) < 100:
            break
        page += 1
    if not prior:
        return
    # Every admitted job first reconciles its predecessor. A successful job or
    # a writer receipt therefore certifies completion of earlier admission.
    run = max(prior, key=lambda item: item['run_number'])
    _require(run['status'] == 'completed')
    raw = subprocess.run(['gh', 'run', 'view', str(run['id']), '--repo', REPO, '--log'],
                         check=True, capture_output=True, timeout=60).stdout.decode('utf-8')
    receipts = []
    for line in raw.splitlines():
        for marker in ('PROOF6_PENDING ', 'PROOF6_RESULT '):
            if marker in line:
                try:
                    receipts.append(json.loads(line.split(marker, 1)[1]))
                except ValueError:
                    pass
    _require(bool(receipts))
    receipt = receipts[-1]
    _require(receipt['manifest_sha256'] == hashlib.sha256(_canonical(manifest)).hexdigest())
    if run['conclusion'] == 'success':
        _require(receipt['result'] in ('COMMITTED', 'REJECTED', 'APP_AUTH_SETUP_VERIFIED'))
        return
    if receipt.get('update_attempted') is False:
        return
    result = reconcile(receipt['old_sha'], receipt['candidate_commit'])
    result['run_id'] = run['id']
    print('PROOF6_RECONCILIATION ' + json.dumps(result, sort_keys=True), flush=True)
    _require(result['result'] in ('COMMITTED', 'NOT_COMMITTED'))


def main():
    # The workflow puts input in the event JSON, never interpolated into code.
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    inputs = event.get('inputs') or {}
    _require(set(inputs) <= {'proposal'})
    proposal = inputs.get('proposal', '')
    _require(type(proposal) is str and len(proposal.encode('utf-8')) <= 65536)
    manifest_text = os.environ.get('PROOF6_FROZEN_MANIFEST', '')
    manifest = json.loads(manifest_text) if manifest_text else None
    dia.start('DIA01')
    guard(manifest)
    dia.ok('DIA01_RUNTIME_GUARD_OK')
    if proposal:
        _require(manifest is not None)
    if manifest is not None:
        _require(os.environ['GITHUB_RUN_ATTEMPT'] == '1')
        reconcile_prior_runs(manifest)
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
                     action_app_slug=action_app_slug, runtime_guard=guard)
    result = (writer.commit_transition(proposal.encode('utf-8')) if proposal else
              writer.verify_setup_auth())
    if not proposal:
        result['manifest_sha256'] = writer._manifest_digest
        result['update_attempted'] = False
    print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['result'] in ('COMMITTED', 'REJECTED', 'APP_AUTH_SETUP_VERIFIED') else 1


if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        dia.blocked(error)
        code = 1
    sys.exit(code)
