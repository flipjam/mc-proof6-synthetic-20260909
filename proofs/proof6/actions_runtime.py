"""Protected Actions launcher. No caller-selectable runtime configuration."""
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.request

from writer import _Writer, _canonical, _require, REPO, REPO_ID, REF, setup_bootstrap_diagnostics
from admission import binding, blocked
import diagnostics as dia
from ruleset_view import visible
import proof_control
import d04_capability
import d04_prerequisite
import d04_signal

RUNTIME_REF = 'refs/heads/proof6-writer-runtime-r3h'
WORKFLOW = '.github/workflows/proof6-writer.yml'
ENVIRONMENT = 'proof6-writer'
CONCURRENCY = 'proof6-authority-writer-r3'
TOKEN_PERMISSIONS = {'contents': 'read', 'actions': 'read'}
APP_TOKEN_PERMISSIONS = {'contents': 'write', 'metadata': 'read'}
APP_ACTION = {'repository': 'actions/create-github-app-token',
              'commit': 'bcd2ba49218906704ab6c1aa796996da409d3eb1'}
# D04 has no ordinary job-token delivery. Its already-authorized App performs
# the unchanged caller-permission metadata read; other D04 GETs are public.
# D03 and every ordinary job retain GH_TOKEN.
_D04_READ_TOKEN = os.environ.get('PROOF6_APP_TOKEN', '') if os.environ.get('GITHUB_JOB') == 'd04_writer' else ''

RULE_FIELDS = ('id', 'name', 'target', 'source_type', 'source', 'enforcement',
               'conditions', 'rules', 'bypass_actors')


def get(path):
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'proof6-runtime-simplified'}
    if os.environ.get('GITHUB_JOB') == 'd04_writer':
        # Public immutable/configuration reads require no workflow credential.
        # The one authenticated metadata read retains the same caller decision.
        if path == 'repos/' + REPO + '/collaborators/peaklinesoftware/permission':
            _require(bool(_D04_READ_TOKEN))
            headers['Authorization'] = 'Bearer ' + _D04_READ_TOKEN
    else:
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    request = urllib.request.Request('https://api.github.com/' + path, headers=headers)
    # Fixed API endpoints only. Disable proxy and redirects as in the writer.
    from writer import _NoRedirect
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with http.open(request, timeout=30) as response:
        return json.load(response)


def runtime_context():
    """Fixed precredential context shared by bootstrap and frozen execution."""
    _require(os.environ['GITHUB_REPOSITORY'] == REPO
             and os.environ['GITHUB_REPOSITORY_ID'] == str(REPO_ID)
             and os.environ['GITHUB_REF'] == RUNTIME_REF
             and os.environ['GITHUB_WORKFLOW_REF'] == REPO + '/' + WORKFLOW + '@' + RUNTIME_REF
             and os.environ['RUNNER_ENVIRONMENT'] == 'github-hosted'
             and os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
             and os.environ['GITHUB_RUN_ATTEMPT'] == '1')
    root = Path(__file__).resolve().parents[2]
    build_raw = (root / 'proofs/proof6/build.json').read_bytes()
    for path, digest in json.loads(build_raw).items():
        _require(hashlib.sha256((root / path).read_bytes()).hexdigest() == digest)
    plan_digest = proof_control.plan()[1]
    _require(plan_digest == '804a7c48581ddbb6910e69860a4a982b9d3cedbd1937ba6b32a2606f9536adc0')
    base = 'repos/' + REPO
    ref = get(base + '/git/ref/' + RUNTIME_REF.removeprefix('refs/'))
    _require(ref['ref'] == RUNTIME_REF and ref['object']['sha'] == os.environ['GITHUB_SHA'])
    env = get(base + '/environments/' + ENVIRONMENT)
    policies = get(base + '/environments/' + ENVIRONMENT + '/deployment-branch-policies')
    _require(env['id'] == 21620162130 and env['name'] == ENVIRONMENT
             and env['can_admins_bypass'] is False
             and env['deployment_branch_policy'] == {
                 'protected_branches': False, 'custom_branch_policies': True})
    _require(policies['total_count'] == 1 and len(policies['branch_policies']) == 1)
    policy = policies['branch_policies'][0]
    _require(policy['name'] == 'proof6-writer-runtime-r3h' and policy['type'] == 'branch')
    return ref, env, policy, hashlib.sha256(build_raw).hexdigest(), plan_digest


def guard(manifest):
    # Bootstrap never weakens the final manifest guard on normal/proof requests.
    _require(manifest is not None and manifest['runtime_variant'] == 'r3h')
    ref, env, policy, build_digest, plan_digest = runtime_context()
    base = 'repos/' + REPO
    expected_view = manifest['runtime']['ruleset']
    _require(expected_view['conditions'] == {'ref_name': {'include': [RUNTIME_REF], 'exclude': []}}
             and expected_view['enforcement'] == 'active'
             and expected_view['rules'] == [{'type': 'update'}, {'type': 'deletion'}, {'type': 'non_fast_forward'}])
    rule = get(base + '/rulesets/' + str(expected_view['id']))
    _require(visible(rule) == expected_view)
    if 'current_user_can_bypass' in rule:
        _require(rule['current_user_can_bypass'] == 'never')
    rule = visible(rule)
    _require(policy['id'] == manifest['runtime']['branch_policy']['id'] and policy['name'] == 'proof6-writer-runtime-r3h'
             and policy['type'] == 'branch')
    runtime = {
        'ref': RUNTIME_REF, 'sha': ref['object']['sha'], 'workflow': WORKFLOW,
        'build_sha256': build_digest,
        'ruleset': rule, 'environment_id': env['id'], 'environment': ENVIRONMENT,
        'deployment_branch_policy': env['deployment_branch_policy'],
        'branch_policy': {k: policy[k] for k in ('id', 'name', 'type')},
        'can_admins_bypass': env['can_admins_bypass'],
        'runner': 'github-hosted', 'runner_label': 'ubuntu-24.04',
        'concurrency': CONCURRENCY, 'cancel_in_progress': False,
        'github_token_permissions': TOKEN_PERMISSIONS,
        'd04_helper_job_permissions': {'statuses': 'write'},
        'd04_writer_read_credential': 'public GETs; existing App caller-metadata GET; no job token',
        'app_token_action': APP_ACTION,
        'app_token_permissions': APP_TOKEN_PERMISSIONS,
        'app_id': 4893415,
        'app_installation_id': 160504789,
        'app_slug': 'mc-proof-6-gate-writer',
        'secret': 'PROOF6_APP_PRIVATE_KEY',
        'manifest_variable': 'PROOF6_FROZEN_MANIFEST',
        'proof_plan_sha256': plan_digest}
    if manifest is not None:
        _require(manifest['runtime'] == runtime)
    # Requalify the same immutable hosted caller at every frozen guard, including
    # each separately admitted completion in the fixed R7 sibling demonstration.
    proof_control.qualify(os.environ, get)
    return runtime


def current_binding(manifest):
    return binding(manifest, int(os.environ['GITHUB_RUN_ID']),
                   int(os.environ['GITHUB_RUN_ATTEMPT']), os.environ['GITHUB_SHA'])


def main(context):
    global _D04_READ_TOKEN
    manifest_text = os.environ.get('PROOF6_FROZEN_MANIFEST', '')
    context['identity'] = current_binding(None)
    if '--prewriter-blocked' in sys.argv:
        raise ValueError('PREWRITER_STEP_FAILED')
    # The workflow puts input in the event JSON, never interpolated into code.
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    inputs = event.get('inputs', {})
    proposal, operation, plan, plan_digest = proof_control.request(inputs)
    if manifest_text == '' and proposal == '' and operation == '':
        ref, env, policy, build_digest, checked_plan = runtime_context()
        _require(checked_plan == plan_digest)
        qualification = d04_prerequisite.setup_qualification(
            os.environ.pop('PROOF6_D04_SETUP_QUALIFICATION', ''))
        signal_qualification = d04_signal.setup_qualification(
            os.environ.pop('PROOF6_D04_SIGNAL_SETUP_QUALIFICATION', ''))
        # This branch cannot instantiate a writer, journal, gate or fault path.
        # Credential is used only by the standalone three-GET diagnostic.
        result = setup_bootstrap_diagnostics(
            installation_token=os.environ.pop('PROOF6_APP_TOKEN', ''),
            action_installation_id=os.environ.pop('PROOF6_APP_INSTALLATION_ID', ''),
            action_app_slug=os.environ.pop('PROOF6_APP_SLUG', ''))
        result.update(context['identity'])
        result.update(phase='SETUP_BOOTSTRAP', frozen=False, manifest_sha256=None,
                      update_attempted=False, remote_outcome='not_attempted',
                      journal_mutation_attempted=False, proof_consumption_attempted=False,
                      acceptance_credit=False, repository=REPO, runtime_ref=RUNTIME_REF,
                      d04_setup_qualification=qualification,
                      d04_signal_setup_qualification=signal_qualification,
                      runtime_sha=ref['object']['sha'], build_sha256=build_digest,
                      proof_plan_sha256=checked_plan, environment_id=env['id'],
                      branch_policy=policy, actor=os.environ['GITHUB_ACTOR'],
                      actor_id=os.environ['GITHUB_ACTOR_ID'],
                      triggering_actor=os.environ['GITHUB_TRIGGERING_ACTOR'])
        print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
        return 0
    # A present manifest, even JSON null, never reopens bootstrap. A qualified
    # frozen empty request enters recovery only, before commit_transition.
    manifest = json.loads(manifest_text) if manifest_text else None
    context['identity'] = current_binding(manifest)
    dia.start('DIA01')
    guard(manifest)
    dia.ok('DIA01_RUNTIME_GUARD_OK')
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
    if not proposal and not operation:
        result = writer.recover_only()
        result.update(context['identity'])
        print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
        return 0
    if operation == proof_control.OUTAGE:
        from journal import Journal
        from outage import isolate_runtime
        context['d04'] = {'stage': 'ADMISSION', 'consumption_attempted': False,
                          'consumed_record': None, 'prerequisite': None}
        token = writer._installation_access()
        writer._enforcement(token)
        journal = Journal(writer)
        def current():
            ref = get('repos/' + REPO + '/git/ref/heads/proof6-authority')
            _require(ref['ref'] == REF and ref['object']['type'] == 'commit')
            from writer import _sha
            return _sha(ref['object']['sha'])
        # D04 admission itself may not append a recovery terminal before a
        # failed prerequisite. Unresolved sends need the existing recovery-only
        # entry first; already complete history is reconciled read-only here.
        _require(set(journal.pending) <= journal.resolved)
        journal.recover(current)
        _require(operation not in journal.used)
        context['d04']['stage'] = 'PREREQUISITE'
        prerequisite = d04_prerequisite.run()
        context['d04']['prerequisite'] = prerequisite
        print('PROOF6_D04_PREREQUISITE ' + json.dumps(prerequisite, sort_keys=True), flush=True)
        _require(prerequisite['qualified'] is True)
        context['d04']['stage'] = 'SIGNAL_READINESS'
        head = journal.head
        helper = d04_signal.Client()
        context['signal_helper'] = helper
        # Recheck exact journal membership after the child, under the same sole
        # workflow concurrency boundary. No new lifecycle may be skipped.
        context['d04']['stage'] = 'PRECONSUMPTION_RECHECK'
        journal.read()
        _require(journal.head == head and operation not in journal.used)
        helper.qualify()
        context['d04'].update(stage='CONSUMPTION', consumption_attempted=True)
        claim = journal.consume(journal.operation_binding(_canonical(plan['infrastructure']), operation))
        context['d04'].update(stage='ACTUAL_ISOLATION', consumed_record=claim)
        # Credential no longer needed. Same interpreter now loses connectivity;
        # it never invokes commit_transition, arms a send or reconnects afterward.
        writer._installation_token = ''
        token = ''
        _D04_READ_TOKEN = ''
        def emit(item):
            print('PROOF6_OUTAGE ' + json.dumps(
                dict(item, consumed_record=claim, **context['identity']), sort_keys=True), flush=True)
            helper.emit(item)
        result = isolate_runtime(emit)
        _require(helper.ended is True)
        helper.close()
        context['signal_helper'] = None
        result.update(context['identity'])
        print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
        return 0
    result = writer.commit_transition(proposal.encode('utf-8'), operation)
    result.update(context['identity'])
    print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
    if operation == 'D03_REMOTE_REJECTION':
        return 0 if result.get('d03_result') == 'PASS' else 1
    return 0 if result['result'] in ('COMMITTED', 'REJECTED', 'APP_AUTH_SETUP_VERIFIED') else 1


def execute():
    context = {'writer': None, 'identity': current_binding(None)}
    try:
        return main(context)
    except BaseException as error:
        if context.get('signal_helper') is not None:
            context['signal_helper'].close()
        if context.get('d04'):
            d04 = context['d04']
            result = blocked(context['identity'])
            result.update(result='D04_FAILED_CONSUMED' if d04['consumed_record'] else
                          'D04_CONSUMPTION_UNCONFIRMED' if d04['consumption_attempted'] else
                          'PRECONDITION_BLOCKED', d04=d04, acceptance_credit=False)
            if isinstance(error, d04_capability.CapabilityError):
                result['d04_diagnostic'] = error.record
            else:
                result['d04_exception'] = d04_capability.exception(error)
            print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
            return 1
        writer = context['writer']
        evidence = None if writer is None else writer._last_evidence
        result = blocked(context['identity']) if evidence is None else dict(evidence)
        if result['update_attempted']:
            # A failure after handoff never becomes a no-update receipt.
            result.update(result='INDETERMINATE', remote_outcome='unknown')
        elif not result.get('journal_completion_attempted'):
            result['result'] = 'BLOCKED'
        print('PROOF6_RESULT ' + json.dumps(result, sort_keys=True), flush=True)
        dia.blocked(error)
        return 1


if __name__ == '__main__':
    sys.exit(execute())
