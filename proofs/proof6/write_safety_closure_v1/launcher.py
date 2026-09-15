"""Hosted fixed-case entry, unavailable until separately provisioned/frozen."""
import os
import sys
from pathlib import Path

# -I suppresses cwd/PYTHONPATH; explicitly load only the checked source directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (CAMPAIGN, REPO, REPO_ID, EXEC_RUNTIME_REF, WORKFLOW, ENVIRONMENT,
                    _canonical, _digest, _require, parse)
from proof_control import request, account_permission, plan, CALLER
from qualification import validate_exec_manifest
from collector import ReadOnlyRemote, Inspection
from ruleset_view import visible


def frozen(env):
    raw = env['P6WSV1_EXEC_COMPAT_FROZEN_MANIFEST'].encode('ascii')
    _require(_digest(raw) == env['P6WSV1_EXEC_COMPAT_MANIFEST_SHA256'])
    m = parse(raw)
    _require(raw == _canonical(m))
    validate_exec_manifest(m, local=True)
    _require(env['GITHUB_REPOSITORY'] == REPO and env['GITHUB_REPOSITORY_ID'] == str(REPO_ID)
             and env['GITHUB_REF'] == EXEC_RUNTIME_REF and env['GITHUB_SHA'] == m['source_commit']
             and env['GITHUB_WORKFLOW_REF'] == REPO + '/' + WORKFLOW + '@' + EXEC_RUNTIME_REF
             and env['GITHUB_EVENT_NAME'] == 'workflow_dispatch' and env['GITHUB_RUN_ATTEMPT'] == '1'
             and env['GITHUB_ACTOR'] == env['GITHUB_TRIGGERING_ACTOR'] == CALLER['login']
             and env['GITHUB_ACTOR_ID'] == str(CALLER['id']) and env['RUNNER_ENVIRONMENT'] == 'github-hosted')
    return m


def run(env):
    m = frozen(env)
    event = parse(Path(env['GITHUB_EVENT_PATH']).read_bytes())
    payload, operation = request(event['inputs'], m)
    remote = ReadOnlyRemote(env['GH_TOKEN'])
    inspect = Inspection(remote.get)
    def guard(manifest):
        _require(manifest == m and inspect.ref(EXEC_RUNTIME_REF) == m['source_commit']
                 and inspect.commit(m['source_commit'])['tree']['sha'] == m['source_tree']
                 and inspect.environment(ENVIRONMENT) == m['environment_policy'])
        for rule in m['runtime_rulesets']:
            actual = remote.get('/rulesets/' + str(rule['id']))
            _require(visible(actual) == visible(rule))
            if 'bypass_actors' in actual:
                _require(actual['bypass_actors'] == [])
    guard(m)
    caller = account_permission(lambda path: remote.get(path.removeprefix('repos/' + REPO)))
    binding = dict(run_id=int(env['GITHUB_RUN_ID']), run_attempt=1, runtime_sha=m['source_commit'],
        caller=caller, proof_operation=operation, proof_plan_sha256=plan()[1])
    from writer import _Writer
    writer = _Writer(frozen_manifest=m, installation_token=env['P6WSV1_APP_TOKEN'],
        action_installation_id=env['P6WSV1_APP_INSTALLATION_ID'],
        action_app_slug=env['P6WSV1_APP_SLUG'], runtime_guard=guard, receipt_binding=binding)
    return writer.recover_only() if payload is None else writer.commit_transition(payload, operation)


if __name__ == '__main__':
    try:
        result = run(os.environ)
    except Exception:
        # No environment values, exception strings or credentials in errors.
        result = {'result': 'BLOCKED', 'reason': 'QUALIFICATION_OR_EXECUTION_UNCONFIRMED'}
    print('P6WSV1_RESULT ' + _canonical(result).decode('ascii'), flush=True)
    raise SystemExit(0 if result['result'] in ('COMMITTED', 'RECOVERY_CONFIRMED', 'INDETERMINATE') else 2)
