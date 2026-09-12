"""Fixed credential-free child qualification; no writer/journal/gate imports."""
import json
import os
from pathlib import Path
import subprocess
import sys

# -I ignores ambient PYTHONPATH and script directory; add only this fixed source.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import d04_capability as capability

SCHEMA = 'PROOF6_R3G_D04_PREREQUISITE_V1'
CONTEXT_KEYS = ('euid', 'kernel', 'cap_eff', 'cap_sys_admin', 'seccomp', 'lsm', 'netns', 'runner')


def matching(parent, child):
    return all(parent[k] == child[k] for k in CONTEXT_KEYS)


def run():
    result = {'schema': SCHEMA, 'stage': 'PARENT_CONTEXT', 'qualified': False,
              'acceptance_credit': False, 'parent_before': None, 'parent_after': None,
              'child': None, 'supervisor_exit': None, 'child_reaped': False,
              'exception': None}
    try:
        parent = result['parent_before'] = capability.context()
        capability.require(parent['euid'] == 0 and parent['cap_sys_admin']
                           and parent['runner']['RUNNER_ENVIRONMENT'] == 'github-hosted')
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', **parent['runner']}
        # The fixed leaf never forks. --foreground makes this inner 20s
        # supervisor inherit the writer's process group, so the unchanged OUTER
        # 120s group kill also covers it. Do not create an escaping session.
        command = ['/usr/bin/timeout', '--foreground', '--signal=KILL', '20s', '/usr/bin/python3',
                   '-I', '-B', str(Path(__file__).with_name('d04_capability.py').resolve())]
        result['stage'] = 'CHILD_SUPERVISOR'
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env=env, close_fds=True,
                              start_new_session=False, cwd='/') as proc:
            raw, _ = proc.communicate()
            result.update(supervisor_exit=proc.returncode, child_reaped=True)
        result['parent_after'] = capability.context()
        capability.require(matching(parent, result['parent_after']))
        result['stage'] = 'CHILD_RECORD'
        capability.require(len(raw) <= 16384)
        child = capability.validate_record(json.loads(raw))
        result['child'] = child
        result['stage'] = 'CONTEXT_MATCH'
        capability.require(child['context'] is not None and matching(parent, child['context'])
                           and child['context']['pid'] != parent['pid'])
        result['stage'] = 'CHILD_QUALIFICATION'
        capability.require(result['supervisor_exit'] == 0 and child['qualified'] is True
                           and child['stage'] == 'QUALIFIED')
        result.update(stage='PREREQUISITE_PASS', qualified=True)
    except Exception as exc:
        result.update(stage=result['stage'] + '_BLOCKED', exception=capability.exception(exc))
    return result


def setup_qualification(raw):
    """Read only the fixed workflow step output; not a public workflow input."""
    capability.require(type(raw) is str and len(raw.encode()) <= 32768)
    result = json.loads(raw)
    capability.require(type(result) is dict and set(result) == {'schema','stage','qualified',
                       'acceptance_credit','parent_before','parent_after','child','supervisor_exit',
                       'child_reaped','exception'})
    capability.validate_context(result['parent_before'])
    capability.validate_context(result['parent_after'])
    capability.validate_record(result['child'])
    capability.require(result['schema'] == SCHEMA and result['stage'] == 'PREREQUISITE_PASS'
                       and result['qualified'] is True and result['acceptance_credit'] is False
                       and type(result['supervisor_exit']) is int and result['supervisor_exit'] == 0
                       and result['child_reaped'] is True
                       and result['exception'] is None and result['child']['qualified'] is True
                       and result['child']['schema'] == capability.SCHEMA
                       and result['child']['context']['pid'] != result['parent_before']['pid']
                       and matching(result['parent_before'], result['parent_after'])
                       and matching(result['parent_before'], result['child']['context']))
    return result


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('{"schema":"PROOF6_R3G_D04_PREREQUISITE_V1","stage":"INPUT_REJECTED","qualified":false}')
        sys.exit(1)
    receipt = run()
    print(json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False), flush=True)
    sys.exit(0 if receipt['qualified'] else 1)
