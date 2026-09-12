"""One-run, non-acceptance startup tracing; never serialize frame values generally."""
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

SCHEMA = 'PROOF6_STARTUP_DIAGNOSTIC_V1'
BASE = 'd4d0d448026b9f0dd0728a852d757543b550208e'
FUNCTIONS = {'binding', 'custody', 'custody_values', '_worker_log',
             'masked_worker_record', '_permission_evidence', '_serve',
             'serve_setup', 'qualify_setup', 'cleanup', 'setup_qualification'}
KNOWN_EXTRA_KEYS = {'LC_CTYPE', 'LC_ALL', 'LANGUAGE', 'SUDO_PS1', 'SUDO_TTY',
                   'SUDO_PROMPT', 'DEBIAN_FRONTEND', 'RUNNER_TRACKING_ID',
                   'GITHUB_ACTIONS', 'CI', 'TZ', 'PYTHONPATH', 'PYTHONHOME'}
ERRORS = {'ValueError', 'KeyError', 'TypeError', 'AttributeError', 'OSError',
          'PermissionError', 'FileNotFoundError', 'FileExistsError', 'TimeoutError',
          'ProcessLookupError', 'UnicodeDecodeError', 'JSONDecodeError',
          'BrokenPipeError', 'ConnectionResetError', 'SystemExit'}
seen = set()
last = None


def emit(stage, **fields):
    value = dict(schema=SCHEMA, stage=stage, pid=os.getpid(), euid=os.geteuid(),
                 utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 monotonic=time.monotonic(), acceptance_credit=False, **fields)
    print('PROOF6_STARTUP_DIAGNOSTIC ' + json.dumps(value, sort_keys=True), flush=True)


def error_fields(error):
    number = getattr(error, 'errno', None)
    number = number if type(number) is int and 0 <= number <= 4096 else None
    name = type(error).__name__
    return dict(exception=name if name in ERRORS else 'OTHER_EXCEPTION',
                errno=number, errno_name=errno.errorcode.get(number))


def install(source):
    source = str(Path(source).resolve())
    raw = Path(source).read_bytes()
    emit('PYTHON_ENTRY', source_base=BASE, source_sha256=hashlib.sha256(raw).hexdigest(),
         cwd_bytes=len(os.fsencode(os.getcwd())), script_path_bytes=len(os.fsencode(source)),
         kernel=os.uname().release[:100],
         token_slot_present='PROOF6_D04_STATUS_TOKEN' in os.environ,
         argv_mode_valid=len(sys.argv) == 2 and sys.argv[1] in
                         ('serve-setup', 'qualify-setup', 'cleanup-setup'))

    def trace(frame, event, arg):
        global last
        if frame.f_code.co_filename != source:
            return None
        name = frame.f_code.co_name
        if name not in FUNCTIONS:
            return trace
        stage = 'SOURCE_L%04d' % frame.f_lineno
        if event == 'line':
            last = stage
            if stage not in seen:
                seen.add(stage)
                extra = {'function': name}
                local = frame.f_locals
                if name == 'custody_values' and 'allowed' in local:
                    unexpected = set(local['initial_env']) - local['allowed']
                    extra.update(unexpected_environment_key_count=len(unexpected),
                                 known_unexpected_keys=sorted(unexpected & KNOWN_EXTRA_KEYS),
                                 token_slot_present='PROOF6_D04_STATUS_TOKEN' in local['initial_env'])
                if name == '_worker_log':
                    if type(local.get('pid')) is int:
                        extra['ancestor_pid'] = local['pid']
                    if 'exe' in local:
                        extra['ancestor_is_worker'] = local['exe'].name == 'Runner.Worker'
                    if 'logs' in local:
                        extra['matching_diagnostic_fd_count'] = len(local['logs'])
                if name == 'masked_worker_record' and 'prefix' in local:
                    extra['bounded_header_bytes'] = len(local['prefix'])
                    header = local['prefix']
                    extra['header_versions'] = [x.decode('ascii') for x in re.findall(
                        rb' INFO Worker\] Version: ([0-9.]{1,30})\r?\n', header)][:3]
                    extra['header_commits'] = [x.decode('ascii') for x in re.findall(
                        rb' INFO Worker\] Commit: ([0-9a-f]{40})\r?\n', header)][:3]
                if name == '_permission_evidence' and 'permissions' in local:
                    permissions = local['permissions']
                    extra['effective_permissions_exact'] = permissions == {'Metadata': 'read', 'Statuses': 'write'}
                if name == '_serve' and 'root' in local:
                    extra['socket_path_bytes'] = len(os.fsencode(str(local['root'] / 'events.sock')))
                emit(stage, **extra)
        elif event == 'exception':
            key = (stage, type(arg[1]).__name__)
            if key not in seen:
                seen.add(key)
                extra = {}
                if name == '_permission_evidence' and frame.f_locals.get('key') in {
                        'repository', 'repository_id', 'ref', 'workflow_ref', 'sha',
                        'run_id', 'run_attempt', 'event_name'}:
                    extra['context_field'] = frame.f_locals['key']
                emit('EXCEPTION_AT_' + stage, function=name, **extra, **error_fields(arg[1]))
        return trace

    sys.settrace(trace)


def blocked(error):
    sys.settrace(None)
    emit('UNHANDLED_FAILURE', last_stage=last, **error_fields(error))


if __name__ == '__main__':
    # Failure-independent replay of ONLY fixed structured nonsecret records.
    try:
        run = os.environ['GITHUB_RUN_ID']; sha = os.environ['GITHUB_SHA']
        assert re.fullmatch('[1-9][0-9]{0,19}', run) and re.fullmatch('[0-9a-f]{40}', sha)
        path = Path('/tmp') / ('proof6-d04-signal-' + run + '-1-' + sha) / 'helper.log'
        raw = path.read_bytes()
        assert len(raw) <= 262144
        retained = 0
        for line in raw.splitlines():
            if line.startswith((b'PROOF6_STARTUP_DIAGNOSTIC ', b'PROOF6_STARTUP_SHELL ', b'PROOF6_D04_SIGNAL ')):
                prefix, data = line.split(b' ', 1)
                value = json.loads(data)
                print(prefix.decode('ascii') + ' ' + json.dumps(value, sort_keys=True), flush=True)
                retained += 1
        emit('FAILURE_INDEPENDENT_REPLAY', retained_records=retained)
    except BaseException as error:
        blocked(error)
        sys.exit(1)
