"""Fixed D04 evidence transport. No authority, journal, or credential fallback."""
import datetime
import array
import json
import math
import os
from pathlib import Path
import re
import signal
import select
import socket
import struct
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import d04_capability as capability

REPO = 'flipjam/mc-proof6-synthetic-20260909'
RUNTIME = 'refs/heads/codex/proof6-r3h-s1-startup-diagnostic-20260912-01'
SCHEMA = 'PROOF6_R3H_D04_SIGNAL_V1'
TOKEN_SLOT = 'PROOF6_D04_STATUS_TOKEN'
PERMISSIONS = {'Metadata': 'read', 'Statuses': 'write'}
RUNNER_VERSION = '2.337.0'
RUNNER_COMMIT = '397b032cbf865e9c3ddfab89d533ec19325e1273'
WINDOW = 30
MAX_PACKET = 16384
CONTROL_BYTES = 4096  # Linux SCM_MAX_FD=253 plus credential/control headers.
POLICY = {'acceptance_credit': False, 'actual_writer_cap_seconds': 120, 'actual_writer_token': 'no GITHUB_TOKEN; public fixed GETs; existing App Metadata:read only for fixed caller-permission GET', 'audited_provider_runner': {'commit': '397b032cbf865e9c3ddfab89d533ec19325e1273', 'masking': 'verify version/commit in bounded header BEFORE reading masked startup job payload', 'version': '2.337.0'}, 'canary_evidence': 'a272b335e884e88ddc88155f5bd1691d1a647606', 'canary_run': 34715785446, 'canary_source': '2b7d0fa62e41bc500f6bf2dc5c540910501cabc3', 'context': 'proof6/d04-signal/<run_id>/1/<runtime_sha>', 'effective_permissions': {'Metadata': 'read', 'Statuses': 'write'}, 'end': '30 seconds after READY; fresh actual writer recheck; ordered local END', 'helper_alarm_seconds': 105, 'helper_job': 'd04_writer', 'helper_permissions': {'statuses': 'write'}, 'ipc': 'fixed AF_UNIX SOCK_SEQPACKET; bounded 4096-byte ancillary reception, close all received SCM_RIGHTS, reject all control/truncation; completion enables SO_PASSCRED and requires control-free EOF plus POLLRDHUP, rejecting every trailing packet', 'native_helper_cap_seconds': 120, 'normal_permissions': {'actions': 'read', 'contents': 'read'}, 'preconsumption': 'isolation prerequisite, helper custody/effective permissions, target/context GET, peer handshake, unchanged journal reread', 'preconsumption_remaining_helper_seconds': 50, 'provider_timeout_seconds': 5, 'ready': 'actual writer unshare and all accepted predicates qualified', 'schema': 'PROOF6_R3H_D04_SIGNAL_V1', 'target': 'exact frozen runtime commit', 'verification_limit': 'GET and effective grant do not prove future POST success or live propagation; independent disposition required before freeze; post-consumption failure permanently spends D04; public GET rate limits and time spent confirming CONSUMED can still exhaust the remaining window', 'observer_policy': 'Poll full statuses for exact runtime target/context. Require READY pending, END success, exact binding/PID/target_url and creator github-actions[bot] id 41898282; retain REST timestamps/IDs and in_progress observations. Final credit requires exactly the two HTTP-201 status IDs in trusted helper receipts, matching actual writer READY/END and the intervening ordinary PATCH. Extra/forged/ambiguous statuses lose credit; shared bot identity alone does not authenticate the origin job.', 'ipc_namespace_limit': 'Pathname AF_UNIX; connected before unshare. Offline custody/IPC models do not attest a hosted cross-netns run; local WSL CLONE_NEWNET denied errno 13.', 'setup': {'job': 'signal_setup', 'helper_entry': 'serve-setup', 'peer_entry': 'qualify-setup', 'cleanup_entry': 'cleanup-setup', 'permissions': {'Metadata': 'read', 'Statuses': 'write'}, 'same_audit_custody_ipc': True, 'status_posts': 0, 'actual_isolation': False, 'authority_or_journal_mutation': False, 'D04_consumption': False, 'acceptance_credit': False, 'required_before_freeze': 'S1 requires isolation prerequisite, exact bound signal setup result with both processes reaped, and existing App authentication'}}


def require(value):
    if not value:
        raise ValueError('D04_SIGNAL_INVALID')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(len(raw) <= MAX_PACKET)
    return json.loads(raw.decode('ascii'), object_pairs_hook=unique)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def binding():
    require(os.environ['GITHUB_REPOSITORY'] == REPO
            and os.environ['GITHUB_REPOSITORY_ID'] == '1363510385'
            and os.environ['GITHUB_REF'] == RUNTIME
            and os.environ['GITHUB_WORKFLOW_REF'] == REPO + '/.github/workflows/proof6-writer.yml@' + RUNTIME
            and os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
            and os.environ['GITHUB_RUN_ATTEMPT'] == '1')
    run = os.environ['GITHUB_RUN_ID']; sha = os.environ['GITHUB_SHA']
    require(re.fullmatch('[1-9][0-9]{0,19}', run) and re.fullmatch('[0-9a-f]{40}', sha))
    return {'run_id': int(run), 'attempt': 1, 'runtime_sha': sha, 'target_sha': sha,
            'context': 'proof6/d04-signal/' + run + '/1/' + sha}


def directory(b):
    return Path('/tmp') / ('proof6-d04-signal-' + str(b['run_id']) + '-1-' + b['runtime_sha'])


def receipt(kind, **data):
    print('PROOF6_D04_SIGNAL ' + json.dumps(dict(data, schema=SCHEMA, kind=kind, utc=utc()),
                                         sort_keys=True, allow_nan=False), flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('D04_SIGNAL_REDIRECT')


def status_request(token, b, event=None):
    # The only two API shapes are fixed to the frozen runtime commit. No input
    # selects endpoint, method, text, context, repository, ref or force value.
    payload = None if event is None else {
        'context': b['context'], 'state': 'pending' if event['phase'] == 'READY' else 'success',
        'description': f"{event['phase']} r={b['run_id']} a=1 sha={b['runtime_sha']} p={event['pid']}",
        'target_url': f"https://github.com/{REPO}/actions/runs/{b['run_id']}"}
    path = (f"commits/{b['target_sha']}/statuses?per_page=100" if payload is None
            else f"statuses/{b['target_sha']}")
    req = urllib.request.Request('https://api.github.com/repos/' + REPO + '/' + path,
        data=None if payload is None else canonical(payload), headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'proof6-fixed-d04-signal'})
    started = utc()
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(req, timeout=5) as response:
        require(response.status == (200 if payload is None else 201))
        raw = response.read(1_000_001); require(len(raw) <= 1_000_000)
        value = json.loads(raw, object_pairs_hook=unique)
        if payload is None:
            # Fail closed on pagination: no uninspected stale context can hide.
            require(isinstance(value, list) and 'next' not in response.headers.get('Link', ''))
            require(all(item['context'] != b['context'] for item in value))
        else:
            require(all(value[k] == v for k, v in payload.items())
                    and value['creator']['login'] == 'github-actions[bot]' and value['creator']['id'] == 41898282)
        result = {'started_at': started, 'completed_at': utc(), 'http_status': response.status,
                  'date': response.headers.get('Date'),
                  'request_id': response.headers.get('X-GitHub-Request-Id'), 'payload': payload}
        if payload is not None:
            require(type(value['id']) is int and value['id'] > 0)
            result.update(status_id=value['id'], created_at=value['created_at'],
                          creator={'login': 'github-actions[bot]', 'id': 41898282})
        return result


def peer(sock):
    return struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))


def packet(sock, value):
    raw = canonical(value); require(len(raw) <= MAX_PACKET)
    require(sock.send(raw) == len(raw))


def receive_boundary(sock):
    raw, ancillary, flags, _ = sock.recvmsg(MAX_PACKET + 1, CONTROL_BYTES)
    # recvmsg installs SCM_RIGHTS descriptors even when validation will fail.
    # Close every complete received descriptor BEFORE any parsing/flag rejection.
    for level, kind, data in ancillary:
        if level == 1 and kind == 1:  # Fixed Linux SOL_SOCKET / SCM_RIGHTS.
            fds = array.array('i')
            fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass  # Still reject the entire control-bearing packet.
    require(not ancillary and flags & ~getattr(socket, 'MSG_EOR', 0) == 0)
    return raw


def receive(sock):
    raw = receive_boundary(sock)
    require(raw)
    value = decode(raw)
    require(raw == canonical(value))
    return value


def peer_shutdown(sock):
    # Linux supplies SCM_CREDENTIALS for EVERY queued packet when SO_PASSCRED
    # is enabled, including a zero-length packet queued before this call.
    # Transport EOF has no packet/control message. Thus receive_boundary
    # rejects all trailing records, even empty records followed by close.
    # This option is enabled only after the fixed protocol has completed.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    sock.settimeout(5)
    require(receive_boundary(sock) == b'')
    poller = select.poll()
    poller.register(sock, select.POLLRDHUP | select.POLLHUP | select.POLLERR)
    events = poller.poll(0)
    require(len(events) == 1 and events[0][1] & select.POLLRDHUP
            and not events[0][1] & (select.POLLERR | select.POLLNVAL))


PUBLIC_ENV = {'GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_REF', 'GITHUB_WORKFLOW_REF',
    'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_EVENT_NAME'}
SYSTEM_ENV = {'PATH', 'LANG', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'TERM', 'MAIL',
    'SUDO_COMMAND', 'SUDO_USER', 'SUDO_UID', 'SUDO_GID', 'PWD', 'SHLVL', '_'}
WRITER_ENV = {'GITHUB_JOB', 'GITHUB_RUN_NUMBER', 'GITHUB_ACTOR', 'GITHUB_ACTOR_ID',
    'GITHUB_TRIGGERING_ACTOR', 'GITHUB_EVENT_PATH', 'RUNNER_ENVIRONMENT', 'RUNNER_OS',
    'RUNNER_ARCH', 'ImageOS', 'ImageVersion', 'PROOF6_APP_TOKEN', 'PROOF6_APP_INSTALLATION_ID',
    'PROOF6_APP_SLUG', 'PROOF6_FROZEN_MANIFEST', 'PROOF6_D04_SETUP_QUALIFICATION'}


def custody_values(helper, initial_env, argv, descriptors, setup=False):
    allowed = PUBLIC_ENV | SYSTEM_ENV | ({TOKEN_SLOT} if helper else (set() if setup else WRITER_ENV))
    require(set(initial_env) <= allowed)
    require(TOKEN_SLOT in initial_env if helper else TOKEN_SLOT not in initial_env)
    expected = [b'/usr/bin/python3', b'-I', b'-B', b'proofs/proof6/d04_signal.py', b'serve'] if helper else [
                b'/usr/bin/python3', b'-B', b'proofs/proof6/actions_runtime.py']
    if setup:
        expected = [b'/usr/bin/python3', b'-I', b'-B', b'proofs/proof6/d04_signal.py',
                    b'serve-setup' if helper else b'qualify-setup']
    require(argv == expected and set(descriptors) == {0, 1, 2})
    require(descriptors[0] == ('/dev/null', os.O_RDONLY))
    for fd in (1, 2):
        target, mode = descriptors[fd]
        require(mode == os.O_WRONLY)
        require(target == str(directory(binding()) / 'helper.log') if helper
                else re.fullmatch(r'pipe:\[[0-9]+\]', target) is not None)
    return {'role': 'helper' if helper else 'actual_writer', 'environment_keys': sorted(initial_env),
            'argv_exact': True, 'descriptors_exact': True, 'acceptance_credit': False}


def custody(helper, setup=False):
    import fcntl
    # Inspect only this process. Never read the opposite process's environment,
    # memory or FDs. Initial kernel environment catches pre-pop exposure too.
    raw = Path('/proc/self/environ').read_bytes()
    require(len(raw) <= 262144)
    initial = unique(item.split(b'=', 1) for item in raw.rstrip(b'\0').split(b'\0'))
    initial = {k.decode('ascii'): v for k, v in initial.items()}
    descriptors = {}
    for entry in Path('/proc/self/fd').iterdir():
        try:
            target = os.readlink(entry)
            mode = fcntl.fcntl(int(entry.name), fcntl.F_GETFL) & os.O_ACCMODE
        except OSError:
            continue  # The enumeration's own already-closed descriptor.
        descriptors[int(entry.name)] = (target, mode)
    result = custody_values(helper, initial, Path('/proc/self/cmdline').read_bytes().split(b'\0')[:-1], descriptors, setup)
    receipt('CUSTODY', role=result['role'], argv_exact=True, descriptors_exact=True, acceptance_credit=False)
    return result


def event_valid(event, b, pid, phase, ready=None, now=None):
    require(type(event) is dict and set(event) == {
        'schema', 'binding', 'pid', 'phase', 'monotonic', 'utc', 'observation'})
    require(event['schema'] == SCHEMA and canonical(event['binding']) == canonical(b) and type(event['pid']) is int
            and event['pid'] == pid and event['phase'] == phase)
    stamp = event['monotonic']; now = time.monotonic() if now is None else now
    require(type(stamp) in (int, float) and math.isfinite(stamp) and 0 <= now - stamp <= 5)
    require(type(event['utc']) is str and len(event['utc']) <= 40)
    parsed = datetime.datetime.fromisoformat(event['utc'])
    require(parsed.utcoffset() == datetime.timedelta(0))
    record = event['observation']; capability.validate_record(record)
    require(record['qualified'] is True and record['context']['pid'] == pid)
    if phase == 'END':
        require(ready is not None and stamp - ready['monotonic'] >= WINDOW
                and record['netns_after'] == ready['observation']['netns_after'])
    else:
        require(phase == 'READY' and ready is None)


def hello_valid(value, b):
    require(type(value) is dict and set(value) == {
        'schema', 'binding', 'phase', 'pid', 'permissions', 'provider_preflight', 'deadline'})
    require(value['schema'] == SCHEMA and canonical(value['binding']) == canonical(b)
            and value['phase'] == 'QUALIFIED' and value['permissions'] == PERMISSIONS
            and type(value['pid']) is int and value['pid'] > 1)
    preflight = value['provider_preflight']
    require(type(preflight) is dict and set(preflight) == {
        'started_at', 'completed_at', 'http_status', 'date', 'request_id', 'payload'})
    require(type(preflight['http_status']) is int and preflight['http_status'] == 200
            and preflight['payload'] is None)
    for key in ('started_at', 'completed_at'):
        require(type(preflight[key]) is str and len(preflight[key]) <= 40
                and datetime.datetime.fromisoformat(preflight[key]).utcoffset() == datetime.timedelta(0))
    for key in ('date', 'request_id'):
        require(preflight[key] is None or (type(preflight[key]) is str and len(preflight[key]) <= 128
                and all(32 <= ord(c) < 127 for c in preflight[key])))


class Client:
    """Writer side has no token argument, token read, API, or helper inspection."""
    def __init__(self):
        self.binding = binding()
        custody(False)
        require(TOKEN_SLOT not in os.environ and 'GH_TOKEN' not in os.environ
                and 'PROOF6_D03_JOB_TOKEN' not in os.environ)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.socket.settimeout(8)
        self.socket.connect(str(directory(self.binding) / 'events.sock'))
        value = receive(self.socket)
        hello_valid(value, self.binding)
        helper_pid, uid, _ = peer(self.socket)
        require(helper_pid == value['pid'] and uid == 0 and helper_pid != os.getpid())
        self.deadline = value['deadline']
        self.qualify()
        self.ready = None
        self.ended = False
        receipt('WRITER_SIGNAL_READY', binding=self.binding, helper_pid=helper_pid,
                producer_pid=os.getpid(), acceptance_credit=False)

    def qualify(self):
        require(type(self.deadline) in (int, float) and math.isfinite(self.deadline)
                and self.deadline - time.monotonic() >= 50)
        # No pre-READY writer packet: detect EOF/error/unsolicited payload
        # without sending a command or admitting any authority work.
        previous = self.socket.gettimeout()
        self.socket.setblocking(False)
        try:
            try:
                self.socket.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            except BlockingIOError:
                return
        finally:
            self.socket.settimeout(previous)
        raise ValueError('D04_HELPER_NOT_WAITING')

    def emit(self, item):
        if item['phase'] not in ('READY', 'END'):
            return
        event = dict(schema=SCHEMA, binding=self.binding, pid=os.getpid(), phase=item['phase'],
                     monotonic=time.monotonic(), utc=utc(), observation=item['observation'])
        require(not self.ended and (item['phase'] == 'READY') == (self.ready is None))
        event_valid(event, self.binding, os.getpid(), item['phase'], self.ready)
        if item['phase'] == 'END':
            ready_ack = receive(self.socket)
            require(canonical(ready_ack) == canonical({'phase': 'READY', 'binding': self.binding, 'posted': True}))
        packet(self.socket, event)
        if item['phase'] == 'READY':
            # Keep the existing actual 30-second timer independent of provider
            # latency. READY acknowledgment is checked at END, never awaited
            # before starting or during the actual isolation interval.
            self.ready = event
        else:
            ack = receive(self.socket)
            require(canonical(ack) == canonical({'phase': 'END', 'binding': self.binding, 'posted': True}))
            self.ended = True

    def close(self):
        if self.socket.fileno() < 0:
            return
        try:
            if self.ended:
                self.socket.shutdown(socket.SHUT_WR)
                peer_shutdown(self.socket)
        finally:
            self.socket.close()


def masked_worker_record(stream):
    # Do not read the job payload until its actual provider build matches the
    # audited secret-mask-before-Trace.Info implementation. Unknown builds block.
    prefix = b''
    for _ in range(256):
        line = stream.readline(2049)
        require(line and len(line) <= 2048 and line.endswith(b'\n'))
        prefix += line
        if re.fullmatch(rb'\[[^\r\n]+ INFO Worker\] Job message:\r?\n', line):
            text = prefix.decode('ascii')
            require(re.findall(r'^\[[^\r\n]+ INFO Worker\] Version: ([0-9.]+)\r?$',text,re.M) == [RUNNER_VERSION])
            require(re.findall(r'^\[[^\r\n]+ INFO Worker\] Commit: ([0-9a-f]{40})\r?$',text,re.M) == [RUNNER_COMMIT])
            raw = prefix + stream.read(2_000_001 - len(prefix))
            require(len(raw) <= 2_000_000)
            return raw
    raise ValueError('D04_AUDITED_WORKER_HEADER_UNAVAILABLE')


def _worker_log():
    # Only our actual Runner.Worker ancestor and its already-open diagnostic.
    # No caller path, environment override, retained Actions log or API token.
    pid = os.getppid()
    for _ in range(32):
        proc = Path('/proc') / str(pid)
        exe = (proc / 'exe').resolve(strict=True)
        if exe.name == 'Runner.Worker':
            expected = exe.parent.parent / '_diag'
            logs = []
            for fd in (proc / 'fd').iterdir():
                try:
                    target = fd.resolve(strict=True)
                except OSError:
                    continue
                if target.parent == expected and re.fullmatch(r'Worker_[A-Za-z0-9_.-]+\.log', target.name):
                    logs.append(fd)
            require(len(logs) == 1)
            with logs[0].open('rb') as stream:
                return masked_worker_record(stream)
        parents = re.findall(r'^PPid:\s+(\d+)$', (proc / 'status').read_text(), re.M)
        require(len(parents) == 1 and int(parents[0]) > 1)
        pid = int(parents[0])
    raise ValueError('D03_CURRENT_WORKER_UNAVAILABLE')


def _permission_evidence(raw, binding, setup=False):
    # Runner initializes its secret masker BEFORE recording this startup message.
    # Never retain, hash, print or return the whole diagnostic/message. Only the
    # non-secret allowlist below enters protected evidence; no token inspection.
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result)
            result[k] = v
        return result
    text = raw.decode('utf-8')
    starts = list(re.finditer(r'^\[[^\r\n]+ INFO Worker\] Job message:\r?\n', text, re.M))
    require(len(starts) == 1)
    message, _ = json.JSONDecoder(object_pairs_hook=unique).raw_decode(text[starts[0].end():].lstrip())
    variables = message['variables']
    permissions = json.loads(variables['system.github.token.permissions']['value'], object_pairs_hook=unique)
    require(permissions == PERMISSIONS)
    github = message['contextData']['github']
    require(github['t'] == 2)
    context = unique((entry['k'], entry['v']) for entry in github['d'])
    expected = {'repository': REPO, 'repository_id': '1363510385', 'ref': RUNTIME,
                'workflow_ref': REPO + '/.github/workflows/proof6-writer.yml@' + RUNTIME, 'sha': binding['runtime_sha'],
                'run_id': str(binding['run_id']), 'run_attempt': str(binding['attempt']),
                'event_name': 'workflow_dispatch'}
    for key, value in expected.items():
        require(type(context[key]) is str and context[key] == value)
    job_name = 'signal_setup' if setup else 'd04_writer'
    require(variables['system.github.job']['value'] == job_name)
    job = message['jobId']
    require(type(job) is str and re.fullmatch('[0-9a-f-]{36}', job))
    versions = re.findall(r'^\[[^\r\n]+ INFO Worker\] Version: ([0-9.]+)\r?$', text, re.M)
    commits = re.findall(r'^\[[^\r\n]+ INFO Worker\] Commit: ([0-9a-f]{40})\r?$', text, re.M)
    require(versions == [RUNNER_VERSION] and commits == [RUNNER_COMMIT])
    return dict(source='github.token/current-worker-job-message/v1', permissions=permissions, job=job_name, worker_job_id=job,
                runner_version=versions[0], runner_commit=commits[0], context=expected,
                binding=binding)


def serve():
    _serve(False)


def serve_setup():
    _serve(True)


def _serve(setup):
    # This entry is started in a separate credential-scoped workflow step BEFORE
    # the App-token action. It never imports writer/journal/admission or reads
    # the writer's environment or credential stores. Its sole ancestor inspection
    # is the fixed provider-masked Worker startup diagnostic for permissions.
    b = binding()
    custody(True, setup)
    require(not any(k.startswith('PROOF6_APP') or k in ('GH_TOKEN', 'PROOF6_D03_JOB_TOKEN',
                       'PROOF6_FROZEN_MANIFEST') for k in os.environ))
    token = os.environ.pop(TOKEN_SLOT)
    require(token and token not in '\0'.join(sys.argv))
    permissions = _permission_evidence(_worker_log(), b, setup) if setup else _permission_evidence(_worker_log(), b)
    root = directory(b)
    require(root.is_dir() and root.stat().st_uid == 0 and root.stat().st_mode & 0o077 == 0)
    # Exact startup identity/effective permissions are read before the workflow
    # proceeds to create the App installation token. The provider masks secrets
    # before writing its startup diagnostic; no raw diagnostic is retained.
    # Setup has no provider request, event loop or App/authority import.
    # Discard its token immediately after auditing the exact effective grant.
    preflight = None if setup else status_request(token, b)
    if setup:
        token = None
    def deadline(*_):
        raise TimeoutError('D04_SIGNAL_DEADLINE')
    signal.signal(signal.SIGALRM, deadline)
    signal.signal(signal.SIGTERM, deadline)
    expires = time.monotonic() + 105
    signal.alarm(105)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
        server.bind(str(root / 'events.sock'))
        server.listen(1); server.settimeout(90)
        marker = {'schema': SCHEMA, 'pid': os.getpid(), 'binding': b,
                  'permissions': PERMISSIONS, 'provider_preflight': preflight,
                  'deadline': expires}
        (root / 'started.json').write_bytes(canonical(marker))
        receipt('HELPER_STARTED', **marker, permission_evidence=permissions, acceptance_credit=False)
        conn, _ = server.accept()
        with conn:
            pid, uid, _ = peer(conn)
            require(uid == 0 and pid != os.getpid())
            expected = [b'/usr/bin/python3', b'-B', b'proofs/proof6/actions_runtime.py']
            if setup:
                expected = [b'/usr/bin/python3', b'-I', b'-B', b'proofs/proof6/d04_signal.py', b'qualify-setup']
            require(Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[:-1] == expected)
            if setup:
                conn.settimeout(8)
                packet(conn, dict(marker, phase='SETUP_QUALIFIED'))
                require(canonical(receive(conn)) == canonical({'schema': SCHEMA, 'binding': b, 'pid': pid, 'phase': 'SETUP_FINISH'}))
                packet(conn, {'schema': SCHEMA, 'binding': b, 'phase': 'SETUP_FINISHED'})
                peer_shutdown(conn)
                result = {'schema': SCHEMA, 'binding': b, 'phase': 'SETUP_SIGNAL_QUALIFIED',
                    'permissions': PERMISSIONS, 'runner_version': RUNNER_VERSION, 'runner_commit': RUNNER_COMMIT,
                    'helper_pid': os.getpid(), 'producer_pid': pid, 'custody': True,
                    'status_posts': 0, 'acceptance_credit': False}
                (root / 'setup-result.json').write_bytes(canonical(result))
                signal.alarm(0)
                receipt('SETUP_HELPER_COMPLETED', **result)
                return
            packet(conn, dict(marker, phase='QUALIFIED'))
            conn.settimeout(45)
            ready = None
            for phase in ('READY', 'END'):
                event = receive(conn)
                event_valid(event, b, pid, phase, ready)
                require(os.readlink(f'/proc/{pid}/ns/net') == event['observation']['netns_after'])
                result = status_request(token, b, event)
                receipt('STATUS_POST', binding=b, event=event, provider=result, acceptance_credit=False)
                packet(conn, {'phase': phase, 'binding': b, 'posted': True})
                if phase == 'READY':
                    ready = event
            peer_shutdown(conn)
    signal.alarm(0)
    receipt('HELPER_COMPLETED', binding=b, acceptance_credit=False)


def cleanup(setup=False):
    b = binding(); root = directory(b)
    require(root.is_dir() and root.stat().st_uid == 0)
    # Always execute after the actual writer. A live helper now represents a
    # failed/incomplete sequence and must be terminated, never credited.
    complete = root / 'reaped.exit'
    settle = time.monotonic() + 2
    while not complete.exists() and time.monotonic() < settle:
        time.sleep(0.05)
    interrupted = not complete.exists()
    if interrupted:
        native = int((root / 'native.pid').read_text())
        proc = Path('/proc') / str(native)
        if proc.exists():
            require((proc / 'cmdline').read_bytes().split(b'\0')[:-1] == [
                b'/usr/bin/timeout', b'--signal=KILL', b'120s', b'/usr/bin/python3',
                b'-I', b'-B', b'proofs/proof6/d04_signal.py', b'serve-setup' if setup else b'serve'])
            require(os.getpgid(native) == native)
            os.kill(native, signal.SIGTERM)  # timeout forwards to and reaps child.
    end = time.monotonic() + 8
    while not complete.exists() and time.monotonic() < end:
        time.sleep(0.1)
    require(complete.exists())
    code = int(complete.read_text())
    if (root / 'started.json').exists():
        marker = decode((root / 'started.json').read_bytes())
        require(marker['binding'] == b and not Path('/proc', str(marker['pid'])).exists())
    receipt('HELPER_REAPED', binding=b, exit_code=code, interrupted=interrupted, acceptance_credit=False)
    # Fixed bounded nonsecret log; no arbitrary file or credential-store read.
    raw = (root / 'helper.log').read_bytes()
    require(len(raw) <= 262144)
    print(raw.decode('utf-8'), end='', flush=True)
    require(code == 0 and not interrupted)
    if setup:
        value = decode((root / 'setup-result.json').read_bytes())
        value.update(helper_reaped=True, producer_reaped=True)
        value = setup_qualification(canonical(value))
        require(value['helper_pid'] == marker['pid'] and not Path('/proc', str(value['producer_pid'])).exists())
        print('PROOF6_SIGNAL_SETUP_OUTPUT ' + canonical(value).decode(), flush=True)


def qualify_setup():
    b = binding()
    custody(False, True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(8)
        conn.connect(str(directory(b) / 'events.sock'))
        hello = receive(conn)
        require(type(hello) is dict and set(hello) == {
            'schema', 'binding', 'phase', 'pid', 'permissions', 'provider_preflight', 'deadline'})
        require(hello['schema'] == SCHEMA and canonical(hello['binding']) == canonical(b) and hello['phase'] == 'SETUP_QUALIFIED'
                and hello['permissions'] == PERMISSIONS and hello['provider_preflight'] is None)
        pid, uid, _ = peer(conn)
        require(type(hello['pid']) is int and hello['pid'] == pid and uid == 0 and pid != os.getpid())
        require(type(hello['deadline']) in (int, float) and math.isfinite(hello['deadline'])
                and hello['deadline'] - time.monotonic() >= 50)
        packet(conn, {'schema': SCHEMA, 'binding': b, 'phase': 'SETUP_FINISH', 'pid': os.getpid()})
        require(canonical(receive(conn)) == canonical({'schema': SCHEMA, 'binding': b, 'phase': 'SETUP_FINISHED'}))
        conn.shutdown(socket.SHUT_WR)
        peer_shutdown(conn)
    receipt('SETUP_PEER_COMPLETED', binding=b, producer_pid=os.getpid(), acceptance_credit=False)


def setup_qualification(raw):
    if isinstance(raw, str):
        raw = raw.encode('ascii')
    value = decode(raw)
    expected = {'schema': SCHEMA, 'binding': binding(), 'phase': 'SETUP_SIGNAL_QUALIFIED',
        'permissions': PERMISSIONS, 'runner_version': RUNNER_VERSION, 'runner_commit': RUNNER_COMMIT,
        'custody': True, 'status_posts': 0, 'acceptance_credit': False,
        'helper_reaped': True, 'producer_reaped': True}
    require(type(value) is dict and set(value) == set(expected) | {'helper_pid', 'producer_pid'})
    require(canonical({k:value[k] for k in expected}) == canonical(expected))
    require(all(type(value[k]) is int and value[k] > 1 for k in ('helper_pid', 'producer_pid'))
            and value['helper_pid'] != value['producer_pid'])
    return value


if __name__ == '__main__':
    import d04_startup_diagnostic as diagnostic
    diagnostic.install(__file__)
    try:
        require(len(sys.argv) == 2 and sys.argv[1] in (
            'serve-setup', 'qualify-setup', 'cleanup-setup'))
        {'serve': serve, 'cleanup': cleanup, 'serve-setup': serve_setup,
         'qualify-setup': qualify_setup, 'cleanup-setup': lambda: cleanup(True)}[sys.argv[1]]()
    except BaseException as error:
        diagnostic.blocked(error)
        receipt('BLOCKED', exception=type(error).__name__, acceptance_credit=False)
        sys.exit(1)
