import ast
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch, Mock
import yaml

OUT = Path(__file__).parent
source = (OUT / 'diagnostic.py').read_text()
tree = ast.parse(source)
workflow = yaml.load(Path('D:/Projects/mc-proof6-d04-diagnostic-20260912/.github/workflows/proof6-writer.yml').read_text(), Loader=yaml.BaseLoader)
assert workflow['on'] == {'workflow_dispatch': ''}
assert workflow['permissions'] == {}
job = workflow['jobs']['capability']
assert job['permissions'] == {} and job['runs-on'] == 'ubuntu-24.04'
assert 'environment' not in job and len(job['steps']) == 1
script = job['steps'][0]['run']
assert script.split("<<'D04_PY'\n")[1].split('D04_PY\n')[0] == source
(OUT / 'diagnostic-step.sh').write_bytes(script.encode())
subprocess.run(['C:/Program Files/Git/bin/bash.exe', '-n', str(OUT / 'diagnostic-step.sh')], check=True)

results = []
for scenario in ('success', 'libc_fail', 'symbol_fail', 'unshare_fail', 'interfaces_fail',
                 'routes_fail', 'header_fail', 'connect_live', 'unknown_exception', 'same_netns'):
    scope = {}
    with patch.object(os, 'geteuid', return_value=0, create=True):
        exec(compile(ast.Module(body=tree.body[:-2], type_ignores=[]), '<fixed-diagnostic>', 'exec'), scope)
    libc = Mock()
    libc.unshare.return_value = -1 if scenario == 'unshare_fail' else 0
    if scenario == 'symbol_fail':
        del libc.unshare
    cdll = Mock(return_value=libc)
    if scenario == 'libc_fail':
        cdll.side_effect = OSError(2, 'must never serialize')
    names = Mock(return_value=[(1, 'eth0' if scenario == 'interfaces_fail' else 'lo')])
    if scenario == 'unknown_exception':
        names.side_effect = RuntimeError('must never serialize')
    connection = Mock()
    if scenario != 'connect_live':
        connection.side_effect = OSError(101, 'must never serialize')
    def read(path, limit=65536):
        return {'/proc/self/status': 'CapEff:\t000001ffffffffff\nSeccomp:\t0\n',
                '/proc/self/attr/current': 'unconfined\n',
                '/proc/net/route': ('bad\n' if scenario == 'header_fail' else
                    'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n') +
                    ('eth0 data\n' if scenario == 'routes_fail' else ''),
                '/proc/net/ipv6_route': ''}[path]
    scope['read'] = read
    output = io.StringIO()
    with patch.object(scope['ctypes'], 'CDLL', cdll), patch.object(scope['ctypes'], 'get_errno', return_value=1 if scenario == 'unshare_fail' else 0), \
         patch.object(scope['socket'], 'if_nameindex', names), patch.object(scope['socket'], 'create_connection', connection), \
         patch.object(scope['os'], 'uname', return_value=Mock(release='test-kernel'), create=True), \
         patch.object(scope['os'], 'readlink', side_effect=['net:[1]', 'net:[1]' if scenario == 'same_netns' else 'net:[2]']), \
         contextlib.redirect_stdout(output):
        try:
            exec(compile(ast.Module(body=tree.body[-2:], type_ignores=[]), '<fixed-diagnostic>', 'exec'), scope)
        except SystemExit as exc:
            code = exc.code
    raw = output.getvalue()
    record = json.loads(raw)
    assert len(raw) < 8192 and 'must never serialize' not in raw
    assert code == (0 if scenario == 'success' else 1), (scenario, record)
    if scenario == 'unshare_fail':
        assert record['unshare'] == {'return_code': -1, 'errno': 1, 'errno_name': 'EPERM'}
    if scenario == 'unknown_exception':
        assert record['observation_error']['type'] == 'UNKNOWN_EXCEPTION'
    results.append({'scenario': scenario, 'test': 'PASS', 'stage': record['stage']})
(OUT / 'offline-diagnostic-validation.json').write_text(json.dumps(results, indent=2) + '\n')
print('PASS: YAML scope, exact inline bytes, bash syntax, 10 mocked diagnostic paths; no isolation executed locally.')
