"""Fixed D04 process-local unshare and routing qualification. No writer imports."""
import ctypes
import errno
import json
import math
import os
import re
import socket
import sys
import time

SCHEMA = 'PROOF6_R3G_D04_CAPABILITY_V1'
CLONE_NEWNET = 0x40000000
RUNNER_KEYS = ('RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion')
POLICY = {
    'schema': SCHEMA, 'primitive': 'libc.unshare(CLONE_NEWNET)',
    'netns_change_required': True, 'interfaces': ['lo'],
    'ipv4': 'successful read: empty bytes or exact header only; reject malformed content and every data route',
    'ipv6': 'successful strict 10-field parse; only lo, zero next-hop, no gateway; source ::/0 or ::1/128; destination ::1/128, ff00::/8, or reject-flagged ::/0',
    'target': 'api.github.com', 'port': 443, 'connect_timeout_seconds': 1,
    'connect_failure': 'gaierror EAI_AGAIN/EAI_NONAME/EAI_FAIL; timeout; network unreachable/down, host unreachable/down, refused; all other errors fail',
    'read_limit_bytes': 65536, 'route_limit': 256,
    'prerequisite_native_seconds': 20, 'actual_window_seconds': 30,
    'prerequisite_supervisor': 'timeout --foreground --signal=KILL 20s; inherit outer process group; fixed nonforking leaf',
    'actual_native_seconds': 120, 'qualification_is_acceptance': False,
}
STAGES = ('CONTEXT', 'LIBC', 'UNSHARE', 'NETNS', 'INTERFACES',
          'IPV4_ROUTES', 'IPV6_ROUTES', 'CONNECTIVITY')
HEADER = 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT'.split(' ')
# Frozen lexical boundary: ASCII printable fields, space/HT separators, LF or
# CRLF line endings. Bare CR and every other control/non-ASCII character fail.
ROUTE_WHITESPACE = ' \t\r\n'
ZERO = '0' * 32
LOOPBACK = '0' * 31 + '1'


class CapabilityError(ValueError):
    def __init__(self, record):
        super().__init__('D04_CAPABILITY_FAILED')
        self.record = record


def require(value):
    if not value:
        raise ValueError('D04_OBSERVATION_INVALID')


def bounded(value, length=256):
    require(type(value) is str and len(value) <= length
            and all(32 <= ord(c) < 127 for c in value))
    return value


def read(path):
    with open(path, 'rb') as stream:
        raw = stream.read(POLICY['read_limit_bytes'] + 1)
    require(len(raw) <= POLICY['read_limit_bytes'])
    return raw.decode('ascii')


def exception(exc):
    classes = (OSError, ValueError, AttributeError, FileNotFoundError, PermissionError,
               socket.gaierror, TimeoutError, ConnectionRefusedError, UnicodeDecodeError,
               KeyError, TypeError)
    number = getattr(exc, 'errno', None)
    return {'type': type(exc).__name__ if type(exc) in classes else 'UNKNOWN_EXCEPTION',
            'errno': number if type(number) is int and -(2**31) <= number < 2**31 else None}


def netns():
    value = os.readlink('/proc/self/ns/net')
    require(re.fullmatch(r'net:\[[0-9]{1,20}\]', value) is not None)
    return value


def context():
    status = dict(line.split(':', 1) for line in read('/proc/self/status').splitlines() if ':' in line)
    cap = status['CapEff'].strip()
    require(re.fullmatch('[0-9a-f]{16}', cap) is not None)
    seccomp = status['Seccomp'].strip()
    require(seccomp in ('0', '1', '2'))
    lsm = bounded(read('/proc/self/attr/current').strip())
    require(bool(lsm))
    return {'pid': os.getpid(), 'euid': os.geteuid(), 'kernel': bounded(os.uname().release),
            'cap_eff': cap, 'cap_sys_admin': bool(int(cap, 16) & (1 << 21)),
            'seccomp': int(seccomp), 'lsm': lsm, 'netns': netns(),
            'runner': {key: bounded(os.environ.get(key, ''), 128) for key in RUNNER_KEYS}}


def validate_context(value):
    require(type(value) is dict and set(value) == {'pid','euid','kernel','cap_eff',
        'cap_sys_admin','seccomp','lsm','netns','runner'})
    require(type(value['pid']) is int and 0 < value['pid'] < 2**31
            and type(value['euid']) is int and 0 <= value['euid'] < 2**32
            and type(value['seccomp']) is int and value['seccomp'] in (0,1,2)
            and type(value['cap_sys_admin']) is bool
            and re.fullmatch('[0-9a-f]{16}', value['cap_eff']) is not None
            and value['cap_sys_admin'] == bool(int(value['cap_eff'],16) & (1 << 21))
            and re.fullmatch(r'net:\[[0-9]{1,20}\]', value['netns']) is not None)
    bounded(value['kernel']); bounded(value['lsm'])
    require(type(value['runner']) is dict and set(value['runner']) == set(RUNNER_KEYS))
    for v in value['runner'].values():
        bounded(v,128)


def validate_exception(value):
    if value is None:
        return
    require(type(value) is dict and set(value) == {'type','errno'}
            and value['type'] in ('OSError','ValueError','AttributeError','FileNotFoundError',
                'PermissionError','gaierror','TimeoutError','ConnectionRefusedError',
                'UnicodeDecodeError','KeyError','TypeError','UNKNOWN_EXCEPTION')
            and (value['errno'] is None or type(value['errno']) is int and -(2**31) <= value['errno'] < 2**31))


def expected_disconnect(value):
    if value is None:
        return False
    kind, number = value['type'], value['errno']
    return ((kind == 'gaierror' and number in (-2, -3, -4))
            or (kind == 'TimeoutError' and number in (None, 110))
            or (kind in ('OSError', 'ConnectionRefusedError')
                and number in (100, 101, 110, 111, 112, 113)))


def validate_record(value):
    """Fixed leaf stdout boundary: reject additions, malformed values and text."""
    require(type(value) is dict and set(value) == {'schema','stage','qualified',
        'acceptance_credit','context','libc_loaded','unshare','netns_after','interfaces',
        'ipv4','ipv6','connectivity','exception','elapsed_seconds'})
    require(value['schema'] == SCHEMA and type(value['qualified']) is bool
            and value['acceptance_credit'] is False and type(value['libc_loaded']) is bool
            and value['stage'] in ('QUALIFIED','CONNECTIVITY_STILL_LIVE',*(s+'_FAILED' for s in STAGES))
            and type(value['elapsed_seconds']) in (int,float) and math.isfinite(value['elapsed_seconds'])
            and 0 <= value['elapsed_seconds'] <= 120)
    if value['context'] is not None:
        validate_context(value['context'])
    if value['unshare'] is not None:
        u = value['unshare']
        require(type(u) is dict and set(u) == {'return_code','errno','errno_name'}
                and type(u['return_code']) is int and u['return_code'] in (-1,0)
                and type(u['errno']) is int and 0 <= u['errno'] < 2**31
                and u['errno_name'] == errno.errorcode.get(u['errno'],'NONE' if u['errno']==0 else 'UNKNOWN'))
    if value['netns_after'] is not None:
        require(re.fullmatch(r'net:\[[0-9]{1,20}\]',value['netns_after']) is not None)
    if value['interfaces'] is not None:
        require(type(value['interfaces']) is list and len(value['interfaces']) <= 32)
        for name in value['interfaces']:
            bounded(name,16)
    for family, keys in [('ipv4',{'read_success','header_present','header_valid','entry_count','valid','qualified'}),
                         ('ipv6',{'read_success','entry_count','interfaces','valid','qualified'})]:
        route = value[family]
        require(type(route) is dict)
        if set(route) == {'read_success'} and route['read_success'] is False:
            continue
        require(set(route) == keys and route['read_success'] is True
                and type(route['entry_count']) is int and 0 <= route['entry_count'] <= 65536)
        for k in keys - {'entry_count','interfaces'}:
            require(type(route[k]) is bool)
        if family == 'ipv6':
            require(type(route['interfaces']) is list and len(route['interfaces']) <= 256)
            for name in route['interfaces']:
                bounded(name,16)
    if value['connectivity'] is not None:
        c = value['connectivity']
        require(type(c) is dict and set(c) == {'connected','exception'} and type(c['connected']) is bool)
        validate_exception(c['exception'])
    validate_exception(value['exception'])
    if value['qualified']:
        # Both non-null namespaces have passed their syntax checks above.
        # Partial unsuccessful diagnostics may still omit later observations.
        require(value['context'] is not None and value['netns_after'] is not None)
        require(value['stage']=='QUALIFIED' and value['exception'] is None and value['libc_loaded']
                and value['unshare']['return_code']==0
                and value['unshare']['errno']==0
                and value['netns_after'] != value['context']['netns']
                and value['interfaces']==['lo']
                and value['ipv4']['qualified'] and value['ipv4']['valid']
                and value['ipv4']['entry_count']==0
                and value['ipv4']['header_present']==value['ipv4']['header_valid']
                and value['ipv6']['qualified'] and value['ipv6']['valid']
                and set(value['ipv6']['interfaces']) <= {'lo'}
                and value['connectivity']['connected'] is False
                and expected_disconnect(value['connectivity']['exception']))
    return value


def route_lines(raw):
    """Reject unsupported lexical characters before any route tokenization."""
    if type(raw) is not str or any(c not in ROUTE_WHITESPACE and not ' ' <= c <= '~' for c in raw):
        return None
    normalized = raw.replace('\r\n', '\n')
    if '\r' in normalized:
        return None
    lines = normalized.split('\n')
    if lines[-1] == '':
        lines.pop()
    return lines


def route_fields(line):
    return re.split(r'[ \t]+', line.strip(' \t'))


def ipv4(raw):
    result = {'read_success': True, 'header_present': False, 'header_valid': False,
              'entry_count': 0, 'valid': False, 'qualified': False}
    lines = route_lines(raw)
    if lines is None:
        return result
    if raw == '':
        result.update(valid=True, qualified=True)
        return result
    result['header_present'] = bool(lines and route_fields(lines[0])[:1] == ['Iface'])
    result['header_valid'] = bool(lines and route_fields(lines[0]) == HEADER)
    if not result['header_valid'] or len(lines) > 257:
        return result
    result['entry_count'] = len(lines) - 1
    for line in lines[1:]:
        fields = route_fields(line)
        if (len(fields) != 11 or re.fullmatch(r'[A-Za-z0-9_.:-]{1,16}', fields[0]) is None
            or any(re.fullmatch('[0-9A-Fa-f]{8}', fields[i]) is None for i in (1, 2, 7))
            or re.fullmatch('[0-9A-Fa-f]{4}', fields[3]) is None
            or any(re.fullmatch('[0-9]{1,20}', fields[i]) is None for i in (4, 5, 6, 8, 9, 10))):
            return result
    result.update(valid=True, qualified=result['entry_count'] == 0)
    return result


def ipv6(raw):
    lines = route_lines(raw)
    result = {'read_success': True, 'entry_count': 0 if lines is None else len(lines), 'interfaces': [],
              'valid': False, 'qualified': False}
    if lines is None or len(lines) > POLICY['route_limit']:
        return result
    interfaces, safe = set(), True
    for line in lines:
        f = route_fields(line)
        widths = (32, 2, 32, 2, 32, 8, 8, 8, 8)
        if (len(f) != 10 or any(re.fullmatch('[0-9a-fA-F]{'+str(n)+'}', v) is None
                                for v, n in zip(f[:9], widths))
                or re.fullmatch(r'[A-Za-z0-9_.:-]{1,16}', f[9]) is None):
            return result
        f = [v.lower() for v in f[:9]] + [f[9]]
        dest, prefix, src, src_prefix, hop = f[:5]
        prefix, src_prefix, flags = int(prefix, 16), int(src_prefix, 16), int(f[8], 16)
        if prefix > 128 or src_prefix > 128:
            return result
        interfaces.add(f[9])
        allowed_dest = ((dest, prefix) == (LOOPBACK, 128)
                        or (dest, prefix) == ('ff' + '0' * 30, 8)
                        or ((dest, prefix) == (ZERO, 0) and bool(flags & 0x200)))
        safe = safe and f[9] == 'lo' and hop == ZERO and not flags & 0x2 and allowed_dest
        safe = safe and (src, src_prefix) in ((ZERO, 0), (LOOPBACK, 128))
    result.update(valid=True, qualified=bool(safe), interfaces=sorted(interfaces))
    return result


def observe(record, emit=None):
    """Same post-unshare observation at initial qualification and actual END."""
    for stage in STAGES[3:]:
        record['stage'] = stage
        if stage == 'NETNS':
            record['netns_after'] = netns()
            require(record['netns_after'] != record['context']['netns'])
        elif stage == 'INTERFACES':
            names = sorted(name for _, name in socket.if_nameindex())
            require(len(names) <= 32)
            record['interfaces'] = [bounded(name, 16) for name in names]
            require(names == ['lo'])
        elif stage == 'IPV4_ROUTES':
            record['ipv4'] = {'read_success': False}
            record['ipv4'] = ipv4(read('/proc/net/route'))
            require(record['ipv4']['qualified'])
        elif stage == 'IPV6_ROUTES':
            record['ipv6'] = {'read_success': False}
            record['ipv6'] = ipv6(read('/proc/net/ipv6_route'))
            require(record['ipv6']['qualified'])
        else:
            record['connectivity'] = None
            try:
                socket.create_connection(('api.github.com', 443), timeout=1).close()
            except OSError as exc:
                record['connectivity'] = {'connected': False, 'exception': exception(exc)}
                require(expected_disconnect(record['connectivity']['exception']))
            else:
                record['connectivity'] = {'connected': True, 'exception': None}
                require(False)
        record['stage'] = 'CONNECTIVITY_ISOLATED' if stage == 'CONNECTIVITY' else stage + '_OK'
        if emit:
            emit({'phase': record['stage'], 'diagnostic': record})
    return record


def isolate(emit=None):
    """Mutate THIS interpreter's namespace. Never fork or reconnect here."""
    start = time.monotonic()
    record = {'schema': SCHEMA, 'stage': 'CONTEXT', 'qualified': False,
              'acceptance_credit': False, 'context': None, 'libc_loaded': False,
              'unshare': None, 'netns_after': None, 'interfaces': None,
              'ipv4': {'read_success': False}, 'ipv6': {'read_success': False},
              'connectivity': None, 'exception': None, 'elapsed_seconds': 0}
    try:
        record['context'] = context()
        record['stage'] = 'LIBC'
        libc = ctypes.CDLL(None, use_errno=True)
        libc.unshare.argtypes = [ctypes.c_int]
        libc.unshare.restype = ctypes.c_int
        record.update(libc_loaded=True, stage='LIBC_OK')
        if emit:
            emit({'phase': 'LIBC_OK', 'diagnostic': record})
        record['stage'] = 'UNSHARE'
        ctypes.set_errno(0)
        rc = libc.unshare(CLONE_NEWNET)
        number = ctypes.get_errno()
        record['unshare'] = {'return_code': rc, 'errno': number,
                            'errno_name': errno.errorcode.get(number, 'NONE' if number == 0 else 'UNKNOWN')}
        require(rc == 0 and number == 0)
        record['stage'] = 'UNSHARE_OK'
        if emit:
            emit({'phase': 'UNSHARE_OK', 'diagnostic': record})
        observe(record, emit)
        record.update(qualified=True, stage='QUALIFIED')
    except Exception as exc:
        failed(record, exc)
        if emit:
            emit({'phase': record['stage'], 'diagnostic': record})
    record['elapsed_seconds'] = round(time.monotonic() - start, 6)
    return record


def failed(record, exc):
    stage = record['stage']
    record.update(qualified=False, exception=exception(exc),
                  stage='CONNECTIVITY_STILL_LIVE' if stage == 'CONNECTIVITY' and
                    (record.get('connectivity') or {}).get('connected') else stage + '_FAILED')


def recheck(record, emit=None):
    record.update(qualified=False, exception=None)
    try:
        observe(record, emit)
    except Exception as exc:
        failed(record, exc)
        if emit:
            emit({'phase': record['stage'], 'diagnostic': record})
        raise CapabilityError(record) from None
    record.update(qualified=True, stage='QUALIFIED')
    return record


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('{"schema":"PROOF6_R3G_D04_CAPABILITY_V1","stage":"INPUT_REJECTED","qualified":false}')
        sys.exit(1)
    result = isolate()
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False), flush=True)
    sys.exit(0 if result['qualified'] else 1)
