"""In-process D04 isolation, invoked only by the actual actions_runtime process."""
import ctypes
import os
from pathlib import Path
import socket
import time

MAX_SECONDS = 120
WINDOW_SECONDS = 30
CLONE_NEWNET = 0x40000000


def isolated():
    devices = sorted(name for _, name in socket.if_nameindex())
    if devices != ['lo'] or len(Path('/proc/net/route').read_text().splitlines()) != 1:
        raise ValueError('ACTUAL_PROCESS_ISOLATION_FAILED')
    try:
        socket.create_connection(('api.github.com', 443), timeout=1).close()
    except OSError:
        return {'api_github_connection': 'unavailable', 'devices': devices}
    raise ValueError('ACTUAL_PROCESS_STILL_CONNECTED')


def isolate_runtime(emit):
    # No forked probe/worker: change THIS Python process, the same interpreter
    # that instantiated _Writer and confirmed protected CONSUMED.
    pid = os.getpid()
    # The workflow's native timeout process already supervises this process
    # group with a fixed SIGKILL deadline before this interpreter starts.
    start = time.monotonic()
    emit({'phase': 'START', 'pid': pid, 'maximum_seconds': MAX_SECONDS})
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    if libc.unshare(CLONE_NEWNET) != 0:
        raise ValueError('ACTUAL_PROCESS_UNSHARE_FAILED')
    emit({'phase': 'READY', 'pid': pid, 'observation': isolated()})
    # Reserve time for final verification/exit within the hard 120-second limit.
    # No setns/reconnection fallback; the next hosted job restores service.
    ready = time.monotonic()
    while time.monotonic() - ready < WINDOW_SECONDS:
        time.sleep(max(0, min(1, WINDOW_SECONDS - (time.monotonic() - ready))))
    emit({'phase': 'END', 'pid': pid, 'observation': isolated(),
          'elapsed_seconds': time.monotonic() - start})
    return {'result': 'OUTAGE_COMPLETED', 'update_attempted': False,
            'remote_outcome': 'not_attempted', 'new_sha': None}
