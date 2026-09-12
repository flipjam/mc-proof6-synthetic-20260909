"""In-process D04 isolation, invoked only by the actual actions_runtime process."""
import os
import time

import d04_capability as capability

MAX_SECONDS = 120
WINDOW_SECONDS = 30


def isolate_runtime(emit):
    # No forked probe/worker: change THIS Python process, the same interpreter
    # that instantiated _Writer and confirmed protected CONSUMED.
    pid = os.getpid()
    # The workflow's native timeout process already supervises this process
    # group with a fixed SIGKILL deadline before this interpreter starts.
    start = time.monotonic()
    emit({'phase': 'START', 'pid': pid, 'maximum_seconds': MAX_SECONDS})
    record = capability.isolate(emit)
    if not record['qualified']:
        raise capability.CapabilityError(record)
    emit({'phase': 'READY', 'pid': pid, 'observation': record})
    # Reserve time for final verification/exit within the hard 120-second limit.
    # No setns/reconnection fallback; the next hosted job restores service.
    ready = time.monotonic()
    while time.monotonic() - ready < WINDOW_SECONDS:
        time.sleep(max(0, min(1, WINDOW_SECONDS - (time.monotonic() - ready))))
    capability.recheck(record, emit)
    emit({'phase': 'END', 'pid': pid, 'observation': record,
          'elapsed_seconds': time.monotonic() - start})
    return {'result': 'OUTAGE_COMPLETED', 'update_attempted': False,
            'remote_outcome': 'not_attempted', 'new_sha': None}
