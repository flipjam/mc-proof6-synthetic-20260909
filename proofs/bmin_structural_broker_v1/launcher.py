"""Privileged provider entry point. Caller controls only the proposal JSON."""
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import *


def frozen_config():
    raw = os.environ['BMIN_FROZEN_CONFIG'].encode('ascii')
    require(hashlib.sha256(raw).hexdigest() == os.environ['BMIN_CONFIG_SHA256'])
    c = validate_config(parse(raw))
    expected = dict(GITHUB_REPOSITORY=REPOSITORY, GITHUB_REPOSITORY_ID=str(REPOSITORY_ID),
                    GITHUB_REF=RUNTIME, GITHUB_SHA=c['runtime_sha'],
                    GITHUB_WORKFLOW_REF=REPOSITORY + '/' + WORKFLOW + '@' + RUNTIME,
                    GITHUB_WORKFLOW_SHA=c['runtime_sha'], GITHUB_EVENT_NAME='workflow_dispatch',
                    GITHUB_JOB='broker', GITHUB_RUN_ATTEMPT='1', RUNNER_ENVIRONMENT='github-hosted')
    expected['BMIN_APP_ID'] = str(c['app_id'])
    require(all(os.environ.get(key) == value for key, value in expected.items()))
    return c


def main():
    try:
        require(sys.argv[1:] in (['preflight'], ['submit'], ['reconcile']))
        c = frozen_config()
        if sys.argv[1] == 'preflight':
            proposal(os.environ['BMIN_PROPOSAL'].encode('utf-8'))
            print('BMIN_PREFLIGHT_OK')
            return 0
        from broker import Broker
        from provider import GitHub
        broker = Broker(c, GitHub(c))
        result = (broker.submit(os.environ['BMIN_PROPOSAL'].encode('utf-8'))
                  if sys.argv[1] == 'submit' else broker.reconcile())
        print(canonical(result).decode('ascii'), flush=True)
        return 0 if result['result'] in ('INDETERMINATE', 'COMMITTED') else 2
    except Exception:
        # Never print credentials, HTTP bodies, headers, input or tracebacks.
        print('{"result":"BLOCKED"}', flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
