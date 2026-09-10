"""Separate read-only R2 reconciliation. Never resubmits a mutation."""
import json
import re
import sys
import urllib.request

URL = 'https://api.github.com/repos/flipjam/mc-proof6-synthetic-20260909/git/ref/heads/proof6-authority'


def disposition(old_sha, candidate_sha, remote_sha):
    for sha in (old_sha, candidate_sha, remote_sha):
        if type(sha) is not str or re.fullmatch('[0-9a-f]{40}', sha) is None:
            raise ValueError('INVALID_SHA')
    if old_sha == candidate_sha:
        raise ValueError('INVALID_CANDIDATE')
    result = ('COMMITTED' if remote_sha == candidate_sha else
              'NOT_COMMITTED' if remote_sha == old_sha else 'INCONSISTENT/BLOCKED')
    return {'result': result, 'old_sha': old_sha, 'candidate_commit': candidate_sha,
            'remote_sha': remote_sha, 'read_only': True}


def reconcile(old_sha, candidate_sha):
    # Validate before networking; inputs are evidence identities, not write targets.
    disposition(old_sha, candidate_sha, old_sha)
    request = urllib.request.Request(URL, headers={'User-Agent': 'proof6-reconcile'})
    with urllib.request.urlopen(request, timeout=30) as response:
        ref = json.load(response)
    if ref['ref'] != 'refs/heads/proof6-authority':
        raise ValueError('WRONG_REF')
    return disposition(old_sha, candidate_sha, ref['object']['sha'])


if __name__ == '__main__':
    try:
        result = reconcile(*sys.argv[1:])
    except Exception:
        result = {'result': 'INCONSISTENT/BLOCKED', 'read_only': True}
    print(json.dumps(result, sort_keys=True))
