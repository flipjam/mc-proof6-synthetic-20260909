"""Evidence formatting only. Journal owns all admission and safety membership."""
import hashlib
import json


def binding(manifest, run_id, attempt, runtime_sha):
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return {'manifest_sha256': None if manifest is None else hashlib.sha256(raw).hexdigest(),
            'run_id': run_id, 'run_attempt': attempt, 'runtime_sha': runtime_sha}


def blocked(identity):
    return dict(identity, result='BLOCKED', update_attempted=False,
                old_sha=None, candidate_commit=None, new_sha=None,
                remote_outcome='not_attempted', phase='before_writer')
