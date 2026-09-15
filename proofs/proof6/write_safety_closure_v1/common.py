"""Fixed campaign identities and pure encoding. No credentials or transport."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
AREA = Path(__file__).resolve().parent
CAMPAIGN = 'P6-WS-CLOSURE-V1'
REPO = 'flipjam/mc-proof6-synthetic-20260909'
REPO_ID = 1363510385
REF = 'refs/heads/proof6-ws-closure-v1-authority'
JOURNAL_REF = 'refs/heads/proof6-ws-closure-v1-journal'
RUNTIME_REF = 'refs/heads/proof6-ws-closure-v1-runtime'
# Prospective execution identities; historical RUNTIME_REF remains frozen.
EXEC_CONTRACT = 'P6WSV1_EXEC_COMPAT_V1'
EXEC_ADMISSION_SCHEMA = 'P6WSV1_EXEC_COMPAT_ADMISSION_V1'
EXEC_MANIFEST_SCHEMA = 'P6WSV1_EXEC_COMPAT_MANIFEST_V1'
EXEC_SOURCE = 'P6WSV1_EXEC_COMPAT_V1_SOURCE'
EXEC_WORKFLOW = 'P6WSV1_EXEC_COMPAT_V1_WORKFLOW'
EXEC_RUNTIME_REF = 'refs/heads/proof6-ws-closure-v1-exec-compat-v1-runtime'
ACCEPTED_SOURCE = '6313eb40da86a179a48a87a5a28c6bc7217e4b6f'
ACCEPTED_TREE = 'b22f39001d08e2df508fee953d4f96e3f2ce32be'
CONTROL_REF = 'refs/heads/proof6-ws-closure-v1-ordinary-control'
ENVIRONMENT = 'proof6-ws-closure-v1'
CONCURRENCY = 'proof6-ws-closure-v1-writer'
WORKFLOW = '.github/workflows/proof6-write-safety-closure-v1.yml'
APP_ID = 4893415
INSTALLATION = 160504789
PERMISSIONS = {'contents': 'write', 'metadata': 'read'}
BASE = '118e8bbe2994689e819f7ae217e43df7df3f70b9'
BASE_TREE = '478f5a466690cd6c4ab96d94da25ffd052b00603'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition):
    if not condition:
        raise ValueError('P6WSV1_PRECONDITION_FAILED')


def _sha(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{40}', value))
    return value


def hash64(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value))
    return value


def parse(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            _require(key not in obj)
            obj[key] = value
        return obj
    def invalid(value):
        raise ValueError('NONINTEGER_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_float=invalid, parse_constant=invalid)
