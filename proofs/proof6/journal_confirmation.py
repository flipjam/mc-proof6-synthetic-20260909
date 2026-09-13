"""Fixed nonsecret append diagnostics. No transport, credentials or retry API."""
import copy
import json
import re

SCHEMA = 'PROOF6_R3J_JOURNAL_CONFIRMATION_V1'
STAGES = {'VALIDATION', 'PROTECTION', 'PARENT_CHECK', 'OBJECT_CREATION',
          'CANDIDATE_CHECK', 'PATCH_ENTERED', 'PATCH_RESULT', 'D03_LOSS',
          'REF_OBSERVATION', 'OLD_PARENT_WAIT', 'RECONSTRUCTION', 'FINAL'}
REASONS = {'NONE', 'VALIDATION_FAILED', 'PROTECTION_FAILED', 'PARENT_CHANGED',
           'OBJECT_CREATION_FAILED', 'CANDIDATE_INVALID', 'PATCH_UNCONFIRMED',
           'D03_CONFIRMATION_LOST', 'REF_OBSERVATION_FAILED', 'WAIT_FAILED',
           'PARENT_UNCONFIRMED', 'CONFLICTING_HEAD', 'RECONSTRUCTION_FAILED',
           'RECONSTRUCTION_ENTRY_MISMATCH', 'RECONSTRUCTION_FINAL_MISMATCH',
           'RECONSTRUCTION_PARENT_MISMATCH',
           'RECORD_MISMATCH', 'EXACT_APPEND', 'DIAGNOSTIC_FAILURE'}


class _AppendEvidence:
    def __init__(self, writer, kind, parent, record_digest):
        binding = writer._receipt_binding
        self.writer = writer
        self.failed = False
        self.reason = 'VALIDATION_FAILED'
        self.value = dict(schema=SCHEMA, lifecycle=kind, run_id=binding['run_id'],
            run_attempt=binding['run_attempt'], runtime_sha=binding['runtime_sha'],
            manifest_sha256=writer._manifest_digest, parent=parent, candidate=None,
            record_sha256=record_digest, stage='VALIDATION', patch_entered=False,
            patch_call='UNKNOWN', patch_response='UNKNOWN', http_status=None,
            request_id=None, observed_heads=[], reconstruction_entry_head=None,
            reconstruction_final_head=None, result='IN_PROGRESS', reason='NONE')

    def http_response(self, status, request_id):
        # Called only for this append's exact journal PATCH, before body parsing.
        self.value['patch_response'] = 'HTTP_RESPONSE'
        self.value['http_status'] = status if type(status) is int and 100 <= status <= 599 else None
        self.value['request_id'] = request_id if type(request_id) is str and re.fullmatch(
            '[A-Za-z0-9:-]{1,128}', request_id) else None

    def parsed_response(self):
        self.value['patch_response'] = 'PARSED_RESPONSE'

    def require(self, condition, reason):
        if reason not in REASONS:
            raise ValueError('JOURNAL_DIAGNOSTIC_INVALID')
        if not condition:
            self.reason = reason
            raise ValueError('JOURNAL_CONFIRMATION_BLOCKED')

    def emit(self, stage, reason='NONE', result='IN_PROGRESS'):
        # Validate all output slots. Neither arbitrary caller fields nor response
        # bodies/exception text can enter the record. Emission failure blocks.
        try:
            self.require(not self.failed and stage in STAGES and reason in REASONS,
                         'DIAGNOSTIC_FAILURE')
            v = self.value
            self.require(v['lifecycle'] in ('CONSUMED','PENDING','SEND_ARMED','TERMINAL')
                         and type(v['run_id']) is int and v['run_id'] > 0
                         and type(v['run_attempt']) is int and v['run_attempt'] == 1
                         and result in ('IN_PROGRESS','CONFIRMED','BLOCKED'), 'DIAGNOSTIC_FAILURE')
            for name in ('parent','candidate','runtime_sha','reconstruction_entry_head','reconstruction_final_head'):
                self.require(v[name] is None or type(v[name]) is str and re.fullmatch('[0-9a-f]{40}',v[name]), 'DIAGNOSTIC_FAILURE')
            for name in ('manifest_sha256','record_sha256'):
                self.require(type(v[name]) is str and re.fullmatch('[0-9a-f]{64}',v[name]), 'DIAGNOSTIC_FAILURE')
            self.require(len(v['observed_heads']) <= 3 and all(type(h) is str and
                re.fullmatch('[0-9a-f]{40}',h) for h in v['observed_heads']), 'DIAGNOSTIC_FAILURE')
            v.update(stage=stage, result=result, reason=reason)
            self.writer._journal_confirmation = copy.deepcopy(v)
            print('PROOF6_JOURNAL_APPEND ' + json.dumps(v,sort_keys=True,separators=(',',':')),flush=True)
        except BaseException:
            self.failed = True
            # Even a final-output failure is a blocked invocation. Preserve a
            # fixed snapshot for the outer handler without attempting output again.
            safe = getattr(self.writer, '_journal_confirmation', None)
            safe = copy.deepcopy(safe) if type(safe) is dict else {'schema': SCHEMA}
            safe.update(stage='FINAL', result='BLOCKED', reason='DIAGNOSTIC_FAILURE')
            self.writer._journal_confirmation = safe
            raise

    def at(self, stage, failure_reason):
        self.reason = failure_reason
        self.emit(stage)
