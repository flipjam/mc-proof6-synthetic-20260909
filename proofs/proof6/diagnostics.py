"""Allowlisted stage diagnostics; never stringify secret-bearing errors."""
import urllib.error

STAGE = 'DIA01'
STAGES = {'DIA%02d' % i for i in range(1, 14)} | {'DIA03A', 'DIA03B', 'DIA03C'}


class SafeDiagnosticFailure(Exception):
    """A fixed, non-secret category selected by a protected diagnostic check."""

    def __init__(self, category):
        self.category = category
        super().__init__()


def start(stage):
    global STAGE
    if stage not in STAGES:
        raise ValueError('INVALID_DIAGNOSTIC_STAGE')
    STAGE = stage


def ok(marker):
    start(marker.split('_', 1)[0])
    print(marker, flush=True)


def fail(stage, category):
    start(stage)
    raise SafeDiagnosticFailure(category)


def blocked(error):
    category = 'PRECONDITION_FAILED'
    if isinstance(error, SafeDiagnosticFailure):
        category = error.category
    elif isinstance(error, urllib.error.HTTPError):
        category = 'HTTP_' + str(int(error.code))
    elif isinstance(error, KeyError):
        category = ('MECHANICAL_RULESET_VISIBILITY_MISMATCH'
                    if error.args == ('bypass_actors',) else 'MISSING_REQUIRED_FIELD')
    elif isinstance(error, OSError):
        category = 'OS_OPERATION_FAILED'
    print('PROOF6_SETUP_DIAGNOSTIC_BLOCKED ' + STAGE + ' ' + category, flush=True)
