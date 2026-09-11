"""No standalone log/old-SHA resolver. Journal.recover owns safe disposition."""


def reconcile(*args, **kwargs):
    raise ValueError('PROTECTED_JOURNAL_REQUIRED')
