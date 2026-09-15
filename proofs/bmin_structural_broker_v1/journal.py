"""Protected Git ancestry as a durable, bounded, one-operation write-ahead log.

No cache, artifact download, local file, or process lifetime is a recovery oracle.
Missing/rewritten genesis, extra records, siblings and malformed data fail closed.
"""
from core import *

GENESIS = {'schema': 'BMIN_JOURNAL_V1', 'stage': 'GENESIS'}


class Journal:
    def __init__(self, provider, config):
        self.p, self.c = provider, config
        self.head = self.p.ref(JOURNAL)
        cursor = self.head
        backwards = []
        for _ in range(4):
            parents, record = self.p.read_file(cursor, 'journal.json')
            if cursor == config['journal_genesis_sha']:
                require(record == GENESIS)
                break
            require(len(parents) == 1)
            backwards.append((cursor, record))
            cursor = parents[0]
        else:
            raise ValueError('JOURNAL_ANCESTRY')
        self.records = list(reversed(backwards))
        self.validate()

    def validate(self):
        self.auth = self.intent = None
        self.stage = 'GENESIS'
        self.result = None
        if not self.records:
            return
        _, prepared = self.records[0]
        gate.proof1.fields(prepared, 'schema stage proposal authorization authorization_sha256')
        require(prepared['schema'] == 'BMIN_JOURNAL_V1' and prepared['stage'] == 'PREPARED')
        self.intent = proposal(canonical(prepared['proposal']))
        _, history = self.p.read_file(self.c['initial_authority_sha'], 'history.json')
        expected, plan = authorize(self.c, self.intent, self.c['initial_authority_sha'], history)
        require(prepared['authorization'] == expected and prepared['authorization_sha256'] == digest(expected))
        parents, candidate = self.p.read_file(plan['sha'], 'history.json')
        require(parents == [plan['parent']] and candidate == plan['value'])
        self.auth = expected
        self.stage = 'PREPARED'
        for _, record in self.records[1:]:
            gate.proof1.fields(record, 'schema stage authorization_sha256 disposition observed_authority')
            require(record['schema'] == 'BMIN_JOURNAL_V1'
                    and record['authorization_sha256'] == digest(self.auth))
            sha(record['observed_authority'])
            if record['stage'] == 'SEND_ARMED':
                require(self.stage == 'PREPARED' and record['disposition'] is None
                        and record['observed_authority'] == self.auth['expected_old_sha'])
                self.stage = 'SEND_ARMED'
            else:
                require(record['stage'] == 'TERMINAL')
                if record['disposition'] == 'COMMITTED':
                    require(self.stage == 'SEND_ARMED' and record['observed_authority'] == self.auth['candidate_sha'])
                else:
                    require(self.stage == 'PREPARED' and record['disposition'] == 'NO_SEND')
                self.stage = 'TERMINAL'
                self.result = record['disposition']

    def append(self, record):
        # Non-force one-parent append elects at most one sibling. Never retry.
        require(self.p.ref(JOURNAL) == self.head, 'JOURNAL_STALE')
        plan = object_plan('journal.json', record, self.head, 'BMIN journal ' + digest(record))
        self.p.create(plan)
        self.p.append_journal(plan)
        require(self.p.ref(JOURNAL) == plan['sha'], 'JOURNAL_UNCONFIRMED')
        fresh = Journal(self.p, self.c)
        require(fresh.head == plan['sha'])
        self.__dict__.update(fresh.__dict__)

    def prepare(self, p, authorization):
        require(self.stage == 'GENESIS')
        self.append(dict(schema='BMIN_JOURNAL_V1', stage='PREPARED', proposal=p,
                         authorization=authorization, authorization_sha256=digest(authorization)))

    def arm(self):
        require(self.stage == 'PREPARED')
        self.append(self.record('SEND_ARMED', None, self.auth['expected_old_sha']))

    def record(self, stage, disposition, observed):
        return dict(schema='BMIN_JOURNAL_V1', stage=stage, authorization_sha256=digest(self.auth),
                    disposition=disposition, observed_authority=observed)

    def finish(self, disposition, observed):
        self.append(self.record('TERMINAL', disposition, observed))
