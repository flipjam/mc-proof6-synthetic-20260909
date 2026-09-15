"""Inert durable provider. There are no credentials or external endpoints."""
import copy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import *
from broker import Broker
from journal import GENESIS, Journal


def history():
    return {'version': 1, 'events': [dict(id='init', seq=1, op='init', data=dict(
        project=PROJECT, subject=SUBJECT, roadmap=0,
        dependency=dict(repository='synthetic/dependency', revision=1, sha='d'*40),
        loop=dict(id=LOOP, baton=0, owner='broker'),
        child=dict(id='child', parent=SUBJECT, status='UNRESOLVED', blocks_parent=False)))]}


def config():
    return dict(schema='BMIN_FROZEN_CONFIG_V1', repository=REPOSITORY, repository_id=REPOSITORY_ID,
        project=PROJECT, subject=SUBJECT, loop=LOOP, authority_ref=AUTHORITY, journal_ref=JOURNAL,
        runtime_ref=RUNTIME, environment=ENVIRONMENT, scenario=SCENARIO, runtime_sha='c'*40,
        source_hashes=source_hashes(), initial_authority_sha='a'*40, journal_genesis_sha='b'*40,
        policy_sha256='e'*64, app_id=123, installation_id=456, app_slug='offline-bmin',
        ruleset_ids=list(range(1, 7)))


def intent(h=None):
    return dict(schema='BMIN_PROPOSAL_V1', action='ADVANCE_ROADMAP',
                expected_state_sha256=gate.proof1.reconstruct(h or history())['state_sha256'], expected_baton=0)


class Fake:
    def __init__(self, c):
        self.c = copy.deepcopy(c)
        self.refs = {AUTHORITY: 'a'*40, JOURNAL: 'b'*40, RUNTIME: 'c'*40}
        self.objects = {'a'*40: ([], history()), 'b'*40: ([], GENESIS)}
        self.sends = 0
        self.journal_sends = 0
        self.checks = 0
        self.on_check = None
        self.on_append = None
        self.send_effect = 'commit'
        self.result = {'result': 'INDETERMINATE'}

    def check(self, c):
        self.checks += 1
        if self.on_check:
            self.on_check(self)
        require(c == self.c and self.refs[RUNTIME] == c['runtime_sha'])

    def ref(self, ref):
        return self.refs[ref]

    def read_file(self, sha, filename):
        return copy.deepcopy(self.objects[sha])

    def create(self, plan):
        self.objects[plan['sha']] = ([plan['parent']], copy.deepcopy(plan['value']))

    def append_journal(self, plan):
        require(self.refs[JOURNAL] == plan['parent'])
        self.journal_sends += 1
        self.refs[JOURNAL] = plan['sha']
        if self.on_append:
            self.on_append(self, plan)

    def send_authority(self, plan, authorization, journal_head):
        require(self.refs[JOURNAL] == journal_head and self.refs[AUTHORITY] == plan['parent'])
        self.sends += 1
        if self.send_effect == 'commit':
            self.refs[AUTHORITY] = plan['sha']
        elif self.send_effect == 'conflict':
            self.refs[AUTHORITY] = 'f'*40
        elif self.send_effect == 'raise':
            raise ConnectionError()
        return self.result

    def save(self, path):
        Path(path).write_bytes(canonical(dict(c=self.c, refs=self.refs, objects=self.objects,
                                            sends=self.sends, journal_sends=self.journal_sends)))

    @classmethod
    def restore(cls, path):
        value = parse(Path(path).read_bytes())
        obj = cls(value['c'])
        obj.refs, obj.objects = value['refs'], {k: (v[0], v[1]) for k, v in value['objects'].items()}
        obj.sends, obj.journal_sends = value['sends'], value['journal_sends']
        return obj
