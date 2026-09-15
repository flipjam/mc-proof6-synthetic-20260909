"""Synthetic successor freeze only. IDs below are not provider assignments."""
import copy
import fixtures as f
from common import *
from common import _canonical, _digest
import qualification as q


def seal_configuration(m):
    m['configuration_sha256'] = _digest(_canonical(dict(
        authority=m['authority_rulesets'], journal=m['journal']['rulesets'],
        runtime=m['runtime_rulesets'], environment=m['environment_policy'])))


def setup():
    g, m, _ = f.setup()
    del m['q0_evidence_sha256']
    m.update(schema=EXEC_MANIFEST_SCHEMA, successor_contract=EXEC_CONTRACT,
        source_identity=EXEC_SOURCE, accepted_source_commit=ACCEPTED_SOURCE,
        accepted_source_tree=ACCEPTED_TREE, workflow_identity=EXEC_WORKFLOW,
        workflow_ref=REPO + '/' + WORKFLOW + '@' + EXEC_RUNTIME_REF,
        workflow_sha256=m['source_hashes'][WORKFLOW],
        compatibility_admission=copy.deepcopy(q.EXEC_COMPAT_ADMISSION),
        compatibility_admission_sha256=q.EXEC_COMPAT_ADMISSION_SHA256)
    m['runtime']['ref'] = EXEC_RUNTIME_REF
    m['runtime_rulesets'] = f.rules(EXEC_RUNTIME_REF, 1101, True)
    m['environment_policy']['deployment_branches'][0]['name'] = EXEC_RUNTIME_REF.removeprefix('refs/heads/')
    seal_configuration(m)
    g.q0_provider.clear()
    g.rules = {str(r['id']): r for r in m['authority_rulesets'] +
               list(m['journal']['rulesets'].values()) + m['runtime_rulesets']}
    del g.refs[RUNTIME_REF]
    g.refs[EXEC_RUNTIME_REF] = m['source_commit']
    g.objects[m['source_commit']]['parents'] = [{'sha': ACCEPTED_SOURCE}]
    original_api = g.api
    def api(token, method, path, body=None):
        # Observe the response at the requested URL, even if its ID contradicts it.
        if method == 'GET' and path.startswith(f.j.BASE + '/rulesets/'):
            return copy.deepcopy(g.rules[path.rsplit('/', 1)[1]])
        return original_api(token, method, path, body)
    g.api = api
    return g, m


def environment(m, run=50):
    return dict(P6WSV1_EXEC_COMPAT_FROZEN_MANIFEST=_canonical(m).decode('ascii'),
        P6WSV1_EXEC_COMPAT_MANIFEST_SHA256=_digest(_canonical(m)),
        GITHUB_REPOSITORY=REPO, GITHUB_REPOSITORY_ID=str(REPO_ID),
        GITHUB_REF=EXEC_RUNTIME_REF, GITHUB_SHA=m['source_commit'],
        GITHUB_WORKFLOW_REF=m['workflow_ref'], GITHUB_EVENT_NAME='workflow_dispatch',
        GITHUB_RUN_ATTEMPT='1', GITHUB_RUN_ID=str(run),
        GITHUB_ACTOR=f.pc.CALLER['login'], GITHUB_TRIGGERING_ACTOR=f.pc.CALLER['login'],
        GITHUB_ACTOR_ID=str(f.pc.CALLER['id']), RUNNER_ENVIRONMENT='github-hosted',
        GH_TOKEN='offline-job-token', P6WSV1_D03_JOB_TOKEN='offline-job-token',
        P6WSV1_APP_TOKEN='offline-token', P6WSV1_APP_INSTALLATION_ID=str(INSTALLATION),
        P6WSV1_APP_SLUG='mc-proof-6-gate-writer', GITHUB_EVENT_PATH='offline-event.json')
