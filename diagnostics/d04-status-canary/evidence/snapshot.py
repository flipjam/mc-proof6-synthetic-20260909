import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

BASE = 'repos/flipjam/mc-proof6-synthetic-20260909'
ROOT = Path('D:/Projects/mc-proof6-r3g-candidate')

def api(path):
    p = subprocess.run(['gh', 'api', path, '--paginate', '--slurp'], capture_output=True, text=True, check=True)
    pages = json.loads(p.stdout)
    if pages and isinstance(pages[0], list):
        return sum(pages, [])
    assert len(pages) == 1, (path, len(pages))
    return pages[0]

def snapshot():
    paths = {'repo': BASE, 'rulesets': BASE + '/rulesets?per_page=100',
             'branches': BASE + '/branches?per_page=100', 'environments': BASE + '/environments?per_page=100',
             'workflows': BASE + '/actions/workflows?per_page=100', 'hooks': BASE + '/hooks?per_page=100',
             'runs': BASE + '/actions/runs?per_page=100',
             'manifest': BASE + '/environments/proof6-writer/variables/PROOF6_FROZEN_MANIFEST'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        result = dict(zip(paths, pool.map(api, paths.values())))
    result['repo'] = {k: result['repo'][k] for k in ('id', 'full_name', 'default_branch')}
    result['hooks'] = [{k: h[k] for k in ('id', 'active', 'events')} for h in result['hooks']]
    result['runs'] = [{k: r[k] for k in ('id','head_sha','head_branch','event','status','conclusion','run_number','run_attempt')}
                      for r in result['runs']['workflow_runs']]
    result['manifest'] = {'sha256': hashlib.sha256(result['manifest']['value'].encode()).hexdigest()}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        result['rulesets'] = list(pool.map(api, [BASE + '/rulesets/' + str(r['id']) for r in result['rulesets']]))
    query = 'query { repository(owner:"flipjam",name:"mc-proof6-synthetic-20260909") { branchProtectionRules(first:100) { totalCount pageInfo { hasNextPage } nodes { pattern requiresStatusChecks requiredStatusCheckContexts } } } }'
    raw = subprocess.check_output(['gh','api','graphql','-f','query='+query])
    classic = json.loads(raw)
    assert not classic.get('errors')
    result['classic'] = classic['data']['repository']['branchProtectionRules']
    assert not result['classic']['pageInfo']['hasNextPage']
    for e in result['environments']['environments']:
        e['branch_policies'] = api(BASE + '/environments/' + e['name'] + '/deployment-branch-policies?per_page=100')
        e['custom_rules'] = api(BASE + '/environments/' + e['name'] + '/deployment_protection_rules')
    result['protected_refs'] = {b['name']: b['commit']['sha'] for b in result['branches'] if b['protected']}
    def git(*args):
        return subprocess.check_output(['git','-C',str(ROOT),*args])
    import yaml
    workflow_views = []
    for b in result['branches']:
        if not b['name'].startswith('proof6-writer-runtime'):
            continue
        sha = b['commit']['sha']
        for path in git('ls-tree','-r','--name-only',sha,'.github/workflows').decode().splitlines():
            data = git('show',sha+':'+path)
            doc = yaml.load(data, Loader=yaml.BaseLoader)
            workflow_views.append({'ref':b['name'],'sha':sha,'path':path,'blob':git('rev-parse',sha+':'+path).decode().strip(),
                                   'sha256':hashlib.sha256(data).hexdigest(),'on':doc['on']})
    result['protected_workflows'] = workflow_views
    source_sha = git('rev-parse','HEAD').decode().strip()
    assert source_sha == '73b686f16b052695a4c41706b4b777206a6b0ba1'
    inventory = json.loads(git('show',source_sha+':proofs/proof6/build.json'))
    for path, digest in inventory.items():
        assert hashlib.sha256(git('show',source_sha+':'+path)).hexdigest() == digest
    result['source'] = {'sha':source_sha,'build_entries':len(inventory),'inventory':inventory}
    assert all(x['type'] in ('update','creation','deletion','non_fast_forward') for r in result['rulesets'] for x in r['rules'])
    assert not result['classic']['nodes'] and not result['hooks']
    assert all(set(w['on']) == {'workflow_dispatch'} for w in workflow_views)
    assert len(result['environments']['environments']) == 1
    e = result['environments']['environments'][0]
    assert [r['type'] for r in e['protection_rules']] == ['branch_policy']
    assert e['custom_rules']['total_count'] == 0
    assert [p['name'] for p in e['branch_policies']['branch_policies']] == ['proof6-writer-runtime-r3g']
    assert result['manifest']['sha256'] == '0d40dd07278bf56b91b4ac76668fb7d0273a0e88080d5ccebe43e510a21a0bb1'
    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return result

if __name__ == '__main__':
    s = snapshot()
    raw = json.dumps(s, sort_keys=True, indent=2).encode()
    Path(sys.argv[1]).write_bytes(raw)
    print(json.dumps({'file':sys.argv[1],'sha256':hashlib.sha256(raw).hexdigest(),'observed_at':s['observed_at'],
                      'rulesets':len(s['rulesets']),'protected_refs':len(s['protected_refs']),
                      'workflows':len(s['protected_workflows']),'latest_run':s['runs'][0]},sort_keys=True))
