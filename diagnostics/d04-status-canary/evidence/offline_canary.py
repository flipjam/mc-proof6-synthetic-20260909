"""Offline source/custody exercise. NO provider call or acceptance credit."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile

source = Path('/mnt/d/Projects/mc-proof6-r3h-live-status-canary/diagnostics/d04-status-canary')
with tempfile.TemporaryDirectory(prefix='proof6-offline-canary-') as tmp:
    root = Path(tmp)
    for name in ('producer.py','helper.py'):
        shutil.copyfile(source/name,root/name)
    os.environ.clear()
    branch = 'refs/heads/codex/proof6-r3h-live-status-canary-20260912-01'
    os.environ.update(GITHUB_REPOSITORY='flipjam/mc-proof6-synthetic-20260909',GITHUB_REPOSITORY_ID='1363510385',
        GITHUB_REF=branch,GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='999',
        GITHUB_SHA='a'*40,CANARY_STATUS_TOKEN='OFFLINE-NONSECRET-CUSTODY-MARKER',
        GITHUB_WORKFLOW_REF='flipjam/mc-proof6-synthetic-20260909/.github/workflows/proof6-writer.yml@'+branch)
    spec=importlib.util.spec_from_file_location('fixed_helper',root/'helper.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    events=[]
    def mock_post(token,sha,run_id,attempt,event):
        assert token=='OFFLINE-NONSECRET-CUSTODY-MARKER'
        assert sha=='a'*40 and run_id==999 and attempt==1
        events.append(event)
        print('OFFLINE_MOCK_POST',event['phase'],flush=True)
    helper.post=mock_post
    helper.main()
    assert [x['phase'] for x in events]==['READY','END']
    assert events[1]['monotonic']-events[0]['monotonic']>=20
    print('OFFLINE_SOURCE_CUSTODY_PASS; zero provider calls; zero acceptance credit',flush=True)
